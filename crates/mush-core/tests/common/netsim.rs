// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The simulated network the prober's netsim suites share: real quinn
//! endpoints on mush-netsim sockets, the session engines' own pinning,
//! and the bounds the design's active recovery promises.
//!
//! Determinism rules per mush-netsim's crate docs: current-thread
//! runtime, `start_paused`, no real sockets, `biased` selects.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use mush_core::client::{self, ClientOptions, ClientSession};
use mush_core::roaming::{
  FreshSocket, PathWake, ProbeOptions, ProbeStats, Prober, RouteCheck,
  SocketFactory,
};
use mush_core::server::{self, ServerOptions, ServerSession};
use mush_core::transport::{
  DEFAULT_PROBE_INTERVAL, DEFAULT_STALL_THRESHOLD, TransportOptions,
};
use mush_netsim::{
  EventKind, LinkConfig, SimNet, derive_u64, seeded_endpoint_config,
};
use quinn::{Endpoint, TokioRuntime};
use tokio::io::DuplexStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

/// Virtual-time bound on any single await, so a stuck scenario fails
/// crisply instead of hanging the paused runtime.
pub const DEADLINE: Duration = Duration::from_secs(2400);

/// App-level traffic cadence in both directions.
pub const TICK: Duration = Duration::from_millis(100);

const CLIENT_IP: &str = "10.0.0.1";
pub const SERVER_ADDR: &str = "10.0.0.2:60123";

/// Worst case from a path dying to the prober's first probe: two probe
/// intervals of sampling lag (the tick that last saw the path answer,
/// and the tick that first sees something outstanding), then the stall
/// threshold, which the tick schedule is pulled in to coincide with
/// exactly.
pub const DETECT_BOUND: Duration = DEFAULT_PROBE_INTERVAL
  .saturating_add(DEFAULT_PROBE_INTERVAL)
  .saturating_add(DEFAULT_STALL_THRESHOLD);

/// Worst case from a restored path to the first byte arriving, with a
/// stall episode already underway: the next probe is at most a probe
/// interval off, and a second interval covers the probe that crosses
/// mid-restore plus the round trip its answer takes.
pub const RESTORE_BOUND: Duration =
  DEFAULT_PROBE_INTERVAL.saturating_add(DEFAULT_PROBE_INTERVAL);

/// Worst case for a whole episode, detection included: the bound the
/// design's active recovery promises. The episode opens with the
/// fresh-socket rebind, so the first probe already carries the recovery,
/// and [`RESTORE_BOUND`] covers its round trip and the slot after it.
pub const RECOVERY_BOUND: Duration = DETECT_BOUND.saturating_add(RESTORE_BOUND);

pub fn addr(s: &str) -> SocketAddr {
  s.parse().unwrap()
}

pub fn client_ip() -> IpAddr {
  CLIENT_IP.parse().unwrap()
}

pub fn client_addr() -> SocketAddr {
  addr("10.0.0.1:41000")
}

/// An endpoint on the simulated network with no crypto config yet; the
/// engines install their pinned configs themselves.
fn sim_endpoint(net: &SimNet, addr: SocketAddr, seed: u64) -> Endpoint {
  let socket = net.bind(addr).unwrap();
  Endpoint::new_with_abstract_socket(
    seeded_endpoint_config(seed),
    None,
    Box::new(socket),
    Arc::new(TokioRuntime),
  )
  .unwrap()
}

/// A [`SocketFactory`] binding fresh simulated-network sockets at `ip`,
/// ports counting up from `first_port` and wrapping within the ephemeral
/// range: a probe that rebinds tens of thousands of times must exhaust
/// ports the way a real host does, not overflow the counter.
pub fn sim_socket_factory(
  net: &SimNet,
  ip: IpAddr,
  first_port: u16,
) -> SocketFactory {
  let net = net.clone();
  let span = u16::MAX - first_port;
  let mut n: u32 = 0;
  Box::new(move || {
    let port = first_port + (n % u32::from(span)) as u16;
    n += 1;
    let socket = net.bind(SocketAddr::new(ip, port))?;
    Ok(FreshSocket::plain(socket))
  })
}

/// A [`RouteCheck`] with a fixed answer: the simulated network has no
/// kernel routing table, so each test says whether its client can still
/// reach the peer.
pub fn sim_route(reachable: bool) -> RouteCheck {
  counting_route(reachable).0
}

/// [`sim_route`] with the consultation count, for the probes that care
/// how often the prober asks the kernel anything.
pub fn counting_route(reachable: bool) -> (RouteCheck, Arc<AtomicU64>) {
  let calls = Arc::new(AtomicU64::new(0));
  let counter = calls.clone();
  (
    Box::new(move || {
      counter.fetch_add(1, Ordering::Relaxed);
      reachable
    }),
    calls,
  )
}

/// A 30ms-each-way quiet WAN, the lab recovery scenario's shape.
pub fn wan(seed: u64) -> SimNet {
  let net = SimNet::new(seed);
  net.set_default_link(LinkConfig {
    latency: Duration::from_millis(30),
    ..LinkConfig::default()
  });
  net
}

/// Establishes a session across the simulated network with the engines'
/// own pinning, as production does.
pub async fn establish(
  net: &SimNet,
  seed: u64,
  transport: TransportOptions,
) -> anyhow::Result<(ClientSession<DuplexStream>, ServerSession<DuplexStream>)>
{
  let server_ip = addr(SERVER_ADDR).ip();
  establish_racing(net, seed, transport, server_ip, Vec::new(), Vec::new())
    .await
}

/// [`establish`] with the candidates spelled out. The server, listening
/// at [`SERVER_ADDR`], hints `reached`, where `$SSH_CONNECTION` says the
/// client's ssh arrived, and then `interface_ips`. The client adds its own
/// `resolved_ips`.
pub async fn establish_racing(
  net: &SimNet,
  seed: u64,
  transport: TransportOptions,
  reached: IpAddr,
  interface_ips: Vec<IpAddr>,
  resolved_ips: Vec<IpAddr>,
) -> anyhow::Result<(ClientSession<DuplexStream>, ServerSession<DuplexStream>)>
{
  let server_endpoint =
    sim_endpoint(net, addr(SERVER_ADDR), derive_u64(seed, "server"));
  let client_endpoint =
    sim_endpoint(net, client_addr(), derive_u64(seed, "client"));
  let (client_io, server_io) = tokio::io::duplex(64 * 1024);
  let server_task = tokio::spawn(ServerSession::run(
    server_io,
    ServerOptions {
      endpoint: server::EndpointSource::Endpoint(server_endpoint),
      ssh_connection: Some(format!("{CLIENT_IP} 41000 {reached} 22")),
      interface_ips,
      ..ServerOptions::default()
    },
  ));
  let mut client = timeout(
    DEADLINE,
    ClientSession::establish(
      client_io,
      ClientOptions {
        endpoint: client::EndpointSource::Endpoint(client_endpoint),
        transport,
        establish_timeout: Duration::from_secs(30),
        resolved_ips,
        ..ClientOptions::default()
      },
    ),
  )
  .await??;
  // The server surfaces its stream on the client's first stream bytes.
  client.send.write_all(b"hi").await?;
  let server = timeout(DEADLINE, server_task).await???;
  Ok((client, server))
}

/// Spawns the prober for the client side of an established session.
pub fn spawn_prober(
  client: &ClientSession<DuplexStream>,
  fresh_socket: SocketFactory,
  route_check: RouteCheck,
  events: Option<mpsc::UnboundedReceiver<PathWake>>,
  options: ProbeOptions,
) -> (JoinHandle<()>, Arc<ProbeStats>) {
  let stats = Arc::new(ProbeStats::default());
  let task = tokio::spawn(
    Prober {
      connection: client.connection.clone(),
      endpoint: client.endpoint.clone(),
      fresh_socket,
      route_check,
      events,
      session_socket: None,
      options,
      stats: stats.clone(),
    }
    .run(),
  );
  (task, stats)
}

/// What a prober scenario varies. `new` is the shape almost all of them
/// want; override with struct update syntax, then [`start`](Self::start).
pub struct ScenarioPlan<'a> {
  /// The network to establish over, kept by the caller so it can stop
  /// delivering and come back under the running session.
  pub net: &'a SimNet,
  /// Seeds the network's randomness and both endpoints' crypto.
  pub seed: u64,
  pub transport: TransportOptions,
  pub probe: ProbeOptions,
  /// Where the prober's rebinds get their sockets; `None` binds fresh
  /// ones at the client's own address, counting up from port 41001.
  pub fresh_socket: Option<SocketFactory>,
  /// What the kernel answers about routing to the peer; `None` says it can.
  pub route_check: Option<RouteCheck>,
  /// The platform wake stream, for the scenarios that drive one.
  pub wakes: Option<mpsc::UnboundedReceiver<PathWake>>,
  /// Whether the prober runs at all. The scenarios that model one by
  /// hand, or that measure a session without it, say no.
  pub prober: bool,
  /// How often the client writes, or `None` for a client that only reads.
  /// Both shapes matter: outstanding data parks in the congestion window,
  /// which the prober's send-window clamp exists to keep clear.
  pub client_tick: Option<Duration>,
}

impl<'a> ScenarioPlan<'a> {
  /// A session on `net` with the shipped transport and probe policy,
  /// the prober running against a kernel that still routes to the peer,
  /// no wakes, and both ends ticking at [`TICK`].
  pub fn new(net: &'a SimNet, seed: u64) -> Self {
    Self {
      net,
      seed,
      transport: TransportOptions::default(),
      probe: ProbeOptions::default(),
      fresh_socket: None,
      route_check: None,
      wakes: None,
      prober: true,
      client_tick: Some(TICK),
    }
  }

  /// Establishes the session and spawns everything that drives it.
  pub async fn start(self) -> anyhow::Result<Scenario> {
    let net = self.net;
    let (client, server) = establish(net, self.seed, self.transport).await?;
    let probing = self.prober.then(|| {
      spawn_prober(
        &client,
        self
          .fresh_socket
          .unwrap_or_else(|| sim_socket_factory(net, client_ip(), 41001)),
        self.route_check.unwrap_or_else(|| sim_route(true)),
        self.wakes,
        self.probe,
      )
    });
    let (prober, stats) = match probing {
      Some((task, stats)) => (Some(task), stats),
      None => (None, Arc::new(ProbeStats::default())),
    };
    let client_connection = client.connection.clone();
    let server_connection = server.connection.clone();
    let endpoints = (client.endpoint.clone(), server.endpoint.clone());
    // A ticker that is not wanted still consumes the send stream, so
    // the client's half closes the same way either way.
    let client_tick = self
      .client_tick
      .map(|every| spawn_ticker_every(client.send, every));
    let server_tick = spawn_ticker(server.send);
    let (server_drain, server_arrivals) = spawn_arrivals(server.recv);
    let (client_reader, arrivals) = spawn_arrivals(client.recv);
    Ok(Scenario {
      client: client_connection,
      server: server_connection,
      stats,
      arrivals,
      server_arrivals,
      tasks: prober
        .into_iter()
        .chain(client_tick)
        .chain([server_tick, server_drain, client_reader])
        .collect(),
      _endpoints: endpoints,
    })
  }
}

/// A running prober scenario built by [`ScenarioPlan::start`]: the session
/// both ends feed, the prober's counters, and each end's arrival instants.
pub struct Scenario {
  /// The client's connection, for its stats and its closure.
  pub client: quinn::Connection,
  /// The destination's connection, whose remote address shows a migration.
  pub server: quinn::Connection,
  /// The prober's intervention counters; all zero without a prober.
  pub stats: Arc<ProbeStats>,
  /// When the client's reader saw each read.
  pub arrivals: mpsc::UnboundedReceiver<Instant>,
  /// The same at the destination, for scenarios checking the client's own
  /// writes resume.
  pub server_arrivals: mpsc::UnboundedReceiver<Instant>,
  tasks: Vec<JoinHandle<()>>,
  /// Dropping either endpoint tears its connection down.
  _endpoints: (Endpoint, Endpoint),
}

impl Scenario {
  /// Stops everything the scenario spawned and closes the session,
  /// handing back the prober's counters for a caller that reports them.
  pub fn finish(self) -> Arc<ProbeStats> {
    for task in &self.tasks {
      task.abort();
    }
    self.client.close(0u32.into(), b"test over");
    self.stats
  }
}

/// Writes one byte every `every` until the stream dies.
fn spawn_ticker_every(
  mut send: quinn::SendStream,
  every: Duration,
) -> JoinHandle<()> {
  tokio::spawn(async move {
    loop {
      if send.write_all(b"T").await.is_err() {
        return;
      }
      tokio::time::sleep(every).await;
    }
  })
}

/// Writes one byte every [`TICK`] until the stream dies.
pub fn spawn_ticker(send: quinn::SendStream) -> JoinHandle<()> {
  spawn_ticker_every(send, TICK)
}

/// Reads the stream and reports each read's virtual arrival instant.
///
/// A clean end and a dead connection both close this channel, and every
/// scenario reads its verdict through it, so a failing read says why
/// before the channel goes: otherwise a session the transport killed is
/// indistinguishable from a peer that went quiet.
pub fn spawn_arrivals(
  mut recv: quinn::RecvStream,
) -> (JoinHandle<()>, mpsc::UnboundedReceiver<Instant>) {
  let (tx, rx) = mpsc::unbounded_channel();
  let task = tokio::spawn(async move {
    let mut buf = [0u8; 4096];
    loop {
      match recv.read(&mut buf).await {
        Ok(Some(_)) => {
          if tx.send(Instant::now()).is_err() {
            return;
          }
        }
        Ok(None) => return,
        // Debug, not Display: `ReadError::ConnectionLost` displays as
        // three words and keeps the close reason -- the whole diagnosis
        // when a transport kills a healthy session -- inside.
        Err(error) => {
          eprintln!("session stream read failed: {error:?}");
          return;
        }
      }
    }
  });
  (task, rx)
}

/// The first arrival at or after `after`, discarding earlier ones.
pub async fn arrival_after(
  arrivals: &mut mpsc::UnboundedReceiver<Instant>,
  after: Instant,
) -> anyhow::Result<Instant> {
  loop {
    let at = timeout(DEADLINE, arrivals.recv())
      .await?
      .ok_or_else(|| anyhow::anyhow!("tick stream ended"))?;
    if at >= after {
      return Ok(at);
    }
  }
}

/// Client-side datagrams on the wire, and the distinct source addresses.
pub fn client_wire(net: &SimNet) -> (usize, Vec<SocketAddr>) {
  let mut count = 0;
  let mut sources: Vec<SocketAddr> = Vec::new();
  for event in net.trace() {
    if let EventKind::Sent { src, .. } = event.kind
      && src.ip() == client_ip()
    {
      count += 1;
      if !sources.contains(&src) {
        sources.push(src);
      }
    }
  }
  (count, sources)
}
