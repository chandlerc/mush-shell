// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The traversal lab shared by the path-establishment netsim suites:
//! the real jump helper on the simulated network, and a destination
//! wired exactly as `mush server bootstrap` wires one. The addresses
//! below are one lab, so a scenario in either suite reads against the
//! same topology: a client behind whatever edge it is given, a
//! destination behind another, and a bastion both can reach.
//!
//! Determinism rules per mush-netsim's crate docs: current-thread
//! runtime, `start_paused`, no real sockets, `biased` selects.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mush_core::bootstrap::{
  Connect, Hello, PROTOCOL_VERSION, SessionNonce, SessionSecret,
};
use mush_core::channel::SignalChannel;
use mush_core::client::{self, ClientOptions, ClientSession, Traversal};
use mush_core::helper::{
  Control, HelperOptions, HelperService, ProbeSocket, Registration, serve,
};
use mush_core::path::{
  Arrival, ClientPlan, DestinationPaths, PathKind, TRAVERSAL_ESTABLISH_TIMEOUT,
  drive_destination,
};
use mush_core::pinning::{self, SessionIdentity};
use mush_core::server::{accept_session, addr_hints};
use mush_core::transport::TransportOptions;
use mush_core::traversal::TraversalEndpoint;
use mush_core::traversal::TraversalSocket;
use mush_core::upgrade::{DestinationUpgrade, UpgradeEvent, UpgradePolicy};
use mush_netsim::{
  LinkConfig, SimNet, SimSocket, derive_u64, seeded_endpoint_config,
};
use tokio::io::{
  AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream,
};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};

/// Virtual-time bound on any single await, so a stuck scenario fails
/// crisply instead of hanging the paused runtime.
pub const DEADLINE: Duration = Duration::from_secs(600);

/// The jump host's traversal socket: the one address both peers can
/// reach, whatever their edges do.
pub const HELPER: &str = "198.51.100.7:60123";

/// The jump host's second address, for the dual-homed bastion: the
/// address on the network its own side of the lab is on.
pub const HELPER_DMZ: &str = "10.9.0.7:60123";

/// The client's own address, inside its edge.
pub const CLIENT: &str = "203.0.113.2:41000";

/// The public address the client's edge translates to.
pub const CLIENT_PUBLIC: &str = "5.5.5.5";

/// The destination's own address, inside its edge. Reachable from the
/// client only where the edge does not translate.
pub const DEST: &str = "192.0.2.2:60123";

/// The public address the destination's edge translates to.
pub const DEST_PUBLIC: &str = "6.6.6.6";

pub fn addr(s: &str) -> SocketAddr {
  s.parse().unwrap()
}

pub fn ip(s: &str) -> IpAddr {
  s.parse().unwrap()
}

/// The session secret every scenario uses: the client generates one
/// alongside the nonce and hands it to the helper over its ssh channel,
/// which is what makes the helper act on this session's probes.
pub fn secret() -> SessionSecret {
  SessionSecret::from_bytes([0xa7; 16])
}

/// The jump host's traversal sockets under the helper's own socket trait,
/// which lets the production loop run on the simulated network.
///
/// A real bastion binds the unspecified address and answers on each of
/// its addresses; the simulated network binds one socket per address, so
/// this stands in. A peer is answered and forwarded to on the address it
/// was last heard on, which is what the route lookup behind a wildcard
/// socket amounts to.
pub struct MultiHomedSocket {
  sockets: Vec<SimSocket>,
  seen: Mutex<HashMap<SocketAddr, usize>>,
}

/// Binds `addrs` on the simulated network as one helper socket.
pub fn helper_socket(net: &SimNet, addrs: &[SocketAddr]) -> MultiHomedSocket {
  MultiHomedSocket {
    sockets: addrs.iter().map(|&a| net.bind(a).unwrap()).collect(),
    seen: Mutex::new(HashMap::new()),
  }
}

impl ProbeSocket for MultiHomedSocket {
  async fn recv_from(
    &self,
    buf: &mut [u8],
  ) -> std::io::Result<(usize, SocketAddr)> {
    let mut spare = vec![0u8; buf.len()];
    let (received, index) = match self.sockets.as_slice() {
      [one] => (one.recv_from(buf).await, 0),
      [first, second] => tokio::select! {
        biased;
        received = first.recv_from(buf) => (received, 0),
        received = second.recv_from(&mut spare) => (received, 1),
      },
      sockets => unreachable!(
        "the lab has one or two helper addresses, not {}",
        sockets.len()
      ),
    };
    let (len, from) = received?;
    if index == 1 {
      buf[..len].copy_from_slice(&spare[..len]);
    }
    self.seen.lock().unwrap().insert(from, index);
    Ok((len, from))
  }

  async fn send_to(
    &self,
    datagram: &[u8],
    to: SocketAddr,
  ) -> std::io::Result<()> {
    let index = self.seen.lock().unwrap().get(&to).copied().unwrap_or(0);
    self.sockets[index].send_to(datagram, to)
  }
}

/// Starts the real helper service on the simulated network, serving
/// `nonce` on `addr_count` addresses, with the handle a scenario needs to
/// kill it and start another in its place (the design's restarted
/// bastion).
///
/// Two addresses is the dual-homed bastion the relay path exists for: one
/// service and one address table behind two addresses, which a peer whose
/// NAT maps per destination reaches with two different mappings.
pub fn spawn_helper_handle(
  net: &SimNet,
  nonce: SessionNonce,
  addr_count: usize,
) -> (Vec<SocketAddr>, tokio::task::JoinHandle<()>) {
  let addrs: Vec<SocketAddr> = [HELPER, HELPER_DMZ][..addr_count]
    .iter()
    .copied()
    .map(addr)
    .collect();
  let socket = helper_socket(net, &addrs);
  let mut service =
    HelperService::new(Instant::now(), HelperOptions::default());
  service.admit(Instant::now(), nonce, secret()).unwrap();
  let handle = tokio::spawn(async move {
    // The nonce arrived over the helper's own ssh channel before the
    // service started, so nothing else drives the control channel here;
    // the registration reports are drained and dropped (the client's own
    // signaling carries the same news).
    let (_control_tx, mut control_rx) = mpsc::channel::<Control>(1);
    let (registrations_tx, mut registrations_rx) =
      mpsc::channel::<Registration>(16);
    tokio::spawn(
      async move { while registrations_rx.recv().await.is_some() {} },
    );
    serve(&socket, &mut service, &mut control_rx, &registrations_tx).await;
  });
  (addrs, handle)
}

/// The destination's half of a session: the bootstrap conversation, then
/// the accept and the path driver running together over one socket.
pub struct Destination {
  /// Kept for the session's lifetime: dropping it tears the connection down.
  pub _endpoint: quinn::Endpoint,
  pub connection: quinn::Connection,
  pub send: quinn::SendStream,
  pub recv: quinn::RecvStream,
}

pub async fn run_destination(
  net: SimNet,
  mut channel: DuplexStream,
  seed: u64,
) -> anyhow::Result<Destination> {
  let paths = TraversalEndpoint::over(
    Box::new(net.bind(addr(DEST))?),
    seeded_endpoint_config(seed),
    None,
    Arc::new(quinn::TokioRuntime),
  )?;
  let (hello, leftover) = read_hello(&mut channel).await?;
  let identity = SessionIdentity::generate()?;
  paths
    .endpoint
    .set_server_config(Some(pinning::server_config(
      &identity,
      hello.client_key,
      &TransportOptions::default(),
    )?));

  // The connect line's hints are what a jump-side `$SSH_CONNECTION` and
  // this host's own interfaces give it: its address inside its edge,
  // which only an edge that does not translate leaves reachable.
  let local = addr(DEST);
  let connect = Connect {
    version: PROTOCOL_VERSION,
    udp_port: local.port(),
    server_key: identity.pin(),
    addr_hints: addr_hints(
      Some("198.51.100.7 40000 192.0.2.2 22"),
      &[local.ip()],
      local,
    ),
  };
  channel.write_all(connect.to_wire().as_bytes()).await?;
  channel.flush().await?;

  let nonce = hello.nonce.expect("the client asked to signal");
  let mut signaling = SignalChannel::new(channel, leftover);
  let mut destination = DestinationPaths::new(nonce);
  let TraversalEndpoint {
    endpoint,
    socket,
    mut probes,
  } = paths;
  let accepted = {
    let driver =
      drive_destination(&mut signaling, &socket, &mut probes, &mut destination);
    let accept = accept_session(&endpoint, DEADLINE);
    tokio::pin!(driver);
    tokio::select! {
      biased;
      accepted = accept => accepted,
      () = &mut driver => {
        anyhow::bail!("the destination's signaling ended before the session")
      }
    }
  };
  let (connection, send, recv) = accepted?;
  // Spawned where `mush server bootstrap` spawns it: once the session is
  // accepted and establishment has handed over what it learned.
  if let Some(upgrade) = DestinationUpgrade::new(
    Instant::now(),
    destination.handoff(),
    UpgradePolicy::default(),
    socket,
    probes,
  ) {
    tokio::spawn(upgrade.run(connection.clone()));
  }
  Ok(Destination {
    _endpoint: endpoint,
    connection,
    send,
    recv,
  })
}

/// Reads the single `MUSH HELLO` line, with the bytes read past it.
pub async fn read_hello<C: AsyncRead + AsyncWrite + Unpin>(
  channel: &mut C,
) -> anyhow::Result<(Hello, Vec<u8>)> {
  let mut buf = Vec::new();
  let mut chunk = [0u8; 512];
  loop {
    if let Some(newline) = buf.iter().position(|&b| b == b'\n') {
      let hello = Hello::parse(str::from_utf8(&buf[..newline])?)?;
      return Ok((hello, buf[newline + 1..].to_vec()));
    }
    let read = channel.read(&mut chunk).await?;
    anyhow::ensure!(read > 0, "the bootstrap channel closed before the hello");
    buf.extend_from_slice(&chunk[..read]);
  }
}

/// What a scenario varies about the lab's client. Everything else -- its
/// secret, upgrade policy, and the rest of its plan -- is the same
/// wherever a client is built, so no suite can drift on what a client is.
pub struct ClientSetup {
  /// The address the client binds, inside its own edge.
  pub client_addr: SocketAddr,
  pub nonce: SessionNonce,
  /// The entropy source for the client's own endpoint.
  pub endpoint_seed: u64,
  /// The `--stun <server>` servers the plan names, if any.
  pub stun_servers: Vec<SocketAddr>,
  /// What the client's second ssh delivers during establishment, in
  /// order: the helper's ready line, then what the jump saw of this client.
  pub arrivals: Vec<Arrival>,
}

/// A lab client ready to establish, and the two pieces a scenario keeps.
pub struct LabClient {
  pub options: ClientOptions,
  /// The session's path manager, which is also the socket it probes from.
  pub socket: Arc<TraversalSocket>,
  /// Held open for the scenario's lifetime: establishment reads this
  /// sender's drop as `mush connect` saying there is no helper.
  pub arrivals: mpsc::Sender<Arrival>,
}

/// Builds the client half of a lab session: a traversal endpoint on the
/// simulated network, and the options `ClientSession::establish` takes.
pub async fn lab_client(
  net: &SimNet,
  setup: ClientSetup,
) -> anyhow::Result<LabClient> {
  let paths = TraversalEndpoint::over(
    Box::new(net.bind(setup.client_addr)?),
    seeded_endpoint_config(setup.endpoint_seed),
    None,
    Arc::new(quinn::TokioRuntime),
  )?;
  let (arrivals_tx, arrivals_rx) = mpsc::channel(4);
  for arrival in setup.arrivals {
    arrivals_tx.send(arrival).await?;
  }
  let socket = paths.socket.clone();
  let options = ClientOptions {
    endpoint: client::EndpointSource::Endpoint(paths.endpoint),
    session_nonce: Some(setup.nonce),
    establish_timeout: TRAVERSAL_ESTABLISH_TIMEOUT,
    traversal: Some(Traversal {
      socket: paths.socket,
      secret: secret(),
      probes: paths.probes,
      arrivals: Some(arrivals_rx),
      plan: ClientPlan {
        self_addrs: vec![setup.client_addr],
        local_ips: vec![setup.client_addr.ip()],
        stun_servers: setup.stun_servers,
        helper_expected: true,
        allow_loopback: false,
      },
      upgrade: UpgradePolicy::default(),
    }),
    ..ClientOptions::default()
  };
  Ok(LabClient {
    options,
    socket,
    arrivals: arrivals_tx,
  })
}

/// Drives the client's path policy for a session, as `mush connect`
/// does, handing back the moves it reports.
pub fn spawn_policy(
  session: &mut ClientSession<DuplexStream>,
) -> (tokio::task::JoinHandle<()>, mpsc::Receiver<UpgradeEvent>) {
  let upgrade = session
    .upgrade
    .take()
    .expect("a relayed session carries a path policy");
  let connection = session.connection.clone();
  let (moves, moved) = mpsc::channel(8);
  (tokio::spawn(upgrade.run(connection, moves)), moved)
}

/// A whole session on the lab's simulated network, up on the relay
/// because the client and the destination could not reach each other at
/// all.
pub struct RelayedLab {
  pub net: SimNet,
  /// The client's own socket, which is also the session's path manager.
  pub socket: Arc<TraversalSocket>,
  pub session: ClientSession<DuplexStream>,
  pub destination: Destination,
  /// The session this lab's helper serves, needed to start its successor.
  pub nonce: SessionNonce,
  /// The running helper, killable so a scenario can reboot the bastion.
  pub helper: tokio::task::JoinHandle<()>,
}

/// Opens or closes the direct path between the two peers.
///
/// Closed during establishment, leaving the relay to carry the session
/// and a genuine upgrade to make; opening it afterwards is the network
/// change a punch that finally succeeds, or a route that came back, would
/// be.
pub fn direct_path(net: &SimNet, open: bool) {
  net.set_link_blackhole(addr(CLIENT).ip(), addr(DEST).ip(), !open);
  net.set_link_blackhole(addr(DEST).ip(), addr(CLIENT).ip(), !open);
}

/// Brings a session up on the relay, with the direct path still shut.
pub async fn relayed_session(
  seed: u64,
  link: LinkConfig,
) -> anyhow::Result<RelayedLab> {
  let net = SimNet::new(seed);
  net.set_default_link(link);
  direct_path(&net, false);

  let nonce = SessionNonce::from_bytes([0xc3; 16]);
  let (helper, running) = spawn_helper_handle(&net, nonce, 1);
  let (client_io, server_io) = tokio::io::duplex(64 * 1024);
  let destination = tokio::spawn(run_destination(
    net.clone(),
    server_io,
    derive_u64(seed, "destination"),
  ));

  let LabClient {
    options,
    socket,
    arrivals: _arrivals,
  } = lab_client(
    &net,
    ClientSetup {
      client_addr: addr(CLIENT),
      nonce,
      endpoint_seed: derive_u64(seed, "client"),
      stun_servers: Vec::new(),
      arrivals: vec![Arrival::Helper(helper)],
    },
  )
  .await?;

  let mut session =
    timeout(DEADLINE, ClientSession::establish(client_io, options)).await??;
  anyhow::ensure!(
    session.path_kind == PathKind::Relayed,
    "the session came up on the {} path, not the relay",
    session.path_kind
  );
  anyhow::ensure!(session.chosen_addr == addr(HELPER));

  // The destination's accept completes on the client's first stream
  // bytes, so the session has to speak before either end is settled.
  session.send.write_all(b"up").await?;
  let mut destination = timeout(DEADLINE, destination).await???;
  let mut hello = [0u8; 2];
  timeout(DEADLINE, destination.recv.read_exact(&mut hello)).await??;

  Ok(RelayedLab {
    net,
    socket,
    session,
    destination,
    nonce,
    helper: running,
  })
}
