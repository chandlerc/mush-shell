// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Active path recovery for the client (design doc, "Timers and
//! budgets"). The [`Prober`] runs beside the client's relay: when the
//! connection looks stalled it forces an ack-eliciting exchange every
//! [`ProbeOptions::probe_interval`] and stops the moment traffic flows
//! again, so recovery after a long outage is bounded by that cadence
//! instead of quinn's backed-off PTO, which measured ~10s between probes
//! after a 30s outage.
//!
//! # Stall detection
//!
//! The prober polls [`quinn::Connection::stats`]. "Stalled" means "we
//! sent and nothing came back" for [`ProbeOptions::stall_threshold`],
//! not "nothing received lately": an idle session legitimately hears
//! nothing between keep-alives. Two signals say that, because a path can
//! break in one direction alone:
//!
//! - No inbound datagram since a transmission. A working path answers
//!   every transmission, an ACK at minimum, since pure ACKs are never
//!   sent unprompted. The client's keep-alives ([`crate::transport`])
//!   guarantee a transmission every keep-alive interval, so even an idle
//!   session finds a dead path.
//! - No inbound ACK frame since an ack-eliciting frame went out. The
//!   first signal proves the peer reaches us, not that we reach the
//!   peer: on a server-driven transfer whose only broken direction is
//!   the client's egress (a dropped upstream NAT mapping, an egress ACL
//!   on the source port, a one-way middlebox), the peer's datagrams keep
//!   arriving and the first signal never fires. Only ack-eliciting
//!   frames count, so a healthy download -- whose inbound data the
//!   client answers with pure ACKs that elicit no ACK back -- does not
//!   trip it.
//!
//! Onset is bounded by two probe intervals of sampling lag plus the
//! threshold, not by the threshold alone: one interval before the tick
//! that last sees the path answer, one more before the tick that first
//! sees something outstanding. From there the tick schedule is pulled in
//! to fire exactly at the threshold, adding no further rounding.
//!
//! # Probing
//!
//! quinn exposes no ping API on [`quinn::Connection`]
//! (`quinn_proto::Connection::ping` exists but is not surfaced), so the
//! prober uses the endpoint's rebind path, whose handling in quinn is
//! an immediate ack-eliciting PING: `Endpoint::rebind_abstract` sends
//! every connection a rebind event, and the connection driver responds
//! with `local_address_changed()`, which queues a PING frame for the
//! next transmit (`quinn/src/connection.rs`, `process_conn_events`).
//! Probe ticks alternate two flavors:
//!
//! - a *rebind* onto a freshly bound socket -- the design doc's
//!   rebind-on-stall heuristic, and the only recovery when the old
//!   source address itself died (wifi off, VPN down). The peer sees an
//!   ordinary client migration, path-validates it, and resets its own
//!   congestion state for the new path (RFC 9000 section 9.4), which is
//!   what lets a peer whose window is full of undeliverable data start
//!   sending again.
//! - a *ping*: the same rebind call aimed at the socket already
//!   installed, which changes nothing about the path but still queues
//!   the PING, keeping the cadence without churning sockets, ports, and
//!   NAT mappings on every tick.
//!
//! A stall episode opens with the rebind flavor: a stall is evidence
//! against the current path, and the first probe should already carry
//! the recovery that works when the source address is gone.
//!
//! Every session rebinds, the relayed one included, and the prober knows
//! nothing about which kind of path carries one: a rebind on a session
//! under the path manager ([`crate::traversal::TraversalSocket`]) hands
//! quinn a replacement socket wrapped in the same shim, so the session's
//! paths and the virtual peer it addresses survive the move (arranged in
//! [`Prober::fresh_socket`]), and the shim tells the session's path
//! policy ([`crate::upgrade`]) that its mappings moved, re-registering
//! the relay path at once. Without that re-registration the client sends
//! from a mapping the helper has never seen and drops, turning a
//! recoverable stall into a session that never returns.
//!
//! ## Keeping room for the probe
//!
//! The PING is subject to quinn's normal congestion control: quinn-proto
//! refuses to build an ack-eliciting non-loss-probe packet once
//! `in_flight.bytes + segment_size >= cwnd`, charging a full MTU per
//! packet. Nothing is acknowledged during an outage, so a client that
//! keeps writing leaves its own undeliverable data in flight until the
//! window is full, after which every probe is dropped before the socket
//! and recovery falls back to exactly the PTO backoff the prober exists
//! to bypass. At the default window that takes only tens of seconds of
//! ordinary interactive traffic.
//!
//! So declaring a stall also clamps [`quinn::Connection::set_send_window`]
//! to zero: the transport stops accepting new application data, the
//! relay stops reading local input, and the local writer blocks exactly
//! as it would on a stalled TCP socket ([`crate::transport`]), until
//! traffic flows again. What is in flight when the stall is declared
//! stays in flight, leaving a narrow caveat: a connection whose window
//! was *already* full when the path died -- a bulk upload cut off
//! mid-stream -- still cannot probe and stays PTO-bound.
//!
//! # Wake events
//!
//! A [`PathWake`] lets a platform monitor (Linux: [`crate::netlink`])
//! short-circuit stall detection. A wake is evidence about the host's
//! networking, not a command about this connection: the kernel reports
//! every interface on the machine, and RTM_NEWADDR fires for address
//! refreshes (DHCP renewal, SLAAC lifetimes, privacy-address
//! regeneration) as readily as for genuinely new addresses. Acting on
//! each one would give any chatty or flapping source unbounded influence
//! over a healthy session, since every rebind is a migration the peer
//! path-validates and resets its congestion state for.
//!
//! So a wake is acted on only when it proves this connection's path is
//! gone: [`Prober::route_check`] asks the kernel whether it can still
//! route to the peer at all, and a "no" (wifi off, VPN down, cable out)
//! starts probing on the spot. The kernel makes that claim only when it
//! is true, so no amount of wake churn can use it to disturb a working
//! session. Which message the kernel sent is not carried at all,
//! since none of them is evidence by itself. The cross-check is a route
//! lookup rather than a comparison against the connection's own source
//! address, which quinn does not expose on the client side
//! (`quinn_proto::Connection::local_ip` is `None` for clients).
//!
//! Everything else is left to the stall detector, and no probe of any
//! kind runs more often than once per [`ProbeOptions::probe_interval`],
//! so a flapping link or an overflowing netlink socket cannot drive the
//! rebind rate.
//!
//! The server needs none of this: in QUIC only the client may change
//! address, and the server's PTO probes are re-anchored by the
//! client-driven exchange.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::transport::{
  DEFAULT_PROBE_INTERVAL, DEFAULT_STALL_THRESHOLD, DEFAULT_WINDOW,
};
use crate::traversal::{Handable, SharedSocket};

/// A network-change wake from a platform monitor: this host's links or
/// addresses changed somehow. The module docs have what a wake must
/// clear before it costs the session anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathWake;

/// Tunable probing settings. `Default` is the policy documented in
/// [`crate::transport`].
#[derive(Debug, Clone)]
pub struct ProbeOptions {
  /// How long either liveness signal may go unanswered before probing
  /// starts; see the module docs.
  pub stall_threshold: std::time::Duration,
  /// Interval between probes while stalled, and the granularity of
  /// stall detection. Also the minimum interval between wake-driven
  /// probes.
  pub probe_interval: std::time::Duration,
}

impl Default for ProbeOptions {
  fn default() -> Self {
    Self {
      stall_threshold: DEFAULT_STALL_THRESHOLD,
      probe_interval: DEFAULT_PROBE_INTERVAL,
    }
  }
}

/// Counters of the prober's interventions. Zero on a healthy path is a
/// test invariant: the prober must never disturb a working session.
#[derive(Debug, Default)]
pub struct ProbeStats {
  pings: AtomicU64,
  rebinds: AtomicU64,
}

impl ProbeStats {
  /// Ping-flavor probes sent (rebind onto the current socket).
  pub fn pings(&self) -> u64 {
    self.pings.load(Ordering::Relaxed)
  }

  /// Rebind-flavor probes sent (rebind onto a fresh socket).
  pub fn rebinds(&self) -> u64 {
    self.rebinds.load(Ordering::Relaxed)
  }

  /// All probes sent.
  pub fn probes(&self) -> u64 {
    self.pings() + self.rebinds()
  }
}

/// A replacement socket for a rebind probe, and what to do once the
/// endpoint has taken it.
///
/// The two are separate because a rebind can fail to install, and a
/// caller whose socket carries session state must not publish one the
/// endpoint refused: for a session under the path manager
/// ([`crate::traversal::TraversalSocket::adopt`]) that would leave the
/// session's probes -- and the relay registration they carry -- coming
/// from a mapping quinn no longer sends on.
pub struct FreshSocket {
  /// The socket to hand the endpoint.
  pub socket: Arc<dyn Handable>,
  /// Called once, after the endpoint has accepted it. A plain OS socket
  /// has nothing to do here.
  pub adopt: Box<dyn FnOnce() + Send>,
}

impl FreshSocket {
  /// A socket with nothing to publish.
  pub fn plain(socket: impl Handable) -> Self {
    Self {
      socket: Arc::new(socket),
      adopt: Box::new(|| {}),
    }
  }
}

impl std::fmt::Debug for FreshSocket {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("FreshSocket")
      .field("socket", &self.socket)
      .finish_non_exhaustive()
  }
}

/// Source of replacement sockets for rebind probes. Production:
/// [`os_socket_factory`]; tests bind fresh simulated sockets.
pub type SocketFactory = Box<dyn FnMut() -> io::Result<FreshSocket> + Send>;

/// Whether this host can still route to the session's peer, the
/// cross-check that decides whether a wake is about this path.
/// Production: [`os_route_check`]; tests answer for the simulated
/// network.
pub type RouteCheck = Box<dyn Fn() -> bool + Send>;

/// A [`SocketFactory`] binding OS UDP sockets: an unspecified address
/// of the connection's current remote family, so a rebound socket can
/// always reach the (fixed) server address, and the kernel picks the
/// route -- which matters when the old route died.
pub fn os_socket_factory(connection: &quinn::Connection) -> SocketFactory {
  let connection = connection.clone();
  Box::new(move || {
    let ip: IpAddr = match connection.remote_address() {
      SocketAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
      SocketAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    let socket = std::net::UdpSocket::bind(SocketAddr::new(ip, 0))?;
    Ok(FreshSocket::plain(SharedSocket::new(
      crate::traversal::wrap_os_socket(socket, &quinn::TokioRuntime)?,
    )))
  })
}

/// A [`RouteCheck`] that asks the kernel for a route to the connection's
/// peer; see [`os_route_check_to`], which it is the ordinary case of.
///
/// Not for a session under the path manager
/// ([`crate::traversal::TraversalSocket`]): the peer quinn names there is
/// virtual, and asking the kernel to route to it answers about the
/// default route rather than about this session's path.
pub fn os_route_check(connection: &quinn::Connection) -> RouteCheck {
  let connection = connection.clone();
  os_route_check_to(Box::new(move || connection.remote_address()))
}

/// A [`RouteCheck`] that asks the kernel for a route to whatever `peer`
/// names when it is called: `connect(2)` on a wildcard-bound UDP socket
/// resolves the route and picks a source address without sending
/// anything, and answers ENETUNREACH or EHOSTUNREACH when the host has
/// no way to reach it. The claim is one-sided on purpose -- a lingering
/// default route still answers "reachable" -- so the check can only fail
/// to notice a dead path, never invent one.
///
/// The address is asked for per call because a session's path can move
/// under it (see [`crate::traversal`]).
pub fn os_route_check_to(
  peer: Box<dyn Fn() -> SocketAddr + Send>,
) -> RouteCheck {
  Box::new(move || {
    let remote = peer();
    let local: IpAddr = match remote {
      SocketAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
      SocketAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    match std::net::UdpSocket::bind(SocketAddr::new(local, 0))
      .and_then(|socket| socket.connect(remote))
    {
      Ok(()) => true,
      Err(error) => {
        debug!(%error, %remote, "no route to the peer");
        false
      }
    }
  })
}

/// The stall prober; see the module docs. Construct one per client
/// session and drive [`Prober::run`] beside the relay.
pub struct Prober {
  /// The session's connection, watched for traffic and closure.
  pub connection: quinn::Connection,
  /// The endpoint the connection runs on, rebound to probe.
  pub endpoint: quinn::Endpoint,
  /// Where rebind probes get their replacement sockets.
  pub fresh_socket: SocketFactory,
  /// How a wake is cross-checked against this connection's own path.
  pub route_check: RouteCheck,
  /// Platform network-change wakes; `None` runs the portable stall
  /// prober alone.
  pub events: Option<mpsc::UnboundedReceiver<PathWake>>,
  /// The socket the endpoint is running on now, when the caller kept a
  /// handle; a ping probe aims at it until the first rebind.
  pub session_socket: Option<Arc<dyn Handable>>,
  pub options: ProbeOptions,
  /// Intervention counters, shared so the caller can observe them.
  pub stats: Arc<ProbeStats>,
}

impl Prober {
  /// Runs until the connection closes. Cancellation-safe at any await.
  pub async fn run(self) {
    let Self {
      connection,
      endpoint,
      mut fresh_socket,
      route_check,
      mut events,
      session_socket,
      options,
      stats,
    } = self;
    let closed = connection.closed();
    tokio::pin!(closed);

    // The socket most recently installed by a rebind probe, and the
    // target of ping probes: the session's own when the caller kept a
    // handle, and otherwise nothing until a stall episode's opening
    // rebind sets it.
    let mut current: Option<Arc<dyn Handable>> = session_socket;

    let start = connection.stats();
    let mut last_rx = start.udp_rx.datagrams;
    // Transmit count as of the last received datagram: transmissions
    // beyond it are unanswered.
    let mut tx_at_rx = start.udp_tx.datagrams;
    let mut last_acks = start.frame_rx.acks;
    // Ack-eliciting frames sent as of the last ACK frame received:
    // frames beyond it are unacknowledged.
    let mut elicited_at_ack = ack_eliciting(&start);
    // When each signal was first observed outstanding.
    let mut pending_since: Option<Instant> = None;
    let mut unacked_since: Option<Instant> = None;
    let mut probing = false;
    let mut rebind_next = true;
    // The last probe, and the last wake acted on far enough to consult
    // the route: the two minimum intervals a wake has to satisfy.
    let mut last_probe: Option<Instant> = None;
    let mut last_wake: Option<Instant> = None;
    let mut next_tick = Instant::now() + options.probe_interval;

    loop {
      let woken = tokio::select! {
        biased;
        _ = &mut closed => return,
        wake = next_wake(&mut events) => match wake {
          Some(PathWake) => true,
          // The monitor went away; continue on ticks alone.
          None => {
            events = None;
            continue;
          }
        },
        _ = tokio::time::sleep_until(next_tick) => false,
      };

      let now = Instant::now();
      let snapshot = connection.stats();
      if snapshot.udp_rx.datagrams != last_rx {
        last_rx = snapshot.udp_rx.datagrams;
        tx_at_rx = snapshot.udp_tx.datagrams;
        pending_since = None;
      } else if snapshot.udp_tx.datagrams > tx_at_rx && pending_since.is_none()
      {
        pending_since = Some(now);
      }
      let elicited = ack_eliciting(&snapshot);
      if snapshot.frame_rx.acks != last_acks {
        last_acks = snapshot.frame_rx.acks;
        elicited_at_ack = elicited;
        unacked_since = None;
      } else if elicited > elicited_at_ack && unacked_since.is_none() {
        unacked_since = Some(now);
      }
      if probing && pending_since.is_none() && unacked_since.is_none() {
        debug!(
          pings = stats.pings(),
          rebinds = stats.rebinds(),
          "path recovered; probing stops"
        );
        connection.set_send_window(u64::from(DEFAULT_WINDOW));
        probing = false;
      }

      if woken {
        // A wake leads to a probe only by proving the path is gone, at
        // most once per interval (module docs). The minimum interval
        // covers the route check itself, not just the probe it may lead
        // to, so a wake flood cannot turn into a syscall flood.
        let spaced = |at: Option<Instant>| {
          at.is_none_or(|at| now.duration_since(at) >= options.probe_interval)
        };
        if !spaced(last_probe) || !spaced(last_wake) {
          continue;
        }
        last_wake = Some(now);
        if route_check() {
          continue;
        }
        // A ping over a route that no longer exists cannot reach
        // anything; only a replacement socket can.
        rebind_next = true;
        if !probing {
          debug!("no route to the peer; probing starts");
          probing = true;
          connection.set_send_window(0);
        }
      }

      let outstanding_since =
        [pending_since, unacked_since].into_iter().flatten().min();
      if !probing
        && let Some(since) = outstanding_since
        && now.duration_since(since) >= options.stall_threshold
      {
        debug!(
          stalled_for = ?now.duration_since(since),
          "connection stalled; probing starts"
        );
        probing = true;
        // An episode opens with the rebind flavor (module docs).
        rebind_next = true;
        // Keep congestion-window room for the probes (module docs).
        connection.set_send_window(0);
      }
      if probing {
        match &current {
          Some(socket) if !rebind_next => ping(&endpoint, socket, &stats),
          _ => rebind(&endpoint, &mut fresh_socket, &mut current, &stats),
        }
        rebind_next = !rebind_next;
        last_probe = Some(now);
      }
      next_tick = now + options.probe_interval;
      if !probing && let Some(since) = outstanding_since {
        // Fire at the threshold itself rather than the next multiple of
        // the probe interval, so detection costs no rounding.
        next_tick = next_tick.min(since + options.stall_threshold);
      }
    }
  }
}

/// Ack-eliciting frames this connection has sent: the two kinds a live
/// Mush session produces, stream data and the PINGs that keep-alives and
/// probes queue. Deliberately not a count of transmitted packets, which
/// includes the pure ACKs that answer an inbound stream and elicit
/// nothing in return.
fn ack_eliciting(stats: &quinn::ConnectionStats) -> u64 {
  stats.frame_tx.stream + stats.frame_tx.ping
}

async fn next_wake(
  events: &mut Option<mpsc::UnboundedReceiver<PathWake>>,
) -> Option<PathWake> {
  match events {
    Some(receiver) => receiver.recv().await,
    None => std::future::pending().await,
  }
}

/// Rebind probe: a fresh socket, installed live. Failure (no address
/// to bind on, mid-outage) is logged and retried next tick.
fn rebind(
  endpoint: &quinn::Endpoint,
  fresh_socket: &mut SocketFactory,
  current: &mut Option<Arc<dyn Handable>>,
  stats: &ProbeStats,
) {
  let fresh = match fresh_socket() {
    Ok(fresh) => fresh,
    Err(error) => {
      warn!(%error, "binding a fresh socket for a rebind probe failed");
      return;
    }
  };
  let FreshSocket { socket, adopt } = fresh;
  match endpoint.rebind_abstract(socket.hand()) {
    Ok(()) => {
      adopt();
      *current = Some(socket);
      stats.rebinds.fetch_add(1, Ordering::Relaxed);
    }
    Err(error) => warn!(%error, "rebind probe failed"),
  }
}

/// Ping probe: the rebind call aimed at the already-installed socket,
/// which queues an immediate ack-eliciting PING and changes nothing
/// else (see the module docs).
fn ping(
  endpoint: &quinn::Endpoint,
  current: &Arc<dyn Handable>,
  stats: &ProbeStats,
) {
  match endpoint.rebind_abstract(current.hand()) {
    Ok(()) => {
      stats.pings.fetch_add(1, Ordering::Relaxed);
    }
    Err(error) => warn!(%error, "ping probe failed"),
  }
}
