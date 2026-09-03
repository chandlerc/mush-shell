// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The jump helper: traversal assistance on a bastion.
//!
//! The design doc's "The jump helper" and "Security analysis" have what
//! the three services are for and what a compromised helper can and
//! cannot do. Here they are: reflection, answering a binding request
//! with the source address observed; punch rendezvous, reporting every
//! registration and move over the ssh channel as a [`Peer`] line the
//! client orders probing from; and relay of last resort, forwarding
//! non-STUN datagrams verbatim to the session's other peer. All three
//! use the one STUN probe [`crate::stun`] defines, over one UDP socket.
//!
//! The helper is never told anything it could learn from: a relayed
//! datagram is inspected only for the header bit separating probe from
//! payload, and nothing here handshakes or holds a session key.
//!
//! # Security posture
//!
//! This is the one part of Mush that listens to the open internet, so
//! every rule here is stated and tested rather than assumed:
//!
//! - **Nonce checking.** Only nonces delivered over the ssh channel are
//!   served ([`HelperService::admit`]). Anything else is dropped before
//!   it can allocate so much as a rate-limiter entry, so every table
//!   entry traces back to a nonce the jump host's owner authenticated.
//! - **Signed probes.** Naming the session is not enough to move this
//!   table: a probe must also carry `MESSAGE-INTEGRITY-SHA256` over the
//!   session's [`SessionSecret`], which reaches the two peers over ssh
//!   and never over a network. Without it a source address is an
//!   unverified claim, and anyone who saw one probe go past could point
//!   the relay at an address of their choosing, turning the bastion
//!   into an arbitrary-destination UDP forwarder. The check precedes
//!   every table, so a forged probe changes nothing.
//! - **Probes meant for here.** A signature says who wrote a probe, not
//!   who it was for, and the same secret signs a peer's probes at
//!   candidate addresses -- which include addresses this helper named.
//!   So the probe says where it was going ([`crate::stun::Aim`]) inside
//!   what the signature covers, and only [`Aim::Helper`] registers here.
//! - **No replayed registrations.** A captured probe is bytes anyone can
//!   resend, so a transaction already acted on may not *move* a
//!   registration: a retransmission from the address holding the slot is
//!   answered as STUN expects, the same bytes from anywhere else are
//!   dropped. A peer generates a fresh transaction every round, so a
//!   capture reaches no further than its own round.
//! - **Liveness before reach.** The helper only ever sends to an address
//!   it received a signed probe from. No address in a packet body is
//!   believed and payload from an unregistered source is dropped, so the
//!   relay cannot be aimed at a third party.
//! - **No amplification.** A reflection response is refused if it would
//!   be larger than the request ([`crate::stun::BindingRequest::reflect`]),
//!   and the relay is one datagram out per datagram in.
//! - **Rate limits.** Reflection is limited per source address and again
//!   across the service; the relay is limited per session, by a byte
//!   budget that charges each datagram its packet overhead so a flood of
//!   empty datagrams costs what it really uses.
//! - **Bounded tables.** Sessions, peers per session, and rate-limiter
//!   entries are all capped ([`HelperLimits`]), with the least recently
//!   used entry evicted rather than the table growing.
//! - **Bounded lifetime.** The helper self-destructs if no peer arrives
//!   within the bootstrap timeout, exits when the client closes the last
//!   session, gives up on a session that never relayed once the client's
//!   channel is gone, and honors `--retain` ([`HelperService::poll`]).
//!
//! # Chained jumps
//!
//! With `-J a,b` the helper runs on the last hop, the one closest to the
//! destination; [`HelperHop`] is that rule and why.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{debug, trace};

use crate::bootstrap::{SessionNonce, SessionSecret};
use crate::channel::LineChannel;
use crate::path::{earliest, wait_until};
use crate::server::DEFAULT_BOOTSTRAP_TIMEOUT;
use crate::stun::{self, Aim, Datagram, PeerRole};
use crate::wire::{line_message, line_message_enum};

/// Line prefix of the client's instruction to serve a session.
pub const SERVE_PREFIX: &str = "MUSH SERVE";

/// Line prefix of the helper's announcement of itself.
pub const READY_PREFIX: &str = "MUSH READY";

/// Line prefix of a peer registration report.
pub const PEER_PREFIX: &str = "MUSH PEER";

/// Line prefix of the client's instruction to stop serving a session.
pub const CLOSE_PREFIX: &str = "MUSH CLOSE";

/// Bound on the serve line, the one message read before the helper
/// announces itself. It arrives on an exec channel's stdin, written by
/// the Mush client with no shell in between, so like the destination's
/// hello it tolerates no non-protocol output: anything without a newline
/// in this many bytes is not a Mush client.
pub const MAX_SERVE_BYTES: usize = 4096;

/// The receive buffer for the traversal socket: the largest a UDP
/// datagram can be, so relayed payload is never truncated -- which would
/// corrupt a session silently. The policy bounds are the rate limits,
/// not the buffer.
const MAX_DATAGRAM_BYTES: usize = 65535;

/// What each relayed datagram is charged beyond its payload, covering
/// the IPv6 and UDP headers the bastion actually puts on the wire.
/// Without it a flood of empty datagrams would be free.
pub const RELAY_DATAGRAM_OVERHEAD: f64 = 48.0;

/// How many consecutive receive failures end the service. A UDP socket
/// can report a transient error (a queued ICMP report, a momentarily
/// unroutable path) and keep working, so one failure is not fatal; a run
/// of them means the socket is gone and spinning on it is a busy loop.
const MAX_RECV_FAILURES: usize = 16;

/// Client -> helper: serve this session, and sign for it with this
/// secret.
///
/// Both arrive over the jump host's own authenticated ssh channel, and
/// are together the only thing that makes the helper answer anyone: the
/// nonce names the session, the secret is what a probe must prove.
///
/// Wire form: `MUSH SERVE v=1 nonce=<nonce> secret=<secret>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Serve {
  /// Protocol version (`v`).
  pub version: u32,
  /// The session to serve (`nonce`).
  pub nonce: SessionNonce,
  /// The secret the session's probes are signed with (`secret`).
  pub secret: SessionSecret,
}

/// Helper -> client: the traversal socket is up, at this port and these
/// addresses, and this is the address the jump host sees the client at.
///
/// The mirror of the destination's `MUSH CONNECT` line: the address
/// hints lead with the jump's own address as the client reached it over
/// ssh, which is the one address the client demonstrably has a path to.
///
/// [`client_ip`](Self::client_ip) is the design's `echo $SSH_CONNECTION`
/// step, taken from the ssh channel the helper already runs on: the
/// client's public address as the jump observed it, which the
/// destination's reverse punch aims at when reflection is unavailable.
/// Reporting it costs no extra ssh and makes a helper whose UDP cannot
/// be reached degrade like a bastion with no helper on it, not worse.
///
/// Wire form: `MUSH READY v=1 port=<udp port> [client=<ip>]
/// [addr=<ip:port>]...`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
  /// Protocol version (`v`).
  pub version: u32,
  /// The UDP port the helper bound (`port`).
  pub udp_port: u16,
  /// The client's address as this hop observed it (`client`), absent
  /// when the helper's `$SSH_CONNECTION` says nothing usable.
  pub client_ip: Option<IpAddr>,
  /// Addresses the helper can be reached at (`addr`, repeatable).
  pub addr_hints: Vec<SocketAddr>,
}

/// Helper -> client: a peer of `nonce` proved liveness at `addr`.
///
/// The rendezvous report, sent when a peer first registers and whenever
/// it moves, so the client learns each side's reflexive candidate as it
/// appears and a roaming peer's new address at once.
///
/// Wire form: `MUSH PEER v=1 nonce=<nonce> role=<role> addr=<ip:port>`,
/// with the `v=` [`HelperMessage`] describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
  /// The session the peer belongs to (`nonce`).
  pub nonce: SessionNonce,
  /// Which side registered (`role`).
  pub role: PeerRole,
  /// The address the helper observed it at (`addr`).
  pub addr: SocketAddr,
}

/// Client -> helper: this session is over.
///
/// The clean end of a helper's life: with no session left to serve it
/// exits at once, rather than lingering out its retention window.
///
/// Wire form: `MUSH CLOSE v=1 nonce=<nonce>`, with the `v=`
/// [`HelperMessage`] describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Close {
  /// The session that is over (`nonce`).
  pub nonce: SessionNonce,
}

/// Any message on the helper's control channel.
///
/// The channel's version handshake is its opening pair, [`Serve`] and
/// [`Ready`], which keep what they parsed. [`Peer`] and [`Close`] carry
/// `v=` too, from [`crate::bootstrap::PROTOCOL_VERSION`] and
/// required-but-discarded on parse, so their encoders normalize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperMessage {
  /// Serve a session.
  Serve(Serve),
  /// The helper's announcement of itself.
  Ready(Ready),
  /// A peer registration report.
  Peer(Peer),
  /// Stop serving a session.
  Close(Close),
}

line_message! {
  Serve, SERVE_PREFIX {
    version: "v" required,
    nonce: "nonce" required,
    secret: "secret" redacted,
  }
}

line_message! {
  Ready, READY_PREFIX {
    version: "v" required,
    udp_port: "port" required,
    client_ip: "client" optional,
    addr_hints: "addr" repeated,
  }
}

line_message! {
  Peer, PEER_PREFIX, version {
    nonce: "nonce" required,
    role: "role" required,
    addr: "addr" required,
  }
}

line_message! {
  Close, CLOSE_PREFIX, version {
    nonce: "nonce" required,
  }
}

line_message_enum! {
  HelperMessage {
    Serve => SERVE_PREFIX,
    Ready => READY_PREFIX,
    Peer => PEER_PREFIX,
    Close => CLOSE_PREFIX,
  }
}

/// The helper channel's view of the jump host's ssh channel.
pub type HelperChannel<C> = LineChannel<C, HelperMessage>;

/// Where the jump helper runs for an `ssh -J` spec.
///
/// The design's chained-jump rule: with `-J a,b` the helper runs on the
/// last hop, `b`, closest to the destination, reached through the hops
/// in front of it. That is where the helper-to-destination hop is
/// shortest and where
/// jump-to-destination traffic is most likely to be permitted, which is
/// why the relayed path beats the internet-facing candidates at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperHop<'a> {
  /// The hop the helper runs on: the destination of its ssh channel.
  pub host: &'a str,
  /// The hops in front of it, spelled as the `-J` spec that reaches
  /// [`host`](Self::host), or `None` when the helper's hop is the
  /// first one.
  pub via: Option<&'a str>,
}

impl<'a> HelperHop<'a> {
  /// Splits an `ssh -J` spec into the hop the helper runs on and the
  /// jump spec that reaches it.
  ///
  /// `None` for a spec ssh itself would refuse: empty, or with an empty
  /// hop in it.
  pub fn from_jump_spec(spec: &'a str) -> Option<Self> {
    if spec.is_empty() || spec.split(',').any(str::is_empty) {
      return None;
    }
    match spec.rfind(',') {
      Some(last) => Some(Self {
        host: &spec[last + 1..],
        via: Some(&spec[..last]),
      }),
      None => Some(Self {
        host: spec,
        via: None,
      }),
    }
  }
}

/// The service's bounds. `Default` is the shipped policy; construct
/// with struct update syntax to override values.
///
/// Every one of these is an upper bound on what an unauthenticated sender
/// can make the jump host do, not a quality-of-service policy: the
/// defaults are generous enough that a real session never notices them.
#[derive(Debug, Clone, Copy)]
pub struct HelperLimits {
  /// Sessions served at once. One helper serves one client's
  /// establishment, so this bounds a client sending serve lines rather
  /// than a real workload.
  pub max_sessions: usize,
  /// Source addresses tracked for reflection rate limiting. Only
  /// addresses probing for an admitted nonce are ever tracked.
  pub max_probe_sources: usize,
  /// Reflection responses per second to one source address.
  pub probes_per_second: f64,
  /// Burst of reflection responses to one source address.
  pub probe_burst: f64,
  /// Reflection responses per second across every source: the limit
  /// that holds when there are many sources rather than a few busy ones.
  pub service_probes_per_second: f64,
  /// Burst of reflection responses across every source.
  pub service_probe_burst: f64,
  /// Relayed bytes per second for one session, counting each
  /// datagram's packet overhead.
  pub relay_bytes_per_second: f64,
  /// Relayed bytes one session may burst.
  pub relay_burst_bytes: f64,
}

impl Default for HelperLimits {
  fn default() -> Self {
    Self {
      max_sessions: 8,
      max_probe_sources: 256,
      probes_per_second: 10.0,
      probe_burst: 20.0,
      service_probes_per_second: 100.0,
      service_probe_burst: 200.0,
      // 32 MiB/s: far above what an interactive session or a bulk copy
      // through a bastion asks for, low enough that the jump host
      // cannot be turned into somebody's bulk relay.
      relay_bytes_per_second: 32.0 * 1024.0 * 1024.0,
      relay_burst_bytes: 4.0 * 1024.0 * 1024.0,
    }
  }
}

/// Options for [`HelperService::new`].
#[derive(Debug, Clone, Copy)]
pub struct HelperOptions {
  /// The service's bounds.
  pub limits: HelperLimits,
  /// How long to wait for the first peer before self-destructing. The
  /// destination server's give-up window, for the same reason: a helper
  /// nobody came to must not outlive the attempt that started it.
  pub bootstrap_timeout: Duration,
  /// How long the service may sit idle once it has served a peer.
  /// `None` retains indefinitely, mosh-style (the design's default), so
  /// a relayed session survives a long offline period.
  pub retain: Option<Duration>,
}

impl Default for HelperOptions {
  fn default() -> Self {
    Self {
      limits: HelperLimits::default(),
      bootstrap_timeout: DEFAULT_BOOTSTRAP_TIMEOUT,
      retain: None,
    }
  }
}

/// Why a datagram produced nothing. Every variant is one of the module
/// docs' rules refusing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
  /// A probe for a nonce that never arrived over the ssh channel.
  UnknownNonce,
  /// A probe naming a served session without a valid signature over
  /// that session's secret: a forged source address, or a stranger who
  /// saw a nonce go past.
  Unauthenticated,
  /// A binding request with no session label: nothing to check it
  /// against.
  Unlabeled,
  /// A probe aimed at the session's peer rather than the helper: signed,
  /// but for a context this service does not act on.
  Misaimed,
  /// A probe repeating a transaction this service already registered,
  /// from somewhere else: a replay, which must not move a peer.
  Replayed,
  /// STUN, but not a binding request this service answers.
  NotBinding,
  /// This source's reflection budget is spent.
  SourceRateLimited,
  /// The service's overall reflection budget is spent.
  ServiceRateLimited,
  /// The response would have been larger than the request.
  Amplification,
  /// Payload from an address that has proven liveness for no session.
  UnknownSource,
  /// The session's other peer has not registered: nowhere to forward.
  NoPeer,
  /// The session's relay budget is spent.
  RelayBudget,
}

/// A peer arriving, or moving, at an address (design doc: "peer
/// addresses updated on receipt so a roaming client keeps its relay").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registration {
  /// The session it belongs to.
  pub nonce: SessionNonce,
  /// Which side it is.
  pub role: PeerRole,
  /// Where it proved liveness.
  pub addr: SocketAddr,
  /// Where it was before, when this is a move rather than an arrival.
  pub previous: Option<SocketAddr>,
}

impl Registration {
  /// The [`Peer`] line reporting this registration to the client.
  pub fn message(&self) -> HelperMessage {
    HelperMessage::Peer(Peer {
      nonce: self.nonce,
      role: self.role,
      addr: self.addr,
    })
  }
}

/// What one received datagram asks the service to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
  /// Answer the sender with these bytes: a reflection response, plus
  /// the registration it proved when the address is new.
  Reflect {
    /// The response bytes, never longer than the request.
    reply: Vec<u8>,
    /// The peer's arrival or move, when this probe was one.
    registration: Option<Registration>,
  },
  /// Forward the datagram verbatim to the session's other peer.
  Relay {
    /// The peer's current address.
    to: SocketAddr,
  },
  /// Nothing to send.
  Drop(DropReason),
}

/// Why the service stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
  /// No peer arrived within the bootstrap timeout.
  Unused,
  /// The client closed the last session being served.
  SessionsClosed,
  /// Every session went idle past the retention window.
  Retained,
  /// The control channel closed and nothing was ever relayed: the
  /// client is gone and no session here needs preserving.
  Abandoned,
  /// The traversal socket stopped working.
  SocketFailed,
}

/// Whether the service is still serving, and when to look again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
  /// Still serving.
  Serving {
    /// When a timeout would next fire; `None` when nothing is timing
    /// out (indefinite retention with a live session).
    deadline: Option<Instant>,
  },
  /// Done, for this reason.
  Finished(ExitReason),
}

/// The session nonce table was full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("already serving the maximum of {max} sessions")]
pub struct TooManySessions {
  /// The cap that was hit.
  pub max: usize,
}

/// A token bucket over the virtual-or-real tokio clock.
#[derive(Debug)]
struct Bucket {
  tokens: f64,
  rate: f64,
  burst: f64,
  /// When it was last drawn on, which is what makes a table of them
  /// evictable by least recent use.
  last: Instant,
}

impl Bucket {
  fn new(rate: f64, burst: f64, now: Instant) -> Self {
    Self {
      tokens: burst,
      rate,
      burst,
      last: now,
    }
  }

  /// Refills for the time since the last draw and takes `cost` if it is
  /// there.
  fn take(&mut self, now: Instant, cost: f64) -> bool {
    let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
    self.last = self.last.max(now);
    self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
    if self.tokens < cost {
      return false;
    }
    self.tokens -= cost;
    true
  }
}

/// Which of a [`ProbeBudget`]'s two limits refused a draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
  /// The source's own bucket: one address is sending too much.
  Source,
  /// The limit across every source: the sources are many.
  Service,
}

/// Per-source probe budgets under a service-wide limit, with the
/// source table bounded by least-recent-use eviction.
///
/// The two places that limit probe work -- this service's reflection
/// ([`HelperService::handle`]) and a session's own probe handling
/// ([`crate::upgrade`]) -- are the same shape for the same reason. Probe
/// traffic is public: the nonce labeling it travels in the clear, so
/// anyone who has watched one probe can send well-formed ones that fail
/// the signature check. Charging the source bucket before that check
/// bounds the keyed-hash work such a flood can cause, and charging it
/// before the service-wide one keeps a busy address from spending the
/// share the real peer needs; the service-wide bucket bounds the work
/// when there are many sources rather than a few busy ones.
///
/// Evicting the least recently drawn on source hands the evicted one a
/// fresh bucket rather than a starved one, which is why the service-wide
/// bucket is the real limit.
#[derive(Debug)]
pub(crate) struct ProbeBudget {
  sources: HashMap<IpAddr, Bucket>,
  service: Bucket,
  rate: f64,
  burst: f64,
  max_sources: usize,
}

impl ProbeBudget {
  /// A budget admitting `rate` draws per second from one source address
  /// (bursting to `burst`) under a limit across every source.
  pub(crate) fn new(
    now: Instant,
    rate: f64,
    burst: f64,
    service_rate: f64,
    service_burst: f64,
    max_sources: usize,
  ) -> Self {
    Self {
      sources: HashMap::new(),
      service: Bucket::new(service_rate, service_burst, now),
      rate,
      burst,
      max_sources,
    }
  }

  /// Draws one probe's worth of work for `source`, naming the limit
  /// that refused when there is none to be had.
  pub(crate) fn take(
    &mut self,
    now: Instant,
    source: IpAddr,
  ) -> Result<(), Refused> {
    if !self.source(now, source).take(now, 1.0) {
      return Err(Refused::Source);
    }
    match self.service.take(now, 1.0) {
      true => Ok(()),
      false => Err(Refused::Service),
    }
  }

  /// How many source addresses are tracked.
  pub(crate) fn tracked_sources(&self) -> usize {
    self.sources.len()
  }

  /// This source's bucket, evicting the least recently drawn on when the
  /// table is full so the table is a bound rather than a leak.
  fn source(&mut self, now: Instant, source: IpAddr) -> &mut Bucket {
    if !self.sources.contains_key(&source)
      && self.sources.len() >= self.max_sources
      && let Some(oldest) = self
        .sources
        .iter()
        .min_by_key(|(_, bucket)| bucket.last)
        .map(|(&ip, _)| ip)
    {
      self.sources.remove(&oldest);
    }
    self
      .sources
      .entry(source)
      .or_insert_with(|| Bucket::new(self.rate, self.burst, now))
  }
}

/// How many of a peer's most recent probe transactions one session
/// remembers.
///
/// Only enough to tell a retransmission of a live round from a replay of
/// an old one: a peer generates one transaction per round and repeats it
/// while the round is outstanding, so a handful is all the history that
/// can matter. Bounded because the network feeds it.
const REMEMBERED_TRANSACTIONS: usize = 8;

/// One served session: its secret, up to two peers, and the relay
/// between them.
#[derive(Debug)]
struct Session {
  /// What a probe must sign with to act on this session.
  secret: SessionSecret,
  /// Where each peer proved liveness, indexed by [`slot`]: the client's
  /// address and the destination's.
  peers: [Option<SocketAddr>; 2],
  /// The transactions each peer's recent probes carried, oldest first,
  /// so a replay cannot move a peer that has already been placed by the
  /// probe it copies.
  transactions: [Vec<u128>; 2],
  relay: Bucket,
  relayed_bytes: u64,
  last_activity: Instant,
}

impl Session {
  /// Remembers that `role` was registered on `transaction`, forgetting
  /// the oldest round when the history is full.
  fn remember(&mut self, role: PeerRole, transaction: u128) {
    let history = &mut self.transactions[slot(role)];
    if history.contains(&transaction) {
      return;
    }
    if history.len() >= REMEMBERED_TRANSACTIONS {
      history.remove(0);
    }
    history.push(transaction);
  }
}

fn slot(role: PeerRole) -> usize {
  match role {
    PeerRole::Client => 0,
    PeerRole::Destination => 1,
  }
}

/// The helper's three services as one state machine.
///
/// Pure and time-parametric: every entry point takes the current
/// [`Instant`], so the module docs' rules are unit-testable without a
/// socket, a runtime, or a clock. [`serve`] drives it over a real or
/// simulated socket.
#[derive(Debug)]
pub struct HelperService {
  limits: HelperLimits,
  bootstrap_timeout: Duration,
  retain: Option<Duration>,
  sessions: HashMap<SessionNonce, Session>,
  /// Every registered peer address, so relay payload routes on an
  /// exact-address lookup and never on anything the packet claims.
  /// Kept in exact correspondence with the sessions' peer slots.
  registered: HashMap<SocketAddr, (SessionNonce, PeerRole)>,
  probes: ProbeBudget,
  started: Instant,
  last_activity: Instant,
  admitted_ever: bool,
  registered_ever: bool,
  control_closed: Option<Instant>,
}

impl HelperService {
  /// A service with no sessions, started at `now`.
  pub fn new(now: Instant, options: HelperOptions) -> Self {
    Self {
      limits: options.limits,
      bootstrap_timeout: options.bootstrap_timeout,
      retain: options.retain,
      sessions: HashMap::new(),
      registered: HashMap::new(),
      probes: ProbeBudget::new(
        now,
        options.limits.probes_per_second,
        options.limits.probe_burst,
        options.limits.service_probes_per_second,
        options.limits.service_probe_burst,
        options.limits.max_probe_sources,
      ),
      started: now,
      last_activity: now,
      admitted_ever: false,
      registered_ever: false,
      control_closed: None,
    }
  }

  /// Serves `nonce`, signed for with `secret`, which is what the ssh
  /// channel's authority grants. Admitting one already served is a no-op,
  /// so a repeated serve line cannot re-key a live session.
  pub fn admit(
    &mut self,
    now: Instant,
    nonce: SessionNonce,
    secret: SessionSecret,
  ) -> Result<(), TooManySessions> {
    self.admitted_ever = true;
    if self.sessions.contains_key(&nonce) {
      return Ok(());
    }
    if self.sessions.len() >= self.limits.max_sessions {
      return Err(TooManySessions {
        max: self.limits.max_sessions,
      });
    }
    self.sessions.insert(
      nonce,
      Session {
        secret,
        peers: [None, None],
        transactions: [Vec::new(), Vec::new()],
        relay: Bucket::new(
          self.limits.relay_bytes_per_second,
          self.limits.relay_burst_bytes,
          now,
        ),
        relayed_bytes: 0,
        last_activity: now,
      },
    );
    Ok(())
  }

  /// Stops serving `nonce` and forgets its peers. Reports whether it
  /// was being served.
  pub fn close(&mut self, nonce: SessionNonce) -> bool {
    let Some(session) = self.sessions.remove(&nonce) else {
      return false;
    };
    for addr in session.peers.iter().flatten() {
      self.registered.remove(addr);
    }
    true
  }

  /// How many sessions are being served.
  pub fn session_count(&self) -> usize {
    self.sessions.len()
  }

  /// Where a session's peer is registered, if it is.
  pub fn peer_addr(
    &self,
    nonce: SessionNonce,
    role: PeerRole,
  ) -> Option<SocketAddr> {
    self.sessions.get(&nonce)?.peers[slot(role)]
  }

  /// Bytes relayed for a session so far, payload only.
  pub fn relayed_bytes(&self, nonce: SessionNonce) -> u64 {
    self
      .sessions
      .get(&nonce)
      .map_or(0, |session| session.relayed_bytes)
  }

  /// Source addresses currently tracked for reflection rate limiting.
  pub fn tracked_sources(&self) -> usize {
    self.probes.tracked_sources()
  }

  /// Decides what one received datagram gets.
  pub fn handle(
    &mut self,
    now: Instant,
    from: SocketAddr,
    datagram: &[u8],
  ) -> Outcome {
    match stun::classify(datagram) {
      Datagram::Binding(request) => {
        let Some(label) = request.label() else {
          return Outcome::Drop(DropReason::Unlabeled);
        };
        // A probe on its way to the session's peer is signed with the
        // same secret, so what keeps it out here is that it says where
        // it was going.
        if label.aim != Aim::Helper {
          return Outcome::Drop(DropReason::Misaimed);
        }
        // The nonce check precedes every table this could touch, so a
        // sender without an admitted nonce leaves no state behind.
        let Some(session) = self.sessions.get(&label.nonce) else {
          return Outcome::Drop(DropReason::UnknownNonce);
        };
        let secret = session.secret;
        // The rate limit precedes the signature check, bounding the HMAC
        // work an unauthenticated flood can cause by the same budget the
        // reflections draw on. Its own source table is therefore the one
        // an unsigned probe can touch, and holding a bounded entry there
        // is what that bound costs; the signature precedes every other
        // table, so a forged source address changes nothing else.
        if let Err(refused) = self.probes.take(now, from.ip()) {
          return Outcome::Drop(match refused {
            Refused::Source => DropReason::SourceRateLimited,
            Refused::Service => DropReason::ServiceRateLimited,
          });
        }
        if !request.authentic(&secret) {
          return Outcome::Drop(DropReason::Unauthenticated);
        }
        // Signed and for this service, but bytes are copyable: a
        // transaction already registered may not place a peer elsewhere.
        let transaction = request.transaction_id();
        if self.replayed(label.nonce, label.role, transaction, from) {
          debug!(%from, "a probe replayed a transaction that already registered");
          return Outcome::Drop(DropReason::Replayed);
        }
        let Ok(reply) = request.reflect(from, &secret) else {
          return Outcome::Drop(DropReason::Amplification);
        };
        let registration =
          self.register(now, label.nonce, label.role, from, transaction);
        Outcome::Reflect {
          reply,
          registration,
        }
      }
      Datagram::OtherStun => Outcome::Drop(DropReason::NotBinding),
      Datagram::Payload => self.relay(now, from, datagram.len()),
    }
  }

  /// Whether a probe repeats a transaction this service has already
  /// registered on, from an address other than the one it placed.
  ///
  /// A retransmission from the peer holding the slot is what STUN asks
  /// of a lost probe and is answered as usual; the same bytes from
  /// anywhere else replay a round that is over (see the module docs).
  fn replayed(
    &self,
    nonce: SessionNonce,
    role: PeerRole,
    transaction: u128,
    from: SocketAddr,
  ) -> bool {
    self.sessions.get(&nonce).is_some_and(|session| {
      session.transactions[slot(role)].contains(&transaction)
        && session.peers[slot(role)] != Some(from)
    })
  }

  /// Records that `addr` proved liveness for a session's role,
  /// reporting an arrival or a move.
  ///
  /// The address table and the peer slots stay in exact correspondence
  /// throughout, which is what makes relay routing a lookup.
  fn register(
    &mut self,
    now: Instant,
    nonce: SessionNonce,
    role: PeerRole,
    addr: SocketAddr,
    transaction: u128,
  ) -> Option<Registration> {
    if !self.sessions.contains_key(&nonce) {
      return None;
    }
    self.last_activity = now;
    self.registered_ever = true;
    if let Some(session) = self.sessions.get_mut(&nonce) {
      session.last_activity = now;
      session.remember(role, transaction);
      if session.peers[slot(role)] == Some(addr) {
        return None;
      }
    }
    // An address stands for one peer of one session: whoever held it
    // last loses it.
    if let Some((prior_nonce, prior_role)) = self.registered.remove(&addr)
      && let Some(session) = self.sessions.get_mut(&prior_nonce)
    {
      session.peers[slot(prior_role)] = None;
    }
    let session = self.sessions.get_mut(&nonce)?;
    let previous = session.peers[slot(role)].replace(addr);
    if let Some(previous) = previous {
      self.registered.remove(&previous);
    }
    self.registered.insert(addr, (nonce, role));
    Some(Registration {
      nonce,
      role,
      addr,
      previous,
    })
  }

  /// Forwards payload between the two peers of whichever session the
  /// sender registered for.
  ///
  /// The route comes from the address the datagram arrived from and
  /// nothing else: payload is opaque ciphertext carrying no nonce, so a
  /// peer that has moved is unreachable until its next probe
  /// re-registers it. That is both the cost and the benefit of
  /// liveness-before-reach.
  fn relay(&mut self, now: Instant, from: SocketAddr, bytes: usize) -> Outcome {
    let Some(&(nonce, role)) = self.registered.get(&from) else {
      return Outcome::Drop(DropReason::UnknownSource);
    };
    let Some(session) = self.sessions.get_mut(&nonce) else {
      return Outcome::Drop(DropReason::UnknownSource);
    };
    let Some(to) = session.peers[slot(role.peer())] else {
      return Outcome::Drop(DropReason::NoPeer);
    };
    if !session
      .relay
      .take(now, bytes as f64 + RELAY_DATAGRAM_OVERHEAD)
    {
      return Outcome::Drop(DropReason::RelayBudget);
    }
    session.relayed_bytes += bytes as u64;
    session.last_activity = now;
    self.last_activity = now;
    Outcome::Relay { to }
  }

  /// Records that the client's control channel closed without a
  /// `MUSH CLOSE`, which is what an abandoned helper looks like: the
  /// client was SIGKILLed, crashed, or lost its path to the bastion.
  /// Repeats keep the first instant.
  pub fn control_closed(&mut self, now: Instant) {
    self.control_closed.get_or_insert(now);
  }

  /// Whether the service should still be running, and when its next
  /// timeout falls.
  ///
  /// Only work counts as activity against the retention window -- a peer
  /// registering or moving, payload relayed -- so datagrams the rules
  /// above refuse cannot keep a helper alive.
  ///
  /// Indefinite retention is scoped to what the design asks it for:
  /// "so relayed sessions survive long offline periods too". While the
  /// client holds its control channel that is unconditional. Once the
  /// channel is gone -- the client crashed, or roamed off the address
  /// its ssh ran on -- what keeps the helper is the session proving it
  /// is still there: the destination heartbeats the relay while it is a
  /// path the session may need and something is still arriving from the
  /// client ([`crate::upgrade`]). Silence past the bootstrap timeout
  /// means the session is over with nobody left to say so; without that
  /// bound every roaming relayed session would hold a process and a UDP
  /// port on a shared bastion for good, and a heartbeat that outlived
  /// its own client would hold one in spite of the bound.
  pub fn poll(&self, now: Instant) -> Lifecycle {
    if self.admitted_ever && self.sessions.is_empty() {
      return Lifecycle::Finished(ExitReason::SessionsClosed);
    }
    if !self.registered_ever {
      let deadline = self.started + self.bootstrap_timeout;
      if now >= deadline {
        return Lifecycle::Finished(ExitReason::Unused);
      }
      return Lifecycle::Serving {
        deadline: Some(deadline),
      };
    }
    let abandoned = self.abandoned_deadline();
    let retained = self.retain.map(|retain| self.last_activity + retain);
    let Some(deadline) = earliest(abandoned, retained) else {
      return Lifecycle::Serving { deadline: None };
    };
    if now >= deadline {
      return Lifecycle::Finished(match Some(deadline) == abandoned {
        true => ExitReason::Abandoned,
        false => ExitReason::Retained,
      });
    }
    Lifecycle::Serving {
      deadline: Some(deadline),
    }
  }

  /// When an abandoned helper gives up: with the control channel closed
  /// and nothing proving a session is still there, the last thing that
  /// happened plus the bootstrap timeout is the whole remaining life.
  fn abandoned_deadline(&self) -> Option<Instant> {
    let closed = self.control_closed?;
    Some(closed.max(self.last_activity) + self.bootstrap_timeout)
  }
}

/// The datagram socket the helper serves on.
///
/// Production is a `tokio::net::UdpSocket`; the deterministic simulator
/// hosts the same loop, which is why `mush-netsim`'s `SimSocket` exposes
/// a plain `send_to`/`recv_from` pair alongside its quinn
/// `AsyncUdpSocket`.
///
/// Implementations must make `recv_from` cancel-safe: [`serve`] selects
/// on it against the retention timer, and a receive that consumed a
/// datagram it did not return would lose it.
pub trait ProbeSocket {
  /// Receives one datagram, returning its length and source address.
  fn recv_from(
    &self,
    buf: &mut [u8],
  ) -> impl Future<Output = io::Result<(usize, SocketAddr)>>;

  /// Sends one datagram.
  fn send_to(
    &self,
    datagram: &[u8],
    to: SocketAddr,
  ) -> impl Future<Output = io::Result<()>>;
}

impl ProbeSocket for tokio::net::UdpSocket {
  async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    Self::recv_from(self, buf).await
  }

  async fn send_to(&self, datagram: &[u8], to: SocketAddr) -> io::Result<()> {
    Self::send_to(self, datagram, to).await.map(|_| ())
  }
}

/// What the ssh channel asks of a running service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
  /// Serve this session, signed for with this secret (a `MUSH SERVE`
  /// line).
  Serve {
    /// The session to serve.
    nonce: SessionNonce,
    /// What its probes are signed with.
    secret: SessionSecret,
  },
  /// Stop serving it (a `MUSH CLOSE` line).
  Close(SessionNonce),
}

/// Runs the helper's datagram handling until the service is finished.
///
/// Drives `service` over `socket`: probes answered, payload forwarded,
/// every registration reported on `registrations` for the ssh channel to
/// carry back as a [`Peer`] line. The lifecycle is the service's own
/// ([`HelperService::poll`]).
pub async fn serve<S: ProbeSocket>(
  socket: &S,
  service: &mut HelperService,
  control: &mut mpsc::Receiver<Control>,
  registrations: &mpsc::Sender<Registration>,
) -> ExitReason {
  let mut buf = vec![0u8; MAX_DATAGRAM_BYTES];
  let mut failures = 0usize;
  // The control channel ends when the client hangs up, but a session in
  // flight does not: relayed sessions outlive the channel that set them
  // up (design doc, "The jump helper"), so serving continues with the
  // branch disabled -- left enabled it would spin, a closed channel
  // being always ready. What the closure costs a session is in
  // [`HelperService::poll`].
  let mut controlled = true;
  loop {
    let deadline = match service.poll(Instant::now()) {
      Lifecycle::Finished(reason) => return reason,
      Lifecycle::Serving { deadline } => deadline,
    };
    let received = tokio::select! {
      biased;
      command = control.recv(), if controlled => {
        match command {
          Some(Control::Serve { nonce, secret }) => {
            if let Err(error) = service.admit(Instant::now(), nonce, secret) {
              debug!(%nonce, %error, "refusing to serve another session");
            }
          }
          Some(Control::Close(nonce)) => {
            // Never inside the tracing field: a disabled subscriber
            // does not evaluate one, and the close would not happen.
            let served = service.close(nonce);
            debug!(%nonce, served, "session closed");
          }
          None => {
            debug!("helper control channel closed; serving on");
            service.control_closed(Instant::now());
            controlled = false;
          }
        }
        continue;
      }
      result = socket.recv_from(&mut buf) => result,
      () = wait_until(deadline) => continue,
    };
    let (len, from) = match received {
      Ok(received) => {
        failures = 0;
        received
      }
      Err(error) => {
        failures += 1;
        debug!(%error, failures, "traversal socket receive failed");
        if failures >= MAX_RECV_FAILURES {
          return ExitReason::SocketFailed;
        }
        continue;
      }
    };
    match service.handle(Instant::now(), from, &buf[..len]) {
      Outcome::Reflect {
        reply,
        registration,
      } => {
        if let Err(error) = socket.send_to(&reply, from).await {
          debug!(%from, %error, "reflection response failed");
        }
        if let Some(registration) = registration {
          trace!(?registration, "peer registered");
          // A client that stopped reading its channel loses the
          // reports, never the service.
          let _ = registrations.try_send(registration);
        }
      }
      Outcome::Relay { to } => {
        if let Err(error) = socket.send_to(&buf[..len], to).await {
          debug!(%to, %error, "relay forward failed");
        }
      }
      Outcome::Drop(reason) => trace!(%from, ?reason, "datagram dropped"),
    }
  }
}

#[cfg(test)]
mod tests {
  use std::net::Ipv4Addr;

  use super::*;
  use crate::bootstrap::{PROTOCOL_VERSION, ParseError};
  use crate::stun::{BindingTransaction, ProbeLabel};

  fn nonce(seed: u8) -> SessionNonce {
    SessionNonce::from_bytes([seed; 16])
  }

  /// One secret per nonce, so a probe for a session is signed with that
  /// session's secret and nothing else.
  fn secret(seed: u8) -> SessionSecret {
    SessionSecret::from_bytes([seed ^ 0xa5; 16])
  }

  fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
  }

  fn probe(seed: u8, role: PeerRole) -> BindingTransaction {
    BindingTransaction::new(
      ProbeLabel::to_helper(nonce(seed), role),
      &secret(seed),
    )
  }

  /// A service serving one session, with the clock it was started at.
  fn service(options: HelperOptions) -> (HelperService, Instant) {
    let now = Instant::now();
    let mut service = HelperService::new(now, options);
    service.admit(now, nonce(1), secret(1)).unwrap();
    (service, now)
  }

  /// Registers `role` at `from`, asserting the probe was answered.
  fn register(
    service: &mut HelperService,
    now: Instant,
    role: PeerRole,
    from: SocketAddr,
  ) -> Option<Registration> {
    let probe = probe(1, role);
    match service.handle(now, from, probe.request()) {
      Outcome::Reflect {
        reply,
        registration,
      } => {
        assert_eq!(probe.reflexive(&reply), Some(from));
        registration
      }
      other => panic!("probe was not reflected: {other:?}"),
    }
  }

  #[tokio::test(start_paused = true)]
  async fn a_probe_is_reflected_and_registers_its_peer() {
    let (mut service, now) = service(HelperOptions::default());
    let client = addr("192.0.2.7:41000");
    let registration = register(&mut service, now, PeerRole::Client, client);
    assert_eq!(
      registration,
      Some(Registration {
        nonce: nonce(1),
        role: PeerRole::Client,
        addr: client,
        previous: None,
      })
    );
    assert_eq!(service.peer_addr(nonce(1), PeerRole::Client), Some(client));
    // A repeat from the same address is answered but registers nothing
    // new.
    assert_eq!(register(&mut service, now, PeerRole::Client, client), None);
  }

  /// The check the whole service depends on: a nonce that never came over
  /// the ssh channel leaves nothing behind, not even a rate-limiter
  /// entry.
  #[tokio::test(start_paused = true)]
  async fn only_nonces_from_the_ssh_channel_are_served() {
    let (mut service, now) = service(HelperOptions::default());
    let stranger = probe(9, PeerRole::Client);
    let from = addr("198.51.100.4:5000");
    assert_eq!(
      service.handle(now, from, stranger.request()),
      Outcome::Drop(DropReason::UnknownNonce)
    );
    assert_eq!(service.tracked_sources(), 0);
    assert_eq!(service.peer_addr(nonce(9), PeerRole::Client), None);

    // Closing the served session revokes it just as plainly.
    assert!(service.close(nonce(1)));
    let served = probe(1, PeerRole::Client);
    assert_eq!(
      service.handle(now, from, served.request()),
      Outcome::Drop(DropReason::UnknownNonce)
    );
    assert!(!service.close(nonce(1)));
  }

  /// A binding request with no label belongs to no session either.
  #[tokio::test(start_paused = true)]
  async fn an_unlabeled_probe_is_dropped() {
    let (mut service, now) = service(HelperOptions::default());
    let bare = stun_types::message::Message::builder_request(
      stun_types::message::BINDING,
      stun_types::message::MessageWriteVec::new(),
    );
    let bare = stun_types::prelude::MessageWrite::finish(bare);
    assert_eq!(
      service.handle(now, addr("192.0.2.7:1"), &bare),
      Outcome::Drop(DropReason::Unlabeled)
    );
    assert_eq!(service.tracked_sources(), 0);
  }

  #[tokio::test(start_paused = true)]
  async fn payload_relays_between_the_two_peers() {
    let (mut service, now) = service(HelperOptions::default());
    let client = addr("192.0.2.7:41000");
    let dest = addr("203.0.113.9:60001");
    register(&mut service, now, PeerRole::Client, client);
    // Before the destination arrives there is nowhere to forward to.
    assert_eq!(
      service.handle(now, client, b"ciphertext"),
      Outcome::Drop(DropReason::NoPeer)
    );
    register(&mut service, now, PeerRole::Destination, dest);
    assert_eq!(
      service.handle(now, client, b"ciphertext"),
      Outcome::Relay { to: dest }
    );
    assert_eq!(
      service.handle(now, dest, b"answer"),
      Outcome::Relay { to: client }
    );
    assert_eq!(service.relayed_bytes(nonce(1)), 16);
  }

  /// The relay never carries anything from an address that has not
  /// proven liveness for the session.
  #[tokio::test(start_paused = true)]
  async fn payload_from_an_unregistered_source_is_dropped() {
    let (mut service, now) = service(HelperOptions::default());
    let client = addr("192.0.2.7:41000");
    let dest = addr("203.0.113.9:60001");
    register(&mut service, now, PeerRole::Client, client);
    register(&mut service, now, PeerRole::Destination, dest);
    for stranger in ["198.51.100.4:5000", "192.0.2.7:41001"] {
      assert_eq!(
        service.handle(now, addr(stranger), b"ciphertext"),
        Outcome::Drop(DropReason::UnknownSource)
      );
    }
  }

  /// Knowing a session's nonce achieves nothing on its own.
  ///
  /// The nonce travels in cleartext in every probe's `USERNAME`, so any
  /// on-path observer has one. Without the secret a probe claiming a
  /// served session registers nothing, which is what keeps the relay
  /// from being aimed at a third party.
  #[tokio::test(start_paused = true)]
  async fn a_probe_without_the_secret_registers_nothing() {
    let (mut service, now) = service(HelperOptions::default());
    let client = addr("192.0.2.7:41000");
    let dest = addr("203.0.113.9:60001");
    register(&mut service, now, PeerRole::Client, client);
    register(&mut service, now, PeerRole::Destination, dest);

    // An attacker who has seen a probe knows the label and forges the
    // rest: the source address of a victim it wants the relay aimed at,
    // and a signature it cannot produce.
    let victim = addr("10.0.0.53:53");
    let guessed = BindingTransaction::new(
      ProbeLabel::to_helper(nonce(1), PeerRole::Destination),
      &SessionSecret::from_bytes([0xff; 16]),
    );
    assert_eq!(
      service.handle(now, victim, guessed.request()),
      Outcome::Drop(DropReason::Unauthenticated)
    );
    // An unsigned probe carrying the same label fares no better.
    let mut bare = stun_types::message::Message::builder_request(
      stun_types::message::BINDING,
      stun_types::message::MessageWriteVec::new(),
    );
    let username = stun_types::attribute::Username::new(
      &ProbeLabel::to_helper(nonce(1), PeerRole::Destination).to_string(),
    )
    .unwrap();
    stun_types::prelude::MessageWriteExt::add_attribute(&mut bare, &username)
      .unwrap();
    let bare = stun_types::prelude::MessageWrite::finish(bare);
    assert_eq!(
      service.handle(now, victim, &bare),
      Outcome::Drop(DropReason::Unauthenticated)
    );

    // The table is exactly as it was: the real destination still holds
    // its slot, and nothing will be forwarded to the victim.
    assert_eq!(
      service.peer_addr(nonce(1), PeerRole::Destination),
      Some(dest)
    );
    assert_eq!(
      service.handle(now, client, b"ciphertext"),
      Outcome::Relay { to: dest }
    );
    // Nor can the forger inject payload of its own.
    assert_eq!(
      service.handle(now, victim, b"\x40attacker payload"),
      Outcome::Drop(DropReason::UnknownSource)
    );
  }

  /// The relay's own registration is signed too, so a peer that really
  /// holds the secret still moves only its own slot.
  #[tokio::test(start_paused = true)]
  async fn a_probe_signed_for_another_session_is_not_this_ones() {
    let (mut service, now) = service(HelperOptions::default());
    service.admit(now, nonce(2), secret(2)).unwrap();
    let from = addr("192.0.2.7:41000");
    // Session 2's secret against session 1's label: the label decides
    // which secret is checked, so this is simply unauthenticated.
    let crossed = BindingTransaction::new(
      ProbeLabel::to_helper(nonce(1), PeerRole::Client),
      &secret(2),
    );
    assert_eq!(
      service.handle(now, from, crossed.request()),
      Outcome::Drop(DropReason::Unauthenticated)
    );
    assert_eq!(service.peer_addr(nonce(1), PeerRole::Client), None);
  }

  /// A signature says who wrote a probe, not who it was for, and a
  /// peer's punch probes go to candidate addresses -- which can include
  /// an address this very helper named. Replaying one here registers
  /// nothing.
  #[tokio::test(start_paused = true)]
  async fn a_probe_aimed_at_the_peer_registers_nothing_here() {
    let (mut service, now) = service(HelperOptions::default());
    let client = addr("192.0.2.7:41000");
    let dest = addr("203.0.113.9:60001");
    register(&mut service, now, PeerRole::Client, client);
    register(&mut service, now, PeerRole::Destination, dest);

    // Genuinely signed by the destination, and genuinely not for here.
    let at_peer = BindingTransaction::new(
      ProbeLabel::to_peer(nonce(1), PeerRole::Destination),
      &secret(1),
    );
    let attacker = addr("10.0.0.53:53");
    assert_eq!(
      service.handle(now, attacker, at_peer.request()),
      Outcome::Drop(DropReason::Misaimed)
    );
    assert_eq!(
      service.peer_addr(nonce(1), PeerRole::Destination),
      Some(dest)
    );
    assert_eq!(
      service.handle(now, client, b"ciphertext"),
      Outcome::Relay { to: dest }
    );
  }

  /// A probe is copyable bytes, so the transaction it carries may
  /// register once and no more: the peer holding the slot may repeat it
  /// as loss requires, the same bytes from anywhere else move nothing.
  #[tokio::test(start_paused = true)]
  async fn a_replayed_probe_cannot_steal_a_registration() {
    let (mut service, now) = service(HelperOptions::default());
    let client = addr("192.0.2.7:41000");
    let dest = addr("203.0.113.9:60001");
    let round = probe(1, PeerRole::Client);
    assert!(matches!(
      service.handle(now, client, round.request()),
      Outcome::Reflect { .. }
    ));
    register(&mut service, now, PeerRole::Destination, dest);

    // The eavesdropper resends the very bytes it watched go past.
    let attacker = addr("10.0.0.53:53");
    assert_eq!(
      service.handle(now, attacker, round.request()),
      Outcome::Drop(DropReason::Replayed)
    );
    assert_eq!(service.peer_addr(nonce(1), PeerRole::Client), Some(client));
    assert_eq!(
      service.handle(now, dest, b"answer"),
      Outcome::Relay { to: client }
    );
    // The client's own retransmission of the same round is what STUN
    // asks of a lost probe, and is answered as usual.
    assert!(matches!(
      service.handle(now, client, round.request()),
      Outcome::Reflect { .. }
    ));

    // And the history is bounded: rounds past the last few are
    // forgotten, which costs nothing because a peer never returns to
    // one.
    for _ in 0..REMEMBERED_TRANSACTIONS * 2 {
      let later = probe(1, PeerRole::Client);
      assert!(matches!(
        service.handle(now, client, later.request()),
        Outcome::Reflect { .. }
      ));
    }
    let last = probe(1, PeerRole::Client);
    assert!(matches!(
      service.handle(now, client, last.request()),
      Outcome::Reflect { .. }
    ));
    assert_eq!(
      service.handle(now, attacker, last.request()),
      Outcome::Drop(DropReason::Replayed)
    );
    assert_eq!(service.peer_addr(nonce(1), PeerRole::Client), Some(client));
  }

  /// A roaming peer's next probe moves its slot, and the relay follows
  /// it there while the address it left stops being served.
  #[tokio::test(start_paused = true)]
  async fn a_roaming_peer_moves_its_relay_with_it() {
    let (mut service, now) = service(HelperOptions::default());
    let old = addr("192.0.2.7:41000");
    let new = addr("192.0.2.8:52000");
    let dest = addr("203.0.113.9:60001");
    register(&mut service, now, PeerRole::Client, old);
    register(&mut service, now, PeerRole::Destination, dest);
    assert_eq!(
      service.handle(now, dest, b"before"),
      Outcome::Relay { to: old }
    );

    let later = now + Duration::from_secs(30);
    assert_eq!(
      register(&mut service, later, PeerRole::Client, new),
      Some(Registration {
        nonce: nonce(1),
        role: PeerRole::Client,
        addr: new,
        previous: Some(old),
      })
    );
    assert_eq!(
      service.handle(later, dest, b"after"),
      Outcome::Relay { to: new }
    );
    assert_eq!(service.peer_addr(nonce(1), PeerRole::Client), Some(new));
    // The address it left keeps nothing: no route out, and no way in.
    assert_eq!(
      service.handle(later, old, b"stale"),
      Outcome::Drop(DropReason::UnknownSource)
    );
  }

  /// One address stands for one peer of one session, so the address
  /// table and the peer slots can never disagree about where a datagram
  /// goes -- across roles and across sessions alike.
  #[tokio::test(start_paused = true)]
  async fn an_address_claimed_twice_belongs_to_its_last_claim() {
    let (mut service, now) = service(HelperOptions::default());
    service.admit(now, nonce(2), secret(2)).unwrap();
    let shared = addr("192.0.2.7:41000");
    let dest = addr("203.0.113.9:60001");
    register(&mut service, now, PeerRole::Client, shared);
    register(&mut service, now, PeerRole::Destination, dest);

    // The same address claims the other role of the same session: it
    // moves, and the slot it left is empty rather than stale.
    let stolen =
      service.handle(now, shared, probe(1, PeerRole::Destination).request());
    assert!(matches!(stolen, Outcome::Reflect { .. }));
    assert_eq!(service.peer_addr(nonce(1), PeerRole::Client), None);
    assert_eq!(
      service.peer_addr(nonce(1), PeerRole::Destination),
      Some(shared)
    );
    assert_eq!(
      service.handle(now, shared, b"ciphertext"),
      Outcome::Drop(DropReason::NoPeer)
    );
    // The address it displaced keeps nothing either.
    assert_eq!(
      service.handle(now, dest, b"ciphertext"),
      Outcome::Drop(DropReason::UnknownSource)
    );

    // And across sessions: the second session takes the address, and
    // the first is left with no peer at it.
    let probe = BindingTransaction::new(
      ProbeLabel::to_helper(nonce(2), PeerRole::Client),
      &secret(2),
    );
    assert!(matches!(
      service.handle(now, shared, probe.request()),
      Outcome::Reflect { .. }
    ));
    assert_eq!(service.peer_addr(nonce(1), PeerRole::Destination), None);
    assert_eq!(service.peer_addr(nonce(2), PeerRole::Client), Some(shared));
  }

  #[tokio::test(start_paused = true)]
  async fn reflection_is_rate_limited_per_source() {
    let limits = HelperLimits {
      probes_per_second: 1.0,
      probe_burst: 3.0,
      ..HelperLimits::default()
    };
    let (mut service, now) = service(HelperOptions {
      limits,
      ..HelperOptions::default()
    });
    let from = addr("192.0.2.7:41000");
    let mine = probe(1, PeerRole::Client);
    for _ in 0..3 {
      assert!(matches!(
        service.handle(now, from, mine.request()),
        Outcome::Reflect { .. }
      ));
    }
    assert_eq!(
      service.handle(now, from, mine.request()),
      Outcome::Drop(DropReason::SourceRateLimited)
    );
    // Another source has its own budget, and the refill is real. Its
    // own probe, too: one address repeating another's transaction is a
    // replay, and refused by a later check.
    assert!(matches!(
      service.handle(
        now,
        addr("198.51.100.4:5000"),
        probe(1, PeerRole::Client).request()
      ),
      Outcome::Reflect { .. }
    ));
    assert!(matches!(
      service.handle(
        now + Duration::from_secs(1),
        from,
        probe(1, PeerRole::Client).request()
      ),
      Outcome::Reflect { .. }
    ));
  }

  /// The per-source limit alone would let many sources add up, so the
  /// service has a limit of its own.
  #[tokio::test(start_paused = true)]
  async fn reflection_is_rate_limited_across_sources() {
    let limits = HelperLimits {
      service_probes_per_second: 1.0,
      service_probe_burst: 4.0,
      ..HelperLimits::default()
    };
    let (mut service, now) = service(HelperOptions {
      limits,
      ..HelperOptions::default()
    });
    let source =
      |i: u8| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, i)), 5000);
    for i in 0..4 {
      assert!(matches!(
        service.handle(now, source(i), probe(1, PeerRole::Client).request()),
        Outcome::Reflect { .. }
      ));
    }
    assert_eq!(
      service.handle(now, source(9), probe(1, PeerRole::Client).request()),
      Outcome::Drop(DropReason::ServiceRateLimited)
    );
  }

  /// Which source makes room when the table is full: the one that has
  /// gone longest without drawing, not the oldest entry. A source that
  /// is still probing keeps the bucket it has spent, so a flood of new
  /// addresses cannot gain a fresh budget by evicting one.
  #[tokio::test(start_paused = true)]
  async fn a_probe_budget_evicts_the_least_recently_drawn_on_source() {
    let now = Instant::now();
    // No refill, so what a source has left is what it has drawn.
    let mut budget = ProbeBudget::new(now, 0.0, 2.0, 100.0, 200.0, 2);
    let ip = |n: u8| IpAddr::V4(Ipv4Addr::new(192, 0, 2, n));
    assert_eq!(budget.take(now, ip(1)), Ok(()));
    assert_eq!(budget.take(now, ip(1)), Ok(()));
    let later = now + Duration::from_secs(1);
    assert_eq!(budget.take(later, ip(2)), Ok(()));

    // The table is full, and the source that drew least recently is the
    // one it drops.
    assert_eq!(budget.take(later, ip(3)), Ok(()));
    assert_eq!(budget.tracked_sources(), 2);
    // The source still tracked kept its spent bucket rather than a fresh
    // one.
    assert_eq!(budget.take(later, ip(2)), Ok(()));
    assert_eq!(budget.take(later, ip(2)), Err(Refused::Source));
    // The evicted one comes back to a bucket it has not spent.
    assert_eq!(budget.take(later, ip(1)), Ok(()));
  }

  /// The rate-limiter table is a bound, not a leak: it stops at its cap.
  #[tokio::test(start_paused = true)]
  async fn the_source_table_is_bounded_and_evicts_the_oldest() {
    let limits = HelperLimits {
      max_probe_sources: 4,
      ..HelperLimits::default()
    };
    let (mut service, now) = service(HelperOptions {
      limits,
      ..HelperOptions::default()
    });
    let source =
      |i: u8| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, i)), 5000);
    let probe = || probe(1, PeerRole::Client);
    for i in 0..4 {
      let at = now + Duration::from_millis(u64::from(i));
      service.handle(at, source(i), probe().request());
    }
    assert_eq!(service.tracked_sources(), 4);
    // Keep the oldest fresh, then add a new source: the eviction takes
    // whichever has gone longest without a probe, not the oldest entry.
    let later = now + Duration::from_secs(1);
    service.handle(later, source(0), probe().request());
    service.handle(later, source(9), probe().request());
    assert_eq!(service.tracked_sources(), 4);
    for i in 20..64 {
      service.handle(later, source(i), probe().request());
      assert!(service.tracked_sources() <= 4);
    }
  }

  #[tokio::test(start_paused = true)]
  async fn the_relay_budget_bounds_a_session() {
    let limits = HelperLimits {
      relay_bytes_per_second: 1000.0,
      relay_burst_bytes: 1000.0,
      ..HelperLimits::default()
    };
    let (mut service, now) = service(HelperOptions {
      limits,
      ..HelperOptions::default()
    });
    let client = addr("192.0.2.7:41000");
    let dest = addr("203.0.113.9:60001");
    register(&mut service, now, PeerRole::Client, client);
    register(&mut service, now, PeerRole::Destination, dest);

    // A QUIC short-header packet, which is what relay payload is.
    let payload = [0x40u8; 200];
    // 200 + 48 bytes of packet overhead each: four fit in the burst.
    for _ in 0..4 {
      assert_eq!(
        service.handle(now, client, &payload),
        Outcome::Relay { to: dest }
      );
    }
    assert_eq!(
      service.handle(now, client, &payload),
      Outcome::Drop(DropReason::RelayBudget)
    );
    // Empty datagrams are charged their packet overhead, so a flood of
    // them is bounded like any other.
    assert_eq!(
      service.handle(now, client, b""),
      Outcome::Drop(DropReason::RelayBudget)
    );
    assert_eq!(
      service.handle(now + Duration::from_secs(1), client, &payload),
      Outcome::Relay { to: dest }
    );
  }

  #[tokio::test(start_paused = true)]
  async fn the_session_table_is_bounded() {
    let limits = HelperLimits {
      max_sessions: 2,
      ..HelperLimits::default()
    };
    let now = Instant::now();
    let mut service = HelperService::new(
      now,
      HelperOptions {
        limits,
        ..HelperOptions::default()
      },
    );
    service.admit(now, nonce(1), secret(1)).unwrap();
    service.admit(now, nonce(2), secret(2)).unwrap();
    // A repeat is not a new session.
    service.admit(now, nonce(1), secret(1)).unwrap();
    assert_eq!(
      service.admit(now, nonce(3), secret(3)),
      Err(TooManySessions { max: 2 })
    );
    assert_eq!(service.session_count(), 2);
    assert!(service.close(nonce(1)));
    service.admit(now, nonce(3), secret(3)).unwrap();
  }

  #[tokio::test(start_paused = true)]
  async fn an_unused_helper_self_destructs() {
    let bootstrap_timeout = Duration::from_secs(60);
    let (mut service, now) = service(HelperOptions {
      bootstrap_timeout,
      ..HelperOptions::default()
    });
    assert_eq!(
      service.poll(now),
      Lifecycle::Serving {
        deadline: Some(now + bootstrap_timeout)
      }
    );
    assert_eq!(
      service.poll(now + bootstrap_timeout),
      Lifecycle::Finished(ExitReason::Unused)
    );
    // One peer is enough to make it a session worth keeping.
    register(&mut service, now, PeerRole::Client, addr("192.0.2.7:41000"));
    assert_eq!(
      service.poll(now + bootstrap_timeout),
      Lifecycle::Serving { deadline: None }
    );
  }

  #[tokio::test(start_paused = true)]
  async fn retention_bounds_an_idle_helper_only_when_asked() {
    let retain = Duration::from_secs(600);
    let (mut service, now) = service(HelperOptions {
      retain: Some(retain),
      ..HelperOptions::default()
    });
    let client = addr("192.0.2.7:41000");
    let dest = addr("203.0.113.9:60001");
    register(&mut service, now, PeerRole::Client, client);
    register(&mut service, now, PeerRole::Destination, dest);
    assert_eq!(
      service.poll(now + retain - Duration::from_secs(1)),
      Lifecycle::Serving {
        deadline: Some(now + retain)
      }
    );
    // Traffic extends the timeout; silence past it ends the helper.
    let busy = now + Duration::from_secs(300);
    assert_eq!(
      service.handle(busy, client, b"ciphertext"),
      Outcome::Relay { to: dest }
    );
    assert_eq!(
      service.poll(now + retain),
      Lifecycle::Serving {
        deadline: Some(busy + retain)
      }
    );
    assert_eq!(
      service.poll(busy + retain),
      Lifecycle::Finished(ExitReason::Retained)
    );
  }

  /// Indefinite retention is for relayed sessions. A client that
  /// vanished without a `MUSH CLOSE` leaves a helper whose session went
  /// direct or punched, and that one must not hold a process and a UDP
  /// port on a shared bastion for good.
  #[tokio::test(start_paused = true)]
  async fn an_abandoned_helper_gives_up_when_nothing_relayed() {
    let bootstrap_timeout = Duration::from_secs(60);
    let (mut service, now) = service(HelperOptions {
      bootstrap_timeout,
      ..HelperOptions::default()
    });
    let client = addr("192.0.2.7:41000");
    let dest = addr("203.0.113.9:60001");
    register(&mut service, now, PeerRole::Client, client);
    register(&mut service, now, PeerRole::Destination, dest);
    // With the client still on the channel, retention is indefinite.
    assert_eq!(
      service.poll(now + bootstrap_timeout),
      Lifecycle::Serving { deadline: None }
    );

    let gone = now + Duration::from_secs(5);
    service.control_closed(gone);
    assert_eq!(
      service.poll(gone),
      Lifecycle::Serving {
        deadline: Some(gone + bootstrap_timeout)
      }
    );
    assert_eq!(
      service.poll(gone + bootstrap_timeout),
      Lifecycle::Finished(ExitReason::Abandoned)
    );
  }

  /// The session indefinite retention exists for: one whose peers keep
  /// proving they are there outlives the client's channel however long
  /// the client is away, because the destination heartbeats the relay
  /// for the life of its connection.
  #[tokio::test(start_paused = true)]
  async fn a_heartbeat_retains_a_helper_past_its_control_channel() {
    let bootstrap_timeout = Duration::from_secs(60);
    let (mut service, now) = service(HelperOptions {
      bootstrap_timeout,
      ..HelperOptions::default()
    });
    let client = addr("192.0.2.7:41000");
    let dest = addr("203.0.113.9:60001");
    register(&mut service, now, PeerRole::Client, client);
    register(&mut service, now, PeerRole::Destination, dest);
    assert_eq!(
      service.handle(now, client, b"ciphertext"),
      Outcome::Relay { to: dest }
    );
    service.control_closed(now);

    // The client is gone; the destination is not, and says so.
    let mut at = now;
    for _ in 0..10 {
      at += bootstrap_timeout / 2;
      register(&mut service, at, PeerRole::Destination, dest);
      assert!(matches!(service.poll(at), Lifecycle::Serving { .. }));
    }
    // Once both peers go quiet there is no session left to preserve,
    // and nobody left to say so either.
    assert_eq!(
      service.poll(at + bootstrap_timeout),
      Lifecycle::Finished(ExitReason::Abandoned)
    );
  }

  /// `--retain` still bounds a relayed session that lost its client,
  /// and is the limit whenever it is the shorter of the two.
  #[tokio::test(start_paused = true)]
  async fn retention_still_bounds_an_abandoned_relayed_helper() {
    let retain = Duration::from_secs(30);
    let (mut service, now) = service(HelperOptions {
      retain: Some(retain),
      bootstrap_timeout: Duration::from_secs(60),
      ..HelperOptions::default()
    });
    let client = addr("192.0.2.7:41000");
    let dest = addr("203.0.113.9:60001");
    register(&mut service, now, PeerRole::Client, client);
    register(&mut service, now, PeerRole::Destination, dest);
    assert_eq!(
      service.handle(now, client, b"ciphertext"),
      Outcome::Relay { to: dest }
    );
    service.control_closed(now);
    assert_eq!(
      service.poll(now + retain),
      Lifecycle::Finished(ExitReason::Retained)
    );
  }

  #[tokio::test(start_paused = true)]
  async fn closing_the_last_session_ends_the_helper() {
    let (mut service, now) = service(HelperOptions::default());
    register(&mut service, now, PeerRole::Client, addr("192.0.2.7:41000"));
    assert!(matches!(service.poll(now), Lifecycle::Serving { .. }));
    service.close(nonce(1));
    assert_eq!(
      service.poll(now),
      Lifecycle::Finished(ExitReason::SessionsClosed)
    );
  }

  #[test]
  fn the_helper_runs_on_the_last_hop() {
    assert_eq!(
      HelperHop::from_jump_spec("bastion"),
      Some(HelperHop {
        host: "bastion",
        via: None
      })
    );
    assert_eq!(
      HelperHop::from_jump_spec("a,b"),
      Some(HelperHop {
        host: "b",
        via: Some("a")
      })
    );
    assert_eq!(
      HelperHop::from_jump_spec("me@a:2222,you@b:2022,c"),
      Some(HelperHop {
        host: "c",
        via: Some("me@a:2222,you@b:2022")
      })
    );
    for bad in ["", ",", "a,", ",a", "a,,b"] {
      assert_eq!(HelperHop::from_jump_spec(bad), None, "{bad}");
    }
  }

  fn sample_messages() -> Vec<HelperMessage> {
    vec![
      HelperMessage::Serve(Serve {
        version: PROTOCOL_VERSION,
        nonce: nonce(0x11),
        secret: secret(0x11),
      }),
      HelperMessage::Ready(Ready {
        version: PROTOCOL_VERSION,
        udp_port: 60123,
        client_ip: Some("203.0.113.5".parse().unwrap()),
        addr_hints: vec![
          addr("198.51.100.7:60123"),
          addr("[2001:db8::7]:60123"),
        ],
      }),
      HelperMessage::Peer(Peer {
        nonce: nonce(0x11),
        role: PeerRole::Destination,
        addr: addr("203.0.113.9:60001"),
      }),
      HelperMessage::Close(Close { nonce: nonce(0x11) }),
      // The bare ready line: no usable `$SSH_CONNECTION` and no address
      // worth hinting at. Both variable-length fields empty is the one
      // shape that renders no `key=` at all.
      HelperMessage::Ready(Ready {
        version: PROTOCOL_VERSION,
        udp_port: 60123,
        client_ip: None,
        addr_hints: Vec::new(),
      }),
    ]
  }

  #[test]
  fn control_messages_round_trip() {
    for message in sample_messages() {
      let wire = message.to_wire();
      assert_eq!(HelperMessage::parse(&wire).unwrap(), Some(message.clone()));
      assert_eq!(
        HelperMessage::parse(wire.trim_end()).unwrap(),
        Some(message.clone())
      );
      let crlf = format!("{}\r\n", wire.trim_end());
      assert_eq!(HelperMessage::parse(&crlf).unwrap(), Some(message.clone()));
      // Every message names the version it was built with, whether or
      // not it keeps the one it parsed.
      assert!(wire.contains(&format!(" v={PROTOCOL_VERSION} ")), "{wire}");
    }
    let registration = Registration {
      nonce: nonce(0x11),
      role: PeerRole::Destination,
      addr: addr("203.0.113.9:60001"),
      previous: None,
    };
    assert_eq!(registration.message(), sample_messages()[2]);
  }

  /// The serve line is the other place the session secret goes on an ssh
  /// channel, and the same rule holds as for the destination's helper
  /// announcement
  /// (`bootstrap::the_session_secret_is_redacted_everywhere_but_the_wire`):
  /// the wire form spells it out and nothing a log line reaches for does.
  #[test]
  fn the_serve_lines_secret_is_redacted_everywhere_but_the_wire() {
    let serve = Serve {
      version: PROTOCOL_VERSION,
      nonce: nonce(0x11),
      secret: secret(0x77),
    };
    let exposed = serve.secret.expose();
    assert!(serve.to_wire().contains(&exposed));
    for rendered in [
      serve.to_string(),
      format!("{serve:?}"),
      HelperMessage::Serve(serve.clone()).to_string(),
    ] {
      assert!(!rendered.contains(&exposed), "leaked in: {rendered}");
    }
    assert_eq!(
      HelperMessage::parse(&HelperMessage::Serve(serve.clone()).to_wire())
        .unwrap(),
      Some(HelperMessage::Serve(serve))
    );
  }

  /// The helper channel is a login channel like every other, so shell
  /// output past the ready line must not read as protocol, and a
  /// message that is one must not be skipped for getting it wrong.
  #[test]
  fn other_output_is_not_protocol_and_malformed_protocol_is_an_error() {
    let n = nonce(0x11).to_string();
    for line in [
      "",
      "Welcome to bastion.example",
      "MUSH SERVED v=1 nonce=x",
      " MUSH SERVE v=1 nonce=x",
      "mush serve v=1",
      "MUSH DONE v=1 nonce=x",
    ] {
      assert_eq!(HelperMessage::parse(line).unwrap(), None, "line: {line}");
    }
    for (line, err) in [
      (
        "MUSH SERVE v=1".to_string(),
        ParseError::MissingKey { key: "nonce" },
      ),
      (
        format!("MUSH SERVE v=1 nonce={n} nonce={n}"),
        ParseError::RepeatedKey { key: "nonce" },
      ),
      (
        "MUSH SERVE v=1 nonce=zz".to_string(),
        ParseError::InvalidValue { key: "nonce" },
      ),
      (
        format!("MUSH SERVE v=1 nonce={n}"),
        ParseError::MissingKey { key: "secret" },
      ),
      (
        format!("MUSH SERVE v=1 nonce={n} secret=zz"),
        ParseError::InvalidValue { key: "secret" },
      ),
      (
        "MUSH READY v=1 port=1 client=nonsense".to_string(),
        ParseError::InvalidValue { key: "client" },
      ),
      (
        "MUSH READY v=1".to_string(),
        ParseError::MissingKey { key: "port" },
      ),
      (
        "MUSH READY v=1 port=1 addr=nonsense".to_string(),
        ParseError::InvalidValue { key: "addr" },
      ),
      (
        format!("MUSH PEER v=1 nonce={n} role=bystander addr=1.2.3.4:5"),
        ParseError::InvalidValue { key: "role" },
      ),
      (
        format!("MUSH PEER v=1 nonce={n} role=client"),
        ParseError::MissingKey { key: "addr" },
      ),
      (
        "MUSH CLOSE v=1".to_string(),
        ParseError::MissingKey { key: "nonce" },
      ),
    ] {
      assert_eq!(
        HelperMessage::parse(&line).unwrap_err(),
        err,
        "line: {line}"
      );
    }
  }

  /// A STUN datagram that is not a binding request touches nothing.
  ///
  /// The service answers one message shape; anything else STUN-shaped is
  /// dropped before a nonce is looked up, a budget spent, or a source
  /// tracked. The service's own reflection is such a datagram, so a
  /// peer that echoed one back cannot move anything.
  #[tokio::test(start_paused = true)]
  async fn a_stun_datagram_that_is_not_a_binding_request_is_dropped() {
    let (mut service, now) = service(HelperOptions::default());
    let client = addr("192.0.2.7:41000");
    let probe = probe(1, PeerRole::Client);
    let Outcome::Reflect { reply, .. } =
      service.handle(now, client, probe.request())
    else {
      panic!("the probe was not reflected");
    };
    assert_eq!(service.tracked_sources(), 1);
    assert_eq!(
      service.handle(now, addr("198.51.100.9:41000"), &reply),
      Outcome::Drop(DropReason::NotBinding)
    );
    assert_eq!(service.peer_addr(nonce(1), PeerRole::Client), Some(client));
    assert_eq!(
      service.tracked_sources(),
      1,
      "a non-binding datagram allocated rate-limiting state"
    );
  }

  /// A socket that has stopped working ends the helper rather than
  /// spinning on it.
  ///
  /// A bastion process whose socket is gone can neither reflect nor
  /// relay, and holds a UDP port on somebody else's machine for as long
  /// as it lives, so the loop gives up after a bounded run of failures.
  #[tokio::test(start_paused = true)]
  async fn a_socket_that_only_fails_ends_the_service() {
    struct DeadSocket(std::cell::Cell<usize>);

    impl ProbeSocket for DeadSocket {
      async fn recv_from(
        &self,
        _buf: &mut [u8],
      ) -> io::Result<(usize, SocketAddr)> {
        self.0.set(self.0.get() + 1);
        Err(io::Error::from(io::ErrorKind::NotConnected))
      }

      async fn send_to(
        &self,
        _datagram: &[u8],
        _to: SocketAddr,
      ) -> io::Result<()> {
        Ok(())
      }
    }

    let socket = DeadSocket(std::cell::Cell::new(0));
    let (mut service, _) = service(HelperOptions::default());
    let (_control_tx, mut control) = mpsc::channel::<Control>(1);
    let (registrations, _reports) = mpsc::channel::<Registration>(1);
    let reason =
      serve(&socket, &mut service, &mut control, &registrations).await;
    assert_eq!(reason, ExitReason::SocketFailed);
    assert_eq!(socket.0.get(), MAX_RECV_FAILURES);
  }

  /// Control lines longer than `bootstrap_lines` can reach under its
  /// `-max_len=65536`, where a quadratic parser would be invisible. The
  /// framing bounds a line well below this before a parser sees one, so
  /// this is about the parsers, not a reachable input.
  #[test]
  fn control_parsers_stay_linear_past_the_fuzz_bound() {
    let tails = [
      format!("v=1 {}", "a=b ".repeat(10_000)),
      format!("nokey{}", "x".repeat(100_000)),
      "addr=1.2.3.4:5 ".repeat(10_000),
    ];
    for tail in &tails {
      let line = format!("{SERVE_PREFIX} {tail}");
      assert!(Serve::parse(&line).is_err(), "line len {}", line.len());
      assert!(
        matches!(HelperMessage::parse(&line), Err(_) | Ok(None)),
        "line len {}",
        line.len()
      );
    }
  }
}
