// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Path establishment: candidate gathering, coordinated punching, and
//! the fallback order (design doc, "Path establishment").
//!
//! There are four kinds of path, tried in order: **direct** (the
//! destination's own addresses), **punched** (paths both peers opened
//! by probing each other simultaneously), **relayed** (through the jump
//! helper), and the TCP fallback, which lives in the CLI because it is
//! no longer a UDP path at all. [`PathKind`] names them, and the kind of
//! path that won is reported so a test can assert which one carried the
//! session.
//!
//! # Why the kinds of path are staged rather than raced all at once
//!
//! A path's kind is a claim about *what the path needed*, so the stages
//! have to be exclusive for that claim to mean anything. The client
//! dials the direct addresses alone for [`DIRECT_WINDOW`]; only when
//! that window closes does it order the punch, abandoning the direct
//! dials and reissuing them at the same addresses as punched dials. That
//! reissue keeps attribution exact: a destination behind a stateful
//! firewall answers the same address either way, and without the
//! restart the stale dial's next retransmission would take credit for a
//! path the punch opened.
//!
//! # Coordinated punching
//!
//! The standard simultaneous open (design doc, "Path establishment").
//! Two details are required here: probes are STUN binding requests
//! ([`crate::stun`]), and they leave from the session's own socket
//! ([`crate::traversal`]), so the mapping a probe opens is the mapping
//! the session gets. What they carry authorizes the jump helper to
//! act and nothing else: pinning is what makes racing hostile paths
//! safe, and every candidate still has to survive the pinned handshake.
//!
//! One target of those rounds is not a candidate at all: the helper
//! address this peer registered with. The relay routes on the address a
//! peer's last probe arrived from, so the rounds keep that registration
//! current -- through a NAT rebind mid-establishment, and against a
//! dual-homed bastion's other addresses. That target gets its own probe:
//! a candidate address may be anywhere, including somewhere a lying
//! helper named, so what goes there says it was aimed at a peer
//! ([`crate::stun::Aim`]) and registers nothing if it is replayed at the
//! helper. Each round generates a fresh transaction for the same reason,
//! so a captured probe is good only for its own round.
//!
//! Nothing here answers a probe. A peer's probe has done its work by
//! being sent -- it is the peer's own firewall it opened -- and the
//! handshake, not a connectivity check, is what decides whether a path
//! connects the right two parties.
//!
//! # Without a helper
//!
//! The same driver covers the design's "Degrading without the helper":
//! no helper means no relayed candidate and no reflection but the
//! `--stun` opt-in's, yet the client still names itself to the
//! destination and still orders the punch, so the destination's outward
//! probes open its firewall for the client's dial. When the candidate
//! set shows UDP is futile the driver says so at once
//! ([`PathEvent::Futile`]) instead of spending the establishment budget.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{debug, trace};

use crate::bootstrap::{
  Candidate, CandidateKind, InvalidValue, SessionNonce, SessionSecret, Signal,
};
use crate::channel::SignalChannel;
use crate::server::MAX_ADDR_HINTS;
use crate::stun::{Aim, BindingTransaction, PeerRole, ProbeLabel};
use crate::traversal::{Probe, TraversalSocket};
use crate::wire::str_enum;

/// Which of the design's kinds of path carried the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathKind {
  /// An address the destination named itself -- an interface address,
  /// DNS, or the `$SSH_CONNECTION` hint -- reached with no traversal
  /// assistance at all.
  Direct,
  /// A path both peers had to probe open: a reflexive address the helper
  /// reported, or a direct address whose firewall the destination's
  /// outward probes had to unlock.
  Punched,
  /// Through the jump helper, which forwards between the peers' flows.
  Relayed,
  /// No UDP path at all: a plain TCP connection to the destination's ssh
  /// port, through the jump when one is configured.
  Fallback,
}

str_enum! {
  PathKind => InvalidValue {
    Direct => "direct",
    Punched => "punched",
    Relayed => "relayed",
    Fallback => "fallback",
  }
}

/// How long direct dialing runs alone before the punch is ordered.
///
/// Long enough that a healthy direct path -- a handshake over a WAN RTT,
/// with room for a lost Initial -- wins as a direct path, short enough
/// that a destination that needs punching is not left waiting on direct
/// dials that will never be answered.
pub const DIRECT_WINDOW: Duration = Duration::from_secs(1);

/// Gap between reflection attempts at one reflector.
pub const REFLECT_INTERVAL: Duration = Duration::from_millis(200);

/// Reflection attempts per reflector. A binding request is a single
/// datagram, so repeats are how loss is survived.
pub const REFLECT_ATTEMPTS: u32 = 5;

/// How long reflection may take before establishment moves on without
/// it.
const REFLECT_BUDGET: Duration =
  REFLECT_INTERVAL.saturating_mul(REFLECT_ATTEMPTS);

/// Gap between punch rounds.
pub const PUNCH_INTERVAL: Duration = Duration::from_millis(250);

/// How many punch rounds each side sends. Their span has to outlast the
/// signaling round trip that starts the peer punching plus the handshake
/// that follows, and each round is one small datagram per candidate.
pub const PUNCH_ROUNDS: u32 = 12;

/// Delay from ordering the punch to the punched dials: long enough for
/// the first round to be on the wire.
pub const PUNCHED_DIAL_DELAY: Duration = Duration::from_millis(250);

/// Delay from ordering the punch to falling to the relay.
///
/// Short on purpose: the relay is dialed while the punch is still
/// running, not after it has been given up on. A punched path that
/// works completes its handshake inside this window and wins the race
/// outright; one that does not would otherwise cost every session on a
/// hostile network the whole punch schedule before it saw a byte.
/// Starting on the relay and upgrading in the background
/// ([`crate::upgrade`]) beats waiting -- the design's "connect through
/// the relay immediately", and Tailscale's before it.
pub const RELAY_DELAY: Duration = Duration::from_millis(500);

/// Bound on waiting for the jump helper's answer before establishment
/// moves on without it. The helper's ssh is started alongside the
/// bootstrap's and normally answers well before the connect line does,
/// so this covers a bastion that hangs rather than one that is merely
/// busy.
pub const HELPER_WAIT: Duration = Duration::from_secs(3);

/// Establishment budget for a session that tries the kinds of path in
/// order, replacing [`crate::client::DEFAULT_ESTABLISH_TIMEOUT`] (which
/// bounds a single kind of path).
///
/// It covers every stage before the TCP fallback: the direct window,
/// whatever the helper and reflection cost (bounded by
/// [`HELPER_WAIT`]), the punch, and the relayed handshake after all of
/// them. Those values put the relayed dial no later than 4.5 seconds
/// in, and a second and a half in when the helper answers at once,
/// leaving the rest for the handshake it starts. The whole of it is
/// what a session with no UDP path at all waits before falling back.
pub const TRAVERSAL_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on the reflectors one peer will probe.
///
/// The helper's own addresses are already bounded where they arrive, but
/// the `--stun` opt-in resolves a hostname, and a DNS answer is somebody
/// else's list. The same bound as the candidate lists: what a peer or a
/// resolver names must not become this side's workload.
const MAX_REFLECTORS: usize = MAX_ADDR_HINTS;

/// Cap on the peer's *reflexive* candidates, kept separately from its
/// direct ones.
///
/// A reflexive address is one a reflector named, so it is the one
/// candidate class a hostile jump host can choose outright (design doc,
/// "Security"). A conforming peer offers one -- it stops probing helper
/// addresses as soon as one answers -- so four leaves room for a dual-stack
/// helper and the `--stun` opt-in while keeping what a lying helper can
/// aim traffic at to a fraction of the direct budget.
const MAX_REFLEXIVE_HINTS: usize = 4;

/// One reflector being asked for this peer's server-reflexive address.
#[derive(Debug)]
struct Reflection {
  reflector: SocketAddr,
  transaction: BindingTransaction,
  /// An address of the jump helper, as opposed to a `--stun` server:
  /// only these register this peer for the relay, and only one of them
  /// may be the address this peer uses (see
  /// [`Probes::settle_helper_addr`]).
  is_helper: bool,
  sent: u32,
  next: Instant,
  answered: bool,
  /// Dropped in favour of the helper address that answered first.
  abandoned: bool,
}

impl Reflection {
  /// Whether this reflector may still be probed.
  fn pending(&self) -> bool {
    !self.answered && !self.abandoned && self.sent < REFLECT_ATTEMPTS
  }
}

/// A punch series: paced rounds of probes at the peer's candidates.
///
/// The probes themselves are generated per round rather than kept, so each
/// round is a transaction of its own (see the module docs).
#[derive(Debug)]
struct Punching {
  targets: Vec<SocketAddr>,
  sent: u32,
  next: Instant,
}

/// The probing half of path establishment, as a pure state machine.
///
/// Time-parametric like [`crate::helper::HelperService`]: every entry
/// point takes the current [`Instant`], and what it decides to send goes
/// into an outbox the driver empties, so pacing, retransmission, and the
/// reflexive-address match are testable without a socket or a clock.
#[derive(Debug)]
struct Probes {
  label: ProbeLabel,
  /// What labeled probes are signed with, which is what the helper acts
  /// on ([`crate::stun`]). The destination learns it from the client's
  /// helper announcement, so it arrives after this side starts.
  secret: Option<SessionSecret>,
  /// Whether a loopback target can name this session's peer, which is
  /// true only when the peer really is this host.
  allow_loopback: bool,
  reflections: Vec<Reflection>,
  punch: Option<Punching>,
  /// The helper address this peer registered with, probed alongside every
  /// punch round; see [`Probes::settle_helper_addr`].
  registered_helper: Option<SocketAddr>,
  outbox: Vec<(Vec<u8>, SocketAddr)>,
}

impl Probes {
  /// A state machine probing as `label`'s session and role.
  pub fn new(
    label: ProbeLabel,
    secret: Option<SessionSecret>,
    allow_loopback: bool,
  ) -> Self {
    Self {
      label,
      secret,
      allow_loopback,
      reflections: Vec::new(),
      punch: None,
      registered_helper: None,
      outbox: Vec::new(),
    }
  }

  /// Records the session secret, once this side learns it.
  ///
  /// A punch series already running was built with nothing to sign
  /// with; its next round signs, because rounds are generated as they
  /// go out and one of their targets comes to be the helper address,
  /// which answers nothing unsigned.
  pub fn set_secret(&mut self, secret: SessionSecret) {
    if self.secret.is_some() {
      return;
    }
    self.secret = Some(secret);
  }

  /// Starts asking `reflector` for this peer's reflexive address.
  ///
  /// A helper address is asked with a labeled, signed probe, which is
  /// what the jump helper checks; a third-party `--stun` server has
  /// nothing to check and no secret to share, so it is asked with
  /// neither.
  pub fn reflect(
    &mut self,
    now: Instant,
    reflector: SocketAddr,
    is_helper: bool,
  ) {
    if self.reflections.iter().any(|r| r.reflector == reflector) {
      return;
    }
    if self.reflections.len() >= MAX_REFLECTORS {
      debug!(%reflector, "reflector table full; not asking");
      return;
    }
    if !is_dialable(reflector, self.allow_loopback) {
      debug!(%reflector, "skipping a reflector that names no host");
      return;
    }
    let transaction = match (is_helper, &self.secret) {
      (true, Some(secret)) => BindingTransaction::new(self.label, secret),
      _ => BindingTransaction::unlabeled(),
    };
    self.reflections.push(Reflection {
      reflector,
      transaction,
      is_helper,
      sent: 0,
      next: now,
      answered: false,
      abandoned: false,
    });
  }

  /// Whether any reflector has been asked and has not answered.
  pub fn reflecting(&self) -> bool {
    self.reflections.iter().any(Reflection::pending)
  }

  /// Keeps `chosen` as this peer's one helper address: abandons the
  /// reflections at the other addresses, and adds this one to every
  /// punch round, whose paced probes re-register the current mapping
  /// and keep it open.
  ///
  /// The helper keeps one address per role, and a peer whose NAT
  /// allocates a mapping per destination shows each of a dual-homed
  /// bastion's addresses a different source address, so probing all of
  /// them leaves the registration pointing at a mapping this peer does
  /// not relay through. The registration is also a single moment: the
  /// reflection that made it happens seconds before the relayed dial, so
  /// a NAT that rebinds in between leaves the relay with nothing to
  /// re-register it.
  fn settle_helper_addr(&mut self, chosen: SocketAddr) {
    self.registered_helper = Some(chosen);
    for reflection in &mut self.reflections {
      if reflection.is_helper && reflection.reflector != chosen {
        reflection.abandoned = true;
      }
    }
  }

  /// Starts (or restarts) the punch series at `targets`, bounded and
  /// filtered like every other address list establishment takes from a
  /// peer, and signed when this side has a secret (one target of the
  /// rounds is the helper address, which acts on nothing else).
  pub fn punch(&mut self, now: Instant, targets: &[SocketAddr]) {
    self.punch = Some(Punching {
      targets: targets
        .iter()
        .copied()
        .filter(|&addr| is_dialable(addr, self.allow_loopback))
        .take(MAX_ADDR_HINTS)
        .collect(),
      sent: 0,
      next: now,
    });
  }

  /// Adds one more address to an already-running punch series, for a
  /// candidate that arrived after the rendezvous.
  pub fn punch_also(&mut self, target: SocketAddr) {
    if !is_dialable(target, self.allow_loopback) {
      return;
    }
    if let Some(punch) = &mut self.punch
      && !punch.targets.contains(&target)
      && punch.targets.len() < MAX_ADDR_HINTS
    {
      punch.targets.push(target);
    }
  }

  /// Feeds one received probe, returning the reflector and the reflexive
  /// address when it answers an outstanding reflection.
  ///
  /// Matching is STUN's own transaction id, plus the two things STUN's
  /// response rules ask for and the driver already has: the answer must
  /// come from the reflector the request went to, and a signed
  /// transaction's answer must carry the session's signature. A
  /// reflexive address attracts traffic from both peers, so no single
  /// guard should be all that stands between an attacker and planting
  /// one. Everything else -- the peer's own punch probes above all --
  /// is nothing to answer and nothing to learn from.
  pub fn on_probe(
    &mut self,
    from: SocketAddr,
    datagram: &[u8],
  ) -> Option<(SocketAddr, SocketAddr)> {
    for reflection in &mut self.reflections {
      if reflection.answered || reflection.abandoned {
        continue;
      }
      if reflection.reflector != from {
        continue;
      }
      if let Some(reflexive) = reflection.transaction.reflexive(datagram) {
        reflection.answered = true;
        return Some((reflection.reflector, reflexive));
      }
    }
    None
  }

  /// Queues everything due and reports when to look again.
  pub fn poll(&mut self, now: Instant) -> Option<Instant> {
    let mut deadline: Option<Instant> = None;
    for reflection in &mut self.reflections {
      if !reflection.pending() {
        continue;
      }
      if now >= reflection.next {
        self.outbox.push((
          reflection.transaction.request().to_vec(),
          reflection.reflector,
        ));
        reflection.sent += 1;
        reflection.next = now + REFLECT_INTERVAL;
      }
      if reflection.sent < REFLECT_ATTEMPTS {
        deadline = earliest(deadline, Some(reflection.next));
      }
    }
    // Two probes when a round is due, because they are going to two
    // kinds of place: the candidates get one that says it was aimed at
    // a peer, and the helper address gets the one the helper registers
    // on.
    if let Some(punch) = &mut self.punch
      && punch.sent < PUNCH_ROUNDS
    {
      if now >= punch.next {
        let at_peers = probe_round(self.label, self.secret.as_ref(), Aim::Peer);
        for &target in &punch.targets {
          self.outbox.push((at_peers.clone(), target));
        }
        if let Some(helper) = self.registered_helper {
          let at_helper =
            probe_round(self.label, self.secret.as_ref(), Aim::Helper);
          self.outbox.push((at_helper, helper));
        }
        punch.sent += 1;
        punch.next = now + PUNCH_INTERVAL;
      }
      if punch.sent < PUNCH_ROUNDS {
        deadline = earliest(deadline, Some(punch.next));
      }
    }
    deadline
  }

  /// The probes queued since the last call.
  pub fn take_outbox(&mut self) -> Vec<(Vec<u8>, SocketAddr)> {
    std::mem::take(&mut self.outbox)
  }

  /// The addresses the punch series is aimed at.
  fn targets(&self) -> Vec<SocketAddr> {
    self
      .punch
      .as_ref()
      .map(|punch| punch.targets.clone())
      .unwrap_or_default()
  }
}

/// One round's probe bytes for one aim: a fresh transaction, signed when
/// this side has a secret to sign with.
///
/// With no secret there is no helper either, and nothing answers a
/// punch probe: the label exists to be checked, and there is nothing
/// to check.
///
/// A free function, not a method, so a round can be generated while the
/// punch series it belongs to is already borrowed.
fn probe_round(
  label: ProbeLabel,
  secret: Option<&SessionSecret>,
  aim: Aim,
) -> Vec<u8> {
  let label = ProbeLabel { aim, ..label };
  match secret {
    Some(secret) => BindingTransaction::new(label, secret),
    None => BindingTransaction::unlabeled(),
  }
  .request()
  .to_vec()
}

/// What the client learns about itself while establishment is running.
///
/// Both facts arrive late by nature: the helper is a second ssh whose
/// answer the establishment does not wait on, and the jump's view of
/// this client is a plain shell probe worth making only once the helper
/// is known to be missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arrival {
  /// The jump helper answered at these addresses. An empty set is the
  /// degraded case: no helper, so no reflection and no relay.
  Helper(Vec<SocketAddr>),
  /// The jump observed this client at this address (`echo
  /// $SSH_CONNECTION`, no `mush` binary required), which is where the
  /// destination's reverse punch aims under port-preserving 1:1 NAT.
  Observed(SocketAddr),
}

/// What the establishment driver asks the racer to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathEvent {
  /// Dial this address as this kind of path.
  Dial {
    /// The candidate.
    addr: SocketAddr,
    /// The kind of path it belongs to.
    path_kind: PathKind,
  },
  /// Establishment moved to this kind of path: abandon the kinds below
  /// it, whose candidates are reissued here when they still apply. Only
  /// the punch does this, because it is the only stage that redials what
  /// came before it.
  Stage(PathKind),
  /// No UDP path is possible with the candidates on offer, for this
  /// reason. Nothing is gained by spending the rest of the budget.
  Futile(String),
}

/// Whether an address can name this session's peer at all.
///
/// Every address that enters establishment passes here, whichever channel
/// carried it: the connect line's hints, a signaled candidate, a punch
/// target, a reflector, and this peer's own view of itself. Otherwise a
/// confused or hostile peer, or a helper laundering an address through
/// one, has this host sending QUIC Initials and probes wherever it
/// named -- at this host's own loopback ports, or at a multicast group.
/// Rejected: the unspecified address and port 0 (neither names an
/// endpoint), multicast and broadcast (a session is unicast), link-local
/// (names something on this segment rather than a peer, and its scope
/// does not survive the wire format), and loopback unless
/// `allow_loopback` says the peer really is this host.
///
/// The v4-mapped v6 spelling of any of those is the same address, and
/// the wire lines they arrive on accept both spellings, so
/// `canonical_ip` settles the family before anything is asked.
pub(crate) fn is_dialable(addr: SocketAddr, allow_loopback: bool) -> bool {
  addr.port() != 0 && is_dialable_ip(addr.ip(), allow_loopback)
}

/// [`is_dialable`] without the port: whether an address of this host can
/// name it to a peer at all.
///
/// The same rejections for the one caller that holds an address with no
/// port yet ([`crate::server::interface_ips`]). Kept with the
/// establishment filter deliberately: an interface address this host
/// hints and a candidate a peer signals are judged by one rule, so there
/// is one predicate to review rather than two that must be shown to
/// agree.
pub(crate) fn is_dialable_ip(ip: IpAddr, allow_loopback: bool) -> bool {
  let ip = canonical_ip(ip);
  if ip.is_unspecified() || ip.is_multicast() {
    return false;
  }
  match ip {
    IpAddr::V4(v4) if v4.is_broadcast() || v4.is_link_local() => return false,
    // fe80::/10; `is_unicast_link_local` is still unstable.
    IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80 => return false,
    _ => {}
  }
  allow_loopback || !ip.is_loopback()
}

/// An address in the one form its properties can be read from.
///
/// `::ffff:127.0.0.1` is loopback and `::ffff:224.0.0.1` is multicast,
/// but `Ipv6Addr`'s predicates answer for the native v6 forms alone, so
/// a v4-mapped address has to become the v4 address it stands for
/// before any of them is asked.
fn canonical_ip(ip: IpAddr) -> IpAddr {
  match ip {
    IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
    v4 => v4,
  }
}

/// Whether `addr` could name a host this client can route to.
///
/// Conservative in the direction of trying: a wasted dial costs a slot
/// of the establishment budget, while wrongly declaring a path
/// impossible costs the session. So only an address in a private block
/// this client shares no interface with is hopeless.
///
/// A prediction, and used as one: it decides whether establishment as a
/// whole is futile, never whether a single candidate is dialed. The
/// ordinary shape behind a bastion -- a client on one private block
/// reaching a destination on another through a VPN or a corporate
/// router -- fails this test while the dial succeeds.
fn plausible(addr: SocketAddr, local_ips: &[IpAddr]) -> bool {
  let Some(block) = private_block(addr.ip()) else {
    return true;
  };
  local_ips
    .iter()
    .any(|&local| private_block(local) == Some(block))
}

/// Which private block an address sits in, if any: the v4 ranges of RFC
/// 1918 and the shared address space of RFC 6598, and v6 unique-local.
fn private_block(ip: IpAddr) -> Option<u8> {
  match ip {
    IpAddr::V4(v4) => {
      let [a, b, ..] = v4.octets();
      match (a, b) {
        (10, _) => Some(0),
        (172, 16..=31) => Some(1),
        (192, 168) => Some(2),
        (100, 64..=127) => Some(3),
        _ => None,
      }
    }
    // fc00::/7.
    IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00 == 0xfc00).then_some(4),
  }
}

/// What the traversal phase saw, for the log line and the test hook.
#[derive(Debug, Clone, Default)]
pub struct PathReport {
  /// Whether a jump helper answered over ssh and named an address to
  /// reach it at, which is what makes reflection and the relay part of
  /// establishment at all. Whether one was reached over UDP is
  /// [`helper`](Self::helper).
  pub helper_offered: bool,
  /// The helper address this peer reached, when one answered.
  pub helper: Option<SocketAddr>,
  /// This peer's own reflexive address, as a reflector observed it.
  pub reflexive: Option<SocketAddr>,
  /// Whether the punch rendezvous was ordered.
  pub punched: bool,
  /// Whether the peer's candidate terminator arrived.
  pub peer_done: bool,
}

/// The client's half of path establishment: the side that holds both
/// channels, passes candidates between them, orders the punch, and
/// feeds the candidate race.
#[derive(Debug)]
pub struct ClientPaths {
  nonce: SessionNonce,
  secret: SessionSecret,
  probes: Probes,
  /// Whether a loopback candidate can name the destination
  /// (`ClientPlan::allow_loopback`).
  allow_loopback: bool,
  /// Addresses this client offers the destination to punch at.
  self_addrs: Vec<SocketAddr>,
  /// This client's own addresses, for judging what it can route to.
  local_ips: Vec<IpAddr>,
  /// The destination's own addresses, from the connect line.
  peer_direct: Vec<SocketAddr>,
  peer_reflexive: Vec<SocketAddr>,
  helper_addrs: Vec<SocketAddr>,
  helper_settled: bool,
  helper_deadline: Instant,
  report: PathReport,
  stage: PathKind,
  started: Instant,
  punch_round: u32,
  punch_at: Instant,
  punched_dial_at: Option<Instant>,
  relay_at: Option<Instant>,
  announced_done: bool,
  dialed: Vec<(SocketAddr, PathKind)>,
  signals: Vec<Signal>,
  events: Vec<PathEvent>,
}

impl ClientPaths {
  /// Client-side establishment for `nonce`.
  ///
  /// `plan`'s `self_addrs` are what the destination's reverse punch aims
  /// at; `peer_direct` is the connect line's candidate set, already
  /// being dialed as direct paths.
  pub fn new(
    now: Instant,
    nonce: SessionNonce,
    secret: SessionSecret,
    plan: ClientPlan,
    peer_direct: Vec<SocketAddr>,
  ) -> Self {
    let mut paths = Self {
      nonce,
      secret,
      probes: Probes::new(
        ProbeLabel::to_helper(nonce, PeerRole::Client),
        Some(secret),
        plan.allow_loopback,
      ),
      allow_loopback: plan.allow_loopback,
      self_addrs: Vec::new(),
      local_ips: plan.local_ips,
      peer_direct,
      peer_reflexive: Vec::new(),
      helper_addrs: Vec::new(),
      helper_settled: !plan.helper_expected,
      helper_deadline: now + HELPER_WAIT,
      report: PathReport::default(),
      stage: PathKind::Direct,
      started: now,
      punch_round: 0,
      punch_at: now + DIRECT_WINDOW,
      punched_dial_at: None,
      relay_at: None,
      announced_done: false,
      dialed: Vec::new(),
      signals: Vec::new(),
      events: Vec::new(),
    };
    for addr in plan.self_addrs {
      paths.offer_self(addr, CandidateKind::Direct);
    }
    // The `--stun` opt-in's reflectors, which are used here and never
    // again: a reflexive address arrives as a probe answer, not by
    // asking the list a second time.
    for server in &plan.stun_servers {
      paths.probes.reflect(now, *server, false);
    }
    if !plan.stun_servers.is_empty() {
      paths.punch_at = paths.punch_at.max(now + REFLECT_BUDGET);
    }
    paths
  }

  /// What the phase saw so far.
  pub fn report(&self) -> &PathReport {
    &self.report
  }

  /// Records something the client learned about itself.
  pub fn on_arrival(&mut self, now: Instant, arrival: Arrival) {
    match arrival {
      Arrival::Helper(addrs) => self.on_helper(now, addrs),
      Arrival::Observed(addr) => self.offer_self(addr, CandidateKind::Direct),
    }
  }

  /// Records the helper's addresses, or that there is none.
  ///
  /// An empty set is the design's "Degrading without the helper":
  /// reflection and relay are gone, and establishment carries on with
  /// direct dialing and the reverse punch. Settled once, so a channel
  /// that closes after the answer changes nothing.
  ///
  /// The addresses pass the martian filter here rather than one call
  /// deeper, so a bastion naming only addresses that cannot be a helper
  /// reads as the degraded case it is: keeping them would make
  /// establishment believe a relayed path exists and spend the whole
  /// budget waiting for one.
  pub fn on_helper(&mut self, now: Instant, addrs: Vec<SocketAddr>) {
    if self.helper_settled {
      return;
    }
    self.helper_settled = true;
    self.helper_addrs = addrs
      .into_iter()
      .filter(|&addr| is_dialable(addr, self.allow_loopback))
      .take(MAX_ADDR_HINTS)
      .collect();
    if self.helper_addrs.is_empty() {
      return;
    }
    self.report.helper_offered = true;
    // The destination is told every address the helper answers on,
    // because which one it can reach is a fact only it has: a dual-homed
    // bastion faces the client on one address and the destination's own
    // network on the other.
    for &addr in &self.helper_addrs {
      self
        .signals
        .push(Signal::helper(self.nonce, addr, self.secret));
      self.probes.reflect(now, addr, true);
    }
    self.punch_at = self.punch_at.max(now + REFLECT_BUDGET);
  }

  /// Feeds one signaling message from the destination.
  pub fn on_signal(&mut self, signal: &Signal) {
    if signal.nonce() != self.nonce {
      debug!(%signal, "signaling for another session");
      return;
    }
    match signal {
      Signal::Candidate(candidate) => self.on_candidate(candidate),
      Signal::Done(_) => self.report.peer_done = true,
      // The client coordinates: it announces the helper and orders the
      // punch, and has no use for the destination doing either.
      Signal::Helper(_) | Signal::Punch(_) => {
        debug!(%signal, "unexpected signal from the destination")
      }
    }
  }

  fn on_candidate(&mut self, candidate: &Candidate) {
    match candidate.kind {
      CandidateKind::Direct => {
        push_bounded(&mut self.peer_direct, candidate.addr);
      }
      CandidateKind::Reflexive => {
        if push_capped(
          &mut self.peer_reflexive,
          candidate.addr,
          MAX_REFLEXIVE_HINTS,
        ) {
          self.probes.punch_also(candidate.addr);
          if self.stage >= PathKind::Punched {
            self.dial(candidate.addr, PathKind::Punched);
          }
        }
      }
      // The destination reaching the helper is what makes the relay a
      // path, but the address it names is the helper address it reached,
      // not the one this client dials: it reports readiness, not an
      // address.
      CandidateKind::Relayed => debug!(
        addr = %candidate.addr,
        "the destination registered with the helper"
      ),
    }
  }

  /// Feeds one probe received on the session's socket.
  pub fn on_probe(&mut self, probe: &Probe) {
    let Some((reflector, reflexive)) =
      self.probes.on_probe(probe.from, &probe.datagram)
    else {
      return;
    };
    debug!(%reflector, %reflexive, "reflexive address learned");
    if self.helper_addrs.contains(&reflector) {
      self.report.helper.get_or_insert(reflector);
      self.probes.settle_helper_addr(reflector);
    }
    self.report.reflexive.get_or_insert(reflexive);
    self.offer_self(reflexive, CandidateKind::Reflexive);
    // The punch waits on reflection only while a reflector might still
    // answer; once none can, the direct window is the whole delay again.
    if !self.probes.reflecting() {
      self.punch_at = self.punch_at.min(self.started + DIRECT_WINDOW);
    }
  }

  /// Announces one of this client's own addresses to the destination.
  ///
  /// An address that turns up after the rendezvous is worth a second
  /// one: `round` makes a punch over a grown candidate set a distinct
  /// event rather than a repeat, and the destination has no other way
  /// to learn it should be probing somewhere new.
  fn offer_self(&mut self, addr: SocketAddr, kind: CandidateKind) {
    if !push_bounded(&mut self.self_addrs, addr) {
      return;
    }
    self.signals.push(Signal::candidate(self.nonce, kind, addr));
    if self.punch_round > 0 {
      self.rendezvous();
    }
  }

  /// Tells the destination to punch at everything this client can name
  /// for itself, as the next round.
  fn rendezvous(&mut self) {
    self.punch_round += 1;
    self.signals.push(Signal::punch(
      self.nonce,
      self.punch_round,
      self.self_addrs.clone(),
    ));
  }

  /// Advances establishment and the probing, reporting when to look
  /// again.
  pub fn poll(&mut self, now: Instant) -> Option<Instant> {
    if self.stage == PathKind::Direct
      && now >= self.punch_at
      && (self.helper_settled || now >= self.helper_deadline)
    {
      self.order_punch(now);
    }
    if self.stage == PathKind::Punched
      && let Some(at) = self.punched_dial_at
      && now >= at
    {
      self.punched_dial_at = None;
      // The destination's own addresses are dialed again here, as the
      // kind of path that names what opened them: a firewalled
      // destination answers the same address, and only the punch made it
      // answer.
      for addr in self.peer_direct.clone() {
        self.dial(addr, PathKind::Punched);
      }
      for addr in self.peer_reflexive.clone() {
        self.dial(addr, PathKind::Punched);
      }
    }
    if self.stage == PathKind::Punched
      && let Some(at) = self.relay_at
      && now >= at
      && let Some(helper) = self.report.helper
    {
      self.relay_at = None;
      self.stage = PathKind::Relayed;
      // No stage event: the relay is a last resort added alongside the
      // punched dials, not a replacement for them. A punched path that
      // completes late is still the better one, and abandoning its dials
      // here would throw that away for a longer path.
      self.dial(helper, PathKind::Relayed);
    }
    let mut deadline = self.probes.poll(now);
    if self.stage == PathKind::Direct {
      // When the punch is due but the helper has not answered, wake at
      // the instant the wait expires, not the one already behind us: a
      // deadline in the past spins the driver instead of sleeping it,
      // and on a current-thread runtime a spin is the whole session.
      deadline = earliest(
        deadline,
        Some(match self.helper_settled {
          true => self.punch_at,
          false => self.punch_at.max(self.helper_deadline),
        }),
      );
    }
    if let Some(at) = self.punched_dial_at {
      deadline = earliest(deadline, Some(at));
    }
    if self.stage == PathKind::Punched
      && let Some(at) = self.relay_at
      && self.report.helper.is_some()
    {
      deadline = earliest(deadline, Some(at));
    }
    deadline
  }

  /// The rendezvous: tell the destination to punch at this client's
  /// addresses, start punching at the destination's, and move
  /// establishment past the direct stage.
  fn order_punch(&mut self, now: Instant) {
    self.stage = PathKind::Punched;
    self.report.punched = true;
    self.rendezvous();
    self.finish_candidates();
    // The helper address is probed alongside these rounds without being
    // in `targets`; see `Probes::settle_helper_addr`.
    let targets: Vec<SocketAddr> = self
      .peer_direct
      .iter()
      .chain(self.peer_reflexive.iter())
      .copied()
      .collect();
    self.probes.punch(now, &targets);
    self.punched_dial_at = Some(now + PUNCHED_DIAL_DELAY);
    self.relay_at = Some(now + RELAY_DELAY);
    self.events.push(PathEvent::Stage(PathKind::Punched));
    debug!(peers = ?self.self_addrs, "punch rendezvous ordered");
  }

  fn finish_candidates(&mut self) {
    if self.announced_done {
      return;
    }
    self.announced_done = true;
    self.signals.push(Signal::done(self.nonce));
  }

  fn dial(&mut self, addr: SocketAddr, path_kind: PathKind) {
    if self.dialed.contains(&(addr, path_kind)) {
      return;
    }
    // Only whether the address can name the destination at all;
    // `plausible` is a prediction and belongs to the futility judgment.
    // Filtering dials with it would drop the connect line's candidates
    // when the punch reissues them, spending a working path on a guess.
    if !is_dialable(addr, self.allow_loopback) {
      debug!(%addr, "skipping a candidate that names no destination");
      return;
    }
    self.dialed.push((addr, path_kind));
    self.events.push(PathEvent::Dial { addr, path_kind });
  }

  /// Whether UDP is hopeless, given everything gathered so far: no
  /// helper to reflect or relay, and not one candidate this host could
  /// route to.
  ///
  /// Only decided once the helper question is settled, since a helper
  /// makes the relayed path available whatever the direct set looks
  /// like.
  fn futile(&self) -> Option<String> {
    if !self.helper_settled || !self.helper_addrs.is_empty() {
      return None;
    }
    let candidates = self.peer_direct.iter().chain(self.peer_reflexive.iter());
    if candidates
      .clone()
      .any(|&addr| plausible(addr, &self.local_ips))
    {
      return None;
    }
    let listed: Vec<String> =
      candidates.map(std::string::ToString::to_string).collect();
    Some(match listed.is_empty() {
      true => "the destination named no address and no jump helper answered"
        .to_string(),
      false => format!(
        "no jump helper answered and every address the destination named \
         is on a network this host cannot reach ({})",
        listed.join(", ")
      ),
    })
  }

  /// What the session's maintenance phase inherits from establishment
  /// (see [`crate::upgrade`]).
  pub fn handoff(&self) -> crate::upgrade::Inherited {
    crate::upgrade::Inherited {
      nonce: self.nonce,
      secret: Some(self.secret),
      helper: self.report.helper,
      peers: self
        .peer_direct
        .iter()
        .chain(self.peer_reflexive.iter())
        .copied()
        .collect(),
      allow_loopback: self.allow_loopback,
    }
  }

  fn take_signals(&mut self) -> Vec<Signal> {
    std::mem::take(&mut self.signals)
  }

  fn take_probes(&mut self) -> Vec<(Vec<u8>, SocketAddr)> {
    self.probes.take_outbox()
  }

  fn take_events(&mut self) -> Vec<PathEvent> {
    std::mem::take(&mut self.events)
  }
}

/// What the caller knows before establishment starts.
#[derive(Debug, Default)]
pub struct ClientPlan {
  /// Addresses this client can name for itself: its interface addresses
  /// at the session's own port, and its public address as observed by
  /// the jump over a plain shell probe.
  pub self_addrs: Vec<SocketAddr>,
  /// This host's own addresses, for judging what it can route to.
  pub local_ips: Vec<IpAddr>,
  /// The `--stun <server>` opt-in.
  pub stun_servers: Vec<SocketAddr>,
  /// Whether a helper is being started at all. When it is,
  /// establishment waits for its answer before ordering the punch.
  pub helper_expected: bool,
  /// Whether a loopback address can name the destination, which is
  /// true only when the destination is this host. The caller's own
  /// resolution is the evidence, exactly as it is for the connect
  /// line's hints (see [`crate::client`]).
  pub allow_loopback: bool,
}

/// The destination's half: answer the client's rendezvous, gather what
/// the helper can tell it about itself, and probe outward when told.
#[derive(Debug)]
pub struct DestinationPaths {
  nonce: SessionNonce,
  probes: Probes,
  helper_addrs: Vec<SocketAddr>,
  report: PathReport,
  client_done: bool,
  announced_done: bool,
  signals: Vec<Signal>,
  saw_helper: bool,
}

impl DestinationPaths {
  /// Destination-side establishment for `nonce`.
  ///
  /// The session secret is not here: this side learns it from the
  /// client's helper announcement, which is the only thing that gives
  /// it something to sign for.
  pub fn new(nonce: SessionNonce) -> Self {
    Self {
      nonce,
      probes: Probes::new(
        ProbeLabel::to_helper(nonce, PeerRole::Destination),
        None,
        // Loopback names this host, never the client, and the client
        // names itself by its interface addresses.
        false,
      ),
      helper_addrs: Vec::new(),
      report: PathReport::default(),
      client_done: false,
      announced_done: false,
      signals: Vec::new(),
      saw_helper: false,
    }
  }

  /// What the phase saw so far.
  pub fn report(&self) -> &PathReport {
    &self.report
  }

  /// Feeds one signaling message from the client.
  pub fn on_signal(&mut self, now: Instant, signal: &Signal) {
    if signal.nonce() != self.nonce {
      debug!(%signal, "signaling for another session");
      return;
    }
    match signal {
      Signal::Helper(helper) => {
        self.saw_helper = true;
        self.probes.set_secret(helper.secret);
        if push_bounded(&mut self.helper_addrs, helper.addr) {
          self.probes.reflect(now, helper.addr, true);
        }
      }
      // The reverse punch: probe outward at every address the client
      // named for itself, which is what opens this host's own NAT or
      // firewall for the dial that follows. Bounded and filtered inside
      // `punch`, like every other address list a peer supplies.
      Signal::Punch(punch) => {
        debug!(round = punch.round, peers = ?punch.peers, "punching");
        self.probes.punch(now, &punch.peers);
      }
      Signal::Done(_) => self.client_done = true,
      // The client dials; a candidate of its own is for the punch list,
      // which its rendezvous carries.
      Signal::Candidate(_) => trace!(%signal, "client candidate"),
    }
  }

  /// Feeds one probe received on the session's socket.
  pub fn on_probe(&mut self, probe: &Probe) {
    let Some((reflector, reflexive)) =
      self.probes.on_probe(probe.from, &probe.datagram)
    else {
      return;
    };
    debug!(%reflector, %reflexive, "reflexive address learned");
    self.report.helper.get_or_insert(reflector);
    self.probes.settle_helper_addr(reflector);
    self.report.reflexive.get_or_insert(reflexive);
    self.signals.push(Signal::candidate(
      self.nonce,
      CandidateKind::Reflexive,
      reflexive,
    ));
    // The reflection proved the flow the relay routes on, so this is the
    // client's cue that the relayed path has somewhere to forward to.
    self.signals.push(Signal::candidate(
      self.nonce,
      CandidateKind::Relayed,
      reflector,
    ));
  }

  /// Advances probing and reports when to look again.
  pub fn poll(&mut self, now: Instant) -> Option<Instant> {
    let deadline = self.probes.poll(now);
    // Nothing more is coming from this side once every reflector has
    // answered or given up and the client has finished its candidates
    // or named the helper, the only thing that could produce another
    // candidate here.
    if !self.announced_done
      && (self.client_done || self.saw_helper)
      && !self.probes.reflecting()
    {
      self.announced_done = true;
      self.signals.push(Signal::done(self.nonce));
    }
    deadline
  }

  /// What the session's maintenance phase inherits from establishment
  /// (see [`crate::upgrade`]).
  pub fn handoff(&self) -> crate::upgrade::Inherited {
    crate::upgrade::Inherited {
      nonce: self.nonce,
      secret: self.probes.secret,
      helper: self.report.helper,
      peers: self.probes.targets(),
      // Loopback names this host, never the client.
      allow_loopback: false,
    }
  }

  fn take_signals(&mut self) -> Vec<Signal> {
    std::mem::take(&mut self.signals)
  }

  fn take_probes(&mut self) -> Vec<(Vec<u8>, SocketAddr)> {
    self.probes.take_outbox()
  }
}

/// Appends `addr` unless it is already there or the list is full,
/// reporting whether it was added. The bound is what keeps a peer's
/// candidate stream from becoming this side's workload.
fn push_bounded(list: &mut Vec<SocketAddr>, addr: SocketAddr) -> bool {
  push_capped(list, addr, MAX_ADDR_HINTS)
}

/// [`push_bounded`] with a cap of its own, for the reflexive candidates
/// whose budget is deliberately smaller.
fn push_capped(
  list: &mut Vec<SocketAddr>,
  addr: SocketAddr,
  cap: usize,
) -> bool {
  if list.contains(&addr) || list.len() >= cap {
    return false;
  }
  list.push(addr);
  true
}

/// Sends one queued probe. Best effort by nature: the state machine
/// repeats its probes, so a socket that refuses one costs a round of
/// pacing and nothing else.
pub(crate) async fn emit(
  socket: &TraversalSocket,
  datagram: &[u8],
  to: SocketAddr,
) {
  match socket.send_probe(datagram, to).await {
    Ok(()) => trace!(%to, "probe sent"),
    Err(error) => trace!(%to, %error, "probe not sent"),
  }
}

/// The earlier of two optional deadlines.
pub(crate) fn earliest(
  a: Option<Instant>,
  b: Option<Instant>,
) -> Option<Instant> {
  match (a, b) {
    (Some(a), Some(b)) => Some(a.min(b)),
    (deadline, None) | (None, deadline) => deadline,
  }
}

/// Sleeps until `deadline`, or forever when nothing is pending.
pub(crate) async fn wait_until(deadline: Option<Instant>) {
  match deadline {
    Some(deadline) => tokio::time::sleep_until(deadline).await,
    None => std::future::pending().await,
  }
}

/// Runs client-side establishment over the bootstrap channel and the
/// session's own socket, feeding `events` as candidates become dialable.
///
/// Returns only when there is nothing left it could do: the candidate
/// set turned out hopeless (reported first, so the caller can stop
/// early), or the socket is gone. Otherwise the caller ends it by
/// dropping the future, which is what happens the moment a handshake
/// wins or the establishment budget runs out.
pub async fn drive_client<C: AsyncRead + AsyncWrite + Unpin>(
  channel: &mut SignalChannel<C>,
  socket: &TraversalSocket,
  probes: &mut mpsc::Receiver<Probe>,
  arrivals: &mut Option<mpsc::Receiver<Arrival>>,
  paths: &mut ClientPaths,
  events: &mpsc::Sender<PathEvent>,
) {
  let mut channel_open = true;
  loop {
    let deadline = paths.poll(Instant::now());
    for (datagram, to) in paths.take_probes() {
      emit(socket, &datagram, to).await;
    }
    for signal in paths.take_signals() {
      if !channel_open {
        continue;
      }
      trace!(%signal, "signaling out");
      if let Err(error) = channel.send(&signal).await {
        debug!(%error, "signaling channel ended");
        channel_open = false;
      }
    }
    if let Some(reason) = paths.futile() {
      let _ = events.send(PathEvent::Futile(reason)).await;
      return;
    }
    for event in paths.take_events() {
      if events.send(event).await.is_err() {
        return;
      }
    }

    let awaiting_arrivals = arrivals.is_some();
    tokio::select! {
      biased;
      arrival = next_arrival(arrivals), if awaiting_arrivals => match arrival {
        Some(arrival) => paths.on_arrival(Instant::now(), arrival),
        // Nothing more is coming, which for a helper that never
        // answered is the answer: there is none.
        None => {
          *arrivals = None;
          paths.on_helper(Instant::now(), Vec::new());
        }
      },
      probe = probes.recv() => match probe {
        Some(probe) => paths.on_probe(&probe),
        // The socket is gone, which means the endpoint is: nothing left
        // to probe from.
        None => return,
      },
      signal = channel.recv(), if channel_open => match signal {
        Ok(Some(signal)) => paths.on_signal(&signal),
        Ok(None) => channel_open = false,
        Err(error) => {
          debug!(%error, "signaling channel ended");
          channel_open = false;
        }
      },
      () = wait_until(deadline) => {}
    }
  }
}

/// Awaits the next thing the client learns about itself; the channel
/// closing without a helper answer is the CLI saying there is none.
async fn next_arrival(
  arrivals: &mut Option<mpsc::Receiver<Arrival>>,
) -> Option<Arrival> {
  match arrivals {
    Some(receiver) => receiver.recv().await,
    None => std::future::pending().await,
  }
}

/// Runs destination-side establishment over the bootstrap channel and
/// the session's own socket.
///
/// Returns when the client lets the channel go, which it does once a
/// path has won. Until then it keeps probing, because the pinhole the
/// client's handshake arrives through is one this side has to hold open.
pub async fn drive_destination<C: AsyncRead + AsyncWrite + Unpin>(
  channel: &mut SignalChannel<C>,
  socket: &TraversalSocket,
  probes: &mut mpsc::Receiver<Probe>,
  paths: &mut DestinationPaths,
) {
  loop {
    let deadline = paths.poll(Instant::now());
    for (datagram, to) in paths.take_probes() {
      emit(socket, &datagram, to).await;
    }
    for signal in paths.take_signals() {
      trace!(%signal, "signaling out");
      if let Err(error) = channel.send(&signal).await {
        debug!(%error, "signaling channel ended");
        return;
      }
    }
    tokio::select! {
      biased;
      probe = probes.recv() => match probe {
        Some(probe) => paths.on_probe(&probe),
        None => return,
      },
      signal = channel.recv() => match signal {
        Ok(Some(signal)) => paths.on_signal(Instant::now(), &signal),
        Ok(None) => return,
        Err(error) => {
          debug!(%error, "signaling channel ended");
          return;
        }
      },
      () = wait_until(deadline) => {}
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
  }

  fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
  }

  fn nonce() -> SessionNonce {
    SessionNonce::from_bytes([0x11; 16])
  }

  fn secret() -> SessionSecret {
    SessionSecret::from_bytes([0x77; 16])
  }

  /// Client-side establishment started now, which is what every test but
  /// the ones that walk the clock themselves wants.
  fn client(plan: ClientPlan, peer_direct: Vec<SocketAddr>) -> ClientPaths {
    ClientPaths::new(Instant::now(), nonce(), secret(), plan, peer_direct)
  }

  #[test]
  fn path_kinds_round_trip_through_their_names() {
    for path_kind in [
      PathKind::Direct,
      PathKind::Punched,
      PathKind::Relayed,
      PathKind::Fallback,
    ] {
      assert_eq!(path_kind.to_string().parse::<PathKind>(), Ok(path_kind));
    }
    assert_eq!("punch".parse::<PathKind>(), Err(InvalidValue));
    // The fallback order is the enum's, which the racer relies on.
    assert!(PathKind::Direct < PathKind::Punched);
    assert!(PathKind::Punched < PathKind::Relayed);
  }

  /// The routability judgment: anything global is worth a dial, and a
  /// private address only when this host shares its block.
  #[test]
  fn private_candidates_need_a_shared_block() {
    let home = [ip("192.168.1.50")];
    assert!(plausible(addr("198.51.100.7:60123"), &home));
    assert!(plausible(addr("192.168.1.9:60123"), &home));
    assert!(!plausible(addr("10.0.0.5:60123"), &home));
    assert!(!plausible(addr("172.20.1.1:60123"), &home));
    assert!(!plausible(addr("[fd00::1]:60123"), &home));
    assert!(plausible(addr("[2001:db8::1]:60123"), &home));
    // A host on the same private block reaches it; a host with no
    // addresses at all has no evidence and tries anyway.
    assert!(plausible(addr("10.0.0.5:60123"), &[ip("10.9.9.9")]));
    assert!(plausible(addr("[fd00::1]:60123"), &[ip("fd12::4")]));
    assert!(!plausible(addr("10.0.0.5:60123"), &[]));
  }

  /// A client with no helper and nothing routable to dial says so at
  /// once rather than spending the establishment budget on it.
  #[test]
  fn a_hopeless_candidate_set_is_futile_without_a_helper() {
    let now = Instant::now();
    let plan = ClientPlan {
      local_ips: vec![ip("192.168.1.50")],
      helper_expected: true,
      ..ClientPlan::default()
    };
    let mut paths = ClientPaths::new(
      now,
      nonce(),
      secret(),
      plan,
      vec![addr("10.10.0.2:60123")],
    );
    // While the helper might still answer, nothing is decided.
    assert_eq!(paths.futile(), None);
    paths.on_helper(now, Vec::new());
    let reason = paths.futile().expect("a hopeless set must be futile");
    assert!(reason.contains("10.10.0.2:60123"), "{reason}");
    // A helper makes the relayed path available whatever the direct set
    // looks like.
    let mut paths = ClientPaths::new(
      now,
      nonce(),
      secret(),
      ClientPlan {
        local_ips: vec![ip("192.168.1.50")],
        helper_expected: true,
        ..ClientPlan::default()
      },
      vec![addr("10.10.0.2:60123")],
    );
    paths.on_helper(now, vec![addr("198.51.100.7:60123")]);
    assert_eq!(paths.futile(), None);
  }

  /// The filter reads an address, not a spelling of one.
  ///
  /// A wire line's `addr=` is parsed by `SocketAddr`, which accepts the
  /// v4-mapped v6 form of every v4 address, so a peer that wants this
  /// host to probe its own loopback has only to write it that way.
  #[test]
  fn martians_are_refused_however_they_are_spelled() {
    let refused = [
      "127.0.0.1:22",
      "[::1]:22",
      "[::ffff:127.0.0.1]:22",
      "224.0.0.1:1234",
      "[::ffff:224.0.0.1]:1234",
      "255.255.255.255:9",
      "[::ffff:255.255.255.255]:9",
      "0.0.0.0:9",
      "[::]:9",
      "[::ffff:0.0.0.0]:9",
      "169.254.1.2:60123",
      "[::ffff:169.254.1.2]:60123",
      "[fe80::1]:60123",
      "198.51.100.1:0",
    ];
    for martian in refused {
      assert!(!is_dialable(addr(martian), false), "dialable: {martian}");
    }
    // Only loopback answers to `allow_loopback`, in either spelling.
    for local in ["127.0.0.1:22", "[::1]:22", "[::ffff:127.0.0.1]:22"] {
      assert!(
        is_dialable(addr(local), true),
        "refused a local peer: {local}"
      );
    }
    for martian in ["224.0.0.1:1234", "[::ffff:169.254.1.2]:60123"] {
      assert!(!is_dialable(addr(martian), true), "dialable: {martian}");
    }
    for real in [
      "198.51.100.1:60123",
      "[2001:db8::1]:60123",
      "[::ffff:198.51.100.1]:60123",
      "10.0.0.1:60123",
      "[fd00::1]:60123",
    ] {
      assert!(is_dialable(addr(real), false), "refused a peer: {real}");
    }
  }

  /// Every address establishment acts on passes the same martian filter,
  /// whichever channel carried it.
  ///
  /// A candidate that arrives over signaling is exactly as unverified
  /// as the connect line's hints -- more so, since a hostile helper can
  /// launder one through an honest peer.
  #[test]
  fn signaled_martian_candidates_are_never_dialed() {
    let martians = [
      "224.0.0.1:60123",
      "255.255.255.255:60123",
      "127.0.0.1:60123",
      "0.0.0.0:60123",
      "198.51.100.9:0",
      "[ff02::1]:60123",
      "[::]:60123",
      "169.254.10.20:60123",
      "[fe80::1]:60123",
      "[::ffff:127.0.0.1]:60123",
      "[::ffff:224.0.0.1]:60123",
      "[::ffff:255.255.255.255]:60123",
      "[::ffff:0.0.0.0]:60123",
      "[::ffff:169.254.10.20]:60123",
    ];
    for kind in [CandidateKind::Direct, CandidateKind::Reflexive] {
      let mut paths = client(ClientPlan::default(), Vec::new());
      for martian in martians {
        paths.on_signal(&Signal::candidate(nonce(), kind, addr(martian)));
      }
      // Reach the punched stage, where every candidate gathered so far
      // is dialed and probed.
      let mut now = Instant::now();
      paths.on_helper(now, Vec::new());
      for _ in 0..8 {
        now += Duration::from_millis(500);
        paths.poll(now);
      }
      let dialed: Vec<String> = paths
        .take_events()
        .into_iter()
        .filter_map(|event| match event {
          PathEvent::Dial { addr, .. } => Some(addr.to_string()),
          _ => None,
        })
        .collect();
      assert!(dialed.is_empty(), "{kind} martians were dialed: {dialed:?}");
      let probed: Vec<String> = paths
        .take_probes()
        .into_iter()
        .map(|(_, to)| to.to_string())
        .collect();
      assert!(probed.is_empty(), "{kind} martians were probed: {probed:?}");
    }
  }

  /// A candidate this host is unlikely to route to is still dialed.
  ///
  /// The racer dials the connect line's candidates whatever `plausible`
  /// says, so filtering them out of the punch's reissue would abandon a
  /// working handshake a second into the session and never try again.
  #[test]
  fn an_implausible_candidate_is_still_dialed_as_a_punched_path() {
    let elsewhere = addr("10.0.0.5:60123");
    let mut paths = client(
      ClientPlan {
        local_ips: vec![ip("192.168.1.50")],
        helper_expected: true,
        ..ClientPlan::default()
      },
      vec![elsewhere],
    );
    assert!(!plausible(elsewhere, &[ip("192.168.1.50")]));
    let mut now = Instant::now();
    // A helper answers, so establishment is not futile and goes on
    // through its stages.
    paths.on_helper(now, vec![addr("198.51.100.7:60123")]);
    let mut dialed = Vec::new();
    for _ in 0..24 {
      now += Duration::from_millis(250);
      paths.poll(now);
      dialed.extend(paths.take_events().into_iter().filter_map(|event| {
        match event {
          PathEvent::Dial { addr, path_kind } => Some((addr, path_kind)),
          _ => None,
        }
      }));
    }
    assert!(
      dialed.contains(&(elsewhere, PathKind::Punched)),
      "the punch never reissued the destination's own address: {dialed:?}"
    );
  }

  /// A loopback candidate is a martian unless the destination really is
  /// this host, which is the same evidence the connect line's hints are
  /// judged by.
  #[test]
  fn loopback_candidates_need_a_local_destination() {
    let mut paths = client(
      ClientPlan {
        allow_loopback: true,
        ..ClientPlan::default()
      },
      vec![addr("127.0.0.1:60123")],
    );
    let mut now = Instant::now();
    paths.on_helper(now, Vec::new());
    for _ in 0..8 {
      now += Duration::from_millis(500);
      paths.poll(now);
    }
    let local = addr("127.0.0.1:60123");
    assert!(paths.take_events().iter().any(
      |event| matches!(event, PathEvent::Dial { addr, .. } if *addr == local)
    ));
  }

  /// The punch target list is the one address list a peer supplies that
  /// is used verbatim, so it takes the same bound and the same filter
  /// as every other: one line inside the protocol's 8 KiB must not turn
  /// into hundreds of probes per round, aimed wherever it named.
  #[test]
  fn punch_targets_are_bounded_and_filtered() {
    let now = Instant::now();
    let mut dest = DestinationPaths::new(nonce());
    let mut peers: Vec<SocketAddr> = (1..=40)
      .map(|n| addr(&format!("198.51.100.{n}:60123")))
      .collect();
    peers.push(addr("255.255.255.255:9"));
    peers.push(addr("127.0.0.1:22"));
    peers.push(addr("224.0.0.1:60123"));
    peers.push(addr("0.0.0.0:60123"));
    peers.push(addr("198.51.100.1:0"));
    dest.on_signal(now, &Signal::punch(nonce(), 1, peers));
    dest.poll(now);
    let probed: Vec<SocketAddr> =
      dest.take_probes().into_iter().map(|(_, to)| to).collect();
    assert_eq!(probed.len(), MAX_ADDR_HINTS);
    for target in &probed {
      assert!(
        is_dialable(*target, false),
        "a martian was probed: {target}"
      );
    }
  }

  /// A peer that never stops advertising cannot grow this side's work:
  /// candidate lists are bounded, the surplus is dropped, and the
  /// reflexive class takes the tighter budget of the two.
  #[test]
  fn candidate_lists_are_bounded() {
    let mut paths = client(ClientPlan::default(), Vec::new());
    for n in 1..=40 {
      for kind in [CandidateKind::Reflexive, CandidateKind::Direct] {
        paths.on_signal(&Signal::candidate(
          nonce(),
          kind,
          addr(&format!("198.51.100.{n}:60123")),
        ));
      }
    }
    assert_eq!(paths.peer_reflexive.len(), MAX_REFLEXIVE_HINTS);
    assert_eq!(paths.peer_direct.len(), MAX_ADDR_HINTS);
    const { assert!(MAX_REFLEXIVE_HINTS < MAX_ADDR_HINTS) };
  }

  /// What a hostile jump host can aim this side's traffic at is
  /// bounded, and by a smaller bound than the peer's own addresses
  /// (`MAX_REFLEXIVE_HINTS`). The design's answer to a lying reflector
  /// is not to trust it less (a pinned handshake decides what connects)
  /// but to cap what it costs: a few probes and a handshake per
  /// address, for a few addresses.
  #[test]
  fn a_lying_reflector_aims_a_bounded_amount_of_traffic() {
    let mut paths = client(ClientPlan::default(), Vec::new());
    for n in 1..=40 {
      paths.on_signal(&Signal::candidate(
        nonce(),
        CandidateKind::Reflexive,
        addr(&format!("203.0.113.{n}:60123")),
      ));
    }
    let mut now = Instant::now();
    paths.on_helper(now, Vec::new());
    let (mut dials, mut probes) = (0, 0);
    for _ in 0..200 {
      now += Duration::from_millis(100);
      paths.poll(now);
      dials += paths
        .take_events()
        .iter()
        .filter(|event| matches!(event, PathEvent::Dial { .. }))
        .count();
      probes += paths.take_probes().len();
    }
    assert_eq!(dials, MAX_REFLEXIVE_HINTS);
    assert_eq!(probes, MAX_REFLEXIVE_HINTS * PUNCH_ROUNDS as usize);
  }

  /// A bastion is the design's declared untrusted party, and the
  /// addresses it names in its ready line are the one address list that
  /// arrives from it directly. An address that cannot be a helper is
  /// refused where it enters, and a ready line made of nothing else is
  /// the degraded case, which the client must report at once rather than
  /// spend the establishment budget on.
  #[test]
  fn a_helper_naming_only_martians_reads_as_no_helper() {
    let now = Instant::now();
    let mut paths = client(
      ClientPlan {
        helper_expected: true,
        local_ips: vec![ip("192.168.1.50")],
        ..ClientPlan::default()
      },
      vec![addr("10.10.0.2:60123")],
    );
    paths.on_helper(
      now,
      vec![
        addr("127.0.0.1:53"),
        addr("[::ffff:127.0.0.1]:5353"),
        addr("169.254.1.2:60123"),
        addr("0.0.0.0:60123"),
      ],
    );
    assert!(
      paths.take_probes().is_empty(),
      "a martian helper address was probed"
    );
    assert!(
      paths.take_signals().is_empty(),
      "a martian helper address was announced to the destination"
    );
    assert!(!paths.report().helper_offered);
    assert!(
      paths.futile().is_some(),
      "a helper that named nothing usable still made establishment wait"
    );
  }

  /// Signaling for another session is ignored outright, in both
  /// directions: concurrent sessions share nothing but the channel's
  /// shape.
  #[test]
  fn another_sessions_signaling_is_ignored() {
    let now = Instant::now();
    let other = SessionNonce::from_bytes([0x22; 16]);
    let mut paths = ClientPaths::new(
      now,
      nonce(),
      secret(),
      ClientPlan::default(),
      Vec::new(),
    );
    paths.on_signal(&Signal::done(other));
    assert!(!paths.report().peer_done);

    let mut dest = DestinationPaths::new(nonce());
    dest.on_signal(
      now,
      &Signal::punch(other, 1, vec![addr("198.51.100.1:41000")]),
    );
    dest.poll(now);
    assert!(dest.take_probes().is_empty(), "punched for another session");
  }

  /// A driver sleeps until the instant `poll` names, so an instant
  /// already behind it is a spin rather than a wait.
  ///
  /// Walked through every stage of establishment with the helper answer
  /// withheld, which is the state that holds the punch back while its
  /// own deadline has passed.
  #[test]
  fn establishment_never_asks_to_be_woken_in_the_past() {
    let start = Instant::now();
    let mut paths = ClientPaths::new(
      start,
      nonce(),
      secret(),
      ClientPlan {
        self_addrs: vec![addr("192.168.1.50:41000")],
        local_ips: vec![ip("192.168.1.50")],
        helper_expected: true,
        ..ClientPlan::default()
      },
      vec![addr("198.51.100.7:60123")],
    );
    let mut now = start;
    let mut steps = 0;
    while let Some(deadline) = paths.poll(now) {
      assert!(
        deadline > now,
        "establishment asked to be woken {:?} in the past",
        now - deadline
      );
      paths.take_signals();
      paths.take_probes();
      paths.take_events();
      now = deadline;
      steps += 1;
      assert!(steps < 1000, "establishment never settles");
    }

    // The destination's half, driven the same way by the rendezvous.
    let mut dest = DestinationPaths::new(nonce());
    dest.on_signal(
      start,
      &Signal::helper(nonce(), addr("198.51.100.7:60123"), secret()),
    );
    dest.on_signal(
      start,
      &Signal::punch(nonce(), 1, vec![addr("192.168.1.50:41000")]),
    );
    let mut now = start;
    let mut steps = 0;
    while let Some(deadline) = dest.poll(now) {
      assert!(deadline > now, "the destination asked for a past instant");
      dest.take_signals();
      dest.take_probes();
      now = deadline;
      steps += 1;
      assert!(steps < 1000, "the destination never settles");
    }
  }

  /// The reflexive match is the transaction id and nothing else, so a
  /// forged answer to a probe the peer never sent reports nothing.
  #[test]
  fn only_this_transactions_answer_is_believed() {
    let label = ProbeLabel::to_helper(nonce(), PeerRole::Client);
    let reflector = addr("198.51.100.7:60123");
    let mut probes = Probes::new(label, Some(secret()), false);
    probes.reflect(Instant::now(), reflector, true);
    let forged = BindingTransaction::new(label, &secret());
    let answer = match crate::stun::classify(forged.request()) {
      crate::stun::Datagram::Binding(request) => request
        .reflect(addr("203.0.113.9:41000"), &secret())
        .unwrap(),
      other => panic!("not a binding request: {other:?}"),
    };
    assert_eq!(probes.on_probe(reflector, &answer), None);
    assert!(probes.reflecting());
  }

  /// A reflection is believed only from the reflector it was asked of,
  /// which is STUN's own response rule and costs nothing here: the
  /// driver has the source address in hand.
  #[test]
  fn an_answer_from_the_wrong_source_is_ignored() {
    let label = ProbeLabel::to_helper(nonce(), PeerRole::Client);
    let reflector = addr("198.51.100.7:60123");
    let mut probes = Probes::new(label, Some(secret()), false);
    probes.reflect(Instant::now(), reflector, true);
    let request = probes.reflections[0].transaction.request().to_vec();
    let answer = match crate::stun::classify(&request) {
      crate::stun::Datagram::Binding(request) => request
        .reflect(addr("203.0.113.9:41000"), &secret())
        .unwrap(),
      other => panic!("not a binding request: {other:?}"),
    };
    // The reflector's own transaction, answered from somewhere else.
    assert_eq!(probes.on_probe(addr("192.0.2.66:60123"), &answer), None);
    assert!(probes.reflecting());
    assert_eq!(
      probes.on_probe(reflector, &answer),
      Some((reflector, addr("203.0.113.9:41000")))
    );
  }

  /// The reflector table is bounded like every other list built from
  /// somebody else's answer (`MAX_REFLECTORS`).
  #[test]
  fn the_reflector_table_is_bounded() {
    let label = ProbeLabel::to_helper(nonce(), PeerRole::Client);
    let mut probes = Probes::new(label, Some(secret()), false);
    let now = Instant::now();
    for n in 1..=40 {
      probes.reflect(now, addr(&format!("198.51.100.{n}:3478")), false);
    }
    assert_eq!(probes.reflections.len(), MAX_REFLECTORS);
  }

  /// One helper address, once one answers, and it alone keeps being probed
  /// (see `Probes::settle_helper_addr`).
  #[test]
  fn one_helper_addr_wins_and_keeps_being_probed() {
    let now = Instant::now();
    let addrs = [addr("198.51.100.7:60123"), addr("10.9.0.7:60123")];
    let mut paths = client(
      ClientPlan {
        helper_expected: true,
        ..ClientPlan::default()
      },
      vec![addr("203.0.113.5:60123")],
    );
    paths.on_helper(now, addrs.to_vec());
    paths.poll(now);
    let asked: Vec<SocketAddr> =
      paths.take_probes().into_iter().map(|(_, to)| to).collect();
    assert_eq!(asked, addrs, "both addresses are asked to begin with");

    // The second address answers first, so it is the one this client
    // keeps.
    let request = paths.probes.reflections[1].transaction.request().to_vec();
    let answer = match crate::stun::classify(&request) {
      crate::stun::Datagram::Binding(request) => {
        request.reflect(addr("5.5.5.5:41000"), &secret()).unwrap()
      }
      other => panic!("not a binding request: {other:?}"),
    };
    paths.on_probe(&Probe {
      from: addrs[1],
      datagram: answer,
    });
    assert_eq!(paths.report().helper, Some(addrs[1]));

    // From here the other address is never asked again, and every punch
    // round shows the chosen one where this client is.
    let mut now = now;
    let mut rounds = 0;
    for _ in 0..24 {
      now += Duration::from_millis(250);
      paths.poll(now);
      let asked: Vec<SocketAddr> =
        paths.take_probes().into_iter().map(|(_, to)| to).collect();
      assert!(
        !asked.contains(&addrs[0]),
        "the abandoned address was asked"
      );
      rounds += usize::from(asked.contains(&addrs[1]));
    }
    assert!(rounds > 1, "the chosen address was probed {rounds} times");
  }
}
