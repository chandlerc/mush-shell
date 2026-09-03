// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! What a session does about its path once it has one.
//!
//! Why a session starts on the relay and moves off it, what the two
//! proofs are for, and why the relay is kept afterwards, are the design
//! doc's "Upgrading from relay to direct"; this module is that policy.
//!
//! The two proofs a candidate needs, in order:
//!
//! 1. A signed probe round trip on the candidate path, answered by
//!    [`DestinationUpgrade`] from the socket its session runs on.
//! 2. The destination's `PATH_CHALLENGE` after the switch, awaited
//!    within [`UpgradePolicy::confirm`]. It is read from quinn's
//!    post-decryption frame counters ([`quinn::ConnectionStats`]) and
//!    never from the shim's datagram count, which is the invariant that
//!    makes it unforgeable: a datagram merely arriving from an address
//!    is a claim, and a counted challenge is proof the destination
//!    received something over the new path and answered over it.
//!
//! Proof 2 exists because liveness alone is never enough: a middlebox
//! that passes a 60-byte STUN exchange and drops 1200-byte QUIC packets
//! is a real shape.
//!
//! # Downgrading, and why the relay is kept
//!
//! The relay stays a path in the map and the helper stays alive for
//! [`UpgradePolicy::helper_grace`] after a switch, with the client
//! keeping both paths active: a probe round at the direct path every
//! [`UpgradePolicy::probe_interval`], a keepalive at the helper every
//! [`UpgradePolicy::relay_keepalive`].
//!
//! A path is alive while *either* its probes or the session's own ACKs
//! have answered within [`UpgradePolicy::misses`] rounds. Both are
//! needed: a probe round trip is two small datagrams, so at loss rates
//! QUIC tolerates, that many rounds go unanswered often enough to
//! matter, while an ACK says the path carried something this side sent
//! and carried the answer back. The probes decide for an idle session
//! and the session itself for a busy one.
//!
//! Once a direct path has carried the session through the grace the
//! helper is released and the relay is gone; from there a failing path
//! is the ordinary roaming case, which [`crate::roaming`] owns.
//!
//! # Hysteresis
//!
//! A path that takes the session and loses it is not tried again for
//! [`UpgradePolicy::retry_backoff`] times the number of times it has
//! failed, and after [`UpgradePolicy::max_attempts`] failures not at
//! all. Without that, a path that answers probes and drops session
//! traffic would flap the session between paths forever, costing the
//! destination a congestion reset (RFC 9000 section 9.4) every time. A
//! downgrade also puts the session back on the relay *and* restarts the
//! grace, so the fallback a flapping path keeps reaching for stays
//! there.
//!
//! That budget is for a path that cannot carry the session, so
//! confirming spends it back: a network that later takes away a path
//! the destination validated is not evidence against the path. Only
//! failures to confirm accumulate, so a path can be retired for never
//! working and never for having worked.
//!
//! # What an arriving probe costs
//!
//! Both sides handle probes from whoever finds the session's socket:
//! the labeling nonce travels in the clear, so anyone who has watched a
//! probe go past can generate well-formed ones and only the signature
//! refuses them. Handling a probe is a keyed hash and answering one is
//! another, so both are budgeted -- per source address first and across
//! the session second, the shape the helper limits reflection with
//! ([`crate::helper::HelperLimits`]). One address flooding then spends
//! only its own share, which keeps a flood from blocking the upgrade: on
//! the destination by using up the budget for the answers the client's
//! validation needs, and on the client by mixing those answers into a
//! flood of datagrams that all need validating.
//!
//! # Keeping the relay reachable
//!
//! The helper forwards to the address a peer's last signed probe
//! arrived from, so a mapping that moves takes the relay with it. Two
//! things move one: a stall rebind ([`crate::roaming`]) and a NAT that
//! rebinds under an idle flow. The client answers both the same way --
//! it re-registers, immediately on a rebind
//! ([`crate::traversal::TraversalSocket::moved`]) and on a keepalive
//! cadence otherwise -- which is what makes a relayed session survive a
//! roam instead of ending at one.
//!
//! The destination does the mirror image, and it matters more there: it
//! may be behind a NAT strict enough that the helper can only reach it
//! through a pinhole the destination opened itself. Its heartbeat keeps
//! that pinhole fresh, and lets a helper that restarted relearn where to
//! forward without either peer being told anything.
//!
//! That heartbeat is the one thing here that spends somebody else's
//! resources -- a process and a UDP port on a third party's bastion --
//! so it is bounded by evidence rather than by the connection alone.
//! Mush sets no idle timeout (see [`crate::transport`]), so a client
//! whose machine vanished leaves a connection open forever, and a
//! heartbeat conditioned on that alone would hold the bastion for good:
//! the helper reads one as the session still being there
//! ([`crate::helper::HelperService::poll`]). So the destination stops
//! heartbeating after [`UpgradePolicy::silence`] with nothing arriving
//! from the client, and starts again the moment something does -- the
//! offline-and-return shape the design keeps working, with a limit on
//! the shape it does not.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{debug, trace, warn};

use crate::bootstrap::{SessionNonce, SessionSecret};
use crate::helper::ProbeBudget;
use crate::path::{PathKind, earliest, emit, is_dialable, wait_until};
use crate::stun::{
  self, Aim, BindingTransaction, Datagram, PeerRole, ProbeLabel,
};
use crate::traversal::{Probe, TraversalSocket};

/// Default gap between probe rounds while a session is looking for a
/// better path, and the granularity of the liveness a switch rests on.
///
/// Named for the round rather than the probe because
/// [`crate::transport::DEFAULT_PROBE_INTERVAL`] is a different cadence
/// on the same connection: the stall prober's.
pub const DEFAULT_ROUND_INTERVAL: Duration = Duration::from_secs(2);

/// Default length of the dense probing that follows establishment,
/// while the pinholes establishment opened are still fresh.
pub const DEFAULT_PUNCH_WINDOW: Duration = Duration::from_secs(30);

/// Default gap between rounds once the dense window has passed.
///
/// A relayed session keeps looking for the whole of its life, because
/// the network it could not punch through at second one is often a
/// network that changes later (a route comes back, a VPN drops, a
/// laptop moves). Comfortably inside the 30 seconds RFC 4787 asks NATs
/// to keep an idle UDP mapping for, so both sides' rounds arrive in each
/// other's open window without either being told when the other probes.
pub const DEFAULT_PUNCH_RETRY: Duration = Duration::from_secs(15);

/// Default gap between keepalive probes at the jump helper, which are
/// what keep a relayed session's registration and pinhole current.
pub const DEFAULT_RELAY_KEEPALIVE: Duration = Duration::from_secs(15);

/// Default time a path that has just taken the session has to be
/// validated by the destination before the session goes back.
///
/// It has to cover a QUIC path validation and the round trip that
/// answers it, on a path whose RTT is unknown, plus a retransmission.
pub const DEFAULT_CONFIRM: Duration = Duration::from_secs(3);

/// Default time the relay is kept as a fallback after an upgrade,
/// before the jump helper is released.
pub const DEFAULT_HELPER_GRACE: Duration = Duration::from_secs(30);

/// Default backoff before a path that lost the session may take it
/// again, multiplied by the number of times it has lost it.
pub const DEFAULT_RETRY_BACKOFF: Duration = Duration::from_secs(10);

/// Default number of times one path may take the session and fail to
/// prove itself before the session stops trying it.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;

/// Default number of unanswered probe rounds that make a path dead.
pub const DEFAULT_MISSES: u32 = 3;

/// Default time the destination goes on heartbeating the relay with
/// nothing arriving from the client.
///
/// Long enough that an outage the session is meant to survive does not
/// reach it -- a roam, a suspend, a route flapping for minutes -- and
/// short enough that a client that never comes back costs a third
/// party's bastion minutes rather than forever. A limit on silence, not
/// a timeout: anything from the client starts the heartbeat again.
pub const DEFAULT_SILENCE: Duration = Duration::from_secs(300);

/// How much probe work one side of a session will do per second, and
/// the burst it tolerates.
///
/// Handling a probe is a signature check and answering one adds a
/// response no larger than the request (see [`crate::stun`]), so
/// neither amplification nor state is on offer; the budget bounds the
/// HMAC work an unauthenticated flood can cause. A session's own probes
/// are a handful per second at their densest, far below this.
const PROBES_PER_SECOND: f64 = 20.0;
const PROBE_BURST: f64 = 40.0;

/// The same, per source address ([`ProbeBudget`]).
const SOURCE_PROBES_PER_SECOND: f64 = 10.0;
const SOURCE_PROBE_BURST: f64 = 20.0;

/// How many source addresses one session tracks budgets for. It hears
/// probes from a handful -- its peer's, the helper's, and whatever else
/// finds the socket -- and anything past that is the flood
/// [`ProbeBudget`]'s eviction rule is for.
const MAX_PROBE_SOURCES: usize = 32;

/// How many addresses one side will hold for the other. The same bound
/// establishment's candidate lists carry, for the same reason.
const MAX_PEERS: usize = crate::server::MAX_ADDR_HINTS;

/// Timing policy for the upgrade. `Default` is the shipped policy;
/// construct with struct update syntax to override values.
#[derive(Debug, Clone, Copy)]
pub struct UpgradePolicy {
  /// Gap between probe rounds while the pinholes are fresh.
  pub probe_interval: Duration,
  /// How long that dense probing lasts.
  pub punch_window: Duration,
  /// Gap between rounds afterwards.
  pub punch_retry: Duration,
  /// Gap between keepalive probes at the jump helper.
  pub relay_keepalive: Duration,
  /// How long a path that took the session has to carry something.
  pub confirm: Duration,
  /// How long the relay is kept as a fallback after an upgrade.
  pub helper_grace: Duration,
  /// Backoff before a failed path may be tried again, per failure.
  pub retry_backoff: Duration,
  /// How many times one path may fail to confirm before it is retired.
  pub max_attempts: u32,
  /// How many unanswered rounds make a path dead.
  pub misses: u32,
  /// How long the destination keeps the relay path active with nothing
  /// arriving from the client.
  pub silence: Duration,
}

impl Default for UpgradePolicy {
  fn default() -> Self {
    Self {
      probe_interval: DEFAULT_ROUND_INTERVAL,
      punch_window: DEFAULT_PUNCH_WINDOW,
      punch_retry: DEFAULT_PUNCH_RETRY,
      relay_keepalive: DEFAULT_RELAY_KEEPALIVE,
      confirm: DEFAULT_CONFIRM,
      helper_grace: DEFAULT_HELPER_GRACE,
      retry_backoff: DEFAULT_RETRY_BACKOFF,
      max_attempts: DEFAULT_MAX_ATTEMPTS,
      misses: DEFAULT_MISSES,
      silence: DEFAULT_SILENCE,
    }
  }
}

impl UpgradePolicy {
  /// How long a path may go unanswered before it counts as dead.
  fn dead_after(&self) -> Duration {
    self.probe_interval.saturating_mul(self.misses)
  }
}

/// What the maintenance phase inherits from establishment.
#[derive(Debug, Clone)]
pub struct Inherited {
  /// The session's nonce, which labels every probe.
  pub nonce: SessionNonce,
  /// What labeled probes are signed with. The destination learns it
  /// from the client's helper announcement, so it is absent exactly
  /// when there was no helper -- and then there is no relay either, and
  /// nothing here to do.
  pub secret: Option<SessionSecret>,
  /// The helper address this peer registered with.
  pub helper: Option<SocketAddr>,
  /// The addresses the other peer can be probed at.
  pub peers: Vec<SocketAddr>,
  /// Whether a loopback address can name the peer.
  pub allow_loopback: bool,
}

impl Inherited {
  /// The same addresses in the form the session's path map holds them.
  ///
  /// A v6-bound socket sees a v4 peer as `::ffff:a.b.c.d`, which is
  /// what a probe's source address and a path's own address are in
  /// ([`crate::traversal::TraversalSocket::normalize`]), while the
  /// establishment hands these over exactly as they were signaled.
  /// Comparing the two forms would match nothing, and everything below
  /// is comparisons: a probe against the candidate it answers, a
  /// candidate against the path the map opened for it.
  fn normalized(self, socket: &TraversalSocket) -> Self {
    Self {
      helper: self.helper.map(|addr| socket.normalize(addr)),
      peers: self
        .peers
        .into_iter()
        .map(|addr| socket.normalize(addr))
        .collect(),
      ..self
    }
  }
}

/// The budget each side limits probe handling with: the same shape and
/// reason as the jump helper's reflection limits ([`ProbeBudget`]).
fn probe_budget(now: Instant) -> ProbeBudget {
  ProbeBudget::new(
    now,
    SOURCE_PROBES_PER_SECOND,
    SOURCE_PROBE_BURST,
    PROBES_PER_SECOND,
    PROBE_BURST,
    MAX_PROBE_SOURCES,
  )
}

/// What the session's own connection has heard from its peer, read from
/// quinn's frame counters.
///
/// Every one is counted after decryption, so it is liveness nobody but
/// the peer can produce: the evidence a path switch and a path's death
/// rest on, rather than the count of datagrams that merely arrived from
/// an address ([`crate::traversal::PathStatus`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Heard {
  /// ACKs from the peer: proof it is receiving what this side sends,
  /// over the path this side sends on.
  acks: u64,
  /// Path validations the peer started, which a QUIC server does
  /// exactly when its client's address changes (RFC 9000 section 9), so
  /// one arriving after a switch is the destination's own word that the
  /// new path reached it and reaches back.
  challenges: u64,
  /// Everything a live session makes its peer send, for the coarser
  /// question of whether the peer is there at all.
  frames: u64,
}

impl Heard {
  fn of(connection: &quinn::Connection) -> Self {
    let rx = connection.stats().frame_rx;
    Self {
      acks: rx.acks,
      challenges: rx.path_challenge,
      frames: rx.acks + rx.stream + rx.ping + rx.path_response,
    }
  }
}

/// What the session's path policy asks of its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeEvent {
  /// The session is now on this path, of this kind.
  Moved {
    /// The real address its datagrams go to.
    addr: SocketAddr,
    path_kind: PathKind,
  },
  /// The relay is no longer a path this session may need, so the jump
  /// helper can be released.
  HelperReleased,
}

/// One address being probed, and what its answers prove.
///
/// The transaction is rotated every round and the previous one kept, so
/// an answer is evidence about the round it belongs to (or the one
/// before it, which is how a path whose round trip outlasts the round
/// still counts as alive) rather than about any round ever.
#[derive(Debug)]
struct Probing {
  addr: SocketAddr,
  /// What its probes say: the session, this side, and which of the two
  /// services the address is ([`Aim`]), which is what keeps a probe
  /// meant for one from being replayed at the other.
  label: ProbeLabel,
  current: BindingTransaction,
  previous: Option<BindingTransaction>,
  last_answer: Option<Instant>,
}

impl Probing {
  fn new(addr: SocketAddr, label: ProbeLabel, secret: &SessionSecret) -> Self {
    Self {
      addr,
      label,
      current: BindingTransaction::new(label, secret),
      previous: None,
      last_answer: None,
    }
  }

  /// The next round's request bytes.
  fn request(&mut self, secret: &SessionSecret) -> Vec<u8> {
    let next = BindingTransaction::new(self.label, secret);
    self.previous = Some(std::mem::replace(&mut self.current, next));
    self.current.request().to_vec()
  }

  /// Feeds a datagram from this address, reporting whether it answered
  /// an outstanding round.
  fn answered(&mut self, now: Instant, datagram: &[u8]) -> bool {
    let matched = self.current.reflexive(datagram).is_some()
      || self
        .previous
        .as_ref()
        .is_some_and(|previous| previous.reflexive(datagram).is_some());
    if matched {
      self.last_answer = Some(now);
    }
    matched
  }

  /// Whether an answer arrived within `within`.
  fn alive(&self, now: Instant, within: Duration) -> bool {
    self
      .last_answer
      .is_some_and(|at| now.saturating_duration_since(at) < within)
  }
}

/// One candidate path the session may move onto, with the hysteresis
/// that keeps it from being tried forever.
#[derive(Debug)]
struct Trial {
  probe: Probing,
  /// How many times it has taken the session and lost it.
  attempts: u32,
  /// Not tried again before this.
  blocked_until: Option<Instant>,
  /// Out of attempts: never tried again.
  retired: bool,
}

impl Trial {
  fn ready(&self, now: Instant, within: Duration) -> bool {
    !self.retired
      && self.blocked_until.is_none_or(|at| now >= at)
      && self.probe.alive(now, within)
  }

  /// Confirming gives the attempts back; see the module docs on
  /// hysteresis.
  fn confirmed(&mut self) {
    self.attempts = 0;
  }

  fn probeable(&self, now: Instant) -> bool {
    !self.retired && self.blocked_until.is_none_or(|at| now >= at)
  }
}

/// Where the session is, from the policy's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
  /// On the relay, looking for something better.
  Relayed,
  /// Just moved onto `addr`, waiting for the destination to validate
  /// the move.
  Confirming {
    addr: SocketAddr,
    since: Instant,
    /// Path validations the destination had started when the switch
    /// happened; one more is what says this one reached it.
    challenges: u64,
  },
  /// On `addr`, with the relay held as a fallback until `until`.
  Upgraded {
    addr: SocketAddr,
    until: Instant,
    /// ACKs heard at the last poll, so that the session's own traffic
    /// counts as the path answering.
    acks: u64,
    /// When it last carried something, by the ACKs above.
    carried: Instant,
  },
  /// On a direct path with the helper released. Nothing left to do.
  Settled,
}

impl Phase {
  fn addr(self) -> Option<SocketAddr> {
    match self {
      Self::Confirming { addr, .. } | Self::Upgraded { addr, .. } => Some(addr),
      Self::Relayed | Self::Settled => None,
    }
  }
}

/// What the policy asks the driver to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
  /// Offer this path to the map and move the session onto it.
  Switch {
    addr: SocketAddr,
    path_kind: PathKind,
  },
  /// Release the jump helper.
  Release,
}

/// The client's upgrade policy as a pure state machine.
///
/// Time-parametric like the rest of the traversal machinery: every
/// entry point takes the current [`Instant`] and what it decides to
/// send goes into an outbox the driver empties, so the whole policy is
/// testable without a socket or a clock.
#[derive(Debug)]
struct ClientPolicy {
  secret: SessionSecret,
  policy: UpgradePolicy,
  /// The relay path carrying the session, and the keepalive that keeps
  /// its registration current.
  relay: Probing,
  trials: Vec<Trial>,
  phase: Phase,
  /// When the dense probing after establishment stops.
  dense_until: Instant,
  next_round: Instant,
  next_relay: Instant,
  /// What handling arriving probes may cost.
  budget: ProbeBudget,
  outbox: Vec<(Vec<u8>, SocketAddr)>,
  actions: Vec<Action>,
}

impl ClientPolicy {
  /// A policy for a session the relay is carrying, or `None` when there
  /// is no relay under it and so nothing to keep active or move off.
  fn new(
    now: Instant,
    inherited: Inherited,
    policy: UpgradePolicy,
  ) -> Option<Self> {
    let (helper, secret) = (inherited.helper?, inherited.secret?);
    // Two labels, because a candidate and the helper are two different
    // services (see `Probing::label`).
    let at_helper = ProbeLabel::to_helper(inherited.nonce, PeerRole::Client);
    let at_peer = ProbeLabel::to_peer(inherited.nonce, PeerRole::Client);
    // Establishment gathers a peer's direct and reflexive candidates
    // separately and an unNATed peer offers the same address as both,
    // so what arrives here is not a set.
    let mut addrs: Vec<SocketAddr> = Vec::new();
    for &addr in &inherited.peers {
      if addr != helper
        && is_dialable(addr, inherited.allow_loopback)
        && !addrs.contains(&addr)
        && addrs.len() < MAX_PEERS
      {
        addrs.push(addr);
      }
    }
    let trials = addrs
      .into_iter()
      .map(|addr| Trial {
        probe: Probing::new(addr, at_peer, &secret),
        attempts: 0,
        blocked_until: None,
        retired: false,
      })
      .collect();
    Some(Self {
      secret,
      policy,
      relay: Probing::new(helper, at_helper, &secret),
      trials,
      phase: Phase::Relayed,
      dense_until: now + policy.punch_window,
      next_round: now,
      next_relay: now + policy.relay_keepalive,
      budget: probe_budget(now),
      outbox: Vec::new(),
      actions: Vec::new(),
    })
  }

  /// Advances the policy against what the session's own connection has
  /// heard, and reports when to look again.
  fn poll(&mut self, now: Instant, heard: Heard) -> Option<Instant> {
    let mut downgraded = false;
    match self.phase {
      Phase::Confirming {
        addr,
        since,
        challenges,
      } => {
        if heard.challenges > challenges {
          debug!(%addr, "the destination validated the direct path; upgraded");
          if let Some(trial) = self.trial_mut(addr) {
            trial.confirmed();
          }
          self.phase = Phase::Upgraded {
            addr,
            until: now + self.policy.helper_grace,
            acks: heard.acks,
            carried: now,
          };
        } else if now.saturating_duration_since(since) >= self.policy.confirm {
          self.give_up(now, addr, "the destination never validated it");
          downgraded = true;
        }
      }
      Phase::Upgraded {
        addr,
        until,
        acks,
        carried,
      } => {
        // Either proof will do: the probes answer for an idle session,
        // the session's own ACKs for a busy one on a path too lossy for
        // a two-datagram round trip to be reliable evidence.
        let carried = match heard.acks > acks {
          true => now,
          false => carried,
        };
        let dead = self.policy.dead_after();
        let answering = self
          .trial(addr)
          .is_some_and(|trial| trial.probe.alive(now, dead));
        if !answering && now.saturating_duration_since(carried) >= dead {
          self.give_up(now, addr, "it stopped answering and stopped carrying");
          downgraded = true;
        } else {
          self.phase = Phase::Upgraded {
            addr,
            until,
            acks: heard.acks,
            carried,
          };
          if now >= until {
            debug!(%addr, "the direct path held; releasing the helper");
            self.phase = Phase::Settled;
            self.actions.push(Action::Release);
          }
        }
      }
      Phase::Relayed | Phase::Settled => {}
    }

    if now >= self.next_round {
      self.round(now);
    }
    if now >= self.next_relay && self.phase != Phase::Settled {
      let request = self.relay.request(&self.secret);
      self.outbox.push((request, self.relay.addr));
      self.next_relay = now + self.policy.relay_keepalive;
    }
    // Not after a downgrade: the relay has just been handed the session
    // back, and a sibling candidate that answered a moment ago is still
    // inside its liveness window, so taking one here would migrate the
    // session twice in one poll -- two path validations and two
    // congestion resets at the destination for no gain. The round above
    // has already set when to look again.
    if !downgraded
      && self.phase == Phase::Relayed
      && let Some(addr) = self.candidate(now)
    {
      self.take(now, addr, heard);
    }
    self.deadline(now)
  }

  /// Queues this round's probes: every candidate worth trying while the
  /// session is on the relay, and the path it is on otherwise.
  fn round(&mut self, now: Instant) {
    let gap = self.round_gap(now);
    // Destructured so the trials can be walked mutably while the outbox
    // is pushed to: generating a probe advances the trial's transaction,
    // so this is one pass over the trials rather than a list of
    // addresses looked up again one at a time.
    let Self {
      trials,
      outbox,
      secret,
      phase,
      ..
    } = self;
    let mut queue = |trial: &mut Trial| {
      let addr = trial.probe.addr;
      let request = trial.probe.request(secret);
      outbox.push((request, addr));
    };
    match *phase {
      Phase::Relayed => trials
        .iter_mut()
        .filter(|trial| trial.probeable(now))
        .for_each(&mut queue),
      Phase::Confirming { addr, .. } | Phase::Upgraded { addr, .. } => {
        if let Some(trial) =
          trials.iter_mut().find(|trial| trial.probe.addr == addr)
        {
          queue(trial);
        }
      }
      Phase::Settled => {}
    }
    self.next_round = now + gap;
  }

  /// The gap to the next round: dense while the pinholes are fresh and
  /// while a path is being watched, slow once a session has settled
  /// onto the relay and is only checking whether the network changed.
  fn round_gap(&self, now: Instant) -> Duration {
    match self.phase {
      Phase::Relayed if now >= self.dense_until => self.policy.punch_retry,
      Phase::Settled => self.policy.punch_retry,
      _ => self.policy.probe_interval,
    }
  }

  /// The first candidate that has answered recently and is not serving
  /// out a backoff. Order is establishment's preference order.
  fn candidate(&self, now: Instant) -> Option<SocketAddr> {
    self
      .trials
      .iter()
      .find(|trial| trial.ready(now, self.policy.dead_after()))
      .map(|trial| trial.probe.addr)
  }

  /// Moves the session onto `addr` and starts watching for the
  /// destination's path validation.
  fn take(&mut self, now: Instant, addr: SocketAddr, heard: Heard) {
    self.phase = Phase::Confirming {
      addr,
      since: now,
      challenges: heard.challenges,
    };
    // Watch it closely from here, whatever cadence the search was on:
    // whether it goes on answering is what decides, after the
    // confirmation, whether it keeps the session.
    self.round(now);
    // Always the punched kind of path, whichever list the address came
    // from: establishment has already dialed every candidate it had as a
    // punched path and none of them answered, so a path that works now
    // is one the background punching opened. That is the same rule
    // establishment itself reports by ([`crate::path`]).
    self.actions.push(Action::Switch {
      addr,
      path_kind: PathKind::Punched,
    });
  }

  /// Hands the session back to the relay and blocks `addr` from being
  /// tried for a while; see the module docs on hysteresis.
  fn give_up(&mut self, now: Instant, addr: SocketAddr, why: &str) {
    let backoff = self.policy.retry_backoff;
    let max = self.policy.max_attempts;
    if let Some(trial) = self.trial_mut(addr) {
      trial.attempts += 1;
      trial.probe.last_answer = None;
      trial.retired = trial.attempts >= max;
      trial.blocked_until = Some(now + backoff.saturating_mul(trial.attempts));
    }
    warn!(%addr, why, "the direct path lost the session; back to the relay");
    self.phase = Phase::Relayed;
    // The relay is the path again, so its registration is what matters
    // most; renew it now rather than at the next keepalive.
    self.next_relay = now;
    self.next_round = now;
    self.actions.push(Action::Switch {
      addr: self.relay.addr,
      path_kind: PathKind::Relayed,
    });
  }

  /// The map could not take this path, so the session cannot move onto
  /// it however well it probes.
  fn unmappable(&mut self, addr: SocketAddr) {
    if let Some(trial) = self.trial_mut(addr) {
      trial.retired = true;
    }
    debug!(%addr, "the path manager would not take the path");
    self.phase = Phase::Relayed;
  }

  fn trial(&self, addr: SocketAddr) -> Option<&Trial> {
    self.trials.iter().find(|trial| trial.probe.addr == addr)
  }

  fn trial_mut(&mut self, addr: SocketAddr) -> Option<&mut Trial> {
    self
      .trials
      .iter_mut()
      .find(|trial| trial.probe.addr == addr)
  }

  /// Feeds one probe the socket sorted out of the session's traffic.
  ///
  /// Budgeted before anything else here reads the datagram: matching an
  /// answer is a keyed hash over it, the session's socket is reachable
  /// by anyone who can find it, and the client is the side whose
  /// runtime also carries the user's session.
  fn on_probe(&mut self, now: Instant, probe: &Probe) {
    if let Err(refused) = self.budget.take(now, probe.from.ip()) {
      trace!(from = %probe.from, ?refused, "not handling a probe: budget spent");
      return;
    }
    // The relay path answers this side's keepalives and nothing reads
    // whether it did: no decision rests on the liveness of the path an
    // upgrade moves *off*. Consumed here so a keepalive response is
    // never matched against a candidate sharing the helper's address.
    if probe.from == self.relay.addr {
      return;
    }
    let Some(trial) = self.trial_mut(probe.from) else {
      return;
    };
    if trial.probe.answered(now, &probe.datagram) {
      trace!(addr = %probe.from, "a candidate path answered");
    }
  }

  /// The session's socket moved: every mapping this side opened is
  /// stale, so nothing a path proved before still stands.
  ///
  /// The path the session is on keeps its grace, because a rebind is
  /// not evidence against it and the probes about to go out will settle
  /// the question either way; the others have to prove themselves again
  /// before they may take the session.
  fn on_move(&mut self, now: Instant) {
    let current = self.phase.addr();
    for trial in &mut self.trials {
      trial.probe.last_answer = match Some(trial.probe.addr) == current {
        true => Some(now),
        false => None,
      };
    }
    self.next_relay = now;
    self.next_round = now;
    debug!("the session's socket moved; re-registering");
  }

  /// When to look again. Never an instant already past: this drives a
  /// sleep, and a deadline behind the clock is a driver that spins
  /// instead of sleeping.
  fn deadline(&self, now: Instant) -> Option<Instant> {
    let mut deadline = None;
    let mut consider = |at: Instant| {
      if at > now {
        deadline = earliest(deadline, Some(at));
      }
    };
    // A settled session has nothing left to probe or keep active, so it
    // waits on the connection and nothing else.
    if self.phase != Phase::Settled {
      consider(self.next_round);
      consider(self.next_relay);
    }
    match self.phase {
      Phase::Confirming { since, .. } => consider(since + self.policy.confirm),
      Phase::Upgraded { until, .. } => consider(until),
      // A backoff expiring is when a path may be tried again, and the
      // only thing that would otherwise wake a session with nothing due.
      Phase::Relayed => {
        for trial in &self.trials {
          if !trial.retired
            && let Some(at) = trial.blocked_until
          {
            consider(at);
          }
        }
      }
      Phase::Settled => {}
    }
    deadline
  }

  fn take_outbox(&mut self) -> Vec<(Vec<u8>, SocketAddr)> {
    std::mem::take(&mut self.outbox)
  }

  fn take_actions(&mut self) -> Vec<Action> {
    std::mem::take(&mut self.actions)
  }
}

/// The client's half of the upgrade: the policy above, the session's
/// socket, and the probes it sorts out of the session's traffic.
///
/// Handed back by [`crate::client::ClientSession::establish`] for a
/// session the relay carried, and driven beside the relay for as long
/// as the connection lives.
#[derive(Debug)]
pub struct ClientUpgrade {
  socket: Arc<TraversalSocket>,
  /// The endpoint the session runs on, for the ack-eliciting nudge that
  /// starts a switch's path validation ([`TraversalSocket::nudge`]).
  endpoint: quinn::Endpoint,
  probes: mpsc::Receiver<Probe>,
  policy: ClientPolicy,
}

/// How many probes one wake of the driver takes off the queue.
///
/// A flood is a burst of small datagrams, and handling them one wake
/// apiece would pay for a poll and a clock read per datagram. The queue
/// bounds the memory ([`crate::traversal::PROBE_QUEUE`]); this bounds
/// what draining it costs.
const PROBE_BATCH: usize = 16;

impl ClientUpgrade {
  /// A client upgrade for a session on the relay, or `None` when there
  /// is nothing to upgrade from -- no relay under it, or a session the
  /// path manager never took, which cannot be moved anywhere.
  pub fn new(
    now: Instant,
    inherited: Inherited,
    policy: UpgradePolicy,
    socket: Arc<TraversalSocket>,
    endpoint: quinn::Endpoint,
    probes: mpsc::Receiver<Probe>,
  ) -> Option<Self> {
    // Every action this policy can take is a switch, and the map takes
    // none of them for a session whose winning path it never mapped
    // (see [`TraversalSocket::dial_target`]). Probing on would retire
    // each candidate as the map refused it, silently, so say so once.
    if socket.peer().is_none() {
      warn!("the session's path was not mapped; it cannot be upgraded");
      return None;
    }
    let inherited = inherited.normalized(&socket);
    Some(Self {
      socket,
      endpoint,
      probes,
      policy: ClientPolicy::new(now, inherited, policy)?,
    })
  }

  /// Runs until the connection closes, reporting what it does on
  /// `events`.
  ///
  /// Cancellation-safe at any await: nothing here holds state the
  /// session depends on, so a caller that drops the future simply stops
  /// improving the path.
  pub async fn run(
    mut self,
    connection: quinn::Connection,
    events: mpsc::Sender<UpgradeEvent>,
  ) {
    let closed = connection.closed();
    tokio::pin!(closed);
    let mut batch = Vec::with_capacity(PROBE_BATCH);
    loop {
      let now = Instant::now();
      let deadline = self.policy.poll(now, Heard::of(&connection));
      for (datagram, to) in self.policy.take_outbox() {
        emit(&self.socket, &datagram, to).await;
      }
      for action in self.policy.take_actions() {
        match action {
          Action::Switch { addr, path_kind } => {
            let moved = (path_kind == PathKind::Relayed
              || self.socket.add_path(addr, path_kind))
              && self.socket.switch_to(addr);
            if !moved {
              self.policy.unmappable(addr);
              continue;
            }
            // An idle session would otherwise leave nothing on the new
            // path to validate until its next keep-alive, and a path on
            // trial has only the confirmation window to prove itself.
            self.socket.nudge(&self.endpoint);
            tracing::info!(%addr, %path_kind, "the session moved onto another path");
            if events
              .send(UpgradeEvent::Moved { addr, path_kind })
              .await
              .is_err()
            {
              return;
            }
          }
          Action::Release => {
            if events.send(UpgradeEvent::HelperReleased).await.is_err() {
              return;
            }
          }
        }
      }

      tokio::select! {
        biased;
        _ = &mut closed => return,
        received = self.probes.recv_many(&mut batch, PROBE_BATCH) => {
          // The socket is gone, which means the endpoint is.
          if received == 0 {
            return;
          }
          let now = Instant::now();
          for probe in batch.drain(..) {
            self.policy.on_probe(now, &probe);
          }
        }
        () = self.socket.moved() => self.policy.on_move(Instant::now()),
        () = wait_until(deadline) => {}
      }
    }
  }
}

/// One address the client may be at, and what it has proven.
///
/// A client names its own addresses over signaling, and one can be an
/// address a hostile helper reflected back at it, so what enters this
/// table is claims. A signed probe sorts them: only the client can
/// produce one, and the address it comes from is where the client is.
#[derive(Debug)]
struct Target {
  addr: SocketAddr,
  /// When a signed probe last arrived from it.
  proven: Option<Instant>,
}

/// The destination's upgrade policy as a pure state machine: answer the
/// client's validation probes, keep punching outward while the relay is
/// carrying the session, and keep the relay's pinhole open.
#[derive(Debug)]
struct DestinationPolicy {
  nonce: SessionNonce,
  secret: SessionSecret,
  policy: UpgradePolicy,
  helper: Option<Probing>,
  /// What a probe at the client says, as against what one at the helper
  /// says ([`crate::stun::Aim`]).
  at_client: ProbeLabel,
  /// The client's addresses, punched at so its own probes can get in.
  peers: Vec<Target>,
  dense_until: Instant,
  /// When the relay was last seen carrying the session, which is what
  /// this side has to keep a pinhole open for.
  relayed_at: Option<Instant>,
  /// When anything last arrived from the client on the session itself,
  /// which is what bounds how long this side spends a third party's
  /// bastion (see the module docs).
  heard_at: Instant,
  /// Frames heard at the last poll, so that growth is what counts.
  heard: u64,
  next_round: Instant,
  next_heartbeat: Instant,
  budget: ProbeBudget,
  outbox: Vec<(Vec<u8>, SocketAddr)>,
}

impl DestinationPolicy {
  /// A policy for a session that has a secret to answer with, or `None`
  /// when there was no helper and so nothing to answer, punch, or keep
  /// active.
  fn new(
    now: Instant,
    inherited: Inherited,
    policy: UpgradePolicy,
  ) -> Option<Self> {
    let secret = inherited.secret?;
    let at_helper =
      ProbeLabel::to_helper(inherited.nonce, PeerRole::Destination);
    let at_client = ProbeLabel::to_peer(inherited.nonce, PeerRole::Destination);
    Some(Self {
      nonce: inherited.nonce,
      secret,
      policy,
      helper: inherited
        .helper
        .map(|addr| Probing::new(addr, at_helper, &secret)),
      at_client,
      peers: inherited
        .peers
        .into_iter()
        .filter(|&addr| is_dialable(addr, false))
        .take(MAX_PEERS)
        .map(|addr| Target { addr, proven: None })
        .collect(),
      dense_until: now + policy.punch_window,
      relayed_at: None,
      heard_at: now,
      heard: 0,
      next_round: now,
      next_heartbeat: now,
      budget: probe_budget(now),
      outbox: Vec::new(),
    })
  }

  /// Advances the policy. `relayed` is whether the session's datagrams
  /// are still arriving through the helper, which is the whole of what
  /// this side knows about which kind of path carries it; `heard` is
  /// what the connection itself has had from the client.
  fn poll(
    &mut self,
    now: Instant,
    relayed: bool,
    heard: Heard,
  ) -> Option<Instant> {
    if relayed {
      self.relayed_at = Some(now);
    }
    if heard.frames > self.heard {
      self.heard = heard.frames;
      self.heard_at = now;
    }
    if now >= self.next_round {
      if relayed {
        // Outward probes at the client's addresses: the pinhole its own
        // validation probe must arrive through is one this side has to
        // open. Generated per round, and labeled as aimed at the client, so
        // one captured on its way to a merely claimed address registers
        // nothing anywhere ([`crate::stun`]).
        let request = BindingTransaction::new(self.at_client, &self.secret);
        let request = request.request().to_vec();
        for peer in &self.peers {
          self.outbox.push((request.clone(), peer.addr));
        }
      }
      self.next_round = now + self.round_gap(now, relayed);
    }
    // The heartbeat runs while the relay is a path this session may use
    // -- carrying it, or the fallback the client holds through its
    // grace after an upgrade -- and stops afterwards, where it would be
    // the only thing keeping a bastion process open for a session with
    // no use left for it ([`crate::helper::HelperService::poll`]).
    let wanted = self.wanted(now);
    if wanted
      && now >= self.next_heartbeat
      && let Some(helper) = &mut self.helper
    {
      let request = helper.request(&self.secret);
      self.outbox.push((request, helper.addr));
      self.next_heartbeat = now + self.policy.relay_keepalive;
    }
    let mut deadline = (self.next_round > now).then_some(self.next_round);
    if wanted && self.helper.is_some() && self.next_heartbeat > now {
      deadline = earliest(deadline, Some(self.next_heartbeat));
    }
    deadline
  }

  /// Whether the relay is still a path this session may need, and this
  /// side still has reason to believe there is a session.
  fn wanted(&self, now: Instant) -> bool {
    let needed = self.relayed_at.is_some_and(|at| {
      now.saturating_duration_since(at) < self.policy.helper_grace
    });
    needed && now.saturating_duration_since(self.heard_at) < self.policy.silence
  }

  fn round_gap(&self, now: Instant, relayed: bool) -> Duration {
    match relayed && now < self.dense_until {
      true => self.policy.probe_interval,
      false => self.policy.punch_retry,
    }
  }

  /// Feeds one probe, answering the client's validation checks.
  ///
  /// The helper's address is not sorted out first, because the client's
  /// own probes arrive from it whenever the relay is carrying them. The
  /// answers to this side's keepalives arrive from it too, but they are
  /// binding *responses*, which the classification below drops as
  /// surely as a dedicated branch would.
  fn on_probe(&mut self, now: Instant, probe: &Probe) {
    let Datagram::Binding(request) = stun::classify(&probe.datagram) else {
      return;
    };
    // The checks, in the order the helper uses them: the session and
    // what the probe was aimed at, then the budget that bounds what an
    // unauthenticated flood can spend -- per source first, so one
    // address cannot spend the client's share -- then the signature
    // that says the client sent it.
    let Some(label) = request.label() else {
      return;
    };
    if label.nonce != self.nonce
      || label.role != PeerRole::Client
      || label.aim != Aim::Peer
    {
      return;
    }
    if let Err(refused) = self.budget.take(now, probe.from.ip()) {
      trace!(from = %probe.from, ?refused, "not answering: probe budget spent");
      return;
    }
    if !request.authentic(&self.secret) {
      debug!(from = %probe.from, "a probe for this session was not signed");
      return;
    }
    match request.reflect(probe.from, &self.secret) {
      Ok(reply) => self.outbox.push((reply, probe.from)),
      Err(refused) => trace!(%refused, "not answering"),
    }
    // A client that moved is named only by the probe it sent, and the
    // pinhole its next one needs is one this side has to have punched.
    // So a signed probe's source is somewhere to keep punching at, and
    // the one place the table may never be too full to hold.
    if is_dialable(probe.from, false) {
      self.proven(now, probe.from);
    }
  }

  /// Records that a signed probe arrived from `addr`, making room for
  /// it if the table is full.
  ///
  /// What is evicted is whatever has gone longest without proving
  /// anything -- an address the client merely claimed, ahead of one it
  /// has actually been at. A first-come cap would instead let the
  /// claims fill the table and leave a roaming client unpunched at,
  /// which silently disables the upgrade for the rest of the session.
  fn proven(&mut self, now: Instant, addr: SocketAddr) {
    if let Some(target) = self.peers.iter_mut().find(|peer| peer.addr == addr) {
      target.proven = Some(now);
      return;
    }
    if self.peers.len() >= MAX_PEERS {
      let stalest = self
        .peers
        .iter()
        .enumerate()
        .min_by_key(|(at, peer)| (peer.proven, *at))
        .map(|(at, _)| at);
      match stalest {
        Some(at) => {
          debug!(dropped = %self.peers[at].addr, "the peer table is full");
          self.peers.remove(at);
        }
        None => return,
      }
    }
    debug!(%addr, "the client named a new address");
    self.peers.push(Target {
      addr,
      proven: Some(now),
    });
  }

  fn take_outbox(&mut self) -> Vec<(Vec<u8>, SocketAddr)> {
    std::mem::take(&mut self.outbox)
  }
}

/// The destination's half of the upgrade, driven for the life of the
/// connection.
#[derive(Debug)]
pub struct DestinationUpgrade {
  socket: Arc<TraversalSocket>,
  probes: mpsc::Receiver<Probe>,
  policy: DestinationPolicy,
}

impl DestinationUpgrade {
  /// A destination upgrade for a session with a helper behind it, or
  /// `None` when there is nothing to answer or keep active.
  pub fn new(
    now: Instant,
    inherited: Inherited,
    policy: UpgradePolicy,
    socket: Arc<TraversalSocket>,
    probes: mpsc::Receiver<Probe>,
  ) -> Option<Self> {
    let inherited = inherited.normalized(&socket);
    Some(Self {
      socket,
      probes,
      policy: DestinationPolicy::new(now, inherited, policy)?,
    })
  }

  /// Runs until the connection closes.
  pub async fn run(mut self, connection: quinn::Connection) {
    let closed = connection.closed();
    tokio::pin!(closed);
    let helper = self.policy.helper.as_ref().map(|helper| helper.addr);
    let mut batch = Vec::with_capacity(PROBE_BATCH);
    loop {
      // Which kind of path carries the session is not signaled and need
      // not be: the client's datagrams arrive from the helper while the
      // relay carries them, and from the client itself once it does not.
      let relayed = helper == Some(connection.remote_address());
      let now = Instant::now();
      let heard = Heard::of(&connection);
      let deadline = self.policy.poll(now, relayed, heard);
      for (datagram, to) in self.policy.take_outbox() {
        emit(&self.socket, &datagram, to).await;
      }
      tokio::select! {
        biased;
        _ = &mut closed => return,
        received = self.probes.recv_many(&mut batch, PROBE_BATCH) => {
          if received == 0 {
            return;
          }
          let now = Instant::now();
          for probe in batch.drain(..) {
            self.policy.on_probe(now, &probe);
          }
        }
        () = wait_until(deadline) => {}
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
  }

  fn nonce() -> SessionNonce {
    SessionNonce::from_bytes([0x31; 16])
  }

  fn secret() -> SessionSecret {
    SessionSecret::from_bytes([0x93; 16])
  }

  const HELPER: &str = "198.51.100.7:60123";
  const DIRECT: &str = "192.0.2.2:60123";
  const OTHER: &str = "192.0.2.3:60123";
  const CLIENT: &str = "5.5.5.5:41000";

  fn inherited(peers: &[&str]) -> Inherited {
    Inherited {
      nonce: nonce(),
      secret: Some(secret()),
      helper: Some(addr(HELPER)),
      peers: peers.iter().copied().map(addr).collect(),
      allow_loopback: false,
    }
  }

  fn client(now: Instant, peers: &[&str]) -> ClientPolicy {
    client_with(now, peers, UpgradePolicy::default())
  }

  fn client_with(
    now: Instant,
    peers: &[&str],
    policy: UpgradePolicy,
  ) -> ClientPolicy {
    ClientPolicy::new(now, inherited(peers), policy)
      .expect("a relayed session has a policy")
  }

  fn destination(now: Instant) -> DestinationPolicy {
    DestinationPolicy::new(now, inherited(&[]), UpgradePolicy::default())
      .expect("a session with a helper has a policy")
  }

  /// Nothing has been heard from the peer at all.
  fn silent() -> Heard {
    Heard::default()
  }

  /// The destination validated the path `challenges` times over the
  /// session's life, and acknowledged `acks` of what this side sent.
  fn heard(acks: u64, challenges: u64) -> Heard {
    Heard {
      acks,
      challenges,
      frames: acks + challenges,
    }
  }

  /// The destination's answer to what the client sent at a candidate,
  /// which is what makes that path one to switch to.
  fn answer(
    destination: &mut DestinationPolicy,
    now: Instant,
    from: SocketAddr,
    datagram: Vec<u8>,
  ) -> Vec<(Vec<u8>, SocketAddr)> {
    destination.on_probe(now, &Probe { from, datagram });
    destination.take_outbox()
  }

  /// A validation probe as the client sends one: aimed at the peer, so
  /// that a copy of it is worth nothing at the jump helper.
  fn validation() -> BindingTransaction {
    BindingTransaction::new(
      ProbeLabel::to_peer(nonce(), PeerRole::Client),
      &secret(),
    )
  }

  /// A session with no helper under it has nothing to upgrade from and
  /// no registration to keep, on either side.
  #[test]
  fn a_session_without_a_relay_has_no_policy() {
    let now = Instant::now();
    let bare = Inherited {
      helper: None,
      ..inherited(&[DIRECT])
    };
    assert!(
      ClientPolicy::new(now, bare.clone(), UpgradePolicy::default()).is_none()
    );
    let unsigned = Inherited {
      secret: None,
      ..inherited(&[DIRECT])
    };
    assert!(
      ClientPolicy::new(now, unsigned.clone(), UpgradePolicy::default())
        .is_none()
    );
    assert!(
      DestinationPolicy::new(now, unsigned, UpgradePolicy::default()).is_none()
    );
  }

  /// The whole upgrade, end to end through the two state machines: the
  /// client probes, the destination answers, the client switches, and
  /// the destination's own path validation is what confirms it.
  #[test]
  fn a_path_that_answers_and_is_validated_takes_the_session() {
    let start = Instant::now();
    let mut client = client(start, &[DIRECT]);
    let mut destination = destination(start);

    // The first round goes out at once, at the candidate and nowhere
    // else; the relay's own keepalive is on its own clock.
    assert_eq!(
      client.poll(start, silent()),
      Some(start + DEFAULT_ROUND_INTERVAL)
    );
    let round = client.take_outbox();
    assert_eq!(round.len(), 1);
    assert_eq!(round[0].1, addr(DIRECT));
    assert!(client.take_actions().is_empty());

    // The destination answers it, and the answer proves the round trip.
    let replies =
      answer(&mut destination, start, addr(CLIENT), round[0].0.clone());
    assert_eq!(replies.len(), 1);
    client.on_probe(
      start,
      &Probe {
        from: addr(DIRECT),
        datagram: replies[0].0.clone(),
      },
    );

    // Which is what makes the client take it.
    client.poll(start, silent());
    assert_eq!(
      client.take_actions(),
      vec![Action::Switch {
        addr: addr(DIRECT),
        path_kind: PathKind::Punched
      }]
    );

    // The destination has not validated the new address yet, so it is
    // still on trial: datagrams arriving from it prove nothing.
    let confirming = start + Duration::from_millis(500);
    client.poll(confirming, heard(9, 0));
    assert!(client.take_actions().is_empty());
    assert!(matches!(client.phase, Phase::Confirming { .. }));
    // The destination's PATH_CHALLENGE settles it: only the destination
    // can produce one, and only when its client's address changes.
    client.poll(confirming, heard(9, 1));
    assert!(client.take_actions().is_empty());
    assert!(matches!(client.phase, Phase::Upgraded { .. }));
  }

  /// A path that answers probes and carries nothing is exactly the
  /// shape the confirmation window exists for: the session goes back to
  /// the relay rather than stalling on it.
  #[test]
  fn a_path_that_is_never_validated_hands_the_session_back() {
    let start = Instant::now();
    let mut client = client(start, &[DIRECT]);
    client.trials[0].probe.last_answer = Some(start);
    client.poll(start, silent());
    assert_eq!(
      client.take_actions(),
      vec![Action::Switch {
        addr: addr(DIRECT),
        path_kind: PathKind::Punched
      }]
    );

    let late = start + DEFAULT_CONFIRM;
    client.poll(late, heard(40, 0));
    assert_eq!(
      client.take_actions(),
      vec![Action::Switch {
        addr: addr(HELPER),
        path_kind: PathKind::Relayed
      }]
    );
    assert_eq!(client.phase, Phase::Relayed);
    // And it is not tried again at once, however well it probes.
    client.trials[0].probe.last_answer = Some(late);
    client.poll(late, heard(40, 0));
    assert!(client.take_actions().is_empty());
  }

  /// A downgrade hands the session to the relay, and that is all one
  /// poll may do: taking a sibling still inside its liveness window
  /// would cost the destination two path validations and two
  /// congestion resets back to back.
  #[test]
  fn a_downgrade_does_not_hand_the_session_on_in_the_same_poll() {
    let start = Instant::now();
    let mut client = client(start, &[DIRECT, OTHER]);
    for trial in &mut client.trials {
      trial.probe.last_answer = Some(start);
    }
    client.poll(start, silent());
    assert_eq!(
      client.take_actions(),
      vec![Action::Switch {
        addr: addr(DIRECT),
        path_kind: PathKind::Punched
      }]
    );

    let late = start + DEFAULT_CONFIRM;
    client.trials[1].probe.last_answer = Some(late);
    client.poll(late, silent());
    assert_eq!(
      client.take_actions(),
      vec![Action::Switch {
        addr: addr(HELPER),
        path_kind: PathKind::Relayed
      }],
      "the session was handed on before the relay had it back"
    );
    assert_eq!(client.phase, Phase::Relayed);
    // The sibling is still there to be taken at the next round.
    client.poll(late + DEFAULT_ROUND_INTERVAL, silent());
    assert_eq!(
      client.take_actions(),
      vec![Action::Switch {
        addr: addr(OTHER),
        path_kind: PathKind::Punched
      }]
    );
  }

  /// Hysteresis has an end: a path that keeps taking the session and
  /// failing to prove itself is dropped rather than retried for the
  /// session's life.
  #[test]
  fn a_path_that_never_confirms_is_retired() {
    let mut now = Instant::now();
    let mut client = client(now, &[DIRECT]);
    for attempt in 1..=DEFAULT_MAX_ATTEMPTS {
      client.trials[0].probe.last_answer = Some(now);
      client.trials[0].blocked_until = None;
      client.poll(now, silent());
      assert!(
        !client.take_actions().is_empty(),
        "attempt {attempt} never switched"
      );
      now += DEFAULT_CONFIRM;
      client.poll(now, silent());
      client.take_actions();
    }
    assert!(client.trials[0].retired);
    now += DEFAULT_RETRY_BACKOFF * 100;
    client.trials[0].probe.last_answer = Some(now);
    client.poll(now, silent());
    assert!(client.take_actions().is_empty());
    // With nothing left to try, the session sits on the relay and keeps
    // its registration current, which is the other half of the job.
    let mut relay_probes = 0;
    for _ in 0..10 {
      now += DEFAULT_RELAY_KEEPALIVE;
      client.poll(now, silent());
      relay_probes += client
        .take_outbox()
        .iter()
        .filter(|(_, to)| *to == addr(HELPER))
        .count();
    }
    assert!(relay_probes >= 9, "the relay went unprobed: {relay_probes}");
  }

  /// Confirming spends the attempt budget back. Otherwise a direct path
  /// that works, and that the network takes away three times over a
  /// long session, would be abandoned for the rest of it.
  #[test]
  fn a_path_that_carried_the_session_is_never_retired_for_losing_it() {
    let mut now = Instant::now();
    let mut client = client(now, &[DIRECT]);
    let mut challenges = 0;
    for round in 0..DEFAULT_MAX_ATTEMPTS * 3 {
      client.trials[0].probe.last_answer = Some(now);
      client.trials[0].blocked_until = None;
      client.poll(now, heard(round.into(), challenges));
      assert!(
        !client.take_actions().is_empty(),
        "round {round} never switched"
      );
      // The destination validates the move, and the path carries the
      // session for a while.
      challenges += 1;
      client.poll(now, heard(round.into(), challenges));
      assert!(matches!(client.phase, Phase::Upgraded { .. }));
      assert_eq!(client.trials[0].attempts, 0);

      // Then the network takes it away.
      now += DEFAULT_ROUND_INTERVAL * DEFAULT_MISSES;
      client.poll(now, heard(round.into(), challenges));
      client.take_actions();
      assert_eq!(client.phase, Phase::Relayed);
      assert!(!client.trials[0].retired, "round {round} retired the path");
      now += DEFAULT_RETRY_BACKOFF;
    }
  }

  /// A direct path that dies after the grace has started gives the
  /// session back before the helper is released.
  #[test]
  fn a_dead_direct_path_downgrades_within_the_grace() {
    let start = Instant::now();
    let mut client = client(start, &[DIRECT]);
    client.trials[0].probe.last_answer = Some(start);
    client.poll(start, silent());
    client.take_actions();
    client.poll(start, heard(0, 1));
    assert!(matches!(client.phase, Phase::Upgraded { .. }));

    // Nothing answers and nothing arrives from here on.
    let dead = start + DEFAULT_ROUND_INTERVAL * DEFAULT_MISSES;
    client.poll(dead, heard(0, 1));
    assert_eq!(
      client.take_actions(),
      vec![Action::Switch {
        addr: addr(HELPER),
        path_kind: PathKind::Relayed
      }]
    );
  }

  /// While the session's own traffic is arriving the path keeps the
  /// session, however many probe rounds are lost: the alternative is a
  /// working direct path handed back to the relay for ordinary loss, at
  /// the cost of a congestion reset each time.
  #[test]
  fn a_busy_session_keeps_a_path_whose_probes_are_lost() {
    let start = Instant::now();
    // A grace long enough that the session stays in the phase under
    // test for the whole run, rather than settling out of it.
    let mut client = client_with(
      start,
      &[DIRECT],
      UpgradePolicy {
        helper_grace: Duration::from_secs(3600),
        ..UpgradePolicy::default()
      },
    );
    client.trials[0].probe.last_answer = Some(start);
    client.poll(start, silent());
    client.take_actions();
    client.poll(start, heard(1, 1));
    assert!(matches!(client.phase, Phase::Upgraded { .. }));

    // Ten minutes of probes that never come back, over a path carrying
    // the session the whole time.
    let mut now = start;
    let mut acks = 1;
    while now < start + Duration::from_secs(600) {
      now += DEFAULT_ROUND_INTERVAL;
      acks += 1;
      client.poll(now, heard(acks, 1));
      assert!(
        client.take_actions().is_empty(),
        "a path carrying the session was given up at {:?}",
        now.saturating_duration_since(start)
      );
    }
    assert!(matches!(client.phase, Phase::Upgraded { .. }));

    // And when the session's own traffic stops arriving too, the path
    // is dead by both measures and goes back.
    let dead = now + DEFAULT_ROUND_INTERVAL * DEFAULT_MISSES;
    client.poll(dead, heard(acks, 1));
    assert_eq!(
      client.take_actions(),
      vec![Action::Switch {
        addr: addr(HELPER),
        path_kind: PathKind::Relayed
      }]
    );
  }

  /// A path that holds through the grace releases the helper, and the
  /// session stops probing anything.
  #[test]
  fn a_path_that_holds_releases_the_helper() {
    let start = Instant::now();
    let mut client = client(start, &[DIRECT]);
    client.trials[0].probe.last_answer = Some(start);
    client.poll(start, silent());
    client.take_actions();
    client.poll(start, heard(0, 1));

    let mut now = start;
    let end = start + DEFAULT_HELPER_GRACE;
    let mut released = false;
    while now <= end + DEFAULT_ROUND_INTERVAL {
      // The path keeps answering every round.
      client.trials[0].probe.last_answer = Some(now);
      client.poll(now, heard(0, 1));
      released |= client.take_actions().contains(&Action::Release);
      client.take_outbox();
      now += DEFAULT_ROUND_INTERVAL;
    }
    assert!(released, "the helper was never released");
    assert_eq!(client.phase, Phase::Settled);
    // Nothing is kept active once the relay is gone.
    now += DEFAULT_RELAY_KEEPALIVE * 4;
    client.poll(now, heard(0, 1));
    assert!(
      client
        .take_outbox()
        .iter()
        .all(|(_, to)| *to != addr(HELPER))
    );
  }

  /// A rebind invalidates every mapping this side opened, so the relay
  /// is re-registered at once rather than at the next keepalive -- which
  /// is what makes a relayed session survive a roam.
  #[test]
  fn a_rebind_re_registers_the_relay_at_once() {
    let start = Instant::now();
    let mut client = client(start, &[DIRECT, OTHER]);
    client.poll(start, silent());
    client.take_outbox();

    let moved = start + Duration::from_secs(1);
    client.trials[0].probe.last_answer = Some(start);
    client.on_move(moved);
    // What a path proved from the old mapping proves nothing now.
    assert!(client.trials[0].probe.last_answer.is_none());
    client.poll(moved, silent());
    let sent = client.take_outbox();
    assert!(
      sent.iter().any(|(_, to)| *to == addr(HELPER)),
      "the relay was not re-registered"
    );
  }

  /// Handling a probe is a keyed hash over a datagram anyone can send
  /// at the session's socket, so it is budgeted per source first: a
  /// flood from one address cannot spend the session's own share.
  #[test]
  fn a_flood_at_the_client_leaves_its_own_answers_a_share() {
    let now = Instant::now();
    let mut client = client(now, &[DIRECT]);
    let flood = addr("198.51.100.99:5000");
    let mut admitted = 0;
    for _ in 0..500 {
      admitted += usize::from(client.budget.take(now, flood.ip()).is_ok());
    }
    assert_eq!(admitted, SOURCE_PROBE_BURST as usize);
    // The path the session is trying still has its own share of the
    // service budget.
    assert!(client.budget.take(now, addr(DIRECT).ip()).is_ok());
  }

  /// And the budget is spent before the datagram is read, which is the
  /// point: validating a probe is a keyed hash, and the client is the
  /// side whose runtime also carries the user's session.
  #[test]
  fn the_client_budgets_probe_handling_before_validating_one() {
    let now = Instant::now();
    let mut client = client(now, &[DIRECT]);
    let mut destination = destination(now);
    client.poll(now, silent());
    let round = client.take_outbox();
    let probe = round
      .iter()
      .find(|(_, to)| *to == addr(DIRECT))
      .expect("the candidate was probed");
    let replies = answer(&mut destination, now, addr(CLIENT), probe.0.clone());
    let reply = replies[0].0.clone();

    // A flood from the candidate's own address spends that source's
    // budget, and the answer that follows costs nothing to refuse.
    for _ in 0..500 {
      client.on_probe(
        now,
        &Probe {
          from: addr(DIRECT),
          datagram: vec![0u8; 64],
        },
      );
    }
    client.on_probe(
      now,
      &Probe {
        from: addr(DIRECT),
        datagram: reply.clone(),
      },
    );
    assert!(!client.trials[0].probe.alive(now, DEFAULT_ROUND_INTERVAL));

    // A second later the bucket has refilled and the same answer counts.
    let later = now + Duration::from_secs(1);
    client.on_probe(
      later,
      &Probe {
        from: addr(DIRECT),
        datagram: reply,
      },
    );
    assert!(client.trials[0].probe.alive(later, DEFAULT_ROUND_INTERVAL));
  }

  /// The destination answers only what the session's secret signs, only
  /// for its own nonce, and only what was aimed at it: a probe on its
  /// way to the jump helper is signed with the same secret and is not
  /// this side's to answer.
  #[test]
  fn the_destination_answers_only_signed_probes_aimed_at_it() {
    let now = Instant::now();
    let mut destination = destination(now);
    let client = addr(CLIENT);

    let stranger = BindingTransaction::new(
      ProbeLabel::to_peer(nonce(), PeerRole::Client),
      &SessionSecret::from_bytes([0x01; 16]),
    );
    assert!(
      answer(&mut destination, now, client, stranger.request().to_vec())
        .is_empty()
    );

    let other_session = BindingTransaction::new(
      ProbeLabel::to_peer(
        SessionNonce::from_bytes([0x02; 16]),
        PeerRole::Client,
      ),
      &secret(),
    );
    assert!(
      answer(
        &mut destination,
        now,
        client,
        other_session.request().to_vec()
      )
      .is_empty()
    );

    let at_the_helper = BindingTransaction::new(
      ProbeLabel::to_helper(nonce(), PeerRole::Client),
      &secret(),
    );
    assert!(
      answer(
        &mut destination,
        now,
        client,
        at_the_helper.request().to_vec()
      )
      .is_empty(),
      "a probe on its way to the helper was answered as a validation"
    );

    let unlabeled = BindingTransaction::unlabeled();
    assert!(
      answer(&mut destination, now, client, unlabeled.request().to_vec())
        .is_empty()
    );

    let mine = validation();
    let replies =
      answer(&mut destination, now, client, mine.request().to_vec());
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].1, client);
    assert_eq!(mine.reflexive(&replies[0].0), Some(client));
  }

  /// Answering is bounded: a flood of probes for a served session causes
  /// a fixed number of signature checks per second and no more, and one
  /// address's flood cannot spend the client's share of it.
  #[test]
  fn the_destination_bounds_what_it_answers_per_source() {
    let now = Instant::now();
    let mut destination = destination(now);
    let flood = addr("198.51.100.99:5000");
    let mut answered = 0;
    for _ in 0..500 {
      answered += answer(
        &mut destination,
        now,
        flood,
        validation().request().to_vec(),
      )
      .len();
    }
    assert_eq!(answered, SOURCE_PROBE_BURST as usize);

    // The client's own validation probe is answered all the same.
    let mine = validation();
    let replies =
      answer(&mut destination, now, addr(CLIENT), mine.request().to_vec());
    assert_eq!(replies.len(), 1);
    assert_eq!(mine.reflexive(&replies[0].0), Some(addr(CLIENT)));
  }

  /// The destination punches outward only while the relay is carrying
  /// the session, and keeps the relay's own pinhole open for as long as
  /// the session might come back to it.
  #[test]
  fn the_destination_punches_while_relayed_and_heartbeats_the_relay() {
    let start = Instant::now();
    let mut destination = DestinationPolicy::new(
      start,
      Inherited {
        peers: vec![addr(CLIENT)],
        ..inherited(&[])
      },
      UpgradePolicy::default(),
    )
    .expect("a session with a helper has a policy");

    destination.poll(start, true, heard(1, 0));
    let sent = destination.take_outbox();
    assert!(sent.iter().any(|(_, to)| *to == addr(CLIENT)));
    assert!(sent.iter().any(|(_, to)| *to == addr(HELPER)));

    // Once the session is direct there is nothing to punch for, but the
    // relay stays active for as long as the client may hand it back.
    let mut punched = 0;
    let mut heartbeats = 0;
    let mut now = start;
    let mut acks = 1;
    let grace_ends = start + DEFAULT_HELPER_GRACE;
    while now < grace_ends {
      now += DEFAULT_RELAY_KEEPALIVE;
      acks += 1;
      destination.poll(now, false, heard(acks, 0));
      for (_, to) in destination.take_outbox() {
        match to == addr(HELPER) {
          true => heartbeats += 1,
          false => punched += 1,
        }
      }
    }
    assert_eq!(punched, 0);
    assert!(heartbeats > 0, "the relay went unheartbeated");
    for _ in 0..10 {
      now += DEFAULT_RELAY_KEEPALIVE;
      acks += 1;
      destination.poll(now, false, heard(acks, 0));
      assert!(
        destination.take_outbox().is_empty(),
        "the relay is kept active for a session that no longer needs it"
      );
    }
  }

  /// A destination whose client vanished holds a bastion process on
  /// somebody else's machine, and the connection alone will never say
  /// so: Mush sets no idle timeout. So silence bounds the heartbeat --
  /// and only bounds it, because a client that comes back carries on.
  #[test]
  fn the_destination_stops_heartbeating_a_vanished_client() {
    let start = Instant::now();
    let mut destination = destination(start);
    let mut acks = 1;
    destination.poll(start, true, heard(acks, 0));
    assert!(
      destination
        .take_outbox()
        .iter()
        .any(|(_, to)| *to == addr(HELPER))
    );

    // The client's machine is destroyed. Its connection stays open
    // forever, and `relayed` stays true with it, because the peer
    // address it is talking to never changes.
    let mut now = start;
    let silent_until = start + DEFAULT_SILENCE;
    while now < silent_until {
      now += DEFAULT_RELAY_KEEPALIVE;
      destination.poll(now, true, heard(acks, 0));
      destination.take_outbox();
    }
    for _ in 0..40 {
      now += DEFAULT_RELAY_KEEPALIVE;
      destination.poll(now, true, heard(acks, 0));
      assert!(
        destination.take_outbox().is_empty(),
        "the bastion is still being heartbeat for a client that is gone"
      );
    }

    // A client that comes back is heard from, and the relay path it will
    // need is opened again at once.
    acks += 1;
    destination.poll(now, true, heard(acks, 0));
    assert!(
      destination
        .take_outbox()
        .iter()
        .any(|(_, to)| *to == addr(HELPER)),
      "the relay was not re-opened for a client that came back"
    );
  }

  /// A client that moved is named only by the probe it sends, so that
  /// is where the destination keeps punching -- the pinhole a roamed
  /// client's next probe has to arrive through.
  #[test]
  fn the_destination_follows_a_client_that_moved() {
    let now = Instant::now();
    let mut destination = destination(now);
    let moved = addr("5.5.5.6:42000");
    answer(
      &mut destination,
      now,
      moved,
      validation().request().to_vec(),
    );
    assert!(destination.peers.iter().any(|peer| peer.addr == moved));
  }

  /// A shim over a v6 socket, which is where the two forms of a v4
  /// address differ.
  fn v6_shim() -> Arc<TraversalSocket> {
    use quinn::Runtime as _;

    let socket = std::net::UdpSocket::bind("[::]:0").expect("a v6 socket");
    let inner = quinn::TokioRuntime
      .wrap_udp_socket(socket)
      .expect("quinn takes the socket");
    TraversalSocket::new(inner).0
  }

  /// Holding the signaled form of an address rather than the map's
  /// (`Inherited::normalized`) would leave the whole upgrade silently
  /// inert for a v4 destination on a v6-bound session.
  #[tokio::test]
  async fn a_v6_session_holds_its_peers_the_way_the_map_does() {
    let socket = v6_shim();
    let now = Instant::now();
    let mut client = ClientPolicy::new(
      now,
      inherited(&[DIRECT]).normalized(&socket),
      UpgradePolicy::default(),
    )
    .expect("a relayed session has a policy");
    let mapped = addr("[::ffff:192.0.2.2]:60123");
    assert_eq!(client.trials[0].probe.addr, mapped);
    assert_eq!(client.relay.addr, addr("[::ffff:198.51.100.7]:60123"));

    // And an answer arriving in that form is the answer to the probe
    // that went out, which is what makes the path a candidate at all.
    let mut destination = destination(now);
    client.poll(now, silent());
    let round = client.take_outbox();
    let probe = round
      .iter()
      .find(|(_, to)| *to == mapped)
      .expect("the candidate was probed");
    let replies = answer(&mut destination, now, addr(CLIENT), probe.0.clone());
    client.on_probe(
      now,
      &Probe {
        from: mapped,
        datagram: replies[0].0.clone(),
      },
    );
    assert!(client.trials[0].probe.alive(now, DEFAULT_ROUND_INTERVAL));
    client.poll(now, silent());
    assert_eq!(
      client.take_actions(),
      vec![Action::Switch {
        addr: mapped,
        path_kind: PathKind::Punched
      }]
    );
  }

  /// A session whose winning path the map never took has no upgrade:
  /// every action the policy can take is a switch the map would refuse.
  #[tokio::test]
  async fn a_session_the_map_never_took_has_no_upgrade() -> anyhow::Result<()> {
    let paths =
      crate::traversal::TraversalEndpoint::bind("127.0.0.1:0".parse()?)?;
    let now = Instant::now();
    assert!(
      ClientUpgrade::new(
        now,
        inherited(&[DIRECT]),
        UpgradePolicy::default(),
        paths.socket.clone(),
        paths.endpoint.clone(),
        paths.probes,
      )
      .is_none(),
      "a session with no mapped path was given a policy that cannot act"
    );

    // With a path the map did take, there is something to upgrade.
    let (socket, probes) = {
      let paths =
        crate::traversal::TraversalEndpoint::bind("127.0.0.1:0".parse()?)?;
      (paths.socket, paths.probes)
    };
    socket.dial_target(addr(HELPER), PathKind::Relayed);
    assert!(socket.commit(addr(HELPER)));
    assert!(
      ClientUpgrade::new(
        now,
        inherited(&[DIRECT]),
        UpgradePolicy::default(),
        socket,
        paths.endpoint,
        probes,
      )
      .is_some()
    );
    Ok(())
  }

  /// The peer table is bounded and what fills it is addresses the
  /// client merely claimed, so what gives way to a proven one is
  /// whatever has proven least (`DestinationPolicy::proven`).
  #[test]
  fn a_full_peer_table_still_makes_room_for_where_the_client_is() {
    let now = Instant::now();
    let claimed: Vec<String> = (0..MAX_PEERS)
      .map(|n| format!("203.0.113.{}:41000", n + 1))
      .collect();
    let mut destination = DestinationPolicy::new(
      now,
      Inherited {
        peers: claimed.iter().map(|addr| addr.parse().unwrap()).collect(),
        ..inherited(&[])
      },
      UpgradePolicy::default(),
    )
    .expect("a session with a helper has a policy");
    assert_eq!(destination.peers.len(), MAX_PEERS);

    let roamed = addr("5.5.5.6:42000");
    answer(
      &mut destination,
      now,
      roamed,
      validation().request().to_vec(),
    );
    assert_eq!(destination.peers.len(), MAX_PEERS);
    assert!(
      destination.peers.iter().any(|peer| peer.addr == roamed),
      "a client that proved where it is was not punched at"
    );
    // What it displaced is a claim, and the rest of them are still
    // there: an address that has proven nothing is not evidence against
    // itself either.
    let held = destination
      .peers
      .iter()
      .filter(|peer| peer.proven.is_none())
      .count();
    assert_eq!(held, MAX_PEERS - 1);

    // Probing the same address again refreshes it rather than filling
    // the table with copies of where the client already is.
    let later = now + Duration::from_secs(60);
    answer(
      &mut destination,
      later,
      roamed,
      validation().request().to_vec(),
    );
    assert_eq!(destination.peers.len(), MAX_PEERS);
    assert_eq!(
      destination
        .peers
        .iter()
        .filter(|peer| peer.addr == roamed)
        .count(),
      1
    );
  }
}
