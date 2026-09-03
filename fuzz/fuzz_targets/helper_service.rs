// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The jump helper's request handling on arbitrary datagrams.
//!
//! The helper is the only part of Mush that listens to the open
//! internet, so this target drives `HelperService::handle` as the
//! network would: arbitrary datagrams from arbitrary sources, mixed with
//! genuinely signed probes (unforgeable by the fuzzer, and without which
//! registration, roaming, relay, and eviction are unreachable), against
//! a session table and a clock the input drives (`Step`).
//!
//! The invariants asserted are the security posture `helper.rs` states:
//! nothing is served for a nonce that was never admitted, no unsigned or
//! wrongly signed probe is answered, a reflection never answers more
//! bytes than it was asked, the relay never sends a datagram back to its
//! own source, the tables stay bounded, and -- the half of a required
//! bound that is easiest to lose quietly -- what the service actually
//! emits stays inside the token buckets it publishes.
//! The harness owns the clock, so those bounds are exact.
//!
//! Probe transaction ids come from the input rather than the system
//! random source, for the determinism `stun_probe.rs` explains, and out
//! of a space small enough that the fuzzer repeats one -- the only way
//! to reach the guard against a probe replaying a transaction that
//! already registered.

#![no_main]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use mush_core::bootstrap::{SessionNonce, SessionSecret};
use mush_core::helper::{
  HelperLimits, HelperOptions, HelperService, Outcome, RELAY_DATAGRAM_OVERHEAD,
};
use mush_core::stun::{BindingTransaction, PeerRole, ProbeLabel};
use tokio::time::Instant;

/// How many distinct sessions the input can name. Larger than the
/// service's session cap would be, if the cap were not itself part of
/// what is under test; small enough that the fuzzer reuses nonces
/// rather than always generating fresh ones.
const SESSIONS: u8 = 4;

/// Room in the budget bounds for floating-point drift. A budget is
/// checked against the same arithmetic the buckets do, so a token of
/// slack is far more than the gap can ever be, and far less than any
/// widening of a limit would be.
const SLACK: f64 = 1.0;

/// One thing the network or the client does to the service.
#[derive(Arbitrary, Debug)]
enum Step<'a> {
  /// The client's ssh channel asked for a session to be served.
  Admit { session: u8 },
  /// The client's ssh channel ended a session.
  Close { session: u8 },
  /// The client's ssh channel went away without saying so.
  ControlClosed,
  /// Time passes: rate-limit buckets refill, deadlines approach.
  Advance { millis: u16 },
  /// A datagram of the sender's choosing.
  Raw { source: Source, datagram: &'a [u8] },
  /// A real probe, optionally signed with the wrong session's secret or
  /// corrupted in one byte. `transaction` is its STUN transaction id,
  /// from a space narrow enough that repeating one is ordinary: a peer
  /// retransmits the same transaction on loss.
  Probe {
    source: Source,
    session: u8,
    destination: bool,
    wrong_secret: bool,
    transaction: u16,
    corrupt: Option<(u16, u8)>,
  },
}

/// A source address, which the helper may never take on trust. The
/// `Reused` variant is what makes the relay reachable: payload is only
/// forwarded from an address a probe already registered, so the input
/// needs a cheap way to send two datagrams from one address.
#[derive(Arbitrary, Debug)]
enum Source {
  Reused { slot: u8 },
  V4 { ip: u32, port: u16 },
  V6 { ip: u128, port: u16 },
}

/// The addresses `Source::Reused` picks from.
const REUSED: [SocketAddr; 4] = [
  SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 41234),
  SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 60123),
  SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
    41234,
  ),
  SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 41235),
];

impl Source {
  fn addr(&self) -> SocketAddr {
    match *self {
      Self::Reused { slot } => REUSED[usize::from(slot) % REUSED.len()],
      // Port 0 is not a source a socket can produce, and using it would
      // make two different sources compare equal in the tables.
      Self::V4 { ip, port } => {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port.max(1))
      }
      Self::V6 { ip, port } => {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port.max(1))
      }
    }
  }
}

fn nonce(session: u8) -> SessionNonce {
  SessionNonce::from_bytes([session % SESSIONS; 16])
}

fn secret(session: u8) -> SessionSecret {
  SessionSecret::from_bytes([0xc0 ^ (session % SESSIONS); 16])
}

/// What the harness knows about a served session: when its relay bucket
/// was filled, and what the relay has been charged since.
struct Served {
  since: Instant,
  charged: f64,
  relayed: u64,
}

/// What the harness knows about one probe source: when its bucket could
/// first have been filled, and how many reflections it has drawn.
struct Probed {
  since: Instant,
  reflections: f64,
}

/// State the harness keeps alongside the service, so each outcome can be
/// checked against what the service was told and the budgets it publishes.
struct Harness {
  limits: HelperLimits,
  /// When the service-wide probe bucket was filled.
  start: Instant,
  served: HashMap<SessionNonce, Served>,
  sources: HashMap<IpAddr, Probed>,
  reflections: f64,
  /// Whether the source table ever filled. Eviction refills a bucket,
  /// so the per-source bound only holds while nothing has been evicted.
  evicting: bool,
}

impl Harness {
  /// The most a bucket of this shape can have spent by now.
  fn bound(burst: f64, rate: f64, since: Instant, now: Instant) -> f64 {
    burst + rate * now.saturating_duration_since(since).as_secs_f64() + SLACK
  }

  /// Which session's peer sent this datagram, by the address it arrived
  /// from and nothing else, which is how the service routes it.
  fn routed(
    &self,
    service: &HelperService,
    from: SocketAddr,
  ) -> Option<SessionNonce> {
    self.served.keys().copied().find(|nonce| {
      [PeerRole::Client, PeerRole::Destination]
        .iter()
        .any(|role| service.peer_addr(*nonce, *role) == Some(from))
    })
  }

  /// Checks one outcome against the posture the module documents.
  fn check(
    &mut self,
    service: &HelperService,
    now: Instant,
    from: SocketAddr,
    datagram: &[u8],
    outcome: &Outcome,
  ) {
    match outcome {
      Outcome::Reflect {
        reply,
        registration,
      } => {
        assert!(
          reply.len() <= datagram.len(),
          "reflecting {} bytes at a {}-byte datagram amplifies",
          reply.len(),
          datagram.len()
        );
        if let Some(registration) = registration {
          assert!(
            self.served.contains_key(&registration.nonce),
            "the service registered a peer for a nonce it was never given"
          );
          assert_eq!(
            registration.addr, from,
            "the service registered an address the datagram did not come from"
          );
          assert_eq!(
            service.peer_addr(registration.nonce, registration.role),
            Some(from),
            "the registration and the peer table disagree"
          );
        }
        self.charge_reflection(now, from.ip());
      }
      Outcome::Relay { to } => {
        assert_ne!(
          *to, from,
          "the service relayed a datagram back to its own source"
        );
        // Never relay to an address that has not proven liveness for a
        // session the service was told to serve.
        let nonce = self.routed(service, *to).expect(
          "the service relayed to an address no peer of a served session \
           registered",
        );
        self.charge_relay(now, nonce, datagram.len());
      }
      Outcome::Drop(_) => {}
    }
    // Relayed byte counts only ever grow, and only for a served session.
    for (nonce, served) in &mut self.served {
      let relayed = service.relayed_bytes(*nonce);
      assert!(
        relayed >= served.relayed,
        "a session's relayed byte count went backwards"
      );
      served.relayed = relayed;
    }
  }

  /// Draws one reflection from both probe budgets and checks that
  /// neither has paid out more than its bucket held.
  fn charge_reflection(&mut self, now: Instant, source: IpAddr) {
    let limits = self.limits;
    self.reflections += 1.0;
    assert!(
      self.reflections
        <= Self::bound(
          limits.service_probe_burst,
          limits.service_probes_per_second,
          self.start,
          now
        ),
      "the service answered {} probes on a {}/s budget with a burst of {}",
      self.reflections,
      limits.service_probes_per_second,
      limits.service_probe_burst
    );

    let evicting = self.evicting;
    let probed = self.sources.entry(source).or_insert(Probed {
      since: now,
      reflections: 0.0,
    });
    probed.reflections += 1.0;
    let (since, drawn) = (probed.since, probed.reflections);
    assert!(
      evicting
        || drawn
          <= Self::bound(
            limits.probe_burst,
            limits.probes_per_second,
            since,
            now
          ),
      "the service answered {drawn} probes from {source} on a {}/s budget \
       with a burst of {}",
      limits.probes_per_second,
      limits.probe_burst
    );
  }

  /// Charges one relayed datagram to its session and checks that the
  /// session's relay has not carried more than its bucket allowed.
  fn charge_relay(&mut self, now: Instant, nonce: SessionNonce, bytes: usize) {
    let limits = self.limits;
    let served = self
      .served
      .get_mut(&nonce)
      .expect("a nonce the routing found is a nonce the harness served");
    served.charged += bytes as f64 + RELAY_DATAGRAM_OVERHEAD;
    let (since, charged) = (served.since, served.charged);
    assert!(
      charged
        <= Self::bound(
          limits.relay_burst_bytes,
          limits.relay_bytes_per_second,
          since,
          now
        ),
      "a session relayed {charged} charged bytes on a {}/s budget with a \
       burst of {}",
      limits.relay_bytes_per_second,
      limits.relay_burst_bytes
    );
  }

  /// Records that a datagram arrived from this source, dating its bucket
  /// no later than the first moment the service could have filled one.
  fn note_source(&mut self, now: Instant, source: IpAddr) {
    self.sources.entry(source).or_insert(Probed {
      since: now,
      reflections: 0.0,
    });
  }
}

fuzz_target!(|steps: Vec<Step<'_>>| {
  let limits = HelperLimits::default();
  let mut now = Instant::now();
  let mut service = HelperService::new(
    now,
    HelperOptions {
      limits,
      ..HelperOptions::default()
    },
  );
  let mut harness = Harness {
    limits,
    start: now,
    served: HashMap::new(),
    sources: HashMap::new(),
    reflections: 0.0,
    evicting: false,
  };

  for step in &steps {
    match step {
      Step::Admit { session } => {
        if service
          .admit(now, nonce(*session), secret(*session))
          .is_ok()
        {
          harness.served.entry(nonce(*session)).or_insert(Served {
            since: now,
            charged: 0.0,
            relayed: 0,
          });
        }
      }
      Step::Close { session } => {
        service.close(nonce(*session));
        harness.served.remove(&nonce(*session));
      }
      Step::ControlClosed => service.control_closed(now),
      Step::Advance { millis } => {
        now += Duration::from_millis(u64::from(*millis));
      }
      Step::Raw { source, datagram } => {
        let from = source.addr();
        harness.note_source(now, from.ip());
        let outcome = service.handle(now, from, datagram);
        assert!(
          !matches!(outcome, Outcome::Reflect { .. }),
          "an unsigned datagram was answered"
        );
        harness.check(&service, now, from, datagram, &outcome);
      }
      Step::Probe {
        source,
        session,
        destination,
        wrong_secret,
        transaction,
        corrupt,
      } => {
        let role = match destination {
          true => PeerRole::Destination,
          false => PeerRole::Client,
        };
        let label = ProbeLabel::to_helper(nonce(*session), role);
        let signing = match wrong_secret {
          true => secret(session.wrapping_add(1)),
          false => secret(*session),
        };
        let mut datagram =
          BindingTransaction::seeded(label, &signing, u128::from(*transaction))
            .request()
            .to_vec();
        if let Some((at, value)) = corrupt
          && !datagram.is_empty()
        {
          let at = usize::from(*at) % datagram.len();
          datagram[at] ^= *value;
        }
        let from = source.addr();
        harness.note_source(now, from.ip());
        let outcome = service.handle(now, from, &datagram);
        if *wrong_secret && corrupt.is_none() {
          assert!(
            !matches!(outcome, Outcome::Reflect { .. }),
            "a probe signed with another session's secret was answered"
          );
        }
        harness.check(&service, now, from, &datagram, &outcome);
      }
    }
    let _ = service.poll(now);
    assert!(
      service.session_count() <= limits.max_sessions,
      "the service is serving {} sessions on a cap of {}",
      service.session_count(),
      limits.max_sessions
    );
    assert_eq!(
      service.session_count(),
      harness.served.len(),
      "the service and the harness disagree on which sessions are served"
    );
    assert!(
      service.tracked_sources() <= limits.max_probe_sources,
      "the service is tracking {} sources on a cap of {}",
      service.tracked_sources(),
      limits.max_probe_sources
    );
    // A full source table evicts on the next new source, and an evicted
    // bucket comes back full.
    harness.evicting |= service.tracked_sources() >= limits.max_probe_sources;
  }
});
