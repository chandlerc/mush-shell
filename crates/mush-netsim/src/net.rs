// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! A [`SimNet`] owns every socket, link, NAT box, and in-flight datagram of
//! one simulated network.
//!
//! Datagram lifecycle: a send enters synchronously and makes every
//! sender-side and link-level decision on the spot, in a fixed order
//! under one lock -- outbound NAT translation, link blackholes, MTU,
//! loss, duplication, and the latency/jitter sample. Survivors go on a
//! delivery queue ordered by (virtual delivery time, send sequence
//! number); a single pump task sleeps on the tokio clock and moves due
//! datagrams along. The receiver-side decisions -- NAT translation and
//! filtering, and the destination host blackhole -- are only made then,
//! at the arrival instant, against state that may have changed since,
//! exactly as a real path composes sender NAT, WAN latency, then
//! receiver NAT. What survives that second round arrives in the
//! destination inboxes, waking their receivers. Under a paused runtime
//! the pump's sleep is the discrete-event engine: time jumps straight to
//! the next delivery or protocol timer.
//!
//! Every random decision draws from the one seeded network RNG in send
//! order and delivery order is total, so identical seeds and scenarios
//! replay identically.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::Bytes;
use quinn::udp::EcnCodepoint;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::nat::{Nat, NatGrade};
use crate::socket::SimSocket;
use crate::trace::{DropReason, EventKind, NatRejectReason, TraceEvent};

/// Impairment and property configuration for one directed link.
///
/// A link is identified by the pair (sender host IP, final receiver host
/// IP) -- for NATed hosts, the *inside* address on both ends, so tests
/// configure links in the same address terms they bind sockets in. For a
/// NATed receiver the lookup previews the NAT's current mapping at send
/// time (the authoritative translation still happens at arrival); when no
/// live mapping resolves the destination, the public address keys the
/// lookup, which normally falls through to the default. Traffic between
/// hosts with no specific link configured uses the network-wide default.
#[derive(Debug, Clone)]
pub struct LinkConfig {
  /// One-way propagation delay.
  pub latency: Duration,
  /// Extra delay sampled uniformly from `[0, jitter]` per datagram.
  /// Reordering happens naturally when jitter exceeds packet spacing.
  pub jitter: Duration,
  /// Probability a datagram is silently lost. Must be within
  /// `[0.0, 1.0]`; the link setters panic otherwise.
  pub loss: f64,
  /// Probability a datagram is delivered twice (independent jitter each).
  /// Must be within `[0.0, 1.0]`; the link setters panic otherwise.
  pub duplicate: f64,
  /// Datagrams larger than this are silently dropped, which is how
  /// DPLPMTUD probing and MTU black holes are exercised.
  pub mtu: usize,
}

impl Default for LinkConfig {
  /// A quiet link: 5ms latency, no jitter, no loss, MTU 1452 (the default
  /// DPLPMTUD upper bound, so discovery succeeds on default links).
  fn default() -> Self {
    Self {
      latency: Duration::from_millis(5),
      jitter: Duration::ZERO,
      loss: 0.0,
      duplicate: 0.0,
      mtu: 1452,
    }
  }
}

/// Panic on out-of-range probabilities at configuration time, where the
/// mistake is visible. Rejecting them here keeps `rand`'s own range panic
/// from firing later inside a quinn driver task, under the network lock.
fn validate_link(cfg: &LinkConfig) {
  assert!(
    (0.0..=1.0).contains(&cfg.loss),
    "LinkConfig.loss must be within [0.0, 1.0], got {}",
    cfg.loss
  );
  assert!(
    (0.0..=1.0).contains(&cfg.duplicate),
    "LinkConfig.duplicate must be within [0.0, 1.0], got {}",
    cfg.duplicate
  );
}

/// One datagram sitting in a socket's inbox, post-NAT.
pub(crate) struct InboundDatagram {
  pub(crate) src: SocketAddr,
  pub(crate) ecn: Option<EcnCodepoint>,
  pub(crate) payload: Bytes,
}

struct SocketEntry {
  inbox: VecDeque<InboundDatagram>,
  waker: Option<Waker>,
}

/// A datagram scheduled for future delivery.
struct Scheduled {
  deliver_at: Instant,
  /// Network-wide send sequence number: the deterministic tie-breaker for
  /// datagrams due at the same instant.
  seq: u64,
  /// Wire source: post-NAT on the sender side.
  src: SocketAddr,
  /// Wire destination as the sender addressed it; receiver-side NAT
  /// translation happens at delivery.
  dst: SocketAddr,
  /// Whether delivery must consult a receiver-side NAT. False for
  /// traffic within one NAT realm, which never crosses the boundary.
  translate_inbound: bool,
  ecn: Option<EcnCodepoint>,
  payload: Bytes,
}

impl PartialEq for Scheduled {
  fn eq(&self, other: &Self) -> bool {
    self.seq == other.seq
  }
}
impl Eq for Scheduled {}
impl PartialOrd for Scheduled {
  fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
    Some(self.cmp(other))
  }
}
impl Ord for Scheduled {
  fn cmp(&self, other: &Self) -> std::cmp::Ordering {
    (self.deliver_at, self.seq).cmp(&(other.deliver_at, other.seq))
  }
}

struct State {
  rng: StdRng,
  sockets: HashMap<SocketAddr, SocketEntry>,
  default_link: LinkConfig,
  links: HashMap<(IpAddr, IpAddr), LinkConfig>,
  link_blackholes: HashSet<(IpAddr, IpAddr)>,
  host_blackholes: HashSet<IpAddr>,
  nats: Vec<Nat>,
  queue: BinaryHeap<Reverse<Scheduled>>,
  next_seq: u64,
  trace: Vec<TraceEvent>,
}

pub(crate) struct Inner {
  epoch: Instant,
  /// Shared with the pump task, which holds the network itself only
  /// weakly; see [`pump`].
  notify: Arc<Notify>,
  state: Mutex<State>,
}

impl Drop for Inner {
  fn drop(&mut self) {
    // Wake the pump so it observes that every strong handle is gone and
    // exits instead of idling forever.
    self.notify.notify_one();
  }
}

/// Handle to a simulated network. Cheaply cloneable; all clones share the
/// same network.
///
/// Must be created (and used) inside a tokio runtime; for determinism that
/// runtime must be `current_thread` with `start_paused(true)`. See the
/// crate documentation for the full determinism rules.
#[derive(Clone)]
pub struct SimNet {
  inner: Arc<Inner>,
}

/// Handle to one NAT box, for mid-test manipulation.
#[derive(Clone)]
pub struct NatHandle {
  inner: Arc<Inner>,
  idx: usize,
}

impl SimNet {
  /// Create a simulated network whose every random decision derives from
  /// `seed`.
  ///
  /// # Panics
  ///
  /// Panics when called outside a tokio runtime: the network spawns its
  /// delivery pump task immediately.
  pub fn new(seed: u64) -> Self {
    let notify = Arc::new(Notify::new());
    let inner = Arc::new(Inner {
      epoch: Instant::now(),
      notify: notify.clone(),
      state: Mutex::new(State {
        rng: StdRng::seed_from_u64(seed),
        sockets: HashMap::new(),
        default_link: LinkConfig::default(),
        links: HashMap::new(),
        link_blackholes: HashSet::new(),
        host_blackholes: HashSet::new(),
        nats: Vec::new(),
        queue: BinaryHeap::new(),
        next_seq: 0,
        trace: Vec::new(),
      }),
    });
    tokio::spawn(pump(Arc::downgrade(&inner), notify));
    Self { inner }
  }

  /// Bind a socket at a simulated address. Ports are explicit: there is no
  /// ephemeral-port allocation, so `addr` must have a nonzero port.
  pub fn bind(&self, addr: SocketAddr) -> io::Result<SimSocket> {
    if addr.port() == 0 {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "simulated sockets require an explicit nonzero port",
      ));
    }
    let mut st = self.inner.state();
    if st.sockets.contains_key(&addr) {
      return Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        format!("simulated address {addr} is already bound"),
      ));
    }
    st.sockets.insert(
      addr,
      SocketEntry {
        inbox: VecDeque::new(),
        waker: None,
      },
    );
    Ok(SimSocket::new(self.inner.clone(), addr))
  }

  /// Replace the network-wide default link configuration.
  ///
  /// # Panics
  ///
  /// Panics when `cfg.loss` or `cfg.duplicate` is outside `[0.0, 1.0]`.
  pub fn set_default_link(&self, cfg: LinkConfig) {
    validate_link(&cfg);
    self.inner.state().default_link = cfg;
  }

  /// Configure the directed link from `src` to `dst` (host IPs; the inside
  /// addresses for NATed hosts).
  ///
  /// # Panics
  ///
  /// Panics when `cfg.loss` or `cfg.duplicate` is outside `[0.0, 1.0]`.
  pub fn set_link(&self, src: IpAddr, dst: IpAddr, cfg: LinkConfig) {
    validate_link(&cfg);
    self.inner.state().links.insert((src, dst), cfg);
  }

  /// Configure both directions between `a` and `b` identically.
  ///
  /// # Panics
  ///
  /// Panics when `cfg.loss` or `cfg.duplicate` is outside `[0.0, 1.0]`.
  pub fn set_link_symmetric(&self, a: IpAddr, b: IpAddr, cfg: LinkConfig) {
    validate_link(&cfg);
    let mut st = self.inner.state();
    st.links.insert((a, b), cfg.clone());
    st.links.insert((b, a), cfg);
  }

  /// Drop all traffic on the directed link from `src` to `dst`.
  pub fn set_link_blackhole(&self, src: IpAddr, dst: IpAddr, on: bool) {
    let mut st = self.inner.state();
    if on {
      st.link_blackholes.insert((src, dst));
    } else {
      st.link_blackholes.remove(&(src, dst));
    }
  }

  /// Drop all traffic from and to `host` (its inside address if NATed):
  /// a total connectivity outage for that host.
  pub fn set_host_blackhole(&self, host: IpAddr, on: bool) {
    let mut st = self.inner.state();
    if on {
      st.host_blackholes.insert(host);
    } else {
      st.host_blackholes.remove(&host);
    }
  }

  /// Add a NAT box translating between `inside` host addresses and
  /// `public_ip`. `public_ip` is unused for [`NatGrade::FirewallOnly`]
  /// (whose inside addresses are directly routable).
  ///
  /// # Panics
  ///
  /// Panics if `grade` is [`NatGrade::OneToOne`] and `inside` does not name
  /// exactly one host.
  pub fn add_nat(
    &self,
    grade: NatGrade,
    public_ip: IpAddr,
    inside: &[IpAddr],
  ) -> NatHandle {
    let mut st = self.inner.state();
    st.nats.push(Nat::new(grade, public_ip, inside.to_vec()));
    NatHandle {
      inner: self.inner.clone(),
      idx: st.nats.len() - 1,
    }
  }

  /// Snapshot the full event trace, exact datagram sizes included.
  pub fn trace(&self) -> Vec<TraceEvent> {
    self.inner.state().trace.clone()
  }

  /// Snapshot the trace as one line per event with sizes omitted: the view
  /// to compare across runs in determinism assertions. See
  /// [`TraceEvent::summary`] for why sizes are excluded.
  pub fn trace_summary(&self) -> Vec<String> {
    let st = self.inner.state();
    st.trace.iter().map(TraceEvent::summary).collect()
  }

  /// Discard all recorded trace events.
  pub fn clear_trace(&self) {
    self.inner.state().trace.clear();
  }
}

impl NatHandle {
  /// Drop every live mapping, as a rebooted or timed-out NAT would. The
  /// next outbound datagram from each inside socket allocates a fresh
  /// public mapping, which peers observe as an address change.
  pub fn flush_mappings(&self) {
    self.with(Nat::flush);
  }

  /// Set the idle timeout after which unused mappings expire. Only
  /// outbound traffic refreshes a mapping.
  pub fn set_mapping_ttl(&self, ttl: Duration) {
    self.with(|n| n.set_mapping_ttl(ttl));
  }

  /// The NAT's current public IP.
  pub fn public_ip(&self) -> IpAddr {
    self.inner.state().nats[self.idx].public_ip
  }

  fn with(&self, f: impl FnOnce(&mut Nat)) {
    f(&mut self.inner.state().nats[self.idx])
  }
}

impl Inner {
  /// Lock the network state, tolerating poison: the state holds no
  /// invariant a panicking mutation could leave half-established in a way
  /// later operations must not see, and [`SimSocket`]'s `Drop` runs
  /// through here during unwind, where a second panic would abort the
  /// whole process and mask the original failure.
  fn state(&self) -> std::sync::MutexGuard<'_, State> {
    self
      .state
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
  }

  /// Process one datagram send: the full pipeline described in the module
  /// docs, synchronously, then schedule any surviving copies.
  pub(crate) fn send_datagram(
    &self,
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
    ecn: Option<EcnCodepoint>,
  ) -> io::Result<()> {
    let now = Instant::now();
    let at = now.duration_since(self.epoch);
    {
      let mut st = self.state();
      let st = &mut *st;
      let len = payload.len();
      let push = |trace: &mut Vec<TraceEvent>, kind| {
        trace.push(TraceEvent { at, kind });
      };
      push(&mut st.trace, EventKind::Sent { src, dst, len });

      if st.host_blackholes.contains(&src.ip()) {
        push(
          &mut st.trace,
          EventKind::Dropped {
            reason: DropReason::HostBlackhole,
            src,
            dst,
            len,
          },
        );
        return Ok(());
      }

      // Outbound translation at the sender's NAT, if any. Traffic to a
      // destination inside the same realm bypasses the NAT (LAN traffic).
      let mut wire_src = src;
      let mut same_realm = false;
      if let Some(nat) = st.nats.iter_mut().find(|n| n.is_inside(src.ip())) {
        if nat.is_inside(dst.ip()) {
          same_realm = true;
        } else if dst.ip() == nat.public_ip
          && nat.grade != NatGrade::FirewallOnly
        {
          push(
            &mut st.trace,
            EventKind::Dropped {
              reason: DropReason::Hairpin,
              src,
              dst,
              len,
            },
          );
          return Ok(());
        } else {
          let (ws, new_mapping) = nat.outbound(now, &mut st.rng, src, dst);
          wire_src = ws;
          if let Some(m) = new_mapping {
            push(
              &mut st.trace,
              EventKind::NatMapped {
                inside: m.inside,
                outside: m.outside,
              },
            );
          }
        }
      }

      // A side-effect-free preview of the arrival-time translation (see
      // [`LinkConfig`]): the inside address when a live mapping resolves
      // the destination now, the wire address otherwise.
      let link_dst_ip = if same_realm {
        dst.ip()
      } else {
        st.nats
          .iter()
          .find(|n| {
            n.grade != NatGrade::FirewallOnly && n.public_ip == dst.ip()
          })
          .and_then(|n| n.peek_inside_ip(now, dst))
          .unwrap_or(dst.ip())
      };

      // Link-level processing, keyed by original sender and (previewed)
      // final receiver.
      let link_key = (src.ip(), link_dst_ip);
      let cfg = st.links.get(&link_key).unwrap_or(&st.default_link).clone();
      if st.link_blackholes.contains(&link_key) {
        push(
          &mut st.trace,
          EventKind::Dropped {
            reason: DropReason::LinkBlackhole,
            src: wire_src,
            dst,
            len,
          },
        );
        return Ok(());
      }
      if len > cfg.mtu {
        push(
          &mut st.trace,
          EventKind::Dropped {
            reason: DropReason::OversizedMtu,
            src: wire_src,
            dst,
            len,
          },
        );
        return Ok(());
      }
      if st.rng.random_bool(cfg.loss) {
        push(
          &mut st.trace,
          EventKind::Dropped {
            reason: DropReason::Loss,
            src: wire_src,
            dst,
            len,
          },
        );
        return Ok(());
      }
      let duplicated = st.rng.random_bool(cfg.duplicate);
      if duplicated {
        push(
          &mut st.trace,
          EventKind::Duplicated {
            src: wire_src,
            dst,
            len,
          },
        );
      }
      let bytes = Bytes::copy_from_slice(payload);
      let copies = 1 + usize::from(duplicated);
      for _ in 0..copies {
        let jitter = sample_jitter(&mut st.rng, cfg.jitter);
        let seq = st.next_seq;
        st.next_seq += 1;
        st.queue.push(Reverse(Scheduled {
          deliver_at: now + cfg.latency + jitter,
          seq,
          src: wire_src,
          dst,
          translate_inbound: !same_realm,
          ecn,
          payload: bytes.clone(),
        }));
      }
    }
    self.notify.notify_one();
    Ok(())
  }

  /// Move every due datagram from the delivery queue toward its
  /// destination inbox, in (delivery time, sequence) order, and wake
  /// receivers. Receiver-side NAT translation and filtering, and the
  /// destination host blackhole, are evaluated here, at the arrival
  /// instant and against the state of that moment.
  fn deliver_due(&self) {
    let now = Instant::now();
    let mut wakers = Vec::new();
    let mut guard = self.state();
    let st = &mut *guard;
    while st
      .queue
      .peek()
      .is_some_and(|Reverse(s)| s.deliver_at <= now)
    {
      let Reverse(s) = st.queue.pop().unwrap();
      let at = s.deliver_at.duration_since(self.epoch);
      let final_dst = if s.translate_inbound {
        match resolve_inbound(&mut st.nats, s.deliver_at, s.src, s.dst) {
          InboundFate::Deliver(d) => d,
          InboundFate::NatRejected(reason) => {
            st.trace.push(TraceEvent {
              at,
              kind: EventKind::NatRejected {
                reason,
                src: s.src,
                dst: s.dst,
              },
            });
            continue;
          }
          InboundFate::Unroutable => {
            st.trace.push(TraceEvent {
              at,
              kind: EventKind::Dropped {
                reason: DropReason::UnroutableInsideAddr,
                src: s.src,
                dst: s.dst,
                len: s.payload.len(),
              },
            });
            continue;
          }
        }
      } else {
        s.dst
      };
      if st.host_blackholes.contains(&final_dst.ip()) {
        st.trace.push(TraceEvent {
          at,
          kind: EventKind::Dropped {
            reason: DropReason::HostBlackhole,
            src: s.src,
            dst: final_dst,
            len: s.payload.len(),
          },
        });
        continue;
      }
      match st.sockets.get_mut(&final_dst) {
        None => st.trace.push(TraceEvent {
          at,
          kind: EventKind::Dropped {
            reason: DropReason::NoSocket,
            src: s.src,
            dst: final_dst,
            len: s.payload.len(),
          },
        }),
        Some(entry) => {
          st.trace.push(TraceEvent {
            at,
            kind: EventKind::Delivered {
              src: s.src,
              dst: final_dst,
              len: s.payload.len(),
            },
          });
          entry.inbox.push_back(InboundDatagram {
            src: s.src,
            ecn: s.ecn,
            payload: s.payload,
          });
          if let Some(w) = entry.waker.take() {
            wakers.push(w);
          }
        }
      }
    }
    drop(guard);
    for w in wakers {
      w.wake();
    }
  }

  /// Poll for one datagram from the inbox of the socket bound at `addr`,
  /// copying as much as fits into `buf` (excess is discarded, standard UDP
  /// truncation semantics).
  pub(crate) fn poll_recv_from(
    &self,
    addr: SocketAddr,
    cx: &mut Context<'_>,
    buf: &mut [u8],
  ) -> Poll<io::Result<(usize, SocketAddr, Option<EcnCodepoint>)>> {
    let mut st = self.state();
    let Some(entry) = st.sockets.get_mut(&addr) else {
      return Poll::Ready(Err(io::Error::new(
        io::ErrorKind::NotConnected,
        format!("simulated socket {addr} is no longer bound"),
      )));
    };
    match entry.inbox.pop_front() {
      Some(d) => {
        let n = d.payload.len().min(buf.len());
        buf[..n].copy_from_slice(&d.payload[..n]);
        Poll::Ready(Ok((n, d.src, d.ecn)))
      }
      None => {
        entry.waker = Some(cx.waker().clone());
        Poll::Pending
      }
    }
  }

  pub(crate) fn unbind(&self, addr: SocketAddr) {
    self.state().sockets.remove(&addr);
  }
}

fn sample_jitter(rng: &mut StdRng, jitter: Duration) -> Duration {
  if jitter.is_zero() {
    return Duration::ZERO;
  }
  let max_micros = u64::try_from(jitter.as_micros()).unwrap_or(u64::MAX);
  Duration::from_micros(rng.random_range(0..=max_micros))
}

/// What the receiver side decided about one arriving datagram.
enum InboundFate {
  /// Deliver to this (inside) destination.
  Deliver(SocketAddr),
  /// A NAT rejected it; trace and drop.
  NatRejected(NatRejectReason),
  /// The destination is a translating NAT's inside address, unreachable
  /// from outside its realm.
  Unroutable,
}

/// Receiver-side NAT resolution for one arriving datagram: translate at a
/// NAT owning the destination's public address, filter at a firewall
/// protecting it, or pass it through untouched.
fn resolve_inbound(
  nats: &mut [Nat],
  now: Instant,
  wire_src: SocketAddr,
  dst: SocketAddr,
) -> InboundFate {
  if let Some(nat) = nats
    .iter_mut()
    .find(|n| n.grade != NatGrade::FirewallOnly && n.public_ip == dst.ip())
  {
    return match nat.inbound(now, wire_src, dst) {
      Ok(d) => InboundFate::Deliver(d),
      Err(reason) => InboundFate::NatRejected(reason),
    };
  }
  if let Some(nat) = nats.iter_mut().find(|n| n.is_inside(dst.ip())) {
    if nat.grade != NatGrade::FirewallOnly {
      return InboundFate::Unroutable;
    }
    return match nat.inbound(now, wire_src, dst) {
      Ok(d) => InboundFate::Deliver(d),
      Err(reason) => InboundFate::NatRejected(reason),
    };
  }
  InboundFate::Deliver(dst)
}

/// The delivery pump: the only task that moves datagrams. It sleeps on the
/// (virtual) clock until the earliest scheduled delivery, preempted by the
/// network's notify whenever a send schedules something earlier.
///
/// The pump holds the network only weakly and exits once every strong
/// handle ([`SimNet`], [`SimSocket`], [`NatHandle`]) is gone -- woken by
/// [`Inner`]'s `Drop` -- so a long-lived runtime hosting many simulated
/// networks (seed sweeps, fuzzing) does not accumulate pump tasks or
/// network state.
async fn pump(inner: std::sync::Weak<Inner>, notify: Arc<Notify>) {
  loop {
    let next = {
      let Some(inner) = inner.upgrade() else { return };
      let st = inner.state();
      st.queue.peek().map(|Reverse(s)| s.deliver_at)
    };
    match next {
      None => notify.notified().await,
      Some(at) => {
        tokio::select! {
          biased;
          _ = notify.notified() => {}
          _ = tokio::time::sleep_until(at) => {
            let Some(inner) = inner.upgrade() else { return };
            inner.deliver_due();
          }
        }
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// The pump must not keep a dropped network alive; see [`pump`].
  #[tokio::test(start_paused = true)]
  async fn dropping_all_handles_frees_the_network_and_stops_the_pump() {
    let net = SimNet::new(1);
    let weak = Arc::downgrade(&net.inner);
    let notify = net.inner.notify.clone();
    let sock = net.bind("10.0.0.1:100".parse().unwrap()).unwrap();
    sock.send_to(b"x", "10.0.0.2:200".parse().unwrap()).unwrap();
    drop(sock);
    drop(net);
    assert_eq!(weak.strong_count(), 0, "pump must hold the network weakly");
    // Let the woken pump run, observe the drop, and exit, releasing its
    // clone of the notify handle.
    for _ in 0..4 {
      tokio::task::yield_now().await;
    }
    assert_eq!(
      Arc::strong_count(&notify),
      1,
      "pump task should have exited"
    );
  }
}
