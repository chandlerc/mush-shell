// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! NAT boxes: address-translation state machines between an inside realm
//! and the outside world.
//!
//! Each [`Nat`] is a pure state machine: the simulated network applies it
//! per-datagram and passes the current virtual time and the network RNG in,
//! so the models are directly unit-testable without a running network or a
//! tokio runtime.
//!
//! Grades follow RFC 4787 terminology for mapping and filtering behavior:
//!
//! | grade                | mapping                    | filtering          |
//! |----------------------|----------------------------|--------------------|
//! | `Open`               | endpoint-independent (EIM) | none (EIF)         |
//! | `AddressRestricted`  | EIM                        | by remote IP (ADF) |
//! | `PortRestricted`     | EIM                        | by remote IP:port  |
//! | `Symmetric`          | endpoint-dependent (EDM)   | by remote IP:port  |
//! | `OneToOne`           | 1:1, port-preserving       | none, stateless    |
//! | `FirewallOnly`       | none (public inside addrs) | by remote IP:port  |
//!
//! Mappings idle out on the virtual clock, and filtering state expires
//! independently per remote endpoint: each mapping (or pinhole) remembers
//! when the inside socket last sent to each remote, and a filter entry
//! older than the TTL stops admitting its remote even while traffic to
//! other remotes keeps the mapping itself alive -- RFC 4787 gives
//! filtering state its own timer, and conntrack-style firewalls expire
//! per-flow, so a missing keep-alive toward one peer must be observable
//! even when a helper or rendezvous flow stays busy. Only outbound traffic
//! refreshes state (the conservative model; many consumer NATs also
//! refresh on inbound, but assuming they do not is the safe behavior to
//! test against). Hairpinning is not modeled; the simulated network drops
//! hairpin traffic.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use rand::Rng;
use rand::rngs::StdRng;
use tokio::time::Instant;

use crate::trace::NatRejectReason;

/// Range public ports are allocated from, using the network RNG.
const PORT_RANGE: std::ops::Range<u16> = 40000..60000;

/// Default idle timeout for mappings and pinholes. Matches the short end of
/// real-world UDP NAT timeouts so tests exercising keep-alives see a
/// realistic timeout.
pub(crate) const DEFAULT_MAPPING_TTL: Duration = Duration::from_secs(30);

/// NAT behavior grade. See the module docs for the RFC 4787 mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatGrade {
  /// Endpoint-independent mapping and filtering ("full cone"). Anyone may
  /// send to a public mapping once it exists.
  Open,
  /// Endpoint-independent mapping; inbound allowed only from IP addresses
  /// the inside socket has previously sent to (any port).
  AddressRestricted,
  /// Endpoint-independent mapping; inbound allowed only from exact
  /// IP:port endpoints the inside socket has previously sent to.
  PortRestricted,
  /// Endpoint-dependent mapping (a fresh public port per remote endpoint)
  /// with exact-endpoint filtering. Defeats reflexive-address traversal.
  Symmetric,
  /// Stateless 1:1 port-preserving translation between one inside host and
  /// one public IP, with unsolicited inbound allowed (cloud-VM style).
  OneToOne,
  /// No translation: inside addresses are publicly routable, but inbound
  /// traffic must match a pinhole created by earlier outbound traffic to
  /// the exact remote endpoint (stateful firewall).
  FirewallOnly,
}

/// One live mapping (translating grades) or pinhole (`FirewallOnly`).
struct Mapping {
  inside: SocketAddr,
  /// `Some` only for `Symmetric`, whose mappings are per-remote.
  remote: Option<SocketAddr>,
  public_port: u16,
  last_send: Instant,
  /// Remote endpoints the inside socket has sent to through this mapping,
  /// each with the most recent send toward it. The filtering policies
  /// read this; entries idle out on the TTL independently of the
  /// mapping.
  peers: Vec<(SocketAddr, Instant)>,
}

/// A NAT box between its inside hosts and the outside address space.
pub(crate) struct Nat {
  pub(crate) grade: NatGrade,
  pub(crate) public_ip: IpAddr,
  inside: Vec<IpAddr>,
  ttl: Duration,
  mappings: Vec<Mapping>,
}

/// A newly created mapping, reported so the network can trace it.
pub(crate) struct NewMapping {
  pub(crate) inside: SocketAddr,
  pub(crate) outside: SocketAddr,
}

impl Nat {
  pub(crate) fn new(
    grade: NatGrade,
    public_ip: IpAddr,
    inside: Vec<IpAddr>,
  ) -> Self {
    if grade == NatGrade::OneToOne {
      assert_eq!(
        inside.len(),
        1,
        "OneToOne NAT maps exactly one inside host to one public IP"
      );
    }
    Self {
      grade,
      public_ip,
      inside,
      ttl: DEFAULT_MAPPING_TTL,
      mappings: Vec::new(),
    }
  }

  pub(crate) fn is_inside(&self, ip: IpAddr) -> bool {
    self.inside.contains(&ip)
  }

  pub(crate) fn flush(&mut self) {
    self.mappings.clear();
  }

  pub(crate) fn set_mapping_ttl(&mut self, ttl: Duration) {
    self.ttl = ttl;
  }

  fn prune(&mut self, now: Instant) {
    let ttl = self.ttl;
    self.mappings.retain_mut(|m| {
      if now.duration_since(m.last_send) > ttl {
        return false;
      }
      m.peers.retain(|(_, sent)| now.duration_since(*sent) <= ttl);
      true
    });
  }

  fn alloc_port(&self, rng: &mut StdRng) -> u16 {
    loop {
      let port = rng.random_range(PORT_RANGE);
      if !self.mappings.iter().any(|m| m.public_port == port) {
        return port;
      }
    }
  }

  /// Translate an outbound datagram from inside socket `src` to `dst`.
  ///
  /// Returns the wire source address and, when this call created a new
  /// mapping or pinhole, its description for the event trace. Outbound
  /// traffic always passes; it creates or refreshes state as a side effect.
  pub(crate) fn outbound(
    &mut self,
    now: Instant,
    rng: &mut StdRng,
    src: SocketAddr,
    dst: SocketAddr,
  ) -> (SocketAddr, Option<NewMapping>) {
    self.prune(now);
    match self.grade {
      NatGrade::OneToOne => (SocketAddr::new(self.public_ip, src.port()), None),
      NatGrade::FirewallOnly => {
        let created = self.touch_mapping(now, rng, src, dst, false);
        (
          src,
          created.then_some(NewMapping {
            inside: src,
            outside: src,
          }),
        )
      }
      NatGrade::Open
      | NatGrade::AddressRestricted
      | NatGrade::PortRestricted => {
        let created = self.touch_mapping(now, rng, src, dst, false);
        let port = self
          .find_eim(src)
          .expect("mapping just touched")
          .public_port;
        let outside = SocketAddr::new(self.public_ip, port);
        (
          outside,
          created.then_some(NewMapping {
            inside: src,
            outside,
          }),
        )
      }
      NatGrade::Symmetric => {
        let created = self.touch_mapping(now, rng, src, dst, true);
        let port = self
          .mappings
          .iter()
          .find(|m| m.inside == src && m.remote == Some(dst))
          .expect("mapping just touched")
          .public_port;
        let outside = SocketAddr::new(self.public_ip, port);
        (
          outside,
          created.then_some(NewMapping {
            inside: src,
            outside,
          }),
        )
      }
    }
  }

  /// Find or create the mapping for `src` (and `dst`, when `per_remote`),
  /// refresh it, and record `dst` as a contacted peer. Returns whether the
  /// mapping was newly created.
  fn touch_mapping(
    &mut self,
    now: Instant,
    rng: &mut StdRng,
    src: SocketAddr,
    dst: SocketAddr,
    per_remote: bool,
  ) -> bool {
    let key_remote = per_remote.then_some(dst);
    let existing = self
      .mappings
      .iter_mut()
      .find(|m| m.inside == src && m.remote == key_remote);
    match existing {
      Some(m) => {
        m.last_send = now;
        match m.peers.iter_mut().find(|(p, _)| *p == dst) {
          Some((_, sent)) => *sent = now,
          None => m.peers.push((dst, now)),
        }
        false
      }
      None => {
        let public_port = if self.grade == NatGrade::FirewallOnly {
          src.port()
        } else {
          self.alloc_port(rng)
        };
        self.mappings.push(Mapping {
          inside: src,
          remote: key_remote,
          public_port,
          last_send: now,
          peers: vec![(dst, now)],
        });
        true
      }
    }
  }

  fn find_eim(&self, inside: SocketAddr) -> Option<&Mapping> {
    self
      .mappings
      .iter()
      .find(|m| m.inside == inside && m.remote.is_none())
  }

  /// Resolve, without side effects, the inside address a datagram to
  /// public address `dst` would reach right now, or `None` when no live
  /// mapping matches. The network uses this only to pick link
  /// configuration at send time; the authoritative translation happens at
  /// arrival via [`Self::inbound`].
  pub(crate) fn peek_inside_ip(
    &self,
    now: Instant,
    dst: SocketAddr,
  ) -> Option<IpAddr> {
    match self.grade {
      NatGrade::OneToOne => Some(self.inside[0]),
      NatGrade::FirewallOnly => Some(dst.ip()),
      NatGrade::Open
      | NatGrade::AddressRestricted
      | NatGrade::PortRestricted
      | NatGrade::Symmetric => self
        .mappings
        .iter()
        .find(|m| {
          m.public_port == dst.port()
            && now.duration_since(m.last_send) <= self.ttl
        })
        .map(|m| m.inside.ip()),
    }
  }

  /// Translate and filter an inbound datagram from `wire_src` to `dst`.
  ///
  /// For translating grades `dst` is a public address of this NAT; for
  /// `FirewallOnly` it is the (public) inside address itself. Returns the
  /// final destination or the rejection reason. Inbound traffic does not
  /// refresh mappings.
  pub(crate) fn inbound(
    &mut self,
    now: Instant,
    wire_src: SocketAddr,
    dst: SocketAddr,
  ) -> Result<SocketAddr, NatRejectReason> {
    self.prune(now);
    match self.grade {
      NatGrade::OneToOne => Ok(SocketAddr::new(self.inside[0], dst.port())),
      NatGrade::FirewallOnly => {
        let m = self
          .mappings
          .iter()
          .find(|m| m.inside == dst)
          .ok_or(NatRejectReason::NoMapping)?;
        if m.peers.iter().any(|(p, _)| *p == wire_src) {
          Ok(dst)
        } else {
          Err(NatRejectReason::Filtered)
        }
      }
      NatGrade::Open
      | NatGrade::AddressRestricted
      | NatGrade::PortRestricted => {
        let m = self
          .mappings
          .iter()
          .find(|m| m.public_port == dst.port())
          .ok_or(NatRejectReason::NoMapping)?;
        let allowed = match self.grade {
          NatGrade::Open => true,
          NatGrade::AddressRestricted => {
            m.peers.iter().any(|(p, _)| p.ip() == wire_src.ip())
          }
          _ => m.peers.iter().any(|(p, _)| *p == wire_src),
        };
        if allowed {
          Ok(m.inside)
        } else {
          Err(NatRejectReason::Filtered)
        }
      }
      NatGrade::Symmetric => {
        let m = self
          .mappings
          .iter()
          .find(|m| m.public_port == dst.port())
          .ok_or(NatRejectReason::NoMapping)?;
        if m.remote == Some(wire_src) {
          Ok(m.inside)
        } else {
          Err(NatRejectReason::Filtered)
        }
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use rand::SeedableRng;

  use super::*;

  const PUBLIC: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(5, 5, 5, 5));

  fn inside_ip() -> IpAddr {
    "192.168.1.2".parse().unwrap()
  }

  fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
  }

  fn nat(grade: NatGrade) -> (Nat, StdRng, Instant) {
    (
      Nat::new(grade, PUBLIC, vec![inside_ip()]),
      StdRng::seed_from_u64(7),
      Instant::now(),
    )
  }

  #[test]
  fn open_maps_endpoint_independently_and_accepts_anyone() {
    let (mut nat, mut rng, t0) = nat(NatGrade::Open);
    let src = addr("192.168.1.2:1000");
    let (pub1, new1) = nat.outbound(t0, &mut rng, src, addr("8.8.8.8:53"));
    let (pub2, new2) = nat.outbound(t0, &mut rng, src, addr("9.9.9.9:99"));
    assert!(new1.is_some());
    assert!(new2.is_none(), "EIM reuses the mapping for a second remote");
    assert_eq!(pub1, pub2);
    assert_eq!(pub1.ip(), PUBLIC);
    // EIF: a never-contacted host may send inbound.
    assert_eq!(nat.inbound(t0, addr("7.7.7.7:1"), pub1), Ok(src));
  }

  #[test]
  fn address_restricted_filters_by_remote_ip() {
    let (mut nat, mut rng, t0) = nat(NatGrade::AddressRestricted);
    let src = addr("192.168.1.2:1000");
    let (public, _) = nat.outbound(t0, &mut rng, src, addr("8.8.8.8:53"));
    // Same IP, different port: allowed (ADF).
    assert_eq!(nat.inbound(t0, addr("8.8.8.8:5300"), public), Ok(src));
    // Different IP: filtered.
    assert_eq!(
      nat.inbound(t0, addr("7.7.7.7:53"), public),
      Err(NatRejectReason::Filtered)
    );
  }

  #[test]
  fn port_restricted_filters_by_exact_endpoint() {
    let (mut nat, mut rng, t0) = nat(NatGrade::PortRestricted);
    let src = addr("192.168.1.2:1000");
    let (public, _) = nat.outbound(t0, &mut rng, src, addr("8.8.8.8:53"));
    assert_eq!(nat.inbound(t0, addr("8.8.8.8:53"), public), Ok(src));
    assert_eq!(
      nat.inbound(t0, addr("8.8.8.8:54"), public),
      Err(NatRejectReason::Filtered)
    );
    assert_eq!(
      nat.inbound(t0, addr("7.7.7.7:53"), public),
      Err(NatRejectReason::Filtered)
    );
  }

  #[test]
  fn symmetric_allocates_per_destination_and_filters_exactly() {
    let (mut nat, mut rng, t0) = nat(NatGrade::Symmetric);
    let src = addr("192.168.1.2:1000");
    let r1 = addr("8.8.8.8:53");
    let r2 = addr("9.9.9.9:99");
    let (pub1, new1) = nat.outbound(t0, &mut rng, src, r1);
    let (pub2, new2) = nat.outbound(t0, &mut rng, src, r2);
    assert!(new1.is_some() && new2.is_some(), "EDM maps per remote");
    assert_ne!(pub1.port(), pub2.port());
    // Each mapping accepts exactly its own remote.
    assert_eq!(nat.inbound(t0, r1, pub1), Ok(src));
    assert_eq!(nat.inbound(t0, r2, pub2), Ok(src));
    assert_eq!(nat.inbound(t0, r2, pub1), Err(NatRejectReason::Filtered));
    assert_eq!(nat.inbound(t0, r1, pub2), Err(NatRejectReason::Filtered));
  }

  #[test]
  fn one_to_one_preserves_ports_and_needs_no_state() {
    let (mut nat, mut rng, t0) = nat(NatGrade::OneToOne);
    let src = addr("192.168.1.2:1000");
    let (public, new) = nat.outbound(t0, &mut rng, src, addr("8.8.8.8:53"));
    assert_eq!(public, addr("5.5.5.5:1000"));
    assert!(new.is_none());
    // Unsolicited inbound to any port translates straight through.
    assert_eq!(
      nat.inbound(t0, addr("7.7.7.7:1"), addr("5.5.5.5:2222")),
      Ok(addr("192.168.1.2:2222"))
    );
  }

  #[test]
  fn firewall_only_passes_addresses_but_requires_a_pinhole() {
    let (mut nat, mut rng, t0) = nat(NatGrade::FirewallOnly);
    let src = addr("192.168.1.2:1000");
    let remote = addr("8.8.8.8:53");
    // Unsolicited inbound: no pinhole yet.
    assert_eq!(
      nat.inbound(t0, remote, src),
      Err(NatRejectReason::NoMapping)
    );
    let (wire, new) = nat.outbound(t0, &mut rng, src, remote);
    assert_eq!(wire, src, "no translation");
    assert!(new.is_some(), "pinhole creation is reported");
    assert_eq!(nat.inbound(t0, remote, src), Ok(src));
    // Exact-endpoint filtering: same IP, different port is rejected.
    assert_eq!(
      nat.inbound(t0, addr("8.8.8.8:54"), src),
      Err(NatRejectReason::Filtered)
    );
  }

  #[test]
  fn mappings_expire_after_the_idle_ttl() {
    let (mut nat, mut rng, t0) = nat(NatGrade::PortRestricted);
    let src = addr("192.168.1.2:1000");
    let remote = addr("8.8.8.8:53");
    let (public, _) = nat.outbound(t0, &mut rng, src, remote);
    let just_alive = t0 + DEFAULT_MAPPING_TTL;
    assert_eq!(nat.inbound(just_alive, remote, public), Ok(src));
    let expired = t0 + DEFAULT_MAPPING_TTL + Duration::from_millis(1);
    assert_eq!(
      nat.inbound(expired, remote, public),
      Err(NatRejectReason::NoMapping)
    );
    // The next outbound datagram re-establishes a mapping.
    let (public2, new) = nat.outbound(expired, &mut rng, src, remote);
    assert!(new.is_some());
    assert_eq!(nat.inbound(expired, remote, public2), Ok(src));
  }

  #[test]
  fn outbound_traffic_refreshes_the_ttl() {
    let (mut nat, mut rng, t0) = nat(NatGrade::PortRestricted);
    let src = addr("192.168.1.2:1000");
    let remote = addr("8.8.8.8:53");
    let (public, _) = nat.outbound(t0, &mut rng, src, remote);
    let mid = t0 + DEFAULT_MAPPING_TTL / 2;
    let (public2, new) = nat.outbound(mid, &mut rng, src, remote);
    assert_eq!(public, public2);
    assert!(new.is_none());
    // Past the original expiry but within the refreshed window.
    let later = t0 + DEFAULT_MAPPING_TTL + Duration::from_secs(1);
    assert_eq!(nat.inbound(later, remote, public), Ok(src));
  }

  #[test]
  fn filter_entries_expire_per_peer() {
    let (mut nat, mut rng, t0) = nat(NatGrade::PortRestricted);
    let src = addr("192.168.1.2:1000");
    let peer = addr("8.8.8.8:53");
    let helper = addr("9.9.9.9:99");
    let (public, _) = nat.outbound(t0, &mut rng, src, peer);
    // Steady traffic to the helper keeps the mapping alive well past the
    // peer's filter lifetime...
    let mut t = t0;
    while t < t0 + DEFAULT_MAPPING_TTL * 3 {
      t += DEFAULT_MAPPING_TTL / 3;
      let (public2, _) = nat.outbound(t, &mut rng, src, helper);
      assert_eq!(public, public2, "EIM mapping survives");
    }
    // ...so the helper still passes the filter...
    assert_eq!(nat.inbound(t, helper, public), Ok(src));
    // ...but the peer's filter entry has idled out on its own timer.
    assert_eq!(nat.inbound(t, peer, public), Err(NatRejectReason::Filtered));
    // A fresh outbound toward the peer reopens it.
    nat.outbound(t, &mut rng, src, peer);
    assert_eq!(nat.inbound(t, peer, public), Ok(src));
  }

  #[test]
  fn firewall_pinholes_expire_per_peer() {
    let (mut nat, mut rng, t0) = nat(NatGrade::FirewallOnly);
    let src = addr("192.168.1.2:1000");
    let r1 = addr("8.8.8.8:53");
    let r2 = addr("9.9.9.9:99");
    nat.outbound(t0, &mut rng, src, r1);
    let mid = t0 + DEFAULT_MAPPING_TTL / 2;
    nat.outbound(mid, &mut rng, src, r2);
    let past_r1 = t0 + DEFAULT_MAPPING_TTL + Duration::from_millis(1);
    // Traffic toward r2 kept the inside socket's state alive, but r1's
    // pinhole expired individually.
    assert_eq!(nat.inbound(past_r1, r2, src), Ok(src));
    assert_eq!(
      nat.inbound(past_r1, r1, src),
      Err(NatRejectReason::Filtered)
    );
  }

  #[test]
  fn flush_and_ttl_config_hooks_work() {
    let (mut nat, mut rng, t0) = nat(NatGrade::PortRestricted);
    let src = addr("192.168.1.2:1000");
    let remote = addr("8.8.8.8:53");
    let (public, _) = nat.outbound(t0, &mut rng, src, remote);
    nat.flush();
    assert_eq!(
      nat.inbound(t0, remote, public),
      Err(NatRejectReason::NoMapping)
    );
    // A short configured TTL expires mappings sooner than the default.
    nat.set_mapping_ttl(Duration::from_secs(1));
    let (public2, _) = nat.outbound(t0, &mut rng, src, remote);
    let expired = t0 + Duration::from_secs(2);
    assert_eq!(
      nat.inbound(expired, remote, public2),
      Err(NatRejectReason::NoMapping)
    );
  }
}
