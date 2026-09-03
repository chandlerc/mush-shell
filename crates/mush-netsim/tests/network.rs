// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Tests of the simulated network itself: raw datagram behavior, no quinn
//! involved.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use mush_netsim::{
  DropReason, EventKind, LinkConfig, NatGrade, NatRejectReason, SimNet,
};

fn ip(s: &str) -> IpAddr {
  s.parse().unwrap()
}

fn addr(s: &str) -> SocketAddr {
  s.parse().unwrap()
}

fn has_drop(net: &SimNet, want: DropReason) -> bool {
  net.trace().iter().any(
    |e| matches!(&e.kind, EventKind::Dropped { reason, .. } if *reason == want),
  )
}

#[tokio::test(start_paused = true)]
async fn delivers_after_the_configured_latency() {
  let net = SimNet::new(1);
  net.set_default_link(LinkConfig {
    latency: Duration::from_millis(25),
    ..LinkConfig::default()
  });
  let a = net.bind(addr("10.0.0.1:100")).unwrap();
  let b = net.bind(addr("10.0.0.2:200")).unwrap();
  let start = tokio::time::Instant::now();
  a.send_to(b"hello", b.addr()).unwrap();
  let mut buf = [0u8; 16];
  let (n, src) = b.recv_from(&mut buf).await.unwrap();
  assert_eq!(&buf[..n], b"hello");
  assert_eq!(src, a.addr());
  let elapsed = start.elapsed();
  assert!(elapsed >= Duration::from_millis(25), "elapsed {elapsed:?}");
  assert!(elapsed < Duration::from_millis(30), "elapsed {elapsed:?}");
}

#[tokio::test(start_paused = true)]
async fn total_loss_drops_and_traces() {
  let net = SimNet::new(2);
  net.set_default_link(LinkConfig {
    loss: 1.0,
    ..LinkConfig::default()
  });
  let a = net.bind(addr("10.0.0.1:100")).unwrap();
  let b = net.bind(addr("10.0.0.2:200")).unwrap();
  a.send_to(b"gone", b.addr()).unwrap();
  let mut buf = [0u8; 16];
  let timed_out =
    tokio::time::timeout(Duration::from_secs(1), b.recv_from(&mut buf))
      .await
      .is_err();
  assert!(timed_out);
  assert!(has_drop(&net, DropReason::Loss));
}

#[tokio::test(start_paused = true)]
async fn duplication_delivers_two_copies() {
  let net = SimNet::new(3);
  net.set_default_link(LinkConfig {
    duplicate: 1.0,
    ..LinkConfig::default()
  });
  let a = net.bind(addr("10.0.0.1:100")).unwrap();
  let b = net.bind(addr("10.0.0.2:200")).unwrap();
  a.send_to(b"twice", b.addr()).unwrap();
  let mut buf = [0u8; 16];
  for _ in 0..2 {
    let (n, _) = b.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"twice");
  }
  let dups = net
    .trace()
    .iter()
    .filter(|e| matches!(e.kind, EventKind::Duplicated { .. }))
    .count();
  assert_eq!(dups, 1);
}

#[tokio::test(start_paused = true)]
async fn oversized_datagrams_are_silently_dropped() {
  let net = SimNet::new(4);
  let a = net.bind(addr("10.0.0.1:100")).unwrap();
  let b = net.bind(addr("10.0.0.2:200")).unwrap();
  // Default link MTU is 1452.
  a.send_to(&[0u8; 2000], b.addr()).unwrap();
  a.send_to(b"fits", b.addr()).unwrap();
  let mut buf = [0u8; 16];
  let (n, _) = b.recv_from(&mut buf).await.unwrap();
  assert_eq!(&buf[..n], b"fits", "only the small datagram arrives");
  assert!(has_drop(&net, DropReason::OversizedMtu));
}

#[tokio::test(start_paused = true)]
async fn host_blackhole_cuts_both_directions() {
  let net = SimNet::new(5);
  let a = net.bind(addr("10.0.0.1:100")).unwrap();
  let b = net.bind(addr("10.0.0.2:200")).unwrap();
  net.set_host_blackhole(ip("10.0.0.1"), true);
  a.send_to(b"out", b.addr()).unwrap();
  b.send_to(b"in", a.addr()).unwrap();
  let mut buf = [0u8; 16];
  assert!(
    tokio::time::timeout(Duration::from_secs(1), b.recv_from(&mut buf))
      .await
      .is_err()
  );
  assert!(
    tokio::time::timeout(Duration::from_secs(1), a.recv_from(&mut buf))
      .await
      .is_err()
  );
  net.set_host_blackhole(ip("10.0.0.1"), false);
  a.send_to(b"back", b.addr()).unwrap();
  let (n, _) = b.recv_from(&mut buf).await.unwrap();
  assert_eq!(&buf[..n], b"back");
}

#[tokio::test(start_paused = true)]
async fn link_blackhole_is_directional() {
  let net = SimNet::new(6);
  let a = net.bind(addr("10.0.0.1:100")).unwrap();
  let b = net.bind(addr("10.0.0.2:200")).unwrap();
  net.set_link_blackhole(ip("10.0.0.1"), ip("10.0.0.2"), true);
  a.send_to(b"blocked", b.addr()).unwrap();
  b.send_to(b"open", a.addr()).unwrap();
  let mut buf = [0u8; 16];
  let (n, _) = a.recv_from(&mut buf).await.unwrap();
  assert_eq!(&buf[..n], b"open");
  assert!(
    tokio::time::timeout(Duration::from_secs(1), b.recv_from(&mut buf))
      .await
      .is_err()
  );
  assert!(has_drop(&net, DropReason::LinkBlackhole));
}

#[tokio::test(start_paused = true)]
async fn per_link_overrides_beat_the_default_per_direction() {
  let net = SimNet::new(10);
  net.set_link(
    ip("10.0.0.1"),
    ip("10.0.0.2"),
    LinkConfig {
      latency: Duration::from_millis(100),
      ..LinkConfig::default()
    },
  );
  let a = net.bind(addr("10.0.0.1:100")).unwrap();
  let b = net.bind(addr("10.0.0.2:200")).unwrap();
  let mut buf = [0u8; 16];

  let start = tokio::time::Instant::now();
  a.send_to(b"slow", b.addr()).unwrap();
  b.recv_from(&mut buf).await.unwrap();
  assert_eq!(start.elapsed(), Duration::from_millis(100));

  // The reverse direction is unconfigured and keeps the 5ms default.
  let start = tokio::time::Instant::now();
  b.send_to(b"fast", a.addr()).unwrap();
  a.recv_from(&mut buf).await.unwrap();
  assert_eq!(start.elapsed(), Duration::from_millis(5));
}

#[tokio::test(start_paused = true)]
async fn binding_a_bound_address_fails_until_dropped() {
  let net = SimNet::new(7);
  let a = net.bind(addr("10.0.0.1:100")).unwrap();
  let err = net.bind(addr("10.0.0.1:100")).unwrap_err();
  assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
  drop(a);
  net.bind(addr("10.0.0.1:100")).unwrap();
}

#[tokio::test(start_paused = true)]
async fn nat_translates_and_filters_end_to_end() {
  let net = SimNet::new(8);
  let nat = net.add_nat(
    NatGrade::PortRestricted,
    ip("5.5.5.5"),
    &[ip("192.168.1.2")],
  );
  let client = net.bind(addr("192.168.1.2:1111")).unwrap();
  let server = net.bind(addr("8.8.8.8:2000")).unwrap();
  let outsider = net.bind(addr("7.7.7.7:3000")).unwrap();

  client.send_to(b"ping", server.addr()).unwrap();
  let mut buf = [0u8; 16];
  let (n, mapped) = server.recv_from(&mut buf).await.unwrap();
  assert_eq!(&buf[..n], b"ping");
  assert_eq!(mapped.ip(), nat.public_ip(), "server sees the public IP");
  assert_ne!(mapped, client.addr());

  // The reply to the mapping reaches the inside socket.
  server.send_to(b"pong", mapped).unwrap();
  let (n, from) = client.recv_from(&mut buf).await.unwrap();
  assert_eq!(&buf[..n], b"pong");
  assert_eq!(from, server.addr());

  // A third party sending to the same mapping is filtered out.
  outsider.send_to(b"intrude", mapped).unwrap();
  assert!(
    tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
      .await
      .is_err()
  );
  let rejected = net.trace().iter().any(|e| {
    matches!(
      e.kind,
      EventKind::NatRejected {
        reason: NatRejectReason::Filtered,
        ..
      }
    )
  });
  assert!(rejected);
  let mapped_events = net
    .trace()
    .iter()
    .filter(|e| matches!(e.kind, EventKind::NatMapped { .. }))
    .count();
  assert_eq!(mapped_events, 1, "EIM: one mapping for the inside socket");
}

#[tokio::test(start_paused = true)]
#[should_panic(expected = "LinkConfig.loss must be within [0.0, 1.0]")]
async fn out_of_range_loss_panics_at_configuration_time() {
  let net = SimNet::new(20);
  net.set_default_link(LinkConfig {
    loss: 1.5,
    ..LinkConfig::default()
  });
}

#[tokio::test(start_paused = true)]
#[should_panic(expected = "LinkConfig.duplicate must be within [0.0, 1.0]")]
async fn out_of_range_duplicate_panics_at_configuration_time() {
  let net = SimNet::new(20);
  net.set_link(
    ip("10.0.0.1"),
    ip("10.0.0.2"),
    LinkConfig {
      duplicate: f64::NAN,
      ..LinkConfig::default()
    },
  );
}

/// The simultaneous-open punch race: a datagram in flight toward a
/// filtering NAT is admitted if the pinhole opens *before it arrives*,
/// even though it did not exist when the datagram was sent.
#[tokio::test(start_paused = true)]
async fn inbound_nat_filtering_is_evaluated_at_arrival_not_send() {
  let net = SimNet::new(21);
  net.set_default_link(LinkConfig {
    latency: Duration::from_millis(50),
    ..LinkConfig::default()
  });
  let nat = net.add_nat(
    NatGrade::PortRestricted,
    ip("5.5.5.5"),
    &[ip("192.168.1.2")],
  );
  let client = net.bind(addr("192.168.1.2:1111")).unwrap();
  let server = net.bind(addr("8.8.8.8:2000")).unwrap();
  let peer = net.bind(addr("7.7.7.7:3000")).unwrap();

  // Contacting the server creates the client's public mapping.
  client.send_to(b"open", server.addr()).unwrap();
  let mut buf = [0u8; 16];
  let (_, mapped) = server.recv_from(&mut buf).await.unwrap();
  assert_eq!(mapped.ip(), nat.public_ip());

  // The peer's punch is in flight when the client's own opens the
  // filter for it...
  peer.send_to(b"punch", mapped).unwrap();
  tokio::time::sleep(Duration::from_millis(10)).await;
  client.send_to(b"punch", peer.addr()).unwrap();

  // ...and it is admitted, because filtering ran at arrival.
  let (n, from) = client.recv_from(&mut buf).await.unwrap();
  assert_eq!(&buf[..n], b"punch");
  assert_eq!(from, peer.addr());
}

/// The converse: NAT state changes take effect for datagrams already in
/// flight, so a flushed (rebooted) NAT rejects inbound datagrams
/// immediately.
#[tokio::test(start_paused = true)]
async fn nat_flush_rejects_datagrams_already_in_flight() {
  let net = SimNet::new(22);
  net.set_default_link(LinkConfig {
    latency: Duration::from_millis(50),
    ..LinkConfig::default()
  });
  let nat = net.add_nat(
    NatGrade::PortRestricted,
    ip("5.5.5.5"),
    &[ip("192.168.1.2")],
  );
  let client = net.bind(addr("192.168.1.2:1111")).unwrap();
  let server = net.bind(addr("8.8.8.8:2000")).unwrap();

  client.send_to(b"open", server.addr()).unwrap();
  let mut buf = [0u8; 16];
  let (_, mapped) = server.recv_from(&mut buf).await.unwrap();

  // The reply is in flight when the NAT reboots, so it arrives at a
  // dead mapping rather than the state the sender saw.
  server.send_to(b"reply", mapped).unwrap();
  tokio::time::sleep(Duration::from_millis(10)).await;
  nat.flush_mappings();
  assert!(
    tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
      .await
      .is_err()
  );
  let rejected = net.trace().iter().any(|e| {
    matches!(
      e.kind,
      EventKind::NatRejected {
        reason: NatRejectReason::NoMapping,
        ..
      }
    )
  });
  assert!(rejected);
}
