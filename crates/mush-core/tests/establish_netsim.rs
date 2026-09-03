// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The establishment engines over mush-netsim's simulated network: real
//! quinn endpoints on simulated sockets, the tokio virtual clock, and an
//! impaired link. Drives the engines' pre-built-endpoint interfaces
//! (`EndpointSource::Endpoint` on both sides) with Mush's own pinning
//! configs.
//!
//! Determinism rules per mush-netsim's crate docs: current-thread
//! runtime, `start_paused`, no real sockets.
//!
//! The engines' own entropy stays unseeded -- a fresh session identity
//! and rustls handshake randoms per run, and quinn's initial destination
//! CID -- which the replay test tolerates because all of them are
//! fixed-length: Ed25519 keys and signatures, and an 8-byte CID. Datagram
//! counts, addresses, and timings are stable even though the bytes are
//! not, which is exactly the view `trace_summary` reports.

mod common;

use std::net::IpAddr;
use std::time::Duration;

use common::netsim::{
  DEADLINE, SERVER_ADDR, addr, client_addr, client_ip, establish,
};
use common::payload;
use mush_core::transport::TransportOptions;
use mush_netsim::{LinkConfig, NatGrade, SimNet};
use tokio::time::timeout;

/// The one link in the suite with both loss and jitter: a handshake is
/// several round trips of small datagrams, so it has to survive a lost
/// Initial and a reordered one, not just a steady path.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn establishment_across_lossy_simulated_link() -> anyhow::Result<()> {
  let seed = 0x6d75_7368; // "mush"
  let net = SimNet::new(seed);
  net.set_default_link(LinkConfig {
    latency: Duration::from_millis(30),
    jitter: Duration::from_millis(5),
    loss: 0.05,
    ..LinkConfig::default()
  });

  let (mut client, mut server) =
    establish(&net, seed, TransportOptions::default()).await?;
  assert_eq!(client.chosen_addr, addr(SERVER_ADDR));
  assert_eq!(server.client_addr, client_addr());
  assert_eq!(server.udp_port, addr(SERVER_ADDR).port());

  // Establishment's own warmup bytes, read off the far side so the
  // stream is live before either direction is measured.
  let mut warmup = [0u8; 2];
  timeout(DEADLINE, server.recv.read_exact(&mut warmup)).await??;

  client.send.write_all(b"across the network").await?;
  client.send.finish()?;
  let got = timeout(DEADLINE, server.recv.read_to_end(1024)).await??;
  assert_eq!(got, b"across the network");
  server.send.write_all(b"and back").await?;
  server.send.finish()?;
  let got = timeout(DEADLINE, client.recv.read_to_end(1024)).await??;
  assert_eq!(got, b"and back");
  Ok(())
}

/// A deliberately busy scenario run to a quiescent point: a client behind
/// a port-restricted NAT, a lossy jittery path, a bulk transfer, and a
/// mid-stream NAT flush forcing a migration. Returns the trace summary.
///
/// Each run builds its own current-thread, paused-clock runtime rather
/// than sharing one `#[tokio::test]` runtime, so the virtual clock and
/// timer wheel start from identical state -- a mush-netsim determinism
/// rule.
fn replay(seed: u64) -> anyhow::Result<Vec<String>> {
  let rt = tokio::runtime::Builder::new_current_thread()
    .enable_time()
    .start_paused(true)
    .build()?;
  rt.block_on(async move {
    let net = SimNet::new(seed);
    net.set_default_link(LinkConfig {
      latency: Duration::from_millis(20),
      jitter: Duration::from_millis(5),
      loss: 0.03,
      ..LinkConfig::default()
    });
    let nat = net.add_nat(
      NatGrade::PortRestricted,
      "198.51.100.5".parse::<IpAddr>()?,
      &[client_ip()],
    );

    let (mut client, mut server) =
      establish(&net, seed, TransportOptions::default()).await?;
    let mut warmup = [0u8; 2];
    timeout(DEADLINE, server.recv.read_exact(&mut warmup)).await??;

    let data = payload(128 * 1024);
    let (first, second) = data.split_at(data.len() / 2);
    client.send.write_all(first).await?;
    let mut got = vec![0u8; first.len()];
    timeout(DEADLINE, server.recv.read_exact(&mut got)).await??;
    // The NAT reboots mid-stream: the rest crosses a fresh mapping the
    // server has to path-validate, so the trace covers a migration too.
    nat.flush_mappings();
    client.send.write_all(second).await?;
    client.send.finish()?;
    let rest =
      timeout(DEADLINE, server.recv.read_to_end(second.len())).await??;
    got.extend_from_slice(&rest);
    anyhow::ensure!(got == data, "the network lost or reordered bytes");

    // Quiesce, so a datagram still in flight cannot end up in one run's
    // trace and fall outside the other's.
    client.connection.close(0u32.into(), b"done");
    server.connection.close(0u32.into(), b"done");
    tokio::time::sleep(Duration::from_secs(5)).await;
    Ok(net.trace_summary())
  })
}

/// The simulated network's replay guarantee under the engines that use
/// it: the same seed puts the same datagrams on the same addresses at the
/// same virtual times, so every seeded netsim scenario reruns to the same
/// answer.
#[test]
fn the_same_seed_replays_an_identical_trace() -> anyhow::Result<()> {
  let first = replay(0x6d75_7368)?;
  let second = replay(0x6d75_7368)?;
  let impaired = first
    .iter()
    .filter(|line| line.contains("dropped") || line.contains("nat_rejected"))
    .count();
  assert!(
    impaired > 0,
    "the scenario lost nothing, so the comparison proves little"
  );
  assert_eq!(first, second);
  Ok(())
}
