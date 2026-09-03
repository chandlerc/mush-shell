// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The active-recovery prober over mush-netsim's simulated network:
//! deterministic blackholes, uplink death, and wake events on the tokio
//! virtual clock, with real quinn endpoints on simulated sockets. The S2
//! target is asserted exactly here: post-outage recovery is bounded by
//! the probe cadence, not by quinn's backed-off PTO.
//!
//! Determinism rules per mush-netsim's crate docs: current-thread
//! runtime, `start_paused`, no real sockets, `biased` selects. These
//! tests assert outcomes and bounds, not event traces, except the
//! healthy test's source-address property, which is size-independent.

mod common;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use common::netsim::{
  DEADLINE, DETECT_BOUND, RECOVERY_BOUND, RESTORE_BOUND, SERVER_ADDR,
  ScenarioPlan, TICK, addr, arrival_after, client_addr, client_ip, establish,
  sim_route, sim_socket_factory, spawn_prober, wan,
};
use mush_core::relay;
use mush_core::roaming::{PathWake, ProbeOptions, ProbeStats};
use mush_core::transport::{DEFAULT_STALL_THRESHOLD, TransportOptions};
use mush_netsim::{EventKind, NatGrade};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};

/// One end-to-end blackhole scenario: a total client-side outage of
/// `outage`, then the recovery latency from restoration to the first
/// server byte reaching the client.
async fn blackhole_recovery(
  seed: u64,
  outage: Duration,
  client_ticks: bool,
) -> anyhow::Result<(Duration, Option<Duration>, Arc<ProbeStats>)> {
  let net = wan(seed);
  let mut s = ScenarioPlan {
    client_tick: client_ticks.then_some(TICK),
    ..ScenarioPlan::new(&net, seed)
  }
  .start()
  .await?;

  // Healthy warmup: flowing traffic must draw zero probes.
  let start = Instant::now();
  arrival_after(&mut s.arrivals, start).await?;
  tokio::time::sleep(Duration::from_secs(2)).await;
  assert_eq!(s.stats.probes(), 0, "probe traffic on a healthy path");

  let outage_start = Instant::now();
  net.set_host_blackhole(client_ip(), true);
  tokio::time::sleep(outage).await;
  // Nothing may have crossed mid-outage beyond the in-flight tail.
  let settle = outage_start + Duration::from_millis(200);
  while let Ok(at) = s.arrivals.try_recv() {
    assert!(
      at <= settle,
      "delivery mid-blackhole at {:?}",
      at - outage_start
    );
  }
  net.set_host_blackhole(client_ip(), false);
  let restored = Instant::now();

  let recovery = arrival_after(&mut s.arrivals, restored).await? - restored;
  // Steady flow resumes, not just one byte.
  tokio::time::sleep(Duration::from_secs(2)).await;
  let mut resumed = 0;
  while s.arrivals.try_recv().is_ok() {
    resumed += 1;
  }
  assert!(resumed >= 5, "only {resumed} ticks in 2s after recovery");

  // The client's own writes have to resume too -- an interactive
  // keystroke or a port forward is carried by them, and the stall's
  // send-window clamp blocks them until the episode ends. The transport's
  // own backlog was retransmitted long ago, so what arrives here is new.
  let uplink = if client_ticks {
    while s.server_arrivals.try_recv().is_ok() {}
    let from = Instant::now();
    let first = arrival_after(&mut s.server_arrivals, from).await? - from;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut flowing = 0;
    while s.server_arrivals.try_recv().is_ok() {
      flowing += 1;
    }
    assert!(
      flowing >= 5,
      "the client's writes are still clamped: only {flowing} reached \
       the server in a second"
    );
    Some(first)
  } else {
    None
  };

  let stats = s.finish();
  eprintln!(
    "{outage:?} blackhole (client_ticks={client_ticks}): recovered in \
     {recovery:?}, a fresh client write arrived {uplink:?} later \
     ({} pings, {} rebinds)",
    stats.pings(),
    stats.rebinds()
  );
  Ok((recovery, uplink, stats))
}

/// The recovery bound across outage lengths, in both traffic shapes,
/// over two independent network samples.
///
/// Sampling one or two lengths hides real behavior: quinn's PTO backoff
/// means an outage ending early in a backoff cycle recovers promptly
/// whatever the transport does, so a sparse sample can be green for
/// reasons that have nothing to do with the prober. The two seed bases
/// are the same argument about the simulated network's own randomness: a
/// bound that holds for one packet schedule and not the next is not a
/// bound.
/// Virtual time makes the whole sweep cost a fraction of a second.
async fn sweep(client_ticks: bool) -> anyhow::Result<()> {
  for base in [0x6d75_7368u64, 0x6c6f_6e67] {
    for secs in [30, 60, 120, 300] {
      let seed = base + secs + u64::from(client_ticks);
      let (recovery, uplink, stats) =
        blackhole_recovery(seed, Duration::from_secs(secs), client_ticks)
          .await?;
      assert!(
        recovery <= RESTORE_BOUND,
        "{secs}s outage at seed {seed:#x} recovered in {recovery:?}, \
         bound {RESTORE_BOUND:?}"
      );
      if let Some(uplink) = uplink {
        assert!(
          uplink <= TICK * 2,
          "{secs}s outage at seed {seed:#x} left a fresh client write \
           {uplink:?} behind its own cadence"
        );
      }
      // Long enough that both probe flavors ran.
      assert!(stats.pings() >= 1, "no ping probes at {secs}s: {stats:?}");
      assert!(
        stats.rebinds() >= 1,
        "no rebind probes at {secs}s: {stats:?}"
      );
    }
  }
  Ok(())
}

/// A session only the server feeds: the client sends acknowledgements
/// and nothing else.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn blackhole_sweep_recovers_within_the_probe_bound() -> anyhow::Result<()>
{
  sweep(false).await
}

/// The same sweep on a session the client is also writing into: an
/// interactive shell, a port forward, an upload. Without the prober's
/// send-window clamp the client's own undeliverable data fills the
/// congestion window and drops every probe before it reaches the socket.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn blackhole_sweep_recovers_while_the_client_is_sending()
-> anyhow::Result<()> {
  sweep(true).await
}

/// A healthy, continuously flowing path must see zero probe traffic:
/// no prober interventions, no PING frames (keep-alives are disabled
/// here so any PING would be the prober's), and every client datagram
/// on the wire from the original source address.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn healthy_path_sees_zero_probe_traffic() -> anyhow::Result<()> {
  let seed = 0x6865_616c;
  let net = wan(seed);
  let mut s = ScenarioPlan {
    transport: TransportOptions {
      keep_alive_interval: None,
      ..TransportOptions::default()
    },
    ..ScenarioPlan::new(&net, seed)
  }
  .start()
  .await?;

  tokio::time::sleep(Duration::from_secs(60)).await;
  // Sampled after the sleep: an arrival from before it would prove
  // nothing about a session that died along the way, and every
  // assertion below passes trivially on a dead connection.
  let alive_from = Instant::now();
  arrival_after(&mut s.arrivals, alive_from).await?;
  assert!(
    s.client.close_reason().is_none(),
    "session died while healthy: {:?}",
    s.client.close_reason()
  );

  assert_eq!(s.stats.probes(), 0, "prober intervened on a healthy path");
  // With keep-alives disabled the only legitimate PING frames are
  // DPLPMTUD's probe padding; one more would be a prober ping.
  let quic = s.client.stats();
  assert_eq!(
    quic.frame_tx.ping, quic.path.sent_plpmtud_probes,
    "PING frames beyond MTU discovery on a healthy path"
  );
  let original = client_addr();
  for event in net.trace() {
    if let EventKind::Sent { src, .. } = event.kind
      && src.ip() == client_ip()
    {
      assert_eq!(src, original, "client traffic from an unexpected socket");
    }
  }

  s.finish();
  Ok(())
}

/// The promise indefinite retention exists for (design doc,
/// "Teardown"): sshd closes while the client is unreachable, and the
/// server holds the undelivered tail of the stream and the EOF until
/// the client comes back for them, however long that takes.
///
/// The server's half is wired as `mush server bootstrap` wires it --
/// the real relay engine between the session stream and the loopback
/// sshd -- so what is under test is that engine's half-close mapping
/// across an outage, not quinn alone. The outage runs ten times quinn's
/// own 30s idle-timeout default, which the design overrides for exactly
/// this, and the relay's `to_peer` direction cannot report `Clean`
/// until the tail is acknowledged: a client that came back to a hang,
/// or to a truncated stream, fails here rather than reading as a pass.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_session_ending_mid_outage_delivers_its_tail_on_return()
-> anyhow::Result<()> {
  const TAIL: &[u8] = b"logout\r\nConnection to dev closed.\r\n";
  let seed = 0x7a11_0117;
  let net = wan(seed);
  let (mut client, server) =
    establish(&net, seed, TransportOptions::default()).await?;
  let (prober, _stats) = spawn_prober(
    &client,
    sim_socket_factory(&net, client_ip(), 41001),
    sim_route(true),
    None,
    ProbeOptions::default(),
  );
  let (sshd, mut session) = tokio::io::duplex(64 * 1024);
  let relay = tokio::spawn(relay::relay(sshd, server.send, server.recv));
  // Establishment's own warmup bytes, read off the far side so the
  // stream is live in both directions before the outage starts.
  let mut warmup = [0u8; 2];
  timeout(DEADLINE, session.read_exact(&mut warmup)).await??;

  net.set_host_blackhole(client_ip(), true);
  tokio::time::sleep(Duration::from_secs(1)).await;
  // The remote session ends while the client is gone: its last output,
  // then the close that becomes a stream FIN.
  session.write_all(TAIL).await?;
  session.shutdown().await?;
  tokio::time::sleep(Duration::from_secs(300)).await;
  net.set_host_blackhole(client_ip(), false);

  let tail = timeout(DEADLINE, client.recv.read_to_end(4096)).await??;
  assert_eq!(tail, TAIL, "the held tail did not survive the outage");
  // The client's own side closes, as ssh exiting closes it, and the
  // whole splice reports a clean end in both directions.
  client.send.finish()?;
  let outcome = timeout(DEADLINE, relay).await??;
  assert!(outcome.is_clean(), "{outcome:?}");
  prober.abort();
  Ok(())
}

/// A NAT rebind on a plain session, the design's second session killer:
/// the client's address does not change, but every mapping behind it
/// does, so the path is dead inbound until something the client sends
/// builds a new one. The lab covers this with real conntrack
/// (`nat_rebind_mid_session_*` in `mush-lab`), which needs a binary that
/// is not always installed; this is the tier-1 statement of the same
/// goal, on a plain session with no jump and no traversal machinery.
/// Returns how long the server's traffic took to reach the client again.
async fn nat_rebind(
  seed: u64,
  client_ticks: bool,
) -> anyhow::Result<(Duration, Arc<ProbeStats>)> {
  let net = wan(seed);
  let nat = net.add_nat(
    NatGrade::PortRestricted,
    "198.51.100.5".parse::<IpAddr>()?,
    &[client_ip()],
  );
  let mut s = ScenarioPlan {
    client_tick: client_ticks.then_some(TICK),
    ..ScenarioPlan::new(&net, seed)
  }
  .start()
  .await?;
  arrival_after(&mut s.arrivals, Instant::now()).await?;
  tokio::time::sleep(Duration::from_secs(2)).await;
  assert_eq!(s.stats.probes(), 0, "probe traffic on a healthy path");

  net.clear_trace();
  let rebound = Instant::now();
  nat.flush_mappings();
  let recovery = arrival_after(&mut s.arrivals, rebound).await? - rebound;
  // Steady flow, not one byte that happened through.
  tokio::time::sleep(Duration::from_secs(2)).await;
  let mut resumed = 0;
  while s.arrivals.try_recv().is_ok() {
    resumed += 1;
  }
  assert!(resumed >= 5, "only {resumed} ticks in 2s after the rebind");
  // The flush really took the mapping away, rather than the simulated
  // network ignoring it and this measuring nothing.
  assert!(
    net
      .trace()
      .iter()
      .any(|event| matches!(event.kind, EventKind::NatRejected { .. })),
    "no datagram was refused after the flush"
  );
  assert!(
    s.client.close_reason().is_none(),
    "the session did not survive its own rebind: {:?}",
    s.client.close_reason()
  );

  Ok((recovery, s.finish()))
}

/// A client that is writing rebuilds the mapping with its own next
/// write: nothing has to detect anything, and the server takes the new
/// source address as the ordinary client migration it is.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_nat_rebind_recovers_on_the_clients_next_write() -> anyhow::Result<()>
{
  let (recovery, stats) = nat_rebind(0x7265_6269, true).await?;
  eprintln!(
    "NAT rebind, client writing: recovered in {recovery:?} \
     ({} pings, {} rebinds)",
    stats.pings(),
    stats.rebinds()
  );
  assert!(
    recovery <= RECOVERY_BOUND,
    "a NAT rebind cost {recovery:?}, bound {RECOVERY_BOUND:?}"
  );
  Ok(())
}

/// The receive-only shape, which is the slow one, and neither the
/// prober's doing nor its failure. A stall is "we sent and nothing came
/// back", and a client that is only reading sends nothing but
/// acknowledgements, which are not ack-eliciting and so are never owed
/// an answer. Nothing is outstanding for the detector to notice, and
/// what rebuilds the mapping is the keep-alive, the design's other
/// reason for having one (see "Connection configuration"). So the bound
/// here is that interval rather than the probe cadence.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_rebind_on_a_reading_client_waits_for_the_keepalive()
-> anyhow::Result<()> {
  let (recovery, stats) = nat_rebind(0x7265_626a, false).await?;
  eprintln!(
    "NAT rebind, client reading only: recovered in {recovery:?} \
     ({} pings, {} rebinds)",
    stats.pings(),
    stats.rebinds()
  );
  let bound = mush_core::transport::DEFAULT_KEEP_ALIVE + RECOVERY_BOUND;
  assert!(
    recovery <= bound,
    "a NAT rebind on a reading client cost {recovery:?}, bound {bound:?}"
  );
  Ok(())
}

/// NAT timeout is one of the four session killers the design opens with,
/// and the 20s client-side keep-alive is the whole answer to it (design
/// doc, "Connection configuration"): only outbound traffic refreshes a
/// mapping, and an idle session produces none of its own. The mapping
/// here idles out in half the time the session sits idle, so the
/// keep-alives are the only thing that can hold it. The negative control
/// is the same session with them off, where the server's post-idle byte
/// reaches a mapping that no longer exists; without it a simulated
/// network that never expired anything would pass this.
async fn idle_behind_a_nat(
  seed: u64,
  keep_alive: Option<Duration>,
) -> anyhow::Result<(bool, Arc<ProbeStats>)> {
  const MAPPING_TTL: Duration = Duration::from_secs(30);
  const IDLE: Duration = Duration::from_secs(120);

  let net = wan(seed);
  let nat = net.add_nat(
    NatGrade::PortRestricted,
    "198.51.100.5".parse::<IpAddr>()?,
    &[client_ip()],
  );
  nat.set_mapping_ttl(MAPPING_TTL);
  drop(nat);
  let (mut client, mut server) = establish(
    &net,
    seed,
    TransportOptions {
      keep_alive_interval: keep_alive,
      ..TransportOptions::default()
    },
  )
  .await?;
  let (prober, stats) = spawn_prober(
    &client,
    sim_socket_factory(&net, client_ip(), 41001),
    sim_route(true),
    None,
    ProbeOptions::default(),
  );

  tokio::time::sleep(IDLE).await;
  // The far side speaks first after the idle window, as a session waking
  // on remote output does: it can only arrive through a live mapping.
  server.send.write_all(b"T").await?;
  let mut byte = [0u8; 1];
  let arrived = timeout(MAPPING_TTL, client.recv.read_exact(&mut byte))
    .await
    .is_ok();
  prober.abort();
  client.connection.close(0u32.into(), b"test over");
  Ok((arrived, stats))
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn keepalives_hold_a_nat_mapping_open_across_an_idle_session()
-> anyhow::Result<()> {
  let (arrived, stats) = idle_behind_a_nat(
    0x6b65_6570,
    Some(mush_core::transport::DEFAULT_KEEP_ALIVE),
  )
  .await?;
  assert!(arrived, "the NAT mapping timed out under the keep-alives");
  // Held by the keep-alives alone: nothing the prober did.
  assert_eq!(
    stats.probes(),
    0,
    "the prober had to rescue an idle session"
  );

  let (arrived, _) = idle_behind_a_nat(0x6b65_6571, None).await?;
  assert!(
    !arrived,
    "the mapping outlived its TTL with no keep-alives, so the positive \
     case proves nothing"
  );
  Ok(())
}

/// The old source address dies outright (suspend, wifi off) and never
/// comes back; only the fresh-socket rebind path can recover, from a
/// new local address, and the server must accept it as a migration.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn uplink_death_rebind_restores_traffic() -> anyhow::Result<()> {
  let new_ip: IpAddr = "10.0.0.9".parse().unwrap();
  let seed = 0x6465_6164;
  let net = wan(seed);
  let mut s = ScenarioPlan {
    fresh_socket: Some(sim_socket_factory(&net, new_ip, 41001)),
    ..ScenarioPlan::new(&net, seed)
  }
  .start()
  .await?;
  let original_remote = s.server.remote_address();

  let start = Instant::now();
  arrival_after(&mut s.arrivals, start).await?;
  tokio::time::sleep(Duration::from_secs(2)).await;

  // The uplink dies for good: the old address delivers nothing from here
  // on.
  let died = Instant::now();
  net.set_host_blackhole(client_ip(), true);

  let resumed = arrival_after(&mut s.arrivals, died).await? - died;
  // Detection plus the episode's opening rebind, the probe that
  // recovers here.
  assert!(
    resumed <= RECOVERY_BOUND,
    "traffic resumed after {resumed:?}, bound {RECOVERY_BOUND:?}"
  );
  assert!(
    s.stats.rebinds() >= 1,
    "recovered without a rebind: {:?}",
    s.stats
  );
  let migrated = s.server.remote_address();
  assert_eq!(
    migrated.ip(),
    new_ip,
    "server did not observe the migration"
  );
  assert_ne!(migrated, original_remote);

  s.finish();
  Ok(())
}

/// The netlink fast path for the design's main roaming case: the
/// uplink goes away (wifi off, VPN down, cable out), the kernel has no
/// route to the peer any more -- positive proof about *this* path -- so
/// the rebind happens on the wake rather than after stall detection. The
/// probe interval is stretched so no tick can fire in the window.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn route_loss_wake_probes_before_stall_detection() -> anyhow::Result<()> {
  let new_ip: IpAddr = "10.0.0.9".parse().unwrap();
  let seed = 0x7769_6669;
  let net = wan(seed);
  let (events_tx, events_rx) = mpsc::unbounded_channel();
  let mut s = ScenarioPlan {
    probe: ProbeOptions {
      probe_interval: Duration::from_secs(60),
      ..ProbeOptions::default()
    },
    fresh_socket: Some(sim_socket_factory(&net, new_ip, 41001)),
    route_check: Some(sim_route(false)),
    wakes: Some(events_rx),
    ..ScenarioPlan::new(&net, seed)
  }
  .start()
  .await?;
  let original_remote = s.server.remote_address();

  let start = Instant::now();
  arrival_after(&mut s.arrivals, start).await?;

  net.set_host_blackhole(client_ip(), true);
  let died = Instant::now();
  events_tx.send(PathWake)?;

  let resumed = arrival_after(&mut s.arrivals, died).await? - died;
  eprintln!("route-loss wake: traffic back {resumed:?} after the uplink died");
  // Nothing but the wake could have produced this: the stall threshold
  // has not elapsed and the next tick is a minute away.
  assert!(
    resumed < DEFAULT_STALL_THRESHOLD,
    "the wake did not short-circuit stall detection: {resumed:?}"
  );
  assert_eq!(
    s.stats.rebinds(),
    1,
    "not exactly one rebind: {:?}",
    s.stats
  );
  assert_ne!(
    s.server.remote_address(),
    original_remote,
    "server did not observe the migration"
  );

  s.finish();
  Ok(())
}

/// A wake that proves nothing changes nothing, even mid-stall. The
/// probe interval does not change: a wake whose route check still answers
/// "reachable" is only a report about some interface on the host, and
/// letting it probe out of band would put the wake rate in charge of
/// the rebind rate exactly when the path is already in trouble.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn wake_without_route_loss_does_not_probe_out_of_band()
-> anyhow::Result<()> {
  let seed = 0x7761_6b65;
  let net = wan(seed);
  let (events_tx, events_rx) = mpsc::unbounded_channel();
  let mut s = ScenarioPlan {
    probe: ProbeOptions {
      probe_interval: Duration::from_secs(60),
      ..ProbeOptions::default()
    },
    wakes: Some(events_rx),
    ..ScenarioPlan::new(&net, seed)
  }
  .start()
  .await?;

  let start = Instant::now();
  arrival_after(&mut s.arrivals, start).await?;
  net.set_host_blackhole(client_ip(), true);

  // With a 60s probe interval the schedule is coarse: the first tick
  // still sees pre-outage traffic and resets, the tick after is pulled
  // in to the stall threshold, declares the stall and sends the opening
  // rebind probe. Wait past that, into the quiet before the next tick.
  tokio::time::sleep(Duration::from_secs(130)).await;
  let before = s.stats.probes();
  assert!(before >= 1, "probing never started: {:?}", s.stats);

  for _ in 0..100 {
    events_tx.send(PathWake)?;
  }
  tokio::time::sleep(Duration::from_secs(10)).await;
  assert_eq!(
    s.stats.probes(),
    before,
    "100 wakes probed out of band mid-stall: {:?}",
    s.stats
  );

  s.finish();
  Ok(())
}

/// The stall detector must see an outbound-only blackhole. The peer's
/// datagrams keep arriving, so "nothing received lately" stays false
/// throughout; what proves the path is broken is that nothing this side
/// sends is ever acknowledged.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn outbound_only_blackhole_is_detected() -> anyhow::Result<()> {
  let seed = 0x6f75_7462;
  let net = wan(seed);
  let mut s = ScenarioPlan::new(&net, seed).start().await?;

  let start = Instant::now();
  arrival_after(&mut s.arrivals, start).await?;
  tokio::time::sleep(Duration::from_secs(2)).await;

  // Only the client's egress dies: an upstream NAT mapping dropped, an
  // egress ACL on the source port, a middlebox forwarding one way.
  let died = Instant::now();
  net.set_link_blackhole(client_ip(), addr(SERVER_ADDR).ip(), true);

  let stats = s.stats.clone();
  let detected = timeout(DEADLINE, async {
    while stats.probes() == 0 {
      tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Instant::now()
  })
  .await?
    - died;
  eprintln!("outbound-only blackhole: first probe {detected:?} after death");
  assert!(
    detected <= DETECT_BOUND,
    "outbound-only death took {detected:?} to detect, bound {DETECT_BOUND:?}"
  );
  assert!(
    stats.rebinds() >= 1,
    "the fresh-socket rebind, the recovery for a dead outbound \
     mapping, never ran: {stats:?}"
  );

  s.finish();
  Ok(())
}
