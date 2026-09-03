// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Hostile probes against the active-recovery prober, over mush-netsim.
//! Each tries to make the prober misbehave -- probe when healthy, storm
//! rebinds, miss a stall, cost packets on an idle session -- rather
//! than confirm it behaves. Determinism rules are mush-netsim's:
//! current-thread runtime, `start_paused`, no real sockets.

mod common;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use common::netsim::{
  RECOVERY_BOUND, RESTORE_BOUND, ScenarioPlan, arrival_after, client_ip,
  client_wire, counting_route, establish, sim_route, sim_socket_factory,
  spawn_arrivals, spawn_prober, spawn_ticker, wan,
};
use mush_core::roaming::{PathWake, ProbeOptions, SocketFactory};
use mush_core::transport::{DEFAULT_PROBE_INTERVAL, TransportOptions};
use mush_core::traversal::Handable;
use tokio::sync::mpsc;
use tokio::time::Instant;

// (1) Spurious probing

/// Mutation check on `recovery_netsim::healthy_path_sees_zero_probe_
/// traffic`: with the stall check removed, does that test's evidence
/// fire? The prober without its stall check is modelled exactly --
/// `Prober::run`'s tick loop with `probing` forced true, the same
/// alternating rebind/ping calls on the same endpoint, stall detection
/// deleted. Both of that test's observables must catch it: PING frames
/// beyond DPLPMTUD's, and client datagrams from a source other than the
/// original socket.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_prober_without_its_stall_check_is_caught_by_the_healthy_path_evidence()
-> anyhow::Result<()> {
  let seed = 0x6865_616c;
  let net = wan(seed);
  let (client, server) = establish(
    &net,
    seed,
    TransportOptions {
      keep_alive_interval: None,
      ..TransportOptions::default()
    },
  )
  .await?;
  let connection = client.connection.clone();
  let endpoint = client.endpoint.clone();

  let mut fresh_socket = sim_socket_factory(&net, client_ip(), 41001);
  let chatty = tokio::spawn(async move {
    let mut current: Option<Arc<dyn Handable>> = None;
    let mut rebind_next = true;
    loop {
      tokio::time::sleep(DEFAULT_PROBE_INTERVAL).await;
      match &current {
        Some(socket) if !rebind_next => {
          endpoint.rebind_abstract(socket.hand()).unwrap();
        }
        _ => {
          let fresh = fresh_socket().unwrap();
          endpoint.rebind_abstract(fresh.socket.hand()).unwrap();
          (fresh.adopt)();
          current = Some(fresh.socket);
        }
      }
      rebind_next = !rebind_next;
    }
  });

  let client_tick = spawn_ticker(client.send);
  let server_tick = spawn_ticker(server.send);
  let (server_drain, _server_arrivals) = spawn_arrivals(server.recv);
  let (client_reader, mut arrivals) = spawn_arrivals(client.recv);

  let start = Instant::now();
  tokio::time::sleep(Duration::from_secs(60)).await;
  arrival_after(&mut arrivals, start).await?;

  let quic = connection.stats();
  assert!(
    quic.frame_tx.ping > quic.path.sent_plpmtud_probes,
    "the PING-frame assertion does not catch a prober without its \
     stall check (ping={}, plpmtud={})",
    quic.frame_tx.ping,
    quic.path.sent_plpmtud_probes
  );
  let (_, sources) = client_wire(&net);
  assert!(
    sources.len() > 1,
    "the source-address assertion does not catch a prober without its \
     stall check: {sources:?}"
  );

  chatty.abort();
  for task in [client_tick, server_tick, server_drain, client_reader] {
    task.abort();
  }
  Ok(())
}

/// Rapid blackhole flapping: 2s down / 2s up, twenty cycles. Each
/// outage is shorter than the stall threshold, so a correct detector
/// barely engages. The failure mode under test is a rebind storm
/// churning the client's source port (and the NAT mapping behind it) on
/// a path that keeps recovering on its own.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn flapping_blackhole_does_not_storm_rebinds() -> anyhow::Result<()> {
  let seed = 0x666c_6170;
  let net = wan(seed);
  let mut s = ScenarioPlan::new(&net, seed).start().await?;

  let start = Instant::now();
  arrival_after(&mut s.arrivals, start).await?;
  tokio::time::sleep(Duration::from_secs(2)).await;

  const CYCLES: u32 = 20;
  for _ in 0..CYCLES {
    net.set_host_blackhole(client_ip(), true);
    tokio::time::sleep(Duration::from_secs(2)).await;
    net.set_host_blackhole(client_ip(), false);
    tokio::time::sleep(Duration::from_secs(2)).await;
  }

  let (_, sources) = client_wire(&net);
  eprintln!(
    "flapping {CYCLES} x (2s down / 2s up): {} pings, {} rebinds, \
     {} source addresses",
    s.stats.pings(),
    s.stats.rebinds(),
    sources.len()
  );

  // The path is up at the end of the loop; traffic must be flowing.
  let t = Instant::now();
  arrival_after(&mut s.arrivals, t).await?;
  // One rebind per outage is the upper bound for a correct prober: a
  // stall episode opens with one rebind, and a window this short cannot
  // justify more.
  assert!(
    s.stats.rebinds() <= u64::from(CYCLES),
    "rebind storm under flapping: {:?}",
    s.stats
  );

  s.finish();
  Ok(())
}

// (2) Interaction with roaming

/// A roam that happens mid-outage: the path stops delivering, probing
/// engages, and only then does the host acquire its new uplink --
/// announced by a netlink wake while the fresh-socket factory starts
/// handing out sockets on the new address. Recovery must follow the new
/// address, and the wake must not confuse the episode's bookkeeping.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn roam_during_probing_follows_the_new_uplink() -> anyhow::Result<()> {
  let new_ip: IpAddr = "10.0.0.9".parse().unwrap();
  let seed = 0x726f_616d;
  let net = wan(seed);
  let (events_tx, events_rx) = mpsc::unbounded_channel();

  // The factory models the host's address set: old address until the
  // roam, new one after. Binding a dead address succeeds (the simulated
  // network has no address ownership) but blackholes, as on a dead
  // uplink.
  let old_factory = sim_socket_factory(&net, client_ip(), 41001);
  let new_factory = sim_socket_factory(&net, new_ip, 41501);
  let roamed = Arc::new(std::sync::atomic::AtomicBool::new(false));
  let factory_flag = roamed.clone();
  let mut old_factory = old_factory;
  let mut new_factory = new_factory;
  let fresh_socket: SocketFactory = Box::new(move || {
    if factory_flag.load(std::sync::atomic::Ordering::Relaxed) {
      new_factory()
    } else {
      old_factory()
    }
  });
  let mut s = ScenarioPlan {
    fresh_socket: Some(fresh_socket),
    wakes: Some(events_rx),
    ..ScenarioPlan::new(&net, seed)
  }
  .start()
  .await?;
  let original_remote = s.server.remote_address();

  let start = Instant::now();
  arrival_after(&mut s.arrivals, start).await?;
  tokio::time::sleep(Duration::from_secs(2)).await;

  // The old uplink dies; probing engages against a dead address.
  net.set_host_blackhole(client_ip(), true);
  tokio::time::sleep(Duration::from_secs(15)).await;
  assert!(
    s.stats.rebinds() >= 1,
    "probing never engaged: {:?}",
    s.stats
  );

  // The roam: new uplink, netlink says so.
  let roam_at = Instant::now();
  roamed.store(true, std::sync::atomic::Ordering::Relaxed);
  events_tx.send(PathWake)?;

  let resumed = arrival_after(&mut s.arrivals, roam_at).await? - roam_at;
  eprintln!(
    "roam during probing: traffic back {resumed:?} after the wake \
     ({} pings, {} rebinds)",
    s.stats.pings(),
    s.stats.rebinds()
  );
  assert!(
    resumed <= RECOVERY_BOUND,
    "traffic resumed {resumed:?} after the roam, bound {RECOVERY_BOUND:?}"
  );
  let migrated = s.server.remote_address();
  assert_eq!(migrated.ip(), new_ip, "server did not follow the roam");
  assert_ne!(migrated, original_remote);

  s.finish();
  Ok(())
}

/// A netlink wake arriving in the same instant as a probe tick. The
/// select is `biased` toward events, so the wake wins; the tick must
/// not simply be lost -- the stall episode keeps making progress, and
/// one wake costs at most one probe interval of recovery latency.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn wake_racing_the_stall_tick_still_recovers() -> anyhow::Result<()> {
  let seed = 0x7261_6365;
  let net = wan(seed);
  let (events_tx, events_rx) = mpsc::unbounded_channel();
  let mut s = ScenarioPlan {
    wakes: Some(events_rx),
    ..ScenarioPlan::new(&net, seed)
  }
  .start()
  .await?;

  let start = Instant::now();
  arrival_after(&mut s.arrivals, start).await?;
  tokio::time::sleep(Duration::from_secs(2)).await;

  // Blackhole the client, then deliver a wake on every probe-interval
  // boundary for the whole outage: every wake races a tick.
  net.set_host_blackhole(client_ip(), true);
  let outage_start = Instant::now();
  let racer = tokio::spawn(async move {
    loop {
      tokio::time::sleep(DEFAULT_PROBE_INTERVAL).await;
      if events_tx.send(PathWake).is_err() {
        return;
      }
    }
  });
  tokio::time::sleep(Duration::from_secs(30)).await;
  net.set_host_blackhole(client_ip(), false);
  let restored = Instant::now();

  let recovery = arrival_after(&mut s.arrivals, restored).await? - restored;
  eprintln!(
    "wake racing every tick over a {:?} outage: recovered in {recovery:?} \
     ({} pings, {} rebinds)",
    restored - outage_start,
    s.stats.pings(),
    s.stats.rebinds()
  );
  assert!(
    recovery <= RESTORE_BOUND,
    "recovery took {recovery:?} with wakes racing ticks, \
     bound {RESTORE_BOUND:?}"
  );
  // `transport`'s policy docs promise fresh-socket rebinds on every
  // *other* probe, "so sockets and NAT mappings churn at half this rate
  // during an outage". A wake wins the biased select, so it must take
  // the flavor the tick would have taken rather than hard-coding a
  // rebind, or the churn doubles exactly when the path is in trouble.
  assert!(
    s.stats.pings() * 2 >= s.stats.rebinds(),
    "the alternation collapsed to rebind-only under tick-aligned \
     wakes: {:?}",
    s.stats
  );

  racer.abort();
  s.finish();
  Ok(())
}

/// A wake stream that never lets the channel go empty: the select is
/// `biased` toward events, so the tick runs only if the wake path
/// yields it. The path delivers nothing throughout, so stall detection
/// failing to fire drops recovery to quinn's backed-off PTO and loses
/// the S2 bound. Nor may the wake rate become the rebind rate: each
/// rebind is a fresh bind, a fresh source port, and a peer-validated
/// migration.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn saturated_wakes_do_not_starve_stall_detection() -> anyhow::Result<()> {
  let seed = 0x7374_7276;
  let net = wan(seed);
  let (events_tx, events_rx) = mpsc::unbounded_channel();
  let (route_check, route_calls) = counting_route(true);
  let mut s = ScenarioPlan {
    route_check: Some(route_check),
    wakes: Some(events_rx),
    ..ScenarioPlan::new(&net, seed)
  }
  .start()
  .await?;

  let start = Instant::now();
  arrival_after(&mut s.arrivals, start).await?;
  tokio::time::sleep(Duration::from_secs(2)).await;

  net.set_host_blackhole(client_ip(), true);
  // A link flapping hard: a hundred wakes a second, the rate a bouncing
  // interface or an ENOBUFS overflow reaches on a real netlink socket.
  let flooder = tokio::spawn(async move {
    loop {
      if events_tx.send(PathWake).is_err() {
        return;
      }
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
  });
  // Long enough for a correct detector to declare the stall many times.
  tokio::time::sleep(Duration::from_secs(30)).await;
  let probes_during_outage = s.stats.probes();
  flooder.abort();
  net.set_host_blackhole(client_ip(), false);
  let restored = Instant::now();

  let recovery = arrival_after(&mut s.arrivals, restored).await? - restored;
  eprintln!(
    "saturated wakes over a 30s outage: {probes_during_outage} probes \
     during it, recovered in {recovery:?} ({} pings, {} rebinds)",
    s.stats.pings(),
    s.stats.rebinds()
  );
  assert!(
    probes_during_outage >= 1,
    "stall detection never fired under a saturated wake stream"
  );
  // 3000 wakes crossed the channel; the probe cadence is the upper bound
  // for the probes, and for the route check each one would otherwise
  // have asked the kernel to run.
  let limit = 30_000 / DEFAULT_PROBE_INTERVAL.as_millis() as u64 + 1;
  assert!(
    probes_during_outage <= limit,
    "the wake rate became the probe rate: {probes_during_outage} probes in 30s"
  );
  let checks = route_calls.load(std::sync::atomic::Ordering::Relaxed);
  assert!(
    checks <= limit,
    "the wake rate became the route-check rate: {checks} checks in 30s"
  );
  assert!(
    recovery <= RESTORE_BOUND,
    "recovery took {recovery:?} under a saturated wake stream, \
     bound {RESTORE_BOUND:?}"
  );

  s.finish();
  Ok(())
}

/// A wake stream on a perfectly healthy path. Each rebind is a QUIC
/// migration: the peer path-validates it and (RFC 9000 section 9.4)
/// resets its congestion controller and RTT estimator, and the client
/// uses up a source port. RTM_NEWADDR fires for address refreshes as
/// readily as for new addresses, so a host with SLAAC lifetime churn or
/// a DHCP renew loop emits these all day. None of it may reach a
/// session that is answering.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn wakes_on_a_healthy_path_cost_nothing() -> anyhow::Result<()> {
  let seed = 0x6e61_6464;
  let net = wan(seed);
  let (events_tx, events_rx) = mpsc::unbounded_channel();
  let mut s = ScenarioPlan {
    wakes: Some(events_rx),
    ..ScenarioPlan::new(&net, seed)
  }
  .start()
  .await?;

  let start = Instant::now();
  arrival_after(&mut s.arrivals, start).await?;
  tokio::time::sleep(Duration::from_secs(2)).await;
  assert_eq!(s.stats.probes(), 0);

  // One wake per second for a minute: a rate any address-churning host
  // reaches, and well inside what an unbounded channel delivers.
  let waker = tokio::spawn(async move {
    loop {
      tokio::time::sleep(Duration::from_secs(1)).await;
      if events_tx.send(PathWake).is_err() {
        return;
      }
    }
  });
  tokio::time::sleep(Duration::from_secs(60)).await;
  waker.abort();

  let (_, sources) = client_wire(&net);
  eprintln!(
    "60 wakes on a healthy path: {} rebinds, \
     {} distinct client source addresses",
    s.stats.rebinds(),
    sources.len()
  );
  let t = Instant::now();
  arrival_after(&mut s.arrivals, t).await?;
  assert_eq!(
    s.stats.probes(),
    0,
    "address wakes churned a healthy path: {:?}",
    s.stats
  );
  assert_eq!(
    sources.len(),
    1,
    "the client's source address moved on a healthy path: {sources:?}"
  );

  s.finish();
  Ok(())
}

// (3) Overhead

/// Packet-for-packet overhead of running the prober on a healthy,
/// keep-alive-only idle session: the same seeded scenario with and
/// without the prober must put exactly the same datagrams on the wire.
/// The prober must also leave such a session alone entirely -- the
/// detector requires an *unanswered* transmission, and a healthy path
/// answers every keep-alive within an RTT. The window is twice quinn's
/// own idle timeout, so a session that died in it fails here.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn idle_session_wire_is_identical_with_and_without_the_prober()
-> anyhow::Result<()> {
  async fn run(with_prober: bool) -> anyhow::Result<(usize, Vec<String>)> {
    let seed = 0x6f76_6864;
    let net = wan(seed);
    let (client, _server) =
      establish(&net, seed, TransportOptions::default()).await?;
    let prober = with_prober.then(|| {
      spawn_prober(
        &client,
        sim_socket_factory(&net, client_ip(), 41001),
        sim_route(true),
        None,
        ProbeOptions::default(),
      )
    });
    net.clear_trace();
    tokio::time::sleep(Duration::from_secs(120)).await;
    if let Some((prober, stats)) = prober {
      assert_eq!(stats.probes(), 0, "prober intervened while idle");
      prober.abort();
    }
    assert!(
      client.connection.close_reason().is_none(),
      "idle session died: {:?}",
      client.connection.close_reason()
    );
    let summary = net.trace_summary();
    let (count, _) = client_wire(&net);
    client.connection.close(0u32.into(), b"test over");
    Ok((count, summary))
  }

  let (without, without_trace) = run(false).await?;
  let (with, with_trace) = run(true).await?;
  eprintln!(
    "60s idle: {without} client datagrams without the prober, \
     {with} with it"
  );
  assert_eq!(
    without, with,
    "the prober changed the datagram count on an idle session"
  );
  assert_eq!(
    without_trace, with_trace,
    "the prober changed the wire trace on an idle session"
  );
  Ok(())
}
