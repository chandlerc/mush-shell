// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The recovery bound as a table: each test sweeps a dimension the
//! bound has to hold across and checks the one claim its table is
//! evidence for. That check is always the same and always one-sided --
//! with the prober, recovery stays inside `RESTORE_BOUND` whatever the
//! outage length, traffic shape, or client write rate. The no-prober
//! column is context only: it is quinn's PTO backoff, so where an
//! outage ends inside a backoff cycle decides it, sometimes better than
//! the prober's fixed cadence and sometimes two orders of magnitude
//! worse. Asserting the prober always wins would be asserting something
//! untrue (design doc, S2: "the residual is that probe interval and
//! nothing else").

mod common;

use std::time::Duration;

use common::netsim::{
  RESTORE_BOUND, ScenarioPlan, TICK, arrival_after, client_ip, wan,
};
use tokio::time::Instant;

/// One outage with the prober present or absent, so the prober's
/// effect on recovery is isolated from quinn's own PTO behavior.
async fn compare(
  outage: Duration,
  ticking: bool,
  with_prober: bool,
) -> anyhow::Result<Duration> {
  let seed = 0x636d_7061 + outage.as_secs() + u64::from(ticking);
  let net = wan(seed);
  let mut s = ScenarioPlan {
    prober: with_prober,
    client_tick: ticking.then_some(TICK),
    ..ScenarioPlan::new(&net, seed)
  }
  .start()
  .await?;

  let start = Instant::now();
  arrival_after(&mut s.arrivals, start).await?;
  tokio::time::sleep(Duration::from_secs(2)).await;

  net.set_host_blackhole(client_ip(), true);
  tokio::time::sleep(outage).await;
  while s.arrivals.try_recv().is_ok() {}
  net.set_host_blackhole(client_ip(), false);
  let restored = Instant::now();
  let recovery = arrival_after(&mut s.arrivals, restored).await? - restored;

  s.finish();
  Ok(recovery)
}

/// How light the client's own traffic has to be before the prober's
/// probes still reach the wire: writes at `rate` for the whole outage.
async fn rate_probe(rate: Duration) -> anyhow::Result<(Duration, u64, u64)> {
  let seed = 0x7261_7465 + rate.as_millis() as u64;
  let net = wan(seed);
  let mut s = ScenarioPlan {
    client_tick: Some(rate),
    ..ScenarioPlan::new(&net, seed)
  }
  .start()
  .await?;

  let start = Instant::now();
  arrival_after(&mut s.arrivals, start).await?;
  tokio::time::sleep(Duration::from_secs(2)).await;
  net.set_host_blackhole(client_ip(), true);
  let before_pings = s.client.stats().frame_tx.ping;
  tokio::time::sleep(Duration::from_secs(300)).await;
  let pings_on_the_wire = s.client.stats().frame_tx.ping - before_pings;
  while s.arrivals.try_recv().is_ok() {}
  net.set_host_blackhole(client_ip(), false);
  let restored = Instant::now();
  let recovery = arrival_after(&mut s.arrivals, restored).await? - restored;

  Ok((recovery, s.finish().probes(), pings_on_the_wire))
}

/// The probe cadence is 2s, so a 300s outage asks for ~150 probes. How
/// many reach the wire, as a function of how chatty the client is? The
/// send-window clamp exists to flatten this: without it, delivery falls
/// off sharply once the client's own undeliverable data fills the
/// congestion window.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn diag_probe_delivery_versus_client_write_rate() -> anyhow::Result<()> {
  eprintln!("300s outage; probes asked for ~150");
  eprintln!("write rate   recovery     probes asked   PINGs on the wire");
  for ms in [100u64, 500, 1000, 2000, 5000, 10000, 30000] {
    let rate = Duration::from_millis(ms);
    let (recovery, asked, on_wire) = rate_probe(rate).await?;
    eprintln!("{rate:>10?}   {recovery:>10?}   {asked:>12}   {on_wire:>17}");
    // What the clamp is for: how chatty the client is must not decide
    // how many probes reach the wire, and so must not decide recovery.
    assert!(
      recovery <= RESTORE_BOUND,
      "a {rate:?} write rate cost {recovery:?}, bound {RESTORE_BOUND:?}"
    );
    assert!(
      on_wire * 10 >= asked * 9,
      "a {rate:?} write rate suppressed probes: {on_wire} of {asked} \
       reached the wire"
    );
  }
  Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn diag_prober_versus_none() -> anyhow::Result<()> {
  eprintln!("outage    ticking  no-prober   prober");
  let mut worst_without = Duration::ZERO;
  for secs in [30, 45, 60, 90, 120, 150, 180, 240, 300, 600] {
    let outage = Duration::from_secs(secs);
    for ticking in [true, false] {
      let without = compare(outage, ticking, false).await?;
      let with = compare(outage, ticking, true).await?;
      assert!(
        with <= RESTORE_BOUND,
        "a {secs}s outage recovered in {with:?} with the prober, \
         bound {RESTORE_BOUND:?}"
      );
      worst_without = worst_without.max(without);
      eprintln!(
        "{:>5}s   {:>5}    {:>9?}   {:>9?}{}",
        secs,
        ticking,
        without,
        with,
        if with > without {
          "   <-- prober is worse"
        } else {
          ""
        }
      );
    }
  }
  // The comparison has to be doing work: without the prober some cell
  // must be far outside the bound, or the table proves nothing.
  assert!(
    worst_without > RESTORE_BOUND * 4,
    "no unprobed cell was slow ({worst_without:?}); the comparison is \
     measuring nothing"
  );
  Ok(())
}
