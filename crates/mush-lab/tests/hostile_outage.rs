// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Lab-tier confirmation that the active-recovery prober's bound holds
//! in both of the session's traffic shapes.
//!
//! The rest of the outage matrix, and the S2 recovery measurement in
//! `perf.rs`, drive the session from the server side alone, where the
//! prober's PING can never be congestion-blocked; none of them can tell
//! whether the bound survives a client with data outstanding. The probe
//! is subject to quinn's congestion control, and a client's
//! undeliverable data would fill the window within tens of seconds of
//! interactive traffic if the prober did not clamp the send window on a
//! stall (`mush_core::roaming`). This runs the same outage both ways.
//!
//! Runs under the nextest `lab` profile; the `outage_` prefix selects
//! the long-window slow-timeout override in `.config/nextest.toml`.

#![cfg(target_os = "linux")]

use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use mush_core::transport::DEFAULT_PROBE_INTERVAL;
use mush_testenv::patchbay::{LinkCondition, LinkDirection};
use mush_testenv::{Topology, direct};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

mod common;

use common::{Lab, drain, spawn_session};

mush_testenv::userns_bootstrap!();

const OUTAGE: Duration = Duration::from_secs(60);
/// Long enough to catch a PTO-bound recovery without hanging the run.
const RECOVERY_LIMIT: Duration = Duration::from_secs(100);
/// Scheduling slack for a lab tier that runs on a real kernel, real
/// sshd, and a shared CI machine, on top of the derived bound.
const LAB_SLACK: Duration = Duration::from_secs(3);
/// What the design promises, derived from the policy itself rather than
/// restated: with probing already engaged, the probe that crosses the
/// restored path is at most a probe interval off, plus its round trip.
const PROBE_BOUND: Duration = DEFAULT_PROBE_INTERVAL
  .saturating_add(DEFAULT_PROBE_INTERVAL)
  .saturating_add(LAB_SLACK);

/// One outage rep. `client_writes` picks a `cat` the client feeds, or
/// the read-only shape every committed outage test uses. Returns the
/// time from restore to the first byte arriving.
async fn outage_rep(
  lab: &Lab<Topology>,
  client_writes: bool,
) -> Result<Duration> {
  let remote = if client_writes {
    "cat"
  } else {
    "sh -c 'while :; do echo R; sleep 0.1; done'"
  };
  let args = lab.mush.ssh_args_with(lab.dest_ip, &["--no-fallback"]);
  let mut child = spawn_session(&lab.topo.client, &args, remote, None)?;
  let stdin = child.stdin.take().context("stdin piped")?;
  let mut stdout = child.stdout.take().context("stdout piped")?;
  let stderr = drain(child.stderr.take().context("stderr piped")?);

  let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
  let reader = tokio::spawn(async move {
    let mut buf = [0u8; 4096];
    loop {
      match stdout.read(&mut buf).await {
        Ok(0) | Err(_) => return,
        Ok(_) => {
          if tx.send(Instant::now()).is_err() {
            return;
          }
        }
      }
    }
  });

  // A line every 100ms for the whole rep, outage included. `cat` echoes
  // it, so arrivals prove both directions.
  let writer = if client_writes {
    let mut stdin = stdin;
    Some(tokio::spawn(async move {
      let mut n: u64 = 0;
      loop {
        if stdin
          .write_all(format!("tick-{n}\n").as_bytes())
          .await
          .is_err()
        {
          return;
        }
        n += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
      }
    }))
  } else {
    drop(stdin);
    None
  };

  // Steady state before the outage.
  for _ in 0..10 {
    tokio::time::timeout(Duration::from_secs(30), rx.recv())
      .await
      .context("no steady traffic before the outage")?
      .context("session ended before the outage")?;
  }

  let iface = lab.topo.client.iface("eth0").context("client eth0")?;
  iface
    .set_condition(LinkCondition::new().loss_pct(100.0), LinkDirection::Both)
    .await?;
  tokio::time::sleep(Duration::from_secs(1)).await;
  while rx.try_recv().is_ok() {}
  tokio::time::sleep(OUTAGE - Duration::from_secs(1)).await;
  ensure!(
    rx.try_recv().is_err(),
    "traffic crossed the blackhole; the lab is not delivering the outage"
  );
  iface.clear_condition(LinkDirection::Both).await?;
  let restored = Instant::now();

  let arrival = tokio::time::timeout(RECOVERY_LIMIT, rx.recv())
    .await
    .with_context(|| {
      format!("nothing arrived within {RECOVERY_LIMIT:?} of restore")
    })?
    .context("the session died across the outage")?;
  let recovery = arrival.saturating_duration_since(restored);

  child.kill().await?;
  reader.abort();
  if let Some(writer) = writer {
    writer.abort();
  }
  let stderr = String::from_utf8_lossy(&stderr.await?).into_owned();
  ensure!(
    !stderr.contains("falling back"),
    "the session must use QUIC:\n{stderr}"
  );
  Ok(recovery)
}

/// The control: the client sends only acknowledgements, so the prober's
/// PING is never congestion-blocked and recovery tracks the probe
/// cadence.
#[tokio::test(flavor = "current_thread")]
async fn outage_60s_recovers_promptly_when_only_the_server_sends() -> Result<()>
{
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let recovery = outage_rep(&lab, false).await?;
  eprintln!("60s outage, server-driven session: recovered in {recovery:?}");
  ensure!(
    recovery <= PROBE_BOUND,
    "recovery took {recovery:?}, probe bound {PROBE_BOUND:?}"
  );
  Ok(())
}

/// The same outage with the client also writing, at ten small lines a
/// second -- a fast typist, or any forwarded stream. The probes still
/// bound recovery only because declaring a stall stops the transport
/// taking more application data (`mush_core::roaming`).
#[tokio::test(flavor = "current_thread")]
async fn outage_60s_recovers_promptly_when_the_client_also_sends() -> Result<()>
{
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let recovery = outage_rep(&lab, true).await?;
  eprintln!("60s outage, client also sending: recovered in {recovery:?}");
  ensure!(
    recovery <= PROBE_BOUND,
    "recovery took {recovery:?}, probe bound {PROBE_BOUND:?}"
  );
  Ok(())
}
