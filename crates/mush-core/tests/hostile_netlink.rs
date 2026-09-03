// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! What the netlink monitor costs while nothing is happening: a spin
//! would show up here as a full core. Real sockets and real time, with
//! the process's own CPU accounting as the measurement. What it emits
//! when something does happen needs manufactured kernel events, so it
//! is stated as a contract on `netlink::watch` and exercised through
//! the prober in `hostile_netsim`.

#![cfg(target_os = "linux")]

use std::time::{Duration, Instant};

use mush_core::netlink;

/// This process's CPU time (user + system), from `getrusage(RUSAGE_SELF)`.
fn cpu_time() -> Duration {
  let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
  assert_eq!(
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) },
    0,
    "getrusage failed"
  );
  let secs = |t: libc::timeval| {
    Duration::new(t.tv_sec as u64, (t.tv_usec as u32) * 1000)
  };
  secs(usage.ru_utime) + secs(usage.ru_stime)
}

/// The monitor must be free while the network is quiet: it blocks in
/// `AsyncFd::readable`, so an idle window costs no measurable CPU. A
/// spin (readiness never cleared, a busy retry loop) shows up here as
/// a full core.
#[tokio::test(flavor = "current_thread")]
async fn idle_netlink_monitor_costs_no_measurable_cpu() {
  const WINDOW: Duration = Duration::from_secs(10);

  let Some(mut events) = netlink::watch() else {
    eprintln!("netlink unavailable here (fine); nothing to measure");
    return;
  };

  // Warm up so one-time allocation is not charged to the window.
  tokio::time::sleep(Duration::from_millis(200)).await;
  let cpu_before = cpu_time();
  let wall_before = Instant::now();

  // Drain whatever the host emits; a busy host is not a failure, only
  // an uninformative measurement, which is reported.
  let mut seen = 0u64;
  let deadline = tokio::time::Instant::now() + WINDOW;
  loop {
    tokio::select! {
      _ = tokio::time::sleep_until(deadline) => break,
      event = events.recv() => match event {
        Some(_) => seen += 1,
        None => break,
      },
    }
  }
  let cpu = cpu_time() - cpu_before;
  let wall = wall_before.elapsed();
  let share = cpu.as_secs_f64() / wall.as_secs_f64();
  eprintln!(
    "netlink monitor over {wall:?}: {cpu:?} CPU ({:.4}% of one core), \
     {seen} events from the host",
    share * 100.0
  );
  assert!(
    share < 0.01,
    "the netlink monitor burned {:.2}% of a core while idle",
    share * 100.0
  );
}
