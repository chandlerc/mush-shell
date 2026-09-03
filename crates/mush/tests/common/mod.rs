// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The leak guard both loopback suites need: Mush's remote-side
//! processes detach, so a test failing between establishment and clean
//! teardown leaves an unparented server or helper on a UDP port in the
//! shared Mosh range indefinitely (retention is unbounded by default).
//! Each is tagged with a unique `--marker` and swept with pgrep.

use std::time::Duration;

/// Generous bound on any single await: orders of magnitude above
/// loopback expectations, so timing variation cannot flake these tests.
const DEADLINE: Duration = Duration::from_secs(60);

/// The built `mush` binary both suites drive.
pub const MUSH_BIN: &str = env!("CARGO_BIN_EXE_mush");

pub async fn t<F: Future>(future: F) -> F::Output {
  tokio::time::timeout(DEADLINE, future)
    .await
    .expect("test deadline hit")
}

/// A unique marker for `--marker`/pgrep, per suite, test, and process.
pub fn unique_marker(prefix: &str, name: &str) -> String {
  let nanos = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .subsec_nanos();
  format!("{prefix}-{name}-{}-{nanos}", std::process::id())
}

/// Kills any marked process left behind when a test unwinds.
/// `kill_on_drop` reaches only the direct child, and a detached server
/// or helper is unparented.
pub struct MarkerGuard(String);

impl MarkerGuard {
  pub fn new(marker: &str) -> Self {
    Self(marker.to_owned())
  }
}

impl Drop for MarkerGuard {
  fn drop(&mut self) {
    let _ = std::process::Command::new("pkill")
      .args(["-KILL", "-f", &self.0])
      .status();
  }
}

/// PIDs of processes whose argv contains `marker`.
// Both suites reach this through `assert_marker_gone`; only one of them
// also asks directly.
#[allow(dead_code)]
pub fn marker_pids(marker: &str) -> Vec<String> {
  let output = std::process::Command::new("pgrep")
    .args(["-f", marker])
    .output()
    .expect("pgrep is available");
  String::from_utf8_lossy(&output.stdout)
    .split_whitespace()
    .map(str::to_owned)
    .collect()
}

/// Asserts every marked process exits within 30 seconds: prompt on the
/// normal paths, comfortably past the bounded-retention windows.
///
/// A survivor is reported with what it is waiting on and which sockets
/// it holds: one still on its UDP socket alone never served anything,
/// one holding a loopback TCP connection is still relaying, and those
/// are unrelated failures.
pub async fn assert_marker_gone(marker: &str) {
  for _ in 0..300 {
    if marker_pids(marker).is_empty() {
      return;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
  }
  let surviving: Vec<String> = marker_pids(marker)
    .iter()
    .map(|pid| {
      let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|raw| String::from_utf8_lossy(&raw).replace('\0', " "))
        .unwrap_or_default();
      let wchan = std::fs::read_to_string(format!("/proc/{pid}/wchan"))
        .unwrap_or_default();
      let sockets = std::process::Command::new("ss")
        .args(["-tunap"])
        .output()
        .map(|out| {
          String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|line| line.contains(&format!("pid={pid},")))
            .collect::<Vec<_>>()
            .join("\n      ")
        })
        .unwrap_or_default();
      format!("{pid} [{wchan}] {cmdline}\n      {sockets}")
    })
    .collect();
  panic!("marked mush process still running: {surviving:#?}");
}
