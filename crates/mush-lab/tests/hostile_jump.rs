// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Hostile probes against jump-host Phase A in the lab: what happens to
//! a live session when the bastion it bootstrapped through disappears.
//!
//! The jump carries the bootstrap and nothing else -- once the pinned
//! QUIC handshake is up the session goes straight to the destination --
//! so a jump that dies mid-session must be invisible to it. The
//! teardown here is as violent as the lab allows: sshd killed, both
//! interfaces downed.
//!
//! Runs under the nextest `lab` profile; see `docs/testing.md`. The
//! `mush` binary must be built first (`cargo build -p mush`).

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use mush_testenv::patchbay::Device;
use mush_testenv::wait_tcp_ready;

mod common;

use common::{JumpLab, Session, drain, established_at, spawn_session, t};

mush_testenv::userns_bootstrap!();

const STEP: Duration = Duration::from_secs(30);
const CANDIDATE_LOG: &str = "mush_core::client=debug";

/// Takes a lab host off the network entirely: every interface down.
/// Blunter than a firewall rule, because the point is a jump that is
/// simply gone.
fn sever(dev: &Device, ifaces: &[&str]) -> Result<()> {
  let ip = which_ip()?;
  let ifaces: Vec<String> = ifaces.iter().map(|s| s.to_string()).collect();
  dev.run_sync(move || {
    for iface in &ifaces {
      let status = std::process::Command::new(&ip)
        .args(["link", "set", iface, "down"])
        .status()
        .context("spawning ip")?;
      ensure!(status.success(), "`ip link set {iface} down` failed");
    }
    Ok(())
  })
}

fn which_ip() -> Result<std::path::PathBuf> {
  let path = std::env::var_os("PATH").unwrap_or_default();
  std::env::split_paths(&path)
    .chain(["/usr/sbin", "/sbin"].iter().map(std::path::PathBuf::from))
    .map(|d| d.join("ip"))
    .find(|p| p.is_file())
    .context("required binary `ip` not found")
}

/// The bastion dies after establishment. A session established through
/// it must not notice: the QUIC path is direct to the destination, and
/// the bootstrap channel's job ended at the connect line.
#[tokio::test(flavor = "current_thread")]
async fn jump_death_mid_session_is_invisible() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let mut lab = JumpLab::policy().await?;

  let args = lab
    .mush
    .ssh_args_with(lab.dest_ip, &["--no-fallback", "-J", &lab.jump_spec]);
  let mut session = Session::attach(
    spawn_session(&lab.topo.client, &args, "cat", Some(CANDIDATE_LOG))?,
    STEP,
  )?;

  // The session works while the jump is alive.
  session
    .echo_within("before-jump-death", STEP, "the pre-death echo")
    .await?;
  ensure!(
    lab.mush.marked_process_exists(),
    "no marked mush server found during the session"
  );

  // Kill the jump: sshd first, then the host off the network.
  drop(lab.sshd_jump.take());
  sever(&lab.topo.jump, &["eth0", "eth1"])?;
  // The jump really is gone: its ssh port is unreachable.
  ensure!(
    wait_tcp_ready(
      &lab.topo.client,
      SocketAddr::new(lab.jump_ip.into(), lab.fix.port),
      Duration::from_secs(2),
    )
    .await
    .is_err(),
    "the jump must be unreachable after being severed"
  );

  // Several round trips, spread over enough time that a stall shows.
  for n in 0..5 {
    session
      .echo_within(&format!("after-jump-death-{n}"), STEP, "a post-death echo")
      .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
  }

  let stderr = session.close_no_fallback().await?;
  ensure!(
    established_at(&stderr, lab.dest_ip),
    "the session must have gone straight to {}; stderr:\n{stderr}",
    lab.dest_ip
  );
  lab.mush.wait_no_marked_processes().await
}

/// The same teardown with the jump severed *during* establishment: the
/// bootstrap ssh is mid-flight when the bastion disappears. This must
/// fail cleanly and say why, never hang for the bootstrap timeout's
/// full two minutes or degrade to a direct TCP connection that bypasses
/// the policy the jump exists to enforce. Both are asserted positively,
/// since a non-zero exit alone is what any unrelated breakage produces.
#[tokio::test(flavor = "current_thread")]
async fn jump_death_during_bootstrap_fails_without_bypassing_the_policy()
-> Result<()> {
  mush_testenv::skip_unless_available!();
  let mut lab = JumpLab::policy().await?;

  // Sever first: the bootstrap has no jump to traverse at all.
  drop(lab.sshd_jump.take());
  sever(&lab.topo.jump, &["eth0", "eth1"])?;

  // No --no-fallback here: the point is that the fallback must not fire
  // and reach the destination by bypassing the jump.
  let args = lab.mush.ssh_args_with(lab.dest_ip, &["-J", &lab.jump_spec]);
  let mut child =
    spawn_session(&lab.topo.client, &args, "cat", Some(CANDIDATE_LOG))?;
  let stdout = drain(child.stdout.take().context("stdout piped")?);
  let stderr = drain(child.stderr.take().context("stderr piped")?);
  let status = tokio::time::timeout(Duration::from_secs(45), child.wait())
    .await
    .context("a session with a dead jump must fail promptly, not hang")??;
  let stdout = String::from_utf8_lossy(&t(STEP, stdout).await?).into_owned();
  let stderr = String::from_utf8_lossy(&t(STEP, stderr).await?).into_owned();
  eprintln!(
    "dead-jump session: {status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
  );
  ensure!(
    !status.success(),
    "a session with a dead jump must not succeed"
  );
  // The diagnostic `connect.rs` emits for a failed establishment, and
  // the bootstrap child's own status inside it, rather than an exit
  // code a missing binary or a bad key would produce just as well.
  ensure!(
    stderr.contains("session establishment failed"),
    "a dead jump must fail with the establishment diagnostic:\n{stderr}"
  );
  ensure!(
    stderr.contains("bootstrap ssh exited with"),
    "the diagnostic must name the bootstrap ssh's failure:\n{stderr}"
  );
  // No server was reached, so the policy held. Nor may the fallback
  // fire: it is the last kind of path for a destination that answered but is
  // unreachable over UDP, not for a bootstrap that never happened.
  ensure!(
    !lab.mush.marked_process_exists(),
    "a mush server was reached by bypassing the dead jump"
  );
  ensure!(
    !stderr.contains("falling back"),
    "the TCP fallback must not bypass a configured jump:\n{stderr}"
  );
  lab.mush.wait_no_marked_processes().await
}
