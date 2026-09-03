// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Candidate gathering and racing end to end (design doc, "Jump hosts
//! and NAT traversal", Phase A): the destination announces every
//! address it can be reached at, and the client races them. Two
//! topologies, both with the real binary in real namespaces:
//! jump-for-policy (dest ssh reachable only through the bastion, its
//! UDP wide open) and multi-address (a second dest address, the first
//! one's UDP blackholed).
//!
//! Runs under the nextest `lab` profile; see `docs/testing.md`. The
//! `mush` binary must be built first (`cargo build -p mush`).

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use mush_testenv::{
  MushFixture, blackhole_udp_to, direct, query_reflector, wait_tcp_ready,
};
use tokio::process::{Child, Command};

mod common;

use common::{
  JumpLab, Lab, READY, Session, established_at, next_line, spawn_in,
  spawn_session,
};

mush_testenv::userns_bootstrap!();

/// Generous timeout for any single await that should be quick.
const STEP: Duration = Duration::from_secs(60);

/// Turns on the three client-side lines these tests read: the winning
/// candidate ("pinned handshake established", with the address it was
/// established at), the path report, and the end of the signaling phase
/// ("signaling settled", from the channel that runs it). Every session
/// below inherits this environment down to `mush connect`.
const CLIENT_LOG: &str =
  "mush_core::client=debug,mush_core::channel=debug,mush::connect=debug";

/// Runs one `cat` session over spawned Mush processes: echo a line
/// through it, confirm a marked Mush server is serving it, then close
/// stdin and return the session's stderr. The echo proves the tunnel
/// carries real ssh traffic; the marker proves it is Mush's tunnel and
/// not plain ssh.
async fn cat_session(
  mush: &MushFixture,
  child: Child,
  line: &str,
) -> Result<String> {
  let mut session = Session::attach(child, STEP)?;
  session.write_line(line).await?;
  match next_line(&mut session.lines, STEP, "the session echo").await {
    Ok(echo) => ensure!(echo == line, "unexpected echo {echo:?}"),
    Err(error) => {
      let stderr = session.stderr_now().await?;
      bail!("{error}; session stderr:\n{stderr}");
    }
  }
  ensure!(
    mush.marked_process_exists(),
    "no marked mush server found during the session"
  );
  session.close_no_fallback().await
}

/// Proves what the sessions below assume, on top of the unreachable ssh
/// port [`JumpLab::policy`] checks: plain `ssh -J` reaches the
/// destination through the jump, and the destination's UDP is open to
/// the client. Without these the sessions could pass for the wrong
/// reason, or fail for one unrelated to Mush.
async fn assert_policy(lab: &JumpLab) -> Result<()> {
  let via_jump = lab
    .fix
    .ssh_exec(
      &lab.topo.client,
      &lab.fix.client_ssh_args_via_jump(lab.dest_ip, lab.jump_ip),
      "echo MUSH-CAND-JUMP-OK",
    )
    .await?;
  ensure!(
    via_jump.success && via_jump.stdout.contains("MUSH-CAND-JUMP-OK"),
    "ssh -J through the jump must work; stdout={} stderr={}",
    via_jump.stdout,
    via_jump.stderr
  );

  let _reflector = lab
    .topo
    .dest
    .spawn_reflector("0.0.0.0:7500".parse()?)
    .await?;
  query_reflector(
    &lab.topo.client,
    SocketAddr::new(lab.dest_ip.into(), 7500),
    5,
    Duration::from_millis(500),
  )
  .await
  .context("the dest's UDP must be open to the client")?;
  Ok(())
}

/// The design's "jump required for ssh policy but UDP actually
/// reachable" case: `mush connect -J` bootstraps through the bastion as
/// `ssh -J` would, and the session goes straight to the destination,
/// whose address the connect line hinted. `--no-fallback` pins the QUIC
/// path so a silently degraded session could not pass.
#[tokio::test(flavor = "current_thread")]
async fn jump_bootstrap_establishes_quic_directly() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = JumpLab::policy().await?;
  assert_policy(&lab).await?;

  let args = lab
    .mush
    .ssh_args_with(lab.dest_ip, &["--no-fallback", "-J", &lab.jump_spec]);
  let child = spawn_session(&lab.topo.client, &args, "cat", Some(CLIENT_LOG))?;
  let stderr = cat_session(&lab.mush, child, "jump-direct").await?;
  ensure!(
    established_at(&stderr, lab.dest_ip),
    "the session must go over QUIC straight to {}; stderr:\n{stderr}",
    lab.dest_ip
  );
  // A jump also engages the signaling phase (design doc, "Signaling"):
  // the destination held the bootstrap channel open past its detach and
  // answered with its terminator, which settles the phase. A channel
  // that closed at the detach, or a terminator that never crossed the
  // bastion, would leave the phase to time out.
  ensure!(
    stderr.contains("signaling settled"),
    "the jumped session must settle its signaling phase; stderr:\n{stderr}"
  );
  lab.mush.wait_no_marked_processes().await
}

/// The same path through wrapper mode: `mush -J <jump> <dest> <cmd>`
/// strips `-J` from the outer ssh and forwards it to the bootstrap ssh
/// through the environment, so the bootstrap traverses the bastion and
/// the tunnel is direct. With a jump configured the TCP fallback is
/// refused outright, so the session either uses QUIC or fails.
#[tokio::test(flavor = "current_thread")]
async fn wrapper_jump_passthrough_establishes_quic_directly() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = JumpLab::policy().await?;

  let mut cmd = Command::new(lab.mush.mush_bin());
  cmd
    .args(["-J", &lab.jump_spec])
    .args(lab.mush.wrapper_args(lab.dest_ip, "cat"))
    .env("PATH", lab.mush.wrapper_path_env())
    .env("HOME", lab.fix.dir())
    .env_remove("MUSH_BOOTSTRAP_SSH_ARGS")
    .env_remove("MUSH_CONNECT_SSH")
    .env_remove("MUSH_CONNECT_SERVER");
  let child = spawn_in(&lab.topo.client, cmd, Some(CLIENT_LOG))?;
  let stderr = cat_session(&lab.mush, child, "wrapper-jump").await?;
  ensure!(
    established_at(&stderr, lab.dest_ip),
    "the wrapper session must go over QUIC straight to {}; stderr:\n{stderr}",
    lab.dest_ip
  );
  lab.mush.wait_no_marked_processes().await
}

/// Multi-address racing: the destination has two addresses, and the
/// first hint (the one the bootstrap ssh arrived on, which the server
/// ranks first) is a UDP black hole. Only a client that gathers the
/// remaining hint and keeps racing after the leader goes quiet gets a
/// session, and it must be established at the second address.
#[tokio::test(flavor = "current_thread")]
async fn blackholed_first_hint_loses_the_race_to_the_second() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let topo = direct().await?;
  let alias = topo.add_dest_alias().await?;
  // The address the client reaches over ssh, and so the leading hint,
  // answers TCP but no UDP at all.
  blackhole_udp_to(&topo.dest, topo.dest_ip()?)?;

  let lab = Lab::new(topo).await?;
  let (topo, mush) = (&lab.topo, &lab.mush);
  let dest_ip = lab.dest_ip;

  // The topology is what the test assumes: the second address reaches
  // the same host, and the first one's UDP is blackholed.
  wait_tcp_ready(
    &topo.client,
    SocketAddr::new(alias.into(), lab.fix.port),
    READY,
  )
  .await
  .context("the dest's second address must reach the same host")?;
  let _reflector = topo.dest.spawn_reflector("0.0.0.0:7501".parse()?).await?;
  let reply = query_reflector(
    &topo.client,
    SocketAddr::new(dest_ip.into(), 7501),
    2,
    Duration::from_millis(400),
  )
  .await;
  ensure!(
    reply.is_err(),
    "the blackholed address must not answer UDP, got {reply:?}"
  );

  let args = mush.ssh_args_with(dest_ip, &["--no-fallback"]);
  let child = spawn_session(&topo.client, &args, "cat", Some(CLIENT_LOG))?;
  let stderr = cat_session(mush, child, "second-hint").await?;
  ensure!(
    established_at(&stderr, alias),
    "the session must have been established at the second hint {alias}; \
     stderr:\n{stderr}"
  );
  mush.wait_no_marked_processes().await
}
