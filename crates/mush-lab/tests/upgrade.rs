// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Relay-first startup and the upgrade to a direct path on the real
//! kernel (design doc, "Upgrading from relay to direct"): a real
//! OpenSSH session moved onto a real punched path underneath it, and a
//! relayed session carried through a real uplink switch.
//!
//! The session stays open across the network change in both, which is
//! the whole claim: an upgrade and a re-registration are things that
//! happen to a session in flight, so a test that established afterwards
//! would prove nothing. Each asserts the client's path report --
//! rewritten on every switch -- plus the ssh echo saying the session
//! still carries traffic on the path it ended up on.
//!
//! The report is what the client believes, so the test does not rely on
//! it for the upgrade: the bastion's UDP is taken away afterwards, and
//! the session has to go on working without it. The netsim tier reads
//! the simulated network's own trace and can be that exact; here the
//! relay path is simply removed, which is the same question asked of a
//! real kernel.
//!
//! Runs under the nextest `lab` profile; see `docs/testing.md`. The
//! `mush` binary must be built first (`cargo build -p mush`).

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, ensure};
use mush_core::path::PathKind;
use mush_testenv::{
  NatMode, Uplink, block_udp_from, jump_chain_with, jump_roaming,
  unblock_udp_from,
};

use tokio::process::Command;

mod common;

use common::{JumpLab, Report, Session, spawn_in};

mush_testenv::userns_bootstrap!();

/// Generous timeout for any single await, against an establishment
/// budget of ten seconds and a policy that probes on a two-second
/// cadence for thirty.
const STEP: Duration = Duration::from_secs(90);

/// How long the path may take to switch after the network changes.
const SWITCH: Duration = Duration::from_secs(45);

/// How often the client's path report is re-read while waiting.
const POLL: Duration = Duration::from_millis(200);

/// A bastion helper with a retention limit, comfortably above the
/// peers' own heartbeat cadence so it holds for the session's life, and
/// short enough that the hygiene sweep can wait it out.
const RETAINED_HELPER: &str = "mush jump-helper --retain 20s";

/// Opens a `cat` session over Mush, with its own path-report file, kept
/// open so the network can change under it.
async fn open_session(
  lab: &JumpLab,
  connect_args: &[&str],
) -> Result<(Session, PathBuf)> {
  let report = lab.report_path()?;
  let mut args = vec!["-J".to_string(), lab.jump_spec.clone()];
  args.extend(connect_args.iter().map(|arg| (*arg).to_string()));
  let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
  let mut cmd = Command::new("ssh");
  cmd
    .args(lab.mush.ssh_args_with(lab.dest_ip, &borrowed))
    .arg("cat")
    .env("MUSH_PATH_REPORT", &report);
  let session = Session::attach(spawn_in(&lab.topo.client, cmd, None)?, STEP)?;
  Ok((session, report))
}

/// Waits for the session's path to reach `path_kind`.
async fn settles_on(report: &Path, path_kind: PathKind) -> Result<Report> {
  Report::settles_on(report, path_kind, SWITCH, POLL).await
}

/// The design's Tailscale-style promise on real hardware: a session
/// that had to start on the relay moves onto a direct path once one
/// becomes possible, with a real ssh session carried across the switch.
///
/// The destination sits behind a stateful firewall, the cell the punch
/// normally opens; a rule dropping the client's UDP there makes it fail
/// at first, leaving the bastion's relay as the only path. Removing the
/// rule is the network change -- a route that came back, a policy that
/// lifted -- and nothing tells either peer about it.
#[tokio::test(flavor = "current_thread")]
async fn a_relayed_session_upgrades_when_punching_becomes_possible()
-> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = JumpLab::new(
    jump_chain_with(NatMode::PortRestricted, NatMode::FirewallOnly).await?,
  )
  .await?;
  let client_wan = lab.topo.client_public_ip()?;
  block_udp_from(&lab.topo.dest, client_wan)?;

  let (mut session, report) = open_session(&lab, &["--no-fallback"]).await?;
  session.echo("over the relay").await?;
  let relayed = Report::read(&report)?;
  ensure!(
    relayed.path_kind == PathKind::Relayed,
    "the session should have started on the relay, not {}: {relayed:?}",
    relayed.path_kind
  );
  ensure!(
    relayed.helper != "-",
    "there is no relay without a helper: {relayed:?}"
  );

  // The punch can succeed from here on; the session must notice on its own.
  unblock_udp_from(&lab.topo.dest)?;
  let upgraded = settles_on(&report, PathKind::Punched).await?;
  ensure!(
    upgraded.addr != relayed.addr,
    "the session did not actually move: {upgraded:?}"
  );

  // The session that started on the relay is still the one running.
  session.echo("over the direct path").await?;

  // The bastion is asked to prove it: with its UDP taken from the
  // client, only a real direct path can carry the next line. The report
  // alone would not settle it -- a session switched in name only would
  // echo just as well over the relay -- and this is the tier where a
  // regression the netsim cannot see would live.
  block_udp_from(&lab.topo.jump, client_wan)?;
  session.echo("with the relay path cut").await?;
  let after = Report::read(&report)?;
  ensure!(
    after.path_kind == PathKind::Punched,
    "the session left the direct path when the relay was cut: {after:?}"
  );

  let stderr = session.close().await?;
  ensure!(
    !stderr.contains("falling back"),
    "the session fell back to TCP:\n{stderr}"
  );
  lab.mush.wait_no_marked_processes().await
}

/// The helper forwards to the address a peer's last signed probe came
/// from, so moving the client onto another uplink -- a new WAN address,
/// a new mapping -- leaves it sending from somewhere the helper drops
/// as unknown. The client's own path policy re-registers, and the ssh
/// echo afterwards is what says it did: nothing else could carry those
/// bytes, with the destination behind a symmetric NAT and no direct
/// path to offer.
#[tokio::test(flavor = "current_thread")]
async fn a_relayed_session_survives_an_uplink_switch() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = JumpLab::new(
    jump_roaming(NatMode::PortRestricted, NatMode::Symmetric).await?,
  )
  .await?;

  // A limit on the bastion, because this session ends without being
  // able to say so: the client's ssh to the jump runs over the uplink
  // it is about to leave, so the channel carrying `MUSH CLOSE` dies
  // with the switch. What is left is the helper's own rule -- silence
  // past its limit once nothing heartbeats it -- kept short here.
  let (mut session, report) =
    open_session(&lab, &["--no-fallback", "--helper", RETAINED_HELPER]).await?;
  session.echo("before the switch").await?;
  let before = Report::read(&report)?;
  ensure!(
    before.path_kind == PathKind::Relayed,
    "a symmetric destination must end up on the relay, not {}: {before:?}",
    before.path_kind
  );

  ensure!(
    lab.topo.wan_ip(Uplink::A)? != lab.topo.wan_ip(Uplink::B)?,
    "the two uplinks share a WAN address; the switch would prove nothing"
  );
  lab.topo.use_uplink(Uplink::B).await?;

  // The registration the relay routes on came from a mapping that no
  // longer exists: this line arrives only if the session made a new one.
  session.echo("after the switch").await?;
  let after = Report::read(&report)?;
  ensure!(
    after.path_kind == PathKind::Relayed,
    "the session left the relay it has no alternative to: {after:?}"
  );
  session.close().await?;
  lab.mush.wait_no_marked_processes().await
}
