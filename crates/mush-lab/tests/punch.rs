// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Coordinated punching and the fallback order on the real kernel
//! (design doc, "Path establishment"): real `mush jump-helper` on a real
//! bastion, real nftables edges on both sides, and a real OpenSSH
//! session using whichever kind of path establishment settled on. The
//! cells below are the ones the design names, with a helper and without.
//!
//! Which kind of path carried a session is the assertion, read from the
//! client's own path report rather than inferred: a relayed session and
//! a punched one look identical from the outside, and a punched one that
//! quietly became a relay (or a TCP fallback) would otherwise pass.
//!
//! Runs under the nextest `lab` profile; see `docs/testing.md`. The
//! `mush` binary must be built first (`cargo build -p mush`).

#![cfg(target_os = "linux")]

use std::time::Duration;

use anyhow::{Result, bail, ensure};
use mush_core::path::PathKind;
use mush_testenv::patchbay::Device;
use mush_testenv::{
  NatMode, jump_chain_two_hops, jump_chain_with, jump_policy,
};
use tokio::process::Command;

mod common;

use common::{JumpLab, Report, Session, spawn_in};

mush_testenv::userns_bootstrap!();

/// Generous timeout for any single await. Establishment's own budget is
/// ten seconds before it gives up on UDP, and the fallback bridge starts
/// after that.
const STEP: Duration = Duration::from_secs(90);

/// A `--helper` command that is not there: the design's bastion with no
/// `mush` installed on it, which every degradation case uses.
const NO_HELPER: &str = "/nonexistent/mush jump-helper";

/// Runs one real `cat` session over Mush and returns the client's
/// stderr with the path report it wrote. The echo proves the session
/// carries real ssh traffic; the report says which kind of path.
async fn session(
  lab: &JumpLab,
  dev: &Device,
  connect_args: &[&str],
) -> Result<(String, Report)> {
  let report = lab.report_path()?;
  let mut args = vec!["-J".to_string(), lab.jump_spec.clone()];
  args.extend(connect_args.iter().map(|arg| (*arg).to_string()));
  let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
  let mut cmd = Command::new("ssh");
  cmd
    .args(lab.mush.ssh_args_with(lab.dest_ip, &borrowed))
    .arg("cat")
    .env("MUSH_PATH_REPORT", &report);
  let mut session = Session::attach(spawn_in(dev, cmd, None)?, STEP)?;
  if let Err(error) = session.echo("over the chosen path").await {
    // Only the client's stderr says why establishment never settled on a path.
    let stderr = session.stderr_now().await?;
    bail!("{error}; session stderr:\n{stderr}");
  }
  let stderr = session.close().await?;
  Ok((stderr, Report::read(&report)?))
}

/// The destination sits behind a stateful firewall with a public
/// address: reachable in principle, dropping everything unsolicited.
/// Only the punch opens it, and the helper tells the destination where
/// to aim -- the client is behind a port-restricted home NAT, so only a
/// reflector knows the address its packets arrive from.
#[tokio::test(flavor = "current_thread")]
async fn a_firewalled_destination_is_punched_open() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = JumpLab::new(
    jump_chain_with(NatMode::PortRestricted, NatMode::FirewallOnly).await?,
  )
  .await?;

  let (stderr, report) =
    session(&lab, &lab.topo.client, &["--no-fallback"]).await?;
  ensure!(
    report.path_kind == PathKind::Punched,
    "the session should have been punched open, not {}: {report:?}\n{stderr}",
    report.path_kind
  );
  ensure!(
    report.punched,
    "the rendezvous was never ordered: {report:?}"
  );
  // The helper made it possible: the client's own reflexive address is
  // what the destination's probes had to aim at.
  ensure!(
    report.helper != "-" && report.reflexive != "-",
    "the helper never reflected: {report:?}\n{stderr}"
  );
  ensure!(
    report
      .reflexive
      .starts_with(&format!("{}:", lab.topo.client_public_ip()?)),
    "the reflexive address is not the client's WAN address: {report:?}"
  );
  lab.mush.wait_no_marked_processes().await
}

/// The same cell over a chained jump (`-J a,b`), which the design says
/// works the same way with the helper on the last hop.
///
/// The extra bastion is on the public core with no interface on the
/// dest's LAN, so it carries the ssh chain and nothing else. Everything
/// the session needs -- the bootstrap through both hops, the helper's
/// own ssh through the first to the second, the reflection that names
/// this client, the rendezvous that opens the destination's firewall --
/// has to work across the chain for the punched path to carry it.
#[tokio::test(flavor = "current_thread")]
async fn a_chained_jump_runs_the_helper_on_the_last_hop() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = JumpLab::new(
    jump_chain_two_hops(NatMode::PortRestricted, NatMode::FirewallOnly).await?,
  )
  .await?;
  ensure!(
    lab.jump_spec.contains(','),
    "the chain collapsed to one hop: {}",
    lab.jump_spec
  );

  let (stderr, report) =
    session(&lab, &lab.topo.client, &["--no-fallback"]).await?;
  ensure!(
    report.path_kind == PathKind::Punched,
    "a chained jump should punch as a single one does, not {}: \
     {report:?}\n{stderr}",
    report.path_kind
  );
  // The helper answered on the last hop: the first has no route to the
  // destination, so a helper there could reflect but never relay.
  ensure!(
    report.helper.starts_with(&format!("{}:", lab.jump_ip)),
    "the helper did not run on the last hop: {report:?}\n{stderr}"
  );
  ensure!(
    report
      .reflexive
      .starts_with(&format!("{}:", lab.topo.client_public_ip()?)),
    "the reflexive address is not the client's WAN address: {report:?}"
  );
  lab.mush.wait_no_marked_processes().await
}

/// A destination behind a symmetric NAT has no reflexive address worth
/// punching at -- its mapping is bound to the helper -- so establishment
/// ends on the relay, and a real ssh session travels through the bastion.
#[tokio::test(flavor = "current_thread")]
async fn a_symmetric_destination_uses_the_relay() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = JumpLab::new(
    jump_chain_with(NatMode::PortRestricted, NatMode::Symmetric).await?,
  )
  .await?;

  let (stderr, report) =
    session(&lab, &lab.topo.client, &["--no-fallback"]).await?;
  ensure!(
    report.path_kind == PathKind::Relayed,
    "a symmetric destination must end up on the relay, not {}: \
     {report:?}\n{stderr}",
    report.path_kind
  );
  ensure!(
    report.helper.starts_with(&format!("{}:", lab.jump_ip)),
    "the relay should run on the bastion's public address: {report:?}"
  );
  lab.mush.wait_no_marked_processes().await
}

/// Without a helper, direct dialing is unaffected: the jump exists for
/// ssh policy alone, the destination's UDP is open, and the session goes
/// straight there. What the client loses is said once, on stderr.
#[tokio::test(flavor = "current_thread")]
async fn without_a_helper_direct_dialing_is_unaffected() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = JumpLab::new(jump_policy().await?).await?;
  mush_testenv::restrict_inbound_tcp(&lab.topo.dest, lab.topo.jump_dmz_ip()?)?;

  let (stderr, report) = session(
    &lab,
    &lab.topo.client,
    &["--no-fallback", "--helper", NO_HELPER],
  )
  .await?;
  ensure!(
    report.path_kind == PathKind::Direct,
    "an open destination should be dialed directly, not {}: {report:?}\n{stderr}",
    report.path_kind
  );
  ensure!(
    stderr.contains("no jump helper")
      && stderr.contains("relay of last resort"),
    "the client must say once what the missing helper costs:\n{stderr}"
  );
  ensure!(
    report.helper == "-",
    "there was no helper to reflect off: {report:?}"
  );
  lab.mush.wait_no_marked_processes().await
}

/// The design's signaling-only reverse punch, with no `mush` on the
/// bastion: the client names itself with the address the jump observes
/// for it (a plain `echo $SSH_CONNECTION` over ssh), and under a
/// port-preserving edge that is exactly what the destination's outward
/// probes must aim at to open its firewall.
#[tokio::test(flavor = "current_thread")]
async fn without_a_helper_the_reverse_punch_opens_a_firewall() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = JumpLab::new(
    jump_chain_with(NatMode::FullCone, NatMode::FirewallOnly).await?,
  )
  .await?;

  let (stderr, report) = session(
    &lab,
    &lab.topo.client,
    &["--no-fallback", "--helper", NO_HELPER],
  )
  .await?;
  ensure!(
    report.path_kind == PathKind::Punched,
    "the reverse punch should have opened the firewall, not {}: \
     {report:?}\n{stderr}",
    report.path_kind
  );
  ensure!(
    report.helper == "-" && report.reflexive == "-",
    "nothing reflected here; the punch had only the jump's own view: \
     {report:?}"
  );
  lab.mush.wait_no_marked_processes().await
}

/// A helper that answers on ssh but cannot be reached over UDP degrades
/// exactly like a bastion with no `mush` on it (design doc, "Degrading
/// without the helper"), not worse. The helper is real and serving; the
/// client's whole UDP path to it is dropped. That costs reflection and
/// the relay, both of which establishment prunes. What must survive is
/// what a helperless bastion would still give the punched path: the
/// jump's own view of this client, on the ready line so no extra ssh
/// asks for it. Without it the destination has nothing to aim its
/// reverse punch at and the session spends the whole budget on the way
/// to the fallback.
#[tokio::test(flavor = "current_thread")]
async fn a_helper_with_unreachable_udp_keeps_the_reverse_punch() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = JumpLab::new(
    jump_chain_with(NatMode::FullCone, NatMode::FirewallOnly).await?,
  )
  .await?;
  // Inbound UDP to the address the client reaches, and nothing else: ssh
  // to the bastion still works, and the destination still reaches the
  // DMZ address.
  mush_testenv::blackhole_udp_to(&lab.topo.jump, lab.jump_ip)?;

  let (stderr, report) =
    session(&lab, &lab.topo.client, &["--no-fallback"]).await?;
  ensure!(
    report.path_kind == PathKind::Punched,
    "the reverse punch should still have opened the firewall, not {}: \
     {report:?}\n{stderr}",
    report.path_kind
  );
  ensure!(
    report.helper == "-" && report.reflexive == "-",
    "nothing of this client reached the helper: {report:?}"
  );
  ensure!(
    stderr.contains("nothing reached its UDP port")
      && stderr.contains("relay of last resort"),
    "the client must say once what the unreachable helper costs:\n{stderr}"
  );
  lab.mush.wait_no_marked_processes().await
}

/// The last kind of path: with no helper and a destination behind a
/// symmetric NAT there is no UDP path at all, so the session falls back
/// to an `ssh -W` bridge from the bastion and carries real ssh over
/// it -- never a direct dial that would bypass the policy the jump
/// enforces.
#[tokio::test(flavor = "current_thread")]
async fn without_a_helper_a_natted_destination_falls_back_through_the_jump()
-> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = JumpLab::new(
    jump_chain_with(NatMode::PortRestricted, NatMode::Symmetric).await?,
  )
  .await?;

  let (stderr, report) =
    session(&lab, &lab.topo.client, &["--helper", NO_HELPER]).await?;
  ensure!(
    report.path_kind == PathKind::Fallback,
    "the session should have fallen back, not {}: {report:?}\n{stderr}",
    report.path_kind
  );
  ensure!(
    stderr.contains("falling back to plain TCP"),
    "the fallback must be loud:\n{stderr}"
  );
  // The destination's ssh port is unreachable from the client, so the
  // bridge could only have come from the bastion.
  ensure!(
    mush_testenv::wait_tcp_ready(
      &lab.topo.client,
      std::net::SocketAddr::new(lab.dest_ip.into(), lab.fix.port),
      Duration::from_secs(2),
    )
    .await
    .is_err(),
    "the destination's ssh port must be unreachable from the client"
  );
  // No marker sweep here: a session that gave up on UDP leaves the
  // destination's server behind by design, to exit on its own bootstrap
  // timeout. The topology's namespace sweep is the last-resort cleanup.
  Ok(())
}
