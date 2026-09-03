// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Smoke suite proving the patchbay lab platform itself, with no Mush
//! binary anywhere in it: NAT observability across the modeled grades,
//! real-sshd jump-chain reachability (firewalled DMZ and NATed-dest
//! variants), readiness deadlines on SYN-dropping paths, and leak-free
//! teardown including live session trees. What the grades do to a live
//! Mush session is covered by the acceptance, resilience, and punch
//! suites; this file only pins that the lab builds the edges it claims
//! to.
//!
//! Runs under the nextest `lab` profile; see `docs/testing.md`.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use mush_testenv::{
  NatMode, NatProbe, SshFixture, client_nat, direct, jump_chain, nat_both,
  pgrep_matches, poll_until, procs_in_netns, query_reflector, udp_burst,
  wait_tcp_ready,
};

mush_testenv::userns_bootstrap!();

const REFLECTOR_PORT: u16 = 3478;

/// The client-side source port every edge observation probes from. Each
/// row below builds its own namespaced lab, so one port serves them all.
const PROBE_PORT: u16 = 52101;

/// What the public internet observed for one client socket behind an
/// edge: the mapped address per vantage point, and whether a third
/// party's unsolicited datagram got through.
struct EdgeObservation {
  mapped: Vec<SocketAddr>,
  unsolicited: Option<(SocketAddr, String)>,
  client_public_ip: Ipv4Addr,
  client_ip: Ipv4Addr,
  local_port: u16,
}

/// Builds `client_nat(mode)`, probes reflectors on both vantage routers
/// from one client socket, then sends unsolicited traffic at the first
/// mapped address from the never-contacted third-party router.
async fn observe_edge(
  mode: NatMode,
  local_port: u16,
) -> Result<EdgeObservation> {
  let topo = client_nat(mode).await?;
  let r1 = SocketAddr::new(
    IpAddr::V4(topo.vantage_a.uplink_ip().context("vantage a ip")?),
    REFLECTOR_PORT,
  );
  let r2 = SocketAddr::new(
    IpAddr::V4(topo.vantage_b.uplink_ip().context("vantage b ip")?),
    REFLECTOR_PORT,
  );
  let _g1 = topo.vantage_a.spawn_reflector(r1).await?;
  let _g2 = topo.vantage_b.spawn_reflector(r2).await?;

  let probe = NatProbe::start(
    &topo.client,
    local_port,
    vec![r1, r2],
    Duration::from_secs(2),
  )
  .await?;
  let mapped = probe.mapped.clone();
  udp_burst(
    &topo.third_party,
    mapped[0],
    "UNSOLICITED",
    6,
    Duration::from_millis(150),
  )
  .await?;
  let unsolicited = probe.unsolicited().await?;

  Ok(EdgeObservation {
    mapped,
    unsolicited,
    client_public_ip: topo.client_public_ip()?,
    client_ip: topo.client_ip()?,
    local_port,
  })
}

/// What the public internet must observe for one client socket behind a
/// given edge grade, in RFC 4787's terms.
#[derive(Clone, Copy, Debug)]
enum Mapping {
  /// Endpoint-independent (EIM): one mapping toward every vantage, on
  /// the WAN address, with the source port preserved.
  Stable,
  /// Endpoint-dependent (EDM): a distinct port per destination, still
  /// on the WAN address. No reflexive candidate is worth offering, so
  /// the relayed path exists for exactly this grade.
  PerDestination,
  /// No translation at all: the world sees the client's own address.
  Untranslated,
}

/// The edge grades establishment's expectations rest on. Two vantage
/// points off one client socket separate endpoint-independent mapping
/// from endpoint-dependent; a probe from a router the client never
/// contacted separates endpoint-independent filtering (EIF) from
/// address-and-port-dependent (APDF).
#[tokio::test(flavor = "current_thread")]
async fn nat_matrix_maps_and_filters_per_grade() -> Result<()> {
  mush_testenv::skip_unless_available!();
  for (mode, mapping, delivers_unsolicited) in [
    (NatMode::FullCone, Mapping::Stable, true),
    (NatMode::PortRestricted, Mapping::Stable, false),
    (NatMode::Symmetric, Mapping::PerDestination, false),
    (NatMode::FirewallOnly, Mapping::Untranslated, false),
  ] {
    let obs = observe_edge(mode, PROBE_PORT).await?;
    let wan = IpAddr::V4(obs.client_public_ip);
    match mapping {
      Mapping::Stable => {
        assert_eq!(
          obs.mapped[0], obs.mapped[1],
          "{mode:?}: the mapping must not vary by destination"
        );
        assert_eq!(obs.mapped[0].ip(), wan, "{mode:?}: not the WAN address");
        assert_eq!(
          obs.mapped[0].port(),
          obs.local_port,
          "{mode:?}: the source port must be preserved"
        );
      }
      Mapping::PerDestination => {
        assert_eq!(obs.mapped[0].ip(), wan, "{mode:?}: not the WAN address");
        assert_eq!(obs.mapped[1].ip(), wan, "{mode:?}: not the WAN address");
        assert_ne!(
          obs.mapped[0].port(),
          obs.mapped[1].port(),
          "{mode:?}: each destination must map separately"
        );
      }
      Mapping::Untranslated => {
        let own = SocketAddr::new(IpAddr::V4(obs.client_ip), obs.local_port);
        assert_eq!(obs.mapped[0], own, "{mode:?}: unexpected translation");
        assert_eq!(obs.mapped[1], own, "{mode:?}: unexpected translation");
      }
    }
    if delivers_unsolicited {
      let (_, payload) = obs.unsolicited.with_context(|| {
        format!("{mode:?} must deliver third-party inbound")
      })?;
      assert_eq!(payload, "UNSOLICITED", "{mode:?}: payload corrupted");
    } else {
      assert!(
        obs.unsolicited.is_none(),
        "{mode:?} must filter third-party inbound, got {:?}",
        obs.unsolicited
      );
    }
  }
  Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn jump_chain_ssh_reachability() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let topo = jump_chain(NatMode::FirewallOnly).await?;
  let jump_ip = topo.jump_public_ip()?;
  let dest_ip = topo.dest_ip()?;
  let fix = SshFixture::new()?;
  fix.trust_host(jump_ip)?;
  fix.trust_host(dest_ip)?;

  let mut sshd_jump = fix.spawn_sshd(&topo.jump)?;
  let mut sshd_dest = fix.spawn_sshd(&topo.dest)?;
  sshd_jump
    .wait_ready(&topo.client, jump_ip, Duration::from_secs(10))
    .await?;
  // The dest's sshd is only reachable from inside the DMZ.
  sshd_dest
    .wait_ready(&topo.jump, dest_ip, Duration::from_secs(10))
    .await?;

  // Direct client -> dest must fail: the DMZ drops it.
  let direct_try = fix
    .ssh_exec(&topo.client, &fix.client_ssh_args(dest_ip), "true")
    .await?;
  assert!(
    !direct_try.success,
    "direct client->dest ssh must fail; stdout={} stderr={}",
    direct_try.stdout, direct_try.stderr
  );

  // Through the jump, a real end-to-end exec must work.
  let via_jump = fix
    .ssh_exec(
      &topo.client,
      &fix.client_ssh_args_via_jump(dest_ip, jump_ip),
      "echo MUSH_LAB_JUMP_OK",
    )
    .await?;
  assert!(
    via_jump.success && via_jump.stdout.contains("MUSH_LAB_JUMP_OK"),
    "ssh -J through the jump failed; stdout={} stderr={}",
    via_jump.stdout,
    via_jump.stderr
  );
  Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn jump_chain_nat_dest_reachable_only_from_jump() -> Result<()> {
  mush_testenv::skip_unless_available!();
  // The relayed-path topology: dest behind a symmetric NAT, jump
  // dual-homed into its LAN. The dest's address is private and its
  // reflexive candidates useless, so the design doc's establishment
  // must fall back to relaying through the jump.
  let topo = jump_chain(NatMode::Symmetric).await?;
  let dest_ip = topo.dest_ip()?;
  let target = SocketAddr::new(IpAddr::V4(dest_ip), 7400);
  let _echo = topo
    .dest
    .spawn_reflector(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 7400))
    .await?;

  let from_jump =
    query_reflector(&topo.jump, target, 5, Duration::from_millis(500)).await?;
  assert_eq!(from_jump.ip(), IpAddr::V4(topo.jump_dmz_ip()?));

  let from_client =
    query_reflector(&topo.client, target, 2, Duration::from_millis(400)).await;
  assert!(
    from_client.is_err(),
    "client must not reach a NATed dest directly, got {from_client:?}"
  );
  Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn tcp_readiness_honors_deadline_on_dropped_syns() -> Result<()> {
  mush_testenv::skip_unless_available!();
  // A firewalled dest drops SYNs silently; the readiness poll must still
  // fail at its own deadline instead of waiting out the kernel's SYN
  // retransmit cycle (~2 minutes) past it.
  let topo = nat_both(NatMode::PortRestricted, NatMode::FirewallOnly).await?;
  let addr = SocketAddr::new(IpAddr::V4(topo.dest_ip()?), 2222);
  let started = std::time::Instant::now();
  let ready = wait_tcp_ready(&topo.client, addr, Duration::from_secs(2)).await;
  let elapsed = started.elapsed();
  assert!(ready.is_err(), "firewalled port must not become ready");
  assert!(
    elapsed < Duration::from_secs(10),
    "deadline overshot: {elapsed:?}"
  );
  Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn teardown_leaves_no_processes() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let topo = direct().await?;
  let dest_ip = topo.dest_ip()?;
  let fix = SshFixture::new()?;
  fix.trust_host(dest_ip)?;
  // The fixture dir is unique to this test and appears in sshd's argv,
  // so it doubles as the process marker for the leak check.
  let marker = fix.dir().display().to_string();

  let mut sshd = fix.spawn_sshd(&topo.dest)?;
  sshd
    .wait_ready(&topo.client, dest_ip, Duration::from_secs(10))
    .await?;
  let out = fix
    .ssh_exec(
      &topo.client,
      &fix.client_ssh_args(dest_ip),
      "echo MUSH_LAB_OK",
    )
    .await?;
  assert!(
    out.success && out.stdout.contains("MUSH_LAB_OK"),
    "ssh exec failed; stdout={} stderr={}",
    out.stdout,
    out.stderr
  );
  assert!(
    pgrep_matches(&marker),
    "sshd should be running while the lab is up"
  );

  drop(sshd);
  drop(topo);
  drop(fix);
  poll_until(
    "spawned processes to exit after teardown",
    Duration::from_secs(5),
    Duration::from_millis(100),
    || {
      let marker = marker.clone();
      async move { !pgrep_matches(&marker) }
    },
  )
  .await
}

#[tokio::test(flavor = "current_thread")]
async fn teardown_kills_live_session_trees() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let topo = direct().await?;
  let dest_ip = topo.dest_ip()?;
  let fix = SshFixture::new()?;
  fix.trust_host(dest_ip)?;
  let mut sshd = fix.spawn_sshd(&topo.dest)?;
  sshd
    .wait_ready(&topo.client, dest_ip, Duration::from_secs(10))
    .await?;

  // A session still running at teardown. Its remote tree (sshd-session,
  // login shell, the command) carries no fixture marker in argv and
  // sits outside PDEATHSIG's direct-child reach, so only the topology's
  // netns sweep can reap it.
  let mut cmd = tokio::process::Command::new("ssh");
  cmd
    .args(fix.client_ssh_args(dest_ip))
    .arg("echo MUSH-LAB-SESSION-UP; sleep 300")
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());
  mush_testenv::harden_command(&mut cmd);
  let mut session = topo.client.spawn_command(cmd)?;
  let stdout = session.stdout.take().context("session stdout")?;
  {
    use tokio::io::AsyncBufReadExt;
    let mut lines = tokio::io::BufReader::new(stdout).lines();
    let line = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
      .await
      .context("session did not come up")??;
    assert_eq!(line.as_deref(), Some("MUSH-LAB-SESSION-UP"));
  }

  let inodes = topo.netns_inodes().to_vec();
  assert!(
    !procs_in_netns(&inodes).is_empty(),
    "live session processes should be visible in the lab namespaces"
  );

  drop(session);
  drop(sshd);
  drop(topo);
  drop(fix);
  poll_until(
    "lab namespaces to be empty after teardown",
    Duration::from_secs(5),
    Duration::from_millis(100),
    || {
      let inodes = inodes.clone();
      async move { procs_in_netns(&inodes).is_empty() }
    },
  )
  .await
}

/// Regression test: sshd's stderr (the VERBOSE log) must be drained for
/// the server's whole lifetime. An undrained pipe fills after ~64KB of
/// log, sshd blocks writing it, and every subsequent connection hangs
/// mid-auth -- visible only in long-lived labs like the perf harness.
/// 100 sequential execs write well past one pipe buffer of log.
#[tokio::test(flavor = "current_thread")]
async fn sshd_log_volume_does_not_stall_connections() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let topo = direct().await?;
  let dest_ip = topo.dest_ip()?;
  let fix = SshFixture::new()?;
  fix.trust_host(dest_ip)?;
  let mut sshd = fix.spawn_sshd(&topo.dest)?;
  sshd
    .wait_ready(&topo.client, dest_ip, Duration::from_secs(10))
    .await?;
  for i in 0..100 {
    let out = tokio::time::timeout(
      Duration::from_secs(10),
      fix.ssh_exec(&topo.client, &fix.client_ssh_args(dest_ip), "true"),
    )
    .await
    .with_context(|| format!("ssh exec {i} hung: sshd log not drained?"))??;
    assert!(out.success, "ssh exec {i} failed: {}", out.stderr);
  }
  Ok(())
}
