// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Acceptance suite: real OpenSSH over the real `mush` binary in real
//! network namespaces. Every session runs the full production setup --
//! outer ssh with an injected ProxyCommand, `mush connect`, a real
//! bootstrap ssh, the detached `mush server bootstrap`, QUIC across the
//! lab, loopback TCP into a real sshd -- with no fakes anywhere. The
//! outage matrix (blackholes past quinn's default idle timeout, the
//! limits, the asymmetric windows) lives in `resilience.rs`.
//!
//! Runs under the nextest `lab` profile; see `docs/testing.md`. The
//! `mush` binary must be built first (`cargo build -p mush`).

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use mush_testenv::{
  MushFixture, NatMode, Topology, Uplink, block_inbound_udp, client_nat,
  direct, jump_chain, query_reflector, roaming, spawn_tcp_echo, wait_tcp_ready,
};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::Command;

mod common;

use common::{
  JumpLab, Lab, READY, Session, drain, next_line, pseudo_bytes, spawn_session,
  t, tcp_round_trip,
};

mush_testenv::userns_bootstrap!();

/// Generous timeout for any single await that should be quick.
const STEP: Duration = Duration::from_secs(60);

/// Pipes `len` pseudo-random bytes through a remote `cat` and asserts a
/// byte-exact echo: stdin streaming, flow control, and the half-close
/// mapping (client EOF -> FIN -> sshd shutdown, return path still
/// delivering) in one round trip.
async fn cat_round_trip(
  lab: &Lab<Topology>,
  len: usize,
  seed: u64,
) -> Result<()> {
  let payload = pseudo_bytes(len, seed);
  let mut child = spawn_session(
    &lab.topo.client,
    &lab.mush.ssh_args(lab.dest_ip),
    "cat",
    None,
  )?;
  let mut stdin = child.stdin.take().context("stdin piped")?;
  let stdout = drain(child.stdout.take().context("stdout piped")?);
  let stderr = drain(child.stderr.take().context("stderr piped")?);

  // Concurrent writer: the payload exceeds every pipe buffer, so the
  // echo must be drained while writing.
  let to_write = payload.clone();
  let writer = tokio::spawn(async move {
    stdin.write_all(&to_write).await?;
    // Dropping stdin is the half-close; the echo's tail follows.
    drop(stdin);
    Ok::<_, std::io::Error>(())
  });

  let echoed = t(STEP, stdout).await?;
  let status = t(STEP, child.wait()).await?;
  t(STEP, writer).await??;
  let stderr = t(STEP, stderr).await?;
  ensure!(
    status.success(),
    "ssh cat session failed ({status}); stderr:\n{}",
    String::from_utf8_lossy(&stderr)
  );
  // A QUIC-path assertion, not just byte fidelity: the TCP fallback
  // passes the round trip too, distinguishable only by a stderr warning.
  ensure!(
    !String::from_utf8_lossy(&stderr).contains("falling back"),
    "the session must use QUIC, not the TCP fallback:\n{}",
    String::from_utf8_lossy(&stderr)
  );
  ensure!(
    echoed == payload,
    "cat round-trip corrupted: {} bytes sent, {} bytes back",
    payload.len(),
    echoed.len()
  );
  Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn exec_round_trip_and_exit_code_propagation() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let args = lab.mush.ssh_args(lab.dest_ip);

  let out = lab
    .fix
    .ssh_exec(&lab.topo.client, &args, "echo MUSH-ACC-ECHO")
    .await?;
  ensure!(
    out.success && out.stdout.contains("MUSH-ACC-ECHO"),
    "exec through mush failed; stdout={} stderr={}",
    out.stdout,
    out.stderr
  );

  // ssh exits with the remote command's status, tunneled or not.
  let fail = lab.fix.ssh_exec(&lab.topo.client, &args, "false").await?;
  ensure!(
    fail.code == Some(1),
    "remote `false` must propagate exit 1, got {:?}; stderr={}",
    fail.code,
    fail.stderr
  );

  lab.mush.wait_no_marked_processes().await
}

#[tokio::test(flavor = "current_thread")]
async fn stdin_streams_through_remote_cat_with_half_close() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  cat_round_trip(&lab, 2 * 1024 * 1024, 0x6d75_7368).await?;
  lab.mush.wait_no_marked_processes().await
}

#[tokio::test(flavor = "current_thread")]
async fn second_session_runs_concurrently() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let args = lab.mush.ssh_args(lab.dest_ip);

  let mut held = Session::attach(
    spawn_session(&lab.topo.client, &args, "cat", None)?,
    STEP,
  )?;
  held
    .echo_within("held-open-1", STEP, "first echo line")
    .await?;

  // A second complete session (its own bootstrap ssh, server process,
  // and tunnel) while the first stays live.
  let out = lab
    .fix
    .ssh_exec(&lab.topo.client, &args, "echo MUSH-ACC-SECOND")
    .await?;
  ensure!(
    out.success && out.stdout.contains("MUSH-ACC-SECOND"),
    "second concurrent session failed; stdout={} stderr={}",
    out.stdout,
    out.stderr
  );

  // The first session is unaffected by the second's lifecycle.
  held
    .echo_within("held-open-2", STEP, "second echo line")
    .await?;
  held.close().await?;

  lab.mush.wait_no_marked_processes().await
}

/// One scp from inside the client namespace, through the ProxyCommand.
async fn scp(lab: &Lab<Topology>, from: &str, to: &str) -> Result<()> {
  let mut cmd = Command::new("scp");
  cmd
    .arg("-F")
    .arg(lab.fix.ssh_config())
    .arg("-o")
    .arg(format!("ProxyCommand={}", lab.mush.proxy_command()))
    .args(["-o", "ConnectTimeout=30", from, to])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
  mush_testenv::harden_command(&mut cmd);
  let child = lab.topo.client.spawn_command(cmd)?;
  let out = t(STEP, child.wait_with_output()).await?;
  ensure!(
    out.status.success(),
    "scp {from} -> {to} failed ({}): {}",
    out.status,
    String::from_utf8_lossy(&out.stderr)
  );
  Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn scp_transfers_both_directions() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  // The lab shares the host filesystem, so "remote" files are just
  // distinct paths written by the sftp server running on the dest.
  let files = tempfile::TempDir::with_prefix("mush-acc-scp-")?;
  let src = files.path().join("push.bin");
  let remote = files.path().join("remote.bin");
  let back = files.path().join("back.bin");
  let payload = pseudo_bytes(3 * 1024 * 1024, 0x7363_7000);
  std::fs::write(&src, &payload)?;

  scp(
    &lab,
    &src.display().to_string(),
    &format!("{}:{}", lab.dest_ip, remote.display()),
  )
  .await?;
  ensure!(
    std::fs::read(&remote)? == payload,
    "scp push corrupted the payload"
  );

  scp(
    &lab,
    &format!("{}:{}", lab.dest_ip, remote.display()),
    &back.display().to_string(),
  )
  .await?;
  ensure!(
    std::fs::read(&back)? == payload,
    "scp pull corrupted the payload"
  );

  lab.mush.wait_no_marked_processes().await
}

#[tokio::test(flavor = "current_thread")]
async fn local_forward_uses_the_tunnel() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  // The echo lives on the dest's loopback: the only path to it from the
  // client is a forwarded channel inside the tunneled SSH connection.
  let echo_addr: SocketAddr = "127.0.0.1:7641".parse()?;
  let _echo = spawn_tcp_echo(&lab.topo.dest, echo_addr).await?;

  let mut args = lab.mush.ssh_opts_with(&[]);
  args.extend(
    [
      "-L",
      "7640:127.0.0.1:7641",
      "-o",
      "ExitOnForwardFailure=yes",
    ]
    .map(String::from),
  );
  args.push(lab.dest_ip.to_string());
  let mut session = Session::attach(
    spawn_session(&lab.topo.client, &args, "cat", None)?,
    STEP,
  )?;

  // Session up (the forward listener exists once the connection is).
  session.echo("fwd-up").await?;
  let local: SocketAddr = "127.0.0.1:7640".parse()?;
  wait_tcp_ready(&lab.topo.client, local, READY).await?;

  let payload = pseudo_bytes(256 * 1024, 0x4c66_7764);
  let echoed =
    tcp_round_trip(&lab.topo.client, local, payload.clone(), STEP).await?;
  ensure!(
    echoed == payload,
    "forwarded channel corrupted: {} bytes sent, {} bytes back",
    payload.len(),
    echoed.len()
  );

  session.close().await?;
  lab.mush.wait_no_marked_processes().await
}

#[tokio::test(flavor = "current_thread")]
async fn roaming_uplink_switch_keeps_the_session() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(roaming().await?).await?;
  let topo = &lab.topo;
  let dest_ip = lab.dest_ip;

  // A reflector on the dest observes which WAN address the client's
  // egress actually uses; the roam below must flip it.
  let _reflector = topo.dest.spawn_reflector("0.0.0.0:3479".parse()?).await?;
  let reflect = SocketAddr::new(dest_ip.into(), 3479);
  let before =
    query_reflector(&topo.client, reflect, 5, Duration::from_millis(500))
      .await?;
  ensure!(
    before.ip() == std::net::IpAddr::V4(topo.wan_ip(Uplink::A)?),
    "expected uplink A before the roam, got {before}"
  );

  // A long-lived session streaming periodic output. --no-fallback pins
  // the QUIC path; a fallen-back TCP session would die at the roam
  // instead of proving anything about migration.
  let remote = "sh -c 'i=0; while [ $i -lt 120 ]; do echo TICK-$i; \
                i=$((i+1)); sleep 0.1; done; echo ROAM-DONE'";
  let args = lab.mush.ssh_args_with(dest_ip, &["--no-fallback"]);
  let mut child = spawn_session(&topo.client, &args, remote, None)?;
  drop(child.stdin.take());
  let mut lines =
    BufReader::new(child.stdout.take().context("stdout piped")?).lines();
  let stderr = drain(child.stderr.take().context("stderr piped")?);

  let first = next_line(&mut lines, STEP, "the first tick").await?;
  ensure!(first.starts_with("TICK-"), "unexpected line {first:?}");
  loop {
    let line = next_line(&mut lines, READY, "steady pre-roam ticks").await?;
    if line == "TICK-10" {
      break;
    }
  }

  // Roam: flip the default route to the other uplink mid-session, and
  // verify the visible address really changed rather than assuming.
  topo.use_uplink(Uplink::B).await?;
  let after =
    query_reflector(&topo.client, reflect, 5, Duration::from_millis(500))
      .await?;
  ensure!(
    after.ip() == std::net::IpAddr::V4(topo.wan_ip(Uplink::B)?),
    "expected uplink B after the roam, got {after}"
  );
  ensure!(
    before.ip() != after.ip(),
    "the roam must change the client's visible address"
  );

  // Kill the old path outright before demanding more output: after a
  // pure route flip uplink A stays serviceable (link up, NAT mapping
  // refreshed by the server's ticks), so a server that never migrated
  // could keep delivering through A. With A dead, delivery must go over
  // uplink B's WAN address, which the server serves only after
  // validating the client migration (design doc, "Roam and recover").
  // ssh dies with the transport, so no reconnect hides behind it.
  topo.fail_uplink(Uplink::A).await?;
  // 20s bounds the recovery, matching the mid-outage roam resilience test:
  // killing the link mid-flight can cost the client a stall-detection
  // and re-egress cycle on top of the migration itself.
  let post_roam =
    next_line(&mut lines, Duration::from_secs(20), "a post-roam tick").await?;
  ensure!(
    post_roam.starts_with("TICK-"),
    "unexpected line {post_roam:?}"
  );
  loop {
    let line =
      next_line(&mut lines, Duration::from_secs(20), "ROAM-DONE").await?;
    if line == "ROAM-DONE" {
      break;
    }
    ensure!(line.starts_with("TICK-"), "unexpected line {line:?}");
  }
  let status = t(STEP, child.wait()).await?;
  ensure!(
    status.success(),
    "roamed session failed ({status}); stderr:\n{}",
    String::from_utf8_lossy(&t(STEP, stderr).await?)
  );
  lab.mush.wait_no_marked_processes().await
}

#[tokio::test(flavor = "current_thread")]
async fn client_nat_full_flow() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(client_nat(NatMode::PortRestricted).await?).await?;
  let out = lab
    .fix
    .ssh_exec(
      &lab.topo.client,
      &lab.mush.ssh_args(lab.dest_ip),
      "echo MUSH-ACC-NAT",
    )
    .await?;
  ensure!(
    out.success && out.stdout.contains("MUSH-ACC-NAT"),
    "exec through NAT failed; stdout={} stderr={}",
    out.stdout,
    out.stderr
  );
  cat_round_trip(&lab, 256 * 1024, 0x6e61_7431).await?;
  lab.mush.wait_no_marked_processes().await
}

#[tokio::test(flavor = "current_thread")]
async fn nat_rebind_mid_session_survives() -> Result<()> {
  mush_testenv::skip_unless_available!();
  // flush_nat_state shells out to `conntrack`, which available() does
  // not require; skip visibly where it cannot work.
  if let Err(reason) = mush_testenv::conntrack_available() {
    eprintln!(
      "{}: {reason} (needed for NAT rebind)",
      mush_testenv::SKIP_MARKER
    );
    return Ok(());
  }
  let lab = Lab::new(client_nat(NatMode::PortRestricted).await?).await?;
  // --no-fallback pins the QUIC path; a fallen-back TCP session uses
  // its own conntrack entry and would prove nothing about Mush.
  let args = lab.mush.ssh_args_with(lab.dest_ip, &["--no-fallback"]);
  let mut session = Session::attach(
    spawn_session(&lab.topo.client, &args, "cat", None)?,
    STEP,
  )?;

  session
    .echo_within("pre-rebind", STEP, "pre-rebind echo")
    .await?;

  // Flush the NAT: the WAN address stays but every mapping dies,
  // blackholing server-to-client traffic until the client's next
  // outbound datagram re-opens one. Masquerade prefers the same source
  // port and nothing contends for it, so the fresh mapping almost
  // certainly reuses the same WAN ip:port: this pins recovery from NAT
  // state loss, not migration (the roaming test carries the migration
  // claim by killing the old path outright).
  lab.topo.client_net.flush_nat_state().await?;
  for round in 0..3u32 {
    session
      .echo_within(
        &format!("post-rebind-{round}"),
        Duration::from_secs(20),
        "post-rebind echo",
      )
      .await?;
  }

  session.close().await?;
  lab.mush.wait_no_marked_processes().await
}

#[tokio::test(flavor = "current_thread")]
async fn udp_blocked_falls_back_to_tcp() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  // Enterprise shape: every UDP datagram into the dest dies, TCP 2222
  // still flows, so bootstrap succeeds and QUIC cannot.
  block_inbound_udp(&lab.topo.dest)?;

  let out = lab
    .fix
    .ssh_exec(
      &lab.topo.client,
      &lab.mush.ssh_args(lab.dest_ip),
      "echo MUSH-ACC-FALLBACK",
    )
    .await?;
  ensure!(
    out.success && out.stdout.contains("MUSH-ACC-FALLBACK"),
    "session must still work over the TCP fallback; stdout={} stderr={}",
    out.stdout,
    out.stderr
  );
  ensure!(
    out.stderr.contains("WARNING") && out.stderr.contains("falling back"),
    "the fallback must warn loudly on stderr:\n{}",
    out.stderr
  );
  ensure!(
    out.stderr.contains("QUIC unreachable"),
    "the warning should name the trigger:\n{}",
    out.stderr
  );
  // Unreachability and pin rejection are distinct paths; a fallback
  // must never look like (or mask) a refused handshake.
  ensure!(
    !out.stderr.contains("refusing to fall back"),
    "pin rejection must not be involved in the fallback path:\n{}",
    out.stderr
  );
  lab.teardown_swept().await
}

#[tokio::test(flavor = "current_thread")]
async fn udp_blocked_no_fallback_fails_hard() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  block_inbound_udp(&lab.topo.dest)?;

  let out = lab
    .fix
    .ssh_exec(
      &lab.topo.client,
      &lab.mush.ssh_args_with(lab.dest_ip, &["--no-fallback"]),
      "echo MUSH-ACC-NOFALLBACK",
    )
    .await?;
  ensure!(
    !out.success && !out.stdout.contains("MUSH-ACC-NOFALLBACK"),
    "--no-fallback must fail the session; stdout={} stderr={}",
    out.stdout,
    out.stderr
  );
  ensure!(
    out.stderr.contains("--no-fallback")
      && out.stderr.contains("QUIC unreachable"),
    "the failure should cite --no-fallback and the trigger:\n{}",
    out.stderr
  );
  ensure!(
    !out.stderr.contains("refusing to fall back"),
    "pin rejection must not be involved in the unreachable path:\n{}",
    out.stderr
  );
  lab.teardown_swept().await
}

/// A wrapper `-J` through a real jump chain: the wrapper strips `-J`
/// from the outer argv and forwards it to the bootstrap ssh through the
/// environment, and both halves must respect it. With UDP blocked the
/// fallback path must traverse the jump too -- an `ssh -W` bridge from
/// the bastion, never a direct dial of the destination's TCP port,
/// which would silently bypass the policy the jump enforces. The
/// destination is unreachable from the client, so a session that works
/// at all came over the bridge.
#[tokio::test(flavor = "current_thread")]
async fn wrapper_jump_udp_blocked_falls_back_through_the_jump() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = JumpLab::new(jump_chain(NatMode::FirewallOnly).await?).await?;
  let (topo, fix, mush) = (&lab.topo, &lab.fix, &lab.mush);
  let (jump_ip, dest_ip) = (lab.jump_ip, lab.dest_ip);
  // The DMZ firewall already drops unsolicited inbound; blocking UDP on
  // the dest as well keeps this test valid if the firewall's rules change.
  block_inbound_udp(&topo.dest)?;

  // Control: the jump chain itself works over plain ssh, so the Mush
  // failure below can only be the fallback decision.
  let control = fix
    .ssh_exec(
      &topo.client,
      &fix.client_ssh_args_via_jump(dest_ip, jump_ip),
      "echo MUSH-ACC-JUMP-CONTROL",
    )
    .await?;
  ensure!(
    control.success && control.stdout.contains("MUSH-ACC-JUMP-CONTROL"),
    "control ssh -J run broke; stdout={} stderr={}",
    control.stdout,
    control.stderr
  );

  let mut cmd = Command::new(mush.mush_bin());
  cmd
    .args(["-J", &lab.jump_spec])
    .args(mush.wrapper_args(dest_ip, "echo MUSH-ACC-JUMP-BRIDGE"))
    .env("PATH", mush.wrapper_path_env())
    .env("HOME", fix.dir())
    .env_remove("MUSH_BOOTSTRAP_SSH_ARGS")
    .env_remove("MUSH_CONNECT_SSH")
    .env_remove("MUSH_CONNECT_SERVER")
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
  mush_testenv::harden_command(&mut cmd);
  let child = topo.client.spawn_command(cmd)?;
  let out = t(STEP, child.wait_with_output()).await?;
  let stdout = String::from_utf8_lossy(&out.stdout);
  let stderr = String::from_utf8_lossy(&out.stderr);
  ensure!(
    out.status.success() && stdout.contains("MUSH-ACC-JUMP-BRIDGE"),
    "the fallback bridge must carry the session; stdout={stdout} \
     stderr={stderr}"
  );
  ensure!(
    stderr.contains("falling back to plain TCP"),
    "the fallback must be loud:\n{stderr}"
  );
  // The destination's ssh port does not answer the client at all, so
  // nothing here could have been a direct dial.
  ensure!(
    mush_testenv::wait_tcp_ready(
      &topo.client,
      SocketAddr::new(dest_ip.into(), fix.port),
      Duration::from_secs(2),
    )
    .await
    .is_err(),
    "the dest's ssh port must be unreachable from the client"
  );

  // The bootstrap started a dest server that the fallback then
  // orphaned; the namespace sweep reaps it (the fallback tests' shape).
  let JumpLab { topo, mush, .. } = lab;
  drop(topo);
  mush.wait_no_marked_processes().await
}

/// A wrapper-mode invocation (`mush [extra args] [fixture ssh args]
/// dest command`) by absolute argv0, ready to spawn in the client
/// namespace: the ssh the wrapper execs (and the bare ssh `mush
/// connect` runs) resolve to the fixture-config shim first on PATH,
/// HOME points at the fixture dir so no user ssh config is found, and
/// the wrapper environment variables are cleared so only argv drives it.
fn wrapper_cmd(
  lab: &Lab<Topology>,
  extra: &[String],
  command: &str,
) -> Command {
  let mut cmd = Command::new(lab.mush.mush_bin());
  cmd
    .args(extra)
    .args(lab.mush.wrapper_args(lab.dest_ip, command))
    .env("PATH", lab.mush.wrapper_path_env())
    .env("HOME", lab.fix.dir())
    .env_remove("MUSH_BOOTSTRAP_SSH_ARGS")
    .env_remove("MUSH_CONNECT_SSH")
    .env_remove("MUSH_CONNECT_SERVER")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
  mush_testenv::harden_command(&mut cmd);
  cmd
}

/// Runs one wrapper-mode `cat` session: echo a tag through it, confirm
/// a marked Mush server is serving it, then close and return the
/// wrapper's stderr for the caller's own claim. The marker check is the
/// positive proof the session went through Mush rather than plain ssh,
/// which would also succeed on these topologies.
async fn wrapper_echo(
  lab: &Lab<Topology>,
  extra: &[String],
  tag: &str,
) -> Result<String> {
  let mut session = Session::attach(
    lab
      .topo
      .client
      .spawn_command(wrapper_cmd(lab, extra, "cat"))?,
    STEP,
  )?;
  session.write_line(tag).await?;
  let echo =
    match next_line(&mut session.lines, STEP, "wrapper session echo").await {
      Ok(line) => line,
      Err(error) => {
        let stderr = session.stderr_now().await?;
        bail!("{error}; wrapper stderr:\n{stderr}");
      }
    };
  ensure!(echo == tag, "unexpected echo {echo:?}");
  ensure!(
    lab.mush.marked_process_exists(),
    "no marked mush server found during the wrapper session"
  );
  session.close().await
}

#[tokio::test(flavor = "current_thread")]
async fn wrapper_mode_end_to_end() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;

  // The wrapper execs ssh with the injected ProxyCommand and forwards
  // the fixed -i/-J/-o set to the bootstrap ssh through the environment;
  // the remote `mush` resolves through the shim directory MushFixture
  // wired onto the sshd session PATH (no --server here).
  wrapper_echo(&lab, &[], "wrapper-ping").await?;
  lab.mush.wait_no_marked_processes().await
}

/// The wrapper's `--server=` override on a host where `mush` is not on
/// the remote non-interactive PATH: the default remote command cannot
/// resolve there (the first part proves the simulation is real),
/// and `--server=` naming the binary by absolute path fixes it.
#[tokio::test(flavor = "current_thread")]
async fn wrapper_server_flag_reaches_host_without_remote_mush() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab =
    Lab::with_mush(direct().await?, MushFixture::new_without_remote_mush)
      .await?;

  // Without --server=: the bare `mush server bootstrap` does not resolve
  // remotely, so the bootstrap never speaks Mush and the session fails.
  let mut child =
    lab
      .topo
      .client
      .spawn_command(wrapper_cmd(&lab, &[], "true"))?;
  drop(child.stdin.take());
  let out = t(STEP, child.wait_with_output()).await?;
  let stderr = String::from_utf8_lossy(&out.stderr);
  ensure!(
    !out.status.success(),
    "the default wrapper invocation cannot work without remote mush"
  );
  ensure!(
    stderr.contains("no MUSH CONNECT"),
    "the failure should be the missing remote mush:\n{stderr}"
  );

  // With --server= naming the binary by absolute path, the same session
  // works end to end. The marker `wrapper_echo` checks proves the
  // --server command is what ran: only it carries one, with no remote
  // shim to add one here.
  let extra = vec![format!("--server={}", lab.mush.server_command())];
  let stderr = wrapper_echo(&lab, &extra, "server-flag-ping").await?;
  ensure!(
    !stderr.contains("falling back"),
    "the session must not have used the TCP fallback:\n{stderr}"
  );
  lab.mush.wait_no_marked_processes().await
}

/// A multi-word `--ssh=` value: the whole value travels through the
/// environment as one string and `mush connect` splits it on whitespace,
/// so every word after the program must end up in the bootstrap ssh's
/// argv. Proven by asking for verbosity there and nowhere else: the
/// debug output can only come from the bootstrap ssh (whose stderr is
/// inherited through the ProxyCommand).
#[tokio::test(flavor = "current_thread")]
async fn wrapper_multiword_ssh_value_reaches_the_bootstrap_ssh() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;

  let extra = vec!["--ssh=ssh -v".to_string()];
  let stderr = wrapper_echo(&lab, &extra, "ssh-value-ping").await?;
  ensure!(
    stderr.contains("debug1:"),
    "the --ssh value's -v never reached the bootstrap ssh; stderr:\n{stderr}"
  );
  lab.mush.wait_no_marked_processes().await
}

/// A `--server=` value with embedded spaces and shell quotes: the value
/// travels whole through the environment (no re-quoting anywhere) and
/// the remote shell interprets the quoting exactly once. The fixture has
/// no remote `mush` on PATH and the quoted word is glued to the marker,
/// so a session that succeeds with a marked server proves the value
/// arrived byte-for-byte and unquoted correctly -- any added or lost
/// quoting layer breaks the remote command and fails the session.
#[tokio::test(flavor = "current_thread")]
async fn wrapper_server_value_quoting_survives_to_the_remote_shell()
-> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab =
    Lab::with_mush(direct().await?, MushFixture::new_without_remote_mush)
      .await?;

  let extra = vec![format!(
    "--server={} server bootstrap --marker '{} quoted'",
    lab.mush.mush_bin().display(),
    lab.mush.marker()
  )];
  let stderr = wrapper_echo(&lab, &extra, "quoted-ping").await?;
  ensure!(
    !stderr.contains("falling back"),
    "the session must not have used the TCP fallback:\n{stderr}"
  );
  lab.mush.wait_no_marked_processes().await
}

/// Hostile `--server=` shapes fail loudly. A lone destination-looking
/// `--server=evil` is taken as the wrapper's own option and refused for
/// having no destination, before any ssh runs; with a real destination
/// alongside, the override is honored over a remote default that would
/// have worked, and the poisoned command fails the session with the
/// bootstrap's error rather than silently succeeding some other way.
#[tokio::test(flavor = "current_thread")]
async fn wrapper_server_override_failures_are_loud() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;

  let mut cmd = Command::new(lab.mush.mush_bin());
  cmd
    .arg("--server=evil")
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
  mush_testenv::harden_command(&mut cmd);
  let child = lab.topo.client.spawn_command(cmd)?;
  let out = t(STEP, child.wait_with_output()).await?;
  let stderr = String::from_utf8_lossy(&out.stderr);
  ensure!(
    !out.status.success(),
    "a lone --server=evil must not launch anything"
  );
  ensure!(
    stderr.contains("no destination"),
    "the refusal should name the missing destination:\n{stderr}"
  );

  // This fixture has remote `mush` on PATH, so the default server command
  // would succeed: only an honored override can make this fail.
  let mut child = lab.topo.client.spawn_command(wrapper_cmd(
    &lab,
    &["--server=evil".to_string()],
    "true",
  ))?;
  drop(child.stdin.take());
  let out = t(STEP, child.wait_with_output()).await?;
  let stderr = String::from_utf8_lossy(&out.stderr);
  ensure!(
    !out.status.success(),
    "a poisoned --server= must fail the session; stderr:\n{stderr}"
  );
  ensure!(
    stderr.contains("no MUSH CONNECT"),
    "the failure should be the poisoned server command:\n{stderr}"
  );
  ensure!(
    !lab.mush.marked_process_exists(),
    "no marked mush process can exist when the server command never ran"
  );
  Ok(())
}
