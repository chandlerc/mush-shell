// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Resilience acceptance tests: the hostile end of the matrix the
//! design must survive -- roam torture, the outage matrix past quinn's
//! default idle timeout, and process-kill behavior for each of the
//! session's processes (`mush connect`, the detached server) with and
//! without the opt-in limits.
//!
//! Same rules as `acceptance.rs`: the full production setup with no
//! fakes, and `--no-fallback` on every session so a QUIC regression
//! fails loudly instead of hiding behind the TCP fallback. Runs under
//! the nextest `lab` profile; the long-window tests carry their own
//! slow-timeout override in `.config/nextest.toml`.

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use mush_testenv::patchbay::{Device, LinkCondition, LinkDirection};
use mush_testenv::{Topology, Uplink, direct, query_reflector, roaming};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout};

mod common;

use common::{
  Lab, Outage, drain, fd_count, find_marked, marked_roles, next_line,
  outage_session, spawn_session, t,
};

mush_testenv::userns_bootstrap!();

/// Generous timeout for any single await that should be quick.
const STEP: Duration = Duration::from_secs(60);

/// [`outage_session`] against an assembled lab.
async fn outage(lab: &Lab<Topology>, outage: Outage) -> Result<()> {
  outage_session(&lab.topo.client, &lab.mush, lab.dest_ip, outage, STEP).await
}

fn kill9(pid: u32) {
  unsafe {
    libc::kill(pid as i32, libc::SIGKILL);
  }
}

/// Waits for the marked `mush` process of the given kind to exit.
async fn poll_marker_gone(
  marker: &str,
  kind: &str,
  timeout: Duration,
) -> Result<()> {
  let deadline = tokio::time::Instant::now() + timeout;
  loop {
    if find_marked(marker, kind).is_none() {
      return Ok(());
    }
    if tokio::time::Instant::now() > deadline {
      bail!("marked {kind} still alive after {timeout:?}");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
  }
}

/// Waits for the client-side processes (`mush connect` and its bootstrap
/// ssh) to be gone from the process table: with the outer ssh dead,
/// both must follow on their own (PDEATHSIG and the bounded drain), not
/// wait for the namespace sweep.
async fn poll_no_client_processes(
  marker: &str,
  timeout: Duration,
) -> Result<()> {
  let deadline = tokio::time::Instant::now() + timeout;
  loop {
    let roles = marked_roles(marker);
    if !roles
      .iter()
      .any(|(_, r)| *r == "mush-connect" || *r == "bootstrap-ssh")
    {
      return Ok(());
    }
    if tokio::time::Instant::now() > deadline {
      bail!("client-side processes still alive after {timeout:?}: {roles:?}");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
  }
}

fn expect_tick(line: &str, expected: u64) -> Result<()> {
  let n: u64 = line
    .strip_prefix("TICK-")
    .with_context(|| format!("unexpected line {line:?}"))?
    .parse()
    .with_context(|| format!("bad tick {line:?}"))?;
  ensure!(
    n == expected,
    "tick gap: expected TICK-{expected}, got {line:?}"
  );
  Ok(())
}

/// A remote command streaming `count` consecutive ticks at 10Hz, then
/// `done`.
fn tick_remote(count: u32, done: &str) -> String {
  format!(
    "sh -c 'i=0; while [ $i -lt {count} ]; do echo TICK-$i; i=$((i+1)); \
     sleep 0.1; done; echo {done}'"
  )
}

/// Establishes a held `cat` session and proves it live; returns the
/// child with its stdin and line reader (stderr left in the child).
async fn held_session(
  dev: &Device,
  args: &[String],
) -> Result<(Child, ChildStdin, Lines<BufReader<ChildStdout>>)> {
  let mut child = spawn_session(dev, args, "cat", None)?;
  let mut stdin = child.stdin.take().context("stdin piped")?;
  let mut lines =
    BufReader::new(child.stdout.take().context("stdout piped")?).lines();
  t(STEP, stdin.write_all(b"held-open\n")).await?;
  let echo = next_line(&mut lines, STEP, "session echo").await?;
  ensure!(echo == "held-open", "unexpected echo {echo:?}");
  Ok((child, stdin, lines))
}

/// Roam torture: flip the default route between the two uplinks every
/// 2s, nine times, under a continuously streaming session. The byte
/// stream must stay gap-free and in order, the same detached server
/// must serve throughout (a restarted server would be a new session),
/// fd counts must stay flat across the migrations, and the client's
/// visible address must really end up on the other uplink.
#[tokio::test(flavor = "current_thread")]
async fn roam_rapid_flapping_keeps_stream_intact() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(roaming().await?).await?;
  let topo = &lab.topo;

  let _reflector = topo.dest.spawn_reflector("0.0.0.0:3479".parse()?).await?;
  let reflect = SocketAddr::new(lab.dest_ip.into(), 3479);
  let before =
    query_reflector(&topo.client, reflect, 5, Duration::from_millis(500))
      .await?;
  ensure!(
    before.ip() == std::net::IpAddr::V4(topo.wan_ip(Uplink::A)?),
    "expected uplink A before the torture, got {before}"
  );

  let remote = tick_remote(260, "FLAP-DONE");
  let args = lab.mush.ssh_args_with(lab.dest_ip, &["--no-fallback"]);
  let mut child = spawn_session(&topo.client, &args, &remote, None)?;
  drop(child.stdin.take());
  let mut lines =
    BufReader::new(child.stdout.take().context("stdout piped")?).lines();
  let stderr = drain(child.stderr.take().context("stderr piped")?);

  // Establishment: first tick seen, session fully up.
  let first = next_line(&mut lines, STEP, "first tick").await?;
  expect_tick(&first, 0)?;

  let marker = lab.mush.marker().to_string();
  let connect_pid =
    find_marked(&marker, "connect").context("mush connect not found")?;
  let server_pid =
    find_marked(&marker, "server").context("mush server not found")?;
  let connect_fds_start = fd_count(connect_pid);
  let server_fds_start = fd_count(server_pid);

  let mut expected = 1u64;
  let mut flips_done = 0u32;
  let mut next_flip = tokio::time::Instant::now() + Duration::from_secs(2);
  loop {
    tokio::select! {
      line = next_line(&mut lines, STEP, "tick stream") => {
        let line = line?;
        if line == "FLAP-DONE" {
          break;
        }
        expect_tick(&line, expected)?;
        expected += 1;
      }
      _ = tokio::time::sleep_until(next_flip), if flips_done < 9 => {
        flips_done += 1;
        let target = if flips_done % 2 == 1 { Uplink::B } else { Uplink::A };
        topo.use_uplink(target).await?;
        next_flip += Duration::from_secs(2);
        if flips_done == 9 {
          // Mid-session, post-torture sampling while ticks still flow.
          let server_now = find_marked(&marker, "server");
          ensure!(
            server_now == Some(server_pid),
            "server changed across the flapping: {server_pid} -> \
             {server_now:?}"
          );
          let servers = marked_roles(&marker)
            .iter()
            .filter(|(_, role)| *role == "mush-server")
            .count();
          ensure!(servers == 1, "expected exactly one server, found {servers}");
          if let (Some(a), Some(b)) = (connect_fds_start, fd_count(connect_pid))
          {
            ensure!(b <= a + 8, "mush connect fd growth {a} -> {b}");
          }
          if let (Some(a), Some(b)) = (server_fds_start, fd_count(server_pid)) {
            ensure!(b <= a + 8, "mush server fd growth {a} -> {b}");
          }
        }
      }
    }
  }
  ensure!(expected == 260, "tick stream truncated at {expected}");
  ensure!(
    flips_done == 9,
    "only {flips_done} flips before session end"
  );

  let status = t(STEP, child.wait()).await?;
  ensure!(
    status.success(),
    "flapped session failed ({status}); stderr:\n{}",
    String::from_utf8_lossy(&t(STEP, stderr).await?)
  );

  // Nine flips from A ends on B; the address must really have changed.
  let after =
    query_reflector(&topo.client, reflect, 5, Duration::from_millis(500))
      .await?;
  ensure!(
    after.ip() == std::net::IpAddr::V4(topo.wan_ip(Uplink::B)?),
    "expected uplink B after the torture, got {after}"
  );
  lab.mush.wait_no_marked_processes().await
}

/// Roam torture: the active uplink dies outright (link down, routes
/// gone) mid-stream; 6 seconds into the outage the client roams to the other
/// uplink, and once the stream is flowing again the dead uplink is
/// restored and the session roams back onto it. The stream must resume
/// with no gaps across both moves and finish cleanly.
#[tokio::test(flavor = "current_thread")]
async fn roam_during_outage_after_uplink_death() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(roaming().await?).await?;
  let topo = &lab.topo;

  let _reflector = topo.dest.spawn_reflector("0.0.0.0:3479".parse()?).await?;
  let reflect = SocketAddr::new(lab.dest_ip.into(), 3479);

  let remote = tick_remote(400, "OUTAGE-DONE");
  let args = lab.mush.ssh_args_with(lab.dest_ip, &["--no-fallback"]);
  let mut child = spawn_session(&topo.client, &args, &remote, None)?;
  drop(child.stdin.take());
  let mut lines =
    BufReader::new(child.stdout.take().context("stdout piped")?).lines();
  let stderr = drain(child.stderr.take().context("stderr piped")?);

  let mut expected = 0u64;
  while expected < 10 {
    let line = next_line(&mut lines, STEP, "pre-outage ticks").await?;
    expect_tick(&line, expected)?;
    expected += 1;
  }

  // The uplink dies while it is the active path.
  topo.fail_uplink(Uplink::A).await?;
  let reply =
    query_reflector(&topo.client, reflect, 2, Duration::from_millis(400)).await;
  ensure!(
    reply.is_err(),
    "uplink A down must not answer, got {reply:?}"
  );
  tokio::time::sleep(Duration::from_secs(6)).await;

  // Roam to uplink B during the outage.
  topo.use_uplink(Uplink::B).await?;
  let resumed = next_line(
    &mut lines,
    Duration::from_secs(20),
    "first tick after the mid-outage roam",
  )
  .await?;
  expect_tick(&resumed, expected)?;
  expected += 1;

  // The dead uplink comes back and the session roams onto it: the rest
  // of the stream arriving gap-free is what says a restored uplink
  // carries traffic again, and the reflector below says it was A.
  topo.restore_uplink(Uplink::A).await?;
  topo.use_uplink(Uplink::A).await?;

  loop {
    let line =
      next_line(&mut lines, Duration::from_secs(20), "OUTAGE-DONE").await?;
    if line == "OUTAGE-DONE" {
      break;
    }
    expect_tick(&line, expected)?;
    expected += 1;
  }
  ensure!(expected == 400, "tick stream truncated at {expected}");
  let back =
    query_reflector(&topo.client, reflect, 5, Duration::from_millis(500))
      .await?;
  ensure!(
    back.ip() == std::net::IpAddr::V4(topo.wan_ip(Uplink::A)?),
    "expected the restored uplink A to be carrying traffic, got {back}"
  );
  let status = t(STEP, child.wait()).await?;
  ensure!(
    status.success(),
    "session roamed during the outage failed ({status}); stderr:\n{}",
    String::from_utf8_lossy(&t(STEP, stderr).await?)
  );
  lab.mush.wait_no_marked_processes().await
}

/// Roam torture: flip the uplink while the session is still being
/// established (bootstrap ssh up, QUIC dial in flight). Every attempt
/// must resolve -- clean success or clean failure -- within the
/// documented limits (the 120s client bootstrap budget is the
/// largest), honor `--no-fallback`, and leave no client-side process
/// behind once the outer ssh is gone.
#[tokio::test(flavor = "current_thread")]
async fn roam_during_establishment_resolves_and_leaks_nothing() -> Result<()> {
  mush_testenv::skip_unless_available!();
  for (delay_ms, extra_args) in [
    (0u64, &[][..]),
    (150, &[]),
    (400, &[]),
    (900, &[]),
    (0, &["--no-fallback"][..]),
    (400, &["--no-fallback"]),
  ] {
    let lab = Lab::new(roaming().await?).await?;
    let topo = &lab.topo;
    let marker = lab.mush.marker().to_string();
    let args = lab.mush.ssh_args_with(lab.dest_ip, extra_args);
    let mut child =
      spawn_session(&topo.client, &args, "echo ESTABLISH-OK", None)?;
    let stdout = drain(child.stdout.take().context("stdout piped")?);
    let stderr = drain(child.stderr.take().context("stderr piped")?);
    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    topo.use_uplink(Uplink::B).await?;

    let status = tokio::time::timeout(Duration::from_secs(150), child.wait())
      .await
      .map_err(|_| {
        anyhow::anyhow!(
          "establishment roam at {delay_ms}ms {extra_args:?} hung past \
           150s (outlives every documented limit)"
        )
      })??;
    let stdout = String::from_utf8_lossy(&t(STEP, stdout).await?).into_owned();
    let stderr = String::from_utf8_lossy(&t(STEP, stderr).await?).into_owned();
    if status.success() {
      ensure!(
        stdout.contains("ESTABLISH-OK"),
        "exit 0 without the remote output; stderr:\n{stderr}"
      );
    }
    ensure!(
      !(extra_args.contains(&"--no-fallback")
        && stderr.contains("falling back")),
      "--no-fallback must not fall back:\n{stderr}"
    );

    // The client-side processes follow on their own, however it resolved.
    poll_no_client_processes(&marker, Duration::from_secs(15)).await?;

    // An establishment torn down mid-way may orphan the server until
    // its own accept timeout; the namespace sweep reaps it.
    let Lab { topo, mush, .. } = lab;
    drop(topo);
    mush.wait_no_marked_processes().await?;
  }
  Ok(())
}

/// Outage matrix: a 70s blackhole (3.5 keep-alive intervals, 2.3x
/// quinn's default idle timeout) with no `--idle-timeout` must freeze
/// and resume, and the session must still be alive mid-outage.
#[tokio::test(flavor = "current_thread")]
async fn outage_70s_survives_without_idle_timeout() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  outage(
    &lab,
    // The liveness check comes after quinn's default 30s idle timeout:
    // the session must still be up there, frozen rather than dead.
    Outage {
      alive_at: Some(Duration::from_secs(35)),
      ..Outage::new(Duration::from_secs(70), 80)
    },
  )
  .await
}

/// Outage matrix: with `--idle-timeout 30s`, a longer blackhole must
/// kill the session inside the documented window -- never before the
/// timeout could have elapsed -- with the diagnosis on stderr.
#[tokio::test(flavor = "current_thread")]
async fn outage_with_idle_timeout_dies_at_the_limit() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let args = lab
    .mush
    .ssh_args_with(lab.dest_ip, &["--no-fallback", "--idle-timeout", "30s"]);
  let remote = "sh -c 'echo OUTAGE-START; sleep 600; echo OUTAGE-END'";
  let mut child = spawn_session(&lab.topo.client, &args, remote, None)?;
  drop(child.stdin.take());
  let mut lines =
    BufReader::new(child.stdout.take().context("stdout piped")?).lines();
  let stderr = drain(child.stderr.take().context("stderr piped")?);

  let start = next_line(&mut lines, STEP, "OUTAGE-START").await?;
  ensure!(start == "OUTAGE-START", "unexpected line {start:?}");

  let iface = lab.topo.client.iface("eth0").context("client eth0")?;
  iface
    .set_condition(LinkCondition::new().loss_pct(100.0), LinkDirection::Both)
    .await?;
  let t0 = tokio::time::Instant::now();
  let status = tokio::time::timeout(Duration::from_secs(75), child.wait())
    .await
    .map_err(|_| {
      anyhow::anyhow!(
        "session survived 75s of outage despite --idle-timeout 30s"
      )
    })??;
  let elapsed = t0.elapsed();
  let stderr = String::from_utf8_lossy(&t(STEP, stderr).await?).into_owned();
  ensure!(!status.success(), "session must fail, got {status}");
  ensure!(
    elapsed >= Duration::from_secs(25),
    "died at {elapsed:?}, before the 30s timeout could have elapsed"
  );
  ensure!(
    elapsed <= Duration::from_secs(60),
    "death took {elapsed:?}, far past the 30s timeout"
  );
  ensure!(
    stderr.contains("session ended uncleanly"),
    "missing the unclean-session line:\n{stderr}"
  );
  ensure!(
    stderr.contains("idle timeout elapsed")
      && stderr.contains("--idle-timeout"),
    "missing the documented idle-timeout diagnosis:\n{stderr}"
  );

  // The server has no --retain and holds the session; only the
  // namespace sweep reaps it.
  lab.teardown_swept().await
}

/// One-way blackhole in the given direction for 30s (past the keep-alive
/// interval and quinn's default idle timeout); the session must survive
/// and finish cleanly.
async fn asymmetric_outage(direction: LinkDirection) -> Result<()> {
  let lab = Lab::new(direct().await?).await?;
  outage(
    &lab,
    // The liveness check sits at the end of the window: a session that
    // lost only one direction would already have died there.
    Outage {
      direction,
      alive_at: Some(Duration::from_secs(30)),
      ..Outage::new(Duration::from_secs(30), 45)
    },
  )
  .await
}

/// Outage matrix: client-egress-only blackhole (keep-alives die,
/// server-to-client stays open).
#[tokio::test(flavor = "current_thread")]
async fn outage_asymmetric_egress_only() -> Result<()> {
  mush_testenv::skip_unless_available!();
  asymmetric_outage(LinkDirection::Egress).await
}

/// Outage matrix: client-ingress-only blackhole (acks and server data
/// die, client keep-alives still arrive).
#[tokio::test(flavor = "current_thread")]
async fn outage_asymmetric_ingress_only() -> Result<()> {
  mush_testenv::skip_unless_available!();
  asymmetric_outage(LinkDirection::Ingress).await
}

/// SIGKILL `mush connect` mid-session: the outer ssh must die promptly
/// (its transport pipes EOF), while the detached server lingers by
/// design -- retention is indefinite without `--retain` -- and the
/// documented recourse is a sweep by marker.
#[tokio::test(flavor = "current_thread")]
async fn sigkill_connect_leaves_the_server_by_default() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let args = lab.mush.ssh_args_with(lab.dest_ip, &["--no-fallback"]);
  let (mut child, _stdin, _lines) =
    held_session(&lab.topo.client, &args).await?;
  let marker = lab.mush.marker().to_string();

  let connect_pid =
    find_marked(&marker, "connect").context("mush connect not found")?;
  let server_pid =
    find_marked(&marker, "server").context("mush server not found")?;
  kill9(connect_pid);

  let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
    .await
    .map_err(|_| {
      anyhow::anyhow!("outer ssh still alive 10s after mush connect SIGKILL")
    })??;
  ensure!(!status.success(), "outer ssh must fail, got {status}");

  // The server must still be there well after the client vanished.
  tokio::time::sleep(Duration::from_secs(8)).await;
  ensure!(
    find_marked(&marker, "server") == Some(server_pid),
    "server disappeared without --retain; it must linger by design"
  );

  // The documented recourse: sweep by marker.
  let _ = std::process::Command::new("pkill")
    .args(["-KILL", "-f", &marker])
    .status();
  poll_marker_gone(&marker, "server", Duration::from_secs(10)).await
}

/// SIGKILL `mush connect` when the server was started with
/// `--retain 30s`: the server must self-reap on its own, neither before
/// the retention window nor unboundedly after it.
#[tokio::test(flavor = "current_thread")]
async fn sigkill_connect_with_retain_self_reaps_the_server() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let args = lab.mush.ssh_args_with_args(
    lab.dest_ip,
    &["--no-fallback"],
    &["--retain", "30s"],
  );
  let (mut child, _stdin, _lines) =
    held_session(&lab.topo.client, &args).await?;
  let marker = lab.mush.marker().to_string();

  let connect_pid =
    find_marked(&marker, "connect").context("mush connect not found")?;
  ensure!(
    find_marked(&marker, "server").is_some(),
    "mush server not found"
  );
  kill9(connect_pid);

  let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
    .await
    .map_err(|_| {
      anyhow::anyhow!("outer ssh still alive 10s after mush connect SIGKILL")
    })??;
  ensure!(!status.success(), "outer ssh must fail, got {status}");

  // Not early: at 15s the 30s retention window is only half spent.
  tokio::time::sleep(Duration::from_secs(15)).await;
  ensure!(
    find_marked(&marker, "server").is_some(),
    "server self-reaped before the 30s retention window"
  );
  // Not late: gone within the limit plus detection slack.
  poll_marker_gone(&marker, "server", Duration::from_secs(60)).await?;
  lab.mush.wait_no_marked_processes().await
}

/// SIGKILL the detached server mid-session with default settings: the
/// design treats the dead peer as an outage (`max_idle_timeout: None`),
/// so the session must NOT die on its own -- it freezes past quinn's
/// default 30s idle timeout until a limit expires or the user gives up
/// (the next test pins the recourse). Once the outer ssh dies, here by
/// SIGKILL so no SIGHUP is sent, `mush connect` must still tear down
/// within its bounded drain rather than linger as a relay for nobody.
#[tokio::test(flavor = "current_thread")]
async fn sigkill_server_default_hang_outlasts_quinn_idle_timeout() -> Result<()>
{
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let args = lab.mush.ssh_args_with(lab.dest_ip, &["--no-fallback"]);
  let (mut child, stdin, _lines) =
    held_session(&lab.topo.client, &args).await?;
  let marker = lab.mush.marker().to_string();

  let server_pid =
    find_marked(&marker, "server").context("mush server not found")?;
  kill9(server_pid);

  // Keep client->server traffic flowing so even active writes (and the
  // ICMP unreachables the dead port answers them with) surface nothing.
  let mut stdin = stdin;
  let writer = tokio::spawn(async move {
    loop {
      if stdin.write_all(b"poke\n").await.is_err() {
        break;
      }
      tokio::time::sleep(Duration::from_secs(1)).await;
    }
  });

  // Well past quinn's default 30s idle timeout: still frozen, not dead.
  tokio::time::sleep(Duration::from_secs(45)).await;
  ensure!(
    child.try_wait()?.is_none(),
    "outer ssh died on its own; a dead server must look like an outage"
  );
  writer.abort();

  // The user gives up: SIGKILL the outer ssh, which delivers no SIGHUP.
  // The relay must still end within its bounded drain (PDEATHSIG).
  child.start_kill()?;
  let _ = child.wait().await;
  poll_marker_gone(&marker, "connect", Duration::from_secs(20)).await?;
  lab.mush.wait_no_marked_processes().await
}

/// The documented recourse for a dead server: `--idle-timeout` bounds
/// the hang, with its diagnosis on stderr, and the ssh-exit SIGHUP then
/// ends `mush connect` promptly even though the peer is dead.
#[tokio::test(flavor = "current_thread")]
async fn sigkill_server_idle_timeout_bounds_the_hang() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let args = lab
    .mush
    .ssh_args_with(lab.dest_ip, &["--no-fallback", "--idle-timeout", "30s"]);
  let (mut child, _stdin, _lines) =
    held_session(&lab.topo.client, &args).await?;
  let stderr = drain(child.stderr.take().context("stderr piped")?);
  let marker = lab.mush.marker().to_string();

  let server_pid =
    find_marked(&marker, "server").context("mush server not found")?;
  kill9(server_pid);
  let t0 = tokio::time::Instant::now();

  let status = tokio::time::timeout(Duration::from_secs(75), child.wait())
    .await
    .map_err(|_| {
      anyhow::anyhow!(
        "outer ssh survived 75s past the server kill despite \
         --idle-timeout 30s"
      )
    })??;
  let elapsed = t0.elapsed();
  ensure!(!status.success(), "ssh must not exit 0, got {status}");
  // Not early (the timeout is 30s), not unboundedly late (the timeout
  // plus PTO detection slack).
  ensure!(
    elapsed >= Duration::from_secs(25) && elapsed <= Duration::from_secs(60),
    "death at {elapsed:?} is outside the 30s timeout's window"
  );
  let stderr = String::from_utf8_lossy(&t(STEP, stderr).await?).into_owned();
  ensure!(
    stderr.contains("idle timeout elapsed"),
    "missing the documented idle-timeout diagnosis:\n{stderr}"
  );

  // ssh's exit SIGHUPs `mush connect`; the bounded drain ends it promptly
  // despite the dead peer.
  poll_marker_gone(&marker, "connect", Duration::from_secs(15)).await?;
  lab.mush.wait_no_marked_processes().await
}

/// `mush connect` dying by signal mid-bootstrap must take the bootstrap
/// ssh with it: kill_on_drop never runs on a signal death (the outer
/// ssh's SIGHUP at ConnectTimeout, a crash, SIGKILL), so PDEATHSIG on
/// the bootstrap child is what prevents an orphaned ssh holding the
/// inherited stderr and its remote command alive with no owner.
#[tokio::test(flavor = "current_thread")]
async fn sigkill_connect_mid_bootstrap_reaps_the_bootstrap_ssh() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let marker = lab.mush.marker().to_string();
  // The remote command never prints MUSH CONNECT, so `mush connect`
  // sits in its bootstrap scan (120s budget) with the bootstrap ssh
  // live; the trailing comment puts the marker in both processes' argv.
  let proxy = lab
    .mush
    .proxy_command_with_server(&[], &format!("sleep 300 # {marker}"));
  let mut args = lab.mush.ssh_opts_for(&proxy);
  args.push(lab.dest_ip.to_string());
  let mut child = spawn_session(&lab.topo.client, &args, "true", None)?;

  // Wait for the processes: connect spawned, bootstrap ssh running.
  let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
  let connect_pid = loop {
    let roles = marked_roles(&marker);
    let connect = roles.iter().find(|(_, r)| *r == "mush-connect");
    let bootstrap = roles.iter().find(|(_, r)| *r == "bootstrap-ssh");
    if let (Some(&(pid, _)), Some(_)) = (connect, bootstrap) {
      break pid;
    }
    ensure!(
      tokio::time::Instant::now() < deadline,
      "bootstrap processes never appeared: {roles:?}"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  };

  kill9(connect_pid);
  let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
    .await
    .map_err(|_| anyhow::anyhow!("outer ssh survived the connect kill"))??;
  ensure!(!status.success(), "outer ssh must fail, got {status}");

  // The bootstrap ssh dies with its parent, not the namespace sweep.
  poll_no_client_processes(&marker, Duration::from_secs(5)).await?;

  // The sshd session running the hung remote command outlives the
  // client's processes; the namespace sweep reaps it.
  lab.teardown_swept().await
}
