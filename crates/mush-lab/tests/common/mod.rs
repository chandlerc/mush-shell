// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Scenario helpers the lab suites share: how a lab is assembled
//! ([`Lab`], [`JumpLab`]), how a session's processes are spawned and its
//! streams read ([`Session`]), what the client says about the path it is
//! on ([`Report`]), and how the marked processes are identified.
//!
//! Several carry a safety property a call site cannot see: skipping
//! `harden_command` leaks a process tree, an undrained stream blocks the
//! child on a full pipe, `MushFixture::new` must run before `spawn_sshd`
//! because it wires the remote PATH, and the argv-classification rules
//! below are a fact about how `mush connect` invokes itself.

// Each test binary uses part of this module; the rest is unreachable
// from that binary, not dead.
#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use mush_core::path::PathKind;
use mush_testenv::patchbay::{Device, LinkCondition, LinkDirection};
use mush_testenv::{
  JumpTopo, MushFixture, RoamingTopo, SshFixture, SshServer, Topology,
  jump_policy, wait_tcp_ready,
};
use tokio::io::{
  AsyncBufRead, AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _,
  AsyncWriteExt as _, BufReader, Lines,
};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

/// Deadline for sshd readiness.
pub const READY: Duration = Duration::from_secs(10);

/// Awaits `future` under `limit`, panicking when the deadline passes.
/// Each suite passes its own `STEP`, a timeout orders of magnitude above
/// lab expectations: timing variation cannot flake a test, and a step
/// that is genuinely stuck fails where it happened rather than hanging
/// the run.
pub async fn t<F: Future>(limit: Duration, future: F) -> F::Output {
  tokio::time::timeout(limit, future)
    .await
    .expect("test step deadline hit")
}

/// Spawns a command inside `dev`'s namespace with piped stdio and the
/// harness's process hygiene (kill-on-drop plus `PR_SET_PDEATHSIG`; see
/// `docs/testing.md`). `rust_log` turns on the client-side lines a suite
/// reads back out of the session's stderr, undecorated so a failure
/// dumps something readable.
pub fn spawn_in(
  dev: &Device,
  mut cmd: Command,
  rust_log: Option<&str>,
) -> Result<Child> {
  if let Some(filter) = rust_log {
    cmd.env("RUST_LOG", filter).env("NO_COLOR", "1");
  }
  cmd
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
  mush_testenv::harden_command(&mut cmd);
  dev.spawn_command(cmd)
}

/// Spawns the outer ssh from inside `dev`'s namespace.
pub fn spawn_session(
  dev: &Device,
  args: &[String],
  remote: &str,
  rust_log: Option<&str>,
) -> Result<Child> {
  let mut cmd = Command::new("ssh");
  cmd.args(args).arg(remote);
  spawn_in(dev, cmd, rust_log)
}

/// [`spawn_session`] for an invocation whose destination is already the
/// last entry of `args`, with extra environment for the child.
pub fn spawn_ssh(
  dev: &Device,
  args: &[String],
  envs: &[(&str, String)],
) -> Result<Child> {
  let mut cmd = Command::new("ssh");
  cmd.args(args);
  for (key, value) in envs {
    cmd.env(key, value);
  }
  spawn_in(dev, cmd, None)
}

/// Drains a stream in the background (a full pipe must never block the
/// child).
pub fn drain<R: AsyncRead + Unpin + Send + 'static>(
  mut stream: R,
) -> tokio::task::JoinHandle<Vec<u8>> {
  tokio::spawn(async move {
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    buf
  })
}

/// Reads the next line within `within`, naming `what` on failure.
pub async fn next_line<R: AsyncBufRead + Unpin>(
  lines: &mut Lines<R>,
  within: Duration,
  what: &str,
) -> Result<String> {
  match tokio::time::timeout(within, lines.next_line()).await {
    Ok(Ok(Some(line))) => Ok(line),
    Ok(Ok(None)) => bail!("stream ended while waiting for {what}"),
    Ok(Err(error)) => Err(error).with_context(|| format!("reading {what}")),
    Err(_) => bail!("timed out after {within:?} waiting for {what}"),
  }
}

/// Deterministic pseudo-random bytes (xorshift64), so transfers are
/// incompressible and corruption cannot alias.
pub fn pseudo_bytes(len: usize, mut seed: u64) -> Vec<u8> {
  let mut bytes = Vec::with_capacity(len + 8);
  while bytes.len() < len {
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    bytes.extend_from_slice(&seed.to_le_bytes());
  }
  bytes.truncate(len);
  bytes
}

/// One TCP round trip against `addr` from inside `dev`'s namespace:
/// write everything, half-close, read everything back.
pub async fn tcp_round_trip(
  dev: &Device,
  addr: SocketAddr,
  payload: Vec<u8>,
  within: Duration,
) -> Result<Vec<u8>> {
  let task = dev.spawn(move |_| async move {
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    stream.write_all(&payload).await?;
    stream.shutdown().await?;
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).await?;
    anyhow::Ok(echoed)
  })?;
  tokio::time::timeout(within, task).await??
}

/// Whether the client's winning handshake was at `addr`. Matches the
/// address on the line announcing it rather than the whole field, which
/// the log decorates.
pub fn established_at(stderr: &str, addr: Ipv4Addr) -> bool {
  stderr.lines().any(|line| {
    line.contains("pinned handshake established")
      && line.contains(&format!("{addr}:"))
  })
}

/// Open-fd count for `pid`; labs share the host pid namespace, so
/// `/proc` answers for processes inside them.
pub fn fd_count(pid: u32) -> Option<usize> {
  std::fs::read_dir(format!("/proc/{pid}/fd"))
    .ok()
    .map(|dir| dir.count())
}

/// All processes whose argv carries `marker`, as (pid, cmdline).
pub fn marked_lines(marker: &str) -> Vec<(u32, String)> {
  let Ok(out) = std::process::Command::new("pgrep")
    .args(["-af", marker])
    .output()
  else {
    return Vec::new();
  };
  String::from_utf8_lossy(&out.stdout)
    .lines()
    .filter_map(|line| {
      let (pid, cmd) = line.split_once(' ')?;
      Some((pid.parse().ok()?, cmd.to_string()))
    })
    .collect()
}

/// Classifies a marker-carrying process by role. The Mush processes
/// carry the binary path as argv0 and the subcommand as argv1. Both ssh
/// invocations carry the marker as well -- the outer one inside its
/// injected ProxyCommand string, the bootstrap one in its remote
/// command -- and only the bootstrap disables ProxyCommand.
pub fn classify_marked(cmd: &str) -> &'static str {
  let mut it = cmd.split_whitespace();
  let argv0 = it.next().unwrap_or("");
  let argv1 = it.next().unwrap_or("");
  if argv0.ends_with("/mush") {
    return match argv1 {
      "connect" => "mush-connect",
      "server" => "mush-server",
      _ => "mush-other",
    };
  }
  if cmd.contains("ProxyCommand=none") {
    "bootstrap-ssh"
  } else if cmd.contains("ProxyCommand=") {
    "outer-ssh"
  } else {
    "other"
  }
}

pub fn marked_roles(marker: &str) -> Vec<(u32, &'static str)> {
  marked_lines(marker)
    .iter()
    .map(|(pid, cmd)| (*pid, classify_marked(cmd)))
    .collect()
}

/// Finds the marked `mush` process of `kind` ("connect" or "server").
pub fn find_marked(marker: &str, kind: &str) -> Option<u32> {
  let want = match kind {
    "connect" => "mush-connect",
    "server" => "mush-server",
    _ => return None,
  };
  marked_roles(marker)
    .into_iter()
    .find_map(|(pid, role)| (role == want).then_some(pid))
}

/// Pids of live marked `mush` processes running `subcommand` ("server":
/// the detached server; "connect": the ProxyCommand child).
pub fn marked_mush_pids(marker: &str, subcommand: &str) -> Vec<u32> {
  marked_lines(marker)
    .into_iter()
    .filter_map(|(pid, cmd)| {
      let mut fields = cmd.split_whitespace();
      let argv0 = fields.next().unwrap_or("");
      let argv1 = fields.next().unwrap_or("");
      (argv0.ends_with("/mush") && argv1 == subcommand).then_some(pid)
    })
    .collect()
}

pub fn marked_server_count(marker: &str) -> usize {
  marked_mush_pids(marker, "server").len()
}

/// A live ssh session over Mush: the child, its stdin, its stdout as
/// lines, and its stderr draining in the background. Going through here
/// keeps a suite from losing one by hand -- an undrained stderr
/// deadlocks the child on a full pipe -- and makes the exit check on
/// [`close`](Self::close) structural rather than remembered.
pub struct Session {
  pub child: Child,
  pub stdin: ChildStdin,
  pub lines: Lines<BufReader<ChildStdout>>,
  stderr: tokio::task::JoinHandle<Vec<u8>>,
  /// The suite's own timeout for any single await here.
  step: Duration,
}

impl Session {
  /// Takes over a spawned child's three piped streams.
  pub fn attach(mut child: Child, step: Duration) -> Result<Self> {
    let stdin = child.stdin.take().context("stdin piped")?;
    let lines =
      BufReader::new(child.stdout.take().context("stdout piped")?).lines();
    let stderr = drain(child.stderr.take().context("stderr piped")?);
    Ok(Self {
      child,
      stdin,
      lines,
      stderr,
      step,
    })
  }

  /// One round trip through the real ssh session: proof the path it is
  /// on carries traffic right now.
  pub async fn echo(&mut self, line: &str) -> Result<()> {
    self.echo_within(line, self.step, "the session echo").await
  }

  /// [`echo`](Self::echo) with its own deadline, for a round trip whose
  /// timing is what a test is measuring.
  pub async fn echo_within(
    &mut self,
    line: &str,
    within: Duration,
    what: &str,
  ) -> Result<()> {
    self.write_line(line).await?;
    let echo = next_line(&mut self.lines, within, what).await?;
    ensure!(echo == line, "unexpected echo {echo:?}");
    Ok(())
  }

  /// Writes one line into the session without waiting for its echo.
  pub async fn write_line(&mut self, line: &str) -> Result<()> {
    tokio::time::timeout(
      self.step,
      self.stdin.write_all(format!("{line}\n").as_bytes()),
    )
    .await??;
    Ok(())
  }

  /// The session's stderr, for a test reporting why a round trip failed.
  /// Waits for the stream to end, so the child must be on its way out.
  pub async fn stderr_now(&mut self) -> Result<String> {
    let raw = tokio::time::timeout(self.step, &mut self.stderr).await??;
    Ok(String::from_utf8_lossy(&raw).into_owned())
  }

  /// Ends the session by closing its stdin and returns the client's
  /// stderr, asserting the exit was clean.
  pub async fn close(mut self) -> Result<String> {
    drop(self.stdin);
    let status = tokio::time::timeout(self.step, self.child.wait()).await??;
    let raw = tokio::time::timeout(self.step, self.stderr).await??;
    let stderr = String::from_utf8_lossy(&raw).into_owned();
    ensure!(
      status.success(),
      "session failed ({status}); stderr:\n{stderr}"
    );
    Ok(stderr)
  }

  /// [`close`](Self::close), additionally pinning that the session used
  /// QUIC. Kernel TCP retransmits carry a silently fallen-back session
  /// through most of these scenarios, so an unpinned test stays green
  /// with QUIC establishment broken (see `docs/testing.md`).
  pub async fn close_no_fallback(self) -> Result<String> {
    let stderr = self.close().await?;
    ensure!(
      !stderr.contains("falling back"),
      "the session must use QUIC, not the TCP fallback:\n{stderr}"
    );
    Ok(stderr)
  }
}

/// The client's own account of the path it is on, from the report file
/// `mush connect` writes at `MUSH_PATH_REPORT`. One parser for the
/// writer's whole line (`mush/src/connect.rs`), so a field added there
/// cannot be picked up by one suite and missed by another. The file is
/// rewritten on every later path switch, so the answer changes.
#[derive(Debug)]
pub struct Report {
  pub path_kind: PathKind,
  pub addr: String,
  pub helper: String,
  pub reflexive: String,
  pub punched: bool,
}

impl Report {
  pub fn parse(line: &str) -> Result<Self> {
    let mut fields = std::collections::HashMap::new();
    for token in line.split_whitespace() {
      let (key, value) = token
        .split_once('=')
        .with_context(|| format!("malformed path report {line:?}"))?;
      fields.insert(key, value);
    }
    let field = |key: &str| -> Result<String> {
      Ok((*fields.get(key).context("missing path report field")?).to_string())
    };
    Ok(Self {
      path_kind: field("path")?.parse().ok().context("unknown path kind")?,
      addr: field("addr")?,
      helper: field("helper")?,
      reflexive: field("reflexive")?,
      punched: field("punched")? == "true",
    })
  }

  /// Reads the report file, which the client rewrites through a rename
  /// so a reader polling it never sees half a line.
  pub fn read(path: &std::path::Path) -> Result<Self> {
    let text = std::fs::read_to_string(path)
      .with_context(|| format!("no path report at {}", path.display()))?;
    Self::parse(text.trim_end())
  }

  /// Polls the report until the session's path reaches `path_kind`.
  pub async fn settles_on(
    path: &std::path::Path,
    path_kind: PathKind,
    within: Duration,
    poll: Duration,
  ) -> Result<Self> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
      let report = Self::read(path)?;
      if report.path_kind == path_kind {
        return Ok(report);
      }
      if tokio::time::Instant::now() >= deadline {
        bail!(
          "the session is still on the {} path: {report:?}",
          report.path_kind
        );
      }
      tokio::time::sleep(poll).await;
    }
  }
}

/// One point on the outage matrix: a client-side blackhole opened under
/// a live session.
pub struct Outage {
  pub window: Duration,
  pub direction: LinkDirection,
  /// When, inside the window, the session is checked still alive. The
  /// instant is the claim: 35s into a 70s outage is just past quinn's
  /// 30s default idle timeout, while the end of a 30s one-way window is
  /// where a session that lost only one direction would have died.
  pub alive_at: Option<Duration>,
  /// How long the remote sleeps between its two marker lines; must
  /// comfortably outlast `after + window`.
  pub remote_sleep: u32,
}

impl Outage {
  /// A both-directions blackhole opening as soon as the session's first
  /// line arrives, with no mid-window liveness check.
  pub fn new(window: Duration, remote_sleep: u32) -> Self {
    Self {
      window,
      direction: LinkDirection::Both,
      alive_at: None,
      remote_sleep,
    }
  }
}

/// Runs a session through a client-side blackhole window: remote output
/// before the window, silence across it, then output and a clean exit
/// after. `--no-fallback` is not a parameter: kernel TCP retransmits
/// carry a silently fallen-back session across every window in this
/// matrix, so without the pin a broken QUIC establishment would keep
/// them green (see `docs/testing.md`).
pub async fn outage_session(
  client: &Device,
  mush: &MushFixture,
  dest_ip: Ipv4Addr,
  outage: Outage,
  step: Duration,
) -> Result<()> {
  let remote = format!(
    "sh -c 'echo OUTAGE-START; sleep {}; echo OUTAGE-END'",
    outage.remote_sleep
  );
  let args = mush.ssh_args_with(dest_ip, &["--no-fallback"]);
  let mut child = spawn_session(client, &args, &remote, None)?;
  drop(child.stdin.take());
  let mut lines =
    BufReader::new(child.stdout.take().context("stdout piped")?).lines();
  let stderr = drain(child.stderr.take().context("stderr piped")?);

  let start = next_line(&mut lines, step, "OUTAGE-START").await?;
  ensure!(start == "OUTAGE-START", "unexpected line {start:?}");

  let iface = client.iface("eth0").context("client eth0")?;
  iface
    .set_condition(LinkCondition::new().loss_pct(100.0), outage.direction)
    .await?;
  match outage.alive_at {
    Some(at) => {
      tokio::time::sleep(at).await;
      ensure!(
        child.try_wait()?.is_none(),
        "session died {at:?} into the {:?} blackhole",
        outage.direction
      );
      tokio::time::sleep(outage.window.saturating_sub(at)).await;
    }
    None => tokio::time::sleep(outage.window).await,
  }
  iface.clear_condition(outage.direction).await?;

  let end =
    next_line(&mut lines, step, "OUTAGE-END after the blackhole").await?;
  ensure!(end == "OUTAGE-END", "unexpected line {end:?}");
  let status = tokio::time::timeout(step, child.wait()).await??;
  let stderr = tokio::time::timeout(step, stderr).await??;
  ensure!(
    status.success(),
    "session died across the {:?} blackhole ({status}); stderr:\n{}",
    outage.direction,
    String::from_utf8_lossy(&stderr)
  );
  mush.wait_no_marked_processes().await
}

/// What a lab's topology offers the assembly below: the client that
/// runs ssh, and the destination it reaches.
pub trait LabTopo {
  fn client(&self) -> &Device;
  fn dest(&self) -> &Device;
  fn dest_ip(&self) -> Result<Ipv4Addr>;
}

impl LabTopo for Topology {
  fn client(&self) -> &Device {
    &self.client
  }
  fn dest(&self) -> &Device {
    &self.dest
  }
  fn dest_ip(&self) -> Result<Ipv4Addr> {
    Topology::dest_ip(self)
  }
}

impl LabTopo for RoamingTopo {
  fn client(&self) -> &Device {
    &self.client
  }
  fn dest(&self) -> &Device {
    &self.dest
  }
  fn dest_ip(&self) -> Result<Ipv4Addr> {
    RoamingTopo::dest_ip(self)
  }
}

/// One assembled lab: a topology with a ready sshd on the dest and the
/// Mush fixture pointing at it.
pub struct Lab<T: LabTopo> {
  pub topo: T,
  pub fix: SshFixture,
  pub mush: MushFixture,
  pub dest_ip: Ipv4Addr,
  _sshd: SshServer,
}

impl<T: LabTopo> Lab<T> {
  pub async fn new(topo: T) -> Result<Self> {
    Self::build(topo, MushFixture::new, false).await
  }

  /// [`new`](Self::new) whose sshd can allocate a PTY; see
  /// [`SshFixture::spawn_sshd_with_pty`].
  pub async fn with_pty(topo: T) -> Result<Self> {
    Self::build(topo, MushFixture::new, true).await
  }

  /// [`new`](Self::new) with the `MushFixture` constructor the test
  /// wants (e.g. [`MushFixture::new_without_remote_mush`]).
  pub async fn with_mush(
    topo: T,
    mush_fixture: fn(&SshFixture) -> Result<MushFixture>,
  ) -> Result<Self> {
    Self::build(topo, mush_fixture, false).await
  }

  async fn build(
    topo: T,
    mush_fixture: fn(&SshFixture) -> Result<MushFixture>,
    pty: bool,
  ) -> Result<Self> {
    let dest_ip = topo.dest_ip()?;
    let fix = SshFixture::new()?;
    fix.trust_host(dest_ip)?;
    // Before the sshd: the fixture also wires a shim directory onto
    // remote sessions' PATH, which wrapper mode resolves through.
    let mush = mush_fixture(&fix)?;
    let mut sshd = match pty {
      true => fix.spawn_sshd_with_pty(topo.dest())?,
      false => fix.spawn_sshd(topo.dest())?,
    };
    sshd.wait_ready(topo.client(), dest_ip, READY).await?;
    Ok(Self {
      topo,
      fix,
      mush,
      dest_ip,
      _sshd: sshd,
    })
  }

  /// Tears down a lab whose server side may outlive the client's
  /// processes (a hung remote command, an abandoned session): the
  /// namespace sweep reaps it, and the marker check proves nothing
  /// survived.
  pub async fn teardown_swept(self) -> Result<()> {
    let Self { topo, mush, .. } = self;
    drop(topo);
    mush.wait_no_marked_processes().await
  }
}

/// A jump lab: bastion and destination sshds up, the Mush wiring in
/// place, and the `-J` spec the client uses.
pub struct JumpLab {
  pub topo: JumpTopo,
  pub fix: SshFixture,
  pub mush: MushFixture,
  pub jump_ip: Ipv4Addr,
  pub dest_ip: Ipv4Addr,
  /// The `-J` chain the topology has, so a two-hop topology produces
  /// the design's `-J a,b` with no other change to a scenario.
  pub jump_spec: String,
  /// Scratch space for the path-report files a scenario reads.
  pub dir: tempfile::TempDir,
  /// The bastion's sshd, droppable so a scenario can kill it.
  pub sshd_jump: Option<SshServer>,
  _sshd_dest: SshServer,
  /// The extra bastion's sshd, under a two-hop topology.
  _sshd_first: Option<SshServer>,
}

impl JumpLab {
  pub async fn new(topo: JumpTopo) -> Result<Self> {
    let jump_ip = topo.jump_public_ip()?;
    let dest_ip = topo.dest_ip()?;
    let fix = SshFixture::new()?;
    fix.trust_host(jump_ip)?;
    fix.trust_host(dest_ip)?;
    // Before the sshds: the fixture wires the remote PATH that the
    // bastion's bare `mush jump-helper` resolves through.
    let mush = MushFixture::new(&fix)?;
    let mut sshd_jump = fix.spawn_sshd(&topo.jump)?;
    let mut sshd_dest = fix.spawn_sshd(&topo.dest)?;
    let hop = format!("{}@{jump_ip}:{}", fix.user, fix.port);
    let (jump_spec, sshd_first) = match &topo.first_hop {
      None => (hop, None),
      Some(device) => {
        let first_ip = topo.first_hop_ip()?;
        fix.trust_host(first_ip)?;
        let mut sshd = fix.spawn_sshd(device)?;
        sshd.wait_ready(&topo.client, first_ip, READY).await?;
        let spec = format!("{}@{first_ip}:{},{hop}", fix.user, fix.port);
        (spec, Some(sshd))
      }
    };
    sshd_jump.wait_ready(&topo.client, jump_ip, READY).await?;
    sshd_dest.wait_ready(&topo.jump, dest_ip, READY).await?;
    Ok(Self {
      topo,
      fix,
      mush,
      jump_ip,
      dest_ip,
      jump_spec,
      dir: tempfile::TempDir::with_prefix("mush-jump-")?,
      sshd_jump: Some(sshd_jump),
      _sshd_dest: sshd_dest,
      _sshd_first: sshd_first,
    })
  }

  /// [`new`](Self::new) on the `jump_policy` topology, additionally
  /// proving the policy is real: the destination's ssh port does not
  /// answer the client at all, so every session there has to bootstrap
  /// through the jump to get anywhere.
  pub async fn policy() -> Result<Self> {
    let lab = Self::new(jump_policy().await?).await?;
    let dest_ssh = SocketAddr::new(lab.dest_ip.into(), lab.fix.port);
    ensure!(
      wait_tcp_ready(&lab.topo.client, dest_ssh, Duration::from_secs(2))
        .await
        .is_err(),
      "the dest's ssh port must be unreachable from the client"
    );
    Ok(lab)
  }

  /// A fresh path-report path for one session, under [`dir`](Self::dir).
  pub fn report_path(&self) -> Result<std::path::PathBuf> {
    Ok(self.dir.path().join(format!(
      "report-{}",
      std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos()
    )))
  }
}
