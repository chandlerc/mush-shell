// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Compatibility matrix: the design doc's "What OpenSSH provides"
//! claims exercised over the real Mush tunnel -- `-R` and `-D`
//! forwarding, agent forwarding, ControlMaster mux, sftp, rsync, git,
//! `ssh -N`, and exit fidelity.
//!
//! Same rules as `acceptance.rs`: the full production setup with no
//! fakes, and `--no-fallback` on every Mush session so nothing silently
//! uses the TCP fallback. Where a claim is about parity rather than
//! absolute behavior, the baseline is a control run of the same command
//! over plain ssh in the same lab, not a hard-coded expectation. Tests
//! needing tools outside the base capability probe (`sftp`,
//! `ssh-agent`/`ssh-add`, `rsync`, `git`) check for them individually via
//! `skip_unless_tools!` and skip visibly when absent.
//!
//! Runs under the nextest `lab` profile; see `docs/testing.md`. The
//! `mush` binary must be built first (`cargo build -p mush`).

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use mush_testenv::patchbay::{Device, LinkCondition, LinkDirection};
use mush_testenv::{
  SshFixture, Topology, Uplink, direct, poll_until, roaming, spawn_tcp_echo,
  wait_tcp_ready,
};
use tokio::io::{
  AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader,
};
use tokio::process::{Child, Command};

mod common;

use common::{
  Lab, READY, Session, drain, fd_count, marked_mush_pids, marked_server_count,
  next_line, pseudo_bytes, spawn_ssh, t, tcp_round_trip,
};

mush_testenv::userns_bootstrap!();

/// Timeout for any single await that should be quick; orders of
/// magnitude above lab timings, so timing variation cannot flake.
const STEP: Duration = Duration::from_secs(60);

/// Captured result of one completed command.
struct Exec {
  status: std::process::ExitStatus,
  stdout: String,
  stderr: String,
}

/// Runs `cmd` in `dev`'s namespace, stdin closed, output captured.
async fn run_in(dev: &Device, mut cmd: Command, what: &str) -> Result<Exec> {
  cmd
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
  mush_testenv::harden_command(&mut cmd);
  let child = dev.spawn_command(cmd)?;
  let out = t(STEP, child.wait_with_output())
    .await
    .with_context(|| format!("running {what}"))?;
  Ok(Exec {
    status: out.status,
    stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
    stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
  })
}

/// [`run_in`], requiring success.
async fn run_ok(dev: &Device, cmd: Command, what: &str) -> Result<Exec> {
  let out = run_in(dev, cmd, what).await?;
  ensure!(
    out.status.success(),
    "{what} failed ({}); stdout:\n{}\nstderr:\n{}",
    out.status,
    out.stdout,
    out.stderr
  );
  Ok(out)
}

/// Single-quotes `word` for `/bin/sh`: wrapper scripts, ProxyCommands.
fn sq(word: &str) -> String {
  format!("'{}'", word.replace('\'', r"'\''"))
}

/// Writes an executable ssh stand-in splicing in the fixture config and
/// the pinned Mush ProxyCommand, for tools that name an ssh command
/// (rsync's `-e`, git's `GIT_SSH`) where an inline quoted ProxyCommand
/// would need another quoting layer.
///
/// Every invocation appends its arguments to the returned log first.
/// The lab shares a filesystem, so correct files prove nothing on their
/// own; the log growing across an operation is what proves the tool
/// shelled out through this script, and so through Mush.
fn write_ssh_via_mush(
  dir: &Path,
  lab: &Lab<Topology>,
) -> Result<(PathBuf, PathBuf)> {
  let script = dir.join("ssh-via-mush");
  let log = dir.join("ssh-via-mush.log");
  let body = format!(
    "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\nexec ssh -F {} -o \
     ProxyCommand={} -o ConnectTimeout=30 \"$@\"\n",
    sq(&log.display().to_string()),
    sq(&lab.fix.ssh_config().display().to_string()),
    sq(&lab.mush.proxy_command_with(&["--no-fallback"])),
  );
  std::fs::write(&script, body)?;
  let mut permissions = std::fs::metadata(&script)?.permissions();
  use std::os::unix::fs::PermissionsExt as _;
  permissions.set_mode(0o755);
  std::fs::set_permissions(&script, permissions)?;
  Ok((script, log))
}

/// Lines in a transport-invocation log; zero before the first call.
fn invocation_count(log: &Path) -> usize {
  std::fs::read_to_string(log)
    .map(|text| text.lines().count())
    .unwrap_or(0)
}

/// A short-path tempdir for unix sockets: `sun_path` tops out around
/// 100 bytes, which TMPDIR-based tempdirs can exceed.
fn socket_dir(prefix: &str) -> Result<tempfile::TempDir> {
  Ok(tempfile::Builder::new().prefix(prefix).tempdir_in("/tmp")?)
}

#[derive(Default)]
struct ServerWatchState {
  max_concurrent: usize,
  pids: BTreeSet<u32>,
}

/// Continuous monitor of the marked detached servers on a sampling
/// thread. A point-in-time count cannot rule out a transient extra
/// bootstrap between samples; this narrows that gap to the 50ms
/// sampling interval, and the accumulated pid set pins server identity,
/// catching a replacement even when the concurrency peak slips between
/// samples.
struct ServerWatch {
  stop: Arc<AtomicBool>,
  state: Arc<Mutex<ServerWatchState>>,
  thread: Option<std::thread::JoinHandle<()>>,
}

impl ServerWatch {
  /// Starts sampling. Start only after establishment: the detach fork
  /// briefly shows the bootstrapping server twice, so a watch spanning
  /// a legitimate bootstrap would count its fork pair as concurrency.
  fn start(marker: &str) -> Self {
    let stop = Arc::new(AtomicBool::new(false));
    let state = Arc::new(Mutex::new(ServerWatchState::default()));
    let thread = {
      let stop = Arc::clone(&stop);
      let state = Arc::clone(&state);
      let marker = marker.to_string();
      std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
          let pids = marked_mush_pids(&marker, "server");
          let mut state = state.lock().expect("watch state lock");
          state.max_concurrent = state.max_concurrent.max(pids.len());
          state.pids.extend(pids);
          drop(state);
          std::thread::sleep(Duration::from_millis(50));
        }
      })
    };
    ServerWatch {
      stop,
      state,
      thread: Some(thread),
    }
  }

  /// Stops sampling and asserts `expected` served alone throughout:
  /// never a second concurrently, no other pid even transiently.
  fn finish_expecting(mut self, expected: u32) -> Result<()> {
    self.stop.store(true, Ordering::Relaxed);
    if let Some(thread) = self.thread.take() {
      let _ = thread.join();
    }
    let state = self.state.lock().expect("watch state lock");
    ensure!(
      state.max_concurrent <= 1,
      "{} marked servers ran concurrently during the mux phase",
      state.max_concurrent
    );
    ensure!(
      state.pids.len() == 1 && state.pids.contains(&expected),
      "server identity changed during the mux phase: saw {:?}, want \
       {{{expected}}}",
      state.pids
    );
    Ok(())
  }
}

impl Drop for ServerWatch {
  fn drop(&mut self) {
    self.stop.store(true, Ordering::Relaxed);
    if let Some(thread) = self.thread.take() {
      let _ = thread.join();
    }
  }
}

/// Whether some process's full command line is exactly `pattern`.
fn process_running(pattern: &str) -> bool {
  std::process::Command::new("pgrep")
    .args(["-fx", pattern])
    .stdout(Stdio::null())
    .status()
    .is_ok_and(|status| status.success())
}

/// `ssh -R`: a TCP echo on the client's loopback, reachable from the
/// dest only through the reverse-forwarded channel -- the
/// server-to-client multiplexing direction `-L` does not exercise.
#[tokio::test(flavor = "current_thread")]
async fn remote_forward_reaches_client_side_listener() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let echo_addr: SocketAddr = "127.0.0.1:7852".parse()?;
  let _echo = spawn_tcp_echo(&lab.topo.client, echo_addr).await?;

  let session = forwarding_session(
    &lab,
    Forward::Remote(7851, 7852),
    &lab.topo.dest,
    "rfwd-up",
  )
  .await?;
  let remote: SocketAddr = "127.0.0.1:7851".parse()?;

  let payload = pseudo_bytes(256 * 1024, 0x5266_7764);
  let echoed =
    tcp_round_trip(&lab.topo.dest, remote, payload.clone(), STEP).await?;
  ensure!(
    echoed == payload,
    "reverse-forwarded channel corrupted: {} bytes sent, {} bytes back",
    payload.len(),
    echoed.len()
  );

  session.close().await?;
  lab.mush.wait_no_marked_processes().await
}

/// Which forward a session carries, with the ports it uses.
enum Forward {
  /// `-R <port>:127.0.0.1:<echo>`: the dest reaches a listener on the
  /// client through the reverse-forwarded channel.
  Remote(u16, u16),
  /// `-D <port>`: a SOCKS proxy on the client.
  Dynamic(u16),
}

/// Brings up a forwarding session held open by a `cat`, echoes `tag` to
/// prove it is live, then waits for the forward's listener on
/// `listens_on` -- the dest for a `-R` forward, the client for a `-D`.
async fn forwarding_session(
  lab: &Lab<Topology>,
  forward: Forward,
  listens_on: &Device,
  tag: &str,
) -> Result<Session> {
  let mut args = lab.mush.ssh_opts_with(&["--no-fallback"]);
  let port = match forward {
    Forward::Remote(port, echo) => {
      args.extend(["-R".to_string(), format!("{port}:127.0.0.1:{echo}")]);
      port
    }
    Forward::Dynamic(port) => {
      args.extend(["-D".to_string(), port.to_string()]);
      port
    }
  };
  args.extend(["-o", "ExitOnForwardFailure=yes"].map(String::from));
  args.push(lab.dest_ip.to_string());
  args.push("cat".to_string());
  let mut session =
    Session::attach(spawn_ssh(&lab.topo.client, &args, &[])?, STEP)?;
  session.echo(tag).await?;
  let listener: SocketAddr = format!("127.0.0.1:{port}").parse()?;
  wait_tcp_ready(listens_on, listener, READY).await?;
  Ok(session)
}

/// Minimal SOCKS5 handshake (RFC 1928, no auth) on an open stream:
/// greeting, then CONNECT to an IPv4 target.
async fn socks5_connect(
  stream: &mut tokio::net::TcpStream,
  target: SocketAddrV4,
) -> Result<()> {
  stream.write_all(&[0x05, 0x01, 0x00]).await?;
  let mut greeting = [0u8; 2];
  stream.read_exact(&mut greeting).await?;
  ensure!(
    greeting == [0x05, 0x00],
    "SOCKS greeting reply {greeting:?}"
  );
  let mut request = vec![0x05, 0x01, 0x00, 0x01];
  request.extend_from_slice(&target.ip().octets());
  request.extend_from_slice(&target.port().to_be_bytes());
  stream.write_all(&request).await?;
  let mut reply = [0u8; 4];
  stream.read_exact(&mut reply).await?;
  ensure!(reply[1] == 0x00, "SOCKS CONNECT refused: {reply:?}");
  // Consume the bound address: 4-byte IPv4 or 16-byte IPv6, plus port.
  let addr_len = match reply[3] {
    0x01 => 4,
    0x04 => 16,
    atyp => bail!("unexpected bound-address type {atyp}"),
  };
  let mut bound = [0u8; 18];
  stream.read_exact(&mut bound[..addr_len + 2]).await?;
  Ok(())
}

/// One SOCKS5 round trip from inside `dev`: CONNECT to `target` via the
/// proxy at `socks`, then a byte round trip with half-close.
async fn socks5_round_trip(
  dev: &Device,
  socks: SocketAddr,
  target: SocketAddrV4,
  payload: Vec<u8>,
) -> Result<Vec<u8>> {
  let task = dev.spawn(move |_| async move {
    let mut stream = tokio::net::TcpStream::connect(socks).await?;
    socks5_connect(&mut stream, target).await?;
    stream.write_all(&payload).await?;
    stream.shutdown().await?;
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).await?;
    anyhow::Ok(echoed)
  })?;
  t(STEP, task).await?
}

/// `ssh -D`: a dest-side TCP echo reached through the dynamic SOCKS
/// forward, with the CONNECT target resolved on the dest (its loopback
/// is unreachable from the client any other way).
#[tokio::test(flavor = "current_thread")]
async fn dynamic_socks_forward_reaches_dest_echo() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let echo_addr: SocketAddr = "127.0.0.1:7862".parse()?;
  let _echo = spawn_tcp_echo(&lab.topo.dest, echo_addr).await?;

  let session = forwarding_session(
    &lab,
    Forward::Dynamic(7861),
    &lab.topo.client,
    "socks-up",
  )
  .await?;
  let socks: SocketAddr = "127.0.0.1:7861".parse()?;

  let payload = pseudo_bytes(256 * 1024, 0x536f_636b);
  let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7862);
  let echoed =
    socks5_round_trip(&lab.topo.client, socks, target, payload.clone()).await?;
  ensure!(
    echoed == payload,
    "SOCKS round trip corrupted: {} bytes sent, {} bytes back",
    payload.len(),
    echoed.len()
  );

  session.close().await?;
  lab.mush.wait_no_marked_processes().await
}

/// Whether the agent behind `sock` answers `ssh-add -l` (0: identities
/// listed, 1: agent reachable but empty; 2 means no agent yet).
async fn agent_ready(dev: &Device, sock: &Path) -> bool {
  let mut cmd = Command::new("ssh-add");
  cmd
    .arg("-l")
    .env("SSH_AUTH_SOCK", sock)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
  mush_testenv::harden_command(&mut cmd);
  let Ok(child) = dev.spawn_command(cmd) else {
    return false;
  };
  match child.wait_with_output().await {
    Ok(out) => out.status.code().is_some_and(|code| code == 0 || code == 1),
    Err(_) => false,
  }
}

/// Starts an ssh-agent at `sock` in `dev` with exactly the fixture user
/// key; returns the child (killed on drop) and its SHA256 fingerprint.
async fn agent_with_fixture_key(
  dev: &Device,
  fix: &SshFixture,
  sock: &Path,
) -> Result<(Child, String)> {
  let mut agent_cmd = Command::new("ssh-agent");
  agent_cmd
    .arg("-D")
    .arg("-a")
    .arg(sock)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
  mush_testenv::harden_command(&mut agent_cmd);
  let agent = dev.spawn_command(agent_cmd)?;
  poll_until(
    "the ssh-agent socket",
    READY,
    Duration::from_millis(100),
    || agent_ready(dev, sock),
  )
  .await?;

  let mut add = Command::new("ssh-add");
  add.arg(fix.user_key()).env("SSH_AUTH_SOCK", sock);
  run_ok(dev, add, "ssh-add of the fixture key").await?;

  let keygen = std::process::Command::new("ssh-keygen")
    .arg("-lf")
    .arg(fix.user_key().with_extension("pub"))
    .output()
    .context("running ssh-keygen -l")?;
  ensure!(keygen.status.success(), "ssh-keygen -l failed");
  let keygen = String::from_utf8_lossy(&keygen.stdout).into_owned();
  let fingerprint = keygen
    .split_whitespace()
    .find(|field| field.starts_with("SHA256:"))
    .context("no SHA256 fingerprint in ssh-keygen output")?
    .to_string();
  Ok((agent, fingerprint))
}

/// Agent forwarding: a real ssh-agent in the client namespace holding
/// exactly the fixture key; the remote `ssh-add -l` must list it alone.
#[tokio::test(flavor = "current_thread")]
async fn agent_forwarding_lists_exactly_the_fixture_key() -> Result<()> {
  mush_testenv::skip_unless_available!();
  mush_testenv::skip_unless_tools!("ssh-agent", "ssh-add");
  let lab = Lab::new(direct().await?).await?;

  let sock_dir = socket_dir("mush-agent-")?;
  let sock = sock_dir.path().join("agent");
  let (_agent, fingerprint) =
    agent_with_fixture_key(&lab.topo.client, &lab.fix, &sock).await?;

  // ForwardAgent is opt-in and the fixture config does not set it: with
  // no forwarded agent the remote session has no SSH_AUTH_SOCK at all.
  let mut args = lab.mush.ssh_opts_with(&["--no-fallback"]);
  args.extend(["-o", "ForwardAgent=yes"].map(String::from));
  args.push(lab.dest_ip.to_string());
  args.push("ssh-add -l".to_string());
  let mut cmd = Command::new("ssh");
  cmd.args(&args).env("SSH_AUTH_SOCK", &sock);
  let out = run_ok(&lab.topo.client, cmd, "agent-forwarded ssh-add -l").await?;
  let listed: Vec<&str> = out
    .stdout
    .lines()
    .filter(|line| !line.trim().is_empty())
    .collect();
  ensure!(
    listed.len() == 1,
    "expected exactly one forwarded key:\n{}",
    out.stdout
  );
  ensure!(
    listed[0].contains(&fingerprint),
    "forwarded agent listed the wrong key: {} (want {fingerprint})",
    listed[0]
  );
  lab.mush.wait_no_marked_processes().await
}

/// Agent forwarding across a roam: each remote `ssh-add -l` opens a
/// fresh agent channel back over the session, so answering after the
/// client's address changed exercises the server-to-client direction
/// under migration. The old uplink is killed before the post-roam
/// query, so a working answer can only travel over a server-validated
/// migration (the pattern the acceptance roaming test uses to rule out
/// a false pass).
#[tokio::test(flavor = "current_thread")]
async fn agent_forwarding_survives_roam_to_new_uplink() -> Result<()> {
  mush_testenv::skip_unless_available!();
  mush_testenv::skip_unless_tools!("ssh-agent", "ssh-add");
  let lab = Lab::new(roaming().await?).await?;
  let (topo, mush) = (&lab.topo, &lab.mush);
  let dest_ip = lab.dest_ip;

  let sock_dir = socket_dir("mush-agent-roam-")?;
  let sock = sock_dir.path().join("agent");
  let (_agent, fingerprint) =
    agent_with_fixture_key(&topo.client, &lab.fix, &sock).await?;

  let mut args = mush.ssh_opts_with(&["--no-fallback"]);
  args.extend(["-o", "ForwardAgent=yes"].map(String::from));
  args.push(dest_ip.to_string());
  args.push(
    "sh -c 'while read tag; do ssh-add -l; echo DONE-$tag; done'".to_string(),
  );
  let mut session = Session::attach(
    spawn_ssh(
      &topo.client,
      &args,
      &[("SSH_AUTH_SOCK", sock.display().to_string())],
    )?,
    STEP,
  )?;

  session.write_line("pre").await?;
  let listing =
    next_line(&mut session.lines, STEP, "pre-roam agent listing").await?;
  ensure!(
    listing.contains(&fingerprint),
    "pre-roam agent listing wrong: {listing:?} (want {fingerprint})"
  );
  let done = next_line(&mut session.lines, STEP, "pre-roam marker").await?;
  ensure!(done == "DONE-pre", "unexpected line {done:?}");

  // Kill A after roaming: agent service can only use the migrated path.
  topo.use_uplink(Uplink::B).await?;
  topo.fail_uplink(Uplink::A).await?;

  // 20s bounds the recovery, matching the acceptance roaming test.
  let within = Duration::from_secs(20);
  session.write_line("post").await?;
  let listing =
    next_line(&mut session.lines, within, "post-roam agent listing").await?;
  ensure!(
    listing.contains(&fingerprint),
    "post-roam agent listing wrong: {listing:?} (want {fingerprint})"
  );
  let done = next_line(&mut session.lines, within, "post-roam marker").await?;
  ensure!(done == "DONE-post", "unexpected line {done:?}");

  session.close().await?;
  mush.wait_no_marked_processes().await
}

/// Agent socket hygiene: sshd's forwarded-agent socket on the dest must
/// be gone once the session ends. The shared lab filesystem makes the
/// remote path observable, and for the same reason the test pins that
/// it is sshd's socket, not the client's leaking through.
#[tokio::test(flavor = "current_thread")]
async fn agent_socket_removed_after_session_end() -> Result<()> {
  mush_testenv::skip_unless_available!();
  mush_testenv::skip_unless_tools!("ssh-agent", "ssh-add");
  let lab = Lab::new(direct().await?).await?;

  let sock_dir = socket_dir("mush-agent-gc-")?;
  let sock = sock_dir.path().join("agent");
  let (_agent, _fingerprint) =
    agent_with_fixture_key(&lab.topo.client, &lab.fix, &sock).await?;

  let mut args = lab.mush.ssh_opts_with(&["--no-fallback"]);
  args.extend(["-o", "ForwardAgent=yes"].map(String::from));
  args.push(lab.dest_ip.to_string());
  args.push(
    r#"sh -c 'test -S "$SSH_AUTH_SOCK" && echo "AGENT-SOCK=$SSH_AUTH_SOCK"'"#
      .to_string(),
  );
  let mut cmd = Command::new("ssh");
  cmd.args(&args).env("SSH_AUTH_SOCK", &sock);
  let out =
    run_ok(&lab.topo.client, cmd, "agent-forwarded socket probe").await?;
  let remote_sock = out
    .stdout
    .lines()
    .find_map(|line| line.strip_prefix("AGENT-SOCK="))
    .context("no AGENT-SOCK line in the session output")?
    .trim()
    .to_string();
  ensure!(
    remote_sock != sock.display().to_string(),
    "the remote agent socket must be sshd's forwarded socket, not the \
     client's own"
  );

  let path = PathBuf::from(&remote_sock);
  poll_until(
    "the forwarded agent socket to be removed",
    Duration::from_secs(10),
    Duration::from_millis(100),
    || {
      let path = path.clone();
      async move { !path.exists() }
    },
  )
  .await?;
  lab.mush.wait_no_marked_processes().await
}

/// Mux-client argv using the master at `ctl`: no Mush configuration at
/// all, and a ProxyCommand of `false` rules out a false pass -- in these
/// direct topologies a non-mux dial would succeed over plain TCP and
/// fake the result, but with the pin any path except the master's socket
/// fails.
fn mux_client_args(cfg: &str, ctl: &str, extra: &[&str]) -> Vec<String> {
  let mut args = vec![
    "-F".to_string(),
    cfg.to_string(),
    "-S".to_string(),
    ctl.to_string(),
    "-o".to_string(),
    "ProxyCommand=false".to_string(),
  ];
  args.extend(extra.iter().map(|s| s.to_string()));
  args
}

/// The single marked detached server's pid, required to exist.
fn the_marked_server(marker: &str) -> Result<u32> {
  let servers = marked_mush_pids(marker, "server");
  ensure!(
    servers.len() == 1,
    "expected exactly one mush server, saw pids {servers:?}"
  );
  Ok(servers[0])
}

/// Five mux exec sessions over one held master, all established before
/// any payload moves so the transfers demonstrably overlap, each
/// streaming its own incompressible payload through a remote `cat`. One
/// detached server must serve the entire phase.
#[tokio::test(flavor = "current_thread")]
async fn mux_five_concurrent_slaves_share_one_tunnel() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let sock_dir = socket_dir("mush-mux5-")?;
  let ctl = sock_dir.path().join("ctl").display().to_string();
  let dest = lab.dest_ip.to_string();
  let cfg = lab.fix.ssh_config().display().to_string();

  // The master holds its own session open for the whole phase; mux
  // lifetime (ControlPersist, master death) has its own tests.
  let mut args = lab.mush.ssh_opts_with(&["--no-fallback"]);
  args.extend(["-M", "-S", ctl.as_str()].map(String::from));
  args.push(dest.clone());
  args.push("cat".to_string());
  let mut master = spawn_ssh(&lab.topo.client, &args, &[])?;
  let mut master_stdin = master.stdin.take().context("stdin piped")?;
  let mut master_lines =
    BufReader::new(master.stdout.take().context("stdout piped")?).lines();
  let master_stderr = drain(master.stderr.take().context("stderr piped")?);
  t(STEP, master_stdin.write_all(b"master-up\n")).await?;
  let echo = next_line(&mut master_lines, STEP, "master echo").await?;
  ensure!(echo == "master-up", "unexpected echo {echo:?}");
  let marker = lab.mush.marker().to_string();
  let server = the_marked_server(&marker)?;
  let watch = ServerWatch::start(&marker);

  let mut slaves = Vec::new();
  for i in 0..5u32 {
    let args = mux_client_args(&cfg, &ctl, &[&dest, "cat"]);
    let mut child = spawn_ssh(&lab.topo.client, &args, &[])?;
    let mut stdin = child.stdin.take().context("stdin piped")?;
    let mut lines =
      BufReader::new(child.stdout.take().context("stdout piped")?).lines();
    let stderr = drain(child.stderr.take().context("stderr piped")?);
    t(STEP, stdin.write_all(format!("up-{i}\n").as_bytes())).await?;
    let echo = next_line(&mut lines, STEP, "slave establishment echo").await?;
    ensure!(echo == format!("up-{i}"), "unexpected echo {echo:?}");
    slaves.push((child, stdin, lines, stderr, i));
  }

  let mut transfers = Vec::new();
  for (mut child, mut stdin, lines, stderr, i) in slaves {
    let payload = pseudo_bytes(512 * 1024, 0x6d75_7830 + u64::from(i));
    transfers.push(tokio::spawn(async move {
      let to_write = payload.clone();
      let writer = tokio::spawn(async move {
        stdin.write_all(&to_write).await?;
        // Dropping stdin is the half-close; the echo's tail follows it.
        drop(stdin);
        Ok::<_, std::io::Error>(())
      });
      // The establishment echo was fully consumed, so the buffered
      // reader continues cleanly as a byte reader.
      let mut reader = lines.into_inner();
      let mut echoed = Vec::new();
      reader.read_to_end(&mut echoed).await?;
      let status = child.wait().await?;
      writer.await??;
      anyhow::ensure!(
        status.success(),
        "mux slave {i} failed ({status}); stderr:\n{}",
        String::from_utf8_lossy(&stderr.await?)
      );
      anyhow::ensure!(
        echoed == payload,
        "mux slave {i} corrupted: {} bytes sent, {} bytes back",
        payload.len(),
        echoed.len()
      );
      anyhow::Ok(())
    }));
  }
  for transfer in transfers {
    t(STEP, transfer).await??;
  }
  watch.finish_expecting(server)?;

  drop(master_stdin);
  let status = t(STEP, master.wait()).await?;
  ensure!(
    status.success(),
    "master session failed ({status}); stderr:\n{}",
    String::from_utf8_lossy(&t(STEP, master_stderr).await?)
  );
  lab.mush.wait_no_marked_processes().await
}

/// One master-death-under-active-slave run: a held mux master, a slave
/// holding a live `cat` session through it, then `-O exit` mid-session.
/// Returns the slave's exit status and stderr.
async fn master_exit_run(
  lab: &Lab<Topology>,
  master_opts: Vec<String>,
  sock_prefix: &str,
) -> Result<(std::process::ExitStatus, String)> {
  let sock_dir = socket_dir(sock_prefix)?;
  let ctl = sock_dir.path().join("ctl").display().to_string();
  let dest = lab.dest_ip.to_string();
  let cfg = lab.fix.ssh_config().display().to_string();

  let mut args = master_opts;
  args.extend(["-M", "-S", ctl.as_str()].map(String::from));
  args.push(dest.clone());
  args.push("cat".to_string());
  let mut master = spawn_ssh(&lab.topo.client, &args, &[])?;
  let mut master_stdin = master.stdin.take().context("stdin piped")?;
  let mut master_lines =
    BufReader::new(master.stdout.take().context("stdout piped")?).lines();
  drop(master.stderr.take());
  t(STEP, master_stdin.write_all(b"master-up\n")).await?;
  let echo = next_line(&mut master_lines, STEP, "master echo").await?;
  ensure!(echo == "master-up", "unexpected echo {echo:?}");

  let mut slave = spawn_ssh(
    &lab.topo.client,
    &mux_client_args(&cfg, &ctl, &[&dest, "cat"]),
    &[],
  )?;
  let mut slave_stdin = slave.stdin.take().context("stdin piped")?;
  let mut slave_lines =
    BufReader::new(slave.stdout.take().context("stdout piped")?).lines();
  let slave_stderr = drain(slave.stderr.take().context("stderr piped")?);
  t(STEP, slave_stdin.write_all(b"slave-up\n")).await?;
  let echo = next_line(&mut slave_lines, STEP, "slave echo").await?;
  ensure!(echo == "slave-up", "unexpected echo {echo:?}");

  let mut exit = Command::new("ssh");
  exit.args(mux_client_args(&cfg, &ctl, &["-O", "exit", &dest]));
  run_ok(&lab.topo.client, exit, "ssh -O exit").await?;

  // Both stdins stay open: the deaths must come from the master's exit,
  // not from an EOF the test sent.
  let status = t(STEP, slave.wait()).await?;
  let _ = t(STEP, master.wait()).await?;
  drop(slave_stdin);
  drop(master_stdin);
  let stderr =
    String::from_utf8_lossy(&t(STEP, slave_stderr).await?).into_owned();
  Ok((status, stderr))
}

/// `-O exit` while a slave session is active. The slave must die
/// exactly as over plain TCP, and the session's Mush processes must tear
/// down completely even though the tunnel died out from under an active
/// mux client.
#[tokio::test(flavor = "current_thread")]
async fn mux_master_exit_with_active_slave_matches_plain_ssh() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;

  let (tunneled, tunneled_stderr) = master_exit_run(
    &lab,
    lab.mush.ssh_opts_with(&["--no-fallback"]),
    "mush-muxexit-",
  )
  .await?;
  ensure!(
    !tunneled_stderr.contains("falling back"),
    "the session must use QUIC, not the TCP fallback:\n{tunneled_stderr}"
  );
  // The mush-specific claim: no Mush process survives the master.
  lab.mush.wait_no_marked_processes().await?;

  let ctrl_opts =
    vec!["-F".to_string(), lab.fix.ssh_config().display().to_string()];
  let (control, control_stderr) =
    master_exit_run(&lab, ctrl_opts, "mush-muxexit-ctrl-").await?;
  ensure!(
    !control.success(),
    "control run broke: the slave survived -O exit"
  );
  use std::os::unix::process::ExitStatusExt as _;
  ensure!(
    tunneled.code() == control.code() && tunneled.signal() == control.signal(),
    "slave-death parity broke: mush {tunneled:?} vs control {control:?}; \
     mush stderr:\n{tunneled_stderr}\ncontrol stderr:\n{control_stderr}",
  );
  Ok(())
}

/// ControlPersist expiry armed while a slave is active. The countdown
/// must not fire while the slave holds the only session, however far
/// past the window it runs; once the slave ends the master must expire
/// on its own -- no `-O exit` -- and take every Mush process with it.
#[tokio::test(flavor = "current_thread")]
async fn mux_control_persist_expiry_waits_for_active_slave() -> Result<()> {
  const PERSIST: Duration = Duration::from_secs(2);
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let sock_dir = socket_dir("mush-muxpersist-")?;
  let ctl = sock_dir.path().join("ctl").display().to_string();
  let dest = lab.dest_ip.to_string();
  let cfg = lab.fix.ssh_config().display().to_string();

  // The master's own session is held while the slave establishes, so
  // the persist countdown can never race the slave into existence.
  let mut args = lab.mush.ssh_opts_with(&["--no-fallback"]);
  args.extend(
    [
      "-M",
      "-S",
      ctl.as_str(),
      "-o",
      &format!("ControlPersist={}", PERSIST.as_secs()),
    ]
    .map(String::from),
  );
  args.push(dest.clone());
  args.push("cat".to_string());
  let mut master = spawn_ssh(&lab.topo.client, &args, &[])?;
  let mut master_stdin = master.stdin.take().context("stdin piped")?;
  let mut master_lines =
    BufReader::new(master.stdout.take().context("stdout piped")?).lines();
  let master_stderr = drain(master.stderr.take().context("stderr piped")?);
  t(STEP, master_stdin.write_all(b"master-up\n")).await?;
  let echo = next_line(&mut master_lines, STEP, "master echo").await?;
  ensure!(echo == "master-up", "unexpected echo {echo:?}");

  let mut slave = spawn_ssh(
    &lab.topo.client,
    &mux_client_args(&cfg, &ctl, &[&dest, "cat"]),
    &[],
  )?;
  let mut slave_stdin = slave.stdin.take().context("stdin piped")?;
  let mut slave_lines =
    BufReader::new(slave.stdout.take().context("stdout piped")?).lines();
  let slave_stderr = drain(slave.stderr.take().context("stderr piped")?);
  t(STEP, slave_stdin.write_all(b"slave-up\n")).await?;
  let echo = next_line(&mut slave_lines, STEP, "slave echo").await?;
  ensure!(echo == "slave-up", "unexpected echo {echo:?}");

  // End the master's own session; from here the slave alone keeps the
  // persisting master (and the tunnel under it) alive.
  drop(master_stdin);
  let status = t(STEP, master.wait()).await?;
  ensure!(
    status.success(),
    "master session failed ({status}); stderr:\n{}",
    String::from_utf8_lossy(&t(STEP, master_stderr).await?)
  );
  let marker = lab.mush.marker().to_string();
  let server = the_marked_server(&marker)?;
  let watch = ServerWatch::start(&marker);

  // Sit far past the persist window with the slave active; this sleep
  // is the window under test, not a readiness wait. An EPIPE means the
  // persisting master's tunnel died out from under the active slave --
  // over plain TCP the slave survives indefinitely, so must the tunnel.
  tokio::time::sleep(3 * PERSIST).await;

  t(STEP, slave_stdin.write_all(b"past-window\n"))
    .await
    .context("writing to the slave past the persist window")?;
  let echo = next_line(&mut slave_lines, STEP, "post-window echo").await?;
  ensure!(echo == "past-window", "unexpected echo {echo:?}");
  let mut check = Command::new("ssh");
  check.args(mux_client_args(&cfg, &ctl, &["-O", "check", &dest]));
  run_ok(&lab.topo.client, check, "ssh -O check past the window").await?;
  ensure!(
    marked_server_count(&marker) == 1,
    "the server must have survived the persist window"
  );

  // Slave done: the countdown runs, and expiry must stop the master
  // shortly after PERSIST, with no `-O exit` anywhere. The wait must be
  // passive -- polling `-O check` re-arms the ControlPersist timer and
  // would hold expiry off -- so watch for the master removing its
  // control socket instead.
  drop(slave_stdin);
  let status = t(STEP, slave.wait()).await?;
  ensure!(
    status.success(),
    "slave session failed ({status}); stderr:\n{}",
    String::from_utf8_lossy(&t(STEP, slave_stderr).await?)
  );
  let ctl_path = PathBuf::from(&ctl);
  poll_until(
    "ControlPersist expiry to remove the control socket",
    Duration::from_secs(15),
    Duration::from_millis(200),
    || {
      let ctl_path = ctl_path.clone();
      async move { !ctl_path.exists() }
    },
  )
  .await?;
  // A late mux client finds no master; the ProxyCommand=false pin
  // keeps this from silently dialing a fresh tunnel instead.
  let mut check = Command::new("ssh");
  check.args(mux_client_args(&cfg, &ctl, &["-O", "check", &dest]));
  let out =
    run_in(&lab.topo.client, check, "ssh -O check after expiry").await?;
  ensure!(
    !out.status.success(),
    "a mux check must fail once the master expired"
  );
  watch.finish_expecting(server)?;
  lab.mush.wait_no_marked_processes().await
}

/// sftp in batch mode: put then get, byte-compared. Modern scp speaks
/// SFTP too, so this covers the file-transfer subsystem directly.
#[tokio::test(flavor = "current_thread")]
async fn sftp_batch_round_trip() -> Result<()> {
  mush_testenv::skip_unless_available!();
  mush_testenv::skip_unless_tools!("sftp");
  let lab = Lab::new(direct().await?).await?;
  let files = tempfile::TempDir::with_prefix("mush-compat-sftp-")?;
  let src = files.path().join("push.bin");
  let remote = files.path().join("remote.bin");
  let back = files.path().join("back.bin");
  let payload = pseudo_bytes(1024 * 1024, 0x7366_7470);
  std::fs::write(&src, &payload)?;
  let batch = files.path().join("batch");
  std::fs::write(
    &batch,
    format!(
      "put {} {}\nget {} {}\n",
      src.display(),
      remote.display(),
      remote.display(),
      back.display()
    ),
  )?;

  let mut cmd = Command::new("sftp");
  cmd
    .arg("-F")
    .arg(lab.fix.ssh_config())
    .arg("-o")
    .arg(format!(
      "ProxyCommand={}",
      lab.mush.proxy_command_with(&["--no-fallback"])
    ))
    .args(["-o", "ConnectTimeout=30", "-b"])
    .arg(&batch)
    .arg(lab.dest_ip.to_string());
  run_ok(&lab.topo.client, cmd, "sftp batch").await?;

  ensure!(
    std::fs::read(&remote)? == payload,
    "sftp put corrupted the payload"
  );
  ensure!(
    std::fs::read(&back)? == payload,
    "sftp get corrupted the payload"
  );
  lab.mush.wait_no_marked_processes().await
}

/// Every regular file under `root` as relative path -> contents.
fn tree_entries(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
  fn walk(
    root: &Path,
    dir: &Path,
    map: &mut BTreeMap<PathBuf, Vec<u8>>,
  ) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
      let entry = entry?;
      let path = entry.path();
      if entry.file_type()?.is_dir() {
        walk(root, &path, map)?;
      } else {
        map.insert(
          path.strip_prefix(root)?.to_path_buf(),
          std::fs::read(&path)?,
        );
      }
    }
    Ok(())
  }
  let mut map = BTreeMap::new();
  walk(root, root, &mut map)?;
  Ok(map)
}

/// rsync over ssh through Mush: push a 2MB tree, pull it back
/// elsewhere, compare every file.
#[tokio::test(flavor = "current_thread")]
async fn rsync_tree_round_trip() -> Result<()> {
  mush_testenv::skip_unless_available!();
  mush_testenv::skip_unless_tools!("rsync");
  let lab = Lab::new(direct().await?).await?;
  let files = tempfile::TempDir::with_prefix("mush-compat-rsync-")?;
  let src = files.path().join("src");
  std::fs::create_dir_all(src.join("sub/deep"))?;
  for (name, len, seed) in [
    ("a.bin", 1024 * 1024, 0x7273_0001u64),
    ("b.bin", 512 * 1024, 0x7273_0002),
    ("sub/c.bin", 512 * 1024, 0x7273_0003),
    ("sub/deep/d.bin", 64 * 1024, 0x7273_0004),
  ] {
    std::fs::write(src.join(name), pseudo_bytes(len, seed))?;
  }
  std::fs::write(src.join("e.txt"), "mush compat matrix\n")?;
  let (script, log) = write_ssh_via_mush(files.path(), &lab)?;
  let pushed = files.path().join("pushed");
  let back = files.path().join("back");

  // -a minus ownership: the lab's nested user namespaces leave the
  // peer's uids unmapped on the receiving side, so `chown` fails with
  // EINVAL over plain ssh and Mush alike -- a harness artifact.
  let rsync_args = ["-a", "--no-owner", "--no-group"];
  let mut push = Command::new("rsync");
  push
    .args(rsync_args)
    .arg("-e")
    .arg(&script)
    .arg(format!("{}/", src.display()))
    .arg(format!("{}:{}", lab.dest_ip, pushed.display()));
  run_ok(&lab.topo.client, push, "rsync push").await?;
  // The log is what proves the transport; see [`write_ssh_via_mush`].
  let after_push = invocation_count(&log);
  ensure!(after_push >= 1, "rsync push never invoked the pinned ssh");

  let mut pull = Command::new("rsync");
  pull
    .args(rsync_args)
    .arg("-e")
    .arg(&script)
    .arg(format!("{}:{}/", lab.dest_ip, pushed.display()))
    .arg(&back);
  run_ok(&lab.topo.client, pull, "rsync pull").await?;
  ensure!(
    invocation_count(&log) > after_push,
    "rsync pull never invoked the pinned ssh"
  );

  let sent = tree_entries(&src)?;
  let returned = tree_entries(&back)?;
  ensure!(
    sent == returned,
    "rsync round trip diverged: {} files sent, {} files back",
    sent.len(),
    returned.len()
  );
  lab.mush.wait_no_marked_processes().await
}

/// git over ssh through Mush: init a bare repo on the dest through a
/// tunneled exec, clone, push a commit, clone again elsewhere, verify.
#[tokio::test(flavor = "current_thread")]
async fn git_clone_push_clone_via_mush() -> Result<()> {
  mush_testenv::skip_unless_available!();
  mush_testenv::skip_unless_tools!("git");
  let lab = Lab::new(direct().await?).await?;
  let files = tempfile::TempDir::with_prefix("mush-compat-git-")?;
  let (script, log) = write_ssh_via_mush(files.path(), &lab)?;
  let bare = files.path().join("repo.git");
  let clone1 = files.path().join("clone1");
  let clone2 = files.path().join("clone2");
  let url = format!("{}:{}", lab.dest_ip, bare.display());

  // git's own ssh invocations go through the wrapper script; author
  // identity and config isolation come from the environment.
  let home = files.path().to_path_buf();
  let git = |args: &[&str]| -> Command {
    let mut cmd = Command::new("git");
    cmd
      .args(args)
      .env("GIT_SSH", &script)
      .env("HOME", &home)
      .env("GIT_CONFIG_NOSYSTEM", "1")
      .env("GIT_AUTHOR_NAME", "Mush Compat")
      .env("GIT_AUTHOR_EMAIL", "mush-compat@example.invalid")
      .env("GIT_COMMITTER_NAME", "Mush Compat")
      .env("GIT_COMMITTER_EMAIL", "mush-compat@example.invalid");
    cmd
  };

  let init = lab
    .fix
    .ssh_exec(
      &lab.topo.client,
      &lab.mush.ssh_args_with(lab.dest_ip, &["--no-fallback"]),
      &format!("git init --bare {}", bare.display()),
    )
    .await?;
  ensure!(
    init.success,
    "git init --bare over the tunnel failed; stderr={}",
    init.stderr
  );

  let clone1_s = clone1.display().to_string();
  run_ok(
    &lab.topo.client,
    git(&["clone", &url, &clone1_s]),
    "git clone (empty)",
  )
  .await?;
  // The log is what proves the transport; see [`write_ssh_via_mush`].
  let after_clone = invocation_count(&log);
  ensure!(after_clone >= 1, "git clone never invoked the pinned ssh");
  // Pin the branch name instead of depending on init.defaultBranch.
  run_ok(
    &lab.topo.client,
    git(&["-C", &clone1_s, "symbolic-ref", "HEAD", "refs/heads/trunk"]),
    "git symbolic-ref",
  )
  .await?;
  std::fs::write(clone1.join("hello.txt"), "mush compat matrix\n")?;
  run_ok(
    &lab.topo.client,
    git(&["-C", &clone1_s, "add", "hello.txt"]),
    "git add",
  )
  .await?;
  run_ok(
    &lab.topo.client,
    git(&["-C", &clone1_s, "commit", "-m", "compat: seed"]),
    "git commit",
  )
  .await?;
  run_ok(
    &lab.topo.client,
    git(&["-C", &clone1_s, "push", "origin", "trunk"]),
    "git push",
  )
  .await?;
  let after_push = invocation_count(&log);
  ensure!(
    after_push > after_clone,
    "git push never invoked the pinned ssh"
  );

  let clone2_s = clone2.display().to_string();
  run_ok(
    &lab.topo.client,
    git(&["clone", "--branch", "trunk", &url, &clone2_s]),
    "git clone (verify)",
  )
  .await?;
  ensure!(
    invocation_count(&log) > after_push,
    "the verifying git clone never invoked the pinned ssh"
  );
  ensure!(
    std::fs::read_to_string(clone2.join("hello.txt"))?
      == "mush compat matrix\n",
    "cloned file content diverged"
  );
  let head1 = run_ok(
    &lab.topo.client,
    git(&["-C", &clone1_s, "rev-parse", "HEAD"]),
    "git rev-parse (clone1)",
  )
  .await?;
  let head2 = run_ok(
    &lab.topo.client,
    git(&["-C", &clone2_s, "rev-parse", "HEAD"]),
    "git rev-parse (clone2)",
  )
  .await?;
  ensure!(
    !head1.stdout.trim().is_empty() && head1.stdout == head2.stdout,
    "clone heads diverged: {} vs {}",
    head1.stdout.trim(),
    head2.stdout.trim()
  );
  lab.mush.wait_no_marked_processes().await
}

/// One forwarding-only (`-N -L`) session over the given base options:
/// waits for the forward listener (with `-N` there is no session
/// output, so the listener appearing is establishment), round-trips
/// bytes through it, SIGTERMs ssh, returns exit status and stderr.
async fn forwarding_only_run(
  lab: &Lab<Topology>,
  mut args: Vec<String>,
  local_port: u16,
) -> Result<(std::process::ExitStatus, String)> {
  args.extend(
    [
      "-N",
      "-L",
      &format!("{local_port}:127.0.0.1:7872"),
      "-o",
      "ExitOnForwardFailure=yes",
    ]
    .map(String::from),
  );
  args.push(lab.dest_ip.to_string());
  let mut child = spawn_ssh(&lab.topo.client, &args, &[])?;
  drop(child.stdin.take());
  drop(child.stdout.take());
  let stderr = drain(child.stderr.take().context("stderr piped")?);

  let local = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), local_port);
  wait_tcp_ready(&lab.topo.client, local, Duration::from_secs(30)).await?;
  let payload = pseudo_bytes(64 * 1024, 0x4e66_7764);
  let echoed =
    tcp_round_trip(&lab.topo.client, local, payload.clone(), STEP).await?;
  ensure!(echoed == payload, "forwarded channel corrupted");

  let pid = child.id().context("ssh child pid")?;
  unsafe {
    libc::kill(pid as i32, libc::SIGTERM);
  }
  let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
    .await
    .map_err(|_| anyhow::anyhow!("ssh -N survived SIGTERM past 10s"))??;
  let stderr = String::from_utf8_lossy(&t(STEP, stderr).await?).into_owned();
  Ok((status, stderr))
}

/// `ssh -N`: a forwarding-only session (no remote command) starts,
/// forwards traffic, and a SIGTERM ends it exactly as over plain TCP.
/// The signal exit is a parity claim -- OpenSSH's status for a
/// signalled `-N` session has varied across releases -- while teardown
/// of the Mush processes (detached server included) is asserted
/// absolutely.
#[tokio::test(flavor = "current_thread")]
async fn forwarding_only_session_terminates_on_signal() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let echo_addr: SocketAddr = "127.0.0.1:7872".parse()?;
  let _echo = spawn_tcp_echo(&lab.topo.dest, echo_addr).await?;

  let (tunneled, tunneled_stderr) =
    forwarding_only_run(&lab, lab.mush.ssh_opts_with(&["--no-fallback"]), 7871)
      .await?;
  ensure!(
    !tunneled_stderr.contains("falling back"),
    "the session must use QUIC, not the TCP fallback:\n{tunneled_stderr}"
  );
  // The mush-specific claim: the signal ends every Mush process.
  lab.mush.wait_no_marked_processes().await?;

  let ctrl_opts =
    vec!["-F".to_string(), lab.fix.ssh_config().display().to_string()];
  let (control, control_stderr) =
    forwarding_only_run(&lab, ctrl_opts, 7873).await?;
  use std::os::unix::process::ExitStatusExt as _;
  ensure!(
    tunneled.code() == control.code() && tunneled.signal() == control.signal(),
    "-N signal-exit parity broke: mush {tunneled:?} vs control \
     {control:?}; mush stderr:\n{tunneled_stderr}\ncontrol stderr:\n\
     {control_stderr}",
  );
  Ok(())
}

/// One session whose remote command (`exec` makes the sleep the command
/// process, whatever the login shell) is killed with SIGTERM once it
/// exists; returns the outer ssh's result. `token` must be unique per
/// run: the kill matches the sleep by its full command line.
async fn signal_death(
  lab: &Lab<Topology>,
  args: &[String],
  token: u32,
) -> Result<Exec> {
  let pattern = format!("sleep {token}");
  let mut args = args.to_vec();
  args.push(format!("exec sleep {token}"));
  let mut child = spawn_ssh(&lab.topo.client, &args, &[])?;
  drop(child.stdin.take());
  let stdout = drain(child.stdout.take().context("stdout piped")?);
  let stderr = drain(child.stderr.take().context("stderr piped")?);

  poll_until(
    "the remote sleep",
    READY,
    Duration::from_millis(100),
    || {
      let pattern = pattern.clone();
      async move { process_running(&pattern) }
    },
  )
  .await?;
  let killed = std::process::Command::new("pkill")
    .args(["-TERM", "-fx", &pattern])
    .status()
    .context("running pkill")?;
  ensure!(killed.success(), "pkill did not match the remote sleep");

  let status = t(STEP, child.wait()).await?;
  Ok(Exec {
    status,
    stdout: String::from_utf8_lossy(&t(STEP, stdout).await?).into_owned(),
    stderr: String::from_utf8_lossy(&t(STEP, stderr).await?).into_owned(),
  })
}

/// The remote session a PTY case drives: quiet the tty's echo, announce
/// itself, report its window size, then report it again on demand and
/// exit with a status the outer ssh must carry back over a tty channel.
const PTY_SCRIPT: &str = "sh -c 'stty -echo; echo READY; stty size; \
   while read line; do case \"$line\" in \
   size) stty size;; quit) exit 7;; esac; done'";

/// The window the outer ssh's pty starts at, and the one it is resized
/// to mid-session. Distinct in both dimensions so a report that changed
/// cannot have changed by half.
const PTY_START: (u16, u16) = (24, 80);
const PTY_RESIZED: (u16, u16) = (50, 132);

/// A pseudo-terminal for an outer ssh, with the master this test
/// drives. A pty master has no EOF until the last slave descriptor
/// closes, so its reads live on a detached thread appending into a
/// shared buffer the test polls; nothing here may block the runtime.
struct Pty {
  master: std::os::fd::OwnedFd,
  output: Arc<Mutex<Vec<u8>>>,
}

impl Pty {
  /// Opens a pty sized `rows` x `cols`, returning it with the slave
  /// descriptor to hand a child as its controlling terminal.
  fn open(rows: u16, cols: u16) -> Result<(Self, std::os::fd::OwnedFd)> {
    use std::os::fd::FromRawFd as _;
    let (mut master, mut slave) = (-1, -1);
    let size = winsize(rows, cols);
    let opened = unsafe {
      libc::openpty(
        &mut master,
        &mut slave,
        std::ptr::null_mut(),
        std::ptr::null(),
        &size,
      )
    };
    ensure!(opened == 0, "openpty: {}", std::io::Error::last_os_error());
    let (master, slave) = unsafe {
      (
        std::os::fd::OwnedFd::from_raw_fd(master),
        std::os::fd::OwnedFd::from_raw_fd(slave),
      )
    };
    let output = Arc::new(Mutex::new(Vec::new()));
    let reader = master.try_clone()?;
    let sink = output.clone();
    std::thread::spawn(move || {
      use std::os::fd::AsRawFd as _;
      let mut buf = [0u8; 4096];
      loop {
        let read = unsafe {
          libc::read(reader.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len())
        };
        if read <= 0 {
          return;
        }
        sink
          .lock()
          .unwrap()
          .extend_from_slice(&buf[..read as usize]);
      }
    });
    Ok((Self { master, output }, slave))
  }

  /// Everything the session has printed, carriage returns dropped.
  fn output(&self) -> String {
    String::from_utf8_lossy(&self.output.lock().unwrap()).replace('\r', "")
  }

  fn type_line(&self, line: &str) -> Result<()> {
    use std::os::fd::AsRawFd as _;
    let text = format!("{line}\n");
    let written = unsafe {
      libc::write(self.master.as_raw_fd(), text.as_ptr().cast(), text.len())
    };
    ensure!(
      written == text.len() as isize,
      "writing to the pty: {}",
      std::io::Error::last_os_error()
    );
    Ok(())
  }

  /// Resizes the terminal, which is what raises SIGWINCH in the ssh
  /// holding it and makes it send a `window-change` request.
  fn resize(&self, rows: u16, cols: u16) -> Result<()> {
    use std::os::fd::AsRawFd as _;
    let size = winsize(rows, cols);
    let set =
      unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &size) };
    ensure!(set == 0, "TIOCSWINSZ: {}", std::io::Error::last_os_error());
    Ok(())
  }

  /// Waits for `what` to appear in the session's output.
  async fn wait_for(&self, what: &str) -> Result<()> {
    poll_until(
      &format!("{what:?} on the pty"),
      STEP,
      Duration::from_millis(100),
      || async { self.output().contains(what) },
    )
    .await
    .with_context(|| format!("pty output so far:\n{}", self.output()))
  }
}

fn winsize(rows: u16, cols: u16) -> libc::winsize {
  libc::winsize {
    ws_row: rows,
    ws_col: cols,
    ws_xpixel: 0,
    ws_ypixel: 0,
  }
}

/// Runs [`PTY_SCRIPT`] over `args` on a real pty, resizing mid-session;
/// returns the two reported window sizes and the exit status.
async fn pty_session(
  lab: &Lab<Topology>,
  args: &[String],
) -> Result<(Vec<String>, std::process::ExitStatus)> {
  let (pty, slave) = Pty::open(PTY_START.0, PTY_START.1)?;
  let mut cmd = Command::new("ssh");
  cmd
    .args(args)
    .stdin(Stdio::from(slave.try_clone()?))
    .stdout(Stdio::from(slave.try_clone()?))
    .stderr(Stdio::from(slave.try_clone()?));
  // The child has to lead its own session with this pty as its
  // controlling terminal, or the resize below raises SIGWINCH at
  // nobody and ssh never sends the window-change request.
  unsafe {
    cmd.pre_exec(|| {
      if libc::setsid() < 0 {
        return Err(std::io::Error::last_os_error());
      }
      if libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
        return Err(std::io::Error::last_os_error());
      }
      Ok(())
    });
  }
  mush_testenv::harden_command(&mut cmd);
  let mut child = lab.topo.client.spawn_command(cmd)?;
  // The parent's own slave copies must go, or the pty never reports
  // the child's exit as an end of output.
  drop(slave);

  pty.wait_for("READY").await?;
  pty
    .wait_for(&format!("{} {}", PTY_START.0, PTY_START.1))
    .await?;
  pty.resize(PTY_RESIZED.0, PTY_RESIZED.1)?;
  pty.type_line("size")?;
  pty
    .wait_for(&format!("{} {}", PTY_RESIZED.0, PTY_RESIZED.1))
    .await?;
  pty.type_line("quit")?;
  let status = t(STEP, child.wait()).await?;
  let sizes: Vec<String> = pty
    .output()
    .lines()
    .filter(|line| {
      line.split_whitespace().count() == 2
        && line.split_whitespace().all(|n| n.parse::<u16>().is_ok())
    })
    .map(str::to_owned)
    .collect();
  Ok((sizes, status))
}

/// An interactive PTY session over the tunnel, the design's first goal
/// and the one SSH channel shape the rest of this matrix cannot reach:
/// every other case runs a remote command with piped stdio, leaving
/// `pty-req`, the terminal modes it carries, `window-change`, and an
/// exit status over a tty channel unexercised.
///
/// Mush knows none of that is happening -- it carries ciphertext -- so
/// the claim is parity: both runs must report the same two window sizes
/// and the same exit status.
#[tokio::test(flavor = "current_thread")]
async fn a_pty_session_matches_plain_ssh() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::with_pty(direct().await?).await?;

  let mut mush_args = lab.mush.ssh_opts_with(&["--no-fallback"]);
  mush_args.push("-tt".to_string());
  mush_args.push(lab.dest_ip.to_string());
  mush_args.push(PTY_SCRIPT.to_string());
  let mut ctrl_args = lab.fix.client_ssh_args(lab.dest_ip);
  ctrl_args.insert(ctrl_args.len() - 1, "-tt".to_string());
  ctrl_args.push(PTY_SCRIPT.to_string());

  let (control_sizes, control_status) = pty_session(&lab, &ctrl_args).await?;
  ensure!(
    control_status.code() == Some(7),
    "control run broke: a tty session exited {control_status:?}"
  );
  let expected = vec![
    format!("{} {}", PTY_START.0, PTY_START.1),
    format!("{} {}", PTY_RESIZED.0, PTY_RESIZED.1),
  ];
  ensure!(
    control_sizes == expected,
    "control run broke: window sizes {control_sizes:?}, expected {expected:?}"
  );

  let (sizes, status) = pty_session(&lab, &mush_args).await?;
  ensure!(
    sizes == control_sizes,
    "window-size parity broke: mush {sizes:?} vs control {control_sizes:?}"
  );
  ensure!(
    status.code() == control_status.code(),
    "tty exit parity broke: mush {status:?} vs control {control_status:?}"
  );
  lab.mush.wait_no_marked_processes().await
}

/// Exit fidelity: exit codes and remote-command signal death behave
/// through Mush exactly as over plain TCP, against a control run rather
/// than assumptions about OpenSSH's behavior.
#[tokio::test(flavor = "current_thread")]
async fn exit_fidelity_matches_plain_ssh() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let mush_args = lab.mush.ssh_args_with(lab.dest_ip, &["--no-fallback"]);
  let ctrl_args = lab.fix.client_ssh_args(lab.dest_ip);

  for code in [0, 1, 42] {
    let command = format!("sh -c 'exit {code}'");
    let tunneled = lab
      .fix
      .ssh_exec(&lab.topo.client, &mush_args, &command)
      .await?;
    let control = lab
      .fix
      .ssh_exec(&lab.topo.client, &ctrl_args, &command)
      .await?;
    ensure!(
      control.code == Some(code),
      "control run broke: exit {code} came back as {:?}; stderr={}",
      control.code,
      control.stderr
    );
    ensure!(
      !tunneled.stderr.contains("falling back"),
      "the session must use QUIC, not the TCP fallback:\n{}",
      tunneled.stderr
    );
    ensure!(
      tunneled.code == control.code,
      "exit {code} parity broke: mush {:?} vs control {:?}; mush stderr={}",
      tunneled.code,
      control.code,
      tunneled.stderr
    );
    ensure!(
      tunneled.stdout == control.stdout && tunneled.stderr == control.stderr,
      "exit {code} output parity broke; mush stdout={:?} stderr={:?}, \
       control stdout={:?} stderr={:?}",
      tunneled.stdout,
      tunneled.stderr,
      control.stdout,
      control.stderr
    );
  }

  let tunneled = signal_death(&lab, &mush_args, 31427).await?;
  let control = signal_death(&lab, &ctrl_args, 31429).await?;
  ensure!(
    !control.status.success(),
    "control run broke: signal death exited 0"
  );
  ensure!(
    !tunneled.stderr.contains("falling back"),
    "the session must use QUIC, not the TCP fallback:\n{}",
    tunneled.stderr
  );
  use std::os::unix::process::ExitStatusExt as _;
  ensure!(
    tunneled.status.code() == control.status.code()
      && tunneled.status.signal() == control.status.signal(),
    "signal-death parity broke: mush {:?} vs control {:?}",
    tunneled.status,
    control.status
  );
  ensure!(
    tunneled.stdout == control.stdout && tunneled.stderr == control.stderr,
    "signal-death output parity broke; mush stdout={:?} stderr={:?}, \
     control stdout={:?} stderr={:?}",
    tunneled.stdout,
    tunneled.stderr,
    control.stdout,
    control.stderr
  );
  lab.mush.wait_no_marked_processes().await
}

/// A [`phased_round_trip`] in flight: the first-phase completion
/// signal, the second-phase go-ahead, and the task to join.
struct PhasedTransfer {
  phase1_rx: tokio::sync::oneshot::Receiver<()>,
  go_tx: tokio::sync::oneshot::Sender<()>,
  task: tokio::task::JoinHandle<Result<()>>,
}

/// Starts a two-phase echo round trip against `addr` from inside `dev`
/// (through a SOCKS CONNECT to `socks_target` when given): round trip
/// `first`, report, await the go-ahead, then round trip `second` with a
/// half-close. The second phase runs during a blackhole window the test
/// opens between the signals, where the connection must stall, not die.
fn phased_round_trip(
  dev: &Device,
  addr: SocketAddr,
  socks_target: Option<SocketAddrV4>,
  first: Vec<u8>,
  second: Vec<u8>,
) -> Result<PhasedTransfer> {
  let (phase1_tx, phase1_rx) = tokio::sync::oneshot::channel();
  let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
  let task = dev.spawn(move |_| async move {
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    if let Some(target) = socks_target {
      socks5_connect(&mut stream, target).await?;
    }
    stream.write_all(&first).await?;
    let mut echoed = vec![0u8; first.len()];
    stream.read_exact(&mut echoed).await?;
    anyhow::ensure!(echoed == first, "first-phase echo corrupted");
    let _ = phase1_tx.send(());
    let _ = go_rx.await;
    stream.write_all(&second).await?;
    stream.shutdown().await?;
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await?;
    anyhow::ensure!(
      rest == second,
      "second-phase echo corrupted: {} bytes sent, {} bytes back",
      second.len(),
      rest.len()
    );
    anyhow::Ok(())
  })?;
  Ok(PhasedTransfer {
    phase1_rx,
    go_tx,
    task,
  })
}

/// Blackholes the client's uplink for `window` around the go-ahead of
/// an armed [`phased_round_trip`], then joins it: the forwarded
/// connection's second phase must survive the outage and complete.
async fn blackhole_second_phase(
  lab: &Lab<Topology>,
  transfer: PhasedTransfer,
  window: Duration,
) -> Result<()> {
  let PhasedTransfer {
    phase1_rx,
    go_tx,
    task,
  } = transfer;
  t(STEP, phase1_rx)
    .await
    .context("waiting for the first-phase round trip")?;
  let iface = lab.topo.client.iface("eth0").context("client eth0")?;
  iface
    .set_condition(LinkCondition::new().loss_pct(100.0), LinkDirection::Both)
    .await?;
  let _ = go_tx.send(());
  tokio::time::sleep(window).await;
  iface.clear_condition(LinkDirection::Both).await?;
  t(STEP, task).await?
}

/// `-R` under stress: an established reverse-forwarded connection with
/// a 10s blackhole mid-transfer. Carried by the tunnel, it must stall and
/// resume, not die, and the session carrying it must stay healthy.
#[tokio::test(flavor = "current_thread")]
async fn remote_forward_survives_blackhole_window() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let echo_addr: SocketAddr = "127.0.0.1:7952".parse()?;
  let _echo = spawn_tcp_echo(&lab.topo.client, echo_addr).await?;

  let mut session = forwarding_session(
    &lab,
    Forward::Remote(7951, 7952),
    &lab.topo.dest,
    "rfwd-up",
  )
  .await?;
  let remote: SocketAddr = "127.0.0.1:7951".parse()?;

  let transfer = phased_round_trip(
    &lab.topo.dest,
    remote,
    None,
    pseudo_bytes(64 * 1024, 0x5262_6801),
    pseudo_bytes(256 * 1024, 0x5262_6802),
  )?;
  blackhole_second_phase(&lab, transfer, Duration::from_secs(10)).await?;

  // The carrying session must have survived it too.
  session.echo("post-outage").await?;
  session.close().await?;
  lab.mush.wait_no_marked_processes().await
}

/// `-D` under stress: the [`remote_forward_survives_blackhole_window`]
/// claim for a dynamically forwarded connection.
#[tokio::test(flavor = "current_thread")]
async fn dynamic_forward_survives_blackhole_window() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let echo_addr: SocketAddr = "127.0.0.1:7962".parse()?;
  let _echo = spawn_tcp_echo(&lab.topo.dest, echo_addr).await?;

  let mut session = forwarding_session(
    &lab,
    Forward::Dynamic(7961),
    &lab.topo.client,
    "socks-up",
  )
  .await?;
  let socks: SocketAddr = "127.0.0.1:7961".parse()?;

  let transfer = phased_round_trip(
    &lab.topo.client,
    socks,
    Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7962)),
    pseudo_bytes(64 * 1024, 0x4466_6801),
    pseudo_bytes(256 * 1024, 0x4466_6802),
  )?;
  blackhole_second_phase(&lab, transfer, Duration::from_secs(10)).await?;

  session.echo("post-outage").await?;
  session.close().await?;
  lab.mush.wait_no_marked_processes().await
}

/// Forwarded-connection churn: 60 short-lived connections through a
/// dynamic forward. Channel churn lives entirely inside the multiplexed
/// SSH byte stream, so the Mush relay holds no per-connection state:
/// both Mush processes' fd counts must end where they started, the same
/// server must still serve, and the session must stay healthy.
#[tokio::test(flavor = "current_thread")]
async fn dynamic_forward_connection_churn_leaks_nothing() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = Lab::new(direct().await?).await?;
  let echo_addr: SocketAddr = "127.0.0.1:7972".parse()?;
  let _echo = spawn_tcp_echo(&lab.topo.dest, echo_addr).await?;

  let session = forwarding_session(
    &lab,
    Forward::Dynamic(7971),
    &lab.topo.client,
    "churn-up",
  )
  .await?;
  let socks: SocketAddr = "127.0.0.1:7971".parse()?;

  let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7972);
  let client = &lab.topo.client;
  let round_trip = |seed: u64| {
    let payload = pseudo_bytes(4 * 1024, seed);
    async move {
      let echoed =
        socks5_round_trip(client, socks, target, payload.clone()).await?;
      ensure!(
        echoed == payload,
        "SOCKS round trip corrupted at seed {seed:#x}"
      );
      Ok(())
    }
  };
  // Settle the session, then baseline the Mush processes' fd usage.
  round_trip(0x6368_0000).await?;
  let marker = lab.mush.marker().to_string();
  let server = the_marked_server(&marker)?;
  let connects = marked_mush_pids(&marker, "connect");
  ensure!(
    connects.len() == 1,
    "expected exactly one mush connect, saw pids {connects:?}"
  );
  let connect = connects[0];
  let server_fds = fd_count(server).context("server fd count")?;
  let connect_fds = fd_count(connect).context("connect fd count")?;

  for i in 1..=60u64 {
    round_trip(0x6368_0000 + i).await?;
  }

  ensure!(
    marked_server_count(&marker) == 1,
    "the server must have survived the churn alone"
  );
  // Closed connections may settle asynchronously; poll to the baseline.
  poll_until(
    "fd counts to settle back to the baseline",
    Duration::from_secs(10),
    Duration::from_millis(200),
    || async {
      fd_count(server).is_some_and(|now| now <= server_fds)
        && fd_count(connect).is_some_and(|now| now <= connect_fds)
    },
  )
  .await
  .with_context(|| {
    format!(
      "fd leak: server {} -> {:?}, connect {} -> {:?}",
      server_fds,
      fd_count(server),
      connect_fds,
      fd_count(connect)
    )
  })?;

  round_trip(0x6368_ffff).await?;
  session.close().await?;
  lab.mush.wait_no_marked_processes().await
}
