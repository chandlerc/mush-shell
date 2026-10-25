// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Loopback tests of the `mush` binary: no real ssh, no sshd.
//! A TCP echo server plays sshd, and `--ssh` substitutes a script that
//! runs `mush server bootstrap` locally in place of the bootstrap ssh.
//!
//! Hermetic: every port is bound at 0 and discovered, and detached
//! servers are tracked by a unique argv marker (`--marker`) so leaks
//! are caught with pgrep.

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use mush_core::bootstrap::{
  Connect, ConnectScanner, Hello, PROTOCOL_VERSION, ScanLimits, SessionNonce,
  SessionSecret, Signal,
};
use mush_core::pinning::{self, KeyPin, SessionIdentity};
use mush_core::server::MAX_ADDR_HINTS;
use mush_core::transport::TransportOptions;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};

mod common;

use common::{MUSH_BIN, MarkerGuard, assert_marker_gone, marker_pids, t};

/// What the echo "sshd" appends after client EOF, proving the EOF
/// crossed and the return path still delivers after it.
const TAIL: &[u8] = b"|TAIL";

fn unique_marker(name: &str) -> String {
  common::unique_marker("mush-loopback", name)
}

/// Binds the echo "sshd" on a fresh loopback port: echoes every byte,
/// and on client EOF writes [`TAIL`] and half-closes.
async fn spawn_echo_sshd() -> Result<(u16, tokio::task::JoinHandle<()>)> {
  let listener = TcpListener::bind("127.0.0.1:0").await?;
  let port = listener.local_addr()?.port();
  let task = tokio::spawn(async move {
    while let Ok((mut socket, _)) = listener.accept().await {
      tokio::spawn(async move {
        let _ = socket.set_nodelay(true);
        let (mut read, mut write) = socket.split();
        let mut buf = [0u8; 4096];
        loop {
          match read.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
              if write.write_all(&buf[..n]).await.is_err() {
                return;
              }
            }
            Err(_) => return,
          }
        }
        let _ = write.write_all(TAIL).await;
        let _ = write.shutdown().await;
      });
    }
  });
  Ok((port, task))
}

/// Writes an executable helper script.
fn write_script(dir: &Path, name: &str, body: &str) -> Result<PathBuf> {
  let path = dir.join(name);
  std::fs::write(&path, body)?;
  let mut permissions = std::fs::metadata(&path)?.permissions();
  permissions.set_mode(0o755);
  std::fs::set_permissions(&path, permissions)?;
  Ok(path)
}

/// The `$SSH_CONNECTION` every fake bootstrap ssh exports for the
/// server it runs, naming the loopback address a real ssh would have
/// arrived on. Set explicitly rather than inherited: it fixes the
/// leading address hint at loopback whatever the machine's interfaces
/// look like (the server hints those too, and the client races them
/// behind the leader), which is what a real session sees.
const FAKE_SSH_CONNECTION: &str =
  "SSH_CONNECTION='127.0.0.1 40000 127.0.0.1 22'\nexport SSH_CONNECTION\n";

/// Fake-ssh preamble refusing the two side channels a jumped session
/// opens: the jump helper's, and the plain shell probe that recovers
/// this client's address from the jump. These fakes stand in for the
/// bootstrap ssh alone, and refusing is exactly the design's "no helper
/// on the bastion" degradation, which every `-J` test here runs under.
const FAKE_SSH_NO_SIDE_CHANNELS: &str =
  "case \"$*\" in *jump-helper*|*SSH_CONNECTION*) exit 1;; esac\n";

/// A `--ssh` stand-in that ignores the ssh arguments and runs the real
/// Mush server on this host.
fn server_helper(dir: &Path, marker: &str, no_detach: bool) -> Result<PathBuf> {
  server_helper_with(dir, marker, no_detach, "")
}

/// [`server_helper`] with extra `mush server bootstrap` arguments
/// (leading space included, e.g. `" --retain 5s"`).
fn server_helper_with(
  dir: &Path,
  marker: &str,
  no_detach: bool,
  extra: &str,
) -> Result<PathBuf> {
  let no_detach = if no_detach { " --no-detach" } else { "" };
  write_script(
    dir,
    "fake-ssh",
    &format!(
      "#!/bin/sh\n{FAKE_SSH_NO_SIDE_CHANNELS}{FAKE_SSH_CONNECTION}\
       exec '{MUSH_BIN}' server bootstrap{no_detach}{extra} \
       --marker '{marker}'\n"
    ),
  )
}

/// The environment and stdio every `mush connect` here shares: piped
/// stdio, and a scrub of everything that would otherwise affect the
/// bootstrap. Callers append the flags under test, then the destination.
fn connect_base() -> Command {
  let mut command = Command::new(MUSH_BIN);
  command
    .arg("connect")
    .env_remove("SSH_CONNECTION")
    .env_remove("MUSH_BOOTSTRAP_SSH_ARGS")
    .env_remove("MUSH_CONNECT_SSH")
    .env_remove("MUSH_CONNECT_SERVER")
    .env_remove("MUSH_CONNECT_HELPER")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true);
  command
}

/// `mush connect` against a helper script named by `--ssh`.
fn connect_command(helper: &Path, target_port: u16, extra: &[&str]) -> Command {
  let mut command = connect_base();
  command.arg("--ssh").arg(helper).args(extra).args([
    "testuser",
    "127.0.0.1",
    &target_port.to_string(),
  ]);
  command
}

/// Drains a stream in the background (a full stderr pipe must never
/// block the child).
fn drain<R: AsyncRead + Unpin + Send + 'static>(
  mut stream: R,
) -> tokio::task::JoinHandle<Vec<u8>> {
  tokio::spawn(async move {
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    buf
  })
}

/// Spawns `mush server bootstrap` directly, as a bootstrap ssh runs it,
/// with its stderr draining in the background so a failure reports it.
fn spawn_bootstrap(
  marker: &str,
) -> Result<(Child, tokio::task::JoinHandle<Vec<u8>>)> {
  let mut child = Command::new(MUSH_BIN)
    .args(["server", "bootstrap", "--marker", marker])
    .env("SSH_CONNECTION", "203.0.113.5 40000 127.0.0.1 22")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true)
    .spawn()?;
  let stderr = drain(child.stderr.take().context("stderr piped")?);
  Ok((child, stderr))
}

/// Waits for the bootstrap parent to exit, reporting stderr if it failed.
async fn parent_exited_cleanly(
  child: &mut Child,
  stderr: tokio::task::JoinHandle<Vec<u8>>,
) -> Result<()> {
  let status = t(child.wait()).await?;
  let stderr = t(stderr).await?;
  ensure!(
    status.success(),
    "server parent failed ({status}); stderr:\n{}",
    String::from_utf8_lossy(&stderr)
  );
  Ok(())
}

/// A live session over the library client against a detached server,
/// held open so the caller decides when it ends.
struct Roundtrip {
  endpoint: quinn::Endpoint,
  connection: quinn::Connection,
  send: quinn::SendStream,
  recv: quinn::RecvStream,
}

/// Opens a pinned session at `server_addr` and proves it echoes.
async fn quic_roundtrip(
  identity: &SessionIdentity,
  server_key: KeyPin,
  server_addr: SocketAddr,
) -> Result<Roundtrip> {
  let config =
    pinning::client_config(identity, server_key, &TransportOptions::default())?;
  let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
  let connection =
    t(endpoint.connect_with(config, server_addr, "mush")?).await?;
  let (mut send, mut recv) = t(connection.open_bi()).await?;
  t(send.write_all(b"roundtrip")).await?;
  let mut buf = [0u8; 9];
  t(recv.read_exact(&mut buf)).await?;
  ensure!(&buf == b"roundtrip", "unexpected echo {buf:?}");
  Ok(Roundtrip {
    endpoint,
    connection,
    send,
    recv,
  })
}

impl Roundtrip {
  /// Ends the session and checks the [`TAIL`], which proves the
  /// half-close crossed the echo sshd.
  async fn finish(mut self) -> Result<()> {
    self.send.finish()?;
    let tail = t(self.recv.read_to_end(1024)).await?;
    ensure!(tail == TAIL, "unexpected tail {tail:?}");
    self.connection.close(0u32.into(), b"done");
    t(self.endpoint.wait_idle()).await;
    Ok(())
  }
}

/// Drives one echo session through a spawned `mush connect` that must
/// use the tunnel. Returns the child's stderr.
async fn drive_echo_session(child: &mut Child) -> Result<Vec<u8>> {
  let stderr = drive_any_echo_session(child).await?;
  // The TCP fallback carries this echo exactly as the tunnel does, so
  // without this any session could have quietly used it, and the
  // stranded server the marker sweep catches points nowhere near the cause.
  let text = String::from_utf8_lossy(&stderr);
  ensure!(
    !text.contains("falling back"),
    "the session fell back to TCP instead of using the tunnel:\n{text}"
  );
  Ok(stderr)
}

/// Drives a `mush connect` that must fail cleanly, this crate's
/// diagnosis contract: no session bytes reach stdout, a nonzero exit,
/// and stderr saying what went wrong (`must_say`) without reading as
/// another failure mode (`must_not_say`). stdin is dropped unless the
/// caller took it, which a session that must reach the server first
/// does (the server dials sshd only once the stream carries bytes).
async fn expect_clean_failure(
  mut child: Child,
  must_say: &[&str],
  must_not_say: &[&str],
) -> Result<()> {
  let stderr = drain(child.stderr.take().context("stderr piped")?);
  let mut stdout = child.stdout.take().context("stdout piped")?;
  drop(child.stdin.take());

  let mut out = Vec::new();
  t(stdout.read_to_end(&mut out)).await?;
  let status = t(child.wait()).await?;
  let stderr = String::from_utf8_lossy(&t(stderr).await?).into_owned();
  ensure!(out.is_empty(), "bytes reached stdout: {out:?}\n{stderr}");
  ensure!(!status.success(), "the session succeeded:\n{stderr}");
  for text in must_say {
    ensure!(stderr.contains(text), "stderr omits {text:?}:\n{stderr}");
  }
  for text in must_not_say {
    ensure!(!stderr.contains(text), "stderr says {text:?}:\n{stderr}");
  }
  Ok(())
}

/// [`drive_echo_session`] without the tunnel requirement, for the
/// tests of the fallback order itself: duplex echo, stdin EOF, then the
/// tail.
async fn drive_any_echo_session(child: &mut Child) -> Result<Vec<u8>> {
  let mut stdin = child.stdin.take().context("stdin piped")?;
  let mut stdout = child.stdout.take().context("stdout piped")?;
  let stderr = drain(child.stderr.take().context("stderr piped")?);

  t(stdin.write_all(b"ping-1")).await?;
  let mut buf = [0u8; 6];
  t(stdout.read_exact(&mut buf)).await?;
  assert_eq!(&buf, b"ping-1");
  t(stdin.write_all(b"second-ping")).await?;
  let mut buf = [0u8; 11];
  t(stdout.read_exact(&mut buf)).await?;
  assert_eq!(&buf, b"second-ping");

  // Half-close: our EOF must reach the far TCP side while the return
  // path keeps delivering (the echo tail).
  drop(stdin);
  let mut tail = Vec::new();
  t(stdout.read_to_end(&mut tail)).await?;
  assert_eq!(tail, TAIL);

  let status = t(child.wait()).await?;
  let stderr = t(stderr).await?;
  ensure!(
    status.success(),
    "mush connect failed ({status}); stderr:\n{}",
    String::from_utf8_lossy(&stderr)
  );
  Ok(stderr)
}

/// Runs one whole echo session over the tunnel: the real `mush connect`
/// against a fake bootstrap ssh that starts the real server on this
/// host, then the marker sweep that proves the server went with it.
async fn run_echo_session(
  name: &str,
  no_detach: bool,
  extra: &[&str],
) -> Result<()> {
  let (echo_port, _echo) = spawn_echo_sshd().await?;
  let dir = tempfile::tempdir()?;
  let marker = unique_marker(name);
  let _guard = MarkerGuard::new(&marker);
  let helper = server_helper(dir.path(), &marker, no_detach)?;
  let mut child = connect_command(&helper, echo_port, extra).spawn()?;
  drive_echo_session(&mut child).await?;
  assert_marker_gone(&marker).await;
  Ok(())
}

#[tokio::test]
async fn tunnel_echoes_and_half_closes_foreground_server() -> Result<()> {
  run_echo_session("fg", true, &[]).await
}

#[tokio::test]
async fn tunnel_works_with_detached_server() -> Result<()> {
  // The detached server must not outlive the session it served.
  run_echo_session("detach", false, &[]).await
}

/// A destination whose public ssh port is not the port sshd listens on
/// (the design's remapped-port sharp edge: public 2222 forwarded to
/// internal 22). The client announces ssh's own `%p`, which is the port
/// it dialed, so the deployment says what the real one is on the server
/// side: `--server 'mush server bootstrap --target 22'`.
#[tokio::test]
async fn a_server_side_target_overrides_the_announced_port() -> Result<()> {
  let (echo_port, _echo) = spawn_echo_sshd().await?;
  let dir = tempfile::tempdir()?;
  let marker = unique_marker("target");
  let _guard = MarkerGuard::new(&marker);
  let helper = server_helper_with(
    dir.path(),
    &marker,
    false,
    &format!(" --target {echo_port}"),
  )?;
  // A `%p` that names nothing: without the override this session
  // cannot reach the echo "sshd" at all.
  let unused_port = {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    listener.local_addr()?.port()
  };
  let mut child = connect_command(&helper, unused_port, &[]).spawn()?;
  drive_echo_session(&mut child).await?;
  assert_marker_gone(&marker).await;
  Ok(())
}

/// Without the override the same mismatch is a clean, diagnosed failure
/// rather than a hang: the server's close reason reaches the user.
#[tokio::test]
async fn an_unreachable_target_port_reports_what_it_could_not_reach()
-> Result<()> {
  let dir = tempfile::tempdir()?;
  let marker = unique_marker("notarget");
  let _guard = MarkerGuard::new(&marker);
  let helper = server_helper(dir.path(), &marker, false)?;
  let unused_port = {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    listener.local_addr()?.port()
  };
  let child =
    connect_command(&helper, unused_port, &["--no-fallback"]).spawn()?;
  expect_clean_failure(child, &[&format!("127.0.0.1:{unused_port}")], &[])
    .await?;
  assert_marker_gone(&marker).await;
  Ok(())
}

/// ssh SIGHUPs its ProxyCommand when it exits (OpenSSH's
/// `ssh_kill_proxy_command`), concurrently with closing the stdio pipes.
/// The client must survive the signal and drain the relay tail -- ssh's
/// final bytes (its disconnect, in production), the FIN, and the
/// connection close -- or the detached server never learns the session
/// ended and lingers forever, retention being indefinite by default.
#[tokio::test]
async fn sighup_at_ssh_exit_still_tears_down_cleanly() -> Result<()> {
  let (echo_port, _echo) = spawn_echo_sshd().await?;
  let dir = tempfile::tempdir()?;
  let marker = unique_marker("hup");
  let _guard = MarkerGuard::new(&marker);
  let helper = server_helper(dir.path(), &marker, false)?;
  let mut child = connect_command(&helper, echo_port, &[]).spawn()?;
  let mut stdin = child.stdin.take().context("stdin piped")?;
  let mut stdout = child.stdout.take().context("stdout piped")?;
  let stderr = drain(child.stderr.take().context("stderr piped")?);

  t(stdin.write_all(b"final-bytes")).await?;
  let mut buf = [0u8; 11];
  t(stdout.read_exact(&mut buf)).await?;
  assert_eq!(&buf, b"final-bytes");

  // ssh's exit sequence: SIGHUP to the proxy, pipes closed.
  let pid = child.id().context("child already reaped")? as i32;
  unsafe {
    libc::kill(pid, libc::SIGHUP);
  }
  drop(stdin);

  // The return path still drains: the echo tail proves our EOF crossed
  // to the far TCP side and the relay outlived the signal.
  let mut tail = Vec::new();
  t(stdout.read_to_end(&mut tail)).await?;
  assert_eq!(tail, TAIL);
  let status = t(child.wait()).await?;
  let stderr = t(stderr).await?;
  ensure!(
    status.success(),
    "mush connect failed ({status}); stderr:\n{}",
    String::from_utf8_lossy(&stderr)
  );
  // The clean close reached the server, so it exits instead of
  // retaining a session whose client is gone.
  assert_marker_gone(&marker).await;
  Ok(())
}

/// The reverse half-close: the far side closes first while our stdin
/// stays open. The remote EOF must reach the outer ssh (the test) as a
/// real close of the client's stdout -- the contract
/// `tokio::io::stdout()` cannot honor, and the reason for the owned-fd
/// stdio wrapper -- while the outbound direction keeps relaying.
#[tokio::test]
async fn remote_close_reaches_stdout_while_stdin_open() -> Result<()> {
  // A "sshd" that speaks first and half-closes immediately, then
  // drains whatever the client sends.
  let listener = TcpListener::bind("127.0.0.1:0").await?;
  let port = listener.local_addr()?.port();
  let _server = tokio::spawn(async move {
    while let Ok((mut socket, _)) = listener.accept().await {
      tokio::spawn(async move {
        let (mut read, mut write) = socket.split();
        let _ = write.write_all(b"BANNER").await;
        let _ = write.shutdown().await;
        let mut sink = [0u8; 4096];
        while matches!(read.read(&mut sink).await, Ok(n) if n > 0) {}
      });
    }
  });

  let dir = tempfile::tempdir()?;
  let marker = unique_marker("reveof");
  let _guard = MarkerGuard::new(&marker);
  let helper = server_helper(dir.path(), &marker, true)?;
  let mut child = connect_command(&helper, port, &[]).spawn()?;
  let mut stdin = child.stdin.take().context("stdin piped")?;
  let mut stdout = child.stdout.take().context("stdout piped")?;
  let stderr = drain(child.stderr.take().context("stderr piped")?);

  // The ssh client banner's analogue: QUIC opens streams lazily, so the
  // server reaches sshd only once the client's first stream bytes arrive.
  t(stdin.write_all(b"early")).await?;

  // The banner and its EOF arrive while our stdin is still open; a stdout
  // shutdown not truly closing the pipe would hang this read forever.
  let mut banner = Vec::new();
  t(stdout.read_to_end(&mut banner)).await?;
  assert_eq!(banner, b"BANNER");

  // The outbound direction still relays after the inbound one ended.
  t(stdin.write_all(b"late bytes")).await?;
  drop(stdin);
  let status = t(child.wait()).await?;
  let stderr = t(stderr).await?;
  ensure!(
    status.success(),
    "mush connect failed ({status}); stderr:\n{}",
    String::from_utf8_lossy(&stderr)
  );
  assert_marker_gone(&marker).await;
  Ok(())
}

/// The server binary's detach lifecycle, driven directly: hello in,
/// connect line out, the parent (the "bootstrap ssh") exits promptly, and
/// the detached child serves a full session and exits with it.
#[tokio::test]
async fn server_bootstrap_detaches_and_serves() -> Result<()> {
  let (echo_port, _echo) = spawn_echo_sshd().await?;
  let marker = unique_marker("direct");
  let _guard = MarkerGuard::new(&marker);
  let identity = SessionIdentity::generate()?;
  let (mut child, stderr) = spawn_bootstrap(&marker)?;

  let hello = Hello {
    version: PROTOCOL_VERSION,
    client_key: identity.pin(),
    target_port: echo_port,
    nonce: None,
  };
  let mut stdin = child.stdin.take().context("stdin piped")?;
  t(stdin.write_all(hello.to_wire().as_bytes())).await?;

  // The connect line arrives on real stdout, carrying the gathered
  // candidates: the SSH_CONNECTION-derived address leads, then this
  // machine's own interfaces (whatever they are here).
  let mut stdout = child.stdout.take().context("stdout piped")?;
  let (connect, _) = read_connect_line(&mut stdout).await?;
  assert_eq!(connect.version, PROTOCOL_VERSION);
  let server_addr: SocketAddr =
    format!("127.0.0.1:{}", connect.udp_port).parse()?;
  let hints = &connect.addr_hints;
  assert_eq!(hints.first(), Some(&server_addr));
  assert!(hints.len() <= MAX_ADDR_HINTS, "hints: {hints:?}");
  for (index, hint) in hints.iter().enumerate() {
    assert_eq!(hint.port(), connect.udp_port, "hints: {hints:?}");
    assert!(!hints[..index].contains(hint), "hints: {hints:?}");
    // Loopback is the SSH_CONNECTION address here, never enumerated.
    assert!(index == 0 || !hint.ip().is_loopback(), "hints: {hints:?}");
  }

  // The parent exits promptly (this is what lets the bootstrap ssh
  // finish) while the detached child stays.
  parent_exited_cleanly(&mut child, stderr).await?;
  assert!(!marker_pids(&marker).is_empty(), "no detached child found");

  // A hello with no nonce asks for no signaling, so the detach takes the
  // channel with it: with nothing holding the write end, the bootstrap
  // ssh ends immediately -- the timing every no-jump session depends on.
  let mut tail = Vec::new();
  t(stdout.read_to_end(&mut tail)).await?;
  assert_eq!(
    tail, b"",
    "the detached server held the bootstrap channel open"
  );

  quic_roundtrip(&identity, connect.server_key, server_addr)
    .await?
    .finish()
    .await?;
  assert_marker_gone(&marker).await;
  Ok(())
}

/// The other half of the detach lifecycle: a hello announcing a session
/// nonce asks for the bootstrap channel to stay open, so the detached
/// server keeps stdio on the ssh channel through path establishment,
/// leaving the process sshd waits on in place (design doc, "Signaling";
/// sshd stops feeding a command's stdin the moment the command exits, so
/// both halves are needed to signal both ways). It answers with its
/// terminator once detached -- long before any path can come up, so a
/// client never waits on it -- reads what the client signals, and lets
/// both go once the path settles, which finally ends the bootstrap ssh.
#[tokio::test]
async fn server_bootstrap_signals_before_closing_the_channel() -> Result<()> {
  let (echo_port, _echo) = spawn_echo_sshd().await?;
  let marker = unique_marker("signal");
  let _guard = MarkerGuard::new(&marker);
  let identity = SessionIdentity::generate()?;
  let nonce = SessionNonce::generate()?;
  let (mut child, stderr) = spawn_bootstrap(&marker)?;

  let hello = Hello {
    version: PROTOCOL_VERSION,
    client_key: identity.pin(),
    target_port: echo_port,
    nonce: Some(nonce),
  };
  let mut stdin = child.stdin.take().context("stdin piped")?;
  t(stdin.write_all(hello.to_wire().as_bytes())).await?;

  let mut stdout = child.stdout.take().context("stdout piped")?;
  let (connect, mut leftover) = read_connect_line(&mut stdout).await?;
  let server_addr: SocketAddr =
    format!("127.0.0.1:{}", connect.udp_port).parse()?;

  // The channel is alive past the detach both ways: the destination reads
  // the client's terminator and answers with its own, and the process sshd
  // would wait on is still there to keep the inbound direction open.
  let done = Signal::done(nonce);
  t(stdin.write_all(done.to_wire().as_bytes())).await?;
  let line = read_signal_line(&mut stdout, &mut leftover).await?;
  let signal = Signal::parse(&line)?.context("not a signaling line")?;
  assert_eq!(signal.nonce(), nonce, "signal: {line}");
  assert!(matches!(signal, Signal::Done(_)), "signal: {line}");
  assert!(
    child.try_wait()?.is_none(),
    "the remote command exited, which closes the client's direction"
  );

  // A helper the destination cannot reach: it probes, gives up, and
  // carries on serving rather than failing the session over it.
  let helper = Signal::helper(
    nonce,
    "198.51.100.7:9999".parse()?,
    SessionSecret::generate()?,
  );
  t(stdin.write_all(helper.to_wire().as_bytes())).await?;

  let session =
    quic_roundtrip(&identity, connect.server_key, server_addr).await?;

  // Path settled: the channel closes and the remote command finishes,
  // so the bootstrap ssh ends while the session runs on.
  parent_exited_cleanly(&mut child, stderr).await?;
  let mut tail = Vec::new();
  t(stdout.read_to_end(&mut tail)).await?;
  assert_eq!(
    tail, b"",
    "the destination kept signaling after the path settled"
  );

  session.finish().await?;
  assert_marker_gone(&marker).await;
  Ok(())
}

/// A jumped session drives the whole signaling phase through the real
/// binaries: `mush connect` generates a nonce because a jump is
/// configured, the destination holds the channel open for it, and the
/// tunnel behaves as an unjumped one does. The fake bootstrap ssh
/// ignores `-J`, so only Mush's own behavior is under test.
#[tokio::test]
async fn jumped_session_signals_and_still_relays() -> Result<()> {
  run_echo_session("jumpsig", false, &["-J", "bastion"]).await
}

/// The wrapper's variables are consumed by this process and must not
/// travel further: a nested `mush connect` under the bootstrap ssh -- a
/// jump hop whose host also resolves through a Mush ProxyCommand --
/// would otherwise apply values meant for this destination to a
/// different host, and `--helper` names a command to run on a bastion.
#[tokio::test]
async fn the_wrappers_variables_do_not_reach_the_bootstrap_ssh() -> Result<()> {
  let (echo_port, _echo) = spawn_echo_sshd().await?;
  let dir = tempfile::tempdir()?;
  let marker = unique_marker("envscrub");
  let _guard = MarkerGuard::new(&marker);
  let log = dir.path().join("env");
  let helper = write_script(
    dir.path(),
    "fake-ssh",
    &format!(
      "#!/bin/sh\n{FAKE_SSH_NO_SIDE_CHANNELS}{FAKE_SSH_CONNECTION}\
       env | grep '^MUSH_' > '{}'\n\
       exec '{MUSH_BIN}' server bootstrap --marker '{marker}'\n",
      log.display()
    ),
  )?;
  let mut child = connect_command(&helper, echo_port, &["-J", "bastion"])
    .env("MUSH_BOOTSTRAP_SSH_ARGS", "-i\x1fkey")
    .env("MUSH_CONNECT_SSH", "ssh")
    .env("MUSH_CONNECT_SERVER", "mush server bootstrap")
    .env("MUSH_CONNECT_HELPER", "mush jump-helper")
    .spawn()?;
  drive_echo_session(&mut child).await?;
  let leaked = std::fs::read_to_string(&log).unwrap_or_default();
  assert_eq!(
    leaked.trim(),
    "",
    "the bootstrap ssh inherited the wrapper's variables:\n{leaked}"
  );
  assert_marker_gone(&marker).await;
  Ok(())
}

/// A bastion that answers its ssh and then says nothing must not hold up
/// a session that no longer needs it. The helper's opening conversation
/// has a minute to complete, but the client shuts the helper down the
/// moment a kind of path that does not need it wins, immediately for a
/// reachable destination. Waiting out the opening would stall the
/// session's first byte behind a bastion it had already given up on.
#[tokio::test]
async fn a_silent_jump_helper_does_not_delay_the_session() -> Result<()> {
  let (echo_port, _echo) = spawn_echo_sshd().await?;
  let dir = tempfile::tempdir()?;
  let marker = unique_marker("silentjump");
  let _guard = MarkerGuard::new(&marker);
  // The helper's channel is answered and then goes silent forever; the
  // shell probe is refused, as a bastion without `mush` would refuse it.
  let helper = write_script(
    dir.path(),
    "fake-ssh",
    &format!(
      "#!/bin/sh\n\
       case \"$*\" in\n\
       \x20 *jump-helper*) exec sleep 300;;\n\
       \x20 *SSH_CONNECTION*) exit 1;;\n\
       esac\n{FAKE_SSH_CONNECTION}\
       exec '{MUSH_BIN}' server bootstrap --marker '{marker}'\n"
    ),
  )?;
  let mut child =
    connect_command(&helper, echo_port, &["-J", "bastion"]).spawn()?;
  let started = std::time::Instant::now();
  drive_echo_session(&mut child).await?;
  let elapsed = started.elapsed();
  assert!(
    elapsed < Duration::from_secs(20),
    "the session waited {elapsed:?} on a helper it had finished with"
  );
  assert_marker_gone(&marker).await;
  Ok(())
}

/// What turns signaling on is the jump and nothing else: `mush connect`
/// generates a session nonce only for a jumped session, and the hello's
/// nonce is what the destination decides its detach by. A plain
/// session's hello is therefore the line it was before signaling
/// existed, which is the whole no-jump guarantee.
#[tokio::test]
async fn only_a_jumped_session_announces_a_nonce() -> Result<()> {
  let (echo_port, _echo) = spawn_echo_sshd().await?;
  let dir = tempfile::tempdir()?;
  for (extra, jumped) in [(&[][..], false), (&["-J", "bastion"][..], true)] {
    let marker = unique_marker("hellowire");
    let _guard = MarkerGuard::new(&marker);
    let log = dir.path().join(format!("hello-{jumped}"));
    // Capture the hello line, then hand it and everything behind it to
    // the real server so the session runs exactly as it otherwise would.
    let helper = write_script(
      dir.path(),
      "fake-ssh",
      &format!(
        "#!/bin/sh\n{FAKE_SSH_NO_SIDE_CHANNELS}{FAKE_SSH_CONNECTION}\
         IFS= read -r hello\n\
         printf '%s\\n' \"$hello\" > '{}'\n\
         {{ printf '%s\\n' \"$hello\"; cat; }} | \
         '{MUSH_BIN}' server bootstrap --marker '{marker}'\n",
        log.display()
      ),
    )?;
    let mut child = connect_command(&helper, echo_port, extra).spawn()?;
    drive_echo_session(&mut child).await?;
    let line = std::fs::read_to_string(&log)?;
    let hello = Hello::parse(line.trim_end())?;
    assert_eq!(
      hello.nonce.is_some(),
      jumped,
      "wrong signaling intent for {extra:?}: {line}"
    );
    assert_marker_gone(&marker).await;
  }
  Ok(())
}

/// Reads the `MUSH CONNECT` line from a server's stdout with the bytes
/// read past it, the handoff point the signaling phase resumes from.
async fn read_connect_line<R: AsyncRead + Unpin>(
  stdout: &mut R,
) -> Result<(Connect, Vec<u8>)> {
  let mut scanner = ConnectScanner::new(ScanLimits::default());
  loop {
    let mut buf = [0u8; 4096];
    let n = t(stdout.read(&mut buf)).await?;
    ensure!(n > 0, "server stdout closed before MUSH CONNECT");
    if let Some((connect, consumed)) = scanner.push(&buf[..n])? {
      return Ok((connect, buf[consumed..n].to_vec()));
    }
  }
}

/// Reads one line from `leftover`, refilling it from `stdout`.
async fn read_signal_line<R: AsyncRead + Unpin>(
  stdout: &mut R,
  leftover: &mut Vec<u8>,
) -> Result<String> {
  loop {
    if let Some(newline) = leftover.iter().position(|&b| b == b'\n') {
      let line: Vec<u8> = leftover.drain(..=newline).collect();
      return Ok(String::from_utf8(line[..newline].to_vec())?);
    }
    let mut buf = [0u8; 4096];
    let n = t(stdout.read(&mut buf)).await?;
    ensure!(n > 0, "server stdout closed before the signaling line");
    leftover.extend_from_slice(&buf[..n]);
  }
}

#[tokio::test]
async fn bootstrap_that_never_speaks_mush_fails_cleanly() -> Result<()> {
  let dir = tempfile::tempdir()?;
  // Consume the hello (as a real remote command would) before the
  // garbage, so the client fails on the scan, not on a broken pipe.
  let helper = write_script(
    dir.path(),
    "fake-ssh",
    &format!(
      "#!/bin/sh\n{FAKE_SSH_NO_SIDE_CHANNELS}read -r _hello\n\
       echo 'Welcome to nowhere'\necho 'not mush'\nexit 3\n"
    ),
  )?;
  // Port 9 (discard) is never dialed: establishment fails first.
  let child = connect_command(&helper, 9, &[]).spawn()?;
  expect_clean_failure(child, &["no MUSH CONNECT", "exit status: 3"], &[])
    .await?;
  Ok(())
}

/// A crafted connect line pointing at a black hole (a bound UDP socket
/// nobody reads) makes every candidate time out; the client must warn
/// loudly and fall back to plain TCP against the "sshd" port.
#[tokio::test]
async fn udp_unreachable_falls_back_to_tcp() -> Result<()> {
  let (echo_port, _echo) = spawn_echo_sshd().await?;
  let blackhole = std::net::UdpSocket::bind("127.0.0.1:0")?;
  let dir = tempfile::tempdir()?;
  let helper =
    crafted_connect_line(dir.path(), blackhole.local_addr()?.port())?;

  let mut child = connect_command(&helper, echo_port, &[]).spawn()?;
  let stderr = drive_any_echo_session(&mut child).await?;
  let stderr = String::from_utf8_lossy(&stderr).into_owned();
  assert!(
    stderr.contains("WARNING") && stderr.contains("falling back"),
    "fallback must warn loudly on stderr:\n{stderr}"
  );
  assert!(
    stderr.contains("QUIC unreachable"),
    "the warning should name the failure:\n{stderr}"
  );
  Ok(())
}

#[tokio::test]
async fn no_fallback_makes_unreachable_fatal() -> Result<()> {
  let (echo_port, _echo) = spawn_echo_sshd().await?;
  let blackhole = std::net::UdpSocket::bind("127.0.0.1:0")?;
  let dir = tempfile::tempdir()?;
  let helper =
    crafted_connect_line(dir.path(), blackhole.local_addr()?.port())?;

  let child =
    connect_command(&helper, echo_port, &["--no-fallback"]).spawn()?;
  expect_clean_failure(child, &["--no-fallback"], &[]).await?;
  Ok(())
}

/// A live endpoint that answers QUIC without holding the pinned key must
/// be a hard failure with no TCP fallback and no session bytes: the
/// refusal proves UDP works and that whoever answered is not the
/// bootstrapped server, which is the signal to fail loudly, not downgrade.
#[tokio::test]
async fn pin_rejection_is_fatal_and_never_falls_back() -> Result<()> {
  let (echo_port, _echo) = spawn_echo_sshd().await?;
  // A real pinned Mush server endpoint whose identity cannot match the
  // key the crafted connect line advertises.
  let identity = SessionIdentity::generate()?;
  let config = pinning::server_config(
    &identity,
    KeyPin::from_bytes([9; 32]),
    &TransportOptions::default(),
  )?;
  let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse()?)?;
  let udp_port = endpoint.local_addr()?.port();
  let _accept = tokio::spawn({
    let endpoint = endpoint.clone();
    async move {
      while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
          let _ = incoming.await;
        });
      }
    }
  });

  let dir = tempfile::tempdir()?;
  let helper = crafted_connect_line(dir.path(), udp_port)?;

  let child = connect_command(&helper, echo_port, &[]).spawn()?;
  // Nothing about it may read as the fallback path, which is the one
  // ending a pin rejection must never have.
  expect_clean_failure(
    child,
    &["refusing to fall back"],
    &["falling back", "WARNING"],
  )
  .await?;
  Ok(())
}

/// A fake bootstrap ssh pointing every candidate at `port` under a key
/// the client will pin: the bootstrap conversation succeeds, and what
/// answers there (nothing, or the wrong endpoint) is the test.
fn crafted_connect_line(dir: &Path, port: u16) -> Result<PathBuf> {
  let key = KeyPin::from_bytes([7; 32]);
  write_script(
    dir,
    "fake-ssh",
    &format!(
      "#!/bin/sh\n{FAKE_SSH_NO_SIDE_CHANNELS}read -r _hello\n\
       printf 'MUSH CONNECT v=1 port={port} key={key} \
       addr=127.0.0.1:{port}\\n'\n"
    ),
  )
}

/// A fake ssh answering three roles by argv: the bootstrap (a connect
/// line pointing at a UDP black hole), the fallback bridge (`-W`, a
/// loopback echo so the session it carries is observable), and everything
/// else refused. Records the bridge's arguments to prove where it aimed.
fn blackholed_bootstrap_with_bridge(
  dir: &Path,
  blackhole_port: u16,
  bridge_log: &Path,
) -> Result<PathBuf> {
  let key = KeyPin::from_bytes([7; 32]);
  write_script(
    dir,
    "fake-ssh",
    &format!(
      "#!/bin/sh\n\
       case \"$*\" in\n\
       \x20 *-W*) for a; do printf '%s\\n' \"$a\"; done > '{}'; exec cat;;\n\
       \x20 *jump-helper*|*SSH_CONNECTION*) exit 1;;\n\
       esac\n\
       read -r _hello\n\
       printf 'MUSH CONNECT v=1 port={blackhole_port} key={key} \
       addr=127.0.0.1:{blackhole_port}\\n'\n",
      bridge_log.display()
    ),
  )
}

/// Drives one fallback session and returns the client's stderr with the
/// arguments the bridge was invoked with.
async fn fallback_through_bridge(
  mut child: Child,
  bridge_log: &Path,
) -> Result<(String, String)> {
  let mut stdin = child.stdin.take().context("stdin piped")?;
  let mut stdout = child.stdout.take().context("stdout piped")?;
  let stderr = drain(child.stderr.take().context("stderr piped")?);
  t(stdin.write_all(b"through the bridge\n")).await?;
  let mut buf = [0u8; 19];
  t(stdout.read_exact(&mut buf)).await?;
  ensure!(&buf == b"through the bridge\n", "unexpected echo {buf:?}");
  drop(stdin);
  let status = t(child.wait()).await?;
  ensure!(
    status.success(),
    "the fallback session failed with {status}"
  );
  let stderr = String::from_utf8_lossy(&t(stderr).await?).into_owned();
  Ok((stderr, std::fs::read_to_string(bridge_log)?))
}

/// The last kind of path in the fallback order for a jumped destination:
/// with UDP blocked, the fallback is an `ssh -W` bridge from the jump,
/// never a direct dial of the destination's TCP port -- the jump exists
/// because that path is not usable, and bypassing it bypasses the policy
/// it enforces.
///
/// Both ways a jump reaches `mush connect` are covered: an explicit `-J`
/// on its own argv, and the wrapper's, which travels only through the
/// environment and so leaves `mush connect` no `-J` flag. A forwarded
/// jump that shaped the fallback differently would dial the destination
/// directly.
#[tokio::test]
async fn a_jumped_session_falls_back_through_the_jump() -> Result<()> {
  for forwarded in [false, true] {
    let (echo_port, _echo) = spawn_echo_sshd().await?;
    let blackhole = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let blackhole_port = blackhole.local_addr()?.port();
    let dir = tempfile::tempdir()?;
    let bridge_log = dir.path().join("bridge-args");
    let helper = blackholed_bootstrap_with_bridge(
      dir.path(),
      blackhole_port,
      &bridge_log,
    )?;

    let jump: &[&str] = if forwarded { &[] } else { &["-J", "bastion"] };
    let mut cmd = connect_command(&helper, echo_port, jump);
    if forwarded {
      cmd.env("MUSH_BOOTSTRAP_SSH_ARGS", "-J\u{1f}bastion");
    }
    let (stderr, bridge) =
      fallback_through_bridge(cmd.spawn()?, &bridge_log).await?;
    assert!(
      stderr.contains("falling back to plain TCP"),
      "the fallback should be loud (forwarded={forwarded}):\n{stderr}"
    );
    // Aimed from the jump at the destination's ssh port, and at the jump
    // itself as the hop that opens it.
    assert!(
      bridge.contains(&format!("-W\n127.0.0.1:{echo_port}\n")),
      "the bridge was not aimed at the destination's ssh port \
       (forwarded={forwarded}):\n{bridge}"
    );
    assert!(
      bridge.lines().next_back() == Some("bastion"),
      "the bridge did not run on the jump (forwarded={forwarded}):\n{bridge}"
    );
  }
  Ok(())
}

/// The outcome of establishment is observable: the path report records
/// the kind of path that carried the session, so a test can assert it
/// rather than infer it.
#[tokio::test]
async fn the_path_report_names_the_kind_of_path_that_carried_the_session()
-> Result<()> {
  let (echo_port, _echo) = spawn_echo_sshd().await?;
  let dir = tempfile::tempdir()?;
  let marker = unique_marker("report");
  let _guard = MarkerGuard::new(&marker);
  let helper = server_helper(dir.path(), &marker, false)?;
  let report = dir.path().join("path-report");
  let mut command = connect_command(&helper, echo_port, &[]);
  command.env("MUSH_PATH_REPORT", &report);
  let mut child = command.spawn()?;
  drive_echo_session(&mut child).await?;
  let line = std::fs::read_to_string(&report)?;
  assert!(
    line.starts_with("path=direct addr=127.0.0.1:"),
    "unexpected path report: {line}"
  );
  assert_marker_gone(&marker).await;
  Ok(())
}

/// A bootstrap-ssh stand-in for the `--server` plumbing: it refuses to run
/// if the MUSH_CONNECT_* variables leaked into its environment, then hands
/// its last argument (the remote command) to `sh -c`, as sshd's shell would.
fn exec_remote_command_helper(dir: &Path) -> Result<PathBuf> {
  write_script(
    dir,
    "fake-ssh",
    &format!(
      "#!/bin/sh\n\
       if [ -n \"${{MUSH_CONNECT_SSH+set}}\" ] || \
          [ -n \"${{MUSH_CONNECT_SERVER+set}}\" ]; then\n\
       \x20 echo 'MUSH_CONNECT_* leaked into the bootstrap ssh' >&2\n\
       \x20 exit 97\n\
       fi\n\
       {FAKE_SSH_NO_SIDE_CHANNELS}{FAKE_SSH_CONNECTION}\
       for a; do last=$a; done\n\
       exec sh -c \"$last\"\n"
    ),
  )
}

/// MUSH_CONNECT_SSH/MUSH_CONNECT_SERVER (the wrapper's `--ssh=` and
/// `--server=`) supply `mush connect`'s defaults, and neither reaches the
/// bootstrap ssh. The helper execs the env-carried server command as a
/// remote shell would, so a working session proves the value drove it.
#[tokio::test]
async fn connect_env_defaults_are_consumed_not_inherited() -> Result<()> {
  let (echo_port, _echo) = spawn_echo_sshd().await?;
  let dir = tempfile::tempdir()?;
  let marker = unique_marker("connectenv");
  let _guard = MarkerGuard::new(&marker);
  let helper = exec_remote_command_helper(dir.path())?;
  let mut command = connect_base();
  // No --ssh/--server flags: both come from the environment.
  command
    .args(["testuser", "127.0.0.1", &echo_port.to_string()])
    .env("MUSH_CONNECT_SSH", &helper)
    .env(
      "MUSH_CONNECT_SERVER",
      format!("'{MUSH_BIN}' server bootstrap --no-detach --marker '{marker}'"),
    );
  let mut child = command.spawn()?;
  drive_echo_session(&mut child).await?;
  assert_marker_gone(&marker).await;
  Ok(())
}

/// Explicit `--ssh`/`--server` flags take precedence over the environment
/// variables: decoy env values that would fail the bootstrap outright
/// must lose.
#[tokio::test]
async fn explicit_flags_beat_connect_env() -> Result<()> {
  let (echo_port, _echo) = spawn_echo_sshd().await?;
  let dir = tempfile::tempdir()?;
  let marker = unique_marker("envprec");
  let _guard = MarkerGuard::new(&marker);
  let helper = exec_remote_command_helper(dir.path())?;
  let decoy = write_script(
    dir.path(),
    "decoy-ssh",
    "#!/bin/sh\necho 'the env decoy must not run' >&2\nexit 99\n",
  )?;
  let mut command = connect_base();
  command
    .arg("--ssh")
    .arg(&helper)
    .arg("--server")
    .arg(format!(
      "'{MUSH_BIN}' server bootstrap --no-detach --marker '{marker}'"
    ))
    .args(["testuser", "127.0.0.1", &echo_port.to_string()])
    .env("MUSH_CONNECT_SSH", &decoy)
    .env("MUSH_CONNECT_SERVER", "exit 98");
  let mut child = command.spawn()?;
  drive_echo_session(&mut child).await?;
  assert_marker_gone(&marker).await;
  Ok(())
}

/// A wrong target port (the design's remapped-port sharp edge) must
/// reach the user as a distinct diagnosis naming sshd and the address,
/// not a generic connection loss: the detached server's stderr is
/// /dev/null, so the connection close reason is the only channel.
#[tokio::test]
async fn unreachable_sshd_reports_distinct_close_reason() -> Result<()> {
  // A port with nothing listening: bind, take the number, drop it.
  let listener = TcpListener::bind("127.0.0.1:0").await?;
  let dead_port = listener.local_addr()?.port();
  drop(listener);

  let dir = tempfile::tempdir()?;
  let marker = unique_marker("nosshd");
  let _guard = MarkerGuard::new(&marker);
  let helper = server_helper(dir.path(), &marker, false)?;
  let mut child = connect_command(&helper, dead_port, &[]).spawn()?;
  // The server dials sshd only once the stream carries bytes.
  let mut stdin = child.stdin.take().context("stdin piped")?;
  t(stdin.write_all(b"x")).await?;
  drop(stdin);

  expect_clean_failure(
    child,
    &["could not reach sshd", &format!("127.0.0.1:{dead_port}")],
    &[],
  )
  .await?;
  assert_marker_gone(&marker).await;
  Ok(())
}

/// A non-mush remote command spewing an overlong newline-free line is
/// diagnosed as such, not misreported as a closed channel.
#[tokio::test]
async fn overlong_hello_line_reports_too_long() -> Result<()> {
  let mut child = Command::new(MUSH_BIN)
    .args(["server", "bootstrap", "--no-detach"])
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true)
    .spawn()?;
  let stderr = drain(child.stderr.take().context("stderr piped")?);
  let mut stdin = child.stdin.take().context("stdin piped")?;
  t(stdin.write_all(&vec![b'x'; 8192])).await?;
  drop(stdin);

  let status = t(child.wait()).await?;
  assert!(!status.success());
  let stderr = String::from_utf8_lossy(&t(stderr).await?).into_owned();
  assert!(
    stderr.contains("no complete MUSH HELLO line"),
    "stderr should diagnose the overlong line:\n{stderr}"
  );
  Ok(())
}

/// `--retain` bounds how long a dead client keeps the detached server
/// alive: SIGKILL the client mid-relay (so no close ever reaches the
/// server) and the server must exit once the retention window lapses.
#[tokio::test]
async fn retain_bounds_server_lifetime_after_client_death() -> Result<()> {
  let (echo_port, _echo) = spawn_echo_sshd().await?;
  let dir = tempfile::tempdir()?;
  let marker = unique_marker("retain");
  let _guard = MarkerGuard::new(&marker);
  let helper = server_helper_with(dir.path(), &marker, false, " --retain 5s")?;
  let mut child = connect_command(&helper, echo_port, &[]).spawn()?;
  let mut stdin = child.stdin.take().context("stdin piped")?;
  let mut stdout = child.stdout.take().context("stdout piped")?;
  let _stderr = drain(child.stderr.take().context("stderr piped")?);

  t(stdin.write_all(b"ping")).await?;
  let mut buf = [0u8; 4];
  t(stdout.read_exact(&mut buf)).await?;
  assert_eq!(&buf, b"ping");

  // SIGKILL: no clean close, no FIN; only the retention limit can
  // tell the server this client is gone for good.
  child.start_kill()?;
  let _ = child.wait().await;
  assert_marker_gone(&marker).await;
  Ok(())
}

/// `mush connect` dying by signal mid-bootstrap must take every ssh it
/// spawned with it: kill_on_drop only runs when the process unwinds, and
/// a signal death (the outer ssh's SIGHUP at ConnectTimeout, a crash,
/// SIGKILL) skips Drop, so only PDEATHSIG on each child covers it. The
/// session is jumped, so the shell probe asking the jump how it sees this
/// client runs alongside the bootstrap and, unlike it, has nothing else
/// that would end it. Both hang here as a real ssh with a live remote
/// command does: stdin EOF ignored, running until killed.
///
/// Linux only, as PDEATHSIG is; see the design doc's open questions.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn signal_death_mid_bootstrap_reaps_every_ssh_it_spawned() -> Result<()> {
  let dir = tempfile::tempdir()?;
  let marker = unique_marker("boothang");
  let _guard = MarkerGuard::new(&marker);
  // Hangs without ever printing MUSH CONNECT; the marker-bearing script
  // path in its argv is what the sweep tracks. Refusing the helper's own
  // channel, as a bastion without `mush` does, sends the client to the probe.
  let helper = write_script(
    dir.path(),
    &format!("hang-{marker}"),
    "#!/bin/sh\n\
     case \"$*\" in *jump-helper*) exit 1;; esac\n\
     read -r _hello\nwhile :; do sleep 1; done\n",
  )?;
  // Port 9 (discard) is never dialed: the bootstrap never completes.
  let mut child = connect_command(&helper, 9, &["-J", "bastion"]).spawn()?;
  let _stderr = drain(child.stderr.take().context("stderr piped")?);

  // All three marked processes up: `mush connect` (the helper path in
  // its argv), the hung bootstrap, and the hung probe.
  for _ in 0..100 {
    if marker_pids(&marker).len() >= 3 {
      break;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
  }
  ensure!(
    marker_pids(&marker).len() >= 3,
    "bootstrap processes never appeared: {:?}",
    marker_pids(&marker)
  );

  let pid = child.id().context("child already reaped")? as i32;
  unsafe {
    libc::kill(pid, libc::SIGKILL);
  }
  let _ = child.wait().await;
  assert_marker_gone(&marker).await;
  Ok(())
}

/// The outer ssh SIGHUPs its ProxyCommand when it exits; dying without
/// delivering it (SIGKILL, a crash, the OOM killer) must not leave the
/// relay running forever once nothing holds the stdio channel, and
/// PDEATHSIG turns the parent's death into the hangup. The hangup alone
/// proves nothing about the session, though: OpenSSH's ControlPersist
/// forks a background mux master that keeps the ProxyCommand pipes open,
/// live sessions using them, after the initiating ssh exits. So the
/// relay must keep serving while the channel stays open -- past the
/// hangup drain grace -- and tear down only once it closes. The sh here
/// is the initiating ssh that dies silently; the test's own pipe ends are
/// the persisting mux master.
#[tokio::test]
async fn parent_death_serves_until_the_channel_closes() -> Result<()> {
  let (echo_port, _echo) = spawn_echo_sshd().await?;
  let dir = tempfile::tempdir()?;
  let marker = unique_marker("parentkill");
  let _guard = MarkerGuard::new(&marker);
  let helper = server_helper(dir.path(), &marker, false)?;
  // The trailing `exit` keeps sh from exec-ing `mush` into its own pid,
  // so sh stays the parent; the marker travels in the (ignored) --server
  // argument so `mush connect` itself is sweepable.
  let parent = write_script(
    dir.path(),
    "outer-stand-in",
    &format!(
      "#!/bin/sh\n'{MUSH_BIN}' connect --ssh '{}' \
       --server 'ignored {marker}' testuser 127.0.0.1 {echo_port}\n\
       exit $?\n",
      helper.display()
    ),
  )?;
  let mut child = Command::new(&parent)
    .env_remove("SSH_CONNECTION")
    .env_remove("MUSH_BOOTSTRAP_SSH_ARGS")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true)
    .spawn()?;
  let mut stdin = child.stdin.take().context("stdin piped")?;
  let mut stdout = child.stdout.take().context("stdout piped")?;
  let _stderr = drain(child.stderr.take().context("stderr piped")?);

  t(stdin.write_all(b"ping")).await?;
  let mut buf = [0u8; 4];
  t(stdout.read_exact(&mut buf)).await?;
  assert_eq!(&buf, b"ping");

  // SIGKILL the parent while our end of the pipes stays open: no SIGHUP
  // is sent and no EOF ends the relay. PDEATHSIG fires in `mush connect`,
  // which must not start the teardown countdown while the channel is held.
  let pid = child.id().context("child already reaped")? as i32;
  unsafe {
    libc::kill(pid, libc::SIGKILL);
  }
  let _ = child.wait().await;

  // Well past the hangup drain grace (5s) the relay must still serve --
  // the ControlPersist shape, where teardown kills every live mux client.
  tokio::time::sleep(Duration::from_secs(6)).await;
  t(stdin.write_all(b"pong")).await?;
  let mut buf = [0u8; 4];
  t(stdout.read_exact(&mut buf)).await?;
  assert_eq!(&buf, b"pong");

  // Closing our write end is the channel hangup; the bounded drain finishes
  // the relay (the echo tail proves the return path drained) and all exits.
  drop(stdin);
  let mut tail = Vec::new();
  t(stdout.read_to_end(&mut tail)).await?;
  assert_eq!(tail, TAIL);
  assert_marker_gone(&marker).await;
  Ok(())
}

/// `--idle-timeout` bounds the otherwise-silent client hang when the server
/// dies by SIGKILL with nothing to tell the client: the timeout expires, the
/// relay delivers EOF on stdout, and the client exits nonzero naming it.
#[tokio::test]
async fn idle_timeout_bounds_client_hang_after_server_death() -> Result<()> {
  let (echo_port, _echo) = spawn_echo_sshd().await?;
  let dir = tempfile::tempdir()?;
  let marker = unique_marker("srvdeath");
  let _guard = MarkerGuard::new(&marker);
  let helper = server_helper(dir.path(), &marker, false)?;
  let mut child =
    connect_command(&helper, echo_port, &["--idle-timeout", "3s"]).spawn()?;
  let mut stdin = child.stdin.take().context("stdin piped")?;
  let mut stdout = child.stdout.take().context("stdout piped")?;
  let stderr = drain(child.stderr.take().context("stderr piped")?);

  t(stdin.write_all(b"ping")).await?;
  let mut buf = [0u8; 4];
  t(stdout.read_exact(&mut buf)).await?;
  assert_eq!(&buf, b"ping");

  // Kill the detached server outright; no close reaches the client.
  let killed = std::process::Command::new("pkill")
    .args(["-KILL", "-f", &marker])
    .status()?;
  ensure!(killed.success(), "no detached server found to kill");

  // The timeout expires: EOF arrives on stdout while our stdin stays open
  // (the shape in which an unbounded client hangs forever) ...
  let mut tail = Vec::new();
  t(stdout.read_to_end(&mut tail)).await?;
  assert_eq!(tail, b"");
  // ... and the client winds down once its own stdin closes (as ssh
  // would close it after seeing that EOF), reporting why.
  drop(stdin);
  let status = t(child.wait()).await?;
  assert!(!status.success());
  let stderr = String::from_utf8_lossy(&t(stderr).await?).into_owned();
  assert!(
    stderr.contains("idle timeout"),
    "stderr should name the idle limit:\n{stderr}"
  );
  Ok(())
}
