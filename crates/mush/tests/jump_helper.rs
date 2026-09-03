// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Loopback tests of `mush jump-helper`: the real binary,
//! driven over its control channel the way the client's second ssh
//! would drive it, with two local UDP sockets as the session's peers.
//!
//! What this tier covers that the service's own tests cannot is the
//! process -- the opening conversation, the holding detach, and the two
//! ways the helper's life ends. The rules of the datagram handling
//! belong to `mush_core::helper`'s unit tests and the netsim tier; here
//! they are only proven wired to a real socket.
//!
//! Hermetic: peer sockets bind at port 0, the helper's port comes from
//! its ready line, and the detached process is tracked by a unique argv
//! marker (`--marker`) so leaks are caught with pgrep.

use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use mush_core::bootstrap::{PROTOCOL_VERSION, SessionNonce, SessionSecret};
use mush_core::helper::{Close, HelperMessage, Serve};
use mush_core::stun::{BindingTransaction, PeerRole, ProbeLabel};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UdpSocket;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

mod common;

use common::{MUSH_BIN, MarkerGuard, assert_marker_gone, t};

fn unique_marker(name: &str) -> String {
  common::unique_marker("mush-helper", name)
}

/// A running `mush jump-helper` with its control channel in hand.
struct Helper {
  child: Child,
  stdin: ChildStdin,
  stdout: Lines,
  addr: SocketAddr,
}

/// Line reader over the helper's stdout, keeping bytes read past a line.
struct Lines {
  stdout: ChildStdout,
  leftover: Vec<u8>,
}

impl Lines {
  async fn next(&mut self) -> Result<String> {
    loop {
      if let Some(newline) = self.leftover.iter().position(|&b| b == b'\n') {
        let line: Vec<u8> = self.leftover.drain(..=newline).collect();
        return Ok(String::from_utf8(line[..newline].to_vec())?);
      }
      let mut buf = [0u8; 4096];
      let read = t(self.stdout.read(&mut buf)).await?;
      ensure!(read > 0, "helper stdout closed before the next line");
      self.leftover.extend_from_slice(&buf[..read]);
    }
  }

  /// The next line, parsed as a control message.
  async fn message(&mut self) -> Result<HelperMessage> {
    let line = self.next().await?;
    HelperMessage::parse(&line)?
      .with_context(|| format!("not a control line: {line}"))
  }
}

impl Helper {
  /// Starts the helper, hands it `nonce`, and reads its ready line.
  async fn start(
    marker: &str,
    nonce: SessionNonce,
    secret: SessionSecret,
    args: &[&str],
  ) -> Result<Self> {
    let mut child = Command::new(MUSH_BIN)
      .arg("jump-helper")
      .args(["--marker", marker])
      .args(args)
      .env("SSH_CONNECTION", "203.0.113.5 40000 127.0.0.1 22")
      .stdin(Stdio::piped())
      .stdout(Stdio::piped())
      .stderr(Stdio::inherit())
      .kill_on_drop(true)
      .spawn()?;
    let mut stdin = child.stdin.take().context("stdin piped")?;
    let mut stdout = Lines {
      stdout: child.stdout.take().context("stdout piped")?,
      leftover: Vec::new(),
    };
    let serve = Serve {
      version: PROTOCOL_VERSION,
      nonce,
      secret,
    };
    t(stdin.write_all(serve.to_wire().as_bytes())).await?;

    let HelperMessage::Ready(ready) = stdout.message().await? else {
      bail!("the helper's first line is not its ready line");
    };
    ensure!(ready.version == PROTOCOL_VERSION);
    // The hints lead with the address the client reached over ssh, the
    // one address it demonstrably has a path to.
    ensure!(
      ready.addr_hints.first().map(SocketAddr::ip)
        == Some("127.0.0.1".parse()?),
      "unexpected helper hints: {:?}",
      ready.addr_hints
    );
    for hint in &ready.addr_hints {
      ensure!(hint.port() == ready.udp_port, "hint on the wrong port");
    }
    Ok(Self {
      child,
      stdin,
      stdout,
      addr: SocketAddr::new("127.0.0.1".parse()?, ready.udp_port),
    })
  }
}

/// One of the session's two peers, on its own loopback socket.
struct Peer {
  socket: UdpSocket,
  label: ProbeLabel,
  secret: SessionSecret,
}

impl Peer {
  async fn new(
    nonce: SessionNonce,
    secret: SessionSecret,
    role: PeerRole,
  ) -> Result<Self> {
    Ok(Self {
      socket: UdpSocket::bind("127.0.0.1:0").await?,
      label: ProbeLabel::to_helper(nonce, role),
      secret,
    })
  }

  fn addr(&self) -> Result<SocketAddr> {
    Ok(self.socket.local_addr()?)
  }

  /// Probes the helper and returns the reflexive address it reports.
  async fn probe(&self, helper: SocketAddr) -> Result<SocketAddr> {
    let transaction = BindingTransaction::new(self.label, &self.secret);
    self.socket.send_to(transaction.request(), helper).await?;
    let mut buf = [0u8; 1024];
    let (len, from) = t(self.socket.recv_from(&mut buf)).await?;
    ensure!(from == helper, "answer came from {from}");
    transaction
      .reflexive(&buf[..len])
      .context("not this transaction's reflection")
  }

  /// Sends relay payload at the helper: a QUIC short-header packet, so
  /// nothing about it can be read as a probe.
  async fn send(&self, helper: SocketAddr, body: &str) -> Result<Vec<u8>> {
    let mut packet = vec![0x40u8];
    packet.extend_from_slice(body.as_bytes());
    self.socket.send_to(&packet, helper).await?;
    Ok(packet)
  }

  /// The next datagram, which must have come from the helper.
  async fn recv(&self, helper: SocketAddr) -> Result<Vec<u8>> {
    let mut buf = [0u8; 2048];
    let (len, from) = t(self.socket.recv_from(&mut buf)).await?;
    ensure!(from == helper, "payload arrived from {from}");
    Ok(buf[..len].to_vec())
  }
}

/// The whole service through the real binary, from the ready line to the
/// clean end when the client closes the session.
#[tokio::test]
async fn the_helper_reflects_relays_and_reports() -> Result<()> {
  let marker = unique_marker("serve");
  let _guard = MarkerGuard::new(&marker);
  let nonce = SessionNonce::generate()?;
  let secret = SessionSecret::generate()?;
  let mut helper = Helper::start(&marker, nonce, secret, &[]).await?;

  // The holding detach keeps the channel alive both ways: the process
  // the ssh channel waits on is still there.
  ensure!(
    helper.child.try_wait()?.is_none(),
    "the helper's parent exited, which closes the client's direction"
  );

  let client = Peer::new(nonce, secret, PeerRole::Client).await?;
  let dest = Peer::new(nonce, secret, PeerRole::Destination).await?;

  // Reflection: each peer is told the address the helper observed,
  // which on loopback is its own.
  ensure!(client.probe(helper.addr).await? == client.addr()?);
  ensure!(dest.probe(helper.addr).await? == dest.addr()?);

  // Rendezvous: both arrivals are reported back up the channel, which
  // is how the client learns the destination is reachable and where.
  let mut reported = Vec::new();
  for _ in 0..2 {
    let HelperMessage::Peer(peer) = helper.stdout.message().await? else {
      bail!("expected a peer report");
    };
    ensure!(peer.nonce == nonce, "a report for another session");
    reported.push((peer.role, peer.addr));
  }
  reported.sort_by_key(|(role, _)| role.as_str());
  ensure!(
    reported
      == vec![
        (PeerRole::Client, client.addr()?),
        (PeerRole::Destination, dest.addr()?),
      ],
    "unexpected peer reports: {reported:?}"
  );

  // Relay: opaque payload, forwarded byte for byte, both ways.
  let sent = client.send(helper.addr, "to-the-destination").await?;
  ensure!(dest.recv(helper.addr).await? == sent);
  let sent = dest.send(helper.addr, "and-back").await?;
  ensure!(client.recv(helper.addr).await? == sent);

  // The clean end: the session is over, so the helper goes with it.
  let close = Close { nonce };
  t(helper.stdin.write_all(close.to_wire().as_bytes())).await?;
  let status = t(helper.child.wait()).await?;
  ensure!(status.success(), "the helper exited with {status}");
  assert_marker_gone(&marker).await;
  Ok(())
}

/// A probe for a nonce that never came over the ssh channel gets no
/// answer at all: the check the whole service depends on.
#[tokio::test]
async fn an_unserved_nonce_gets_no_answer() -> Result<()> {
  let marker = unique_marker("nonce");
  let _guard = MarkerGuard::new(&marker);
  let nonce = SessionNonce::generate()?;
  let secret = SessionSecret::generate()?;
  let helper = Helper::start(&marker, nonce, secret, &[]).await?;

  let stranger = Peer::new(
    SessionNonce::generate()?,
    SessionSecret::generate()?,
    PeerRole::Client,
  )
  .await?;
  ensure!(
    timeout(Duration::from_secs(2), stranger.probe(helper.addr))
      .await
      .is_err(),
    "a probe for an unserved nonce was answered"
  );
  // The served session is answered from the same socket moments later,
  // so the silence was the check and not a dead helper.
  let client = Peer::new(nonce, secret, PeerRole::Client).await?;
  ensure!(client.probe(helper.addr).await? == client.addr()?);
  Ok(())
}

/// Non-protocol output that never ends a line is diagnosed as such, not
/// as a closed channel -- as in
/// `loopback::overlong_hello_line_reports_too_long`, since both opening
/// lines go through the one reader in `mush::remote`.
#[tokio::test]
async fn overlong_serve_line_reports_too_long() -> Result<()> {
  let mut child = Command::new(MUSH_BIN)
    .args(["jump-helper", "--no-detach"])
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true)
    .spawn()?;
  let mut stdin = child.stdin.take().context("stdin piped")?;
  t(stdin.write_all(&vec![b'x'; 8192])).await?;
  drop(stdin);

  let output = t(child.wait_with_output()).await?;
  ensure!(!output.status.success(), "the overlong line was accepted");
  let stderr = String::from_utf8_lossy(&output.stderr);
  ensure!(
    stderr.contains("no complete MUSH SERVE line"),
    "stderr should diagnose the overlong line:\n{stderr}"
  );
  Ok(())
}

/// The retention limit ends a helper whose session went quiet, even
/// with the client's channel still open.
#[tokio::test]
async fn retain_bounds_a_silent_helper() -> Result<()> {
  let marker = unique_marker("retain");
  let _guard = MarkerGuard::new(&marker);
  let nonce = SessionNonce::generate()?;
  let secret = SessionSecret::generate()?;
  let mut helper =
    Helper::start(&marker, nonce, secret, &["--retain", "5s"]).await?;
  let client = Peer::new(nonce, secret, PeerRole::Client).await?;
  ensure!(client.probe(helper.addr).await? == client.addr()?);

  let status = t(helper.child.wait()).await?;
  ensure!(status.success(), "the helper exited with {status}");
  assert_marker_gone(&marker).await;
  Ok(())
}
