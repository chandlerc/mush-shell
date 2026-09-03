// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The jump helper on a real bastion (design doc, "The jump helper"):
//! `mush jump-helper` started over a real ssh exec channel to the jump
//! host, exercised from two devices in separate network namespaces.
//!
//! The topology is the one the relayed path exists for: the client
//! behind a port-restricted home NAT, the destination behind a symmetric
//! NAT that defeats reflexive candidates outright, and the jump
//! dual-homed with a public address the client reaches and a DMZ address
//! the destination does. None of it can be faked in-process: the
//! reflected addresses are whatever nftables actually mapped, the
//! relayed datagrams have to survive both edges' filtering, and the
//! helper's channel is a real sshd exec channel with a real detach under
//! it.
//!
//! Runs under the nextest `lab` profile; see `docs/testing.md`. The
//! `mush` binary must be built first (`cargo build -p mush`).

#![cfg(target_os = "linux")]

use std::net::{Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use mush_core::bootstrap::{PROTOCOL_VERSION, SessionNonce, SessionSecret};
use mush_core::helper::{Close, HelperMessage, Serve};
use mush_core::stun::{BindingTransaction, PeerRole, ProbeLabel};
use mush_testenv::patchbay::Device;
use mush_testenv::{JumpTopo, MushFixture, NatMode, SshFixture, jump_chain};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::mpsc;

mod common;

use common::{READY, t};

mush_testenv::userns_bootstrap!();

/// Generous timeout for any single await that should be quick.
const STEP: Duration = Duration::from_secs(60);

/// How long a peer waits for one answer before resending. UDP across
/// the lab is not lossy, but a probe raced against namespace setup is
/// cheaper to repeat than to debug.
const PER_TRY: Duration = Duration::from_millis(500);

/// How many times a peer resends before giving up.
const TRIES: usize = 5;

/// One of the session's peers: a UDP socket living inside a lab
/// device's namespace, driven over channels from the test. It outlives
/// every step, so the address the helper registers is still the address
/// the peer sends and receives on when the relay is exercised.
struct Peer {
  outbound: mpsc::Sender<Vec<u8>>,
  inbound: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
  label: ProbeLabel,
  secret: SessionSecret,
  _task: tokio::task::JoinHandle<()>,
}

impl Peer {
  /// Binds a socket inside `dev` and starts pumping it.
  fn new(
    dev: &Device,
    nonce: SessionNonce,
    secret: SessionSecret,
    role: PeerRole,
  ) -> Result<Self> {
    let (outbound, mut commands) = mpsc::channel::<Vec<u8>>(8);
    let (received, inbound) = mpsc::channel::<(Vec<u8>, SocketAddr)>(8);
    let task = dev.spawn(move |_| async move {
      let socket = match tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await {
        Ok(socket) => socket,
        Err(_) => return,
      };
      let mut buf = [0u8; 2048];
      loop {
        tokio::select! {
          command = commands.recv() => {
            let Some(datagram) = command else { return };
            // `send` prepends 6 bytes of target address to the payload.
            let (target, payload) = datagram.split_at(6);
            let target = SocketAddr::from((
              Ipv4Addr::new(target[0], target[1], target[2], target[3]),
              u16::from_be_bytes([target[4], target[5]]),
            ));
            if socket.send_to(payload, target).await.is_err() {
              return;
            }
          }
          result = socket.recv_from(&mut buf) => {
            let Ok((len, from)) = result else { return };
            if received.send((buf[..len].to_vec(), from)).await.is_err() {
              return;
            }
          }
        }
      }
    })?;
    Ok(Self {
      outbound,
      inbound,
      label: ProbeLabel::to_helper(nonce, role),
      secret,
      _task: task,
    })
  }

  /// Sends one datagram at `target` from inside the namespace.
  async fn send(&self, target: SocketAddr, payload: &[u8]) -> Result<()> {
    let SocketAddr::V4(v4) = target else {
      bail!("the lab is IPv4 only");
    };
    let mut datagram = v4.ip().octets().to_vec();
    datagram.extend_from_slice(&v4.port().to_be_bytes());
    datagram.extend_from_slice(payload);
    self.outbound.send(datagram).await?;
    Ok(())
  }

  /// The next datagram received, within `within`.
  async fn recv(&mut self, within: Duration) -> Option<(Vec<u8>, SocketAddr)> {
    tokio::time::timeout(within, self.inbound.recv())
      .await
      .ok()
      .flatten()
  }

  /// Probes `helper` until it answers, returning the reflexive address
  /// it reports.
  async fn probe(&mut self, helper: SocketAddr) -> Result<SocketAddr> {
    let transaction = BindingTransaction::new(self.label, &self.secret);
    for _ in 0..TRIES {
      self.send(helper, transaction.request()).await?;
      let Some((datagram, from)) = self.recv(PER_TRY).await else {
        continue;
      };
      ensure!(from == helper, "an answer arrived from {from}");
      if let Some(reflexive) = transaction.reflexive(&datagram) {
        return Ok(reflexive);
      }
    }
    bail!("no reflection from {helper} after {TRIES} probes")
  }

  /// Sends relay payload: a QUIC short-header packet, so nothing about
  /// it can be read as a probe.
  async fn relay(&self, helper: SocketAddr, body: &str) -> Result<Vec<u8>> {
    let mut packet = vec![0x40u8];
    packet.extend_from_slice(body.as_bytes());
    self.send(helper, &packet).await?;
    Ok(packet)
  }
}

/// The helper's ssh channel: the exec channel's stdio, line-framed.
struct HelperChannel {
  child: Child,
  stdin: ChildStdin,
  stdout: ChildStdout,
  leftover: Vec<u8>,
}

impl HelperChannel {
  /// Runs `mush jump-helper` on the jump host from inside the client's
  /// namespace, exactly as `mush connect` would over its second ssh.
  fn start(lab: &Lab, client: &Device, args: &[&str]) -> Result<Self> {
    let mut remote = format!(
      "{} jump-helper --marker {}",
      lab.mush.mush_bin().display(),
      lab.mush.marker()
    );
    for arg in args {
      remote.push(' ');
      remote.push_str(arg);
    }
    let mut cmd = Command::new("ssh");
    cmd
      .args(["-F"])
      .arg(lab.fix.ssh_config())
      .args(["-T", &lab.jump_ip.to_string(), &remote])
      .stdin(Stdio::piped())
      .stdout(Stdio::piped())
      .stderr(Stdio::inherit());
    mush_testenv::harden_command(&mut cmd);
    let mut child = client.spawn_command(cmd)?;
    let stdin = child.stdin.take().context("stdin piped")?;
    let stdout = child.stdout.take().context("stdout piped")?;
    Ok(Self {
      child,
      stdin,
      stdout,
      leftover: Vec::new(),
    })
  }

  async fn write(&mut self, line: &str) -> Result<()> {
    t(STEP, self.stdin.write_all(line.as_bytes())).await?;
    Ok(())
  }

  /// The next control message, skipping any login output the channel
  /// carries around it.
  async fn message(&mut self) -> Result<HelperMessage> {
    loop {
      if let Some(newline) = self.leftover.iter().position(|&b| b == b'\n') {
        let line: Vec<u8> = self.leftover.drain(..=newline).collect();
        let line = String::from_utf8_lossy(&line[..newline]).into_owned();
        if let Some(message) = HelperMessage::parse(&line)? {
          return Ok(message);
        }
        continue;
      }
      let mut buf = [0u8; 4096];
      let read = t(STEP, self.stdout.read(&mut buf)).await?;
      ensure!(read > 0, "the helper channel closed before its next line");
      self.leftover.extend_from_slice(&buf[..read]);
    }
  }
}

/// The client's WAN address, as the public internet and so the bastion
/// observes it.
fn home_wan(lab: &Lab) -> Result<Ipv4Addr> {
  lab.topo.home.uplink_ip().context("home NAT WAN ip")
}

/// The jump lab: bastion sshd up, the Mush fixture wired, and the
/// addresses each side reaches the jump at.
struct Lab {
  topo: JumpTopo,
  fix: SshFixture,
  mush: MushFixture,
  jump_ip: Ipv4Addr,
  jump_dmz_ip: Ipv4Addr,
  _sshd_jump: mush_testenv::SshServer,
}

async fn lab() -> Result<Lab> {
  let topo = jump_chain(NatMode::Symmetric).await?;
  let jump_ip = topo.jump_public_ip()?;
  let jump_dmz_ip = topo.jump_dmz_ip()?;
  let fix = SshFixture::new()?;
  fix.trust_host(jump_ip)?;
  let mush = MushFixture::new(&fix)?;
  let mut sshd_jump = fix.spawn_sshd(&topo.jump)?;
  sshd_jump.wait_ready(&topo.client, jump_ip, READY).await?;
  Ok(Lab {
    topo,
    fix,
    mush,
    jump_ip,
    jump_dmz_ip,
    _sshd_jump: sshd_jump,
  })
}

/// The whole service on a real bastion: a probe for an unadmitted nonce
/// gets nothing, both peers learn the address the bastion observes them
/// at, both arrivals are reported back up the ssh channel, and payload
/// crosses between two hosts with no path to each other at all.
#[tokio::test(flavor = "current_thread")]
async fn the_helper_reflects_and_relays_across_a_real_bastion() -> Result<()> {
  mush_testenv::skip_unless_available!();
  let lab = lab().await?;
  let nonce = SessionNonce::generate()?;
  let secret = SessionSecret::generate()?;
  let mut channel = HelperChannel::start(&lab, &lab.topo.client, &[])?;

  // Control: the nonce arrives over the authenticated channel, and the
  // helper answers with the port it bound and where to find it.
  let serve = Serve {
    version: PROTOCOL_VERSION,
    nonce,
    secret,
  };
  channel.write(&serve.to_wire()).await?;
  let HelperMessage::Ready(ready) = channel.message().await? else {
    bail!("the helper's first line is not its ready line");
  };
  let from_client = SocketAddr::new(lab.jump_ip.into(), ready.udp_port);
  let from_dest = SocketAddr::new(lab.jump_dmz_ip.into(), ready.udp_port);
  // Both of the bastion's addresses are hinted: the address ssh arrived
  // on leads, and the DMZ address is what a destination the client
  // cannot address reaches.
  ensure!(
    ready.addr_hints.first() == Some(&from_client),
    "the ready hints must lead with the address ssh arrived on: {:?}",
    ready.addr_hints
  );
  ensure!(
    ready.addr_hints.contains(&from_dest),
    "the ready hints must include the DMZ address: {:?}",
    ready.addr_hints
  );
  // The jump's own view of the client, carried on the ready line so a
  // helper whose UDP is unreachable still leaves the destination an
  // address to punch at (design doc, "Degrading without the helper").
  // Behind the home NAT that is the WAN address
  // `echo $SSH_CONNECTION` on this hop would report.
  ensure!(
    ready.client_ip == Some(home_wan(&lab)?.into()),
    "the ready line must name the client as the jump sees it: {:?}",
    ready.client_ip
  );

  // The admission check, on the same socket the served session is
  // answered on: a probe naming a nonce that never came over the ssh
  // channel gets nothing back.
  let mut stranger = Peer::new(
    &lab.topo.client,
    SessionNonce::generate()?,
    SessionSecret::generate()?,
    PeerRole::Client,
  )?;
  ensure!(
    stranger.probe(from_client).await.is_err(),
    "a probe for an unserved nonce was answered"
  );

  let mut client =
    Peer::new(&lab.topo.client, nonce, secret, PeerRole::Client)?;
  let mut dest =
    Peer::new(&lab.topo.dest, nonce, secret, PeerRole::Destination)?;

  // Reflection: the client sees its home NAT's WAN address, and the
  // destination -- reaching the bastion over the DMZ LAN, inside its
  // own edge -- sees its own.
  let client_reflexive = client.probe(from_client).await?;
  ensure!(
    client_reflexive.ip() == home_wan(&lab)?,
    "the client's reflexive address {client_reflexive} is not its NAT's"
  );
  let dest_reflexive = dest.probe(from_dest).await?;
  ensure!(
    dest_reflexive.ip() == lab.topo.dest_ip()?,
    "the destination's reflexive address {dest_reflexive} is not its own"
  );

  // Rendezvous: both arrivals come back up the ssh channel, which is
  // how the client learns the destination is there and where from.
  let mut reported = Vec::new();
  for _ in 0..2 {
    let HelperMessage::Peer(peer) = channel.message().await? else {
      bail!("expected a peer report");
    };
    ensure!(peer.nonce == nonce, "a report for another session");
    reported.push((peer.role, peer.addr));
  }
  reported.sort_by_key(|(role, _)| role.as_str());
  ensure!(
    reported
      == vec![
        (PeerRole::Client, client_reflexive),
        (PeerRole::Destination, dest_reflexive),
      ],
    "unexpected peer reports: {reported:?}"
  );

  // Relay of last resort: two hosts with no path to each other, each
  // with an ordinary outbound flow to the bastion, trading payload byte
  // for byte.
  let sent = client.relay(from_client, "to-the-destination").await?;
  let (got, from) =
    dest.recv(STEP).await.context("nothing reached the dest")?;
  ensure!(got == sent, "the relay changed the payload");
  ensure!(from == from_dest, "relayed payload arrived from {from}");

  let sent = dest.relay(from_dest, "and-back").await?;
  let (got, from) = client
    .recv(STEP)
    .await
    .context("nothing reached the client")?;
  ensure!(got == sent, "the relay changed the payload");
  ensure!(from == from_client, "relayed payload arrived from {from}");

  // The clean end: the client says the session is over, the helper
  // exits, and its ssh finishes with it.
  let close = Close { nonce };
  channel.write(&close.to_wire()).await?;
  let status = t(STEP, channel.child.wait()).await?;
  ensure!(status.success(), "the helper's ssh exited with {status}");
  lab.mush.wait_no_marked_processes().await
}
