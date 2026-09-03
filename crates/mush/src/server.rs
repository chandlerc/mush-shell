// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! `mush server bootstrap`: the remote side of a session.
//!
//! The bootstrap conversation (read `MUSH HELLO` on stdin, bind the UDP
//! port, answer `MUSH CONNECT` on stdout) runs synchronously, in the
//! order [`crate::remote`] holds both remote-side commands to, because
//! the detach that follows must fork before any tokio runtime exists
//! ([`crate::detach`] has why). Only after the detach decision is the
//! runtime built and the pre-bound socket handed to quinn for the
//! accept, relay, and teardown -- [`mush_core::server`]'s standalone
//! pieces, because the async `ServerSession` engine cannot be split
//! around a fork.
//!
//! Which detach depends on the client: one that asked to signal gets
//! [`crate::detach`]'s holding form, which keeps the bootstrap channel
//! alive in both directions; the no-jump case, with nothing to signal,
//! gets the single-step detach, and its bootstrap ssh finishes at once.

use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::OwnedFd;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use mush_core::bootstrap::{Connect, Hello, PROTOCOL_VERSION, SessionNonce};
use mush_core::channel::SignalChannel;
use mush_core::path::{DestinationPaths, drive_destination};
use mush_core::pinning::{self, SessionIdentity};
use mush_core::relay;
use mush_core::server::{
  DEFAULT_BOOTSTRAP_TIMEOUT, DEFAULT_PORT_RANGE, MAX_HELLO_BYTES,
  accept_session, addr_hints, bind_socket, interface_ips,
};
use mush_core::transport::{self, TransportOptions};
use mush_core::traversal::{Probe, TraversalEndpoint, TraversalSocket};
use mush_core::upgrade::{DestinationUpgrade, UpgradePolicy};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use crate::detach::close_stdio;
use crate::remote;
use crate::stdio::take_stdio;

/// Application error code for a connection closed by a server-side
/// failure after accept, distinct from the relay-outcome closes (0
/// clean, 1 unclean). The close reason carries the diagnosis: the
/// detached server's stderr is /dev/null, so the reason is the only
/// channel the detail can reach the user through (the client prints it
/// verbatim).
const SERVER_FAILURE_CLOSE_CODE: quinn::VarInt = quinn::VarInt::from_u32(2);

/// Runs `mush server bootstrap`. `retain` bounds how long a silent,
/// unreachable client keeps this server alive; `None` retains
/// indefinitely, mosh-style (the design's default). `target` overrides
/// the sshd port to relay into, for a destination whose public ssh port
/// is not the one sshd listens on.
pub fn run(
  no_detach: bool,
  retain: Option<Duration>,
  target: Option<u16>,
) -> Result<ExitCode> {
  // The accept phase re-covers this with a tokio timeout of its own.
  remote::arm_bootstrap_alarm();

  let socket =
    bind_socket(IpAddr::V4(Ipv4Addr::UNSPECIFIED), &DEFAULT_PORT_RANGE)?;
  let local = socket.local_addr()?;
  let udp_port = local.port();
  let (hello, leftover) = read_hello()?;
  let identity = SessionIdentity::generate()?;

  // Candidate gathering (design doc, "Path establishment"): the address
  // the client reached over ssh, then this host's own interfaces, which
  // is what lets a client whose ssh goes through a jump still dial the
  // destination directly.
  let ssh_connection = std::env::var("SSH_CONNECTION").ok();
  let connect = Connect {
    version: PROTOCOL_VERSION,
    udp_port,
    server_key: identity.pin(),
    addr_hints: addr_hints(ssh_connection.as_deref(), &interface_ips(), local),
  };
  remote::announce(
    &connect.to_wire(),
    "writing MUSH CONNECT to the bootstrap channel",
  )?;

  // A client that will signal needs the channel through path
  // establishment; one that will not gets it closed here.
  let signaling = hello.nonce.is_some();
  remote::run_detached(no_detach, signaling, |release| {
    serve(socket, identity, hello, leftover, release, retain, target)
  })
}

/// Reads the `MUSH HELLO` line the client opens with, with any bytes
/// read past it: the synchronous mirror of the engine's hello read.
fn read_hello() -> Result<(Hello, Vec<u8>)> {
  let (line, leftover) = remote::read_opening_line(
    MAX_HELLO_BYTES,
    "MUSH HELLO",
    "bootstrap channel",
  )?;
  let hello = Hello::parse(&line)?;
  remote::check_version(hello.version)?;
  Ok((hello, leftover))
}

/// The session proper: accept the pinned connection on the pre-bound
/// socket, splice it into the loopback sshd connection, and tear down.
async fn serve(
  socket: std::net::UdpSocket,
  identity: SessionIdentity,
  hello: Hello,
  leftover: Vec<u8>,
  release: Option<OwnedFd>,
  retain: Option<Duration>,
  target: Option<u16>,
) -> Result<ExitCode> {
  // The session's endpoint runs on the traversal shim so that this
  // side's outward probes leave from the very mapping the client's
  // handshake has to arrive through (design doc, "Path establishment").
  // Without a session nonce nothing probes, and the shim only sorts
  // stray STUN-shaped datagrams away from quinn.
  let TraversalEndpoint {
    endpoint,
    socket: probe_socket,
    probes,
  } = TraversalEndpoint::over_std(
    socket,
    mush_core::transport::endpoint_config(),
    None,
  )
  .context("wrapping the bound socket in a QUIC endpoint")?;
  let transport = TransportOptions {
    max_idle_timeout: retain,
    ..TransportOptions::default()
  };
  endpoint.set_server_config(Some(pinning::server_config(
    &identity,
    hello.client_key,
    &transport,
  )?));

  // Signaling runs alongside the accept and ends with it (design doc,
  // "Signaling"). The task owns both the channel and the release pipe,
  // so however it ends -- the
  // client hung up, the accept finished, the give-up timeout fired --
  // the descriptors and the waiting parent go with it, and the
  // bootstrap ssh finishes. Awaiting the task rather than aborting it
  // is what makes that release ordered, and what hands back the state
  // the session's path policy inherits.
  let (settled, stop) = oneshot::channel();
  let signaling = match hello.nonce {
    Some(nonce) => {
      spawn_signaling(leftover, nonce, release, probe_socket, probes, stop)
    }
    None => {
      drop(probes);
      None
    }
  };
  let accepted = accept_session(&endpoint, DEFAULT_BOOTSTRAP_TIMEOUT).await;
  let _ = settled.send(());
  let upgrade = match signaling {
    Some(signaling) => signaling.await.ok().flatten(),
    None => None,
  };
  let (connection, send, recv) = accepted?;

  // The destination's half of the design's relay-to-direct upgrade
  // (mush_core::upgrade): answer the client's path validation checks,
  // keep punching outward while the relay is carrying the session, and
  // keep the relay's own pinhole open. It ends with the connection.
  if let Some(upgrade) = upgrade {
    tokio::spawn(upgrade.run(connection.clone()));
  }

  // The client announces ssh's own `%p`, which is the port it dialed
  // rather than the one sshd listens on: a destination behind a
  // port-forwarding NAT is reached at 2222 and serves on 22. `--target`
  // is where the deployment says so (design doc, "Sharp edges").
  let target_port = target.unwrap_or(hello.target_port);
  let sshd = match connect_sshd(target_port).await {
    Ok(sshd) => sshd,
    Err(error) => {
      // A wrong target port, or an sshd that is down, reaches the user
      // through the close reason rather than as a connection loss.
      let reason = format!(
        "server could not reach sshd at 127.0.0.1:{target_port}: {error}"
      );
      transport::close_and_flush(
        &endpoint,
        &connection,
        SERVER_FAILURE_CLOSE_CODE,
        reason.as_bytes(),
      )
      .await;
      bail!(reason);
    }
  };

  // No explicit timeout around the relay: retention is indefinite by
  // design unless `--retain` bounded it via the transport's idle
  // timeout. If sshd closes while the client is unreachable, the
  // engine holds the undelivered tail and the EOF until the client
  // comes back for them.
  let outcome = relay::relay(sshd, send, recv).await;

  let clean = outcome.is_clean();
  transport::close_and_flush(
    &endpoint,
    &connection,
    u32::from(!clean).into(),
    b"session over",
  )
  .await;
  if clean {
    Ok(ExitCode::SUCCESS)
  } else {
    tracing::warn!(?outcome, "session ended uncleanly");
    Ok(ExitCode::FAILURE)
  }
}

/// Starts the destination's end of path establishment over the stdio
/// the detach left on the ssh channel, resuming from the bytes
/// [`read_hello`] read past the hello line.
///
/// This is the destination's whole half of establishment
/// ([`mush_core::path`]): reflect off the helper the client names,
/// advertise what that reveals, and probe outward at the client's own
/// addresses when the rendezvous says to, which is what opens this
/// host's NAT or firewall for the handshake that follows.
///
/// The task owns `release`, the pipe end [`crate::detach::detach`] left
/// the bootstrap ssh's remote command waiting on, so the task returning
/// releases the channel and the parent together and in that order. It
/// returns when the client lets the channel go or when `settled` says
/// the session has been accepted, whichever comes first, handing back
/// what the session's path policy inherits from establishment.
///
/// Signaling is an optimization, so stdio this process cannot take over
/// (a descriptor the reactor refuses, which is what `--no-detach` on a
/// terminal gives) costs the session its signaling and nothing else.
/// The channel still closes on that path: leaving it open would hang
/// the user's bootstrap ssh for the session's whole life.
fn spawn_signaling(
  leftover: Vec<u8>,
  nonce: SessionNonce,
  release: Option<OwnedFd>,
  socket: Arc<TraversalSocket>,
  mut probes: mpsc::Receiver<Probe>,
  settled: oneshot::Receiver<()>,
) -> Option<tokio::task::JoinHandle<Option<DestinationUpgrade>>> {
  let (stdin, stdout) = match take_stdio() {
    Ok(stdio) => stdio,
    Err(error) => {
      tracing::debug!(%error, "no signaling: stdio could not be taken over");
      close_stdio();
      drop(release);
      return None;
    }
  };
  let mut channel =
    SignalChannel::new(tokio::io::join(stdin, stdout), leftover);
  Some(tokio::spawn(async move {
    let mut paths = DestinationPaths::new(nonce);
    {
      let _release = release;
      let driver =
        drive_destination(&mut channel, &socket, &mut probes, &mut paths);
      tokio::pin!(driver);
      tokio::select! {
        biased;
        () = &mut driver => {}
        _ = settled => {}
      }
    }
    tracing::debug!(report = ?paths.report(), "path establishment ended");
    DestinationUpgrade::new(
      tokio::time::Instant::now(),
      paths.handoff(),
      UpgradePolicy::default(),
      socket,
      probes,
    )
  }))
}

/// Connects to the loopback sshd target. Interactive keystrokes must
/// not sit in Nagle buffers on the last hop, hence TCP_NODELAY.
async fn connect_sshd(port: u16) -> std::io::Result<TcpStream> {
  let sshd = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
  sshd.set_nodelay(true)?;
  Ok(sshd)
}
