// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! `mush jump-helper`: the traversal assistance service on a jump host.
//!
//! The lifecycle mirrors `mush server bootstrap` exactly, and literally
//! -- both run through [`crate::remote`]: an opening conversation that
//! runs synchronously because the detach behind it must fork before any
//! tokio runtime exists ([`crate::detach`]), the UDP port bound before
//! anything is announced, and self-destruction if the client never
//! arrives.
//!
//! - Control arrives on stdin: a `MUSH SERVE` line naming the session
//!   nonce this helper is authorized to serve. It comes over the jump
//!   host's own ssh channel, which is the only authority in the whole
//!   service.
//! - The helper binds a UDP port from the same range the destination
//!   server uses, and answers with a `MUSH READY` line naming that port
//!   and the addresses it can be reached at.
//! - It detaches, keeping the channel open in the holding form: the
//!   client keeps sending control lines (further sessions, and the
//!   `MUSH CLOSE` that ends one), and the helper keeps reporting each
//!   peer's arrival as a `MUSH PEER` line. The channel is released the
//!   moment the client hangs up, which is what lets the helper's ssh
//!   finish while the relay it set up keeps running.
//! - It lingers while serving: indefinitely by default so a relayed
//!   session survives a long offline period, bounded by `--retain`.
//!
//! Everything about what the service will and will not do for a
//! datagram lives in [`mush_core::helper`], including the security
//! posture; this process only hosts it.

use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::OwnedFd;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context as _, Result};
use mush_core::bootstrap::PROTOCOL_VERSION;
use mush_core::helper::{
  Control, ExitReason, HelperChannel, HelperMessage, HelperOptions,
  HelperService, MAX_SERVE_BYTES, Ready, Registration, Serve, serve,
};
use mush_core::server::{
  DEFAULT_PORT_RANGE, addr_hints, bind_socket, interface_ips,
  ssh_connection_client_ip,
};
use tokio::sync::mpsc;

use crate::detach::close_stdio;
use crate::remote;
use crate::stdio::take_stdio;

/// Depth of the queues between the ssh channel and the datagram
/// handling.
/// Both carry a handful of messages per session; the bound is what
/// keeps a client that stopped reading from growing a queue instead of
/// losing reports.
const CONTROL_QUEUE: usize = 16;

/// Runs `mush jump-helper`. `retain` bounds how long a silent session
/// keeps this helper alive; `None` retains indefinitely, mosh-style
/// (the design's default).
pub fn run(no_detach: bool, retain: Option<Duration>) -> Result<ExitCode> {
  // The service's own bootstrap timeout covers the wait for the first
  // peer that follows.
  remote::arm_bootstrap_alarm();

  // The unspecified address, so the helper answers on every address a
  // dual-homed bastion has: the client reaches it on the public one and
  // the destination on the one facing its own network, which is the
  // reason a jump host is where the relay belongs.
  let socket =
    bind_socket(IpAddr::V4(Ipv4Addr::UNSPECIFIED), &DEFAULT_PORT_RANGE)?;
  let local = socket.local_addr()?;
  let udp_port = local.port();
  let (first, leftover) = read_serve()?;

  // The same hint gathering the destination does: the address the
  // client reached over ssh leads, because it is the one address the
  // client demonstrably has a path to, and this host's own interfaces
  // follow, which is how a destination on the jump's other network
  // reaches it.
  let ssh_connection = std::env::var("SSH_CONNECTION").ok();
  let ready = Ready {
    version: PROTOCOL_VERSION,
    udp_port,
    // The jump's own view of the client, which the channel this helper
    // already runs on provides with no extra exchange. It is what the
    // destination's reverse punch aims at when this helper's UDP turns
    // out to be unreachable, so a helper that answers degrades no worse
    // than a bastion with none.
    client_ip: ssh_connection.as_deref().and_then(ssh_connection_client_ip),
    addr_hints: addr_hints(ssh_connection.as_deref(), &interface_ips(), local),
  };
  remote::announce(
    &ready.to_wire(),
    "writing MUSH READY to the helper channel",
  )?;

  // Always the holding detach: the control channel runs for as long as
  // the client keeps the channel open, in both directions.
  remote::run_detached(no_detach, true, |release| {
    assist(socket, first, leftover, release, retain)
  })
}

/// Reads the `MUSH SERVE` line the client opens with, with any bytes
/// read past it: the mirror of the server's hello read.
fn read_serve() -> Result<(Serve, Vec<u8>)> {
  let (line, leftover) =
    remote::read_opening_line(MAX_SERVE_BYTES, "MUSH SERVE", "helper channel")?;
  let serve = Serve::parse(&line)?;
  remote::check_version(serve.version)?;
  Ok((serve, leftover))
}

/// The service proper: the datagram handling on the pre-bound socket,
/// with the control channel over ssh alongside it.
async fn assist(
  socket: std::net::UdpSocket,
  first: Serve,
  leftover: Vec<u8>,
  release: Option<OwnedFd>,
  retain: Option<Duration>,
) -> Result<ExitCode> {
  socket
    .set_nonblocking(true)
    .context("making the traversal socket nonblocking")?;
  let socket = tokio::net::UdpSocket::from_std(socket)
    .context("adopting the traversal socket")?;

  let now = tokio::time::Instant::now();
  let mut service = HelperService::new(
    now,
    HelperOptions {
      retain,
      ..HelperOptions::default()
    },
  );
  // The nonce from the opening line is authorized exactly like every
  // later one: it arrived over the authenticated channel.
  service
    .admit(now, first.nonce, first.secret)
    .context("admitting the session from the MUSH SERVE line")?;

  let (control_tx, mut control_rx) = mpsc::channel(CONTROL_QUEUE);
  let (registrations_tx, registrations_rx) = mpsc::channel(CONTROL_QUEUE);
  let control = spawn_control(leftover, release, control_tx, registrations_rx);
  let reason =
    serve(&socket, &mut service, &mut control_rx, &registrations_tx).await;

  // Ending the control channel releases the ssh channel and the process
  // waiting on it, in that order; awaiting the abort is what makes the
  // release ordered rather than eventual.
  if let Some(control) = control {
    control.abort();
    let _ = control.await;
  }
  tracing::debug!(?reason, "jump helper finished");
  match reason {
    // Nobody came, or the socket died: the traversal this helper was
    // started for did not happen, and the exit status says so for the
    // foreground case (a detached helper's stderr is /dev/null).
    ExitReason::Unused | ExitReason::SocketFailed => {
      tracing::warn!(?reason, "jump helper served no session");
      Ok(ExitCode::FAILURE)
    }
    _ => Ok(ExitCode::SUCCESS),
  }
}

/// Starts the control channel over the stdio the detach left on the ssh
/// channel, resuming from the bytes [`read_serve`] read past the serve
/// line.
///
/// It reads the client's control lines into `control` and writes each
/// peer registration back as a `MUSH PEER` line, until the client hangs
/// up. Then it closes the channel and releases `release`, which finishes
/// the helper's ssh while the datagram handling keeps serving: a
/// relayed session outlives the channel that set it up.
///
/// The service must never fail for want of a control channel, so stdio
/// this process cannot take over (`--no-detach` on a terminal, whose
/// descriptor the reactor refuses) costs the helper its reports and
/// nothing else, and the channel still closes, since leaving it open
/// would hang the user's ssh for the session's life.
fn spawn_control(
  leftover: Vec<u8>,
  release: Option<OwnedFd>,
  control: mpsc::Sender<Control>,
  mut registrations: mpsc::Receiver<Registration>,
) -> Option<tokio::task::JoinHandle<()>> {
  let (stdin, stdout) = match take_stdio() {
    Ok(stdio) => stdio,
    Err(error) => {
      tracing::debug!(%error, "no control channel: stdio could not be taken over");
      close_stdio();
      drop(release);
      return None;
    }
  };
  let mut channel =
    HelperChannel::new(tokio::io::join(stdin, stdout), leftover);
  Some(tokio::spawn(async move {
    loop {
      // One task drives both directions, so the read is cancelled
      // every time a report goes out; `recv` is cancel-safe for
      // exactly this.
      tokio::select! {
        biased;
        message = channel.recv() => match message {
          Ok(Some(HelperMessage::Serve(serve))) => {
            let command = Control::Serve {
              nonce: serve.nonce,
              secret: serve.secret,
            };
            if control.send(command).await.is_err() {
              break;
            }
          }
          Ok(Some(HelperMessage::Close(close))) => {
            if control.send(Control::Close(close.nonce)).await.is_err() {
              break;
            }
          }
          // The helper's own messages, echoed back at it. Nothing to
          // do, and no reason to end a session over it.
          Ok(Some(message)) => tracing::debug!(%message, "unexpected control line"),
          Ok(None) => break,
          Err(error) => {
            tracing::debug!(%error, "helper channel ended");
            break;
          }
        },
        registration = registrations.recv() => match registration {
          Some(registration) => {
            if let Err(error) = channel.send(&registration.message()).await {
              tracing::debug!(%error, "peer report failed");
              break;
            }
          }
          None => break,
        },
      }
    }
    // Descriptors first, then the release pipe: the parent must not be
    // released before the channel it is holding open is finished with.
    drop(channel);
    close_stdio();
    drop(release);
  }))
}
