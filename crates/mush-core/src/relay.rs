// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The byte splice engine used by every Mush process: bidirectional copy
//! between a local byte stream (ProxyCommand stdio on the client, the
//! loopback sshd TCP socket on the server, in-memory duplexes in tests)
//! and one QUIC bidirectional stream.
//!
//! The engine reproduces TCP semantics exactly, including independent
//! half-close of each direction (design doc, "Session lifecycle: Relay"):
//!
//! - Local read EOF becomes [`quinn::SendStream::finish`] (a stream
//!   FIN); the opposite direction keeps relaying.
//! - A clean peer FIN ([`quinn::RecvStream::read`] returning `Ok(None)`)
//!   becomes a shutdown of the local write side, the `SHUT_WR` analogue.
//!   The engine's one demand on the local endpoint: `poll_shutdown` must
//!   deliver EOF to whatever reads from it (half-close the socket, close
//!   the descriptor). `tokio::net::TcpStream` and in-memory duplexes
//!   qualify; `tokio::io::stdout()` does not -- its shutdown only
//!   flushes and never closes fd 1, so a peer FIN would never reach the
//!   ssh process behind a ProxyCommand pipe. The client wraps its stdout
//!   in an owned pipe handle whose shutdown closes it.
//! - An abrupt local read failure becomes [`quinn::SendStream::reset`]
//!   with [`RESET_CODE_LOCAL_READ_FAILED`]; a local write failure
//!   becomes [`quinn::RecvStream::stop`] with
//!   [`STOP_CODE_LOCAL_WRITE_FAILED`].
//! - A peer reset or stop surfaces as a typed [`DirectionEnd`] carrying
//!   the peer's application error code. On a peer reset the local write
//!   side is closed; a generic `AsyncWrite` has no RST analogue, so this
//!   is an orderly close, and callers that own a real socket can act on
//!   the surfaced code if they need more.
//! - A lost connection ends both directions at once and likewise closes
//!   the local write side: the process on the other end of the pipe
//!   (ssh, on a ProxyCommand) sees EOF and winds down instead of waiting
//!   forever on a byte stream that can no longer move. That EOF is the
//!   one place the engine makes a failure look like a success, and it is
//!   deliberate: the alternative hangs ssh on a dead stream, and ssh has
//!   its own framing to notice a transport cut short. The local stream
//!   cannot tell that EOF from a clean one, so the whole truth is in the
//!   returned [`RelayOutcome`]; a caller that ignores it reports a
//!   truncated transfer as finished.
//!
//! Buffering is one fixed [`BUF_BYTES`] buffer per direction; QUIC
//! stream flow control (sized in [`crate::transport`]) provides all
//! backpressure, so an outage fills the window and stalls the local
//! reader exactly as a stalled TCP socket would. The other half of that
//! backpressure is this engine parking in `local.write_all` and reading
//! nothing from the stream until the sink drains, leaving the peer's
//! data unread in the receive window. The window bounds those bytes; it
//! does not bound the buffers the receiver holds one of per unread
//! frame, and a transport that gives up on a deep backlog surfaces here
//! as a lost connection on a healthy path.
//! `mush-core/tests/relay_netsim.rs` runs that shape end to end, and is
//! what the pinned quinn revision's assembler fix exists for (root
//! `Cargo.toml`).

use std::io;
use std::pin::Pin;

use quinn::{
  ReadError, RecvStream, SendStream, StoppedError, VarInt, WriteError,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tracing::debug;

/// Copy buffer size per direction.
pub const BUF_BYTES: usize = 16 * 1024;

/// Application error code sent in RESET_STREAM when the local read side
/// fails abruptly: the peer's reads then fail with this code instead of
/// seeing a fake clean EOF.
pub const RESET_CODE_LOCAL_READ_FAILED: VarInt = VarInt::from_u32(1);

/// Application error code sent in STOP_SENDING when the local write side
/// fails: tells the peer to stop transmitting data that can no longer be
/// delivered.
pub const STOP_CODE_LOCAL_WRITE_FAILED: VarInt = VarInt::from_u32(2);

/// How one relay direction ended.
#[derive(Debug)]
pub enum DirectionEnd {
  /// Clean EOF, fully propagated. Toward the peer this additionally
  /// means every byte was acknowledged ([`quinn::SendStream::stopped`]
  /// resolved `None` after the FIN), so a clean/clean outcome is safe to
  /// follow with a connection close.
  Clean,
  /// The peer aborted its sending side; reads failed with this code.
  PeerReset(VarInt),
  /// The peer stopped its receiving side; writes failed with this code.
  PeerStopped(VarInt),
  /// The QUIC connection itself was lost.
  ConnectionLost(quinn::ConnectionError),
  /// The local endpoint failed, after signaling the peer with the
  /// direction's documented abort code where the stream still allowed
  /// it.
  LocalError(io::Error),
}

/// One direction's result: bytes successfully relayed and how it ended.
#[derive(Debug)]
pub struct DirectionOutcome {
  /// Bytes fully relayed: read from the source and completely written
  /// to the destination.
  pub bytes: u64,
  /// How the direction ended.
  pub end: DirectionEnd,
}

/// The result of a completed relay: both directions have ended.
#[derive(Debug)]
pub struct RelayOutcome {
  /// The local-to-peer direction (local reads, QUIC sends).
  pub to_peer: DirectionOutcome,
  /// The peer-to-local direction (QUIC reads, local writes).
  pub from_peer: DirectionOutcome,
}

impl RelayOutcome {
  /// Whether both directions ended in clean, fully acknowledged EOF.
  pub fn is_clean(&self) -> bool {
    matches!(self.to_peer.end, DirectionEnd::Clean)
      && matches!(self.from_peer.end, DirectionEnd::Clean)
  }
}

/// Splices `local` and the QUIC stream until both directions end.
///
/// Never returns early: a half-close in one direction leaves the other
/// relaying, so `ssh host cmd < file` behaves exactly as over TCP. The
/// QUIC connection itself is not closed; that stays with the caller,
/// which typically closes it once the outcome [`RelayOutcome::is_clean`].
///
/// `local`'s write half must deliver EOF from its `poll_shutdown`, or
/// peer FINs are lost; see the module docs for what qualifies.
pub async fn relay<L>(
  local: L,
  send: SendStream,
  recv: RecvStream,
) -> RelayOutcome
where
  L: AsyncRead + AsyncWrite,
{
  let (local_read, local_write) = tokio::io::split(local);
  relay_split(local_read, local_write, send, recv).await
}

/// [`relay`] over independently owned local read and write halves, for
/// local endpoints that are not a single object (stdin/stdout, or test
/// harnesses injecting failures on one side).
///
/// `local_write` carries the same `poll_shutdown`-delivers-EOF
/// requirement as [`relay`].
pub async fn relay_split<R, W>(
  local_read: R,
  local_write: W,
  mut send: SendStream,
  mut recv: RecvStream,
) -> RelayOutcome
where
  R: AsyncRead,
  W: AsyncWrite,
{
  tokio::pin!(local_read, local_write);
  let (to_peer, from_peer) = tokio::join!(
    copy_local_to_peer(local_read, &mut send),
    copy_peer_to_local(local_write, &mut recv),
  );
  debug!(?to_peer, ?from_peer, "relay finished");
  RelayOutcome { to_peer, from_peer }
}

/// Relays local reads into the QUIC send stream until EOF or failure.
async fn copy_local_to_peer<R: AsyncRead>(
  mut local: Pin<&mut R>,
  send: &mut SendStream,
) -> DirectionOutcome {
  let mut buf = vec![0u8; BUF_BYTES];
  let mut bytes = 0u64;
  loop {
    let end = match local.read(&mut buf).await {
      Ok(0) => {
        // finish() only fails once the stream is already finished or
        // reset, which this loop rules out.
        let _ = send.finish();
        debug!(bytes, "local EOF, stream finished; awaiting delivery");
        match send.stopped().await {
          Ok(None) => DirectionEnd::Clean,
          Ok(Some(code)) => DirectionEnd::PeerStopped(code),
          Err(StoppedError::ConnectionLost(e)) => {
            DirectionEnd::ConnectionLost(e)
          }
          Err(e @ StoppedError::ZeroRttRejected) => {
            DirectionEnd::LocalError(io::Error::other(e))
          }
        }
      }
      Ok(n) => match send.write_all(&buf[..n]).await {
        Ok(()) => {
          bytes += n as u64;
          continue;
        }
        Err(WriteError::Stopped(code)) => DirectionEnd::PeerStopped(code),
        Err(WriteError::ConnectionLost(e)) => DirectionEnd::ConnectionLost(e),
        Err(e @ (WriteError::ClosedStream | WriteError::ZeroRttRejected)) => {
          DirectionEnd::LocalError(io::Error::other(e))
        }
      },
      Err(error) => {
        // Abrupt local failure: propagate as an abort, not a clean FIN.
        let _ = send.reset(RESET_CODE_LOCAL_READ_FAILED);
        debug!(bytes, %error, "local read failed, stream reset");
        DirectionEnd::LocalError(error)
      }
    };
    return DirectionOutcome { bytes, end };
  }
}

/// Relays QUIC receive-stream data into local writes until EOF or
/// failure.
async fn copy_peer_to_local<W: AsyncWrite>(
  mut local: Pin<&mut W>,
  recv: &mut RecvStream,
) -> DirectionOutcome {
  let mut buf = vec![0u8; BUF_BYTES];
  let mut bytes = 0u64;
  loop {
    let end = match recv.read(&mut buf).await {
      Ok(Some(n)) => match local.write_all(&buf[..n]).await {
        Ok(()) => {
          bytes += n as u64;
          continue;
        }
        Err(error) => {
          let _ = recv.stop(STOP_CODE_LOCAL_WRITE_FAILED);
          debug!(bytes, %error, "local write failed, stream stopped");
          DirectionEnd::LocalError(error)
        }
      },
      Ok(None) => {
        // Peer FIN, all data delivered: propagate as SHUT_WR.
        debug!(bytes, "peer EOF, shutting down local write side");
        match local.shutdown().await {
          Ok(()) => DirectionEnd::Clean,
          Err(error) => DirectionEnd::LocalError(error),
        }
      }
      Err(ReadError::Reset(code)) => {
        debug!(bytes, code = code.into_inner(), "peer reset");
        let _ = local.shutdown().await;
        DirectionEnd::PeerReset(code)
      }
      Err(ReadError::ConnectionLost(e)) => {
        // The connection is gone in both directions; deliver the local
        // EOF so the neighboring process can wind down (see the module
        // docs).
        debug!(bytes, error = %e, "connection lost, closing local write side");
        let _ = local.shutdown().await;
        DirectionEnd::ConnectionLost(e)
      }
      Err(
        e @ (ReadError::ClosedStream
        | ReadError::IllegalOrderedRead
        | ReadError::ZeroRttRejected),
      ) => DirectionEnd::LocalError(io::Error::other(e)),
    };
    return DirectionOutcome { bytes, end };
  }
}
