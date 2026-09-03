// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The relay engine over tokio duplexes and a real loopback quinn pair.

mod common;

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use common::{DEADLINE, Pair, connected_pair};
use mush_core::relay::{
  DirectionEnd, RESET_CODE_LOCAL_READ_FAILED, RelayOutcome,
  STOP_CODE_LOCAL_WRITE_FAILED, relay, relay_split,
};
use rand::RngCore as _;
use rand::SeedableRng as _;
use tokio::io::{
  AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream,
  ReadBuf,
};
use tokio::task::JoinHandle;
use tokio::time::timeout;

fn payload(seed: u64, len: usize) -> Vec<u8> {
  let mut data = vec![0u8; len];
  rand::rngs::StdRng::seed_from_u64(seed).fill_bytes(&mut data);
  data
}

/// The full topology: test <-> duplex `a` <-> client relay <-> QUIC <->
/// server relay <-> duplex `b` <-> test.
struct Splice {
  a: DuplexStream,
  b: DuplexStream,
  client: JoinHandle<RelayOutcome>,
  server: JoinHandle<RelayOutcome>,
  _pair: Pair,
}

async fn splice() -> anyhow::Result<Splice> {
  let pair = connected_pair().await?;
  let (a, a_relay) = tokio::io::duplex(64 * 1024);
  let (b, b_relay) = tokio::io::duplex(64 * 1024);
  let client_connection = pair.client.clone();
  let client = tokio::spawn(async move {
    let (send, recv) = client_connection.open_bi().await.unwrap();
    relay(a_relay, send, recv).await
  });
  let server_connection = pair.server.clone();
  let server = tokio::spawn(async move {
    let (send, recv) = server_connection.accept_bi().await.unwrap();
    relay(b_relay, send, recv).await
  });
  Ok(Splice {
    a,
    b,
    client,
    server,
    _pair: pair,
  })
}

fn assert_clean(outcome: &RelayOutcome, to_peer: u64, from_peer: u64) {
  assert!(outcome.is_clean(), "expected clean outcome: {outcome:?}");
  assert_eq!(outcome.to_peer.bytes, to_peer, "to_peer bytes: {outcome:?}");
  assert_eq!(
    outcome.from_peer.bytes, from_peer,
    "from_peer bytes: {outcome:?}"
  );
}

#[tokio::test]
async fn full_duplex_bulk_both_directions() -> anyhow::Result<()> {
  const UP: usize = 4 * 1024 * 1024;
  const DOWN: usize = 6 * 1024 * 1024;
  let splice = splice().await?;
  let up_payload = payload(1, UP);
  let down_payload = payload(2, DOWN);

  let (a_read, a_write) = tokio::io::split(splice.a);
  let (b_read, b_write) = tokio::io::split(splice.b);
  let drive_a = async {
    let up = up_payload.clone();
    let write = async move {
      let mut a_write = a_write;
      a_write.write_all(&up).await?;
      a_write.shutdown().await?;
      io::Result::Ok(())
    };
    let read = async move {
      let mut a_read = a_read;
      let mut got = Vec::new();
      a_read.read_to_end(&mut got).await?;
      io::Result::Ok(got)
    };
    tokio::try_join!(write, read)
  };
  let drive_b = async {
    let down = down_payload.clone();
    let write = async move {
      let mut b_write = b_write;
      b_write.write_all(&down).await?;
      b_write.shutdown().await?;
      io::Result::Ok(())
    };
    let read = async move {
      let mut b_read = b_read;
      let mut got = Vec::new();
      b_read.read_to_end(&mut got).await?;
      io::Result::Ok(got)
    };
    tokio::try_join!(write, read)
  };
  let ((_, got_down), (_, got_up)) =
    timeout(DEADLINE, async { tokio::try_join!(drive_a, drive_b) }).await??;
  assert!(got_up == up_payload, "upstream payload corrupted");
  assert!(got_down == down_payload, "downstream payload corrupted");

  let client_outcome = timeout(DEADLINE, splice.client).await??;
  let server_outcome = timeout(DEADLINE, splice.server).await??;
  assert_clean(&client_outcome, UP as u64, DOWN as u64);
  assert_clean(&server_outcome, DOWN as u64, UP as u64);
  Ok(())
}

/// TCP-exact half-close: the client side hits EOF first and the FIN
/// must propagate while the response direction keeps flowing. Two
/// shapes, because the empty one is its own case: `ssh host cmd < file`
/// uploads and then half-closes, while `ssh host cmd < /dev/null`
/// closes its write side before sending anything, and a relay that
/// waits for a byte before mapping the FIN hangs only on the second.
#[tokio::test]
async fn half_close_propagates_while_reverse_flows() -> anyhow::Result<()> {
  for (up_len, down_len, seed) in
    [(1024 * 1024, 2 * 1024 * 1024, 3), (0, 512 * 1024, 5)]
  {
    let splice = splice().await?;
    let up_payload = payload(seed, up_len);
    let down_payload = payload(seed + 1, down_len);

    let mut a = splice.a;
    let mut b = splice.b;
    let drive = async {
      // Upload everything, then half-close the client's local side.
      a.write_all(&up_payload).await?;
      a.shutdown().await?;
      // The server side must observe EOF (this read terminating at all
      // proves the FIN mapped through), and only then respond.
      let mut got_up = Vec::new();
      b.read_to_end(&mut got_up).await?;
      assert!(got_up == up_payload, "upstream payload corrupted");
      b.write_all(&down_payload).await?;
      b.shutdown().await?;
      // The response flows over the half-closed session.
      let mut got_down = Vec::new();
      a.read_to_end(&mut got_down).await?;
      assert!(got_down == down_payload, "downstream payload corrupted");
      io::Result::Ok(())
    };
    timeout(DEADLINE, drive).await??;

    let client_outcome = timeout(DEADLINE, splice.client).await??;
    let server_outcome = timeout(DEADLINE, splice.server).await??;
    assert_clean(&client_outcome, up_len as u64, down_len as u64);
    assert_clean(&server_outcome, down_len as u64, up_len as u64);
  }
  Ok(())
}

/// An abruptly lost connection (a peer close with no stream end) must
/// deliver EOF to the local write side -- so the neighboring process
/// can wind down instead of waiting on a dead stream -- and surface as
/// `ConnectionLost` in both directions.
#[tokio::test]
async fn connection_loss_delivers_local_eof() -> anyhow::Result<()> {
  let pair = connected_pair().await?;
  let (mut a, a_relay) = tokio::io::duplex(64 * 1024);
  let client_connection = pair.client.clone();
  let client = tokio::spawn(async move {
    let (send, recv) = client_connection.open_bi().await.unwrap();
    relay(a_relay, send, recv).await
  });

  // Surface the stream on the server side (streams open lazily, with
  // the first bytes), then kill the connection without ending it.
  timeout(DEADLINE, a.write_all(b"x")).await??;
  let (_send, mut recv) = timeout(DEADLINE, pair.server.accept_bi()).await??;
  let mut byte = [0u8; 1];
  timeout(DEADLINE, recv.read_exact(&mut byte)).await??;
  pair.server.close(9u32.into(), b"gone");

  // The relay must deliver a local EOF for the lost connection...
  let mut got = Vec::new();
  timeout(DEADLINE, a.read_to_end(&mut got)).await??;
  assert!(got.is_empty(), "no data was ever sent downstream");
  // ... and finish once the local read side ends too (as ssh closing
  // the pipe after seeing that EOF would).
  timeout(DEADLINE, a.shutdown()).await??;

  let outcome = timeout(DEADLINE, client).await??;
  assert!(
    matches!(outcome.from_peer.end, DirectionEnd::ConnectionLost(_)),
    "outcome: {outcome:?}"
  );
  assert!(
    matches!(outcome.to_peer.end, DirectionEnd::ConnectionLost(_)),
    "outcome: {outcome:?}"
  );
  Ok(())
}

/// Reads `data`, then fails with `kind`: models a local endpoint that
/// dies mid-transfer.
struct FailingReader {
  data: Vec<u8>,
  offset: usize,
  kind: io::ErrorKind,
}

impl AsyncRead for FailingReader {
  fn poll_read(
    mut self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    if self.offset < self.data.len() {
      let n = (self.data.len() - self.offset).min(buf.remaining());
      let offset = self.offset;
      buf.put_slice(&self.data[offset..offset + n]);
      self.offset += n;
      return Poll::Ready(Ok(()));
    }
    Poll::Ready(Err(io::Error::from(self.kind)))
  }
}

/// Accepts `limit` bytes, then fails every write.
struct FailingWriter {
  limit: usize,
}

impl AsyncWrite for FailingWriter {
  fn poll_write(
    mut self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    if self.limit == 0 {
      return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
    }
    let n = buf.len().min(self.limit);
    self.limit -= n;
    Poll::Ready(Ok(n))
  }

  fn poll_flush(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }
}

/// A server-side local read failure becomes a stream reset, and the
/// client surfaces it as `PeerReset` with the documented code.
#[tokio::test]
async fn peer_reset_surfaces_as_typed_outcome() -> anyhow::Result<()> {
  let pair = connected_pair().await?;
  let (a, a_relay) = tokio::io::duplex(64 * 1024);
  let client_connection = pair.client.clone();
  let client = tokio::spawn(async move {
    let (send, recv) = client_connection.open_bi().await.unwrap();
    relay(a_relay, send, recv).await
  });
  let server_connection = pair.server.clone();
  let server = tokio::spawn(async move {
    let (send, recv) = server_connection.accept_bi().await.unwrap();
    let reader = FailingReader {
      data: payload(6, 128 * 1024),
      offset: 0,
      kind: io::ErrorKind::ConnectionReset,
    };
    relay_split(reader, tokio::io::sink(), send, recv).await
  });

  // Half-close the client's local side so its uplink ends cleanly and
  // the stream opens; then drain whatever arrives before the reset.
  let (mut a_read, mut a_write) = tokio::io::split(a);
  timeout(DEADLINE, a_write.shutdown()).await??;
  let mut got = Vec::new();
  let _ = timeout(DEADLINE, a_read.read_to_end(&mut got)).await?;

  let client_outcome = timeout(DEADLINE, client).await??;
  let server_outcome = timeout(DEADLINE, server).await??;
  assert!(
    matches!(
      client_outcome.from_peer.end,
      DirectionEnd::PeerReset(code) if code == RESET_CODE_LOCAL_READ_FAILED
    ),
    "client outcome: {client_outcome:?}"
  );
  assert!(
    matches!(client_outcome.to_peer.end, DirectionEnd::Clean),
    "client outcome: {client_outcome:?}"
  );
  assert!(
    matches!(server_outcome.to_peer.end, DirectionEnd::LocalError(_)),
    "server outcome: {server_outcome:?}"
  );
  Ok(())
}

/// A server-side local write failure becomes STOP_SENDING, and the
/// client's sending direction surfaces it as `PeerStopped` with the
/// documented code.
#[tokio::test]
async fn peer_stop_surfaces_as_typed_outcome() -> anyhow::Result<()> {
  let pair = connected_pair().await?;
  let (a, a_relay) = tokio::io::duplex(64 * 1024);
  let client_connection = pair.client.clone();
  let client = tokio::spawn(async move {
    let (send, recv) = client_connection.open_bi().await.unwrap();
    relay(a_relay, send, recv).await
  });
  let server_connection = pair.server.clone();
  let server = tokio::spawn(async move {
    let (send, recv) = server_connection.accept_bi().await.unwrap();
    relay_split(
      tokio::io::empty(),
      FailingWriter { limit: 64 * 1024 },
      send,
      recv,
    )
    .await
  });

  // Pump data upstream until the relay tears the duplex down; the stop
  // has to travel server -> client, so this cannot be a single write.
  let (mut a_read, mut a_write) = tokio::io::split(a);
  let chunk = payload(7, 64 * 1024);
  let pump = async {
    while a_write.write_all(&chunk).await.is_ok() {
      tokio::time::sleep(Duration::from_millis(1)).await;
    }
  };
  timeout(DEADLINE, pump).await?;
  let mut got = Vec::new();
  let _ = timeout(DEADLINE, a_read.read_to_end(&mut got)).await?;
  assert!(got.is_empty(), "server sent no data");

  let client_outcome = timeout(DEADLINE, client).await??;
  let server_outcome = timeout(DEADLINE, server).await??;
  assert!(
    matches!(
      client_outcome.to_peer.end,
      DirectionEnd::PeerStopped(code) if code == STOP_CODE_LOCAL_WRITE_FAILED
    ),
    "client outcome: {client_outcome:?}"
  );
  assert!(
    matches!(client_outcome.from_peer.end, DirectionEnd::Clean),
    "client outcome: {client_outcome:?}"
  );
  assert!(
    matches!(server_outcome.from_peer.end, DirectionEnd::LocalError(_)),
    "server outcome: {server_outcome:?}"
  );
  Ok(())
}
