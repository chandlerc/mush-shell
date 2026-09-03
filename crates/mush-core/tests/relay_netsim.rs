// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The relay against a local sink that stops draining, on the
//! deterministic simulated network.
//!
//! The transport policy's receive window doubles as the session's buffer
//! bound ("Connection configuration" in the design doc): a local
//! endpoint that stops reading -- ssh not draining its ProxyCommand
//! pipe, an sshd busy elsewhere -- parks the relay in a local write, and
//! what the peer keeps sending piles up unread. Outage survival is built
//! on that shape, so the session must come out of it with every byte in
//! order and the connection live, however deep the backlog got.
//!
//! The window is sized in bytes, but a receiver holds one buffer per
//! unread STREAM frame, and that count is what this drives up.
//! quinn-proto kills the connection with `INTERNAL_ERROR("too many gaps
//! in stream buffer")` past 2048 buffered frames, even with no gaps,
//! because its assembler will not merge chunks already flagged as
//! defragmented; Mush runs on a revision that coalesces contiguous runs
//! instead (root `Cargo.toml`). Against a quinn without the fix --
//! every release, and upstream's own main -- this truncates at roughly
//! 3MB of the 8MB downstream.
//!
//! Determinism rules per mush-netsim's crate docs: current-thread
//! runtime, `start_paused`, no real sockets, `biased` selects.

mod common;

use std::time::Duration;

use common::netsim::{DEADLINE, establish, wan};
use common::payload;
use mush_core::relay::relay;
use mush_core::transport::TransportOptions;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::time::timeout;

/// Bytes the peer sends while the sink is stalled. Under the default
/// window, so flow control never stops the sender and the whole payload
/// buffers unread at once; large enough to be thousands of frames.
const DOWN: usize = 8 * 1024 * 1024;

/// How long the sink refuses to read; virtual time, so its only job is
/// to outlast the transfer.
const STALL: Duration = Duration::from_secs(10);

/// The backlog the scenario has to build to be testing anything. Past
/// the 2048 frames that trip the bug above, so a transfer arriving in
/// fewer, larger frames -- a bigger path MTU, a future quinn coalescing
/// differently -- fails here rather than passing without covering the
/// shape.
const STALLED_FRAMES: u64 = 4096;

#[tokio::test(start_paused = true)]
async fn stalled_local_sink_keeps_the_session_and_every_byte()
-> anyhow::Result<()> {
  const SEED: u64 = 0x6d757368;
  let net = wan(SEED);
  // Both sessions are held for the whole scenario: each owns its
  // endpoint, and dropping one tears its connection down.
  let (client, server) =
    establish(&net, SEED, TransportOptions::default()).await?;
  let connection = client.connection.clone();

  // Nothing reads `local`, so the relay fills the duplex, blocks in its
  // local write, and stops reading the stream: what the peer sends goes
  // nowhere but the receive window.
  let (mut local, local_relay) = tokio::io::duplex(64 * 1024);
  let relaying = tokio::spawn(relay(local_relay, client.send, client.recv));
  // The uplink carries nothing; ending it early leaves just the one
  // direction under test.
  local.shutdown().await?;

  let expected = payload(DOWN);
  let mut send = server.send;
  let sending = {
    let down = expected.clone();
    tokio::spawn(async move {
      send.write_all(&down).await?;
      send.finish()?;
      anyhow::Ok(())
    })
  };
  tokio::time::sleep(STALL).await;
  let stalled = connection.stats().frame_rx.stream;

  let mut got = Vec::new();
  timeout(DEADLINE, local.read_to_end(&mut got)).await??;
  assert_eq!(
    got.len(),
    DOWN,
    "downstream truncated; the first thing to suspect is the transport \
     giving up on the frame backlog; the root Cargo.toml has why the \
     quinn revision is pinned"
  );
  assert!(got == expected, "downstream payload corrupted");
  let outcome = timeout(DEADLINE, relaying).await??;
  assert!(outcome.is_clean(), "expected clean outcome: {outcome:?}");
  timeout(DEADLINE, sending).await???;
  assert!(
    stalled >= STALLED_FRAMES,
    "only {stalled} stream frames arrived while the sink was stalled: \
     the scenario no longer builds the backlog it exists to test"
  );
  Ok(())
}
