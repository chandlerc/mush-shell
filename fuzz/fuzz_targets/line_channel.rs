// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! `LineChannel` fed an arbitrary byte stream in arbitrary chunks.
//!
//! The framing that carries signaling on the bootstrap channel and all
//! control traffic on the jump helper's channel. It resumes from the
//! leftover bytes its opener read past the first line, so a prefix of the
//! stream arrives that way rather than through the reader. Its contract
//! matches the connect scanner's: never panic, buffer no more than one
//! line and one read, skip only what the non-protocol budget allows,
//! yield the same messages however the bytes were chunked.
//!
//! The handoff has two sides. Starting from leftover bytes must be
//! indistinguishable from having read those bytes off the wire, which is
//! what `new`'s leftover argument promises; `into_parts`, its inverse,
//! must hand the channel on so a resuming phase continues the message
//! sequence exactly where the last stopped -- the arithmetic every
//! handover between the bootstrap phases and the traversal driver
//! depends on.

#![no_main]

use std::io;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use mush_core::bootstrap::{MAX_LINE_BYTES, Signal};
use mush_core::channel::{
  LineChannel, LineError, LineLimits, LineMessage, READ_CHUNK,
};
use mush_core::helper::HelperMessage;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::runtime::Runtime;

/// The largest chunk the input can ask for: past both the per-line
/// bound and the channel's own read size.
const MAX_CHUNK: usize = 16 * 1024;

/// One channel's lifetime: which message set it carries, its
/// non-protocol budget, how much of the stream its opener already read,
/// how many messages the borrowing phase takes before handing the channel
/// back, and the chunk lengths the rest arrives in.
///
/// The stream is a borrowed slice in the last field for the reason
/// `connect_scanner.rs` gives, so a corpus entry is a 16-byte header
/// followed by literal channel output.
#[derive(Arbitrary, Debug)]
struct Session<'a> {
  helper: bool,
  budget_lines: u16,
  budget_bytes: u16,
  leftover_bytes: u16,
  resume_after: u8,
  splits: [u16; 4],
  stream: &'a [u8],
}

impl<'a> Session<'a> {
  /// The bytes the opening phase already read, and the rest.
  fn split_leftover(&self) -> (&'a [u8], &'a [u8]) {
    let at = usize::from(self.leftover_bytes) % (self.stream.len() + 1);
    self.stream.split_at(at)
  }

  fn chunks(&self, mut rest: &'a [u8]) -> Vec<&'a [u8]> {
    let mut chunks = Vec::new();
    let mut split = 0;
    while !rest.is_empty() {
      let take =
        (1 + usize::from(self.splits[split % 4]) % MAX_CHUNK).min(rest.len());
      let (chunk, tail) = rest.split_at(take);
      chunks.push(chunk);
      rest = tail;
      split += 1;
    }
    chunks
  }
}

/// A reader that hands out one chunk per poll, so the channel's line
/// splitting meets exactly the boundaries the input asked for.
struct Chunked<'a> {
  chunks: &'a [&'a [u8]],
  chunk: usize,
  offset: usize,
}

impl<'a> Chunked<'a> {
  fn new(chunks: &'a [&'a [u8]]) -> Self {
    Self {
      chunks,
      chunk: 0,
      offset: 0,
    }
  }
}

impl AsyncRead for Chunked<'_> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    let me = &mut *self;
    while me.chunk < me.chunks.len() {
      let current = me.chunks[me.chunk];
      if me.offset >= current.len() {
        me.chunk += 1;
        me.offset = 0;
        continue;
      }
      let take = (current.len() - me.offset).min(buf.remaining());
      if take == 0 {
        break;
      }
      buf.put_slice(&current[me.offset..me.offset + take]);
      me.offset += take;
      break;
    }
    // Running out of chunks fills nothing, which is end of stream.
    Poll::Ready(Ok(()))
  }
}

/// How a channel's receive loop ended.
#[derive(Debug, PartialEq)]
enum Ending {
  Eof,
  Malformed,
  NonProtocolLimit,
}

/// What one channel is held to over one stream: the non-protocol budget
/// it was given, the bytes it is fed in all, and the most it may ever
/// hold.
#[derive(Clone, Copy)]
struct Bounds {
  limits: LineLimits,
  fed: usize,
  buffered: usize,
}

impl Bounds {
  fn new(limits: LineLimits, leftover: &[u8], chunks: &[&[u8]]) -> Self {
    Self {
      limits,
      fed: leftover.len() + chunks.iter().map(|c| c.len()).sum::<usize>(),
      // Leftover bytes arrive whole, so the channel starts out holding
      // all of them; everything past that is one line and one read at
      // most, however long the stream and however few newlines it
      // carries.
      buffered: MAX_LINE_BYTES + READ_CHUNK + leftover.len(),
    }
  }
}

/// Receives into `messages` until the channel ends or `take` of them
/// have arrived, checking the bounds contract at every step. Reports how
/// the channel ended, or `None` when it stopped only because `take` was
/// reached and the channel is still live.
fn pump<M: LineMessage>(
  channel: &mut LineChannel<Chunked<'_>, M>,
  messages: &mut Vec<String>,
  bounds: Bounds,
  take: usize,
) -> Option<Ending> {
  let Bounds {
    limits,
    fed,
    buffered,
  } = bounds;
  runtime().block_on(async {
    while messages.len() < take {
      let received = channel.recv().await;
      // The memory bound, which nothing else here would notice going: an
      // overlong line is dropped rather than buffered, so a stream that
      // never sends a newline cannot make the channel grow.
      assert!(
        channel.buffered_bytes() <= buffered,
        "the channel is holding {} bytes on a {buffered}-byte bound",
        channel.buffered_bytes()
      );
      match received {
        Ok(Some(message)) => {
          let wire = message.to_wire();
          let again = M::parse(&wire)
            .expect("a line this encoder produced must parse again")
            .expect("a line this encoder produced must still be a message");
          assert_eq!(
            again.to_wire(),
            wire,
            "re-encoding a received message is not stable"
          );
          messages.push(wire);
        }
        Ok(None) => return Some(Ending::Eof),
        Err(LineError::Malformed(_)) => return Some(Ending::Malformed),
        Err(LineError::NonProtocolLimit { .. }) => {
          return Some(Ending::NonProtocolLimit);
        }
        Err(LineError::Io(error)) => panic!("the reader cannot fail: {error}"),
      }
      // `recv` checks the non-protocol budget last, so a returned
      // message leaves the channel strictly inside it, having ignored no
      // more than it read.
      assert!(
        channel.ignored_lines() < limits.max_ignored_lines,
        "the channel skipped {} lines on a {}-line budget",
        channel.ignored_lines(),
        limits.max_ignored_lines
      );
      assert!(
        channel.ignored_bytes() < limits.max_ignored_bytes,
        "the channel skipped {} bytes on a {}-byte budget",
        channel.ignored_bytes(),
        limits.max_ignored_bytes
      );
      assert!(
        channel.ignored_bytes() <= fed,
        "the channel skipped {} bytes over a {fed}-byte stream",
        channel.ignored_bytes()
      );
    }
    None
  })
}

/// Drains a channel; reports the messages it yielded and how it ended.
fn drain<M: LineMessage>(
  leftover: &[u8],
  chunks: &[&[u8]],
  limits: LineLimits,
) -> (Vec<String>, Ending) {
  let bounds = Bounds::new(limits, leftover, chunks);
  let mut channel: LineChannel<_, M> =
    LineChannel::with_limits(Chunked::new(chunks), leftover.to_vec(), limits);
  let mut messages = Vec::new();
  let ending = pump(&mut channel, &mut messages, bounds, usize::MAX)
    .expect("an unbounded drain ends only when the channel does");
  (messages, ending)
}

/// The same drain, with the channel handed back after `take` messages
/// and a second channel built from what `into_parts` returned.
fn drain_resumed<M: LineMessage>(
  leftover: &[u8],
  chunks: &[&[u8]],
  limits: LineLimits,
  take: usize,
) -> (Vec<String>, Ending) {
  let bounds = Bounds::new(limits, leftover, chunks);
  let mut channel: LineChannel<_, M> =
    LineChannel::with_limits(Chunked::new(chunks), leftover.to_vec(), limits);
  let mut messages = Vec::new();
  if let Some(ending) = pump(&mut channel, &mut messages, bounds, take) {
    return (messages, ending);
  }
  let (reader, leftover) = channel.into_parts();
  // The handover is the resumed channel's leftover bytes, so it starts
  // out holding whatever the first one had read past its last message.
  let bounds = Bounds {
    buffered: MAX_LINE_BYTES + READ_CHUNK + leftover.len(),
    ..bounds
  };
  let mut channel: LineChannel<_, M> =
    LineChannel::with_limits(reader, leftover, limits);
  let ending = pump(&mut channel, &mut messages, bounds, usize::MAX)
    .expect("an unbounded drain ends only when the channel does");
  (messages, ending)
}

/// Every pass over one message set: the budget contract under an
/// input-chosen budget, then the three equivalences with it lifted --
/// chunking, starting from leftover bytes, and the handover.
fn exercise<M: LineMessage>(session: &Session<'_>) {
  let (leftover, rest) = session.split_leftover();
  let chunks = session.chunks(rest);
  let limits = LineLimits {
    max_ignored_lines: 1 + usize::from(session.budget_lines) % 64,
    max_ignored_bytes: 1 + usize::from(session.budget_bytes),
  };
  drain::<M>(leftover, &chunks, limits);

  let unlimited = LineLimits {
    max_ignored_lines: usize::MAX,
    max_ignored_bytes: usize::MAX,
  };
  let whole = drain::<M>(leftover, &chunks, unlimited);
  assert_eq!(
    whole,
    drain::<M>(leftover, &[rest], unlimited),
    "chunking changed what the channel received"
  );
  // Leftover bytes are a prefix handed over out of band, so they must
  // read the same as a stream that carried them.
  assert_eq!(
    whole,
    drain::<M>(&[], &[session.stream], unlimited),
    "starting from leftover bytes changed what the channel received"
  );
  // `into_parts` at an input-chosen message, then a fresh channel from
  // what it returned: the sequence must be the same one, unbroken.
  assert_eq!(
    whole,
    drain_resumed::<M>(
      leftover,
      &chunks,
      unlimited,
      usize::from(session.resume_after)
    ),
    "handing the channel over changed what it received"
  );
}

/// One runtime per worker: the reader never yields, so `block_on` only
/// has to drive the receive loop to completion.
fn runtime() -> &'static Runtime {
  static RUNTIME: OnceLock<Runtime> = OnceLock::new();
  RUNTIME.get_or_init(|| {
    tokio::runtime::Builder::new_current_thread()
      .build()
      .expect("a current-thread runtime")
  })
}

fuzz_target!(|session: Session<'_>| {
  match session.helper {
    false => exercise::<Signal>(&session),
    true => exercise::<HelperMessage>(&session),
  }
});
