// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! `LineChannel`'s writer, and both directions under cancellation.
//!
//! Every driver that writes to one of these channels is cancelled by
//! design -- the client's the moment a handshake wins, the destination's
//! the moment its accept finishes, the helper's when its service ends --
//! so `send` and `recv` both carry a cancel-safety contract, and neither
//! is reachable from a target that only feeds a reader that always
//! succeeds. Here the channel underneath is adversarial in the one way a
//! real ssh channel is: it accepts an input-chosen number of bytes at a
//! time and stalls where the input says, and the futures are polled a
//! bounded number of times and then dropped where they stand.
//!
//! The contract `channel.rs` states: a send that returns leaves the
//! channel at a line boundary; a send abandoned mid-line leaves the rest
//! for the next one to finish, so the far side reads whole lines in
//! order, never a half line with another writer's line appended; a
//! receive abandoned mid-line loses nothing, so reading the written
//! stream back, cancelled wherever the input asks, yields exactly the
//! messages that were sent.

#![no_main]

use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use mush_core::bootstrap::{
  Candidate, CandidateKind, Helper, Punch, SessionNonce, SessionSecret, Signal,
};
use mush_core::channel::{LineChannel, SignalChannel};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The most lines one plan sends. Enough for sends to queue up behind
/// one another repeatedly; short enough that the closing flush, bounded
/// in polls, stays cheap.
const MAX_LINES: usize = 16;

/// The most addresses one line carries, so no line comes anywhere near
/// `MAX_LINE_BYTES` and the reader never discards one for length.
const MAX_ADDRS: usize = 4;

/// One signaling line to send.
#[derive(Arbitrary, Debug)]
enum Line {
  Candidate {
    nonce: [u8; 16],
    kind: u8,
    addr: Addr,
    priority: u32,
  },
  Helper {
    nonce: [u8; 16],
    addr: Addr,
    secret: [u8; 16],
  },
  Punch {
    nonce: [u8; 16],
    round: u32,
    peers: Vec<Addr>,
  },
  Done {
    nonce: [u8; 16],
  },
}

/// An address of either family; their wire forms differ in length and in
/// shape.
#[derive(Arbitrary, Debug)]
enum Addr {
  V4 { ip: u32, port: u16 },
  V6 { ip: u128, port: u16 },
}

impl Addr {
  fn addr(&self) -> SocketAddr {
    match *self {
      Self::V4 { ip, port } => {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
      }
      Self::V6 { ip, port } => {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)
      }
    }
  }
}

impl Line {
  fn signal(&self) -> Signal {
    match self {
      Self::Candidate {
        nonce,
        kind,
        addr,
        priority,
      } => Signal::Candidate(Candidate {
        nonce: SessionNonce::from_bytes(*nonce),
        kind: match kind % 3 {
          0 => CandidateKind::Direct,
          1 => CandidateKind::Reflexive,
          _ => CandidateKind::Relayed,
        },
        addr: addr.addr(),
        priority: *priority,
      }),
      Self::Helper {
        nonce,
        addr,
        secret,
      } => Signal::Helper(Helper {
        nonce: SessionNonce::from_bytes(*nonce),
        addr: addr.addr(),
        secret: SessionSecret::from_bytes(*secret),
      }),
      Self::Punch {
        nonce,
        round,
        peers,
      } => Signal::Punch(Punch {
        nonce: SessionNonce::from_bytes(*nonce),
        round: *round,
        peers: peers.iter().take(MAX_ADDRS).map(Addr::addr).collect(),
      }),
      Self::Done { nonce } => Signal::done(SessionNonce::from_bytes(*nonce)),
    }
  }
}

/// One channel's lifetime: the lines to send, how grudgingly the channel
/// accepts and delivers bytes, and where each future is abandoned.
#[derive(Arbitrary, Debug)]
struct Plan {
  lines: Vec<Line>,
  accepts: [u8; 8],
  send_polls: [u8; 8],
  delivers: [u8; 8],
  recv_polls: [u8; 8],
}

/// How many bytes a poll moves, from a cycled schedule. Zero is a stall,
/// which is where a cancellation occurs mid-line; every fourth poll moves
/// at least one byte regardless, so a transfer given enough polls always
/// finishes and the closing flush cannot hang.
fn allowance(schedule: &[u8; 8], step: usize) -> usize {
  let allowance = usize::from(schedule[step % schedule.len()]);
  match allowance == 0 && step % 4 != 3 {
    true => 0,
    false => allowance.max(1),
  }
}

/// What the far side of the channel has read, shared so the harness can
/// watch it grow while the channel still owns the writer.
type Wire = Rc<RefCell<Vec<u8>>>;

/// A channel that accepts bytes a few at a time and stalls where the
/// schedule says.
struct Trickle {
  wire: Wire,
  accepts: [u8; 8],
  step: usize,
}

impl AsyncWrite for Trickle {
  fn poll_write(
    mut self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    let me = &mut *self;
    let take = allowance(&me.accepts, me.step).min(buf.len());
    me.step += 1;
    if take == 0 {
      return Poll::Pending;
    }
    me.wire.borrow_mut().extend_from_slice(&buf[..take]);
    Poll::Ready(Ok(take))
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

/// The same channel read back: a few bytes at a time, stalling where the
/// schedule says. A stall delivers nothing, which makes a cancelled
/// receive a fair test of the channel rather than of a reader that eats
/// bytes it never handed over.
struct Stalling<'a> {
  bytes: &'a [u8],
  offset: usize,
  delivers: [u8; 8],
  step: usize,
}

impl AsyncRead for Stalling<'_> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    let me = &mut *self;
    let step = me.step;
    me.step += 1;
    let take = allowance(&me.delivers, step)
      .min(buf.remaining())
      .min(me.bytes.len() - me.offset);
    if take == 0 && me.offset < me.bytes.len() {
      return Poll::Pending;
    }
    buf.put_slice(&me.bytes[me.offset..me.offset + take]);
    me.offset += take;
    Poll::Ready(Ok(()))
  }
}

/// Polls `future` at most `polls` times, dropping it where it stands if
/// it has not finished.
fn poll_bounded<F: Future>(future: F, polls: usize) -> Option<F::Output> {
  let mut future = pin!(future);
  let mut context = Context::from_waker(Waker::noop());
  for _ in 0..polls {
    if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
      return Some(output);
    }
  }
  None
}

fuzz_target!(|plan: Plan| {
  let wire: Wire = Rc::new(RefCell::new(Vec::new()));
  let mut channel: SignalChannel<_> = LineChannel::new(
    Trickle {
      wire: Rc::clone(&wire),
      accepts: plan.accepts,
      step: 0,
    },
    Vec::new(),
  );

  // Every message whose send was started, in order, and the bytes they
  // amount to: what the far side must read, and nothing else.
  let mut sent = Vec::new();
  let mut queued: Vec<u8> = Vec::new();
  for (index, line) in plan.lines.iter().take(MAX_LINES).enumerate() {
    let signal = line.signal();
    let polls = 1 + usize::from(plan.send_polls[index % 8]);
    let finished = poll_bounded(channel.send(&signal), polls);
    // The wire goes into the channel on the first poll, whether or not
    // the send survives to finish writing it.
    queued.extend_from_slice(signal.to_wire().as_bytes());
    sent.push(signal.to_wire());
    match finished {
      Some(Ok(())) => assert_eq!(
        wire.borrow().len(),
        queued.len(),
        "a send returned with a line still unwritten"
      ),
      Some(Err(error)) => panic!("the channel cannot fail: {error}"),
      None => {}
    }
    assert!(
      queued.starts_with(&wire.borrow()),
      "the channel wrote bytes no send had queued, or wrote them out of order"
    );
  }

  // A last line, given enough polls to finish: what a cancelled send
  // left behind must go out ahead of it, whole and in order.
  let sentinel = Signal::done(SessionNonce::from_bytes([0xa5; 16]));
  queued.extend_from_slice(sentinel.to_wire().as_bytes());
  sent.push(sentinel.to_wire());
  poll_bounded(channel.send(&sentinel), 4 * queued.len() + 8)
    .expect("a send given four polls a byte must finish")
    .expect("the channel cannot fail");
  assert_eq!(
    *wire.borrow(),
    queued,
    "what reached the far side is not the lines that were sent"
  );

  // The reading half: the same stream, with the receive abandoned
  // wherever the input asks.
  let written = wire.borrow().clone();
  let mut channel: SignalChannel<_> = LineChannel::new(
    Stalling {
      bytes: &written,
      offset: 0,
      delivers: plan.delivers,
      step: 0,
    },
    Vec::new(),
  );
  let mut received = Vec::new();
  let mut eof = false;
  for attempt in 0..4 * written.len() + 8 {
    let polls = 1 + usize::from(plan.recv_polls[attempt % 8]) % 8;
    match poll_bounded(channel.recv(), polls) {
      Some(Ok(Some(message))) => received.push(message.to_wire()),
      Some(Ok(None)) => {
        eof = true;
        break;
      }
      Some(Err(error)) => {
        panic!("a channel of whole lines cannot fail: {error}")
      }
      // Abandoned mid-line: the channel keeps what it read, so the next
      // receive picks the sequence up where this one left it.
      None => {}
    }
  }
  assert!(eof, "the receive loop never reached the end of the channel");
  assert_eq!(
    received, sent,
    "cancelled receives changed the message sequence"
  );
});
