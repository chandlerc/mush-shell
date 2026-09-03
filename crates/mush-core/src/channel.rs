// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Line framing over the ssh channels Mush talks protocol on.
//!
//! Two channels carry `key=value` lines past their opening message: the
//! bootstrap channel to the destination, which becomes the signaling
//! path once the connect line is out ([`Signal`] messages, design doc
//! "Signaling"), and the jump helper's own channel, which carries
//! [`HelperMessage`](crate::helper::HelperMessage)s, all of the helper's
//! control messages. [`LineChannel`] is the framing both use over a
//! duplex byte stream, with the discipline
//! [`ConnectScanner`](crate::bootstrap::ConnectScanner) applies before
//! the connect line: these are login channels and can carry shell output
//! at any point.
//!
//! - Lines are bounded by [`MAX_LINE_BYTES`]; a longer one cannot be a
//!   message and is discarded without being buffered.
//! - A line that is not a message at all -- a motd tail, a background
//!   job's output, invalid UTF-8 -- is skipped against a budget
//!   ([`LineLimits`]), so a shell that never stops talking cannot keep
//!   a phase alive forever.
//! - A line that *is* a message and fails strict parsing is an error.
//!
//! It takes over from the leftover bytes the openers hand back
//! (`ClientSession::bootstrap_leftover`,
//! `ServerSession::bootstrap_leftover`, the helper's serve line): the
//! bytes read past that first line, which routinely include the peer's
//! first protocol lines when they coalesce into one read. Constructing
//! it with those leftover bytes is what keeps the handoff lossless.
//!
//! One task drives both directions, and both halves are cancel-safe:
//! every byte [`LineChannel::recv`] reads goes into the channel's own
//! buffer before the next await, and every byte [`LineChannel::send`]
//! has not written yet stays there too. Both sit in `select!`s that
//! path establishment abandons the moment a session settles.

use std::io;
use std::marker::PhantomData;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tracing::debug;

use crate::bootstrap::{MAX_LINE_BYTES, ParseError, SessionNonce, Signal};

/// How much of one read the channel asks for at a time. Protocol lines
/// are small and arrive in ones and twos; this only bounds how much a
/// single read can add to the line buffer, which is what makes
/// [`LineChannel::buffered_bytes`] bounded.
pub const READ_CHUNK: usize = 4096;

/// One line-protocol message set a [`LineChannel`] can carry.
///
/// The two implementations are [`Signal`] and
/// [`HelperMessage`](crate::helper::HelperMessage). Both directions of a
/// channel use the same set, so each side ignores what it does not
/// expect.
pub trait LineMessage: Sized {
  /// Parses one line, returning `Ok(None)` for a line that is not a
  /// message of this set: the channel is a login channel, and a shell
  /// that keeps talking must not be able to end the phase.
  fn parse(line: &str) -> Result<Option<Self>, ParseError>;

  /// The complete wire line, including the terminating newline.
  fn to_wire(&self) -> String;
}

/// Budget for the non-message lines a [`LineChannel`] will skip.
///
/// Counts only what is ignored, never messages: a session that signals
/// for a long time is ordinary, while a channel producing nothing but
/// non-protocol output is a shell that never stopped talking.
#[derive(Debug, Clone, Copy)]
pub struct LineLimits {
  /// Maximum number of complete non-message lines to skip.
  pub max_ignored_lines: usize,
  /// Maximum number of non-message bytes to consume, including line
  /// terminators and the overlong lines discarded unexamined.
  pub max_ignored_bytes: usize,
}

impl Default for LineLimits {
  /// The connect scan's budget
  /// ([`ScanLimits`](crate::bootstrap::ScanLimits)), for the same
  /// reason: far beyond any plausible login output, small enough to give
  /// up on a channel that will never speak the protocol.
  fn default() -> Self {
    Self {
      max_ignored_lines: 512,
      max_ignored_bytes: 256 * 1024,
    }
  }
}

/// Errors from [`LineChannel`].
#[derive(Debug, thiserror::Error)]
pub enum LineError {
  /// The underlying channel failed (the ssh child died, a pipe broke).
  #[error("protocol channel failed: {0}")]
  Io(#[source] io::Error),
  /// A line carrying a protocol message failed strict parsing.
  #[error("malformed protocol line: {0}")]
  Malformed(#[from] ParseError),
  /// The budget for non-protocol output was exhausted.
  #[error(
    "protocol channel carried {lines} lines / {bytes} bytes that are \
     not protocol"
  )]
  NonProtocolLimit {
    /// Complete non-message lines skipped.
    lines: usize,
    /// Non-message bytes consumed.
    bytes: usize,
  },
}

/// A protocol phase's view of an ssh channel: `M` messages in and out,
/// non-protocol lines skipped, lines bounded.
#[derive(Debug)]
pub struct LineChannel<C, M> {
  channel: C,
  limits: LineLimits,
  /// Bytes received and not yet split into lines: at most one partial
  /// line plus one read.
  pending: Vec<u8>,
  /// The line being received passed [`MAX_LINE_BYTES`] and what had
  /// been buffered of it is gone, so its length can no longer be read
  /// off `pending`; the rest of it is discarded up to the next newline.
  overflowed: bool,
  /// Read scratch, owned so that a cancelled [`Self::recv`] cannot
  /// leave bytes in a local buffer.
  chunk: Vec<u8>,
  /// The tail of a message not yet written, owned for the same reason;
  /// see [`Self::send`].
  outgoing: Vec<u8>,
  ignored_lines: usize,
  ignored_bytes: usize,
  message: PhantomData<fn() -> M>,
}

/// The signaling phase's view of the bootstrap channel.
pub type SignalChannel<C> = LineChannel<C, Signal>;

impl<C, M> LineChannel<C, M> {
  /// Wraps `channel`, resuming from `leftover`: the bytes the phase's
  /// opener read past its own line.
  pub fn new(channel: C, leftover: Vec<u8>) -> Self {
    Self::with_limits(channel, leftover, LineLimits::default())
  }

  /// [`new`](Self::new) with an explicit budget for non-protocol output.
  pub fn with_limits(
    channel: C,
    leftover: Vec<u8>,
    limits: LineLimits,
  ) -> Self {
    Self {
      channel,
      limits,
      pending: leftover,
      overflowed: false,
      chunk: vec![0u8; READ_CHUNK],
      outgoing: Vec::new(),
      ignored_lines: 0,
      ignored_bytes: 0,
      message: PhantomData,
    }
  }

  /// Complete non-message lines skipped so far.
  pub fn ignored_lines(&self) -> usize {
    self.ignored_lines
  }

  /// Non-message bytes consumed so far.
  pub fn ignored_bytes(&self) -> usize {
    self.ignored_bytes
  }

  /// Received bytes not yet delivered as a line.
  ///
  /// Past the leftover bytes it has not reached yet, this stays within
  /// [`MAX_LINE_BYTES`] plus one [`READ_CHUNK`]: a line that cannot be a
  /// message is dropped rather than buffered, so a channel that never
  /// sends a newline cannot make the buffer grow.
  pub fn buffered_bytes(&self) -> usize {
    self.pending.len()
  }

  /// Gives the channel back, with whatever bytes were read past the last
  /// message it returned: the mirror of [`new`](Self::new), so the next
  /// phase resumes at the same handoff point with nothing dropped.
  ///
  /// Bytes are all the handoff carries, so the handover is exact only
  /// where the channel's state is its bytes: before the first message, or
  /// after one. A channel part-way through discarding an overlong line
  /// holds that in a flag instead, and [`Self::recv`] leaves it set only
  /// where the channel is already spent -- end of stream, a failed read,
  /// an exhausted non-protocol budget -- so nothing hands one on.
  ///
  /// A message a cancelled [`Self::send`] had not finished writing goes
  /// no further: the next phase inherits a channel at a line boundary.
  pub fn into_parts(self) -> (C, Vec<u8>) {
    debug_assert!(
      !self.overflowed,
      "handing over a channel mid-discard resumes the line it abandoned"
    );
    (self.channel, self.pending)
  }

  /// The next complete line, with its terminator removed, skipping any
  /// line past [`MAX_LINE_BYTES`].
  ///
  /// The bound is the line's, not the buffer's: whether one read
  /// happened to carry the terminator along with the bytes that broke
  /// the bound decides nothing, so a stream reads the same way however
  /// the peer split its writes. A line already abandoned by
  /// [`discard_overlong`](Self::discard_overlong) stays abandoned to
  /// its terminator.
  fn take_line(&mut self) -> Result<Option<Vec<u8>>, LineError> {
    loop {
      let Some(newline) = self.pending.iter().position(|&b| b == b'\n') else {
        return Ok(None);
      };
      let overflowed =
        std::mem::take(&mut self.overflowed) || newline > MAX_LINE_BYTES;
      let mut line: Vec<u8> = self.pending.drain(..=newline).collect();
      line.pop();
      if overflowed {
        self.ignored_lines += 1;
        self.note_ignored(line.len() + 1)?;
        continue;
      }
      return Ok(Some(line));
    }
  }

  /// Drops what has been buffered of a line already past
  /// [`MAX_LINE_BYTES`] with no terminator in sight, so neither the
  /// buffer nor the phase is unbounded when the channel produces a
  /// newline-free flood. The rest of that line is dropped by
  /// [`take_line`](Self::take_line) when its terminator arrives.
  fn discard_overlong(&mut self) -> Result<(), LineError> {
    if self.pending.len() <= MAX_LINE_BYTES || self.pending.contains(&b'\n') {
      return Ok(());
    }
    let dropped = self.pending.len();
    self.pending.clear();
    self.overflowed = true;
    self.note_ignored(dropped)
  }

  fn note_ignored(&mut self, bytes: usize) -> Result<(), LineError> {
    self.ignored_bytes += bytes;
    if self.ignored_lines >= self.limits.max_ignored_lines
      || self.ignored_bytes >= self.limits.max_ignored_bytes
    {
      return Err(LineError::NonProtocolLimit {
        lines: self.ignored_lines,
        bytes: self.ignored_bytes,
      });
    }
    Ok(())
  }
}

impl<C: AsyncRead + Unpin, M: LineMessage> LineChannel<C, M> {
  /// Receives the next message, or `Ok(None)` at end of channel.
  ///
  /// Lines that are not messages are skipped against the non-protocol
  /// budget; a malformed message and an exhausted budget are errors.
  pub async fn recv(&mut self) -> Result<Option<M>, LineError> {
    loop {
      self.discard_overlong()?;
      while let Some(line) = self.take_line()? {
        // Non-UTF-8 lines are binary non-protocol output; a real message
        // is ASCII.
        let message = match str::from_utf8(&line) {
          Ok(text) => M::parse(text)?,
          Err(_) => None,
        };
        if let Some(message) = message {
          return Ok(Some(message));
        }
        self.ignored_lines += 1;
        self.note_ignored(line.len() + 1)?;
      }
      let read = {
        let Self { channel, chunk, .. } = &mut *self;
        channel.read(chunk).await.map_err(LineError::Io)?
      };
      if read == 0 {
        return Ok(None);
      }
      self.pending.extend_from_slice(&self.chunk[..read]);
    }
  }
}

impl<C: AsyncWrite + Unpin, M: LineMessage> LineChannel<C, M> {
  /// Sends one message as a complete line.
  ///
  /// Cancel-safe, like [`Self::recv`], and for a sharper reason: every
  /// driver that writes here is cancelled by design -- the client's the
  /// moment a handshake wins, the destination's the moment its accept
  /// finishes, the helper's when its service ends -- and a write
  /// abandoned mid-line would leave half a `key=value` line on the ssh
  /// channel for the next writer's line to be appended to. What the
  /// peer would read then is a malformed message, which ends its phase.
  ///
  /// So the line being written stays in the channel, and the next send
  /// finishes it before starting its own: a cancelled send costs the
  /// message its promptness and nothing else, and the peer always reads
  /// whole lines, in order.
  pub async fn send(&mut self, message: &M) -> Result<(), LineError> {
    self
      .outgoing
      .extend_from_slice(message.to_wire().as_bytes());
    self.flush_outgoing().await
  }

  /// Writes whatever is queued, keeping what has not been written yet.
  async fn flush_outgoing(&mut self) -> Result<(), LineError> {
    while !self.outgoing.is_empty() {
      let written = self
        .channel
        .write(&self.outgoing)
        .await
        .map_err(LineError::Io)?;
      if written == 0 {
        return Err(LineError::Io(io::Error::new(
          io::ErrorKind::WriteZero,
          "the protocol channel accepted no bytes",
        )));
      }
      self.outgoing.drain(..written);
    }
    self.channel.flush().await.map_err(LineError::Io)
  }
}

impl<C: AsyncRead + AsyncWrite + Unpin> SignalChannel<C> {
  /// Ends the signaling phase once the session's path is settled: say
  /// this side has no more candidates, wait up to `grace` for the peer
  /// to say the same, then let the channel go, which is what lets the
  /// ssh child holding it exit.
  ///
  /// Establishment normally exchanges both terminators as it proceeds,
  /// and then there is nothing left to wait for -- `peer_done` says so.
  /// This is for the session that won on the direct path before
  /// establishment ever ordered a punch: the peer holds the channel open
  /// with no way to know the phase is over, and a terminator is how it
  /// is told.
  ///
  /// Nothing here is fatal: the session is already up, so a channel that
  /// broke, went quiet, or spoke nonsense costs the phase its terminator
  /// and nothing else.
  pub async fn settle(
    mut self,
    nonce: SessionNonce,
    mut peer_done: bool,
    grace: Duration,
  ) {
    let settled = tokio::time::timeout(grace, async {
      self.send(&Signal::done(nonce)).await?;
      while !peer_done {
        let Some(signal) = self.recv().await? else {
          break;
        };
        if signal.nonce() != nonce {
          debug!(%signal, "signaling for another session");
          continue;
        }
        peer_done = matches!(signal, Signal::Done(_));
      }
      Ok::<(), LineError>(())
    })
    .await;
    match (settled, peer_done) {
      (Ok(Ok(())), true) => debug!("signaling settled"),
      (Ok(Ok(())), false) => {
        debug!("signaling ended without the peer's terminator")
      }
      (Ok(Err(error)), _) => debug!(%error, "signaling channel ended"),
      (Err(_), _) => debug!(?grace, "signaling did not settle"),
    }
  }
}

#[cfg(test)]
mod tests {
  use std::net::SocketAddr;

  use super::*;
  use crate::bootstrap::CandidateKind;

  fn nonce() -> SessionNonce {
    SessionNonce::from_bytes([0x5a; 16])
  }

  fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
  }

  fn sample_signals() -> Vec<Signal> {
    vec![
      Signal::helper(
        nonce(),
        addr("198.51.100.7:60123"),
        crate::bootstrap::SessionSecret::from_bytes([0x77; 16]),
      ),
      Signal::candidate(
        nonce(),
        CandidateKind::Reflexive,
        addr("[2001:db8::1]:60123"),
      ),
      Signal::punch(
        nonce(),
        1,
        vec![addr("192.0.2.1:5000"), addr("192.0.2.2:5001")],
      ),
      Signal::done(nonce()),
    ]
  }

  fn wire(signals: &[Signal]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for signal in signals {
      bytes.extend_from_slice(signal.to_wire().as_bytes());
    }
    bytes
  }

  /// A read-only channel that delivers `script` in pieces no larger
  /// than `chunk`, then ends: control over read boundaries, which is
  /// what the framing has to survive.
  fn chunked(script: &[u8], chunk: usize) -> tokio::io::DuplexStream {
    let (ours, mut writer) = tokio::io::duplex(chunk.max(1));
    let script = script.to_vec();
    tokio::spawn(async move {
      for piece in script.chunks(chunk.max(1)) {
        if writer.write_all(piece).await.is_err() {
          return;
        }
      }
    });
    ours
  }

  async fn collect<C: AsyncRead + Unpin>(
    channel: &mut SignalChannel<C>,
  ) -> Result<Vec<Signal>, LineError> {
    let mut got = Vec::new();
    while let Some(signal) = channel.recv().await? {
      got.push(signal);
    }
    Ok(got)
  }

  #[tokio::test]
  async fn messages_round_trip_over_a_duplex() {
    let (near, far) = tokio::io::duplex(64 * 1024);
    let mut sender = SignalChannel::new(near, Vec::new());
    let mut receiver = SignalChannel::new(far, Vec::new());
    let signals = sample_signals();
    let sent = signals.clone();
    let writer = tokio::spawn(async move {
      for signal in &sent {
        sender.send(signal).await.unwrap();
      }
      sender
    });
    let mut got = Vec::new();
    for _ in 0..signals.len() {
      got.push(receiver.recv().await.unwrap().unwrap());
    }
    assert_eq!(got, signals);
    // Dropping the far side ends the channel cleanly.
    drop(writer.await.unwrap());
    assert_eq!(receiver.recv().await.unwrap(), None);
  }

  #[tokio::test]
  async fn framing_survives_every_read_boundary() {
    let signals = sample_signals();
    let script = wire(&signals);
    for chunk in [1, 2, 3, 7, 64, script.len()] {
      let mut channel = SignalChannel::new(chunked(&script, chunk), Vec::new());
      assert_eq!(
        collect(&mut channel).await.unwrap(),
        signals,
        "chunk {chunk}"
      );
    }
  }

  /// Where the establishment engines hand over: the peer's first
  /// signaling lines arrived in the same read as the connect line, so they
  /// reach the channel as leftover bytes rather than off the wire, and a
  /// line split across the handoff completes from the wire.
  #[tokio::test]
  async fn leftover_bytes_survive_the_handoff() {
    let signals = sample_signals();
    let mut leftover = wire(&signals[..2]);
    let split = signals[2].to_wire();
    let (head, tail) = split.split_at(10);
    leftover.extend_from_slice(head.as_bytes());
    let mut script = tail.as_bytes().to_vec();
    script.extend_from_slice(&wire(&signals[3..]));

    let mut channel = SignalChannel::new(chunked(&script, 3), leftover);
    assert_eq!(collect(&mut channel).await.unwrap(), signals);
  }

  #[tokio::test]
  async fn non_signaling_lines_are_skipped() {
    let done = Signal::done(nonce());
    let mut script = Vec::new();
    script.extend_from_slice(b"Welcome to example.org\r\n");
    script.extend_from_slice(b"binary junk: \xff\xfe\x00\x01\n");
    script.extend_from_slice(b"MUSH DONEISH v=1 nonce=x\n");
    script.extend_from_slice(b"XMUSH DONE v=1 nonce=x\n");
    script.extend_from_slice(b" MUSH DONE v=1 nonce=x\n");
    script.extend_from_slice(b"\n");
    script.extend_from_slice(done.to_wire().as_bytes());
    let mut channel = SignalChannel::new(chunked(&script, 5), Vec::new());
    assert_eq!(collect(&mut channel).await.unwrap(), vec![done]);
    assert_eq!(channel.ignored_lines(), 6);
  }

  #[tokio::test]
  async fn crlf_terminated_messages_are_accepted() {
    let script = format!("{}\r\n", Signal::done(nonce()));
    let mut channel =
      SignalChannel::new(chunked(script.as_bytes(), 4), Vec::new());
    assert!(matches!(
      channel.recv().await.unwrap(),
      Some(Signal::Done(_))
    ));
  }

  #[tokio::test]
  async fn a_malformed_message_is_an_error() {
    let script =
      b"MUSH CANDIDATE v=1 nonce=x kind=direct addr=1.2.3.4:5 prio=1\n";
    let mut channel = SignalChannel::new(chunked(script, 64), Vec::new());
    assert!(matches!(
      channel.recv().await,
      Err(LineError::Malformed(ParseError::InvalidValue {
        key: "nonce"
      }))
    ));
  }

  #[tokio::test]
  async fn overlong_lines_are_discarded_without_unbounded_buffering() {
    let done = Signal::done(nonce());
    let mut script = vec![b'y'; MAX_LINE_BYTES * 3];
    script.push(b'\n');
    script.extend_from_slice(done.to_wire().as_bytes());
    let mut channel = SignalChannel::with_limits(
      chunked(&script, 1024),
      Vec::new(),
      LineLimits {
        max_ignored_lines: 512,
        max_ignored_bytes: MAX_LINE_BYTES * 8,
      },
    );
    assert_eq!(channel.recv().await.unwrap(), Some(done));
    assert!(channel.buffered_bytes() <= MAX_LINE_BYTES);
  }

  /// A line is discarded for its own length, never for where the peer's
  /// writes happened to break: a message line padded past the bound by
  /// less than one read is ignored under every chunking, the one that
  /// delivers it together with its terminator included.
  #[tokio::test]
  async fn an_overlong_line_is_discarded_however_it_arrives() {
    let done = Signal::done(nonce());
    let mut script = done.to_wire().trim_end().as_bytes().to_vec();
    script.resize(MAX_LINE_BYTES + 150, b' ');
    script.push(b'\n');
    script.extend_from_slice(done.to_wire().as_bytes());

    for chunk in [1, READ_CHUNK] {
      let mut channel = SignalChannel::new(chunked(&script, chunk), Vec::new());
      assert_eq!(
        collect(&mut channel).await.unwrap(),
        vec![done.clone()],
        "chunk {chunk}"
      );
      assert_eq!(channel.ignored_lines(), 1, "chunk {chunk}");
      assert_eq!(
        channel.ignored_bytes(),
        MAX_LINE_BYTES + 151,
        "chunk {chunk}"
      );
    }
  }

  #[tokio::test]
  async fn the_non_protocol_budget_ends_the_phase() {
    let mut script = Vec::new();
    for i in 0..64 {
      script.extend_from_slice(format!("login line {i}\n").as_bytes());
    }
    let mut channel = SignalChannel::with_limits(
      chunked(&script, 64),
      Vec::new(),
      LineLimits {
        max_ignored_lines: 8,
        max_ignored_bytes: 256 * 1024,
      },
    );
    assert!(matches!(
      channel.recv().await,
      Err(LineError::NonProtocolLimit { lines: 8, .. })
    ));
  }

  /// A newline-free flood is bounded in time as well as memory: the
  /// discarded bytes count against the budget, so the phase ends
  /// instead of spinning on a stream that will never produce a line.
  #[tokio::test]
  async fn a_newline_free_flood_hits_the_byte_budget() {
    let script = vec![b'z'; MAX_LINE_BYTES * 16];
    let mut channel = SignalChannel::with_limits(
      chunked(&script, 4096),
      Vec::new(),
      LineLimits {
        max_ignored_lines: 512,
        max_ignored_bytes: MAX_LINE_BYTES * 4,
      },
    );
    assert!(matches!(
      channel.recv().await,
      Err(LineError::NonProtocolLimit { lines: 0, .. })
    ));
  }

  /// `send` in a `select!` must not leave half a line on the wire: the
  /// next writer's line would be appended to the fragment and reach the
  /// peer as a malformed message that ends its phase.
  #[tokio::test]
  async fn send_is_cancel_safe() {
    // A duplex narrow enough that one message cannot be written in one
    // go, so the cancellation happens mid-line.
    let (peer, ours) = tokio::io::duplex(8);
    let mut channel = SignalChannel::new(ours, Vec::new());
    let signals = sample_signals();
    tokio::select! {
      result = channel.send(&signals[0]) => panic!("the send finished: {result:?}"),
      () = tokio::time::sleep(Duration::from_millis(50)) => {}
    }

    // The reader starts only now, so nothing drained the duplex during
    // the cancelled write: what it finds is whatever the channel wrote.
    let mut reader = SignalChannel::new(peer, Vec::new());
    let sent = signals.clone();
    let writer = tokio::spawn(async move {
      for signal in &sent[1..] {
        channel.send(signal).await.unwrap();
      }
      channel
    });
    let mut got = Vec::new();
    for _ in 0..signals.len() {
      let next = tokio::time::timeout(Duration::from_secs(5), reader.recv())
        .await
        .expect("a message was lost in the cancelled line");
      got.push(next.unwrap().unwrap());
    }
    // Every message arrives whole and in order, the cancelled one
    // included: it was finished by the send that followed it.
    assert_eq!(got, signals);
    drop(writer.await.unwrap());
  }

  /// The case [`SignalChannel::settle`] exists for: a session that won
  /// on the direct path before establishment ever ordered a punch, so
  /// neither side has sent a terminator. This side says it is finished,
  /// the peer answers, and the channel is let go.
  #[tokio::test]
  async fn settle_exchanges_the_terminator_a_direct_win_never_sent() {
    let (near, far) = tokio::io::duplex(64 * 1024);
    let peer = tokio::spawn(async move {
      let mut peer = SignalChannel::new(far, Vec::new());
      let terminator = peer.recv().await.unwrap();
      peer.send(&Signal::done(nonce())).await.unwrap();
      (terminator, peer.recv().await.unwrap())
    });
    SignalChannel::new(near, Vec::new())
      .settle(nonce(), false, Duration::from_secs(5))
      .await;
    let (terminator, after) = peer.await.unwrap();
    assert_eq!(terminator, Some(Signal::done(nonce())));
    assert_eq!(after, None, "the channel outlived the exchange");
  }

  /// A peer that never answers costs the phase its grace and nothing
  /// else: the session is already up, and the channel is let go
  /// regardless.
  #[tokio::test(start_paused = true)]
  async fn settle_gives_up_on_a_silent_peer() {
    const GRACE: Duration = Duration::from_secs(5);
    let (near, far) = tokio::io::duplex(64 * 1024);
    let started = tokio::time::Instant::now();
    SignalChannel::new(near, Vec::new())
      .settle(nonce(), false, GRACE)
      .await;
    assert_eq!(started.elapsed(), GRACE);
    // The terminator went out before the wait, so a peer that was
    // merely slow still learns the phase is over.
    let mut peer = SignalChannel::new(far, Vec::new());
    assert_eq!(peer.recv().await.unwrap(), Some(Signal::done(nonce())));
    assert_eq!(peer.recv().await.unwrap(), None);
  }

  /// `recv` in a `select!` must not consume bytes it does not return: a
  /// cancelled read's partial line stays in the channel's buffer.
  #[tokio::test]
  async fn recv_is_cancel_safe() {
    let (mut peer, ours) = tokio::io::duplex(64 * 1024);
    let mut channel = SignalChannel::new(ours, Vec::new());
    let signal = sample_signals().remove(1);
    let line = signal.to_wire();
    let (head, tail) = line.split_at(line.len() / 2);
    peer.write_all(head.as_bytes()).await.unwrap();
    tokio::select! {
      result = channel.recv() => panic!("half a line parsed: {result:?}"),
      () = tokio::time::sleep(Duration::from_millis(50)) => {}
    }
    peer.write_all(tail.as_bytes()).await.unwrap();
    assert_eq!(channel.recv().await.unwrap(), Some(signal));
  }
}
