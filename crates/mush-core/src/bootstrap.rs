// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The line protocol spoken over the bootstrap ssh channel.
//!
//! Two messages establish a session (design doc, "Session lifecycle"):
//! the client writes a [`Hello`] line to the remote `mush server
//! bootstrap` process's stdin, and the server answers with a [`Connect`]
//! line on stdout. Each is a fixed prefix followed by space-separated
//! `key=value` pairs. Unknown keys are ignored for forward
//! compatibility; repeated `addr` keys accumulate; any other repeated
//! known key, and any malformed required field, is a hard parse error.
//!
//! The channel then stays open as the session's signaling path (design
//! doc, "Signaling"): the [`Signal`] messages -- [`Candidate`],
//! [`Helper`], [`Punch`], [`Done`] -- flow both ways in the same shape,
//! carrying the [`SessionNonce`] from the client's hello. ssh makes that
//! path reliable, ordered, private, and mutually authenticated, so there
//! is no offer/answer, no role negotiation, and no trickle machinery
//! here: only candidate exchange and a synchronized start.
//!
//! The server's stdout is a login channel and may carry motd, shell-rc
//! output, and partial lines around the `MUSH CONNECT` line, so the
//! client finds that line with [`ConnectScanner`].
//! [`crate::channel::LineChannel`] applies the same discipline to
//! everything after it, and to the jump helper's own channel, whose
//! message set is [`crate::helper`]'s.
//!
//! This parser handles pre-authentication-adjacent input and is one of
//! the seven areas the design doc's "Security analysis" puts in review
//! scope: it must never panic on any input, and the per-message parsers
//! are pure
//! `fn(&str)` so they can be fuzzed directly. Prefix matching,
//! tokenizing, the error sanitizer, and the typed field accessors are
//! hand-written here and shared by every message; each contributes only
//! a table of field, key, and kind, from which `wire`'s `line_message`
//! macro generates its parser and encoders.

use std::net::SocketAddr;

use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;

use crate::pinning::KeyPin;
use crate::wire::{line_message, line_message_enum, str_enum};

/// The protocol version this implementation speaks and emits.
pub const PROTOCOL_VERSION: u32 = 1;

/// Line prefix of the client-to-server hello message.
pub const HELLO_PREFIX: &str = "MUSH HELLO";

/// Line prefix of the server-to-client connect message.
pub const CONNECT_PREFIX: &str = "MUSH CONNECT";

/// Line prefix of a candidate advertisement, in either direction.
pub const CANDIDATE_PREFIX: &str = "MUSH CANDIDATE";

/// Line prefix of the client's helper announcement.
pub const HELPER_PREFIX: &str = "MUSH HELPER";

/// Line prefix of the client's punch rendezvous.
pub const PUNCH_PREFIX: &str = "MUSH PUNCH";

/// Line prefix of a candidate terminator.
pub const DONE_PREFIX: &str = "MUSH DONE";

/// Longest line either side examines as a potential message. A real one
/// is a few hundred bytes even with a full candidate set, so anything
/// longer is non-protocol output and is discarded unexamined rather than
/// buffered.
pub const MAX_LINE_BYTES: usize = 8 * 1024;

/// Bytes in a [`SessionNonce`].
const NONCE_BYTES: usize = 16;

/// The value that names one session's traversal attempt across the
/// three parties that take part in it (design doc, "The jump helper").
///
/// The client generates it, announces it in its [`Hello`], repeats it on
/// every [`Signal`], hands it to the jump helper over the helper's own
/// ssh channel, and carries it in the punch and reflection probes. The
/// helper reflects and forwards only for nonces it was given that way,
/// and each peer drops signaling whose nonce is not its own, which is
/// what keeps concurrent sessions from crossing.
///
/// A flow label, not a credential: it travels in probes an on-path
/// observer sees, every path it proposes still has to survive the pinned
/// handshake, and the [`SessionSecret`] alongside it is what authorizes
/// the helper. 128 random bits make collision between concurrent
/// sessions and blind guessing by an off-path attacker uninteresting.
///
/// The wire encoding ([`std::fmt::Display`] / [`std::str::FromStr`]) is
/// canonical unpadded standard base64 (22 characters), matching
/// [`KeyPin`]; parsing rejects any other form.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionNonce([u8; NONCE_BYTES]);

impl SessionNonce {
  /// Draws a fresh nonce from the system random source.
  pub fn generate() -> Result<Self, RandomUnavailable> {
    let mut bytes = [0u8; NONCE_BYTES];
    SystemRandom::new()
      .fill(&mut bytes)
      .map_err(|_| RandomUnavailable)?;
    Ok(Self(bytes))
  }

  /// Wraps nonce bytes chosen by the caller (tests).
  pub fn from_bytes(bytes: [u8; NONCE_BYTES]) -> Self {
    Self(bytes)
  }

  /// The raw nonce bytes, as probes carry them.
  pub fn as_bytes(&self) -> &[u8; NONCE_BYTES] {
    &self.0
  }
}

impl std::fmt::Display for SessionNonce {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&STANDARD_NO_PAD.encode(self.0))
  }
}

impl std::fmt::Debug for SessionNonce {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "SessionNonce({self})")
  }
}

impl std::str::FromStr for SessionNonce {
  type Err = InvalidValue;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let decoded = STANDARD_NO_PAD.decode(s).map_err(|_| InvalidValue)?;
    let bytes: [u8; NONCE_BYTES] =
      decoded.try_into().map_err(|_| InvalidValue)?;
    Ok(Self(bytes))
  }
}

/// Bytes in a [`SessionSecret`].
const SECRET_BYTES: usize = 16;

/// The per-session secret that authorizes the jump helper to act on a
/// peer's behalf (design doc, "The jump helper").
///
/// The client generates one with the [`SessionNonce`] and distributes it
/// over the two ssh channels it already holds: to the helper in its
/// `MUSH SERVE` line, and to the destination in its [`Helper`] line.
/// Both are private and mutually authenticated, so the secret never
/// crosses a network in the clear. It keys the `MESSAGE-INTEGRITY-
/// SHA256` of every probe the helper acts on ([`crate::stun`]), which
/// is what makes the helper's "never relay to an address that has not
/// proven liveness" rule mean something: without it, a UDP source
/// address is a claim anyone can forge.
///
/// Unlike the nonce, this *is* a secret. [`Debug`] and
/// [`Display`](std::fmt::Display) redact it so it cannot reach a log or
/// an error message by accident; [`expose`](Self::expose) is the one way
/// to its wire form, and only the two messages that put it on an ssh
/// channel use it, in the `to_wire` half of their `redacted` field alone
/// ([`Helper`] and [`crate::helper::Serve`]).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionSecret([u8; SECRET_BYTES]);

impl SessionSecret {
  /// Draws a fresh secret from the system random source.
  pub fn generate() -> Result<Self, RandomUnavailable> {
    let mut bytes = [0u8; SECRET_BYTES];
    SystemRandom::new()
      .fill(&mut bytes)
      .map_err(|_| RandomUnavailable)?;
    Ok(Self(bytes))
  }

  /// Wraps secret bytes chosen by the caller (tests).
  pub fn from_bytes(bytes: [u8; SECRET_BYTES]) -> Self {
    Self(bytes)
  }

  /// The wire form: canonical unpadded standard base64, the same
  /// encoding [`SessionNonce`] uses, and the password the probe's
  /// short-term credentials are keyed with. Named so that every call
  /// site says out loud that it is putting the secret somewhere.
  pub fn expose(&self) -> String {
    STANDARD_NO_PAD.encode(self.0)
  }
}

impl std::fmt::Display for SessionSecret {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("<redacted>")
  }
}

impl std::fmt::Debug for SessionSecret {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("SessionSecret(<redacted>)")
  }
}

impl std::str::FromStr for SessionSecret {
  type Err = InvalidValue;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let decoded = STANDARD_NO_PAD.decode(s).map_err(|_| InvalidValue)?;
    let bytes: [u8; SECRET_BYTES] =
      decoded.try_into().map_err(|_| InvalidValue)?;
    Ok(Self(bytes))
  }
}

/// A value that is not the wire form its key calls for.
///
/// Every value-level `FromStr` in the protocol's vocabulary fails as
/// this one type -- key pins, nonces, secrets, probe labels, candidate
/// kinds, path kinds -- because exactly one thing in the shipped code reads
/// any of them: `Fields::value`, which discards what it is handed and
/// reports [`ParseError::InvalidValue`] naming the key instead. The key
/// is the part a reader needs; a per-type spelling of "not that" was
/// eight public types nothing distinguished.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid value")]
pub struct InvalidValue;

/// The system random source refused to produce a session value.
///
/// Callers add the context naming which value was being generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the system random source failed")]
pub struct RandomUnavailable;

/// Client -> server, on the bootstrap channel's stdin: the message that
/// opens a session.
///
/// Wire form: `MUSH HELLO v=1 key=<base64 pin> target=<port>
/// [nonce=<base64 nonce>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
  /// Protocol version (`v`). Emitted as [`PROTOCOL_VERSION`]; the parser
  /// accepts any value and leaves compatibility policy to the caller.
  pub version: u32,
  /// Pin of the client's ephemeral session key (`key`).
  pub client_key: KeyPin,
  /// The sshd port the server should connect to on loopback (`target`).
  pub target_port: u16,
  /// The session nonce (`nonce`), present exactly when the client will
  /// signal after the connect line; its presence is the request to hold
  /// the channel open through path establishment.
  ///
  /// Its absence is the whole no-jump case: the server closes the
  /// channel as it detaches, the bootstrap ssh exits at once, and no
  /// signaling ever happens.
  pub nonce: Option<SessionNonce>,
}

line_message! {
  Hello, HELLO_PREFIX {
    version: "v" required,
    client_key: "key" required,
    target_port: "target" required,
    nonce: "nonce" optional,
  }
}

/// Server -> client, on the bootstrap channel's stdout: the answer to a
/// [`Hello`].
///
/// Wire form: `MUSH CONNECT v=1 port=<udp port> key=<base64 pin>
/// [addr=<ip:port>]...`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect {
  /// Protocol version (`v`); see [`Hello::version`].
  pub version: u32,
  /// The UDP port the server's QUIC endpoint is bound to (`port`).
  pub udp_port: u16,
  /// Pin of the server's ephemeral session key (`key`).
  pub server_key: KeyPin,
  /// Candidate addresses for the server (`addr`, repeatable), e.g. its
  /// own address as reported by `$SSH_CONNECTION`. Hints only: the
  /// client also dials its own resolution of the destination.
  pub addr_hints: Vec<SocketAddr>,
}

line_message! {
  Connect, CONNECT_PREFIX {
    version: "v" required,
    udp_port: "port" required,
    server_key: "key" required,
    addr_hints: "addr" repeated,
  }
}

/// Where a candidate address came from (design doc, "Path
/// establishment"), which is also the preference order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
  /// An address of the peer itself: an interface address, a DNS
  /// resolution, or the address the bootstrap ssh demonstrably reached.
  Direct,
  /// The peer's address as some reflector observed it, opened by
  /// simultaneous hole punching.
  Reflexive,
  /// An address on the jump helper, which forwards to the peer.
  Relayed,
}

str_enum! {
  CandidateKind => InvalidValue {
    Direct => "direct",
    Reflexive => "reflexive",
    Relayed => "relayed",
  }
}

impl CandidateKind {
  /// The ordering hint a candidate of this kind carries
  /// ([`Candidate::priority`]). A hint only: the receiver races what it
  /// can reach, and every path still has to survive the pinned
  /// handshake.
  pub fn priority(self) -> u32 {
    match self {
      Self::Direct => 100,
      Self::Reflexive => 50,
      Self::Relayed => 10,
    }
  }
}

/// Either direction, after the connect line: one address at which the
/// sender can be reached.
///
/// One address per line, so a side can advertise as it discovers
/// (a reflexive address takes a round trip to the helper that a direct
/// one does not) without holding back what it already knows. A side
/// says it has finished with [`Done`].
///
/// Wire form: `MUSH CANDIDATE v=1 nonce=<nonce> kind=<kind>
/// addr=<ip:port> prio=<priority>`, with the `v=` [`Signal`] describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
  /// The session this candidate belongs to (`nonce`).
  pub nonce: SessionNonce,
  /// Where the address came from (`kind`).
  pub kind: CandidateKind,
  /// The address itself (`addr`).
  pub addr: SocketAddr,
  /// Ordering hint (`prio`), higher first, ties broken by arrival
  /// order. A sender sets it from the kind
  /// ([`CandidateKind::priority`]).
  pub priority: u32,
}

line_message! {
  Candidate, CANDIDATE_PREFIX, version {
    nonce: "nonce" required,
    kind: "kind" required,
    addr: "addr" required,
    priority: "prio" required,
  }
}

/// Client -> server: the jump helper serving this session.
///
/// The client carries all signaling between the destination and the
/// helper (design doc, "Signaling"): it holds the helper's own ssh
/// channel and passes the helper's address on so the destination can
/// reach it for reflection and relay. The secret travels in this line
/// because the bootstrap channel is exactly as private and mutually
/// authenticated as the helper's own channel, which is what lets the
/// two peers and the helper share one without a key exchange.
///
/// Wire form: `MUSH HELPER v=1 nonce=<nonce> addr=<ip:port>
/// secret=<secret>`, with the `v=` [`Signal`] describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Helper {
  /// The session the helper is limited to (`nonce`).
  pub nonce: SessionNonce,
  /// The helper's UDP address (`addr`).
  pub addr: SocketAddr,
  /// The secret the session's probes are signed with (`secret`).
  pub secret: SessionSecret,
}

line_message! {
  Helper, HELPER_PREFIX, version {
    nonce: "nonce" required,
    addr: "addr" required,
    secret: "secret" redacted,
  }
}

/// Client -> server: punch now, at these addresses.
///
/// Signaling is ordered and reliable, so the message's own position in
/// the stream is the rendezvous both sides start from; `round` names
/// that point so a second punch over a grown candidate set is a
/// distinct event rather than a repeat of the first, in logs and in the
/// receiver's own pacing.
///
/// Wire form: `MUSH PUNCH v=1 nonce=<nonce> round=<n>
/// [addr=<ip:port>]...`, with the `v=` [`Signal`] describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Punch {
  /// The session to punch for (`nonce`).
  pub nonce: SessionNonce,
  /// The rendezvous marker (`round`), counting from 1.
  pub round: u32,
  /// The peer addresses to probe (`addr`, repeatable). Empty when the
  /// sender has no reachable candidates to name.
  pub peers: Vec<SocketAddr>,
}

line_message! {
  Punch, PUNCH_PREFIX, version {
    nonce: "nonce" required,
    round: "round" required,
    peers: "addr" repeated,
  }
}

/// Either direction: no more candidates from this side.
///
/// The channel stays open across it: the sender may still be waiting on
/// the other side and, until the paths settle, on the punch that
/// follows. Repeats are harmless, which makes this also the shape to
/// send when a long path establishment needs traffic on the channel.
///
/// Wire form: `MUSH DONE v=1 nonce=<nonce>`, with the `v=` [`Signal`]
/// describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Done {
  /// The session with no more candidates (`nonce`).
  pub nonce: SessionNonce,
}

line_message! {
  Done, DONE_PREFIX, version {
    nonce: "nonce" required,
  }
}

/// Any message of the post-connect signaling set.
///
/// Every one of them carries `v=`, emitted from [`PROTOCOL_VERSION`]
/// and required-but-discarded on parse: the version handshake happens
/// once per channel, on [`Hello`] and [`Connect`], and signaling starts
/// only between peers that already agreed. So these encoders normalize
/// rather than echo -- a line parsed with a `v=` this build did not
/// write is re-encoded with the one it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
  /// A candidate advertisement.
  Candidate(Candidate),
  /// A helper announcement.
  Helper(Helper),
  /// A punch rendezvous.
  Punch(Punch),
  /// A candidate terminator.
  Done(Done),
}

line_message_enum! {
  Signal {
    Candidate => CANDIDATE_PREFIX,
    Helper => HELPER_PREFIX,
    Punch => PUNCH_PREFIX,
    Done => DONE_PREFIX,
  }
}

impl Signal {
  /// A [`Candidate`] advertisement, at the priority its kind carries.
  pub fn candidate(
    nonce: SessionNonce,
    kind: CandidateKind,
    addr: SocketAddr,
  ) -> Self {
    Self::Candidate(Candidate {
      nonce,
      kind,
      addr,
      priority: kind.priority(),
    })
  }

  /// A [`Helper`] announcement.
  pub fn helper(
    nonce: SessionNonce,
    addr: SocketAddr,
    secret: SessionSecret,
  ) -> Self {
    Self::Helper(Helper {
      nonce,
      addr,
      secret,
    })
  }

  /// A [`Punch`] rendezvous.
  pub fn punch(
    nonce: SessionNonce,
    round: u32,
    peers: Vec<SocketAddr>,
  ) -> Self {
    Self::Punch(Punch {
      nonce,
      round,
      peers,
    })
  }

  /// A [`Done`] terminator.
  pub fn done(nonce: SessionNonce) -> Self {
    Self::Done(Done { nonce })
  }

  /// The session the message belongs to. Every signal names one: the
  /// channel is shared with whatever else the login shell says, and a
  /// peer drops signaling whose nonce is not its own.
  pub fn nonce(&self) -> SessionNonce {
    match self {
      Self::Candidate(m) => m.nonce,
      Self::Helper(m) => m.nonce,
      Self::Punch(m) => m.nonce,
      Self::Done(m) => m.nonce,
    }
  }
}

/// Errors from parsing a single protocol line.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
  /// The line does not start with the expected message prefix.
  #[error("line does not start with `{expected}`")]
  WrongPrefix {
    /// The prefix the parser was looking for.
    expected: &'static str,
  },
  /// A token after the prefix is not of the form `key=value`.
  #[error("malformed token `{token}`, expected key=value")]
  MalformedToken {
    /// The offending token, truncated and escaped by `sanitize_token`
    /// so channel content cannot smuggle terminal escapes into an error.
    token: String,
  },
  /// A required key is missing.
  #[error("missing required key `{key}`")]
  MissingKey {
    /// The missing key.
    key: &'static str,
  },
  /// A known single-valued key appeared more than once. Ambiguous input
  /// is rejected rather than resolved by position.
  #[error("repeated key `{key}`")]
  RepeatedKey {
    /// The repeated key.
    key: &'static str,
  },
  /// A value failed to parse as its key's type.
  #[error("invalid value for key `{key}`")]
  InvalidValue {
    /// The key whose value is invalid.
    key: &'static str,
  },
}

/// The `key=value` fields of one line, split but not yet interpreted.
pub(crate) struct Fields<'a> {
  pairs: Vec<(&'a str, &'a str)>,
}

/// Drops one optional trailing `\r\n` or `\n`.
pub(crate) fn strip_line_end(line: &str) -> &str {
  let line = line.strip_suffix('\n').unwrap_or(line);
  line.strip_suffix('\r').unwrap_or(line)
}

/// Whether `line` (already stripped of its terminator) is a message
/// with `prefix`.
///
/// The prefix must be followed by end-of-line or a space: `MUSH
/// CONNECTX` is a lookalike, not a message.
pub(crate) fn has_message_prefix(line: &str, prefix: &str) -> bool {
  line
    .strip_prefix(prefix)
    .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '))
}

/// Splits `line` into fields after checking `prefix`.
///
/// Runs of spaces between tokens are tolerated; every non-empty token
/// must contain `=`.
pub(crate) fn parse_fields<'a>(
  line: &'a str,
  prefix: &'static str,
) -> Result<Fields<'a>, ParseError> {
  let line = strip_line_end(line);
  if !has_message_prefix(line, prefix) {
    return Err(ParseError::WrongPrefix { expected: prefix });
  }
  let rest = &line[prefix.len()..];
  let mut pairs = Vec::new();
  for token in rest.split(' ').filter(|t| !t.is_empty()) {
    let Some((key, value)) = token.split_once('=') else {
      return Err(ParseError::MalformedToken {
        token: sanitize_token(token),
      });
    };
    pairs.push((key, value));
  }
  Ok(Fields { pairs })
}

/// Prepares an offending token for embedding in a [`ParseError`]: at most
/// 64 characters, with control characters and other non-printables
/// escaped (`char::escape_debug`). The input is channel content an
/// attacker can influence and the error ends up on the user's terminal,
/// so raw bytes must never pass through; escaping per character also
/// keeps truncation on UTF-8 character boundaries.
fn sanitize_token(token: &str) -> String {
  token
    .chars()
    .take(64)
    .flat_map(char::escape_debug)
    .collect()
}

impl Fields<'_> {
  /// The value of single-valued `key`; errors on repeats, `None` when
  /// absent.
  fn get(&self, key: &'static str) -> Result<Option<&str>, ParseError> {
    let mut found = None;
    for &(k, v) in &self.pairs {
      if k != key {
        continue;
      }
      if found.is_some() {
        return Err(ParseError::RepeatedKey { key });
      }
      found = Some(v);
    }
    Ok(found)
  }

  /// The value of required single-valued `key`.
  fn require(&self, key: &'static str) -> Result<&str, ParseError> {
    self.get(key)?.ok_or(ParseError::MissingKey { key })
  }

  /// The parsed value of required single-valued `key`.
  pub(crate) fn value<T: std::str::FromStr>(
    &self,
    key: &'static str,
  ) -> Result<T, ParseError> {
    self
      .require(key)?
      .parse()
      .map_err(|_| ParseError::InvalidValue { key })
  }

  /// The parsed value of optional single-valued `key`. Unlike an
  /// unknown key, a present-but-malformed one is rejected: the sender
  /// meant this field and got it wrong.
  pub(crate) fn optional_value<T: std::str::FromStr>(
    &self,
    key: &'static str,
  ) -> Result<Option<T>, ParseError> {
    self
      .get(key)?
      .map(|value| value.parse().map_err(|_| ParseError::InvalidValue { key }))
      .transpose()
  }

  /// All values of repeatable `key`, in order. Unlike unknown keys, a
  /// present-but-malformed one is rejected: the sender generates these
  /// mechanically, so a bad one is protocol corruption, not a later
  /// protocol version.
  pub(crate) fn repeated<T: std::str::FromStr>(
    &self,
    key: &'static str,
  ) -> Result<Vec<T>, ParseError> {
    let mut values = Vec::new();
    for &(k, v) in &self.pairs {
      if k != key {
        continue;
      }
      values.push(v.parse().map_err(|_| ParseError::InvalidValue { key })?);
    }
    Ok(values)
  }
}

/// Budget for [`ConnectScanner`]: how much login output to read through
/// before concluding the server is not going to speak Mush.
#[derive(Debug, Clone, Copy)]
pub struct ScanLimits {
  /// Maximum number of complete lines to examine.
  pub max_lines: usize,
  /// Maximum total bytes to consume, including line terminators.
  pub max_bytes: usize,
}

impl Default for ScanLimits {
  /// Generous defaults: far beyond any plausible motd, small enough to
  /// fail fast when pointed at something that will never answer.
  fn default() -> Self {
    Self {
      max_lines: 512,
      max_bytes: 256 * 1024,
    }
  }
}

/// Errors from [`ConnectScanner`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScanError {
  /// A `MUSH CONNECT` line was found but failed strict parsing. This is
  /// fatal rather than skippable: the server spoke the protocol and got
  /// it wrong (or the line was truncated), and continuing to scan could
  /// only find an attacker-influenced lookalike later in the stream.
  #[error("malformed MUSH CONNECT line: {0}")]
  MalformedConnect(#[from] ParseError),
  /// The scan budget was exhausted without finding a connect line.
  #[error(
    "no MUSH CONNECT line within {lines} lines / {bytes} bytes of output"
  )]
  LimitExceeded {
    /// Complete lines examined.
    lines: usize,
    /// Bytes consumed.
    bytes: usize,
  },
}

/// Incremental scanner that finds the `MUSH CONNECT` line amid arbitrary
/// login output on the bootstrap channel.
///
/// Feed it raw stdout bytes in whatever chunks arrive; it splits them
/// into `\n`-terminated lines and skips everything that is not a connect
/// line: motd text, shell-rc output, invalid UTF-8, embedded NULs,
/// prefix lookalikes (`XMUSH CONNECT`, `MUSH CONNECTED`, indented
/// copies), and lines beyond [`MAX_LINE_BYTES`]. A line that genuinely
/// starts with the connect prefix is parsed strictly; failure there is
/// a hard error, as is exhausting the scan budget.
#[derive(Debug)]
pub struct ConnectScanner {
  limits: ScanLimits,
  line_buf: Vec<u8>,
  /// The current line already exceeded [`MAX_LINE_BYTES`]; its
  /// remaining bytes are discarded up to the next newline.
  line_overflowed: bool,
  lines_seen: usize,
  bytes_seen: usize,
  done: bool,
}

impl ConnectScanner {
  /// Creates a scanner with the given budget.
  pub fn new(limits: ScanLimits) -> Self {
    Self {
      limits,
      line_buf: Vec::new(),
      line_overflowed: false,
      lines_seen: 0,
      bytes_seen: 0,
      done: false,
    }
  }

  /// Consumes the next chunk of channel output.
  ///
  /// Returns `Ok(Some((connect, consumed)))` when the connect line is
  /// found: `consumed` is the number of bytes of `chunk` the scanner
  /// used, ending just past the connect line's newline. The scanner
  /// never examines `chunk[consumed..]`; the channel stays open for
  /// `key=value` signaling, so the caller must hand those bytes to
  /// whatever reads it. Returns `Ok(None)` when the whole chunk was
  /// consumed without finding the line; after the line is found,
  /// further calls consume nothing and return `Ok(None)`.
  pub fn push(
    &mut self,
    chunk: &[u8],
  ) -> Result<Option<(Connect, usize)>, ScanError> {
    if self.done {
      return Ok(None);
    }
    let mut rest = chunk;
    while let Some(newline) = rest.iter().position(|&b| b == b'\n') {
      let (segment, tail) = rest.split_at(newline);
      rest = &tail[1..];
      self.bytes_seen += segment.len() + 1;
      let overflowed = self.line_overflowed
        || self.line_buf.len() + segment.len() > MAX_LINE_BYTES;
      self.line_overflowed = false;
      if !overflowed {
        self.line_buf.extend_from_slice(segment);
        if let Some(connect) = self.examine_line()? {
          self.done = true;
          return Ok(Some((connect, chunk.len() - rest.len())));
        }
      }
      self.line_buf.clear();
      self.lines_seen += 1;
      self.check_budget()?;
    }
    // Partial trailing line: buffer it within the per-line bound.
    self.bytes_seen += rest.len();
    if !self.line_overflowed {
      self.line_buf.extend_from_slice(rest);
      if self.line_buf.len() > MAX_LINE_BYTES {
        self.line_buf.clear();
        self.line_overflowed = true;
      }
    }
    self.check_budget()?;
    Ok(None)
  }

  /// Complete lines examined so far, for caller-side error reporting.
  pub fn lines_seen(&self) -> usize {
    self.lines_seen
  }

  /// Bytes consumed so far, for caller-side error reporting.
  pub fn bytes_seen(&self) -> usize {
    self.bytes_seen
  }

  /// Bytes of an incomplete line held in the scanner. Never past
  /// [`MAX_LINE_BYTES`], so a stream that never sends a newline costs
  /// the scan nothing but its budget.
  pub fn buffered_bytes(&self) -> usize {
    self.line_buf.len()
  }

  /// Parses the buffered complete line if it is a connect line.
  fn examine_line(&self) -> Result<Option<Connect>, ScanError> {
    // Non-UTF-8 lines are binary non-protocol output; a real connect
    // line is ASCII.
    let Ok(line) = str::from_utf8(&self.line_buf) else {
      return Ok(None);
    };
    let line = strip_line_end(line);
    if !has_message_prefix(line, CONNECT_PREFIX) {
      return Ok(None);
    }
    Ok(Some(Connect::parse(line)?))
  }

  fn check_budget(&self) -> Result<(), ScanError> {
    if self.lines_seen >= self.limits.max_lines
      || self.bytes_seen >= self.limits.max_bytes
    {
      return Err(ScanError::LimitExceeded {
        lines: self.lines_seen,
        bytes: self.bytes_seen,
      });
    }
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn pin(seed: u8) -> KeyPin {
    KeyPin::from_bytes([seed; 32])
  }

  fn sample_connect() -> Connect {
    Connect {
      version: 1,
      udp_port: 60123,
      server_key: pin(7),
      addr_hints: vec![
        "192.0.2.10:60123".parse().unwrap(),
        "[2001:db8::1]:60123".parse().unwrap(),
      ],
    }
  }

  fn nonce(seed: u8) -> SessionNonce {
    SessionNonce::from_bytes([seed; NONCE_BYTES])
  }

  fn secret(seed: u8) -> SessionSecret {
    SessionSecret::from_bytes([seed; SECRET_BYTES])
  }

  #[test]
  fn hello_round_trips() {
    let hello = Hello {
      version: 1,
      client_key: pin(3),
      target_port: 22,
      nonce: None,
    };
    let wire = hello.to_wire();
    assert!(wire.starts_with("MUSH HELLO v=1 key="));
    assert!(wire.ends_with(" target=22\n"));
    assert_eq!(Hello::parse(&wire).unwrap(), hello);
    assert_eq!(Hello::parse(wire.trim_end()).unwrap(), hello);
  }

  /// A client that will signal announces the session nonce; one that
  /// will not omits the key entirely, so the no-jump hello stays plain.
  #[test]
  fn hello_carries_the_session_nonce_only_when_signaling() {
    let plain = Hello {
      version: 1,
      client_key: pin(3),
      target_port: 22,
      nonce: None,
    };
    let signaling = Hello {
      nonce: Some(nonce(0x11)),
      ..plain.clone()
    };
    assert!(!plain.to_wire().contains("nonce="));
    assert_eq!(
      signaling.to_wire(),
      format!("{plain} nonce={}\n", nonce(0x11))
    );
    assert_eq!(Hello::parse(&signaling.to_wire()).unwrap(), signaling);
    // A present-but-malformed nonce is an error, not an unknown key.
    let broken = signaling.to_wire().replace(&nonce(0x11).to_string(), "!!");
    assert_eq!(
      Hello::parse(&broken).unwrap_err(),
      ParseError::InvalidValue { key: "nonce" }
    );
  }

  #[test]
  fn session_nonces_round_trip_and_reject_bad_input() {
    let text = nonce(0x5a).to_string();
    assert_eq!(text.len(), 22);
    assert_eq!(text.parse::<SessionNonce>().unwrap(), nonce(0x5a));
    for bad in [
      "",
      "not base64!",
      "AAAA",
      &STANDARD_NO_PAD.encode([0u8; 32]),
    ] {
      assert_eq!(bad.parse::<SessionNonce>(), Err(InvalidValue));
    }
    // Padded base64 is non-canonical.
    let padded = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
    assert!(padded.contains('='));
    assert_eq!(padded.parse::<SessionNonce>(), Err(InvalidValue));
    assert_ne!(
      SessionNonce::generate().unwrap(),
      SessionNonce::generate().unwrap()
    );
  }

  /// The session secret travels on the two ssh channels and nowhere
  /// else: the display and debug forms a log line would use redact it,
  /// and only the wire form spells it out.
  #[test]
  fn the_session_secret_is_redacted_everywhere_but_the_wire() {
    let helper = Helper {
      nonce: nonce(0x11),
      addr: "198.51.100.7:9999".parse().unwrap(),
      secret: secret(0x77),
    };
    let exposed = helper.secret.expose();
    assert_eq!(exposed.len(), 22);
    assert!(helper.to_wire().contains(&exposed));
    for rendered in [
      helper.to_string(),
      format!("{helper:?}"),
      Signal::Helper(helper.clone()).to_string(),
      helper.secret.to_string(),
      format!("{:?}", helper.secret),
    ] {
      assert!(!rendered.contains(&exposed), "leaked in: {rendered}");
    }
    // The wire form is what the peer parses back.
    assert_eq!(Helper::parse(&helper.to_wire()).unwrap(), helper);
    assert_eq!(
      Signal::parse(&Signal::Helper(helper.clone()).to_wire()).unwrap(),
      Some(Signal::Helper(helper))
    );
    assert_eq!(exposed.parse::<SessionSecret>().unwrap(), secret(0x77));
    for bad in [
      "",
      "not base64!",
      "AAAA",
      &STANDARD_NO_PAD.encode([0u8; 32]),
    ] {
      assert_eq!(bad.parse::<SessionSecret>(), Err(InvalidValue));
    }
    assert_ne!(
      SessionSecret::generate().unwrap(),
      SessionSecret::generate().unwrap()
    );
  }

  /// A helper announcement without the secret authorizes nothing, so it
  /// is a malformed message rather than a usable one.
  #[test]
  fn a_helper_announcement_requires_the_secret() {
    let line = format!(
      "MUSH HELPER v=1 nonce={} addr=198.51.100.7:9999",
      nonce(0x11)
    );
    assert_eq!(
      Helper::parse(&line).unwrap_err(),
      ParseError::MissingKey { key: "secret" }
    );
    let line = format!("{line} secret=zz");
    assert_eq!(
      Helper::parse(&line).unwrap_err(),
      ParseError::InvalidValue { key: "secret" }
    );
  }

  #[test]
  fn connect_round_trips() {
    let connect = sample_connect();
    let wire = connect.to_wire();
    assert_eq!(Connect::parse(&wire).unwrap(), connect);
    // CRLF is tolerated.
    let crlf = format!("{}\r\n", wire.trim_end());
    assert_eq!(Connect::parse(&crlf).unwrap(), connect);
  }

  #[test]
  fn connect_without_addr_hints_round_trips() {
    let connect = Connect {
      addr_hints: vec![],
      ..sample_connect()
    };
    assert_eq!(Connect::parse(&connect.to_wire()).unwrap(), connect);
  }

  #[test]
  fn unknown_keys_are_ignored() {
    let line = format!(
      "MUSH CONNECT v=1 future=stuff port=60123 key={} x= addr=192.0.2.10:60123 z=1 z=2",
      pin(7)
    );
    let connect = Connect::parse(&line).unwrap();
    assert_eq!(connect.udp_port, 60123);
    assert_eq!(connect.addr_hints.len(), 1);
  }

  #[test]
  fn extra_spaces_are_tolerated() {
    let line = format!("MUSH CONNECT  v=1   port=60123  key={} ", pin(7));
    assert_eq!(Connect::parse(&line).unwrap().udp_port, 60123);
  }

  #[test]
  fn missing_and_repeated_keys_are_rejected() {
    let key = pin(7).to_string();
    for (line, err) in [
      (
        format!("MUSH CONNECT v=1 key={key}"),
        ParseError::MissingKey { key: "port" },
      ),
      (
        format!("MUSH CONNECT port=1 key={key}"),
        ParseError::MissingKey { key: "v" },
      ),
      (
        format!("MUSH CONNECT v=1 port=1 port=2 key={key}"),
        ParseError::RepeatedKey { key: "port" },
      ),
      (
        format!("MUSH CONNECT v=1 port=1 key={key} key={key}"),
        ParseError::RepeatedKey { key: "key" },
      ),
    ] {
      assert_eq!(Connect::parse(&line).unwrap_err(), err, "line: {line}");
    }
  }

  #[test]
  fn malformed_values_are_rejected() {
    let key = pin(7).to_string();
    for (line, bad_key) in [
      (format!("MUSH CONNECT v=x port=1 key={key}"), "v"),
      (format!("MUSH CONNECT v=1 port=65536 key={key}"), "port"),
      (format!("MUSH CONNECT v=1 port=-1 key={key}"), "port"),
      ("MUSH CONNECT v=1 port=1 key=short".to_string(), "key"),
      (
        format!("MUSH CONNECT v=1 port=1 key={key} addr=nonsense"),
        "addr",
      ),
      (
        format!("MUSH CONNECT v=1 port=1 key={key} addr=192.0.2.1"),
        "addr",
      ),
      (format!("MUSH HELLO v=1 key={key} target=99999"), "target"),
    ] {
      let err = if line.starts_with(HELLO_PREFIX) {
        Hello::parse(&line).unwrap_err()
      } else {
        Connect::parse(&line).unwrap_err()
      };
      assert_eq!(
        err,
        ParseError::InvalidValue { key: bad_key },
        "line: {line}"
      );
    }
  }

  #[test]
  fn tokens_without_equals_are_rejected() {
    assert_eq!(
      Connect::parse("MUSH CONNECT v=1 bogus").unwrap_err(),
      ParseError::MalformedToken {
        token: "bogus".into()
      }
    );
  }

  #[test]
  fn prefix_lookalikes_are_rejected() {
    for line in [
      "MUSH CONNECTED v=1 port=1",
      " MUSH CONNECT v=1 port=1",
      "mush connect v=1 port=1",
      "MUSH",
      "",
      "MUSH HELLO v=1",
    ] {
      assert_eq!(
        Connect::parse(line).unwrap_err(),
        ParseError::WrongPrefix {
          expected: CONNECT_PREFIX
        },
        "line: {line}"
      );
    }
  }

  #[test]
  fn bare_prefix_is_a_truncated_message_not_ignored_output() {
    // The bare prefix parses as a connect line and fails on the
    // missing fields.
    assert_eq!(
      Connect::parse("MUSH CONNECT").unwrap_err(),
      ParseError::MissingKey { key: "v" }
    );
  }

  fn sample_signals() -> Vec<Signal> {
    vec![
      Signal::candidate(
        nonce(0x11),
        CandidateKind::Direct,
        "192.0.2.10:60123".parse().unwrap(),
      ),
      Signal::candidate(
        nonce(0x11),
        CandidateKind::Reflexive,
        "[2001:db8::1]:60123".parse().unwrap(),
      ),
      Signal::helper(
        nonce(0x11),
        "198.51.100.7:9999".parse().unwrap(),
        secret(0x77),
      ),
      Signal::punch(
        nonce(0x11),
        2,
        vec![
          "192.0.2.1:5000".parse().unwrap(),
          "[2001:db8::2]:5001".parse().unwrap(),
        ],
      ),
      Signal::done(nonce(0x11)),
    ]
  }

  #[test]
  fn signals_round_trip() {
    for signal in sample_signals() {
      let wire = signal.to_wire();
      assert_eq!(Signal::parse(&wire).unwrap(), Some(signal.clone()));
      // Unterminated and CRLF-terminated forms parse the same.
      assert_eq!(
        Signal::parse(wire.trim_end()).unwrap(),
        Some(signal.clone())
      );
      let crlf = format!("{}\r\n", wire.trim_end());
      assert_eq!(Signal::parse(&crlf).unwrap(), Some(signal.clone()));
      assert_eq!(signal.nonce(), nonce(0x11));
      // The version is a constant of the build, not a field.
      assert!(wire.contains(&format!(" v={PROTOCOL_VERSION} ")), "{wire}");
    }
  }

  #[test]
  fn a_punch_with_no_peers_round_trips() {
    // Nothing reachable to offer: an empty set, not a missing key.
    let punch = Punch {
      nonce: nonce(0x11),
      round: 1,
      peers: vec![],
    };
    assert_eq!(Punch::parse(&punch.to_wire()).unwrap(), punch);
  }

  #[test]
  fn candidate_kinds_round_trip_and_reject_the_unknown() {
    for kind in [
      CandidateKind::Direct,
      CandidateKind::Reflexive,
      CandidateKind::Relayed,
    ] {
      assert_eq!(kind.as_str().parse::<CandidateKind>().unwrap(), kind);
    }
    for bad in ["", "Direct", "punched", "relay"] {
      assert_eq!(bad.parse::<CandidateKind>(), Err(InvalidValue));
    }
  }

  /// The channel stays a login channel: shell output past the connect
  /// line must not read as protocol.
  #[test]
  fn lines_that_are_not_signals_are_not_signals() {
    for line in [
      "",
      "Welcome to example.org",
      "MUSH",
      "MUSH DONEISH v=1 nonce=x",
      " MUSH DONE v=1 nonce=x",
      "mush done v=1",
      &format!("MUSH HELLO v=1 key={} target=22", pin(3)),
      &sample_connect().to_string(),
    ] {
      assert_eq!(Signal::parse(line).unwrap(), None, "line: {line}");
    }
  }

  /// A line that *is* a signaling message and fails strict parsing is
  /// an error, never a skippable non-message.
  #[test]
  fn malformed_signals_are_errors_not_ignored_output() {
    let n = nonce(0x11).to_string();
    for (line, err) in [
      (
        format!("MUSH DONE v=1 nonce={n} nonce={n}"),
        ParseError::RepeatedKey { key: "nonce" },
      ),
      (
        "MUSH DONE v=1".to_string(),
        ParseError::MissingKey { key: "nonce" },
      ),
      (
        "MUSH DONE nonce=zzz".to_string(),
        ParseError::MissingKey { key: "v" },
      ),
      (
        format!("MUSH CANDIDATE v=1 nonce={n} kind=direct addr=1.2.3.4:5"),
        ParseError::MissingKey { key: "prio" },
      ),
      (
        format!(
          "MUSH CANDIDATE v=1 nonce={n} kind=punched addr=1.2.3.4:5 prio=1"
        ),
        ParseError::InvalidValue { key: "kind" },
      ),
      (
        format!("MUSH CANDIDATE v=1 nonce={n} kind=direct addr=1.2.3.4 prio=1"),
        ParseError::InvalidValue { key: "addr" },
      ),
      (
        format!(
          "MUSH CANDIDATE v=1 nonce={n} kind=direct addr=1.2.3.4:5 \
           prio=4294967296"
        ),
        ParseError::InvalidValue { key: "prio" },
      ),
      (
        format!("MUSH HELPER v=1 nonce={n}"),
        ParseError::MissingKey { key: "addr" },
      ),
      (
        format!("MUSH PUNCH v=1 nonce={n} round=x"),
        ParseError::InvalidValue { key: "round" },
      ),
      (
        format!("MUSH PUNCH v=1 nonce={n} round=1 addr=nonsense"),
        ParseError::InvalidValue { key: "addr" },
      ),
      (
        format!("MUSH DONE v=1 nonce={n} bogus"),
        ParseError::MalformedToken {
          token: "bogus".into(),
        },
      ),
    ] {
      assert_eq!(Signal::parse(&line).unwrap_err(), err, "line: {line}");
    }
  }

  #[test]
  fn signals_ignore_unknown_keys() {
    let line = format!(
      "MUSH DONE v=1 future=stuff nonce={} x= trailing=",
      nonce(0x11)
    );
    assert!(matches!(
      Signal::parse(&line).unwrap(),
      Some(Signal::Done(_))
    ));
  }

  #[test]
  fn scanner_finds_connect_amid_login_output() {
    let connect = sample_connect();
    let mut output = Vec::new();
    output.extend_from_slice(b"Welcome to example.org!\n");
    output.extend_from_slice(b"binary junk: \xff\xfe\x00\x01\n");
    output.extend_from_slice(b"line with NUL \x00 embedded\n");
    output.extend_from_slice(b"XMUSH CONNECT v=9 port=9 key=evil\n");
    output.extend_from_slice(b"MUSH CONNECTING...\n");
    output.extend_from_slice(connect.to_wire().as_bytes());
    output.extend_from_slice(b"post-connect signaling line\n");

    // Feed in every chunk size to exercise partial-line reassembly. The
    // unconsumed tail of the final chunk plus the unpushed chunks must
    // reassemble the post-connect bytes exactly.
    for chunk_size in [1, 2, 3, 7, 64, output.len()] {
      let mut scanner = ConnectScanner::new(ScanLimits::default());
      let mut found = None;
      let mut tail = Vec::new();
      let mut chunks = output.chunks(chunk_size);
      for chunk in &mut chunks {
        if let Some((c, consumed)) = scanner.push(chunk).unwrap() {
          found = Some(c);
          tail.extend_from_slice(&chunk[consumed..]);
          break;
        }
      }
      for chunk in chunks {
        tail.extend_from_slice(chunk);
      }
      assert_eq!(found.as_ref(), Some(&connect), "chunk size {chunk_size}");
      assert_eq!(
        tail, b"post-connect signaling line\n",
        "chunk size {chunk_size}"
      );
    }
  }

  #[test]
  fn scanner_reports_consumed_bytes_within_a_chunk() {
    // The connect line and the first signaling bytes coalesced into one
    // chunk: the consumed offset recovers the tail for the caller.
    let connect = sample_connect();
    let wire = connect.to_wire();
    let signaling = b"cand=192.0.2.5:5000\n";
    let mut chunk = Vec::new();
    chunk.extend_from_slice(b"login output\n");
    chunk.extend_from_slice(wire.as_bytes());
    chunk.extend_from_slice(signaling);

    let mut scanner = ConnectScanner::new(ScanLimits::default());
    let (found, consumed) = scanner.push(&chunk).unwrap().unwrap();
    assert_eq!(found, connect);
    assert_eq!(consumed, b"login output\n".len() + wire.len());
    assert_eq!(&chunk[consumed..], signaling);
  }

  #[test]
  fn scanner_tolerates_crlf() {
    let mut scanner = ConnectScanner::new(ScanLimits::default());
    let wire = format!("banner\r\n{}\r\n", sample_connect());
    let found = scanner.push(wire.as_bytes()).unwrap();
    assert_eq!(found, Some((sample_connect(), wire.len())));
  }

  #[test]
  fn scanner_rejects_malformed_connect_line() {
    let mut scanner = ConnectScanner::new(ScanLimits::default());
    let err = scanner.push(b"MUSH CONNECT v=1 port=bogus\n").unwrap_err();
    assert!(matches!(err, ScanError::MalformedConnect(_)));
  }

  #[test]
  fn scanner_enforces_line_budget() {
    let mut scanner = ConnectScanner::new(ScanLimits {
      max_lines: 3,
      max_bytes: 1 << 20,
    });
    assert_eq!(scanner.push(b"one\ntwo\n").unwrap(), None);
    let err = scanner.push(b"three\nnever seen\n").unwrap_err();
    assert!(matches!(err, ScanError::LimitExceeded { lines: 3, .. }));
  }

  #[test]
  fn scanner_enforces_byte_budget_without_newlines() {
    // A huge newline-free stream must still terminate the scan.
    let mut scanner = ConnectScanner::new(ScanLimits {
      max_lines: 512,
      max_bytes: 4096,
    });
    let chunk = [b'x'; 1024];
    let mut result = Ok(None);
    for _ in 0..8 {
      result = scanner.push(&chunk);
      if result.is_err() {
        break;
      }
    }
    assert!(matches!(result, Err(ScanError::LimitExceeded { .. })));
  }

  #[test]
  fn scanner_discards_overlong_lines_without_unbounded_buffering() {
    let mut scanner = ConnectScanner::new(ScanLimits {
      max_lines: 512,
      max_bytes: MAX_LINE_BYTES * 8,
    });
    // One line far beyond the per-line bound, then the real connect line.
    let long = vec![b'y'; MAX_LINE_BYTES * 2];
    assert_eq!(scanner.push(&long).unwrap(), None);
    assert!(scanner.buffered_bytes() <= MAX_LINE_BYTES);
    assert_eq!(scanner.push(b"\n").unwrap(), None);
    let wire = sample_connect().to_wire();
    let found = scanner.push(wire.as_bytes()).unwrap();
    assert_eq!(found, Some((sample_connect(), wire.len())));
  }

  #[test]
  fn scanner_ignores_input_after_success() {
    let mut scanner = ConnectScanner::new(ScanLimits::default());
    let wire = sample_connect().to_wire();
    let found = scanner.push(wire.as_bytes()).unwrap();
    assert_eq!(found, Some((sample_connect(), wire.len())));
    assert_eq!(scanner.push(b"MUSH CONNECT v=broken\n").unwrap(), None);
  }

  /// Lines longer than the fuzz targets can reach: `bootstrap_lines`
  /// runs under `-max_len=65536`, so a parser going quadratic past that
  /// is invisible there. The framing bounds a line at [`MAX_LINE_BYTES`]
  /// before a parser sees one, so this is about the parsers' own
  /// robustness rather than a reachable input.
  #[test]
  fn parsers_stay_linear_on_lines_past_the_fuzz_bound() {
    let tails = [
      format!("v=1 {}", "a=b ".repeat(10_000)),
      format!("nokey{}", "x".repeat(100_000)),
      format!("nokey{}", "\u{e9}".repeat(50_000)),
      "addr=1.2.3.4:5 ".repeat(10_000),
    ];
    for tail in &tails {
      let line = format!("{CONNECT_PREFIX} {tail}");
      assert!(Connect::parse(&line).is_err(), "line len {}", line.len());
      assert!(
        matches!(Signal::parse(&line), Err(_) | Ok(None)),
        "line len {}",
        line.len()
      );
    }
  }

  #[test]
  fn overlong_multibyte_tokens_error_without_panicking() {
    // Regression: truncating the display token at byte 64 panics when a
    // multi-byte character straddles that index. Cover 2-, 3-, and
    // 4-byte characters, each padded so the character spans byte 64.
    for straddler in ['\u{e9}', '\u{20ac}', '\u{1f600}'] {
      let token = format!("{}{}tail", "x".repeat(63), straddler);
      assert!(!token.is_char_boundary(64), "straddler: {straddler:?}");
      for prefix in [
        HELLO_PREFIX,
        CONNECT_PREFIX,
        CANDIDATE_PREFIX,
        HELPER_PREFIX,
        PUNCH_PREFIX,
        DONE_PREFIX,
      ] {
        let line = format!("{prefix} {token}");
        let err = match prefix {
          HELLO_PREFIX => Hello::parse(&line).unwrap_err(),
          CONNECT_PREFIX => Connect::parse(&line).unwrap_err(),
          _ => Signal::parse(&line).unwrap_err(),
        };
        assert!(
          matches!(err, ParseError::MalformedToken { .. }),
          "line: {line}"
        );
      }
      // The same line through the scanner, whole and one byte at a time:
      // it is valid UTF-8, so the scanner hands it to the strict parser.
      let line = format!("{CONNECT_PREFIX} {token}\n");
      let mut scanner = ConnectScanner::new(ScanLimits::default());
      let err = scanner.push(line.as_bytes()).unwrap_err();
      assert!(matches!(err, ScanError::MalformedConnect(_)));
      let mut scanner = ConnectScanner::new(ScanLimits::default());
      let mut result = Ok(None);
      for byte in line.as_bytes() {
        result = scanner.push(std::slice::from_ref(byte));
        if result.is_err() {
          break;
        }
      }
      assert!(matches!(result, Err(ScanError::MalformedConnect(_))));
    }
  }

  #[test]
  fn malformed_token_display_is_escaped_and_bounded() {
    // Terminal escape sequences and control bytes in channel content must
    // not reach the user's terminal raw through the error message.
    let err = Connect::parse("MUSH CONNECT \u{1b}[2Jevil\u{7}").unwrap_err();
    let message = err.to_string();
    assert!(!message.contains('\u{1b}'));
    assert!(!message.contains('\u{7}'));
    assert!(message.contains("\\u{1b}[2Jevil\\u{7}"), "got: {message}");

    // Overlong tokens are truncated to a bounded display length.
    let long = format!("MUSH CONNECT {}", "z".repeat(1000));
    let ParseError::MalformedToken { token } =
      Connect::parse(&long).unwrap_err()
    else {
      panic!("expected MalformedToken");
    };
    assert_eq!(token, "z".repeat(64));
  }
}
