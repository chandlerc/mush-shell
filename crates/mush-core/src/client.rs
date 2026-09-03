// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The client side of session establishment (design doc, "Session
//! lifecycle"): write the `MUSH HELLO` line to the bootstrap channel,
//! scan the channel for the `MUSH CONNECT` line amid login output, race
//! pinned QUIC handshakes across the candidate addresses, and hand back
//! the established session.
//!
//! [`ClientSession::establish`] is the engine the `mush connect` CLI is
//! a thin shell over, parameterized so tests can drive it end to end in
//! one process: the bootstrap channel is any `AsyncRead + AsyncWrite`
//! (the bootstrap ssh child's stdio; an in-process duplex in tests),
//! and the QUIC endpoint is a fresh UDP bind or a caller-built
//! [`quinn::Endpoint`] (in tests, one over a simulated network).
//!
//! The typed [`EstablishError`] classes drive the caller's fallback
//! order: [`EstablishError::QuicUnreachable`] and
//! [`EstablishError::UdpFutile`] are the two TCP-fallback triggers, the
//! establishment outcomes that mean no UDP path exists;
//! [`EstablishError::PinRejected`] never is (see its docs).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinSet};
use tracing::{debug, warn};

use crate::bootstrap::{
  Connect, ConnectScanner, Hello, PROTOCOL_VERSION, ScanError, ScanLimits,
  SessionNonce, SessionSecret,
};
use crate::channel::SignalChannel;
use crate::path::{
  Arrival, ClientPaths, ClientPlan, PathEvent, PathKind, PathReport,
  is_dialable,
};
use crate::pinning::{self, CryptoError, SessionIdentity};
use crate::server::MAX_ADDR_HINTS;
use crate::transport::TransportOptions;
use crate::traversal::{Probe, SharedSocket, TraversalSocket};
use crate::upgrade::{ClientUpgrade, UpgradePolicy};

/// TLS server name passed to quinn's connect API, which requires one.
/// It carries no trust: the pinning verifiers ignore names entirely.
pub const SERVER_NAME: &str = "mush";

/// Delay between starting successive candidate dials.
///
/// The design calls for candidates "tried concurrently with slight
/// stagger": a head start that lets the preferred candidate (the
/// server's own view of its address) usually win alone, not a
/// per-candidate timeout -- earlier candidates keep racing. 250ms
/// mirrors Happy Eyeballs' connection attempt delay (RFC 8305 section
/// 5), comfortably above typical path RTTs and small enough that dead
/// early candidates cost a fraction of the establishment budget.
pub const DIAL_STAGGER: Duration = Duration::from_millis(250);

/// Default bound on the bootstrap phase: writing the hello and scanning
/// the channel for the `MUSH CONNECT` line.
///
/// Deliberately interactive-scale, not network-scale: until the
/// bootstrap ssh authenticates and executes the remote command, the
/// channel produces nothing, and password or 2FA prompts sit on the
/// user's tty for as long as the user takes. 120 seconds matches sshd's
/// default `LoginGraceTime`, after which an unauthenticated bootstrap
/// is dead anyway.
pub const DEFAULT_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(120);

/// Default bound on the QUIC dialing phase, once the `MUSH CONNECT`
/// line has arrived: the design's fallback timeout ("Fallback when UDP
/// is blocked"). Bootstrap succeeding proves the host is reachable over
/// TCP, so if no pinned handshake completes within this budget, UDP is
/// presumed blocked and the caller falls back.
pub const DEFAULT_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(5);

/// Where the client's QUIC endpoint comes from.
#[derive(Debug)]
pub enum EndpointSource {
  /// Bind a fresh UDP socket at this local address (typically
  /// `0.0.0.0:0`).
  Bind(SocketAddr),
  /// Use a caller-built endpoint (tests: over a simulated network). Its
  /// default client config is left untouched; every dial passes the
  /// pinned config explicitly.
  Endpoint(quinn::Endpoint),
}

/// Options for [`ClientSession::establish`]. `Default` is the design
/// policy; construct with struct update syntax to override values.
#[derive(Debug)]
pub struct ClientOptions {
  /// The QUIC endpoint to dial from.
  pub endpoint: EndpointSource,
  /// The sshd port the server should relay to, announced in the hello.
  pub target_port: u16,
  /// The caller's own resolution of the destination (its A/AAAA
  /// lookups), combined with the `MUSH CONNECT` line's UDP port to form
  /// candidates after the server's own address hints.
  pub resolved_ips: Vec<IpAddr>,
  /// Transport policy; the client side of it is applied.
  pub transport: TransportOptions,
  /// Scan budget for login output ahead of the `MUSH CONNECT` line.
  pub scan_limits: ScanLimits,
  /// Bound on the bootstrap phase; see [`DEFAULT_BOOTSTRAP_TIMEOUT`]
  /// for why it is interactive-scale.
  pub bootstrap_timeout: Duration,
  /// Bound on the QUIC dialing phase; see
  /// [`DEFAULT_ESTABLISH_TIMEOUT`].
  pub establish_timeout: Duration,
  /// The session nonce to announce in the hello, present exactly when
  /// the caller will signal over the bootstrap channel afterwards; see
  /// [`Hello::nonce`]. With `None` the server closes the channel as it
  /// detaches and the bootstrap ssh exits at once.
  pub session_nonce: Option<SessionNonce>,
  /// The traversal machinery, for a session that will try each kind of
  /// path in order (design doc, "Path establishment"). `None` -- the
  /// whole no-jump case -- dials the connect line's candidates and
  /// nothing else, as direct paths.
  ///
  /// Present only alongside a [`session_nonce`](Self::session_nonce)
  /// (see [`EstablishError::MissingSessionNonce`]), and needs an
  /// [`establish_timeout`](Self::establish_timeout) of
  /// [`crate::path::TRAVERSAL_ESTABLISH_TIMEOUT`]: the default bounds
  /// one kind of path, not every stage.
  pub traversal: Option<Traversal>,
}

/// What the caller hands the engine to run the staged dials with.
///
/// The socket must be the one the endpoint runs on, which
/// [`crate::traversal::TraversalEndpoint`] guarantees by constructing
/// both together and [`EstablishError::TraversalSocketMismatch`]
/// checks.
#[derive(Debug)]
pub struct Traversal {
  /// The session's own socket, which sends the probes and maps the
  /// paths: each candidate is dialed at an alias this hands out, and the
  /// alias the winning handshake ran over becomes the session's virtual
  /// peer for life (see [`crate::traversal`]). A caller that keeps a
  /// clone of it can move the session between paths afterwards.
  pub socket: Arc<TraversalSocket>,
  /// The secret this session's probes are signed with, generated with
  /// the nonce and handed to the helper over its own ssh channel.
  pub secret: SessionSecret,
  /// Probes the socket sorted out of the session's traffic.
  pub probes: mpsc::Receiver<Probe>,
  /// What the client learns about itself while establishment runs: the
  /// helper's addresses, and the jump's view of this client. A channel
  /// that closes without a helper answer says there is none, which
  /// establishment degrades around (design doc, "Degrading without the
  /// helper").
  pub arrivals: Option<mpsc::Receiver<Arrival>>,
  /// What the client knows about itself before establishment starts.
  pub plan: ClientPlan,
  /// The policy for what the session does about its path afterwards
  /// (see [`crate::upgrade`]).
  pub upgrade: UpgradePolicy,
}

impl Default for ClientOptions {
  fn default() -> Self {
    Self {
      endpoint: EndpointSource::Bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        0,
      )),
      target_port: 22,
      resolved_ips: Vec::new(),
      transport: TransportOptions::default(),
      scan_limits: ScanLimits::default(),
      bootstrap_timeout: DEFAULT_BOOTSTRAP_TIMEOUT,
      establish_timeout: DEFAULT_ESTABLISH_TIMEOUT,
      session_nonce: None,
      traversal: None,
    }
  }
}

/// How one candidate address failed, for the unreachable report.
#[derive(Debug, Clone)]
pub struct CandidateFailure {
  /// The candidate that failed.
  pub addr: SocketAddr,
  /// Human-readable failure reason.
  pub reason: String,
}

/// How many candidate failures the unreachable message spells out.
///
/// The whole message is printed to the user's stderr as one warning
/// line, and the candidate list is only as bounded as the server chose
/// to make it, so the tail is summarized instead.
const MAX_RENDERED_FAILURES: usize = 8;

fn format_candidate_failures(failures: &[CandidateFailure]) -> String {
  let rendered = failures
    .iter()
    .take(MAX_RENDERED_FAILURES)
    .map(|failure| format!("{}: {}", failure.addr, failure.reason))
    .collect::<Vec<_>>()
    .join("; ");
  match failures.len().saturating_sub(MAX_RENDERED_FAILURES) {
    0 => rendered,
    more => format!("{rendered}; and {more} more"),
  }
}

/// Errors from [`ClientSession::establish`], typed by what the caller
/// does next.
#[derive(Debug, thiserror::Error)]
pub enum EstablishError {
  /// Session key generation or TLS config construction failed.
  #[error("session crypto setup failed: {0}")]
  Crypto(#[from] CryptoError),
  /// The bootstrap channel itself failed (the ssh child died, a pipe
  /// broke). The bootstrap never completed, so there is nothing to
  /// fall back to; the caller reports the ssh failure.
  #[error("bootstrap channel failed: {0}")]
  BootstrapChannel(#[source] io::Error),
  /// The bootstrap channel reached EOF before a `MUSH CONNECT` line:
  /// the remote command exited or was never Mush. The counts say how
  /// much login output was scanned first.
  #[error(
    "bootstrap channel closed with no MUSH CONNECT line \
     ({lines} lines / {bytes} bytes of output scanned)"
  )]
  BootstrapEof {
    /// Complete lines scanned before EOF.
    lines: usize,
    /// Bytes consumed before EOF.
    bytes: usize,
  },
  /// The scanner gave up: a malformed `MUSH CONNECT` line, or the scan
  /// budget exhausted by non-protocol output (the error carries the
  /// counts).
  #[error("bootstrap scan failed: {0}")]
  Scan(#[from] ScanError),
  /// No `MUSH CONNECT` line within the bootstrap timeout.
  #[error(
    "no MUSH CONNECT line within {timeout:?} \
     ({lines} lines / {bytes} bytes of output scanned)"
  )]
  BootstrapTimeout {
    /// The timeout that elapsed.
    timeout: Duration,
    /// Complete lines scanned before the timeout.
    lines: usize,
    /// Bytes consumed before the timeout.
    bytes: usize,
  },
  /// The server speaks a protocol version this client does not.
  #[error("server speaks unsupported protocol version {version}")]
  ProtocolVersion {
    /// The version the `MUSH CONNECT` line announced.
    version: u32,
  },
  /// The `MUSH CONNECT` line carried no address hints and the caller
  /// supplied no resolved addresses: nothing to dial.
  #[error("no candidate addresses to dial")]
  NoCandidates,
  /// The candidate set showed UDP could not work at all, so
  /// establishment stopped rather than spending its budget proving it
  /// (design doc, "Degrading without the helper"). A fallback trigger
  /// exactly like [`EstablishError::QuicUnreachable`], reached sooner.
  #[error("no usable UDP path: {reason}")]
  UdpFutile {
    /// What the candidate set showed.
    reason: String,
  },
  /// A traversal plan was supplied without the session nonce that names
  /// the attempt to the destination and the helper. Refused before the
  /// hello goes out, since without the nonce the destination would
  /// never hold the channel open to signal on.
  #[error("traversal needs a session nonce in the hello")]
  MissingSessionNonce,
  /// The traversal socket is not the one the endpoint runs on. The
  /// design's path establishment rests on the two being the same
  /// ("Both peers probe from the same UDP socket their QUIC endpoint
  /// uses"), and a mismatch would probe from a mapping the session can
  /// never be reached at -- surfacing only as an unexplained relay or
  /// fallback much later.
  #[error(
    "the traversal socket at {socket} is not the endpoint's socket at \
     {endpoint}"
  )]
  TraversalSocketMismatch {
    /// Where the endpoint is bound.
    endpoint: SocketAddr,
    /// Where the probes would have left from.
    socket: SocketAddr,
  },
  /// Binding or constructing the QUIC endpoint failed.
  #[error("UDP endpoint setup failed: {0}")]
  Endpoint(#[source] io::Error),
  /// A live QUIC endpoint answered a candidate and the pinned
  /// handshake was refused: either our verifier rejected the presented
  /// server key, or the peer's TLS stack rejected ours.
  ///
  /// Deliberately NOT a fallback trigger, unlike
  /// [`EstablishError::QuicUnreachable`]: the refusal proves UDP works
  /// on that path and that whoever answered does not hold the pinned
  /// key. In a correct deployment that means active interference or a
  /// version/config mismatch, and silently dropping to TCP would mask
  /// exactly the signal worth failing loudly over.
  #[error(
    "QUIC handshake with {addr} refused ({error}); the address answers \
     but does not hold the pinned session key, refusing to fall back"
  )]
  PinRejected {
    /// The candidate whose handshake was refused.
    addr: SocketAddr,
    /// The handshake failure as quinn reported it.
    error: quinn::ConnectionError,
  },
  /// No candidate completed a pinned handshake within the
  /// establishment deadline and none actively refused: UDP is presumed
  /// blocked. This is the design's TCP-fallback trigger ("Fallback
  /// when UDP is blocked").
  #[error(
    "QUIC unreachable: no pinned handshake within {timeout:?} [{}]",
    format_candidate_failures(.failures)
  )]
  QuicUnreachable {
    /// The establishment deadline that elapsed.
    timeout: Duration,
    /// Per-candidate failure detail for the loud stderr warning.
    failures: Vec<CandidateFailure>,
  },
  /// The winning connection died before the session stream opened.
  #[error("opening the session stream failed: {0}")]
  StreamOpen(#[source] quinn::ConnectionError),
}

/// An established client session: the pinned QUIC connection, the one
/// bidirectional stream, and the bootstrap channel handed back for
/// later `key=value` signaling.
pub struct ClientSession<C> {
  /// The endpoint the session runs on. Kept for its lifetime (dropping
  /// it tears the connection down) and for future socket rebinds.
  pub endpoint: quinn::Endpoint,
  /// The QUIC connection to the Mush server.
  pub connection: quinn::Connection,
  /// The session stream's send half (relays local reads to the peer).
  pub send: quinn::SendStream,
  /// The session stream's receive half.
  pub recv: quinn::RecvStream,
  /// The candidate address the winning handshake used.
  pub chosen_addr: SocketAddr,
  /// Which kind of path carried it (design doc, "Path establishment").
  /// Without traversal there is only one kind, and it is always
  /// [`PathKind::Direct`].
  pub path_kind: PathKind,
  /// What the traversal phase saw, when one ran.
  pub paths: Option<PathReport>,
  /// What keeps improving the session's path after establishment
  /// ([`crate::upgrade`]), for a session the relay carried. `None`
  /// whenever there is nothing better to move to, or no relay to move
  /// off: the caller drives it beside the relay when it is there.
  pub upgrade: Option<ClientUpgrade>,
  /// The parsed `MUSH CONNECT` line (server pin, port, address hints).
  pub connect: Connect,
  /// The bootstrap channel, still open: the design keeps it as a
  /// signaling path after the connect line.
  pub bootstrap: C,
  /// Channel bytes that arrived after the `MUSH CONNECT` line but were
  /// read with it; the start of any post-connect signaling.
  pub bootstrap_leftover: Vec<u8>,
}

impl<C> std::fmt::Debug for ClientSession<C> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ClientSession")
      .field("chosen_addr", &self.chosen_addr)
      .field("path_kind", &self.path_kind)
      .field("paths", &self.paths)
      .field("connect", &self.connect)
      .finish_non_exhaustive()
  }
}

impl<C: AsyncRead + AsyncWrite + Unpin> ClientSession<C> {
  /// Runs the client side of session establishment over `channel` and
  /// returns the established session.
  ///
  /// Flow, per the design's "Session lifecycle": generate the session
  /// identity, write the `MUSH HELLO` line, scan for `MUSH CONNECT`
  /// (bounded by [`ClientOptions::scan_limits`] and
  /// [`ClientOptions::bootstrap_timeout`]), dial the candidate set
  /// concurrently with [`DIAL_STAGGER`], keep the first pinned
  /// handshake and abort the losers, and open the session's
  /// bidirectional stream.
  ///
  /// With [`ClientOptions::traversal`] the dialing phase covers every
  /// kind of path instead of one: the candidates above are the direct
  /// dials, and the traversal driver ([`crate::path`]) runs alongside
  /// them over the same bootstrap channel, ordering the punch and widening
  /// the race as candidates appear. The channel handed back is the one
  /// the driver left, so signaling and the caller never disagree about
  /// where the stream is.
  pub async fn establish(
    mut channel: C,
    options: ClientOptions,
  ) -> Result<Self, EstablishError> {
    if options.traversal.is_some() && options.session_nonce.is_none() {
      return Err(EstablishError::MissingSessionNonce);
    }
    let identity = SessionIdentity::generate()?;
    let hello = Hello {
      version: PROTOCOL_VERSION,
      client_key: identity.pin(),
      target_port: options.target_port,
      nonce: options.session_nonce,
    };

    let mut scanner = ConnectScanner::new(options.scan_limits);
    let scan = scan_for_connect(&mut channel, &mut scanner, &hello);
    let scan_result =
      tokio::time::timeout(options.bootstrap_timeout, scan).await;
    let (connect, bootstrap_leftover) = match scan_result {
      Ok(result) => result?,
      Err(_) => {
        return Err(EstablishError::BootstrapTimeout {
          timeout: options.bootstrap_timeout,
          lines: scanner.lines_seen(),
          bytes: scanner.bytes_seen(),
        });
      }
    };
    if connect.version != PROTOCOL_VERSION {
      return Err(EstablishError::ProtocolVersion {
        version: connect.version,
      });
    }
    debug!(?connect, "bootstrap complete");

    let candidates =
      candidates(&connect, &options.resolved_ips, options.traversal.is_some());
    // Without traversal direct dialing is all of establishment, so an
    // empty set is the end of it. With one, a helper can still relay for a
    // destination that named nothing this client can reach.
    if candidates.is_empty() && options.traversal.is_none() {
      return Err(EstablishError::NoCandidates);
    }

    let endpoint = match options.endpoint {
      EndpointSource::Bind(addr) => bind_endpoint(addr)?,
      EndpointSource::Endpoint(endpoint) => endpoint,
    };
    // Checked rather than trusted: the two arrive here as separate
    // fields, so a refactor or a test that builds them apart cannot
    // slip past the pairing `TraversalEndpoint` exists to guarantee.
    if let Some(traversal) = &options.traversal {
      let endpoint_addr =
        endpoint.local_addr().map_err(EstablishError::Endpoint)?;
      let socket_addr = traversal
        .socket
        .local_addr()
        .map_err(EstablishError::Endpoint)?;
      if endpoint_addr != socket_addr {
        return Err(EstablishError::TraversalSocketMismatch {
          endpoint: endpoint_addr,
          socket: socket_addr,
        });
      }
    }
    let config = pinning::client_config(
      &identity,
      connect.server_key,
      &options.transport,
    )?;

    let mut signaling = SignalChannel::new(&mut channel, bootstrap_leftover);
    // What establishment leaves behind for the maintenance phase: who
    // the peers turned out to be, and the socket and probe stream the
    // session goes on sharing with them.
    let mut inherited = None;
    let (won, paths) = match options.traversal {
      None => {
        let (events_tx, mut events_rx) = mpsc::channel(1);
        let won = race_candidates(
          &endpoint,
          &config,
          &candidates,
          options.establish_timeout,
          std::future::pending(),
          &mut events_rx,
          None,
        )
        .await;
        drop(events_tx);
        (won, None)
      }
      Some(mut traversal) => {
        let mut paths = ClientPaths::new(
          tokio::time::Instant::now(),
          // Checked before the hello went out: a traversal plan
          // without a nonce has nothing to signal about.
          options.session_nonce.expect("checked at entry"),
          traversal.secret,
          traversal.plan,
          candidates.clone(),
        );
        let (events_tx, mut events_rx) = mpsc::channel(64);
        let won = {
          let driver = crate::path::drive_client(
            &mut signaling,
            &traversal.socket,
            &mut traversal.probes,
            &mut traversal.arrivals,
            &mut paths,
            &events_tx,
          );
          race_candidates(
            &endpoint,
            &config,
            &candidates,
            options.establish_timeout,
            driver,
            &mut events_rx,
            Some(&traversal.socket),
          )
          .await
        };
        inherited = Some((
          paths.handoff(),
          traversal.socket,
          traversal.probes,
          traversal.upgrade,
        ));
        (won, Some(paths.report().clone()))
      }
    };
    let (_, bootstrap_leftover) = signaling.into_parts();
    let (chosen_addr, path_kind, connection) = won?;
    debug!(%chosen_addr, %path_kind, "pinned handshake established");

    // Only a relayed session has somewhere better to go and a helper
    // to keep active on the way; every other kind of path is already the
    // peers talking to each other.
    let upgrade = inherited.and_then(|(inherited, socket, probes, policy)| {
      (path_kind == PathKind::Relayed)
        .then(|| {
          ClientUpgrade::new(
            tokio::time::Instant::now(),
            inherited,
            policy,
            socket,
            endpoint.clone(),
            probes,
          )
        })
        .flatten()
    });

    let (send, recv) = connection
      .open_bi()
      .await
      .map_err(EstablishError::StreamOpen)?;
    Ok(Self {
      endpoint,
      connection,
      send,
      recv,
      chosen_addr,
      path_kind,
      paths,
      upgrade,
      connect,
      bootstrap: channel,
      bootstrap_leftover,
    })
  }
}

/// Binds a client endpoint at `addr` under the transport policy.
///
/// Not `quinn::Endpoint::client`, which would take quinn's default
/// endpoint configuration and its QUIC bit greasing; Mush declines that
/// everywhere so the fixed bit goes on separating session traffic from
/// probes (see [`crate::transport::endpoint_config`]).
///
/// Over a [`SharedSocket`] because every Mush endpoint is: this is the
/// endpoint of a session without `--jump`, and an ICMP report has to be
/// kept away from quinn here exactly as much as on a jumped one.
fn bind_endpoint(addr: SocketAddr) -> Result<quinn::Endpoint, EstablishError> {
  let socket =
    std::net::UdpSocket::bind(addr).map_err(EstablishError::Endpoint)?;
  SharedSocket::endpoint(socket, crate::transport::endpoint_config(), None)
    .map_err(EstablishError::Endpoint)
}

/// Whether loopback can name this session's destination.
///
/// Loopback names whoever dials it, so a loopback address offered by a
/// remote peer is a martian -- unless the destination really is this
/// host, which the client's own resolution of the name is the evidence
/// for. With no resolution at all (a failed lookup, a caller that does
/// not resolve) there is no evidence either way, and for an ordinary
/// session dropping the only hints on offer would break a working one.
///
/// A jumped session is where that fallback costs something: its
/// destination is reached through a bastion, so it is by construction
/// not this host, and a name resolving only on the far side of the jump
/// is the canonical shape. Granting the fallback there would let the
/// bastion -- the design's declared untrusted party -- point the
/// client's probes at ports on its own workstation.
pub fn allows_loopback(resolved_ips: &[IpAddr], jumped: bool) -> bool {
  resolved_ips.iter().any(IpAddr::is_loopback)
    || (!jumped && resolved_ips.is_empty())
}

/// The candidate set in dial-preference order (design doc, "Connect"):
/// the server's address hints in the order the server ranked them,
/// then the caller's own resolution of the destination. Duplicates keep
/// their best slot, and addresses that cannot name the destination are
/// dropped ([`crate::path::is_dialable`], the same filter every later
/// candidate passes). The server generates hints mechanically from
/// `$SSH_CONNECTION` and its own interfaces, so a martian here means a
/// confused or hostile server; dialing one wastes a stagger slot of the
/// establishment budget.
///
/// Both lists are truncated to [`crate::server::MAX_ADDR_HINTS`], the
/// quota the stagger budget is sized against. Enforcing it only where
/// hints are generated would leave the client dialing whatever fits in
/// the connect line -- several hundred addresses -- so a server that
/// emits more than its quota could push the client's *own* resolution
/// of the destination past the establishment budget and turn a
/// reachable host into a TCP fallback. Resolution is capped for the
/// second reason as well: the path manager's table is bounded
/// ([`crate::traversal::MAX_PATHS`]), and a name with enough address
/// records to fill it would leave the kinds of path above the direct
/// one unmapped, costing the session its ability to switch paths for the
/// rest of its life.
fn candidates(
  connect: &Connect,
  resolved_ips: &[IpAddr],
  jumped: bool,
) -> Vec<SocketAddr> {
  let allow_loopback = allows_loopback(resolved_ips, jumped);
  let resolved = resolved_ips
    .iter()
    .take(MAX_ADDR_HINTS)
    .map(|&ip| SocketAddr::new(ip, connect.udp_port));
  let hints = connect.addr_hints.iter().copied().take(MAX_ADDR_HINTS);
  let mut candidates: Vec<SocketAddr> = Vec::new();
  for addr in hints.chain(resolved) {
    if !is_dialable(addr, allow_loopback) {
      debug!(%addr, "skipping candidate that cannot name the destination");
      continue;
    }
    if !candidates.contains(&addr) {
      candidates.push(addr);
    }
  }
  candidates
}

/// Writes the hello, then scans channel output for the `MUSH CONNECT`
/// line, tolerating login output. Returns the parsed line and the bytes
/// read past it.
async fn scan_for_connect<C: AsyncRead + AsyncWrite + Unpin>(
  channel: &mut C,
  scanner: &mut ConnectScanner,
  hello: &Hello,
) -> Result<(Connect, Vec<u8>), EstablishError> {
  channel
    .write_all(hello.to_wire().as_bytes())
    .await
    .map_err(EstablishError::BootstrapChannel)?;
  channel
    .flush()
    .await
    .map_err(EstablishError::BootstrapChannel)?;
  let mut buf = [0u8; 4096];
  loop {
    let n = channel
      .read(&mut buf)
      .await
      .map_err(EstablishError::BootstrapChannel)?;
    if n == 0 {
      return Err(EstablishError::BootstrapEof {
        lines: scanner.lines_seen(),
        bytes: scanner.bytes_seen(),
      });
    }
    if let Some((connect, consumed)) = scanner.push(&buf[..n])? {
      return Ok((connect, buf[consumed..n].to_vec()));
    }
  }
}

/// A single candidate dial's failure.
#[derive(Debug, thiserror::Error)]
enum DialFailure {
  /// The dial could not even start (wrong address family for the
  /// socket, endpoint shutting down).
  #[error("{0}")]
  Connect(#[from] quinn::ConnectError),
  /// The connection attempt failed.
  #[error("{0}")]
  Connection(#[from] quinn::ConnectionError),
}

/// Whether a live QUIC endpoint actively refused the handshake, as
/// opposed to nobody answering.
///
/// `TransportError` is our own side aborting, which during a dial means
/// the pinning verifier rejected the presented server key;
/// `ConnectionClosed` is the peer's QUIC stack aborting, which for a
/// Mush server means its verifier rejected our key. Both prove the
/// candidate address answers QUIC, so neither may trigger the TCP
/// fallback; see [`EstablishError::PinRejected`].
fn is_handshake_refusal(error: &quinn::ConnectionError) -> bool {
  matches!(
    error,
    quinn::ConnectionError::TransportError(_)
      | quinn::ConnectionError::ConnectionClosed(_)
  )
}

/// Whether a candidate is one this endpoint can even attempt.
///
/// quinn refuses an IPv6 remote on a v4-bound endpoint under the
/// endpoint lock, with no I/O (`ConnectError::InvalidRemoteAddress`),
/// and maps a v4 remote into a v6-bound endpoint's family. Since
/// `mush connect` binds IPv4 whenever the destination resolves to
/// anything IPv4, a dual-stack destination announcing IPv6 hints is the
/// ordinary shape, not a hostile one.
fn family_reachable(local: SocketAddr, addr: SocketAddr) -> bool {
  local.is_ipv6() || addr.is_ipv4()
}

/// The candidate race: every dial in flight, with the kind of path it
/// belongs to, and the failure record the unreachable report is built
/// from.
///
/// Dials are grouped by kind of path because the stages of
/// establishment are exclusive (see [`crate::path`]): entering a stage
/// abandons the dials of the kinds below it, so a handshake that
/// completes can only be credited to the machinery that was actually in
/// play when it did.
struct DialRace {
  dials:
    JoinSet<(SocketAddr, PathKind, Result<quinn::Connection, DialFailure>)>,
  /// One entry per dial spawned, in order: the candidate, the kind of
  /// path it was dialed as, and the handle that abandons it. One vector
  /// rather than a pair, because a dial's identity and its abort handle
  /// have to be added and dropped together and nothing else keeps them
  /// in step.
  started: Vec<(SocketAddr, PathKind, AbortHandle)>,
  /// Stagger slots handed out to direct dials.
  slot: u32,
  failures: Vec<CandidateFailure>,
  refusal: Option<(SocketAddr, quinn::ConnectionError)>,
}

impl DialRace {
  fn new() -> Self {
    Self {
      dials: JoinSet::new(),
      started: Vec::new(),
      slot: 0,
      failures: Vec::new(),
      refusal: None,
    }
  }

  fn is_dialing(&self) -> bool {
    !self.dials.is_empty()
  }

  /// Starts one dial, unless it was already started as this kind of
  /// path.
  ///
  /// Direct dials are staggered ([`DIAL_STAGGER`]) over a set nothing
  /// has yet proven anything about. The punched and relayed dials are
  /// not: their candidates arrive because a rendezvous just established
  /// them, and each is a distinct opened path rather than a guess, so
  /// delaying them would only spend the window that opened them.
  ///
  /// Stagger slots go only to candidates this endpoint can dial: one
  /// that fails under the endpoint lock without any I/O starts
  /// immediately and reports, rather than holding a slot of the
  /// establishment budget open for a dial that never happens.
  fn dial(
    &mut self,
    endpoint: &quinn::Endpoint,
    config: &quinn::ClientConfig,
    addr: SocketAddr,
    path_kind: PathKind,
    paths: Option<&Arc<TraversalSocket>>,
  ) {
    if self
      .started
      .iter()
      .any(|&(at, on, _)| (at, on) == (addr, path_kind))
    {
      return;
    }
    let dialable = endpoint
      .local_addr()
      .ok()
      .is_none_or(|local| family_reachable(local, addr));
    let delay = match (path_kind, dialable) {
      (PathKind::Direct, true) => {
        let delay = DIAL_STAGGER * self.slot;
        self.slot += 1;
        delay
      }
      _ => Duration::ZERO,
    };
    // With the path manager in play the dial is aimed at the
    // candidate's alias, which lets the manager re-point the winning
    // connection later (see [`crate::traversal`]). The real address is
    // what establishment reports and what the wire carries either way.
    let target = match paths {
      Some(socket) => socket.dial_target(addr, path_kind),
      None => addr,
    };
    let endpoint = endpoint.clone();
    let config = config.clone();
    let abort = self.dials.spawn(async move {
      tokio::time::sleep(delay).await;
      let connecting = match endpoint.connect_with(config, target, SERVER_NAME)
      {
        Ok(connecting) => connecting,
        Err(error) => {
          return (addr, path_kind, Err(DialFailure::Connect(error)));
        }
      };
      (
        addr,
        path_kind,
        connecting.await.map_err(DialFailure::Connection),
      )
    });
    self.started.push((addr, path_kind, abort));
  }

  /// Abandons every dial below `path_kind`.
  ///
  /// What is abandoned is reissued as the new kind of path when it
  /// still applies, keeping the winner's kind of path an exact claim: a
  /// destination behind a stateful firewall answers the same address
  /// either way, and only the punch made it answer. The relay never asks
  /// for this: it is a last resort raced alongside the punched dials,
  /// not a replacement for them.
  fn abandon_below(&mut self, path_kind: PathKind) {
    self.started.retain(|(_, at, abort)| {
      if *at >= path_kind {
        return true;
      }
      abort.abort();
      false
    });
  }

  /// Records one finished dial, returning the winner.
  fn finished(
    &mut self,
    joined: Result<
      (SocketAddr, PathKind, Result<quinn::Connection, DialFailure>),
      tokio::task::JoinError,
    >,
  ) -> Option<(SocketAddr, PathKind, quinn::Connection)> {
    match joined {
      Ok((addr, path_kind, Ok(connection))) => {
        Some((addr, path_kind, connection))
      }
      Ok((addr, _, Err(failure))) => {
        self.record(addr, failure);
        None
      }
      Err(join_error) if join_error.is_panic() => {
        std::panic::resume_unwind(join_error.into_panic())
      }
      // An aborted dial is establishment moving on, not a failure.
      Err(_) => None,
    }
  }

  fn record(&mut self, addr: SocketAddr, failure: DialFailure) {
    if let DialFailure::Connection(error) = &failure
      && self.refusal.is_none()
      && is_handshake_refusal(error)
    {
      self.refusal = Some((addr, error.clone()));
    }
    warn!(%addr, %failure, "candidate dial failed");
    self.failures.push(CandidateFailure {
      addr,
      reason: failure.to_string(),
    });
  }
}

/// Runs the staged dials: races the direct candidates while `driver`
/// adds candidates from `events`, and keeps the first pinned handshake
/// that completes.
///
/// `driver` is the traversal phase ([`crate::path::drive_client`]) or,
/// for a session with no jump, a future that never completes: direct
/// dialing is then all of establishment, raced on the stagger alone.
async fn race_candidates<F: Future<Output = ()>>(
  endpoint: &quinn::Endpoint,
  config: &quinn::ClientConfig,
  direct: &[SocketAddr],
  timeout: Duration,
  driver: F,
  events: &mut mpsc::Receiver<PathEvent>,
  paths: Option<&Arc<TraversalSocket>>,
) -> Result<(SocketAddr, PathKind, quinn::Connection), EstablishError> {
  let deadline = tokio::time::Instant::now() + timeout;
  let mut race = DialRace::new();
  for &addr in direct {
    race.dial(endpoint, config, addr, PathKind::Direct, paths);
  }

  let mut winner = None;
  let mut futile = None;
  let mut driver_done = false;
  let mut driver = std::pin::pin!(driver);
  while winner.is_none() && futile.is_none() {
    let dialing = race.is_dialing();
    tokio::select! {
      biased;
      joined = race.dials.join_next(), if dialing => {
        let Some(joined) = joined else { continue };
        winner = race.finished(joined);
      }
      event = events.recv() => match event {
        Some(PathEvent::Dial { addr, path_kind }) => {
          race.dial(endpoint, config, addr, path_kind, paths);
        }
        Some(PathEvent::Stage(path_kind)) => race.abandon_below(path_kind),
        Some(PathEvent::Futile(reason)) => futile = Some(reason),
        // Only the driver holds a sender, and it outlives this loop.
        None => std::future::pending().await,
      },
      () = &mut driver, if !driver_done => driver_done = true,
      () = tokio::time::sleep_until(deadline) => break,
    }
  }

  // Abort and drain the rest. A straggler that completed its handshake
  // in the same instant is a usable path: with a winner it is a lost
  // duplicate and is closed; without one (the deadline just elapsed) it
  // is strictly better than falling back, so it wins after all.
  race.dials.abort_all();
  while let Some(joined) = race.dials.join_next().await {
    match race.finished(joined) {
      // A handshake outranks a prediction: `futile` is a judgment
      // about the candidate set, and this candidate just disproved it.
      Some(late) if winner.is_none() => winner = Some(late),
      Some((_, _, connection)) => {
        connection.close(0u32.into(), b"lost candidate race");
      }
      None => {}
    }
  }

  if let Some((addr, path_kind, connection)) = winner {
    // The session's path from here on: the alias the winning handshake
    // ran over becomes the peer address quinn keeps for life and the
    // manager re-points on a switch. A candidate dialed unmapped has
    // nothing to commit, and the session stays on the path that won it.
    if let Some(socket) = paths
      && !socket.commit(addr)
    {
      debug!(%addr, "the winning path is not under the path manager");
    }
    return Ok((addr, path_kind, connection));
  }
  // A refusal outranks every other ending, however the rest of
  // establishment fared: it must fail loudly, never trigger the fallback.
  if let Some((addr, error)) = race.refusal {
    return Err(EstablishError::PinRejected { addr, error });
  }
  if let Some(reason) = futile {
    return Err(EstablishError::UdpFutile { reason });
  }
  let mut failures = race.failures;
  for (addr, _, _) in race.started {
    if !failures.iter().any(|failure| failure.addr == addr) {
      failures.push(CandidateFailure {
        addr,
        reason: format!("no handshake response within {timeout:?}"),
      });
    }
  }
  Err(EstablishError::QuicUnreachable { timeout, failures })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bootstrap::PROTOCOL_VERSION;
  use crate::pinning::KeyPin;

  fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
  }

  fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
  }

  fn connect(hints: &[&str], udp_port: u16) -> Connect {
    Connect {
      version: PROTOCOL_VERSION,
      udp_port,
      server_key: KeyPin::from_bytes([9; 32]),
      addr_hints: hints.iter().copied().map(addr).collect(),
    }
  }

  #[test]
  fn candidates_keep_hint_order_then_resolution() {
    let candidates = candidates(
      &connect(&["198.51.100.7:60123", "10.0.0.5:60123"], 60123),
      &[ip("198.51.100.7"), ip("203.0.113.8")],
      false,
    );
    assert_eq!(
      candidates,
      vec![
        // Hints first, in the server's order; the resolved address that
        // repeats a hint keeps the hint's better slot.
        addr("198.51.100.7:60123"),
        addr("10.0.0.5:60123"),
        addr("203.0.113.8:60123"),
      ]
    );
  }

  #[test]
  fn martian_hints_are_dropped() {
    let hints = [
      "0.0.0.0:60123",
      "224.0.0.1:60123",
      "255.255.255.255:60123",
      "[::]:60123",
      "[ff02::1]:60123",
      "198.51.100.7:0",
      "198.51.100.7:60123",
    ];
    let candidates =
      candidates(&connect(&hints, 60123), &[ip("198.51.100.7")], false);
    assert_eq!(candidates, vec![addr("198.51.100.7:60123")]);
  }

  #[test]
  fn loopback_hints_need_a_loopback_destination() {
    let line = connect(&["127.0.0.1:60123", "[::1]:60123"], 60123);
    // A remote destination: loopback names this host, never that one,
    // so only the resolved address survives.
    assert_eq!(
      candidates(&line, &[ip("198.51.100.7")], false),
      vec![addr("198.51.100.7:60123")]
    );
    // The destination is this host (the shape every loopback test and a
    // `mush connect 127.0.0.1` have), so the hints are real.
    assert_eq!(
      candidates(&line, &[ip("127.0.0.1")], false),
      vec![addr("127.0.0.1:60123"), addr("[::1]:60123")]
    );
    // Nothing resolved: no evidence either way, and the hints are all
    // there is.
    assert_eq!(
      candidates(&line, &[], false),
      vec![addr("127.0.0.1:60123"), addr("[::1]:60123")]
    );
  }

  /// The no-evidence fallback is not extended to a jumped session (see
  /// `allows_loopback`): `mush -J bastion internal.corp`, where the
  /// name resolves only on the bastion's side, is the canonical jumped
  /// shape and the one that leaves this client with no resolution at
  /// all.
  #[test]
  fn an_unresolvable_jumped_destination_does_not_unlock_loopback() {
    let line = connect(&["127.0.0.1:60123", "198.51.100.7:60123"], 60123);
    assert_eq!(
      candidates(&line, &[], true),
      vec![addr("198.51.100.7:60123")]
    );
    // Resolution that really does name this host is still evidence,
    // jump or no jump: `mush -J bastion 127.0.0.1` in the loopback labs.
    assert_eq!(
      candidates(&line, &[ip("127.0.0.1")], true),
      vec![addr("127.0.0.1:60123"), addr("198.51.100.7:60123")]
    );
    assert!(allows_loopback(&[], false));
    assert!(!allows_loopback(&[], true));
  }

  #[test]
  fn hints_are_truncated_to_the_servers_own_quota() {
    let flood: Vec<String> =
      (1..=40).map(|n| format!("198.51.100.{n}:60123")).collect();
    let refs: Vec<&str> = flood.iter().map(String::as_str).collect();
    let candidates =
      candidates(&connect(&refs, 60123), &[ip("203.0.113.8")], false);
    // The truncated hints, then the caller's own resolution, which a
    // flood must never be able to push out of the dial budget.
    assert_eq!(candidates.len(), MAX_ADDR_HINTS + 1);
    assert_eq!(candidates[0], addr("198.51.100.1:60123"));
    assert_eq!(candidates[MAX_ADDR_HINTS], addr("203.0.113.8:60123"));
  }

  #[test]
  fn only_v6_candidates_are_unreachable_from_a_v4_endpoint() {
    let v4 = addr("0.0.0.0:0");
    let v6 = addr("[::]:0");
    assert!(family_reachable(v4, addr("198.51.100.7:60123")));
    assert!(!family_reachable(v4, addr("[2001:db8::1]:60123")));
    // A v6-bound endpoint takes both: quinn maps the v4 remote into it.
    assert!(family_reachable(v6, addr("198.51.100.7:60123")));
    assert!(family_reachable(v6, addr("[2001:db8::1]:60123")));
  }

  #[test]
  fn the_failure_report_summarizes_a_long_tail() {
    let failures: Vec<CandidateFailure> = (1..=12)
      .map(|n| CandidateFailure {
        addr: addr(&format!("198.51.100.{n}:60123")),
        reason: "silent".into(),
      })
      .collect();
    let rendered = format_candidate_failures(&failures);
    assert_eq!(rendered.matches("silent").count(), MAX_RENDERED_FAILURES);
    assert!(rendered.ends_with("; and 4 more"), "{rendered}");
    // A list inside the cap is rendered whole, with no tail note.
    let rendered = format_candidate_failures(&failures[..3]);
    assert_eq!(rendered.matches("silent").count(), 3);
    assert!(!rendered.contains("more"), "{rendered}");
  }

  #[test]
  fn resolved_addresses_are_filtered_too() {
    // A destination port of 0 poisons every resolved candidate, which
    // must show up as nothing to dial rather than a doomed dial.
    assert!(
      candidates(&connect(&[], 0), &[ip("198.51.100.7")], false).is_empty()
    );
  }
}
