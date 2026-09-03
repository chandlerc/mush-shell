// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The server side of session establishment (design doc, "Session
//! lifecycle"): bind a UDP port, read the `MUSH HELLO` line from the
//! bootstrap channel, answer with the `MUSH CONNECT` line, and accept
//! exactly one QUIC connection from the pinned client.
//!
//! [`ServerSession::run`] is the engine `mush server bootstrap` is a
//! thin layer over, parameterized like the client side: the bootstrap
//! channel is any `AsyncRead + AsyncWrite` (production: stdio on the ssh
//! exec channel; tests: an in-process duplex), the endpoint is either a
//! bind from a configurable port range or a caller-built
//! [`quinn::Endpoint`], and both address-hint sources are injected
//! (production: `$SSH_CONNECTION` and [`interface_ips`]) so tests see
//! exactly the hints they arrange.
//!
//! Detaching (fork, setsid, close stdio) and the retention window are
//! CLI concerns. The detached production server cannot run this engine
//! at all -- it must fork before any async runtime exists -- so the
//! pieces are also exposed standalone: it answers the bootstrap
//! conversation synchronously over [`bind_socket`]'s socket, forks, and
//! picks up at [`accept_session`].

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tracing::debug;

use crate::bootstrap::{Connect, Hello, PROTOCOL_VERSION, ParseError};
use crate::path::is_dialable_ip;
use crate::pinning::{self, CryptoError, SessionIdentity};
use crate::transport::TransportOptions;
use crate::traversal::SharedSocket;

/// Default UDP port range, first free port wins: Mosh's range,
/// deliberately ("mosh-style configurable range" in the design doc). A
/// host already running Mosh has it open, so Mush works there with no
/// new firewall policy.
pub const DEFAULT_PORT_RANGE: RangeInclusive<u16> = 60000..=61000;

/// Default bound on the whole bootstrap conversation: reading the
/// hello, emitting the connect line, and the pinned client connecting
/// with its stream. The design's give-up timeout. Unlike the client's
/// scan timeout this is network-scale: interactive authentication
/// happens before sshd execs this process, so by the time it runs the
/// client is moments from dialing.
pub const DEFAULT_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(60);

/// Cap on the connect line's address hints.
///
/// Hints are raced with a stagger (see [`crate::client::DIAL_STAGGER`]),
/// so their number is a budget, not just a line length: eight covers a
/// multi-homed host with both families and still leaves the last
/// candidate most of the establishment window.
pub const MAX_ADDR_HINTS: usize = 8;

/// Bound on the hello line. It arrives on an exec channel's stdin,
/// written by the Mush client with no shell in between, so unlike the
/// client's connect scan there is no login output to tolerate: a real
/// hello is under 100 bytes, and anything without a newline in this many
/// is not a Mush client.
pub const MAX_HELLO_BYTES: usize = 4096;

/// Where the server's QUIC endpoint comes from.
#[derive(Debug)]
pub enum EndpointSource {
  /// Bind the first free UDP port in `ports` on `ip`.
  Bind {
    /// Local address to bind on.
    ip: IpAddr,
    /// Ports to try, in order.
    ports: RangeInclusive<u16>,
  },
  /// Use a caller-built endpoint (tests: over a simulated network). Its
  /// server config is installed once the hello supplies the client
  /// pin, so it should be built without one.
  Endpoint(quinn::Endpoint),
}

/// Options for [`ServerSession::run`]. `Default` is the design policy;
/// construct with struct update syntax to override values.
#[derive(Debug)]
pub struct ServerOptions {
  /// The QUIC endpoint to accept on.
  pub endpoint: EndpointSource,
  /// The `$SSH_CONNECTION` value ("client_ip client_port server_ip
  /// server_port"), injected rather than read from the environment so
  /// tests control it. Its server address leads the connect line's
  /// hints (see [`addr_hints`]).
  pub ssh_connection: Option<String>,
  /// This host's interface addresses, hinted after the
  /// `$SSH_CONNECTION` address. Injected too (production passes
  /// [`interface_ips`]) so tests do not depend on the machine they run
  /// on.
  pub interface_ips: Vec<IpAddr>,
  /// Transport policy; the server side of it is applied.
  pub transport: TransportOptions,
  /// Bound on the whole run; see [`DEFAULT_BOOTSTRAP_TIMEOUT`].
  pub bootstrap_timeout: Duration,
}

impl Default for ServerOptions {
  fn default() -> Self {
    Self {
      endpoint: EndpointSource::Bind {
        ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        ports: DEFAULT_PORT_RANGE,
      },
      ssh_connection: None,
      interface_ips: Vec::new(),
      transport: TransportOptions::default(),
      bootstrap_timeout: DEFAULT_BOOTSTRAP_TIMEOUT,
    }
  }
}

/// Errors from [`ServerSession::run`].
#[derive(Debug, thiserror::Error)]
pub enum RunError {
  /// Session key generation or TLS config construction failed.
  #[error("session crypto setup failed: {0}")]
  Crypto(#[from] CryptoError),
  /// The bootstrap channel itself failed.
  #[error("bootstrap channel failed: {0}")]
  BootstrapChannel(#[source] io::Error),
  /// The bootstrap channel reached EOF before a hello line.
  #[error("bootstrap channel closed before a MUSH HELLO line")]
  BootstrapEof,
  /// No newline within [`MAX_HELLO_BYTES`]: not a Mush client.
  #[error("no complete MUSH HELLO line in the first {MAX_HELLO_BYTES} bytes")]
  HelloTooLong,
  /// The hello line is not UTF-8, which a real hello always is.
  #[error("MUSH HELLO line is not valid UTF-8")]
  HelloNotUtf8,
  /// The hello line failed strict parsing.
  #[error("malformed MUSH HELLO line: {0}")]
  Hello(#[from] ParseError),
  /// The client speaks a protocol version this server does not.
  #[error("client speaks unsupported protocol version {version}")]
  ProtocolVersion {
    /// The version the hello announced.
    version: u32,
  },
  /// Every port in the configured range failed to bind.
  #[error("no UDP port available in {ports:?}: {last_error}")]
  NoUdpPort {
    /// The range that was tried.
    ports: RangeInclusive<u16>,
    /// The last bind failure.
    last_error: io::Error,
  },
  /// Constructing or querying the QUIC endpoint failed.
  #[error("UDP endpoint setup failed: {0}")]
  Endpoint(#[source] io::Error),
  /// The QUIC endpoint closed while waiting for the client.
  #[error("QUIC endpoint closed while waiting for the pinned client")]
  EndpointClosed,
  /// No pinned connection (with its stream) within the timeout.
  #[error("no pinned QUIC connection within {timeout:?}; giving up")]
  BootstrapTimeout {
    /// The timeout that elapsed.
    timeout: Duration,
  },
}

/// An established server session: the pinned QUIC connection, the one
/// bidirectional stream, and the accept-time metadata the caller needs
/// to run the relay.
pub struct ServerSession<C> {
  /// The endpoint the session runs on; kept for the session's lifetime
  /// (dropping it tears the connection down).
  pub endpoint: quinn::Endpoint,
  /// The QUIC connection from the pinned client.
  pub connection: quinn::Connection,
  /// The session stream's send half.
  pub send: quinn::SendStream,
  /// The session stream's receive half.
  pub recv: quinn::RecvStream,
  /// The UDP port the endpoint is bound to (as announced in the
  /// connect line).
  pub udp_port: u16,
  /// The client's address at accept time. Metadata only: the client
  /// roams, so this is where the session started, not where it stays.
  pub client_addr: SocketAddr,
  /// The parsed hello; its target port is the sshd port the caller
  /// relays to.
  pub hello: Hello,
  /// The bootstrap channel, still open: the design keeps it as a
  /// signaling path until the server detaches.
  pub bootstrap: C,
  /// Channel bytes that arrived after the hello line but were read
  /// with it; the start of any post-hello signaling.
  pub bootstrap_leftover: Vec<u8>,
}

impl<C> std::fmt::Debug for ServerSession<C> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ServerSession")
      .field("udp_port", &self.udp_port)
      .field("client_addr", &self.client_addr)
      .field("hello", &self.hello)
      .finish_non_exhaustive()
  }
}

impl<C: AsyncRead + AsyncWrite + Unpin> ServerSession<C> {
  /// Runs the server side of session establishment over `channel` and
  /// returns the established session.
  ///
  /// Flow, per the design's "Session lifecycle": bind the UDP port,
  /// read the hello, pin the client key from it, emit the connect line
  /// (port, own pin, address hints), and accept exactly one connection
  /// matching the pinned client key, plus its bidirectional stream,
  /// within [`ServerOptions::bootstrap_timeout`]. Nobody else can
  /// complete the handshake (quinn's job, via the pinning verifier), and
  /// once the session is established no further handshake is accepted at
  /// all.
  pub async fn run(
    channel: C,
    options: ServerOptions,
  ) -> Result<Self, RunError> {
    let timeout = options.bootstrap_timeout;
    match tokio::time::timeout(timeout, Self::run_inner(channel, options)).await
    {
      Ok(result) => result,
      Err(_) => Err(RunError::BootstrapTimeout { timeout }),
    }
  }

  async fn run_inner(
    mut channel: C,
    options: ServerOptions,
  ) -> Result<Self, RunError> {
    let endpoint = match options.endpoint {
      EndpointSource::Bind { ip, ports } => bind_endpoint(ip, &ports)?,
      EndpointSource::Endpoint(endpoint) => endpoint,
    };
    let local = endpoint.local_addr().map_err(RunError::Endpoint)?;
    let udp_port = local.port();

    let (hello, bootstrap_leftover) = read_hello(&mut channel).await?;
    if hello.version != PROTOCOL_VERSION {
      return Err(RunError::ProtocolVersion {
        version: hello.version,
      });
    }
    debug!(?hello, udp_port, "hello received");

    let identity = SessionIdentity::generate()?;
    let config =
      pinning::server_config(&identity, hello.client_key, &options.transport)?;
    endpoint.set_server_config(Some(config));

    let addr_hints = addr_hints(
      options.ssh_connection.as_deref(),
      &options.interface_ips,
      local,
    );
    let connect = Connect {
      version: PROTOCOL_VERSION,
      udp_port,
      server_key: identity.pin(),
      addr_hints,
    };
    channel
      .write_all(connect.to_wire().as_bytes())
      .await
      .map_err(RunError::BootstrapChannel)?;
    channel.flush().await.map_err(RunError::BootstrapChannel)?;

    let (connection, send, recv) = accept_pinned(&endpoint).await?;
    // One session, one connection: never accept a second. Existing
    // state is unaffected; new handshake attempts get nothing.
    endpoint.set_server_config(None);
    let client_addr = connection.remote_address();
    debug!(%client_addr, "pinned client connected");
    Ok(Self {
      endpoint,
      connection,
      send,
      recv,
      udp_port,
      client_addr,
      hello,
      bootstrap: channel,
      bootstrap_leftover,
    })
  }
}

/// Binds the first free UDP port in `ports` on `ip`.
///
/// Public on its own, rather than folded into endpoint construction,
/// for the detached production server: it must announce the port and
/// fork before its async runtime, and therefore its quinn endpoint, can
/// exist.
pub fn bind_socket(
  ip: IpAddr,
  ports: &RangeInclusive<u16>,
) -> Result<std::net::UdpSocket, RunError> {
  let mut last_error =
    io::Error::new(io::ErrorKind::InvalidInput, "empty port range");
  for port in ports.clone() {
    match std::net::UdpSocket::bind(SocketAddr::new(ip, port)) {
      Ok(socket) => return Ok(socket),
      Err(error) => last_error = error,
    }
  }
  Err(RunError::NoUdpPort {
    ports: ports.clone(),
    last_error,
  })
}

/// Binds the first free UDP port in `ports` on `ip` and wraps it in an
/// endpoint with no server config yet (the client pin arrives later).
///
/// Over a [`SharedSocket`] for the reason the client's endpoint is: an
/// ICMP report reaching quinn ends the endpoint and every session on
/// it, and this side answers whoever can reach its port. The detached
/// production server does not come through here; it picks up at
/// [`crate::traversal::TraversalEndpoint::over_std`], which wraps its
/// socket the same way.
fn bind_endpoint(
  ip: IpAddr,
  ports: &RangeInclusive<u16>,
) -> Result<quinn::Endpoint, RunError> {
  let socket = bind_socket(ip, ports)?;
  SharedSocket::endpoint(socket, crate::transport::endpoint_config(), None)
    .map_err(RunError::Endpoint)
}

/// Reads the single `MUSH HELLO` line, returning it with any bytes read
/// past its newline.
async fn read_hello<C: AsyncRead + Unpin>(
  channel: &mut C,
) -> Result<(Hello, Vec<u8>), RunError> {
  let mut buf = Vec::new();
  let mut chunk = [0u8; 1024];
  let newline = loop {
    if let Some(position) = buf.iter().position(|&b| b == b'\n') {
      break position;
    }
    if buf.len() > MAX_HELLO_BYTES {
      return Err(RunError::HelloTooLong);
    }
    let n = channel
      .read(&mut chunk)
      .await
      .map_err(RunError::BootstrapChannel)?;
    if n == 0 {
      return Err(RunError::BootstrapEof);
    }
    buf.extend_from_slice(&chunk[..n]);
  };
  let line =
    str::from_utf8(&buf[..newline]).map_err(|_| RunError::HelloNotUtf8)?;
  let hello = Hello::parse(line)?;
  Ok((hello, buf[newline + 1..].to_vec()))
}

/// The connect line's address hint from an `$SSH_CONNECTION` value
/// ("client_ip client_port server_ip server_port"): the server-side
/// address the client actually reached over ssh, which handles
/// split-horizon DNS. Malformed input yields no hint rather than an
/// error: hints are an optimization the client dials without.
pub fn ssh_connection_hint(
  ssh_connection: &str,
  udp_port: u16,
) -> Option<SocketAddr> {
  let server_ip = ssh_connection.split_whitespace().nth(2)?;
  let ip: IpAddr = server_ip.parse().ok()?;
  Some(SocketAddr::new(ip, udp_port))
}

/// The client-side address of an `$SSH_CONNECTION` value: this host's
/// view of whoever opened the channel.
///
/// The jump helper's use of it is the design's `echo $SSH_CONNECTION`
/// step ("Degrading without the helper"): the client's public address
/// as the jump observed it, which under a port-preserving 1:1 NAT is
/// where the destination's reverse punch aims. Malformed input yields
/// no address rather than an error, exactly as the server-side hint
/// does.
pub fn ssh_connection_client_ip(ssh_connection: &str) -> Option<IpAddr> {
  ssh_connection.split_whitespace().next()?.parse().ok()
}

/// The hints to announce for a socket bound at `local`, in
/// dial-preference order (design doc, "Path establishment"): the
/// `$SSH_CONNECTION` address first, the one address the client
/// demonstrably reached, then `interface_ips` (production:
/// [`interface_ips`]), which makes a destination dialable whose ssh
/// runs through a jump but whose UDP is open, or whose second interface
/// faces the client's network. Every hint takes `local`'s port.
///
/// Duplicates keep their best slot, addresses of a family `local` does
/// not answer on are dropped, and the rest is capped at
/// [`MAX_ADDR_HINTS`] -- in that order, so a dual-stack host spends its
/// slots on hints a peer can actually reach. This server and the jump
/// helper both bind a v4 socket while interface enumeration and
/// `$SSH_CONNECTION` name whatever families the host has, so a hint of
/// the other family would cost the client a dial slot and fail every
/// time. The consequence, recorded in the design doc's "Upgrading from
/// relay to direct", is that a v6-only destination has no UDP path at
/// all and falls back to TCP.
///
/// Hints are dial candidates: the client races them against its own
/// resolution of the destination and filters what it will not dial.
pub fn addr_hints(
  ssh_connection: Option<&str>,
  interface_ips: &[IpAddr],
  local: SocketAddr,
) -> Vec<SocketAddr> {
  let port = local.port();
  let ssh_hint = ssh_connection
    .and_then(|value| ssh_connection_hint(value, port))
    .into_iter();
  let interfaces = interface_ips.iter().map(|&ip| SocketAddr::new(ip, port));
  let mut hints: Vec<SocketAddr> = Vec::new();
  for addr in ssh_hint.chain(interfaces) {
    if hints.len() == MAX_ADDR_HINTS {
      break;
    }
    if addr.is_ipv4() == local.is_ipv4() && !hints.contains(&addr) {
      hints.push(addr);
    }
  }
  hints
}

/// This host's interface addresses worth hinting: everything
/// `getifaddrs` reports on an up interface, minus what can never name
/// this host to a peer (`is_hint_ip`).
///
/// Enumeration goes straight to libc's `getifaddrs`, matching the
/// project's dependency posture: what a crate would add here is a
/// wrapper around two pointer walks. Failure is not an error -- the
/// `$SSH_CONNECTION` hint and the client's own resolution carry the
/// session -- so a host that refuses the call contributes no extra
/// hints.
#[cfg(unix)]
pub fn interface_ips() -> Vec<IpAddr> {
  let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
  if unsafe { libc::getifaddrs(&mut head) } != 0 {
    debug!(
      error = %io::Error::last_os_error(),
      "interface enumeration failed; hinting $SSH_CONNECTION only"
    );
    return Vec::new();
  }
  let mut ips = Vec::new();
  let mut cursor = head;
  while !cursor.is_null() {
    let entry = unsafe { &*cursor };
    cursor = entry.ifa_next;
    if entry.ifa_flags & libc::IFF_UP as u32 == 0 {
      continue;
    }
    if let Some(ip) = sockaddr_ip(entry.ifa_addr)
      && is_hint_ip(ip)
      && !ips.contains(&ip)
    {
      ips.push(ip);
    }
  }
  unsafe { libc::freeifaddrs(head) };
  ips
}

/// Interface enumeration is a `getifaddrs` call; platforms without one
/// hint `$SSH_CONNECTION` alone.
#[cfg(not(unix))]
pub fn interface_ips() -> Vec<IpAddr> {
  Vec::new()
}

/// The address in a `getifaddrs` entry, for the two families a session
/// can run over.
///
/// The pointer is one the C library filled in and sized for the family
/// its `sa_family` names, which is what makes reading the concrete
/// address structure sound.
#[cfg(unix)]
fn sockaddr_ip(addr: *const libc::sockaddr) -> Option<IpAddr> {
  if addr.is_null() {
    return None;
  }
  match i32::from(unsafe { (*addr).sa_family }) {
    libc::AF_INET => {
      let v4: libc::sockaddr_in =
        unsafe { std::ptr::read_unaligned(addr.cast()) };
      Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr))))
    }
    libc::AF_INET6 => {
      let v6: libc::sockaddr_in6 =
        unsafe { std::ptr::read_unaligned(addr.cast()) };
      Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.s6_addr)))
    }
    _ => None,
  }
}

/// Whether an interface address can name this host to a peer.
///
/// Kept: global unicast of both families, and the addresses that are
/// private but routable between peers who share a network -- the v4
/// private ranges and their v6 counterpart, unique-local. That case is
/// the ordinary one behind a jump: the destination's LAN address is
/// exactly what a client on the same LAN can reach. Dropped: loopback
/// (names the peer's own host, not this one), link-local (meaningless
/// without the scope the wire format cannot carry), multicast, and the
/// unspecified address.
///
/// That is establishment's martian filter with loopback refused, so it
/// calls that filter rather than copying it: an address this host hints
/// is one a peer will dial, and the two sides must not be able to
/// disagree.
fn is_hint_ip(ip: IpAddr) -> bool {
  is_dialable_ip(ip, false)
}

/// The accept phase of [`ServerSession::run`], standalone: accepts the
/// pinned connection and its session stream within `timeout` (the
/// design's give-up window), then disables further handshakes.
///
/// For the detached production server (see the module docs): it arrives
/// here with [`bind_socket`]'s socket wrapped in an endpoint carrying
/// the pinned config from [`crate::pinning::server_config`].
pub async fn accept_session(
  endpoint: &quinn::Endpoint,
  timeout: Duration,
) -> Result<(quinn::Connection, quinn::SendStream, quinn::RecvStream), RunError>
{
  let accepted = tokio::time::timeout(timeout, accept_pinned(endpoint)).await;
  // One session, one connection: never accept a second (nor, past the
  // deadline, a first). Established state is unaffected.
  endpoint.set_server_config(None);
  match accepted {
    Ok(result) => result,
    Err(_) => Err(RunError::BootstrapTimeout { timeout }),
  }
}

/// Accepts connections until one both completes the pinned handshake
/// and delivers the session's bidirectional stream.
///
/// The pinning verifier refuses everyone but the bootstrapped client,
/// so a completed handshake is that client; quinn closes failed
/// handshakes on its own and they never surface here. A connection can
/// still die between handshake and stream: the client dials all
/// candidates concurrently and aborts the losers, and the accepted
/// connection may have been one of those. Moving on to the next
/// connection keeps that race harmless.
///
/// QUIC opens streams lazily, so the stream surfaces here once the
/// client's first bytes on it arrive; with ssh driving the client side
/// that is immediate (the client's protocol banner).
async fn accept_pinned(
  endpoint: &quinn::Endpoint,
) -> Result<(quinn::Connection, quinn::SendStream, quinn::RecvStream), RunError>
{
  loop {
    let Some(incoming) = endpoint.accept().await else {
      return Err(RunError::EndpointClosed);
    };
    let Ok(connection) = incoming.await else {
      continue;
    };
    let Ok((send, recv)) = connection.accept_bi().await else {
      debug!("authenticated connection lost before its stream");
      continue;
    };
    return Ok((connection, send, recv));
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ssh_connection_hint_extracts_server_address() {
    assert_eq!(
      ssh_connection_hint("192.0.2.1 51000 198.51.100.7 22", 60123),
      Some("198.51.100.7:60123".parse().unwrap())
    );
    assert_eq!(
      ssh_connection_hint("2001:db8::c 51000 2001:db8::5 22", 60123),
      Some("[2001:db8::5]:60123".parse().unwrap())
    );
  }

  #[test]
  fn ssh_connection_hint_tolerates_malformed_input() {
    for value in [
      "",
      "192.0.2.1 51000",
      "192.0.2.1 51000 not-an-ip 22",
      // Scoped link-local addresses do not parse as bare IpAddrs.
      "fe80::1%eth0 51000 fe80::2%eth0 22",
    ] {
      assert_eq!(ssh_connection_hint(value, 60123), None, "value: {value}");
    }
  }

  fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
  }

  fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
  }

  /// The `$SSH_CONNECTION` address leads, and each family's socket
  /// announces its own family alone: nothing answers at an address of
  /// the other one, so each hint the client raced there would be a
  /// wasted slot of its establishment budget.
  #[test]
  fn addr_hints_lead_with_the_ssh_connection_address() {
    let interfaces = [ip("10.0.0.5"), ip("2001:db8::5")];
    assert_eq!(
      addr_hints(
        Some("192.0.2.1 51000 198.51.100.7 22"),
        &interfaces,
        addr("0.0.0.0:60123"),
      ),
      vec![addr("198.51.100.7:60123"), addr("10.0.0.5:60123")]
    );
    assert_eq!(
      addr_hints(
        Some("2001:db8::1 51000 2001:db8::7 22"),
        &interfaces,
        addr("[::]:60123"),
      ),
      vec![addr("[2001:db8::7]:60123"), addr("[2001:db8::5]:60123")]
    );
  }

  #[test]
  fn addr_hints_dedupe_and_survive_a_missing_ssh_connection() {
    // The interface address the client reached over ssh repeats as an
    // interface address; it keeps its leading slot and appears once.
    let hints = addr_hints(
      Some("192.0.2.1 51000 198.51.100.7 22"),
      &[ip("198.51.100.7"), ip("10.0.0.5"), ip("10.0.0.5")],
      addr("0.0.0.0:60123"),
    );
    assert_eq!(
      hints,
      vec![addr("198.51.100.7:60123"), addr("10.0.0.5:60123")]
    );

    // A malformed or absent $SSH_CONNECTION leaves the interface
    // addresses to carry the session.
    assert_eq!(
      addr_hints(None, &[ip("10.0.0.5")], addr("0.0.0.0:60123")),
      vec![addr("10.0.0.5:60123")]
    );
    assert_eq!(
      addr_hints(Some("garbage"), &[ip("10.0.0.5")], addr("0.0.0.0:60123")),
      vec![addr("10.0.0.5:60123")]
    );
    assert!(addr_hints(None, &[], addr("0.0.0.0:60123")).is_empty());
  }

  #[test]
  fn addr_hints_are_capped() {
    let ips: Vec<IpAddr> =
      (0..32).map(|i| ip(&format!("10.0.0.{}", i + 1))).collect();
    let hints = addr_hints(
      Some("192.0.2.1 51000 198.51.100.7 22"),
      &ips,
      addr("0.0.0.0:60123"),
    );
    assert_eq!(hints.len(), MAX_ADDR_HINTS);
    // The cap trims the tail, never the demonstrably reachable address.
    assert_eq!(hints[0], addr("198.51.100.7:60123"));
    assert_eq!(hints[1], addr("10.0.0.1:60123"));
  }

  /// The family filter runs before the cap, so a dual-stack host still
  /// announces a full quota of hints its socket can answer on. Filtering
  /// afterwards would spend slots on addresses that are then dropped.
  #[test]
  fn addr_hints_spend_the_cap_on_the_family_the_socket_answers_on() {
    let mut ips: Vec<IpAddr> = Vec::new();
    for i in 0..MAX_ADDR_HINTS * 2 {
      ips.push(ip(&format!("2001:db8::{}", i + 1)));
      ips.push(ip(&format!("10.0.0.{}", i + 1)));
    }
    let hints = addr_hints(None, &ips, addr("0.0.0.0:60123"));
    assert_eq!(hints.len(), MAX_ADDR_HINTS);
    assert!(hints.iter().all(SocketAddr::is_ipv4), "{hints:?}");
    assert_eq!(hints[0], addr("10.0.0.1:60123"));
  }

  #[test]
  fn hint_addresses_exclude_what_cannot_name_this_host() {
    for keep in [
      "198.51.100.7",
      "10.1.2.3",
      "172.16.9.9",
      "192.168.1.4",
      "2001:db8::1",
      "fd00::1",
    ] {
      assert!(is_hint_ip(ip(keep)), "dropped usable address {keep}");
    }
    for drop in [
      "127.0.0.1",
      "0.0.0.0",
      "169.254.3.4",
      "224.0.0.1",
      "255.255.255.255",
      "::1",
      "::",
      "fe80::1",
      "febf::1",
      "ff02::1",
    ] {
      assert!(!is_hint_ip(ip(drop)), "kept unusable address {drop}");
    }
  }

  /// The real enumeration, whatever this machine looks like: every
  /// address it reports must be hintable and distinct. A namespace with
  /// only loopback yields nothing, which is also correct.
  #[test]
  #[cfg(unix)]
  fn interface_enumeration_reports_only_usable_addresses() {
    let ips = interface_ips();
    for &ip in &ips {
      assert!(is_hint_ip(ip), "enumerated unusable address {ip}");
      assert_eq!(
        ips.iter().filter(|&&other| other == ip).count(),
        1,
        "duplicate address {ip} in {ips:?}"
      );
    }
  }
}
