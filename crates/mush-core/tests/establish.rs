// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The session-establishment engines end to end over loopback UDP, with
//! the bootstrap channel as an in-process duplex.

mod common;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use common::{DEADLINE, addr, ip, read_line, server_options};
use mush_core::bootstrap::{
  Connect, ConnectScanner, Hello, PROTOCOL_VERSION, ScanError, ScanLimits,
  SessionNonce, SessionSecret,
};
use mush_core::client::{
  self, ClientOptions, ClientSession, DIAL_STAGGER, EstablishError, Traversal,
};
use mush_core::path::ClientPlan;
use mush_core::pinning::{self, KeyPin, SessionIdentity};
use mush_core::server::{
  self, DEFAULT_PORT_RANGE, RunError, ServerOptions, ServerSession,
};
use mush_core::transport::TransportOptions;
use mush_core::traversal::TraversalEndpoint;
use mush_core::upgrade::UpgradePolicy;
use quinn::ConnectionError;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::time::timeout;

fn client_options() -> ClientOptions {
  ClientOptions {
    endpoint: client::EndpointSource::Bind(addr("127.0.0.1:0")),
    ..ClientOptions::default()
  }
}

/// Binds the same UDP port on two loopback addresses: the real server on
/// one, a black hole on the other, which is how the candidate-racing
/// scenarios give a hint an address that answers nothing.
///
/// The retry is what this function is for. Ephemeral ports are per bind
/// address, so a port free on `real` says nothing about `decoy`: a
/// concurrent test holding it there fails the second bind with
/// `EADDRINUSE`, worth about one failure per twenty workspace runs at
/// this suite's parallel peak of around 145 UDP sockets. The cap only
/// stops a stuck machine spinning.
fn bind_with_decoy(
  real: &str,
  decoy: &str,
) -> anyhow::Result<(std::net::UdpSocket, std::net::UdpSocket, u16)> {
  for _ in 0..64 {
    let socket = std::net::UdpSocket::bind((real, 0))?;
    let port = socket.local_addr()?.port();
    if let Ok(decoy) = std::net::UdpSocket::bind((decoy, port)) {
      return Ok((socket, decoy, port));
    }
  }
  anyhow::bail!("no port free on both {real} and {decoy}")
}

/// Reads the `MUSH CONNECT` line from a raw channel, for tests driving
/// the client side by hand.
async fn read_connect<R: AsyncRead + Unpin>(
  reader: &mut R,
) -> anyhow::Result<Connect> {
  let mut scanner = ConnectScanner::new(ScanLimits::default());
  let mut buf = [0u8; 4096];
  loop {
    let n = reader.read(&mut buf).await?;
    anyhow::ensure!(n > 0, "channel closed before MUSH CONNECT");
    if let Some((connect, _)) = scanner.push(&buf[..n])? {
      return Ok(connect);
    }
  }
}

#[tokio::test]
async fn happy_path_establishes_and_relays_both_ways() -> anyhow::Result<()> {
  let (client_io, server_io) = tokio::io::duplex(64 * 1024);
  let server_task =
    tokio::spawn(ServerSession::run(server_io, server_options()));
  let mut client = timeout(
    DEADLINE,
    ClientSession::establish(
      client_io,
      ClientOptions {
        target_port: 2222,
        ..client_options()
      },
    ),
  )
  .await??;

  // The server surfaces the stream (and returns) once the client's
  // first stream bytes arrive; QUIC opens streams lazily.
  client.send.write_all(b"client->server").await?;
  client.send.finish()?;
  let mut server = timeout(DEADLINE, server_task).await???;

  assert_eq!(server.hello.target_port, 2222);
  assert!(DEFAULT_PORT_RANGE.contains(&server.udp_port));
  assert_eq!(
    client.chosen_addr,
    addr(&format!("127.0.0.1:{}", server.udp_port))
  );
  assert_eq!(server.client_addr, client.endpoint.local_addr()?);
  assert_eq!(client.connect.addr_hints, vec![client.chosen_addr]);

  let got = timeout(DEADLINE, server.recv.read_to_end(1024)).await??;
  assert_eq!(got, b"client->server");
  server.send.write_all(b"server->client").await?;
  server.send.finish()?;
  let got = timeout(DEADLINE, client.recv.read_to_end(1024)).await??;
  assert_eq!(got, b"server->client");
  Ok(())
}

/// How many times [`provoke_icmp`] tries. One report is enough to kill an
/// unprotected endpoint, but whether a given dial draws one back is not
/// this test's to control, and an attempt that draws none proves nothing.
/// Four make a run where no report arrives an implausible way to go
/// green.
const ICMP_ATTEMPTS: usize = 4;

/// Draws ICMP port-unreachable reports at `endpoint`'s own socket, then
/// makes the endpoint read whatever they left there.
///
/// Only that socket can draw them: Linux keys the error it latches on the
/// four-tuple quoted back in the ICMP message. Whether one is latched at
/// all is what the endpoint's construction decides, and is what this asks.
///
/// A latched report waits for the next receive: the kernel reports it as
/// `EPOLLERR`, which tokio does not count as read readiness, so an idle
/// endpoint sits on one. The stray datagram makes the socket readable,
/// standing in for the peer's next packet on a live session.
async fn provoke_icmp(endpoint: &quinn::Endpoint) -> anyhow::Result<()> {
  let config = pinning::client_config(
    &SessionIdentity::generate()?,
    KeyPin::from_bytes([0; 32]),
    &TransportOptions::default(),
  )?;
  for _ in 0..ICMP_ATTEMPTS {
    let closed =
      std::net::UdpSocket::bind(addr("127.0.0.1:0"))?.local_addr()?;
    // Nothing is listening there, so the dial can only fail; its one
    // job is to put a datagram on the wire from this endpoint's socket.
    // Awaiting it keeps quinn from abandoning the attempt before it
    // transmits, and gives the report time to come back.
    let dial = endpoint.connect_with(config.clone(), closed, "mush")?;
    let _ = timeout(Duration::from_millis(40), dial).await;
    let stray = std::net::UdpSocket::bind(addr("127.0.0.1:0"))?;
    stray.send_to(b"stray", endpoint.local_addr()?)?;
    tokio::time::sleep(Duration::from_millis(30)).await;
  }
  Ok(())
}

/// An ICMP report about somewhere else must not take the session with it,
/// on the endpoints an ordinary `mush host` runs on.
///
/// quinn's endpoint driver ends the endpoint -- and every connection on
/// it -- over any receive error it does not recognize, and `IP_RECVERR`
/// turns an unauthenticated, trivially forgeable ICMP message into one of
/// those: a one-packet kill for anyone who can guess the four-tuple
/// (design doc, "Threat model"). Both sides here are built the way a
/// session without `--jump` builds them, the case the traversal suite's
/// shim tests do not reach.
#[tokio::test]
async fn an_icmp_report_does_not_kill_an_unjumped_session() -> anyhow::Result<()>
{
  let (client_io, server_io) = tokio::io::duplex(64 * 1024);
  let server_task =
    tokio::spawn(ServerSession::run(server_io, server_options()));
  let mut client = timeout(
    DEADLINE,
    ClientSession::establish(client_io, client_options()),
  )
  .await??;

  // The opening exchange is also what hands this test the server side.
  client.send.write_all(b"round-0").await?;
  let mut server = timeout(DEADLINE, server_task).await???;
  let mut got = [0u8; 7];
  timeout(DEADLINE, server.recv.read_exact(&mut got)).await??;
  assert_eq!(&got, b"round-0");

  for (round, endpoint) in
    [(1u8, &client.endpoint), (2, &server.endpoint)].into_iter()
  {
    provoke_icmp(endpoint).await?;
    assert!(
      client.connection.close_reason().is_none(),
      "round {round}: the ICMP report killed the client's session: {:?}",
      client.connection.close_reason()
    );
    let sent = [b'r', b'o', b'u', b'n', b'd', b'-', b'0' + round];
    client.send.write_all(&sent).await?;
    timeout(DEADLINE, server.recv.read_exact(&mut got)).await??;
    assert_eq!(got, sent);
    server.send.write_all(&sent).await?;
    timeout(DEADLINE, client.recv.read_exact(&mut got)).await??;
    assert_eq!(got, sent);
  }
  Ok(())
}

#[tokio::test]
async fn login_output_before_connect_is_tolerated() -> anyhow::Result<()> {
  let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
  // What a hostile login environment emits before the server engine
  // gets to speak: motd, binary junk, NULs, and prefix lookalikes.
  server_io
    .write_all(b"Welcome to example.org!\r\n\xff\xfe binary \x00 junk\nMUSH CONNECTING is a lookalike\n")
    .await?;
  let server_task =
    tokio::spawn(ServerSession::run(server_io, server_options()));
  let mut client = timeout(
    DEADLINE,
    ClientSession::establish(client_io, client_options()),
  )
  .await??;
  client.send.write_all(b"x").await?;
  client.send.finish()?;
  let server = timeout(DEADLINE, server_task).await???;
  assert_eq!(server.client_addr, client.endpoint.local_addr()?);
  Ok(())
}

/// The scan budget the client passes reaches the scanner, and the
/// scanner's refusal reaches the caller with its line count intact.
#[tokio::test]
async fn scan_limit_exceeded_is_a_typed_error() -> anyhow::Result<()> {
  const LIMIT: usize = 16;
  let (client_io, mut login_io) = tokio::io::duplex(64 * 1024);
  // One line past the budget, written up front: the whole scenario fits
  // the duplex, so nothing has to keep feeding it.
  for i in 0..=LIMIT {
    login_io
      .write_all(format!("login line {i}\n").as_bytes())
      .await?;
  }
  let err = timeout(
    DEADLINE,
    ClientSession::establish(
      client_io,
      ClientOptions {
        scan_limits: ScanLimits {
          max_lines: LIMIT,
          max_bytes: 64 * 1024,
        },
        ..client_options()
      },
    ),
  )
  .await?
  .unwrap_err();
  assert!(
    matches!(
      err,
      EstablishError::Scan(ScanError::LimitExceeded { lines: LIMIT, .. })
    ),
    "unexpected error: {err:?}"
  );
  Ok(())
}

/// The design's "wrong client key" outcome, end to end: an attacker who
/// saw the hello announces its pin but cannot present the key. The
/// server refuses the handshake and keeps waiting; the dial fails at
/// the TLS level; the server gives up only at its bootstrap timeout.
#[tokio::test]
async fn unpinned_client_is_refused_and_server_times_out() -> anyhow::Result<()>
{
  let (mut attacker_io, server_io) = tokio::io::duplex(64 * 1024);
  let server_task = tokio::spawn(ServerSession::run(
    server_io,
    ServerOptions {
      bootstrap_timeout: Duration::from_secs(3),
      ..server_options()
    },
  ));

  let announced = SessionIdentity::generate()?;
  let actual = SessionIdentity::generate()?;
  let hello = Hello {
    version: PROTOCOL_VERSION,
    client_key: announced.pin(),
    target_port: 22,
    nonce: None,
  };
  attacker_io.write_all(hello.to_wire().as_bytes()).await?;
  let connect = timeout(DEADLINE, read_connect(&mut attacker_io)).await??;

  let config = pinning::client_config(
    &actual,
    connect.server_key,
    &TransportOptions::default(),
  )?;
  let endpoint = quinn::Endpoint::client(addr("127.0.0.1:0"))?;
  let dial = endpoint.connect_with(config, connect.addr_hints[0], "mush")?;
  match timeout(DEADLINE, dial).await? {
    // TLS 1.3 clients can complete their side before the server evaluates
    // the client certificate; the refusal arrives as a TLS-level close.
    Ok(connection) => {
      let reason = timeout(DEADLINE, connection.closed()).await?;
      assert!(
        matches!(
          reason,
          ConnectionError::ConnectionClosed(_)
            | ConnectionError::TransportError(_)
        ),
        "expected a TLS-level close, got: {reason:?}"
      );
    }
    Err(err) => assert!(
      matches!(
        err,
        ConnectionError::ConnectionClosed(_)
          | ConnectionError::TransportError(_)
      ),
      "expected a TLS-level failure, got: {err:?}"
    ),
  }

  let result = timeout(DEADLINE, server_task).await??;
  assert!(
    matches!(result, Err(RunError::BootstrapTimeout { .. })),
    "server should time out, got: {result:?}"
  );
  Ok(())
}

/// Runs one candidate race on the loopback pair `bind_with_decoy` builds: the
/// server listens on `real` while `decoy` holds the same port open and
/// answers nothing. `decoy` is also where the "ssh session" arrived, so it
/// heads the hints via `$SSH_CONNECTION`; `interface_ips` supplies any
/// hint behind it. Hands back both ends and the port they share.
async fn race(
  real: &str,
  decoy: &str,
  interface_ips: Vec<IpAddr>,
  resolved_ips: Vec<IpAddr>,
) -> anyhow::Result<(
  ClientSession<tokio::io::DuplexStream>,
  ServerSession<tokio::io::DuplexStream>,
  u16,
)> {
  let (server_socket, _decoy, port) = bind_with_decoy(real, decoy)?;
  let server_endpoint = quinn::Endpoint::new(
    quinn::EndpointConfig::default(),
    None,
    server_socket,
    Arc::new(quinn::TokioRuntime),
  )?;

  let (client_io, server_io) = tokio::io::duplex(64 * 1024);
  let server_task = tokio::spawn(ServerSession::run(
    server_io,
    ServerOptions {
      endpoint: server::EndpointSource::Endpoint(server_endpoint),
      ssh_connection: Some(format!("198.51.100.7 40000 {decoy} 22")),
      interface_ips,
      ..ServerOptions::default()
    },
  ));

  let mut client = timeout(
    DEADLINE,
    ClientSession::establish(
      client_io,
      ClientOptions {
        resolved_ips,
        ..client_options()
      },
    ),
  )
  .await??;
  // The server surfaces the session on the client's first stream bytes.
  client.send.write_all(b"x").await?;
  client.send.finish()?;
  let server = timeout(DEADLINE, server_task).await???;
  assert_eq!(server.client_addr, client.endpoint.local_addr()?);
  Ok((client, server, port))
}

/// Candidate racing with stagger: the first hint is a black hole, the
/// second is the client's own resolution where the real server is, and
/// establishment succeeds on it after the stagger.
#[tokio::test]
async fn stagger_racing_wins_on_second_candidate() -> anyhow::Result<()> {
  let started = std::time::Instant::now();
  let (client, _server, port) =
    race("127.0.0.1", "127.0.0.2", Vec::new(), vec![ip("127.0.0.1")]).await?;
  assert_eq!(client.chosen_addr, addr(&format!("127.0.0.1:{port}")));
  assert!(
    started.elapsed() >= DIAL_STAGGER,
    "the winning dial cannot have started before the stagger"
  );
  Ok(())
}

/// The server's gathered candidates, raced (the design's Phase A): the
/// `$SSH_CONNECTION` address leads and is a black hole, and the interface
/// address behind it is where the server actually listens. The client
/// resolves nothing itself, so it can only win on the gathered hint --
/// the case a destination whose ssh runs through a jump depends on.
#[tokio::test]
async fn interface_hints_win_when_the_reached_address_is_silent()
-> anyhow::Result<()> {
  let (client, _server, port) =
    race("127.0.0.2", "127.0.0.1", vec![ip("127.0.0.2")], Vec::new()).await?;
  assert_eq!(
    client.connect.addr_hints,
    vec![
      addr(&format!("127.0.0.1:{port}")),
      addr(&format!("127.0.0.2:{port}"))
    ]
  );
  assert_eq!(client.chosen_addr, addr(&format!("127.0.0.2:{port}")));
  Ok(())
}

/// All candidates black holes: the establishment deadline elapses and
/// the typed unreachable error (the TCP-fallback trigger) comes back
/// with per-candidate detail.
#[tokio::test]
async fn establishment_deadline_yields_quic_unreachable() -> anyhow::Result<()>
{
  let decoy = std::net::UdpSocket::bind("127.0.0.1:0")?;
  let hint = decoy.local_addr()?;
  let (client_io, mut fake_io) = tokio::io::duplex(64 * 1024);
  // Speak the server's half by hand, pointing at the black hole. The
  // returned handle keeps the channel open past the client's failure.
  let responder = tokio::spawn(async move {
    let connect = Connect {
      version: PROTOCOL_VERSION,
      udp_port: hint.port(),
      server_key: KeyPin::from_bytes([7; 32]),
      addr_hints: vec![hint],
    };
    fake_io
      .write_all(connect.to_wire().as_bytes())
      .await
      .unwrap();
    fake_io
  });

  let started = std::time::Instant::now();
  let err = timeout(
    DEADLINE,
    ClientSession::establish(
      client_io,
      ClientOptions {
        establish_timeout: Duration::from_millis(400),
        ..client_options()
      },
    ),
  )
  .await?
  .unwrap_err();
  match &err {
    EstablishError::QuicUnreachable { failures, .. } => {
      assert_eq!(failures.len(), 1, "failures: {failures:?}");
      assert_eq!(failures[0].addr, hint);
    }
    other => panic!("expected QuicUnreachable, got: {other:?}"),
  }
  assert!(started.elapsed() >= Duration::from_millis(400));
  drop(timeout(DEADLINE, responder).await??);
  Ok(())
}

/// A live endpoint that presents a key other than the pinned one: the
/// client must fail loudly with the pin-rejection error, not report
/// unreachability, and must not wait out the establishment deadline.
#[tokio::test]
async fn pin_rejection_is_loud_and_distinct_from_unreachable()
-> anyhow::Result<()> {
  let (client_io, mut fake_io) = tokio::io::duplex(64 * 1024);
  let responder = tokio::spawn(async move {
    // Learn the client's pin from its hello, then run a real pinned QUIC
    // server whose key differs from the connect line's.
    let hello = Hello::parse(&read_line(&mut fake_io).await.unwrap()).unwrap();
    let server_identity = SessionIdentity::generate().unwrap();
    let config = pinning::server_config(
      &server_identity,
      hello.client_key,
      &TransportOptions::default(),
    )
    .unwrap();
    let endpoint =
      quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let local = endpoint.local_addr().unwrap();
    let connect = Connect {
      version: PROTOCOL_VERSION,
      udp_port: local.port(),
      server_key: KeyPin::from_bytes([0x5a; 32]),
      addr_hints: vec![local],
    };
    fake_io
      .write_all(connect.to_wire().as_bytes())
      .await
      .unwrap();
    // Drive the one handshake so the client's verifier sees the
    // mismatched key; the client aborts it at the TLS level.
    if let Some(incoming) = endpoint.accept().await {
      let _ = incoming.await;
    }
    fake_io
  });

  let err = timeout(
    DEADLINE,
    ClientSession::establish(
      client_io,
      ClientOptions {
        establish_timeout: Duration::from_secs(30),
        ..client_options()
      },
    ),
  )
  .await?
  .unwrap_err();
  assert!(
    matches!(err, EstablishError::PinRejected { .. }),
    "expected PinRejected, got: {err:?}"
  );
  drop(timeout(DEADLINE, responder).await??);
  Ok(())
}

#[tokio::test]
async fn connect_version_mismatch_is_rejected() -> anyhow::Result<()> {
  let (client_io, mut fake_io) = tokio::io::duplex(64 * 1024);
  let connect = Connect {
    version: PROTOCOL_VERSION + 1,
    udp_port: 60123,
    server_key: KeyPin::from_bytes([1; 32]),
    addr_hints: vec![addr("127.0.0.1:60123")],
  };
  fake_io.write_all(connect.to_wire().as_bytes()).await?;
  let err = timeout(
    DEADLINE,
    ClientSession::establish(client_io, client_options()),
  )
  .await?
  .unwrap_err();
  assert!(
    matches!(err, EstablishError::ProtocolVersion { version } if version == PROTOCOL_VERSION + 1),
    "unexpected error: {err:?}"
  );
  Ok(())
}

/// The design's path establishment rests on one constraint: "Both
/// peers probe from the same UDP socket their QUIC endpoint uses". The
/// two halves reach the engine as separate fields, so the pairing is
/// checked at entry rather than trusted: probing from a mapping the
/// session will never be reached at fails much later, as an
/// unexplained relay or fallback, with nothing pointing back here.
#[tokio::test]
async fn a_traversal_socket_must_be_the_endpoints_own() -> anyhow::Result<()> {
  let (client_io, mut fake_io) = tokio::io::duplex(64 * 1024);
  let connect = Connect {
    version: PROTOCOL_VERSION,
    udp_port: 60123,
    server_key: KeyPin::from_bytes([1; 32]),
    addr_hints: vec![addr("127.0.0.1:60123")],
  };
  fake_io.write_all(connect.to_wire().as_bytes()).await?;

  // Two endpoints, each with the socket it runs on: the session is
  // given one endpoint and the *other* endpoint's socket.
  let session = TraversalEndpoint::bind(addr("127.0.0.1:0"))?;
  let stranger = TraversalEndpoint::bind(addr("127.0.0.1:0"))?;
  let err = timeout(
    DEADLINE,
    ClientSession::establish(
      client_io,
      ClientOptions {
        endpoint: client::EndpointSource::Endpoint(session.endpoint),
        session_nonce: Some(SessionNonce::from_bytes([7; 16])),
        traversal: Some(Traversal {
          socket: stranger.socket.clone(),
          secret: SessionSecret::from_bytes([8; 16]),
          probes: stranger.probes,
          arrivals: None,
          plan: ClientPlan::default(),
          upgrade: UpgradePolicy::default(),
        }),
        ..client_options()
      },
    ),
  )
  .await?
  .unwrap_err();
  assert!(
    matches!(err, EstablishError::TraversalSocketMismatch { .. }),
    "unexpected error: {err:?}"
  );
  Ok(())
}

/// The server engine's verdict on one hello line, from a server that
/// binds nothing (the line never gets far enough for a socket to matter).
async fn hello_verdict(line: &[u8]) -> anyhow::Result<RunError> {
  let (mut fake_io, server_io) = tokio::io::duplex(64 * 1024);
  fake_io.write_all(line).await?;
  Ok(
    timeout(
      DEADLINE,
      ServerSession::run(
        server_io,
        ServerOptions {
          endpoint: server::EndpointSource::Bind {
            ip: ip("127.0.0.1"),
            ports: 0..=0,
          },
          ..ServerOptions::default()
        },
      ),
    )
    .await?
    .unwrap_err(),
  )
}

/// A hello the server cannot act on ends the run with the typed error
/// naming why, and never with a bound socket waiting for a peer.
#[tokio::test]
async fn an_unusable_hello_is_rejected() -> anyhow::Result<()> {
  let newer = Hello {
    version: PROTOCOL_VERSION + 1,
    client_key: KeyPin::from_bytes([2; 32]),
    target_port: 22,
    nonce: None,
  };
  let err = hello_verdict(newer.to_wire().as_bytes()).await?;
  assert!(
    matches!(err, RunError::ProtocolVersion { version } if version == PROTOCOL_VERSION + 1),
    "unexpected error: {err:?}"
  );

  let err = hello_verdict(b"not a hello at all\n").await?;
  assert!(
    matches!(err, RunError::Hello(_)),
    "unexpected error: {err:?}"
  );
  Ok(())
}
