// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Hostile probes against candidate gathering and racing (design doc,
//! "Jump hosts and NAT traversal", Phase A). The server side of the
//! bootstrap channel is spoken by hand throughout, so the connect line
//! carries exactly the hints each probe wants -- including hint sets no
//! genuine `mush server bootstrap` would emit.

mod common;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use common::{DEADLINE, addr, ip, read_line};
use mush_core::bootstrap::{Connect, Hello, PROTOCOL_VERSION};
use mush_core::client::{
  self, ClientOptions, ClientSession, DEFAULT_ESTABLISH_TIMEOUT, DIAL_STAGGER,
  EstablishError,
};
use mush_core::pinning::{self, KeyPin, SessionIdentity};
use mush_core::transport::TransportOptions;
use tokio::io::AsyncWriteExt as _;
use tokio::time::timeout;

fn client_options() -> ClientOptions {
  ClientOptions {
    endpoint: client::EndpointSource::Bind(addr("127.0.0.1:0")),
    establish_timeout: DEFAULT_ESTABLISH_TIMEOUT,
    ..ClientOptions::default()
  }
}

/// A bound UDP socket that answers nothing: a hint whose port is open
/// (so nothing is ICMP-refused) but which never completes a handshake.
fn silent_hint() -> anyhow::Result<(std::net::UdpSocket, SocketAddr)> {
  let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
  let addr = socket.local_addr()?;
  Ok((socket, addr))
}

/// A live pinned Mush server on loopback, accepting connections until
/// dropped. Returns its address and the pin of the key it presents.
fn live_server(
  pinned_client: KeyPin,
) -> anyhow::Result<(SocketAddr, KeyPin, tokio::task::JoinHandle<()>)> {
  let identity = SessionIdentity::generate()?;
  let pin = identity.pin();
  let config = pinning::server_config(
    &identity,
    pinned_client,
    &TransportOptions::default(),
  )?;
  let endpoint = quinn::Endpoint::server(config, addr("127.0.0.1:0"))?;
  let local = endpoint.local_addr()?;
  let task = tokio::spawn(async move {
    while let Some(incoming) = endpoint.accept().await {
      tokio::spawn(async move {
        if let Ok(connection) = incoming.await {
          let _ = connection.accept_bi().await;
          std::future::pending::<()>().await;
        }
      });
    }
  });
  Ok((local, pin, task))
}

/// The client's end of a hand-driven bootstrap.
struct Bootstrap {
  /// The bootstrap channel to hand to `ClientSession::establish`.
  channel: tokio::io::DuplexStream,
  /// The real pinned server's address, once the responder bound it.
  real: tokio::sync::oneshot::Receiver<SocketAddr>,
  _responder: tokio::task::JoinHandle<()>,
}

/// A real pinned server for this session, announced by a hand-written
/// connect line that puts `before(real)` ahead of its address.
fn bootstrap_with(
  before: impl FnOnce(SocketAddr) -> Vec<SocketAddr> + Send + 'static,
) -> Bootstrap {
  let (client_io, mut fake_io) = tokio::io::duplex(64 * 1024);
  let (real_tx, real_rx) = tokio::sync::oneshot::channel();
  let responder = tokio::spawn(async move {
    let line = read_line(&mut fake_io).await.unwrap();
    let hello = Hello::parse(&line).unwrap();
    let identity = SessionIdentity::generate().unwrap();
    let server_pin = identity.pin();
    let config = pinning::server_config(
      &identity,
      hello.client_key,
      &TransportOptions::default(),
    )
    .unwrap();
    let endpoint =
      quinn::Endpoint::server(config, addr("127.0.0.1:0")).unwrap();
    let real = endpoint.local_addr().unwrap();
    let _ = real_tx.send(real);
    let mut hints = before(real);
    hints.push(real);
    let connect = Connect {
      version: PROTOCOL_VERSION,
      udp_port: real.port(),
      server_key: server_pin,
      addr_hints: hints,
    };
    fake_io
      .write_all(connect.to_wire().as_bytes())
      .await
      .unwrap();
    while let Some(incoming) = endpoint.accept().await {
      tokio::spawn(async move {
        if let Ok(connection) = incoming.await {
          let _ = connection.accept_bi().await;
          std::future::pending::<()>().await;
        }
      });
    }
  });
  Bootstrap {
    channel: client_io,
    real: real_rx,
    _responder: responder,
  }
}

/// A server filling its whole hint quota (`server::MAX_ADDR_HINTS`)
/// with the good address last, inside the *default* establishment
/// budget: the design's stagger arithmetic puts the eighth candidate
/// at 7 x 250ms = 1.75s of a 5s budget.
#[tokio::test]
async fn a_full_hint_quota_of_garbage_still_establishes() -> anyhow::Result<()>
{
  let mut silent = Vec::new();
  let mut garbage = Vec::new();
  for _ in 0..7 {
    let (socket, addr) = silent_hint()?;
    silent.push(socket);
    garbage.push(addr);
  }
  let started = std::time::Instant::now();
  let bootstrap = bootstrap_with(move |_| garbage);
  let session = timeout(
    DEADLINE,
    ClientSession::establish(bootstrap.channel, client_options()),
  )
  .await?;
  let elapsed = started.elapsed();
  let real = bootstrap.real.await?;
  let session = match session {
    Ok(session) => session,
    Err(error) => {
      panic!("a full hint quota did not establish within {elapsed:?}: {error}")
    }
  };
  eprintln!(
    "eight hints (7 silent): established at {} in {elapsed:?}",
    session.chosen_addr
  );
  assert_eq!(session.chosen_addr, real);
  assert!(
    elapsed >= DIAL_STAGGER * 7,
    "the eighth candidate cannot have started before its stagger slot"
  );
  assert!(
    elapsed < DEFAULT_ESTABLISH_TIMEOUT,
    "a full quota used {elapsed:?} of a {DEFAULT_ESTABLISH_TIMEOUT:?} budget"
  );
  Ok(())
}

/// A hint flood cannot push the client's *own* resolution of the
/// destination out of the establishment budget. `MAX_ADDR_HINTS` is the
/// budget arithmetic, so the client truncates the connect line's hints
/// to it rather than dialing whatever fits in an 8KB line; the
/// self-resolved address still gets a slot, and the whole candidate set
/// stays inside the 5s window.
#[tokio::test]
async fn a_hint_flood_cannot_bury_the_resolved_address() -> anyhow::Result<()> {
  let mut silent = Vec::new();
  let mut garbage = Vec::new();
  for _ in 0..40 {
    let (socket, addr) = silent_hint()?;
    silent.push(socket);
    garbage.push(addr);
  }
  let started = std::time::Instant::now();
  let bootstrap = bootstrap_with(move |_| garbage);
  let session = timeout(
    DEADLINE,
    ClientSession::establish(
      bootstrap.channel,
      ClientOptions {
        resolved_ips: vec![ip("127.0.0.1")],
        ..client_options()
      },
    ),
  )
  .await?;
  let elapsed = started.elapsed();
  let real = bootstrap.real.await?;
  match session {
    Ok(session) => {
      eprintln!(
        "40 flooded hints, resolved address won at {} in {elapsed:?}",
        session.chosen_addr
      );
      assert_eq!(session.chosen_addr, real);
      assert!(
        elapsed < DEFAULT_ESTABLISH_TIMEOUT,
        "a hint flood used {elapsed:?} of a \
         {DEFAULT_ESTABLISH_TIMEOUT:?} budget"
      );
    }
    Err(error) => panic!("a hint flood buried the resolved address: {error}"),
  }
  Ok(())
}

/// Hints pointing at other live Mush servers: one whose own key differs
/// (this client's verifier refuses it) and one pinning a different
/// client (its verifier refuses this client).
#[tokio::test]
async fn foreign_mush_server_hints_lose_the_race() -> anyhow::Result<()> {
  // A live Mush server that pins somebody else's client key: it
  // completes enough of a handshake to refuse this client.
  let (wrong_client, _, decoy) = live_server(KeyPin::from_bytes([0xa5; 32]))?;
  let bootstrap = bootstrap_with(move |_| vec![wrong_client]);
  let session = timeout(
    DEADLINE,
    ClientSession::establish(bootstrap.channel, client_options()),
  )
  .await?;
  let real = bootstrap.real.await?;
  decoy.abort();
  match session {
    Ok(session) => {
      eprintln!("foreign-server hint: won at {}", session.chosen_addr);
      assert_eq!(session.chosen_addr, real, "raced onto the wrong server");
    }
    Err(error) => {
      panic!(
        "a foreign mush server ahead of the real one broke the race: {error}"
      )
    }
  }
  Ok(())
}

/// The same shape with the real address unreachable: one hint answers
/// QUIC without the pinned key, so the client reports a pin rejection
/// and refuses the TCP fallback. The answerer is whatever the hint
/// pointed at, not the destination, so a stale hint or a NAT
/// port-forward to an unrelated host can veto the fallback for a
/// destination whose UDP is genuinely blocked.
#[tokio::test]
async fn a_foreign_answerer_vetoes_the_tcp_fallback() -> anyhow::Result<()> {
  let (silent_socket, silent) = silent_hint()?;
  let (foreign, _, decoy) = live_server(KeyPin::from_bytes([0xa5; 32]))?;
  let (client_io, mut fake_io) = tokio::io::duplex(64 * 1024);
  let responder = tokio::spawn(async move {
    let _ = read_line(&mut fake_io).await;
    let connect = Connect {
      version: PROTOCOL_VERSION,
      udp_port: silent.port(),
      server_key: KeyPin::from_bytes([0x11; 32]),
      addr_hints: vec![silent, foreign],
    };
    let _ = fake_io.write_all(connect.to_wire().as_bytes()).await;
    fake_io
  });

  let error = timeout(
    DEADLINE,
    ClientSession::establish(
      client_io,
      ClientOptions {
        establish_timeout: Duration::from_secs(3),
        ..client_options()
      },
    ),
  )
  .await?
  .unwrap_err();
  eprintln!("foreign answerer, real address unreachable: {error}");
  assert!(
    matches!(error, EstablishError::PinRejected { .. }),
    "expected PinRejected (and so no TCP fallback), got: {error:?}"
  );
  decoy.abort();
  drop(timeout(DEADLINE, responder).await??);
  drop(silent_socket);
  Ok(())
}

/// A dual-stack destination filling its whole hint quota with IPv6
/// addresses, reached by a v4-only client (what `mush connect` binds
/// whenever the destination resolves to anything IPv4). Every v6 dial
/// fails synchronously (`quinn::ConnectError::InvalidRemoteAddress`,
/// decided under the endpoint lock before any I/O), and a candidate
/// undialable from this endpoint takes no stagger slot, so eight dead
/// hints ahead of the live one cost nothing against the 5s budget.
/// Guards the `dialable` short-circuit in `DialRace::dial`: without it
/// the stagger is indexed by list position and those eight hints hold
/// two seconds of budget open for dials that were never going to
/// happen.
///
/// The last hint is `::1`, not another documentation address: a v4
/// resolution allows loopback hints, so it clears the martian filter
/// and reaches the family check like the rest, which is what `mush
/// connect` produces for a dual-stack destination reached over IPv4.
#[tokio::test]
async fn undialable_hints_consume_no_stagger_slots() -> anyhow::Result<()> {
  let started = std::time::Instant::now();
  let bootstrap = bootstrap_with(|real| {
    (1u16..=7)
      .map(|n| {
        SocketAddr::new(
          IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n)),
          real.port(),
        )
      })
      .chain([SocketAddr::new(ip("::1"), real.port())])
      .collect()
  });
  let session = timeout(
    DEADLINE,
    ClientSession::establish(
      bootstrap.channel,
      ClientOptions {
        resolved_ips: vec![ip("127.0.0.1")],
        ..client_options()
      },
    ),
  )
  .await??;
  let elapsed = started.elapsed();
  eprintln!(
    "8 v6 hints ahead of v4 on a v4-only client: established at {} \
     in {elapsed:?} of a {DEFAULT_ESTABLISH_TIMEOUT:?} budget",
    session.chosen_addr
  );
  assert!(
    session.chosen_addr.is_ipv4(),
    "the winner was not the v4 candidate: {}",
    session.chosen_addr
  );
  assert!(
    elapsed < DIAL_STAGGER,
    "hints that fail synchronously cost {elapsed:?}; the stagger is \
     being indexed by list position rather than by dials in flight"
  );
  Ok(())
}

/// The mirror image: a client bound to IPv6 only (what `mush connect`
/// does for a destination that resolves to IPv6 alone) reaching a
/// server whose hints are all IPv4. The family mismatch must read as
/// unreachable -- a fallback trigger -- never as a pin rejection.
#[tokio::test]
async fn v4_hints_reaching_a_v6_only_client_fail_as_unreachable()
-> anyhow::Result<()> {
  let (silent, hint) = silent_hint()?;
  let (client_io, mut fake_io) = tokio::io::duplex(64 * 1024);
  let responder = tokio::spawn(async move {
    let _ = read_line(&mut fake_io).await;
    let connect = Connect {
      version: PROTOCOL_VERSION,
      udp_port: hint.port(),
      server_key: KeyPin::from_bytes([7; 32]),
      addr_hints: vec![hint],
    };
    let _ = fake_io.write_all(connect.to_wire().as_bytes()).await;
    fake_io
  });

  let error = timeout(
    DEADLINE,
    ClientSession::establish(
      client_io,
      ClientOptions {
        endpoint: client::EndpointSource::Bind(addr("[::1]:0")),
        establish_timeout: Duration::from_secs(2),
        ..ClientOptions::default()
      },
    ),
  )
  .await?
  .unwrap_err();
  eprintln!("v4 hints on a v6-only client: {error}");
  assert!(
    matches!(error, EstablishError::QuicUnreachable { .. }),
    "expected QuicUnreachable, got: {error:?}"
  );
  drop(timeout(DEADLINE, responder).await??);
  drop(silent);
  Ok(())
}
