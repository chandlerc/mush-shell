// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The signaling phase end to end over loopback UDP, with the bootstrap
//! channel as an in-process duplex.

mod common;

use std::time::Duration;

use common::{DEADLINE, addr, read_line, server_options};
use mush_core::bootstrap::{
  CandidateKind, Connect, Hello, PROTOCOL_VERSION, SessionNonce, SessionSecret,
  Signal,
};
use mush_core::channel::SignalChannel;
use mush_core::client::{self, ClientOptions, ClientSession};
use mush_core::pinning::{self, SessionIdentity};
use mush_core::server::ServerSession;
use mush_core::transport::TransportOptions;
use tokio::io::AsyncWriteExt as _;
use tokio::time::timeout;

fn nonce() -> SessionNonce {
  SessionNonce::from_bytes([0x27; 16])
}

fn client_options(nonce: SessionNonce) -> ClientOptions {
  ClientOptions {
    endpoint: client::EndpointSource::Bind(addr("127.0.0.1:0")),
    session_nonce: Some(nonce),
    ..ClientOptions::default()
  }
}

/// What the destination offers once it has a reflector to ask.
fn server_signals() -> Vec<Signal> {
  vec![
    Signal::candidate(
      nonce(),
      CandidateKind::Reflexive,
      addr("198.51.100.9:41000"),
    ),
    Signal::candidate(
      nonce(),
      CandidateKind::Relayed,
      addr("198.51.100.7:9999"),
    ),
    Signal::done(nonce()),
  ]
}

/// What the client sends the destination; the client carries all
/// signaling between the destination and the helper.
fn client_signals() -> Vec<Signal> {
  vec![
    Signal::helper(
      nonce(),
      addr("198.51.100.7:9999"),
      SessionSecret::from_bytes([0x77; 16]),
    ),
    Signal::candidate(
      nonce(),
      CandidateKind::Direct,
      addr("[2001:db8::5]:41001"),
    ),
    Signal::punch(
      nonce(),
      1,
      vec![addr("198.51.100.9:41000"), addr("192.0.2.5:41002")],
    ),
    Signal::done(nonce()),
  ]
}

/// The whole phase over a real establishment: both engines run, and the
/// channel each hands back carries the signaling set and then ends
/// cleanly when its peer lets go.
#[tokio::test]
async fn a_full_establishment_signals_in_both_directions() -> anyhow::Result<()>
{
  let (client_io, server_io) = tokio::io::duplex(64 * 1024);
  let server_task =
    tokio::spawn(ServerSession::run(server_io, server_options()));
  let mut client = timeout(
    DEADLINE,
    ClientSession::establish(client_io, client_options(nonce())),
  )
  .await??;
  // The server engine surfaces the session once the client's first
  // stream bytes arrive; QUIC opens streams lazily.
  client.send.write_all(b"x").await?;
  let server = timeout(DEADLINE, server_task).await???;

  // The hello carried the nonce, which is the destination's cue that
  // the channel stays open.
  assert_eq!(server.hello.nonce, Some(nonce()));

  let mut client_channel =
    SignalChannel::new(client.bootstrap, client.bootstrap_leftover);
  let mut server_channel =
    SignalChannel::new(server.bootstrap, server.bootstrap_leftover);

  for signal in server_signals() {
    server_channel.send(&signal).await?;
  }
  for expected in server_signals() {
    let got = timeout(DEADLINE, client_channel.recv()).await??;
    assert_eq!(got, Some(expected));
  }
  for signal in client_signals() {
    client_channel.send(&signal).await?;
  }
  for expected in client_signals() {
    let got = timeout(DEADLINE, server_channel.recv()).await??;
    assert_eq!(got, Some(expected));
  }

  // Every message named this session; none cost the non-protocol
  // budget.
  assert_eq!(client_channel.ignored_lines(), 0);
  assert_eq!(server_channel.ignored_lines(), 0);

  // The paths are settled: the client lets the channel go, and the
  // destination sees a clean end rather than an error.
  drop(client_channel);
  assert_eq!(timeout(DEADLINE, server_channel.recv()).await??, None);
  Ok(())
}

/// The point where the connect scan hands over. A destination that has
/// already detached writes its connect line and its first signaling
/// lines in one go, so they arrive in the same read: the scan must
/// leave them in the leftover bytes for the signaling channel to pick
/// up.
#[tokio::test]
async fn signaling_coalesced_with_the_connect_line_is_not_lost()
-> anyhow::Result<()> {
  let (client_io, mut fake_io) = tokio::io::duplex(64 * 1024);
  let responder = tokio::spawn(async move {
    let hello = Hello::parse(&read_line(&mut fake_io).await.unwrap()).unwrap();
    assert_eq!(hello.nonce, Some(nonce()));
    let identity = SessionIdentity::generate().unwrap();
    let config = pinning::server_config(
      &identity,
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
      server_key: identity.pin(),
      addr_hints: vec![local],
    };
    // One write: login output, the connect line, and the destination's
    // whole signaling set behind it.
    let mut blob = Vec::from(&b"a late shell-rc line\n"[..]);
    blob.extend_from_slice(connect.to_wire().as_bytes());
    for signal in server_signals() {
      blob.extend_from_slice(signal.to_wire().as_bytes());
    }
    fake_io.write_all(&blob).await.unwrap();
    let accept = async {
      while let Some(incoming) = endpoint.accept().await {
        if let Ok(connection) = incoming.await {
          let _ = connection.accept_bi().await;
          std::future::pending::<()>().await;
        }
      }
    };
    tokio::select! {
      () = accept => {}
      () = std::future::pending() => {}
    }
  });

  let client = timeout(
    DEADLINE,
    ClientSession::establish(client_io, client_options(nonce())),
  )
  .await??;
  assert!(
    !client.bootstrap_leftover.is_empty(),
    "the signaling lines should have arrived with the connect line"
  );
  let mut channel =
    SignalChannel::new(client.bootstrap, client.bootstrap_leftover);
  for expected in server_signals() {
    assert_eq!(timeout(DEADLINE, channel.recv()).await??, Some(expected));
  }
  responder.abort();
  Ok(())
}

/// A client with nothing to signal announces no nonce, and its hello is
/// the line it was before signaling existed: the no-jump flow, where
/// the destination has no reason to hold the channel open.
#[tokio::test]
async fn a_client_that_will_not_signal_announces_no_nonce() -> anyhow::Result<()>
{
  let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
  let client = tokio::spawn(ClientSession::establish(
    client_io,
    ClientOptions {
      endpoint: client::EndpointSource::Bind(addr("127.0.0.1:0")),
      establish_timeout: Duration::from_millis(100),
      ..ClientOptions::default()
    },
  ));
  let line = timeout(DEADLINE, read_line(&mut server_io)).await??;
  assert!(!line.contains("nonce="), "hello carried a nonce: {line}");
  assert_eq!(Hello::parse(&line)?.nonce, None);
  client.abort();
  Ok(())
}
