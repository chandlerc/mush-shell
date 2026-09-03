// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Loopback quinn endpoint helpers shared by the integration tests.

// Each test binary uses the part it needs; the rest is unreachable from
// that binary, not dead.
#![allow(dead_code)]

pub mod netsim;
pub mod traversal;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use mush_core::pinning::{self, KeyPin, SessionIdentity};
use mush_core::server::{self, DEFAULT_PORT_RANGE, ServerOptions};
use mush_core::transport::TransportOptions;
use tokio::io::{AsyncRead, AsyncReadExt as _};

/// Generous bound on any single await in these tests: orders of magnitude
/// above loopback expectations, so timing variation cannot flake them.
pub const DEADLINE: Duration = Duration::from_secs(60);

pub fn addr(s: &str) -> SocketAddr {
  s.parse().unwrap()
}

pub fn ip(s: &str) -> IpAddr {
  s.parse().unwrap()
}

pub fn loopback() -> SocketAddr {
  "127.0.0.1:0".parse().unwrap()
}

/// The server engine's options for a loopback session. Its
/// `$SSH_CONNECTION` is where the fixture assumes the two sides sit: a
/// remapped public address for the client, and for the server its
/// loopback address, the one the client reaches it at.
pub fn server_options() -> ServerOptions {
  ServerOptions {
    endpoint: server::EndpointSource::Bind {
      ip: ip("127.0.0.1"),
      ports: DEFAULT_PORT_RANGE,
    },
    ssh_connection: Some("203.0.113.9 52611 127.0.0.1 22".into()),
    ..ServerOptions::default()
  }
}

/// A pattern with no repeating period at QUIC's chunk sizes, so a lost or
/// reordered range fails comparison rather than matching by luck.
pub fn payload(len: usize) -> Vec<u8> {
  (0..len).map(|at| (at % 251) as u8).collect()
}

/// Reads one newline-terminated line, for tests driving a side of the
/// bootstrap channel by hand.
pub async fn read_line<R: AsyncRead + Unpin>(
  reader: &mut R,
) -> anyhow::Result<String> {
  let mut line = Vec::new();
  let mut byte = [0u8; 1];
  loop {
    let n = reader.read(&mut byte).await?;
    anyhow::ensure!(n > 0, "channel closed mid-line");
    if byte[0] == b'\n' {
      return Ok(String::from_utf8(line)?);
    }
    line.push(byte[0]);
  }
}

pub fn server_endpoint(
  identity: &SessionIdentity,
  pinned_client: KeyPin,
) -> anyhow::Result<quinn::Endpoint> {
  let config = pinning::server_config(
    identity,
    pinned_client,
    &TransportOptions::default(),
  )?;
  Ok(quinn::Endpoint::server(config, loopback())?)
}

pub fn client_endpoint(
  identity: &SessionIdentity,
  pinned_server: KeyPin,
) -> anyhow::Result<quinn::Endpoint> {
  let config = pinning::client_config(
    identity,
    pinned_server,
    &TransportOptions::default(),
  )?;
  let endpoint = quinn::Endpoint::client(loopback())?;
  endpoint.set_default_client_config(config);
  Ok(endpoint)
}

/// A connected loopback pair with correct pins on both sides. The
/// endpoints are held too, because dropping them tears the connections
/// down.
pub struct Pair {
  pub client: quinn::Connection,
  pub server: quinn::Connection,
  pub _client_endpoint: quinn::Endpoint,
  pub _server_endpoint: quinn::Endpoint,
}

pub async fn connected_pair() -> anyhow::Result<Pair> {
  let client_identity = SessionIdentity::generate()?;
  let server_identity = SessionIdentity::generate()?;
  let server_endpoint =
    server_endpoint(&server_identity, client_identity.pin())?;
  let client_endpoint =
    client_endpoint(&client_identity, server_identity.pin())?;
  let server_addr = server_endpoint.local_addr()?;

  let accept = tokio::spawn({
    let server_endpoint = server_endpoint.clone();
    async move {
      let incoming = server_endpoint
        .accept()
        .await
        .expect("endpoint closed early");
      incoming.await
    }
  });
  let client = tokio::time::timeout(
    DEADLINE,
    client_endpoint.connect(server_addr, "mush")?,
  )
  .await??;
  let server = tokio::time::timeout(DEADLINE, accept).await???;
  Ok(Pair {
    client,
    server,
    _client_endpoint: client_endpoint,
    _server_endpoint: server_endpoint,
  })
}
