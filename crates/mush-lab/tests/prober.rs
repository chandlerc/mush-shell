// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Loopback-tier prober validation: real UDP sockets, real time, no
//! namespaces. The netsim tier proves the prober's recovery bound
//! deterministically; this tier proves the other half of its contract
//! on a real kernel path: a healthy long-idle session, kept alive only
//! by keep-alives, is never disturbed -- no probes, no rebinds, no
//! address churn the server could observe.
//!
//! Runs under the lab profile like the rest of this crate (the idle
//! window alone is a minute; see .config/nextest.toml's long-window
//! override, which the `roam_` name selects).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use mush_core::client::{self, ClientOptions, ClientSession};
use mush_core::roaming::{
  ProbeOptions, ProbeStats, Prober, os_route_check, os_socket_factory,
};
use mush_core::server::{self, ServerOptions, ServerSession};
use tokio::time::timeout;

/// Bound on any single establishment await.
const ESTABLISH: Duration = Duration::from_secs(30);

/// The idle window: three-plus keep-alive cycles at the default 20s
/// interval, matching the design discussion's long-idle shape.
const IDLE: Duration = Duration::from_secs(62);

#[tokio::test(flavor = "current_thread")]
async fn roam_prober_leaves_healthy_idle_session_alone() -> anyhow::Result<()> {
  let (client_io, server_io) = tokio::io::duplex(64 * 1024);
  let server_task = tokio::spawn(ServerSession::run(
    server_io,
    ServerOptions {
      endpoint: server::EndpointSource::Bind {
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        ports: server::DEFAULT_PORT_RANGE,
      },
      ..ServerOptions::default()
    },
  ));
  let mut client = timeout(
    ESTABLISH,
    ClientSession::establish(
      client_io,
      ClientOptions {
        endpoint: client::EndpointSource::Bind(
          (IpAddr::V4(Ipv4Addr::LOCALHOST), 0).into(),
        ),
        resolved_ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        ..ClientOptions::default()
      },
    ),
  )
  .await
  .context("establishment timed out")??;
  // The server surfaces its stream on the client's first stream bytes.
  client.send.write_all(b"hi").await?;
  let mut server = timeout(ESTABLISH, server_task)
    .await
    .context("server establishment timed out")???;
  let mut greeting = [0u8; 2];
  server.recv.read_exact(&mut greeting).await?;

  let stats = Arc::new(ProbeStats::default());
  let prober = tokio::spawn(
    Prober {
      connection: client.connection.clone(),
      endpoint: client.endpoint.clone(),
      fresh_socket: os_socket_factory(&client.connection),
      route_check: os_route_check(&client.connection),
      // No netlink here: a genuine address change on the host mid-test
      // would be indistinguishable from a spurious rebind.
      events: None,
      session_socket: None,
      options: ProbeOptions::default(),
      stats: stats.clone(),
    }
    .run(),
  );

  let before = server.connection.remote_address();
  tokio::time::sleep(IDLE).await;

  assert_eq!(
    stats.probes(),
    0,
    "prober disturbed a healthy idle session: {stats:?}"
  );
  assert_eq!(
    server.connection.remote_address(),
    before,
    "client address changed across a healthy idle window"
  );
  assert!(
    client.connection.close_reason().is_none(),
    "session died while idle: {:?}",
    client.connection.close_reason()
  );

  // The session still moves bytes after the idle window.
  client.send.write_all(b"still here").await?;
  let mut echo = [0u8; 10];
  timeout(ESTABLISH, server.recv.read_exact(&mut echo))
    .await
    .context("post-idle read timed out")??;
  assert_eq!(&echo, b"still here");

  prober.abort();
  client.connection.close(0u32.into(), b"test over");
  Ok(())
}
