// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Relay engine throughput over a real loopback QUIC pair.
//!
//! The measured pipeline is exactly what Mush ships between the local
//! byte stream and the peer: the relay engine on both sides of one QUIC
//! bidirectional stream over UDP loopback, with the design-doc transport
//! policy applied. Connection establishment (endpoint creation, key
//! generation, the pinned handshake) happens once per benchmark and is
//! outside the measurement; each iteration opens a fresh stream on the
//! established connection and splices a fixed number of bytes through
//! it, so QUIC framing, crypto, and kernel UDP costs are all inside the
//! measurement.
//!
//! "Message size" is the write granularity of the local endpoint
//! feeding the relay, modeling how ssh hands over its transport bytes:
//! 16KB matches the relay's own copy buffer, 1MB models bulk transfer
//! writes.

use std::time::Duration;

use criterion::{
  BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
};
use mush_core::pinning::{self, SessionIdentity};
use mush_core::relay::{RelayOutcome, relay};
use mush_core::transport::{self, TransportOptions};
use mush_core::traversal::{SharedSocket, TraversalEndpoint};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};

/// Bytes spliced per iteration in each active direction.
const BYTES_PER_DIRECTION: usize = 32 * 1024 * 1024;

/// Local-endpoint write granularities benchmarked.
const MESSAGE_SIZES: [usize; 2] = [16 * 1024, 1024 * 1024];

/// In-memory duplex buffer standing in for the local pipe/socket;
/// large enough not to be the bottleneck.
const DUPLEX_BUF: usize = 256 * 1024;

/// Which shim the pair's datagrams pass through on their way to the
/// kernel.
///
/// Not a tuning option: which one a session gets is decided by how it was
/// started. `Shared` is every session without `--jump`, on both sides;
/// `Traversal` is the destination's session and a jumped client's,
/// where the path map and the probe sort operate on the same datagrams.
/// `Plain` is quinn with no shim at all, which Mush no longer runs
/// anywhere -- it is the reference the other two are read against, so
/// that what the shim costs is a measured number rather than a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shim {
  Plain,
  Shared,
  Traversal,
}

impl Shim {
  fn name(self) -> &'static str {
    match self {
      Self::Plain => "plain",
      Self::Shared => "shared",
      Self::Traversal => "traversal",
    }
  }
}

/// The connected loopback pair the iterations run over. Endpoints are
/// kept alive because dropping them tears the connections down, and so
/// are the traversal shims' probe streams: a shim whose receiver is gone
/// is not the one a session runs on.
struct Pair {
  client: quinn::Connection,
  server: quinn::Connection,
  _client_endpoint: quinn::Endpoint,
  _server_endpoint: quinn::Endpoint,
  _shims: Vec<TraversalEndpoint>,
}

/// One endpoint of `flavor`, bound on loopback.
///
/// All three take Mush's endpoint configuration, so the flavors differ
/// in the socket underneath and in nothing else.
fn endpoint(
  flavor: Shim,
  server_config: Option<quinn::ServerConfig>,
  shims: &mut Vec<TraversalEndpoint>,
) -> quinn::Endpoint {
  let bind = || std::net::UdpSocket::bind("127.0.0.1:0").expect("bind socket");
  match flavor {
    Shim::Plain => quinn::Endpoint::new(
      transport::endpoint_config(),
      server_config,
      bind(),
      std::sync::Arc::new(quinn::TokioRuntime),
    )
    .expect("plain endpoint"),
    Shim::Shared => SharedSocket::endpoint(
      bind(),
      transport::endpoint_config(),
      server_config,
    )
    .expect("shared endpoint"),
    Shim::Traversal => {
      let paths = TraversalEndpoint::over_std(
        bind(),
        transport::endpoint_config(),
        server_config,
      )
      .expect("traversal endpoint");
      let endpoint = paths.endpoint.clone();
      shims.push(paths);
      endpoint
    }
  }
}

async fn connected_pair(flavor: Shim) -> Pair {
  let options = TransportOptions::default();
  let client_identity = SessionIdentity::generate().unwrap();
  let server_identity = SessionIdentity::generate().unwrap();
  let server_config =
    pinning::server_config(&server_identity, client_identity.pin(), &options)
      .unwrap();
  let client_config =
    pinning::client_config(&client_identity, server_identity.pin(), &options)
      .unwrap();
  let mut shims = Vec::new();
  let server_endpoint = endpoint(flavor, Some(server_config), &mut shims);
  let client_endpoint = endpoint(flavor, None, &mut shims);
  client_endpoint.set_default_client_config(client_config);
  let server_addr = server_endpoint.local_addr().unwrap();

  let accept = tokio::spawn({
    let server_endpoint = server_endpoint.clone();
    async move {
      server_endpoint
        .accept()
        .await
        .expect("endpoint closed early")
        .await
    }
  });
  let client = client_endpoint
    .connect(server_addr, "mush")
    .unwrap()
    .await
    .unwrap();
  let server = accept.await.unwrap().unwrap();
  Pair {
    client,
    server,
    _client_endpoint: client_endpoint,
    _server_endpoint: server_endpoint,
    _shims: shims,
  }
}

/// Spawns the client- and server-side relay engines on a fresh stream,
/// returning the local endpoints backing them.
fn start_relays(
  pair: &Pair,
) -> (
  DuplexStream,
  DuplexStream,
  tokio::task::JoinHandle<RelayOutcome>,
  tokio::task::JoinHandle<RelayOutcome>,
) {
  let (a, a_relay) = tokio::io::duplex(DUPLEX_BUF);
  let (b, b_relay) = tokio::io::duplex(DUPLEX_BUF);
  let client_connection = pair.client.clone();
  let client = tokio::spawn(async move {
    let (send, recv) = client_connection.open_bi().await.unwrap();
    relay(a_relay, send, recv).await
  });
  let server_connection = pair.server.clone();
  let server = tokio::spawn(async move {
    let (send, recv) = server_connection.accept_bi().await.unwrap();
    relay(b_relay, send, recv).await
  });
  (a, b, client, server)
}

/// Writes `total` bytes in `message`-sized chunks, then half-closes.
async fn feed<W: tokio::io::AsyncWrite + Unpin>(
  mut writer: W,
  message: &[u8],
  total: usize,
) {
  let mut sent = 0;
  while sent < total {
    let n = message.len().min(total - sent);
    writer.write_all(&message[..n]).await.unwrap();
    sent += n;
  }
  writer.shutdown().await.unwrap();
}

/// Reads to EOF, asserting `expected` bytes arrived.
async fn drain<R: tokio::io::AsyncRead + Unpin>(
  mut reader: R,
  expected: usize,
) {
  let mut buf = vec![0u8; 64 * 1024];
  let mut got = 0;
  loop {
    match reader.read(&mut buf).await.unwrap() {
      0 => break,
      n => got += n,
    }
  }
  assert_eq!(got, expected);
}

/// One iteration, client-to-server only: the reverse direction closes
/// immediately and the whole payload flows one way.
async fn pump_one_way(pair: &Pair, message: &[u8], total: usize) {
  let (a, b, client, server) = start_relays(pair);
  let (a_read, a_write) = tokio::io::split(a);
  let (b_read, mut b_write) = tokio::io::split(b);
  tokio::join!(feed(a_write, message, total), drain(b_read, total), async {
    b_write.shutdown().await.unwrap();
  });
  drain(a_read, 0).await;
  assert!(client.await.unwrap().is_clean());
  assert!(server.await.unwrap().is_clean());
}

/// One iteration, full duplex: `total` bytes in each direction
/// concurrently.
async fn pump_full_duplex(pair: &Pair, message: &[u8], total: usize) {
  let (a, b, client, server) = start_relays(pair);
  let (a_read, a_write) = tokio::io::split(a);
  let (b_read, b_write) = tokio::io::split(b);
  tokio::join!(
    feed(a_write, message, total),
    drain(b_read, total),
    feed(b_write, message, total),
    drain(a_read, total),
  );
  assert!(client.await.unwrap().is_clean());
  assert!(server.await.unwrap().is_clean());
}

/// The current-thread runtime is what Mush ships (the workload is one
/// stream); the benchmarks use the same.
fn runtime() -> tokio::runtime::Runtime {
  tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap()
}

fn bench_relay(c: &mut Criterion) {
  let runtime = runtime();
  let pair = runtime.block_on(connected_pair(Shim::Plain));

  let mut group = c.benchmark_group("relay");
  group
    .sample_size(10)
    .warm_up_time(Duration::from_secs(2))
    .measurement_time(Duration::from_secs(15));

  for size in MESSAGE_SIZES {
    let message = vec![0x5au8; size];
    group.throughput(Throughput::Bytes(BYTES_PER_DIRECTION as u64));
    group.bench_with_input(
      BenchmarkId::new("one_way", format!("{}KB", size / 1024)),
      &message,
      |b, message| {
        b.iter(|| {
          runtime.block_on(pump_one_way(&pair, message, BYTES_PER_DIRECTION))
        });
      },
    );
    // Reported throughput is the aggregate of both directions.
    group.throughput(Throughput::Bytes(2 * BYTES_PER_DIRECTION as u64));
    group.bench_with_input(
      BenchmarkId::new("full_duplex", format!("{}KB", size / 1024)),
      &message,
      |b, message| {
        b.iter(|| {
          runtime.block_on(pump_full_duplex(
            &pair,
            message,
            BYTES_PER_DIRECTION,
          ))
        });
      },
    );
  }
  group.finish();
}

/// What the socket shim costs the relay, measured rather than argued.
///
/// Every server session and every jumped client session receives through
/// one, so the `relay` group above -- which runs on quinn's own socket
/// -- measures a path Mush no longer takes anywhere. This is the same
/// workload over all three flavors back to back, in one group so that
/// what the shims cost is read off a comparison rather than off two runs
/// on a laptop that was not doing the same thing both times.
///
/// One shape rather than the cross product: the shim's cost is per
/// datagram, so full duplex at the relay's own 16KB copy granularity is
/// where the packet rate is highest and a regression would show first.
fn bench_shim(c: &mut Criterion) {
  let runtime = runtime();
  let message = vec![0x5au8; 16 * 1024];

  let mut group = c.benchmark_group("shim");
  group
    .sample_size(10)
    .warm_up_time(Duration::from_secs(2))
    .measurement_time(Duration::from_secs(15))
    .throughput(Throughput::Bytes(2 * BYTES_PER_DIRECTION as u64));

  for flavor in [Shim::Plain, Shim::Shared, Shim::Traversal] {
    let pair = runtime.block_on(connected_pair(flavor));
    group.bench_with_input(
      BenchmarkId::new("full_duplex_16KB", flavor.name()),
      &message,
      |b, message| {
        b.iter(|| {
          runtime.block_on(pump_full_duplex(
            &pair,
            message,
            BYTES_PER_DIRECTION,
          ))
        });
      },
    );
  }
  group.finish();
}

criterion_group!(benches, bench_relay, bench_shim);
criterion_main!(benches);
