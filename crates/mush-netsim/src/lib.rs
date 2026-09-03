// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! In-process, deterministic network simulation for transport tests.
//!
//! This crate hosts *real* quinn endpoints over a simulated datagram
//! network: a [`SimNet`] owns simulated sockets, per-link impairments
//! (latency, jitter, loss, duplication, MTU), blackhole toggles, and NAT
//! boxes, all driven by one seeded RNG and the tokio virtual clock. It
//! makes transport and traversal behavior -- roaming, NAT rebinding, long
//! outages, path/MTU changes -- fast, seeded, and exactly reproducible in
//! ordinary `cargo test` runs, which network-namespace tests (real
//! kernel, real time) cannot be.
//!
//! Pure Rust with no OS network resources, so it runs anywhere, and test
//! infrastructure only: no shipped Mush crate depends on it.
//!
//! # Architecture
//!
//! - [`SimNet`]: the simulated network. Registry of bound sockets, link
//!   table ([`LinkConfig`]), NAT boxes, an event trace, and a delivery
//!   queue drained by a single pump task on the virtual clock. Sender-side
//!   and link-level decisions -- outbound NAT translation, blackholes,
//!   MTU, loss, duplication, latency and jitter -- are made at send time;
//!   receiver-side NAT translation and filtering are evaluated when the
//!   datagram arrives, against the NAT state of that instant, as on a
//!   real path. Surviving copies deliver in (due time, send sequence)
//!   order.
//! - [`SimSocket`]: implements quinn's `AsyncUdpSocket` (and a plain
//!   `send_to`/`recv_from` API for STUN and punch traffic and for tests
//!   of the simulated network). Plug into quinn via
//!   `Endpoint::new_with_abstract_socket` or `Endpoint::rebind_abstract`.
//! - [`NatGrade`]/[`NatHandle`]: NAT boxes between an inside realm and the
//!   public address space, with per-grade mapping and filtering behavior,
//!   idle timeouts on the virtual clock, and test hooks (`flush_mappings`,
//!   `set_mapping_ttl`). Hairpinning is not modeled: traffic from inside
//!   a NAT to its own public address is dropped. NATs do not chain; one
//!   realm boundary per path end.
//! - [`seeded_endpoint_config`]: the `EndpointConfig` half of a
//!   reproducible quinn endpoint, with every entropy source it controls
//!   pinned from a seed. The crypto half is the caller's: Mush's suites
//!   pair it with the session engines' own pinned raw-public-key
//!   configuration, so what they exercise is the production handshake.
//!   [`derive_u64`] splits one scenario seed across the endpoints a
//!   scenario builds.
//! - [`TraceEvent`]: the structured event log; [`SimNet::trace_summary`]
//!   is the canonical cross-run comparison view.
//!
//! # Determinism rules
//!
//! A simulation replays exactly -- same seed, same scenario, same
//! [`SimNet::trace_summary`] output: identical event kinds, addresses,
//! and virtual timestamps, with datagram *sizes* the one exception (see
//! below) -- only under all of the following, which the crate's own
//! tests follow:
//!
//! - **Runtime**: tokio `current_thread` with `start_paused(true)` --
//!   `#[tokio::test(start_paused = true)]`. Never a multi-thread runtime,
//!   OS threads, real sockets, or any kernel-mediated I/O: the paused
//!   clock auto-advances whenever all tasks idle, so readiness the runtime
//!   cannot see (a datagram in a kernel buffer) races the clock. All
//!   readiness in the simulated network is task-internal, making that
//!   race impossible.
//! - **Time**: only via tokio (`tokio::time::Instant`, `sleep`). quinn
//!   reads time exclusively through its `Runtime` trait, which the stock
//!   `TokioRuntime` maps to the tokio clock. Never `std::time::Instant` in
//!   simulation or test code.
//! - **Randomness**: one master seed per scenario. The network RNG makes
//!   every loss/duplication/jitter/NAT-port decision in send order; each
//!   endpoint derives its own sub-seed ([`derive_u64`]) for
//!   [`seeded_endpoint_config`], which pins `EndpointConfig::rng_seed`,
//!   the CID generator, and the stateless-reset key.
//! - **Scheduling**: deliveries are totally ordered by (virtual due time,
//!   send sequence); tasks are spawned in a fixed order; any `select!` in
//!   simulator or test code uses `biased`.
//! - **Comparing runs**: build a fresh runtime per run (each
//!   `#[tokio::test]` does) so clock and timer-wheel state start
//!   identically, and compare [`SimNet::trace_summary`] output.
//!
//! # What is deliberately NOT deterministic
//!
//! Two entropy sources stay unseeded, neither of which a replay can
//! observe through [`SimNet::trace_summary`]:
//!
//! - **TLS byte-level content.** rustls's ephemeral handshake keys and
//!   randoms come from the crypto provider's own entropy and cannot be
//!   seeded, so packet *contents* differ on every run. Handshake message
//!   *lengths* stay stable as long as the caller's certificate or key
//!   material is fixed, which keeps packet counts and the event trace
//!   reproducible. Do not assert on wire bytes, on-the-wire connection
//!   IDs, or exact handshake datagram sizes: [`SimNet::trace_summary`]
//!   omits sizes for exactly this reason (the full [`SimNet::trace`]
//!   retains them for debugging).
//! - **A client's initial destination connection ID.** quinn draws it from
//!   the unseeded process RNG, and [`seeded_endpoint_config`] cannot
//!   reach it: it lives on `ClientConfig`, which the caller's own crypto
//!   configuration owns. It is a fixed-length opaque value that the
//!   server echoes and both ends then replace, so it changes no datagram
//!   size, no address, and no timer -- nothing the trace summary records.
//!
//! # Example
//!
//! ```
//! use mush_netsim::{LinkConfig, SimNet};
//! use std::time::Duration;
//!
//! #[tokio::main(flavor = "current_thread", start_paused = true)]
//! async fn main() {
//!   let net = SimNet::new(42);
//!   net.set_default_link(LinkConfig {
//!     latency: Duration::from_millis(30),
//!     ..LinkConfig::default()
//!   });
//!   let client = net.bind("10.0.0.1:1000".parse().unwrap()).unwrap();
//!   let server = net.bind("10.0.0.2:4433".parse().unwrap()).unwrap();
//!   client.send_to(b"hello", server.addr()).unwrap();
//!   let mut buf = [0u8; 16];
//!   let (n, from) = server.recv_from(&mut buf).await.unwrap();
//!   assert_eq!(&buf[..n], b"hello");
//!   assert_eq!(from, client.addr());
//! }
//! ```

mod nat;
mod net;
mod quinn_kit;
mod socket;
mod trace;

pub use nat::NatGrade;
pub use net::{LinkConfig, NatHandle, SimNet};
pub use quinn_kit::{derive_u64, seeded_endpoint_config};
pub use socket::SimSocket;
pub use trace::{DropReason, EventKind, NatRejectReason, TraceEvent};
