// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! QUIC transport policy: every deliberate deviation from quinn's
//! defaults, in one place.
//!
//! The design doc's "Connection configuration" owns why each setting was
//! chosen, and its "Timers and budgets" indexes the values. Here are the
//! code, the figures behind the constants, and one rule:
//!
//! Build quinn configs only through [`crate::pinning::client_config`] and
//! [`crate::pinning::server_config`], which apply this policy. Assembling
//! one from the crypto pieces directly keeps quinn's default 30-second
//! idle timeout, which costs the outage survival the project exists for.

use std::sync::Arc;
use std::time::Duration;

use quinn::{EndpointConfig, IdleTimeout, TransportConfig, VarInt};

/// Default client keep-alive interval.
pub const DEFAULT_KEEP_ALIVE: Duration = Duration::from_secs(20);

/// Default time an unanswered transmission may go without any inbound
/// datagram before the client starts active probing (see
/// [`crate::roaming`]). Well above any sane path RTT, so ordinary
/// latency never trips it, and small enough that probing is underway
/// long before an outage ends.
pub const DEFAULT_STALL_THRESHOLD: Duration = Duration::from_secs(3);

/// Default interval between the client's active probes while stalled,
/// and the bound probing puts on post-outage recovery. Fresh-socket
/// rebinds happen on every other probe, so sockets and NAT mappings
/// churn at half this rate during an outage.
pub const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_secs(2);

/// Default flow-control window size, per stream and per connection.
///
/// Sized for throughput, and doubling as the buffer bound: during an
/// outage the window fills, the relay stops reading, and ssh blocks on
/// write exactly as it would on a stalled TCP socket.
///
/// The bound is in bytes, but a receiver also holds one buffer per
/// unread STREAM frame, and this window is over ten thousand full-MTU
/// frames deep. Released quinn-proto abandons a connection past 2048 of
/// those even on contiguous data, which Mush answers by running on a
/// revision whose assembler coalesces them (root `Cargo.toml`) rather
/// than by sizing the window down. Sizing down is not the cheaper option
/// it looks like: the upper bound that makes the bug unreachable is 143KB,
/// which measures 3 MiB/s against this window's 33 on a 40ms path.
pub const DEFAULT_WINDOW: u32 = 16 * 1024 * 1024;

/// The endpoint policy every Mush endpoint is built with.
///
/// Endpoint configuration is per socket rather than per connection, and
/// Mush needs exactly one thing from it: no QUIC bit greasing, so that
/// the fixed bit keeps separating session traffic from the traversal
/// probes sharing the socket ([`crate::stun::is_stun`]). Declining is
/// what stops the *peer* greasing, since RFC 9287 lets an endpoint clear
/// the bit only toward one that offered to accept it.
pub fn endpoint_config() -> EndpointConfig {
  let mut config = EndpointConfig::default();
  config.grease_quic_bit(false);
  config
}

/// The two transport settings a caller may set. `Default` is the shipped
/// policy; construct with struct update syntax to override one.
///
/// Everything else the policy settles is a constant applied in
/// `base_transport`, because nothing has asked to vary it (the design
/// doc's "Open questions").
#[derive(Debug, Clone)]
pub struct TransportOptions {
  /// Client-side keep-alive interval; `None` disables keep-alives
  /// entirely (the battery-vs-liveness tradeoff mirrors Mosh's
  /// heartbeats). Ignored for the server side. Clamped to half of
  /// `max_idle_timeout` when that timeout is set: quinn requires the
  /// interval to sit below both peers' idle timeouts, and halving leaves
  /// a missed probe of slack.
  pub keep_alive_interval: Option<Duration>,
  /// Connection idle timeout: how long a silent peer is retained before
  /// the connection is abandoned. `None` -- the default and the design
  /// policy -- means no timeout: sessions survive arbitrarily long
  /// outages, at the cost of holding a dead peer forever (the two are
  /// indistinguishable). QUIC negotiates the minimum of the two sides'
  /// values, so either side's limit bounds the whole connection.
  pub max_idle_timeout: Option<Duration>,
}

impl Default for TransportOptions {
  fn default() -> Self {
    Self {
      keep_alive_interval: Some(DEFAULT_KEEP_ALIVE),
      max_idle_timeout: None,
    }
  }
}

impl TransportOptions {
  /// The client-side transport config: the shared policy plus
  /// keep-alives.
  pub fn client_transport(&self) -> Arc<TransportConfig> {
    let mut config = self.base_transport();
    let keep_alive = match (self.keep_alive_interval, self.max_idle_timeout) {
      (Some(interval), Some(idle)) => Some(interval.min(idle / 2)),
      (interval, None) => interval,
      (None, _) => None,
    };
    config
      .keep_alive_interval(keep_alive)
      // The session's one stream is client-opened; this setting caps only
      // peer-initiated streams, so the client accepts none from the
      // server (and its own `open_bi` is unaffected).
      .max_concurrent_bidi_streams(VarInt::from_u32(0));
    Arc::new(config)
  }

  /// The server-side transport config: the shared policy, no
  /// keep-alives (the client's suffice to preserve the connection).
  pub fn server_transport(&self) -> Arc<TransportConfig> {
    let mut config = self.base_transport();
    // Accept exactly the one client-opened bidirectional stream
    // ("Connection configuration" in the design doc).
    config.max_concurrent_bidi_streams(VarInt::from_u32(1));
    Arc::new(config)
  }

  fn base_transport(&self) -> TransportConfig {
    let mut config = TransportConfig::default();
    config
      .max_idle_timeout(self.max_idle_timeout.map(idle_timeout))
      .stream_receive_window(VarInt::from_u32(DEFAULT_WINDOW))
      .receive_window(VarInt::from_u32(DEFAULT_WINDOW))
      .send_window(u64::from(DEFAULT_WINDOW))
      // The protocol uses no unidirectional streams in either direction.
      .max_concurrent_uni_streams(VarInt::from_u32(0))
      // Nor any QUIC datagrams. Declined rather than merely unused: at
      // quinn's default every connection would carry a 1,250,000-byte
      // peer-fillable buffer for a frame type nothing here reads, and
      // off, a DATAGRAM frame is a protocol violation instead.
      .datagram_receive_buffer_size(None);
    config
  }
}

/// How long a process exiting will spend flushing its connection close.
const CLOSE_GRACE: Duration = Duration::from_secs(3);

/// Closes `connection` and gives the CONNECTION_CLOSE frame a bounded
/// chance to reach the peer.
///
/// Every Mush process ends a session this way. Best-effort by
/// construction: quinn sends the frame from the endpoint driver, so
/// something has to keep the runtime alive long enough for it to leave,
/// and on the clean path the peer acknowledges at once. Bounded because
/// a vanished peer must not hold the process open -- the close is a
/// courtesy that saves the peer an idle timeout, not a step the exit
/// depends on.
pub async fn close_and_flush(
  endpoint: &quinn::Endpoint,
  connection: &quinn::Connection,
  code: VarInt,
  reason: &[u8],
) {
  connection.close(code, reason);
  let _ = tokio::time::timeout(CLOSE_GRACE, endpoint.wait_idle()).await;
}

/// Converts a wall-clock duration to quinn's transport-parameter form.
/// Durations beyond the varint millisecond range (millennia) saturate.
fn idle_timeout(duration: Duration) -> IdleTimeout {
  IdleTimeout::try_from(duration)
    .unwrap_or_else(|_| IdleTimeout::from(VarInt::MAX))
}
