// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Structured event log of simulated network activity.
//!
//! Every datagram that enters the simulated network leaves a [`TraceEvent`]
//! record for each decision made about it: sent, NAT-translated, dropped
//! (with a reason), duplicated, and delivered. Timestamps are virtual time
//! elapsed since [`SimNet`](crate::SimNet) creation, so traces from two runs
//! of the same seeded scenario are directly comparable.
//!
//! Two views exist:
//!
//! - [`SimNet::trace`](crate::SimNet::trace) returns the full events,
//!   including exact datagram sizes, for debugging.
//! - [`SimNet::trace_summary`](crate::SimNet::trace_summary) returns one
//!   formatted line per event with sizes omitted. Determinism assertions
//!   must compare this view: TLS handshake content comes from the TLS
//!   provider's own unseedable entropy, so handshake datagram sizes are
//!   not guaranteed stable across runs even with identical seeds.
//!   Everything else in an event -- kind, addresses, drop reason,
//!   virtual timestamp -- is deterministic.

use std::net::SocketAddr;
use std::time::Duration;

/// Why the simulated network dropped a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
  /// The source or destination host is blackholed.
  HostBlackhole,
  /// The directed link between the hosts is blackholed.
  LinkBlackhole,
  /// Random loss, per the link's loss probability.
  Loss,
  /// The datagram exceeds the link MTU. The drop is silent (no error to the
  /// sender), which is what forces DPLPMTUD to probe for the usable size.
  OversizedMtu,
  /// No socket is bound at the destination address at delivery time.
  NoSocket,
  /// The destination is an inside address of a translating NAT realm and
  /// the sender is outside it; such addresses are not routable.
  UnroutableInsideAddr,
  /// The datagram targets the public address of the sender's own NAT.
  /// Hairpinning is unsupported; see the crate documentation.
  Hairpin,
}

/// Why a NAT refused an inbound datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatRejectReason {
  /// No live mapping exists for the destination public address.
  NoMapping,
  /// A mapping exists but the grade's filtering policy excludes the sender.
  Filtered,
}

/// What happened to a datagram (or NAT mapping) at one instant.
///
/// Address conventions: `Sent` records the addresses as the sending socket
/// used them (pre-NAT). All later events record wire addresses at that
/// stage: post-NAT source everywhere, the sender-addressed destination for
/// send-time events (link-level drops), and the final inside destination
/// for arrival-time events (`Delivered` and the drops evaluated on
/// arrival). Timestamps likewise: send-time events carry the send instant,
/// arrival-time events (including `NatRejected`, since receiver-side NAT
/// state is consulted when the datagram arrives) the delivery instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
  /// A socket handed a datagram to the simulated network.
  Sent {
    src: SocketAddr,
    dst: SocketAddr,
    len: usize,
  },
  /// The simulated network discarded the datagram.
  Dropped {
    reason: DropReason,
    src: SocketAddr,
    dst: SocketAddr,
    len: usize,
  },
  /// The link duplicated the datagram; two copies were scheduled.
  Duplicated {
    src: SocketAddr,
    dst: SocketAddr,
    len: usize,
  },
  /// The datagram reached the destination socket's inbox.
  Delivered {
    src: SocketAddr,
    dst: SocketAddr,
    len: usize,
  },
  /// A NAT allocated a new mapping (or pinhole) for an inside socket.
  NatMapped {
    inside: SocketAddr,
    outside: SocketAddr,
  },
  /// A NAT refused an inbound datagram; the datagram was dropped.
  NatRejected {
    reason: NatRejectReason,
    src: SocketAddr,
    dst: SocketAddr,
  },
}

/// One simulated network event with its virtual timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEvent {
  /// Virtual time elapsed since the owning `SimNet` was created.
  pub at: Duration,
  pub kind: EventKind,
}

impl TraceEvent {
  /// One-line rendering with datagram sizes omitted: the deterministic
  /// view used for cross-run trace comparison.
  ///
  /// Sizes are excluded because TLS handshake content comes from the TLS
  /// provider's own entropy source and is not seedable, so handshake
  /// datagram sizes are not guaranteed stable across runs even with
  /// identical seeds. Everything else in an event -- kind, addresses,
  /// drop reason, virtual timestamp -- is deterministic.
  pub fn summary(&self) -> String {
    let at = self.at.as_micros();
    match &self.kind {
      EventKind::Sent { src, dst, .. } => {
        format!("{at:>10}us sent {src} -> {dst}")
      }
      EventKind::Dropped {
        reason, src, dst, ..
      } => {
        format!("{at:>10}us dropped({reason:?}) {src} -> {dst}")
      }
      EventKind::Duplicated { src, dst, .. } => {
        format!("{at:>10}us duplicated {src} -> {dst}")
      }
      EventKind::Delivered { src, dst, .. } => {
        format!("{at:>10}us delivered {src} -> {dst}")
      }
      EventKind::NatMapped { inside, outside } => {
        format!("{at:>10}us nat_mapped {inside} -> {outside}")
      }
      EventKind::NatRejected { reason, src, dst } => {
        format!("{at:>10}us nat_rejected({reason:?}) {src} -> {dst}")
      }
    }
  }
}
