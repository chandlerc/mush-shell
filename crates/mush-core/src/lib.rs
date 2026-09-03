// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Shared machinery for the Mush client, server, and jump helper.
//!
//! Mush replaces the TCP transport under an unmodified OpenSSH client
//! and sshd with a roaming, resumable QUIC tunnel; this crate holds the
//! pieces every Mush process is built from:
//!
//! - [`bootstrap`]: the `MUSH HELLO` / `MUSH CONNECT` line protocol
//!   spoken over the bootstrap ssh channel, including the scanner that
//!   tolerates login output and finds the connect line amid it, and the
//!   signaling messages the same channel carries afterwards.
//! - [`channel`]: the line framing both protocol channels use, resuming
//!   from the leftover bytes their openers hand back.
//! - [`helper`] and [`stun`]: the jump helper's traversal assistance --
//!   reflection, punch rendezvous, and relay of last resort -- with its
//!   own control-channel line protocol and the STUN probe format the
//!   three services are driven by.
//! - [`path`] and [`traversal`]: path establishment -- candidate
//!   gathering, coordinated punching, and the direct/punched/relayed
//!   fallback order -- over the socket shim that lets the session's own
//!   QUIC endpoint and its traversal probes share one UDP mapping.
//! - [`pinning`]: ephemeral per-session raw-public-key identities and
//!   the pinning TLS verifiers.
//! - [`transport`]: the QUIC transport policy in one documented place --
//!   no idle timeout, client keep-alives, window sizing.
//! - [`upgrade`]: the relay-to-direct upgrade policy -- probe budgets,
//!   two-proof confirmation, and the backoff that bounds how much
//!   traffic a candidate path can attract.
//! - [`relay`]: the byte splice engine between a local byte stream and
//!   a QUIC bidirectional stream, with exact TCP half-close fidelity.
//! - [`client`] / [`server`]: the session-establishment engines -- the
//!   bootstrap conversation over the ssh channel, staggered candidate
//!   dialing on the client, and the pinned single-connection accept on
//!   the server. The CLI is a thin layer over these.
//! - [`roaming`]: the client's active path recovery -- stall detection
//!   and ack-eliciting rebind probes -- with [`netlink`] as its Linux
//!   network-change wake.
//!
//! # Security-relevant surface
//!
//! Mush carries SSH ciphertext and terminates no SSH, so it holds no
//! session keys and makes no authorization decision. What is custom is
//! the code deciding who to believe and what to spend, spread across
//! seven areas rather than one or two: the pinning verifiers, the
//! bootstrap and signal parsers, the STUN probe layer, the jump
//! helper's service, the upgrade policy's budgets and confirmation
//! rules, the martian filter and path table, and the shared socket's
//! handling of ICMP reports. `docs/design.md`'s "Security analysis"
//! says what each has to get right; scope a review by that list.

pub mod bootstrap;
pub mod channel;
pub mod client;
pub mod helper;
#[cfg(target_os = "linux")]
pub mod netlink;
pub mod path;
pub mod pinning;
pub mod relay;
pub mod roaming;
pub mod server;
pub mod stun;
pub mod transport;
pub mod traversal;
pub mod upgrade;
mod wire;
