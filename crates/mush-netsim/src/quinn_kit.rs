// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Determinism kit: [`EndpointConfig`] with every entropy source it
//! controls pinned from a seed, plus the sub-seed derivation the callers
//! that build several endpoints from one scenario seed need.
//!
//! quinn's stock configuration hides entropy draws that
//! `EndpointConfig::rng_seed` does *not* cover, pinned here:
//!
//! - Both stock [`ConnectionIdGenerator`]s draw from `rand::rng()`; a
//!   seeded generator replaces them.
//! - `EndpointConfig::default()` draws a random stateless-reset key. The
//!   fixed, seed-derived stand-in here is NOT cryptographic -- a keyed FNV
//!   hash -- which is fine because reset tokens only ever round-trip
//!   through this same process, and this crate never ships in production
//!   code.
//!
//! `ClientConfig::initial_dst_cid_provider` is the one entropy source left
//! unseeded; see the crate documentation for why replay holds anyway.

use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::{CryptoError, HmacKey};
use quinn::{ConnectionId, ConnectionIdGenerator, EndpointConfig};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

/// Derive an independent `u64` sub-seed from `seed` for `label`.
pub fn derive_u64(seed: u64, label: &str) -> u64 {
  fnv1a64(seed, &[label.as_bytes()])
}

/// Derive an independent 32-byte sub-seed from `seed` for `label`, in the
/// shape `EndpointConfig::rng_seed` wants.
fn derive_seed32(seed: u64, label: &str) -> [u8; 32] {
  mac32(seed, &[label.as_bytes()])
}

/// Deterministic [`ConnectionIdGenerator`], mandatory for reproducible
/// runs; see the module docs.
#[derive(Debug)]
struct SeededCidGenerator {
  rng: StdRng,
}

impl SeededCidGenerator {
  fn new(seed: u64) -> Self {
    Self {
      rng: StdRng::seed_from_u64(seed),
    }
  }
}

impl ConnectionIdGenerator for SeededCidGenerator {
  fn generate_cid(&mut self) -> ConnectionId {
    let mut bytes = [0u8; 8];
    self.rng.fill_bytes(&mut bytes);
    ConnectionId::new(&bytes)
  }

  fn cid_len(&self) -> usize {
    8
  }

  fn cid_lifetime(&self) -> Option<Duration> {
    None
  }
}

/// Fixed, seed-derived stand-in for the stateless-reset HMAC key.
/// Deterministic and non-cryptographic; see the module docs.
#[derive(Debug)]
struct SimHmacKey {
  key: u64,
}

impl HmacKey for SimHmacKey {
  fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
    signature_out.copy_from_slice(&mac32(self.key, &[data]));
  }

  fn signature_len(&self) -> usize {
    32
  }

  fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    if signature == mac32(self.key, &[data]) {
      Ok(())
    } else {
      Err(CryptoError)
    }
  }
}

/// [`EndpointConfig`] with every entropy source it controls pinned from
/// `seed`: a fixed stateless-reset key, `rng_seed` (which seeds the
/// endpoint RNG and, through it, each connection's), and a seeded
/// connection-ID generator.
///
/// Give every endpoint its own seed: two endpoints configured from the
/// same seed share a CID stream and a stateless-reset key, a correlation
/// no real deployment has. [`derive_u64`] with a role label is how
/// callers split one scenario seed across the endpoints they build.
pub fn seeded_endpoint_config(seed: u64) -> EndpointConfig {
  let mut cfg = EndpointConfig::new(Arc::new(SimHmacKey {
    key: derive_u64(seed, "reset"),
  }));
  cfg.rng_seed(Some(derive_seed32(seed, "endpoint-rng")));
  let cid_seed = derive_u64(seed, "cid");
  cfg.cid_generator(Arc::new(move || {
    Box::new(SeededCidGenerator::new(cid_seed))
      as Box<dyn ConnectionIdGenerator>
  }));
  cfg
}

/// Keyed FNV-1a over `chunks`, the base of all seed derivation here.
fn fnv1a64(seed: u64, chunks: &[&[u8]]) -> u64 {
  let mut h = 0xcbf2_9ce4_8422_2325u64 ^ seed;
  for chunk in chunks {
    for &b in *chunk {
      h ^= u64::from(b);
      h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // Chunk separator so ("ab", "c") differs from ("a", "bc").
    h ^= 0xff;
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
  }
  h
}

/// 32 bytes from four independently seeded FNV lanes.
fn mac32(key: u64, chunks: &[&[u8]]) -> [u8; 32] {
  let mut out = [0u8; 32];
  for lane in 0u64..4 {
    let lane_seed = key ^ lane.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let h = fnv1a64(lane_seed, chunks);
    out[usize::try_from(lane).unwrap() * 8..][..8]
      .copy_from_slice(&h.to_le_bytes());
  }
  out
}
