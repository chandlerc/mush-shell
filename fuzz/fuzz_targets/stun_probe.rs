// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The traversal probe format on arbitrary datagrams.
//!
//! `stun.rs` sits directly on the network: `is_stun` sorts every
//! datagram a traversal socket receives, `classify` decides what the
//! jump helper will answer, and `BindingTransaction::reflexive` decides
//! which answer may name this peer's public address. The properties
//! asserted are the ones the helper's safety depends on: the
//! demultiplexer and the classifier agree, nothing over the probe bound
//! is parsed as a request, a reflection is never larger than the request
//! that asked for it, and no datagram outside a transaction -- signed by
//! the secret that transaction was generated with -- can be taken for its
//! answer.
//!
//! A transaction id fills 96 bits of the header, hashed here out of the
//! whole input, so a mutation engine never produces the matching one and
//! everything in `reflexive` past its first check would be unreachable
//! on raw input. The input is therefore also replayed with the
//! transaction's own id spliced in, leaving the signature as the only
//! thing between arbitrary bytes and a reflexive address.
//!
//! Deriving the id rather than generating one keeps the run a function of
//! its input, which libFuzzer's minimization, crash deduplication, and
//! artifact replay all assume.

#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;

use libfuzzer_sys::fuzz_target;
use mush_core::bootstrap::{SessionNonce, SessionSecret};
use mush_core::stun::{
  BindingTransaction, Datagram, MAX_PROBE_BYTES, PeerRole, ProbeLabel,
  classify, is_stun,
};

/// Where a reflection would report the sender: one of each family, so
/// the anti-amplification guard is exercised at both response sizes.
const OBSERVED: [SocketAddr; 2] = [
  SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 61000),
  SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
    61000,
  ),
];

/// The transaction id occupies bytes 8..20 of every STUN message.
const TRANSACTION_ID: Range<usize> = 8..20;

/// The secret every probe this target generates is signed with.
const SESSION: [u8; 16] = [0x5a; 16];

/// A secret nothing here is ever signed with. Producing a valid HMAC
/// over it is beyond a mutation engine, so anything the crate calls
/// authentic under it is an integrity check that stopped happening.
const FOREIGN: [u8; 16] = [0xff; 16];

/// The transaction id this run's probes carry, hashed out of the input
/// rather than copied from it: the point of the id is that nobody who
/// has not seen the request can produce its answer, and an input naming
/// the id directly would hand the mutation engine what the target is
/// checking. Getting past the id check is the splice below's job.
fn transaction_id(data: &[u8]) -> u128 {
  // FNV-1a, widened: any cheap diffusion of the whole input would do.
  let mut hash = 0xcbf2_9ce4_8422_2325u64;
  for byte in data {
    hash ^= u64::from(*byte);
    hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
  }
  u128::from(hash) | (u128::from(hash.rotate_left(17)) << 64)
}

fuzz_target!(|data: &[u8]| {
  let secret = SessionSecret::from_bytes(SESSION);
  let foreign = SessionSecret::from_bytes(FOREIGN);
  let stun = is_stun(data);

  match classify(data) {
    Datagram::Payload => assert!(
      !stun,
      "a datagram the demultiplexer calls STUN was classified as payload"
    ),
    Datagram::OtherStun => assert!(
      stun,
      "a datagram the demultiplexer calls payload was classified as STUN"
    ),
    Datagram::Binding(request) => {
      assert!(stun, "a binding request that is not STUN");
      assert!(
        data.len() <= MAX_PROBE_BYTES,
        "a {}-byte datagram was parsed as a binding request",
        data.len()
      );
      let _ = request.label();
      assert!(
        !request.authentic(&foreign),
        "a request nothing signed passed an integrity check"
      );
      for observed in OBSERVED {
        if let Ok(reply) = request.reflect(observed, &secret) {
          assert!(
            reply.len() <= data.len(),
            "reflecting {} bytes at a {}-byte request amplifies",
            reply.len(),
            data.len()
          );
        }
      }
    }
  }

  // The probing side. Both flavors of transaction: the signed one every
  // session probes with, and the unsigned one a third-party `--stun`
  // reflector is asked with.
  let role = match data.first() {
    Some(byte) if byte % 2 == 0 => PeerRole::Destination,
    _ => PeerRole::Client,
  };
  let label = ProbeLabel::to_helper(SessionNonce::from_bytes([9; 16]), role);
  // The two must never share an id, or the checks below that one
  // transaction does not answer the other's probe assert nothing.
  let id = transaction_id(data);
  let signed = BindingTransaction::seeded(label, &secret, id);
  let unlabeled = BindingTransaction::unlabeled_seeded(id ^ 1);

  for transaction in [&signed, &unlabeled] {
    if transaction.reflexive(data).is_some() {
      assert!(
        data.len() >= TRANSACTION_ID.end,
        "a {}-byte datagram answered a transaction",
        data.len()
      );
      assert_eq!(
        &data[TRANSACTION_ID],
        &transaction.request()[TRANSACTION_ID],
        "a reflexive address was taken from another transaction's answer"
      );
    }
  }

  // The same datagram carrying a transaction's own id, so the id check
  // no longer rejects it before the checks after it can run.
  let mut answer = data.to_vec();
  if answer.len() >= TRANSACTION_ID.end {
    answer[TRANSACTION_ID].copy_from_slice(&signed.request()[TRANSACTION_ID]);
    assert!(
      signed.reflexive(&answer).is_none(),
      "an answer nothing signed named a reflexive address"
    );

    answer[TRANSACTION_ID]
      .copy_from_slice(&unlabeled.request()[TRANSACTION_ID]);
    // An unlabeled transaction has no signature to check, so this is the
    // one place arbitrary bytes may legitimately be accepted. What they
    // may not be is anything but a success response.
    if unlabeled.reflexive(&answer).is_some() {
      assert!(stun, "a datagram outside STUN answered a transaction");
      assert!(
        !matches!(classify(&answer), Datagram::Binding(_)),
        "a binding request was taken for its own answer"
      );
    }
  }

  // The pair traversal actually runs on: a genuine probe, the answer the
  // helper would give it, and the transaction that must recognize that
  // answer and no other.
  let observed = OBSERVED[data.len() % OBSERVED.len()];
  let Datagram::Binding(probe) = classify(signed.request()) else {
    panic!("a signed probe does not classify as a binding request");
  };
  assert_eq!(
    probe.label(),
    Some(label),
    "a signed probe does not carry its own label"
  );
  assert!(
    probe.authentic(&secret),
    "a probe signed with the session secret is not authentic under it"
  );
  assert!(
    !probe.authentic(&foreign),
    "a probe is authentic under a secret it was not signed with"
  );
  let reply = probe
    .reflect(observed, &secret)
    .expect("a signed probe is large enough to be answered");
  assert_eq!(
    signed.reflexive(&reply),
    Some(observed),
    "a transaction did not recognize its own answer"
  );
  assert!(
    unlabeled.reflexive(&reply).is_none(),
    "another transaction's answer named a reflexive address"
  );
});
