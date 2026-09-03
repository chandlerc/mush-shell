// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Every line parser in the protocol, on arbitrary bytes.
//!
//! The bootstrap channel is a login channel, so each parser is fed
//! whatever the far side's shell emits. Past the never-panic contract in
//! `bootstrap.rs`'s module docs, this target adds the two properties
//! that make a parse result trustworthy:
//!
//! - what a parser accepts, its encoder re-emits as a line parsing back
//!   to the same bytes, so an accepted line has no meaning the encoder
//!   cannot express. A fixed point of the encoder, not of the input: the
//!   six messages carrying `v=` without keeping it re-emit this build's
//!   `PROTOCOL_VERSION`, not the one the line named;
//! - a rejected token never smuggles a control character into the error
//!   message, and so onto the user's terminal.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mush_core::bootstrap::{
  Candidate, Connect, Done, Hello, Helper, ParseError, Punch, Signal,
};
use mush_core::channel::LineMessage;
use mush_core::helper::{Close, HelperMessage, Peer, Ready, Serve};

/// Parses, re-encodes, and re-parses one message type.
macro_rules! check {
  ($ty:ty, $line:expr) => {
    match <$ty>::parse($line) {
      Ok(parsed) => {
        let wire = parsed.to_wire();
        let again = <$ty>::parse(&wire)
          .expect("a line this encoder produced must parse again");
        assert_eq!(
          again.to_wire(),
          wire,
          "re-encoding an accepted {} is not stable",
          stringify!($ty)
        );
      }
      Err(error) => check_error(&error),
    }
  };
}

/// The same, for the two message sets whose parse skips non-messages.
macro_rules! check_set {
  ($ty:ty, $line:expr) => {
    match <$ty as LineMessage>::parse($line) {
      Ok(Some(parsed)) => {
        let wire = parsed.to_wire();
        let again = <$ty as LineMessage>::parse(&wire)
          .expect("a line this encoder produced must parse again")
          .expect("a line this encoder produced must still be a message");
        assert_eq!(
          again.to_wire(),
          wire,
          "re-encoding an accepted {} is not stable",
          stringify!($ty)
        );
      }
      Ok(None) => {}
      Err(error) => check_error(&error),
    }
  };
}

/// A parse error reaches the user's terminal, so the token it quotes
/// must be sanitized.
fn check_error(error: &ParseError) {
  let ParseError::MalformedToken { token } = error else {
    return;
  };
  assert!(
    !token.chars().any(char::is_control),
    "an unsanitized token reached a parse error: {token:?}"
  );
}

fuzz_target!(|data: &[u8]| {
  let Ok(line) = str::from_utf8(data) else {
    return;
  };

  // The bootstrap pair.
  check!(Hello, line);
  check!(Connect, line);

  // The signaling set, each parser directly and through the dispatcher.
  check!(Candidate, line);
  check!(Helper, line);
  check!(Punch, line);
  check!(Done, line);
  check_set!(Signal, line);

  // The jump helper's control channel, same treatment.
  check!(Serve, line);
  check!(Ready, line);
  check!(Peer, line);
  check!(Close, line);
  check_set!(HelperMessage, line);
});
