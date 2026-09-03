// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Generators for the protocol's wire spellings.
//!
//! Every spelling Mush puts on a wire is read back by the peer it goes
//! to, so each needs an encoder and a decoder that are exact inverses.
//! By hand that is one string in two places per field with only a
//! round-trip test holding them together; these macros make the
//! spelling a property of the declaration and generate both directions
//! from one table.
//!
//! - [`str_enum`] for a plain enum spelled as one of a fixed set of
//!   words ([`PathKind`](crate::path::PathKind), the STUN label's
//!   [`PeerRole`](crate::stun::PeerRole) and [`Aim`](crate::stun::Aim),
//!   [`CandidateKind`](crate::bootstrap::CandidateKind)).
//! - [`line_message`] and [`line_message_enum`] for the `key=value`
//!   line protocol of [`crate::bootstrap`] and [`crate::helper`].
//!
//! The line-protocol generators sit on the field machinery in
//! [`crate::bootstrap`] ([`parse_fields`](crate::bootstrap::parse_fields)
//! and `Fields`), which is where the security-relevant parsing lives and
//! stays hand-written.

/// Generates an enum's wire spelling from a variant-to-word table:
/// `as_str`, the `Display` that writes it, and the `FromStr` that
/// inverts it.
///
/// The enum, its derives, and its variant docs stay where they are; only
/// the spellings move in here. `$error` is the unit error the generated
/// `FromStr` fails as, which every caller answers with
/// [`InvalidValue`](crate::bootstrap::InvalidValue): the one thing that
/// reads any of these discards it and reports the key instead.
macro_rules! str_enum {
  ($ty:ident => $error:ident {
    $($variant:ident => $word:literal),+ $(,)?
  }) => {
    impl $ty {
      /// The wire and log spelling.
      pub fn as_str(self) -> &'static str {
        match self {
          $(Self::$variant => $word,)+
        }
      }
    }

    impl std::fmt::Display for $ty {
      fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
      }
    }

    impl std::str::FromStr for $ty {
      type Err = $error;

      fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
          $($word => Ok(Self::$variant),)+
          _ => Err($error),
        }
      }
    }
  };
}

/// Generates one line-protocol message's parser and its two encoders
/// from a table of field, key, and kind.
///
/// A message is a fixed prefix followed by space-separated `key=value`
/// tokens in declaration order, so the table holds everything that
/// differs between them. The kinds:
///
/// - `required`: exactly one, a parse error when missing.
/// - `optional`: zero or one. Absent leaves the field `None`, but a
///   present-but-malformed value is still an error.
/// - `repeated`: any number, in order, collected into the field's `Vec`.
/// - `redacted`: required, and the one kind whose two encodings differ.
///   `to_wire` spells the value out through its `expose` method and
///   `Display` does not, which is what keeps the session secret on the
///   ssh channels it is distributed over and out of log lines.
///
/// `version` written after the prefix -- `line_message! { Done,
/// DONE_PREFIX, version { .. } }` -- gives the message a leading `v=`
/// with no field behind it: encoders emit
/// [`PROTOCOL_VERSION`](crate::bootstrap::PROTOCOL_VERSION) and the
/// parser requires the key and type-checks it but keeps nothing, so a
/// line the peer sent is re-encoded normalized rather than verbatim.
/// The messages that keep a `version` field instead are the four whose
/// readers act on it: the two openers of each channel.
///
/// The struct, its derives, and its field docs stay where they are. The
/// generated parser builds a `Self { .. }` from exactly the fields
/// listed, so a table that drifts from the struct does not compile, and
/// each value's type is inferred from the field it is stored in.
macro_rules! line_message {
  ($ty:ident, $prefix:ident { $($fields:tt)* }) => {
    line_message!(@message $ty, $prefix, [] { $($fields)* });
  };

  ($ty:ident, $prefix:ident, version { $($fields:tt)* }) => {
    line_message!(@message $ty, $prefix, ["v"] { $($fields)* });
  };

  // The version key travels as a literal rather than a flag so that
  // `concat!` can build its format string like every other key's.
  (@message $ty:ident, $prefix:ident, [$($version:literal)?] {
    $($field:ident: $key:literal $kind:ident),+ $(,)?
  }) => {
    impl $ty {
      /// Parses one line of this message. Accepts one optional trailing
      /// `\r\n` or `\n`.
      pub fn parse(
        line: &str,
      ) -> Result<Self, $crate::bootstrap::ParseError> {
        let fields = $crate::bootstrap::parse_fields(line, $prefix)?;
        $(let _: u32 = fields.value($version)?;)?
        Ok(Self {
          $($field: line_message!(@read $kind fields $key),)+
        })
      }

      /// The complete wire line, including the terminating newline. Not
      /// always [`Display`](std::fmt::Display)'s output: a redacted
      /// field is spelled out here and nowhere else.
      pub fn to_wire(&self) -> String {
        let mut line = String::new();
        // Writing into a `String` cannot fail.
        let _ = self.write_line(&mut line, true);
        line.push('\n');
        line
      }

      /// The line without its terminator. `expose` picks a redacted
      /// field's wire form over its display form, so a message with no
      /// redacted field never reads it.
      fn write_line(
        &self,
        out: &mut dyn std::fmt::Write,
        #[allow(unused_variables)] expose: bool,
      ) -> std::fmt::Result {
        out.write_str($prefix)?;
        $(write!(
          out,
          concat!(" ", $version, "={}"),
          $crate::bootstrap::PROTOCOL_VERSION
        )?;)?
        $(line_message!(@write $kind out (&self.$field) $key expose);)+
        Ok(())
      }
    }

    impl std::fmt::Display for $ty {
      fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.write_line(f, false)
      }
    }
  };

  (@read required $fields:ident $key:literal) => { $fields.value($key)? };
  (@read redacted $fields:ident $key:literal) => { $fields.value($key)? };
  (@read optional $fields:ident $key:literal) => {
    $fields.optional_value($key)?
  };
  (@read repeated $fields:ident $key:literal) => { $fields.repeated($key)? };

  (@write required
   $out:ident ($value:expr) $key:literal $expose:ident) => {
    write!($out, concat!(" ", $key, "={}"), $value)?
  };
  (@write redacted
   $out:ident ($value:expr) $key:literal $expose:ident) => {
    match $expose {
      true => write!($out, concat!(" ", $key, "={}"), $value.expose())?,
      false => write!($out, concat!(" ", $key, "={}"), $value)?,
    }
  };
  (@write optional
   $out:ident ($value:expr) $key:literal $expose:ident) => {
    if let Some(value) = $value {
      write!($out, concat!(" ", $key, "={}"), value)?;
    }
  };
  (@write repeated
   $out:ident ($value:expr) $key:literal $expose:ident) => {
    for value in $value {
      write!($out, concat!(" ", $key, "={}"), value)?;
    }
  };
}

/// Generates the dispatcher over one channel's message set: a `parse`
/// that picks a message out of a line by its prefix, `to_wire`,
/// `Display`, and the [`LineMessage`](crate::channel::LineMessage) the
/// framing asks for.
///
/// Each variant wraps the message type of the same name, which is what
/// lets the table be variant-to-prefix alone. `nonce` stays hand-written
/// because the two sets differ on it: every signal names a session,
/// while the helper's ready line is about the helper itself.
macro_rules! line_message_enum {
  ($ty:ident { $($variant:ident => $prefix:ident),+ $(,)? }) => {
    impl $ty {
      /// Parses one line, returning `Ok(None)` for a line that is not a
      /// message of this set: these are login channels, and a shell that
      /// keeps talking must not be able to end a phase.
      ///
      /// A line that *is* a message of the set and fails strict parsing
      /// is an error: the peer spoke the protocol and got it wrong.
      pub fn parse(
        line: &str,
      ) -> Result<Option<Self>, $crate::bootstrap::ParseError> {
        let line = $crate::bootstrap::strip_line_end(line);
        $(
          if $crate::bootstrap::has_message_prefix(line, $prefix) {
            return $variant::parse(line).map(Self::$variant).map(Some);
          }
        )+
        Ok(None)
      }

      /// The complete wire line, including the terminating newline.
      /// Dispatched rather than formatted from
      /// [`Display`](std::fmt::Display), because a redacted field's wire
      /// form is not its display form.
      pub fn to_wire(&self) -> String {
        match self {
          $(Self::$variant(m) => m.to_wire(),)+
        }
      }
    }

    impl std::fmt::Display for $ty {
      fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
          $(Self::$variant(m) => m.fmt(f),)+
        }
      }
    }

    impl $crate::channel::LineMessage for $ty {
      fn parse(
        line: &str,
      ) -> Result<Option<Self>, $crate::bootstrap::ParseError> {
        Self::parse(line)
      }

      fn to_wire(&self) -> String {
        self.to_wire()
      }
    }
  };
}

pub(crate) use {line_message, line_message_enum, str_enum};
