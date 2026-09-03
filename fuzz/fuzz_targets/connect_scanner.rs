// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! `ConnectScanner` fed an arbitrary byte stream in arbitrary chunks.
//!
//! The scanner reads a login channel's stdout before the session exists,
//! so its contract is a bounds contract: never panic, never consume past
//! the declared budget, never report having used bytes it was not
//! handed. Chunk boundaries are where a line-splitting scanner goes
//! wrong, so the chunking comes from the input, and the strongest
//! property is an equivalence: with the budget lifted, an arbitrary
//! chunking must reach the same verdict, at the same offset in the
//! stream, as handing the whole stream over at once.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use mush_core::bootstrap::{
  Connect, ConnectScanner, MAX_LINE_BYTES, ParseError, ScanError, ScanLimits,
};

/// The largest chunk the input can ask for: past the scanner's per-line
/// bound and the channel's read size, so a boundary can fall anywhere
/// interesting.
const MAX_CHUNK: usize = 16 * 1024;

/// One scan: the budget to enforce, the chunk lengths to cycle through,
/// and the stream itself.
///
/// The stream is a borrowed slice in the last field, the one shape
/// `arbitrary` hands the remaining bytes over verbatim: a `Vec` spends a
/// byte per byte on continuation flags and ends the stream at the first
/// even one. So a corpus entry is a 12-byte header followed by literal
/// channel output.
#[derive(Arbitrary, Debug)]
struct Scan<'a> {
  budget_lines: u16,
  budget_bytes: u16,
  splits: [u16; 4],
  stream: &'a [u8],
}

impl<'a> Scan<'a> {
  fn chunks(&self) -> Vec<&'a [u8]> {
    let mut chunks = Vec::new();
    let mut rest = self.stream;
    let mut split = 0;
    while !rest.is_empty() {
      let take =
        (1 + usize::from(self.splits[split % 4]) % MAX_CHUNK).min(rest.len());
      let (chunk, tail) = rest.split_at(take);
      chunks.push(chunk);
      rest = tail;
      split += 1;
    }
    chunks
  }
}

/// What a whole scan came to, in terms that do not depend on chunking:
/// the connect line and where in the stream it ended, or why not.
#[derive(Debug, PartialEq)]
enum Verdict {
  Found(Connect, usize),
  NotFound,
  Malformed(ParseError),
  OverBudget,
}

/// Feeds `chunks` to a scanner, checking the bounds contract at every
/// step, and reports the verdict in whole-stream terms.
fn scan(limits: ScanLimits, chunks: &[&[u8]]) -> Verdict {
  let mut scanner = ConnectScanner::new(limits);
  let mut fed = 0;
  for chunk in chunks {
    fed += chunk.len();
    let pushed = scanner.push(chunk);
    // The memory bound, which nothing else here would notice going: a
    // line that cannot be a connect line is dropped, so the scanner
    // holds one line's worth at most between chunks, however long the
    // stream and however few newlines it has.
    assert!(
      scanner.buffered_bytes() <= MAX_LINE_BYTES,
      "the scanner is holding {} bytes of one line",
      scanner.buffered_bytes()
    );
    match pushed {
      Ok(Some((connect, consumed))) => {
        assert!(
          consumed <= chunk.len(),
          "the scanner consumed {consumed} of a {}-byte chunk",
          chunk.len()
        );
        assert!(
          scanner.bytes_seen() <= fed,
          "the scanner counted {} bytes but was fed {fed}",
          scanner.bytes_seen()
        );
        return Verdict::Found(connect, fed - chunk.len() + consumed);
      }
      Ok(None) => {
        // `push` checks the budget last, so a fully consumed chunk
        // leaves the scan strictly inside both halves of the budget,
        // every byte accounted for exactly once.
        assert_eq!(
          scanner.bytes_seen(),
          fed,
          "the scanner's byte count drifted from what it was fed"
        );
        assert!(
          scanner.lines_seen() < limits.max_lines,
          "the scanner examined {} lines on a {}-line budget",
          scanner.lines_seen(),
          limits.max_lines
        );
        assert!(
          scanner.bytes_seen() < limits.max_bytes,
          "the scanner consumed {} bytes on a {}-byte budget",
          scanner.bytes_seen(),
          limits.max_bytes
        );
      }
      Err(ScanError::MalformedConnect(error)) => {
        return Verdict::Malformed(error);
      }
      Err(ScanError::LimitExceeded { lines, bytes }) => {
        assert!(
          bytes <= fed,
          "the scanner reported {bytes} bytes over a {fed}-byte stream"
        );
        assert!(
          lines >= limits.max_lines || bytes >= limits.max_bytes,
          "the scanner gave up inside its budget"
        );
        return Verdict::OverBudget;
      }
    }
  }
  Verdict::NotFound
}

fuzz_target!(|input: Scan<'_>| {
  let chunks = input.chunks();

  // A tight, input-chosen budget: the bounds contract under pressure.
  let limits = ScanLimits {
    max_lines: 1 + usize::from(input.budget_lines) % 64,
    max_bytes: 1 + usize::from(input.budget_bytes),
  };
  if let Verdict::Found(connect, _) = scan(limits, &chunks) {
    let wire = connect.to_wire();
    let again =
      Connect::parse(&wire).expect("a scanned connect line must re-parse");
    assert_eq!(again, connect, "a scanned connect line does not round-trip");
  }

  // Chunking equivalence, with the budget lifted so that only the line
  // splitting can make the two runs differ.
  let unlimited = ScanLimits {
    max_lines: usize::MAX,
    max_bytes: usize::MAX,
  };
  assert_eq!(
    scan(unlimited, &chunks),
    scan(unlimited, &[input.stream]),
    "chunking changed what the scanner found"
  );
});
