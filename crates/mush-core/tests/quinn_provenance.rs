// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Both lockfiles resolve quinn-proto to the pinned revision, at or past
//! the release that fixes three remote memory-exhaustion advisories.
//!
//! quinn comes from a git revision (the root `Cargo.toml` has why), and
//! cargo enforces less about that than it looks: `--locked` holds the
//! lock to the manifest, but the manifest is one edit from naming a
//! different revision, or a branch instead of a revision, and either
//! resolves cleanly with the whole suite green. `relay_netsim` catches
//! one of those -- a revision without the coalescing fix truncates and
//! it fails -- and cannot see the other two. A branch pin is not a build
//! input at all, resolving to whatever the branch points at today; a
//! return to a registry release below the minimum version restores all
//! three advisories while fixing the truncation, so nothing else in the
//! suite would notice.
//!
//! So the two properties the manifest otherwise states only in prose are
//! asserted here: the resolved entry names the exact revision, and its
//! version is at or past the minimum. `fuzz/` is its own workspace with
//! its own lock and reaches quinn only by inheriting the root
//! workspace's entry, so its lock is checked from here rather than left
//! to the fuzz CI job.
//!
//! When the git source retires (the root `Cargo.toml` has the exit
//! condition), the revision half goes with it. The minimum version half
//! stays: the minimum applies whoever supplies the crate.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

/// The oldest quinn-proto carrying the fixes for GHSA-qfwj-vfxf-92j2,
/// GHSA-2hv7-gw8g-gpq5 and GHSA-hmxj-32vh-65vr, all three of which name
/// every earlier 0.11.x as affected.
const MIN_VERSION: Version = Version(0, 11, 17);

/// The tree quinn comes from: quinn main plus quinn-rs/quinn#2814.
const PINNED: &str = "git+https://github.com/lyons-e/quinn.git?rev=\
  8fec33d99621262ea9c43f8de55131f37e27013f#\
  8fec33d99621262ea9c43f8de55131f37e27013f";

#[test]
fn the_workspace_lock_holds_the_pinned_quinn_proto() {
  check_lock(&repo_root().join("Cargo.lock"));
}

#[test]
fn the_fuzz_lock_holds_the_pinned_quinn_proto() {
  check_lock(&repo_root().join("fuzz").join("Cargo.lock"));
}

/// The whole check, against a lockfile's text.
fn check(lock: &str) -> Result<(), String> {
  let entries = quinn_proto_entries(lock);
  let [entry] = entries.as_slice() else {
    // More than one means something put a second quinn-proto in the
    // graph beside the pinned one: a direct dependency on the registry
    // crate, or a `[patch]` that no longer applies.
    return Err(format!(
      "expected one quinn-proto entry, found {}{}",
      entries.len(),
      entries
        .iter()
        .map(|&(version, source)| format!(
          "\n  {version} from {}",
          source.unwrap_or("a path")
        ))
        .collect::<String>()
    ));
  };
  let (version, source) = *entry;
  let Some(source) = source else {
    return Err(format!(
      "quinn-proto {version} came from a path, not from {PINNED}"
    ));
  };
  if source != PINNED {
    return Err(format!(
      "quinn-proto {version} came from {source}, not from {PINNED}. A \
       revision is the pin; a branch or another revision is not, and \
       the root Cargo.toml says what this one carries"
    ));
  }
  let version = Version::parse(version)?;
  if version < MIN_VERSION {
    return Err(format!(
      "quinn-proto {version} is below the minimum version {MIN_VERSION}, \
       which is the oldest release carrying the fixes for \
       GHSA-qfwj-vfxf-92j2, GHSA-2hv7-gw8g-gpq5 and GHSA-hmxj-32vh-65vr; \
       see the root Cargo.toml"
    ));
  }
  Ok(())
}

/// The `version` and `source` of every `quinn-proto` package in a
/// `Cargo.lock`. `source` is absent exactly for a package supplied by a
/// path.
fn quinn_proto_entries(lock: &str) -> Vec<(&str, Option<&str>)> {
  let mut found = Vec::new();
  for block in lock.split("[[package]]") {
    let (mut name, mut version, mut source) = (None, None, None);
    for line in block.lines() {
      // A package's keys are `key = "value"`, one per line. The elements
      // of a `dependencies = [...]` array are bare strings and fall out
      // here, so a package that merely depends on quinn-proto cannot be
      // mistaken for it.
      let Some((key, value)) = line.split_once(" = ") else {
        continue;
      };
      let value = value.trim().trim_matches('"');
      match key {
        "name" => name = Some(value),
        "version" => version = Some(value),
        "source" => source = Some(value),
        _ => {}
      }
    }
    if name != Some("quinn-proto") {
      continue;
    }
    found.push((version.unwrap_or("(no version)"), source));
  }
  found
}

fn repo_root() -> PathBuf {
  Path::new(env!("CARGO_MANIFEST_DIR"))
    .parent()
    .and_then(Path::parent)
    .expect("crates/<crate> is two levels below the repository root")
    .to_path_buf()
}

fn check_lock(path: &Path) {
  let lock = fs::read_to_string(path)
    .unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));
  if let Err(why) = check(&lock) {
    panic!("{}: {why}", path.display());
  }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Version(u32, u32, u32);

impl Version {
  fn parse(text: &str) -> Result<Self, String> {
    let mut fields = [0; 3];
    let mut parts = text.split('.');
    for field in &mut fields {
      *field = parts
        .next()
        .and_then(|part| part.parse().ok())
        .ok_or_else(|| format!("unparseable quinn-proto version {text:?}"))?;
    }
    if parts.next().is_some() {
      return Err(format!("unparseable quinn-proto version {text:?}"));
    }
    Ok(Self(fields[0], fields[1], fields[2]))
  }
}

impl fmt::Display for Version {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}.{}.{}", self.0, self.1, self.2)
  }
}

// What follows checks the check, since a check that cannot fail is worse
// than no check: each case below is a resolution cargo really produces.

/// The shape both lockfiles hold, trimmed to the keys the check reads.
const RESOLVED: &str = r#"
version = 4

[[package]]
name = "quinn"
version = "0.12.0"
source = "git+https://github.com/lyons-e/quinn.git?rev=8fec33d99621262ea9c43f8de55131f37e27013f#8fec33d99621262ea9c43f8de55131f37e27013f"
dependencies = [
 "quinn-proto",
]

[[package]]
name = "quinn-proto"
version = "0.12.0"
source = "git+https://github.com/lyons-e/quinn.git?rev=8fec33d99621262ea9c43f8de55131f37e27013f#8fec33d99621262ea9c43f8de55131f37e27013f"
dependencies = [
 "bytes",
]
"#;

#[test]
fn the_pinned_shape_passes() {
  check(RESOLVED).expect("the pinned shape is what both locks hold");
}

/// Every resolution cargo really produces that the pin exists to
/// refuse, each with the part of the refusal that names it.
#[test]
fn a_drifted_resolution_is_caught() {
  let second_entry = format!(
    "{RESOLVED}\
     \n[[package]]\
     \nname = \"quinn-proto\"\
     \nversion = \"0.11.17\"\n"
  );
  let cases: [(&str, String, &str); 5] = [
    // A bump back to a published quinn: a crate that has the advisory
    // fixes and not the coalescing one.
    (
      "a registry resolution",
      RESOLVED.replace(
        PINNED,
        "registry+https://github.com/rust-lang/crates.io-index",
      ),
      "registry+",
    ),
    (
      "another revision",
      RESOLVED.replace("8fec33d9", "deadbeef"),
      "deadbeef",
    ),
    // The one nothing else in the suite can see: the branch carries the
    // fix today, so every test passes, and the build stops being a
    // function of the tree.
    (
      "a branch pin",
      RESOLVED.replace(
        "?rev=8fec33d99621262ea9c43f8de55131f37e27013f#",
        "?branch=fix-defragment-coalesce-lossless-runs#",
      ),
      "branch=",
    ),
    // What a registry dependency on quinn-proto beside the git one
    // leaves in the lock: two packages of the same name.
    ("a second quinn-proto", second_entry, "found 2"),
    // The one no other test would notice: 0.11.16 has no truncation bug
    // for `relay_netsim` to see, and three advisories that name it.
    (
      "a version below the minimum",
      RESOLVED.replace("version = \"0.12.0\"", "version = \"0.11.16\""),
      "below the minimum version 0.11.17",
    ),
  ];
  for (what, lock, expected) in cases {
    let Err(why) = check(&lock) else {
      panic!("{what} must be caught");
    };
    assert!(why.contains(expected), "{what}: {why}");
  }
}

#[test]
fn a_later_release_meets_the_minimum() {
  check(&RESOLVED.replace("version = \"0.12.0\"", "version = \"0.13.0\""))
    .expect("the minimum version is a minimum, not a pin");
}
