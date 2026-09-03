# Agent notes for Mush

<!--
Part of the Mush project, under the Apache License v2.0 with LLVM
Exceptions. See /LICENSE for license information.
SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-->

Read [docs/design.md](docs/design.md), the authoritative design, and
[docs/testing.md](docs/testing.md) first. [CONTRIBUTING.md](CONTRIBUTING.md)
sets the style and license header rules.

## Commands

-   Build: `cargo build --workspace`
-   Tests: `cargo nextest run`
-   Lab tests: `cargo build -p mush`, then
    `cargo nextest run --profile lab -p mush-lab`. They take about 90 seconds.
    A test that cannot run here prints `MUSH-LAB-SKIP` and passes.
-   Benchmarks: `cargo bench -p mush-core -- --noplot`
-   Fuzzing: see docs/testing.md. Fuzz a changed parser for minutes; CI's
    30-second runs only catch a broken target.
-   Release build:
    `cargo build --release --target x86_64-unknown-linux-musl -p mush`. It needs
    a musl C compiler, and fat LTO makes it slow, so don't use it during
    development. CI's `release` job runs it.
-   Before committing: `cargo clippy --workspace --all-targets -- -D warnings`,
    `prek run -a`, and both test suites.

## Conventions

-   Every commit builds and passes both suites. Write regression tests first,
    and confirm they fail without the fix.
-   Read the comments on the root `Cargo.toml`'s version pins (quinn, patchbay)
    and on the release profile's `panic = "unwind"` before changing them. quinn
    comes from a pinned git revision, quinn-proto must be at least 0.11.17 for
    its security fixes, and `crates/mush-core/tests/quinn_provenance.rs` checks
    both requirements in both lockfiles. `fuzz/` is a separate workspace, so a
    quinn bump regenerates its lockfile too. The two lockfiles can differ on
    transitive crates neither builds here, such as windows-sys; don't force them
    to match.
-   This is a colocated jj repository. The repo config adds the
    `Assisted-by: Claude Code` trailer; don't add trailers by hand.

## Layout

-   `crates/mush`: the binary, with connect, server bootstrap, wrapper, and
    jump-helper modes.
-   `crates/mush-core`: the bootstrap protocol, key pinning, transport policy,
    relay, and session engines. It holds the seven security-relevant areas from
    design.md's security analysis; treat changes to them as security changes.
-   `crates/mush-netsim`: the deterministic simulator, documented in its
    rustdoc.
-   `crates/mush-testenv` and `crates/mush-lab`: the lab harness and suites.
-   `fuzz`: libFuzzer targets, with seed corpora in `fuzz/seeds/`.
