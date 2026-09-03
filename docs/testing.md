# Testing Mush

<!--
Part of the Mush project, under the Apache License v2.0 with LLVM
Exceptions. See /LICENSE for license information.
SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-->

<!-- toc -->

## Table of contents

-   [Overview](#overview)
-   [Tier 1: deterministic simulation](#tier-1-deterministic-simulation)
-   [Tier 2: real-kernel lab](#tier-2-real-kernel-lab)
-   [Test map](#test-map)
-   [Reading the path report](#reading-the-path-report)
-   [Simulator-only suites](#simulator-only-suites)
-   [Running](#running)
-   [Performance comparison](#performance-comparison)
-   [Fuzzing](#fuzzing)

<!-- tocstop -->

## Overview

Mush has two test tiers: a deterministic in-process simulator, and a
real-kernel network lab running real OpenSSH. libFuzzer targets cover the
parsers and the helper service. The types and functions named here are
documented in rustdoc (`cargo doc -p mush-testenv -p mush-netsim --open`), and
each test file starts with a comment saying what it covers.

## Tier 1: deterministic simulation

`crates/mush-netsim` runs real quinn endpoints over a simulated network, plugged
in at quinn's `AsyncUdpSocket` interface, with a seeded RNG, tokio virtual
time, and NAT models: the RFC 4787 grades plus 1:1 and firewall-only. A seed
always produces the same event trace, so roaming, NAT rebinds, blackholes, and
MTU changes become fast, reproducible tests.

## Tier 2: real-kernel lab

`crates/mush-testenv` wraps [patchbay](https://docs.rs/patchbay), a rootless
network lab, for the tests in `crates/mush-lab`. Each test builds network
namespaces joined by veth pairs, with nftables NAT and tc netem impairment, and
runs real sshd, ssh, and `mush` in them. The harness provides:

-   Topologies: `direct`, `client_nat`, `nat_both`, `roaming`, and the `jump_*`
    family, parameterized by `NatMode`. The jump topologies enforce the bastion
    with a real network edge; `jump_policy` instead has the destination's
    nftables drop inbound TCP from everything but the jump host.
-   `SshFixture`: throwaway keys, an unprivileged pubkey-only sshd, and clients
    with pre-seeded `known_hosts`, so host key checking stays on.
-   `MushFixture`: the production setup on an `SshFixture`, including the
    `ProxyCommand`, wrapper-mode shims, and a check that the server processes
    exit.
-   Observation (`query_reflector`, `NatProbe`, `poll_until`, and others) and
    firewall helpers (`block_inbound_udp`, `blackhole_udp_to`, and others).
-   Raw patchbay, re-exported as `mush_testenv::patchbay`, for everything else.

Rules for lab tests:

-   Never sleep for a fixed time. Poll with a deadline.
-   Run every command through `mush_testenv::harden_command`, which kills the
    child when its handle drops or the test process dies; `SshFixture` already
    does. That cannot reach the remote side of an ssh session, so each topology
    also kills everything left in its namespaces when dropped.
-   Resilience tests pass `--no-fallback` or assert the fallback warning is
    absent. Otherwise TCP fallback carries the session through most scenarios,
    and the test passes with QUIC broken.
-   A test that needs an ssh agent starts its own and passes `SSH_AUTH_SOCK`
    explicitly. The bootstrap removes the developer's agent from the
    environment, since every lab ssh would otherwise consult it.

Each lab test binary installs the user-namespace bootstrap, and each test
checks that the lab can run:

```rust
mush_testenv::userns_bootstrap!();

#[tokio::test(flavor = "current_thread")]
async fn my_test() -> anyhow::Result<()> {
  mush_testenv::skip_unless_available!();
  let topo = mush_testenv::client_nat(mush_testenv::NatMode::PortRestricted).await?;
  // ...
  Ok(())
}
```

## Test map

In-process and loopback tests, run by `cargo nextest run`:

| Test                                    | Covers                                                                                                  |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `mush-core/tests/establish.rs`          | Establishment over loopback: login output, scan budgets, candidate racing, pin refusal                  |
| `mush-core/tests/establish_netsim.rs`   | Establishment over an impaired simulated link, and replay determinism                                   |
| `mush-core/tests/handshake.rs`          | Pinning verifiers: correct pins connect, and every wrong or missing credential is refused               |
| `mush-core/tests/signaling.rs`          | Candidate, helper, and punch signaling in both directions                                               |
| `mush-core/tests/relay.rs`              | The relay: bulk transfer, half-close, and each abort outcome                                            |
| `mush-core/tests/relay_netsim.rs`       | The frame backlog (see below)                                                                           |
| `mush-core/tests/recovery_netsim.rs`    | The stall prober's recovery bound across kinds of outage, and netlink wakes                             |
| `mush-core/tests/hostile_netsim.rs`     | Wake floods and flapping against the prober, and a mutation check of the healthy-path test              |
| `mush-core/tests/hostile_diag.rs`       | The recovery bound as tables                                                                            |
| `mush-core/tests/hostile_netlink.rs`    | The netlink monitor's idle CPU cost                                                                     |
| `mush-core/tests/hostile_candidates.rs` | Hostile input to candidate gathering and racing                                                         |
| `mush-core/tests/helper_netsim.rs`      | The helper: reflection through NATs, relaying, and a roaming client                                     |
| `mush-core/tests/punch_netsim.rs`       | The punch matrix (see below)                                                                            |
| `mush-core/tests/switch_netsim.rs`      | The path manager (see below)                                                                            |
| `mush-core/tests/upgrade_netsim.rs`     | The upgrade policy (see below)                                                                          |
| `mush-core/tests/quinn_provenance.rs`   | Both lockfiles use the pinned quinn revision and a quinn-proto with the advisory fixes                  |
| `mush/tests/cli.rs`                     | CLI dispatch, including raw argv for the wrapper and the `--` escape                                    |
| `mush/tests/loopback.rs`                | The binary against a TCP echo server and a stand-in ssh: detach, fallback, `--retain`, `--idle-timeout` |
| `mush/tests/jump_helper.rs`             | `mush jump-helper` over pipes, from the ready line to exit                                              |
| `mush-netsim/tests/network.rs`          | The simulated network, without quinn                                                                    |

Real-kernel lab, run by `cargo nextest run --profile lab -p mush-lab`:

| Test                               | Covers                                                                                                                 |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `mush-lab/tests/lab_smoke.rs`      | The lab itself, without Mush                                                                                           |
| `mush-lab/tests/acceptance.rs`     | End to end: exec, exit codes, stdin, scp, `-L`, roaming, NAT rebinds, fallback, and wrapper mode                       |
| `mush-lab/tests/resilience.rs`     | Uplink flapping, roaming, a 70s blackhole, one-way blackholes, and SIGKILL of each process                             |
| `mush-lab/tests/compat.rs`         | [SSH features](design.md#what-openssh-provides) over the tunnel, with plain-ssh control runs where the claim is parity |
| `mush-lab/tests/candidates.rs`     | The direct path through a jump, and a blackholed first hint                                                            |
| `mush-lab/tests/jump_helper.rs`    | The helper on a real bastion, with NAT on both ends                                                                    |
| `mush-lab/tests/hostile_jump.rs`   | A live session whose bastion disappears                                                                                |
| `mush-lab/tests/punch.rs`          | Seven path-establishment cases on a real bastion, with and without the helper                                          |
| `mush-lab/tests/upgrade.rs`        | Starting on the relay and upgrading to a direct path                                                                   |
| `mush-lab/tests/prober.rs`         | No probes or rebinds on a healthy idle session                                                                         |
| `mush-lab/tests/hostile_outage.rs` | The prober's bound with the client also writing, where a full congestion window could hold the probe                   |
| `mush-lab/tests/perf.rs`           | Manual performance comparison; asserts nothing                                                                         |

## Reading the path report

`mush connect` writes the path a session settled on to the file named by
`MUSH_PATH_REPORT`, rewriting it on every switch; `mush/src/connect.rs` defines
the format. Lab tests read that file instead of the log, which also carries
ssh's output. `RUST_LOG=mush_core::client=debug,mush::connect=debug` turns on
establishment logging.

## Simulator-only suites

Frame backlog (`relay_netsim.rs`). A local sink that stops reading piles up
thousands of unread frames at the receiver, which kills the connection with
released quinn-proto, so this test fails if the quinn pin moves to a release or
to upstream main. It asserts that the backlog formed, so it cannot pass without
testing the case. On real sockets the scenario reproduced in about 2 of 300
runs.

Punch matrix (`punch_netsim.rs`). All 36 pairs of the simulator's six NAT
grades, each a full session with the real engines and helper, asserting which
kind of path carried it. A symmetric destination must use the relay, and so must
a symmetric client against a destination edge that filters on port; everything
else punches. On failure the test prints the grid and a seed for each wrong
cell. Three more cells cover relay edge cases: a NAT rebind before the relayed
dial, a dual-homed bastion, and recovery from an outage while relayed.

Path manager (`switch_netsim.rs`). A megabyte each way survives a switch
mid-transfer byte for byte, on the same QUIC connection, and the virtual peer
address never reaches the network.

Upgrade policy (`upgrade_netsim.rs`). The peers' own policies decide, and the
test reads which path the bytes took from the simulator's trace. It also checks
that a lossy direct path is not abandoned, that unsigned probe floods do not
block an upgrade, and that a vanished client stops costing the bastion.

## Running

```sh
cargo nextest run                             # everything except the lab
cargo build -p mush                           # the lab runs this binary
cargo nextest run --profile lab -p mush-lab   # the lab suite
```

`.config/nextest.toml` defines the profiles. The lab suite runs in parallel,
takes about 90 seconds, and terminates hung tests.

The lab needs Linux with unprivileged user namespaces, `ip`, `tc` with
`sch_netem`, `nft`, `unshare` (util-linux 2.38 or later), `pgrep`, and OpenSSH,
but not root. When something is missing, each test prints
`MUSH-LAB-SKIP: <reason>` and passes; CI fails if that marker appears. Some
tests also need `conntrack`, `sftp`, `ssh-agent`, `rsync`, or `git`, and skip
without them. The NAT-rebind tests also need the `nf_conntrack_netlink` module
loaded, since it does not autoload inside a user namespace.

Lab results vary with the kernel and timing, so lab tests assert properties,
not exact traces; reproducibility belongs to tier 1. nftables cannot express
port-preserving symmetric NAT, so that grade exists only in the simulator. On a
router, rules keyed on source address need raw `nft` through
`Router::spawn_command`; on a device, use `restrict_inbound_tcp` or
`block_udp_from`. The harness uses IP addresses throughout, since name
resolution in namespaces depends on the host.

## Performance comparison

`mush-lab/tests/perf.rs` compares Mush with ssh in the same lab, using scp for
both, so only the transport differs. It runs by hand on an idle machine, never
in CI, and refuses debug builds:

```sh
cargo build --release -p mush
cargo nextest run --profile perf --cargo-profile release -p mush-lab \
  --no-capture
```

It reports medians and spreads per scenario, interleaving the two transports:
`clean` (512 MiB transfers, connect time, echo RTT), `wan` (40 ms RTT),
`lossy05` and `lossy2` (0.5% and 2% loss at 40 ms RTT), and `recovery` (time to
first byte after 5s, 10s, and 30s blackholes). `MUSH_PERF_SCENARIOS` selects a
subset, `MUSH_PERF_REPS`, `MUSH_PERF_LOSSY_REPS`, and `MUSH_PERF_RECOVERY_REPS`
set repetitions, and `MUSH_PERF_DIR` sets where the JSON results go. A full run
takes about an hour.

The harness verifies its own lab: it reads back the netem parameters, measures
RTT with timed TCP connects, runs sessions with `--no-fallback`, and waits for
the load average to drop. netem drops whole kernel buffers, which on the sending
host hold dozens of packets whatever the offload settings, so the harness
applies loss on router interfaces, which carry only already-segmented traffic,
and fails unless the measured per-packet loss rate matches the configured one.
The lossy scenarios need `ethtool`.

## Fuzzing

`fuzz/` is a separate workspace that needs nightly. Each target asserts its
module's documented contract, not only the absence of panics:

| Target              | Covers                                           |
| ------------------- | ------------------------------------------------ |
| `bootstrap_lines`   | The protocol line parsers                        |
| `connect_scanner`   | The connect scan over arbitrary chunk boundaries |
| `line_channel`      | The signaling channel's framing                  |
| `line_channel_send` | The channel writer, cancelled mid-line           |
| `stun_probe`        | The traversal probe format                       |
| `helper_service`    | The jump helper's datagram handling              |

CI runs each target for 30 seconds, which catches a broken target and says
nothing about a parser change. Fuzz a changed parser for minutes:

```sh
cargo install cargo-fuzz
mkdir -p fuzz/corpus/bootstrap_lines
cargo +nightly fuzz run --fuzz-dir fuzz bootstrap_lines \
  fuzz/corpus/bootstrap_lines fuzz/seeds/bootstrap_lines \
  -- -dict=fuzz/mush.dict -max_len=65536
```

libFuzzer writes new inputs to the first directory, `fuzz/corpus/`, which git
ignores; `fuzz/seeds/` holds the committed inputs. `-max_len` must exceed the
8 KiB line limit. Crashes go to `fuzz/artifacts/`. To keep new coverage, copy
inputs into the seeds and minimize them with
`cargo +nightly fuzz cmin --fuzz-dir fuzz <target> fuzz/seeds/<target>`.
`mush-core`'s `fuzzing` feature adds seeded constructors for these targets and
is not used elsewhere.
