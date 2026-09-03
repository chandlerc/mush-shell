// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The real-kernel test lab for Mush, built on
//! [patchbay](https://docs.rs/patchbay): rootless network namespaces, veth
//! topologies, graded nftables NAT, and netem link impairment, with real
//! OpenSSH running inside lab hosts.
//!
//! Tier 2 of the testing strategy in `docs/testing.md`; the
//! deterministic in-process simulator (`mush-netsim`) is tier 1. What
//! the lab tests need, and nothing else:
//!
//! - topology presets matching the design doc ([`direct`], [`client_nat`],
//!   [`nat_both`], [`jump_chain`], [`jump_policy`], [`roaming`]),
//! - a real-sshd fixture ([`SshFixture`]),
//! - the production Mush wiring ([`MushFixture`], [`find_workspace_bin`])
//!   for acceptance tests running real OpenSSH over the real tunnel,
//! - a cached capability probe ([`available`]) so tests skip visibly on
//!   hosts that cannot run the harness,
//! - small observability helpers (reflector queries, NAT mapping probes,
//!   deadline polling, netns leak checks).
//!
//! # Test binary setup
//!
//! Every test binary must bootstrap the user namespace before any thread
//! exists, then guard each test on the capability probe:
//!
//! ```ignore
//! mush_testenv::userns_bootstrap!();
//!
//! #[tokio::test(flavor = "current_thread")]
//! async fn my_test() -> anyhow::Result<()> {
//!   mush_testenv::skip_unless_available!();
//!   let topo = mush_testenv::client_nat(mush_testenv::NatMode::PortRestricted).await?;
//!   // ...
//!   Ok(())
//! }
//! ```

#[cfg(target_os = "linux")]
mod mush;
#[cfg(target_os = "linux")]
mod ssh;
#[cfg(target_os = "linux")]
mod topo;
#[cfg(target_os = "linux")]
mod util;

#[cfg(target_os = "linux")]
pub use mush::{MushFixture, find_workspace_bin, pgrep_matches};
#[cfg(target_os = "linux")]
pub use ssh::{SshFixture, SshOutput, SshServer};
#[cfg(target_os = "linux")]
pub use topo::{
  JumpTopo, NatMode, RoamingTopo, Topology, Uplink, client_nat, direct,
  jump_chain, jump_chain_two_hops, jump_chain_with, jump_policy, jump_roaming,
  nat_both, roaming,
};
#[cfg(target_os = "linux")]
pub use util::{
  NatProbe, TcpEchoGuard, blackhole_udp_to, block_inbound_udp, block_udp_from,
  harden_command, poll_until, procs_in_netns, query_reflector,
  restrict_inbound_tcp, spawn_tcp_echo, udp_burst, unblock_udp_from,
  wait_tcp_ready,
};

// Re-exported for the `userns_bootstrap!` macro expansion and so tests can
// use patchbay types (labs, routers, link conditions) without a direct
// dependency.
#[cfg(target_os = "linux")]
pub use {ctor, patchbay};

/// Marker prefix printed when a test skips because the environment cannot
/// run the harness. CI greps for it and fails the lab job if it appears.
pub const SKIP_MARKER: &str = "MUSH-LAB-SKIP";

/// Installs the user-namespace bootstrap ctor into the calling test binary.
///
/// `patchbay::init_userns` must run while the process is still
/// single-threaded (the test harness spawns threads before any test code
/// runs), so it has to happen from an ELF constructor. Invoke this macro
/// once at the top of every lab test file; the invoking crate needs its
/// own `ctor` dependency, which the expansion references.
///
/// Failure is deliberately not a panic here: the result is cached inside
/// `init_userns` and surfaced by [`available`], so unsupported hosts skip
/// instead of aborting the whole binary.
///
/// The same constructor runs [`isolate_env`].
#[macro_export]
macro_rules! userns_bootstrap {
  () => {
    #[cfg(target_os = "linux")]
    #[$crate::ctor::ctor(unsafe)]
    fn mush_testenv_userns_bootstrap() {
      // SAFETY: an ELF constructor runs before any other thread exists.
      unsafe { $crate::isolate_env() };
      let _ = $crate::patchbay::init_userns();
    }
  };
}

/// Removes host environment that lab processes would otherwise inherit.
///
/// Every ssh in a lab, including the `-J` hop and Mush's bootstrap ssh,
/// consults the agent named by `SSH_AUTH_SOCK` even with `IdentitiesOnly`.
/// A developer's agent, often forwarded from another machine, answers
/// slowly enough under a full suite's load to exceed the fixture's 5s
/// `ConnectTimeout`. Tests that exercise an agent start their own and pass
/// it explicitly.
///
/// # Safety
///
/// Must run while the process is single-threaded, as from the
/// [`userns_bootstrap!`] constructor.
#[cfg(target_os = "linux")]
pub unsafe fn isolate_env() {
  // SAFETY: the caller guarantees no other thread exists.
  unsafe { std::env::remove_var("SSH_AUTH_SOCK") };
}

/// Skips the current test, visibly, when the harness cannot run here.
///
/// Expands to an early `return Ok(())` after printing [`SKIP_MARKER`] and
/// the reason to stderr. The enclosing test must return
/// `anyhow::Result<()>`.
#[macro_export]
macro_rules! skip_unless_available {
  () => {
    if let Err(reason) = $crate::available() {
      eprintln!("{}: {reason}", $crate::SKIP_MARKER);
      return Ok(());
    }
  };
}

/// Skips the current test, visibly, when a binary only some tests need
/// (`rsync`, `git`, `sftp`, the agent pair) is missing. The base
/// capability probe stays deliberately small, so absence skips just the
/// tests that require the tool; see `docs/testing.md`.
#[macro_export]
macro_rules! skip_unless_tools {
  ($($tool:expr),+ $(,)?) => {
    $(
      if !$crate::tool_available($tool) {
        eprintln!(
          "{}: required binary `{}` not found",
          $crate::SKIP_MARKER,
          $tool
        );
        return Ok(());
      }
    )+
  };
}

/// Reports whether this host can run the patchbay harness, with the reason
/// when it cannot. The probe runs once per process and is cached.
///
/// Checks, in order: the userns bootstrap succeeded (see
/// [`userns_bootstrap!`]), the namespace capabilities patchbay needs are
/// present, the external binaries the harness invokes exist, nested user
/// namespaces work (required to run sshd unprivileged), and a minimal
/// NAT-routed lab actually builds on this kernel -- including a netem
/// round-trip, so a kernel without `sch_netem` skips instead of failing
/// mid-test.
#[cfg(target_os = "linux")]
pub fn available() -> Result<(), String> {
  use std::sync::OnceLock;
  static PROBE: OnceLock<Result<(), String>> = OnceLock::new();
  PROBE.get_or_init(probe).clone()
}

/// Non-Linux stub: the harness is Linux-only.
#[cfg(not(target_os = "linux"))]
pub fn available() -> Result<(), String> {
  Err("the mush lab harness requires Linux network namespaces".to_string())
}

#[cfg(target_os = "linux")]
fn probe() -> Result<(), String> {
  // Idempotent: returns the cached result of the ctor bootstrap, or the
  // reason it failed (e.g. unprivileged userns disabled by sysctl).
  patchbay::init_userns().map_err(|e| {
    format!(
      "user namespace bootstrap failed (userns_bootstrap!() missing from \
       this test binary, or unprivileged user namespaces are disabled): {e}"
    )
  })?;
  patchbay::check_caps().map_err(|e| format!("missing capabilities: {e}"))?;

  for bin in [
    "ip",
    "tc",
    "nft",
    "unshare",
    "ssh",
    "ssh-keygen",
    "scp",
    "pgrep",
  ] {
    which(bin).ok_or_else(|| format!("required binary `{bin}` not found"))?;
  }
  ssh::find_sshd().map_err(|e| e.to_string())?;

  // Nested userns is how sshd runs unprivileged inside lab hosts; verify
  // the util-linux on this host supports --map-user (>= 2.38).
  let nested = std::process::Command::new("unshare")
    .args(["--user", "--map-user=1000", "--map-group=1000", "true"])
    .status()
    .map_err(|e| format!("running `unshare` failed: {e}"))?;
  if !nested.success() {
    return Err(
      "nested user namespace creation failed (util-linux with \
       `unshare --map-user` support is required)"
        .to_string(),
    );
  }

  // Build a minimal NAT-routed lab on a scratch runtime: proves veth,
  // routing, and the nftables NAT path work end to end, not merely that a
  // userns exists. Runs on its own thread so callers inside a tokio
  // runtime do not nest runtimes.
  std::thread::spawn(|| -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .map_err(|e| format!("probe runtime: {e}"))?;
    rt.block_on(async {
      let lab = patchbay::Lab::new()
        .await
        .map_err(|e| format!("lab construction failed: {e:#}"))?;
      let nat = lab
        .add_router("probe-nat")
        .nat(patchbay::Nat::Moderate)
        .build()
        .await
        .map_err(|e| format!("NAT router construction failed: {e:#}"))?;
      let dev = lab
        .add_device("probe-dev")
        .iface("eth0", nat.id())
        .build()
        .await
        .map_err(|e| format!("device construction failed: {e:#}"))?;
      // Exercise sch_netem, not merely the tc binary: minimal kernels
      // ship without the module, and qdisc module autoload from inside a
      // non-init user namespace is unreliable, so this is where a missing
      // module must surface.
      let iface = dev
        .iface("eth0")
        .ok_or_else(|| "probe device eth0 missing".to_string())?;
      iface
        .set_condition(
          patchbay::LinkCondition::lan(),
          patchbay::LinkDirection::Egress,
        )
        .await
        .map_err(|e| {
          format!("netem link conditioning failed (no sch_netem?): {e:#}")
        })?;
      iface
        .clear_condition(patchbay::LinkDirection::Egress)
        .await
        .map_err(|e| format!("clearing netem condition failed: {e:#}"))?;
      Ok(())
    })
  })
  .join()
  .map_err(|_| "capability probe thread panicked".to_string())?
}

/// Reports whether `Router::flush_nat_state` can work here, with the
/// reason when it cannot. Outside [`available`] because only NAT-rebind
/// tests need it, so those tests check it individually instead of the
/// whole suite skipping where it is absent. The probe runs once per
/// process and is cached.
///
/// The binary alone is not enough: `conntrack` talks to the kernel over
/// ctnetlink, which needs the `nf_conntrack_netlink` module, and module
/// autoload from inside a non-init user namespace is unreliable. Without
/// the module the kernel rejects every request and `conntrack -F` exits
/// non-zero having flushed nothing, so the probe runs that same flush in
/// a throwaway user and network namespace.
#[cfg(target_os = "linux")]
pub fn conntrack_available() -> Result<(), String> {
  use std::sync::OnceLock;
  static PROBE: OnceLock<Result<(), String>> = OnceLock::new();
  PROBE.get_or_init(probe_conntrack).clone()
}

#[cfg(target_os = "linux")]
fn probe_conntrack() -> Result<(), String> {
  let conntrack = which("conntrack")
    .ok_or_else(|| "required binary `conntrack` not found".to_string())?;
  let out = std::process::Command::new("unshare")
    .args(["--user", "--map-root-user", "--net"])
    .arg(&conntrack)
    .arg("-F")
    .output()
    .map_err(|e| format!("running `unshare` failed: {e}"))?;
  if !out.status.success() {
    let stderr = String::from_utf8_lossy(&out.stderr);
    return Err(format!(
      "`conntrack -F` failed in a user namespace ({}), so ctnetlink is \
       unusable; is the nf_conntrack_netlink module loaded? {}",
      out.status,
      stderr.lines().last().unwrap_or_default().trim()
    ));
  }
  Ok(())
}

/// Whether `bin` resolves on `PATH` (plus the sbin fallbacks): the probe
/// behind [`skip_unless_tools!`]. Lab namespaces share the host
/// filesystem, so this also answers for the remote side of a session.
#[cfg(target_os = "linux")]
pub fn tool_available(bin: &str) -> bool {
  which(bin).is_some()
}

/// Resolves `bin` against `PATH` plus the sbin directories that commonly
/// hold network tools but are absent from user `PATH`s.
#[cfg(target_os = "linux")]
fn which(bin: &str) -> Option<std::path::PathBuf> {
  let path = std::env::var_os("PATH").unwrap_or_default();
  std::env::split_paths(&path)
    .chain(["/usr/sbin", "/sbin"].iter().map(std::path::PathBuf::from))
    .map(|d| d.join(bin))
    .find(|p| p.is_file())
}
