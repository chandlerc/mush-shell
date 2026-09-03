// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Production wiring for the real `mush` binary inside a lab.
//!
//! [`find_workspace_bin`] locates workspace binaries from a test
//! executable, and [`MushFixture`] composes the full production setup:
//! an outer OpenSSH client whose `ProxyCommand` runs the real
//! `mush connect`, which runs a real bootstrap ssh (configured by the
//! [`SshFixture`]) against the lab's sshd, which starts the real
//! detached `mush server bootstrap` on the dest. No fakes anywhere; the
//! only deltas from production are the fixture ssh config and a
//! `--marker` tag on the server for hygiene sweeps.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tempfile::TempDir;

use crate::ssh::SshFixture;

/// Locates a workspace binary (e.g. `mush`) from inside a test
/// executable: test binaries run from `<target>/<profile>/deps`, and
/// the workspace's own binaries live one level up in
/// `<target>/<profile>`.
///
/// Test runs do not build binary crates the tests do not link against,
/// so the binary must be built beforehand; the error names the command.
pub fn find_workspace_bin(name: &str) -> Result<PathBuf> {
  let exe =
    std::env::current_exe().context("resolving the test executable path")?;
  let mut dir = exe.parent();
  while let Some(d) = dir {
    let candidate = d.join(name);
    if candidate.is_file() {
      return Ok(candidate);
    }
    // Walk out of `deps` (or `examples`) to the profile directory, but
    // no further: nothing above the profile directory holds workspace
    // binaries.
    if d
      .file_name()
      .is_some_and(|f| f == "deps" || f == "examples")
    {
      dir = d.parent();
    } else {
      break;
    }
  }
  bail!(
    "workspace binary `{name}` not found near {}; build it first with \
     `cargo build -p {name}`",
    exe.display()
  );
}

/// Single-quotes `word` for `/bin/sh`, the shell ssh hands ProxyCommand
/// strings to.
fn sq(word: &str) -> String {
  format!("'{}'", word.replace('\'', r"'\''"))
}

/// Distinguishes fixtures created in the same process and nanosecond.
static FIXTURE_SEQ: AtomicU64 = AtomicU64::new(0);

/// The production Mush setup, ready to wire into a lab.
///
/// The fixture holds the absolute path of the workspace `mush` binary
/// (runnable inside lab namespaces because they share the host
/// filesystem), a unique argv marker for process-hygiene sweeps, and
/// the `mush`/`ssh` PATH shims wrapper-mode tests need. It borrows
/// nothing from the [`SshFixture`] it is built against, but the paths it
/// captured die with that fixture's tempdir, so keep both alive.
pub struct MushFixture {
  dir: TempDir,
  mush_bin: PathBuf,
  ssh_config: PathBuf,
  user_key: PathBuf,
  known_hosts: PathBuf,
  marker: String,
}

impl MushFixture {
  /// Builds the fixture against `ssh`'s keys and configs. Wires the
  /// fixture's shim directory onto every remote session's PATH by adding
  /// a server-side `SetEnv` to the [`SshFixture`]'s sshd configuration,
  /// so construct the `MushFixture` before spawning sshd. A remote
  /// login-shell init file that assigns PATH wholesale still defeats it,
  /// as it would any non-interactive PATH expectation.
  pub fn new(ssh: &SshFixture) -> Result<Self> {
    Self::build(ssh, true)
  }

  /// [`new`](Self::new) without the remote PATH wiring: remote sessions
  /// cannot resolve a bare `mush`, simulating a host where `mush` is not
  /// installed on the non-interactive PATH. Sessions must then name the
  /// server by absolute path -- the wrapper's `--server=` override.
  /// The client-side shims ([`wrapper_path_env`](Self::wrapper_path_env))
  /// are unaffected.
  pub fn new_without_remote_mush(ssh: &SshFixture) -> Result<Self> {
    Self::build(ssh, false)
  }

  fn build(ssh: &SshFixture, remote_mush: bool) -> Result<Self> {
    let mush_bin = find_workspace_bin("mush")?;
    let nanos = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap_or_default()
      .subsec_nanos();
    let marker = format!(
      "mush-acc-{}-{}-{nanos}",
      std::process::id(),
      FIXTURE_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let dir = TempDir::with_prefix("mush-lab-mush-")?;

    // PATH shims for wrapper mode. `mush`: the default wrapper
    // invocation's remote command is a bare `mush server bootstrap`
    // that must resolve on the remote non-interactive PATH (put there
    // by `prepend_remote_path` below, unless the fixture simulates a
    // mush-less remote PATH); the shim execs the real binary and
    // appends the fixture marker, so wrapper-launched servers are
    // sweepable like every other one.
    // `ssh`: the wrapper and `mush connect` exec a bare `ssh`, which
    // without `-F` reads /etc/ssh/ssh_config.d includes -- root-owned
    // files that appear owned by `nobody` inside the lab's user
    // namespace and fail ssh's ownership check fatally. The shim
    // splices in the fixture config (`-F` also disables the system
    // config), standing in for a user's real ssh setup.
    let bin_dir = dir.path().join("bin");
    std::fs::create_dir(&bin_dir)?;
    let real_ssh = crate::which("ssh")
      .ok_or_else(|| anyhow::anyhow!("required binary `ssh` not found"))?;
    let shims = [
      (
        "mush",
        format!(
          "#!/bin/sh\nexec {} \"$@\" --marker {}\n",
          sq(&mush_bin.display().to_string()),
          sq(&marker)
        ),
      ),
      (
        "ssh",
        format!(
          "#!/bin/sh\nexec {} -F {} \"$@\"\n",
          sq(&real_ssh.display().to_string()),
          sq(&ssh.ssh_config().display().to_string())
        ),
      ),
    ];
    for (name, body) in shims {
      let shim = bin_dir.join(name);
      std::fs::write(&shim, body)?;
      let mut permissions = std::fs::metadata(&shim)?.permissions();
      use std::os::unix::fs::PermissionsExt as _;
      permissions.set_mode(0o755);
      std::fs::set_permissions(&shim, permissions)?;
    }
    if remote_mush {
      ssh.prepend_remote_path(&bin_dir)?;
    }

    Ok(Self {
      dir,
      mush_bin,
      ssh_config: ssh.ssh_config().to_path_buf(),
      user_key: ssh.user_key().to_path_buf(),
      known_hosts: ssh.known_hosts().to_path_buf(),
      marker,
    })
  }

  /// The workspace `mush` binary under test, by absolute path.
  pub fn mush_bin(&self) -> &Path {
    &self.mush_bin
  }

  /// The unique argv marker carried by every Mush server this fixture
  /// starts.
  pub fn marker(&self) -> &str {
    &self.marker
  }

  /// The default server remote command: the workspace binary by
  /// absolute path plus the hygiene marker. What the `proxy_command*`
  /// builders pass as `--server`, and what a wrapper invocation's
  /// `--server=` needs on a host without `mush` on the remote PATH.
  pub fn server_command(&self) -> String {
    format!(
      "{} server bootstrap --marker {}",
      self.mush_bin.display(),
      self.marker
    )
  }

  /// The `ProxyCommand` string for the outer ssh: the real
  /// `mush connect` with `--ssh` pointing at the fixture-configured ssh
  /// and `--server` at the `mush` binary by absolute path, plus the
  /// hygiene marker.
  pub fn proxy_command(&self) -> String {
    self.proxy_command_with(&[])
  }

  /// [`proxy_command`](Self::proxy_command) with extra `mush connect`
  /// arguments spliced in (e.g. `--no-fallback`).
  pub fn proxy_command_with(&self, connect_args: &[&str]) -> String {
    self.proxy_command_with_server(connect_args, &self.server_command())
  }

  /// [`proxy_command_with`](Self::proxy_command_with) with the
  /// `--server` remote command replaced outright (single-quoted as one
  /// word), for tests that hang or misconfigure the remote side. The
  /// default command's `--marker` goes with it, so a replacement must
  /// carry [`marker`](Self::marker) itself for the hygiene sweeps to
  /// see its processes.
  pub fn proxy_command_with_server(
    &self,
    connect_args: &[&str],
    server_command: &str,
  ) -> String {
    let mut cmd = format!(
      "{} connect --ssh {} --server {}",
      sq(&self.mush_bin.display().to_string()),
      sq(&format!("ssh -F {}", self.ssh_config.display())),
      sq(server_command),
    );
    for arg in connect_args {
      cmd.push(' ');
      cmd.push_str(&sq(arg));
    }
    cmd.push_str(" %r %h %p");
    cmd
  }

  /// ssh options (destination not included) routing a client through
  /// the Mush tunnel: the fixture config plus a ProxyCommand carrying
  /// the given `mush connect` arguments.
  pub fn ssh_opts_with(&self, connect_args: &[&str]) -> Vec<String> {
    self.ssh_opts_for(&self.proxy_command_with(connect_args))
  }

  /// [`ssh_opts_with`](Self::ssh_opts_with) around an arbitrary
  /// ProxyCommand string from one of the `proxy_command*` builders.
  ///
  /// The fixture config's `ConnectTimeout 5` also bounds the SSH banner
  /// exchange, which through Mush spans the bootstrap ssh, the QUIC
  /// dial budget (5s), and possibly the TCP fallback; the override here
  /// keeps slow establishment paths from being cut off partway through.
  pub fn ssh_opts_for(&self, proxy_command: &str) -> Vec<String> {
    vec![
      "-F".to_string(),
      self.ssh_config.display().to_string(),
      "-o".to_string(),
      format!("ProxyCommand={proxy_command}"),
      "-o".to_string(),
      "ConnectTimeout=30".to_string(),
    ]
  }

  /// Full outer-ssh arguments for `dest`; append the remote command.
  pub fn ssh_args(&self, dest: Ipv4Addr) -> Vec<String> {
    self.ssh_args_with(dest, &[])
  }

  /// [`ssh_args`](Self::ssh_args) with extra `mush connect` arguments.
  pub fn ssh_args_with(
    &self,
    dest: Ipv4Addr,
    connect_args: &[&str],
  ) -> Vec<String> {
    let mut args = self.ssh_opts_with(connect_args);
    args.push(dest.to_string());
    args
  }

  /// [`ssh_args_with`](Self::ssh_args_with) with extra `mush server
  /// bootstrap` arguments as well (e.g. `--retain`).
  pub fn ssh_args_with_args(
    &self,
    dest: Ipv4Addr,
    connect_args: &[&str],
    server_args: &[&str],
  ) -> Vec<String> {
    let mut server = self.server_command();
    for arg in server_args {
      server.push(' ');
      server.push_str(arg);
    }
    let mut args =
      self.ssh_opts_for(&self.proxy_command_with_server(connect_args, &server));
    args.push(dest.to_string());
    args
  }

  /// Arguments for wrapper mode (`mush <args> <dest> <command>`),
  /// invoked by the absolute binary path inside the client namespace.
  ///
  /// The wrapper forwards only `-i`/`-J`/`-o` to the bootstrap ssh (the
  /// design's fixed set) and not `-F`, so the bootstrap's auth arrives
  /// as forwarded flags: identity, known_hosts and strictness, batch
  /// mode. Without a `--server=` override the remote command is a bare
  /// `mush server bootstrap`, resolving through the shim directory
  /// [`new`](Self::new) put on every remote session's PATH (on a
  /// [`new_without_remote_mush`](Self::new_without_remote_mush) fixture,
  /// prepend a `--server=` argument such as
  /// [`server_command`](Self::server_command)). Spawn the wrapper with
  /// [`wrapper_path_env`](Self::wrapper_path_env) as `PATH` and `HOME`
  /// pointed somewhere without an `.ssh/`.
  pub fn wrapper_args(&self, dest: Ipv4Addr, command: &str) -> Vec<String> {
    vec![
      "-F".to_string(),
      self.ssh_config.display().to_string(),
      "-i".to_string(),
      self.user_key.display().to_string(),
      "-o".to_string(),
      format!("UserKnownHostsFile={}", self.known_hosts.display()),
      "-o".to_string(),
      "StrictHostKeyChecking=yes".to_string(),
      "-o".to_string(),
      "IdentitiesOnly=yes".to_string(),
      "-o".to_string(),
      "BatchMode=yes".to_string(),
      "-o".to_string(),
      "ConnectTimeout=30".to_string(),
      dest.to_string(),
      command.to_string(),
    ]
  }

  /// `PATH` for wrapper-mode invocations: the fixture bin directory
  /// first, so the bare `ssh` the wrapper and `mush connect` exec
  /// resolves to the fixture-config shim (see [`Self::new`]).
  pub fn wrapper_path_env(&self) -> std::ffi::OsString {
    let bin_dir = self.dir.path().join("bin");
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::join_paths(
      std::iter::once(bin_dir).chain(std::env::split_paths(&path)),
    )
    .expect("fixture paths contain no separator")
  }

  /// Whether any live process's argv carries this fixture's marker: the
  /// detached server always, plus the client-side processes (whose
  /// ProxyCommand and `--server` strings embed the marker) while a
  /// session runs.
  pub fn marked_process_exists(&self) -> bool {
    pgrep_matches(&self.marker)
  }

  /// Waits for every marker-carrying process to exit: after a clean
  /// session teardown the detached server must not linger. The failure
  /// lists the survivors' command lines.
  pub async fn wait_no_marked_processes(&self) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
      if !pgrep_matches(&self.marker) {
        return Ok(());
      }
      if tokio::time::Instant::now() > deadline {
        let listing = std::process::Command::new("pgrep")
          .args(["-af", &self.marker])
          .output()
          .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
          .unwrap_or_default();
        bail!("marked mush processes still alive after 30s:\n{listing}");
      }
      tokio::time::sleep(Duration::from_millis(100)).await;
    }
  }
}

impl Drop for MushFixture {
  fn drop(&mut self) {
    // Last resort only: topologies sweep their namespaces and tests wait
    // for marker exit; this catches early unwinds.
    let _ = std::process::Command::new("pkill")
      .args(["-KILL", "-f", &self.marker])
      .status();
  }
}

/// Whether any live process's argv contains `pattern`.
pub fn pgrep_matches(pattern: &str) -> bool {
  std::process::Command::new("pgrep")
    .args(["-f", pattern])
    .stdout(std::process::Stdio::null())
    .status()
    .is_ok_and(|status| status.success())
}
