// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Real OpenSSH inside lab hosts: keys, configs, sshd lifecycle, and
//! client invocation.
//!
//! Lab namespaces share the host filesystem, so keys and configs written
//! to a tempdir here are visible inside every lab node.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use patchbay::Device;
use tempfile::TempDir;

use crate::util::{harden_command, wait_tcp_ready};

/// Where sshd lives on common distros; `/usr/sbin` is usually not on user
/// `PATH`s.
pub(crate) fn find_sshd() -> Result<PathBuf> {
  for candidate in ["/usr/sbin/sshd", "/usr/bin/sshd"] {
    let p = PathBuf::from(candidate);
    if p.is_file() {
      return Ok(p);
    }
  }
  bail!("sshd not found at /usr/sbin/sshd or /usr/bin/sshd");
}

/// The real (init-namespace) uid and gid of this process.
///
/// The harness runs inside patchbay's single-uid user namespace, where
/// `getuid()` reports 0; the real ids are what uid 0 maps to in
/// `/proc/self/uid_map`. sshd must run as the real uid inside a nested
/// userns so its passwd lookups agree with the host's user database.
fn real_ids() -> Result<(u32, u32)> {
  fn mapped_root(path: &str) -> Option<u32> {
    let map = std::fs::read_to_string(path).ok()?;
    let mut fields = map.lines().next()?.split_whitespace();
    if fields.next()? != "0" {
      return None;
    }
    fields.next()?.parse().ok()
  }
  let uid = mapped_root("/proc/self/uid_map")
    .unwrap_or_else(|| unsafe { libc::getuid() });
  let gid = mapped_root("/proc/self/gid_map")
    .unwrap_or_else(|| unsafe { libc::getgid() });
  Ok((uid, gid))
}

/// The username for `uid` from the host's user database.
fn username_for(uid: u32) -> Result<String> {
  let out = std::process::Command::new("getent")
    .args(["passwd", &uid.to_string()])
    .output()
    .context("run getent")?;
  if out.status.success() {
    let line = String::from_utf8_lossy(&out.stdout);
    if let Some(name) = line.split(':').next()
      && !name.is_empty()
    {
      return Ok(name.to_string());
    }
  }
  std::env::var("USER")
    .or_else(|_| std::env::var("LOGNAME"))
    .context("cannot determine the current username")
}

/// Filesystem fixture for running real sshd/ssh inside a lab.
///
/// Holds a tempdir with an ed25519 host key, a client user key (also the
/// only authorized key), a minimal pubkey-only `sshd_config`, a batch-mode
/// `ssh_config`, and a `known_hosts` file that tests seed via
/// [`trust_host`](Self::trust_host). All ssh invocations authenticate as
/// the current (real) user, because sshd runs unprivileged inside a
/// nested user namespace mapped to that user.
pub struct SshFixture {
  dir: TempDir,
  sshd_path: PathBuf,
  sshd_config: PathBuf,
  ssh_config: PathBuf,
  known_hosts: PathBuf,
  uid: u32,
  gid: u32,
  /// The login user for every connection.
  pub user: String,
  /// The port every sshd listens on and every client dials.
  pub port: u16,
}

const SSH_PORT: u16 = 2222;

impl SshFixture {
  /// Generates keys and configs in a fresh tempdir.
  pub fn new() -> Result<Self> {
    let dir = TempDir::with_prefix("mush-lab-ssh-")?;
    let (uid, gid) = real_ids()?;
    let user = username_for(uid)?;
    let sshd_path = find_sshd()?;
    let port = SSH_PORT;

    let host_key = dir.path().join("host_ed25519");
    let user_key = dir.path().join("user_ed25519");
    for key in [&host_key, &user_key] {
      let status = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(key)
        .status()
        .context("run ssh-keygen")?;
      if !status.success() {
        bail!("ssh-keygen failed for {}", key.display());
      }
    }
    let authorized_keys = dir.path().join("authorized_keys");
    std::fs::copy(user_key.with_extension("pub"), &authorized_keys)?;

    // `internal-sftp` keeps sftp (and modern scp, which speaks SFTP)
    // working without depending on the host's sftp-server path.
    let sshd_config = dir.path().join("sshd_config");
    std::fs::write(
      &sshd_config,
      format!(
        "Port {port}\n\
         HostKey {host_key}\n\
         AuthorizedKeysFile {auth}\n\
         StrictModes no\n\
         PasswordAuthentication no\n\
         KbdInteractiveAuthentication no\n\
         PermitRootLogin prohibit-password\n\
         UsePAM no\n\
         PidFile none\n\
         LogLevel VERBOSE\n\
         Subsystem sftp internal-sftp\n",
        host_key = host_key.display(),
        auth = authorized_keys.display(),
      ),
    )?;

    let known_hosts = dir.path().join("known_hosts");
    std::fs::write(&known_hosts, "")?;

    let ssh_config = dir.path().join("ssh_config");
    std::fs::write(
      &ssh_config,
      format!(
        "Host *\n\
         \x20 User {user}\n\
         \x20 Port {port}\n\
         \x20 IdentityFile {key}\n\
         \x20 IdentitiesOnly yes\n\
         \x20 StrictHostKeyChecking yes\n\
         \x20 UserKnownHostsFile {kh}\n\
         \x20 GlobalKnownHostsFile /dev/null\n\
         \x20 BatchMode yes\n\
         \x20 ConnectTimeout 5\n",
        key = user_key.display(),
        kh = known_hosts.display(),
      ),
    )?;

    Ok(Self {
      dir,
      sshd_path,
      sshd_config,
      ssh_config,
      known_hosts,
      uid,
      gid,
      user,
      port,
    })
  }

  /// The fixture directory; its path is unique per fixture and appears in
  /// every spawned sshd's command line, which makes it a process marker
  /// for leak checks.
  pub fn dir(&self) -> &std::path::Path {
    self.dir.path()
  }

  /// The client-side `ssh_config`, for invocations built outside
  /// [`client_ssh_args`](Self::client_ssh_args) (scp, `mush connect`'s
  /// `--ssh`).
  pub fn ssh_config(&self) -> &std::path::Path {
    &self.ssh_config
  }

  /// The client user's private key: the only authorized key.
  pub fn user_key(&self) -> std::path::PathBuf {
    self.dir.path().join("user_ed25519")
  }

  /// The `known_hosts` file seeded by [`trust_host`](Self::trust_host).
  pub(crate) fn known_hosts(&self) -> &std::path::Path {
    &self.known_hosts
  }

  /// Puts `dir` first on the PATH of every remote session, via a
  /// server-side `SetEnv` in `sshd_config` (the client-side route cannot
  /// work: sshd stamps its default PATH over client-sent environment).
  /// The remaining entries are the standard system directories.
  /// Login-shell init files that rebuild PATH around the inherited value
  /// keep the entry; ones that assign wholesale defeat this, as they
  /// would any non-interactive PATH expectation.
  ///
  /// Takes effect only for sshds spawned afterwards; call before
  /// [`spawn_sshd`](Self::spawn_sshd).
  pub(crate) fn prepend_remote_path(
    &self,
    dir: &std::path::Path,
  ) -> Result<()> {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
      .append(true)
      .open(&self.sshd_config)?;
    writeln!(
      f,
      "SetEnv PATH={}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:\
       /sbin:/bin",
      dir.display()
    )?;
    Ok(())
  }

  /// Adds the fixture host key for `ip` to the client's `known_hosts`,
  /// so host key verification (StrictHostKeyChecking yes) passes for
  /// that address. Call for the dest and any jump host before
  /// connecting.
  pub fn trust_host(&self, ip: Ipv4Addr) -> Result<()> {
    use std::io::Write;
    let pubkey =
      std::fs::read_to_string(self.dir.path().join("host_ed25519.pub"))?;
    let mut f = std::fs::OpenOptions::new()
      .append(true)
      .open(&self.known_hosts)?;
    writeln!(f, "[{ip}]:{} {}", self.port, pubkey.trim_end())?;
    Ok(())
  }

  /// Launches sshd inside `dev`, unprivileged.
  ///
  /// sshd cannot run as uid 0 in patchbay's single-uid user namespace
  /// (its privilege-separation preflight rejects root-owned paths that
  /// appear owned by the overflow uid), so it runs inside a further
  /// nested user namespace mapped back to the real uid -- the non-privsep
  /// code path. Use [`SshServer::wait_ready`] before connecting.
  ///
  /// This sshd cannot allocate a PTY; see
  /// [`spawn_sshd_with_pty`](Self::spawn_sshd_with_pty).
  pub fn spawn_sshd(&self, dev: &Device) -> Result<SshServer> {
    self.spawn_sshd_inner(dev, false)
  }

  /// [`spawn_sshd`](Self::spawn_sshd) for a session that wants a PTY.
  ///
  /// The plain lab sshd cannot allocate one, and fails the whole
  /// session rather than the request when asked. The host's `/dev/pts`
  /// slaves carry the `tty` group, which is outside the single-gid
  /// mapping of the namespace sshd runs in, so `pty_setowner`'s
  /// `chown(pts, user, tty)` is refused and sshd treats that as fatal.
  ///
  /// Two ordinary unprivileged-container mounts in a namespace of sshd's
  /// own settle it, and nothing outside that namespace sees either: a
  /// private `devpts` instance whose slaves are created owned by the group
  /// the mapping does have, and an `/etc/group` with no `tty` entry, so
  /// sshd asks for the user's own group -- which is what the slaves
  /// already carry, and the chown is skipped.
  pub fn spawn_sshd_with_pty(&self, dev: &Device) -> Result<SshServer> {
    self.spawn_sshd_inner(dev, true)
  }

  fn spawn_sshd_inner(&self, dev: &Device, pty: bool) -> Result<SshServer> {
    let mut cmd = tokio::process::Command::new("unshare");
    cmd
      .arg("--user")
      .arg(format!("--map-user={}", self.uid))
      .arg(format!("--map-group={}", self.gid))
      .arg(&self.sshd_path)
      .args(["-D", "-e", "-f"])
      .arg(&self.sshd_config)
      // `-e` sends the log to stderr; stdout stays silent.
      .stdout(std::process::Stdio::null())
      .stderr(std::process::Stdio::piped());
    if pty {
      self.mount_pty_namespace(&mut cmd)?;
    }
    harden_command(&mut cmd);
    let mut child = dev.spawn_command(cmd)?;
    // sshd writes VERBOSE log lines to this pipe for its whole
    // lifetime, so it must be drained continuously: once the ~64KB pipe
    // buffer fills (on the order of 70 connections), sshd blocks
    // writing its log and every subsequent connection hangs mid-auth.
    // The drain also preserves the log for wait_ready's diagnostics.
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut stderr = child.stderr.take().context("sshd stderr piped")?;
    let sink = Arc::clone(&log);
    dev.spawn(move |_| async move {
      use tokio::io::AsyncReadExt as _;
      let mut buf = [0u8; 8192];
      loop {
        match stderr.read(&mut buf).await {
          Ok(0) | Err(_) => break,
          Ok(n) => {
            sink.lock().expect("poisoned").extend_from_slice(&buf[..n]);
          }
        }
      }
    })?;
    Ok(SshServer {
      child,
      port: self.port,
      log,
    })
  }

  /// Arranges the mount namespace
  /// [`spawn_sshd_with_pty`](Self::spawn_sshd_with_pty) describes,
  /// between fork and exec so it belongs to that sshd alone.
  ///
  /// Every string the closure needs is built here, before the fork: a
  /// child between fork and exec may only make syscalls, and the
  /// namespace has to exist before `unshare` drops into the nested
  /// user namespace, where the mounts would need privileges it does
  /// not have.
  fn mount_pty_namespace(
    &self,
    cmd: &mut tokio::process::Command,
  ) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let group = self.dir.path().join("group");
    let source = std::fs::read_to_string("/etc/group")
      .context("reading /etc/group to hide its tty entry")?;
    std::fs::write(
      &group,
      source
        .lines()
        .filter(|line| !line.starts_with("tty:"))
        .fold(String::new(), |mut text, line| {
          text.push_str(line);
          text.push('\n');
          text
        }),
    )?;

    let root = CString::new("/")?;
    let devpts = CString::new("devpts")?;
    let pts = CString::new("/dev/pts")?;
    // The slaves' group is this namespace's own, which is the one the
    // nested user namespace maps; `gid=5` (the host's `tty`) is not
    // expressible there.
    let options = CString::new(format!(
      "newinstance,gid={},mode=620,ptmxmode=666",
      unsafe { libc::getgid() }
    ))?;
    let group_source = CString::new(group.as_os_str().as_bytes())?;
    let group_target = CString::new("/etc/group")?;
    let empty = CString::new("")?;

    // SAFETY: the closure runs between fork and exec and makes only
    // syscalls on buffers that outlive it.
    unsafe {
      cmd.pre_exec(move || {
        if libc::unshare(libc::CLONE_NEWNS) != 0 {
          return Err(std::io::Error::last_os_error());
        }
        // Private propagation, or the mounts below escape into the
        // namespace the harness itself runs in.
        if libc::mount(
          std::ptr::null(),
          root.as_ptr(),
          std::ptr::null(),
          libc::MS_REC | libc::MS_PRIVATE,
          std::ptr::null(),
        ) != 0
        {
          return Err(std::io::Error::last_os_error());
        }
        if libc::mount(
          devpts.as_ptr(),
          pts.as_ptr(),
          devpts.as_ptr(),
          0,
          options.as_ptr().cast(),
        ) != 0
        {
          return Err(std::io::Error::last_os_error());
        }
        if libc::mount(
          group_source.as_ptr(),
          group_target.as_ptr(),
          empty.as_ptr(),
          libc::MS_BIND,
          std::ptr::null(),
        ) != 0
        {
          return Err(std::io::Error::last_os_error());
        }
        Ok(())
      });
    }
    Ok(())
  }

  /// Client arguments for connecting to `dest`: `-F <config>` plus the
  /// destination. Append the remote command yourself.
  pub fn client_ssh_args(&self, dest: Ipv4Addr) -> Vec<String> {
    vec![
      "-F".to_string(),
      self.ssh_config.display().to_string(),
      dest.to_string(),
    ]
  }

  /// Like [`client_ssh_args`](Self::client_ssh_args), routed through
  /// `jump` with `-J`.
  pub fn client_ssh_args_via_jump(
    &self,
    dest: Ipv4Addr,
    jump: Ipv4Addr,
  ) -> Vec<String> {
    vec![
      "-F".to_string(),
      self.ssh_config.display().to_string(),
      "-J".to_string(),
      format!("{}@{jump}:{}", self.user, self.port),
      dest.to_string(),
    ]
  }

  /// Runs `ssh <args> -- <command>` from inside `from`'s namespace and
  /// captures the result. `args` comes from
  /// [`client_ssh_args`](Self::client_ssh_args) or
  /// [`client_ssh_args_via_jump`](Self::client_ssh_args_via_jump).
  pub async fn ssh_exec(
    &self,
    from: &Device,
    args: &[String],
    command: &str,
  ) -> Result<SshOutput> {
    let mut cmd = tokio::process::Command::new("ssh");
    cmd
      .args(args)
      .arg(command)
      .stdout(std::process::Stdio::piped())
      .stderr(std::process::Stdio::piped());
    harden_command(&mut cmd);
    let child = from.spawn_command(cmd)?;
    let out = child.wait_with_output().await?;
    Ok(SshOutput {
      success: out.status.success(),
      code: out.status.code(),
      stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
      stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
  }
}

/// Captured result of one ssh invocation.
pub struct SshOutput {
  pub success: bool,
  /// The exit code, `None` when killed by a signal. ssh exits with the
  /// remote command's status, so this is how exit propagation is
  /// asserted.
  pub code: Option<i32>,
  pub stdout: String,
  pub stderr: String,
}

/// A running sshd inside a lab host. Killed on drop.
pub struct SshServer {
  child: tokio::process::Child,
  port: u16,
  /// The continuously drained sshd log (stderr), for diagnostics.
  log: Arc<Mutex<Vec<u8>>>,
}

impl SshServer {
  /// Waits until this sshd accepts TCP connects at `ip` as observed from
  /// inside `from`'s namespace, polling with a deadline. Liveness is
  /// checked alongside readiness, so an sshd that dies (a config error at
  /// startup, a crash between polls) fails immediately with its captured
  /// stderr instead of using up the whole deadline first.
  pub async fn wait_ready(
    &mut self,
    from: &Device,
    ip: Ipv4Addr,
    timeout: Duration,
  ) -> Result<()> {
    let addr = SocketAddr::new(ip.into(), self.port);
    let ready = wait_tcp_ready(from, addr, timeout);
    tokio::pin!(ready);
    let mut liveness = tokio::time::interval(Duration::from_millis(100));
    loop {
      tokio::select! {
        r = &mut ready => return r,
        _ = liveness.tick() => {
          if let Some(status) = self.child.try_wait()? {
            // Give the drain task a moment to consume the final log bytes.
            tokio::time::sleep(Duration::from_millis(100)).await;
            let stderr = String::from_utf8_lossy(
              &self.log.lock().expect("poisoned"),
            )
            .into_owned();
            bail!(
              "sshd exited ({status}) before accepting connections: {stderr}"
            );
          }
        }
      }
    }
  }
}
