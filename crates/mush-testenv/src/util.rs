// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Small helpers the lab tests keep needing: process hygiene, deadline
//! polling, and UDP observability primitives.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use patchbay::{Device, Router};

/// Configures `cmd` so the child cannot outlive the harness.
///
/// Children spawned inside lab namespaces are not killed by lab teardown on
/// their own (they reparent to init and keep the netns alive). Two proven
/// mitigations, both applied: tokio's kill-on-drop, and
/// `PR_SET_PDEATHSIG(SIGKILL)`, which fires when the spawning namespace
/// worker thread exits -- covering lab drop and SIGKILL of the test process
/// alike. Every command handed to `spawn_command` must pass through here.
///
/// Both mechanisms cover only the direct child. Grandchildren -- an sshd
/// session tree, a detached server -- inherit neither, which is why every
/// topology also sweeps its namespaces at drop (see [`procs_in_netns`]).
pub fn harden_command(cmd: &mut tokio::process::Command) {
  cmd.kill_on_drop(true);
  unsafe {
    cmd.pre_exec(|| {
      if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
        return Err(std::io::Error::last_os_error());
      }
      Ok(())
    });
  }
}

/// Polls `check` every `interval` until it returns true, failing with a
/// message naming `what` once `timeout` elapses. Never sleeps past the
/// deadline; the first check runs immediately.
pub async fn poll_until<F, Fut>(
  what: &str,
  timeout: Duration,
  interval: Duration,
  mut check: F,
) -> Result<()>
where
  F: FnMut() -> Fut,
  Fut: Future<Output = bool>,
{
  let deadline = tokio::time::Instant::now() + timeout;
  loop {
    if check().await {
      return Ok(());
    }
    if tokio::time::Instant::now() + interval > deadline {
      bail!("timed out after {timeout:?} waiting for {what}");
    }
    tokio::time::sleep(interval).await;
  }
}

/// Waits until a TCP connect to `addr` succeeds from inside `dev`'s
/// namespace, polling up to `timeout`.
///
/// Each connect attempt is individually capped: on paths that silently
/// drop SYNs (nftables `drop`, the shape every firewalled preset uses) an
/// unbounded connect would keep retrying on the kernel's SYN-retransmit
/// cycle until minutes past the deadline.
pub async fn wait_tcp_ready(
  dev: &Device,
  addr: SocketAddr,
  timeout: Duration,
) -> Result<()> {
  let name = dev.name().to_string();
  let jh = dev.spawn(move |_| async move {
    let interval = Duration::from_millis(100);
    let deadline = tokio::time::Instant::now() + timeout;
    poll_until(
      &format!("tcp {addr} reachable from {name}"),
      timeout,
      interval,
      || async {
        let cap = interval
          .min(deadline.saturating_duration_since(tokio::time::Instant::now()));
        tokio::time::timeout(cap, tokio::net::TcpStream::connect(addr))
          .await
          .is_ok_and(|r| r.is_ok())
      },
    )
    .await
  })?;
  jh.await?
}

/// One query against a patchbay reflector (`Device::spawn_reflector` /
/// `Router::spawn_reflector`) from inside `dev`, from an ephemeral socket:
/// returns the source address the reflector observed. Retries `attempts`
/// times with `per_try` timeout each; errors when every attempt times out
/// (e.g. the path is blackholed).
pub async fn query_reflector(
  dev: &Device,
  target: SocketAddr,
  attempts: usize,
  per_try: Duration,
) -> Result<SocketAddr> {
  let jh = dev.spawn(move |_| async move {
    let sock = tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await?;
    let mut buf = [0u8; 2048];
    for _ in 0..attempts {
      sock.send_to(b"PROBE", target).await?;
      match tokio::time::timeout(per_try, sock.recv_from(&mut buf)).await {
        Ok(Ok((n, src))) if src == target => {
          return parse_observed(&buf[..n]);
        }
        Ok(Ok(_)) => continue, // stray datagram
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => continue, // timeout, retry
      }
    }
    bail!("no reply from {target} after {attempts} attempts")
  })?;
  jh.await?
}

/// Parses a reflector's `OBSERVED <addr>` reply.
fn parse_observed(reply: &[u8]) -> Result<SocketAddr> {
  let s = std::str::from_utf8(reply).context("non-UTF-8 reply")?;
  let rest = s
    .strip_prefix("OBSERVED ")
    .ok_or_else(|| anyhow!("unexpected reply {s:?}"))?;
  let addr = rest.split_whitespace().next().unwrap_or(rest);
  Ok(addr.parse()?)
}

/// The netns inode of the calling thread. Run inside a lab node's
/// namespace (via `run_sync`) to learn that node's netns identity;
/// `/proc/<pid>/ns/net` comparisons against it find every process still
/// inside the namespace.
pub(crate) fn current_netns_inode() -> Result<u64> {
  use std::os::unix::fs::MetadataExt;
  Ok(std::fs::metadata("/proc/thread-self/ns/net")?.ino())
}

/// Pids of processes, other than the calling one, whose network namespace
/// is one of `inodes`. Processes we cannot inspect (other users') are
/// skipped; every process a lab spawns is ours.
pub fn procs_in_netns(inodes: &[u64]) -> Vec<u32> {
  use std::os::unix::fs::MetadataExt;
  let self_pid = std::process::id();
  let mut pids = Vec::new();
  let Ok(entries) = std::fs::read_dir("/proc") else {
    return pids;
  };
  for entry in entries.flatten() {
    let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
      continue;
    };
    if pid == self_pid {
      continue;
    }
    // A process that already exited (zombie or racing away) has no live
    // ns links; metadata failure means it is not holding the namespace.
    let Ok(meta) = std::fs::metadata(entry.path().join("ns/net")) else {
      continue;
    };
    if inodes.contains(&meta.ino()) {
      pids.push(pid);
    }
  }
  pids
}

/// SIGKILLs every process still inside the given lab namespaces and
/// waits for them to disappear. This is the last-resort cleanup
/// [`harden_command`] cannot be: kill-on-drop and PDEATHSIG cover direct
/// children only, and an sshd session tree is grandchildren with no
/// marker in argv to find them by. Detached Mush servers do carry the
/// fixture's marker, but the sweep catches them without needing it.
/// Runs from every topology's `Drop`.
pub(crate) fn sweep_netns(inodes: &[u64]) {
  let deadline = std::time::Instant::now() + Duration::from_secs(5);
  loop {
    let pids = procs_in_netns(inodes);
    if pids.is_empty() {
      return;
    }
    for &pid in &pids {
      unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
      }
    }
    if std::time::Instant::now() > deadline {
      eprintln!("mush-testenv: processes survived the netns sweep: {pids:?}");
      return;
    }
    std::thread::sleep(Duration::from_millis(20));
  }
}

/// A NAT/firewall observation from a single client socket.
///
/// [`NatProbe::start`] binds one UDP socket to `local_port` inside `dev`,
/// queries each target (a patchbay reflector) in order, and records the
/// observed (mapped) source address per target in `mapped`. The socket
/// stays bound and listening, so a test can send unsolicited traffic at a
/// mapped address and ask [`NatProbe::unsolicited`] whether the NAT
/// delivered it.
pub struct NatProbe {
  /// Observed source address per target, in target order.
  pub mapped: Vec<SocketAddr>,
  window: tokio::task::JoinHandle<Result<Option<(SocketAddr, String)>>>,
}

impl NatProbe {
  /// Runs the probe phase and returns once every target has answered.
  /// The listen window for unsolicited traffic starts immediately and
  /// lasts `window`.
  pub async fn start(
    dev: &Device,
    local_port: u16,
    targets: Vec<SocketAddr>,
    window: Duration,
  ) -> Result<NatProbe> {
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let jh = dev.spawn(move |_| async move {
      let sock = tokio::net::UdpSocket::bind(("0.0.0.0", local_port))
        .await
        .context("probe bind")?;
      let mut buf = [0u8; 2048];
      let mut mapped = Vec::new();
      for &target in &targets {
        let mut got = None;
        'attempt: for _ in 0..5 {
          sock.send_to(b"PROBE", target).await?;
          loop {
            match tokio::time::timeout(
              Duration::from_millis(500),
              sock.recv_from(&mut buf),
            )
            .await
            {
              Ok(Ok((n, src))) => {
                if src != target {
                  continue; // stray datagram while probing
                }
                got = Some(parse_observed(&buf[..n])?);
                break 'attempt;
              }
              Ok(Err(e)) => return Err(e.into()),
              Err(_) => break, // per-attempt timeout, resend
            }
          }
        }
        mapped
          .push(got.ok_or_else(|| anyhow!("no reply from target {target}"))?);
      }
      let _ = ready_tx.send(mapped);

      // Listen window: report the first datagram from a non-target source.
      let deadline = tokio::time::Instant::now() + window;
      loop {
        match tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await
        {
          Ok(Ok((n, src))) => {
            if targets.contains(&src) {
              continue; // duplicate reply from a target
            }
            return Ok(Some((
              src,
              String::from_utf8_lossy(&buf[..n]).into_owned(),
            )));
          }
          Ok(Err(e)) => return Err(e.into()),
          Err(_) => return Ok(None),
        }
      }
    })?;
    match ready_rx.await {
      Ok(mapped) => Ok(NatProbe { mapped, window: jh }),
      // The task failed before reporting; surface its real error.
      Err(_) => match jh.await {
        Ok(Ok(_)) => bail!("probe ended without reporting mappings"),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(anyhow!("probe task failed: {e}")),
      },
    }
  }

  /// Waits out the listen window; returns the first unsolicited datagram
  /// (source address and payload) delivered to the probe socket, if any.
  pub async fn unsolicited(self) -> Result<Option<(SocketAddr, String)>> {
    self.window.await?
  }
}

/// A TCP echo server running inside a lab node; the task is aborted on
/// drop.
pub struct TcpEchoGuard {
  task: tokio::task::JoinHandle<()>,
}

impl Drop for TcpEchoGuard {
  fn drop(&mut self) {
    self.task.abort();
  }
}

/// Spawns a TCP echo server bound to `addr` inside `dev`'s namespace:
/// every accepted connection is echoed byte for byte, with the client's
/// EOF mapped through as a write-side shutdown. Returns once the
/// listener is bound.
pub async fn spawn_tcp_echo(
  dev: &Device,
  addr: SocketAddr,
) -> Result<TcpEchoGuard> {
  let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
  let task = dev.spawn(move |_| async move {
    let listener = match tokio::net::TcpListener::bind(addr).await {
      Ok(listener) => listener,
      Err(error) => {
        let _ = ready_tx.send(Err(error));
        return;
      }
    };
    let _ = ready_tx.send(Ok(()));
    loop {
      let Ok((mut socket, _)) = listener.accept().await else {
        return;
      };
      tokio::spawn(async move {
        use tokio::io::AsyncWriteExt as _;
        let _ = socket.set_nodelay(true);
        let (mut read, mut write) = socket.split();
        let _ = tokio::io::copy(&mut read, &mut write).await;
        let _ = write.shutdown().await;
      });
    }
  })?;
  ready_rx
    .await
    .context("tcp echo task ended before binding")?
    .with_context(|| format!("binding tcp echo at {addr}"))?;
  Ok(TcpEchoGuard { task })
}

/// Drops every inbound UDP datagram inside `dev`'s namespace with a raw
/// nftables table, leaving TCP untouched: the "UDP blocked, ssh port
/// open" shape the design's TCP fallback exists for. The rules live in
/// the device's own namespace, so they die with the topology.
pub fn block_inbound_udp(dev: &Device) -> Result<()> {
  apply_nft(
    dev,
    "table inet mush_udp_block {\n\
     \x20 chain input {\n\
     \x20   type filter hook input priority filter; policy accept;\n\
     \x20   meta l4proto udp drop\n\
     \x20 }\n\
     }\n"
      .to_string(),
  )
}

/// Drops inbound TCP inside `dev`'s namespace except from `allow`,
/// leaving UDP untouched: the "ssh policy says bastion, UDP is open"
/// shape Mush's direct candidates exist for.
///
/// Loopback is exempt, which the tunnel needs -- the Mush server relays
/// into sshd over `127.0.0.1` -- and no conntrack state is consulted,
/// so the rule holds identically wherever the harness runs.
pub fn restrict_inbound_tcp(dev: &Device, allow: Ipv4Addr) -> Result<()> {
  apply_nft(
    dev,
    format!(
      "table inet mush_tcp_policy {{\n\
       \x20 chain input {{\n\
       \x20   type filter hook input priority filter; policy accept;\n\
       \x20   iif lo accept\n\
       \x20   ip saddr {allow} accept\n\
       \x20   meta l4proto tcp drop\n\
       \x20 }}\n\
       }}\n"
    ),
  )
}

/// Blackholes inbound UDP addressed to `addr` inside `dev`'s namespace,
/// leaving the host's other addresses reachable: one candidate of a
/// multi-homed destination stops answering UDP while the rest keep answering.
pub fn blackhole_udp_to(dev: &Device, addr: Ipv4Addr) -> Result<()> {
  apply_nft(
    dev,
    format!(
      "table inet mush_udp_blackhole {{\n\
       \x20 chain input {{\n\
       \x20   type filter hook input priority filter; policy accept;\n\
       \x20   ip daddr {addr} meta l4proto udp drop\n\
       \x20 }}\n\
       }}\n"
    ),
  )
}

/// Drops inbound UDP from `addr` inside `dev`'s namespace, leaving
/// everything else reachable: UDP from one peer stops arriving while UDP
/// from the bastion between them does not, which is the shape that
/// leaves a session on the relay with a direct path still to be found.
pub fn block_udp_from(dev: &Device, addr: Ipv4Addr) -> Result<()> {
  apply_nft(
    dev,
    format!(
      "table inet mush_udp_peer {{\n\
       \x20 chain input {{\n\
       \x20   type filter hook input priority filter; policy accept;\n\
       \x20   ip saddr {addr} meta l4proto udp drop\n\
       \x20 }}\n\
       }}\n"
    ),
  )
}

/// Removes what [`block_udp_from`] installed, whether or not it is
/// there: the network change that lets a punch finally succeed.
pub fn unblock_udp_from(dev: &Device) -> Result<()> {
  apply_nft(
    dev,
    "table inet mush_udp_peer {}\n\
     delete table inet mush_udp_peer\n"
      .to_string(),
  )
}

/// Loads `ruleset` into `dev`'s own network namespace, where it dies
/// with the topology.
fn apply_nft(dev: &Device, ruleset: String) -> Result<()> {
  let nft = crate::which("nft")
    .ok_or_else(|| anyhow!("required binary `nft` not found"))?;
  dev.run_sync(move || {
    use std::io::Write as _;
    let mut child = std::process::Command::new(&nft)
      .args(["-f", "-"])
      .stdin(std::process::Stdio::piped())
      .spawn()
      .context("spawning nft")?;
    child
      .stdin
      .as_mut()
      .expect("stdin is piped")
      .write_all(ruleset.as_bytes())
      .context("writing the nft ruleset")?;
    let status = child.wait().context("waiting for nft")?;
    if !status.success() {
      bail!("nft failed with {status}");
    }
    Ok(())
  })
}

/// Sends `count` copies of `payload` from inside router `from`'s namespace
/// to `target`, `gap` apart. The source is the router's own address:
/// combined with a router the probe never contacted, this is the
/// third-party sender for inbound-filtering checks.
pub async fn udp_burst(
  from: &Router,
  target: SocketAddr,
  payload: &str,
  count: usize,
  gap: Duration,
) -> Result<()> {
  let payload = payload.to_string();
  let jh = from.spawn(move |_| async move {
    let sock = tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await?;
    for _ in 0..count {
      sock.send_to(payload.as_bytes(), target).await?;
      tokio::time::sleep(gap).await;
    }
    anyhow::Ok(())
  })?;
  jh.await?
}

/// Relaxes reverse-path filtering to loose mode inside a multi-homed
/// device's namespace. Strict rp_filter is inherited from the host sysctl
/// configuration and silently drops asymmetric flows (requests in one
/// interface, replies out another), so every dual-homed device must do
/// this to stay host-independent.
pub(crate) fn loosen_rp_filter(dev: &Device, ifaces: &[&str]) -> Result<()> {
  let names: Vec<String> = ["all"]
    .into_iter()
    .chain(ifaces.iter().copied())
    .map(String::from)
    .collect();
  dev.run_sync(move || {
    for name in &names {
      std::fs::write(format!("/proc/sys/net/ipv4/conf/{name}/rp_filter"), "2")?;
    }
    Ok(())
  })
}
