// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! S2 performance comparison: Mush versus raw ssh, same lab, same sshd,
//! same netem path, only the transport differing. Every metric
//! interleaves the transports A/B, discards a warmup, and reports median
//! and spread (full samples where variance is high); Mush always runs
//! `--no-fallback`, so a TCP fallback can never masquerade as QUIC
//! numbers. The scenarios are the `scenario_*` functions below.
//!
//! The harness verifies its own lab rather than trusting it -- qdisc
//! readback, a timed RTT probe, and for the lossy scenarios an audit of
//! the loss each transport actually experienced -- and refuses to report
//! numbers when the lab is not what the scenario asked for.
//!
//! A manual measurement harness, not a correctness check: it asserts only
//! mechanics (sessions succeed, bytes match, the lab is what the
//! scenario says, the machine is quiet), never a performance threshold.
//! Runs only under the nextest `perf` profile, never in the default or
//! `lab` profiles and never in CI. `docs/testing.md` has the invocation
//! and the settings (`MUSH_PERF_DIR`, `MUSH_PERF_SCENARIOS`,
//! `MUSH_PERF_REPS`, `MUSH_PERF_LOSSY_REPS`, `MUSH_PERF_RECOVERY_REPS`).

#![cfg(target_os = "linux")]

use std::fmt::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use mush_testenv::patchbay::{Device, LinkCondition, LinkDirection, Router};
use mush_testenv::{MushFixture, SshFixture, SshServer, Topology, direct};
use serde_json::{Value, json};
use tokio::io::{
  AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader,
};
use tokio::process::{Child, Command};

mod common;

use common::{READY, drain, pseudo_bytes};

mush_testenv::userns_bootstrap!();

/// Timeout for one bulk transfer. The slowest expected case (a few MiB
/// over TCP at 2% per-packet loss and 40ms RTT) is loss-bound to well
/// under a minute; anything reaching this is hung.
const TRANSFER_DEADLINE: Duration = Duration::from_secs(900);

/// Timeout for one trivial-exec establishment measurement.
const EXEC_DEADLINE: Duration = Duration::from_secs(60);

/// Timeout for one echoed line.
const LINE_DEADLINE: Duration = Duration::from_secs(30);

/// Timeout for post-outage recovery before the rep fails. Must clear the
/// longest swept outage's TCP retransmit backoff alignment (a 30s
/// outage can delay TCP's next probe to tens of seconds past restore).
const RECOVERY_DEADLINE: Duration = Duration::from_secs(120);

/// The blackhole lengths the recovery scenario sweeps, with the metric
/// name for each.
///
/// The sweep exists for the ssh column: kernel TCP backs its
/// retransmits off further the longer an outage runs, so where in that
/// cycle restore happens sets the recovery latency, and one outage length
/// would hide the structure. Mush replaced that with the prober's fixed
/// cadence (`mush_core::roaming`), so its distribution is over the probe
/// phase within one probe interval and does not widen with outage
/// length -- which the sweep shows by putting the two side by side.
const OUTAGES: [(u64, &str); 3] = [
  (5, "restore-to-first-byte-5s"),
  (10, "restore-to-first-byte-10s"),
  (30, "restore-to-first-byte-30s"),
];

/// The outage length also measured on a session the client is writing
/// into. The rest of the sweep drops the client's stdin, the one traffic
/// shape where the prober's probe can never be congestion-blocked; the
/// longest outage is where a client with data outstanding has had time
/// to fill the window.
const CLIENT_SENDING_OUTAGE: (u64, &str) =
  (30, "restore-to-first-byte-30s-client-sending");

/// Interactive echo shape: interleaved sessions per transport, each
/// discarding the first lines (establishment and window growth) and
/// timing the rest.
const ECHO_SESSIONS: usize = 5;
const ECHO_WARMUP_LINES: usize = 10;
const ECHO_TIMED_LINES: usize = 100;

const MIB: usize = 1024 * 1024;

fn env_reps(var: &str, default: usize) -> usize {
  std::env::var(var)
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(default)
}

/// Timed repetitions per clean/WAN metric (a warmup pair on top is
/// discarded). Below 5 the spread is meaningless; `MUSH_PERF_REPS` can
/// raise it.
fn reps() -> usize {
  env_reps("MUSH_PERF_REPS", 5)
}

/// Timed repetitions for the lossy scenarios. Loss-bound transfer times
/// are strongly multi-modal (which packets are lost sets a rep's wall
/// time), so a median needs far more reps than the clean metrics do.
fn lossy_reps() -> usize {
  env_reps("MUSH_PERF_LOSSY_REPS", 15)
}

/// Timed repetitions per recovery outage length. Recovery latency is a
/// distribution either way (see [`OUTAGES`]), and small n samples only a
/// small part of it.
fn recovery_reps() -> usize {
  env_reps("MUSH_PERF_RECOVERY_REPS", 12)
}

/// Whether `name` is selected by `MUSH_PERF_SCENARIOS` (comma-separated;
/// unset means all).
fn scenario_enabled(name: &str) -> bool {
  match std::env::var("MUSH_PERF_SCENARIOS") {
    Err(_) => true,
    Ok(list) => list.split(',').any(|s| s.trim() == name),
  }
}

/// Where the JSON results file goes: `MUSH_PERF_DIR`, else a
/// `mush-perf-results` directory under the system temp dir.
fn results_dir() -> PathBuf {
  std::env::var_os("MUSH_PERF_DIR")
    .map(PathBuf::from)
    .unwrap_or_else(|| std::env::temp_dir().join("mush-perf-results"))
}

fn load1() -> Result<f64> {
  let s = std::fs::read_to_string("/proc/loadavg")?;
  s.split_whitespace()
    .next()
    .context("empty /proc/loadavg")?
    .parse()
    .context("parsing the load average")
}

/// Refuses to measure on a busy machine, waiting first for the 1-minute
/// load average to decay: a just-finished compile keeps it elevated.
async fn ensure_quiet(scenario: &str) -> Result<()> {
  const LIMIT: f64 = 4.0;
  let deadline = Instant::now() + Duration::from_secs(180);
  loop {
    let load = load1()?;
    if load <= LIMIT {
      return Ok(());
    }
    if Instant::now() >= deadline {
      bail!(
        "machine is loaded before the {scenario} scenario (load1 \
         {load:.2} > {LIMIT}); refusing to measure under load"
      );
    }
    eprintln!("waiting for load to settle before {scenario}: load1 {load:.2}");
    tokio::time::sleep(Duration::from_secs(5)).await;
  }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Transport {
  Ssh,
  Mush,
}

impl Transport {
  fn name(self) -> &'static str {
    match self {
      Transport::Ssh => "ssh",
      Transport::Mush => "mush",
    }
  }
}

/// A/B interleave order for repetition `rep`: alternates which transport
/// goes first, so drift affects both symmetrically.
fn order(rep: usize) -> [Transport; 2] {
  if rep.is_multiple_of(2) {
    [Transport::Ssh, Transport::Mush]
  } else {
    [Transport::Mush, Transport::Ssh]
  }
}

/// One assembled perf lab: the `direct` topology with a ready sshd on
/// the dest, the Mush fixture pointing at it, and the scenario's link
/// condition applied and verified.
struct Lab {
  topo: Topology,
  fix: SshFixture,
  mush: MushFixture,
  dest_ip: Ipv4Addr,
  _sshd: SshServer,
}

/// Builds the lab with no link condition yet.
async fn build_lab() -> Result<Lab> {
  let topo = direct().await?;
  let dest_ip = topo.dest_ip()?;
  let fix = SshFixture::new()?;
  fix.trust_host(dest_ip)?;
  let mush = MushFixture::new(&fix)?;
  let mut sshd = fix.spawn_sshd(&topo.dest)?;
  sshd.wait_ready(&topo.client, dest_ip, READY).await?;
  Ok(Lab {
    topo,
    fix,
    mush,
    dest_ip,
    _sshd: sshd,
  })
}

/// A clean or delay-shaped lab: the condition (if any) goes on the
/// client's interface in both directions -- the one path both transports
/// traverse -- then is verified by qdisc readback and a timed connect.
async fn perf_lab(cond: Option<LinkCondition>) -> Result<Lab> {
  let lab = build_lab().await?;
  if let Some(cond) = cond {
    lab
      .client_iface()?
      .set_condition(cond, LinkDirection::Both)
      .await?;
    // Egress netem lives on the client's own interface, ingress on the
    // gateway router's peer veth; read both back.
    let egress = netem_stats(dev_qdisc_show(&lab.topo.client, "eth0").await?)
      .context("client egress netem missing after set_condition")?;
    expect_netem(&egress, cond)?;
    let ingress =
      netem_stats(router_qdisc_show(&lab.topo.client_net).await?)
        .context("client ingress netem missing after set_condition")?;
    expect_netem(&ingress, cond)?;
  }
  verify_path_rtt(&lab, cond).await?;
  Ok(lab)
}

/// A lossy-WAN lab. The loss condition is deliberately NOT applied on
/// the client's own interface: netem drops whole skbs, TCP and UDP-GSO
/// stacks hand the local qdisc multi-packet super-skbs whatever the
/// device offload settings (segmentation happens after the qdisc), and
/// veths pass those to the peer namespace intact, so a netem on the
/// sender's device would apply loss per ~40-packet batch: a far milder,
/// transport-dependent process than the nominal per-packet rate.
/// Instead: segmentation offloads off on both endpoints' interfaces,
/// forcing per-MTU packets onto the wire at the first hop, and the
/// condition applied ingress-side on both, putting each direction's
/// netem on a router veth carrying only forwarded, already-segmented
/// traffic (GRO is off on veths by default, so nothing re-aggregates).
/// The loss audit at the end of the scenario confirms the effective
/// per-packet rate.
async fn perf_lab_lossy(cond: LinkCondition) -> Result<Lab> {
  let lab = build_lab().await?;
  disable_offloads(&lab.topo.client).await?;
  disable_offloads(&lab.topo.dest).await?;
  lab
    .client_iface()?
    .set_condition(cond, LinkDirection::Ingress)
    .await?;
  lab
    .topo
    .dest
    .iface("eth0")
    .context("dest eth0")?
    .set_condition(cond, LinkDirection::Ingress)
    .await?;
  for router in [&lab.topo.client_net, &lab.topo.dest_net] {
    let stats = netem_stats(router_qdisc_show(router).await?)
      .with_context(|| format!("netem missing in router {}", router.name()))?;
    expect_netem(&stats, cond)?;
  }
  // Placement check: the client's own egress must stay unimpaired.
  ensure!(
    !dev_qdisc_show(&lab.topo.client, "eth0")
      .await?
      .contains("netem"),
    "unexpected netem on the client's egress in the lossy lab"
  );
  verify_path_rtt(&lab, Some(cond)).await?;
  Ok(lab)
}

impl Lab {
  /// Outer-ssh options for one transport. Both share the fixture config
  /// (same cipher defaults, same keys, same sshd); the only difference
  /// is the injected ProxyCommand, with Mush pinned `--no-fallback`.
  fn ssh_opts(&self, transport: Transport) -> Vec<String> {
    match transport {
      Transport::Ssh => vec![
        "-F".to_string(),
        self.fix.ssh_config().display().to_string(),
        "-o".to_string(),
        "ConnectTimeout=30".to_string(),
      ],
      Transport::Mush => self.mush.ssh_opts_with(&["--no-fallback"]),
    }
  }

  fn client_iface(&self) -> Result<mush_testenv::patchbay::Iface> {
    self.topo.client.iface("eth0").context("client eth0")
  }

  /// Current counters of the two directional netems in the lossy lab:
  /// `[toward dest, toward client]`.
  async fn netem_counters(&self) -> Result<[PathCounters; 2]> {
    let to_dest = netem_stats(router_qdisc_show(&self.topo.dest_net).await?)
      .context("dest-side netem vanished")?;
    let to_client =
      netem_stats(router_qdisc_show(&self.topo.client_net).await?)
        .context("client-side netem vanished")?;
    Ok([to_dest.counters, to_client.counters])
  }
}

/// Builds a piped command for running a tool inside a lab namespace.
fn ns_command(program: &str, args: &[&str]) -> Command {
  let mut cmd = Command::new(program);
  cmd
    .args(args)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
  mush_testenv::harden_command(&mut cmd);
  cmd
}

/// Waits for a namespaced command and returns its stdout, failing
/// loudly on a nonzero exit.
async fn ns_output(child: Result<Child>, what: &str) -> Result<String> {
  let out = tokio::time::timeout(EXEC_DEADLINE, child?.wait_with_output())
    .await
    .with_context(|| format!("{what} timed out"))??;
  ensure!(
    out.status.success(),
    "{what} failed ({}): {}",
    out.status,
    String::from_utf8_lossy(&out.stderr)
  );
  Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Turns off segmentation offloads on a device's `eth0`, verified by
/// readback. The device then segments to MTU-sized packets at its own
/// transmit step, so the downstream forwarding hops carrying the lossy
/// netems see the per-packet stream a real network path would.
async fn disable_offloads(dev: &Device) -> Result<()> {
  let args = [
    "-K",
    "eth0",
    "tso",
    "off",
    "gso",
    "off",
    "gro",
    "off",
    "tx-udp-segmentation",
    "off",
  ];
  ns_output(
    dev.spawn_command(ns_command("ethtool", &args)),
    "ethtool -K",
  )
  .await?;
  let feats = ns_output(
    dev.spawn_command(ns_command("ethtool", &["-k", "eth0"])),
    "ethtool -k",
  )
  .await?;
  for feat in [
    "tcp-segmentation-offload: off",
    "generic-segmentation-offload: off",
    "generic-receive-offload: off",
    "tx-udp-segmentation: off",
  ] {
    ensure!(
      feats.contains(feat),
      "offload still enabled after ethtool -K (wanted {feat:?}):\n{feats}"
    );
  }
  Ok(())
}

/// Cumulative counters of one netem qdisc. netem's packet counter
/// counts GSO segments while its drop decision and counter are per skb,
/// so with single-segment skbs (the lossy-lab invariant) dropped
/// against dropped+sent gives the effective per-packet loss rate.
#[derive(Clone, Copy, Default)]
struct PathCounters {
  sent_bytes: u64,
  sent_pkts: u64,
  dropped: u64,
}

impl PathCounters {
  fn delta(self, earlier: PathCounters) -> PathCounters {
    PathCounters {
      sent_bytes: self.sent_bytes.saturating_sub(earlier.sent_bytes),
      sent_pkts: self.sent_pkts.saturating_sub(earlier.sent_pkts),
      dropped: self.dropped.saturating_sub(earlier.dropped),
    }
  }

  fn accumulate(&mut self, other: PathCounters) {
    self.sent_bytes += other.sent_bytes;
    self.sent_pkts += other.sent_pkts;
    self.dropped += other.dropped;
  }

  /// Effective loss percentage over everything that reached this netem.
  fn loss_pct(&self) -> f64 {
    let total = self.sent_pkts + self.dropped;
    if total == 0 {
      return f64::NAN;
    }
    self.dropped as f64 * 100.0 / total as f64
  }

  fn mean_pkt_bytes(&self) -> f64 {
    if self.sent_pkts == 0 {
      return f64::NAN;
    }
    self.sent_bytes as f64 / self.sent_pkts as f64
  }
}

/// One netem qdisc read back from a namespace: parameter line and
/// counters.
struct NetemStats {
  params: String,
  counters: PathCounters,
}

async fn router_qdisc_show(router: &Router) -> Result<String> {
  ns_output(
    router.spawn_command(ns_command("tc", &["-s", "qdisc", "show"])),
    "tc -s qdisc show (router)",
  )
  .await
}

async fn dev_qdisc_show(dev: &Device, ifname: &str) -> Result<String> {
  ns_output(
    dev
      .spawn_command(ns_command("tc", &["-s", "qdisc", "show", "dev", ifname])),
    "tc -s qdisc show (device)",
  )
  .await
}

/// Finds the single netem qdisc in `tc -s qdisc show` output. Errors on
/// zero or several: each lab namespace is expected to carry exactly one.
fn netem_stats(tc_output: String) -> Result<NetemStats> {
  let mut found = None;
  let mut lines = tc_output.lines();
  while let Some(line) = lines.next() {
    if !line.starts_with("qdisc netem") {
      continue;
    }
    ensure!(
      found.is_none(),
      "multiple netem qdiscs in one namespace:\n{tc_output}"
    );
    let sent = lines.next().context("netem qdisc without a stats line")?;
    found = Some(NetemStats {
      params: line.to_string(),
      counters: parse_sent_line(sent)
        .with_context(|| format!("parsing netem stats line {sent:?}"))?,
    });
  }
  found.with_context(|| format!("no netem qdisc found:\n{tc_output}"))
}

/// Parses tc's ` Sent B bytes P pkt (dropped D, ...` counter line.
fn parse_sent_line(line: &str) -> Result<PathCounters> {
  let mut tokens = line.split_whitespace();
  let mut counters = PathCounters::default();
  while let Some(token) = tokens.next() {
    match token {
      "Sent" => {
        counters.sent_bytes =
          tokens.next().context("bytes")?.parse().context("bytes")?;
        ensure!(tokens.next() == Some("bytes"), "expected 'bytes'");
        counters.sent_pkts =
          tokens.next().context("pkts")?.parse().context("pkts")?;
      }
      "(dropped" => {
        counters.dropped = tokens
          .next()
          .context("dropped")?
          .trim_end_matches(',')
          .parse()
          .context("dropped")?;
      }
      _ => {}
    }
  }
  Ok(counters)
}

/// Formats a percentage the way `tc` prints netem loss (no trailing
/// zeros: `2%`, `0.5%`).
fn tc_pct(pct: f32) -> String {
  if pct.fract() == 0.0 {
    format!("{}%", pct as u32)
  } else {
    format!("{pct}%")
  }
}

/// Asserts a read-back netem carries the condition's delay and loss.
fn expect_netem(stats: &NetemStats, cond: LinkCondition) -> Result<()> {
  if cond.latency_ms > 0 {
    let delay = format!("delay {}ms", cond.latency_ms);
    ensure!(
      stats.params.contains(&delay),
      "netem missing {delay:?}: {}",
      stats.params
    );
  }
  if cond.loss_pct > 0.0 {
    let loss = format!("loss {}", tc_pct(cond.loss_pct));
    ensure!(
      stats.params.contains(&loss),
      "netem missing {loss:?}: {}",
      stats.params
    );
  }
  Ok(())
}

/// Times TCP connects from the client namespace to the dest's sshd and
/// asserts the best of five is where the condition puts it: near zero
/// on a clean path, around 2x the one-way delay otherwise (a
/// minimum is robust to a SYN lost under loss). Catches a silently
/// unapplied or doubly applied impairment before anything is measured.
async fn verify_path_rtt(lab: &Lab, cond: Option<LinkCondition>) -> Result<()> {
  let addr = SocketAddr::from((lab.dest_ip, lab.fix.port));
  let best = lab
    .topo
    .client
    .spawn(move |_| async move {
      let mut best = Duration::MAX;
      for _ in 0..5 {
        let start = Instant::now();
        let stream = tokio::time::timeout(
          Duration::from_secs(10),
          tokio::net::TcpStream::connect(addr),
        )
        .await
        .context("connect probe timed out")??;
        best = best.min(start.elapsed());
        drop(stream);
      }
      anyhow::Ok(best)
    })?
    .await??;
  let delay_ms = cond.map_or(0, |c| c.latency_ms);
  let (lo, hi) = if delay_ms == 0 {
    (Duration::ZERO, Duration::from_millis(10))
  } else {
    (
      Duration::from_millis(u64::from(delay_ms) * 2 * 8 / 10),
      Duration::from_millis(u64::from(delay_ms) * 2 + 30),
    )
  };
  ensure!(
    (lo..=hi).contains(&best),
    "path RTT {best:?} outside the expected {lo:?}..{hi:?} for a \
     {delay_ms}ms-each-way condition; refusing to measure a mislabeled lab"
  );
  Ok(())
}

/// Per-transport, per-direction loss accounting for a lossy scenario,
/// accumulated from netem counter deltas around each timed repetition
/// (warmups and inter-rep traffic fall outside the sampled windows).
struct LossLedger {
  before: [PathCounters; 2],
  ssh: [PathCounters; 2],
  mush: [PathCounters; 2],
}

impl LossLedger {
  async fn new(lab: &Lab) -> Result<Self> {
    Ok(Self {
      before: lab.netem_counters().await?,
      ssh: Default::default(),
      mush: Default::default(),
    })
  }

  async fn begin_rep(&mut self, lab: &Lab) -> Result<()> {
    self.before = lab.netem_counters().await?;
    Ok(())
  }

  async fn commit_rep(
    &mut self,
    lab: &Lab,
    transport: Transport,
  ) -> Result<()> {
    let now = lab.netem_counters().await?;
    let acc = match transport {
      Transport::Ssh => &mut self.ssh,
      Transport::Mush => &mut self.mush,
    };
    for (acc, (now, before)) in
      acc.iter_mut().zip(now.iter().zip(self.before.iter()))
    {
      acc.accumulate(now.delta(*before));
    }
    Ok(())
  }

  fn into_audit(self, nominal_pct: f32) -> LossAudit {
    LossAudit {
      nominal_pct,
      ssh: self.ssh,
      mush: self.mush,
    }
  }
}

/// The audited loss a lossy scenario actually applied, per transport
/// and direction: `[toward dest (the upload data path), toward client
/// (the return path)]`.
struct LossAudit {
  nominal_pct: f32,
  ssh: [PathCounters; 2],
  mush: [PathCounters; 2],
}

impl LossAudit {
  /// Verifies each transport's data path experienced the nominal
  /// per-packet rate. A multi-segment-skb regression shows up here as a
  /// large shortfall (loss per batch instead of per packet).
  fn check(&self) -> Result<()> {
    let nominal = f64::from(self.nominal_pct);
    for (name, acc) in [("ssh", &self.ssh), ("mush", &self.mush)] {
      let data = &acc[0];
      ensure!(
        data.sent_pkts + data.dropped >= 1000,
        "loss audit: too little {name} data-path traffic to audit"
      );
      let eff = data.loss_pct();
      ensure!(
        (nominal * 0.4..=nominal * 2.5).contains(&eff),
        "loss audit: {name} data path saw {eff:.3}% effective loss vs \
         {nominal}% nominal; the loss process is not per-packet"
      );
    }
    Ok(())
  }

  fn json(&self) -> Value {
    let path = |c: &PathCounters| {
      json!({
        "pkts": c.sent_pkts + c.dropped,
        "dropped": c.dropped,
        "eff_pct": c.loss_pct(),
        "mean_pkt_bytes": c.mean_pkt_bytes(),
      })
    };
    let transport = |acc: &[PathCounters; 2]| {
      json!({
        "to_dest": path(&acc[0]),
        "to_client": path(&acc[1]),
      })
    };
    json!({
      "nominal_pct": self.nominal_pct,
      "ssh": transport(&self.ssh),
      "mush": transport(&self.mush),
    })
  }

  fn table_lines(&self) -> Vec<String> {
    [("ssh", &self.ssh), ("mush", &self.mush)]
      .into_iter()
      .map(|(name, acc)| {
        format!(
          "loss audit {name} (nominal {}/way): data {:.3}% over {} pkts \
           ({:.0} B/pkt), return {:.3}% over {} pkts ({:.0} B/pkt)",
          tc_pct(self.nominal_pct),
          acc[0].loss_pct(),
          acc[0].sent_pkts + acc[0].dropped,
          acc[0].mean_pkt_bytes(),
          acc[1].loss_pct(),
          acc[1].sent_pkts + acc[1].dropped,
          acc[1].mean_pkt_bytes(),
        )
      })
      .collect()
  }
}

/// Guards against a fallen-back session polluting Mush numbers, on top
/// of the `--no-fallback` pin.
fn ensure_no_fallback(transport: Transport, stderr: &str) -> Result<()> {
  if transport == Transport::Mush {
    ensure!(
      !stderr.contains("falling back"),
      "mush session used the TCP fallback despite --no-fallback:\n{stderr}"
    );
  }
  Ok(())
}

/// The files one bulk metric moves: a local source for uploads, a
/// staged "remote" source for downloads (the lab shares the host
/// filesystem), and per-transport destination paths so nothing aliases.
struct BulkFiles {
  dir: tempfile::TempDir,
  payload: Vec<u8>,
  src: PathBuf,
  remote_src: PathBuf,
}

impl BulkFiles {
  fn new(len: usize, seed: u64) -> Result<Self> {
    let dir = tempfile::TempDir::with_prefix("mush-perf-")?;
    let payload = pseudo_bytes(len, seed);
    let src = dir.path().join("src.bin");
    let remote_src = dir.path().join("remote-src.bin");
    std::fs::write(&src, &payload)?;
    std::fs::write(&remote_src, &payload)?;
    Ok(Self {
      dir,
      payload,
      src,
      remote_src,
    })
  }

  /// Reads both sources fully so every timed rep starts with them in the
  /// page cache (the warmup rep does this too; this makes it explicit).
  fn warm(&self) -> Result<()> {
    ensure!(std::fs::read(&self.src)?.len() == self.payload.len(), "src");
    ensure!(
      std::fs::read(&self.remote_src)?.len() == self.payload.len(),
      "remote src"
    );
    Ok(())
  }

  fn dst(&self, up: bool, transport: Transport) -> PathBuf {
    let dir = if up { "up" } else { "down" };
    self
      .dir
      .path()
      .join(format!("{dir}-{}.bin", transport.name()))
  }
}

/// One timed scp from inside the client namespace. The wall clock spans
/// spawn to exit, so it includes establishment (bootstrap plus QUIC for
/// Mush, one TCP handshake for ssh); `exec-true` measures that share.
async fn scp_timed(
  lab: &Lab,
  transport: Transport,
  from: &str,
  to: &str,
) -> Result<f64> {
  let mut cmd = Command::new("scp");
  cmd.arg("-F").arg(lab.fix.ssh_config());
  if transport == Transport::Mush {
    cmd.arg("-o").arg(format!(
      "ProxyCommand={}",
      lab.mush.proxy_command_with(&["--no-fallback"])
    ));
  }
  cmd
    .args(["-o", "ConnectTimeout=30", from, to])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
  mush_testenv::harden_command(&mut cmd);
  let start = Instant::now();
  let child = lab.topo.client.spawn_command(cmd)?;
  let out = tokio::time::timeout(TRANSFER_DEADLINE, child.wait_with_output())
    .await
    .with_context(|| format!("scp over {} timed out", transport.name()))??;
  let elapsed = start.elapsed().as_secs_f64();
  let stderr = String::from_utf8_lossy(&out.stderr);
  ensure!(
    out.status.success(),
    "scp {from} -> {to} over {} failed ({}): {stderr}",
    transport.name(),
    out.status
  );
  ensure_no_fallback(transport, &stderr)?;
  Ok(elapsed)
}

/// Interleaved timed scps in one direction: a discarded warmup pair
/// (which also verifies content byte-for-byte), then `reps` timed pairs
/// with a size check each. With a ledger (the lossy labs) netem counters
/// are sampled around each timed transfer to attribute the loss applied
/// to each transport. Returns (ssh, Mush) wall-clock seconds.
async fn measure_scp(
  lab: &Lab,
  files: &BulkFiles,
  up: bool,
  reps: usize,
  mut ledger: Option<&mut LossLedger>,
) -> Result<(Vec<f64>, Vec<f64>)> {
  files.warm()?;
  let mut ssh = Vec::new();
  let mut mush = Vec::new();
  for rep in 0..=reps {
    for transport in order(rep) {
      let dst = files.dst(up, transport);
      let (from, to) = if up {
        (
          files.src.display().to_string(),
          format!("{}:{}", lab.dest_ip, dst.display()),
        )
      } else {
        (
          format!("{}:{}", lab.dest_ip, files.remote_src.display()),
          dst.display().to_string(),
        )
      };
      if let Some(ledger) = ledger.as_deref_mut() {
        ledger.begin_rep(lab).await?;
      }
      let secs = scp_timed(lab, transport, &from, &to).await?;
      if rep == 0 {
        ensure!(
          std::fs::read(&dst)? == files.payload,
          "scp warmup corrupted the payload ({}, up={up})",
          transport.name()
        );
      } else {
        ensure!(
          std::fs::metadata(&dst)?.len() == files.payload.len() as u64,
          "scp produced a short file ({}, up={up})",
          transport.name()
        );
        if let Some(ledger) = ledger.as_deref_mut() {
          ledger.commit_rep(lab, transport).await?;
        }
        match transport {
          Transport::Ssh => ssh.push(secs),
          Transport::Mush => mush.push(secs),
        }
      }
    }
  }
  Ok((ssh, mush))
}

/// One timed trivial exec: `ssh <dest> true` wall time, establishment
/// through teardown. For Mush that includes bootstrap plus QUIC by
/// design; the delta is what the extra bootstrap and QUIC handshake cost.
async fn exec_true_timed(lab: &Lab, transport: Transport) -> Result<f64> {
  let mut cmd = Command::new("ssh");
  cmd
    .args(lab.ssh_opts(transport))
    .arg(lab.dest_ip.to_string())
    .arg("true")
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
  mush_testenv::harden_command(&mut cmd);
  let start = Instant::now();
  let child = lab.topo.client.spawn_command(cmd)?;
  let out = tokio::time::timeout(EXEC_DEADLINE, child.wait_with_output())
    .await
    .with_context(|| format!("exec over {} timed out", transport.name()))??;
  let elapsed = start.elapsed().as_secs_f64();
  let stderr = String::from_utf8_lossy(&out.stderr);
  ensure!(
    out.status.success(),
    "`ssh true` over {} failed ({}): {stderr}",
    transport.name(),
    out.status
  );
  ensure_no_fallback(transport, &stderr)?;
  Ok(elapsed)
}

/// Interleaved trivial execs; returns (ssh, Mush) wall seconds.
async fn measure_exec_true(
  lab: &Lab,
  reps: usize,
) -> Result<(Vec<f64>, Vec<f64>)> {
  let mut ssh = Vec::new();
  let mut mush = Vec::new();
  for rep in 0..=reps {
    for transport in order(rep) {
      let secs = exec_true_timed(lab, transport).await?;
      if rep > 0 {
        match transport {
          Transport::Ssh => ssh.push(secs),
          Transport::Mush => mush.push(secs),
        }
      }
    }
  }
  Ok((ssh, mush))
}

/// Spawns the outer ssh inside the client namespace with piped stdio.
fn spawn_session(
  lab: &Lab,
  transport: Transport,
  remote: &str,
) -> Result<Child> {
  let mut cmd = Command::new("ssh");
  cmd
    .args(lab.ssh_opts(transport))
    .arg(lab.dest_ip.to_string())
    .arg(remote)
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
  mush_testenv::harden_command(&mut cmd);
  lab.topo.client.spawn_command(cmd)
}

/// One PTY-less echo session: a remote `cat`, one line written at a
/// time, the next line only after its echo returns. Returns the timed
/// per-line RTTs in milliseconds (warmup lines discarded).
async fn echo_session(lab: &Lab, transport: Transport) -> Result<Vec<f64>> {
  let mut child = spawn_session(lab, transport, "cat")?;
  let mut stdin = child.stdin.take().context("stdin piped")?;
  let mut lines =
    BufReader::new(child.stdout.take().context("stdout piped")?).lines();
  let stderr = drain(child.stderr.take().context("stderr piped")?);

  let mut rtts = Vec::with_capacity(ECHO_TIMED_LINES);
  for i in 0..(ECHO_WARMUP_LINES + ECHO_TIMED_LINES) {
    let line = format!("p{i}");
    let start = Instant::now();
    stdin.write_all(format!("{line}\n").as_bytes()).await?;
    let echo = tokio::time::timeout(LINE_DEADLINE, lines.next_line())
      .await
      .context("echo line timed out")??
      .context("echo stream ended early")?;
    let rtt = start.elapsed();
    ensure!(echo == line, "unexpected echo {echo:?}");
    if i >= ECHO_WARMUP_LINES {
      rtts.push(rtt.as_secs_f64() * 1e3);
    }
  }
  drop(stdin);
  let status = tokio::time::timeout(EXEC_DEADLINE, child.wait()).await??;
  let stderr = String::from_utf8_lossy(&stderr.await?).into_owned();
  ensure!(
    status.success(),
    "echo session over {} failed ({status}): {stderr}",
    transport.name()
  );
  ensure_no_fallback(transport, &stderr)?;
  Ok(rtts)
}

/// Interleaved echo sessions; returns per-line RTT samples in
/// milliseconds, `ECHO_SESSIONS * ECHO_TIMED_LINES` per transport.
async fn measure_echo(lab: &Lab) -> Result<(Vec<f64>, Vec<f64>)> {
  let mut ssh = Vec::new();
  let mut mush = Vec::new();
  for session in 0..ECHO_SESSIONS {
    for transport in order(session) {
      let rtts = echo_session(lab, transport).await?;
      match transport {
        Transport::Ssh => ssh.extend(rtts),
        Transport::Mush => mush.extend(rtts),
      }
    }
  }
  Ok((ssh, mush))
}

/// One recovery rep: a session streaming ticks, a blackhole of `outage`
/// (100% loss layered on the steady condition), then the time from
/// restore to the first new payload byte reaching the client. With
/// `client_writes` the client also feeds the session ten lines a second
/// echoed by a remote `cat`, so arrivals prove both directions;
/// otherwise its stdin is dropped and the remote drives.
async fn recovery_rep(
  lab: &Lab,
  transport: Transport,
  steady: LinkCondition,
  outage: Duration,
  client_writes: bool,
) -> Result<f64> {
  let remote = if client_writes {
    "cat"
  } else {
    "sh -c 'while :; do echo R; sleep 0.05; done'"
  };
  let mut child = spawn_session(lab, transport, remote)?;
  let stdin = child.stdin.take().context("stdin piped")?;
  let writer = if client_writes {
    let mut stdin = stdin;
    Some(tokio::spawn(async move {
      let mut n: u64 = 0;
      loop {
        let line = format!("tick-{n}\n");
        if stdin.write_all(line.as_bytes()).await.is_err() {
          return;
        }
        n += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
      }
    }))
  } else {
    drop(stdin);
    None
  };
  let mut stdout = child.stdout.take().context("stdout piped")?;
  let stderr = drain(child.stderr.take().context("stderr piped")?);
  let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
  let reader = tokio::spawn(async move {
    let mut buf = [0u8; 4096];
    loop {
      match stdout.read(&mut buf).await {
        Ok(0) | Err(_) => return,
        Ok(_) => {
          let _ = tx.send(Instant::now());
        }
      }
    }
  });

  // Steady state: several tick deliveries prove the stream is live and
  // the pipe drained before the outage starts.
  for _ in 0..10 {
    tokio::time::timeout(EXEC_DEADLINE, rx.recv())
      .await
      .context("no steady ticks before the outage")?
      .context("session ended before the outage")?;
  }

  let iface = lab.client_iface()?;
  iface
    .set_condition(steady.loss_pct(100.0), LinkDirection::Both)
    .await?;
  // Give in-flight delivery a moment to settle, drain it, then require
  // silence for the rest of the outage: a tick arriving mid-blackhole
  // means the blackhole is not actually in effect.
  let settle = Duration::from_secs(1).min(outage / 2);
  tokio::time::sleep(settle).await;
  while rx.try_recv().is_ok() {}
  tokio::time::sleep(outage - settle).await;
  ensure!(
    rx.try_recv().is_err(),
    "payload crossed the blackhole mid-outage over {}; the lab is not \
     delivering the outage",
    transport.name()
  );
  iface.set_condition(steady, LinkDirection::Both).await?;
  let restored = Instant::now();
  let arrival = tokio::time::timeout(RECOVERY_DEADLINE, rx.recv())
    .await
    .with_context(|| {
      format!(
        "no payload within {RECOVERY_DEADLINE:?} of restore over {}",
        transport.name()
      )
    })?;
  let Some(arrival) = arrival else {
    bail!(
      "the {} session died across the {outage:?} outage:\n{}",
      transport.name(),
      String::from_utf8_lossy(&stderr.await?)
    );
  };
  let recovery = arrival
    .checked_duration_since(restored)
    .unwrap_or_default()
    .as_secs_f64();

  child.kill().await?;
  reader.abort();
  if let Some(writer) = writer {
    writer.abort();
  }
  Ok(recovery)
}

/// Interleaved recovery reps for one outage length. Each rep is a fresh
/// session, so there is no warmup to discard. Returns (ssh, Mush)
/// restore-to-first-byte seconds.
async fn measure_recovery(
  lab: &Lab,
  steady: LinkCondition,
  outage: Duration,
  reps: usize,
  client_writes: bool,
) -> Result<(Vec<f64>, Vec<f64>)> {
  let mut ssh = Vec::new();
  let mut mush = Vec::new();
  for rep in 0..reps {
    for transport in order(rep) {
      let secs =
        recovery_rep(lab, transport, steady, outage, client_writes).await?;
      match transport {
        Transport::Ssh => ssh.push(secs),
        Transport::Mush => mush.push(secs),
      }
    }
  }
  Ok((ssh, mush))
}

/// One measured metric with samples for both transports.
struct MetricResult {
  scenario: &'static str,
  metric: &'static str,
  unit: &'static str,
  /// Payload size for throughput derivation, when the metric moves one.
  bytes: Option<u64>,
  note: &'static str,
  /// Print every sample in the table: for multi-modal distributions
  /// (lossy transfers, recovery) the median alone misleads.
  list_samples: bool,
  loss_audit: Option<LossAudit>,
  ssh: Vec<f64>,
  mush: Vec<f64>,
}

impl MetricResult {
  fn new(
    scenario: &'static str,
    metric: &'static str,
    unit: &'static str,
    (ssh, mush): (Vec<f64>, Vec<f64>),
  ) -> Self {
    Self {
      scenario,
      metric,
      unit,
      bytes: None,
      note: "",
      list_samples: false,
      loss_audit: None,
      ssh,
      mush,
    }
  }

  fn bytes(mut self, bytes: u64) -> Self {
    self.bytes = Some(bytes);
    self
  }

  fn note(mut self, note: &'static str) -> Self {
    self.note = note;
    self
  }

  fn list_samples(mut self) -> Self {
    self.list_samples = true;
    self
  }

  fn loss_audit(mut self, audit: LossAudit) -> Self {
    self.loss_audit = Some(audit);
    self
  }
}

fn sorted(samples: &[f64]) -> Vec<f64> {
  let mut v = samples.to_vec();
  v.sort_by(f64::total_cmp);
  v
}

/// Linear-interpolation percentile over pre-sorted samples.
fn percentile(sorted: &[f64], p: f64) -> f64 {
  if sorted.is_empty() {
    return f64::NAN;
  }
  let rank = p * (sorted.len() - 1) as f64;
  let lo = rank.floor() as usize;
  let hi = rank.ceil() as usize;
  let frac = rank - lo as f64;
  sorted[lo] + (sorted[hi] - sorted[lo]) * frac
}

fn median(samples: &[f64]) -> f64 {
  percentile(&sorted(samples), 0.5)
}

/// One transport's samples and their spread.
fn stats_json(samples: &[f64]) -> Value {
  let s = sorted(samples);
  json!({
    "samples": samples,
    "median": percentile(&s, 0.5),
    "min": s.first().copied().unwrap_or(f64::NAN),
    "max": s.last().copied().unwrap_or(f64::NAN),
    "p95": percentile(&s, 0.95),
    "p99": percentile(&s, 0.99),
  })
}

fn read_trimmed(path: &str) -> String {
  std::fs::read_to_string(path)
    .unwrap_or_default()
    .trim()
    .to_string()
}

/// Renders the whole run as JSON, through `serde_json` rather than by
/// hand: `NaN` -- every percentile when a scenario collected no
/// samples -- has no JSON token, and neither `$TMPDIR` nor the strings
/// read out of `/proc` and `/sys` are guaranteed free of characters
/// needing escaping.
fn results_json(results: &[MetricResult]) -> String {
  let run = json!({
    "meta": {
      "timestamp": SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs(),
      "kernel": read_trimmed("/proc/sys/kernel/osrelease"),
      "cores": std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(0),
      "governor": read_trimmed(
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
      ),
      "reps": reps(),
      "lossy_reps": lossy_reps(),
      "recovery_reps": recovery_reps(),
      "load1": load1().unwrap_or(f64::NAN),
      "tmpdir": std::env::temp_dir().display().to_string(),
    },
    "results": results.iter().map(|r| {
      let mut result = json!({
        "scenario": r.scenario, "metric": r.metric, "unit": r.unit,
      });
      let fields = result.as_object_mut().expect("a json! object");
      if let Some(bytes) = r.bytes {
        fields.insert("bytes".into(), json!(bytes));
      }
      if !r.note.is_empty() {
        fields.insert("note".into(), json!(r.note));
      }
      if let Some(audit) = &r.loss_audit {
        fields.insert("loss_audit".into(), audit.json());
      }
      fields.insert("ssh".into(), stats_json(&r.ssh));
      fields.insert("mush".into(), stats_json(&r.mush));
      result
    }).collect::<Vec<_>>(),
  });
  let mut out = run.to_string();
  out.push('\n');
  out
}

/// The results file must parse even in the shape that makes a
/// hand-rolled writer emit what no parser accepts: `MUSH_PERF_REPS=0`
/// leaves every percentile `NaN`, which JSON has no token for.
#[test]
fn results_json_parses_with_no_samples() {
  let empty = MetricResult::new("clean", "exec-true", "s", (vec![], vec![]));
  let parsed: Value = serde_json::from_str(&results_json(&[empty]))
    .expect("the results file parses");
  assert!(parsed["results"][0]["ssh"]["median"].is_null());
}

/// Formats one transport's median and spread, with throughput when the
/// metric moves bytes.
fn fmt_line(r: &MetricResult, samples: &[f64]) -> String {
  let s = sorted(samples);
  let med = percentile(&s, 0.5);
  let mut line = format!(
    "{med:9.3} {} ({:.3}..{:.3})",
    r.unit,
    s.first().copied().unwrap_or(f64::NAN),
    s.last().copied().unwrap_or(f64::NAN)
  );
  if let Some(bytes) = r.bytes {
    let mibps = bytes as f64 / MIB as f64 / med;
    write!(line, "  {mibps:8.1} MiB/s").unwrap();
  }
  line
}

fn fmt_samples(samples: &[f64]) -> String {
  let mut line = String::from("[");
  for (i, v) in sorted(samples).iter().enumerate() {
    if i > 0 {
      line.push_str(", ");
    }
    write!(line, "{v:.3}").unwrap();
  }
  line.push(']');
  line
}

fn print_table(results: &[MetricResult]) {
  println!("\n==== mush vs ssh performance comparison ====");
  let mut scenario = "";
  for r in results {
    if r.scenario != scenario {
      scenario = r.scenario;
      println!("\n-- {scenario} --");
    }
    println!("{}:", r.metric);
    println!("  ssh   {}", fmt_line(r, &r.ssh));
    println!("  mush  {}", fmt_line(r, &r.mush));
    let (ssh_med, mush_med) = (median(&r.ssh), median(&r.mush));
    if r.unit == "ms" {
      let (s, m) = (sorted(&r.ssh), sorted(&r.mush));
      println!(
        "  ssh   p50/p95/p99  {:.3}/{:.3}/{:.3} ms",
        percentile(&s, 0.5),
        percentile(&s, 0.95),
        percentile(&s, 0.99)
      );
      println!(
        "  mush  p50/p95/p99  {:.3}/{:.3}/{:.3} ms",
        percentile(&m, 0.5),
        percentile(&m, 0.95),
        percentile(&m, 0.99)
      );
      println!("  p50 delta {:+.3} ms", mush_med - ssh_med);
    } else {
      println!(
        "  mush/ssh {:.2}x (delta {:+.3} {})",
        mush_med / ssh_med,
        mush_med - ssh_med,
        r.unit
      );
    }
    if r.list_samples {
      println!("  ssh   samples {}", fmt_samples(&r.ssh));
      println!("  mush  samples {}", fmt_samples(&r.mush));
    }
    if let Some(audit) = &r.loss_audit {
      for line in audit.table_lines() {
        println!("  {line}");
      }
    }
    if !r.note.is_empty() {
      println!("  note: {}", r.note);
    }
  }
  // Establishment-corrected bulk estimates: wall time minus the same
  // scenario's median trivial-exec time, per transport. Derived, not
  // measured; the raw walls above stay the primary numbers.
  for r in results {
    let Some(bytes) = r.bytes else { continue };
    let Some(exec) = results
      .iter()
      .find(|e| e.scenario == r.scenario && e.metric == "exec-true")
    else {
      continue;
    };
    // Below ~20ms the difference is inside establishment timing variation
    // and the derived rate is meaningless.
    let est = |bulk: &[f64], exec: &[f64]| {
      let t = median(bulk) - median(exec);
      (t > 0.02).then(|| (t, bytes as f64 / MIB as f64 / t))
    };
    let fmt = |est: Option<(f64, f64)>| match est {
      Some((t, rate)) => format!("{t:.3} s = {rate:.1} MiB/s"),
      None => "unresolved (within establishment timing variation)".to_string(),
    };
    println!(
      "[{} / {}] est transfer-only (wall minus exec-true median): \
       ssh {}, mush {}",
      r.scenario,
      r.metric,
      fmt(est(&r.ssh, &exec.ssh)),
      fmt(est(&r.mush, &exec.mush))
    );
  }
}

fn wan() -> LinkCondition {
  LinkCondition::new().latency_ms(20)
}

/// Clean LAN-ish path: no netem. 512 MiB bulk both directions, large
/// enough that establishment is a small fraction of the time, so the
/// transfer-only rate resolves, plus `exec-true` establishment (which
/// the table subtracts to derive that rate) and interactive echo.
async fn scenario_clean(
  results: &mut Vec<MetricResult>,
  reps: usize,
) -> Result<()> {
  ensure_quiet("clean").await?;
  let lab = perf_lab(None).await?;
  let files = BulkFiles::new(512 * MIB, 0x5332_0004)?;
  let up = measure_scp(&lab, &files, true, reps, None).await?;
  results.push(
    MetricResult::new("clean", "scp-up-512MiB", "s", up)
      .bytes(512 * MIB as u64)
      .note("sized to swamp establishment; transfer-only rate resolves here"),
  );
  let down = measure_scp(&lab, &files, false, reps, None).await?;
  results.push(
    MetricResult::new("clean", "scp-down-512MiB", "s", down)
      .bytes(512 * MIB as u64)
      .note("sized to swamp establishment; transfer-only rate resolves here"),
  );
  drop(files);
  let exec = measure_exec_true(&lab, reps).await?;
  results.push(
    MetricResult::new("clean", "exec-true", "s", exec)
      .note("mush includes bootstrap ssh + QUIC establishment by design"),
  );
  let echo = measure_echo(&lab).await?;
  results.push(MetricResult::new("clean", "echo-line-rtt", "ms", echo));
  Ok(())
}

/// WAN path: 20ms each way, no loss. Same bulk, establishment, and echo
/// RTT distribution. At this RTT both transports sit on the same OpenSSH
/// channel flow-control limit (~1.4 MiB in flight), so bulk parity
/// here shows Mush adds no tighter bottleneck; the clean scenario's
/// 512 MiB metric is where raw transport throughput resolves.
async fn scenario_wan(
  results: &mut Vec<MetricResult>,
  reps: usize,
) -> Result<()> {
  ensure_quiet("wan").await?;
  let lab = perf_lab(Some(wan())).await?;
  let files = BulkFiles::new(64 * MIB, 0x5332_0002)?;
  let up = measure_scp(&lab, &files, true, reps, None).await?;
  results.push(
    MetricResult::new("wan-40ms", "scp-up-64MiB", "s", up)
      .bytes(64 * MIB as u64)
      .note(
        "wall includes establishment; transfer-only rate is bound by \
         OpenSSH's ~2MiB channel window at this RTT for both transports",
      ),
  );
  let down = measure_scp(&lab, &files, false, reps, None).await?;
  results.push(
    MetricResult::new("wan-40ms", "scp-down-64MiB", "s", down)
      .bytes(64 * MIB as u64)
      .note(
        "wall includes establishment; transfer-only rate is bound by \
         OpenSSH's ~2MiB channel window at this RTT for both transports",
      ),
  );
  let exec = measure_exec_true(&lab, reps).await?;
  results.push(
    MetricResult::new("wan-40ms", "exec-true", "s", exec)
      .note("mush includes bootstrap ssh + QUIC establishment by design"),
  );
  let echo = measure_echo(&lab).await?;
  results.push(MetricResult::new("wan-40ms", "echo-line-rtt", "ms", echo));
  Ok(())
}

/// Lossy WAN: 20ms each way plus per-MTU-packet Bernoulli loss each way
/// ([`perf_lab_lossy`] has how that is made true and audited). Upload
/// bulk plus establishment-under-loss at the raised [`lossy_reps`]
/// count, payload sized so loss-bound reps stay in the tens of seconds.
/// Wall times here are multi-modal, so full samples are reported rather
/// than the median alone.
async fn scenario_lossy(
  results: &mut Vec<MetricResult>,
  reps: usize,
  loss_pct: f32,
  mib: usize,
  scenario: &'static str,
  metric: &'static str,
) -> Result<()> {
  ensure_quiet(scenario).await?;
  let cond = wan().random_loss(loss_pct);
  let lab = perf_lab_lossy(cond).await?;
  let files = BulkFiles::new(mib * MIB, 0x5332_0003 + mib as u64)?;
  let mut ledger = LossLedger::new(&lab).await?;
  let up = measure_scp(&lab, &files, true, reps, Some(&mut ledger)).await?;
  let audit = ledger.into_audit(loss_pct);
  audit.check()?;
  results.push(
    MetricResult::new(scenario, metric, "s", up)
      .bytes((mib * MIB) as u64)
      .note(
        "upload only; per-packet Bernoulli loss each way on top of 20ms \
         each way, audited from netem drop counters",
      )
      .list_samples()
      .loss_audit(audit),
  );
  let exec = measure_exec_true(&lab, reps).await?;
  results.push(
    MetricResult::new(scenario, "exec-true", "s", exec)
      .note("establishment under loss; handshake losses cost whole RTOs")
      .list_samples(),
  );
  Ok(())
}

/// Recovery: blackholes of several lengths mid-stream on the WAN path,
/// measuring restore-to-first-new-payload-byte. Mush is the design
/// target; the ssh number is context, not a comparison, since kernel TCP
/// retransmission also carries a plain fixed-address blackhole with
/// recovery set by wherever its backoff ended up. Hence full samples and
/// the [`OUTAGES`] sweep, which is where the two diverge. The outages
/// that kill TCP outright (address changes, NAT rebinds, outages past
/// resource limits) are covered by the lab resilience suite, where raw
/// ssh has no equivalent.
async fn scenario_recovery(
  results: &mut Vec<MetricResult>,
  reps: usize,
) -> Result<()> {
  ensure_quiet("recovery").await?;
  let lab = perf_lab(Some(wan())).await?;
  for (secs, metric) in OUTAGES {
    let outage = Duration::from_secs(secs);
    let samples = measure_recovery(&lab, wan(), outage, reps, false).await?;
    results.push(
      MetricResult::new("recovery-wan-40ms", metric, "s", samples)
        .note(
          "ssh column is context (TCP retransmit backoff), not a target; \
           raw ssh dies on the outages the lab resilience suite covers",
        )
        .list_samples(),
    );
  }
  let (secs, metric) = CLIENT_SENDING_OUTAGE;
  let samples =
    measure_recovery(&lab, wan(), Duration::from_secs(secs), reps, true)
      .await?;
  results.push(
    MetricResult::new("recovery-wan-40ms", metric, "s", samples)
      .note(
        "the client writes 10 lines/s throughout, so its own \
         undeliverable data is parked in the congestion window when the \
         path returns",
      )
      .list_samples(),
  );
  Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn perf_comparison() -> Result<()> {
  mush_testenv::skip_unless_available!();
  // The `mush` binary under test sits next to this test executable, so a
  // debug harness measures a debug `mush`; those numbers are meaningless
  // against the system's optimized ssh.
  if cfg!(debug_assertions) {
    bail!(
      "refusing to measure a debug build: `cargo build --release -p mush`, \
       then `cargo nextest run --profile perf --cargo-profile release \
       -p mush-lab --no-capture`"
    );
  }
  let mut results = Vec::new();

  if scenario_enabled("clean") {
    scenario_clean(&mut results, reps()).await?;
  }
  if scenario_enabled("wan") {
    scenario_wan(&mut results, reps()).await?;
  }
  if scenario_enabled("lossy05") {
    scenario_lossy(
      &mut results,
      lossy_reps(),
      0.5,
      8,
      "lossy-0.5pct-40ms",
      "scp-up-8MiB",
    )
    .await?;
  }
  if scenario_enabled("lossy2") {
    scenario_lossy(
      &mut results,
      lossy_reps(),
      2.0,
      4,
      "lossy-2pct-40ms",
      "scp-up-4MiB",
    )
    .await?;
  }
  if scenario_enabled("recovery") {
    scenario_recovery(&mut results, recovery_reps()).await?;
  }
  ensure!(!results.is_empty(), "no scenarios selected");

  let dir = results_dir();
  std::fs::create_dir_all(&dir)?;
  let timestamp = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs();
  let path = dir.join(format!("perf-{timestamp}.json"));
  std::fs::write(&path, results_json(&results))?;

  print_table(&results);
  println!("\nresults written to {}", path.display());
  Ok(())
}
