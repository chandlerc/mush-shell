// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The upgrade policy (tier 1; see `docs/testing.md`): a session that
//! started on the relay because nothing else was reachable, finding a
//! direct path on its own and moving onto it, giving it back when it
//! dies, and holding its relay through a roam.
//!
//! Where `switch_netsim` drives the path manager by hand to pin down
//! what a switch costs, these scenarios drive nothing: the two peers'
//! own policies ([`mush_core::upgrade`]) decide, and the network is all
//! that is arranged. Each asserts the decision, and -- for the upgrade
//! itself -- which path the session's bytes actually crossed, read off
//! the simulated network's trace rather than inferred from a report
//! either end wrote. The lab is `common::traversal`'s, with the direct
//! path blackholed while the staged dials run, which is what forces
//! establishment onto the relay and leaves a genuine upgrade to make.
//!
//! Determinism rules per mush-netsim's crate docs: current-thread
//! runtime, `start_paused`, no real sockets, `biased` selects.

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use common::payload;
use common::traversal::{
  CLIENT, DEADLINE, DEST, HELPER, RelayedLab, addr, direct_path,
  relayed_session, secret, spawn_helper_handle, spawn_policy,
};
use mush_core::bootstrap::{SessionNonce, SessionSecret};
use mush_core::client::ClientSession;
use mush_core::path::PathKind;
use mush_core::stun::{
  BindingTransaction, MAX_PROBE_BYTES, PeerRole, ProbeLabel,
};
use mush_core::upgrade::{DEFAULT_SILENCE, UpgradeEvent};
use mush_netsim::{EventKind, LinkConfig, SimNet};
use std::sync::Mutex;
use tokio::io::DuplexStream;
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};

/// Bytes each direction carries once the session has a path, big enough
/// that where they went is unambiguous in the trace.
const BULK: usize = 256 * 1024;

/// How long a client is away in the offline-and-return scenario: far
/// past any pinhole's lifetime, and past the point where the peers'
/// own heartbeats are the only thing keeping the relay learnable.
const OFFLINE: Duration = Duration::from_secs(120);

/// Time for whatever was in flight on the old path to arrive, so a
/// trace read afterwards is about where the session sends now.
const DRAIN: Duration = Duration::from_secs(1);

/// A link with enough latency that a round trip is a real event.
fn link() -> LinkConfig {
  LinkConfig {
    latency: Duration::from_millis(20),
    ..LinkConfig::default()
  }
}

/// Waits for the session to move onto a path, failing rather than
/// hanging the paused runtime.
async fn next_move(
  moved: &mut mpsc::Receiver<UpgradeEvent>,
) -> anyhow::Result<(SocketAddr, PathKind)> {
  loop {
    let event = timeout(DEADLINE, moved.recv())
      .await?
      .ok_or_else(|| anyhow::anyhow!("the path policy ended"))?;
    if let UpgradeEvent::Moved { addr, path_kind } = event {
      return Ok((addr, path_kind));
    }
  }
}

/// Sends `len` bytes each way and checks both arrive whole.
async fn exchange(lab: &mut RelayedLab, len: usize) -> anyhow::Result<()> {
  let RelayedLab {
    session,
    destination,
    ..
  } = lab;
  let up = payload(len);
  let down = payload(len);
  let mut got_up = vec![0u8; len];
  let mut got_down = vec![0u8; len];
  let transfer = async {
    tokio::try_join!(
      async {
        session
          .send
          .write_all(&up)
          .await
          .map_err(anyhow::Error::from)
      },
      async {
        destination
          .recv
          .read_exact(&mut got_up)
          .await
          .map_err(anyhow::Error::from)
      },
      async {
        destination
          .send
          .write_all(&down)
          .await
          .map_err(anyhow::Error::from)
      },
      async {
        session
          .recv
          .read_exact(&mut got_down)
          .await
          .map_err(anyhow::Error::from)
      },
    )
  };
  timeout(DEADLINE, transfer).await??;
  anyhow::ensure!(got_up == up, "the stream to the destination was corrupted");
  anyhow::ensure!(got_down == down, "the stream to the client was corrupted");
  Ok(())
}

/// Session datagrams the simulated network delivered between two hosts,
/// in either direction. Only what is bigger than a probe can be
/// ([`MAX_PROBE_BYTES`]), which makes this a question about where the
/// session's bytes went rather than where its keepalives did.
fn between(net: &SimNet, a: IpAddr, b: IpAddr) -> usize {
  net
    .trace()
    .iter()
    .filter(|event| match &event.kind {
      EventKind::Delivered { src, dst, len } => {
        *len > MAX_PROBE_BYTES
          && ((src.ip() == a && dst.ip() == b)
            || (src.ip() == b && dst.ip() == a))
      }
      _ => false,
    })
    .count()
}

/// The lab's three links, as the session's bytes crossed them.
fn link_counts(net: &SimNet) -> (usize, usize, usize) {
  (
    between(net, addr(CLIENT).ip(), addr(DEST).ip()),
    between(net, addr(CLIENT).ip(), addr(HELPER).ip()),
    between(net, addr(HELPER).ip(), addr(DEST).ip()),
  )
}

/// Waits for the destination to migrate onto `want`, which is all it
/// does about a switch: QUIC validates its client's new address and
/// carries on. Then lets the old path drain, so a trace read afterwards
/// is about where the session sends its bytes and not what was in flight
/// when it moved -- reordering QUIC tolerates from any migration, and
/// nothing this policy promises to prevent.
async fn migrated(
  destination: &quinn::Connection,
  want: SocketAddr,
) -> anyhow::Result<()> {
  let deadline = tokio::time::Instant::now() + DEADLINE;
  while destination.remote_address() != want {
    anyhow::ensure!(
      tokio::time::Instant::now() < deadline,
      "the destination is still talking to {}",
      destination.remote_address()
    );
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  tokio::time::sleep(DRAIN).await;
  Ok(())
}

/// The design's Phase C claim, end to end and decided by nobody in the
/// test: a session the relay had to carry finds the direct path once it
/// opens, moves onto it, and its bytes stop crossing the bastion. Run on
/// a clean path and on one that loses packets, because the probes the
/// decision rests on are single datagrams: loss is exactly what would
/// make a policy that trusted one of them wrong.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_relayed_session_upgrades_once_a_direct_path_opens()
-> anyhow::Result<()> {
  for (seed, path) in [
    (0x0b9a_de01, link()),
    (
      0x0b9a_de02,
      LinkConfig {
        latency: Duration::from_millis(20),
        loss: 0.05,
        ..LinkConfig::default()
      },
    ),
  ] {
    let mut lab = relayed_session(seed, path).await?;
    let (policy, mut moved) = spawn_policy(&mut lab.session);

    // While nothing else is reachable the relay is the path: every byte
    // crosses the bastion and none go straight.
    exchange(&mut lab, BULK).await?;
    let (direct, to_helper, from_helper) = link_counts(&lab.net);
    assert_eq!(direct, 0, "the destination was reached without the relay");
    assert!(to_helper > 0 && from_helper > 0);

    // The network changes: what the punch could not open, a route coming
    // back does. Nothing tells either peer.
    direct_path(&lab.net, true);
    let (upgraded, path_kind) = next_move(&mut moved).await?;
    assert_eq!((upgraded, path_kind), (addr(DEST), PathKind::Punched));
    assert_eq!(lab.socket.current_path(), Some(addr(DEST)));

    // The destination follows, having been told nothing.
    migrated(&lab.destination.connection, addr(CLIENT)).await?;

    // And the session's bytes go straight from here on.
    lab.net.clear_trace();
    exchange(&mut lab, BULK).await?;
    let (direct, to_helper, from_helper) = link_counts(&lab.net);
    assert!(direct > 0, "nothing crossed the direct path");
    assert_eq!(
      (to_helper, from_helper),
      (0, 0),
      "the session's bytes still cross the bastion"
    );
    assert!(lab.session.connection.close_reason().is_none());
    assert!(lab.destination.connection.close_reason().is_none());
    policy.abort();
  }
  Ok(())
}

/// The other half of the promise: a direct path that dies after an
/// upgrade hands the session back to the relay instead of stalling on
/// it, which is what the helper is kept alive for.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_direct_path_that_dies_hands_the_session_back() -> anyhow::Result<()>
{
  let mut lab = relayed_session(0x0b9a_de03, link()).await?;
  let (policy, mut moved) = spawn_policy(&mut lab.session);
  direct_path(&lab.net, true);
  assert_eq!(
    next_move(&mut moved).await?,
    (addr(DEST), PathKind::Punched)
  );
  migrated(&lab.destination.connection, addr(CLIENT)).await?;
  exchange(&mut lab, BULK / 8).await?;

  // The direct path goes away again while the relay is still held.
  direct_path(&lab.net, false);
  assert_eq!(
    next_move(&mut moved).await?,
    (addr(HELPER), PathKind::Relayed)
  );
  assert_eq!(lab.socket.current_path(), Some(addr(HELPER)));

  // And the session carries on over it.
  migrated(&lab.destination.connection, addr(HELPER)).await?;
  lab.net.clear_trace();
  exchange(&mut lab, BULK / 8).await?;
  let (direct, to_helper, from_helper) = link_counts(&lab.net);
  assert_eq!(direct, 0, "the dead path still carried the session");
  assert!(to_helper > 0 && from_helper > 0);
  assert!(lab.session.connection.close_reason().is_none());
  policy.abort();
  Ok(())
}

/// The design's S4 corner: a client offline long enough to lose every
/// pinhole it had, coming back to a bastion that restarted underneath it
/// and remembers neither peer. Nothing re-signals an address; what the
/// fresh helper learns is what each peer's own heartbeat tells it -- the
/// destination's, which has to punch outward to be reachable at all, and
/// the client's when it comes back -- so the session resumes on a relay
/// rebuilt from nothing but liveness.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_offline_session_returns_through_a_restarted_helper()
-> anyhow::Result<()> {
  let mut lab = relayed_session(0x0b9a_de05, link()).await?;
  let (policy, _moved) = spawn_policy(&mut lab.session);
  exchange(&mut lab, BULK / 16).await?;

  // The client drops off the network entirely.
  lab.net.set_host_blackhole(addr(CLIENT).ip(), true);
  // The bastion reboots: its helper is gone, and the one that replaces
  // it serves the same session (its ssh channel is how it is told) with
  // no memory of where either peer is.
  lab.helper.abort();
  let _ = (&mut lab.helper).await;
  tokio::time::sleep(OFFLINE / 2).await;
  let (addrs, restarted) = spawn_helper_handle(&lab.net, lab.nonce, 1);
  assert_eq!(addrs, vec![addr(HELPER)]);
  tokio::time::sleep(OFFLINE / 2).await;
  lab.net.set_host_blackhole(addr(CLIENT).ip(), false);

  lab.session.send.write_all(b"back").await?;
  let mut got = [0u8; 4];
  timeout(DEADLINE, lab.destination.recv.read_exact(&mut got)).await??;
  assert_eq!(&got, b"back");
  lab.destination.send.write_all(b"still here").await?;
  let mut got = [0u8; 10];
  timeout(DEADLINE, lab.session.recv.read_exact(&mut got)).await??;
  assert_eq!(&got, b"still here");
  restarted.abort();
  policy.abort();
  Ok(())
}

/// Every event the client's policy reported, in order, for a scenario
/// that asks what the policy did rather than waiting for one thing.
type Log = Arc<Mutex<Vec<UpgradeEvent>>>;

/// The same policy `spawn_policy` drives, with its events logged.
fn spawn_logged_policy(
  session: &mut ClientSession<DuplexStream>,
) -> (
  tokio::task::JoinHandle<()>,
  tokio::task::JoinHandle<()>,
  Log,
) {
  let (policy, mut moved) = spawn_policy(session);
  let log: Log = Arc::default();
  let drain = tokio::spawn({
    let log = log.clone();
    async move {
      while let Some(event) = moved.recv().await {
        log.lock().unwrap().push(event);
      }
    }
  });
  (policy, drain, log)
}

fn switches(log: &Log) -> Vec<(SocketAddr, PathKind)> {
  log
    .lock()
    .unwrap()
    .iter()
    .filter_map(|event| match event {
      UpgradeEvent::Moved { addr, path_kind } => Some((*addr, *path_kind)),
      UpgradeEvent::HelperReleased => None,
    })
    .collect()
}

/// Waits for the policy to move the session at least once.
async fn first_switch(log: &Log, within: Duration) -> anyhow::Result<()> {
  let deadline = Instant::now() + within;
  while switches(log).is_empty() {
    anyhow::ensure!(Instant::now() < deadline, "the session never moved");
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  Ok(())
}

/// One round trip through the session's own streams: proof the path it
/// is on carries traffic right now.
async fn echo(lab: &mut RelayedLab, tag: &[u8]) -> anyhow::Result<()> {
  lab.session.send.write_all(tag).await?;
  let mut got = vec![0u8; tag.len()];
  timeout(DEADLINE, lab.destination.recv.read_exact(&mut got)).await??;
  anyhow::ensure!(got == tag, "the session corrupted a round trip");
  lab.destination.send.write_all(tag).await?;
  let mut back = vec![0u8; tag.len()];
  timeout(DEADLINE, lab.session.recv.read_exact(&mut back)).await??;
  anyhow::ensure!(back == tag, "the session corrupted a round trip");
  Ok(())
}

/// Heartbeats the destination delivered to the bastion.
///
/// Every heartbeat is a signed binding request of exactly the same
/// length: one session nonce, one role, one aim, one signature. So its
/// length identifies it in the simulated network's trace, which carries
/// sizes but not payloads, and tells it apart from the session's own
/// datagrams crossing the relay -- which makes this a question about
/// what this side is *spending* the bastion on.
fn heartbeats(net: &SimNet, nonce: SessionNonce) -> usize {
  let probe = BindingTransaction::new(
    ProbeLabel::to_helper(nonce, PeerRole::Destination),
    &secret(),
  );
  let len = probe.request().len();
  net
    .trace()
    .iter()
    .filter(|event| match &event.kind {
      EventKind::Delivered {
        src,
        dst,
        len: seen,
      } => {
        *seen == len
          && src.ip() == addr(DEST).ip()
          && dst.ip() == addr(HELPER).ip()
      }
      _ => false,
    })
    .count()
}

/// A flood of probes that name the session and are signed with nothing.
/// The nonce travels in the clear in every probe's `USERNAME`, so this
/// is what anyone who has watched one go past can send: well formed,
/// correctly labeled, and refused -- the question being what it costs
/// the session before it is.
fn spawn_flood(
  net: &SimNet,
  nonce: SessionNonce,
  from: SocketAddr,
  to: SocketAddr,
) -> tokio::task::JoinHandle<()> {
  let net = net.clone();
  tokio::spawn(async move {
    let socket = net.bind(from).unwrap();
    let label = ProbeLabel::to_peer(nonce, PeerRole::Client);
    let wrong = SessionSecret::from_bytes([0x11; 16]);
    loop {
      let request = BindingTransaction::new(label, &wrong);
      let _ = socket.send_to(request.request(), to);
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
  })
}

/// A direct path the session is using is not handed back for ordinary
/// loss. The probes a path's liveness rests on are two small datagrams a
/// round, so at a loss rate QUIC easily tolerates, three rounds in a row
/// go unanswered often. The session's own traffic is the evidence
/// that has to carry the decision -- otherwise a working direct path
/// goes back to the relay, and the destination pays a congestion reset,
/// for nothing.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn loss_does_not_cost_a_working_direct_path_the_session()
-> anyhow::Result<()> {
  for seed in 0..3u64 {
    let mut lab = relayed_session(0x0b9a_de10 + seed, link()).await?;
    let (policy, drain, log) = spawn_logged_policy(&mut lab.session);
    // Loss on the direct path alone, at a rate a session survives.
    lab.net.set_link_symmetric(
      addr(CLIENT).ip(),
      addr(DEST).ip(),
      LinkConfig {
        latency: Duration::from_millis(20),
        loss: 0.25,
        ..LinkConfig::default()
      },
    );
    direct_path(&lab.net, true);
    first_switch(&log, Duration::from_secs(120)).await?;

    // Through the whole grace and out, with the session busy throughout.
    for round in 0..90u32 {
      echo(&mut lab, format!("lossy {round}").as_bytes()).await?;
      tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let moves = switches(&log);
    assert_eq!(
      lab.socket.current_path(),
      Some(addr(DEST)),
      "seed {seed}: a lossy but working direct path was handed back"
    );
    assert_eq!(
      moves,
      vec![(addr(DEST), PathKind::Punched)],
      "seed {seed}: the session flapped on a path it was using"
    );
    assert!(
      log.lock().unwrap().contains(&UpgradeEvent::HelperReleased),
      "seed {seed}: the session never settled onto the direct path"
    );
    policy.abort();
    drain.abort();
  }
  Ok(())
}

/// The destination answers the client's validation probes out of a
/// budget, and a budget with no per-source share is a veto: anyone who
/// has seen one probe knows the nonce, and a flood from one address
/// would spend the whole of it. The upgrade is the one mechanism that
/// gets a session off an untrusted relay, so nothing that cheap may
/// stop it.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_probe_flood_does_not_veto_the_upgrade() -> anyhow::Result<()> {
  let mut lab = relayed_session(0x0b9a_de13, link()).await?;
  let (policy, drain, log) = spawn_logged_policy(&mut lab.session);
  // At both ends of the session at once: the destination, which answers
  // the probes, and the client, which matches the answers.
  let at_destination =
    spawn_flood(&lab.net, lab.nonce, addr("198.51.100.99:5000"), addr(DEST));
  let at_client = spawn_flood(
    &lab.net,
    lab.nonce,
    addr("198.51.100.98:5000"),
    addr(CLIENT),
  );
  // Long enough that any burst is spent before the network changes.
  tokio::time::sleep(Duration::from_secs(30)).await;
  direct_path(&lab.net, true);

  first_switch(&log, Duration::from_secs(120)).await?;
  assert_eq!(switches(&log), vec![(addr(DEST), PathKind::Punched)]);
  echo(&mut lab, b"through the flood").await?;
  assert_eq!(lab.socket.current_path(), Some(addr(DEST)));
  at_destination.abort();
  at_client.abort();
  policy.abort();
  drain.abort();
  Ok(())
}

/// A client that vanished -- no close frame, no probes, nothing -- must
/// stop costing the bastion. Mush sets no idle timeout, so the
/// destination's connection outlives the machine at the other end of it,
/// and the helper reads the destination's heartbeat as the session still
/// being there. Conditioned on the connection alone, that would hold a
/// third party's process and UDP port for good.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_vanished_client_stops_costing_the_bastion() -> anyhow::Result<()> {
  let mut lab = relayed_session(0x0b9a_de14, link()).await?;
  let (policy, drain, _log) = spawn_logged_policy(&mut lab.session);
  echo(&mut lab, b"alive").await?;

  // The client's machine is destroyed: its own policy stops with it,
  // and nothing it sent is ever seen again.
  policy.abort();
  drain.abort();
  lab.net.set_host_blackhole(addr(CLIENT).ip(), true);

  tokio::time::sleep(DEFAULT_SILENCE + Duration::from_secs(60)).await;
  lab.net.clear_trace();
  tokio::time::sleep(Duration::from_secs(120)).await;
  let heartbeats = heartbeats(&lab.net, lab.nonce);
  assert_eq!(
    heartbeats, 0,
    "the bastion was heartbeat {heartbeats} times for a client that is gone"
  );
  Ok(())
}

/// And the bound is a limit on silence rather than a timeout: a
/// client that comes back is a session that carries on, which is the
/// whole shape the relay exists to keep working.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_client_that_comes_back_gets_its_relay_path_back()
-> anyhow::Result<()> {
  let mut lab = relayed_session(0x0b9a_de15, link()).await?;
  let (policy, drain, _log) = spawn_logged_policy(&mut lab.session);
  echo(&mut lab, b"alive").await?;

  // Away long enough that the destination has stopped heartbeating.
  lab.net.set_host_blackhole(addr(CLIENT).ip(), true);
  tokio::time::sleep(DEFAULT_SILENCE + Duration::from_secs(60)).await;
  lab.net.set_host_blackhole(addr(CLIENT).ip(), false);

  echo(&mut lab, b"back").await?;
  lab.net.clear_trace();
  tokio::time::sleep(Duration::from_secs(60)).await;
  assert!(
    heartbeats(&lab.net, lab.nonce) > 0,
    "the relay path was not kept open for a client that came back"
  );
  policy.abort();
  drain.abort();
  Ok(())
}
