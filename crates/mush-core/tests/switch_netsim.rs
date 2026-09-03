// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The path manager (tier 1; see `docs/testing.md`): a real session,
//! established on the relay because nothing else was reachable, moved
//! onto the direct path mid-stream and back, over the deterministic
//! simulated network.
//!
//! The design's Phase C claim is that a path switch is invisible to
//! everything but the wire: quinn addresses a virtual peer for the
//! session's whole life, and the destination sees an ordinary client
//! migration it validates and accepts with no logic of its own. So these
//! scenarios assert what that claim rules out -- a broken stream, a
//! dropped connection, a second connection at the destination, a virtual
//! address anywhere on the wire -- rather than the switch itself, which
//! is one index. The lab is `common::traversal`'s.
//!
//! Determinism rules per mush-netsim's crate docs: current-thread
//! runtime, `start_paused`, no real sockets, `biased` selects.

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use common::payload;
use common::traversal::{
  CLIENT, DEADLINE, DEST, HELPER, RelayedLab, addr, direct_path,
  relayed_session,
};
use mush_core::path::PathKind;
use mush_core::traversal::Handable;
use mush_netsim::{EventKind, LinkConfig, SimNet};
use tokio::time::timeout;

/// Bytes each direction carries across a switch: enough round trips that
/// the transfer cannot help but straddle it, few enough to stay quick.
const BULK: usize = 1024 * 1024;

/// How much must have arrived before the switch, so that the switch
/// happens on a session with data in flight rather than an idle one.
const IN_FLIGHT: u64 = 64 * 1024;

/// How often progress is sampled while waiting for that.
const SAMPLE: Duration = Duration::from_millis(10);

/// Brings a session up on the relay, then opens the direct path. The
/// client and destination cannot reach each other during establishment,
/// so direct and punched both fail and the relay carries the session --
/// the shape the design's upgrade exists for. Lifting the blackhole
/// afterwards is the network change a real punch or a recovered route
/// would be.
async fn opened_session(
  seed: u64,
  link: LinkConfig,
) -> anyhow::Result<RelayedLab> {
  let lab = relayed_session(seed, link).await?;
  direct_path(&lab.net, true);
  Ok(lab)
}

/// Feeds a stream and finishes it.
fn spawn_writer(
  mut send: quinn::SendStream,
  bytes: Vec<u8>,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
  tokio::spawn(async move {
    send.write_all(&bytes).await?;
    send.finish()?;
    Ok(())
  })
}

/// Reads a stream to length, reporting progress so a scenario can act
/// while the transfer is under way, and checks it byte for byte.
fn spawn_reader(
  mut recv: quinn::RecvStream,
  expected: Vec<u8>,
  progress: Arc<AtomicU64>,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
  tokio::spawn(async move {
    let mut got = vec![0u8; expected.len()];
    let mut at = 0;
    while at < got.len() {
      let read = recv
        .read(&mut got[at..])
        .await?
        .ok_or_else(|| anyhow::anyhow!("the stream ended at {at} bytes"))?;
      at += read;
      progress.store(at as u64, Ordering::Relaxed);
    }
    anyhow::ensure!(got == expected, "the stream was corrupted");
    Ok(())
  })
}

/// Waits until `progress` passes `bytes`, so a switch happens on a
/// session that is actually carrying traffic.
async fn under_way(progress: &AtomicU64, bytes: u64) -> anyhow::Result<u64> {
  let deadline = tokio::time::Instant::now() + DEADLINE;
  loop {
    let at = progress.load(Ordering::Relaxed);
    if at >= bytes {
      return Ok(at);
    }
    anyhow::ensure!(
      tokio::time::Instant::now() < deadline,
      "only {at} bytes moved"
    );
    tokio::time::sleep(SAMPLE).await;
  }
}

/// Waits for the destination to migrate onto `want`, which is the whole
/// of what it has to do about a switch: QUIC validates the client's new
/// address and carries on.
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
    tokio::time::sleep(SAMPLE).await;
  }
  Ok(())
}

/// Whether the simulated network ever saw an address on this host, in
/// either role, on a datagram that was sent, dropped, duplicated, or
/// delivered.
fn on_the_wire(net: &SimNet, host: IpAddr) -> bool {
  net.trace().iter().any(|event| match &event.kind {
    EventKind::Sent { src, dst, .. }
    | EventKind::Dropped { src, dst, .. }
    | EventKind::Duplicated { src, dst, .. }
    | EventKind::Delivered { src, dst, .. }
    | EventKind::NatRejected { src, dst, .. } => {
      src.ip() == host || dst.ip() == host
    }
    EventKind::NatMapped { inside, outside } => {
      inside.ip() == host || outside.ip() == host
    }
  })
}

/// The virtual peer, and every alias allocated beside it, are addresses of
/// one host that exists only inside the client process. One check
/// covers the whole block: a losing candidate's alias would leak from
/// the same address as the session's own.
fn assert_nothing_virtual_on_the_wire(net: &SimNet, virt: SocketAddr) {
  assert!(
    !on_the_wire(net, virt.ip()),
    "the virtual peer {virt} reached the simulated network"
  );
}

/// The upgrade the design's Phase C is for: a session established
/// through the relay is moved onto the direct path while it is carrying
/// data, and the stream neither breaks nor notices.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_switch_mid_stream_keeps_the_stream_and_migrates_the_destination()
-> anyhow::Result<()> {
  let lab = opened_session(
    0x5717_c401,
    LinkConfig {
      latency: Duration::from_millis(20),
      ..LinkConfig::default()
    },
  )
  .await?;

  // quinn is addressing a peer that exists nowhere: the address it
  // dialed is the manager's, and the wire is carrying the relay's.
  let virt = lab.socket.peer().expect("the session committed to a path");
  assert_eq!(lab.session.connection.remote_address(), virt);
  assert_eq!(lab.socket.current_path(), Some(addr(HELPER)));

  // Both connections outlive the streams handed to the transfer tasks.
  let client = lab.session.connection.clone();
  let destination = lab.destination.connection.clone();
  let up = payload(BULK);
  let down = payload(BULK);
  let arrived_up = Arc::new(AtomicU64::new(0));
  let arrived_down = Arc::new(AtomicU64::new(0));
  let writers = (
    spawn_writer(lab.session.send, up.clone()),
    spawn_writer(lab.destination.send, down.clone()),
  );
  let readers = (
    spawn_reader(lab.destination.recv, up, arrived_up.clone()),
    spawn_reader(lab.session.recv, down, arrived_down.clone()),
  );

  under_way(&arrived_up, IN_FLIGHT).await?;
  let at_switch = arrived_up.load(Ordering::Relaxed);
  let opened_at = destination.stable_id();

  // The switch itself, with the transfer running through it.
  assert!(lab.socket.add_path(addr(DEST), PathKind::Direct));
  assert!(lab.socket.switch_to(addr(DEST)));
  assert_eq!(lab.socket.current_path(), Some(addr(DEST)));

  // The destination follows, having been told nothing.
  migrated(&destination, addr(CLIENT)).await?;

  timeout(DEADLINE, readers.0).await???;
  timeout(DEADLINE, readers.1).await???;
  timeout(DEADLINE, writers.0).await???;
  timeout(DEADLINE, writers.1).await???;
  assert!(
    at_switch < BULK as u64,
    "the transfer had finished before the switch"
  );

  // One connection throughout, on both sides, and one peer address as
  // far as quinn on the client ever knew.
  assert_eq!(destination.stable_id(), opened_at);
  assert!(destination.close_reason().is_none());
  assert!(client.close_reason().is_none());
  assert_eq!(client.remote_address(), virt);

  // The path it is on is the one that is answering.
  let paths = lab.socket.observe();
  let current: Vec<_> = paths.iter().filter(|path| path.current).collect();
  assert_eq!(current.len(), 1);
  assert_eq!(current[0].addr, addr(DEST));
  assert_eq!(current[0].path_kind, PathKind::Direct);
  assert!(current[0].inbound > 0, "nothing arrived on the direct path");

  assert_nothing_virtual_on_the_wire(&lab.net, virt);
  Ok(())
}

/// Switching is cheap and reversible, so a policy that changes its mind
/// -- a direct path that comes and goes -- must not cost the session.
/// Under loss, where every switch also resets the destination's
/// congestion state for the new path, the stream still arrives whole.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn repeated_switching_under_loss_keeps_the_stream() -> anyhow::Result<()>
{
  let lab = opened_session(
    0x5717_c402,
    LinkConfig {
      latency: Duration::from_millis(20),
      loss: 0.03,
      ..LinkConfig::default()
    },
  )
  .await?;
  let virt = lab.socket.peer().expect("the session committed to a path");

  let client = lab.session.connection.clone();
  let destination = lab.destination.connection.clone();
  let up = payload(BULK / 4);
  let down = payload(BULK / 4);
  let arrived_up = Arc::new(AtomicU64::new(0));
  let arrived_down = Arc::new(AtomicU64::new(0));
  let writers = (
    spawn_writer(lab.session.send, up.clone()),
    spawn_writer(lab.destination.send, down.clone()),
  );
  let readers = (
    spawn_reader(lab.destination.recv, up, arrived_up.clone()),
    spawn_reader(lab.session.recv, down, arrived_down.clone()),
  );

  under_way(&arrived_up, IN_FLIGHT).await?;
  assert!(lab.socket.add_path(addr(DEST), PathKind::Direct));
  // Long enough apart that each switch is a migration the destination
  // finishes validating before the next one, which is the cadence any
  // upgrade policy would switch on; flapping faster than a round trip
  // is a policy bug, not something the mechanism promises to be good at.
  for round in 0..8 {
    let to = match round % 2 {
      0 => addr(DEST),
      _ => addr(HELPER),
    };
    assert!(lab.socket.switch_to(to), "round {round} could not switch");
    assert_eq!(lab.socket.current_path(), Some(to));
    tokio::time::sleep(Duration::from_millis(200)).await;
  }
  // Ending where the upgrade wanted to be.
  assert!(lab.socket.switch_to(addr(DEST)));

  timeout(DEADLINE, readers.0).await???;
  timeout(DEADLINE, readers.1).await???;
  timeout(DEADLINE, writers.0).await???;
  timeout(DEADLINE, writers.1).await???;
  assert!(client.close_reason().is_none());
  assert!(destination.close_reason().is_none());

  // Both paths carried the session, which is what makes this a switching
  // test rather than eight no-ops.
  let paths = lab.socket.observe();
  for want in [addr(DEST), addr(HELPER)] {
    let path = paths
      .iter()
      .find(|path| path.addr == want)
      .unwrap_or_else(|| panic!("no path at {want}"));
    assert!(path.inbound > 0, "nothing arrived over {want}");
  }
  assert_nothing_virtual_on_the_wire(&lab.net, virt);
  Ok(())
}

/// A rebind and a switch are different moves, and neither may undo the
/// other: the stall prober's fresh socket carries the same session, so
/// the shim goes with it, and the session keeps the path it is on while
/// changing the mapping it leaves from. Without the shim around the
/// replacement the session would go on addressing a peer nothing maps.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_rebind_keeps_the_session_on_its_path() -> anyhow::Result<()> {
  let mut lab = opened_session(
    0x5717_c404,
    LinkConfig {
      latency: Duration::from_millis(20),
      ..LinkConfig::default()
    },
  )
  .await?;
  let virt = lab.socket.peer().expect("the session committed to a path");
  assert!(lab.socket.add_path(addr(DEST), PathKind::Direct));
  assert!(lab.socket.switch_to(addr(DEST)));
  lab.session.send.write_all(b"direct").await?;
  let mut got = [0u8; 6];
  timeout(DEADLINE, lab.destination.recv.read_exact(&mut got)).await??;
  migrated(&lab.destination.connection, addr(CLIENT)).await?;

  // The rebind the prober makes on a stall, wired as the CLI wires it.
  let moved: SocketAddr = "203.0.113.2:41999".parse()?;
  let fresh = Box::new(lab.net.bind(moved)?);
  lab
    .session
    .endpoint
    .rebind_abstract(lab.socket.rebound(fresh).hand())?;

  lab.session.send.write_all(b"rebound").await?;
  let mut got = [0u8; 7];
  timeout(DEADLINE, lab.destination.recv.read_exact(&mut got)).await??;
  assert_eq!(&got, b"rebound");
  // The session is still on the direct path, reached from a new mapping,
  // which the destination takes for the migration it is.
  migrated(&lab.destination.connection, moved).await?;
  assert_eq!(lab.socket.current_path(), Some(addr(DEST)));
  assert_eq!(lab.session.connection.remote_address(), virt);
  assert_nothing_virtual_on_the_wire(&lab.net, virt);
  Ok(())
}

/// A switch onto a path the session was never offered is refused, and
/// the session stays where it was. The manager is the only thing that
/// knows which addresses are the destination's, and a caller that
/// guesses one must not be able to aim the session at it.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_unoffered_path_cannot_take_the_session() -> anyhow::Result<()> {
  let mut lab = opened_session(
    0x5717_c403,
    LinkConfig {
      latency: Duration::from_millis(20),
      ..LinkConfig::default()
    },
  )
  .await?;
  let virt = lab.socket.peer().expect("the session committed to a path");

  assert!(!lab.socket.switch_to(addr(DEST)));
  assert!(!lab.socket.switch_to(virt));
  assert_eq!(lab.socket.current_path(), Some(addr(HELPER)));

  lab.session.send.write_all(b"still here").await?;
  let mut got = [0u8; 10];
  timeout(DEADLINE, lab.destination.recv.read_exact(&mut got)).await??;
  assert_eq!(&got, b"still here");
  assert_nothing_virtual_on_the_wire(&lab.net, virt);
  Ok(())
}
