// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The jump helper over the deterministic simulated network (tier 1; see
//! `docs/testing.md`): the real `mush_core::helper::serve` loop on a
//! simulated socket, exercising reflection and relay as network
//! behavior rather than state transitions. The reflected address is
//! whatever the simulated network's NAT actually mapped, and a relayed
//! datagram has to survive both peers' filtering to arrive. Client behind
//! a port-restricted home NAT, destination behind a symmetric one -- the
//! shape that defeats reflexive candidates and leaves the relay as the
//! only UDP path.
//!
//! Determinism rules per mush-netsim's crate docs: current-thread
//! runtime, `start_paused`, no real sockets, `biased` selects.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::traversal::{
  CLIENT_PUBLIC, DEADLINE, DEST_PUBLIC, HELPER, addr, helper_socket, ip,
};
use mush_core::bootstrap::{SessionNonce, SessionSecret};
use mush_core::helper::{
  Control, ExitReason, HelperOptions, HelperService, Registration, serve,
};
use mush_core::stun::{BindingTransaction, PeerRole, ProbeLabel};
use mush_netsim::{NatGrade, NatHandle, SimNet, SimSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

const CLIENT_INSIDE: &str = "192.168.1.2:41000";
const DEST_INSIDE: &str = "10.10.0.2:60001";

fn nonce(seed: u8) -> SessionNonce {
  SessionNonce::from_bytes([seed; 16])
}

/// One secret per session; probes sign with it or the helper ignores them.
fn secret(seed: u8) -> SessionSecret {
  SessionSecret::from_bytes([seed ^ 0xa5; 16])
}

/// A helper serving one session, with the channels that carry its ssh
/// control traffic.
struct Lab {
  net: SimNet,
  client: SimSocket,
  client_nat: NatHandle,
  dest: SimSocket,
  helper_addr: SocketAddr,
  control: mpsc::Sender<Control>,
  registrations: mpsc::Receiver<Registration>,
  running: JoinHandle<ExitReason>,
}

impl Lab {
  /// The design's relay shape, with the helper publicly addressed.
  async fn new(seed: u64, options: HelperOptions) -> Lab {
    let net = SimNet::new(seed);
    let client_nat = net.add_nat(
      NatGrade::PortRestricted,
      ip(CLIENT_PUBLIC),
      &[addr(CLIENT_INSIDE).ip()],
    );
    net.add_nat(
      NatGrade::Symmetric,
      ip(DEST_PUBLIC),
      &[addr(DEST_INSIDE).ip()],
    );
    let helper_addr = addr(HELPER);
    let socket = helper_socket(&net, &[helper_addr]);
    let client = net.bind(addr(CLIENT_INSIDE)).unwrap();
    let dest = net.bind(addr(DEST_INSIDE)).unwrap();

    let (control_tx, mut control_rx) = mpsc::channel(8);
    let (registrations_tx, registrations_rx) = mpsc::channel(8);
    let mut service = HelperService::new(Instant::now(), options);
    service.admit(Instant::now(), nonce(1), secret(1)).unwrap();
    let running = tokio::spawn(async move {
      serve(&socket, &mut service, &mut control_rx, &registrations_tx).await
    });

    Lab {
      net,
      client,
      client_nat,
      dest,
      helper_addr,
      control: control_tx,
      registrations: registrations_rx,
      running,
    }
  }

  fn socket(&self, role: PeerRole) -> &SimSocket {
    match role {
      PeerRole::Client => &self.client,
      PeerRole::Destination => &self.dest,
    }
  }

  /// Probes as `role`, returning the reflexive address reported and the
  /// registration it produced (`None` for a repeat from a known address).
  async fn probe(
    &mut self,
    role: PeerRole,
    session: u8,
  ) -> Option<(SocketAddr, Option<Registration>)> {
    let transaction = BindingTransaction::new(
      ProbeLabel::to_helper(nonce(session), role),
      &secret(session),
    );
    let socket = self.socket(role);
    socket
      .send_to(transaction.request(), self.helper_addr)
      .unwrap();
    let mut buf = [0u8; 512];
    let (len, from) = timeout(DEADLINE, socket.recv_from(&mut buf))
      .await
      .ok()?
      .unwrap();
    assert_eq!(from, self.helper_addr, "answer came from somewhere else");
    let reflexive = transaction
      .reflexive(&buf[..len])
      .expect("not this transaction's reflection");
    let registration = self.registrations.try_recv().ok();
    Some((reflexive, registration))
  }

  /// Probes as both peers, which puts the session on the map.
  async fn register_both(&mut self, session: u8) {
    for role in [PeerRole::Client, PeerRole::Destination] {
      self
        .probe(role, session)
        .await
        .unwrap_or_else(|| panic!("no reflection for {role:?}"));
    }
  }

  /// The client vanishing: its control channel closes with no
  /// `MUSH CLOSE`, as a SIGKILLed or crashed client leaves it.
  fn hang_up(&mut self) {
    let (dead, _) = mpsc::channel(1);
    self.control = dead;
  }

  async fn relay(&self, role: PeerRole, payload: &[u8]) -> Option<Vec<u8>> {
    self
      .socket(role)
      .send_to(payload, self.helper_addr)
      .unwrap();
    let peer = self.socket(role.peer());
    let mut buf = [0u8; 2048];
    let (len, from) = timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
      .await
      .ok()?
      .unwrap();
    assert_eq!(from, self.helper_addr, "relay arrived from somewhere else");
    Some(buf[..len].to_vec())
  }
}

/// A QUIC short-header first byte: the fixed bit keeps relay payload
/// out of the STUN parser.
fn payload(body: &str) -> Vec<u8> {
  let mut packet = vec![0x40u8];
  packet.extend_from_slice(body.as_bytes());
  packet
}

/// The mapped address is the server-reflexive candidate the design's
/// establishment punches at.
#[tokio::test(start_paused = true)]
async fn reflection_reports_each_peer_s_mapped_address() {
  let mut lab = Lab::new(1, HelperOptions::default()).await;

  let (client_reflexive, registration) =
    lab.probe(PeerRole::Client, 1).await.expect("no reflection");
  assert_eq!(client_reflexive.ip(), ip(CLIENT_PUBLIC));
  assert_ne!(client_reflexive, addr(CLIENT_INSIDE));
  assert_eq!(
    registration,
    Some(Registration {
      nonce: nonce(1),
      role: PeerRole::Client,
      addr: client_reflexive,
      previous: None,
    })
  );

  let (dest_reflexive, registration) = lab
    .probe(PeerRole::Destination, 1)
    .await
    .expect("no reflection");
  assert_eq!(dest_reflexive.ip(), ip(DEST_PUBLIC));
  assert_eq!(registration.map(|r| r.addr), Some(dest_reflexive));

  // A repeat from the same mapping is answered and registers nothing new.
  let (again, registration) =
    lab.probe(PeerRole::Client, 1).await.expect("no reflection");
  assert_eq!(again, client_reflexive);
  assert_eq!(registration, None);
}

/// The relay of last resort: each peer opens its own flow to the helper.
#[tokio::test(start_paused = true)]
async fn the_relay_carries_payload_between_both_peers() {
  let mut lab = Lab::new(2, HelperOptions::default()).await;
  lab.register_both(1).await;

  assert_eq!(
    lab
      .relay(PeerRole::Client, &payload("to-the-destination"))
      .await,
    Some(payload("to-the-destination"))
  );
  assert_eq!(
    lab.relay(PeerRole::Destination, &payload("and-back")).await,
    Some(payload("and-back"))
  );

  // Dumb forwarding: a full-size datagram crosses byte for byte, and
  // this one is not QUIC at all, which an inspecting helper would notice.
  let bulk: Vec<u8> = std::iter::once(0x40)
    .chain((0..1200).map(|i| i as u8))
    .collect();
  assert_eq!(lab.relay(PeerRole::Client, &bulk).await, Some(bulk));
}

/// With no registered far side, the helper says nothing rather than
/// guessing.
#[tokio::test(start_paused = true)]
async fn payload_without_a_registered_peer_goes_nowhere() {
  let mut lab = Lab::new(3, HelperOptions::default()).await;
  lab.probe(PeerRole::Client, 1).await.expect("no reflection");
  assert_eq!(lab.relay(PeerRole::Client, &payload("early")).await, None);
  // Nor does an unregistered sender get anything relayed for it.
  lab
    .dest
    .send_to(&payload("unknown"), lab.helper_addr)
    .unwrap();
  let mut buf = [0u8; 64];
  assert!(
    timeout(Duration::from_secs(5), lab.client.recv_from(&mut buf))
      .await
      .is_err()
  );
}

/// Roaming: the client's mappings die, its next probe registers where
/// it ended up, and the relay follows without the destination noticing.
#[tokio::test(start_paused = true)]
async fn a_roaming_client_keeps_its_relay() {
  let mut lab = Lab::new(4, HelperOptions::default()).await;
  let (before, _) = lab.probe(PeerRole::Client, 1).await.expect("reflection");
  lab
    .probe(PeerRole::Destination, 1)
    .await
    .expect("no reflection");
  assert_eq!(
    lab.relay(PeerRole::Destination, &payload("before")).await,
    Some(payload("before"))
  );

  // The NAT reboots, so the helper's address for the client goes dead.
  lab.client_nat.flush_mappings();
  tokio::time::advance(Duration::from_secs(1)).await;
  assert_eq!(
    lab.relay(PeerRole::Destination, &payload("stranded")).await,
    None
  );

  // The client's next probe puts it back on the map.
  let (after, registration) =
    lab.probe(PeerRole::Client, 1).await.expect("reflection");
  assert_eq!(registration.and_then(|r| r.previous), Some(before));
  assert_ne!(after, before);
  assert_eq!(
    lab.relay(PeerRole::Destination, &payload("after")).await,
    Some(payload("after"))
  );
}

/// The nonce check on the wire, for a session the helper never heard of.
#[tokio::test(start_paused = true)]
async fn an_unserved_nonce_is_answered_with_silence() {
  let mut lab = Lab::new(5, HelperOptions::default()).await;
  let transaction = BindingTransaction::new(
    ProbeLabel::to_helper(nonce(9), PeerRole::Client),
    &secret(9),
  );
  lab
    .client
    .send_to(transaction.request(), lab.helper_addr)
    .unwrap();
  let mut buf = [0u8; 512];
  assert!(
    timeout(Duration::from_secs(5), lab.client.recv_from(&mut buf))
      .await
      .is_err()
  );

  // The same peer, for a served session, is answered at once.
  assert!(lab.probe(PeerRole::Client, 1).await.is_some());
}

/// The process exits instead of lingering out its retention window.
#[tokio::test(start_paused = true)]
async fn closing_the_session_ends_the_loop() {
  let mut lab = Lab::new(6, HelperOptions::default()).await;
  lab.probe(PeerRole::Client, 1).await.expect("no reflection");
  lab.control.send(Control::Close(nonce(1))).await.unwrap();
  assert_eq!(
    timeout(DEADLINE, lab.running).await.unwrap().unwrap(),
    ExitReason::SessionsClosed
  );
  // Nothing was left running: no traffic on the network after the close.
  lab.net.clear_trace();
  lab
    .client
    .send_to(&payload("after"), lab.helper_addr)
    .unwrap();
  let mut buf = [0u8; 64];
  assert!(
    timeout(Duration::from_secs(5), lab.dest.recv_from(&mut buf))
      .await
      .is_err()
  );
}

/// The client hangs up its ssh channel once the path settles.
#[tokio::test(start_paused = true)]
async fn the_relay_outlives_the_control_channel() {
  let mut lab = Lab::new(9, HelperOptions::default()).await;
  lab.register_both(1).await;

  // The channel goes away, and with it any way to report registrations.
  let (control, registrations) = (
    lab.control.clone(),
    std::mem::replace(&mut lab.registrations, mpsc::channel(1).1),
  );
  drop(control);
  drop(registrations);
  lab.control = mpsc::channel(1).0;
  tokio::time::advance(Duration::from_secs(1)).await;

  assert!(!lab.running.is_finished());
  assert_eq!(
    lab
      .relay(PeerRole::Client, &payload("after the hangup"))
      .await,
    Some(payload("after the hangup"))
  );
  // The peers can still re-register, which is what a roam needs.
  assert!(lab.probe(PeerRole::Client, 1).await.is_some());
}

/// A helper nobody ever probes self-destructs on the bootstrap
/// timeout, so a failed establishment leaves nothing on the bastion.
#[tokio::test(start_paused = true)]
async fn an_unused_helper_gives_up() {
  let lab = Lab::new(
    7,
    HelperOptions {
      bootstrap_timeout: Duration::from_secs(60),
      ..HelperOptions::default()
    },
  )
  .await;
  assert_eq!(
    timeout(DEADLINE, lab.running).await.unwrap().unwrap(),
    ExitReason::Unused
  );
}

/// A client that vanished without saying so does not leave a helper
/// behind for good, whether or not the session used the relay.
///
/// Indefinite retention is for a relayed session whose peers still say
/// they are there. One that went direct or punched -- the common case,
/// since the client closes the helper as soon as either wins -- has
/// nothing to preserve once the control channel is gone, and a relayed
/// one whose peers have both fallen silent has nobody to preserve it
/// for. On a shared bastion the alternative is one process and one UDP
/// port per crashed client, forever.
#[tokio::test(start_paused = true)]
async fn a_helper_whose_client_vanished_gives_up() {
  for (seed, bootstrap_timeout, relayed) in [
    (9, Duration::from_secs(60), false),
    (17, Duration::from_secs(5), true),
  ] {
    let mut lab = Lab::new(
      seed,
      HelperOptions {
        bootstrap_timeout,
        ..HelperOptions::default()
      },
    )
    .await;
    lab.register_both(1).await;
    if relayed {
      assert_eq!(
        lab.relay(PeerRole::Client, &payload("hello")).await,
        Some(payload("hello"))
      );
    }
    lab.hang_up();
    assert_eq!(
      timeout(DEADLINE, lab.running).await.unwrap().unwrap(),
      ExitReason::Abandoned,
      "relayed={relayed}"
    );
  }
}

/// The session indefinite retention exists for: one whose peers keep
/// saying they are there outlives the client's channel, however long
/// the client is away. The destination's heartbeat says it
/// (`mush_core::upgrade`) and is all the helper has to go on once the
/// ssh channel that started it is gone -- which a roaming client's is,
/// since the address its ssh ran on is the one that moved.
#[tokio::test(start_paused = true)]
async fn a_heartbeat_outlives_the_control_channel() {
  // A short give-up window keeps the wait that proves the helper is
  // *not* giving up inside the simulated network's NAT mapping lifetime:
  // the helper's own clock is under test, not a NAT forgetting the peers.
  let bootstrap_timeout = Duration::from_secs(5);
  let mut lab = Lab::new(
    10,
    HelperOptions {
      bootstrap_timeout,
      ..HelperOptions::default()
    },
  )
  .await;
  lab.register_both(1).await;
  assert_eq!(
    lab.relay(PeerRole::Client, &payload("hello")).await,
    Some(payload("hello"))
  );
  lab.hang_up();
  for _ in 0..4 {
    tokio::time::advance(bootstrap_timeout / 2).await;
    lab
      .probe(PeerRole::Destination, 1)
      .await
      .expect("no reflection");
    assert!(!lab.running.is_finished(), "the relay was abandoned");
  }
  assert_eq!(
    lab.relay(PeerRole::Client, &payload("still here")).await,
    Some(payload("still here"))
  );
}

/// The `--retain` limit fires on silence; traffic pushes it out.
#[tokio::test(start_paused = true)]
async fn retention_ends_a_silent_helper() {
  // Inside the simulated network's NAT mapping lifetime: the helper's
  // retention clock is under test, not a NAT forgetting the peers.
  let retain = Duration::from_secs(20);
  let mut lab = Lab::new(
    8,
    HelperOptions {
      retain: Some(retain),
      ..HelperOptions::default()
    },
  )
  .await;
  lab.register_both(1).await;
  tokio::time::advance(retain / 2).await;
  assert!(!lab.running.is_finished());
  assert_eq!(
    lab.relay(PeerRole::Client, &payload("still here")).await,
    Some(payload("still here"))
  );
  assert_eq!(
    timeout(DEADLINE, lab.running).await.unwrap().unwrap(),
    ExitReason::Retained
  );
}
