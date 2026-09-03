// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The punch success matrix (tier 1; see `docs/testing.md`): the real
//! establishment engines and the real jump helper working through the
//! design's fallback order over the deterministic simulated network,
//! across every pair of the simulator's six NAT grades.
//!
//! Each cell runs a whole session -- both establishment engines probing
//! from the very socket their QUIC endpoint uses, the helper's own
//! `serve` loop reflecting and relaying in between -- and asserts which
//! kind of path carried it: direct, punched, or relayed. The ordering is
//! the claim, so a cell that quietly settled on the relay when punching
//! should have worked must not read as a pass. The documented impossible
//! cells stay in the matrix rather than excluded from it, asserted as
//! relayed, which is what stops a false success there from passing as a
//! punch. [`expected`] has the reasoning cell by cell.
//!
//! Determinism rules per mush-netsim's crate docs: current-thread
//! runtime, `start_paused`, no real sockets, `biased` selects. Each cell
//! is seeded from its own grade pair, so a failing cell reruns alone.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::traversal::{
  CLIENT, CLIENT_PUBLIC, ClientSetup, DEADLINE, DEST, DEST_PUBLIC, Destination,
  HELPER, HELPER_DMZ, LabClient, addr, ip, lab_client, read_hello,
  run_destination, spawn_helper_handle, spawn_policy,
};
use mush_core::bootstrap::{Connect, PROTOCOL_VERSION, SessionNonce};
use mush_core::client::{ClientSession, EstablishError};
use mush_core::path::{Arrival, PathKind, TRAVERSAL_ESTABLISH_TIMEOUT};
use mush_core::pinning::SessionIdentity;
use mush_core::roaming::{
  FreshSocket, ProbeOptions, ProbeStats, Prober, SocketFactory,
};
use mush_core::traversal::TraversalSocket;
use mush_netsim::{LinkConfig, NatGrade, NatHandle, SimNet, derive_u64};
use stun_types::attribute::XorMappedAddress;
use stun_types::message::{BINDING, Message, MessageClass, MessageWriteVec};
use stun_types::prelude::*;
use tokio::io::{AsyncWriteExt as _, DuplexStream};
use tokio::time::{Instant, timeout};

/// A total outage, long enough that the prober declares the stall (two
/// probe intervals of sampling lag plus the threshold) and probes
/// through it.
const OUTAGE: Duration = Duration::from_secs(12);

/// How long a restored path may take to carry a byte again. Generous
/// against the probe cadence, and far short of forever, which is what a
/// relay whose registration was lost would take.
const RECOVERY: Duration = Duration::from_secs(30);

/// A plain public STUN server, the one third party the design lets a
/// session contact and only when `--stun <server>` asks for it.
const STUN: &str = "198.51.100.99:3478";

/// Starts a plain RFC 8489 reflector at [`STUN`]. Nothing here is Mush:
/// it knows no nonce and no secret, checks nothing, and answers every
/// binding request it can parse with the address it arrived from. Its
/// answer is unsigned, which is why the client's transaction for it is
/// unlabeled and why the address it reports is believed on the strength
/// of the transaction id and the source address alone.
fn spawn_stun_reflector(net: &SimNet) -> tokio::task::JoinHandle<()> {
  let socket = net.bind(addr(STUN)).unwrap();
  tokio::spawn(async move {
    let mut buf = vec![0u8; 2048];
    while let Ok((len, from)) = socket.recv_from(&mut buf).await {
      let Ok(request) = Message::from_bytes(&buf[..len]) else {
        continue;
      };
      if !request.has_class(MessageClass::Request)
        || !request.has_method(BINDING)
      {
        continue;
      }
      let mut response =
        Message::builder_success(&request, MessageWriteVec::new());
      let observed = XorMappedAddress::new(from, request.transaction_id());
      let _ = response.add_attribute(&observed);
      let _ = socket.send_to(&response.finish(), from);
    }
  })
}

/// Every grade the simulated network models, in the order the matrix
/// prints.
const GRADES: [NatGrade; 6] = [
  NatGrade::Open,
  NatGrade::AddressRestricted,
  NatGrade::PortRestricted,
  NatGrade::Symmetric,
  NatGrade::OneToOne,
  NatGrade::FirewallOnly,
];

fn grade_name(grade: NatGrade) -> &'static str {
  match grade {
    NatGrade::Open => "open",
    NatGrade::AddressRestricted => "address-restricted",
    NatGrade::PortRestricted => "port-restricted",
    NatGrade::Symmetric => "symmetric",
    NatGrade::OneToOne => "one-to-one",
    NatGrade::FirewallOnly => "firewall-only",
  }
}

/// One cell of the matrix: a whole session across the two edges, with
/// the helper available. Returns the kind of path that carried it,
/// having first proved bytes cross both ways -- reporting a kind of path
/// claims the path works, and a handshake onto a path nothing crosses
/// would otherwise read as a success.
async fn cell(
  seed: u64,
  client_grade: NatGrade,
  dest_grade: NatGrade,
  helper: bool,
) -> anyhow::Result<PathKind> {
  let settled = open(
    seed,
    client_grade,
    dest_grade,
    Told {
      helper_addrs: usize::from(helper),
      serving: helper,
      observed: None,
      stun: false,
    },
    |_, _| {},
  )
  .await?
  .settle()
  .await?;
  let path_kind = settled.session.path_kind;
  settled
    .destination
    .connection
    .close(0u32.into(), b"cell over");
  settled.session.connection.close(0u32.into(), b"cell over");
  Ok(path_kind)
}

/// A session whose client end is up and whose destination end is still
/// to be resolved: QUIC opens a stream lazily, so the destination's
/// accept finishes only once the client has written to it.
struct Opening {
  net: SimNet,
  /// The client's own socket, which is also what a relayed session may
  /// only ever ping from.
  socket: Arc<TraversalSocket>,
  session: ClientSession<DuplexStream>,
  destination: tokio::task::JoinHandle<anyhow::Result<Destination>>,
}

/// A session proven to carry bytes both ways.
struct Settled {
  net: SimNet,
  socket: Arc<TraversalSocket>,
  session: ClientSession<DuplexStream>,
  destination: Destination,
}

impl Opening {
  async fn settle(self) -> anyhow::Result<Settled> {
    let Self {
      net,
      socket,
      mut session,
      destination,
      ..
    } = self;
    session.send.write_all(b"ping").await?;
    let mut destination = timeout(DEADLINE, destination).await???;
    let mut buf = [0u8; 4];
    timeout(DEADLINE, destination.recv.read_exact(&mut buf)).await??;
    anyhow::ensure!(&buf == b"ping", "the destination read {buf:?}");
    destination.send.write_all(b"pong").await?;
    let mut buf = [0u8; 4];
    timeout(DEADLINE, session.recv.read_exact(&mut buf)).await??;
    anyhow::ensure!(&buf == b"pong", "the client read {buf:?}");
    Ok(Settled {
      net,
      socket,
      session,
      destination,
    })
  }
}

/// What the client is told about itself during establishment, which is
/// what `mush connect` learns from its second ssh.
#[derive(Debug, Default, Clone, Copy)]
struct Told {
  /// How many addresses the jump helper answers on, zero for a bastion
  /// with no helper on it at all.
  helper_addrs: usize,
  /// Whether anything is listening there: a helper that answered its ssh
  /// but cannot be reached over UDP announces addresses it never serves.
  serving: bool,
  /// The jump's view of this client, which a helper reports in its
  /// ready line and a helperless bastion is asked for over ssh.
  observed: Option<SocketAddr>,
  /// Whether this session queries [`STUN`] for its own reflexive address
  /// (`--stun <server>`), default off. Set, a reflector runs there and
  /// the client's plan names it.
  stun: bool,
}

/// Establishes a session across two edges of the given grades.
/// `arrange` runs once the simulated network and its edges exist and
/// before anything is established, for a test that disturbs the session
/// during establishment.
async fn open(
  seed: u64,
  client_grade: NatGrade,
  dest_grade: NatGrade,
  told: Told,
  arrange: impl FnOnce(&SimNet, &NatHandle),
) -> anyhow::Result<Opening> {
  let net = SimNet::new(seed);
  net.set_default_link(LinkConfig {
    latency: Duration::from_millis(20),
    ..LinkConfig::default()
  });
  let client_nat =
    net.add_nat(client_grade, ip(CLIENT_PUBLIC), &[addr(CLIENT).ip()]);
  net.add_nat(dest_grade, ip(DEST_PUBLIC), &[addr(DEST).ip()]);
  arrange(&net, &client_nat);
  drop(client_nat);

  let stun_servers = match told.stun {
    true => {
      spawn_stun_reflector(&net);
      vec![addr(STUN)]
    }
    false => Vec::new(),
  };

  let nonce = SessionNonce::from_bytes([0x5a; 16]);
  let helper = match told.serving {
    true => spawn_helper_handle(&net, nonce, told.helper_addrs).0,
    // Announced but never bound: probes reach nothing, which is a
    // helper whose UDP this client cannot get to.
    false => [HELPER, HELPER_DMZ][..told.helper_addrs]
      .iter()
      .copied()
      .map(addr)
      .collect(),
  };

  let (client_io, server_io) = tokio::io::duplex(64 * 1024);
  let destination = tokio::spawn(run_destination(
    net.clone(),
    server_io,
    derive_u64(seed, "destination"),
  ));

  // The helper's ready line, as `mush connect` would deliver it once its
  // second ssh answers; an empty set is a bastion with no helper on it.
  let mut arrivals = vec![Arrival::Helper(helper)];
  arrivals.extend(told.observed.map(Arrival::Observed));
  let LabClient {
    options,
    socket,
    arrivals: _arrivals,
  } = lab_client(
    &net,
    ClientSetup {
      client_addr: addr(CLIENT),
      nonce,
      endpoint_seed: derive_u64(seed, "client"),
      stun_servers,
      arrivals,
    },
  )
  .await?;

  let session =
    timeout(DEADLINE, ClientSession::establish(client_io, options)).await??;

  Ok(Opening {
    net,
    socket,
    session,
    destination,
  })
}

/// The kind of path each pair of edges is expected to settle on, with
/// the helper available. The reasoning is the design's, cell by cell.
///
/// A destination whose edge keeps one mapping per inside socket is
/// reachable at the reflexive address the helper reported, once its own
/// outward probes open the filter guarding it, so every such pair
/// punches. A symmetric destination has no such address to offer: the
/// mapping it showed the helper is bound to the helper, and the client's
/// packets arriving at it are filtered, leaving only the relay. A
/// symmetric *client* keeps punching against every edge that filters on
/// address alone (its NAT has one public IP), and loses to the two that
/// filter on the exact port it did not use.
fn expected(client: NatGrade, dest: NatGrade) -> PathKind {
  match (dest, client) {
    (NatGrade::Symmetric, _) => PathKind::Relayed,
    (
      NatGrade::PortRestricted | NatGrade::FirewallOnly,
      NatGrade::Symmetric,
    ) => PathKind::Relayed,
    _ => PathKind::Punched,
  }
}

/// The matrix itself: every pair of edges, and the kind of path each
/// settles on.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn the_punch_matrix_settles_on_the_expected_path_kind()
-> anyhow::Result<()> {
  let mut wrong = Vec::new();
  let mut grid = String::from("client \\ destination\n");
  for client in GRADES {
    grid.push_str(&format!("{:>20}:", grade_name(client)));
    for dest in GRADES {
      let seed = derive_u64(
        0x6d75_7368,
        &format!("{}x{}", grade_name(client), grade_name(dest)),
      );
      let path_kind = cell(seed, client, dest, true).await?;
      grid.push_str(&format!(" {path_kind:>8}"));
      let want = expected(client, dest);
      if path_kind != want {
        wrong.push(format!(
          "{} x {}: expected {want}, got {path_kind} (seed {seed:#x})",
          grade_name(client),
          grade_name(dest)
        ));
      }
    }
    grid.push('\n');
  }
  assert!(wrong.is_empty(), "{grid}\n{}", wrong.join("\n"));
  Ok(())
}

/// The impossible cell on its own: two symmetric edges leave no
/// reflexive address either side can use, so the session must settle on
/// the relay and carry bytes there rather than report a punch that never
/// happened.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn symmetric_on_both_sides_uses_the_relay() -> anyhow::Result<()> {
  let path_kind =
    cell(0x5ecd, NatGrade::Symmetric, NatGrade::Symmetric, true).await?;
  assert_eq!(path_kind, PathKind::Relayed);
  Ok(())
}

/// Reproducibility: the same seed and grades produce the same kind of
/// path.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_cell_replays_from_its_seed() -> anyhow::Result<()> {
  for _ in 0..2 {
    let path_kind = cell(
      0x1234_5678,
      NatGrade::PortRestricted,
      NatGrade::Symmetric,
      true,
    )
    .await?;
    assert_eq!(path_kind, PathKind::Relayed);
  }
  Ok(())
}

/// The first kind of path in the fallback order, which the matrix's
/// edges never leave open: a destination simply reachable at the address
/// it named is dialed directly, before the punch is ever ordered, and
/// the reported kind of path says so.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_reachable_destination_wins_with_a_direct_path() -> anyhow::Result<()>
{
  let net = SimNet::new(0xd1_1ec7);
  net.set_default_link(LinkConfig {
    latency: Duration::from_millis(20),
    ..LinkConfig::default()
  });
  let nonce = SessionNonce::from_bytes([0x11; 16]);
  let (helper, _running) = spawn_helper_handle(&net, nonce, 1);
  let (client_io, server_io) = tokio::io::duplex(64 * 1024);
  let destination =
    tokio::spawn(run_destination(net.clone(), server_io, 0xdead));
  let session = establish_over(&net, client_io, nonce, helper).await?;
  assert_eq!(session.path_kind, PathKind::Direct);
  // The punch was never ordered: the direct path answered inside its
  // own window, which is the purpose of racing it alone first.
  assert!(!session.paths.as_ref().unwrap().punched);
  destination.abort();
  Ok(())
}

/// The design's signaling-only reverse punch, with no helper anywhere:
/// the destination's edge drops unsolicited inbound, and only the
/// outward probing the client's rendezvous orders over the bootstrap
/// channel opens it. Nothing reflects or relays, so a session at all is
/// the punched path working.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn the_reverse_punch_opens_a_firewalled_destination() -> anyhow::Result<()>
{
  let path_kind = cell(
    0xf1_2ea11,
    NatGrade::FirewallOnly,
    NatGrade::FirewallOnly,
    false,
  )
  .await?;
  assert_eq!(path_kind, PathKind::Punched);
  Ok(())
}

/// Establishment with the helper addresses spelled out, for the cases
/// that do not vary the edges.
async fn establish_over(
  net: &SimNet,
  channel: DuplexStream,
  nonce: SessionNonce,
  helper: Vec<SocketAddr>,
) -> anyhow::Result<ClientSession<DuplexStream>> {
  let LabClient {
    options,
    arrivals: _arrivals,
    ..
  } = lab_client(
    net,
    ClientSetup {
      client_addr: addr(CLIENT),
      nonce,
      endpoint_seed: 0xc11e,
      stun_servers: Vec::new(),
      arrivals: vec![Arrival::Helper(helper)],
    },
  )
  .await?;
  Ok(timeout(DEADLINE, ClientSession::establish(channel, options)).await??)
}

/// The design's futility rule: with no helper and nothing the client
/// could route to, establishment says so at once instead of spending its
/// budget proving it. The caller's next kind of path is the TCP
/// fallback, and reaching it promptly is the point.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_hopeless_candidate_set_skips_to_the_fallback() -> anyhow::Result<()>
{
  let net = SimNet::new(0xf7115);
  let nonce = SessionNonce::from_bytes([0x33; 16]);
  let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
  // A destination on a private network this client is not on.
  let responder = tokio::spawn(async move {
    read_hello(&mut server_io).await.unwrap();
    let identity = SessionIdentity::generate().unwrap();
    let connect = Connect {
      version: PROTOCOL_VERSION,
      udp_port: 60123,
      server_key: identity.pin(),
      addr_hints: vec![addr("10.10.0.2:60123")],
    };
    server_io
      .write_all(connect.to_wire().as_bytes())
      .await
      .unwrap();
    std::future::pending::<()>().await;
  });

  let LabClient {
    options,
    arrivals: _arrivals,
    ..
  } = lab_client(
    &net,
    ClientSetup {
      client_addr: addr("192.168.1.2:41000"),
      nonce,
      endpoint_seed: 0xfeed,
      stun_servers: Vec::new(),
      // No helper on the bastion: reflection and relay are gone.
      arrivals: vec![Arrival::Helper(Vec::new())],
    },
  )
  .await?;
  let started = Instant::now();
  let error = timeout(DEADLINE, ClientSession::establish(client_io, options))
    .await?
    .expect_err("a hopeless candidate set cannot establish");
  assert!(
    matches!(error, EstablishError::UdpFutile { .. }),
    "unexpected error: {error}"
  );
  assert!(
    Instant::now() - started < TRAVERSAL_ESTABLISH_TIMEOUT,
    "establishment spent the whole budget on a set it could judge at once"
  );
  responder.abort();
  Ok(())
}

/// A helper that answered its ssh and cannot be reached over UDP must
/// degrade exactly like a bastion with no `mush` on it, not worse. The
/// services it provides -- reflection and the relay -- fail path
/// validation and are pruned either way; what must survive is the
/// candidate a helperless bastion would still have given, the jump's own
/// view of this client, which is the only address the destination's
/// reverse punch can aim at here. The client's own address is inside its
/// edge and reaches nobody.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_helper_with_unreachable_udp_keeps_the_observed_address()
-> anyhow::Result<()> {
  // Port-preserving 1:1 NAT on the client, so the jump's view of it plus
  // this session's port is exactly where it can be reached; a stateful
  // firewall on the destination, which only its own outward probes open.
  let told = Told {
    helper_addrs: 1,
    serving: false,
    observed: Some(addr(&format!("{CLIENT_PUBLIC}:{}", addr(CLIENT).port()))),
    stun: false,
  };
  let settled = open(
    0x0dea_d1e6,
    NatGrade::OneToOne,
    NatGrade::FirewallOnly,
    told,
    |_, _| {},
  )
  .await?
  .settle()
  .await?;
  assert_eq!(settled.session.path_kind, PathKind::Punched);
  let report = settled.session.paths.as_ref().expect("a path report");
  assert!(report.helper_offered, "a helper did answer over ssh");
  assert_eq!(report.helper, None, "nothing of this client reached it");
  assert_eq!(report.reflexive, None);

  // Without that address the destination has nothing to aim at, and the
  // session spends the whole budget on the way to the fallback.
  let error = open(
    0x0dea_d1e7,
    NatGrade::OneToOne,
    NatGrade::FirewallOnly,
    Told {
      observed: None,
      ..told
    },
    |_, _| {},
  )
  .await
  .err()
  .expect("the reverse punch had nowhere to aim");
  assert!(
    error.to_string().contains("QUIC unreachable"),
    "unexpected error: {error}"
  );
  Ok(())
}

/// The `--stun <server>` option, on the shape the design names for it:
/// "a destination with a public address behind a stateful firewall",
/// reached by a client behind a NAT, with no helper anywhere.
///
/// Default-off and the one third-party query Mush ever makes, so it has
/// to be shown to be needed: with it, the reflexive address becomes a
/// candidate, the destination punches at it -- which also opens its own
/// firewall outward -- and the punched path carries the session. The
/// negative control below is that same session with the flag off, where
/// the client can name only its address inside its own edge, the reverse
/// punch has nothing to aim at, and nothing establishes at all.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_stun_server_gets_a_natted_client_a_punched_path()
-> anyhow::Result<()> {
  let told = Told {
    helper_addrs: 0,
    serving: false,
    observed: None,
    stun: true,
  };
  let settled = open(
    0x57_0e11,
    NatGrade::PortRestricted,
    NatGrade::FirewallOnly,
    told,
    |_, _| {},
  )
  .await?
  .settle()
  .await?;
  assert_eq!(settled.session.path_kind, PathKind::Punched);
  let report = settled.session.paths.as_ref().expect("a path report");
  assert!(!report.helper_offered, "no bastion had a helper on it");
  // The reflector reported this client's mapping on its own edge, which
  // is the address the destination was then able to punch at.
  let reflexive = report.reflexive.expect("no reflexive address was learned");
  assert_eq!(reflexive.ip(), ip(CLIENT_PUBLIC), "{reflexive}");
  settled.session.connection.close(0u32.into(), b"over");
  settled.destination.connection.close(0u32.into(), b"over");

  // The negative control: the same session with the opt-in off.
  let error = open(
    0x57_0e12,
    NatGrade::PortRestricted,
    NatGrade::FirewallOnly,
    Told {
      stun: false,
      ..told
    },
    |_, _| {},
  )
  .await
  .err()
  .expect("a NATed client with nothing to name itself cannot be punched at");
  assert!(
    error.to_string().contains("QUIC unreachable"),
    "unexpected error: {error}"
  );
  Ok(())
}

/// The relay's registration is a moment, and the client's mapping can
/// change after it: the reflection that registers this client with the
/// helper happens once, seconds before the relayed dial. A NAT that
/// reboots or rebinds in between leaves the helper forwarding to an
/// address the client no longer holds, and its datagrams arriving from
/// one the helper has never seen -- the relay, the last UDP kind of
/// path, failing silently. What keeps it current is the punch series:
/// paced probes to the chosen helper address for as long as
/// establishment runs.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_client_mapping_change_keeps_its_relay() -> anyhow::Result<()> {
  let settled = open(
    0x5e1_f1a5,
    NatGrade::PortRestricted,
    NatGrade::Symmetric,
    Told {
      helper_addrs: 1,
      serving: true,
      observed: None,
      stun: false,
    },
    |_net, client_nat| {
      // After the reflection that registered this client, and before
      // the relayed dial that needs the registration.
      let client_nat = client_nat.clone();
      tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(900)).await;
        client_nat.flush_mappings();
      });
    },
  )
  .await?
  .settle()
  .await?;
  assert_eq!(settled.session.path_kind, PathKind::Relayed);
  Ok(())
}

/// A dual-homed bastion announces two addresses, and the peers must not
/// disagree with it about which one they are on. A peer whose NAT maps
/// per destination shows each helper address a different mapping, and
/// the helper keeps one address per role: probing both helper addresses
/// to the end leaves the registration pointing at the mapping of
/// whichever helper address answered last, while the peer relays through
/// the one that answered first. Both peers are symmetric here, so both
/// would get it wrong, and the relay is the only kind of path left to
/// get wrong.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_dual_homed_helper_relays_through_the_address_that_answered()
-> anyhow::Result<()> {
  let settled = open(
    0xd0a1_11e6,
    NatGrade::Symmetric,
    NatGrade::Symmetric,
    Told {
      helper_addrs: 2,
      serving: true,
      observed: None,
      stun: false,
    },
    |_, _| {},
  )
  .await?
  .settle()
  .await?;
  assert_eq!(settled.session.path_kind, PathKind::Relayed);
  // The helper address the client relays through is the one it
  // registered with, which is the first that answered.
  let report = settled.session.paths.as_ref().expect("a path report");
  assert_eq!(report.helper, Some(addr(HELPER)));
  Ok(())
}

/// A relayed session recovers from an outage, rebind and all. The helper
/// forwards to the address a peer's last signed probe came from, so the
/// prober's rebind -- the only recovery when the client's own address
/// died -- moves the client to a mapping the helper has never seen. What
/// brings the session back is the client's own path policy
/// re-registering the new mapping the moment the socket moves
/// (`mush_core::upgrade`), which is what lets the prober treat every
/// kind of path alike.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_relayed_session_survives_an_outage() -> anyhow::Result<()> {
  let mut settled = open(
    0x0011_7a6e,
    NatGrade::Symmetric,
    NatGrade::Symmetric,
    Told {
      helper_addrs: 1,
      serving: true,
      observed: None,
      stun: false,
    },
    |_, _| {},
  )
  .await?
  .settle()
  .await?;
  assert_eq!(settled.session.path_kind, PathKind::Relayed);

  let net = settled.net.clone();
  let policy = spawn_path_policy(&mut settled.session);
  let stats: Arc<ProbeStats> = Arc::default();
  let prober = tokio::spawn(
    Prober {
      connection: settled.session.connection.clone(),
      endpoint: settled.session.endpoint.clone(),
      // Real sockets on the simulated network, which is what makes a
      // rebind here observable rather than a no-op.
      fresh_socket: net_sockets(&net, &settled.socket),
      route_check: Box::new(|| true),
      events: None,
      session_socket: Some(settled.socket.clone()),
      options: ProbeOptions::default(),
      stats: stats.clone(),
    }
    .run(),
  );

  // A total outage on the client's side.
  net.set_host_blackhole(addr(CLIENT).ip(), true);
  tokio::time::sleep(OUTAGE).await;
  net.set_host_blackhole(addr(CLIENT).ip(), false);

  settled.session.send.write_all(b"back").await?;
  let mut buf = [0u8; 4];
  timeout(RECOVERY, settled.destination.recv.read_exact(&mut buf)).await??;
  anyhow::ensure!(&buf == b"back", "the destination read {buf:?}");
  anyhow::ensure!(
    stats.rebinds() > 0,
    "the session recovered without ever rebinding: {stats:?}"
  );
  // The mapping the helper relays to is the one the session ended up
  // on, which is the whole of what re-registration means.
  anyhow::ensure!(
    settled.socket.live_addr()? != addr(CLIENT),
    "the session never left its original mapping"
  );
  // And it is still the relay's session: re-registering must not be a
  // silent move onto some other path.
  anyhow::ensure!(
    settled.socket.current_path() == Some(addr(HELPER)),
    "the session left the relay: {:?}",
    settled.socket.current_path()
  );
  prober.abort();
  policy.abort();
  Ok(())
}

/// Drives the client's path policy for a session, as `mush connect`
/// does, discarding the moves it reports.
fn spawn_path_policy(
  session: &mut ClientSession<DuplexStream>,
) -> tokio::task::JoinHandle<()> {
  let (policy, mut moved) = spawn_policy(session);
  tokio::spawn(async move { while moved.recv().await.is_some() {} });
  policy
}

/// Replacement sockets for a rebind probe, bound on the simulated
/// network at the client's own address and wrapped in the session's own
/// shim, exactly as the CLI's factory does it.
fn net_sockets(net: &SimNet, socket: &Arc<TraversalSocket>) -> SocketFactory {
  let net = net.clone();
  let socket = socket.clone();
  let mut port = addr(CLIENT).port() + 1;
  Box::new(move || {
    port += 1;
    let fresh = net.bind(SocketAddr::new(addr(CLIENT).ip(), port))?;
    let rebound = socket.rebound(Box::new(fresh));
    Ok(FreshSocket {
      socket: rebound.clone(),
      adopt: Box::new(move || rebound.adopt()),
    })
  })
}
