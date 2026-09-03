// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The socket interface the QUIC session and the traversal probes share.
//!
//! The design's path establishment rests on one constraint: both peers
//! probe from the same UDP socket their QUIC endpoint uses, so the
//! mappings the probes create are the mappings the session uses (design
//! doc, "Path establishment").
//!
//! quinn owns the socket it is given, so sharing it means sitting
//! between them: [`TraversalSocket`] implements
//! [`quinn::AsyncUdpSocket`] over another socket, sorts every arriving
//! datagram by the one bit RFC 7983 demultiplexes on
//! ([`crate::stun::is_stun`]), and hands the STUN ones to the traversal
//! driver instead of quinn.
//!
//! quinn takes that socket by value and receives through `&mut self`, so
//! whatever it is handed, it owns -- while Mush goes on sending probes
//! from the same socket, and hands quinn that socket back to queue a
//! PING ([`TraversalSocket::nudge`], [`crate::roaming`]). So nothing
//! here gives quinn a socket outright: everything it is handed is
//! another view of one somebody else still holds, which is what
//! [`Handable`] produces. [`SharedSocket`] is that view over a plain
//! socket, and [`TraversalSocket`] is it over the session's path map.
//!
//! Sorting is per datagram, not per receive: a receive can carry a GRO
//! batch of several datagrams from one source, and a batch that mixes a
//! probe with session packets must lose neither. The remaining datagrams
//! are repacked in place, keeping the batch's stride valid.
//!
//! # The path manager
//!
//! The same shim is the design's path manager ("Upgrading from relay to
//! direct"): quinn addresses a stable *virtual* peer and never learns
//! any real path address, while the map here rewrites each send onto the
//! current real path and each arrival back to the virtual peer. A switch
//! is then a change to one index, which is what leaves quinn's
//! connection state, congestion window, and stream buffers untouched.
//!
//! Mapping lives in the same layer as the sort rather than in a second
//! socket wrapping this one: both are the same per-datagram inspection
//! at the same interface, and a wrapper would walk every GRO batch a
//! second time and add a virtual call per send, on the one path in Mush
//! that runs per datagram. The state itself is a separate, pure map
//! behind a lock, so the table's rules are testable without a socket.
//!
//! One consequence of the rewrite: a quinn client drops a datagram
//! whose source is not the address its connection is on, and rewriting
//! the source to the virtual peer is what stops it doing that, so the
//! path table is the only thing bounding which sources quinn is asked
//! to parse -- everything in it, and nothing else, reaches the
//! connection. Sound because nothing a received datagram says can put
//! an address in the table (paths come from ssh-authenticated candidate
//! lists) and a forged datagram still fails the AEAD; but an arrival is
//! therefore not evidence about a path, and the policy above must not
//! treat it as any ([`crate::upgrade`]).
//!
//! ## Choosing the virtual address
//!
//! An alias must be an address that can never also be a real path, since
//! the map tells the two apart by comparing addresses. Mush allocates
//! one per session from a block reserved by IANA and routed nowhere:
//! `240.0.0.0/8` on a v4 socket, inside RFC 1112 section 4's reserved /4
//! and clear of the broadcast address at the top of it, and `fd00::/8`
//! on a v6 one (RFC 4193 unique-local). The low bits are random per
//! session, so nothing a peer can say (a candidate it signals, a hint in
//! its connect line) is likely to name it, and the map refuses a real
//! path that does. Both families exist because the socket is bound to
//! whatever family the destination resolves to, and quinn refuses a v6
//! remote on a v4-bound endpoint.
//!
//! An alias never leaves this process, so one on the wire would be a bug
//! rather than a routing accident. Two rules keep it in: every send is
//! mapped, and a send to an unmapped address in the session's own block
//! is dropped rather than passed through (a losing candidate's
//! connection closing after its alias was reused is that case).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{
  Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard,
  RwLockWriteGuard, Weak,
};
use std::task::{Context, Poll};

use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpSender};
use tokio::sync::{Notify, mpsc};
use tracing::{debug, trace, warn};

use crate::path::PathKind;
use crate::stun;

/// How many diverted probes wait for the traversal driver.
///
/// Probes arrive in ones and twos and are consumed at once. The bound is
/// what keeps a flood of STUN-shaped datagrams from an off-path sender
/// costing memory: past it, newly arriving probes are dropped, and a
/// dropped probe is one the sender repeats.
pub const PROBE_QUEUE: usize = 64;

/// How many receives that hold nothing but probes the shim will take
/// before handing the runtime a scheduling point.
///
/// A receive whose every datagram was diverted owes quinn nothing, so
/// the shim polls again rather than reporting a receive of zero, which
/// quinn reads as "nothing more to do". Under a probe-shaped flood that
/// is the one loop in the receive path whose trip count a sender
/// influences, so it is bounded; a few trips cover the ordinary case,
/// where a probe or two arrives among session traffic.
const MAX_ALL_PROBE_RECEIVES: usize = 8;

/// How many ICMP-reported errors one receive absorbs
/// ([`SharedSocket::poll_recv`]) before handing the runtime a
/// scheduling point.
///
/// Same bound and same reason as [`MAX_ALL_PROBE_RECEIVES`]: how many
/// of these arrive is up to whoever is on the path, so the loop that
/// absorbs them cannot be unbounded. A roam produces a handful.
const MAX_ABSORBED_ICMP: usize = 8;

/// One datagram the socket sorted out of the session's traffic.
#[derive(Debug, Clone)]
pub struct Probe {
  /// The address it arrived from.
  pub from: SocketAddr,
  /// The datagram, verbatim.
  pub datagram: Vec<u8>,
}

/// How many paths one session's map holds.
///
/// A session has a handful: the addresses the destination named, the
/// ones a punch opened, and the relay. The bound keeps a peer that
/// signals candidates without end from growing the table every datagram
/// is matched against; past it a dial goes out at its real address,
/// costing that candidate its later agility and nothing else.
pub const MAX_PATHS: usize = 32;

/// One path, as of the [`TraversalSocket::observe`] that reported it.
#[derive(Debug, Clone, Copy)]
pub struct PathStatus {
  /// Where its datagrams really go.
  pub addr: SocketAddr,
  /// The kind of path it was opened as.
  pub path_kind: PathKind,
  /// Datagrams that have arrived over it.
  pub inbound: u64,
  /// Whether the session's sends are going out on it.
  pub current: bool,
}

/// Where a datagram quinn handed over is really going.
enum Route {
  /// Out to this address.
  To(SocketAddr),
  /// Nowhere: an address in this session's own virtual block that no
  /// path claims, which must not reach the wire (see the module docs).
  Drop,
}

/// One real path to the destination, and the address quinn names it by.
struct Path {
  /// Where datagrams on it really go.
  real: SocketAddr,
  /// What quinn addresses it as: the session's virtual peer once the
  /// session has committed, and a per-candidate alias before that, so
  /// that a race across several candidates stays several connections.
  virt: SocketAddr,
  path_kind: PathKind,
  /// Datagrams received over it. An atomic counter so the receive hot
  /// path costs one relaxed increment: a clock read per datagram in a
  /// GRO batch is exactly what the batch exists to avoid.
  inbound: AtomicU64,
}

impl Path {
  fn new(real: SocketAddr, virt: SocketAddr, path_kind: PathKind) -> Self {
    Self {
      real,
      virt,
      path_kind,
      inbound: AtomicU64::new(0),
    }
  }
}

/// The session's paths, and the virtual peer quinn addresses.
///
/// One real address has exactly one alias, so an arrival names exactly
/// one path. Several paths may share the virtual peer -- that is what
/// switching between them means -- and [`PathMap::current`] is which of
/// them sends go out on.
struct PathMap {
  /// Whether the socket is v6, and so whether a real address is
  /// normalized the way quinn normalizes what it is dialed at.
  v6: bool,
  /// The address aliases are allocated from, one per port from here up.
  /// Its IP is what marks an address as this session's own.
  base: SocketAddr,
  /// Aliases allocated so far, which is also the next one's port offset.
  allocated: u16,
  paths: Vec<Path>,
  /// The virtual peer, once a handshake has won and the session has
  /// committed to the path that carried it.
  peer: Option<SocketAddr>,
  /// Index into `paths` of the path sends go out on.
  current: usize,
}

/// The virtual block one session allocates its aliases from; see the
/// module docs for the choice.
fn virtual_base(v6: bool) -> SocketAddr {
  let mut bytes = [0u8; 18];
  if SystemRandom::new().fill(&mut bytes).is_err() {
    // The reserved block is what keeps these addresses off the wire and
    // clear of real ones; the random tail only makes it unguessable as
    // well, so losing it costs that one property rather than the
    // session.
    warn!("no randomness for the session's virtual peer address");
  }
  // Ports run from the base up, so the span leaves room for a full
  // table and starts above the well-known range.
  let span = 60000 - MAX_PATHS as u16;
  let port = 1024 + u16::from_be_bytes([bytes[16], bytes[17]]) % span;
  let ip: IpAddr = match v6 {
    // fd00::/8, with the random global ID and interface ID RFC 4193
    // asks for.
    true => {
      bytes[0] = 0xfd;
      let mut tail = [0u8; 16];
      tail.copy_from_slice(&bytes[..16]);
      Ipv6Addr::from(tail).into()
    }
    // 240.0.0.0/8, inside the reserved /4 and clear of the broadcast
    // address at the top of it.
    false => Ipv4Addr::new(240, bytes[0], bytes[1], bytes[2]).into(),
  };
  SocketAddr::new(ip, port)
}

impl PathMap {
  fn new(local: Option<SocketAddr>) -> Self {
    let v6 = local.is_some_and(|addr| addr.is_ipv6());
    Self {
      v6,
      base: virtual_base(v6),
      allocated: 0,
      paths: Vec::new(),
      peer: None,
      current: 0,
    }
  }

  /// Whether an address is one of this session's own aliases.
  fn is_virtual(&self, addr: SocketAddr) -> bool {
    addr.ip() == self.base.ip()
  }

  /// A real address in the form the socket sees it, which for a
  /// v6-bound socket is the v4-mapped form quinn dials v4 peers at.
  fn normalize(&self, addr: SocketAddr) -> SocketAddr {
    match (self.v6, addr) {
      (true, SocketAddr::V4(v4)) => SocketAddr::V6(SocketAddrV6::new(
        v4.ip().to_ipv6_mapped(),
        v4.port(),
        0,
        0,
      )),
      _ => addr,
    }
  }

  fn find(&self, real: SocketAddr) -> Option<usize> {
    self.paths.iter().position(|path| path.real == real)
  }

  fn allocate(&mut self) -> SocketAddr {
    let alias =
      SocketAddr::new(self.base.ip(), self.base.port() + self.allocated);
    self.allocated += 1;
    alias
  }

  /// The alias to dial `real` at, allocating one if this is a new path.
  /// `None` when the dial must go out unmapped.
  fn alias(
    &mut self,
    real: SocketAddr,
    path_kind: PathKind,
  ) -> Option<SocketAddr> {
    // quinn refuses a v6 remote on a v4-bound endpoint under its own
    // lock with no I/O, and the caller reports that immediately. An
    // alias would hide the refusal behind a dial that could only fail
    // later, at the socket, having spent the establishment budget.
    if !self.v6 && real.is_ipv6() {
      return None;
    }
    let real = self.normalize(real);
    if self.is_virtual(real) {
      warn!(addr = %real, "a real address collided with this session's own");
      return None;
    }
    if let Some(at) = self.find(real) {
      // Establishment reissues a candidate as a punched path at the
      // address it already tried as a direct one; it is one path either
      // way, and one address must keep one alias so that an arrival
      // names one path.
      self.paths[at].path_kind = path_kind;
      return Some(self.paths[at].virt);
    }
    if self.paths.len() >= MAX_PATHS {
      return None;
    }
    let virt = self.allocate();
    self.paths.push(Path::new(real, virt, path_kind));
    Some(virt)
  }

  /// Commits the session to the path at `real`: its alias becomes the
  /// virtual peer for the rest of the session.
  fn commit(&mut self, real: SocketAddr) -> bool {
    let real = self.normalize(real);
    let Some(at) = self.find(real) else {
      return false;
    };
    self.peer = Some(self.paths[at].virt);
    self.current = at;
    true
  }

  /// Adds a path the session may switch onto. A candidate that lost the
  /// race keeps its own alias until this promotes it.
  fn add_path(&mut self, real: SocketAddr, path_kind: PathKind) -> bool {
    let Some(peer) = self.peer else {
      return false;
    };
    let real = self.normalize(real);
    if self.is_virtual(real) || (!self.v6 && real.is_ipv6()) {
      return false;
    }
    if let Some(at) = self.find(real) {
      self.paths[at].virt = peer;
      self.paths[at].path_kind = path_kind;
      return true;
    }
    if self.paths.len() >= MAX_PATHS {
      return false;
    }
    self.paths.push(Path::new(real, peer, path_kind));
    true
  }

  /// Moves the session's sends onto the path at `real`.
  fn switch(&mut self, real: SocketAddr) -> bool {
    let Some(peer) = self.peer else {
      return false;
    };
    let real = self.normalize(real);
    let found = self
      .paths
      .iter()
      .position(|path| path.real == real && path.virt == peer);
    match found {
      Some(at) => {
        self.current = at;
        true
      }
      None => false,
    }
  }

  /// Where a datagram quinn addressed to `dst` goes.
  fn route(&self, dst: SocketAddr) -> Route {
    // The committed session's hot path: one comparison and one index,
    // no scan and no allocation.
    if self.peer == Some(dst)
      && let Some(path) = self.paths.get(self.current)
    {
      return Route::To(path.real);
    }
    if let Some(path) = self.paths.iter().find(|path| path.virt == dst) {
      return Route::To(path.real);
    }
    match self.is_virtual(dst) {
      true => Route::Drop,
      false => Route::To(dst),
    }
  }

  /// The address quinn should see a datagram from `src` as having come
  /// from, and `None` for a source no path claims, which is handed on
  /// unchanged for quinn to judge.
  fn arrival(&self, src: SocketAddr) -> Option<SocketAddr> {
    if let Some(path) = self.paths.get(self.current)
      && path.real == src
    {
      path.inbound.fetch_add(1, Ordering::Relaxed);
      return Some(path.virt);
    }
    let path = self.paths.iter().find(|path| path.real == src)?;
    path.inbound.fetch_add(1, Ordering::Relaxed);
    Some(path.virt)
  }

  fn observe(&self) -> Vec<PathStatus> {
    let committed = self.peer.is_some();
    self
      .paths
      .iter()
      .enumerate()
      .map(|(at, path)| PathStatus {
        addr: path.real,
        path_kind: path.path_kind,
        inbound: path.inbound.load(Ordering::Relaxed),
        current: committed && at == self.current,
      })
      .collect()
  }
}

/// A socket that can be handed to quinn more than once.
///
/// quinn takes an [`AsyncUdpSocket`] by value, so every socket in this
/// crate is a view of one somebody else holds (see the module docs), and
/// this is the one thing those views have in common: another view, in
/// the form quinn takes. Implemented for every `AsyncUdpSocket` that is
/// `Clone`, because a clone is what a second view is.
pub trait Handable: AsyncUdpSocket {
  /// Another view of the same socket, for quinn to own.
  fn hand(&self) -> Box<dyn AsyncUdpSocket>;
}

impl<T: AsyncUdpSocket + Clone> Handable for T {
  fn hand(&self) -> Box<dyn AsyncUdpSocket> {
    Box::new(self.clone())
  }
}

/// One real socket, shared by everything that has to reach it, and the
/// one place Mush decides what the platform reports about it.
///
/// A runtime hands out sockets owned ([`quinn::Runtime::wrap_udp_socket`]
/// returns a `Box`), which is not a shape Mush can use (see the module
/// docs); this wraps one so it can be cloned, which makes it
/// [`Handable`]. Every OS socket Mush hands quinn is one of these, on
/// its own or under a [`TraversalSocket`], which makes it the boundary
/// for [`poll_recv`](Self::poll_recv)'s filtering as well.
///
/// The lock costs one uncontended acquisition per receive. Uncontended
/// by construction: the socket is reached mutably only through
/// [`AsyncUdpSocket::poll_recv`], and only the endpoint driver receives
/// -- one task, even while it is draining a socket a rebind retired.
/// Everything Mush does with a shared socket goes through `&self`.
#[derive(Clone)]
pub struct SharedSocket(Arc<Mutex<Box<dyn AsyncUdpSocket>>>);

/// Whether an error is one an ICMP message put on the socket, rather
/// than something wrong with the socket itself.
///
/// Linux reports ICMP destination-unreachable and friends as the errno
/// of the next socket operation once `IP_RECVERR` is set, which
/// quinn-udp does on every socket it makes. `EHOSTDOWN` has no
/// `ErrorKind` of its own and is not listed: ICMP host-unreachable
/// arrives as `HostUnreachable`.
fn reported_by_icmp(error: &io::Error) -> bool {
  matches!(
    error.kind(),
    io::ErrorKind::ConnectionRefused
      | io::ErrorKind::ConnectionReset
      | io::ErrorKind::HostUnreachable
      | io::ErrorKind::NetworkUnreachable
      | io::ErrorKind::NetworkDown
  )
}

/// Stops the kernel reporting what ICMP says about a socket.
///
/// quinn-udp asks for those reports (`IP_RECVERR`) on every socket it
/// makes and never drains the queue they end up in, so the kernel leaves
/// the errno on the socket for whatever Mush does next. A receive is
/// the visible half ([`SharedSocket::poll_recv`]). A send is the silent
/// half, and the worse one: the pending error is delivered to the next
/// `sendmsg`, whatever its destination, and quinn's senders log a failed
/// `sendmsg` and report success -- so a probe aimed somewhere entirely
/// different is dropped with nothing to see. Probing a candidate this
/// host cannot route to is ordinary (a peer offers its LAN address, a
/// path dies under a roam), and it is what provokes the report, so the
/// next probe out of that burst is the one lost: the rendezvous that
/// opens a firewalled peer, often enough to cost a session its direct
/// path.
///
/// Nothing may be concluded from an ICMP message in any case (see
/// [`SharedSocket::poll_recv`] for why), so the cheapest place to be rid
/// of one is before the kernel ever hands it over. quinn asks for it
/// only to expose `recv_transport_error`, which it never calls itself;
/// it reads path MTU from DPLPMTUD rather than from ICMP, and `EMSGSIZE`
/// on an over-large send comes back from the syscall either way.
///
/// Failure is ignored, exactly as quinn-udp ignores failure to set it: a
/// kernel that will not turn it off leaves [`SharedSocket::poll_recv`]'s
/// absorb standing, which is the receive half of the same policy.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn disown_icmp(socket: &std::net::UdpSocket) {
  use std::os::fd::AsRawFd as _;

  let off: libc::c_int = 0;
  for (level, name) in [
    (libc::IPPROTO_IP, libc::IP_RECVERR),
    (libc::IPPROTO_IPV6, libc::IPV6_RECVERR),
  ] {
    // SAFETY: the descriptor is live for the call, `socket` being
    // borrowed across it, and the value is a `c_int` described by its
    // own size. The v6 option is refused on a v4 socket, which is one
    // of the failures being ignored.
    unsafe {
      libc::setsockopt(
        socket.as_raw_fd(),
        level,
        name,
        std::ptr::from_ref(&off).cast(),
        size_of_val(&off) as libc::socklen_t,
      );
    }
  }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn disown_icmp(_socket: &std::net::UdpSocket) {}

/// Hands an OS socket to a quinn runtime, with what the platform
/// reports about it settled first ([`disown_icmp`]).
///
/// Every OS socket Mush runs a QUIC endpoint on goes through here. The
/// second descriptor is how: the runtime takes the socket by value, and
/// the option has to be cleared after quinn-udp has set it, but it is a
/// property of the open socket rather than of a descriptor, so clearing
/// it through a second one reaches the socket quinn is now driving.
pub(crate) fn wrap_os_socket(
  socket: std::net::UdpSocket,
  runtime: &dyn quinn::Runtime,
) -> io::Result<Box<dyn AsyncUdpSocket>> {
  let handle = socket.try_clone()?;
  let inner = runtime.wrap_udp_socket(socket)?;
  disown_icmp(&handle);
  Ok(inner)
}

impl SharedSocket {
  /// Shares a socket a runtime produced.
  pub fn new(inner: Box<dyn AsyncUdpSocket>) -> Self {
    Self(Arc::new(Mutex::new(inner)))
  }

  /// A quinn endpoint over `socket`, receiving through one of these.
  ///
  /// The plain counterpart of [`TraversalEndpoint::over_std`], and the
  /// reason both exist rather than one: a session with no traversal has
  /// no paths to map and no probes to sort, but it terminates the same
  /// untrusted network input, so it wants
  /// [`poll_recv`](Self::poll_recv)'s filtering just as much. Every
  /// endpoint Mush builds goes through one of the two.
  pub fn endpoint(
    socket: std::net::UdpSocket,
    config: quinn::EndpointConfig,
    server_config: Option<quinn::ServerConfig>,
  ) -> io::Result<quinn::Endpoint> {
    let runtime = Arc::new(quinn::TokioRuntime);
    let inner = wrap_os_socket(socket, runtime.as_ref())?;
    quinn::Endpoint::new_with_abstract_socket(
      config,
      server_config,
      Box::new(Self::new(inner)),
      runtime,
    )
  }

  fn socket(&self) -> MutexGuard<'_, Box<dyn AsyncUdpSocket>> {
    self.0.lock().unwrap_or_else(PoisonError::into_inner)
  }
}

impl std::fmt::Debug for SharedSocket {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    self.socket().fmt(f)
  }
}

impl AsyncUdpSocket for SharedSocket {
  fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
    self.socket().create_sender()
  }

  /// What an ICMP message put on the socket is absorbed here rather
  /// than reported.
  ///
  /// quinn's endpoint driver ends the endpoint -- and with it every
  /// connection on it -- on any receive error it does not recognize, so
  /// a report reaching quinn is a session kill. The path a session just
  /// left answers with unreachables, so a session would die every time
  /// it roamed; and an off-path sender who can guess the four-tuple can
  /// have one sent, so it would be a kill anyone could ask for.
  ///
  /// The reports are asked for by quinn-udp and turned back off by
  /// `disown_icmp`, so on Linux nothing normally reaches here. This is
  /// the half that does not depend on that: a socket from somewhere else
  /// (the simulator's network), a platform with its own way of surfacing
  /// them, a kernel that refused to turn them off.
  ///
  /// Nothing may be concluded from those messages in any case: they are
  /// unauthenticated and forgeable, which is why quinn ignores
  /// `ECONNRESET` and why RFC 9000 has an endpoint validate a path
  /// rather than believe ICMP about it. A path that has really died is
  /// found by its silence ([`crate::roaming`]), which no packet an
  /// attacker sends can fake.
  fn poll_recv(
    &mut self,
    cx: &mut Context,
    bufs: &mut [io::IoSliceMut<'_>],
    meta: &mut [RecvMeta],
  ) -> Poll<io::Result<usize>> {
    for _ in 0..MAX_ABSORBED_ICMP {
      match self.socket().poll_recv(cx, bufs, meta) {
        Poll::Ready(Err(error)) if reported_by_icmp(&error) => {
          trace!(%error, "absorbed an ICMP report on the session socket");
        }
        received => return received,
      }
    }
    // Only a sustained flood of them reaches here. Waking first makes
    // this a scheduling point rather than an end of work, exactly as
    // the probe-flood bound does.
    cx.waker().wake_by_ref();
    Poll::Ready(Ok(0))
  }

  fn local_addr(&self) -> io::Result<SocketAddr> {
    self.socket().local_addr()
  }

  fn max_receive_segments(&self) -> usize {
    self.socket().max_receive_segments()
  }

  fn may_fragment(&self) -> bool {
    self.socket().may_fragment()
  }
}

/// What every shim of one session shares: the paths, and which socket
/// the session is leaving from now.
///
/// A rebind ([`TraversalSocket::rebound`]) hands quinn a second shim
/// over a fresh socket, and quinn keeps the old one for a moment to
/// drain what is still arriving on it. Both shims are the same session,
/// so the map is the same map -- and so is the answer to "where do this
/// session's probes leave from", which has to be the newest socket even
/// when the caller holding a shim is holding the one quinn retired.
struct Shared {
  map: RwLock<PathMap>,
  live: RwLock<SharedSocket>,
  /// The shim quinn is running on now, for a caller that has to hand
  /// quinn its own socket back ([`TraversalSocket::nudge`]). Weak
  /// because quinn and the caller are what keep a shim alive.
  shim: RwLock<Weak<TraversalSocket>>,
  /// Signalled when a rebind replaces the live socket, so whoever is
  /// keeping a registration current can re-register at once rather than
  /// at its next tick.
  moved: Notify,
}

impl Shared {
  fn map(&self) -> RwLockReadGuard<'_, PathMap> {
    self.map.read().unwrap_or_else(PoisonError::into_inner)
  }
}

/// A QUIC endpoint's socket, with the traversal probes sorted out of it
/// and the session's paths mapped under it.
///
/// Built by [`TraversalEndpoint`], which pairs it with the endpoint that
/// must be the one running on it: probes sent here and that endpoint's
/// packets have to leave from the same mapping.
pub struct TraversalSocket {
  /// The socket quinn drives through this shim. A retired shim keeps
  /// its own, which is what lets quinn drain it.
  inner: SharedSocket,
  probes: mpsc::Sender<Probe>,
  shared: Arc<Shared>,
}

/// A second shim on the same socket, over the same map: what
/// [`Handable::hand`] gives quinn. Not [`TraversalSocket::rebound`],
/// which is a shim over a *different* socket and is how a session moves.
impl Clone for TraversalSocket {
  fn clone(&self) -> Self {
    Self {
      inner: self.inner.clone(),
      probes: self.probes.clone(),
      shared: self.shared.clone(),
    }
  }
}

impl std::fmt::Debug for TraversalSocket {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("TraversalSocket")
      .field("inner", &self.inner)
      .finish_non_exhaustive()
  }
}

impl TraversalSocket {
  /// Wraps `inner`, returning the socket and the stream of probes it
  /// will divert.
  pub fn new(
    inner: Box<dyn AsyncUdpSocket>,
  ) -> (Arc<Self>, mpsc::Receiver<Probe>) {
    let (probes, received) = mpsc::channel(PROBE_QUEUE);
    let local = inner.local_addr().ok();
    let inner = SharedSocket::new(inner);
    let shared = Arc::new(Shared {
      map: RwLock::new(PathMap::new(local)),
      live: RwLock::new(inner.clone()),
      shim: RwLock::new(Weak::new()),
      moved: Notify::new(),
    });
    let socket = Arc::new(Self {
      inner,
      probes,
      shared,
    });
    socket.publish();
    (socket, received)
  }

  /// Records this shim as the one quinn is running on.
  fn publish(self: &Arc<Self>) {
    *self
      .shared
      .shim
      .write()
      .unwrap_or_else(PoisonError::into_inner) = Arc::downgrade(self);
  }

  /// The same shim over a freshly bound socket, sharing this one's
  /// paths, probe stream, and identity as the session's live socket.
  ///
  /// A stall rebind ([`crate::roaming`]) hands quinn a new socket in
  /// place of this one. Without the shim around it the session would go
  /// on addressing a virtual peer with nothing left to map it, so the
  /// replacement has to be one of these too, over the very same map: the
  /// same session on the same paths, leaving from a new local mapping.
  ///
  /// This shim stays exactly what it was, because quinn keeps polling it
  /// until traffic arrives on the replacement; what moves is where the
  /// session's *probes* leave from, so that a registration the far side
  /// routes on ([`crate::helper`]) is renewed from the mapping the
  /// session is actually using. That move is [`adopt`](Self::adopt),
  /// which the caller makes only once the endpoint has really taken the
  /// replacement: a rebind that fails to install must leave the
  /// session's probes on the mapping the session still uses, or the
  /// relay would be re-registered at an address quinn no longer sends
  /// from.
  pub fn rebound(&self, inner: Box<dyn AsyncUdpSocket>) -> Arc<Self> {
    Arc::new(Self {
      inner: SharedSocket::new(inner),
      probes: self.probes.clone(),
      shared: self.shared.clone(),
    })
  }

  /// Makes this shim the session's live socket: where its probes leave
  /// from, and the one a nudge hands quinn back.
  ///
  /// Call once [`quinn::Endpoint::rebind_abstract`] has accepted it.
  /// Whoever keeps a registration current is woken
  /// ([`moved`](Self::moved)).
  pub fn adopt(self: &Arc<Self>) {
    *self
      .shared
      .live
      .write()
      .unwrap_or_else(PoisonError::into_inner) = self.inner.clone();
    self.publish();
    self.shared.moved.notify_one();
  }

  /// Makes quinn send something ack-eliciting at once, without moving
  /// the session anywhere.
  ///
  /// A path switch is invisible to quinn (one index under a lock), so on
  /// an idle session nothing would leave on the new path and the
  /// destination would not learn there is one to validate until the next
  /// keep-alive. Handing quinn back the socket it is already running on
  /// is this crate's way of queueing a PING, which starts that
  /// validation now ([`crate::roaming`] probes with the same call).
  pub fn nudge(&self, endpoint: &quinn::Endpoint) {
    let shim = self
      .shared
      .shim
      .read()
      .unwrap_or_else(PoisonError::into_inner)
      .upgrade();
    let Some(shim) = shim else {
      return;
    };
    if let Err(error) = endpoint.rebind_abstract(shim.hand()) {
      debug!(%error, "the session could not be nudged onto its new path");
    }
  }

  /// Resolves once the session's live socket has been replaced by a
  /// rebind since the last resolution.
  ///
  /// Cancel-safe by construction (one notification is held until
  /// somebody takes it), which is what lets a driver select on it.
  pub async fn moved(&self) {
    self.shared.moved.notified().await;
  }

  /// The socket the session is leaving from now, which a rebind
  /// replaces underneath every shim.
  fn live(&self) -> SharedSocket {
    self
      .shared
      .live
      .read()
      .unwrap_or_else(PoisonError::into_inner)
      .clone()
  }

  fn map(&self) -> RwLockReadGuard<'_, PathMap> {
    self.shared.map()
  }

  fn map_mut(&self) -> RwLockWriteGuard<'_, PathMap> {
    self
      .shared
      .map
      .write()
      .unwrap_or_else(PoisonError::into_inner)
  }

  /// The address to dial `addr` at so the session can later be moved off
  /// it: an alias quinn addresses in its place, with `addr` underneath.
  ///
  /// Returns `addr` itself when the map cannot take the path -- a v6
  /// candidate on a v4 socket, which quinn refuses immediately and by
  /// design, or a table already full. Such a dial gives a working
  /// session with no agility.
  pub fn dial_target(
    &self,
    addr: SocketAddr,
    path_kind: PathKind,
  ) -> SocketAddr {
    match self.map_mut().alias(addr, path_kind) {
      Some(virt) => virt,
      None => {
        debug!(%addr, %path_kind, "dialing an unmapped candidate");
        addr
      }
    }
  }

  /// Commits the session to the path at `addr`, whose alias becomes the
  /// virtual peer quinn addresses for the rest of the session.
  ///
  /// False when nothing was mapped for `addr` (see
  /// [`dial_target`](Self::dial_target)), which leaves the session
  /// pinned to the path that won it.
  pub fn commit(&self, addr: SocketAddr) -> bool {
    self.map_mut().commit(addr)
  }

  /// Offers the session another path to `addr`, switchable from then on.
  /// False before the session has committed to one.
  pub fn add_path(&self, addr: SocketAddr, path_kind: PathKind) -> bool {
    self.map_mut().add_path(addr, path_kind)
  }

  /// Moves the session's sends onto the path at `addr`, which must be
  /// one [`add_path`](Self::add_path) offered (or the committed one).
  ///
  /// Cheap, reversible, and atomic against sends: a datagram is routed
  /// under one lock acquisition, so it leaves on the path before the
  /// switch or the path after it, never both and never neither. Nothing
  /// here is queued to be lost or duplicated; what went to the kernel
  /// before the switch is in flight on the old path, reordering of the
  /// kind QUIC tolerates from any path change (see the module docs).
  pub fn switch_to(&self, addr: SocketAddr) -> bool {
    let switched = self.map_mut().switch(addr);
    if switched {
      debug!(%addr, "session moved onto another path");
    }
    switched
  }

  /// The virtual peer quinn addresses, once the session has committed.
  pub fn peer(&self) -> Option<SocketAddr> {
    self.map().peer
  }

  /// A real address in the form this map holds it, which for a v6-bound
  /// socket is the v4-mapped form quinn dials v4 peers at and arrivals
  /// carry.
  ///
  /// Everything here normalizes internally, so this is for callers that
  /// *compare* addresses: a policy matching a probe's source against the
  /// candidate it answers ([`crate::upgrade`]) has to hold the same form
  /// the socket reports.
  pub fn normalize(&self, addr: SocketAddr) -> SocketAddr {
    self.map().normalize(addr)
  }

  /// The real address the session's sends are going to.
  pub fn current_path(&self) -> Option<SocketAddr> {
    let map = self.map();
    map.peer?;
    Some(map.paths.get(map.current)?.real)
  }

  /// Samples every path.
  pub fn observe(&self) -> Vec<PathStatus> {
    self.map().observe()
  }

  /// Sends one probe from the session's own mapping.
  ///
  /// The address is the real one: a probe is aimed at a peer or the
  /// helper to open and hold a mapping there, which is the one thing the
  /// virtual peer must not stand in for.
  ///
  /// A sender is built per send because each holds a single waker and
  /// probes are a handful of datagrams per second; waiting for
  /// writability is part of sending rather than an exceptional path,
  /// since a socket reports back-pressure before its reactor has seen it
  /// writable, which is exactly when a session's first probe goes out.
  ///
  /// `Ok` is weaker than it looks: quinn's own senders log a failed
  /// `sendmsg` and report success, so a probe that never left the host
  /// (no route, a firewall's reject) arrives here as `Ok`. Only a
  /// failure to *wait* for writability surfaces. Nothing here to
  /// recover -- probing is best effort by nature, the caller cannot tell
  /// a send whose failure was suppressed from a dropped datagram, and the
  /// answer to both is the next probe -- but nothing to conclude from
  /// `Ok` either.
  pub async fn send_probe(
    &self,
    datagram: &[u8],
    to: SocketAddr,
  ) -> io::Result<()> {
    let mut sender = self.live().create_sender();
    let transmit = Transmit {
      destination: to,
      ecn: None,
      contents: datagram,
      segment_size: None,
      src_ip: None,
    };
    std::future::poll_fn(|cx| sender.as_mut().poll_send(&transmit, cx)).await
  }

  /// The address this shim's own socket is bound to.
  pub fn local_addr(&self) -> io::Result<SocketAddr> {
    self.inner.local_addr()
  }

  /// The address the session's probes leave from now, which a rebind
  /// moves ([`rebound`](Self::rebound)).
  pub fn live_addr(&self) -> io::Result<SocketAddr> {
    self.live().local_addr()
  }
}

/// Sorts one received slot in place: STUN datagrams go to `probes`, and
/// the rest are repacked at the front of `buf`. Returns the bytes left.
///
/// A slot is one receive, which for a socket doing GRO is a batch of
/// `stride`-sized datagrams (the last may be shorter). Repacking keeps
/// that shape, so what is handed on is still a valid batch.
fn sift(
  buf: &mut [u8],
  meta: &RecvMeta,
  probes: &mpsc::Sender<Probe>,
) -> usize {
  let len = meta.len.min(buf.len());
  // A socket that does not batch reports stride == len; guard the
  // degenerate values rather than trusting them, since a zero stride
  // would not terminate.
  let stride = match meta.stride {
    0 => len,
    stride => stride.min(len),
  };
  let mut kept = 0;
  let mut offset = 0;
  while offset < len {
    let end = (offset + stride).min(len);
    if stun::is_stun(&buf[offset..end]) {
      // Room first, then the copy: a flood of STUN-shaped datagrams
      // from an off-path sender is exactly the case the queue's bound
      // is for, and one past it should not cost an allocation to throw
      // away.
      match probes.try_reserve() {
        Ok(slot) => slot.send(Probe {
          from: meta.addr,
          datagram: buf[offset..end].to_vec(),
        }),
        Err(_) => {
          trace!(from = %meta.addr, "probe queue full; dropping a probe")
        }
      }
    } else {
      if kept != offset {
        buf.copy_within(offset..end, kept);
      }
      kept += end - offset;
    }
    offset = end;
  }
  kept
}

/// A [`TraversalSocket`]'s sender: the path rewrite, then the underlying
/// socket's own sender. One per interested task, as the trait intends,
/// over a map they all share, so a switch moves every one at once.
struct TraversalSender {
  inner: Pin<Box<dyn UdpSender>>,
  shared: Arc<Shared>,
}

impl std::fmt::Debug for TraversalSender {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("TraversalSender")
      .field("inner", &self.inner)
      .finish_non_exhaustive()
  }
}

impl UdpSender for TraversalSender {
  /// The send hot path: one read lock and one address comparison per
  /// transmit -- which is a whole GSO batch, not a datagram -- and no
  /// allocation. Keep it that way. The lock is released before the
  /// send itself, so a switch waits on a table lookup and never on a
  /// syscall.
  fn poll_send(
    self: Pin<&mut Self>,
    transmit: &Transmit<'_>,
    cx: &mut Context,
  ) -> Poll<io::Result<()>> {
    let this = self.get_mut();
    let route = this.shared.map().route(transmit.destination);
    match route {
      Route::To(destination) if destination == transmit.destination => {
        this.inner.as_mut().poll_send(transmit, cx)
      }
      Route::To(destination) => this.inner.as_mut().poll_send(
        &Transmit {
          destination,
          ..*transmit
        },
        cx,
      ),
      Route::Drop => Poll::Ready(Ok(())),
    }
  }

  fn max_transmit_segments(&self) -> usize {
    self.inner.max_transmit_segments()
  }
}

impl AsyncUdpSocket for TraversalSocket {
  fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
    Box::pin(TraversalSender {
      inner: self.inner.create_sender(),
      shared: self.shared.clone(),
    })
  }

  fn poll_recv(
    &mut self,
    cx: &mut Context,
    bufs: &mut [io::IoSliceMut<'_>],
    meta: &mut [RecvMeta],
  ) -> Poll<io::Result<usize>> {
    for _ in 0..MAX_ALL_PROBE_RECEIVES {
      let received = std::task::ready!(self.inner.poll_recv(cx, bufs, meta))?;
      // An empty receive is passed on rather than retried: polling again
      // on a socket that just reported nothing is a spin, and on this
      // runtime a spin blocks the whole session.
      if received == 0 {
        return Poll::Ready(Ok(0));
      }
      let map = self.map();
      let mut kept = 0;
      for i in 0..received.min(bufs.len()).min(meta.len()) {
        // Sorting comes first because the two consumers need different
        // addresses out of the same datagram: a probe carries the
        // mapping it arrived from, quinn is told the session's one peer
        // whichever path it came over.
        let len = sift(&mut bufs[i], &meta[i], &self.probes);
        if len == 0 {
          continue;
        }
        if kept != i {
          let (head, tail) = bufs.split_at_mut(i);
          head[kept][..len].copy_from_slice(&tail[0][..len]);
          meta[kept] = meta[i];
        }
        meta[kept].len = len;
        if let Some(peer) = map.arrival(meta[kept].addr) {
          meta[kept].addr = peer;
        }
        kept += 1;
      }
      drop(map);
      // Every datagram in this receive was a probe; nothing is owed to
      // quinn, and polling again is what re-arms the waker.
      if kept > 0 {
        return Poll::Ready(Ok(kept));
      }
    }
    // Only a sustained probe-shaped flood gets here: how many trips the
    // loop takes is the one thing in this receive path a sender decides,
    // so the loop is bounded. Yielding an empty receive re-arms the
    // waker exactly as the loop would while handing the runtime a
    // scheduling point, which on this runtime is the difference between
    // a busy session and a stalled one.
    cx.waker().wake_by_ref();
    Poll::Ready(Ok(0))
  }

  fn local_addr(&self) -> io::Result<SocketAddr> {
    self.inner.local_addr()
  }

  fn max_receive_segments(&self) -> usize {
    self.inner.max_receive_segments()
  }

  fn may_fragment(&self) -> bool {
    self.inner.may_fragment()
  }
}

/// A QUIC endpoint and the probe stream sharing its socket.
///
/// The pairing is the invariant: probes sent on [`socket`](Self::socket)
/// leave from the mapping [`endpoint`](Self::endpoint) uses, and probes
/// arriving there surface on [`probes`](Self::probes) rather than being
/// handed to quinn as corrupt packets.
#[derive(Debug)]
pub struct TraversalEndpoint {
  /// The endpoint the session runs on.
  pub endpoint: quinn::Endpoint,
  /// The socket underneath it, for sending probes.
  pub socket: Arc<TraversalSocket>,
  /// Probes sorted out of the session's traffic.
  pub probes: mpsc::Receiver<Probe>,
}

impl TraversalEndpoint {
  /// Binds a fresh UDP socket at `addr` for a client endpoint.
  pub fn bind(addr: SocketAddr) -> io::Result<Self> {
    Self::over_std(
      std::net::UdpSocket::bind(addr)?,
      crate::transport::endpoint_config(),
      None,
    )
  }

  /// Adopts an already-bound socket, for the destination server, which
  /// binds and announces its port before it forks (see the CLI's server
  /// module) and only then has a runtime to build an endpoint on.
  pub fn over_std(
    socket: std::net::UdpSocket,
    config: quinn::EndpointConfig,
    server_config: Option<quinn::ServerConfig>,
  ) -> io::Result<Self> {
    let runtime = Arc::new(quinn::TokioRuntime);
    let inner = wrap_os_socket(socket, runtime.as_ref())?;
    Self::over(inner, config, server_config, runtime)
  }

  /// Over any socket quinn can drive (tests: the simulated network).
  pub fn over(
    inner: Box<dyn AsyncUdpSocket>,
    mut config: quinn::EndpointConfig,
    server_config: Option<quinn::ServerConfig>,
    runtime: Arc<dyn quinn::Runtime>,
  ) -> io::Result<Self> {
    // Forced rather than assumed: the sort below is only sound while the
    // peer keeps the fixed bit set, and that is what declining to grease
    // gives (see `crate::transport::endpoint_config`). A caller-built
    // config -- the simulator's seeded one -- must not be able to opt
    // back into losing session packets.
    config.grease_quic_bit(false);
    let (socket, probes) = TraversalSocket::new(inner);
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
      config,
      server_config,
      socket.hand(),
      runtime,
    )?;
    Ok(Self {
      endpoint,
      socket,
      probes,
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bootstrap::{SessionNonce, SessionSecret};
  use crate::stun::{BindingTransaction, PeerRole, ProbeLabel};

  fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
  }

  fn map() -> PathMap {
    PathMap::new(Some(addr("0.0.0.0:41000")))
  }

  fn routed(map: &PathMap, dst: SocketAddr) -> Option<SocketAddr> {
    match map.route(dst) {
      Route::To(addr) => Some(addr),
      Route::Drop => None,
    }
  }

  /// The two rewrites, which are each other's inverse: quinn addresses
  /// the alias, the wire carries the real address, and what comes back
  /// from the real address reaches quinn as the alias.
  #[test]
  fn an_alias_stands_in_for_a_real_address() {
    let mut map = map();
    let real = addr("198.51.100.7:60123");
    let virt = map.alias(real, PathKind::Direct).unwrap();
    assert_ne!(virt, real);
    assert_eq!(routed(&map, virt), Some(real));
    assert_eq!(map.arrival(real), Some(virt));
    // Anything the map knows nothing about is left alone in both
    // directions, which is every datagram before a session commits and
    // every session with no traversal at all.
    let stranger = addr("203.0.113.9:60123");
    assert_eq!(routed(&map, stranger), Some(stranger));
    assert_eq!(map.arrival(stranger), None);
  }

  /// One address keeps one alias whichever kinds of path it is dialed
  /// as, so an arrival names exactly one path: establishment reissues a
  /// direct candidate as a punched path at the same address, and two
  /// aliases for it would leave the reissued dial unable to hear its
  /// answers.
  #[test]
  fn one_address_keeps_one_alias() {
    let mut map = map();
    let real = addr("198.51.100.7:60123");
    let first = map.alias(real, PathKind::Direct).unwrap();
    let again = map.alias(real, PathKind::Punched).unwrap();
    assert_eq!(first, again);
    assert_eq!(map.paths.len(), 1);
    assert_eq!(map.paths[0].path_kind, PathKind::Punched);
  }

  /// A switch is atomic against sends: every datagram leaves on the path
  /// before it or the path after it, never on neither (a dropped or
  /// unmapped send) and never twice -- the claim the lock guarantees.
  #[test]
  fn sends_never_see_a_half_made_switch() {
    let relay = addr("198.51.100.7:60123");
    let direct = addr("192.0.2.2:60123");
    let mut map = map();
    let virt = map.alias(relay, PathKind::Relayed).unwrap();
    assert!(map.commit(relay));
    assert!(map.add_path(direct, PathKind::Direct));
    let map = Arc::new(RwLock::new(map));

    let switching = std::thread::spawn({
      let map = map.clone();
      move || {
        for round in 0..10_000 {
          let to = match round % 2 {
            0 => direct,
            _ => relay,
          };
          assert!(map.write().unwrap().switch(to));
        }
      }
    });
    let mut seen = (0, 0);
    for _ in 0..10_000 {
      match map.read().unwrap().route(virt) {
        Route::To(to) if to == direct => seen.0 += 1,
        Route::To(to) if to == relay => seen.1 += 1,
        Route::To(to) => panic!("a send went to {to}"),
        Route::Drop => panic!("a send was dropped mid-switch"),
      }
    }
    switching.join().unwrap();
    assert_eq!(seen.0 + seen.1, 10_000);
  }

  /// Racing candidates are distinct peers to quinn, which is what keeps
  /// a race several connections rather than one confused one.
  #[test]
  fn racing_candidates_get_their_own_aliases() {
    let mut map = map();
    let one = map
      .alias(addr("198.51.100.7:60123"), PathKind::Direct)
      .unwrap();
    let two = map
      .alias(addr("203.0.113.8:60123"), PathKind::Direct)
      .unwrap();
    assert_ne!(one, two);
  }

  /// The map's purpose: after the switch the same virtual peer reaches
  /// the other path, in both directions, and the session can go back.
  #[test]
  fn a_switch_re_points_the_virtual_peer() {
    let mut map = map();
    let relay = addr("198.51.100.7:60123");
    let direct = addr("192.0.2.2:60123");
    let virt = map.alias(relay, PathKind::Relayed).unwrap();
    assert!(map.commit(relay));
    assert_eq!(map.peer, Some(virt));

    // Nothing to switch to until a path is offered, and no switching at
    // all onto an address the map does not hold.
    assert!(!map.switch(direct));
    assert!(map.add_path(direct, PathKind::Direct));
    assert_eq!(routed(&map, virt), Some(relay));

    assert!(map.switch(direct));
    assert_eq!(routed(&map, virt), Some(direct));
    // Both paths are live as far as the session is concerned: what is
    // still in flight on the old one arrives as the same peer.
    assert_eq!(map.arrival(direct), Some(virt));
    assert_eq!(map.arrival(relay), Some(virt));
    // And it is reversible.
    assert!(map.switch(relay));
    assert_eq!(routed(&map, virt), Some(relay));
  }

  /// A candidate that lost the race keeps its own alias until it is
  /// offered as a path, so its connection's parting packets go to the
  /// address it was talking to rather than onto the session's path.
  #[test]
  fn a_losing_candidate_keeps_its_own_alias() {
    let mut map = map();
    let winner = addr("198.51.100.7:60123");
    let loser = addr("203.0.113.8:60123");
    let won = map.alias(winner, PathKind::Direct).unwrap();
    let lost = map.alias(loser, PathKind::Direct).unwrap();
    assert!(map.commit(winner));
    assert_eq!(routed(&map, lost), Some(loser));
    assert_eq!(map.arrival(loser), Some(lost));
    // Offering it as a path is what adds it to the session.
    assert!(map.add_path(loser, PathKind::Punched));
    assert_eq!(map.arrival(loser), Some(won));
  }

  /// The virtual block never reaches the wire, whatever quinn does with
  /// an alias the map has stopped honoring.
  #[test]
  fn an_unmapped_alias_is_dropped_rather_than_sent() {
    let mut map = map();
    let real = addr("198.51.100.7:60123");
    map.alias(real, PathKind::Direct).unwrap();
    let unmapped = SocketAddr::new(map.base.ip(), map.base.port() + 9);
    assert!(matches!(map.route(unmapped), Route::Drop));
  }

  /// A real address inside the session's own block is refused rather
  /// than mapped: the map tells the two apart by address, and a peer
  /// that could name one could otherwise aim the session's sends.
  #[test]
  fn a_real_address_in_the_virtual_block_is_refused() {
    let mut map = map();
    let collision = SocketAddr::new(map.base.ip(), 60123);
    assert_eq!(map.alias(collision, PathKind::Direct), None);
    let real = addr("198.51.100.7:60123");
    map.alias(real, PathKind::Direct).unwrap();
    assert!(map.commit(real));
    assert!(!map.add_path(collision, PathKind::Direct));
  }

  /// A dual-stack destination's v6 hints fail fast on a v4 socket:
  /// quinn refuses the dial under its own lock, and an alias would hide
  /// that refusal (`PathMap::alias`).
  #[test]
  fn a_v6_candidate_on_a_v4_socket_is_left_unmapped() {
    let mut map = map();
    assert_eq!(
      map.alias(addr("[2001:db8::1]:60123"), PathKind::Direct),
      None
    );
  }

  /// A v6 socket sees v4 peers in the v4-mapped form quinn dials them
  /// at, so the map has to match arrivals in that form too.
  #[test]
  fn a_v6_map_normalizes_v4_paths_the_way_quinn_does() {
    let mut map = PathMap::new(Some(addr("[::]:41000")));
    let virt = map
      .alias(addr("198.51.100.7:60123"), PathKind::Direct)
      .unwrap();
    assert!(virt.is_ipv6());
    assert_eq!(map.arrival(addr("[::ffff:198.51.100.7]:60123")), Some(virt));
    assert_eq!(
      routed(&map, virt),
      Some(addr("[::ffff:198.51.100.7]:60123"))
    );
  }

  /// The table is bounded, and a candidate past the bound is dialed at
  /// its real address rather than refused.
  #[test]
  fn the_table_is_bounded() {
    let mut map = map();
    for n in 0..MAX_PATHS {
      let real = addr(&format!("198.51.100.7:{}", 60000 + n));
      assert!(map.alias(real, PathKind::Direct).is_some());
    }
    assert_eq!(map.alias(addr("203.0.113.8:60123"), PathKind::Direct), None);
    assert_eq!(map.paths.len(), MAX_PATHS);
  }

  /// Arrivals are counted per path and reported by an observation.
  #[test]
  fn arrivals_are_counted_per_path() {
    let mut map = map();
    let real = addr("198.51.100.7:60123");
    map.alias(real, PathKind::Direct).unwrap();
    assert_eq!(map.observe()[0].inbound, 0);
    map.arrival(real);
    map.arrival(real);
    assert_eq!(map.observe()[0].inbound, 2);
  }

  /// Which path the session is on is reported, and only once it has one.
  #[test]
  fn the_current_path_is_the_committed_one() {
    let mut map = map();
    let relay = addr("198.51.100.7:60123");
    let direct = addr("192.0.2.2:60123");
    map.alias(relay, PathKind::Relayed).unwrap();
    assert!(map.observe().iter().all(|path| !path.current));
    assert!(map.commit(relay));
    map.add_path(direct, PathKind::Direct);
    map.switch(direct);
    let current: Vec<SocketAddr> = map
      .observe()
      .iter()
      .filter(|path| path.current)
      .map(|path| path.addr)
      .collect();
    assert_eq!(current, vec![direct]);
  }

  /// `RecvMeta` is `#[non_exhaustive]`, so the fields these tests care
  /// about are written over its defaults.
  fn meta(from: &str, len: usize, stride: usize) -> RecvMeta {
    let mut meta = RecvMeta::default();
    meta.addr = from.parse().unwrap();
    meta.len = len;
    meta.stride = stride;
    meta
  }

  fn probe_bytes() -> Vec<u8> {
    BindingTransaction::new(
      ProbeLabel::to_helper(
        SessionNonce::from_bytes([3; 16]),
        PeerRole::Client,
      ),
      &SessionSecret::from_bytes([5; 16]),
    )
    .request()
    .to_vec()
  }

  /// A QUIC short-header packet of `len` bytes: the fixed bit is what
  /// keeps it out of the probe stream.
  fn packet(len: usize, fill: u8) -> Vec<u8> {
    let mut packet = vec![fill; len];
    packet[0] = 0x40;
    packet
  }

  fn drain(received: &mut mpsc::Receiver<Probe>) -> Vec<Vec<u8>> {
    let mut probes = Vec::new();
    while let Ok(probe) = received.try_recv() {
      probes.push(probe.datagram);
    }
    probes
  }

  /// The plain case: one datagram per receive, sorted by class.
  #[test]
  fn a_single_datagram_sorts_by_class() {
    let (sender, mut received) = mpsc::channel(PROBE_QUEUE);
    let probe = probe_bytes();
    let mut buf = probe.clone();
    let len = buf.len();
    assert_eq!(
      sift(&mut buf, &meta("192.0.2.1:3478", len, len), &sender),
      0
    );
    assert_eq!(drain(&mut received), vec![probe]);

    let mut buf = packet(1200, 0xab);
    assert_eq!(
      sift(&mut buf, &meta("192.0.2.1:3478", 1200, 1200), &sender),
      1200
    );
    assert!(drain(&mut received).is_empty());
  }

  /// A GRO batch that mixes a probe with session packets: the session
  /// keeps every one of its packets, in order, and the probe is the only
  /// thing taken out. A sort that judged the batch by its first datagram
  /// would lose one side or the other.
  #[test]
  fn a_mixed_batch_loses_neither_class() {
    let (sender, mut received) = mpsc::channel(PROBE_QUEUE);
    let stride = 64;
    let mut probe = probe_bytes();
    probe.resize(stride, 0);
    let mut buf = Vec::new();
    buf.extend_from_slice(&packet(stride, 1));
    buf.extend_from_slice(&probe);
    buf.extend_from_slice(&packet(stride, 2));
    // The last segment of a batch may be short.
    buf.extend_from_slice(&packet(20, 3));
    let len = buf.len();

    let kept = sift(&mut buf, &meta("192.0.2.9:60000", len, stride), &sender);
    assert_eq!(kept, stride * 2 + 20);
    assert_eq!(&buf[..stride], &packet(stride, 1)[..]);
    assert_eq!(&buf[stride..stride * 2], &packet(stride, 2)[..]);
    assert_eq!(&buf[stride * 2..kept], &packet(20, 3)[..]);
    assert_eq!(drain(&mut received), vec![probe]);
  }

  /// A full probe queue costs a probe and never the session's packets.
  #[test]
  fn a_full_probe_queue_drops_probes_only() {
    let (sender, mut received) = mpsc::channel(1);
    let probe = probe_bytes();
    let stride = probe.len();
    let mut buf = probe.repeat(3);
    let len = buf.len();
    assert_eq!(
      sift(&mut buf, &meta("192.0.2.1:3478", len, stride), &sender),
      0
    );
    assert_eq!(drain(&mut received).len(), 1);
  }

  /// The session's packets must all reach quinn.
  ///
  /// quinn offers by default to accept packets with the QUIC fixed bit
  /// cleared (RFC 9287), and a peer that takes the offer clears it at
  /// random on about half of them -- which the RFC 7983 sort, on that
  /// bit alone, would read as probes. The loss is invisible to the
  /// session, which merely retransmits, so what this pins is that
  /// nothing was diverted at all: a megabyte is enough packets that any
  /// leak shows up as a probe nobody sent.
  #[tokio::test]
  async fn a_bulk_session_over_the_shim_diverts_nothing() -> anyhow::Result<()>
  {
    use crate::pinning::{self, SessionIdentity};
    use crate::transport::TransportOptions;

    let transport = TransportOptions::default();
    let client_identity = SessionIdentity::generate()?;
    let server_identity = SessionIdentity::generate()?;
    let mut server = TraversalEndpoint::bind("127.0.0.1:0".parse()?)?;
    server
      .endpoint
      .set_server_config(Some(pinning::server_config(
        &server_identity,
        client_identity.pin(),
        &transport,
      )?));
    let mut client = TraversalEndpoint::bind("127.0.0.1:0".parse()?)?;
    let server_addr = server.socket.local_addr()?;
    let config = pinning::client_config(
      &client_identity,
      server_identity.pin(),
      &transport,
    )?;

    let accept = tokio::spawn(async move {
      let connection = server.endpoint.accept().await?.await.ok()?;
      let (_send, mut recv) = connection.accept_bi().await.ok()?;
      let got = recv.read_to_end(4 * 1024 * 1024).await.ok()?;
      Some((got.len(), server.probes.try_recv().is_ok()))
    });

    let connection = client
      .endpoint
      .connect_with(config, server_addr, crate::client::SERVER_NAME)?
      .await?;
    let (mut send, _recv) = connection.open_bi().await?;
    let payload = vec![0x5au8; 1024 * 1024];
    send.write_all(&payload).await?;
    send.finish()?;
    let (received, server_diverted) =
      accept.await?.expect("the session did not complete");
    assert_eq!(received, payload.len());
    assert!(!server_diverted, "the server diverted a session packet");
    assert!(
      client.probes.try_recv().is_err(),
      "the client diverted a session packet"
    );
    Ok(())
  }

  /// Over real sockets: a probe sent from one shim surfaces on the
  /// other's probe stream, at the address the endpoint is reached at.
  #[tokio::test]
  async fn probes_cross_between_two_shims() -> anyhow::Result<()> {
    let server = TraversalEndpoint::bind("127.0.0.1:0".parse()?)?;
    let mut client = TraversalEndpoint::bind("127.0.0.1:0".parse()?)?;
    let server_addr = server.socket.local_addr()?;
    let client_addr = client.socket.local_addr()?;

    // A probe in each direction, which neither endpoint may see.
    let probe = probe_bytes();
    client.socket.send_probe(&probe, server_addr).await?;
    let mut probes = server.probes;
    let seen =
      tokio::time::timeout(std::time::Duration::from_secs(5), probes.recv())
        .await?
        .expect("the probe was not diverted");
    assert_eq!(seen.datagram, probe);
    assert_eq!(seen.from, client_addr);

    server.socket.send_probe(&probe, client_addr).await?;
    let seen = tokio::time::timeout(
      std::time::Duration::from_secs(5),
      client.probes.recv(),
    )
    .await?
    .expect("the probe was not diverted");
    assert_eq!(seen.datagram, probe);
    Ok(())
  }

  /// A socket that answers every receive with one error.
  #[derive(Debug, Clone)]
  struct Faulty(io::ErrorKind);

  impl AsyncUdpSocket for Faulty {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
      unreachable!("nothing sends through a socket that only fails")
    }

    fn poll_recv(
      &mut self,
      _cx: &mut Context,
      _bufs: &mut [io::IoSliceMut<'_>],
      _meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
      Poll::Ready(Err(self.0.into()))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
      Ok(addr("127.0.0.1:1"))
    }
  }

  /// What ICMP reports must not reach quinn, which ends the endpoint --
  /// and every session on it -- over a receive error it does not
  /// recognize. A roam produces them by design. What is really wrong
  /// with a socket still gets through.
  #[test]
  fn icmp_reports_are_absorbed_and_real_faults_are_not() {
    let mut buf = [0u8; 64];
    let mut poll = |kind| {
      let mut socket = SharedSocket::new(Box::new(Faulty(kind)));
      let mut meta = [RecvMeta::default()];
      let mut bufs = [io::IoSliceMut::new(&mut buf)];
      let mut cx = Context::from_waker(std::task::Waker::noop());
      socket.poll_recv(&mut cx, &mut bufs, &mut meta)
    };

    for kind in [
      io::ErrorKind::ConnectionRefused,
      io::ErrorKind::ConnectionReset,
      io::ErrorKind::HostUnreachable,
      io::ErrorKind::NetworkUnreachable,
      io::ErrorKind::NetworkDown,
    ] {
      match poll(kind) {
        Poll::Ready(Ok(0)) => {}
        reached => panic!("{kind:?} reached quinn as {reached:?}"),
      }
    }

    match poll(io::ErrorKind::BrokenPipe) {
      Poll::Ready(Err(error)) => {
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
      }
      other => panic!("a real fault was suppressed: {other:?}"),
    }
  }

  /// What an ICMP report must not cost the *next* datagram out of the
  /// same socket, whoever it is addressed to.
  ///
  /// The kernel hands a pending report to the next socket operation, and
  /// when that is a send, the send fails and quinn reports success -- so
  /// a lost probe leaves nothing behind to find it by. Probing an
  /// address this host cannot reach is what draws the report, so the
  /// probe that follows one in the same burst is the one at risk: during
  /// establishment, the rendezvous that opens a firewalled peer.
  #[tokio::test]
  async fn an_icmp_report_does_not_suppress_the_next_probe()
  -> anyhow::Result<()> {
    let paths = TraversalEndpoint::bind(addr("127.0.0.1:0"))?;
    let listener = tokio::net::UdpSocket::bind(addr("127.0.0.1:0")).await?;
    let live = listener.local_addr()?;

    let mut buf = [0u8; 128];
    for round in 0..4u8 {
      // A port nothing is listening on answers with ICMP port
      // unreachable, which is what a peer's unreachable candidate does.
      let dead =
        std::net::UdpSocket::bind(addr("127.0.0.1:0"))?.local_addr()?;
      paths.socket.send_probe(&[round; 32], dead).await?;
      // The report is delivered to the next operation, so it has to have
      // arrived by then; loopback needs microseconds.
      tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      paths.socket.send_probe(&[round; 32], live).await?;

      let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        listener.recv(&mut buf),
      )
      .await
      .map_err(|_| {
        anyhow::anyhow!("round {round}: the probe after the report was lost")
      })??;
      assert_eq!(&buf[..n], &[round; 32]);
    }
    Ok(())
  }

  /// A shim over a real socket with nothing driving it, so the test
  /// itself is what polls the receive path.
  fn shim()
  -> io::Result<(Arc<TraversalSocket>, mpsc::Receiver<Probe>, SocketAddr)> {
    use quinn::Runtime as _;

    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let inner = quinn::TokioRuntime.wrap_udp_socket(socket)?;
    let addr = inner.local_addr()?;
    let (socket, probes) = TraversalSocket::new(inner);
    Ok((socket, probes, addr))
  }

  /// One receive, two consumers, two addresses: the probe keeps the
  /// mapping it arrived from, which is all the information it carries,
  /// and the session packet beside it reaches quinn as the session's one
  /// peer.
  #[tokio::test]
  async fn a_receive_sorts_by_class_and_rewrites_what_quinn_sees()
  -> anyhow::Result<()> {
    let (sender, _diverted, sender_addr) = shim()?;
    let (receiver, mut probes, receiver_addr) = shim()?;
    let virt = receiver.dial_target(sender_addr, PathKind::Direct);
    assert!(receiver.commit(sender_addr));

    let probe = probe_bytes();
    sender.send_probe(&probe, receiver_addr).await?;
    sender
      .send_probe(&packet(1200, 0xab), receiver_addr)
      .await?;

    // Received through the view quinn would be driving, since that is
    // the only way to reach the socket mutably.
    let mut driven = receiver.hand();
    let mut buf = [0u8; 2048];
    let mut meta = [RecvMeta::default()];
    let received = tokio::time::timeout(
      std::time::Duration::from_secs(5),
      std::future::poll_fn(|cx| {
        let mut bufs = [io::IoSliceMut::new(&mut buf)];
        driven.poll_recv(cx, &mut bufs, &mut meta)
      }),
    )
    .await??;
    assert_eq!(received, 1);
    assert_eq!(meta[0].addr, virt, "quinn was told a real path address");
    assert_eq!(&buf[..meta[0].len], &packet(1200, 0xab)[..]);
    let seen = probes.recv().await.expect("the probe was not diverted");
    assert_eq!(seen.datagram, probe);
    assert_eq!(seen.from, sender_addr, "the probe lost its real source");
    Ok(())
  }

  /// A receive that holds nothing but probes owes quinn nothing, so the
  /// shim polls again rather than reporting a receive of zero -- but
  /// only `MAX_ALL_PROBE_RECEIVES` times. How many trips that loop takes
  /// is the one thing in this receive path a sender decides, and this
  /// runtime is single-threaded, so a sustained probe-shaped flood would
  /// otherwise keep the shim inside one task poll indefinitely. Past the
  /// bound it yields an empty receive, having woken its own waker, which
  /// is a scheduling point rather than an end of work.
  #[tokio::test]
  async fn an_all_probe_flood_yields_to_the_runtime() -> anyhow::Result<()> {
    let (sender, _diverted, _) = shim()?;
    let (receiver, mut probes, receiver_addr) = shim()?;
    let probe = probe_bytes();
    for _ in 0..MAX_ALL_PROBE_RECEIVES + 1 {
      sender.send_probe(&probe, receiver_addr).await?;
    }

    let mut driven = receiver.hand();
    let mut buf = [0u8; 2048];
    let mut meta = [RecvMeta::default()];
    let received = tokio::time::timeout(
      std::time::Duration::from_secs(5),
      std::future::poll_fn(|cx| {
        let mut bufs = [io::IoSliceMut::new(&mut buf)];
        driven.poll_recv(cx, &mut bufs, &mut meta)
      }),
    )
    .await??;
    assert_eq!(received, 0, "quinn was handed a probe");
    let mut diverted = 0;
    while probes.try_recv().is_ok() {
      diverted += 1;
    }
    assert_eq!(
      diverted, MAX_ALL_PROBE_RECEIVES,
      "the shim did not stop at its own bound"
    );
    Ok(())
  }

  /// A rebind hands quinn a new socket; the session's paths are the same
  /// session's, so they follow it and stay shared with whoever still
  /// holds the old shim.
  #[tokio::test]
  async fn a_rebound_shim_keeps_the_session_paths() -> anyhow::Result<()> {
    let (socket, _diverted, _) = shim()?;
    let relay = addr("198.51.100.7:60123");
    let direct = addr("192.0.2.2:60123");
    let virt = socket.dial_target(relay, PathKind::Relayed);
    assert!(socket.commit(relay));

    let (fresh, _, _) = shim()?;
    let rebound = socket.rebound(fresh.inner.hand());
    assert_eq!(rebound.peer(), Some(virt));
    assert_eq!(rebound.current_path(), Some(relay));
    assert!(rebound.add_path(direct, PathKind::Direct));
    assert!(rebound.switch_to(direct));
    assert_eq!(socket.current_path(), Some(direct));
    Ok(())
  }

  /// Building the replacement shim is not installing it.
  ///
  /// The endpoint can refuse a rebind, and then the session is still
  /// leaving from the socket it was on: a shim that had already
  /// published itself would send the session's probes -- and the relay
  /// registration they carry ([`crate::helper`]) -- from a mapping quinn
  /// no longer sends on.
  #[tokio::test]
  async fn a_rebind_moves_the_session_only_once_it_is_installed()
  -> anyhow::Result<()> {
    let (socket, _diverted, first) = shim()?;
    let (fresh, _, second) = shim()?;
    assert_eq!(socket.live_addr()?, first);

    let rebound = socket.rebound(fresh.inner.hand());
    assert_eq!(
      socket.live_addr()?,
      first,
      "the session's probes moved before the endpoint took the socket"
    );
    // And nothing was told to re-register, either.
    assert!(
      tokio::time::timeout(
        std::time::Duration::from_millis(50),
        socket.moved()
      )
      .await
      .is_err(),
      "a rebind that was never installed woke the registration"
    );

    rebound.adopt();
    assert_eq!(socket.live_addr()?, second);
    tokio::time::timeout(std::time::Duration::from_secs(5), socket.moved())
      .await
      .expect("the registration was not woken by the rebind");
    Ok(())
  }

  /// The two ways a shim reaches quinn, and the difference between
  /// them: handing one over gives quinn the socket it is already on,
  /// which is a PING, while rebinding gives it another socket, which is
  /// a move. Both carry the session's paths.
  #[tokio::test]
  async fn a_handed_shim_keeps_the_socket_a_rebound_one_replaces()
  -> anyhow::Result<()> {
    let (socket, _diverted, first) = shim()?;
    let (fresh, _, second) = shim()?;
    assert_ne!(first, second);
    let relay = addr("198.51.100.7:60123");
    let virt = socket.dial_target(relay, PathKind::Relayed);
    assert!(socket.commit(relay));

    let handed = socket.hand();
    assert_eq!(handed.local_addr()?, first, "a nudge moved the session");

    let rebound = socket.rebound(fresh.inner.hand());
    assert_eq!(rebound.local_addr()?, second);
    assert_eq!(rebound.peer(), Some(virt), "the rebind lost the paths");
    Ok(())
  }

  /// Every view of a shared socket is the one socket: what a sender
  /// built from one clone sends leaves the binding another clone
  /// receives on. Handing quinn a socket Mush still holds rests on
  /// exactly this.
  #[tokio::test]
  async fn shared_socket_views_are_one_socket() -> anyhow::Result<()> {
    use quinn::Runtime as _;

    let shared = |port| -> io::Result<SharedSocket> {
      let socket = std::net::UdpSocket::bind(("127.0.0.1", port))?;
      Ok(SharedSocket::new(
        quinn::TokioRuntime.wrap_udp_socket(socket)?,
      ))
    };
    let sender = shared(0)?;
    let receiver = shared(0)?;
    let from = sender.local_addr()?;
    let to = receiver.local_addr()?;

    // Sent through a clone of one, received through a clone of the
    // other; neither original is touched again.
    let mut out = sender.clone().create_sender();
    let payload = packet(64, 0xcd);
    let transmit = Transmit {
      destination: to,
      ecn: None,
      contents: &payload,
      segment_size: None,
      src_ip: None,
    };
    std::future::poll_fn(|cx| out.as_mut().poll_send(&transmit, cx)).await?;

    let mut inbound = receiver.clone();
    let mut buf = [0u8; 2048];
    let mut meta = [RecvMeta::default()];
    let received = tokio::time::timeout(
      std::time::Duration::from_secs(5),
      std::future::poll_fn(|cx| {
        let mut bufs = [io::IoSliceMut::new(&mut buf)];
        inbound.poll_recv(cx, &mut bufs, &mut meta)
      }),
    )
    .await??;
    assert_eq!(received, 1);
    assert_eq!(meta[0].addr, from);
    assert_eq!(&buf[..meta[0].len], &payload[..]);
    Ok(())
  }
}
