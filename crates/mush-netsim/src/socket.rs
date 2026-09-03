// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Simulated UDP sockets: quinn's [`AsyncUdpSocket`] over the simulated
//! network, plus a plain datagram API for non-QUIC traffic (future STUN
//! probes and punch packets) and for tests of the network itself.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpSender};

use crate::net::Inner;

/// A socket bound at one simulated address.
///
/// Obtained from [`SimNet::bind`](crate::SimNet::bind). Implements quinn's
/// [`AsyncUdpSocket`], so `Box::new(socket)` plugs directly into
/// `Endpoint::new_with_abstract_socket` and `Endpoint::rebind_abstract`,
/// and a clone keeps the caller a handle on the socket it just handed
/// over. Cloning is cheap and every clone is the same binding, which is
/// released when the last of them drops.
///
/// One consumer at a time, clones included: the binding holds a single
/// receive waker, so either quinn or [`Self::recv_from`] may wait on it,
/// not both at once.
#[derive(Clone)]
pub struct SimSocket {
  bound: Arc<Bound>,
}

/// The binding itself, so that releasing the address is the last clone's
/// job rather than the first drop's.
struct Bound {
  inner: Arc<Inner>,
  addr: SocketAddr,
}

impl SimSocket {
  pub(crate) fn new(inner: Arc<Inner>, addr: SocketAddr) -> Self {
    Self {
      bound: Arc::new(Bound { inner, addr }),
    }
  }

  /// The simulated address this socket is bound at.
  pub fn addr(&self) -> SocketAddr {
    self.bound.addr
  }

  /// Send one datagram into the simulated network. Never blocks; the
  /// network decides the datagram's fate (drop, delay, duplicate,
  /// translate) on the spot.
  pub fn send_to(&self, payload: &[u8], dst: SocketAddr) -> io::Result<()> {
    self.bound.send(payload, dst, None)
  }

  /// Receive one datagram, returning its length and (post-NAT wire) source
  /// address. A datagram longer than `buf` is truncated, UDP-style.
  pub async fn recv_from(
    &self,
    buf: &mut [u8],
  ) -> io::Result<(usize, SocketAddr)> {
    std::future::poll_fn(|cx| {
      self.bound.inner.poll_recv_from(self.bound.addr, cx, buf)
    })
    .await
    .map(|(n, src, _ecn)| (n, src))
  }
}

impl Bound {
  fn send(
    &self,
    payload: &[u8],
    dst: SocketAddr,
    ecn: Option<quinn::udp::EcnCodepoint>,
  ) -> io::Result<()> {
    self.inner.send_datagram(self.addr, dst, payload, ecn)
  }
}

impl fmt::Debug for Bound {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Bound").field("addr", &self.addr).finish()
  }
}

impl Drop for Bound {
  fn drop(&mut self) {
    self.inner.unbind(self.addr);
  }
}

impl fmt::Debug for SimSocket {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("SimSocket")
      .field("addr", &self.bound.addr)
      .finish()
  }
}

/// Sends into the simulated network never block, so every send completes
/// where it is made.
#[derive(Debug)]
struct SimSender(Arc<Bound>);

impl UdpSender for SimSender {
  fn poll_send(
    self: Pin<&mut Self>,
    transmit: &Transmit<'_>,
    _cx: &mut Context,
  ) -> Poll<io::Result<()>> {
    // max_transmit_segments() keeps its default of 1, so quinn never hands
    // this socket a GSO batch.
    debug_assert!(transmit.segment_size.is_none());
    Poll::Ready(self.0.send(
      transmit.contents,
      transmit.destination,
      transmit.ecn,
    ))
  }
}

impl AsyncUdpSocket for SimSocket {
  fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
    Box::pin(SimSender(self.bound.clone()))
  }

  fn poll_recv(
    &mut self,
    cx: &mut Context,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
  ) -> Poll<io::Result<usize>> {
    debug_assert!(!bufs.is_empty() && !meta.is_empty());
    match self
      .bound
      .inner
      .poll_recv_from(self.bound.addr, cx, &mut bufs[0])
    {
      Poll::Ready(Ok((len, src, ecn))) => {
        // `RecvMeta` is `#[non_exhaustive]` and carries fields no
        // simulated network has an answer for (a receive timestamp, an
        // interface index), so its defaults stand and the ones the
        // network knows are written over them.
        let mut received = RecvMeta::default();
        received.addr = src;
        received.len = len;
        received.stride = len;
        received.ecn = ecn;
        received.dst_ip = Some(self.bound.addr.ip());
        meta[0] = received;
        Poll::Ready(Ok(1))
      }
      Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
      Poll::Pending => Poll::Pending,
    }
  }

  fn local_addr(&self) -> io::Result<SocketAddr> {
    Ok(self.bound.addr)
  }

  fn may_fragment(&self) -> bool {
    // The simulated network never fragments: oversized datagrams are
    // dropped whole, which also tells quinn it may run DPLPMTUD.
    false
  }
}
