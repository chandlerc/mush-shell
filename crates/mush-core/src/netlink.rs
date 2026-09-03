// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Listen-only rtnetlink monitor: the Linux fast path that wakes the
//! stall prober ([`crate::roaming`]) the instant the kernel reports a
//! link or address change, instead of waiting for the next probe tick.
//!
//! Deliberately minimal, matching the project's dependency posture: a
//! raw `NETLINK_ROUTE` socket subscribed to the link and IPv4/IPv6
//! address multicast groups, read through tokio's `AsyncFd`. No
//! requests are ever sent and no attributes are parsed; the only
//! question each datagram answers is "did an address appear, or did
//! something else change?", which takes exactly the 16-byte message
//! headers. A dedicated netlink crate stack would be two orders of
//! magnitude more code for the same two bits.

use std::io;
use std::mem;
use std::os::fd::OwnedFd;

use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{AddressFamily, RecvFlags, SocketFlags, SocketType};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tracing::debug;

use crate::roaming::PathWake;

/// Starts the monitor, returning the wake stream for
/// [`crate::roaming::Prober::events`], or `None` when the socket cannot
/// be opened (a sandbox or seccomp policy), which runs the portable
/// stall prober alone. Must run inside a tokio runtime. The reader task
/// exits when the receiver is dropped or the socket fails.
///
/// The wake rate is the datagram rate: one event per netlink datagram
/// that classifies, with no coalescing, no minimum spacing, and an
/// unbounded channel behind it, so a burst is delivered in full.
/// Throttling is deliberately not here -- the monitor reports what the
/// kernel said -- but in the prober, which acts on a wake at most once
/// per probe interval and only on proof that the path is gone; see
/// [`crate::roaming`] and `hostile_netsim`'s saturated-wake tests, which
/// drive thousands of wakes through one.
pub fn watch() -> Option<mpsc::UnboundedReceiver<PathWake>> {
  let socket = match RouteSocket::new() {
    Ok(socket) => socket,
    Err(error) => {
      debug!(%error, "netlink route monitor unavailable");
      return None;
    }
  };
  let (tx, rx) = mpsc::unbounded_channel();
  tokio::spawn(async move {
    let mut buf = vec![0u8; 8192];
    loop {
      let received = tokio::select! {
        biased;
        _ = tx.closed() => return,
        received = socket.recv(&mut buf) => received,
      };
      let woken = match received {
        Ok(n) => classify(&buf[..n]),
        // The socket buffer overflowed and events were lost; whatever
        // they were, something changed.
        Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => true,
        Err(error) => {
          debug!(%error, "netlink route monitor stopped");
          return;
        }
      };
      if woken && tx.send(PathWake).is_err() {
        return;
      }
    }
  });
  Some(rx)
}

/// The raw listen-only socket.
struct RouteSocket {
  fd: AsyncFd<OwnedFd>,
}

impl RouteSocket {
  fn new() -> io::Result<Self> {
    // `NETLINK_ROUTE` is protocol 0, which rustix spells as no protocol.
    let fd = rustix::net::socket_with(
      AddressFamily::NETLINK,
      SocketType::RAW,
      SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
      None,
    )?;
    // Port id 0 lets the kernel assign one: this socket only listens, so
    // it never needs an address anyone can address it by.
    let groups = (libc::RTMGRP_LINK
      | libc::RTMGRP_IPV4_IFADDR
      | libc::RTMGRP_IPV6_IFADDR) as u32;
    rustix::net::bind(&fd, &SocketAddrNetlink::new(0, groups))?;
    Ok(Self {
      fd: AsyncFd::with_interest(fd, Interest::READABLE)?,
    })
  }

  /// Receives one datagram (one or more netlink messages).
  async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
    loop {
      let mut guard = self.fd.readable().await?;
      let result = guard.try_io(|fd| {
        rustix::net::recv(fd, &mut *buf, RecvFlags::empty())
          .map(|(_, received)| received)
          .map_err(io::Error::from)
      });
      match result {
        Ok(received) => return received,
        // Spurious readiness; wait again.
        Err(_would_block) => continue,
      }
    }
  }
}

/// Whether one datagram carries a wake: any link or address change
/// among its messages. Control messages (errors, done markers) carry
/// none, and a malformed length ends the walk -- the datagram boundary
/// is the error containment, so a message the walk cannot reach is a
/// message it never saw.
fn classify(buf: &[u8]) -> bool {
  const HDR: usize = mem::size_of::<libc::nlmsghdr>();
  let mut offset = 0;
  while offset + HDR <= buf.len() {
    let header = &buf[offset..offset + HDR];
    let len = u32::from_ne_bytes(header[0..4].try_into().unwrap()) as usize;
    let kind = u16::from_ne_bytes(header[4..6].try_into().unwrap());
    if len < HDR || len > buf.len() - offset {
      return false;
    }
    if matches!(
      kind,
      libc::RTM_NEWADDR
        | libc::RTM_DELADDR
        | libc::RTM_NEWLINK
        | libc::RTM_DELLINK
    ) {
      return true;
    }
    // Messages within a datagram are 4-byte aligned.
    offset += len.next_multiple_of(4);
  }
  false
}

#[cfg(test)]
mod tests {
  use std::os::fd::AsRawFd as _;

  use super::*;

  /// One netlink message: a header with `kind` and `body_len` bytes of
  /// zeroed payload, padded to the 4-byte message alignment.
  fn message(kind: u16, body_len: usize) -> Vec<u8> {
    let len = mem::size_of::<libc::nlmsghdr>() + body_len;
    let mut buf = (len as u32).to_ne_bytes().to_vec();
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.resize(len.next_multiple_of(4), 0);
    buf
  }

  #[test]
  fn classify_maps_message_kinds() {
    for kind in [
      libc::RTM_NEWADDR,
      libc::RTM_DELADDR,
      libc::RTM_NEWLINK,
      libc::RTM_DELLINK,
    ] {
      assert!(classify(&message(kind, 16)), "kind {kind} carried no wake");
    }
    // Control messages carry no wake.
    assert!(!classify(&message(libc::NLMSG_DONE as u16, 4)));
    assert!(!classify(&[]));
  }

  #[test]
  fn classify_scans_multi_message_datagrams() {
    // An interesting kind wakes wherever it sits in the datagram, which
    // is what the 4-byte-aligned walk is for.
    let mut buf = message(libc::NLMSG_NOOP as u16, 0);
    buf.extend(message(libc::NLMSG_DONE as u16, 5));
    buf.extend(message(libc::RTM_NEWADDR, 3));
    assert!(classify(&buf));
  }

  #[test]
  fn classify_contains_malformed_lengths() {
    // A length shorter than the header, or past the datagram end, ends
    // the walk without panicking or looping.
    let mut undersized = message(libc::RTM_NEWLINK, 0);
    undersized[0..4].copy_from_slice(&4u32.to_ne_bytes());
    assert!(!classify(&undersized));
    let mut oversized = message(libc::RTM_NEWLINK, 0);
    oversized[0..4].copy_from_slice(&1024u32.to_ne_bytes());
    assert!(!classify(&oversized));
    // A malformed message masks later ones; the walk cannot resync.
    let mut buf = message(libc::RTM_NEWLINK, 0);
    buf[0..4].copy_from_slice(&2u32.to_ne_bytes());
    buf.extend(message(libc::RTM_NEWADDR, 0));
    assert!(!classify(&buf));
  }

  /// Construction either yields a bound socket or an ordinary I/O
  /// error, and never panics or aborts.
  ///
  /// A refusal is not a failure: a sandbox or a seccomp filter that
  /// denies `AF_NETLINK` is what [`watch`] returning `None` exists for.
  /// So the assertion is the shape of both outcomes, which is all this
  /// call promises.
  #[tokio::test]
  async fn route_socket_construction_either_binds_or_errors() {
    match RouteSocket::new() {
      Ok(socket) => {
        // A bound socket, not a half-made one: reading from it is what
        // the monitor does next.
        assert!(socket.fd.as_raw_fd() >= 0);
      }
      Err(error) => {
        // The degraded path the caller handles, reached as an ordinary
        // errno rather than a panic.
        assert!(error.raw_os_error().is_some(), "{error:?}");
        eprintln!("netlink unavailable here (fine): {error}");
      }
    }
  }
}
