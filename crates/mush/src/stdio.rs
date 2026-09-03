// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Owned stdin/stdout handles for relaying the ProxyCommand byte
//! stream.
//!
//! `mush connect` relays its own stdio: fds 0 and 1 are the pipe (or
//! socketpair) the outer ssh created for its ProxyCommand. Shutting down
//! the local write side has to deliver a real EOF to the peer process
//! ([`mush_core::relay`]'s contract), which `tokio::io::stdout()` cannot
//! do: its shutdown only flushes, and fd 1 stays open. So these wrappers
//! own the descriptors outright:
//!
//! - Each fd is duplicated and the original repointed at /dev/null, so
//!   the wrapper holds this process's only reference to the channel: a
//!   stray print cannot corrupt the byte stream, and closing the wrapper
//!   genuinely closes the channel.
//! - The duplicate is made nonblocking and driven through
//!   [`tokio::io::unix::AsyncFd`].
//! - [`StdoutPipe`]'s shutdown half-closes for real: `shutdown(SHUT_WR)`
//!   on a socketpair (ssh may pass one socketpair end as both fd 0 and
//!   fd 1, where a close leaves the write direction open while the stdin
//!   duplicate still references the socket), otherwise a close, which
//!   ends a pipe because the duplicate is its last write reference.
//!
//! The fds are assumed to be that pipe or socketpair; `mush connect` is
//! not meant to run with a terminal on stdio (the nonblocking flag is
//! set on the open file description, which a terminal would share with
//! the shell).

use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use rustix::fs::OFlags;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};

/// The owned read half of the ProxyCommand channel (fd 0's duplicate).
#[derive(Debug)]
pub struct StdinPipe {
  fd: AsyncFd<File>,
}

/// The owned write half of the ProxyCommand channel (fd 1's duplicate).
/// `None` once shut down.
#[derive(Debug)]
pub struct StdoutPipe {
  fd: Option<AsyncFd<File>>,
}

/// Takes ownership of this process's stdio for the relay; see the
/// module docs. Must run inside a tokio runtime.
pub fn take_stdio() -> io::Result<(StdinPipe, StdoutPipe)> {
  let stdin_dup = rustix::io::dup(rustix::stdio::stdin())?;
  let stdout_dup = rustix::io::dup(rustix::stdio::stdout())?;
  let devnull = File::options().read(true).write(true).open("/dev/null")?;
  rustix::stdio::dup2_stdin(&devnull)?;
  rustix::stdio::dup2_stdout(&devnull)?;
  Ok((
    StdinPipe {
      fd: async_fd(stdin_dup, Interest::READABLE)?,
    },
    StdoutPipe {
      fd: Some(async_fd(stdout_dup, Interest::WRITABLE)?),
    },
  ))
}

fn async_fd(fd: OwnedFd, interest: Interest) -> io::Result<AsyncFd<File>> {
  let flags = rustix::fs::fcntl_getfl(&fd)?;
  rustix::fs::fcntl_setfl(&fd, flags | OFlags::NONBLOCK)?;
  AsyncFd::with_interest(File::from(fd), interest)
}

impl AsRawFd for StdinPipe {
  /// The owned descriptor, for readiness observation (`poll(2)` for
  /// POLLHUP) alongside the relay's ownership of the handle. Valid as
  /// long as the `StdinPipe` lives.
  fn as_raw_fd(&self) -> RawFd {
    self.fd.get_ref().as_raw_fd()
  }
}

impl AsyncRead for StdinPipe {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    let this = self.get_mut();
    loop {
      let mut guard = ready!(this.fd.poll_read_ready(cx))?;
      let result = guard.try_io(|inner| {
        let mut file: &File = inner.get_ref();
        file.read(buf.initialize_unfilled())
      });
      match result {
        Ok(Ok(n)) => {
          buf.advance(n);
          return Poll::Ready(Ok(()));
        }
        Ok(Err(error)) => return Poll::Ready(Err(error)),
        // A stale readiness event; poll again.
        Err(_would_block) => {}
      }
    }
  }
}

impl AsyncWrite for StdoutPipe {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    data: &[u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    let Some(fd) = &this.fd else {
      return Poll::Ready(Err(io::Error::new(
        io::ErrorKind::NotConnected,
        "stdout already shut down",
      )));
    };
    loop {
      let mut guard = ready!(fd.poll_write_ready(cx))?;
      let result = guard.try_io(|inner| {
        let mut file: &File = inner.get_ref();
        file.write(data)
      });
      match result {
        Ok(result) => return Poll::Ready(result),
        Err(_would_block) => {}
      }
    }
  }

  fn poll_flush(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<io::Result<()>> {
    // Pipe and socket writes go straight to the kernel; there is no
    // user-space buffer to flush.
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<io::Result<()>> {
    let this = self.get_mut();
    if let Some(fd) = this.fd.take() {
      // into_inner deregisters the fd from the reactor before we end
      // the write direction under it.
      let file = fd.into_inner();
      match rustix::net::shutdown(&file, rustix::net::Shutdown::Write) {
        // A socketpair got its FIN; dropping `file` merely releases
        // the duplicate.
        Ok(()) => {}
        // A pipe: dropping `file` closes the last write reference,
        // which is the EOF.
        Err(rustix::io::Errno::NOTSOCK) => {}
        Err(errno) => return Poll::Ready(Err(errno.into())),
      }
    }
    Poll::Ready(Ok(()))
  }
}
