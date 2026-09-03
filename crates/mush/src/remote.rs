// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The lifecycle `mush server bootstrap` and `mush jump-helper` share.
//!
//! Both are started by an ssh exec channel, both read one opening line
//! from it, both answer with one line of their own, and both then
//! detach and serve ([`crate::detach`], whose module docs carry the
//! sshd constraint the holding form exists for). The order is what
//! keeps a stuck remote command from hanging the user's ssh: the
//! alarm is armed before anything can block, and disarmed only once
//! the answer is out.

use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::process::ExitCode;

use anyhow::{Context as _, Result, bail};
use mush_core::bootstrap::PROTOCOL_VERSION;
use mush_core::server::DEFAULT_BOOTSTRAP_TIMEOUT;

use crate::detach::detach;

/// Arms the self-destruct for a client that never finishes the opening
/// conversation, per the design's give-up behavior: SIGALRM's default
/// disposition terminates the process. [`announce`] disarms it.
pub fn arm_bootstrap_alarm() {
  unsafe { libc::alarm(DEFAULT_BOOTSTRAP_TIMEOUT.as_secs() as u32) };
}

/// Reads one opening line from the real stdin, returning it with any
/// bytes read past its newline.
///
/// The line comes straight from the Mush client on the exec channel, so
/// there is no login output to tolerate, and anything without a newline
/// within `max_bytes` is not a Mush client. The leftover bytes matter
/// because the client may send more the moment it has read the answer:
/// a buffered reader would leave those bytes where the control
/// channel's own handle cannot see them. `line_name` (`MUSH HELLO`) and
/// `channel_name` (`bootstrap channel`) name the two in the diagnostics
/// a non-mush command produces.
pub fn read_opening_line(
  max_bytes: usize,
  line_name: &str,
  channel_name: &str,
) -> Result<(String, Vec<u8>)> {
  let mut buf = Vec::new();
  let mut chunk = [0u8; 1024];
  let newline = loop {
    if let Some(position) = buf.iter().position(|&b| b == b'\n') {
      break position;
    }
    if buf.len() > max_bytes {
      bail!("no complete {line_name} line in the first {max_bytes} bytes");
    }
    let read = match rustix::io::read(std::io::stdin(), &mut chunk) {
      Ok(read) => read,
      Err(rustix::io::Errno::INTR) => continue,
      Err(errno) => {
        return Err(std::io::Error::from(errno)).with_context(|| {
          format!("reading {line_name} from the {channel_name}")
        });
      }
    };
    if read == 0 {
      bail!("{channel_name} closed before a {line_name} line");
    }
    buf.extend_from_slice(&chunk[..read]);
  };
  let text = str::from_utf8(&buf[..newline])
    .ok()
    .with_context(|| format!("{line_name} line is not valid UTF-8"))?;
  let text = text.strip_suffix('\r').unwrap_or(text);
  Ok((text.to_string(), buf[newline + 1..].to_vec()))
}

/// Refuses a peer speaking a protocol version this build does not.
pub fn check_version(version: u32) -> Result<()> {
  if version != PROTOCOL_VERSION {
    bail!("client speaks unsupported protocol version {version}");
  }
  Ok(())
}

/// Answers the opening line, then disarms the alarm -- in that order
/// and never the other way round, since the alarm is what bounds a
/// client that stopped reading. `what` names the write for the error
/// context.
pub fn announce(line: &str, what: &str) -> Result<()> {
  let mut stdout = std::io::stdout().lock();
  stdout
    .write_all(line.as_bytes())
    .and_then(|()| stdout.flush())
    .context(what.to_string())?;
  drop(stdout);
  unsafe { libc::alarm(0) };
  Ok(())
}

/// Detaches, then runs the service the closure builds around the release
/// pipe the detach hands back.
/// `hold_channel` keeps the ssh channel open past the detach;
/// `no_detach` skips the fork and passes no pipe, which is the same
/// thing to the service either way.
///
/// The runtime is built strictly after the fork and the future strictly
/// after the runtime; [`crate::detach`] has why.
pub fn run_detached<F>(
  no_detach: bool,
  hold_channel: bool,
  serve: impl FnOnce(Option<OwnedFd>) -> F,
) -> Result<ExitCode>
where
  F: Future<Output = Result<ExitCode>>,
{
  let release = if no_detach {
    None
  } else {
    detach(hold_channel)?
  };
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .context("building the tokio runtime")?;
  runtime.block_on(serve(release))
}
