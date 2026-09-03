// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The mosh-style detach the remote-side commands share.
//!
//! `mush server bootstrap` and `mush jump-helper` both have to outlive
//! the ssh exec channel that starts them: the session server serves
//! until the session ends, the jump helper until the session it assists
//! does. Both therefore fork, setsid, ignore SIGHUP, and let their
//! parent exit so the ssh that started them finishes.
//!
//! The fork runs strictly before any tokio runtime exists. fork clones
//! only the calling thread, so a runtime's worker and blocking-pool
//! threads -- along with any locks they hold -- would silently vanish
//! in the child.
//!
//! Both also keep talking on the channel past the detach, and that
//! takes two things. sshd holds the channel open until the command's
//! descriptors close, which is what lets the child keep writing; but it
//! stops feeding that command's stdin the moment the command itself
//! exits (OpenSSH's `session_exit_message` fails the channel's write
//! direction), so a child holding the descriptors alone could talk and
//! never be talked to. Only a living parent keeps the inbound direction
//! open, so [`detach`] hands the child a release pipe: the parent blocks
//! until the child closes it, which it does when it is finished with the
//! channel.

use std::os::fd::OwnedFd;

use anyhow::{Context as _, Result};

/// Detaches into a new session, returning the release pipe to close when
/// the ssh channel is no longer needed.
///
/// With `hold_channel`, the child keeps stdin and stdout on the ssh
/// channel and the parent waits on the returned pipe instead of exiting
/// at once; see the module docs for why both halves are needed.
/// Otherwise stdio joins stderr on /dev/null, the parent exits
/// immediately, and the channel ends there.
///
/// stderr goes to /dev/null either way: a detached process has no
/// terminal to report to, so its diagnostics must not reach the user's.
pub fn detach(hold_channel: bool) -> Result<Option<OwnedFd>> {
  let release = hold_channel
    .then(rustix::pipe::pipe)
    .transpose()
    .context("release pipe for the ssh channel")?;
  match unsafe { libc::fork() } {
    -1 => Err(std::io::Error::last_os_error()).context("fork for the detach"),
    0 => {
      rustix::process::setsid().context("setsid in the detached process")?;
      unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
      let devnull = std::fs::File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .context("opening /dev/null")?;
      if release.is_none() {
        rustix::stdio::dup2_stdin(&devnull)?;
        rustix::stdio::dup2_stdout(&devnull)?;
      }
      rustix::stdio::dup2_stderr(&devnull)?;
      Ok(release.map(|(_read, write)| write))
    }
    _ => {
      if let Some((read, write)) = release {
        // The child's copy is the only one that matters; holding this
        // one would make the wait below never end.
        drop(write);
        wait_for_release(&read);
      }
      std::process::exit(0)
    }
  }
}

/// Blocks until the detached child closes its end of the pipe, which is
/// how it says the ssh channel is finished with. A child that died
/// instead closes it just the same, so nothing here can outlive the
/// work it is holding the channel open for.
fn wait_for_release(release: &OwnedFd) {
  let mut byte = [0u8; 1];
  loop {
    match rustix::io::read(release, &mut byte) {
      // Nothing is ever written; the close is the whole signal.
      Ok(0) => return,
      Ok(_) | Err(rustix::io::Errno::INTR) => {}
      Err(_) => return,
    }
  }
}

/// Points stdin and stdout at /dev/null, which is what ends an ssh
/// channel a holding detach kept open. Best effort: a process that
/// cannot open /dev/null has nothing better left to try.
pub fn close_stdio() {
  let Ok(devnull) = std::fs::File::options()
    .read(true)
    .write(true)
    .open("/dev/null")
  else {
    return;
  };
  let _ = rustix::stdio::dup2_stdin(&devnull);
  let _ = rustix::stdio::dup2_stdout(&devnull);
}
