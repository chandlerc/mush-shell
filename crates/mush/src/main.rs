// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Mush: a roaming, resumable transport for SSH. Carries an unmodified
//! OpenSSH client's byte stream to an unmodified sshd over a QUIC tunnel
//! that survives packet loss, outages, NAT rebinds, and client address
//! changes.

mod connect;
mod detach;
mod helper;
mod remote;
mod server;
mod stdio;
mod wrapper;

use std::ffi::OsString;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};

/// The subcommand words and clap builtins that dispatch through clap
/// when they appear as the first argument; every other invocation is
/// wrapper mode and takes the raw argv (see `main`). These first words
/// are therefore reserved: a destination named like one needs the
/// wrapper's `--` escape (`mush -- connect`).
const CLAP_FIRST_WORDS: [&str; 8] = [
  "connect",
  "server",
  "jump-helper",
  "help",
  "-h",
  "--help",
  "-V",
  "--version",
];

/// Only the reserved first words reach clap; everything else is wrapper
/// mode and never gets here (see `main`), so the subcommand is required
/// and wrapper mode is described rather than parsed.
#[derive(Parser)]
#[command(
  name = "mush",
  version,
  after_help = "\
With no subcommand, mush wraps the real ssh: `mush [ssh args] destination \
[command]` injects a ProxyCommand and passes everything else through \
verbatim. Use `--` before a destination that collides with a subcommand \
name or starts with a dash."
)]
struct Cli {
  #[command(subcommand)]
  command: Command,
}

#[derive(Subcommand)]
enum Command {
  /// ProxyCommand mode: carry ssh's transport bytes over the Mush tunnel.
  /// Intended as `ProxyCommand mush connect %r %h %p` in `~/.ssh/config`.
  #[command(after_help = "\
The wrapper mode (`mush [ssh args] destination`) forwards a fixed set of \
outer ssh flags (-i -J -o) to the bootstrap ssh through the \
MUSH_BOOTSTRAP_SSH_ARGS environment variable: argv entries joined with \
the ASCII unit separator (0x1f), no quoting. Its --ssh=<cmd>, \
--server=<cmd>, and --helper=<cmd> options (equals form only) arrive \
here the same way, as MUSH_CONNECT_SSH, MUSH_CONNECT_SERVER, and \
MUSH_CONNECT_HELPER; each variable supplies the default for the matching \
flag, and an explicit flag wins. `mush connect` consumes all four \
variables without passing any of them on to the bootstrap ssh.")]
  Connect(connect::Options),
  /// Remote side: accept the tunnel and relay it to the local sshd.
  Server {
    #[command(subcommand)]
    command: ServerCommand,
  },
  /// Traversal assistance on a jump host: STUN reflection, punch
  /// rendezvous, and relay of last resort, for the sessions whose
  /// nonces arrive over this ssh channel. Started by `mush connect`
  /// over a second exec channel to the jump; see the design doc's
  /// "The jump helper".
  JumpHelper {
    /// Stay in the foreground instead of detaching: no fork, stdio
    /// kept. For tests and debugging.
    #[arg(long)]
    no_detach: bool,

    /// Stop serving a session that has been silent this long (e.g.
    /// "12h"): the design's retention bound. Default: retain
    /// indefinitely, mosh-style, so a relayed session survives a long
    /// offline period. Must comfortably exceed the client's keep-alive
    /// interval (20s) or live idle sessions lose their relay.
    #[arg(long, value_name = "duration", value_parser = parse_duration)]
    retain: Option<Duration>,

    /// No effect: tags this process's argv so scripts and tests can
    /// find the detached helper (e.g. `pgrep -f`).
    #[arg(long, value_name = "tag")]
    marker: Option<String>,
  },
}

#[derive(Subcommand)]
enum ServerCommand {
  /// Run by the bootstrap ssh: bind a UDP port, print `MUSH CONNECT`,
  /// detach, and serve one pinned QUIC session.
  Bootstrap {
    /// Stay in the foreground instead of detaching: no fork, stdio kept.
    /// For tests and debugging.
    #[arg(long)]
    no_detach: bool,

    /// Give up on a silent client after this long (e.g. "12h"): the
    /// design's retention bound. Default: retain indefinitely,
    /// mosh-style. Bounds both a dead client and an outage (the two are
    /// indistinguishable), so it must comfortably exceed the client's
    /// keep-alive interval (20s) or live idle sessions die too.
    #[arg(long, value_name = "duration", value_parser = parse_duration)]
    retain: Option<Duration>,

    /// The local sshd port to relay into, overriding the one the client
    /// announced (ssh's %p). For a destination whose public ssh port is
    /// remapped to a different internal one: `--server 'mush server
    /// bootstrap --target 22'`.
    #[arg(long, value_name = "port")]
    target: Option<u16>,

    /// No effect: tags this process's argv so scripts and tests can find
    /// the detached server (e.g. `pgrep -f`).
    #[arg(long, value_name = "tag")]
    marker: Option<String>,
  },
}

fn main() -> ExitCode {
  tracing_subscriber::fmt()
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .with_writer(std::io::stderr)
    .init();

  // Wrapper invocations take the raw argv: routed through clap, a
  // leading `--` would be consumed as clap's own end-of-options marker
  // before the wrapper ever saw it, making the documented escape for
  // dash-prefixed destinations (`mush -- -odd-host`) unreachable. Only
  // a reserved first word dispatches through clap.
  let args: Vec<OsString> = std::env::args_os().skip(1).collect();
  let reserved = args
    .first()
    .and_then(|arg| arg.to_str())
    .is_some_and(|arg| CLAP_FIRST_WORDS.contains(&arg));
  if !reserved {
    return report(wrapper::run(args));
  }

  // No async runtime exists here on purpose: the server path must make
  // its detach decision (fork) first, so each mode builds its own
  // runtime; see the server module docs.
  let result = match Cli::parse().command {
    Command::Connect(options) => connect::run(options),
    Command::Server {
      command:
        ServerCommand::Bootstrap {
          no_detach,
          retain,
          target,
          marker: _,
        },
    } => server::run(no_detach, retain, target),
    Command::JumpHelper {
      no_detach,
      retain,
      marker: _,
    } => helper::run(no_detach, retain),
  };
  report(result)
}

fn report(result: anyhow::Result<ExitCode>) -> ExitCode {
  match result {
    Ok(code) => code,
    Err(error) => {
      eprintln!("mush: error: {error:#}");
      ExitCode::FAILURE
    }
  }
}

/// Parses a duration argument: an integer count of seconds, or with an
/// `s`/`m`/`h`/`d` suffix.
fn parse_duration(text: &str) -> Result<Duration, String> {
  let split = text
    .find(|c: char| !c.is_ascii_digit())
    .unwrap_or(text.len());
  let (count, unit) = text.split_at(split);
  let count: u64 = count
    .parse()
    .map_err(|_| format!("invalid duration '{text}'"))?;
  let seconds_per_unit = match unit {
    "" | "s" => 1,
    "m" => 60,
    "h" => 60 * 60,
    "d" => 24 * 60 * 60,
    _ => return Err(format!("invalid duration unit '{unit}' in '{text}'")),
  };
  let seconds = count
    .checked_mul(seconds_per_unit)
    .ok_or_else(|| format!("duration '{text}' is out of range"))?;
  if seconds == 0 {
    return Err(format!("duration '{text}' must be positive"));
  }
  Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
  use clap::CommandFactory;

  use super::*;

  #[test]
  fn cli_definition_is_valid() {
    super::Cli::command().debug_assert();
  }

  #[test]
  fn reserved_first_words_cover_every_subcommand() {
    // The raw-argv dispatch in `main` must route every subcommand word
    // to clap; a subcommand missing here would silently become a
    // wrapper destination.
    for sub in super::Cli::command().get_subcommands() {
      assert!(
        CLAP_FIRST_WORDS.contains(&sub.get_name()),
        "subcommand {} missing from CLAP_FIRST_WORDS",
        sub.get_name()
      );
    }
  }

  #[test]
  fn durations_parse_with_and_without_units() {
    assert_eq!(parse_duration("45"), Ok(Duration::from_secs(45)));
    assert_eq!(parse_duration("45s"), Ok(Duration::from_secs(45)));
    assert_eq!(parse_duration("10m"), Ok(Duration::from_secs(600)));
    assert_eq!(parse_duration("2h"), Ok(Duration::from_secs(7200)));
    assert_eq!(parse_duration("1d"), Ok(Duration::from_secs(86400)));
  }

  #[test]
  fn malformed_durations_are_rejected() {
    for text in ["", "s", "5x", "5 m", "-5s", "0", "0m", "99999999999999999d"] {
      assert!(parse_duration(text).is_err(), "accepted {text:?}");
    }
  }
}
