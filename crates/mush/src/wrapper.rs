// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Wrapper mode: `mush [ssh args] destination [command]` execs the
//! real ssh with a ProxyCommand pointing back at this binary,
//! mosh-style.
//!
//! Argv is parsed only enough to find the destination and pick out a
//! fixed set of flags to forward to the bootstrap ssh; everything else
//! passes through verbatim (the design's "minimal parse" decision).
//! The forwarded flags travel in [`BOOTSTRAP_SSH_ARGS_ENV`] as argv
//! entries joined with the ASCII unit separator: each entry ends up in
//! the bootstrap ssh's argv byte-for-byte, so there is no quoting layer
//! to get wrong. The separator byte itself is reserved: a forwarded
//! value containing it (or an empty one) is refused up front, keeping
//! the encoding injective -- a re-split value could otherwise smuggle a
//! stray token that ssh would take as the destination.
//!
//! The wrapper also accepts three long options of its own,
//! `--ssh=<cmd>`, `--server=<cmd>`, and `--helper=<cmd>` (equals form
//! only), which become the injected `mush connect`'s
//! `--ssh`/`--server`/`--helper` defaults via
//! [`CONNECT_SSH_ENV`]/[`CONNECT_SERVER_ENV`]/[`CONNECT_HELPER_ENV`].
//! ssh has no long options, so the `--` namespace is collision-free;
//! every other `--`-prefixed argument still passes through to ssh
//! untouched. The values travel whole in one variable each -- no
//! joining, so no framing to get wrong -- rather than spliced into the
//! ProxyCommand string, which would need shell quoting.
//!
//! All four variables are an internal wrapper-to-connect channel that
//! the wrapper owns outright: [`run`] clears any value inherited from
//! its own environment (an exported leftover, or an ssh_config
//! `Match exec` child that re-ran `mush`) instead of letting it reach the
//! injected `mush connect` as if this invocation had produced it.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::process::CommandExt as _;
use std::process::ExitCode;

use anyhow::{Context as _, Result, bail};

/// Environment variable carrying outer-ssh flags to the bootstrap ssh
/// spawned by `mush connect`, which the ProxyCommand's `%r %h %p`
/// tokens alone cannot: argv entries joined with [`ARG_SEPARATOR`].
pub const BOOTSTRAP_SSH_ARGS_ENV: &str = "MUSH_BOOTSTRAP_SSH_ARGS";

/// Separator between argv entries in [`BOOTSTRAP_SSH_ARGS_ENV`]: the
/// ASCII unit separator. The byte is reserved: [`plan`] refuses to
/// forward a value containing it, and the consumer rejects framing that
/// could only come from an unvalidated producer (see
/// `connect::forwarded_env_args`).
pub const ARG_SEPARATOR: u8 = 0x1f;

/// Environment variable carrying the wrapper's `--ssh=<cmd>` to
/// `mush connect`, where it becomes the `--ssh` default (an explicit
/// flag wins). One whole value per variable: no joining, no quoting.
pub const CONNECT_SSH_ENV: &str = "MUSH_CONNECT_SSH";

/// Environment variable carrying the wrapper's `--server=<cmd>` to
/// `mush connect`, as [`CONNECT_SSH_ENV`] does for `--ssh`.
pub const CONNECT_SERVER_ENV: &str = "MUSH_CONNECT_SERVER";

/// Environment variable carrying the wrapper's `--helper=<cmd>` to
/// `mush connect`, as [`CONNECT_SSH_ENV`] does for `--ssh`.
pub const CONNECT_HELPER_ENV: &str = "MUSH_CONNECT_HELPER";

/// Every variable of the wrapper-to-connect channel. [`run`] sets or
/// clears each one, and `mush connect` strips all of them from the ssh
/// children it spawns, so the channel is exactly one hop long whatever
/// the invoking environment held.
pub const WRAPPER_ENV: [&str; 4] = [
  BOOTSTRAP_SSH_ARGS_ENV,
  CONNECT_SSH_ENV,
  CONNECT_SERVER_ENV,
  CONNECT_HELPER_ENV,
];

/// ssh's value-taking single-letter options (OpenSSH's getopt string),
/// needed to tell a flag's value apart from the destination.
const VALUE_FLAGS: &str = "BbcDEeFIiJLlmOoPpQRSWw";

/// The flags forwarded to the bootstrap ssh. Deliberately a fixed,
/// small set ("Resolved decisions" in the design doc): the
/// auth-relevant ones plus the jump spec. `-p` and `-l` are not
/// forwarded: they already reach the bootstrap ssh as the explicit flags
/// `mush connect` builds from the ProxyCommand's `%p`/`%r` tokens, and
/// ssh takes the first occurrence of an option, so a forwarded copy
/// could only conflict.
const FORWARDED_FLAGS: [char; 3] = ['i', 'J', 'o'];

/// The exec plan built from the wrapper's argv.
#[derive(Debug, Default, PartialEq, Eq)]
struct Plan {
  /// Arguments for the real ssh: the ProxyCommand injected ahead of
  /// the user's arguments (the first `-o` occurrence of an option
  /// wins), `-J` removed (ssh forbids ProxyJump next to ProxyCommand,
  /// so the jump moves to Mush's side of the split; see "Bootstrap
  /// through the jump" in the design doc).
  ssh_args: Vec<OsString>,
  /// Argv entries destined for [`BOOTSTRAP_SSH_ARGS_ENV`].
  bootstrap_args: Vec<OsString>,
  /// `--ssh=<cmd>`, destined for [`CONNECT_SSH_ENV`].
  connect_ssh: Option<OsString>,
  /// `--server=<cmd>`, destined for [`CONNECT_SERVER_ENV`].
  connect_server: Option<OsString>,
  /// `--helper=<cmd>`, destined for [`CONNECT_HELPER_ENV`].
  connect_helper: Option<OsString>,
}

/// Execs the real ssh per [`Plan`]; returns only on failure.
pub fn run(args: Vec<OsString>) -> Result<ExitCode> {
  let exe =
    std::env::current_exe().context("resolving the mush executable path")?;
  let exe = exe.to_str().context("mush executable path is not UTF-8")?;
  let plan = plan(exe, &args)?;
  let mut command = std::process::Command::new("ssh");
  command.args(&plan.ssh_args);
  // Own the channel in both directions (see the module docs): set what
  // this invocation produced, and clear what it did not.
  let forwarded =
    (!plan.bootstrap_args.is_empty()).then(|| join_args(&plan.bootstrap_args));
  for (name, value) in [
    (BOOTSTRAP_SSH_ARGS_ENV, forwarded),
    (CONNECT_SSH_ENV, plan.connect_ssh),
    (CONNECT_SERVER_ENV, plan.connect_server),
    (CONNECT_HELPER_ENV, plan.connect_helper),
  ] {
    match value {
      Some(value) => command.env(name, value),
      None => command.env_remove(name),
    };
  }
  tracing::debug!(?command, "exec ssh");
  let error = command.exec();
  Err(error).context("exec ssh")
}

/// Scans `args` for the destination and the forwarded flags, and builds
/// the exec plan. `mush_exe` is this binary's absolute path, quoted
/// into the ProxyCommand string.
fn plan(mush_exe: &str, args: &[OsString]) -> Result<Plan> {
  let mut out: Vec<OsString> = Vec::new();
  let mut bootstrap: Vec<OsString> = Vec::new();
  let mut connect_ssh: Option<OsString> = None;
  let mut connect_server: Option<OsString> = None;
  let mut connect_helper: Option<OsString> = None;
  let mut found_destination = false;
  let mut i = 0;
  while i < args.len() {
    let arg = &args[i];
    let bytes = arg.as_bytes();
    if bytes.first() != Some(&b'-') || bytes.len() < 2 {
      // The destination; it and everything after it (an optional
      // remote command) pass through without scanning. ssh still
      // parses options after the destination, up to the first command
      // word, so a post-destination -J reaches ssh as a real option
      // and fails closed against the injected ProxyCommand ("Cannot
      // specify -J with ProxyCommand") rather than being ignored.
      out.extend(args[i..].iter().cloned());
      found_destination = true;
      break;
    }
    if bytes == b"--" {
      // getopt's end-of-options marker: the next argument is the
      // destination even if it starts with a dash.
      out.extend(args[i..].iter().cloned());
      found_destination = args.len() > i + 1;
      break;
    }
    if bytes.starts_with(b"--") {
      // A long option. `--ssh=`/`--server=`/`--helper=` are the
      // wrapper's own (equals form only); everything else -- including
      // a bare one of those -- passes through to ssh verbatim, never
      // scanned as a flag cluster and never forwarded, so ssh's own
      // unknown-option error stays authoritative.
      let ours = [
        ("--ssh", &mut connect_ssh),
        ("--server", &mut connect_server),
        ("--helper", &mut connect_helper),
      ]
      .into_iter()
      .find_map(|(name, slot)| {
        let value = bytes.strip_prefix(name.as_bytes())?;
        let value = value.strip_prefix(b"=")?;
        Some((name, slot, OsStr::from_bytes(value).to_os_string()))
      });
      match ours {
        Some((name, slot, value)) => {
          if value.is_empty() {
            bail!("wrapper option {name}= has an empty value");
          }
          if slot.is_some() {
            bail!("duplicate wrapper option {name}=");
          }
          *slot = Some(value);
        }
        None => out.push(arg.clone()),
      }
      i += 1;
      continue;
    }
    // A flag cluster ("-v", "-4A", "-p2222"). The first value-taking
    // letter consumes the rest of the argument as its value, or the
    // next argument if nothing is attached.
    let letters = &bytes[1..];
    let value_flag = letters.iter().enumerate().find_map(|(j, &b)| {
      VALUE_FLAGS.contains(b as char).then_some((j, b as char))
    });
    let Some((j, flag)) = value_flag else {
      out.push(arg.clone());
      i += 1;
      continue;
    };
    let attached = letters.len() > j + 1;
    let value: OsString = if attached {
      OsStr::from_bytes(&letters[j + 1..]).to_os_string()
    } else {
      let Some(next) = args.get(i + 1) else {
        bail!("ssh option -{flag} is missing its value");
      };
      next.clone()
    };
    if flag == 'o' && option_sets_keyword(value.as_bytes(), b"proxycommand") {
      // ssh takes the first occurrence of an option and the injected
      // ProxyCommand leads, so a user's own could only lose silently.
      bail!(
        "-o {} conflicts with the ProxyCommand the mush wrapper injects; \
         use plain ssh (or `mush connect --ssh ...`) instead",
        value.to_string_lossy()
      );
    }
    if FORWARDED_FLAGS.contains(&flag) {
      // The env encoding cannot represent these; refuse rather than
      // corrupt the framing (see [`ARG_SEPARATOR`]).
      if value.as_bytes().contains(&ARG_SEPARATOR) {
        bail!(
          "ssh option -{flag} value contains the reserved separator \
           byte 0x1f and cannot be forwarded"
        );
      }
      if value.is_empty() {
        bail!("ssh option -{flag} has an empty value");
      }
      bootstrap.push(format!("-{flag}").into());
      bootstrap.push(value.clone());
    }
    if flag == 'J' {
      // Keep any letters clustered ahead of the stripped -J.
      if j > 0 {
        out.push(OsStr::from_bytes(&bytes[..1 + j]).to_os_string());
      }
    } else {
      out.push(arg.clone());
      if !attached {
        out.push(value);
      }
    }
    i += if attached { 1 } else { 2 };
  }
  if !found_destination {
    bail!("no destination in the ssh arguments");
  }

  let proxy_command =
    format!("ProxyCommand={} connect %r %h %p", shell_quote(mush_exe));
  let mut ssh_args = vec![OsString::from("-o"), proxy_command.into()];
  ssh_args.extend(out);
  Ok(Plan {
    ssh_args,
    bootstrap_args: bootstrap,
    connect_ssh,
    connect_server,
    connect_helper,
  })
}

/// Single-quotes `word` for the shell that runs the ProxyCommand
/// string.
fn shell_quote(word: &str) -> String {
  format!("'{}'", word.replace('\'', r"'\''"))
}

/// Whether an `-o` option value sets `keyword` (which must be given
/// lowercase): ssh option keywords are case-insensitive, take their
/// argument after `=` or whitespace, and tolerate leading blanks. A
/// value that is the bare keyword also matches -- ssh rejects it for
/// the missing argument, and callers here fail closed on the keyword
/// alone.
pub(crate) fn option_sets_keyword(value: &[u8], keyword: &[u8]) -> bool {
  let start = value
    .iter()
    .position(|&b| b != b' ' && b != b'\t')
    .unwrap_or(value.len());
  let value = &value[start..];
  if value.len() < keyword.len() {
    return false;
  }
  let (head, rest) = value.split_at(keyword.len());
  head.eq_ignore_ascii_case(keyword)
    && matches!(rest.first(), None | Some(b'=' | b' ' | b'\t'))
}

/// Joins argv entries with [`ARG_SEPARATOR`] for the environment
/// variable.
fn join_args(args: &[OsString]) -> OsString {
  let mut joined = Vec::new();
  for (index, arg) in args.iter().enumerate() {
    if index > 0 {
      joined.push(ARG_SEPARATOR);
    }
    joined.extend_from_slice(arg.as_bytes());
  }
  OsString::from_vec(joined)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn os(args: &[&str]) -> Vec<OsString> {
    args.iter().map(Into::into).collect()
  }

  fn planned(args: &[&str]) -> Plan {
    plan("/opt/mush", &os(args)).unwrap()
  }

  const PROXY: &str = "ProxyCommand='/opt/mush' connect %r %h %p";

  #[test]
  fn bare_destination_gets_the_proxy_command() {
    assert_eq!(
      planned(&["dest"]),
      Plan {
        ssh_args: os(&["-o", PROXY, "dest"]),
        ..Plan::default()
      }
    );
  }

  #[test]
  fn forwarded_flags_reach_the_env_and_stay_in_argv() {
    assert_eq!(
      planned(&["-v", "-i", "key", "-o", "BatchMode=yes", "dest", "true"]),
      Plan {
        ssh_args: os(&[
          "-o",
          PROXY,
          "-v",
          "-i",
          "key",
          "-o",
          "BatchMode=yes",
          "dest",
          "true"
        ]),
        bootstrap_args: os(&["-i", "key", "-o", "BatchMode=yes"]),
        ..Plan::default()
      }
    );
  }

  #[test]
  fn attached_values_are_forwarded_and_passed_through() {
    assert_eq!(
      planned(&["-ikey", "dest"]),
      Plan {
        ssh_args: os(&["-o", PROXY, "-ikey", "dest"]),
        bootstrap_args: os(&["-i", "key"]),
        ..Plan::default()
      }
    );
  }

  #[test]
  fn port_and_login_stay_in_argv_but_are_not_forwarded() {
    assert_eq!(
      planned(&["-p", "2222", "-l", "leaf", "dest"]),
      Plan {
        ssh_args: os(&["-o", PROXY, "-p", "2222", "-l", "leaf", "dest"]),
        ..Plan::default()
      }
    );
  }

  #[test]
  fn separator_bytes_and_empty_values_are_refused() {
    // The env encoding is injective only because these can never be
    // produced.
    assert!(plan("/opt/mush", &os(&["-i", "k\u{1f}ey", "dest"])).is_err());
    assert!(plan("/opt/mush", &os(&["-i", "", "dest"])).is_err());
    // Values of non-forwarded flags never reach the env encoding and
    // pass through untouched.
    assert_eq!(
      planned(&["-L", "80:\u{1f}:80", "dest"]),
      Plan {
        ssh_args: os(&["-o", PROXY, "-L", "80:\u{1f}:80", "dest"]),
        ..Plan::default()
      }
    );
  }

  #[test]
  fn jump_moves_to_the_bootstrap_side() {
    assert_eq!(
      planned(&["-J", "bastion", "dest"]),
      Plan {
        ssh_args: os(&["-o", PROXY, "dest"]),
        bootstrap_args: os(&["-J", "bastion"]),
        ..Plan::default()
      }
    );
  }

  #[test]
  fn jump_stripping_keeps_clustered_flags() {
    assert_eq!(
      planned(&["-vJbastion", "dest"]),
      Plan {
        ssh_args: os(&["-o", PROXY, "-v", "dest"]),
        bootstrap_args: os(&["-J", "bastion"]),
        ..Plan::default()
      }
    );
  }

  #[test]
  fn option_values_are_not_the_destination() {
    // -L's value must not be mistaken for the destination, and -L is
    // not in the forwarded set.
    assert_eq!(
      planned(&["-L", "8080:web:80", "dest"]),
      Plan {
        ssh_args: os(&["-o", PROXY, "-L", "8080:web:80", "dest"]),
        ..Plan::default()
      }
    );
  }

  #[test]
  fn double_dash_marks_the_destination() {
    assert_eq!(
      planned(&["--", "-odd-name"]),
      Plan {
        ssh_args: os(&["-o", PROXY, "--", "-odd-name"]),
        ..Plan::default()
      }
    );
  }

  #[test]
  fn arguments_after_the_destination_are_never_scanned() {
    // The wrapper forwards nothing from "-J after"; ssh still parses
    // it, and fails closed against the injected ProxyCommand.
    assert_eq!(
      planned(&["dest", "-J", "after"]),
      Plan {
        ssh_args: os(&["-o", PROXY, "dest", "-J", "after"]),
        ..Plan::default()
      }
    );
  }

  #[test]
  fn missing_destination_or_value_is_an_error() {
    assert!(plan("/opt/mush", &os(&[])).is_err());
    assert!(plan("/opt/mush", &os(&["-v"])).is_err());
    assert!(plan("/opt/mush", &os(&["--"])).is_err());
    assert!(plan("/opt/mush", &os(&["-p"])).is_err());
  }

  #[test]
  fn long_ssh_and_server_flags_are_extracted() {
    assert_eq!(
      planned(&[
        "--ssh=ssh -F cfg",
        "-v",
        "--server=/opt/mush sb",
        "--helper=/opt/mush jump-helper",
        "dest",
      ]),
      Plan {
        ssh_args: os(&["-o", PROXY, "-v", "dest"]),
        bootstrap_args: vec![],
        connect_ssh: Some("ssh -F cfg".into()),
        connect_server: Some("/opt/mush sb".into()),
        connect_helper: Some("/opt/mush jump-helper".into()),
      }
    );
  }

  #[test]
  fn long_flags_are_equals_form_only() {
    // A bare `--ssh` is not the wrapper's flag: it passes through (and
    // its would-be value is then the destination), leaving ssh's
    // unknown-option error authoritative.
    assert_eq!(
      planned(&["--ssh", "dest"]),
      Plan {
        ssh_args: os(&["-o", PROXY, "--ssh", "dest"]),
        ..Plan::default()
      }
    );
  }

  #[test]
  fn unknown_long_flags_pass_through_unscanned() {
    // Long options are never treated as flag clusters: `--ikey` must
    // not forward `-i key`, and `--ssh-foo=x` is not `--ssh=`.
    assert_eq!(
      planned(&["--foo=bar", "--ikey", "--ssh-foo=x", "dest"]),
      Plan {
        ssh_args: os(&[
          "-o",
          PROXY,
          "--foo=bar",
          "--ikey",
          "--ssh-foo=x",
          "dest"
        ]),
        ..Plan::default()
      }
    );
  }

  #[test]
  fn long_flags_after_the_destination_are_remote_command_text() {
    assert_eq!(
      planned(&["dest", "--server=evil"]),
      Plan {
        ssh_args: os(&["-o", PROXY, "dest", "--server=evil"]),
        ..Plan::default()
      }
    );
  }

  #[test]
  fn empty_or_duplicate_long_flags_are_refused() {
    assert!(plan("/opt/mush", &os(&["--ssh=", "dest"])).is_err());
    assert!(plan("/opt/mush", &os(&["--server=", "dest"])).is_err());
    assert!(plan("/opt/mush", &os(&["--ssh=a", "--ssh=b", "dest"])).is_err());
    assert!(
      plan("/opt/mush", &os(&["--server=a", "--server=b", "dest"])).is_err()
    );
  }

  #[test]
  fn user_proxy_command_override_is_refused() {
    // Every spelling ssh accepts, since an override would otherwise
    // lose silently to the injected ProxyCommand.
    for args in [
      &["-o", "ProxyCommand=none", "dest"][..],
      &["-oProxyCommand=none", "dest"],
      &["-o", "proxycommand other-proxy %h", "dest"],
      &["-o", " ProxyCommand=none", "dest"],
      &["-vo", "ProxyCommand=none", "dest"],
    ] {
      let error = plan("/opt/mush", &os(args)).unwrap_err();
      assert!(
        error.to_string().contains("ProxyCommand"),
        "for {args:?}: {error}"
      );
    }
    // Only the ProxyCommand keyword conflicts; other -o options (and
    // unknown keywords, where ssh's own error stays authoritative)
    // pass through.
    assert!(plan("/opt/mush", &os(&["-o", "BatchMode=yes", "dest"])).is_ok());
    assert!(plan("/opt/mush", &os(&["-o", "ProxyCommandX=1", "dest"])).is_ok());
    // Post-destination arguments are never scanned; ssh still parses
    // them, where the override loses to the injected ProxyCommand as
    // any post-destination option would.
    assert!(
      plan("/opt/mush", &os(&["dest", "-o", "ProxyCommand=none"])).is_ok()
    );
  }

  #[test]
  fn option_keyword_matching_follows_ssh_spelling() {
    assert!(option_sets_keyword(b"ProxyJump=bastion", b"proxyjump"));
    assert!(option_sets_keyword(b"proxyjump bastion", b"proxyjump"));
    assert!(option_sets_keyword(b" \tPROXYJUMP=bastion", b"proxyjump"));
    assert!(option_sets_keyword(b"ProxyJump", b"proxyjump"));
    assert!(!option_sets_keyword(b"ProxyJumpX=bastion", b"proxyjump"));
    assert!(!option_sets_keyword(b"ProxyCommand=none", b"proxyjump"));
    assert!(!option_sets_keyword(b"", b"proxyjump"));
  }

  #[test]
  fn shell_quote_wraps_and_escapes() {
    assert_eq!(shell_quote("/plain/path"), "'/plain/path'");
    assert_eq!(shell_quote("odd'path"), r"'odd'\''path'");
  }

  #[test]
  fn join_args_uses_the_unit_separator() {
    assert_eq!(join_args(&os(&["-p", "2222"])).as_bytes(), b"-p\x1f2222");
  }
}
