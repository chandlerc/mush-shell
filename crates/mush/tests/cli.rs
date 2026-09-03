// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! CLI-level dispatch tests through the real binary: a recording `ssh`
//! stub is the whole PATH and captures what the wrapper execs, so a real
//! ssh can never be picked up. Plan-level unit tests cannot cover any of
//! this, because the gap under test sits in front of them.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::{Command, Output};

use anyhow::{Context as _, Result, ensure};

const MUSH_BIN: &str = env!("CARGO_BIN_EXE_mush");

/// A stub `ssh` in its own directory recording its argv (one line per
/// argument) and the wrapper environment variables, then exiting cleanly.
struct SshStub {
  dir: tempfile::TempDir,
  argv_file: PathBuf,
  env_file: PathBuf,
}

impl SshStub {
  fn new() -> Result<Self> {
    let dir = tempfile::TempDir::with_prefix("mush-cli-stub-")?;
    let argv_file = dir.path().join("argv");
    let env_file = dir.path().join("env");
    let script = format!(
      "#!/bin/sh\n\
       printf '%s\\n' \"$@\" > {argv}\n\
       printf '%s\\n' \"${{MUSH_BOOTSTRAP_SSH_ARGS-UNSET}}\" \
       \"${{MUSH_CONNECT_SSH-UNSET}}\" \"${{MUSH_CONNECT_SERVER-UNSET}}\" \
       > {env}\n",
      argv = sq(&argv_file.display().to_string()),
      env = sq(&env_file.display().to_string()),
    );
    let ssh = dir.path().join("ssh");
    std::fs::write(&ssh, script)?;
    let mut permissions = std::fs::metadata(&ssh)?.permissions();
    use std::os::unix::fs::PermissionsExt as _;
    permissions.set_mode(0o755);
    std::fs::set_permissions(&ssh, permissions)?;
    Ok(Self {
      dir,
      argv_file,
      env_file,
    })
  }

  /// Runs `mush` with the stub directory as the whole `PATH`, sweeping
  /// all three wrapper variables before applying `envs`.
  fn run_mush<S: AsRef<OsStr>>(
    &self,
    args: &[S],
    envs: &[(&str, &str)],
  ) -> Result<Output> {
    let mut cmd = Command::new(MUSH_BIN);
    cmd
      .args(args)
      .env("PATH", self.dir.path())
      .env_remove("MUSH_BOOTSTRAP_SSH_ARGS")
      .env_remove("MUSH_CONNECT_SSH")
      .env_remove("MUSH_CONNECT_SERVER");
    for (key, value) in envs {
      cmd.env(key, value);
    }
    cmd.output().context("running mush")
  }

  /// The stub's recorded argv, one entry per line.
  fn recorded_argv(&self) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(&self.argv_file)
      .context("the ssh stub was never invoked")?;
    Ok(text.lines().map(str::to_string).collect())
  }

  /// The recorded `[MUSH_BOOTSTRAP_SSH_ARGS, MUSH_CONNECT_SSH,
  /// MUSH_CONNECT_SERVER]` values, `UNSET` where absent.
  fn recorded_env(&self) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(&self.env_file)
      .context("the ssh stub was never invoked")?;
    Ok(text.lines().map(str::to_string).collect())
  }
}

/// Single-quotes `word` for `/bin/sh`.
fn sq(word: &str) -> String {
  format!("'{}'", word.replace('\'', r"'\''"))
}

/// The `--` escape must reach the wrapper: clap would otherwise take a
/// leading `--` as its own end-of-options marker and fail with "no
/// destination" instead of passing the destination through to ssh.
#[test]
fn double_dash_escapes_a_dash_prefixed_destination() -> Result<()> {
  for dest in ["--server=evil", "-odd-hostname", "connect"] {
    let stub = SshStub::new()?;
    let out = stub.run_mush(&["--", dest], &[])?;
    ensure!(
      out.status.success(),
      "mush -- {dest} failed: {}",
      String::from_utf8_lossy(&out.stderr)
    );
    let argv = stub.recorded_argv()?;
    ensure!(
      argv.len() == 4
        && argv[0] == "-o"
        && argv[1].starts_with("ProxyCommand=")
        && argv[1].ends_with(" connect %r %h %p")
        && argv[2] == "--"
        && argv[3] == dest,
      "unexpected ssh argv for {dest}: {argv:?}"
    );
  }
  Ok(())
}

/// Reserved first words still dispatch through clap, and each
/// subcommand's own parsing is reachable through it.
#[test]
fn reserved_words_reach_clap() -> Result<()> {
  let stub = SshStub::new()?;

  let help = stub.run_mush(&["connect", "--help"], &[])?;
  ensure!(help.status.success(), "connect --help failed");
  ensure!(
    String::from_utf8_lossy(&help.stdout).contains("ProxyCommand mode"),
    "connect --help lost its about text"
  );

  let version = stub.run_mush(&["--version"], &[])?;
  ensure!(version.status.success(), "--version failed");

  let top = stub.run_mush(&["--help"], &[])?;
  ensure!(top.status.success(), "--help failed");
  ensure!(
    String::from_utf8_lossy(&top.stdout).contains("jump-helper"),
    "the top-level help must list every subcommand"
  );

  let helper = stub.run_mush(&["jump-helper", "--help"], &[])?;
  ensure!(helper.status.success(), "jump-helper --help failed");
  let text = String::from_utf8_lossy(&helper.stdout);
  ensure!(
    text.contains("--retain") && text.contains("--no-detach"),
    "jump-helper --help lost its lifecycle flags: {text}"
  );

  // With no control channel there is nothing to serve, which the helper
  // must say rather than sit waiting for.
  let orphan = stub.run_mush(&["jump-helper"], &[])?;
  ensure!(
    !orphan.status.success(),
    "jump-helper without a control channel cannot succeed"
  );
  ensure!(
    String::from_utf8_lossy(&orphan.stderr).contains("MUSH SERVE"),
    "jump-helper should name what it was waiting for: {}",
    String::from_utf8_lossy(&orphan.stderr)
  );
  Ok(())
}

/// The wrapper owns its environment channels: values it produced are
/// set, and stale inherited ones are cleared rather than reaching the
/// injected `mush connect` as if this invocation had produced them.
#[test]
fn wrapper_owns_its_environment_channels() -> Result<()> {
  let stale: &[(&str, &str)] = &[
    ("MUSH_BOOTSTRAP_SSH_ARGS", "-i\u{1f}/stale/key"),
    ("MUSH_CONNECT_SSH", "stale-ssh"),
    ("MUSH_CONNECT_SERVER", "stale-server"),
  ];

  // Nothing produced: every stale value is cleared.
  let stub = SshStub::new()?;
  let out = stub.run_mush(&["dest"], stale)?;
  ensure!(
    out.status.success(),
    "mush dest failed: {}",
    String::from_utf8_lossy(&out.stderr)
  );
  ensure!(
    stub.recorded_env()? == ["UNSET", "UNSET", "UNSET"],
    "stale wrapper environment leaked through: {:?}",
    stub.recorded_env()?
  );

  // Produced values overwrite the stale ones. `--server=` is here so all
  // three channels are exercised in one run: each is produced by a
  // different part of the plan.
  let stub = SshStub::new()?;
  let out = stub.run_mush(
    &[
      "-i",
      "key",
      "-J",
      "bastion",
      "--ssh=ssh -F cfg",
      "--server=/opt/mush server bootstrap",
      "dest",
    ],
    stale,
  )?;
  ensure!(
    out.status.success(),
    "mush -i key failed: {}",
    String::from_utf8_lossy(&out.stderr)
  );
  ensure!(
    stub.recorded_env()?
      == [
        "-i\u{1f}key\u{1f}-J\u{1f}bastion",
        "ssh -F cfg",
        "/opt/mush server bootstrap"
      ],
    "produced wrapper environment wrong: {:?}",
    stub.recorded_env()?
  );
  Ok(())
}

/// The argv the wrapper execs ssh with: the injected ProxyCommand
/// first, so it wins over any later occurrence, then everything the
/// wrapper does not claim, verbatim and in order. `-J` and the
/// wrapper's own long options leave for the bootstrap side instead.
#[test]
fn wrapper_injects_the_proxy_command_and_passes_the_rest_through() -> Result<()>
{
  let stub = SshStub::new()?;
  let out = stub.run_mush(
    &[
      "-4",
      "-p",
      "2222",
      "-i",
      "idfile",
      "-J",
      "bastion",
      "--ssh=ssh -F cfg",
      "--unknown-long",
      "dest.example",
      "remote-cmd",
    ],
    &[],
  )?;
  ensure!(
    out.status.success(),
    "wrapper failed: {}",
    String::from_utf8_lossy(&out.stderr)
  );
  let argv = stub.recorded_argv()?;
  ensure!(argv[0] == "-o", "argv did not open with -o: {argv:?}");
  ensure!(
    argv[1].starts_with("ProxyCommand=")
      && argv[1].ends_with(" connect %r %h %p"),
    "unexpected ProxyCommand: {}",
    argv[1]
  );
  ensure!(
    argv[2..]
      == [
        "-4",
        "-p",
        "2222",
        "-i",
        "idfile",
        // An unknown long flag reaches ssh for ssh to reject; the
        // wrapper's own never do.
        "--unknown-long",
        "dest.example",
        "remote-cmd",
      ],
    "unexpected passthrough argv: {argv:?}"
  );
  Ok(())
}

/// A user `-o ProxyCommand=...` cannot silently lose to the injected
/// one: the wrapper refuses it before any ssh runs.
#[test]
fn user_proxy_command_override_fails_loudly() -> Result<()> {
  let stub = SshStub::new()?;
  let out = stub.run_mush(&["-o", "ProxyCommand=none", "dest"], &[])?;
  ensure!(!out.status.success(), "the override must be refused");
  ensure!(
    String::from_utf8_lossy(&out.stderr).contains("ProxyCommand"),
    "the refusal should name the conflict: {}",
    String::from_utf8_lossy(&out.stderr)
  );
  ensure!(
    stub.recorded_argv().is_err(),
    "no ssh may run after the refusal"
  );
  Ok(())
}
