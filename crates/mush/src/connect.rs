// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! `mush connect`: ProxyCommand mode. Spawns the bootstrap ssh, drives
//! session establishment through it, then relays this process's stdio
//! (the outer ssh's transport bytes) over the tunnel; falls back to
//! plain TCP when QUIC is unreachable.

use std::ffi::{OsStr, OsString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd as _, RawFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::process::{ExitCode, Stdio};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use mush_core::bootstrap::{PROTOCOL_VERSION, SessionNonce, SessionSecret};
use mush_core::channel::{LineError, SignalChannel};
use mush_core::client::{
  ClientOptions, ClientSession, DEFAULT_ESTABLISH_TIMEOUT, EndpointSource,
  EstablishError, Traversal, allows_loopback,
};
use mush_core::helper::{
  Close, HelperChannel, HelperHop, HelperMessage, Serve,
};
use mush_core::path::{
  Arrival, ClientPlan, PathKind, PathReport, TRAVERSAL_ESTABLISH_TIMEOUT,
};
use mush_core::relay::{self, DirectionEnd, RelayOutcome};
use mush_core::roaming::{
  FreshSocket, ProbeOptions, Prober, RouteCheck, SocketFactory, os_route_check,
  os_route_check_to, os_socket_factory,
};
use mush_core::server::interface_ips;
use mush_core::transport::{self, TransportOptions};
use mush_core::traversal::{TraversalEndpoint, TraversalSocket};
use mush_core::upgrade::{UpgradeEvent, UpgradePolicy};
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};

use crate::stdio::take_stdio;
use crate::wrapper::{
  ARG_SEPARATOR, BOOTSTRAP_SSH_ARGS_ENV, CONNECT_HELPER_ENV,
  CONNECT_SERVER_ENV, CONNECT_SSH_ENV, WRAPPER_ENV, option_sets_keyword,
};

/// How long to wait for the bootstrap ssh to exit on its own before
/// killing it. The detaching server EOFs the channel right after the
/// connect line, so ssh normally exits within moments of
/// establishment.
const REAP_GRACE: Duration = Duration::from_secs(5);

/// How long the relay may keep draining once a hangup has fired and
/// the stdio channel has closed.
///
/// ssh SIGHUPs its ProxyCommand when it exits (OpenSSH's
/// `ssh_kill_proxy_command`), racing the relay of the final protocol
/// bytes ssh just wrote: dying on that signal leaves the disconnect
/// short of sshd, which then keeps its side of the session open, and
/// with it the server (retention is indefinite by default). Nor does
/// the signal prove the session is over: with ControlPersist the
/// initiating ssh exits (firing PDEATHSIG) while its backgrounded mux
/// master keeps the channel open with live sessions using it, for
/// hours if need be. So a hangup starts no countdown; the relay runs
/// until the channel's far side is gone (see [`stdio_hangup`]), and
/// only the drain after that -- a sub-RTT flush on a working path -- is
/// bounded here. A drain that overruns, the peer being unreachable
/// mid-teardown, is abandoned exactly as if the client had died.
const HUP_DRAIN_GRACE: Duration = Duration::from_secs(5);

/// How often, after a hangup, the stdio channel is polled for closure.
/// The poll exists because the relay cannot always observe the close
/// itself: stalled on QUIC backpressure it has no local read pending,
/// and an EOF would go unseen until the peer drains the window.
const HUP_POLL: Duration = Duration::from_millis(200);

/// How long the signaling phase may linger once the session's path is
/// established. It runs off the relay's critical path (see
/// [`SignalChannel::settle`]), so this bounds only how long the
/// bootstrap channel is held open past establishment.
const SIGNAL_SETTLE_GRACE: Duration = Duration::from_secs(5);

/// Bound on the jump helper's opening conversation: its ssh
/// authenticating and the `MUSH READY` line coming back. Started
/// alongside the bootstrap ssh, it has the whole bootstrap
/// conversation to answer in, so this only ever catches a bastion that
/// hangs. Establishment does not wait this long regardless (see
/// [`mush_core::path::HELPER_WAIT`]); a late answer still widens the
/// set of paths establishment tries if it arrives before the paths
/// settle.
const HELPER_READY_GRACE: Duration = Duration::from_secs(60);

/// Bound on the plain shell probe that recovers this client's public
/// address from the jump, which runs only when the helper's own ready
/// line did not already carry it.
const JUMP_PROBE_GRACE: Duration = Duration::from_secs(20);

/// Bound on waiting for the helper's ssh to finish once the client is
/// done with it; see [`Helper::shut_down`].
const HELPER_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Environment variable naming a file the client writes one line to
/// once a path is settled:
/// `path=<kind> addr=<addr> helper=<addr|-> reflexive=<addr|-> punched=<bool>`.
///
/// The test hook for establishment. The kind of path is in the log too
/// (`path established`), but a file the test owns lets it assert which
/// kind of path carried a session without parsing a stream that also
/// carries ssh's diagnostics.
pub const PATH_REPORT_ENV: &str = "MUSH_PATH_REPORT";

/// The `mush connect` arguments.
///
/// Declaration order is the CLI's: the three positionals must stay last
/// and in this order, since they are ssh's `%r %h %p`.
#[derive(clap::Args)]
pub struct Options {
  /// Jump host(s) for the bootstrap ssh, as `ssh -J` specs. ssh forbids
  /// ProxyJump alongside ProxyCommand, so jumped hosts configure the jump
  /// here instead.
  #[arg(short = 'J', value_name = "jump-spec")]
  jump: Option<String>,

  /// The command that runs the bootstrap ssh: a program plus leading
  /// arguments, split on whitespace (Mosh's convention). Lets pure
  /// ProxyCommand mode pass auth flags: --ssh 'ssh -i key'. Defaulted
  /// by the wrapper's --ssh=; an explicit flag wins.
  #[arg(
    long,
    value_name = "command",
    default_value = "ssh",
    env = CONNECT_SSH_ENV
  )]
  ssh: String,

  /// The remote command that starts the server (Mosh's convention), for
  /// hosts where `mush` is not on the non-interactive PATH. Defaulted by
  /// the wrapper's --server=; an explicit flag wins.
  #[arg(
    long,
    value_name = "command",
    default_value = "mush server bootstrap",
    env = CONNECT_SERVER_ENV
  )]
  server: String,

  /// The command that starts the traversal helper on the jump host, for
  /// bastions where `mush` is not on the non-interactive PATH. Only ever
  /// run with -J. Defaulted by the wrapper's --helper=; an explicit flag
  /// wins.
  #[arg(
    long,
    value_name = "command",
    default_value = "mush jump-helper",
    env = CONNECT_HELPER_ENV
  )]
  helper: String,

  /// STUN server for discovering this client's public address when a
  /// jumped session has no helper to reflect off (`host` or
  /// `host:port`, default port 3478); ignored without -J, where
  /// nothing punches. Default off: Mush contacts no third-party
  /// service unless asked to.
  #[arg(long, value_name = "server")]
  stun: Option<String>,

  /// Fail hard when QUIC cannot be established instead of falling back
  /// to a plain TCP connection.
  #[arg(long)]
  no_fallback: bool,

  /// Abandon the session once the peer has been silent this long
  /// (e.g. "30m", "12h"). Default: no limit -- sessions freeze during
  /// outages and resume, which is the intended behavior. A dead server is
  /// indistinguishable from an outage, so only this limit (or ssh's
  /// own ServerAliveInterval) bounds the hang a dead server causes.
  #[arg(long, value_name = "duration", value_parser = crate::parse_duration)]
  idle_timeout: Option<Duration>,

  /// Remote user (ssh's %r).
  user: String,
  /// Destination host (ssh's %h).
  host: String,
  /// Destination ssh port (ssh's %p).
  port: u16,
}

/// Runs `mush connect`.
pub fn run(options: Options) -> Result<ExitCode> {
  // The outer ssh's parting SIGHUP (see HUP_DRAIN_GRACE) is skipped by
  // death by signal -- SIGKILL, a crash, the OOM killer -- and the
  // orphaned relay would then hold the QUIC endpoint and PTO against a
  // possibly-dead peer forever once nothing holds the stdio channel.
  // PDEATHSIG turns the parent's death itself into the hangup: fatal
  // before establishment (SIGHUP's default disposition); after it the
  // relay serves for as long as the channel stays open (a ControlPersist
  // mux master outlives the initiating ssh) and a bounded drain follows
  // the channel's closure. Cannot fail with a valid signal.
  #[cfg(target_os = "linux")]
  let _ = rustix::process::set_parent_process_death_signal(Some(
    rustix::process::Signal::HUP,
  ));
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .context("building the tokio runtime")?;
  runtime.block_on(run_async(options))
}

async fn run_async(options: Options) -> Result<ExitCode> {
  let forwarded_args = forwarded_env_args()?;
  // The wrapper strips `-J` from the outer argv and forwards it only
  // through the environment, so in wrapper mode the jump arrives in
  // the forwarded arguments, never in `options.jump`; every jump-aware
  // decision (the bootstrap argv shape, the traversal machinery, the
  // fallback's shape) must treat both sources alike. A ProxyJump in the
  // bootstrap ssh's config file remains invisible to both.
  let jump = options
    .jump
    .clone()
    .or_else(|| forwarded_jump(&forwarded_args));
  let argv = bootstrap_ssh_argv(&options, forwarded_args.clone())?;
  tracing::debug!(?argv, "spawning bootstrap ssh");
  let mut child = spawn_ssh_child(&argv)
    .with_context(|| format!("spawning bootstrap ssh {:?}", argv[0]))?;
  let channel = tokio::io::join(
    child.stdout.take().expect("bootstrap stdout is piped"),
    child.stdin.take().expect("bootstrap stdin is piped"),
  );

  let resolved_ips = resolve_ips(&options.host, options.port).await;
  // Traversal exists to reach a destination behind a jump (design doc,
  // "Jump hosts and NAT traversal"), so only a jumped session generates
  // a nonce, asks the destination to hold the bootstrap channel open
  // past the connect line, and runs the staged dials. Without a jump
  // there is nothing to exchange, and the hello, the detach, the
  // channel's lifetime, and the dial are exactly what they were.
  let mut helper = None;
  let mut probe_socket: Option<std::sync::Arc<TraversalSocket>> = None;
  let (endpoint, traversal, session_nonce, establish_timeout) = match &jump {
    None => (
      EndpointSource::Bind(bind_addr(&resolved_ips)),
      None,
      None,
      DEFAULT_ESTABLISH_TIMEOUT,
    ),
    Some(spec) => {
      let nonce = SessionNonce::generate().context("generating the nonce")?;
      let secret =
        SessionSecret::generate().context("generating the session secret")?;
      let paths = TraversalEndpoint::bind(bind_addr(&resolved_ips))
        .context("binding the session's UDP socket")?;
      let port = paths
        .socket
        .local_addr()
        .context("reading the session's local port")?
        .port();
      let (arrivals_tx, arrivals) = mpsc::channel(4);
      helper = start_helper(
        &options,
        spec,
        &forwarded_args,
        nonce,
        secret,
        port,
        arrivals_tx,
      );
      let local_ips = interface_ips();
      // Kept for the prober: a session that ends up on the relayed path
      // may only ping from this very socket, since the helper forwards
      // to the address it registered.
      probe_socket = Some(paths.socket.clone());
      let traversal = Traversal {
        socket: paths.socket,
        secret,
        probes: paths.probes,
        arrivals: Some(arrivals),
        plan: ClientPlan {
          self_addrs: local_ips
            .iter()
            .map(|&ip| SocketAddr::new(ip, port))
            .collect(),
          local_ips,
          stun_servers: stun_servers(options.stun.as_deref()).await,
          helper_expected: helper.is_some(),
          // The same rule the connect line's hints are judged by:
          // loopback names this host, so it can only name the
          // destination when the destination is this host. On the
          // jumped arm a name that does not resolve locally is
          // ordinary rather than evidence.
          allow_loopback: allows_loopback(&resolved_ips, true),
        },
        upgrade: UpgradePolicy::default(),
      };
      (
        EndpointSource::Endpoint(paths.endpoint),
        Some(traversal),
        Some(nonce),
        TRAVERSAL_ESTABLISH_TIMEOUT,
      )
    }
  };
  let client_options = ClientOptions {
    endpoint,
    target_port: options.port,
    resolved_ips,
    transport: TransportOptions {
      max_idle_timeout: options.idle_timeout,
      ..TransportOptions::default()
    },
    session_nonce,
    traversal,
    establish_timeout,
    ..ClientOptions::default()
  };
  let session = match ClientSession::establish(channel, client_options).await {
    Ok(session) => session,
    // The two outcomes of establishment that mean no UDP path exists:
    // none answered within the budget, or the candidate set showed none
    // could. Both fall to the last kind of path, the fallback.
    Err(
      error @ (EstablishError::QuicUnreachable { .. }
      | EstablishError::UdpFutile { .. }),
    ) => {
      reap(&mut child).await;
      if let Some(helper) = helper {
        helper.shut_down().await;
      }
      if options.no_fallback {
        bail!("QUIC unreachable and --no-fallback given: {error}");
      }
      report_path(PathKind::Fallback, None, None);
      eprintln!("mush: WARNING: {error}");
      eprintln!(
        "mush: WARNING: falling back to plain TCP to {}:{}; this session \
         has no roaming or resilience",
        options.host, options.port
      );
      return match &jump {
        Some(spec) => tcp_fallback_via_jump(&options, spec, &forwarded_args)
          .await
          .context("TCP fallback through the jump"),
        None => tcp_fallback(&options).await,
      };
    }
    // Every other failure is fatal -- in particular a pin rejection,
    // which proves a live endpoint without the pinned key and must
    // never degrade to TCP (see EstablishError::PinRejected).
    Err(error) => {
      let status = reap(&mut child).await;
      if let Some(helper) = helper {
        helper.shut_down().await;
      }
      let detail = exit_detail(status, "bootstrap ssh");
      bail!("session establishment failed: {error}{detail}");
    }
  };
  let ClientSession {
    endpoint,
    connection,
    send,
    recv,
    chosen_addr,
    path_kind,
    paths,
    upgrade,
    bootstrap,
    bootstrap_leftover,
    ..
  } = session;
  tracing::info!(%chosen_addr, %path_kind, ?paths, "path established");
  report_path(path_kind, Some(chosen_addr), paths.as_ref());
  // Kept for the reports a later path switch writes; the phase itself
  // hands the channel away below.
  let report = paths.clone();
  if reflection_lost(paths.as_ref()) {
    warn_traversal_lost(
      "the jump helper answered on ssh but nothing reached its UDP port",
    );
  }
  match (session_nonce, paths) {
    // The path is settled, so all the signaling phase has left to do is
    // say so and let the channel go. Off the relay's critical path:
    // nothing about starting the session waits on it, and dropping the
    // channel is what closes the ssh child's pipes.
    (Some(nonce), Some(paths)) => {
      let channel = SignalChannel::new(bootstrap, bootstrap_leftover);
      tokio::spawn(channel.settle(nonce, paths.peer_done, SIGNAL_SETTLE_GRACE));
    }
    _ => drop(bootstrap),
  }
  // A helper is needed past establishment only when the relay is the
  // path. Otherwise it is told at once that the session is over, which
  // is what makes it exit instead of lingering out its retention window
  // on a bastion. A relayed session keeps it until its own path policy
  // says the session no longer needs the relay (see mush_core::upgrade).
  let mut helper = match (helper, path_kind) {
    (Some(helper), PathKind::Relayed) => Some(helper),
    (Some(helper), _) => {
      helper.shut_down().await;
      None
    }
    (None, _) => None,
  };

  // The design's relay-to-direct upgrade: a session the relay carried
  // keeps probing for a direct path, moves onto one that proves itself,
  // and hands the session back to the relay if it fails. It also keeps
  // the relay's registration current, which is what carries a relayed
  // session through a rebind.
  let (moves, mut moved) = mpsc::channel(8);
  let upgrading =
    upgrade.map(|upgrade| tokio::spawn(upgrade.run(connection.clone(), moves)));
  let mut watching_moves = upgrading.is_some();

  // Active path recovery for the whole relay phase: the stall prober
  // (with its netlink wake where the platform has one) forces
  // ack-eliciting exchanges and socket rebinds when the connection
  // stalls, and does nothing while traffic flows. See
  // mush_core::roaming.
  let prober = tokio::spawn(
    Prober {
      connection: connection.clone(),
      endpoint: endpoint.clone(),
      fresh_socket: match &probe_socket {
        Some(socket) => rebinding_sockets(socket, &connection),
        None => os_socket_factory(&connection),
      },
      route_check: match &probe_socket {
        Some(socket) => path_route_check(socket, &connection),
        None => os_route_check(&connection),
      },
      events: path_events(),
      options: ProbeOptions::default(),
      // The socket the session already runs on, so a ping has
      // something to aim at before any rebind has happened.
      session_socket: probe_socket.map(|socket| {
        socket as std::sync::Arc<dyn mush_core::traversal::Handable>
      }),
      stats: std::sync::Arc::default(),
    }
    .run(),
  );

  let (stdin, stdout) =
    take_stdio().context("taking ownership of stdio for the relay")?;
  // Polled for channel closure after a hangup; the relay future owns
  // the handle behind it until dropped at return, so the fd outlives
  // every poll below.
  let stdio_fd = stdin.as_raw_fd();
  // Installing the handler replaces SIGHUP's kill disposition for the
  // rest of the process; see HUP_DRAIN_GRACE. Deliberately not
  // installed earlier: on the establishment and TCP-fallback paths the
  // kill disposition stays correct (TCP teardown survives process
  // death; a QUIC teardown does not).
  let mut hangup =
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
      .context("installing the SIGHUP handler")?;
  // Relay while reaping the bootstrap child as it exits, so a
  // long-lived session is not accompanied by a zombie ssh.
  let relay_fut = relay::relay_split(stdin, stdout, send, recv);
  tokio::pin!(relay_fut);
  let mut child_done = false;
  let outcome = 'relay: loop {
    tokio::select! {
      outcome = &mut relay_fut => break Some(outcome),
      _ = child.wait(), if !child_done => child_done = true,
      moved = moved.recv(), if watching_moves => match moved {
        // The move itself is logged where it is decided
        // (mush_core::upgrade); what is owed here is the report file,
        // which is the test hook for establishment and whose answer can
        // now change.
        Some(UpgradeEvent::Moved { addr, path_kind }) => {
          report_path(path_kind, Some(addr), report.as_ref());
        }
        // The relay is no longer a path this session may need, so the
        // bastion gets its process and its UDP port back. Shutting it
        // down is bounded but not instant, and nothing about the
        // session waits on it.
        Some(UpgradeEvent::HelperReleased) => {
          if let Some(helper) = helper.take() {
            tokio::spawn(helper.shut_down());
          }
        }
        None => watching_moves = false,
      },
      _ = hangup.recv() => {
        // The hangup proves the initiating ssh is gone, not the session
        // (see HUP_DRAIN_GRACE), so relay on until the channel closes
        // and bound only the drain that remains.
        let mut ticks = tokio::time::interval(HUP_POLL);
        while !stdio_hangup(stdio_fd) {
          tokio::select! {
            outcome = &mut relay_fut => break 'relay Some(outcome),
            _ = child.wait(), if !child_done => child_done = true,
            _ = ticks.tick() => {}
          }
        }
        // A drain that does not finish is the session abandoned: the
        // teardown below tells the peer so rather than `session over`.
        match tokio::time::timeout(HUP_DRAIN_GRACE, &mut relay_fut).await {
          Ok(outcome) => break Some(outcome),
          Err(_) => break None,
        }
      }
    }
  };
  // One teardown, whichever way the relay ended. The close leads
  // because it is the only part of this the peer is waiting on;
  // everything after it is local cleanup, and each step is separately
  // bounded so a peer or a child that has already gone cannot hold the
  // exit.
  let (code, reason): (u32, &[u8]) = match &outcome {
    Some(outcome) => (u32::from(!outcome.is_clean()), b"session over"),
    None => (1, b"client hangup"),
  };
  prober.abort();
  if let Some(upgrading) = &upgrading {
    upgrading.abort();
  }
  transport::close_and_flush(&endpoint, &connection, code.into(), reason).await;
  if !child_done {
    reap(&mut child).await;
  }
  // The relay this helper was holding open is finished with, which is
  // the design's clean end of a helper's life.
  if let Some(helper) = helper {
    helper.shut_down().await;
  }
  // An abandoned drain has no outcome to report, only a failure.
  let Some(outcome) = outcome else {
    return Ok(ExitCode::FAILURE);
  };
  if outcome.is_clean() {
    Ok(ExitCode::SUCCESS)
  } else {
    eprintln!("mush: session ended uncleanly: {outcome:?}");
    if let Some(detail) = unclean_detail(&outcome) {
      eprintln!("mush: {detail}");
    }
    Ok(ExitCode::FAILURE)
  }
}

/// A human-actionable line for the common unclean endings: the peer's
/// close reason verbatim (the detached server's stderr is /dev/null, so
/// its close reason is the only diagnostic that can reach the user), or
/// the idle-timeout explanation for a timed-out connection.
fn unclean_detail(outcome: &RelayOutcome) -> Option<String> {
  let lost = [&outcome.to_peer.end, &outcome.from_peer.end]
    .into_iter()
    .find_map(|end| match end {
      DirectionEnd::ConnectionLost(error) => Some(error),
      _ => None,
    })?;
  match lost {
    quinn::ConnectionError::ApplicationClosed(close)
      if !close.reason.is_empty() =>
    {
      Some(format!(
        "the server closed the session: {}",
        String::from_utf8_lossy(&close.reason)
      ))
    }
    quinn::ConnectionError::TimedOut => Some(
      "the connection's idle timeout elapsed: the peer died, or an \
       outage outlasted the limit (--idle-timeout here, --retain on \
       the server)"
        .into(),
    ),
    _ => None,
  }
}

/// The jump helper's ssh channel, held for as long as the helper is
/// wanted.
///
/// The design's helper lifetime "mirrors the destination server's":
/// control arrives over its ssh channel, it detaches once it is
/// serving, and it exits on a clean session end. Only the client can
/// say when that is, so the channel lives exactly as long as the
/// helper's work does -- released the moment a path that does not need
/// it wins, held for the session when the relay is the path.
struct Helper {
  close: oneshot::Sender<()>,
  task: tokio::task::JoinHandle<()>,
}

impl Helper {
  /// Tells the helper its session is over and waits for its ssh to
  /// finish.
  ///
  /// Bounded, because this sits on the critical path of a session that
  /// is already up: a jumped session that won on the direct path shuts
  /// the helper down before it starts relaying, and a bastion that
  /// stopped answering must not hold that up. Abandoning the task kills
  /// its ssh; the helper on the far side then self-destructs on its own
  /// timeout.
  async fn shut_down(self) {
    let Self { close, task } = self;
    let _ = close.send(());
    let abort = task.abort_handle();
    if tokio::time::timeout(HELPER_SHUTDOWN_GRACE, task)
      .await
      .is_err()
    {
      tracing::debug!(
        grace = ?HELPER_SHUTDOWN_GRACE,
        "the jump helper's ssh did not finish; abandoning it"
      );
      abort.abort();
    }
  }
}

/// Runs `future` unless the client finishes with the helper first.
///
/// Every step of the helper's conversation that can outlive the
/// session's need for it waits this way: the opening, and the shell
/// probe behind it. The close signal says the session no longer needs
/// this helper, and a step that ignored it would hold up a session that
/// is already running (see [`Helper::shut_down`]).
async fn until_close<T>(
  close: &mut oneshot::Receiver<()>,
  future: impl Future<Output = T>,
) -> Option<T> {
  tokio::select! {
    biased;
    _ = &mut *close => None,
    value = future => Some(value),
  }
}

/// Starts `mush jump-helper` on the jump host over a second ssh exec
/// channel, and drives its control channel for as long as it is wanted.
///
/// Returns `None` only when the jump spec is one ssh itself would refuse.
/// Every other failure -- the binary missing, exec restricted, a bastion
/// that never answers -- surfaces as the empty helper arrival, which is
/// what leaves establishment only the kinds of path that need no helper.
fn start_helper(
  options: &Options,
  jump: &str,
  env_args: &[OsString],
  nonce: SessionNonce,
  secret: SessionSecret,
  local_port: u16,
  arrivals: mpsc::Sender<Arrival>,
) -> Option<Helper> {
  let hop = HelperHop::from_jump_spec(jump)?;
  let argv = helper_ssh_argv(options, hop, env_args);
  let probe = jump_probe_argv(options, jump, env_args);
  let (close_tx, close) = oneshot::channel();
  let task = tokio::spawn(run_helper(
    argv,
    probe,
    HelperSession {
      nonce,
      secret,
      local_port,
      // The helper runs on the last hop of a chain, which sees the hop
      // in front of it rather than this client; only a single-hop jump
      // observes the client itself (see `observed`).
      helper_observes_client: hop.via.is_none(),
    },
    arrivals,
    close,
  ));
  Some(Helper {
    close: close_tx,
    task,
  })
}

/// What the helper's conversation needs to know about the session it is
/// being started for.
#[derive(Debug, Clone, Copy)]
struct HelperSession {
  nonce: SessionNonce,
  secret: SessionSecret,
  /// The port the session's own socket holds, which is what completes
  /// the jump's view of this client into an address to punch at.
  local_port: u16,
  /// Whether the helper's own hop is the one that observes this client.
  helper_observes_client: bool,
}

/// The helper's whole conversation: start it, learn where it is, report
/// what it says, and end it when the client is finished with it.
async fn run_helper(
  argv: Vec<OsString>,
  probe: Vec<OsString>,
  session: HelperSession,
  arrivals: mpsc::Sender<Arrival>,
  mut close: oneshot::Receiver<()>,
) {
  tracing::debug!(?argv, "spawning the jump helper");
  let mut child = match spawn_ssh_child(&argv) {
    Ok(child) => child,
    Err(error) => {
      degraded(&mut close, &arrivals, &probe, session, &error.to_string())
        .await;
      return;
    }
  };
  let channel = tokio::io::join(
    child.stdout.take().expect("helper stdout is piped"),
    child.stdin.take().expect("helper stdin is piped"),
  );
  let mut channel = HelperChannel::new(channel, Vec::new());
  let serve = HelperMessage::Serve(Serve {
    version: PROTOCOL_VERSION,
    nonce: session.nonce,
    secret: session.secret,
  });
  let opening = until_close(
    &mut close,
    tokio::time::timeout(HELPER_READY_GRACE, async {
      channel.send(&serve).await?;
      loop {
        match channel.recv().await? {
          Some(HelperMessage::Ready(ready)) => return Ok(ready),
          Some(message) => tracing::debug!(%message, "unexpected helper line"),
          None => {
            return Err(LineError::Io(std::io::Error::new(
              std::io::ErrorKind::UnexpectedEof,
              "the helper channel closed before its ready line",
            )));
          }
        }
      }
    }),
  )
  .await;
  let Some(opening) = opening else {
    // The session settled without this helper. Nothing has registered
    // with it yet, so it self-destructs on its own bootstrap timeout.
    tracing::debug!("finished with the jump helper before it answered");
    let _ = child.start_kill();
    reap(&mut child).await;
    return;
  };
  let ready = match opening {
    Ok(Ok(ready)) if !ready.addr_hints.is_empty() => ready,
    Ok(Ok(_)) => {
      degraded(
        &mut close,
        &arrivals,
        &probe,
        session,
        "the helper named no address to reach it at",
      )
      .await;
      reap(&mut child).await;
      return;
    }
    Ok(Err(error)) => {
      let status = reap(&mut child).await;
      let detail = format!("{error}{}", exit_detail(status, "its ssh"));
      degraded(&mut close, &arrivals, &probe, session, &detail).await;
      return;
    }
    Err(_) => {
      let _ = child.start_kill();
      degraded(
        &mut close,
        &arrivals,
        &probe,
        session,
        &format!("no ready line within {HELPER_READY_GRACE:?}"),
      )
      .await;
      return;
    }
  };
  tracing::debug!(?ready, "jump helper serving");
  // A receiver already gone means establishment finished without this
  // helper; the loop below still waits for the close that ends it.
  let _ = arrivals
    .send(Arrival::Helper(ready.addr_hints.clone()))
    .await;
  observed(&mut close, &arrivals, &probe, session, ready.client_ip).await;

  // Peer reports are the rendezvous fact the helper owes the client:
  // the other side arrived, and from where. Establishment reaches the
  // same conclusion from the destination's own signaling, so these serve
  // the log and the roaming updates that follow.
  loop {
    tokio::select! {
      biased;
      _ = &mut close => break,
      message = channel.recv() => match message {
        Ok(Some(HelperMessage::Peer(peer))) => {
          tracing::debug!(role = %peer.role, addr = %peer.addr, "peer registered");
        }
        Ok(Some(message)) => tracing::debug!(%message, "helper line"),
        Ok(None) => break,
        Err(error) => {
          tracing::debug!(%error, "helper channel ended");
          break;
        }
      },
    }
  }
  let closed = HelperMessage::Close(Close {
    nonce: session.nonce,
  });
  if let Err(error) = channel.send(&closed).await {
    tracing::debug!(%error, "the helper was not told the session ended");
  }
  drop(channel);
  reap(&mut child).await;
}

/// The one line that says what a session loses when the helper's UDP
/// is out of reach. `reason` names how it happened; the rest is the
/// same either way, because what is lost is the same either way.
fn warn_traversal_lost(reason: &str) {
  eprintln!(
    "mush: WARNING: {reason}; NAT traversal loses reflexive candidates \
     and the relay of last resort, leaving direct dialing, the reverse \
     punch, and the TCP fallback"
  );
}

/// The trailing clause naming how a side ssh died, empty when it exited
/// cleanly or was never reaped: a failed side channel usually explains
/// the failure being reported, and a clean one adds nothing.
fn exit_detail(status: Option<std::process::ExitStatus>, what: &str) -> String {
  match status {
    Some(status) if !status.success() => {
      format!(" ({what} exited with {status})")
    }
    _ => String::new(),
  }
}

/// Announces that there is no helper, says on stderr what that costs,
/// and falls to the one thing left that can name this client to the
/// destination: the jump's own view of it.
async fn degraded(
  close: &mut oneshot::Receiver<()>,
  arrivals: &mpsc::Sender<Arrival>,
  probe: &[OsString],
  session: HelperSession,
  reason: &str,
) {
  warn_traversal_lost(&format!("no jump helper ({reason})"));
  if arrivals.send(Arrival::Helper(Vec::new())).await.is_err() {
    return;
  }
  observed(close, arrivals, probe, session, None).await;
}

/// Names this client to the destination by the jump's own view of it,
/// which is the design's `echo $SSH_CONNECTION` step.
///
/// The reverse punch needs an address the destination can aim at, and
/// under the port-preserving 1:1 NAT typical of cloud VMs the port this
/// session already holds completes it. A helper that answered already
/// reported the address in its ready line (`MUSH READY`), with no extra
/// probe, which is what makes a helper whose UDP is unreachable degrade
/// no worse than a bastion with no helper on it. Only a chained jump
/// has to ask: the helper's hop sees the hop in front of it, never the
/// client, so the plain shell probe runs against the first hop instead.
async fn observed(
  close: &mut oneshot::Receiver<()>,
  arrivals: &mpsc::Sender<Arrival>,
  probe: &[OsString],
  session: HelperSession,
  reported: Option<IpAddr>,
) {
  let observed = match observed_by_the_helper(session, reported) {
    Some(observed) => Some(observed),
    None => until_close(close, jump_observed_ip(probe))
      .await
      .flatten()
      .map(|ip| SocketAddr::new(ip, session.local_port)),
  };
  let Some(observed) = observed else {
    return;
  };
  tracing::debug!(%observed, "the jump observed this client");
  let _ = arrivals.send(Arrival::Observed(observed)).await;
}

/// This client as the helper's ready line reported it, when that hop is
/// the one that observes the client. `None` leaves it to the shell
/// probe, which asks the hop that does.
fn observed_by_the_helper(
  session: HelperSession,
  reported: Option<IpAddr>,
) -> Option<SocketAddr> {
  let ip = reported.filter(|_| session.helper_observes_client)?;
  Some(SocketAddr::new(ip, session.local_port))
}

/// Runs `echo $SSH_CONNECTION` on the jump and returns the client
/// address it reports.
async fn jump_observed_ip(argv: &[OsString]) -> Option<IpAddr> {
  if argv.is_empty() {
    return None;
  }
  tracing::debug!(?argv, "asking the jump how it sees this client");
  // Alone among the ssh children this one inherits no stderr: it cannot
  // prompt (BatchMode is set), so ssh's refusal on a bastion that would
  // have prompted is unwanted output about a step that degrades
  // silently.
  let child = ssh_command(argv)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
    .ok()?;
  let output =
    tokio::time::timeout(JUMP_PROBE_GRACE, child.wait_with_output()).await;
  let output = match output {
    Ok(Ok(output)) if output.status.success() => output,
    _ => return None,
  };
  // "client_ip client_port server_ip server_port", the same shape the
  // destination's own hint is read from.
  String::from_utf8_lossy(&output.stdout)
    .split_whitespace()
    .next()?
    .parse()
    .ok()
}

/// One ssh child of this process, with the hygiene every one of them
/// shares; the caller chooses the stdio.
///
/// The wrapper's variables are consumed by this process -- the forwarded
/// flags into argv, the `--ssh`/`--server`/`--helper` overrides into its
/// options -- and must not travel further: a nested `mush connect` under
/// one of these (a jump hop whose host also resolves through a Mush
/// ProxyCommand) would apply values meant for this destination to a
/// different host, recursing without bound in the worst case.
///
/// `kill_on_drop` only runs when this process unwinds. Death by signal
/// (the outer ssh's SIGHUP before establishment, a crash, SIGKILL)
/// skips Drop and would orphan an ssh holding its remote command alive
/// with no owner; PDEATHSIG covers exactly that path.
fn ssh_command(argv: &[OsString]) -> Command {
  let mut command = Command::new(&argv[0]);
  command.args(&argv[1..]).kill_on_drop(true);
  for name in WRAPPER_ENV {
    command.env_remove(name);
  }
  #[cfg(target_os = "linux")]
  unsafe {
    command.pre_exec(|| {
      rustix::process::set_parent_process_death_signal(Some(
        rustix::process::Signal::KILL,
      ))?;
      Ok(())
    });
  }
  command
}

/// Spawns one ssh that talks Mush over its stdio: the bootstrap
/// channel, the helper's channel, and the fallback bridge.
fn spawn_ssh_child(argv: &[OsString]) -> std::io::Result<Child> {
  ssh_command(argv)
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    // Interactive auth (password, 2FA) prompts pass through to our
    // stderr and tty.
    .stderr(Stdio::inherit())
    .spawn()
}

/// Whether a helper answered on ssh and then could not be reached over
/// UDP, costing the session reflection and the relay, as a bastion with
/// no helper on it does (the design's "A helper that is present but whose
/// UDP cannot be reached from one side degrades identically").
///
/// Reflection failing is the evidence; the punch having been ordered
/// says reflection had its whole budget, since establishment holds the
/// punch back for exactly that long once a helper names itself.
fn reflection_lost(paths: Option<&PathReport>) -> bool {
  paths.is_some_and(|paths| {
    paths.helper_offered && paths.punched && paths.reflexive.is_none()
  })
}

/// Writes the outcome of establishment where a test can read it; see
/// [`PATH_REPORT_ENV`].
///
/// Rewritten on every path switch, so what the file says is where the
/// session is rather than where it started. Through a rename, because a
/// reader polling for an upgrade would otherwise be able to read the
/// file between the truncation and the write.
fn report_path(
  path_kind: PathKind,
  addr: Option<SocketAddr>,
  paths: Option<&PathReport>,
) {
  let Some(file) = std::env::var_os(PATH_REPORT_ENV) else {
    return;
  };
  let shown = |addr: Option<SocketAddr>| match addr {
    Some(addr) => addr.to_string(),
    None => "-".to_string(),
  };
  let line = format!(
    "path={path_kind} addr={} helper={} reflexive={} punched={}\n",
    shown(addr),
    shown(paths.and_then(|paths| paths.helper)),
    shown(paths.and_then(|paths| paths.reflexive)),
    paths.is_some_and(|paths| paths.punched),
  );
  let mut staged = file.clone();
  staged.push(".new");
  let written = std::fs::write(&staged, line)
    .and_then(|()| std::fs::rename(&staged, &file));
  if let Err(error) = written {
    tracing::debug!(?file, %error, "the path report was not written");
  }
}

/// The design's fallback when UDP is blocked: a plain TCP connection
/// to the destination's ssh port, spliced to stdio. The session works
/// exactly like ordinary ssh, with none of Mush's resilience; the
/// orphaned server self-destructs on its bootstrap timeout. Dials
/// directly, so only a session with no jump takes it; a jumped one
/// takes [`tcp_fallback_via_jump`], the same kind of path reached the
/// way the jump requires.
async fn tcp_fallback(options: &Options) -> Result<ExitCode> {
  let mut tcp = TcpStream::connect((options.host.as_str(), options.port))
    .await
    .with_context(|| {
      format!("TCP fallback to {}:{}", options.host, options.port)
    })?;
  tcp.set_nodelay(true)?;
  let (stdin, stdout) =
    take_stdio().context("taking ownership of stdio for the relay")?;
  let mut local = tokio::io::join(stdin, stdout);
  // copy_bidirectional propagates each side's EOF as a shutdown of the
  // other, which the stdio wrapper turns into a real close.
  tokio::io::copy_bidirectional(&mut local, &mut tcp)
    .await
    .context("TCP fallback relay")?;
  Ok(ExitCode::SUCCESS)
}

/// The design's fallback for a jumped destination: an `ssh -W`-style
/// stdio bridge from the last jump hop to the destination's ssh port,
/// spliced to this process's stdio.
///
/// The bridge originates at the hop closest to the destination, reached
/// through the ones in front of it, which is exactly what `ssh -J` does
/// for the session this bridge stands in for. Never a direct dial,
/// which would bypass the network policy the jump enforces.
async fn tcp_fallback_via_jump(
  options: &Options,
  jump: &str,
  env_args: &[OsString],
) -> Result<ExitCode> {
  let hop = HelperHop::from_jump_spec(jump)
    .with_context(|| format!("malformed jump spec {jump:?}"))?;
  let argv = bridge_ssh_argv(options, hop, env_args);
  tracing::debug!(?argv, "spawning the fallback bridge");
  let mut child = spawn_ssh_child(&argv)
    .with_context(|| format!("spawning the fallback bridge {:?}", argv[0]))?;
  let mut bridge_in = child.stdin.take().expect("bridge stdin is piped");
  let mut bridge_out = child.stdout.take().expect("bridge stdout is piped");
  let (mut stdin, mut stdout) =
    take_stdio().context("taking ownership of stdio for the relay")?;
  // Each direction closes its write end when its read end runs out, so
  // an EOF crosses the bridge as an EOF: `copy_bidirectional` over the
  // child's pipes would flush and leave them open, and the ssh on the
  // far side would wait for input that is never coming.
  let up = async move {
    let _ = tokio::io::copy(&mut stdin, &mut bridge_in).await;
    drop(bridge_in);
  };
  let down = async move {
    let _ = tokio::io::copy(&mut bridge_out, &mut stdout).await;
    let _ = stdout.shutdown().await;
  };
  tokio::join!(up, down);
  let status = reap(&mut child).await;
  match status {
    Some(status) if !status.success() => {
      bail!("the fallback bridge exited with {status}")
    }
    _ => Ok(ExitCode::SUCCESS),
  }
}

/// The extra option the helper and probe channels take, which the
/// fallback bridge does not.
///
/// Both run concurrently with the bootstrap ssh. OpenSSH reads
/// passphrases straight from `/dev/tty`, so on a bastion that would
/// prompt -- no key, no mux master, 2FA -- two prompts would race for
/// the user's keystrokes with nothing to say which is which. Failing
/// fast instead degrades through the design's "no jump helper" path,
/// which is a working session. The bridge is exempt because by then it
/// *is* the session, and nothing else is prompting.
fn no_prompting() -> [OsString; 2] {
  ["-o", "BatchMode=yes"].map(OsString::from)
}

/// The ssh options every side channel shares with the bootstrap: no
/// forwardings, no PTY, no agent, and a mux master used when one exists
/// but never created.
fn side_ssh_options() -> [OsString; 7] {
  [
    "-o",
    "ControlMaster=no",
    "-T",
    "-a",
    "-x",
    "-o",
    "ClearAllForwardings=yes",
  ]
  .map(OsString::from)
}

/// Builds one side channel's ssh argv.
///
/// The three side channels differ only in what they put between the
/// shared options and the destination, so the order lives here once.
/// The order matters: ssh takes the *first* occurrence of a repeated
/// option, so anything Mush must not let the user's own configuration
/// override has to precede `auth_args`.
///
/// Unlike the bootstrap ssh, none of these forces `ProxyCommand=none`:
/// the hop is the user's own bastion, reached however their
/// configuration says to reach it, exactly as `ssh -J` would reach it.
fn side_ssh_argv(
  options: &Options,
  via: Option<&str>,
  extra: Vec<OsString>,
  env_args: &[OsString],
  host: &str,
  command: Option<OsString>,
) -> Vec<OsString> {
  let mut argv: Vec<OsString> =
    options.ssh.split_whitespace().map(Into::into).collect();
  if let Some(via) = via {
    argv.push("-J".into());
    argv.push(via.into());
  }
  argv.extend(side_ssh_options());
  argv.extend(extra);
  argv.extend(auth_args(env_args));
  argv.push("--".into());
  argv.push(hop_destination(host).into());
  argv.extend(command);
  argv
}

/// Builds the argv that runs `mush jump-helper` on the helper's hop.
///
/// The helper runs on the last hop of a chain and is reached through the
/// ones in front of it ([`HelperHop`]), so a `-J` here carries only
/// those.
fn helper_ssh_argv(
  options: &Options,
  hop: HelperHop<'_>,
  env_args: &[OsString],
) -> Vec<OsString> {
  side_ssh_argv(
    options,
    hop.via,
    no_prompting().into(),
    env_args,
    hop.host,
    Some(options.helper.clone().into()),
  )
}

/// Builds the argv for the `ssh -W` bridge of the jumped TCP fallback.
///
/// No `no_prompting`: this is the last kind of path, so a bastion that
/// wants to ask the user something is worth waiting for rather than
/// failing past.
fn bridge_ssh_argv(
  options: &Options,
  hop: HelperHop<'_>,
  env_args: &[OsString],
) -> Vec<OsString> {
  let bridge = vec![
    "-W".into(),
    format!("{}:{}", options.host, options.port).into(),
  ];
  side_ssh_argv(options, hop.via, bridge, env_args, hop.host, None)
}

/// Builds the argv for the jump's view of this client: a plain
/// `echo $SSH_CONNECTION` on the hop that observes the client directly.
///
/// That is the *first* hop of a chain, not the helper's (see
/// [`observed`]), so this goes straight to it rather than through it.
/// Empty when there is nothing to ask.
fn jump_probe_argv(
  options: &Options,
  jump: &str,
  env_args: &[OsString],
) -> Vec<OsString> {
  let Some(first) = jump.split(',').next().filter(|hop| !hop.is_empty()) else {
    return Vec::new();
  };
  side_ssh_argv(
    options,
    None,
    no_prompting().into(),
    env_args,
    first,
    Some("echo \"$SSH_CONNECTION\"".into()),
  )
}

/// The ssh destination naming one hop of a jump spec.
///
/// `-J` takes `[user@]host[:port]`, which a plain destination argument
/// does not: ssh reads a port only from `-p` or from the `ssh://` URI
/// form. So a hop that names a port becomes that URI, and one that does
/// not is already a destination.
fn hop_destination(hop: &str) -> String {
  match hop_names_a_port(hop) {
    true => format!("ssh://{hop}"),
    false => hop.to_string(),
  }
}

/// Whether a jump hop names a port.
fn hop_names_a_port(hop: &str) -> bool {
  let host = hop.rsplit_once('@').map_or(hop, |(_, host)| host);
  let tail = match host.rsplit_once(']') {
    // A bracketed IPv6 literal's port follows the bracket.
    Some((_, tail)) => tail,
    // An unbracketed address with several colons is a bare IPv6
    // literal, whose last colon is part of the address.
    None if host.matches(':').count() > 1 => return false,
    None => host,
  };
  tail.rsplit_once(':').is_some_and(|(_, port)| {
    !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
  })
}

/// The wrapper-forwarded flags a side channel keeps: the auth-relevant
/// ones. A forwarded `-J` is dropped, since every side channel names the
/// hop it wants and the route to it explicitly.
fn auth_args(env_args: &[OsString]) -> Vec<OsString> {
  scan_flags(env_args)
    .filter(|flag| !flag.names_a_jump())
    .flat_map(|flag| flag.span.iter().cloned())
    .collect()
}

/// Resolves the `--stun <server>` opt-in, if given. Failure is not
/// fatal: the opt-in only ever adds a candidate.
async fn stun_servers(server: Option<&str>) -> Vec<SocketAddr> {
  let Some(server) = server else {
    return Vec::new();
  };
  // The default STUN port, for a bare hostname.
  let target = match server.contains(':') {
    true => server.to_string(),
    false => format!("{server}:3478"),
  };
  match tokio::net::lookup_host(&target).await {
    Ok(addrs) => addrs.collect(),
    Err(error) => {
      tracing::warn!(server, %error, "the --stun server did not resolve");
      Vec::new()
    }
  }
}

/// Builds the bootstrap ssh argv per the design's "Session lifecycle":
/// the hygiene of [`side_ssh_options`], plus prevented ProxyCommand
/// recursion, no control socket, and the destination's own port and
/// user.
///
/// Ordering matters: ssh takes the first occurrence of an option
/// (verified on OpenSSH 10.5: `ssh -G -p 111 -p 222` resolves port 111,
/// and the first of two `-o ProxyCommand`s wins). The safety `-o`s
/// therefore come first, where nothing forwarded can override them, and
/// the explicit jump/port/user flags come ahead of the wrapper's
/// forwarded flags so the ProxyCommand's `%r`/`%p` tokens (and a
/// ProxyCommand-configured `-J`) stay authoritative.
///
/// With a jump anywhere in the invocation (`options.jump` or one
/// forwarded by the wrapper), it must own ssh's proxy slot, so
/// `ProxyCommand=none` is omitted: ssh fatals on a `-J` that follows any
/// command-line ProxyCommand ("Cannot specify -J with ProxyCommand"),
/// and a forwarded `-o ProxyJump` would lose silently to an earlier
/// ProxyCommand (first-obtained wins across the two keywords; both
/// verified on OpenSSH 10.5). Nothing is lost: a command-line jump also
/// beats a config-file `ProxyCommand mush connect`, so the jump doubles
/// as the recursion guard.
fn bootstrap_ssh_argv(
  options: &Options,
  env_args: Vec<OsString>,
) -> Result<Vec<OsString>> {
  let mut argv: Vec<OsString> =
    options.ssh.split_whitespace().map(Into::into).collect();
  if argv.is_empty() {
    bail!("--ssh command is empty");
  }
  if options.server.trim().is_empty() {
    // An empty remote command would make sshd run a login shell, which
    // can never speak Mush; refuse it up front with a name the user can
    // act on.
    bail!("--server command is empty");
  }
  if let Some(jump) = &options.jump {
    // Ahead of everything: -J rejects any ProxyCommand already given.
    argv.push("-J".into());
    argv.push(jump.into());
  }
  if !(options.jump.is_some() || forwarded_jump(&env_args).is_some()) {
    argv.extend(["-o", "ProxyCommand=none"].map(OsString::from));
  }
  // The session's ssh runs this ProxyCommand only when it shares no
  // connection, so its bootstrap shares none either.
  argv.extend(["-o", "ControlPath=none"].map(OsString::from));
  argv.extend(side_ssh_options());
  argv.push("-p".into());
  argv.push(options.port.to_string().into());
  argv.push("-l".into());
  argv.push(options.user.clone().into());
  argv.extend(env_args);
  argv.push("--".into());
  argv.push(options.host.clone().into());
  argv.push(options.server.clone().into());
  Ok(argv)
}

/// The wrapper's forwarded outer-ssh flags from
/// [`BOOTSTRAP_SSH_ARGS_ENV`]: argv entries joined with the ASCII unit
/// separator (see [`crate::wrapper`]), each passed through as one argv
/// token with no quoting layer.
fn forwarded_env_args() -> Result<Vec<OsString>> {
  let Some(value) = std::env::var_os(BOOTSTRAP_SSH_ARGS_ENV) else {
    return Ok(Vec::new());
  };
  parse_forwarded_args(&value)
}

/// Decodes the variable's separator-joined argv entries. The wrapper
/// never produces an empty entry (it refuses empty and separator-laden
/// values), so one here means a corrupted or hand-forged encoding;
/// refusing it beats passing tokens whose framing was guessed -- a
/// stray non-option token would become the bootstrap ssh's destination.
fn parse_forwarded_args(value: &OsStr) -> Result<Vec<OsString>> {
  if value.is_empty() {
    return Ok(Vec::new());
  }
  let mut args = Vec::new();
  for bytes in value.as_bytes().split(|&b| b == ARG_SEPARATOR) {
    if bytes.is_empty() {
      bail!(
        "malformed {BOOTSTRAP_SSH_ARGS_ENV}: empty forwarded argument \
         (the separator byte 0x1f is reserved)"
      );
    }
    args.push(OsString::from_vec(bytes.to_vec()));
  }
  Ok(args)
}

/// The jump spec in the wrapper-forwarded flags: a `-J`, or a `-o`
/// whose value sets `ProxyJump`.
///
/// The spec itself, not merely its presence: the helper and the
/// fallback bridge both have to name the hop they run on, and in
/// wrapper mode this is the only place it appears.
fn forwarded_jump(args: &[OsString]) -> Option<String> {
  scan_flags(args).find_map(|flag| flag.jump_spec())
}

/// One flag of the wrapper's forwarded encoding, as [`scan_flags`]
/// found it: the option letter, its value (attached to the letter or
/// the argv entry after it; `None` for a value-taking flag with nothing
/// behind it, which ssh rejects too), and the argv entries it occupies,
/// which is what a channel keeping the flag passes through.
struct ForwardedFlag<'a> {
  letter: u8,
  value: Option<&'a [u8]>,
  span: &'a [OsString],
}

impl ForwardedFlag<'_> {
  /// Whether this flag configures a jump, spec or no spec: a bare
  /// `-o ProxyJump` names no hop, and ssh rejects it for the missing
  /// argument, but it must never travel to a channel that named its own.
  fn names_a_jump(&self) -> bool {
    match self.letter {
      b'J' => true,
      b'o' => option_sets_keyword(self.value.unwrap_or_default(), b"proxyjump"),
      _ => false,
    }
  }

  /// The hop this flag names, if it names one.
  fn jump_spec(&self) -> Option<String> {
    match self.letter {
      b'J' => Some(String::from_utf8_lossy(self.value?).into_owned()),
      b'o' => keyword_value(self.value?, b"proxyjump"),
      _ => None,
    }
  }
}

/// Walks the encoding the wrapper produces -- alternating flag and
/// value entries, every forwarded flag value-taking -- and also accepts
/// attached values, so a hand-set variable cannot smuggle a jump past
/// the scan; a flag's separate value is never mistaken for a flag (`-i`
/// with a file literally named `-J` forwards as a value).
///
/// One scan for both consumers, because they have to agree: a `-J` that
/// [`auth_args`] let through to a side channel while [`forwarded_jump`]
/// still found it would put two jumps on one invocation.
fn scan_flags(args: &[OsString]) -> impl Iterator<Item = ForwardedFlag<'_>> {
  let mut i = 0;
  std::iter::from_fn(move || {
    while i < args.len() {
      let bytes = args[i].as_bytes();
      let [b'-', letter, attached @ ..] = bytes else {
        i += 1;
        continue;
      };
      let (value, consumed) = match attached.is_empty() {
        true => (args.get(i + 1).map(|value| value.as_bytes()), 2),
        false => (Some(attached), 1),
      };
      let span = &args[i..args.len().min(i + consumed)];
      i += consumed;
      return Some(ForwardedFlag {
        letter: *letter,
        value,
        span,
      });
    }
    None
  })
}

/// The value of `-o <keyword>=<value>` (or its space form), when the
/// option sets `keyword`. `None` for the bare keyword, which ssh
/// rejects for its missing argument.
fn keyword_value(option: &[u8], keyword: &[u8]) -> Option<String> {
  if !option_sets_keyword(option, keyword) {
    return None;
  }
  let start = option.iter().position(|&b| !matches!(b, b' ' | b'\t'))?;
  let rest = &option[start + keyword.len()..];
  let rest = match rest.first() {
    Some(b'=') => &rest[1..],
    _ => rest,
  };
  let begin = rest.iter().position(|&b| !matches!(b, b' ' | b'\t'))?;
  Some(String::from_utf8_lossy(&rest[begin..]).into_owned())
}

/// Whether the stdio channel's far side is gone: POLLHUP on the pipe
/// read end once no writer holds it (buffered data may remain; the
/// relay drains it), POLLHUP or POLLRDHUP once a socketpair peer has
/// closed or shut down its write side. This is what arms the
/// post-hangup drain (see [`HUP_DRAIN_GRACE`]): the outer ssh and any
/// process continuing its session (a ControlPersist mux master) hold the
/// channel open exactly as long as they live, and the kernel closes
/// their ends even on SIGKILL.
fn stdio_hangup(fd: RawFd) -> bool {
  use rustix::event::{PollFd, PollFlags, Timespec, poll};

  // POLLHUP is reported unasked on Linux, but macOS's poll, built on
  // kqueue, watches a descriptor only for events it was asked about.
  // POLLRDHUP (Linux-only) additionally catches a socket peer that shut
  // down just its write side.
  #[cfg(target_os = "linux")]
  let extra = PollFlags::HUP | PollFlags::RDHUP;
  #[cfg(not(target_os = "linux"))]
  let extra = PollFlags::HUP;
  // The relay future owns the handle behind this descriptor until it is
  // dropped at return, so the fd outlives every poll.
  let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
  let mut fds = [PollFd::new(&fd, extra)];
  // A poll that fails (EINTR, most likely) says nothing about the
  // channel; the caller polls again on its next tick.
  poll(&mut fds, Some(&Timespec::default())).is_ok_and(|ready| ready > 0)
    && fds[0]
      .revents()
      .intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL | extra)
}

/// The prober's network-change wake stream: the netlink monitor on
/// Linux, nothing elsewhere (the portable stall prober still runs).
#[cfg(target_os = "linux")]
fn path_events()
-> Option<tokio::sync::mpsc::UnboundedReceiver<mush_core::roaming::PathWake>> {
  mush_core::netlink::watch()
}

#[cfg(not(target_os = "linux"))]
fn path_events()
-> Option<tokio::sync::mpsc::UnboundedReceiver<mush_core::roaming::PathWake>> {
  None
}

/// Resolves the destination for [`ClientOptions::resolved_ips`].
/// Failure is not fatal: the connect line's address hints may still
/// name a dialable address.
async fn resolve_ips(host: &str, port: u16) -> Vec<IpAddr> {
  match tokio::net::lookup_host((host, port)).await {
    Ok(addrs) => {
      let mut ips: Vec<IpAddr> = Vec::new();
      for addr in addrs {
        if !ips.contains(&addr.ip()) {
          ips.push(addr.ip());
        }
      }
      ips
    }
    Err(error) => {
      tracing::warn!(host, %error, "destination did not resolve");
      Vec::new()
    }
  }
}

/// Replacement sockets for a session under the path manager.
///
/// A rebind probe hands quinn a socket of its own, and this session
/// addresses a virtual peer that only the shim knows how to map, so the
/// replacement has to be one too -- over the same paths, since it is the
/// same session merely leaving from a new local mapping (see
/// `mush_core::traversal`).
fn rebinding_sockets(
  socket: &std::sync::Arc<TraversalSocket>,
  connection: &quinn::Connection,
) -> SocketFactory {
  let socket = socket.clone();
  let mut fresh = os_socket_factory(connection);
  Box::new(move || {
    let rebound = socket.rebound(fresh()?.socket.hand());
    Ok(FreshSocket {
      socket: rebound.clone(),
      // The session's probes move to the new mapping only once the
      // endpoint has taken it, so a failed rebind leaves the relay
      // registered where the session still sends from.
      adopt: Box::new(move || rebound.adopt()),
    })
  })
}

/// The route cross-check for a session under the path manager: the peer
/// quinn names is virtual, so what the kernel is asked about is the real
/// path the session is on at the time of the wake.
fn path_route_check(
  socket: &std::sync::Arc<TraversalSocket>,
  connection: &quinn::Connection,
) -> RouteCheck {
  let socket = socket.clone();
  let connection = connection.clone();
  os_route_check_to(Box::new(move || {
    socket
      .current_path()
      .unwrap_or_else(|| connection.remote_address())
  }))
}

/// Local bind address for the QUIC endpoint. One socket serves one
/// address family: prefer IPv4 unless the destination resolves to IPv6
/// only. Candidates of the other family fail their dials and show up
/// in the unreachable detail rather than blocking establishment.
fn bind_addr(resolved: &[IpAddr]) -> SocketAddr {
  let v6_only = !resolved.is_empty() && resolved.iter().all(|ip| ip.is_ipv6());
  if v6_only {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
  } else {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
  }
}

/// Waits [`REAP_GRACE`] for a child ssh, then kills it: nothing this
/// process spawned may outlive this process.
async fn reap(child: &mut Child) -> Option<std::process::ExitStatus> {
  match tokio::time::timeout(REAP_GRACE, child.wait()).await {
    Ok(status) => status.ok(),
    Err(_) => {
      let _ = child.start_kill();
      child.wait().await.ok()
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn options() -> Options {
    Options {
      jump: None,
      ssh: "ssh".into(),
      server: "mush server bootstrap".into(),
      helper: "mush jump-helper".into(),
      stun: None,
      no_fallback: false,
      idle_timeout: None,
      user: "alice".into(),
      host: "dev.example".into(),
      port: 22,
    }
  }

  fn os(args: &[&str]) -> Vec<OsString> {
    args.iter().map(Into::into).collect()
  }

  fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
  }

  #[test]
  fn default_argv_matches_the_design_invocation() {
    assert_eq!(
      bootstrap_ssh_argv(&options(), Vec::new()).unwrap(),
      os(&[
        "ssh",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ControlPath=none",
        "-o",
        "ControlMaster=no",
        "-T",
        "-a",
        "-x",
        "-o",
        "ClearAllForwardings=yes",
        "-p",
        "22",
        "-l",
        "alice",
        "--",
        "dev.example",
        "mush server bootstrap",
      ])
    );
  }

  #[test]
  fn the_bootstrap_shares_no_control_socket() {
    // Ahead of anything forwarded, jump or no jump, since ssh takes the
    // first value it sees.
    for jump in [None, Some("bastion".to_string())] {
      let argv = bootstrap_ssh_argv(
        &Options {
          jump: jump.clone(),
          ..options()
        },
        os(&["-o", "ControlPath=/tmp/x"]),
      )
      .unwrap();
      let none = argv
        .windows(2)
        .position(|pair| pair == os(&["-o", "ControlPath=none"]))
        .unwrap_or_else(|| panic!("with jump {jump:?}: {argv:?}"));
      let forwarded = argv
        .iter()
        .position(|arg| arg == "ControlPath=/tmp/x")
        .unwrap();
      assert!(none < forwarded, "with jump {jump:?}: {argv:?}");
    }
  }

  #[test]
  fn ssh_override_replaces_program_and_leading_args() {
    let argv = bootstrap_ssh_argv(
      &Options {
        ssh: "ssh -i /k y".into(),
        ..options()
      },
      Vec::new(),
    )
    .unwrap();
    assert_eq!(&argv[..4], &os(&["ssh", "-i", "/k", "y"])[..]);
    assert!(
      bootstrap_ssh_argv(
        &Options {
          ssh: " ".into(),
          ..options()
        },
        Vec::new(),
      )
      .is_err()
    );
  }

  #[test]
  fn empty_server_command_is_refused() {
    for server in ["", " "] {
      assert!(
        bootstrap_ssh_argv(
          &Options {
            server: server.into(),
            ..options()
          },
          Vec::new(),
        )
        .is_err()
      );
    }
  }

  #[test]
  fn explicit_jump_leads_and_suppresses_proxy_command_none() {
    // See `bootstrap_ssh_argv` for why the jump leads, why
    // ProxyCommand=none drops out, and why the port/user flags precede
    // anything forwarded.
    assert_eq!(
      bootstrap_ssh_argv(
        &Options {
          jump: Some("bastion".into()),
          ..options()
        },
        os(&["-i", "key"]),
      )
      .unwrap(),
      os(&[
        "ssh",
        "-J",
        "bastion",
        "-o",
        "ControlPath=none",
        "-o",
        "ControlMaster=no",
        "-T",
        "-a",
        "-x",
        "-o",
        "ClearAllForwardings=yes",
        "-p",
        "22",
        "-l",
        "alice",
        "-i",
        "key",
        "--",
        "dev.example",
        "mush server bootstrap",
      ])
    );
  }

  #[test]
  fn forwarded_jump_also_suppresses_proxy_command_none() {
    // The wrapper forwards -J only through the environment, and the
    // forwarded flag stays in its forwarded position: no earlier
    // ProxyCommand exists for it to conflict with.
    for forwarded in [&["-J", "bastion"][..], &["-o", "ProxyJump=bastion"]] {
      let argv = bootstrap_ssh_argv(&options(), os(forwarded)).unwrap();
      assert!(
        !argv.contains(&OsString::from("ProxyCommand=none")),
        "for {forwarded:?}: {argv:?}"
      );
      assert!(
        argv.ends_with(
          &[
            forwarded[0].into(),
            forwarded[1].into(),
            "--".into(),
            "dev.example".into(),
            "mush server bootstrap".into(),
          ][..]
        ),
        "for {forwarded:?}: {argv:?}"
      );
    }
  }

  #[test]
  fn forwarded_jump_detection_walks_the_wrapper_encoding() {
    for jumped in [
      &["-J", "bastion"][..],
      &["-Jbastion"],
      &["-i", "key", "-J", "bastion"],
      &["-o", "ProxyJump=bastion"],
      &["-o", "proxyjump bastion"],
      &["-oProxyJump=bastion"],
      &["-o", "  ProxyJump=  bastion"],
    ] {
      assert_eq!(
        forwarded_jump(&os(jumped)).as_deref(),
        Some("bastion"),
        "missed jump in {jumped:?}"
      );
    }
    assert_eq!(forwarded_jump(&os(&["-J", "a,b"])).as_deref(), Some("a,b"));
    for plain in [
      &[][..],
      &["-i", "key"],
      &["-o", "BatchMode=yes"],
      // A value is never a flag: an identity file literally named -J.
      &["-i", "-J"],
      &["-o", "ProxyJumpX=bastion"],
      // The bare keyword names no hop, which ssh rejects too.
      &["-o", "ProxyJump"],
    ] {
      assert_eq!(forwarded_jump(&os(plain)), None, "false jump in {plain:?}");
    }
  }

  #[test]
  fn forwarded_args_round_trip_and_reject_bad_framing() {
    use std::os::unix::ffi::OsStrExt as _;

    assert_eq!(
      parse_forwarded_args(OsStr::from_bytes(b"-i\x1fkey")).unwrap(),
      os(&["-i", "key"])
    );
    assert_eq!(parse_forwarded_args(OsStr::new("")).unwrap(), os(&[]));
    // Empty entries cannot come from the wrapper; they mark framing
    // that would re-split into stray tokens.
    for bad in [&b"-i\x1f\x1fkey"[..], b"\x1f-i", b"-i\x1f"] {
      assert!(
        parse_forwarded_args(OsStr::from_bytes(bad)).is_err(),
        "accepted {bad:?}"
      );
    }
  }

  /// A hop naming a port has to become the URI form, which is the only
  /// destination spelling ssh reads a port from.
  #[test]
  fn a_hop_with_a_port_becomes_an_ssh_url() {
    assert_eq!(hop_destination("bastion"), "bastion");
    assert_eq!(hop_destination("me@bastion"), "me@bastion");
    assert_eq!(hop_destination("bastion:2222"), "ssh://bastion:2222");
    assert_eq!(hop_destination("me@bastion:2222"), "ssh://me@bastion:2222");
    assert_eq!(hop_destination("[2001:db8::1]"), "[2001:db8::1]");
    assert_eq!(
      hop_destination("me@[2001:db8::1]:22"),
      "ssh://me@[2001:db8::1]:22"
    );
    // A bare IPv6 literal's last colon belongs to the address.
    assert_eq!(hop_destination("2001:db8::1"), "2001:db8::1");
    // Not a port, so not a URI.
    assert_eq!(hop_destination("bastion:name"), "bastion:name");
  }

  /// Every side channel names its own hop and route, so a forwarded
  /// jump would only duplicate or contradict that; the auth-relevant
  /// flags do travel.
  #[test]
  fn side_channels_keep_the_auth_flags_and_drop_the_jump() {
    assert_eq!(
      auth_args(&os(&["-i", "key", "-J", "bastion", "-o", "BatchMode=yes"])),
      os(&["-i", "key", "-o", "BatchMode=yes"])
    );
    assert_eq!(auth_args(&os(&["-Jbastion"])), os(&[]));
    assert_eq!(auth_args(&os(&["-o", "ProxyJump=bastion"])), os(&[]));
    assert_eq!(auth_args(&os(&["-oProxyJump=bastion"])), os(&[]));
    // A bare ProxyJump names no hop, and still must not travel.
    assert_eq!(auth_args(&os(&["-o", "ProxyJump"])), os(&[]));
  }

  /// Both consumers read one scan, so they have to agree about a
  /// value-taking flag with nothing behind it. The wrapper cannot
  /// produce one (it refuses an absent or empty value); in a hand-set
  /// variable the scan keeps it as its own whole span, and it names no
  /// hop.
  #[test]
  fn a_trailing_flag_with_no_value_reads_the_same_to_both_consumers() {
    let dangling = os(&["-i", "key", "-o"]);
    assert_eq!(auth_args(&dangling), dangling);
    assert_eq!(forwarded_jump(&dangling), None);
    let dangling_jump = os(&["-i", "key", "-J"]);
    assert_eq!(auth_args(&dangling_jump), os(&["-i", "key"]));
    assert_eq!(forwarded_jump(&dangling_jump), None);
  }

  /// Each side channel runs on the hop it belongs on: the helper and
  /// the fallback bridge on the last of a chain, the shell probe on the
  /// first.
  #[test]
  fn the_side_channels_run_on_the_right_hop() {
    let options = Options {
      helper: "mush jump-helper".into(),
      ..options()
    };
    let hop = HelperHop::from_jump_spec("a:22,b:2222").unwrap();
    let helper = helper_ssh_argv(&options, hop, &[]);
    assert!(
      helper.ends_with(&os(&["--", "ssh://b:2222", "mush jump-helper"])[..])
    );
    assert!(
      helper
        .windows(2)
        .any(|pair| *pair == os(&["-J", "a:22"])[..])
    );
    let bridge = bridge_ssh_argv(&options, hop, &[]);
    assert!(
      bridge
        .windows(2)
        .any(|pair| *pair == os(&["-W", "dev.example:22"])[..])
    );
    assert!(bridge.ends_with(&os(&["--", "ssh://b:2222"])[..]));
    // The shell probe asks the first hop, the one that observes the
    // client.
    let probe = jump_probe_argv(&options, "a:22,b:2222", &[]);
    assert!(
      probe
        .ends_with(&os(&["--", "ssh://a:22", "echo \"$SSH_CONNECTION\""])[..])
    );
    assert!(jump_probe_argv(&options, "", &[]).is_empty());
  }

  /// The one stderr line for a helper that answered on ssh and then
  /// could not be reached over UDP, and silence while reflection may
  /// still answer or there was no helper to lose.
  #[test]
  fn a_helper_that_cannot_be_reached_is_reported_once_it_is_known() {
    let reflected = PathReport {
      helper_offered: true,
      helper: Some(addr("198.51.100.7:60123")),
      reflexive: Some(addr("5.5.5.5:41000")),
      punched: true,
      ..PathReport::default()
    };
    assert!(!reflection_lost(Some(&reflected)));
    let unreachable = PathReport {
      helper: None,
      reflexive: None,
      ..reflected.clone()
    };
    assert!(reflection_lost(Some(&unreachable)));
    // Before the punch, reflection may still answer.
    assert!(!reflection_lost(Some(&PathReport {
      punched: false,
      ..unreachable.clone()
    })));
    // No helper at all is the degraded path's own warning, not this
    // one, and a session that ran no staged dials has nothing to report.
    assert!(!reflection_lost(Some(&PathReport {
      helper_offered: false,
      ..unreachable
    })));
    assert!(!reflection_lost(None));
  }

  /// The side channels must not compete with the bootstrap ssh for the
  /// user's tty (see [`no_prompting`]); the fallback bridge is exempt.
  #[test]
  fn the_helper_and_probe_channels_never_prompt() {
    let options = options();
    let hop = HelperHop::from_jump_spec("bastion").unwrap();
    let batch = os(&["-o", "BatchMode=yes"]);
    for argv in [
      helper_ssh_argv(&options, hop, &[]),
      jump_probe_argv(&options, "bastion", &[]),
    ] {
      assert!(
        argv.windows(2).any(|pair| pair == batch),
        "no BatchMode in {argv:?}"
      );
    }
    let bridge = bridge_ssh_argv(&options, hop, &[]);
    assert!(
      !bridge.windows(2).any(|pair| pair == batch),
      "the fallback bridge must still be able to authenticate: {bridge:?}"
    );
  }

  /// The helper's ready line already carries the jump's view of this
  /// client, but only from the hop that observes the client; a later hop
  /// of a chain is left to the shell probe (see [`observed`]).
  #[test]
  fn the_helpers_view_of_the_client_counts_only_on_the_first_hop() {
    let session = |helper_observes_client| HelperSession {
      nonce: SessionNonce::from_bytes([1; 16]),
      secret: SessionSecret::from_bytes([2; 16]),
      local_port: 41000,
      helper_observes_client,
    };
    let seen: IpAddr = "198.51.100.9".parse().unwrap();
    assert_eq!(
      observed_by_the_helper(session(true), Some(seen)),
      Some(addr("198.51.100.9:41000"))
    );
    assert_eq!(observed_by_the_helper(session(false), Some(seen)), None);
    assert_eq!(observed_by_the_helper(session(true), None), None);
  }

  /// The `--stun` opt-in takes a host or a host and port; a bare host
  /// gets STUN's own port, and a failed resolution only costs a
  /// candidate.
  #[tokio::test]
  async fn the_stun_opt_in_defaults_to_the_stun_port() {
    assert!(stun_servers(None).await.is_empty());
    assert_eq!(
      stun_servers(Some("127.0.0.1")).await,
      vec![addr("127.0.0.1:3478")]
    );
    assert_eq!(
      stun_servers(Some("127.0.0.1:19302")).await,
      vec![addr("127.0.0.1:19302")]
    );
    assert!(stun_servers(Some("no.such.host.invalid")).await.is_empty());
  }

  #[test]
  fn stdio_hangup_tracks_pipe_writers() {
    let (read, write) = rustix::pipe::pipe().unwrap();
    assert!(!stdio_hangup(read.as_raw_fd()));
    // Buffered data must not mask the hangup and open writers must not
    // fake one: POLLHUP reports writer absence, not emptiness.
    assert_eq!(rustix::io::write(&write, b"x").unwrap(), 1);
    assert!(!stdio_hangup(read.as_raw_fd()));
    drop(write);
    assert!(stdio_hangup(read.as_raw_fd()));
  }

  #[test]
  fn stdio_hangup_tracks_socketpair_peer() {
    // ssh may hand its ProxyCommand a socketpair instead of pipes.
    let (ours, peer) = rustix::net::socketpair(
      rustix::net::AddressFamily::UNIX,
      rustix::net::SocketType::STREAM,
      rustix::net::SocketFlags::empty(),
      None,
    )
    .unwrap();
    assert!(!stdio_hangup(ours.as_raw_fd()));
    drop(peer);
    assert!(stdio_hangup(ours.as_raw_fd()));
  }

  #[test]
  fn bind_family_follows_the_resolution() {
    let v4: IpAddr = "192.0.2.1".parse().unwrap();
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    assert!(bind_addr(&[]).is_ipv4());
    assert!(bind_addr(&[v4]).is_ipv4());
    assert!(bind_addr(&[v6, v4]).is_ipv4());
    assert!(bind_addr(&[v6]).is_ipv6());
  }
}
