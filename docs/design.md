# Mush design

<!--
Part of the Mush project, under the Apache License v2.0 with LLVM
Exceptions. See /LICENSE for license information.
SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-->

<!-- toc -->

## Table of contents

-   [Problem](#problem)
-   [Goals](#goals)
-   [Non-goals](#non-goals)
-   [Relay SSH ciphertext, never terminate SSH](#relay-ssh-ciphertext-never-terminate-ssh)
-   [Architecture](#architecture)
    -   [Session lifecycle](#session-lifecycle)
-   [Transport layer](#transport-layer)
    -   [QUIC and quinn](#quic-and-quinn)
    -   [Connection configuration](#connection-configuration)
    -   [Timers and budgets](#timers-and-budgets)
    -   [No resume protocol](#no-resume-protocol)
    -   [Fallback](#fallback)
-   [Jump hosts and NAT traversal](#jump-hosts-and-nat-traversal)
    -   [Bootstrap through the jump](#bootstrap-through-the-jump)
    -   [The jump helper](#the-jump-helper)
    -   [Signaling](#signaling)
    -   [Path establishment](#path-establishment)
    -   [Upgrading from relay to direct](#upgrading-from-relay-to-direct)
    -   [Degrading without the helper](#degrading-without-the-helper)
    -   [Reuse versus build](#reuse-versus-build)
-   [SSH integration](#ssh-integration)
    -   [Invocation modes](#invocation-modes)
    -   [What OpenSSH provides](#what-openssh-provides)
    -   [Sharp edges](#sharp-edges)
-   [Security analysis](#security-analysis)
-   [Alternatives and prior art](#alternatives-and-prior-art)
-   [Implementation](#implementation)
    -   [Validation spikes](#validation-spikes)
-   [Open questions](#open-questions)

<!-- tocstop -->

## Problem

An SSH session dies with its TCP connection. Suspend, Wi-Fi to cellular
handoffs, NAT timeouts, VPN flaps, and packet loss end or hang sessions, along
with their port forwards, agent forwarding, and file transfers.

Mosh fixes this for interactive terminals by synchronizing terminal state over
UDP, but it reimplements the terminal, drops the rest of SSH, and cannot serve
tools that run `ssh`. Mush keeps unmodified OpenSSH on both ends and replaces
only the TCP transport between them, with a UDP transport that survives loss,
outages, routing changes, and client address changes.

## Goals

-   Drop-in for `ssh`: shells, exec, `-L`/`-R`/`-D` and UNIX-socket forwarding,
    agent forwarding, sftp, scp, and tools that run `ssh`, configurable through
    `~/.ssh/config` with no wrapper.
-   Sessions survive packet loss, long outages, NAT rebinding, and client
    address changes, and recover promptly.
-   Jump hosts work as with `ssh -J`, while session traffic takes the most
    direct UDP path available, with help from the jump host.
-   No new authentication, authorization, or session encryption. SSH remains the
    end-to-end security boundary.
-   Minimal protocol code. An established QUIC stack provides the cryptography,
    loss recovery, congestion control, and migration.

## Non-goals

-   Local echo and predictive typing. A session freezes during an outage as
    ssh's would, then resumes.
-   Server address changes. QUIC's `preferred_address` could support them later.
-   Third-party relay or discovery services. Only the destination and its jump
    hosts take part, except for the opt-in `--stun <server>`.
-   Terminal awareness. Mush does not interpret the bytes it carries.
-   General TCP tunneling. Scope, defaults, and testing target sshd.

## Relay SSH ciphertext, never terminate SSH

Interpreting the session, as Mosh, a Rust SSH server, or an SSH3-style
reimplementation would, puts new code inside the security boundary and
diverges from OpenSSH. Mush relays SSH's byte stream unchanged:

-   Every SSH feature works, because OpenSSH runs on both ends: key exchange,
    host key verification, channels, forwarding, PTYs, exit status, `~` escapes,
    and keystroke-timing obfuscation.
-   Mush sees only ciphertext, while Mosh's server handles terminal plaintext.
-   The tunnel is not the security boundary. Compromising Mush's transport
    yields SSH ciphertext, a connection to sshd (already reachable), and the
    ability to drop the session, but no plaintext, authentication bypass, or
    privilege.
-   There is no TCP-in-TCP. ssh talks to Mush over pipes, the server's TCP hop
    is loopback, and QUIC is the only transport on the network.

## Architecture

```text
client host                                        server host
-----------                                        -----------
ssh (unmodified)                                   sshd (unmodified)
  |  stdio (ProxyCommand)                               ^  TCP 127.0.0.1:22
  v                                                     |
mush connect  <==== QUIC over UDP (quinn) ====>  mush server
                                                 (per session, runs as the
                                                 user, unprivileged)

bootstrap (once per session, real ssh over TCP):
  ssh user@host -- mush server bootstrap
    stdin:  MUSH HELLO  (client key hash, target port, session nonce)
    stdout: MUSH CONNECT (UDP port, server key hash, address hints)
```

A session is one bootstrap ssh, one `mush server` process, one QUIC connection
carrying one bidirectional stream, and one loopback TCP connection to sshd. A
jumped session adds an ssh channel running `mush jump-helper` on the jump host,
and sometimes a short-lived ssh for a shell probe. There are no shared daemons,
no listeners that outlive a session, and no state files.

### Session lifecycle

Bootstrap. The client generates an ephemeral keypair and runs real `ssh` to
execute `mush server bootstrap` on the destination. It sends a `MUSH HELLO` line
with the protocol version, its key hash, the target sshd port, and, if it will
signal later, a session nonce. This ssh authenticates however the user's ssh
does for that host. It runs with `-T -a -x -o ClearAllForwardings=yes` and
`-o ControlPath=none`, sharing no connection, since the session's ssh runs the
`ProxyCommand` only when it shares none. Without a jump it also sets
`-o ProxyCommand=none` so it does not recurse into Mush; with a jump, `-J` takes
ssh's proxy slot instead, since ssh rejects `-J` after a command-line
`ProxyCommand`.

Server start. The server generates its own keypair, binds a UDP port in Mosh's
range, and prints:

```text
MUSH CONNECT v=1 port=60123 key=<b64 hash> addr=<server addr hint>...
```

<!-- The trailing space is part of the prefix the scanner matches. -->
<!-- rumdl-disable-next-line MD038 -->
The client scans stdout for the `MUSH CONNECT ` prefix as Mosh does, skipping
login output up to a fixed budget, and ignores unknown `key=value` pairs. The
first address hint is the server's `$SSH_CONNECTION` address, which the client
has demonstrably reached. A capped list of interface addresses follows, which
makes a destination behind a jump dialable. Loopback, link-local, multicast,
and addresses the server's socket cannot answer on are left out.

The bootstrap channel stays open for [signaling](#signaling). The server
detaches as `mosh-server` does (fork, setsid, stderr to /dev/null, ignore
SIGHUP) and exits if no valid QUIC connection arrives within its bootstrap
timeout. A session that announced a nonce keeps the remote command running
until the path settles: sshd closes the command's stdin when the command exits,
and signaling needs both directions.

Connect. The client dials QUIC at the server's hints and its own DNS resolution
of the destination, plus punched and relayed candidates behind a jump, with a
Happy Eyeballs stagger (RFC 8305). It first drops addresses that cannot name the
destination: unspecified, port 0, multicast, broadcast, link-local, and
loopback from a server that is not this host, including their v4-mapped forms.
Both sides pin the peer's ephemeral key from bootstrap, so the first
authenticated handshake wins and concurrent dialing is safe. The server accepts
one connection, from the pinned key.

Relay. The client splices ssh's stdio onto one bidirectional stream, and the
server splices the stream onto a TCP connection to `127.0.0.1:<port>`.
Half-closes map through in both directions (stdin EOF, stream FIN,
`shutdown(SHUT_WR)`), so `ssh host cmd < file` behaves as it does over TCP.

Roam and recover. The transport handles roaming, and the byte stream is
continuous.

Teardown. When the stream finishes in both directions, both processes exit. If
sshd closes while the client is unreachable, the server holds the remaining
output and the EOF until the client returns: indefinitely by default, as Mosh
does, or as long as `--retain` allows.

## Transport layer

### QUIC and quinn

The transport needs a reliable ordered stream over UDP with authenticated
encryption, loss recovery, congestion control, PMTUD, and client migration.
That is QUIC (RFC 9000); building it from datagrams and Noise would be the
custom protocol code Mush exists to avoid.

Mush uses [quinn](https://docs.rs/quinn/) (tokio, rustls), which iroh uses in
production for the same roaming and key-pinning patterns. The design depends on
quinn specifically: the path manager implements `AsyncUdpSocket`, the stall
prober calls `Endpoint::rebind_abstract`, and the upgrade reads migration
counters from `ConnectionStats`. quinn is pinned to a git revision (see the root
`Cargo.toml`), because the simulator needs quinn-proto's internals to stay
fixed, and no released quinn-proto has the current security fixes and also
survives a stalled reader.

### Connection configuration

One QUIC connection with one bidirectional stream, configured in `mush-core`'s
`transport` module:

| Setting                       | quinn   | Mush             | Why                                                                                |
| ----------------------------- | ------- | ---------------- | ---------------------------------------------------------------------------------- |
| `max_idle_timeout`            | 30s     | none             | An idle timeout would end a session that an outage should only pause               |
| `keep_alive_interval`         | off     | 20s, client only | Keeps NAT mappings open, and detects a dead path on a session that is only reading |
| Stream receive window         | 1.25MB  | 16MB             | WAN throughput; also bounds outage buffering                                       |
| Datagram receive buffer       | 1.25MB  | disabled         | Nothing uses DATAGRAM frames, so peers cannot make the receiver buffer them        |
| Fixed-bit greasing (RFC 9287) | offered | declined         | QUIC and STUN share a socket and are told apart by the fixed bit (RFC 7983)        |

Client migration and automatic TLS key updates keep quinn's defaults. Roaming
needs the first, and multi-week sessions need the second to stay within AEAD
limits.

Roaming. With RFC 9000's passive migration, the client's address changes and
the server validates the new path. The client's stall prober also forces an
ack-eliciting exchange once a transmission goes unanswered in either direction,
and rebinds to a fresh socket on every other probe, which recovers when the old
source address no longer works. On Linux, a netlink event skips the wait, but
only when the kernel reports no route to the peer, since every rebind costs the
peer a path validation and a congestion reset.

Backpressure. During an outage the flow-control window fills and ssh blocks on
write, as with a stalled TCP socket. Declaring a stall also drops the send
window to zero, so backpressure starts within seconds and new session data
cannot crowd out the probes. The window bounds bytes but not the number of
buffered frames: released quinn-proto abandons a connection with more than 2048
frame buffers even when the data is contiguous, and the pinned revision's
reassembler coalesces them.

Latency. Reads are forwarded immediately, and the loopback socket sets
`TCP_NODELAY`. Interactive latency measured within 0.4 ms of ssh's (see
[Validation spikes](#validation-spikes)).

### Timers and budgets

The constants are in `crates/mush-core/src/`. None has a command-line option;
the two limits that do, `--idle-timeout` and `--retain`, are off by default.

| Value            | Constant                             | Bounds                                                                   |
| ---------------- | ------------------------------------ | ------------------------------------------------------------------------ |
| 60000-61000      | `server::DEFAULT_PORT_RANGE`         | UDP port for a server or helper: the first free one                      |
| 120s             | `client::DEFAULT_BOOTSTRAP_TIMEOUT`  | Bootstrap, including a slow shell and 2FA                                |
| 60s              | `server::DEFAULT_BOOTSTRAP_TIMEOUT`  | A detached server's wait for its QUIC connection                         |
| 512 lines, 256KB | `bootstrap::ScanLimits`              | Login output skipped before the connect line                             |
| 512 lines, 256KB | `channel::LineLimits`                | The same, on the signaling channels                                      |
| 8KB              | `bootstrap::MAX_LINE_BYTES`          | One protocol line                                                        |
| 8                | `server::MAX_ADDR_HINTS`             | Address hints from a peer                                                |
| 8                | `path::MAX_REFLECTORS`               | Reflectors probed                                                        |
| 4                | `path::MAX_REFLEXIVE_HINTS`          | Reflexive candidates, which a lying helper chooses outright              |
| 250ms            | `client::DIAL_STAGGER`               | Stagger between candidate dials                                          |
| 5s               | `client::DEFAULT_ESTABLISH_TIMEOUT`  | Establishment before TCP fallback, without a jump                        |
| 10s              | `path::TRAVERSAL_ESTABLISH_TIMEOUT`  | Establishment before TCP fallback, with a jump                           |
| 1s               | `path::DIRECT_WINDOW`                | Direct path alone, before punching starts                                |
| 200ms            | `path::REFLECT_INTERVAL`             | Interval between binding requests to one reflector                       |
| 5                | `path::REFLECT_ATTEMPTS`             | Binding requests to one reflector                                        |
| 3s               | `path::HELPER_WAIT`                  | Wait for the helper's answer                                             |
| 250ms            | `path::PUNCH_INTERVAL`               | Interval between punch rounds                                            |
| 12               | `path::PUNCH_ROUNDS`                 | Punch rounds, which must outlast signaling plus the handshake            |
| 250ms            | `path::PUNCHED_DIAL_DELAY`           | From the punch order to dialing the punched path                         |
| 500ms            | `path::RELAY_DELAY`                  | From the punch order to dialing the relay                                |
| 3s               | `transport::DEFAULT_STALL_THRESHOLD` | Unanswered time before a stall is declared                               |
| 2s               | `transport::DEFAULT_PROBE_INTERVAL`  | Probe interval during a stall                                            |
| 20s              | `transport::DEFAULT_KEEP_ALIVE`      | Client keep-alive                                                        |
| 16MB             | `transport::DEFAULT_WINDOW`          | Flow-control window, per stream and per connection                       |
| 2s               | `upgrade::DEFAULT_ROUND_INTERVAL`    | Background probe rounds while looking for a better path                  |
| 30s              | `upgrade::DEFAULT_PUNCH_WINDOW`      | Dense background probing after establishment                             |
| 15s              | `upgrade::DEFAULT_PUNCH_RETRY`       | The slow retry after that, within RFC 4787's 30s mapping lifetime        |
| 15s              | `upgrade::DEFAULT_RELAY_KEEPALIVE`   | Re-registration at the helper, which also holds the relay's pinhole open |
| 3s               | `upgrade::DEFAULT_CONFIRM`           | Wait for `PATH_CHALLENGE` after a switch                                 |
| 3                | `upgrade::DEFAULT_MISSES`            | Unanswered rounds that mark a path dead for an idle session              |
| 30s              | `upgrade::DEFAULT_HELPER_GRACE`      | Relay and helper lifetime after an upgrade                               |
| 10s              | `upgrade::DEFAULT_RETRY_BACKOFF`     | Backoff per failure of a path that lost the session                      |
| 3                | `upgrade::DEFAULT_MAX_ATTEMPTS`      | Failures before such a path is retired                                   |
| 300s             | `upgrade::DEFAULT_SILENCE`           | Client silence after which the destination stops heartbeating the relay  |

### No resume protocol

A resume layer like Eternal Terminal's helps only when transport state is lost
while both session endpoints survive. Here, QUIC handles loss, outages,
rebinds, and address changes, and if either Mush process dies, ssh or sshd ends
the session, so there is nothing to resume. Spike S1 looked for networks that
kill long-lived QUIC state, which would have called for a resume layer, and
found none.

### Fallback

If no QUIC handshake completes within the establishment budget, the client warns
on stderr and falls back to plain TCP to the destination's ssh port, through
the jump as an `ssh -W`-style bridge if there is one. The session works as plain
ssh, and the unused server exits at its bootstrap timeout. `--no-fallback`
makes this an error. Fallback keeps Mush from ever being worse than ssh, so it
can be a host's default transport.

## Jump hosts and NAT traversal

The jump host carries the bootstrap ssh as `ssh -J` would. When the destination
is not directly reachable over UDP, the jump host also helps build a UDP path:
reflexive address discovery, hole-punch coordination, and a relay of last
resort, as in ICE and Tailscale but using only hosts the user can ssh to. This
machinery only proposes paths; the pinned handshake decides whether one is used.

### Bootstrap through the jump

A `ProxyJump` in `~/.ssh/config` applies to the bootstrap ssh, and the wrapper
forwards `-J`. ssh rejects `ProxyJump` together with `ProxyCommand`, so pure
`ProxyCommand` configurations give the jump to Mush:

```text
Host dc-*
  ProxyCommand mush connect -J bastion %r %h %p
```

Chains (`-J a,b`) work the same way. The helper runs on the last hop, next to
the destination, because the relay depends on that position.

### The jump helper

The client opens a second ssh channel to the jump host, running
`mush jump-helper`. It reuses any mux master and runs in BatchMode, so a bastion
that would prompt fails fast instead of competing for the tty. The helper binds
a UDP socket and serves the session named by its nonce with:

-   Reflection: STUN binding responses with the probe's observed source address.
-   Rendezvous: an address both peers can reach.
-   Relay: forwarding between the peers' flows, following each peer's latest
    address so a roaming client keeps its relay.

The nonce only names the session. The client also generates a per-session
secret and sends it over its two ssh channels. Every probe the helper acts on
carries a full-length `MESSAGE-INTEGRITY-SHA256` (RFC 8489) under that secret,
and the helper signs its replies; the SHA-1 attribute is refused. The secret
travels only over ssh, so an off-path attacker cannot forge probes. Two more
rules limit replay. The signed data names the service a probe is for, so probes
a peer sends to its candidates cannot be replayed to the helper as
registrations. And a transaction the helper has already registered cannot move
a peer to another address. Peers use a fresh transaction each round, so a
captured probe works only within its own round. What remains is an attacker who
can outrun or suppress the original datagram, who could deny the relay anyway.

The helper detaches and serves the session until it ends, unless `--retain`
bounds it. Once its ssh channel is gone, for example because the client roamed
off the address its ssh used, the helper stays only while the destination
heartbeats the relay, which it does only while the relay is still a possible
path and the client is still sending. Both conditions are needed: a Mush
connection has no idle timeout, and the bastion is someone else's machine.

### Signaling

The client passes candidates between the destination and the helper as
`key=value` lines on its two ssh channels. Those channels are reliable, ordered,
private, and authenticated, so ICE's offer/answer, role conflict, and trickle
machinery are unnecessary.

### Path establishment

The kinds of path, in order of preference:

| Path     | Uses                                         | Requires                         | Without a helper   |
| -------- | -------------------------------------------- | -------------------------------- | ------------------ |
| direct   | The destination's own addresses              | Reachable UDP                    | Unaffected         |
| punched  | Reflexive addresses, opened by hole punching | A reflector, and compatible NATs | Reverse punch only |
| relayed  | Forwarding through the helper                | Outbound UDP to the helper       | Unavailable        |
| fallback | TCP through the jump                         | Nothing beyond `ssh -J`          | Unaffected         |

The direct path uses the destination's interface and `$SSH_CONNECTION`
addresses and the client's own DNS resolution of it. Punching needs a
reflector, the helper or `--stun`, wherever NAT hides an address, and fails
against a symmetric destination, or a symmetric client with a port-filtering
destination. Without a helper, only a reverse punch toward addresses the client
can name itself remains (see
[Degrading without the helper](#degrading-without-the-helper)).

Both peers probe from their QUIC socket, so the NAT mappings the probes create
are the ones the session uses. Each side sends paced probes to the other's
candidates and to the helper, then the client dials every candidate and keeps
the first handshake that authenticates. Addresses are filtered and capped
wherever they enter, since a signaled candidate is no more trustworthy than a
connect-line hint.

The relay covers locked-down networks and symmetric NATs: traffic between the
jump host and the destination is far more likely to be allowed than traffic from
the internet, and signaling gives the helper exact addresses. The kinds of path
are tried in stages, so the report of which one won is exact. The one overlap is
the relay, dialed while the punch is still running, because starting on the
relay and upgrading later beats waiting for a punch that may fail.

### Upgrading from relay to direct

A QUIC server's address must stay fixed, but a client may move. Mush keeps path
changes on the client, in a path manager that implements quinn's
`AsyncUdpSocket`: quinn talks to a stable virtual peer address, and the manager
maps each send to the current real path, so a switch looks like an ordinary
client migration to the destination. This is iroh's magicsock approach on a
small scale: start on the relay, keep punching, and migrate once a direct path
is proven. The manager also takes STUN and punch probes off the socket before
quinn sees them.

The manager tells virtual and real paths apart by address, so virtual addresses
come from blocks nothing routes, `240.0.0.0/8` and `fd00::/8`, with a random
suffix per session. A send into the block that no path claims is dropped, so
they never leave the process. The destination and the jump helper bind IPv4
only, so an IPv6-only destination has no UDP path and falls back to TCP. Each
dialed candidate gets its own virtual address, so racing candidates are separate
connections, and the winner's address stays fixed for the session. A switch
changes one index under the lock each send already takes. Nothing is queued, so
nothing is lost or duplicated; packets in flight on the old path arrive
reordered, which QUIC tolerates from any migration.

A candidate path is adopted only after two proofs:

-   A signed probe round trip to that address, answered from the destination's
    session socket, which shows the exact mappings the session would use carry
    traffic in both directions now.
-   QUIC path validation. After the switch, the destination must send a
    `PATH_CHALLENGE` to the new address within a few seconds, counted after
    decryption, or the client switches back. The client sends something
    ack-eliciting as it switches, so idle sessions are challenged too. This
    catches middleboxes that pass small STUN packets but drop full-size QUIC
    packets.

The relay and helper stay available for a grace period after an upgrade, and a
direct path that stops working hands the session back. ACKs judge liveness on a
busy session and probes on an idle one, since a few lost probes are common at
loss rates QUIC tolerates. A path that fails to confirm backs off and is
retired after a few failures, so a path that answers probes but drops session
traffic cannot flap the session. After the grace period the helper is released,
and later failures are ordinary roaming.

While the relay is in use, both peers re-register with the helper periodically,
and the client also re-registers after each rebind. The relay then follows a NAT
mapping that moves, and a strict NAT's pinhole in front of the relay stays open.
Heartbeats stop when the relay is no longer a possible path, or when the
destination has heard nothing from the client for several minutes.

Each session reports which kind of path carried it, which makes establishment
testable. Sessions without a jump have no path manager.

### Degrading without the helper

If `mush jump-helper` cannot run on the bastion, the client prints one stderr
line naming what was lost and races the remaining kinds of path within the same
budget. Mush never installs itself on a bastion.

Without a helper, the destination can still probe toward addresses the client
can name itself: its interface addresses; its address as the jump host sees it,
which is enough under 1:1 NAT as on cloud VMs; and with `--stun`, a
STUN-discovered address. The jump host's view of the client comes from the
helper's ready line, or from `echo $SSH_CONNECTION` over ssh when there is no
helper; on a chain, from the first hop. This covers a destination with a public
address behind a stateful firewall. A destination behind NAT has no UDP path
without a helper, unless `--stun` is used and both NATs are
endpoint-independent. When UDP clearly cannot work, the client falls back to
TCP without waiting out the budget.

### Reuse versus build

The probe format is STUN, through an existing codec. Mush does not use full ICE
(`webrtc-ice`, str0m), which handles unreliable, unauthenticated signaling
between mutually suspicious browsers. ssh-carried signaling has neither problem,
and a deterministic client-driven scheme is much less code. Spike S4 tested
this against a real NAT matrix.

## SSH integration

### Invocation modes

`~/.ssh/config` with `ProxyCommand mush connect %r %h %p` is the primary
interface. The `mush [ssh args] destination [command]` wrapper adds the
`ProxyCommand`, runs real ssh with the other arguments unchanged, and forwards
`-i`, `-J`, and `-o` to the bootstrap ssh. For hosts where `mush` is not on the
remote `PATH`, it also accepts `--ssh=`, `--server=`, and `--helper=` (equals
form only), which cannot collide with ssh's options because ssh has no `--`
options.

### What OpenSSH provides

All of the SSH connection protocol works, because OpenSSH is on both ends: PTY
and exec sessions, every forwarding type, agent forwarding, X11, sftp, scp,
rsync, git, `~` escapes, exit codes, and ControlMaster. ControlMaster is also
how Mush shares a tunnel: if the tunneled session is a mux master, later
invocations to the host use it. `mush-lab/tests/compat.rs` and `acceptance.rs`
test these over the real tunnel, against plain ssh in the same lab where the
claim is parity. X11, UNIX-socket forwarding, and `~` escapes are untested.

### Sharp edges

-   Dead-peer detection is off by default. `TCPKeepAlive` has no effect, and
    `ServerAliveInterval` and `ClientAliveInterval` default to off. If set, they
    still end a session on an outage longer than they allow, since Mush does not
    override explicit settings. A crashed server looks like an outage until the
    user gives up or an opt-in limit trips: `--idle-timeout` on the client,
    `--retain` on the server.
-   Pure `ProxyCommand` mode passes only `%r`, `%h`, and `%p` to the bootstrap
    ssh. Hosts that need flags such as `-i` need them in `~/.ssh/config`,
    through the wrapper, or in `--ssh`.
-   A cold connection authenticates twice, for bootstrap and for the tunneled
    session: two signatures with key authentication, or two prompts with a
    password or 2FA. A session that joins a master authenticates nothing.
    Granting server-side authorization to skip the second is rejected for the
    security surface it adds, and a persistent server, the other way to avoid
    it, is not planned.
-   An existing plain-TCP ControlMaster for the same host silently bypasses
    `ProxyCommand`. Give Mush hosts their own `ControlPath`.
-   A master whose session fell back to TCP carries every session that joins it
    over TCP until the master exits, even after a move to a network where UDP
    works. `--no-fallback` makes the fallback an error instead.
-   A server behind port-forwarding NAT with no jump host needs the UDP range
    forwarded. A remapped ssh port needs
    `--server 'mush server bootstrap --target 22'`; without it, the server
    reports the unreachable port as the connection's close reason.

## Security analysis

Every Mush credential is ephemeral, per session, and exchanged over the
authenticated bootstrap ssh channel. Mush makes no authentication or
authorization decisions, stores no secrets, and runs no long-lived listeners.
Host trust stays in known_hosts, and user authentication stays in sshd. The
server runs unprivileged as the user, accepts one connection with one pinned
key, completes no handshake for anyone else, and exits if unused.

The QUIC handshake is TLS 1.3 from rustls with RFC 7250 raw public keys, so
there is no X.509. Each side checks that the hash of the peer's ephemeral key
matches the one received during bootstrap. All cryptography (handshake, AEAD,
key updates, anti-amplification, path validation) comes from rustls and quinn,
and helper probes use RFC 8489 short-term credentials from the STUN codec.

The custom code decides which peers to trust and how much traffic to send. It
is thousands of lines in seven areas, all in `crates/mush-core/src`, and a
review should be scoped by this list of what each must get right:

-   Pinning verifiers (`pinning.rs`; inline tests and `tests/handshake.rs`): one
    SHA-256 digest comparison each, and refusing any signature scheme but the
    advertised one.
-   Bootstrap and signal parsers (`bootstrap.rs`, `channel.rs`; fuzz targets
    `bootstrap_lines`, `connect_scanner`, `line_channel`, `line_channel_send`):
    bounded consumption of attacker-influenced login output.
-   STUN probe layer (`stun.rs`; fuzz target `stun_probe` and inline tests):
    probe authenticity, meaning a full-length `MESSAGE-INTEGRITY-SHA256` and no
    other algorithm, and the signed service name.
-   Jump helper service (`helper.rs`; fuzz target `helper_service`, inline
    tests, and `tests/helper_netsim.rs`): nonce admission, reflection budgets,
    the registration and replay rules, the relay's byte budget, and forwarding
    only to signed sources.
-   Upgrade policy (`upgrade.rs`; inline tests and `tests/upgrade_netsim.rs`):
    probe budgets, two-proof confirmation, and backoff, which bound the traffic
    a candidate path can attract.
-   Martian filter and path table (`path.rs`, `server.rs`, `traversal.rs`;
    inline tests and `tests/hostile_candidates.rs`): which addresses this host
    sends to, and which sources quinn parses.
-   Shared socket (`traversal.rs`; inline tests and `tests/establish.rs`): what
    the platform may say about a path.

The shared socket ignores ICMP unreachable reports, which are unauthenticated:
it disables them where the kernel allows and absorbs the rest, including the
pending report the kernel attaches to the next datagram sent. One that reached
the QUIC stack would end the endpoint and every session on it, which would give
any off-path sender a one-packet kill and end the session on every roam, since
the old path answers unreachable. Paths are proven by QUIC path validation and
abandoned after silence.

Traversal is outside the security boundary: it proposes paths, and the pinned
handshake decides whether a path reaches the right peer. The helper acts only on
probes signed with the session secret, which reaches the peers only over ssh,
and forwards only to addresses that signed probes came from, with rate limits.
Without the signature, a forged source address would make the bastion an open
forwarder.

A hostile jump host or network can deny or degrade paths, but sees only QUIC
ciphertext around SSH ciphertext, as with `ssh -J`. A lying reflector can aim
the peers' probes at addresses it chooses, as a hostile STUN server can in ICE.
Reflexive candidates have their own smaller cap, martian addresses are refused
wherever they enter, and such an address gets only paced probes and one failing
handshake. Loopback hints are accepted only when the client's own resolution
shows the destination is this host, or, without a jump, when the name does not
resolve locally; a bastion therefore cannot make the client probe ports on the
user's workstation. On the relay, each peer probes a bounded set of candidates
once per retry interval, and an address a signed probe came from replaces the
stalest entry, so a helper cannot fill the table to block the upgrade.

One gap is accepted. The helper charges its per-source reflection budget before
checking the signature, which bounds the HMAC work a flood can cause. An
attacker who has seen a probe and can spoof its source can drain that peer's
budget, so its re-registrations are dropped and a relayed session loses its
relay. Checking signatures first for registered addresses would close this, but
would let a flood aim HMAC work at those addresses. The attacker gains only
denial of service, which that position already allows.

Traffic analysis exposure matches ssh over TCP. OpenSSH's keystroke timing
obfuscation still works, and Mush adds no padding.

## Alternatives and prior art

-   [Mosh](https://mosh.org): Mush takes its bootstrap over ssh, server detach,
    port range, and roaming behavior. Mosh itself cannot carry an arbitrary byte
    stream, since its protocol synchronizes terminal state.
-   [iroh](https://github.com/n0-computer/iroh): shows quinn sustains roaming
    connections with key-pinned TLS, and is the model for the path manager. iroh
    is built around long-lived node identities, global discovery, and standing
    relays, and magicsock cannot be separated from that, so Mush uses the
    technique but not the crate.
-   [Tailscale](https://tailscale.com/blog/how-nat-traversal-works): the NAT
    traversal techniques, rebuilt on per-session infrastructure bootstrapped
    over ssh instead of a mesh and DERP servers.
-   ICE (RFC 8445) and STUN (RFC 8489): STUN on the wire, and none of ICE's
    negotiation; see [Reuse versus build](#reuse-versus-build).
-   [quicssh](https://github.com/moul/quicssh) and
    [quicssh-rs](https://github.com/oowl/quicssh-rs): the same ssh-over-QUIC
    relay pattern and roaming benefit, but as static daemons with no bootstrap,
    no per-session credentials, and no documented tunnel authentication.
-   [Eternal Terminal](https://eternalterminal.dev): reconnecting TCP rules out
    Mosh-like roaming, and its own encryption and resume layer is the custom
    code Mush avoids.
-   Terminating SSH in Mush with russh: rejected for the reasons in
    [Relay SSH ciphertext, never terminate SSH](#relay-ssh-ciphertext-never-terminate-ssh).
-   WireGuard or another TUN-based VPN: needs root or device provisioning, roams
    only on the client side, and has a far larger blast radius than a
    per-session pipe.
-   A custom UDP protocol over Noise: would reimplement what QUIC standardizes.
-   Migrating the TCP connection itself (MPTCP, TCP_REPAIR): needs kernel
    support and privilege, and cannot take over sshd's socket without root.
-   SSH3-style reimplementation over HTTP/3: replaces the security-critical
    protocol.

## Implementation

The workspace builds one static binary, `mush`, so there is one file to copy to
each host and one version to keep in sync. Its modes are `mush <dest>`
(wrapper), `mush connect` (`ProxyCommand` mode), `mush server bootstrap`
(destination side), and `mush jump-helper`. `--server <cmd>` and
`--helper <cmd>` follow Mosh's convention for hosts where `mush` is not on the
non-interactive `PATH`. The `mush-core` library holds the protocol, the pinning
verifiers, the relay, and the traversal machinery.

The binary's direct dependencies, which with their transitive dependencies are
what a deployment trusts beyond OpenSSH:

| Crate                       | Purpose                                                                             |
| --------------------------- | ----------------------------------------------------------------------------------- |
| tokio                       | Current-thread runtime                                                              |
| quinn, rustls, aws-lc-rs    | Transport and cryptography                                                          |
| `stun-types`                | Probe wire format; its comment in `crates/mush-core/Cargo.toml` counts what it adds |
| base64                      | Connect-line and signal-line encoding                                               |
| subtle                      | Constant-time digest comparison in the pinning verifiers                            |
| clap                        | Command line                                                                        |
| anyhow, thiserror           | Errors                                                                              |
| tracing, tracing-subscriber | Diagnostics on stderr                                                               |
| libc, rustix                | fork, alarm, signal handling, and the netlink socket                                |

### Validation spikes

Four spikes tested the design before it was built out. All four held, and tests
now cover each:

-   S1, transport: a quinn tunnel survives address changes, ten-minute
    blackholes, NAT rebinds, and netem loss with `max_idle_timeout: None` alone.
    It also showed that quinn's PTO backoff makes recovery after a long outage
    arbitrarily slow, which led to the stall prober. Covered by
    `mush-core/tests/recovery_netsim.rs` and
    `mush-lab/tests/{resilience,hostile_outage}.rs`.
-   S2, performance: the measurements below.
-   S3, bootstrap: line scanning survives hostile login environments within a
    fixed output budget. Covered by `mush-core/tests/establish.rs` and the
    `bootstrap_lines`, `connect_scanner`, and `line_channel` fuzz targets.
-   S4, traversal: minimal STUN held up against a real NAT matrix. Covered by
    the punch matrix, which runs in both test tiers because nftables cannot
    express a port-preserving symmetric NAT.

Measured in August 2026 on an idle 16-core AMD Ryzen 9950X (CachyOS, kernel
7.2, release builds) in the patchbay lab, with netem loss audited per packet;
[testing.md](testing.md#performance-comparison) describes the method. Medians,
Mush against ssh over the same path and sshd:

| Path              | Metric                    | ssh           | Mush             |
| ----------------- | ------------------------- | ------------- | ---------------- |
| clean             | echo line RTT p50         | 0.017 ms      | 0.034 ms         |
| clean             | scp 512 MiB transfer-only | 1.7 GiB/s     | 1.8-2.1 GiB/s    |
| 40ms RTT          | echo line RTT p50         | 40.95 ms      | 41.33 ms         |
| 40ms RTT          | scp 64 MiB transfer-only  | 33-34 MiB/s   | 33 MiB/s         |
| 0.5% loss, 40ms   | scp 8 MiB wall (n=15)     | 12.8 s        | 14.6 s           |
| 2% loss, 40ms     | scp 4 MiB wall (n=15)     | 16.4 s        | 15.8 s           |
| clean / 40ms      | cold connect (`ssh true`) | 0.12/0.57 s   | 0.38/1.42 s      |
| 5s/10s/30s outage | restore to first byte     | 2.9/5.9/1.7 s | 0.08/0.26/0.22 s |
| 30s, client sends | restore to first byte     | 1.8 s         | 1.8 s            |

Interactive latency is within a millisecond of ssh's. Bulk throughput matches
or beats ssh on a clean path and reaches 98% at 40 ms, where OpenSSH's 2 MiB
channel window limits both. Under loss, both are loss-bound and within about 15%
of each other.

Connection setup is the cost: the bootstrap ssh and the QUIC handshake add 0.27s
to every cold connect on a clean path, and 0.84s at 40 ms. Recovery after an
outage takes at most one probe interval, whatever the outage length; shortening
it would mean probing more often on every idle session. A connection whose
in-flight window was already full when the path died is outside that bound,
because its probes cannot get past congestion control. The ssh recovery numbers
are TCP retransmission backoff, shown for context; ssh does not survive the
address changes and NAT rebinds that Mush does.

No soak test keeps a session alive for days across roams and outages. The lab's
outage tests run past quinn's default idle timeout, and the simulator covers
ten-minute outages in virtual time, but neither reaches the timescales of TLS
key updates and AEAD limits.

## Open questions

-   A client that roams loses the ssh channels it bootstrapped over, so nothing
    can tell the jump helper when the session ends, and the helper waits out its
    silence timeout. Re-establishing the helper channel after a roam would fix
    this.
-   Upgrades only move a session off the relay. Direct paths are not compared,
    so a session keeps the first one that confirmed. Ranking needs an RTT
    estimate, which the probes already carry, and a rule for when a better path
    is worth a migration.
-   IPv6 is incomplete. The client and the path manager handle both families,
    but the destination and the jump helper bind IPv4 sockets. Fixing that
    raises the question of which family to prefer when both are available.
-   No timer has a command-line option, and nobody has asked to vary one yet.
    The port range is the likeliest to be needed, since firewall rules name a
    range; Mosh has `-p` for this.
-   Off Linux, a `mush connect` killed by a signal before its session starts,
    as by the outer ssh's hangup at `ConnectTimeout`, leaves its ssh children
    running until their remote commands end. Linux's parent-death signal kills
    them. A watchdog process holding a pipe from `mush connect` could do the
    same elsewhere.
-   Every destination, and every bastion that should help with traversal, needs
    `mush` installed, built for its platform and speaking the client's protocol
    version. The client could install it instead: write a POSIX sh script to a
    remote `sh` that starts the host's `mush` if its `--version` reports that
    protocol, and otherwise takes a copy from the client over the same channel
    and keeps it in the host's XDG cache. The script would have to exchange
    lines with the client in lockstep, so that no shell's input buffering reads
    past it, which adds round trips before `MUSH HELLO`. A home shared over NFS
    may hold a copy another host is running, a `noexec` home cannot run a copy
    at all, and an `authorized_keys` forced command bypasses the script. What
    runs on remote hosts would become another area of the security analysis.
-   A copy must be built for the host's platform, so the client's own binary
    serves only hosts of the client's platform. The client could download the
    host's binary from a GitHub release and send it. That needs CI to publish
    releases, an HTTPS client in `mush` (ureq over quinn's rustls adds six
    crates), and a choice for development builds, which have no release and
    whose protocol the latest release may not speak. Having the remote host
    download its own copy instead trusts that host's network, where a proxy
    that intercepts TLS could substitute a binary, and fails on hosts with no
    internet access.
-   Checking a downloaded copy against its release's `SHA256SUMS` catches
    corruption, but not a tampered release or a proxy on the client's network
    that intercepts TLS. CI could sign each `SHA256SUMS` with a key held as a
    repository secret, and every build could carry the public key, at the cost
    of managing the key. Carrying the checksums themselves would take two builds
    per release, since no binary can hold its own checksum.
-   A destination's first copy, about 8 MiB, would upload while the outer ssh
    waits for the server's banner, so `ConnectTimeout` bounds it. A copy cut
    short would start over on the next session unless partial copies were kept.
