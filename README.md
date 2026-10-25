# Mush

<!--
Part of the Mush project, under the Apache License v2.0 with LLVM
Exceptions. See /LICENSE for license information.
SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-->

Mush keeps SSH sessions alive when the network drops out or changes: a laptop
that sleeps, Wi-Fi handing off to cellular, an expired NAT mapping, a new
address. It replaces only the TCP connection between an unmodified `ssh` and an
unmodified `sshd`, using QUIC over UDP.

> [!CAUTION]
>
> Mush is an alpha-quality experiment with no security review. It sits in the
> path of your SSH sessions, and `mush jump-helper` runs a UDP service on a
> bastion. Do not use it to reach machines you care about. See
> [Status](#status).

## Why

An SSH session dies with its TCP connection, taking port forwards, agent
forwarding, and transfers in progress with it. [Mosh](https://mosh.org/) solves
this for interactive terminals by synchronizing terminal state, but gives up the
rest of SSH: forwarding, `exec`, file transfer, multiplexing, and tools that
run `ssh`, such as git and rsync.

Mush relays SSH's encrypted byte stream without interpreting it, so every SSH
feature works. It has no local echo: during an outage the session freezes as it
would with `ssh`, then resumes.

## How it works

```text
client host                                    server host
-----------                                    -----------
ssh (unmodified)                               sshd (unmodified)
  |  stdio (ProxyCommand)                           ^  TCP 127.0.0.1:22
  v                                                 |
mush connect  <=== QUIC over UDP (quinn) ===>  mush server
```

`ssh` hands its transport bytes to `mush connect` through a `ProxyCommand`, and
Mush carries them over QUIC to a per-session `mush server` that relays them to
`sshd` over loopback. Mush starts that server by running real `ssh`, so
authentication works as before, and it only ever sees SSH ciphertext. With
`-J`, it authenticates through the bastion as `ssh -J` does, then moves traffic
to the most direct UDP path available. [docs/design.md](docs/design.md) has the
details.

## Status

-   There has been no security review of any kind. Mush stays out of plaintext,
    credentials, and authorization, but the code that decides which peers to
    trust and how much traffic to send spans seven areas, listed in the
    [security analysis](docs/design.md#security-analysis).
-   `mush jump-helper` accepts UDP from anywhere and reflects and relays
    traffic. It is rate-limited, authenticated per session, and fuzzed, and
    still the component most likely to hurt you.
-   Only the author has tested the threat model.
-   The command line and wire protocol will change without notice.
-   Only Linux is tested on real networks; CI also runs the other tests on
    macOS. On systems other than Linux, Mush reacts more slowly to network
    changes. Other Unix systems should build. Windows is unsupported.
-   IPv6 is incomplete: sessions to IPv6-only destinations fall back to TCP.
-   There are no packages, and the UDP port range is fixed.

The tests run shells, port and dynamic forwarding, agent forwarding,
ControlMaster, sftp, rsync, and git over Mush against real OpenSSH, in a network
lab with real NAT and packet loss. Sessions roam across uplinks, survive NAT
rebinds, and resume after outages that would kill TCP. That shows Mush works,
not that it is safe. Security review is what the project needs most; see
[SECURITY.md](SECURITY.md).

## Install

There are no prebuilt binaries. On Linux, build a static binary with:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl -p mush
```

On 64-bit Arm, substitute `aarch64` for `x86_64`. This needs a C compiler that
targets musl: `musl-tools` on Debian and Ubuntu, `musl` on Arch. Without one,
the build fails with `failed to find tool "x86_64-linux-musl-gcc"`. The binary
runs on other machines, so do not build it with `-C target-cpu=native`.

The result is an 8 MiB executable with no runtime dependencies. On macOS,
`cargo build --release -p mush` builds one that depends only on the system
libraries. Copy it to the client, to each destination, and to each bastion that
should help with traversal. If `mush` is not on a remote host's non-interactive
`PATH`, pass its location with `--server '/opt/mush/mush server bootstrap'` or
`--helper '/opt/mush/mush jump-helper'`.

## Use

With a `ProxyCommand` in `ssh_config`, `ssh` and every tool that runs it use
Mush:

```text
Host dev-*
  ProxyCommand mush connect %r %h %p
```

ssh does not allow `ProxyJump` with `ProxyCommand`, so give the jump host to
Mush instead: `ProxyCommand mush connect -J bastion %r %h %p`. For one-off use,
the wrapper adds the `ProxyCommand` and runs `ssh` with your arguments:
`mush user@host` or `mush -J bastion user@host`.

The destination, and any bastion running the helper, needs one UDP port in
60000-61000 reachable from the client. Otherwise a jumped session punches or
relays through the helper, and other sessions fall back to TCP with a warning;
`--no-fallback` makes that an error. `--idle-timeout` and `--retain` bound how
long a session waits for a dead peer. Both are off by default so that sessions
survive long outages. `mush connect --help` covers the other options.

## Contributing

Bug reports, patches, and above all adversarial review are welcome; see
[CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities as
[SECURITY.md](SECURITY.md) describes.

## License

Mush is under the Apache License v2.0 with LLVM Exceptions. See
[LICENSE](LICENSE).
