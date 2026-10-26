# Mush

<!--
Part of the Mush project, under the Apache License v2.0 with LLVM
Exceptions. See /LICENSE for license information.
SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-->

[![CI](https://github.com/chandlerc/mush-shell/actions/workflows/ci.yml/badge.svg)](https://github.com/chandlerc/mush-shell/actions/workflows/ci.yml)

Mush keeps SSH sessions alive when the network drops out or changes. It
replaces only the TCP connection between an unmodified `ssh` and an unmodified
`sshd`, using QUIC over UDP.

> [!CAUTION]
>
> Mush is an alpha-quality experiment with no security review. It sits in the
> path of your SSH sessions, and `mush jump-helper` runs a UDP service on a
> bastion. Do not use it to reach machines you care about. See
> [Status](#status).

## Features

-   Every SSH feature works, including port and agent forwarding, sftp,
    ControlMaster, and tools that run `ssh` such as git and rsync, because Mush
    relays SSH's encrypted byte stream without interpreting it.
    [Mosh](https://mosh.org/) synchronizes terminal state instead, which serves
    only interactive terminals.
-   Sessions survive a laptop sleeping, Wi-Fi handing off to cellular, a new
    address, NAT rebinding, and long outages. There is no local echo: during an
    outage the session freezes as it would with `ssh`, then resumes.
-   Authentication and encryption stay SSH's own: Mush starts its server by
    running real `ssh`, and carries only SSH ciphertext.
-   With `-J`, Mush authenticates through the bastion as `ssh -J` does, then
    moves traffic to the most direct UDP path, punching through NAT or relaying
    with help from the bastion.
-   When UDP cannot get through, sessions fall back to TCP with a warning.
-   Each session starts its own server as the user, so there are no daemons and
    nothing needs root.

## Install

There are no prebuilt binaries or packages yet. Build and install with Cargo:

```sh
cargo install --locked --git https://github.com/chandlerc/mush-shell mush
```

Install `mush` on the client, on each destination, and on each bastion that
should help with NAT traversal. For a static Linux binary to copy to other
hosts, build for musl, which needs a musl C compiler such as Debian's
`musl-tools`:

```sh
rustup target add x86_64-unknown-linux-musl
cargo install --locked --git https://github.com/chandlerc/mush-shell \
  --target x86_64-unknown-linux-musl mush
```

On 64-bit Arm, substitute `aarch64` for `x86_64`.

If `mush` is not on a remote host's non-interactive `PATH`, name it with
`--server '/opt/mush/mush server bootstrap'` or
`--helper '/opt/mush/mush jump-helper'`.

## Usage

To try Mush, run `mush` where you would run `ssh`. It takes ssh's arguments,
adds a `ProxyCommand` that carries the connection over Mush, and runs the real
`ssh`, with no change to your `~/.ssh/config`:

```sh
mush user@host
mush user@host uptime
mush -J bastion user@host
```

To use Mush for `ssh` and every tool that runs it, such as git and rsync, add a
block for its hosts to `~/.ssh/config`. Put it above any `Host *` block, since
ssh uses the first value it finds for each option:

```text
Host dev-*
  ProxyCommand mush connect %r %h %p
  ControlMaster auto
  ControlPath ~/.ssh/mush-%C
  ControlPersist 10m
```

The `Control` lines let later sessions to a host share the first one's Mush
connection without logging in again. Plain `ssh` must not use that
`ControlPath`: ssh hands a session to any master listening there without running
the `ProxyCommand`, so a plain master would carry it over TCP.

ssh does not allow `ProxyJump` with `ProxyCommand`, so give the jump host to
Mush instead: `ProxyCommand mush connect -J bastion %r %h %p`.

The destination, and any bastion running the helper, needs a UDP port in
60000-61000 reachable from the client. Sessions wait for a lost peer
indefinitely; `--idle-timeout` and `--retain` bound that. `mush connect --help`
lists every option.

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
`sshd` over loopback. [docs/design.md](docs/design.md) has the design, and
[docs/testing.md](docs/testing.md) the tests, which run real OpenSSH in a
network lab with NAT and packet loss.

## Status

-   Nobody has reviewed Mush's security. It stays out of plaintext, credentials,
    and authorization, but decides which peers to trust and how much traffic to
    send; the [security analysis](docs/design.md#security-analysis) lists that
    code.
-   `mush jump-helper` accepts UDP from anywhere and reflects and relays
    traffic. It is rate-limited, authenticated per session, and fuzzed, and
    still the component most likely to hurt you.
-   The command line and wire protocol will change without notice.
-   Only Linux is tested on real networks; CI also runs the other tests on
    macOS, where Mush reacts more slowly to network changes. Windows is
    unsupported.
-   Sessions to IPv6-only destinations fall back to TCP, and the UDP port range
    is fixed.

## Contributing

Bug reports, patches, and above all adversarial review are welcome; see
[CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities as
[SECURITY.md](SECURITY.md) describes.

## License

Mush is under the Apache License v2.0 with LLVM Exceptions. See
[LICENSE](LICENSE).
