# Security policy

<!--
Part of the Mush project, under the Apache License v2.0 with LLVM
Exceptions. See /LICENSE for license information.
SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-->

Mush is alpha software with no security review; see the
[README](README.md#status).

## Reporting a vulnerability

Report vulnerabilities through
<https://github.com/chandlerc/mush-shell/security/advisories/new>. You will get
a response within two weeks, and valid issues are coordinated and disclosed
through GitHub. If you hear nothing, email
[Chandler Carruth](mailto:chandlerc@gmail.com).

## Scope

Mush relays SSH ciphertext and never terminates SSH, so it has no access to
session keys, plaintext, credentials, or authorization decisions. The
[security analysis](docs/design.md#security-analysis) covers what that does and
does not protect. In scope:

-   Key pinning (`crates/mush-core/src/pinning.rs`): anything that lets a QUIC
    connection succeed with a key the bootstrap ssh channel did not name.
-   The parsers of untrusted input: the bootstrap line protocol, the traversal
    probe format, and the jump helper's datagram handling.
-   `mush jump-helper`, the only network-facing service: traffic amplification,
    unauthenticated reflection, and relaying for unauthorized peers.
-   Anything that makes Mush fall back to plain TCP, or to a worse traversal
    path, without telling the user.

Report vulnerabilities in OpenSSH, QUIC, or rustls upstream, unless Mush's use
of them causes the problem.
