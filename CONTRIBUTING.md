# Contributing

<!--
Part of the Mush project, under the Apache License v2.0 with LLVM
Exceptions. See /LICENSE for license information.
SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-->

<!-- toc -->

## Table of contents

-   [Overview](#overview)
-   [What helps most](#what-helps-most)
-   [Standards](#standards)
-   [AI-assisted contributions](#ai-assisted-contributions)
-   [Style](#style)
-   [Building and testing](#building-and-testing)
-   [Pull requests](#pull-requests)
-   [License](#license)
-   [Acknowledgements](#acknowledgements)

<!-- tocstop -->

## Overview

Bug reports, reproductions, and patches are welcome, through
[GitHub issues](https://github.com/chandlerc/mush-shell/issues) and pull
requests. Everyone taking part follows the
[code of conduct](CODE_OF_CONDUCT.md). There is no CLA.

## What helps most

-   Bug reports that give the network topology, each end's ssh version, and
    what the session did.
-   Failing tests: `mush-netsim` for anything expressible as loss, latency, or
    NAT behavior, and the `mush-lab` lab for anything that needs real OpenSSH.
    See [docs/testing.md](docs/testing.md).
-   Compatibility reports. Anything that behaves differently over Mush than over
    plain ssh is a bug.
-   Small, self-contained fixes.

## Standards

-   Every commit builds and passes both test suites.
-   New behavior has tests. A bug fix starts with a regression test that fails
    without the fix.
-   A change to the wire protocol, key pinning, or path establishment updates
    [docs/design.md](docs/design.md) in the same pull request.
-   A change to one of the seven areas in the
    [security analysis](docs/design.md#security-analysis) updates that section.
    Fuzz a changed parser for minutes; CI's 30-second run only shows the target
    still works.
-   The relay path carries every byte of every session, so measure changes to
    it against a baseline.
-   Prefer dependencies already in the tree.

## AI-assisted contributions

AI tools are fine, and [AGENTS.md](AGENTS.md) is written for them. A
contribution must be worth more than it costs to review and maintain. Mark a
change that an AI tool largely produced with an `Assisted-by:` commit trailer,
following the
[Fedora](https://docs.fedoraproject.org/en-US/council/policy/ai-contribution-policy/)
and
[LLVM](https://llvm.org/docs/DeveloperPolicy.html#ai-generated-contributions)
policies.

## Style

`cargo fmt` formats Rust with `rustfmt.toml`'s 80 columns and two-space
indents, and `cargo clippy` lints it. [rumdl](https://github.com/rvben/rumdl)
formats Markdown. Prose follows the
[Google developer documentation style guide](https://developers.google.com/style),
except that it writes ` -- ` for an em dash, which is hard to see in a
fixed-width font. Comments describe the code as it is; commit messages describe
changes.

## Building and testing

```sh
cargo build --workspace
cargo nextest run                             # everything except the lab
cargo nextest run --profile lab -p mush-lab   # the lab suite
```

The lab suite needs unprivileged user namespaces, nftables, and OpenSSH;
[docs/testing.md](docs/testing.md) has the details. Mush builds with current
stable Rust, and the fuzz targets are a separate workspace that needs nightly.

Before sending a pull request, run `prek run -a`
([prek](https://github.com/j178/prek)), which runs the formatters and checks
license headers and whitespace. CI runs the same hooks.

## Pull requests

Pull requests target `trunk` and are merged as linear history. Prefer small
commits that each stand on their own, and keep mechanical changes such as
reformatting in separate commits. A commit message describes the problem, the
approach, and the result, with measurements for performance changes and the
issue a fix resolves. Avoid rebasing a pull request after review starts, since
that breaks review threads.

## License

Mush is under the Apache License v2.0 with LLVM Exceptions; see
[LICENSE](LICENSE). Submitting a pull request means you have the right to
contribute the work and agree to license it under these terms.

Every file except LICENSE, the lockfiles, and the fuzz seeds carries the
license header in its own comment syntax. In Markdown, it is an HTML comment
after the title:

```text
# Doc title

<!--
Part of the Mush project, under the Apache License v2.0 with LLVM
Exceptions. See /LICENSE for license information.
SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-->
```

The `check-copyright` hook enforces this and prints the expected header.

## Acknowledgements

These guidelines are based on the
[Carbon Language project's](https://github.com/carbon-language/carbon-lang/blob/trunk/CONTRIBUTING.md).
