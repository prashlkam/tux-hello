# ADR 0001: Licensing

- **Status:** Accepted. Decided by the maintainer on 2026-11-12 (PLAN.md §19, question 1).
- **Date:** 2026-11-09, revised 2026-11-12

## Context

Tux Hello has two kinds of code:

1. **Code that runs inside other projects' processes or is linked by them.** This is the PAM module (loaded into `sudo`, greeters and screen lockers), the client crate, and the protocol crate. Greeter and locker authors might also link the client directly to show richer UI.
2. **Applications.** These are the daemon, the CLI, and later the GUI and backends.

The first draft of this ADR proposed a split: MIT OR Apache-2.0 for (1) so that permissively licensed lockers could link the client crate, and GPL-3.0-or-later for (2).

## Decision

**The whole project is licensed under `GPL-3.0-or-later`**: every crate, the data files (D-Bus policy, units, PAM snippets) and the scripts.

A single licence is simpler to explain, package and audit, and it keeps improvements to all of the security-critical code public, including the PAM module.

## Consequences

- Every crate's `Cargo.toml` and `meson.build` carry `GPL-3.0-or-later`. The licence text is in `LICENSE` at the repository root.
- `deny.toml` allows only GPL-3.0-compatible dependency licences.
- **Linking the client or protocol crate makes the combined work GPL.** A greeter or locker under a GPL-incompatible licence cannot link `tuxhello-client`. It does not need to: the supported integration points are PAM (the consumer only talks to libpam) and the D-Bus API (`org.tuxhello.Auth1`), and neither involves linking our code. If this turns out to block an integration we want, the copyright holders can relicense those crates or add an exception later; that gets harder once there are outside contributors, so revisit before accepting large external contributions to those crates.
- The PAM module is loaded by libpam into programs under other licences (`sudo`, greeters, lockers). This is the normal arrangement for GPL PAM modules, for example `pam_fprintd`.
- Still to do: SPDX headers in source files, then `reuse lint` in CI.
- Model weights have their own licences; see ADR 0005.
