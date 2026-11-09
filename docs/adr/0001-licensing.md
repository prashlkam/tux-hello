# ADR 0001: Licensing

- **Status:** Proposed. Needs the maintainer's confirmation (PLAN.md §19, question 1).
- **Date:** 2026-11-09

## Context

Tux Hello has two kinds of code:

1. **Code that runs inside other projects' processes or is linked by them.** This is the PAM module (loaded into `sudo`, greeters and screen lockers), the client crate, and the protocol crate. Greeter and locker authors might also link the client directly to show richer UI.
2. **Applications.** These are the daemon, the CLI, and later the GUI and backends.

A copyleft licence on (1) would discourage the integrations we depend on, for example an MIT-licensed screen locker that wants to link the client crate. For (2), copyleft keeps improvements to the security-critical daemon public.

## Decision (proposed)

| Component | Licence |
|---|---|
| `tuxhello-proto`, `tuxhello-client`, `pam-tuxhello` | **MIT OR Apache-2.0** (Rust ecosystem convention) |
| `tuxhello-daemon`, `tuxhello-cli`, future backends and GUIs | **GPL-3.0-or-later** |
| Data files (D-Bus policy, units, PAM snippets) | MIT |

The SPDX identifiers are already set in each `Cargo.toml`. `deny.toml` allows only licences compatible with both groups.

## Consequences

- The licence texts (`LICENSES/MIT.txt`, `LICENSES/Apache-2.0.txt`, `LICENSES/GPL-3.0-or-later.txt`) still need to be added, for example with `reuse download --all`, and SPDX headers added to source files. Then `reuse lint` can run in CI.
- If the maintainer prefers a single licence, change the `license` fields and this ADR. No code depends on the choice yet.
- Model weights have their own licences; see ADR 0005.
