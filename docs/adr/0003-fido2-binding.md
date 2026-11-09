# ADR 0003: FIDO2 library

- **Status:** Accepted. The crate-level detail will be revisited at the start of Phase 1.
- **Date:** 2026-11-09

## Options

| Option | Licence | Notes |
|---|---|---|
| **libfido2** (Yubico, C) via FFI | BSD-2-Clause | Used by `pam_u2f`, `systemd-cryptenroll`, OpenSSH and sssd. Packaged on every target distro. Supports USB HID, NFC (PC/SC), hmac-secret, credProtect, resident keys, UV/PIN, and bio-enrolment. Very widely deployed. |
| `ctap-hid-fido2` (pure Rust) | MIT/Apache | No C dependency. Smaller user base; USB HID only; feature coverage needs checking (hmac-secret, NFC). |
| `authenticator` (Mozilla, Rust) | MPL-2.0 | Built for the browser use case; the API is shaped around WebAuthn in Firefox. MPL is compatible but adds a third licence. |

## Decision

Use **libfido2 through a thin FFI layer** in `backend-key`. This could be an existing `-sys` crate if a maintained one passes review, or our own `bindgen` output for the roughly 30 functions we need.

Reasons:

- It has the same failure modes and device quirks as `pam_u2f`, so users get identical behaviour. Migrating their `u2f_keys` mappings becomes straightforward.
- It provides `hmac-secret`, which keyring escrow (PLAN.md §7.3) and future LUKS unlock depend on.
- Distributions already ship and security-patch it, so we don't vendor crypto/HID code.

The FFI surface will run inside the sandboxed key backend process, not the daemon. A memory-safety bug in C code therefore stays contained (PLAN.md §4.3).

## Follow-ups (Phase 1)

- Review existing libfido2 binding crates for maintenance and soundness; if none qualify, generate our own bindings.
- Test with a virtual authenticator (`uhid`-based) in CI.
