# ADR 0008: FIDO2 security-key backend

- **Status:** Accepted (implemented in Phase 1, milestone 3)
- **Date:** 2026-11-09
- **Builds on:** [ADR 0003](0003-fido2-binding.md), which chose libfido2.

## Design

```
KeyBackend ──► Authenticator (trait, blocking)
   │              ├── LibFido2          real keys: hand-written FFI to libfido2 ≥ 1.13
   │              └── SoftAuthenticator test-only software key (stub-backend feature)
   └── verify_assertion()  ← all security checks happen here, in Rust
```

### Binding

- **Hand-written FFI for 35 libfido2 functions** (`key/fido2.rs`). We found no maintained `-sys` crate worth an extra dependency for this surface.
- **Linking:** to the distro's `libfido2.so`. It is a default Cargo feature, `fido2`.
- **Building without it:** `--no-default-features` builds without security-key support (PIN only).

### Verification: we don't trust the device library's answer

For each assertion, `verify_assertion` checks:

1. the credential id is one the user enrolled;
2. `rpIdHash == SHA-256(rp_id)`, so assertions for another relying party are rejected;
3. the **UP** flag is set, and **UV** too when `[key] require_uv = true`;
4. the signature over `authData ‖ clientDataHash`, using the stored public key (ES256 via `p256`, Ed25519 via `ed25519-dalek`), with a fresh random 32-byte challenge every time, so replays fail;
5. the **signature counter goes up**. A counter that goes backwards is rejected and logged as a "possible cloned key". Keys that always report 0 (no counter) are allowed.

These checks are unit-tested against a software authenticator that signs with real keys, including tampered signatures, replayed challenges, a wrong RP, missing flags and counter regression.

### Credentials and records

- **Non-resident ES256 credentials**, RP id `pam://tuxhello` (`[key] rp_id`), with a random user handle. Nothing personal is stored on the key.
- **One encrypted store record per key** (`key/<id>`): label, RP id, algorithm, credential id, public key, signature counter, product name and creation time.
- **Multiple keys per user.** The CLI suggests enrolling a backup key.

### Assurance and interaction

| Config | Interactive? | Assurance |
|---|---|---|
| `require_uv = false` (default): touch only | no; runs in parallel with other automatic methods | 3 |
| `require_uv = true`: the key's PIN or built-in biometric | yes; the key PIN is asked through the PAM conversation | 4 |

### Cancellation

- Device calls block (waiting for a touch), so they run on tokio's blocking pool.
- If the session ends (policy timeout, PAM timeout, cancel, or another method succeeding), dropping the future triggers a `CancelToken`. That calls `fido_dev_cancel()` from another thread, which libfido2 supports, so the key stops blinking at once.
- The hook is removed under a mutex before the device is freed.
- The integration suite checks this: a key that is never touched is cancelled when the PAM module times out.

### Device access

- **udev:** `data/udev/70-tuxhello-fido.rules` gives the `tuxhello` group access to every hidraw node that systemd's `fido_id` marks as `ID_FIDO_TOKEN=1`, whatever the vendor.
- **systemd:** the unit replaces `PrivateDevices=yes` with `DevicePolicy=closed` + `DeviceAllow=char-hidraw rw`, and allows `AF_NETLINK` for libudev enumeration.
- **eudev/mdev systems** need a vendor-ID rule instead (documented in the rule file).

## Testing

- **Containers:** rootless podman can't create virtual HID devices (`/dev/uhid` needs root on the host). So the integration suite uses the **software authenticator** (`[stub] soft_key_dir`), driven through the real daemon, CLI and PAM stack. It covers:
  - enrolment;
  - login;
  - an unplugged key;
  - a foreign key;
  - a cloned key;
  - an untouched key being cancelled;
  - the key + PIN two-factor policy;
  - a key PIN with UV.
- **libfido2 itself** is covered by an FFI round trip (device enumeration) in unit tests.
- **Real-key testing is still to do:** enrolment and login with a physical key (YubiKey, SoloKey, Nitrokey) on real hardware.

## Not done yet

- Importing `pam_u2f` key mappings: needs a careful check of pam_u2f's on-disk public-key format, and its per-host RP id (`pam://$HOSTNAME`).
- `hmac-secret`, for keyring escrow (Phase 4).
- Waiting for a key to be plugged in after the prompt appears. Today a key must be present when authentication starts; otherwise the method is skipped.

## Addendum (2026-11-12): pam_u2f import and per-record relying-party ids

`tuxhello import pam-u2f` reads a pam_u2f key file (`~/.config/Yubico/u2f_keys` or `/etc/u2f_mappings`) and stores each credential as a normal key record.

- Both formats are read: `KeyHandle,PublicKey,CoseType,Options` (pam_u2f 1.1+) and the older `KeyHandle,HexPublicKey`. ES256 and EdDSA are imported; RS256 and resident credentials (`*`, no key handle) are reported and skipped.
- A credential only answers for the relying-party id it was created for. pam_u2f used its `origin` (`pam://<hostname>` by default), so that id is stored in the record (`--origin` overrides the default). During authentication the key is asked once per distinct id among the user's records; a key that holds none of a group's credentials says so without waiting for a touch.
- The import cannot be checked without the key present. If the origin is wrong the key is simply "not recognised"; `tuxhello test` shows that at once.
- pam_u2f's `+pin`/`+verification` options are not carried over per credential: user verification is one setting for all keys (`[key] require_uv`). The import says so when a credential had them.
- The test authenticator now binds credentials to their relying-party id, as real keys do, so a wrong id fails in tests as it would on hardware.
