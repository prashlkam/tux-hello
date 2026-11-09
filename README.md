# Tux Hello

Windows Hello–style sign-in for Linux, with a PIN, face, fingerprint, voice or FIDO2 security key, on any desktop environment and distribution. The design is in [PLAN.md](PLAN.md).

> **Status: Phase 1 in progress.** The PAM module, daemon, policy engine, encrypted store, a **software PIN** and **FIDO2 security keys** work end to end and are tested on Arch, Debian and Fedora. Fingerprints, the TPM-backed PIN and the safe PAM setup tool are next. Not ready for daily use yet.

## Using the CLI

```sh
sudo tuxhello enroll pin          # set your PIN (sudo verifies your password)
sudo tuxhello enroll key --label yubikey   # register a FIDO2/U2F key (touch it)
sudo tuxhello enroll key --label backup    # ...and a backup key
tuxhello list                     # what you have enrolled
tuxhello policy sudo              # what a PAM service will accept from you
tuxhello test --service sudo      # try a real authentication, without PAM
tuxhello delete pin               # remove your PIN
tuxhello delete key backup        # remove one key
tuxhello status                   # daemon, store and methods
```

The policy lives in `/etc/tuxhello/policy.d/*.toml`; see `crates/tuxhello-policy/src/lib.rs` for the format and the built-in defaults. `systemctl reload`, or sending SIGHUP to `tuxhellod`, re-reads it.

## Layout

| Path | What |
|---|---|
| `crates/tuxhello-proto` | Bus names, session states, error names (no dependencies) |
| `crates/tuxhello-client` | Blocking libdbus client, used by the PAM module and the CLI |
| `crates/tuxhello-policy` | Policy files: classes, services, groups, users, any/all requirements |
| `crates/tuxhello-store` | Encrypted per-user record store (AES-256-GCM) |
| `crates/pam-tuxhello` | `pam_tuxhello.so` |
| `crates/tuxhello-daemon` | `tuxhellod`, the system daemon (zbus/tokio) |
| `crates/tuxhello-cli` | The `tuxhello` CLI |
| `data/` | D-Bus policy and activation file, systemd/OpenRC/sysusers/tmpfiles, example config |
| `tests/integration/` | End-to-end PAM tests (real libpam, real system bus) |
| `docs/adr/` | Architecture decision records |
| `docs/threat-model.md` | Threat model v1 |

## Building

You need Rust ≥ 1.85, plus the libdbus and libpam development files and `pkg-config`.

```sh
# Arch
sudo pacman -S --needed rust pkgconf dbus pam libfido2
# Debian/Ubuntu
sudo apt install cargo rustc pkg-config libdbus-1-dev libpam0g-dev libfido2-dev
# Fedora
sudo dnf install cargo rust pkgconf-pkg-config dbus-devel pam-devel libfido2-devel

cargo build --workspace
cargo test --workspace --all-features
```

To build and install with system paths (for packagers):

```sh
meson setup build --prefix=/usr --buildtype=release
meson compile -C build
DESTDIR=$PWD/stage meson install -C build
```

## Trying it without root (session bus)

```sh
cargo build --workspace --features tuxhello-daemon/stub-backend
printf '[stub]\nenabled = true\noutcome = "success"\n' > /tmp/th.toml
target/debug/tuxhellod --session-bus --config /tmp/th.toml &
target/debug/tuxhello --session-bus status
target/debug/tuxhello --session-bus test
```

## Testing in containers (podman)

`scripts/podman-test.sh` builds a development image for each distro and runs every test inside it: unit tests, the no-root integration test, and the root integration test against a real system bus. Rootless podman works fine. All PAM and D-Bus changes happen inside the throwaway container, never on the host.

```sh
scripts/podman-test.sh all            # arch, debian (rustc = MSRV) and fedora
scripts/podman-test.sh fedora --shell # interactive shell with the source at /src
scripts/podman-test.sh debian --rebuild
```

The images (`containers/Containerfile.*`) already include libfido2, tpm2-tss and swtpm for Phase 1. Cargo caches live in podman volumes named `tuxhello-*`.

## End-to-end PAM test without root

`tests/integration/run-unprivileged.sh` runs the real PAM path with a private `dbus-daemon` standing in for the system bus. It reads PAM services from a temporary directory (`pam_start_confdir`, Linux-PAM ≥ 1.4), installs nothing and needs no root, so it is safe to run on your own machine.

```sh
cargo build --workspace --features tuxhello-daemon/stub-backend
tests/integration/run-unprivileged.sh
```

## End-to-end PAM test as root (disposable VM or container only)

`tests/integration/pam-spike.sh` installs the module, two test PAM services, the D-Bus policy and two test users. It then checks success, failure, unavailable, not-enrolled, timeout, a daemon crash in mid-session, remote-host refusal and cross-user denial, and that every non-success case falls through to the next PAM module.

```sh
cargo build --workspace --features tuxhello-daemon/stub-backend
sudo tests/integration/pam-spike.sh target/debug/tuxhellod target/debug/libpam_tuxhello.so target/debug/tuxhello
```

CI runs this on an Ubuntu runner and in Arch, Debian and Fedora containers (`.github/workflows/ci.yml`).

## Licence

The proposal is in [ADR 0001](docs/adr/0001-licensing.md): MIT OR Apache-2.0 for the PAM module, client and protocol crates, and GPL-3.0-or-later for the daemon and applications. It is not final yet.
