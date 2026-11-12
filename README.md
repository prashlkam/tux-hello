# Tux Hello

Windows Hello–style sign-in for Linux, with a PIN, face, fingerprint, voice or FIDO2 security key, on any desktop environment and distribution. The design is in [PLAN.md](PLAN.md).

> **Status: Phase 1 in progress.** The PAM module, daemon, policy engine, encrypted store, a **software PIN** and **FIDO2 security keys** and **fingerprints (via fprintd)** work end to end, and `tuxhello-pam-setup` turns them on safely. All of it is tested on Arch, Debian and Fedora against their real PAM stacks. The TPM-backed PIN is next. Not ready for daily use yet.

## Using the CLI

```sh
sudo tuxhello enroll pin          # set your PIN (sudo verifies your password)
sudo tuxhello enroll key --label yubikey   # register a FIDO2/U2F key (touch it)
sudo tuxhello enroll key --label backup    # ...and a backup key
tuxhello enroll fingerprint --finger right-index-finger   # via fprintd
tuxhello list                     # what you have enrolled
tuxhello policy sudo              # what a PAM service will accept from you
tuxhello test --service sudo      # try a real authentication, without PAM
tuxhello delete pin               # remove your PIN
tuxhello delete key backup        # remove one key
tuxhello status                   # daemon, store and methods
sudo tuxhello unlock              # clear lockouts after too many failed attempts
```

After 5 wrong fingerprints in a row, biometrics are switched off for that user until a PIN or security-key login succeeds (or `sudo tuxhello unlock`). After 10 failed attempts of any kind within 5 minutes, Tux Hello steps aside for that user until the window passes. In both cases the password keeps working. Every attempt and result is written to the audit log as one JSON line (`journalctl -u tuxhellod | grep audit`). The numbers are in `[limits]` in `/etc/tuxhello/config.toml`; see [ADR 0010](docs/adr/0010-limits-and-audit-log.md).

## Turning it on for sudo, polkit and screen lockers

`tuxhello-pam-setup` edits PAM safely. It adds one marked `auth sufficient pam_tuxhello.so` line in front of each service's existing auth lines, so the password always remains as the fallback. Every change is backed up first.

```sh
sudo tuxhello-pam-setup status                 # what is enabled, possible conflicts
sudo tuxhello-pam-setup enable --dry-run       # show the exact change
sudo tuxhello-pam-setup enable                 # sudo, polkit-1 and installed screen lockers
sudo tuxhello-pam-setup enable gdm-password    # login screens only when you name them
sudo tuxhello-pam-setup disable --all          # remove it again
sudo tuxhello-pam-setup rollback               # restore the previous state from backup
sudo tuxhello-pam-setup system-wide enable     # Debian/Ubuntu: every service via pam-auth-update
```

It never touches `sshd` or shared files such as `system-auth` or `common-auth`. Services that only exist in `/usr/lib/pam.d` get an override in `/etc/pam.d`, which `disable` removes again. Keep a root shell open the first time you try it.

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
| `crates/tuxhello-pam-setup` | Safe PAM configuration: enable, disable, rollback, Debian system-wide |
| `packaging/` | Arch `PKGBUILD`, Debian `debian/`, RPM spec |
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

## Packages

`packaging/` has an Arch `PKGBUILD`, a Debian `debian/` directory and an RPM spec. All three build from the release tarball that `scripts/dist.sh` makes, which carries every crate in `vendor/`, so the builds need no network.

```sh
scripts/dist.sh                       # dist/tux-hello-<version>.tar.xz
scripts/podman-package.sh all         # build, install, test and remove on arch, debian and fedora
```

`podman-package.sh` builds each package in a container with the network switched off, installs it, lets D-Bus start the daemon, enrols a PIN, logs in through PAM with the installed module, and then removes the package with Tux Hello still enabled. Removal must leave the PAM files exactly as they were. The packages land in `dist/`.

Removing a package always takes Tux Hello out of `/etc/pam.d` first. Enrolled data in `/var/lib/tuxhello` is kept (on Debian, `apt purge` deletes it).

Nothing is published yet: there is no AUR entry, PPA or COPR, and the maintainer address in the packaging files is a placeholder.

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

The images (`containers/Containerfile.*`) include libfido2, tpm2-tss, swtpm and each distro's packaging tools. Cargo caches live in podman volumes named `tuxhello-*`.

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

Tux Hello is licensed under the GNU General Public License, version 3 or (at your option) any later version (`GPL-3.0-or-later`). The full text is in [LICENSE](LICENSE); the reasoning is in [ADR 0001](docs/adr/0001-licensing.md).
