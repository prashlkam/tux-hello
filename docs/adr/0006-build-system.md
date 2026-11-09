# ADR 0006: Build system

- **Status:** Accepted (implemented in Phase 0)
- **Date:** 2026-11-09

## Decision

- **Cargo workspace** for all Rust code. `cargo build` and `cargo test` work on their own for development.
- **Meson** is a thin outer layer used for installation (`meson.build`). It calls Cargo through `build-aux/cargo-build.sh` and installs:
  - `pam_tuxhello.so` into `<libdir>/security`. This resolves correctly to `/usr/lib/security` on Arch, `/usr/lib64/security` on Fedora and `/usr/lib/x86_64-linux-gnu/security` on Debian. It can be overridden with `-Dpam_moduledir=`.
  - `tuxhellod` into `<libexecdir>`. It is never started by hand; D-Bus activation runs it.
  - `tuxhello` into `<bindir>`.
  - The D-Bus policy and activation file into `<datadir>/dbus-1/`.
  - The systemd unit, sysusers.d and tmpfiles.d files (`-Dsystemd=auto`), or the OpenRC script (`-Dopenrc=true`).
- `-Dstub_backend=true` builds the test-only stub backend and prints a warning. Distribution packages must never set it.

## Why Meson rather than Cargo alone

Cargo has no notion of install paths, multiarch libdirs, or system integration files. Every distro packager knows Meson, and its `DESTDIR`/`--prefix` handling is standard.

## Notes

- `Cargo.lock` is committed once generated. Packagers should build with `CARGO_NET_OFFLINE=true` and a vendored tarball (`cargo vendor`). A release script will produce the tarball.
- `meson_options.txt` is used, rather than `meson.options`, so that Meson versions older than 1.1 work.
