#!/bin/bash
# Runs inside a test container (see scripts/podman-test.sh). The source tree is
# mounted read-only at /src; build output goes to the /target volume.
set -euo pipefail

export CARGO_TARGET_DIR=/target
export CARGO_HOME=/cargo-home
cd /src

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "toolchain: $(rustc --version)"

step "system bus"
mkdir -p /run/dbus
dbus-uuidgen --ensure
rm -f /run/dbus/pid
dbus-daemon --system --fork

step "build (stub backend enabled)"
cargo build --workspace --features tuxhello-daemon/stub-backend

step "unit tests"
cargo test --workspace --all-features

step "integration: unprivileged"
id thdev >/dev/null 2>&1 || useradd --create-home thdev
runuser -u thdev -- tests/integration/run-unprivileged.sh /target/debug

step "integration: root, real system bus"
tests/integration/pam-spike.sh /target/debug/tuxhellod /target/debug/libpam_tuxhello.so /target/debug/tuxhello

step "all container tests passed"
