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

step "fingerprint: polkitd + fprintd with a virtual sensor"
POLKITD=$(ls /usr/lib/polkit-1/polkitd /usr/libexec/polkitd 2>/dev/null | head -1 || true)
FPRINTD=$(ls /usr/libexec/fprintd /usr/lib/fprintd 2>/dev/null | head -1 || true)
if [ -n "$POLKITD" ] && [ -n "$FPRINTD" ]; then
	install -D -m 0644 data/polkit/50-tuxhello-fprintd.rules /etc/polkit-1/rules.d/50-tuxhello-fprintd.rules
	"$POLKITD" --no-debug >/tmp/polkitd.log 2>&1 &
	sleep 1
	FP_VIRTUAL_DEVICE=/run/fp-virtual.sock "$FPRINTD" --no-timeout >/tmp/fprintd.log 2>&1 &
	export TUXHELLO_FP_SOCKET=/run/fp-virtual.sock
	echo "fprintd $FPRINTD with a virtual sensor at $TUXHELLO_FP_SOCKET"
else
	echo "fprintd or polkitd missing; fingerprint tests will be skipped"
fi

step "software TPM for the unit tests"
mkdir -p /tmp/swtpm-unit
swtpm socket --tpm2 --tpmstate dir=/tmp/swtpm-unit --server type=tcp,port=2321 \
	--ctrl type=tcp,port=2322 --flags not-need-init,startup-clear >/tmp/swtpm-unit.log 2>&1 &
export TUXHELLO_TEST_TCTI="swtpm:host=127.0.0.1,port=2321"

step "build (stub backend enabled)"
cargo build --workspace --features tuxhello-daemon/stub-backend

step "unit tests"
cargo test --workspace --all-features

step "integration: unprivileged"
id thdev >/dev/null 2>&1 || useradd --create-home thdev
runuser -u thdev -- tests/integration/run-unprivileged.sh /target/debug

step "integration: root, real system bus"
tests/integration/pam-spike.sh /target/debug/tuxhellod /target/debug/libpam_tuxhello.so /target/debug/tuxhello

step "integration: tuxhello-pam-setup on the real distro PAM stack"
tests/integration/pam-setup.sh /target/debug

step "all container tests passed"
