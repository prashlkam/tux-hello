#!/bin/bash
# Phase 0 end-to-end test: real libpam + real system bus + tuxhellod (stub).
# Needs: cc, libpam headers, dbus-send, runuser, useradd, a running system bus.
#
# MODIFIES THE SYSTEM: installs a PAM module, PAM services, a D-Bus policy and
# two test users. Run it only in a throwaway VM or CI container/runner.
#
# usage: sudo tests/integration/pam-spike.sh <tuxhellod> <pam_tuxhello.so> <tuxhello-cli>
#   tuxhellod must be built with --features tuxhello-daemon/stub-backend
set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
	echo "must run as root (in a disposable environment)" >&2
	exit 2
fi
if [ $# -ne 3 ]; then
	echo "usage: $0 <tuxhellod> <pam_tuxhello.so> <tuxhello>" >&2
	exit 2
fi

DAEMON=$(realpath "$1")
MODULE=$(realpath "$2")
CLI=$(realpath "$3")
HERE=$(dirname "$(realpath "$0")")
ROOT=$(realpath "$HERE/../..")
WORK=$(mktemp -d)
DAEMON_PID=""
FAILURES=0
USER_A=thtest
USER_B=thother

cleanup() {
	stop_daemon
	rm -rf "$WORK"
}
trap cleanup EXIT

# --- setup -------------------------------------------------------------------

PAMDIR=$(dirname "$(find /lib /lib64 /usr/lib /usr/lib64 -name pam_deny.so -print -quit 2>/dev/null)")
[ -d "$PAMDIR" ] || { echo "cannot find PAM module directory" >&2; exit 2; }
install -m 0755 "$MODULE" "$PAMDIR/pam_tuxhello.so"
install -m 0644 "$HERE/pam.d/tuxhello-test" /etc/pam.d/tuxhello-test
install -m 0644 "$HERE/pam.d/tuxhello-test-fallthrough" /etc/pam.d/tuxhello-test-fallthrough
install -d /etc/dbus-1/system.d
install -m 0644 "$ROOT/data/dbus/org.tuxhello.Auth1.conf" /etc/dbus-1/system.d/org.tuxhello.Auth1.conf
dbus-send --system --type=method_call --print-reply --dest=org.freedesktop.DBus \
	/org/freedesktop/DBus org.freedesktop.DBus.ReloadConfig >/dev/null

chmod 0755 "$WORK"
cc -O1 -o "$WORK/th-pamtest" "$HERE/th-pamtest.c" -lpam -lpam_misc || exit 2
PAMTEST="$WORK/th-pamtest"

for u in "$USER_A" "$USER_B"; do
	id "$u" >/dev/null 2>&1 || useradd --no-create-home --shell /usr/sbin/nologin "$u"
done

# --- helpers -----------------------------------------------------------------

start_daemon() { # $1 = config text
	stop_daemon
	printf '%s\n' "$1" >"$WORK/config.toml"
	RUST_LOG=debug "$DAEMON" --config "$WORK/config.toml" >>"$WORK/daemon.log" 2>&1 &
	DAEMON_PID=$!
	for _ in $(seq 50); do
		if dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
			org.freedesktop.DBus.NameHasOwner string:org.tuxhello.Auth1 2>/dev/null |
			grep -q "boolean true"; then
			return 0
		fi
		sleep 0.1
	done
	echo "daemon did not come up; log:" >&2
	cat "$WORK/daemon.log" >&2
	exit 1
}

stop_daemon() {
	if [ -n "$DAEMON_PID" ]; then
		kill "$DAEMON_PID" 2>/dev/null
		wait "$DAEMON_PID" 2>/dev/null
		DAEMON_PID=""
	fi
}

stub_config() { # $1 outcome, $2 delay_ms, $3 users (TOML array)
	printf '[stub]\nenabled = true\noutcome = "%s"\ndelay_ms = %s\nusers = %s\n' "$1" "$2" "$3"
}

# expect <ok|fail> <max-seconds> <description> <command...>
expect() {
	local want=$1 max=$2 desc=$3
	shift 3
	local start end rc got
	start=$(date +%s)
	"$@" </dev/null >"$WORK/out" 2>&1
	rc=$?
	end=$(date +%s)
	if [ $rc -eq 0 ]; then got=ok; else got=fail; fi
	if [ "$got" = "$want" ] && [ $((end - start)) -le "$max" ]; then
		printf 'PASS  %s\n' "$desc"
	else
		printf 'FAIL  %s (wanted %s, got %s rc=%d in %ss)\n' "$desc" "$want" "$got" $rc $((end - start))
		sed 's/^/      | /' "$WORK/out"
		FAILURES=$((FAILURES + 1))
	fi
}

pt() { # pt <service> <user> [-r rhost]
	local svc=$1 user=$2
	shift 2
	"$PAMTEST" "$@" "$svc" "$user"
}

# --- tests -------------------------------------------------------------------

echo "== daemon not running"
expect fail 5 "no daemon: tuxhello-only stack fails" pt tuxhello-test "$USER_A"
expect ok 5 "no daemon: falls through to next module" pt tuxhello-test-fallthrough "$USER_A"

echo "== stub: success"
start_daemon "$(stub_config success 200 '[]')"
expect ok 5 "root caller, stub success" pt tuxhello-test "$USER_A"
grep -q "Stub backend" "$WORK/out" &&
	echo "PASS  progress message reached the PAM conversation" ||
	{ echo "FAIL  progress message missing"; FAILURES=$((FAILURES + 1)); }
expect ok 5 "unprivileged user authenticating as itself" \
	runuser -u "$USER_A" -- "$PAMTEST" tuxhello-test "$USER_A"
expect fail 5 "unprivileged user authenticating as someone else is denied" \
	runuser -u "$USER_B" -- "$PAMTEST" tuxhello-test "$USER_A"
expect fail 5 "remote host (PAM_RHOST) is ignored" pt tuxhello-test "$USER_A" -r 203.0.113.7
expect ok 5 "remote host still falls through" pt tuxhello-test-fallthrough "$USER_A" -r 203.0.113.7
expect fail 5 "unknown user" pt tuxhello-test no-such-user-xyz
expect ok 5 "CLI status" "$CLI" status
grep -q "stub" "$WORK/out" &&
	echo "PASS  CLI lists the stub backend" ||
	{ echo "FAIL  CLI did not list stub backend"; FAILURES=$((FAILURES + 1)); }
expect ok 5 "CLI test as unprivileged user" runuser -u "$USER_A" -- "$CLI" test

echo "== stub: failure"
start_daemon "$(stub_config failure 200 '[]')"
expect fail 5 "stub failure rejects" pt tuxhello-test "$USER_A"
expect ok 5 "stub failure falls through" pt tuxhello-test-fallthrough "$USER_A"

echo "== stub: unavailable"
start_daemon "$(stub_config unavailable 200 '[]')"
expect fail 5 "stub unavailable rejects" pt tuxhello-test "$USER_A"
expect ok 5 "stub unavailable falls through" pt tuxhello-test-fallthrough "$USER_A"

echo "== not enrolled"
start_daemon "$(stub_config success 200 '["somebody-else"]')"
expect fail 5 "user not enrolled" pt tuxhello-test "$USER_A"
expect ok 5 "not enrolled falls through" pt tuxhello-test-fallthrough "$USER_A"

echo "== timeout (backend slower than module timeout=5)"
start_daemon "$(stub_config success 30000 '[]')"
expect fail 8 "module gives up after its timeout" pt tuxhello-test "$USER_A"
expect ok 8 "timeout falls through" pt tuxhello-test-fallthrough "$USER_A"

echo "== daemon killed mid-session"
start_daemon "$(stub_config success 30000 '[]')"
(sleep 1; kill -9 "$DAEMON_PID") &
KILLER=$!
expect fail 8 "daemon crash during auth fails safely" pt tuxhello-test "$USER_A"
wait "$KILLER"
wait "$DAEMON_PID" 2>/dev/null
DAEMON_PID=""
expect ok 5 "after crash, falls through" pt tuxhello-test-fallthrough "$USER_A"

echo
if [ $FAILURES -eq 0 ]; then
	echo "All integration tests passed."
else
	echo "$FAILURES integration test(s) FAILED. Daemon log:"
	sed 's/^/  | /' "$WORK/daemon.log"
	exit 1
fi
