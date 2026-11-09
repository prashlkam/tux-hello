#!/bin/bash
# End-to-end PAM test that needs NO root and changes nothing on the system.
#
# - A private dbus-daemon stands in for the system bus (DBUS_SYSTEM_BUS_ADDRESS;
#   libdbus ignores that variable in setuid programs, so this is not a way to
#   redirect a real sudo).
# - PAM services are read from a temporary directory via pam_start_confdir()
#   (Linux-PAM >= 1.4), and they load the module by absolute path.
#
# Cross-user denial is tested as "current user authenticating as root".
# The root-only counterpart, which uses the real system bus and /etc/pam.d, is
# pam-spike.sh.
#
# usage: tests/integration/run-unprivileged.sh [target-dir]   (default: target/debug)
#   The binaries must be built with --features tuxhello-daemon/stub-backend.
# Needs: cc, libpam headers, dbus-daemon, dbus-send.
set -uo pipefail

HERE=$(dirname "$(realpath "$0")")
ROOT=$(realpath "$HERE/../..")
TARGET=$(realpath "${1:-$ROOT/target/debug}")
DAEMON=$TARGET/tuxhellod
MODULE=$TARGET/libpam_tuxhello.so
CLI=$TARGET/tuxhello
for f in "$DAEMON" "$MODULE" "$CLI"; do
	[ -e "$f" ] || { echo "missing $f; run: cargo build --workspace --features tuxhello-daemon/stub-backend" >&2; exit 2; }
done

if [ "$(id -u)" -eq 0 ]; then
	echo "run this as a normal user (the cross-user test needs a non-root caller)" >&2
	exit 2
fi

WORK=$(mktemp -d)
BUS_NAME_SOCK="tuxhello-test-$$-$RANDOM"
BUS_PID=""
DAEMON_PID=""
FAILURES=0
ME=$(id -un)

cleanup() {
	stop_daemon
	[ -n "$BUS_PID" ] && kill "$BUS_PID" 2>/dev/null && wait "$BUS_PID" 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

# --- setup -------------------------------------------------------------------

cc -O1 -o "$WORK/th-pamtest" "$HERE/th-pamtest.c" -lpam -lpam_misc || exit 2

PAMDIR=$(dirname "$(find /lib /lib64 /usr/lib /usr/lib64 -name pam_deny.so -print -quit 2>/dev/null)")
[ -d "$PAMDIR" ] || { echo "cannot find PAM module directory" >&2; exit 2; }
mkdir "$WORK/pam.d" "$WORK/policy.d"
for svc in tuxhello-test tuxhello-test-fallthrough; do
	# Same stacks as pam.d/, with absolute module paths.
	sed -e "s|pam_tuxhello.so|$MODULE|" -e "s|pam_\(deny\|permit\).so|$PAMDIR/pam_\1.so|" \
		"$HERE/pam.d/$svc" >"$WORK/pam.d/$svc"
done

cat >"$WORK/bus.conf" <<EOF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <listen>unix:abstract=$BUS_NAME_SOCK</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
  </policy>
</busconfig>
EOF
dbus-daemon --config-file="$WORK/bus.conf" --nofork --nopidfile 2>"$WORK/bus.log" &
BUS_PID=$!
export DBUS_SYSTEM_BUS_ADDRESS="unix:abstract=$BUS_NAME_SOCK"

bus_has_name() {
	dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
		org.freedesktop.DBus.NameHasOwner "string:$1" 2>/dev/null | grep -q "boolean true"
}
for _ in $(seq 50); do
	dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
		org.freedesktop.DBus.GetId >/dev/null 2>&1 && break
	sleep 0.1
done

# --- helpers -----------------------------------------------------------------

start_daemon() { # $1 outcome, $2 delay_ms, $3 users (TOML array)
	stop_daemon
	{
		printf '[store]\npath = "%s"\n[policy]\ndirs = ["%s"]\n' "$WORK/store" "$WORK/policy.d"
		printf '[stub]\nenabled = true\noutcome = "%s"\ndelay_ms = %s\nusers = %s\n' "$1" "$2" "$3"
	} >"$WORK/config.toml"
	RUST_LOG=info "$DAEMON" --config "$WORK/config.toml" >>"$WORK/daemon.log" 2>&1 &
	DAEMON_PID=$!
	for _ in $(seq 50); do
		bus_has_name org.tuxhello.Auth1 && return 0
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

now_ms() { local t=${EPOCHREALTIME/./}; echo $((t / 1000)); }

fail() {
	printf 'FAIL  %s\n' "$1"
	FAILURES=$((FAILURES + 1))
}

# expect <ok|fail> <max-seconds> <description> <command...>
expect() {
	local want=$1 max=$2 desc=$3
	shift 3
	local t0 rc took got
	t0=$(now_ms)
	"$@" </dev/null >"$WORK/out" 2>&1
	rc=$?
	took=$(($(now_ms) - t0))
	if [ $rc -eq 0 ]; then got=ok; else got=fail; fi
	if [ "$got" = "$want" ] && [ "$took" -le $((max * 1000)) ]; then
		printf 'PASS  %-55s %6dms\n' "$desc" "$took"
	else
		fail "$(printf '%s (wanted %s, got %s rc=%d in %dms)' "$desc" "$want" "$got" $rc "$took")"
		sed 's/^/      | /' "$WORK/out"
	fi
}

out_contains() { # $1 pattern, $2 description
	if grep -q "$1" "$WORK/out"; then printf 'PASS  %s\n' "$2"; else fail "$2"; fi
}

pt() { "$WORK/th-pamtest" -c "$WORK/pam.d" "$@"; }

# --- tests -------------------------------------------------------------------

echo "== daemon not running"
expect fail 2 "no daemon: tuxhello-only stack fails" pt tuxhello-test "$ME"
expect ok 2 "no daemon: falls through to next module" pt tuxhello-test-fallthrough "$ME"

echo "== stub: success"
start_daemon success 200 '[]'
expect ok 3 "stub success" pt tuxhello-test "$ME"
out_contains "Stub backend" "progress message reached the PAM conversation"
expect fail 3 "authenticating as another user (root) is denied" pt tuxhello-test root
expect ok 3 "...and falls through" pt tuxhello-test-fallthrough root
expect fail 3 "remote host (PAM_RHOST) is ignored" pt -r 203.0.113.7 tuxhello-test "$ME"
expect ok 3 "remote host still falls through" pt -r 203.0.113.7 tuxhello-test-fallthrough "$ME"
expect ok 3 "rhost=localhost counts as local" pt -r localhost tuxhello-test "$ME"
expect fail 3 "unknown user" pt tuxhello-test no-such-user-xyz
expect ok 3 "CLI status" "$CLI" status
out_contains "stub" "CLI lists the stub backend"
expect ok 3 "CLI test" "$CLI" test
expect fail 3 "non-root PIN enrolment is refused" sh -c "printf '2468\n2468\n' | '$CLI' enroll pin"
out_contains "sudo" "refusal explains how to enrol"
expect fail 3 "non-root key enrolment is refused" "$CLI" enroll key --no-pin
expect ok 3 "CLI list (own enrolments)" "$CLI" list
expect fail 3 "CLI list of another user is refused" "$CLI" list --user root
expect ok 3 "CLI policy" "$CLI" policy sudo
out_contains "elevate" "sudo maps to the elevate class"

echo "== stub: failure"
start_daemon failure 200 '[]'
expect fail 3 "stub failure rejects" pt tuxhello-test "$ME"
expect ok 3 "stub failure falls through" pt tuxhello-test-fallthrough "$ME"

echo "== stub: unavailable"
start_daemon unavailable 200 '[]'
expect fail 3 "stub unavailable rejects" pt tuxhello-test "$ME"
expect ok 3 "stub unavailable falls through" pt tuxhello-test-fallthrough "$ME"

echo "== not enrolled"
start_daemon success 200 '["somebody-else"]'
expect fail 3 "user not enrolled" pt tuxhello-test "$ME"
expect ok 3 "not enrolled falls through" pt tuxhello-test-fallthrough "$ME"

echo "== timeout (backend slower than the policy timeout, 10 s for this class)"
start_daemon success 30000 '[]'
expect fail 13 "daemon gives up after the policy timeout" pt tuxhello-test "$ME"
expect ok 13 "timeout falls through" pt tuxhello-test-fallthrough "$ME"

echo "== daemon killed mid-session"
start_daemon success 30000 '[]'
(sleep 1; kill -9 "$DAEMON_PID") &
KILLER=$!
expect fail 5 "daemon crash during auth fails safely" pt tuxhello-test "$ME"
wait "$KILLER"
wait "$DAEMON_PID" 2>/dev/null
DAEMON_PID=""
expect ok 3 "after crash, falls through" pt tuxhello-test-fallthrough "$ME"

echo "== per-UID session limit (4)"
start_daemon success 2000 '[]'
PIDS=()
for i in 1 2 3 4 5; do
	pt tuxhello-test "$ME" </dev/null >"$WORK/par$i" 2>&1 &
	PIDS+=($!)
	sleep 0.05 # make sure all five overlap but start in order
done
ok=0
for p in "${PIDS[@]}"; do wait "$p" && ok=$((ok + 1)); done
if [ $ok -eq 4 ]; then
	printf 'PASS  %s\n' "4 of 5 concurrent sessions allowed"
else
	fail "expected 4 of 5 concurrent sessions to succeed, got $ok"
fi

echo
if [ $FAILURES -eq 0 ]; then
	echo "All unprivileged integration tests passed."
else
	echo "$FAILURES test(s) FAILED. Daemon log:"
	sed 's/^/  | /' "$WORK/daemon.log"
	exit 1
fi
