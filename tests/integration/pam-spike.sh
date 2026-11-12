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

SWTPM_PID=""
cleanup() {
	stop_daemon
	[ -n "$SWTPM_PID" ] && kill "$SWTPM_PID" 2>/dev/null
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

mkdir -p "$WORK/policy.d"

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

base_config() { # store and policy inside $WORK; no TPM (it has its own section)
	printf '[store]\npath = "%s"\ntpm = "off"\n[pin]\ntpm = "off"\n[policy]\ndirs = ["%s"]\n' \
		"$WORK/store" "$WORK/policy.d"
}

stub_config() { # $1 outcome, $2 delay_ms, $3 users (TOML array)
	base_config
	printf '[stub]\nenabled = true\noutcome = "%s"\ndelay_ms = %s\nusers = %s\n' "$1" "$2" "$3"
}

# expect <ok|fail> <max-seconds> <description> <command...>
expect() {
	local want=$1 max=$2 desc=$3
	shift 3
	local start end rc got
	start=$(date +%s)
	# Set INPUT=... for commands that read a PIN from stdin.
	if [ -n "${INPUT+x}" ]; then
		"$@" <<<"$INPUT" >"$WORK/out" 2>&1
	else
		"$@" </dev/null >"$WORK/out" 2>&1
	fi
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

out_contains() { # $1 pattern, $2 description
	if grep -q "$1" "$WORK/out"; then
		printf 'PASS  %s\n' "$2"
	else
		printf 'FAIL  %s\n' "$2"
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

echo "== timeout (backend slower than the policy timeout, 10 s for this class)"
start_daemon "$(stub_config success 30000 '[]')"
expect fail 13 "daemon gives up after the policy timeout" pt tuxhello-test "$USER_A"
expect ok 13 "timeout falls through" pt tuxhello-test-fallthrough "$USER_A"

echo "== daemon killed mid-session"
start_daemon "$(stub_config success 30000 '[]')"
(sleep 1; kill -9 "$DAEMON_PID") &
KILLER=$!
expect fail 8 "daemon crash during auth fails safely" pt tuxhello-test "$USER_A"
wait "$KILLER"
wait "$DAEMON_PID" 2>/dev/null
DAEMON_PID=""
expect ok 5 "after crash, falls through" pt tuxhello-test-fallthrough "$USER_A"

echo "== PIN"
start_daemon "$(base_config)"
INPUT=$'2468\n2468' expect fail 5 "unprivileged user cannot enroll a PIN" \
	runuser -u "$USER_A" -- "$CLI" enroll pin
INPUT=$'2468\n2468' expect ok 10 "root enrolls a PIN for $USER_A" "$CLI" enroll pin --user "$USER_A"
INPUT=$'12\n12' expect fail 10 "too-short PIN is rejected" "$CLI" enroll pin --user "$USER_B"
expect ok 5 "user lists own enrolments" runuser -u "$USER_A" -- "$CLI" list
out_contains "pin" "list shows the PIN"
grep -q "_lockout" "$WORK/out" && { echo "FAIL  internal records are listed"; FAILURES=$((FAILURES + 1)); }
expect fail 5 "user cannot list someone else's enrolments" runuser -u "$USER_B" -- "$CLI" list --user "$USER_A"
expect ok 5 "policy explanation" runuser -u "$USER_A" -- "$CLI" policy sudo
out_contains "pin:2" "policy shows the PIN as usable"
[ -z "$(find "$WORK/store" -type f -name '*.rec' -perm /077)" ] &&
	echo "PASS  store records are private (0600)" ||
	{ echo "FAIL  store records readable by others"; FAILURES=$((FAILURES + 1)); }
grep -rq 2468 "$WORK/store" &&
	{ echo "FAIL  PIN found in plain text in the store"; FAILURES=$((FAILURES + 1)); } ||
	echo "PASS  PIN is not stored in plain text"

INPUT=2468 expect ok 10 "correct PIN authenticates (root caller)" pt tuxhello-test "$USER_A"
out_contains "PIN" "PIN prompt reached the PAM conversation"
INPUT=2468 expect ok 10 "correct PIN authenticates (user as itself)" \
	runuser -u "$USER_A" -- "$PAMTEST" tuxhello-test "$USER_A"
INPUT=2468 expect fail 10 "PIN is not offered to remote sessions" pt tuxhello-test "$USER_A" -r 203.0.113.7
INPUT='' expect fail 5 "empty PIN skips to the next module" pt tuxhello-test "$USER_A"
INPUT='' expect ok 5 "...which then succeeds (fallthrough stack)" pt tuxhello-test-fallthrough "$USER_A"
INPUT=$'1111\n2222\n3333' expect fail 15 "three wrong PINs fail the session" pt tuxhello-test "$USER_A"
out_contains "Incorrect PIN" "wrong PIN is reported"
INPUT=$'1111\n2222\n2468' expect fail 15 "5th failure locks the PIN, even before the right one" pt tuxhello-test "$USER_A"
out_contains "locked" "lockout is reported"
INPUT=2468 expect fail 10 "locked PIN refuses the correct PIN" pt tuxhello-test "$USER_A"
start_daemon "$(base_config)"
INPUT=2468 expect fail 10 "lockout survives a daemon restart" pt tuxhello-test "$USER_A"
INPUT=$'1357\n1357' expect ok 10 "root resets the PIN" "$CLI" enroll pin --user "$USER_A"
INPUT=1357 expect ok 10 "new PIN works and the lockout is cleared" pt tuxhello-test "$USER_A"

echo "== rate limit across methods, and the audit log"
start_daemon "$(base_config; printf '[limits]\nmax_failures = 3\nwindow_s = 6\n[audit]\nfile = "%s"\n' "$WORK/audit.log")"
INPUT=1357 expect ok 10 "PIN works before the limit is reached" pt tuxhello-test "$USER_A"
INPUT=$'1111\n2222\n3333' expect fail 15 "three wrong PINs reach the limit" pt tuxhello-test "$USER_A"
INPUT=1357 expect fail 3 "rate limited: not even the right PIN is asked for" pt tuxhello-test "$USER_A"
grep -q "PIN" "$WORK/out" &&
	{ echo "FAIL  a PIN prompt was shown while rate limited"; FAILURES=$((FAILURES + 1)); } ||
	echo "PASS  no prompt while rate limited"
INPUT=1357 expect ok 3 "rate limited: falls through to the next module" pt tuxhello-test-fallthrough "$USER_A"
expect ok 5 "list explains the pause" runuser -u "$USER_A" -- "$CLI" list
out_contains "paused" "pause shown"
sleep 7
INPUT=1357 expect ok 10 "the limit lifts after the window" pt tuxhello-test "$USER_A"

audit_has() { # $1 description, $2... fixed strings that one audit line must all contain
	local desc=$1 lines
	shift
	lines=$(cat "$WORK/audit.log" 2>/dev/null)
	for pat in "$@"; do lines=$(grep -F -- "$pat" <<<"$lines"); done
	if [ -n "$lines" ]; then
		printf 'PASS  %s\n' "$desc"
	else
		printf 'FAIL  %s\n' "$desc"
		sed 's/^/      | /' "$WORK/audit.log" 2>/dev/null
		FAILURES=$((FAILURES + 1))
	fi
}
audit_has "audit: session start" '"event":"auth.begin"' "\"user\":\"$USER_A\"" '"service":"tuxhello-test"'
audit_has "audit: success with method and assurance" '"event":"auth.result"' '"result":"success"' '"method":"pin"' '"assurance":2'
audit_has "audit: each failed attempt" '"event":"auth.attempt"' '"method":"pin"' '"result":"failed"'
audit_has "audit: failed session" '"event":"auth.result"' '"result":"failure"'
audit_has "audit: rate-limit refusal" '"event":"auth.refused"' '"reason":"rate-limited"'
[ "$(grep -vc '^{"time":[0-9]*,"event":"[a-z.]*".*}$' "$WORK/audit.log")" = 0 ] &&
	echo "PASS  audit: every line is one JSON object" ||
	{ echo "FAIL  audit: malformed lines"; FAILURES=$((FAILURES + 1)); }
grep -q -e 1357 -e 1111 -e 2222 -e 3333 "$WORK/audit.log" &&
	{ echo "FAIL  audit log contains a PIN"; FAILURES=$((FAILURES + 1)); } ||
	echo "PASS  audit: no PINs in the log"
[ "$(stat -c %a "$WORK/audit.log")" = 600 ] &&
	echo "PASS  audit file is private (0600)" ||
	{ echo "FAIL  audit file mode $(stat -c %a "$WORK/audit.log")"; FAILURES=$((FAILURES + 1)); }

echo "== policy reload (SIGHUP)"
printf '[class.other]\nrequire = "key"\n' >"$WORK/policy.d/50-key-only.toml"
kill -HUP "$DAEMON_PID"
sleep 0.5
INPUT=1357 expect fail 5 "policy requiring a key rejects the PIN" pt tuxhello-test "$USER_A"
expect ok 5 "...and falls through" pt tuxhello-test-fallthrough "$USER_A"
printf '[class.other]\nrequire = "pin"\nmin_assurance = 9\n' >"$WORK/policy.d/50-key-only.toml"
kill -HUP "$DAEMON_PID"
sleep 0.5
INPUT=1357 expect fail 5 "an invalid policy file keeps the previous policy" pt tuxhello-test "$USER_A"
rm "$WORK/policy.d/50-key-only.toml"
kill -HUP "$DAEMON_PID"
sleep 0.5
INPUT=1357 expect ok 10 "PIN accepted again after the policy is removed" pt tuxhello-test "$USER_A"

echo "== delete"
expect ok 5 "user deletes own PIN" runuser -u "$USER_A" -- "$CLI" delete pin
INPUT=1357 expect fail 5 "deleted PIN no longer works" pt tuxhello-test "$USER_A"
expect ok 5 "...and falls through" pt tuxhello-test-fallthrough "$USER_A"

echo "== security key (software authenticator)"
SK="$WORK/softkey"
mkdir -p "$SK"
touch "$SK/present"
key_config() { # $1 = extra TOML
	base_config
	printf '[stub]\nsoft_key_dir = "%s"\n%s\n' "$SK" "${1:-}"
}
start_daemon "$(key_config)"
expect ok 5 "status lists the key method" "$CLI" status
out_contains "key .*available" "key method is available"
expect fail 5 "unprivileged user cannot enroll a key" runuser -u "$USER_A" -- "$CLI" enroll key --no-pin
expect ok 10 "root enrolls a key for $USER_A" "$CLI" enroll key --user "$USER_A" --label "My YubiKey" --no-pin
out_contains "my-yubikey" "label becomes the enrolment id"
expect fail 10 "the same label cannot be enrolled twice" "$CLI" enroll key --user "$USER_A" --label "my yubikey" --no-pin
expect ok 5 "list shows the key" runuser -u "$USER_A" -- "$CLI" list
out_contains "key .*my-yubikey" "key listed"
grep -rq '"pam://tuxhello"' "$WORK/store" &&
	{ echo "FAIL  key record stored in plain text"; FAILURES=$((FAILURES + 1)); } ||
	echo "PASS  key record is encrypted"

expect ok 10 "key authenticates (root caller)" pt tuxhello-test "$USER_A"
out_contains "Touch your security key" "touch prompt reached the PAM conversation"
expect ok 10 "key authenticates (user as itself)" runuser -u "$USER_A" -- "$PAMTEST" tuxhello-test "$USER_A"

rm "$SK/present"
expect fail 3 "unplugged key: fails fast" pt tuxhello-test "$USER_A"
expect ok 3 "unplugged key: falls through" pt tuxhello-test-fallthrough "$USER_A"
touch "$SK/present"

mv "$SK/creds" "$SK/creds.real"
expect fail 10 "a different key (no enrolled credential) is rejected" pt tuxhello-test "$USER_A"
out_contains "not recognised" "foreign key reported"
mv "$SK/creds.real" "$SK/creds"

CRED=$(ls "$SK/creds" | head -1)
sed -i 's/ [0-9]*$/ 0/' "$SK/creds/$CRED"
expect fail 10 "cloned key (counter went backwards) is rejected" pt tuxhello-test "$USER_A"
grep -q "possible cloned key" "$WORK/daemon.log" &&
	echo "PASS  clone suspicion logged" ||
	{ echo "FAIL  clone suspicion not logged"; FAILURES=$((FAILURES + 1)); }
sed -i 's/ [0-9]*$/ 100/' "$SK/creds/$CRED"
expect ok 10 "key works again once its counter is ahead" pt tuxhello-test "$USER_A"

touch "$SK/no-touch"
rm -f "$SK/was-cancelled"
expect fail 13 "nobody touches the key: policy timeout" pt tuxhello-test "$USER_A"
sleep 0.5
[ -e "$SK/was-cancelled" ] &&
	echo "PASS  the waiting key operation was cancelled" ||
	{ echo "FAIL  key operation not cancelled"; FAILURES=$((FAILURES + 1)); }
rm "$SK/no-touch"

echo "== import from pam_u2f"
# A syntactically valid pam_u2f file (the credentials belong to no real key;
# that an imported key authenticates is covered by the daemon's unit tests).
KH=$(head -c 48 /dev/urandom | base64 -w0)
PK=$(head -c 64 /dev/urandom | base64 -w0)
printf '%s:%s,%s,es256,+presence:*,%s,es256,+presence\nsomebody:%s,%s,es256,+presence\n' \
	"$USER_A" "$KH" "$PK" "$PK" "$KH" "$PK" >"$WORK/u2f_keys"
expect fail 5 "unprivileged user cannot import" \
	runuser -u "$USER_A" -- "$CLI" import pam-u2f --file "$WORK/u2f_keys"
expect ok 5 "root imports $USER_A's pam_u2f keys" \
	"$CLI" import pam-u2f --file "$WORK/u2f_keys" --origin pam://oldhost --user "$USER_A"
out_contains "Imported 1 security key" "one credential imported"
out_contains "u2f-1" "it gets an id"
out_contains "resident" "the resident credential is explained, not imported"
expect ok 5 "list shows the imported key" runuser -u "$USER_A" -- "$CLI" list
out_contains "key .*u2f-1" "imported key listed"
expect fail 5 "importing the same file again adds nothing" \
	"$CLI" import pam-u2f --file "$WORK/u2f_keys" --origin pam://oldhost --user "$USER_A"
out_contains "already enrolled" "duplicate explained"
expect fail 5 "a user without a line in the file gets nothing" \
	"$CLI" import pam-u2f --file "$WORK/u2f_keys" --user "$USER_B"
expect fail 5 "a missing file is reported" "$CLI" import pam-u2f --file "$WORK/nope" --user "$USER_A"
expect ok 10 "the enrolled key still works next to the imported one" pt tuxhello-test "$USER_A"
expect ok 5 "delete the imported key" runuser -u "$USER_A" -- "$CLI" delete key u2f-1

echo "== doctor"
# doctor looks for tuxhello-pam-setup on PATH; here it sits next to the CLI.
doctor() { runuser -u "$USER_A" -- env PATH="$(dirname "$CLI"):$PATH" "$CLI" doctor; }
expect ok 10 "doctor finds no failures on a working setup" doctor
out_contains "\[ ok \] daemon .*is running" "doctor: daemon"
out_contains "\[ ok \] pam module" "doctor: PAM module found"
out_contains "\[ ok \] key .*plugged in" "doctor: security key"
out_contains "\[ ok \] enrolments .*key" "doctor: enrolments"
stop_daemon
expect fail 10 "doctor fails when the daemon is down" doctor
out_contains "FAIL.*daemon .*does not answer" "doctor: says the daemon does not answer"
out_contains "journalctl -u tuxhellod" "doctor: says where to look"
start_daemon "$(key_config $'enabled = true\noutcome = "unavailable"')"
expect fail 10 "doctor fails when the stub backend is active" doctor
out_contains "FAIL.*stub .*TEST-ONLY" "doctor: flags the stub backend"
start_daemon "$(key_config)"

echo "== two factors: key AND PIN"
INPUT=$'8642\n8642' expect ok 10 "root enrolls a PIN again" "$CLI" enroll pin --user "$USER_A"
printf '[class.other]\nrequire = { all = ["key", "pin"] }\n' >"$WORK/policy.d/50-2fa.toml"
kill -HUP "$DAEMON_PID"
sleep 0.5
INPUT=8642 expect ok 10 "key + correct PIN succeeds" pt tuxhello-test "$USER_A"
grep -q "authenticated by key+pin" "$WORK/daemon.log" &&
	echo "PASS  both factors credited" ||
	{ echo "FAIL  both factors not credited"; FAILURES=$((FAILURES + 1)); }
INPUT=$'1\n2\n3' expect fail 15 "key + wrong PIN fails" pt tuxhello-test "$USER_A"
rm "$SK/present"
INPUT=8642 expect fail 5 "PIN alone is not enough (key unplugged)" pt tuxhello-test "$USER_A"
touch "$SK/present"
rm "$WORK/policy.d/50-2fa.toml"

echo "== key with user verification (key PIN)"
echo 4321 >"$SK/pin"
start_daemon "$(key_config $'[key]\nrequire_uv = true')"
INPUT=4321 expect ok 10 "enroll a UV key with its PIN" "$CLI" enroll key --user "$USER_A" --label uv
INPUT=4321 expect ok 10 "key PIN + touch authenticates" pt tuxhello-test "$USER_A"
out_contains "Security key PIN" "key PIN prompt shown"
INPUT=1111 expect fail 10 "wrong key PIN fails" pt tuxhello-test "$USER_A"
out_contains "Wrong security key PIN" "wrong key PIN reported"
rm "$SK/pin"

echo "== delete keys"
expect ok 5 "user deletes a key" runuser -u "$USER_A" -- "$CLI" delete key my-yubikey
expect ok 5 "user deletes everything" runuser -u "$USER_A" -- "$CLI" delete --all
expect ok 5 "list after delete" runuser -u "$USER_A" -- "$CLI" list
out_contains "no enrolments" "nothing left"

echo "== fingerprint (fprintd + libfprint virtual sensor)"
if [ -z "${TUXHELLO_FP_SOCKET:-}" ]; then
	echo "SKIP  no virtual fingerprint sensor (set TUXHELLO_FP_SOCKET)"
else
	cc -O1 -o "$WORK/th-fpscan" "$HERE/th-fpscan.c" || exit 2
	scan() { # scan <count> <timeout-s> COMMAND... (in the background)
		"$WORK/th-fpscan" "$TUXHELLO_FP_SOCKET" "$@" >/dev/null 2>&1 &
		SCANNER=$!
	}
	start_daemon "$(base_config)"
	expect fail 5 "nothing enrolled: fingerprint not offered" pt tuxhello-test "$USER_A"
	scan 5 25 SCAN print-a
	expect ok 30 "enroll a finger through fprintd" "$CLI" enroll fingerprint --finger right-index-finger --user "$USER_A"
	wait $SCANNER
	expect fail 5 "unknown finger name refused" "$CLI" enroll fingerprint --finger tentacle --user "$USER_A"
	expect ok 5 "list shows the finger" runuser -u "$USER_A" -- "$CLI" list
	out_contains "fingerprint .*right-index-finger" "finger listed"
	expect ok 5 "policy shows fingerprint usable" runuser -u "$USER_A" -- "$CLI" policy sudo
	out_contains "fingerprint:3" "fingerprint usable at assurance 3"

	scan 1 15 SCAN print-a
	expect ok 15 "matching finger authenticates" pt tuxhello-test "$USER_A"
	wait $SCANNER
	out_contains "fingerprint reader" "touch/swipe prompt reached the PAM conversation"

	scan 1 15 SCAN print-a
	expect ok 15 "matching finger (user as itself)" runuser -u "$USER_A" -- "$PAMTEST" tuxhello-test "$USER_A"
	wait $SCANNER

	scan 3 20 SCAN print-b
	expect fail 20 "unknown finger rejected after 3 tries" pt tuxhello-test "$USER_A"
	wait $SCANNER
	out_contains "not recognised" "no-match reported"

	( "$WORK/th-fpscan" "$TUXHELLO_FP_SOCKET" 1 15 RETRY 0 && "$WORK/th-fpscan" "$TUXHELLO_FP_SOCKET" 1 15 SCAN print-a ) >/dev/null 2>&1 &
	SCANNER=$!
	expect ok 15 "bad scan, retry hint, then match" pt tuxhello-test "$USER_A"
	wait $SCANNER
	out_contains "Try again" "retry hint shown"

	expect fail 13 "no finger: policy timeout" pt tuxhello-test "$USER_A"
	scan 1 15 SCAN print-a
	expect ok 15 "reader was released after the timeout" pt tuxhello-test "$USER_A"
	wait $SCANNER

	INPUT=$'2468\n2468' expect ok 10 "enroll a PIN as well" "$CLI" enroll pin --user "$USER_A"
	scan 3 20 SCAN print-b
	INPUT=2468 expect ok 25 "three wrong fingers, then the PIN works" pt tuxhello-test "$USER_A"
	wait $SCANNER

	echo "== biometric lockout"
	bio_config() { base_config; printf '[limits]\nbiometric_max_failures = 3\n'; }
	no_reader_prompt() { # $1 description
		grep -q "fingerprint reader" "$WORK/out" &&
			{ echo "FAIL  $1"; sed 's/^/      | /' "$WORK/out"; FAILURES=$((FAILURES + 1)); } ||
			echo "PASS  $1"
	}
	start_daemon "$(bio_config)"
	scan 3 20 SCAN print-b
	INPUT='' expect fail 25 "three unknown fingers switch biometrics off" pt tuxhello-test "$USER_A"
	wait $SCANNER
	out_contains "fingerprint is off" "the lockout is explained to the user"
	INPUT='' expect fail 5 "locked out: straight to the PIN prompt" pt tuxhello-test "$USER_A"
	no_reader_prompt "the fingerprint reader is not offered"
	start_daemon "$(bio_config)"
	INPUT='' expect fail 5 "the lockout survives a daemon restart" pt tuxhello-test "$USER_A"
	no_reader_prompt "still not offered after the restart"
	expect ok 5 "list explains the lockout" runuser -u "$USER_A" -- "$CLI" list
	out_contains "switched off" "lockout shown"
	expect fail 5 "an unprivileged user cannot clear it" runuser -u "$USER_A" -- "$CLI" unlock
	INPUT=2468 expect ok 10 "the PIN still works while biometrics are off" pt tuxhello-test "$USER_A"
	scan 1 15 SCAN print-a
	expect ok 15 "a PIN success switches biometrics back on" pt tuxhello-test "$USER_A"
	wait $SCANNER
	scan 3 20 SCAN print-b
	INPUT='' expect fail 25 "lock biometrics out again" pt tuxhello-test "$USER_A"
	wait $SCANNER
	expect ok 5 "root clears the lockout (tuxhello unlock)" "$CLI" unlock --user "$USER_A"
	scan 1 15 SCAN print-a
	expect ok 15 "the finger works again after unlock" pt tuxhello-test "$USER_A"
	wait $SCANNER

	expect ok 10 "user deletes their finger" runuser -u "$USER_A" -- "$CLI" delete fingerprint right-index-finger
	expect ok 5 "list after deleting the finger" runuser -u "$USER_A" -- "$CLI" list
	grep -q fingerprint "$WORK/out" &&
		{ echo "FAIL  finger still listed"; FAILURES=$((FAILURES + 1)); } ||
		echo "PASS  finger gone"
	expect ok 5 "clean up" runuser -u "$USER_A" -- "$CLI" delete --all
fi

echo "== lock-out safety: damaged store"
LS="$WORK/store-damaged"
damaged_config() {
	printf '[store]\npath = "%s"\ntpm = "off"\n[pin]\ntpm = "off"\n[policy]\ndirs = ["%s"]\n' "$LS" "$WORK/policy.d"
}
start_daemon "$(damaged_config)"
INPUT=$'2468\n2468' expect ok 10 "enroll a PIN in a fresh store" "$CLI" enroll pin --user "$USER_B"
INPUT=2468 expect ok 10 "it works" pt tuxhello-test "$USER_B"
printf 'garbage' >"$(find "$LS/users" -path '*/pin/default.rec')"
INPUT=2468 expect fail 5 "damaged PIN record: the PIN is not accepted" pt tuxhello-test "$USER_B"
INPUT=2468 expect ok 5 "damaged PIN record: the next module still runs" pt tuxhello-test-fallthrough "$USER_B"
expect ok 5 "the daemon survives a damaged record" "$CLI" status
stop_daemon
printf 'short' >"$LS/master.key"
damaged_config >"$WORK/config.toml"
if timeout 10 "$DAEMON" --config "$WORK/config.toml" >"$WORK/out" 2>&1; then
	echo "FAIL  the daemon started with a damaged master key"
	FAILURES=$((FAILURES + 1))
else
	echo "PASS  damaged master key: the daemon refuses to start"
fi
[ "$(cat "$LS/master.key")" = short ] &&
	echo "PASS  it did not overwrite the damaged key" ||
	{ echo "FAIL  the damaged key was replaced"; FAILURES=$((FAILURES + 1)); }
INPUT='' expect ok 5 "damaged master key: the next module still runs" pt tuxhello-test-fallthrough "$USER_B"

echo "== TPM (swtpm): sealed master key and TPM-backed PIN"
if ! command -v swtpm >/dev/null || ! command -v tpm2_dictionarylockout >/dev/null; then
	echo "SKIP  swtpm or tpm2-tools not installed"
else
	TPM_PORT=2331
	TCTI="swtpm:host=127.0.0.1,port=$TPM_PORT"
	export TPM2TOOLS_TCTI="$TCTI"
	mkdir -p "$WORK/tpm-state"
	start_swtpm() {
		swtpm socket --tpm2 --tpmstate dir="$WORK/tpm-state" \
			--server type=tcp,port=$TPM_PORT --ctrl type=tcp,port=$((TPM_PORT + 1)) \
			--flags not-need-init,startup-clear >>"$WORK/swtpm.log" 2>&1 &
		SWTPM_PID=$!
		for _ in $(seq 50); do
			tpm2_getcap properties-fixed >/dev/null 2>&1 && return 0
			sleep 0.1
		done
		echo "swtpm did not come up"; cat "$WORK/swtpm.log"; exit 1
	}
	stop_swtpm() { kill "$SWTPM_PID" 2>/dev/null; wait "$SWTPM_PID" 2>/dev/null; SWTPM_PID=""; }
	TS="$WORK/store-tpm"
	tpm_config() { # $1 = [store] tpm, $2 = [pin] tpm
		printf '[tpm]\ntcti = "%s"\n[store]\npath = "%s"\ntpm = "%s"\n[pin]\ntpm = "%s"\n[policy]\ndirs = ["%s"]\n' \
			"$TCTI" "$TS" "$1" "$2" "$WORK/policy.d"
	}
	file_check() { # $1 description, then a test expression
		local desc=$1
		shift
		if [ "$@" ]; then echo "PASS  $desc"; else echo "FAIL  $desc"; ls -la "$TS"; FAILURES=$((FAILURES + 1)); fi
	}
	start_swtpm

	# An installation from before the TPM was used: file key, software PIN.
	start_daemon "$(tpm_config off off)"
	INPUT=$'4321\n4321' expect ok 10 "software PIN on a file-key store" "$CLI" enroll pin --user "$USER_B"
	file_check "the master key is a plain file" -f "$TS/master.key"

	start_daemon "$(tpm_config auto auto)"
	expect ok 5 "auto: status" "$CLI" status
	out_contains "key: file" "auto leaves an existing file key alone"
	INPUT=4321 expect ok 10 "the software PIN keeps working" pt tuxhello-test "$USER_B"
	expect ok 5 "policy" runuser -u "$USER_B" -- "$CLI" policy sudo
	out_contains "pin:2" "a software PIN has assurance 2"

	start_daemon "$(tpm_config require auto)"
	expect ok 5 "require: status" "$CLI" status
	out_contains "key: TPM" "require moves the master key into the TPM"
	file_check "the plain key file is gone" ! -e "$TS/master.key"
	file_check "the sealed key exists" -f "$TS/master.key.tpm"
	INPUT=4321 expect ok 10 "enrolments survive the move" pt tuxhello-test "$USER_B"

	INPUT=$'8520\n8520' expect ok 10 "a PIN enrolled now is TPM-backed" "$CLI" enroll pin --user "$USER_B"
	expect ok 5 "policy" runuser -u "$USER_B" -- "$CLI" policy sudo
	out_contains "pin:3" "a TPM-backed PIN has assurance 3"
	INPUT=8520 expect ok 10 "the TPM-backed PIN authenticates" pt tuxhello-test "$USER_B"
	INPUT=4321 expect fail 10 "the old PIN is gone" pt tuxhello-test "$USER_B"
	INPUT=$'1111\n8520' expect ok 10 "wrong, then right" pt tuxhello-test "$USER_B"
	start_daemon "$(tpm_config auto auto)"
	INPUT=8520 expect ok 10 "works after a daemon restart (sealed key found, auto)" pt tuxhello-test "$USER_B"

	echo "== TPM dictionary-attack lockout"
	tpm2_dictionarylockout --setup-parameters --max-tries=2 --recovery-time=86400 \
		--lockout-recovery-time=0 >/dev/null 2>&1
	tpm2_dictionarylockout --clear-lockout >/dev/null 2>&1
	INPUT=$'1111\n2222\n8520' expect fail 15 "two wrong PINs: the TPM itself refuses the right one" pt tuxhello-test "$USER_B"
	out_contains "TPM has locked" "the hardware lockout is explained"
	INPUT=8520 expect fail 5 "TPM locked: the PIN is not accepted" pt tuxhello-test "$USER_B"
	INPUT=8520 expect ok 5 "TPM locked: falls through to the next module" pt tuxhello-test-fallthrough "$USER_B"
	tpm2_dictionarylockout --clear-lockout >/dev/null 2>&1
	INPUT=8520 expect ok 10 "the PIN works again once the TPM lockout is cleared" pt tuxhello-test "$USER_B"

	echo "== TPM disappears"
	stop_swtpm
	INPUT=8520 expect fail 5 "TPM gone under a running daemon: PIN unavailable" pt tuxhello-test "$USER_B"
	INPUT=8520 expect ok 5 "...and the next module still runs" pt tuxhello-test-fallthrough "$USER_B"
	stop_daemon
	tpm_config auto auto >"$WORK/config.toml"
	if timeout 10 "$DAEMON" --config "$WORK/config.toml" >"$WORK/out" 2>&1; then
		echo "FAIL  the daemon started without the TPM that seals its key"
		FAILURES=$((FAILURES + 1))
	else
		echo "PASS  without its TPM the daemon refuses to start"
	fi
	out_contains "sealed by a TPM that is not available" "it says why"
	file_check "it did not replace the sealed key" -f "$TS/master.key.tpm"
	file_check "it did not create a new file key" ! -e "$TS/master.key"
	INPUT='' expect ok 5 "daemon down: the next module still runs" pt tuxhello-test-fallthrough "$USER_B"
	start_swtpm
	start_daemon "$(tpm_config auto auto)"
	INPUT=8520 expect ok 10 "TPM back: the PIN works again" pt tuxhello-test "$USER_B"
	expect ok 5 "clean up" runuser -u "$USER_B" -- "$CLI" delete --all
	stop_daemon
	stop_swtpm
fi

echo
if [ $FAILURES -eq 0 ]; then
	echo "All integration tests passed."
else
	echo "$FAILURES integration test(s) FAILED. Daemon log:"
	sed 's/^/  | /' "$WORK/daemon.log"
	exit 1
fi
