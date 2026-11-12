#!/bin/bash
# End-to-end test of tuxhello-pam-setup against the distribution's REAL PAM
# stack (system-auth / common-auth with pam_unix), including the real password
# fallback.
#
# MODIFIES THE SYSTEM (PAM files, a test user's password): run it only in a
# disposable container or VM. Run after building with the stub-backend feature.
#
# usage: sudo tests/integration/pam-setup.sh <target-dir>
set -uo pipefail

[ "$(id -u)" -eq 0 ] || { echo "must run as root (in a disposable environment)" >&2; exit 2; }
TARGET=$(realpath "${1:?usage: $0 <target-dir>}")
DAEMON=$TARGET/tuxhellod
MODULE=$TARGET/libpam_tuxhello.so
CLI=$TARGET/tuxhello
SETUP=$TARGET/tuxhello-pam-setup
HERE=$(dirname "$(realpath "$0")")
ROOT=$(realpath "$HERE/../..")
WORK=$(mktemp -d)
DAEMON_PID=""
FAILURES=0
USER_A=thsetup
PASSWORD='Corr3ct-Horse!'
PIN=97531
SVC=tuxhello-setup-test

cleanup() {
	[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null && wait "$DAEMON_PID" 2>/dev/null
	rm -f "/etc/pam.d/$SVC"
	rm -rf "$WORK"
}
trap cleanup EXIT

# --- setup -------------------------------------------------------------------

PAMDIR=$(dirname "$(find /lib /lib64 /usr/lib /usr/lib64 -name pam_deny.so -print -quit 2>/dev/null)")
install -m 0755 "$MODULE" "$PAMDIR/pam_tuxhello.so"
install -d /etc/dbus-1/system.d
install -m 0644 "$ROOT/data/dbus/org.tuxhello.Auth1.conf" /etc/dbus-1/system.d/
dbus-send --system --type=method_call --print-reply --dest=org.freedesktop.DBus \
	/org/freedesktop/DBus org.freedesktop.DBus.ReloadConfig >/dev/null
cc -O1 -o "$WORK/th-pamtest" "$HERE/th-pamtest.c" -lpam -lpam_misc || exit 2
chmod 0755 "$WORK"

id "$USER_A" >/dev/null 2>&1 || useradd --no-create-home --shell /usr/sbin/nologin "$USER_A"
echo "$USER_A:$PASSWORD" | chpasswd
command -v faillock >/dev/null && faillock --user "$USER_A" --reset 2>/dev/null

# A service built like the distro's own sudo/polkit files.
if [ -f /etc/pam.d/common-auth ]; then
	FAMILY=debian
	printf '#%%PAM-1.0\n@include common-auth\n@include common-account\n' >"/etc/pam.d/$SVC"
elif [ -f /etc/pam.d/system-auth ]; then
	FAMILY=system-auth
	printf '#%%PAM-1.0\nauth       include      system-auth\naccount    include      system-auth\n' >"/etc/pam.d/$SVC"
else
	echo "SKIP  no system-auth or common-auth on this system"
	exit 0
fi
cp "/etc/pam.d/$SVC" "$WORK/original"
echo "using the distribution's real stack ($FAMILY)"

start_daemon() {
	[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null && wait "$DAEMON_PID" 2>/dev/null
	printf '[store]\npath = "%s"\ntpm = "off"\n[pin]\ntpm = "off"\n[policy]\ndirs = []\n' "$WORK/store" >"$WORK/config.toml"
	RUST_LOG=info "$DAEMON" --config "$WORK/config.toml" >>"$WORK/daemon.log" 2>&1 &
	DAEMON_PID=$!
	for _ in $(seq 50); do
		dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
			org.freedesktop.DBus.NameHasOwner string:org.tuxhello.Auth1 2>/dev/null |
			grep -q "boolean true" && return 0
		sleep 0.1
	done
	echo "daemon did not start"; cat "$WORK/daemon.log"; exit 1
}

expect() { # expect <ok|fail> <description> <command...>; INPUT=... feeds stdin
	local want=$1 desc=$2 rc got
	shift 2
	if [ -n "${INPUT+x}" ]; then "$@" <<<"$INPUT" >"$WORK/out" 2>&1; else "$@" </dev/null >"$WORK/out" 2>&1; fi
	rc=$?
	if [ $rc -eq 0 ]; then got=ok; else got=fail; fi
	if [ "$got" = "$want" ]; then
		printf 'PASS  %s\n' "$desc"
	else
		printf 'FAIL  %s (wanted %s, got %s rc=%d)\n' "$desc" "$want" "$got" $rc
		sed 's/^/      | /' "$WORK/out"
		FAILURES=$((FAILURES + 1))
	fi
}
check() { # check <description> <command...>
	local desc=$1
	shift
	if "$@" >/dev/null 2>&1; then printf 'PASS  %s\n' "$desc"; else printf 'FAIL  %s\n' "$desc"; FAILURES=$((FAILURES + 1)); fi
}
pt() { "$WORK/th-pamtest" "$SVC" "$USER_A"; }
# Byte-for-byte comparison with coreutils only (cmp/diff may be missing).
same_file() { [ "$(sha256sum <"$1")" = "$(sha256sum <"$2")" ]; }
log_has() { grep -q "$1" "$WORK/daemon.log"; }

# --- tests -------------------------------------------------------------------

start_daemon
INPUT="$PIN"$'\n'"$PIN" expect ok "enroll a PIN" "$CLI" enroll pin --user "$USER_A"

echo "== before enabling: only the password"
INPUT="$PASSWORD" expect ok "real password works through the distro stack" pt

echo "== enable"
expect ok "status works" "$SETUP" status
expect ok "dry run" "$SETUP" enable --dry-run "$SVC"
check "dry run changed nothing" same_file "/etc/pam.d/$SVC" "$WORK/original"
expect fail "refuses sshd" "$SETUP" enable sshd
expect fail "refuses shared include files" "$SETUP" enable system-auth
expect ok "enable the test service" "$SETUP" enable "$SVC"
check "block added" grep -q "pam_tuxhello.so" "/etc/pam.d/$SVC"
expect ok "status shows it enabled" "$SETUP" status
INPUT="$PIN" expect ok "PIN logs in through the real stack" pt
INPUT=$'\n'"$PASSWORD" expect ok "empty PIN falls through to the REAL password" pt
INPUT=$'\nwrong-password' expect fail "empty PIN + wrong password fails" pt
command -v faillock >/dev/null && faillock --user "$USER_A" --reset 2>/dev/null

kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
INPUT="$PASSWORD" expect ok "daemon stopped: password alone works (no PIN prompt)" pt
start_daemon

echo "== disable and rollback"
expect ok "disable" "$SETUP" disable "$SVC"
check "disable restores the file byte for byte" same_file "/etc/pam.d/$SVC" "$WORK/original"
expect ok "enable again" "$SETUP" enable "$SVC"
expect ok "rollback to before the last change" "$SETUP" rollback
check "rollback restores the file byte for byte" same_file "/etc/pam.d/$SVC" "$WORK/original"
expect ok "backups are listed" "$SETUP" rollback --list
INPUT="$PASSWORD" expect ok "password still works after everything" pt

if [ "$FAMILY" = debian ] && command -v pam-auth-update >/dev/null; then
	echo "== Debian system-wide (pam-auth-update)"
	cp /etc/pam.d/common-auth "$WORK/common-auth.orig"
	expect ok "system-wide enable" "$SETUP" system-wide enable
	check "common-auth now uses pam_tuxhello" grep -q pam_tuxhello.so /etc/pam.d/common-auth
	INPUT="$PIN" expect ok "PIN works via common-auth" pt
	INPUT=$'\n'"$PASSWORD" expect ok "empty PIN falls through to the password via common-auth" pt
	expect ok "system-wide disable" "$SETUP" system-wide disable
	check "common-auth no longer uses pam_tuxhello" bash -c '! grep -q pam_tuxhello.so /etc/pam.d/common-auth'
	INPUT="$PASSWORD" expect ok "password works after system-wide disable" pt
fi

if [ "$FAMILY" = system-auth ] && command -v authselect >/dev/null && grep -qi fedora /etc/os-release; then
	echo "== Fedora system-wide (authselect)"
	BEFORE=$(authselect current --raw)
	cp /etc/pam.d/system-auth "$WORK/system-auth.orig"
	cp /etc/pam.d/password-auth "$WORK/password-auth.orig"
	expect ok "system-wide enable" "$SETUP" system-wide enable
	check "system-auth now uses pam_tuxhello" grep -q pam_tuxhello.so /etc/pam.d/system-auth
	check "password-auth (sshd) is untouched" same_file /etc/pam.d/password-auth "$WORK/password-auth.orig"
	check "the feature is on in a custom profile" \
		bash -c 'authselect current --raw | grep -q "^custom/tuxhello-.* with-tuxhello"'
	check "the earlier features are kept" \
		bash -c "for f in ${BEFORE#* }; do authselect current --raw | grep -qw -- \"\$f\" || exit 1; done"
	check "authselect accepts the result" authselect check
	expect ok "status reports it" "$SETUP" status
	check "status names the authselect profile" grep -q "enabled via authselect" "$WORK/out"
	INPUT="$PIN" expect ok "PIN works via system-auth" pt
	INPUT=$'\n'"$PASSWORD" expect ok "empty PIN falls through to the password via system-auth" pt
	INPUT=$'\nwrong-password' expect fail "empty PIN + wrong password fails" pt
	command -v faillock >/dev/null && faillock --user "$USER_A" --reset 2>/dev/null
	expect ok "enabling twice is harmless" "$SETUP" system-wide enable
	check "apply-changes keeps our line (it is in the profile, not hand-edited)" \
		bash -c 'authselect apply-changes && grep -q pam_tuxhello.so /etc/pam.d/system-auth'
	expect ok "system-wide disable" "$SETUP" system-wide disable
	check "system-auth is byte for byte what it was" same_file /etc/pam.d/system-auth "$WORK/system-auth.orig"
	check "the original profile and features are back" \
		bash -c "[ \"\$(authselect current --raw)\" = '$BEFORE' ]"
	check "the custom profile is gone" bash -c '! ls -d /etc/authselect/custom/tuxhello-* 2>/dev/null | grep -q .'
	expect ok "disabling when off is harmless" "$SETUP" system-wide disable
	INPUT="$PASSWORD" expect ok "password works after system-wide disable" pt
fi

echo
if [ $FAILURES -eq 0 ]; then
	echo "All pam-setup tests passed."
else
	echo "$FAILURES pam-setup test(s) FAILED. Daemon log:"
	sed 's/^/  | /' "$WORK/daemon.log"
	exit 1
fi
