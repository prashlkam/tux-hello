#!/bin/bash

# SPDX-FileCopyrightText: 2026 Tux Hello contributors
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Runs inside a container (see scripts/podman-package.sh), with no network:
# builds the distribution package from the release tarball, installs it, uses
# it for a real PAM login, removes it, and checks that nothing is left in PAM.
#
#   package-in-container.sh <arch|debian|fedora>
#
# /src is the source tree (read-only), /dist holds tux-hello-<version>.tar.xz
# and receives the package.
set -euo pipefail

distro=${1:?usage: $0 <arch|debian|fedora>}
tarball=$(ls /dist/tux-hello-*.tar.xz | head -1)
ver=$(basename "$tarball" .tar.xz)
ver=${ver#tux-hello-}
WORK=/work
FAILURES=0
mkdir -p "$WORK"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
check() { # check <description> <command...>
	local desc=$1
	shift
	if "$@" >"$WORK/out" 2>&1; then
		printf 'PASS  %s\n' "$desc"
	else
		printf 'FAIL  %s\n' "$desc"
		sed 's/^/      | /' "$WORK/out"
		FAILURES=$((FAILURES + 1))
	fi
}
not() { ! "$@"; }

# --- build -------------------------------------------------------------------

step "build the $distro package from $(basename "$tarball") (offline)"
case $distro in
arch)
	# makepkg refuses to run as root.
	id builder >/dev/null 2>&1 || useradd --create-home builder
	install -d -o builder "$WORK/pkg"
	cp /src/packaging/arch/PKGBUILD /src/packaging/arch/tuxhello.install "$tarball" "$WORK/pkg/"
	chown builder "$WORK/pkg"/*
	(cd "$WORK/pkg" && runuser -u builder -- env PKGDEST="$WORK/pkg/out" PKGEXT=.pkg.tar.zst makepkg --nodeps --noconfirm)
	pkg=$(ls "$WORK"/pkg/out/tuxhello-"$ver"-*.pkg.tar.zst | grep -v -- -debug- | head -1)
	install_pkg() { pacman -U --noconfirm "$pkg"; }
	remove_pkg() { pacman -R --noconfirm tuxhello; }
	list_pkg() { pacman -Qlq tuxhello; }
	;;
debian)
	mkdir -p "$WORK/deb"
	tar -xf "$tarball" -C "$WORK/deb"
	cp "$tarball" "$WORK/deb/tuxhello_$ver.orig.tar.xz"
	cp -r /src/packaging/debian "$WORK/deb/tux-hello-$ver/debian"
	(cd "$WORK/deb/tux-hello-$ver" && dpkg-buildpackage --no-sign -b)
	pkg=$(ls "$WORK"/deb/tuxhello_"$ver"-*.deb | head -1)
	install_pkg() { dpkg -i "$pkg"; }
	remove_pkg() { dpkg --remove tuxhello; }
	list_pkg() { dpkg -L tuxhello; }
	;;
fedora)
	mkdir -p "$WORK/rpm/SOURCES"
	cp "$tarball" "$WORK/rpm/SOURCES/"
	rpmbuild --define "_topdir $WORK/rpm" -bb /src/packaging/rpm/tuxhello.spec
	pkg=$(ls "$WORK"/rpm/RPMS/*/tuxhello-"$ver"-*.rpm | grep -v -e debuginfo -e debugsource | head -1)
	# Locally built, so unsigned.
	install_pkg() { rpm -i --nosignature "$pkg"; }
	remove_pkg() { rpm -e tuxhello; }
	list_pkg() { rpm -ql tuxhello; }
	;;
*)
	echo "unknown distro: $distro" >&2
	exit 2
	;;
esac
echo "built $pkg"
cp "$pkg" /dist/

# --- install -----------------------------------------------------------------

step "system bus"
mkdir -p /run/dbus
dbus-uuidgen --ensure
rm -f /run/dbus/pid
dbus-daemon --system --fork

# Without systemd, dbus-daemon starts services through its setuid launch
# helper, which only the bus's own group may run. Some container images lose
# that group ownership (Arch's ends up root:root), so put it back. Real
# systems are not affected: there systemd starts tuxhellod.service.
helper=$(sed -n 's:.*<servicehelper>\(.*\)</servicehelper>.*:\1:p' /usr/share/dbus-1/system.conf | head -1)
busgroup=$(id -gn "$(sed -n 's:.*<user>\(.*\)</user>.*:\1:p' /usr/share/dbus-1/system.conf | head -1)")
if [ -n "$helper" ] && [ "$(stat -c %G "$helper")" != "$busgroup" ]; then
	echo "fixing $helper: group $(stat -c %G "$helper") -> $busgroup"
	chgrp "$busgroup" "$helper"
	chmod 4750 "$helper"
fi

step "install"
install_pkg
list_pkg | sed 's/^/  /'

PAMDIR=$(dirname "$(find /lib /lib64 /usr/lib /usr/lib64 -name pam_deny.so -print -quit 2>/dev/null)")
check "PAM module is next to the distro's own modules ($PAMDIR)" test -f "$PAMDIR/pam_tuxhello.so"
check "tuxhello and tuxhello-pam-setup are on PATH" bash -c 'command -v tuxhello && command -v tuxhello-pam-setup'
check "the tuxhello account exists" id tuxhello
check "/var/lib/tuxhello is 0700 and owned by tuxhello" \
	bash -c '[ "$(stat -c "%a %U %G" /var/lib/tuxhello)" = "700 tuxhello tuxhello" ]'
DAEMON=$(list_pkg | grep '/tuxhellod$')
check "the packaged daemon has no stub backend" not grep -qa "Stub backend: recognised" "$DAEMON"
dbus-send --system --type=method_call --print-reply --dest=org.freedesktop.DBus \
	/org/freedesktop/DBus org.freedesktop.DBus.ReloadConfig >/dev/null

# --- use it ------------------------------------------------------------------

step "use the installed package"
USER_A=thpkg
PASSWORD='Corr3ct-Horse!'
PIN=97531
SVC=tuxhello-pkg-test
cc -O1 -o "$WORK/th-pamtest" /src/tests/integration/th-pamtest.c -lpam -lpam_misc
id "$USER_A" >/dev/null 2>&1 || useradd --no-create-home --shell /usr/sbin/nologin "$USER_A"
echo "$USER_A:$PASSWORD" | chpasswd
if [ -f /etc/pam.d/common-auth ]; then
	printf '#%%PAM-1.0\n@include common-auth\n@include common-account\n' >"/etc/pam.d/$SVC"
else
	printf '#%%PAM-1.0\nauth       include      system-auth\naccount    include      system-auth\n' >"/etc/pam.d/$SVC"
fi
cp "/etc/pam.d/$SVC" "$WORK/original"
pt() { "$WORK/th-pamtest" "$SVC" "$USER_A"; }

# Nothing started the daemon: the first call must do it through D-Bus
# activation, as the tuxhello user.
check "D-Bus activation starts the daemon (tuxhello status)" tuxhello status
daemon_runs_as_tuxhello() { # pgrep is not installed everywhere
	local p
	for p in /proc/[0-9]*; do
		if [ "$(cat "$p/comm" 2>/dev/null)" = tuxhellod ]; then
			[ "$(stat -c %U "$p")" = tuxhello ]
			return
		fi
	done
	return 1
}
check "the daemon runs as the tuxhello user" daemon_runs_as_tuxhello
check "enroll a PIN" bash -c "printf '%s\n%s\n' $PIN $PIN | tuxhello enroll pin --user $USER_A"
check "tuxhello-pam-setup enable" tuxhello-pam-setup enable "$SVC"
check "PIN logs in through the installed module" bash -c "echo $PIN | '$WORK/th-pamtest' $SVC $USER_A"
check "empty PIN falls through to the real password" bash -c "printf '\n%s\n' '$PASSWORD' | '$WORK/th-pamtest' $SVC $USER_A"

# --- remove ------------------------------------------------------------------

step "remove (PAM is still enabled: the package must clean up)"
remove_pkg
check "the PAM service file is byte for byte what it was" \
	bash -c "[ \"\$(sha256sum <'/etc/pam.d/$SVC')\" = \"\$(sha256sum <'$WORK/original')\" ]"
check "no pam_tuxhello line is left in /etc/pam.d" not grep -rq pam_tuxhello /etc/pam.d
check "the PAM module is gone" not test -e "$PAMDIR/pam_tuxhello.so"
check "the password still works after removal" bash -c "echo '$PASSWORD' | '$WORK/th-pamtest' $SVC $USER_A"
rm -f "/etc/pam.d/$SVC"

echo
if [ $FAILURES -eq 0 ]; then
	echo "Package test passed on $distro: $(basename "$pkg")"
else
	echo "$FAILURES package check(s) FAILED on $distro."
	exit 1
fi
