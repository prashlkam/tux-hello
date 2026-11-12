Name:           tuxhello
Version:        0.0.1
Release:        1%{?dist}
Summary:        Sign in with a PIN, security key or fingerprint through PAM

# The vendored crates (vendor/) are under licences on the allow-list in
# deny.toml, all GPL-3.0 compatible. An official Fedora package would list
# them here and use packaged crates instead.
License:        GPL-3.0-or-later
URL:            https://github.com/prashlkam/tux-hello
Source0:        %{url}/releases/download/v%{version}/tux-hello-%{version}.tar.xz

BuildRequires:  cargo
BuildRequires:  rust >= 1.85
BuildRequires:  gcc
BuildRequires:  meson >= 0.62
BuildRequires:  pam-devel
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(libfido2) >= 1.13
BuildRequires:  pkgconfig(systemd)
BuildRequires:  pkgconfig(udev)
BuildRequires:  systemd-rpm-macros

Requires:       pam
Requires:       dbus
Recommends:     fprintd
Recommends:     polkit
%{?systemd_requires}

%description
Tux Hello adds Windows Hello-style sign-in to any desktop environment: a PIN,
a FIDO2 security key or a fingerprint can stand in for the password in sudo,
polkit prompts and screen lockers. The password always remains available as
the fallback.

This package contains the PAM module (pam_tuxhello.so), the tuxhellod system
daemon, the tuxhello command-line tool and tuxhello-pam-setup, which edits
the PAM configuration safely and can undo every change.

%prep
%autosetup -n tux-hello-%{version}

%build
# The tarball's .cargo/config.toml points cargo at vendor/, offline.
export CARGO_HOME=$PWD/.cargo-home
# Line tables, so that the -debuginfo package is useful.
export CARGO_PROFILE_RELEASE_DEBUG=line-tables-only
%meson -Dsystemd=enabled
%meson_build

%install
export CARGO_HOME=$PWD/.cargo-home
export CARGO_PROFILE_RELEASE_DEBUG=line-tables-only
%meson_install

%check
export CARGO_HOME=$PWD/.cargo-home
%meson_test

%post
%systemd_post tuxhellod.service
%tmpfiles_create %{_tmpfilesdir}/tuxhello.conf
%udev_rules_update

%preun
%systemd_preun tuxhellod.service
# Take Tux Hello out of PAM while the tool that knows how is still installed.
# Only on removal ($1 == 0): upgrades keep the configuration.
if [ $1 -eq 0 ]; then
    %{_sbindir}/tuxhello-pam-setup disable --all ||
        echo "warning: could not remove Tux Hello from /etc/pam.d; check it by hand" >&2
    # System-wide mode (an authselect profile); does nothing if it is off.
    %{_sbindir}/tuxhello-pam-setup system-wide disable ||
        echo "warning: could not switch the authselect profile back; see authselect current" >&2
fi

%postun
%systemd_postun_with_restart tuxhellod.service
%udev_rules_update

%files
%license LICENSE
%doc README.md
%{_bindir}/tuxhello
%{_sbindir}/tuxhello-pam-setup
%{_libexecdir}/tuxhellod
%{_libdir}/security/pam_tuxhello.so
%{_unitdir}/tuxhellod.service
%{_sysusersdir}/tuxhello.conf
%{_tmpfilesdir}/tuxhello.conf
%{_udevrulesdir}/70-tuxhello-fido.rules
%{_datadir}/dbus-1/system.d/org.tuxhello.Auth1.conf
%{_datadir}/dbus-1/system-services/org.tuxhello.Auth1.service
%{_datadir}/polkit-1/rules.d/50-tuxhello-fprintd.rules
%{_datadir}/tuxhello/

%changelog
* Thu Nov 12 2026 Tux Hello maintainers <maintainers@tuxhello.invalid> - 0.0.1-1
- Initial package: PIN, FIDO2 security key and fingerprint (fprintd)
