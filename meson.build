project('tux-hello',
  version: '0.0.1',
  license: 'GPL-3.0-or-later AND (MIT OR Apache-2.0)',
  meson_version: '>= 0.62.0',
)

# Meson only wraps cargo so that distributions get standard install paths
# (PAM module dir, D-Bus dirs, systemd dirs, multiarch libdir). See ADR 0006.

cargo = find_program('cargo')
prefix = get_option('prefix')
libexecdir = prefix / get_option('libexecdir')
bindir = prefix / get_option('bindir')
datadir = prefix / get_option('datadir')
sysconfdir = get_option('sysconfdir')

pam_moduledir = get_option('pam_moduledir')
if pam_moduledir == ''
  pam_moduledir = prefix / get_option('libdir') / 'security'
endif

# libdbus, libpam and libfido2 are needed at link time by the Rust crates.
dependency('dbus-1')
dependency('libfido2', version: '>= 1.13')
# libpam headers are checked by the C toolchain at link time; not every distro ships pam.pc.

profile = get_option('buildtype') == 'debug' ? 'debug' : 'release'
features = get_option('stub_backend') ? 'tuxhello-daemon/stub-backend' : ''
if get_option('stub_backend')
  warning('Building the STUB backend. Never install this build on a real system.')
endif

rust_build = custom_target('cargo-build',
  output: ['tuxhellod', 'tuxhello', 'pam_tuxhello.so'],
  command: [
    files('build-aux/cargo-build.sh'), cargo,
    meson.project_source_root(),
    meson.current_build_dir() / 'cargo-target',
    meson.current_build_dir(),
    profile,
    features,
  ],
  console: true,
  build_always_stale: true,
  build_by_default: true,
  install: true,
  install_dir: [libexecdir, bindir, pam_moduledir],
)

conf = configuration_data()
conf.set('libexecdir', libexecdir)

# D-Bus
install_data('data/dbus/org.tuxhello.Auth1.conf',
  install_dir: datadir / 'dbus-1' / 'system.d')
configure_file(
  input: 'data/dbus/org.tuxhello.Auth1.service.in',
  output: 'org.tuxhello.Auth1.service',
  configuration: conf,
  install_dir: datadir / 'dbus-1' / 'system-services',
)

# systemd
systemd = dependency('systemd', required: get_option('systemd'))
if systemd.found()
  unitdir = get_option('systemdsystemunitdir')
  if unitdir == ''
    unitdir = systemd.get_variable(pkgconfig: 'systemdsystemunitdir',
                                   pkgconfig_define: ['prefix', prefix])
  endif
  configure_file(
    input: 'data/systemd/tuxhellod.service.in',
    output: 'tuxhellod.service',
    configuration: conf,
    install_dir: unitdir,
  )
  install_data('data/sysusers/tuxhello.conf',
    install_dir: systemd.get_variable(pkgconfig: 'sysusersdir',
                                      pkgconfig_define: ['prefix', prefix]))
  install_data('data/tmpfiles/tuxhello.conf',
    install_dir: systemd.get_variable(pkgconfig: 'tmpfilesdir',
                                      pkgconfig_define: ['prefix', prefix]))
endif

# udev: security-key access for the daemon's group
udev = dependency('udev', required: false)
udevdir = udev.found() ? udev.get_variable(pkgconfig: 'udevdir', pkgconfig_define: ['prefix', prefix]) : prefix / 'lib' / 'udev'
install_data('data/udev/70-tuxhello-fido.rules', install_dir: udevdir / 'rules.d')

# OpenRC
if get_option('openrc')
  configure_file(
    input: 'data/openrc/tuxhellod.in',
    output: 'tuxhellod',
    configuration: conf,
    install_dir: sysconfdir / 'init.d',
    install_mode: 'rwxr-xr-x',
  )
endif

# Example configuration (not installed into /etc: defaults are built in).
install_data('data/config.toml',
  install_dir: datadir / 'tuxhello',
  rename: 'config.toml.example')

test('cargo-test', cargo,
  args: ['test', '--workspace', '--manifest-path',
         meson.project_source_root() / 'Cargo.toml',
         '--target-dir', meson.current_build_dir() / 'cargo-target'],
  timeout: 600,
)

summary({
  'PAM module dir': pam_moduledir,
  'daemon': libexecdir / 'tuxhellod',
  'systemd': systemd.found(),
  'OpenRC': get_option('openrc'),
  'stub backend (TESTING ONLY)': get_option('stub_backend'),
}, section: 'Tux Hello')
