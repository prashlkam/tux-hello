// SPDX-FileCopyrightText: 2026 Tux Hello contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `tuxhello doctor`: checks the installation from the outside in and says
//! what to do about each problem. Works (and is most useful) when the daemon
//! cannot be reached.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use tuxhello_client::Client;

#[derive(Default)]
pub struct Report {
    warnings: u32,
    failures: u32,
}

impl Report {
    fn line(tag: &str, what: &str, detail: &str) {
        println!("[{tag}] {what:<12} {detail}");
    }
    fn ok(&mut self, what: &str, detail: &str) {
        Self::line(" ok ", what, detail);
    }
    fn info(&mut self, what: &str, detail: &str) {
        Self::line("info", what, detail);
    }
    fn warn(&mut self, what: &str, detail: &str) {
        self.warnings += 1;
        Self::line("warn", what, detail);
    }
    fn fail(&mut self, what: &str, detail: &str) {
        self.failures += 1;
        Self::line("FAIL", what, detail);
    }
    fn hint(&mut self, text: &str) {
        println!("       {:<12} -> {text}", "");
    }
}

/// HID report descriptors of FIDO devices start with usage page 0xF1D0.
pub fn is_fido_descriptor(desc: &[u8]) -> bool {
    desc.windows(3).any(|w| w == [0x06, 0xd0, 0xf1])
}

fn fido_devices(sys: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let Ok(rd) = std::fs::read_dir(sys.join("class/hidraw")) else {
        return found;
    };
    for e in rd.flatten() {
        if std::fs::read(e.path().join("device/report_descriptor"))
            .is_ok_and(|d| is_fido_descriptor(&d))
        {
            found.push(e.file_name().to_string_lossy().into_owned());
        }
    }
    found.sort();
    found
}

fn tpm_version(sys: &Path) -> Option<String> {
    std::fs::read_to_string(sys.join("class/tpm/tpm0/tpm_version_major"))
        .ok()
        .map(|v| v.trim().to_string())
}

fn find_program(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        // sbin is often missing from an unprivileged user's PATH.
        .chain(["/usr/sbin".into(), "/sbin".into(), "/usr/bin".into()])
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// What `tuxhello-pam-setup status` says, reduced to what doctor reports.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PamStatus {
    pub module: Option<String>,
    pub enabled: Vec<String>,
    /// (service, other modules it uses) for services Tux Hello is enabled on.
    pub conflicts: Vec<(String, String)>,
}

pub fn parse_pam_status(text: &str) -> PamStatus {
    let mut st = PamStatus::default();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("PAM module:") {
            let v = v.trim();
            st.module = (!v.starts_with("NOT INSTALLED")).then(|| v.to_string());
        } else if let Some(v) = line.strip_prefix("enabled for:") {
            st.enabled = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && s != "nothing")
                .collect();
        } else if let Some((left, uses)) = line.split_once("also uses:") {
            let mut it = left.split_whitespace();
            if let (Some(svc), Some("enabled")) = (it.next(), it.next()) {
                st.conflicts
                    .push((svc.to_string(), uses.trim().to_string()));
            }
        }
    }
    st
}

fn check_daemon(r: &mut Report, client: Option<&Client>) -> bool {
    let Some(client) = client else {
        r.fail("daemon", "cannot connect to the D-Bus system bus");
        r.hint("is dbus running? (`systemctl status dbus`)");
        return false;
    };
    let version = match client.version() {
        Ok(v) => v,
        Err(e) => {
            r.fail("daemon", &format!("tuxhellod does not answer: {e}"));
            r.hint("`systemctl status tuxhellod` and `journalctl -u tuxhellod -b` show why");
            r.hint("if the service is unknown, the package is not installed completely");
            return false;
        }
    };
    let mine = env!("CARGO_PKG_VERSION");
    if version == mine {
        r.ok("daemon", &format!("tuxhellod {version} is running"));
    } else {
        r.warn(
            "daemon",
            &format!("tuxhellod is {version} but this tool is {mine}"),
        );
        r.hint("restart the daemon after an upgrade: `sudo systemctl restart tuxhellod`");
    }
    match client.info() {
        Ok(info) => {
            let get = |k: &str| info.get(k).map(String::as_str).unwrap_or("?");
            let key = get("store-key");
            let line = format!("{} (master key: {key})", get("store"));
            if key.starts_with("file") {
                r.info("store", &line);
            } else {
                r.ok("store", &line);
            }
        }
        Err(e) => r.warn("store", &format!("cannot read daemon information: {e}")),
    }
    true
}

fn check_methods(r: &mut Report, client: &Client, sys: &Path) {
    let backends = client.list_backends().unwrap_or_default();
    let available = |name: &str| {
        backends
            .iter()
            .find(|b| b.name == name)
            .map(|b| b.available)
    };

    match available("pin") {
        Some(true) => r.ok("pin", "available"),
        _ => r.fail("pin", "the PIN method is missing from the daemon"),
    }

    let fido = fido_devices(sys);
    match (available("key"), fido.is_empty()) {
        (None, _) => r.info("key", "this build has no security-key support"),
        (Some(true), _) => r.ok("key", "a security key is plugged in and usable"),
        (Some(false), true) => r.info("key", "no security key is plugged in"),
        (Some(false), false) => {
            r.warn(
                "key",
                &format!(
                    "a FIDO device is plugged in ({}) but the daemon cannot open it",
                    fido.join(", ")
                ),
            );
            r.hint("the udev rule 70-tuxhello-fido.rules must be installed; then replug the key");
        }
    }

    match available("fingerprint") {
        None => r.info("fingerprint", "switched off in the configuration"),
        Some(true) => r.ok("fingerprint", "fprintd has a reader"),
        Some(false) => {
            if find_program("fprintd-enroll").is_none() {
                r.info("fingerprint", "fprintd is not installed");
            } else {
                r.info(
                    "fingerprint",
                    "fprintd reports no reader (or has not been asked yet)",
                );
                r.hint("`fprintd-list $USER` shows what fprintd sees");
            }
        }
    }

    if backends.iter().any(|b| b.name == "stub") {
        r.fail(
            "stub",
            "the TEST-ONLY stub backend is active; it can let anyone in",
        );
        r.hint("install a release build and remove [stub] from /etc/tuxhello/config.toml");
    }
}

fn check_tpm(r: &mut Report, sys: &Path, dev: &Path) {
    match tpm_version(sys) {
        Some(v) if v == "2" => {
            if dev.join("tpmrm0").exists() {
                r.info("tpm", "TPM 2.0 present");
            } else {
                r.info("tpm", "TPM 2.0 present, but /dev/tpmrm0 is missing");
            }
        }
        Some(v) => r.info("tpm", &format!("TPM {v}.x present; only TPM 2.0 is used")),
        None => r.info("tpm", "no TPM found"),
    }
}

fn check_pam(r: &mut Report) {
    let Some(setup) = find_program("tuxhello-pam-setup") else {
        r.fail("pam", "tuxhello-pam-setup is not installed");
        return;
    };
    let out = match Command::new(&setup).arg("status").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        Ok(o) => {
            r.warn(
                "pam",
                &format!(
                    "`tuxhello-pam-setup status` failed: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                ),
            );
            return;
        }
        Err(e) => {
            r.warn("pam", &format!("cannot run {}: {e}", setup.display()));
            return;
        }
    };
    let st = parse_pam_status(&out);
    match &st.module {
        Some(path) => r.ok("pam module", path),
        None => {
            r.fail("pam module", "pam_tuxhello.so is not installed");
            r.hint("PAM skips the missing module, so logins still work, but Tux Hello cannot");
        }
    }
    if st.enabled.is_empty() {
        r.info("pam", "not enabled for any service yet");
        r.hint("`sudo tuxhello-pam-setup enable --dry-run` shows what enabling would change");
    } else {
        r.ok("pam", &format!("enabled for {}", st.enabled.join(", ")));
    }
    for (svc, uses) in &st.conflicts {
        r.warn(
            "pam",
            &format!("{svc} also uses {uses}: you may be asked twice"),
        );
        r.hint("remove the other module from that service, or disable Tux Hello for it");
    }
}

fn check_user(r: &mut Report, client: &Client, name: &str, uid: u32) {
    match client.list_enrollments(uid) {
        Ok(v) if v.is_empty() => {
            r.info("enrolments", &format!("{name} has nothing enrolled"));
            r.hint("`sudo tuxhello enroll pin` is the quickest start");
        }
        Ok(v) => {
            let mut methods: Vec<&str> = v.iter().map(|(m, _)| m.as_str()).collect();
            methods.dedup();
            r.ok(
                "enrolments",
                &format!("{name}: {} ({})", v.len(), methods.join(", ")),
            );
        }
        Err(e) => r.warn("enrolments", &format!("cannot list them: {e}")),
    }
    if let Ok(p) = client.explain_policy(uid, "sudo") {
        let usable = p.get("usable").map(String::as_str).unwrap_or("");
        let require = p.get("require").map(String::as_str).unwrap_or("?");
        if usable.is_empty() {
            r.info(
                "policy",
                &format!("sudo wants {require}; nothing usable now, so the password is asked"),
            );
        } else {
            r.ok(
                "policy",
                &format!("sudo wants {require}; usable now: {usable}"),
            );
        }
    }
    if let Ok(l) = client.lockout(uid) {
        let get = |k: &str| l.get(k).copied().unwrap_or(0);
        if get("biometrics-locked") != 0 {
            r.warn(
                "lockout",
                "biometrics are switched off after failed attempts",
            );
            r.hint("log in with your PIN or security key, or run `sudo tuxhello unlock`");
        }
        if get("pin-locked-s") != 0 {
            r.warn(
                "lockout",
                &format!("the PIN is locked for another {} s", get("pin-locked-s")),
            );
        }
        if get("throttled-s") != 0 {
            r.warn(
                "lockout",
                &format!(
                    "too many failed attempts; paused for another {} s",
                    get("throttled-s")
                ),
            );
        }
    }
}

pub fn run(client: Option<&Client>, session_bus: bool, name: &str, uid: u32) -> ExitCode {
    let mut r = Report::default();
    let sys = Path::new("/sys");
    let daemon_up = check_daemon(&mut r, client);
    if let (true, Some(client)) = (daemon_up, client) {
        check_methods(&mut r, client, sys);
    }
    check_tpm(&mut r, sys, Path::new("/dev"));
    if session_bus {
        r.info(
            "pam",
            "skipped: the PAM module only ever uses the system bus",
        );
    } else {
        check_pam(&mut r);
    }
    if let (true, Some(client)) = (daemon_up, client) {
        check_user(&mut r, client, name, uid);
    }

    println!();
    match (r.failures, r.warnings) {
        (0, 0) => println!("No problems found."),
        (0, w) => println!("{w} warning(s), no failures."),
        (f, w) => println!("{f} failure(s), {w} warning(s)."),
    }
    if r.failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fido_usage_page_detection() {
        // Start of a real FIDO report descriptor: Usage Page (FIDO Alliance).
        assert!(is_fido_descriptor(&[
            0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01
        ]));
        // A keyboard: Usage Page (Generic Desktop).
        assert!(!is_fido_descriptor(&[0x05, 0x01, 0x09, 0x06, 0xa1, 0x01]));
        assert!(!is_fido_descriptor(&[]));
    }

    #[test]
    fn pam_status_parsing() {
        let st = parse_pam_status(
            "distribution family: arch\n\
             PAM module:          /usr/lib/security/pam_tuxhello.so\n\
             enabled for:         sudo, polkit-1\n\
             \n\
             services on this system:\n\
             \x20 sudo           enabled    also uses: pam_u2f\n\
             \x20 login          -          also uses: pam_fprintd\n\
             \x20 polkit-1       enabled   (vendor file)\n",
        );
        assert_eq!(
            st.module.as_deref(),
            Some("/usr/lib/security/pam_tuxhello.so")
        );
        assert_eq!(st.enabled, vec!["sudo", "polkit-1"]);
        // Only services Tux Hello is enabled on can ask twice.
        assert_eq!(st.conflicts, vec![("sudo".into(), "pam_u2f".into())]);
    }

    #[test]
    fn pam_status_when_nothing_is_set_up() {
        let st = parse_pam_status(
            "PAM module:          NOT INSTALLED (pam_tuxhello.so not found)\n\
             enabled for:         nothing\n",
        );
        assert_eq!(st, PamStatus::default());
    }

    #[test]
    fn sysfs_probes_read_fake_trees() {
        let mut id = [0u8; 8];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut id))
            .unwrap();
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        let sys = std::env::temp_dir().join(format!("tuxhello-doctor-{hex}"));
        assert!(fido_devices(&sys).is_empty());
        assert_eq!(tpm_version(&sys), None);

        let key = sys.join("class/hidraw/hidraw3/device");
        let kbd = sys.join("class/hidraw/hidraw0/device");
        std::fs::create_dir_all(&key).unwrap();
        std::fs::create_dir_all(&kbd).unwrap();
        std::fs::write(key.join("report_descriptor"), [0x06, 0xd0, 0xf1, 0x09]).unwrap();
        std::fs::write(kbd.join("report_descriptor"), [0x05, 0x01, 0x09, 0x06]).unwrap();
        std::fs::create_dir_all(sys.join("class/tpm/tpm0")).unwrap();
        std::fs::write(sys.join("class/tpm/tpm0/tpm_version_major"), "2\n").unwrap();

        assert_eq!(fido_devices(&sys), vec!["hidraw3".to_string()]);
        assert_eq!(tpm_version(&sys).as_deref(), Some("2"));
        std::fs::remove_dir_all(&sys).unwrap();
    }
}
