//! `tuxhello-pam-setup` — add or remove Tux Hello in PAM services, safely.
//!
//! * Per-service edits (default, every distro): a marked block in front of
//!   the service's first auth line, e.g. in /etc/pam.d/sudo. Shared files such
//!   as system-auth or common-auth are never edited in this mode.
//! * System-wide on Debian/Ubuntu: a pam-auth-update profile.
//! * Every change is preceded by a backup; `rollback` restores the latest
//!   one. `--dry-run` shows what would change. Each edit is verified to be
//!   exactly "the original plus our block" before it is written.

mod pamfile;

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command as Proc, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

const PAM_DIR: &str = "/etc/pam.d";
/// Vendor directories Linux-PAM falls back to when /etc/pam.d/<svc> is absent.
const VENDOR_PAM_DIRS: &[&str] = &["/usr/lib/pam.d", "/usr/share/pam.d"];
const BACKUP_DIR: &str = "/var/lib/tuxhello/pam-backup";
const MODULE: &str = "pam_tuxhello.so";
const MODULE_DIRS: &[&str] = &[
    "/usr/lib/security",
    "/usr/lib64/security",
    "/lib/security",
    "/lib64/security",
];
/// Parent dirs searched for multiarch module dirs (`<dir>/<triplet>/security`).
const MULTIARCH_PARENTS: &[&str] = &["/usr/lib", "/lib"];
const DEBIAN_PROFILE: &str = "/usr/share/pam-configs/tuxhello";

/// Enabled by default when no services are named: privilege prompts and
/// screen lockers. Login screens must be named explicitly (keyring caveat,
/// PLAN.md §7.3).
const DEFAULT_SERVICES: &[&str] = &[
    "sudo",
    "sudo-i",
    "polkit-1",
    "swaylock",
    "hyprlock",
    "i3lock",
    "gtklock",
    "waylock",
    "kde",
    "xscreensaver",
    "xsecurelock",
    "physlock",
];

const LOGIN_SERVICES: &[&str] = &["gdm-password", "sddm", "lightdm", "greetd", "ly", "login"];

/// Never touched: remote access, and files included by many services.
const FORBIDDEN: &[&str] = &[
    "sshd",
    "xrdp-sesman",
    "cockpit",
    "other",
    "system-auth",
    "password-auth",
    "system-login",
    "system-local-login",
    "system-remote-login",
    "system-services",
    "fingerprint-auth",
    "smartcard-auth",
    "postlogin",
    "common-auth",
    "common-account",
    "common-password",
    "common-session",
    "common-session-noninteractive",
];

const DEBIAN_PROFILE_TEXT: &str = "\
Name: Tux Hello (PIN, security key, fingerprint, face)
Default: no
Priority: 260
Auth-Type: Primary
Auth:
\t[success=end default=ignore]\tpam_tuxhello.so
Auth-Initial:
\t[success=end default=ignore]\tpam_tuxhello.so
";

#[derive(Parser)]
#[command(
    name = "tuxhello-pam-setup",
    version,
    about = "Safely add or remove Tux Hello in PAM service files"
)]
struct Cli {
    /// Operate on a different root directory (for testing and image builds).
    #[arg(long, global = true, default_value = "/")]
    root: PathBuf,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show which services use Tux Hello, and possible conflicts.
    Status,
    /// Add Tux Hello to services (default: sudo, polkit and installed screen lockers).
    Enable {
        /// PAM service names, e.g. sudo polkit-1 swaylock gdm-password.
        services: Vec<String>,
        /// Show what would change without changing anything.
        #[arg(long)]
        dry_run: bool,
        /// Don't require pam_tuxhello.so to be installed (image builds).
        #[arg(long)]
        skip_module_check: bool,
    },
    /// Remove Tux Hello from services.
    Disable {
        services: Vec<String>,
        /// Remove it from every service that has it.
        #[arg(long, conflicts_with = "services")]
        all: bool,
        #[arg(long)]
        dry_run: bool,
    },
    /// Restore PAM files from a backup (default: the most recent one).
    Rollback {
        /// Backup id (see --list).
        id: Option<String>,
        #[arg(long)]
        list: bool,
    },
    /// Debian/Ubuntu: enable or disable for every service via pam-auth-update.
    SystemWide {
        #[arg(value_parser = ["enable", "disable"])]
        action: String,
    },
}

/// Maps absolute paths into `--root`.
struct Env {
    root: PathBuf,
}

impl Env {
    fn p(&self, abs: &str) -> PathBuf {
        self.root.join(abs.trim_start_matches('/'))
    }

    fn is_real_root(&self) -> bool {
        self.root == Path::new("/")
    }

    fn distro_family(&self) -> &'static str {
        let text = fs::read_to_string(self.p("/etc/os-release")).unwrap_or_default();
        let field = |k: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(&format!("{k}=")))
                .map(|v| v.trim_matches('"').to_lowercase())
                .unwrap_or_default()
        };
        let ids = format!("{} {}", field("ID"), field("ID_LIKE"));
        let has = |w: &str| ids.split_whitespace().any(|x| x == w);
        if has("debian") || has("ubuntu") {
            "debian"
        } else if has("fedora") || has("rhel") || has("centos") {
            "fedora"
        } else if has("arch") {
            "arch"
        } else if has("suse") || has("opensuse") {
            "suse"
        } else {
            "other"
        }
    }

    fn module_installed(&self) -> Option<PathBuf> {
        let mut dirs: Vec<PathBuf> = MODULE_DIRS.iter().map(|d| self.p(d)).collect();
        for parent in MULTIARCH_PARENTS {
            if let Ok(rd) = fs::read_dir(self.p(parent)) {
                for e in rd.flatten() {
                    if e.file_name().to_string_lossy().contains("-linux-") {
                        dirs.push(e.path().join("security"));
                    }
                }
            }
        }
        dirs.into_iter()
            .map(|d| d.join(MODULE))
            .find(|f| f.exists())
    }

    /// The file to edit for `svc`, and its current content. A service that
    /// only exists in a vendor dir is overridden by a copy in /etc/pam.d.
    fn service_file(&self, svc: &str) -> Option<(PathBuf, String, bool)> {
        let etc = self.p(PAM_DIR).join(svc);
        if let Ok(t) = fs::read_to_string(&etc) {
            return Some((etc, t, true));
        }
        for d in VENDOR_PAM_DIRS {
            if let Ok(t) = fs::read_to_string(self.p(d).join(svc)) {
                return Some((etc, t, false));
            }
        }
        None
    }

    fn services_with_block(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(rd) = fs::read_dir(self.p(PAM_DIR)) {
            for e in rd.flatten() {
                if let Ok(t) = fs::read_to_string(e.path()) {
                    if pamfile::has_block(&t) {
                        out.push(e.file_name().to_string_lossy().into_owned());
                    }
                }
            }
        }
        out.sort();
        out
    }
}

fn valid_service_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !s.starts_with('.')
}

// --- backups -------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct Manifest {
    created: u64,
    command: String,
    #[serde(default)]
    file: Vec<BackedUp>,
}

#[derive(Serialize, Deserialize)]
struct BackedUp {
    /// Absolute path (relative to --root).
    path: String,
    existed: bool,
    /// File name of the copy inside the backup directory.
    copy: Option<String>,
    mode: Option<u32>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Saves the current state of `paths` (relative to root) and returns the
/// backup id.
fn backup(env: &Env, paths: &[String], command: &str) -> io::Result<String> {
    let base = env.p(BACKUP_DIR);
    fs::create_dir_all(&base)?;
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700))?;
    let mut id = now().to_string();
    let mut n = 1;
    while base.join(&id).exists() {
        id = format!("{}-{n}", now());
        n += 1;
    }
    let dir = base.join(&id);
    fs::create_dir(&dir)?;
    let mut m = Manifest {
        created: now(),
        command: command.to_string(),
        file: Vec::new(),
    };
    for (i, abs) in paths.iter().enumerate() {
        let real = env.p(abs);
        match fs::metadata(&real) {
            Ok(md) => {
                let copy = format!("{i}.bak");
                fs::copy(&real, dir.join(&copy))?;
                m.file.push(BackedUp {
                    path: abs.clone(),
                    existed: true,
                    copy: Some(copy),
                    mode: Some(md.permissions().mode() & 0o7777),
                });
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => m.file.push(BackedUp {
                path: abs.clone(),
                existed: false,
                copy: None,
                mode: None,
            }),
            Err(e) => return Err(e),
        }
    }
    let text = toml::to_string(&m).map_err(io::Error::other)?;
    fs::write(dir.join("manifest.toml"), text)?;
    Ok(id)
}

fn list_backups(env: &Env) -> Vec<(String, Manifest)> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(env.p(BACKUP_DIR)) {
        for e in rd.flatten() {
            let id = e.file_name().to_string_lossy().into_owned();
            if let Ok(t) = fs::read_to_string(e.path().join("manifest.toml")) {
                if let Ok(m) = toml::from_str::<Manifest>(&t) {
                    out.push((id, m));
                }
            }
        }
    }
    out.sort_by(|a, b| a.1.created.cmp(&b.1.created).then(a.0.cmp(&b.0)));
    out
}

/// Writes `text` atomically with `mode`.
fn write_atomic(path: &Path, text: &str, mode: u32) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tuxhello-tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    fs::write(&tmp, text)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    if let Ok(f) = fs::File::open(&tmp) {
        let _ = f.sync_all();
    }
    fs::rename(&tmp, path)
}

// --- commands ------------------------------------------------------------------

type Res = Result<ExitCode, String>;

fn require_root(env: &Env, dry_run: bool) -> Result<(), String> {
    if dry_run || !env.is_real_root() || nix::unistd::geteuid().is_root() {
        Ok(())
    } else {
        Err("this changes /etc/pam.d: run it with sudo (or use --dry-run)".into())
    }
}

fn status(env: &Env) -> Res {
    println!("distribution family: {}", env.distro_family());
    match env.module_installed() {
        Some(p) => println!("PAM module:          {}", p.display()),
        None => println!("PAM module:          NOT INSTALLED ({MODULE} not found)"),
    }
    let enabled = env.services_with_block();
    println!(
        "enabled for:         {}",
        if enabled.is_empty() {
            "nothing".to_string()
        } else {
            enabled.join(", ")
        }
    );
    if let Ok(t) = fs::read_to_string(env.p("/etc/pam.d/common-auth")) {
        if t.contains(MODULE) {
            println!("system-wide:         enabled via pam-auth-update (common-auth)");
        }
    }
    let mut candidates: BTreeSet<&str> = DEFAULT_SERVICES.iter().copied().collect();
    candidates.extend(LOGIN_SERVICES);
    println!("\nservices on this system:");
    for svc in candidates {
        if let Some((_, text, in_etc)) = env.service_file(svc) {
            let on = pamfile::has_block(&text);
            let conflicts = pamfile::conflicts(&text);
            println!(
                "  {:<14} {:<9}{}{}",
                svc,
                if on { "enabled" } else { "-" },
                if in_etc { "" } else { " (vendor file)" },
                if conflicts.is_empty() {
                    String::new()
                } else {
                    format!("  also uses: {}", conflicts.join(", "))
                }
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

struct Planned {
    svc: String,
    path: PathBuf,
    abs: String,
    old_exists: bool,
    new_text: String,
}

fn abs_of(env: &Env, p: &Path) -> String {
    format!(
        "/{}",
        p.strip_prefix(&env.root)
            .unwrap_or(p)
            .to_string_lossy()
            .trim_start_matches('/')
    )
}

fn enable(env: &Env, services: Vec<String>, dry_run: bool, skip_module_check: bool) -> Res {
    require_root(env, dry_run)?;
    if !skip_module_check && env.module_installed().is_none() {
        return Err(format!(
            "{MODULE} is not installed in any PAM module directory; install Tux Hello first \
             (or pass --skip-module-check)"
        ));
    }
    let explicit = !services.is_empty();
    let wanted: Vec<String> = if explicit {
        services
    } else {
        DEFAULT_SERVICES
            .iter()
            .filter(|s| env.service_file(s).is_some())
            .map(|s| s.to_string())
            .collect()
    };
    if wanted.is_empty() {
        return Err("no matching PAM services found".into());
    }

    let mut plan = Vec::new();
    let mut problems = Vec::new();
    for svc in &wanted {
        if !valid_service_name(svc) {
            problems.push(format!("{svc:?}: not a valid service name"));
            continue;
        }
        if FORBIDDEN.contains(&svc.as_str()) {
            problems.push(format!(
                "{svc}: refused (remote access or shared include file; use system-wide on Debian)"
            ));
            continue;
        }
        let Some((path, text, in_etc)) = env.service_file(svc) else {
            if explicit {
                problems.push(format!("{svc}: no such PAM service"));
            }
            continue;
        };
        if pamfile::has_block(&text) {
            println!("{svc}: already enabled");
            continue;
        }
        let new_text = match pamfile::insert_block(&text) {
            Ok(t) => t,
            Err(e) => {
                problems.push(format!("{svc}: {e}"));
                continue;
            }
        };
        if !pamfile::verify_edit(&text, &new_text) || !pamfile::syntax_ok(&new_text) {
            problems.push(format!("{svc}: internal check failed; not touching it"));
            continue;
        }
        for c in pamfile::conflicts(&text) {
            println!("{svc}: note: also uses {c}; you may get two prompts");
        }
        let abs = abs_of(env, &path);
        plan.push(Planned {
            svc: svc.clone(),
            path,
            abs,
            old_exists: in_etc,
            new_text,
        });
    }
    for p in &problems {
        eprintln!("tuxhello-pam-setup: {p}");
    }
    if plan.is_empty() {
        return if problems.is_empty() {
            Ok(ExitCode::SUCCESS)
        } else {
            Err("nothing changed".into())
        };
    }

    for p in &plan {
        println!(
            "{} {}{}",
            if dry_run { "would enable" } else { "enabling" },
            p.abs,
            if p.old_exists {
                ""
            } else {
                " (new override of the vendor file)"
            }
        );
        if dry_run {
            for l in p.new_text.lines() {
                let added = l == pamfile::BEGIN || l == pamfile::MODULE_LINE || l == pamfile::END;
                println!("    {}{}", if added { "+" } else { " " }, l);
            }
        }
    }
    if dry_run {
        return Ok(ExitCode::SUCCESS);
    }

    let abs: Vec<String> = plan.iter().map(|p| p.abs.clone()).collect();
    let id = backup(env, &abs, &format!("enable {}", wanted.join(" ")))
        .map_err(|e| format!("backup failed, nothing changed: {e}"))?;
    for p in &plan {
        let mode = fs::metadata(&p.path)
            .map(|m| m.permissions().mode() & 0o7777)
            .unwrap_or(0o644);
        write_atomic(&p.path, &p.new_text, mode).map_err(|e| {
            format!(
                "{}: {e} (restore with: tuxhello-pam-setup rollback {id})",
                p.svc
            )
        })?;
    }
    println!("Backup saved as {id}. Undo with: sudo tuxhello-pam-setup rollback");
    println!(
        "Keep this terminal open and test in another one (e.g. `sudo -k; sudo true`). \
         Your password always keeps working."
    );
    Ok(if problems.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn disable(env: &Env, services: Vec<String>, all: bool, dry_run: bool) -> Res {
    require_root(env, dry_run)?;
    let targets = if all || services.is_empty() {
        env.services_with_block()
    } else {
        services
    };
    let mut plan = Vec::new();
    for svc in &targets {
        if !valid_service_name(svc) {
            return Err(format!("{svc:?}: not a valid service name"));
        }
        let path = env.p(PAM_DIR).join(svc);
        let Ok(text) = fs::read_to_string(&path) else {
            println!("{svc}: not configured");
            continue;
        };
        if !pamfile::has_block(&text) {
            println!("{svc}: not enabled");
            continue;
        }
        let new_text = pamfile::remove_block(&text).map_err(|e| format!("{svc}: {e}"))?;
        // An override we created from a vendor file: once our block is gone it
        // is identical to the vendor file, so delete it rather than leave a
        // copy that would hide future package updates.
        let vendor_same = VENDOR_PAM_DIRS
            .iter()
            .any(|d| fs::read_to_string(env.p(d).join(svc)).is_ok_and(|v| v == new_text));
        plan.push((svc.clone(), path, (!vendor_same).then_some(new_text)));
    }
    if plan.is_empty() {
        println!("Nothing to disable.");
        return Ok(ExitCode::SUCCESS);
    }
    for (svc, _, _) in &plan {
        println!(
            "{} {svc}",
            if dry_run {
                "would disable"
            } else {
                "disabling"
            }
        );
    }
    if dry_run {
        return Ok(ExitCode::SUCCESS);
    }
    let abs: Vec<String> = plan.iter().map(|(_, p, _)| abs_of(env, p)).collect();
    let id = backup(env, &abs, "disable").map_err(|e| format!("backup failed: {e}"))?;
    for (svc, path, text) in &plan {
        let r = match text {
            Some(text) => {
                let mode = fs::metadata(path)
                    .map(|m| m.permissions().mode() & 0o7777)
                    .unwrap_or(0o644);
                write_atomic(path, text, mode)
            }
            None => fs::remove_file(path).inspect(|()| {
                println!("{svc}: removed the override; the vendor file applies again");
            }),
        };
        r.map_err(|e| format!("{svc}: {e} (restore with: tuxhello-pam-setup rollback {id})"))?;
    }
    println!("Backup saved as {id}.");
    Ok(ExitCode::SUCCESS)
}

fn rollback(env: &Env, id: Option<String>, list: bool) -> Res {
    let backups = list_backups(env);
    if list {
        if backups.is_empty() {
            println!("No backups.");
        }
        for (id, m) in &backups {
            let files: Vec<&str> = m.file.iter().map(|f| f.path.as_str()).collect();
            println!("{id:<14} {:<28} {}", m.command, files.join(" "));
        }
        return Ok(ExitCode::SUCCESS);
    }
    require_root(env, false)?;
    let (id, m) = match id {
        Some(want) => backups
            .into_iter()
            .find(|(i, _)| *i == want)
            .ok_or_else(|| format!("no backup {want:?} (see --list)"))?,
        None => backups.into_iter().last().ok_or("no backups to restore")?,
    };
    let dir = env.p(BACKUP_DIR).join(&id);
    for f in &m.file {
        if !f.path.starts_with("/etc/pam.d/") && f.path != DEBIAN_PROFILE {
            return Err(format!("backup {id} lists unexpected path {}", f.path));
        }
        let target = env.p(&f.path);
        match (&f.existed, &f.copy) {
            (true, Some(copy)) => {
                let text = fs::read_to_string(dir.join(copy))
                    .map_err(|e| format!("{}: {e}", dir.join(copy).display()))?;
                write_atomic(&target, &text, f.mode.unwrap_or(0o644))
                    .map_err(|e| format!("{}: {e}", f.path))?;
                println!("restored {}", f.path);
            }
            _ => match fs::remove_file(&target) {
                Ok(()) => println!("removed {} (it did not exist before)", f.path),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("{}: {e}", f.path)),
            },
        }
    }
    println!(
        "Rolled back to the state before backup {id} ({}).",
        m.command
    );
    Ok(ExitCode::SUCCESS)
}

fn system_wide(env: &Env, action: &str) -> Res {
    if env.distro_family() != "debian" {
        return Err(
            "system-wide mode is only implemented for Debian/Ubuntu (pam-auth-update); \
             enable individual services instead"
                .into(),
        );
    }
    require_root(env, false)?;
    let profile = env.p(DEBIAN_PROFILE);
    if action == "enable" {
        if env.module_installed().is_none() {
            return Err(format!("{MODULE} is not installed"));
        }
        if !profile.exists() {
            write_atomic(&profile, DEBIAN_PROFILE_TEXT, 0o644)
                .map_err(|e| format!("{}: {e}", profile.display()))?;
        }
    }
    if !env.is_real_root() {
        println!("(--root given: not running pam-auth-update)");
        return Ok(ExitCode::SUCCESS);
    }
    let backup_id = backup(
        env,
        &[
            "/etc/pam.d/common-auth".to_string(),
            DEBIAN_PROFILE.to_string(),
        ],
        &format!("system-wide {action}"),
    )
    .map_err(|e| format!("backup failed: {e}"))?;
    let flag = if action == "enable" {
        "--enable"
    } else {
        "--disable"
    };
    let st = Proc::new("pam-auth-update")
        .args(["--package", flag, "tuxhello"])
        .status()
        .map_err(|e| format!("cannot run pam-auth-update: {e}"))?;
    if !st.success() {
        return Err(format!(
            "pam-auth-update failed ({st}); restore with: tuxhello-pam-setup rollback {backup_id}"
        ));
    }
    println!("System-wide Tux Hello {action}d (backup {backup_id}).");
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let env = Env { root: cli.root };
    let r = match cli.command {
        Cmd::Status => status(&env),
        Cmd::Enable {
            services,
            dry_run,
            skip_module_check,
        } => enable(&env, services, dry_run, skip_module_check),
        Cmd::Disable {
            services,
            all,
            dry_run,
        } => disable(&env, services, all, dry_run),
        Cmd::Rollback { id, list } => rollback(&env, id, list),
        Cmd::SystemWide { action } => system_wide(&env, &action),
    };
    r.unwrap_or_else(|e| {
        eprintln!("tuxhello-pam-setup: {e}");
        ExitCode::from(2)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Root(PathBuf);
    impl Root {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "tuxhello-pam-setup-test-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(p.join("etc/pam.d")).unwrap();
            fs::create_dir_all(p.join("usr/lib/security")).unwrap();
            fs::write(p.join("usr/lib/security").join(MODULE), "").unwrap();
            Root(p)
        }
        fn env(&self) -> Env {
            Env {
                root: self.0.clone(),
            }
        }
        fn write(&self, rel: &str, text: &str) {
            let p = self.0.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, text).unwrap();
        }
        fn read(&self, rel: &str) -> String {
            fs::read_to_string(self.0.join(rel)).unwrap()
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const SUDO: &str = "#%PAM-1.0\nauth include system-auth\naccount include system-auth\n";

    #[test]
    fn enable_disable_roundtrip_with_backups() {
        let r = Root::new();
        r.write("etc/pam.d/sudo", SUDO);
        fs::set_permissions(
            r.0.join("etc/pam.d/sudo"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        r.write("etc/pam.d/swaylock", "auth include login\n");
        r.write("etc/pam.d/sshd", "auth include system-remote-login\n");
        let env = r.env();

        enable(&env, vec![], false, false).unwrap();
        assert!(pamfile::has_block(&r.read("etc/pam.d/sudo")));
        assert!(pamfile::has_block(&r.read("etc/pam.d/swaylock")));
        assert!(
            !pamfile::has_block(&r.read("etc/pam.d/sshd")),
            "never by default"
        );
        let mode = fs::metadata(r.0.join("etc/pam.d/sudo"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640, "file mode preserved");
        assert_eq!(env.services_with_block(), vec!["sudo", "swaylock"]);

        // Enabling again changes nothing and needs no new backup.
        let before = list_backups(&env).len();
        enable(&env, vec![], false, false).unwrap();
        assert_eq!(list_backups(&env).len(), before);

        disable(&env, vec!["swaylock".into()], false, false).unwrap();
        assert_eq!(r.read("etc/pam.d/swaylock"), "auth include login\n");
        disable(&env, vec![], true, false).unwrap();
        assert_eq!(r.read("etc/pam.d/sudo"), SUDO);
    }

    #[test]
    fn rollback_restores_previous_state() {
        let r = Root::new();
        r.write("etc/pam.d/sudo", SUDO);
        let env = r.env();
        enable(&env, vec!["sudo".into()], false, false).unwrap();
        assert_ne!(r.read("etc/pam.d/sudo"), SUDO);
        rollback(&env, None, false).unwrap();
        assert_eq!(r.read("etc/pam.d/sudo"), SUDO);
    }

    #[test]
    fn vendor_only_services_get_an_override_that_rollback_removes() {
        let r = Root::new();
        r.write("usr/lib/pam.d/polkit-1", SUDO);
        let env = r.env();
        enable(&env, vec!["polkit-1".into()], false, false).unwrap();
        assert!(pamfile::has_block(&r.read("etc/pam.d/polkit-1")));
        assert_eq!(
            r.read("usr/lib/pam.d/polkit-1"),
            SUDO,
            "vendor file untouched"
        );
        rollback(&env, None, false).unwrap();
        assert!(!r.0.join("etc/pam.d/polkit-1").exists());
    }

    #[test]
    fn disable_removes_an_override_that_matches_the_vendor_file() {
        let r = Root::new();
        r.write("usr/lib/pam.d/kde", SUDO);
        let env = r.env();
        enable(&env, vec!["kde".into()], false, false).unwrap();
        disable(&env, vec!["kde".into()], false, false).unwrap();
        assert!(!r.0.join("etc/pam.d/kde").exists());
        // But a pre-existing, admin-modified override is kept.
        r.write("etc/pam.d/kde", "# local change\nauth include login\n");
        enable(&env, vec!["kde".into()], false, false).unwrap();
        disable(&env, vec!["kde".into()], false, false).unwrap();
        assert_eq!(
            r.read("etc/pam.d/kde"),
            "# local change\nauth include login\n"
        );
    }

    #[test]
    fn dry_run_changes_nothing() {
        let r = Root::new();
        r.write("etc/pam.d/sudo", SUDO);
        let env = r.env();
        enable(&env, vec!["sudo".into()], true, false).unwrap();
        assert_eq!(r.read("etc/pam.d/sudo"), SUDO);
        assert!(list_backups(&env).is_empty());
    }

    #[test]
    fn refuses_forbidden_missing_and_invalid_services() {
        let r = Root::new();
        r.write("etc/pam.d/sshd", SUDO);
        r.write("etc/pam.d/system-auth", SUDO);
        let env = r.env();
        assert!(enable(&env, vec!["sshd".into()], false, false).is_err());
        assert!(enable(&env, vec!["system-auth".into()], false, false).is_err());
        assert!(enable(&env, vec!["nope".into()], false, false).is_err());
        assert!(enable(&env, vec!["../shadow".into()], false, false).is_err());
        assert_eq!(r.read("etc/pam.d/sshd"), SUDO);
    }

    #[test]
    fn requires_installed_module() {
        let r = Root::new();
        fs::remove_file(r.0.join("usr/lib/security").join(MODULE)).unwrap();
        r.write("etc/pam.d/sudo", SUDO);
        let env = r.env();
        assert!(enable(&env, vec!["sudo".into()], false, false).is_err());
        assert!(enable(&env, vec!["sudo".into()], false, true).is_ok());
    }

    #[test]
    fn finds_multiarch_module_dir() {
        let r = Root::new();
        fs::remove_file(r.0.join("usr/lib/security").join(MODULE)).unwrap();
        r.write(&format!("usr/lib/x86_64-linux-gnu/security/{MODULE}"), "");
        assert!(r.env().module_installed().is_some());
    }

    #[test]
    fn distro_detection() {
        let r = Root::new();
        let cases = [
            ("ID=arch\n", "arch"),
            ("ID=endeavouros\nID_LIKE=arch\n", "arch"),
            ("ID=ubuntu\nID_LIKE=debian\n", "debian"),
            ("ID=\"fedora\"\n", "fedora"),
            ("ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n", "fedora"),
            (
                "ID=\"opensuse-tumbleweed\"\nID_LIKE=\"opensuse suse\"\n",
                "suse",
            ),
            ("ID=nixos\n", "other"),
        ];
        for (text, want) in cases {
            r.write("etc/os-release", text);
            assert_eq!(r.env().distro_family(), want, "{text}");
        }
    }

    #[test]
    fn service_name_validation() {
        assert!(valid_service_name("polkit-1"));
        assert!(valid_service_name("gdm-password"));
        assert!(!valid_service_name("../etc/shadow"));
        assert!(!valid_service_name(".hidden"));
        assert!(!valid_service_name("a b"));
    }
}
