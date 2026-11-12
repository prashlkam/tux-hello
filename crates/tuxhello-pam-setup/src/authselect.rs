//! System-wide mode on Fedora and RHEL, through authselect.
//!
//! authselect generates `/etc/pam.d/system-auth` from a profile; editing the
//! generated file by hand is undone by the next `authselect apply-changes`.
//! Vendor profiles cannot take a new feature, so `enable`:
//!
//! 1. creates the custom profile `custom/tuxhello-<base>` from the profile in
//!    use, with everything but `system-auth` symlinked to the base profile so
//!    that vendor updates still reach it;
//! 2. adds one line to that profile's `system-auth` template, tagged
//!    `{include if "with-tuxhello"}`, in the slot `pam_fprintd.so` has;
//! 3. selects the custom profile with the features that were enabled, plus
//!    `with-tuxhello`.
//!
//! `disable` selects the base profile again with the original features and
//! deletes the custom profile.
//!
//! `password-auth` (used by sshd and other remote services) is never touched.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const FEATURE: &str = "with-tuxhello";
const PROFILE_PREFIX: &str = "tuxhello-";
const CUSTOM_DIR: &str = "/etc/authselect/custom";
/// Remembers which profile ours was made from (ids contain `/`, names can't).
const BASE_MARKER: &str = ".tuxhello-base";
const MODULE: &str = "pam_tuxhello.so";

/// The line added to the profile's `system-auth` template, in authselect's
/// column layout.
pub fn template_line() -> String {
    format!(
        "auth        sufficient                                   {MODULE:<54} {{include if \"{FEATURE}\"}}"
    )
}

/// Parses `authselect current --raw`: `"local with-silent-lastlog"`.
pub fn parse_current(raw: &str) -> Option<(String, Vec<String>)> {
    let mut it = raw.split_whitespace();
    let profile = it.next()?.to_string();
    // "No existing configuration detected." has no profile id.
    if !profile
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "/-_.".contains(c))
        || raw.contains("No existing configuration")
    {
        return None;
    }
    Some((profile, it.map(str::to_string).collect()))
}

fn is_auth(line: &str) -> bool {
    matches!(line.split_whitespace().next(), Some("auth") | Some("-auth"))
}

/// Largest numeric jump in a control field such as `[success=1 default=ignore]`.
fn jump(line: &str) -> usize {
    let Some(start) = line.find('[') else {
        return 0;
    };
    let Some(len) = line[start..].find(']') else {
        return 0;
    };
    line[start + 1..start + len]
        .split_whitespace()
        .filter_map(|kv| kv.split_once('=')?.1.parse::<usize>().ok())
        .max()
        .unwrap_or(0)
}

/// Adds our line to a `system-auth` template. It goes where `pam_fprintd.so`
/// is (another "sufficient before the password" method), else before
/// `pam_u2f.so`, else before `pam_unix.so`; and never inside the span of a
/// numeric jump (`[default=1 ...]`), which would change what that jump skips.
pub fn add_feature_line(template: &str) -> Result<String, String> {
    if template.contains(MODULE) {
        return Ok(template.to_string());
    }
    let lines: Vec<&str> = template.lines().collect();
    let auth: Vec<usize> = (0..lines.len()).filter(|&i| is_auth(lines[i])).collect();
    let find = |module: &str| auth.iter().position(|&i| lines[i].contains(module));
    let mut slot = find("pam_fprintd.so")
        .or_else(|| find("pam_u2f.so"))
        .or_else(|| find("pam_unix.so"))
        .ok_or("the profile's system-auth has no pam_unix.so auth line")?;
    // Move in front of any earlier line whose jump would land on or past us.
    while let Some(k) = (0..slot).find(|&k| k + jump(lines[auth[k]]) >= slot) {
        slot = k;
    }
    let at = auth[slot];
    let mut out: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    out.insert(at, template_line());
    let mut text = out.join("\n");
    if template.ends_with('\n') {
        text.push('\n');
    }
    Ok(text)
}

fn run(args: &[&str]) -> Result<String, String> {
    let out = Command::new("authselect")
        .args(args)
        .output()
        .map_err(|e| format!("cannot run authselect: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "`authselect {}` failed: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim(),
            String::from_utf8_lossy(&out.stdout).trim()
        ))
    }
}

fn current() -> Result<(String, Vec<String>), String> {
    let raw = run(&["current", "--raw"]).map_err(|e| {
        format!("{e}\nauthselect does not manage this system's PAM files; enable individual services instead")
    })?;
    parse_current(&raw).ok_or_else(|| {
        "authselect has no profile selected; enable individual services instead".to_string()
    })
}

fn our_profile(profile: &str) -> Option<&str> {
    profile
        .strip_prefix("custom/")
        .filter(|n| n.starts_with(PROFILE_PREFIX))
}

fn custom_dir(name: &str) -> PathBuf {
    Path::new(CUSTOM_DIR).join(name)
}

fn select(profile: &str, features: &[String], backup: Option<&str>) -> Result<(), String> {
    let mut args: Vec<String> = vec!["select".into(), profile.into()];
    args.extend(features.iter().cloned());
    if let Some(b) = backup {
        args.push(format!("--backup={b}"));
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run(&refs).map(|_| ())
}

fn system_auth_uses_module() -> bool {
    fs::read_to_string("/etc/pam.d/system-auth").is_ok_and(|t| t.contains(MODULE))
}

/// The custom profile in use, if system-wide mode is on.
pub fn enabled_profile() -> Option<String> {
    let (profile, features) = parse_current(&run(&["current", "--raw"]).ok()?)?;
    (our_profile(&profile).is_some() && features.iter().any(|f| f == FEATURE)).then_some(profile)
}

pub fn enable(backup_name: &str) -> Result<String, String> {
    // A configuration edited by hand would be overwritten by `select`.
    run(&["check"]).map_err(|e| {
        format!("{e}\nthe PAM files were changed outside authselect; sort that out first (authselect select ... --force discards the changes)")
    })?;
    let (profile, mut features) = current()?;
    if our_profile(&profile).is_some() {
        if !features.iter().any(|f| f == FEATURE) {
            run(&["enable-feature", FEATURE])?;
        }
        return Ok(profile);
    }

    let name = format!("{PROFILE_PREFIX}{}", profile.replace('/', "-"));
    let dir = custom_dir(&name);
    if dir.exists() {
        // Left over from an earlier, interrupted run; it is ours by name.
        fs::remove_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let base_arg = format!("--base-on={profile}");
    run(&[
        "create-profile",
        &name,
        &base_arg,
        "--symlink-meta",
        "--symlink-nsswitch",
        "--symlink-dconf",
        "--symlink=password-auth",
        "--symlink=fingerprint-auth",
        "--symlink=smartcard-auth",
        "--symlink=postlogin",
    ])?;
    let undo_profile = |e: String| {
        let _ = fs::remove_dir_all(&dir);
        e
    };
    let template = dir.join("system-auth");
    let old = fs::read_to_string(&template)
        .map_err(|e| undo_profile(format!("{}: {e}", template.display())))?;
    let new = add_feature_line(&old).map_err(undo_profile)?;
    fs::write(&template, new).map_err(|e| undo_profile(format!("{}: {e}", template.display())))?;
    fs::write(dir.join(BASE_MARKER), format!("{profile}\n"))
        .map_err(|e| undo_profile(e.to_string()))?;

    let ours = format!("custom/{name}");
    let original = features.clone();
    features.push(FEATURE.to_string());
    select(&ours, &features, Some(backup_name)).map_err(undo_profile)?;
    if !system_auth_uses_module() {
        // Never leave a half-applied state behind.
        let _ = select(&profile, &original, None);
        let _ = fs::remove_dir_all(&dir);
        return Err(format!(
            "authselect applied {ours} but /etc/pam.d/system-auth does not use {MODULE}; reverted"
        ));
    }
    Ok(ours)
}

/// Returns the profile that was restored, or `None` if system-wide mode was
/// not on.
pub fn disable() -> Result<Option<String>, String> {
    let Ok((profile, features)) = current() else {
        return Ok(None);
    };
    let Some(name) = our_profile(&profile) else {
        return Ok(None);
    };
    let dir = custom_dir(name);
    let base = fs::read_to_string(dir.join(BASE_MARKER))
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            format!(
                "{} does not say which profile it was made from; select one with `authselect select`",
                dir.display()
            )
        })?;
    let features: Vec<String> = features.into_iter().filter(|f| f != FEATURE).collect();
    select(&base, &features, None)?;
    fs::remove_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(Some(base))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: &str = "\
auth        required                                     pam_env.so
auth        required                                     pam_faildelay.so delay=2000000
auth        required                                     pam_faillock.so preauth silent                         {include if \"with-faillock\"}
auth        sufficient                                   pam_fprintd.so                                         {include if \"with-fingerprint\"}
auth        sufficient                                   pam_u2f.so cue                                         {include if \"with-pam-u2f\"}
-auth       [success=done authtok_err=bad default=ignore] pam_systemd_home.so      {include if \"with-systemd-homed\"}
auth        sufficient                                   pam_unix.so {if not \"without-nullok\":nullok}
auth        required                                     pam_deny.so

account     required                                     pam_unix.so
";

    fn auth_modules(text: &str) -> Vec<String> {
        text.lines()
            .filter(|l| is_auth(l))
            .filter_map(|l| l.split_whitespace().find(|w| w.ends_with(".so")))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn current_raw() {
        assert_eq!(
            parse_current("local with-silent-lastlog with-fingerprint\n"),
            Some((
                "local".into(),
                vec!["with-silent-lastlog".into(), "with-fingerprint".into()]
            ))
        );
        assert_eq!(
            parse_current("custom/tuxhello-local\n"),
            Some(("custom/tuxhello-local".into(), vec![]))
        );
        assert_eq!(parse_current("No existing configuration detected.\n"), None);
        assert_eq!(parse_current(""), None);
    }

    #[test]
    fn goes_where_fprintd_is() {
        let new = add_feature_line(LOCAL).unwrap();
        assert_eq!(
            auth_modules(&new),
            [
                "pam_env.so",
                "pam_faildelay.so",
                "pam_faillock.so",
                "pam_tuxhello.so",
                "pam_fprintd.so",
                "pam_u2f.so",
                "pam_systemd_home.so",
                "pam_unix.so",
                "pam_deny.so"
            ]
        );
        // Exactly one line added, tagged with the feature, nothing else changed.
        assert_eq!(new.lines().count(), LOCAL.lines().count() + 1);
        let added: Vec<&str> = new.lines().filter(|l| !LOCAL.contains(l)).collect();
        assert_eq!(added, [template_line().as_str()]);
        assert!(added[0].ends_with("{include if \"with-tuxhello\"}"));
        assert!(new.ends_with('\n'));
        // Doing it twice changes nothing.
        assert_eq!(add_feature_line(&new).unwrap(), new);
    }

    #[test]
    fn falls_back_to_before_pam_unix() {
        let t =
            "auth required pam_env.so\nauth sufficient pam_unix.so\nauth required pam_deny.so\n";
        assert_eq!(
            auth_modules(&add_feature_line(t).unwrap()),
            [
                "pam_env.so",
                "pam_tuxhello.so",
                "pam_unix.so",
                "pam_deny.so"
            ]
        );
    }

    #[test]
    fn never_lands_inside_a_jump() {
        // sssd-style: two lines jump over pam_unix for non-local users.
        let t = "\
auth        required                                     pam_env.so
auth        [default=1 ignore=ignore success=ok]         pam_usertype.so isregular
auth        [default=1 ignore=ignore success=ok]         pam_localuser.so
auth        sufficient                                   pam_unix.so nullok
auth        sufficient                                   pam_sss.so forward_pass
auth        required                                     pam_deny.so
";
        assert_eq!(
            auth_modules(&add_feature_line(t).unwrap()),
            [
                "pam_env.so",
                "pam_tuxhello.so",
                "pam_usertype.so",
                "pam_localuser.so",
                "pam_unix.so",
                "pam_sss.so",
                "pam_deny.so"
            ]
        );
    }

    #[test]
    fn refuses_a_template_without_pam_unix() {
        assert!(add_feature_line("auth required pam_deny.so\n").is_err());
    }

    #[test]
    fn jump_parsing() {
        assert_eq!(
            jump("auth [default=1 ignore=ignore success=ok] pam_x.so"),
            1
        );
        assert_eq!(jump("auth [success=2 default=ignore] pam_x.so"), 2);
        assert_eq!(jump("auth [success=done default=die] pam_x.so"), 0);
        assert_eq!(jump("auth sufficient pam_x.so"), 0);
    }
}
