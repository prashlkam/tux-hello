//! Pure text transformations on PAM service files. No I/O here, so every
//! rule about what we change is unit-tested.
//!
//! We only ever add or remove one marked block:
//!
//! ```text
//! # tuxhello-begin (managed by tuxhello-pam-setup; do not edit)
//! auth       sufficient   pam_tuxhello.so
//! # tuxhello-end
//! ```
//!
//! placed directly before the first `auth` line (or `@include common-auth`).
//! `sufficient` means: success ends the auth stack, and anything else falls
//! through to the lines that were already there, which is the password.

use std::fmt;

pub const BEGIN: &str = "# tuxhello-begin (managed by tuxhello-pam-setup; do not edit)";
pub const END: &str = "# tuxhello-end";
pub const MODULE_LINE: &str = "auth       sufficient   pam_tuxhello.so";

/// Modules that already do biometric/token auth and may double-prompt.
const CONFLICTS: &[(&str, &str)] = &[
    ("pam_fprintd.so", "fprintd (fingerprint)"),
    ("pam_u2f.so", "pam_u2f (security key)"),
    ("pam_howdy.so", "Howdy (face)"),
    ("howdy", "Howdy (face)"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditError {
    /// The file has no `auth` section to put the block in front of.
    NoAuthSection,
    /// A begin marker without an end marker (or the reverse).
    BrokenMarkers,
}

impl fmt::Display for EditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EditError::NoAuthSection => write!(f, "no auth lines found; not a login-type service"),
            EditError::BrokenMarkers => write!(
                f,
                "unbalanced tuxhello-begin/tuxhello-end markers; fix the file by hand"
            ),
        }
    }
}

impl std::error::Error for EditError {}

/// The first whitespace-separated token of a non-comment line.
fn first_token(line: &str) -> Option<&str> {
    let t = line.trim_start();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    t.split_whitespace().next()
}

/// Lines that start the auth stack: `auth ...`, `-auth ...`, and Debian's
/// `@include common-auth`.
pub fn is_auth_line(line: &str) -> bool {
    match first_token(line) {
        Some("auth") | Some("-auth") => true,
        Some("@include") => line
            .split_whitespace()
            .nth(1)
            .is_some_and(|f| f == "common-auth"),
        _ => false,
    }
}

fn is_begin(line: &str) -> bool {
    line.trim_start().starts_with("# tuxhello-begin")
}

fn is_end(line: &str) -> bool {
    line.trim() == END
}

/// Whether the file contains our block.
pub fn has_block(text: &str) -> bool {
    text.lines().any(is_begin)
}

fn join(lines: &[&str], trailing_newline: bool) -> String {
    let mut s = lines.join("\n");
    if trailing_newline {
        s.push('\n');
    }
    s
}

/// Inserts the block before the first auth line. Idempotent: a file that
/// already has the block is returned unchanged.
pub fn insert_block(text: &str) -> Result<String, EditError> {
    if has_block(text) {
        check_markers(text)?;
        return Ok(text.to_string());
    }
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|l| is_auth_line(l))
        .ok_or(EditError::NoAuthSection)?;
    let mut out: Vec<&str> = Vec::with_capacity(lines.len() + 3);
    out.extend_from_slice(&lines[..at]);
    out.extend_from_slice(&[BEGIN, MODULE_LINE, END]);
    out.extend_from_slice(&lines[at..]);
    Ok(join(&out, text.ends_with('\n') || text.is_empty()))
}

fn check_markers(text: &str) -> Result<(), EditError> {
    let mut open = false;
    for l in text.lines() {
        if is_begin(l) {
            if open {
                return Err(EditError::BrokenMarkers);
            }
            open = true;
        } else if is_end(l) {
            if !open {
                return Err(EditError::BrokenMarkers);
            }
            open = false;
        }
    }
    if open {
        Err(EditError::BrokenMarkers)
    } else {
        Ok(())
    }
}

/// Removes every block (begin marker through end marker).
pub fn remove_block(text: &str) -> Result<String, EditError> {
    check_markers(text)?;
    let mut out = Vec::new();
    let mut inside = false;
    for l in text.lines() {
        if is_begin(l) {
            inside = true;
        } else if inside && is_end(l) {
            inside = false;
        } else if !inside {
            out.push(l);
        }
    }
    Ok(join(&out, text.ends_with('\n')))
}

/// Proves that `new` is `old` plus exactly our block, placed before every
/// pre-existing auth line. Used as a final check before writing.
pub fn verify_edit(old: &str, new: &str) -> bool {
    let Ok(stripped) = remove_block(new) else {
        return false;
    };
    let same = stripped == old || stripped.trim_end_matches('\n') == old.trim_end_matches('\n');
    let first_auth = new.lines().position(is_auth_line);
    let block_line = new.lines().position(|l| l == MODULE_LINE);
    same && matches!((block_line, first_auth), (Some(b), Some(a)) if b == a)
}

/// Other auth modules in the file that may conflict (double prompts).
pub fn conflicts(text: &str) -> Vec<&'static str> {
    let mut found: Vec<&'static str> = Vec::new();
    for l in text.lines() {
        if !is_auth_line(l) || is_begin(l) {
            continue;
        }
        for (needle, name) in CONFLICTS {
            if l.contains(needle) && !found.contains(name) {
                found.push(name);
            }
        }
    }
    found
}

/// Basic PAM syntax check: every non-comment, non-include line has at least
/// `type control module`.
pub fn syntax_ok(text: &str) -> bool {
    text.lines().all(|l| {
        let t = l.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with('@') {
            return true;
        }
        let mut it = t.split_whitespace();
        let ty = it.next().unwrap_or("");
        let ty = ty.strip_prefix('-').unwrap_or(ty);
        let known = matches!(ty, "auth" | "account" | "password" | "session");
        // `[...]` controls may contain spaces: count tokens after joining.
        let rest: Vec<&str> = it.collect();
        known && rest.len() >= 2
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARCH_SUDO: &str = "#%PAM-1.0\nauth\t\tinclude\t\tsystem-auth\naccount\t\tinclude\t\tsystem-auth\nsession\t\tinclude\t\tsystem-auth\n";
    const DEBIAN_SUDO: &str = "#%PAM-1.0\n\n# Set up user limits\nsession    required   pam_limits.so\n\n@include common-auth\n@include common-account\n@include common-session-noninteractive\n";
    const FEDORA_POLKIT: &str = "#%PAM-1.0\nauth       include      system-auth\naccount    include      system-auth\npassword   include      system-auth\nsession    include      system-auth\n";
    const WITH_ENV_FIRST: &str =
        "#%PAM-1.0\nauth       required     pam_env.so\nauth       include      system-auth\n";
    const SWAYLOCK: &str =
        "#\n# PAM configuration file for the swaylock screen locker.\n#\nauth include login\n";
    const NO_AUTH: &str = "#%PAM-1.0\nsession required pam_limits.so\n";

    #[test]
    fn inserts_before_first_auth_line() {
        let out = insert_block(ARCH_SUDO).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "#%PAM-1.0");
        assert_eq!(lines[1], BEGIN);
        assert_eq!(lines[2], MODULE_LINE);
        assert_eq!(lines[3], END);
        assert!(lines[4].starts_with("auth"));
        assert!(out.ends_with('\n'));
        assert!(verify_edit(ARCH_SUDO, &out));
    }

    #[test]
    fn debian_include_counts_as_auth() {
        let out = insert_block(DEBIAN_SUDO).unwrap();
        let i = out.lines().position(|l| l == MODULE_LINE).unwrap();
        assert_eq!(out.lines().nth(i + 2).unwrap(), "@include common-auth");
        // The session line before it is untouched and still first.
        assert!(out.lines().position(|l| l.starts_with("session")).unwrap() < i);
        assert!(verify_edit(DEBIAN_SUDO, &out));
    }

    #[test]
    fn goes_before_pam_env_too() {
        let out = insert_block(WITH_ENV_FIRST).unwrap();
        assert_eq!(out.lines().nth(2).unwrap(), MODULE_LINE);
        assert!(verify_edit(WITH_ENV_FIRST, &out));
    }

    #[test]
    fn comments_mentioning_auth_are_not_auth_lines() {
        assert!(!is_auth_line("# auth required pam_deny.so"));
        assert!(!is_auth_line("   "));
        assert!(is_auth_line("-auth optional pam_gnome_keyring.so"));
        assert!(is_auth_line("  auth include login"));
        assert!(!is_auth_line("@include common-account"));
        let out = insert_block(SWAYLOCK).unwrap();
        assert!(verify_edit(SWAYLOCK, &out));
    }

    #[test]
    fn insert_is_idempotent_and_remove_restores_exactly() {
        for f in [
            ARCH_SUDO,
            DEBIAN_SUDO,
            FEDORA_POLKIT,
            WITH_ENV_FIRST,
            SWAYLOCK,
        ] {
            let once = insert_block(f).unwrap();
            let twice = insert_block(&once).unwrap();
            assert_eq!(once, twice);
            assert_eq!(remove_block(&once).unwrap(), f);
            assert_eq!(
                remove_block(f).unwrap(),
                f,
                "remove on a clean file is a no-op"
            );
        }
    }

    #[test]
    fn preserves_missing_trailing_newline() {
        let f = "auth include system-auth";
        let out = insert_block(f).unwrap();
        assert!(!out.ends_with('\n'));
        assert_eq!(remove_block(&out).unwrap(), f);
    }

    #[test]
    fn refuses_files_without_auth() {
        assert_eq!(insert_block(NO_AUTH), Err(EditError::NoAuthSection));
    }

    #[test]
    fn detects_broken_markers() {
        let broken = format!("{BEGIN}\n{MODULE_LINE}\nauth include system-auth\n");
        assert_eq!(remove_block(&broken), Err(EditError::BrokenMarkers));
        assert_eq!(insert_block(&broken), Err(EditError::BrokenMarkers));
        let stray_end = format!("{END}\nauth include system-auth\n");
        assert_eq!(remove_block(&stray_end), Err(EditError::BrokenMarkers));
    }

    #[test]
    fn verify_rejects_other_changes() {
        let good = insert_block(ARCH_SUDO).unwrap();
        // Extra modification elsewhere.
        let tampered = good.replace("account", "#account");
        assert!(!verify_edit(ARCH_SUDO, &tampered));
        // Block placed after the original auth line.
        let late = format!("{ARCH_SUDO}{BEGIN}\n{MODULE_LINE}\n{END}\n");
        assert!(!verify_edit(ARCH_SUDO, &late));
    }

    #[test]
    fn finds_conflicting_modules() {
        let f = "auth sufficient pam_fprintd.so\nauth sufficient pam_u2f.so cue\nauth include system-auth\n";
        assert_eq!(
            conflicts(f),
            vec!["fprintd (fingerprint)", "pam_u2f (security key)"]
        );
        assert!(conflicts(ARCH_SUDO).is_empty());
        assert!(conflicts("# auth sufficient pam_fprintd.so\n").is_empty());
    }

    #[test]
    fn syntax_check() {
        for f in [ARCH_SUDO, DEBIAN_SUDO, FEDORA_POLKIT, SWAYLOCK] {
            assert!(syntax_ok(&insert_block(f).unwrap()), "{f}");
        }
        assert!(syntax_ok(
            "auth [success=1 default=ignore] pam_unix.so nullok\n"
        ));
        assert!(!syntax_ok("auth sufficient\n"));
        assert!(!syntax_ok("bogus required pam_deny.so\n"));
    }
}
