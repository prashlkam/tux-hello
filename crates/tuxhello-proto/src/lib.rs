// SPDX-FileCopyrightText: 2026 Tux Hello contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Wire-level constants shared by the daemon, the PAM module and clients.
//!
//! This crate is intentionally dependency-free so that it can be linked into
//! the PAM module without pulling anything else into host processes.
//!
//! See `docs/adr/0002-ipc-and-pam-protocol.md` for the protocol description.

/// Well-known name of the daemon on the D-Bus **system** bus.
pub const BUS_NAME: &str = "org.tuxhello.Auth1";
/// Object path of the authentication object.
pub const OBJECT_PATH: &str = "/org/tuxhello/Auth1";
/// Interface used for authentication.
pub const AUTH_INTERFACE: &str = "org.tuxhello.Auth1";
/// Object path of the management object (enrolment, listing, deletion).
pub const MANAGER_PATH: &str = "/org/tuxhello/Manager1";
/// Interface used for management.
pub const MANAGER_INTERFACE: &str = "org.tuxhello.Manager1";

/// Prefix for D-Bus error names returned by the daemon.
pub const ERROR_PREFIX: &str = "org.tuxhello.Error";

/// Upper bound the daemon applies to a single `Wait` call, in milliseconds.
pub const MAX_WAIT_MS: u32 = 5_000;

/// Keys accepted in the `BeginAuth` context dictionary (`a{sv}`, all values are strings).
pub mod ctx {
    /// Name of the user to authenticate. Required.
    pub const USER: &str = "user";
    /// PAM service name (`sudo`, `gdm-password`, ...). Required.
    pub const SERVICE: &str = "service";
    /// PAM_TTY, if any.
    pub const TTY: &str = "tty";
    /// PAM_RHOST, if any. The daemon refuses sessions with a remote host.
    pub const RHOST: &str = "rhost";
}

/// Well-known event states (the second field of a `Wait` event).
pub mod event {
    /// The method wants a secret: show the message as a PAM_PROMPT_ECHO_OFF
    /// prompt and answer with `SubmitSecret(session, method, secret)`. An
    /// empty secret means "skip this method".
    pub const PROMPT: &str = "prompt";
}

/// Error names (suffixes of [`ERROR_PREFIX`]).
pub mod error {
    pub const ACCESS_DENIED: &str = "org.tuxhello.Error.AccessDenied";
    pub const INVALID_ARGS: &str = "org.tuxhello.Error.InvalidArgs";
    pub const NO_SUCH_SESSION: &str = "org.tuxhello.Error.NoSuchSession";
    pub const NOT_ENROLLED: &str = "org.tuxhello.Error.NotEnrolled";
    pub const UNAVAILABLE: &str = "org.tuxhello.Error.Unavailable";
    pub const LIMIT_EXCEEDED: &str = "org.tuxhello.Error.LimitExceeded";
    pub const FAILED: &str = "org.tuxhello.Error.Failed";
}

/// State of an authentication session as reported by `Wait`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Methods are still running; call `Wait` again.
    Running,
    /// A method matched. Authentication succeeded.
    Success,
    /// All methods ran and none matched.
    Failure,
    /// No method could run (no hardware, no enrollment, ...).
    Unavailable,
    /// The session was cancelled by the caller or timed out in the daemon.
    Cancelled,
}

impl SessionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            SessionState::Running => "running",
            SessionState::Success => "success",
            SessionState::Failure => "failure",
            SessionState::Unavailable => "unavailable",
            SessionState::Cancelled => "cancelled",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "running" => SessionState::Running,
            "success" => SessionState::Success,
            "failure" => SessionState::Failure,
            "unavailable" => SessionState::Unavailable,
            "cancelled" => SessionState::Cancelled,
            _ => return None,
        })
    }

    pub const fn is_terminal(self) -> bool {
        !matches!(self, SessionState::Running)
    }
}

/// True if a PAM_RHOST value names a remote machine. Biometrics and PINs are
/// never offered to remote sessions (PLAN.md §10.1). Both the PAM module and
/// the daemon apply this check.
pub fn is_remote_host(rhost: Option<&str>) -> bool {
    match rhost {
        None => false,
        Some(h) => !(h.is_empty() || h == "localhost" || h == "127.0.0.1" || h == "::1"),
    }
}

/// Assurance levels, see PLAN.md §5. Higher is stronger.
pub mod assurance {
    pub const NONE: u32 = 0;
    pub const LOW: u32 = 1;
    pub const MEDIUM: u32 = 2;
    pub const HIGH: u32 = 3;
    pub const HARDWARE_KEY: u32 = 4;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_roundtrip() {
        for s in [
            SessionState::Running,
            SessionState::Success,
            SessionState::Failure,
            SessionState::Unavailable,
            SessionState::Cancelled,
        ] {
            assert_eq!(SessionState::parse(s.as_str()), Some(s));
        }
        assert_eq!(SessionState::parse("bogus"), None);
    }

    #[test]
    fn only_running_is_non_terminal() {
        assert!(!SessionState::Running.is_terminal());
        assert!(SessionState::Success.is_terminal());
        assert!(SessionState::Cancelled.is_terminal());
    }

    #[test]
    fn remote_detection() {
        assert!(!is_remote_host(None));
        assert!(!is_remote_host(Some("")));
        assert!(!is_remote_host(Some("localhost")));
        assert!(!is_remote_host(Some("::1")));
        assert!(is_remote_host(Some("10.0.0.5")));
        assert!(is_remote_host(Some("example.org")));
    }

    #[test]
    fn error_names_share_prefix() {
        for name in [
            error::ACCESS_DENIED,
            error::INVALID_ARGS,
            error::NO_SUCH_SESSION,
            error::NOT_ENROLLED,
            error::UNAVAILABLE,
            error::LIMIT_EXCEEDED,
            error::FAILED,
        ] {
            assert!(name.starts_with(ERROR_PREFIX));
        }
    }
}
