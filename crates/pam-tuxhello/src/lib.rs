//! `pam_tuxhello.so` — thin PAM front end for the Tux Hello daemon.
//!
//! The module does no device I/O and no matching. It forwards the request to
//! `tuxhellod` over the system bus, relays progress messages to the
//! application, and maps the result to a PAM return code.
//!
//! Every error path returns `PAM_AUTHINFO_UNAVAIL` (or `PAM_IGNORE`), so that a
//! stack written as
//!
//! ```text
//! auth  sufficient  pam_tuxhello.so
//! auth  ...         pam_unix.so
//! ```
//!
//! always falls through to the password. See PLAN.md §4.1.
//!
//! Module arguments:
//! * `debug`        — log more detail to syslog (authpriv).
//! * `timeout=N`    — give up after N seconds (1–120, default 10).

mod ffi;

use std::ffi::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

use ffi::{
    Pam, PamHandle, LOG_DEBUG, LOG_ERR, LOG_INFO, LOG_WARNING, PAM_AUTHINFO_UNAVAIL, PAM_AUTH_ERR,
    PAM_IGNORE, PAM_RHOST, PAM_SERVICE, PAM_SILENT, PAM_SUCCESS, PAM_TTY,
};
use tuxhello_client::{AuthContext, Client, ClientError, SessionState};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_TIMEOUT: Duration = Duration::from_secs(120);

/// PAM services for which the module never does anything.
const REMOTE_SERVICES: &[&str] = &["sshd", "xrdp-sesman", "cockpit"];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Options {
    debug: bool,
    timeout: Duration,
    /// Arguments we did not understand (logged, otherwise ignored).
    unknown: Vec<String>,
}

impl Options {
    fn parse<S: AsRef<str>>(args: &[S]) -> Self {
        let mut o = Options {
            debug: false,
            timeout: DEFAULT_TIMEOUT,
            unknown: Vec::new(),
        };
        for a in args {
            let a = a.as_ref();
            if a == "debug" {
                o.debug = true;
            } else if let Some(v) = a.strip_prefix("timeout=") {
                match v.parse::<u64>() {
                    Ok(n) if n >= 1 => o.timeout = Duration::from_secs(n).min(MAX_TIMEOUT),
                    _ => o.unknown.push(a.to_string()),
                }
            } else {
                o.unknown.push(a.to_string());
            }
        }
        o
    }
}

/// Maps a finished session to a PAM return code.
fn map_state(state: SessionState) -> c_int {
    match state {
        SessionState::Success => PAM_SUCCESS,
        SessionState::Failure => PAM_AUTH_ERR,
        // `Running` cannot be returned by `authenticate`; treat defensively.
        SessionState::Unavailable | SessionState::Cancelled | SessionState::Running => {
            PAM_AUTHINFO_UNAVAIL
        }
    }
}

fn authenticate(pam: &Pam, flags: c_int, opts: &Options) -> c_int {
    let debug = |msg: &str| {
        if opts.debug {
            pam.log(LOG_DEBUG, msg);
        }
    };
    for a in &opts.unknown {
        pam.log(
            LOG_WARNING,
            &format!("ignoring unknown or invalid argument {a:?}"),
        );
    }

    let service = pam.item_str(PAM_SERVICE).unwrap_or_default();
    let tty = pam.item_str(PAM_TTY);
    let rhost = pam.item_str(PAM_RHOST);

    if REMOTE_SERVICES.contains(&service.as_str())
        || tuxhello_proto::is_remote_host(rhost.as_deref())
    {
        debug("remote session; not offering Tux Hello");
        return PAM_IGNORE;
    }

    let Some(user) = pam.user() else {
        debug("no user name; skipping");
        return PAM_AUTHINFO_UNAVAIL;
    };

    let client = match Client::connect() {
        Ok(c) => c,
        Err(e) => {
            pam.log(LOG_WARNING, &format!("{e}; falling back"));
            return PAM_AUTHINFO_UNAVAIL;
        }
    };

    let ctx = AuthContext {
        user: &user,
        service: &service,
        tty: tty.as_deref(),
        rhost: rhost.as_deref(),
    };
    let silent = flags & PAM_SILENT != 0;
    let deadline = Instant::now() + opts.timeout;

    let result = client.authenticate(&ctx, deadline, |ev| {
        debug(&format!("event {}/{}: {}", ev.method, ev.state, ev.message));
        if !silent && !ev.message.is_empty() {
            pam.info(&ev.message);
        }
    });

    match result {
        Ok(r) => {
            let rc = map_state(r.state);
            let level = if rc == PAM_SUCCESS {
                LOG_INFO
            } else {
                LOG_DEBUG
            };
            if rc == PAM_SUCCESS || opts.debug {
                pam.log(
                    level,
                    &format!(
                        "user {user:?} service {service:?}: {} (method {:?}, assurance {})",
                        r.state.as_str(),
                        r.method,
                        r.assurance
                    ),
                );
            }
            rc
        }
        Err(e @ ClientError::Daemon { .. }) if e.is_unavailable() => {
            debug(&format!("{e}"));
            PAM_AUTHINFO_UNAVAIL
        }
        Err(e) => {
            pam.log(LOG_ERR, &format!("{e}; falling back"));
            PAM_AUTHINFO_UNAVAIL
        }
    }
}

/// Entry point for `auth` stacks.
///
/// # Safety
/// Must only be called by libpam with a valid handle and argument vector.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // A panic must never unwind into (or abort) the host process.
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: libpam passes a valid handle and argv for this call.
        let pam = unsafe { Pam::new(pamh) };
        let args = unsafe { ffi::args(argc, argv) };
        let opts = Options::parse(&args);
        authenticate(&pam, flags, &opts)
    }))
    .unwrap_or(PAM_AUTHINFO_UNAVAIL)
}

/// No credentials to establish yet (keyring hand-off comes in Phase 4).
///
/// # Safety
/// Must only be called by libpam.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options() {
        let o = Options::parse::<&str>(&[]);
        assert!(!o.debug);
        assert_eq!(o.timeout, DEFAULT_TIMEOUT);
        assert!(o.unknown.is_empty());
    }

    #[test]
    fn parses_known_options() {
        let o = Options::parse(&["debug", "timeout=3"]);
        assert!(o.debug);
        assert_eq!(o.timeout, Duration::from_secs(3));
    }

    #[test]
    fn clamps_and_rejects_timeouts() {
        assert_eq!(Options::parse(&["timeout=9999"]).timeout, MAX_TIMEOUT);
        let o = Options::parse(&["timeout=0", "timeout=abc", "bogus"]);
        assert_eq!(o.timeout, DEFAULT_TIMEOUT);
        assert_eq!(o.unknown.len(), 3);
    }

    #[test]
    fn only_success_maps_to_pam_success() {
        assert_eq!(map_state(SessionState::Success), PAM_SUCCESS);
        assert_eq!(map_state(SessionState::Failure), PAM_AUTH_ERR);
        assert_eq!(map_state(SessionState::Unavailable), PAM_AUTHINFO_UNAVAIL);
        assert_eq!(map_state(SessionState::Cancelled), PAM_AUTHINFO_UNAVAIL);
        assert_eq!(map_state(SessionState::Running), PAM_AUTHINFO_UNAVAIL);
    }
}
