//! Backend interface.
//!
//! Backends currently run in-process. Real hardware backends will move into
//! sandboxed child processes behind this same trait (PLAN.md §4.3).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::audit;
use crate::guard::Guard;
use crate::session::Session;

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// What a backend is asked to verify.
#[derive(Debug, Clone)]
pub struct Request {
    pub user: String,
    pub uid: u32,
    pub service: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The user was recognised, with the given assurance level.
    Match { assurance: u32 },
    /// The backend ran but the user was not recognised.
    NoMatch,
    /// The backend could not run, or the user skipped it.
    Unavailable,
}

/// Handle a backend uses to talk to the client.
pub struct Progress {
    session: Arc<Session>,
    method: &'static str,
    limits: Option<Limits>,
}

/// What a backend's failed attempts are counted against.
struct Limits {
    guard: Arc<Guard>,
    req: Request,
    biometric: bool,
}

impl Progress {
    /// A handle for one backend verifying `req`; failed attempts count
    /// towards the user's limits.
    pub fn for_request(
        session: Arc<Session>,
        method: &'static str,
        guard: Arc<Guard>,
        req: &Request,
        biometric: bool,
    ) -> Self {
        Progress {
            session,
            method,
            limits: Some(Limits {
                guard,
                req: req.clone(),
                biometric,
            }),
        }
    }

    /// Reports one failed attempt (a wrong PIN, an unknown finger, a rejected
    /// key). Returns true if the backend must stop now because the method
    /// has just been locked out.
    pub fn failed_attempt(&self) -> bool {
        let Some(l) = &self.limits else {
            return false;
        };
        audit::Record::new("auth.attempt")
            .s("session", &self.session.id)
            .s("user", &l.req.user)
            .n("uid", u64::from(l.req.uid))
            .s("service", &l.req.service)
            .s("method", self.method)
            .s("result", "failed")
            .emit();
        let locked = l.guard.note_failure(l.req.uid, l.biometric);
        if locked {
            audit::Record::new("lockout.biometric")
                .s("user", &l.req.user)
                .n("uid", u64::from(l.req.uid))
                .s("method", self.method)
                .emit();
        }
        locked
    }

    /// Shows an informational message.
    pub fn emit(&self, state: &str, message: &str) {
        self.session.push_event(self.method, state, message);
    }

    /// Asks the client to prompt the user for a secret (PAM_PROMPT_ECHO_OFF).
    /// Returns `None` if the session ends before an answer arrives.
    pub async fn request_secret(&self, prompt: &str) -> Option<Zeroizing<String>> {
        let rx = self.session.ask_secret(self.method, prompt);
        rx.await.ok()
    }
}

pub trait Backend: Send + Sync {
    /// Method name as used in policy and on the wire (`face`, `pin`, ...).
    fn name(&self) -> &'static str;
    /// Assurance level when this backend reports a match.
    fn assurance(&self) -> u32;
    /// Whether the hardware/software this backend needs is present.
    fn available(&self) -> bool;
    /// Interactive backends prompt the user for input. They run one at a
    /// time, after all non-interactive backends have finished, because a
    /// PAM prompt blocks the conversation.
    fn interactive(&self) -> bool {
        false
    }
    /// Biometric methods share one lockout: after too many consecutive
    /// failures they are not offered until a PIN or security key succeeds.
    fn biometric(&self) -> bool {
        false
    }
    /// Whether the user has enrolled this method (cheap, synchronous
    /// backends). Used by the default [`Backend::usable`].
    fn is_enrolled(&self, _user: &str, _uid: u32) -> bool {
        false
    }
    /// Whether this method can be offered to the user right now: available
    /// and enrolled. Backends that must ask another service (fprintd)
    /// override this.
    fn usable(self: Arc<Self>, user: String, uid: u32) -> BoxFuture<bool> {
        let ok = self.available() && self.is_enrolled(&user, uid);
        Box::pin(async move { ok })
    }
    /// Verifies the user. Must return promptly when the future is dropped.
    fn verify(self: Arc<Self>, req: Request, progress: Progress) -> BoxFuture<Outcome>;
}
