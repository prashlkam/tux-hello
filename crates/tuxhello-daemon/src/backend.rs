//! Backend interface.
//!
//! In Phase 0 backends run in-process. From Phase 1 on, real backends run in
//! sandboxed child processes behind this same trait (PLAN.md §4.3).

// Builds without the stub have no backend implementation yet (Phase 0).
#![cfg_attr(not(feature = "stub-backend"), allow(dead_code))]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::session::Session;

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// What a backend is asked to verify.
#[derive(Debug, Clone)]
pub struct Request {
    pub user: String,
    #[allow(dead_code)] // used by the real backends (Phase 1+)
    pub uid: u32,
    pub service: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The user was recognised, with the given assurance level.
    Match { assurance: u32 },
    /// The backend ran but the user was not recognised.
    NoMatch,
    /// The backend could not run (device missing, busy, ...).
    Unavailable,
}

/// Handle a backend uses to report progress to the client.
pub struct Progress {
    session: Arc<Session>,
    method: &'static str,
}

impl Progress {
    pub fn new(session: Arc<Session>, method: &'static str) -> Self {
        Progress { session, method }
    }

    pub fn emit(&self, state: &str, message: &str) {
        self.session.push_event(self.method, state, message);
    }
}

pub trait Backend: Send + Sync {
    /// Method name as used in policy and on the wire (`face`, `pin`, ...).
    fn name(&self) -> &'static str;
    /// Assurance level when this backend reports a match.
    fn assurance(&self) -> u32;
    /// Whether the hardware/software this backend needs is present.
    fn available(&self) -> bool;
    /// Whether `user` has enrolled this method.
    fn is_enrolled(&self, user: &str) -> bool;
    /// Verifies the user. Must return promptly when the future is dropped.
    fn verify(self: Arc<Self>, req: Request, progress: Progress) -> BoxFuture<Outcome>;
}
