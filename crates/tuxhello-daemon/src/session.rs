//! Authentication sessions and their event queues.

use std::collections::VecDeque;
use std::io::Read;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::{AbortHandle, JoinSet};
use tuxhello_proto::SessionState;

use crate::backend::{Backend, Outcome, Progress, Request};

/// Events beyond this many unread ones are dropped (oldest first), so a
/// client that never polls cannot make the daemon grow without bound.
#[cfg_attr(not(feature = "stub-backend"), allow(dead_code))]
const MAX_QUEUED_EVENTS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub method: String,
    pub state: String,
    pub message: String,
}

/// What a single `Wait` call returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub events: Vec<Event>,
    pub state: SessionState,
    pub method: String,
    pub assurance: u32,
}

struct Inner {
    events: VecDeque<Event>,
    state: SessionState,
    method: String,
    assurance: u32,
    task: Option<AbortHandle>,
}

pub struct Session {
    pub id: String,
    /// Unique bus name of the client that created the session. Only that
    /// connection may wait on or cancel it.
    pub owner: String,
    pub caller_uid: u32,
    #[allow(dead_code)] // kept for audit logging / debugging
    pub user: String,
    inner: Mutex<Inner>,
    notify: Notify,
}

impl Session {
    pub fn new(id: String, owner: String, caller_uid: u32, user: String) -> Self {
        Session {
            id,
            owner,
            caller_uid,
            user,
            inner: Mutex::new(Inner {
                events: VecDeque::new(),
                state: SessionState::Running,
                method: String::new(),
                assurance: 0,
                task: None,
            }),
            notify: Notify::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A poisoned lock means a panic happened while holding it; the data
        // is still structurally valid, so keep going rather than crash.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    #[cfg_attr(not(feature = "stub-backend"), allow(dead_code))]
    pub fn push_event(&self, method: &str, state: &str, message: &str) {
        {
            let mut g = self.lock();
            if g.state.is_terminal() {
                return;
            }
            if g.events.len() >= MAX_QUEUED_EVENTS {
                g.events.pop_front();
            }
            g.events.push_back(Event {
                method: method.to_string(),
                state: state.to_string(),
                message: message.to_string(),
            });
        }
        self.notify.notify_one();
    }

    /// Moves the session to a terminal state. Only the first call has effect.
    pub fn finish(&self, state: SessionState, method: &str, assurance: u32) {
        debug_assert!(state.is_terminal());
        {
            let mut g = self.lock();
            if g.state.is_terminal() {
                return;
            }
            g.state = state;
            g.method = method.to_string();
            g.assurance = assurance;
            g.task = None;
        }
        self.notify.notify_one();
    }

    pub fn set_task(&self, handle: AbortHandle) {
        let mut g = self.lock();
        if g.state.is_terminal() {
            handle.abort();
        } else {
            g.task = Some(handle);
        }
    }

    /// Cancels a running session and stops its backends.
    pub fn cancel(&self) {
        let task = {
            let mut g = self.lock();
            if g.state.is_terminal() {
                return;
            }
            g.state = SessionState::Cancelled;
            g.task.take()
        };
        if let Some(t) = task {
            t.abort();
        }
        self.notify.notify_one();
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn state(&self) -> SessionState {
        self.lock().state
    }

    fn take_snapshot(&self) -> Snapshot {
        let mut g = self.lock();
        Snapshot {
            events: g.events.drain(..).collect(),
            state: g.state,
            method: g.method.clone(),
            assurance: g.assurance,
        }
    }

    fn has_news(&self) -> bool {
        let g = self.lock();
        !g.events.is_empty() || g.state.is_terminal()
    }

    /// Waits until there are events or the session ended, or `timeout`
    /// passes, then returns (and clears) the pending events.
    pub async fn wait(&self, timeout: Duration) -> Snapshot {
        if !self.has_news() {
            // `notify_one` stores a permit if nobody is waiting yet, so an
            // event pushed between the check above and this await is not lost.
            let _ = tokio::time::timeout(timeout, self.notify.notified()).await;
        }
        self.take_snapshot()
    }
}

/// Runs all `backends` concurrently. The first match wins and stops the
/// others; otherwise the session fails if any backend reported a non-match,
/// or is unavailable if none could run.
pub async fn run(session: Arc<Session>, backends: Vec<Arc<dyn Backend>>, req: Request) {
    let mut set = JoinSet::new();
    for b in backends {
        let progress = Progress::new(session.clone(), b.name());
        let req = req.clone();
        set.spawn(async move {
            let name = b.name();
            (name, b.verify(req, progress).await)
        });
    }

    let mut any_no_match = false;
    while let Some(res) = set.join_next().await {
        match res {
            Ok((name, Outcome::Match { assurance })) => {
                log::info!(
                    "session {}: user {:?} authenticated by {name} (service {:?})",
                    session.id,
                    req.user,
                    req.service
                );
                session.finish(SessionState::Success, name, assurance);
                set.abort_all();
                return;
            }
            Ok((name, Outcome::NoMatch)) => {
                log::info!("session {}: {name} did not match", session.id);
                any_no_match = true;
            }
            Ok((name, Outcome::Unavailable)) => {
                log::info!("session {}: {name} unavailable", session.id);
            }
            Err(e) if e.is_cancelled() => {}
            Err(e) => log::error!("session {}: backend task failed: {e}", session.id),
        }
    }

    let state = if any_no_match {
        SessionState::Failure
    } else {
        SessionState::Unavailable
    };
    log::info!(
        "session {}: user {:?} not authenticated ({}) for service {:?}",
        session.id,
        req.user,
        state.as_str(),
        req.service
    );
    session.finish(state, "", 0);
}

/// Returns a random 128-bit session id in hex.
pub fn new_session_id() -> std::io::Result<String> {
    let mut buf = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session::new("id".into(), ":1.1".into(), 1000, "alice".into())
    }

    #[test]
    fn session_ids_are_unique_hex() {
        let a = new_session_id().unwrap();
        let b = new_session_id().unwrap();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn finish_is_sticky() {
        let s = session();
        s.finish(SessionState::Success, "stub", 1);
        s.finish(SessionState::Failure, "", 0);
        s.cancel();
        assert_eq!(s.state(), SessionState::Success);
    }

    #[test]
    fn events_after_finish_are_dropped() {
        let s = session();
        s.finish(SessionState::Failure, "", 0);
        s.push_event("stub", "scanning", "late");
        assert!(s.take_snapshot().events.is_empty());
    }

    #[test]
    fn queue_is_bounded() {
        let s = session();
        for i in 0..(MAX_QUEUED_EVENTS + 10) {
            s.push_event("stub", "tick", &i.to_string());
        }
        let snap = s.take_snapshot();
        assert_eq!(snap.events.len(), MAX_QUEUED_EVENTS);
        assert_eq!(snap.events[0].message, "10");
    }

    #[tokio::test]
    async fn wait_returns_immediately_when_event_pending() {
        let s = session();
        s.push_event("stub", "scanning", "hello");
        let snap = s.wait(Duration::from_secs(10)).await;
        assert_eq!(snap.events.len(), 1);
        assert_eq!(snap.state, SessionState::Running);
    }

    #[tokio::test]
    async fn wait_times_out_without_events() {
        let s = session();
        let start = std::time::Instant::now();
        let snap = s.wait(Duration::from_millis(50)).await;
        assert!(snap.events.is_empty());
        assert!(start.elapsed() >= Duration::from_millis(40));
    }

    #[tokio::test]
    async fn wait_wakes_on_finish() {
        let s = Arc::new(session());
        let s2 = s.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            s2.finish(SessionState::Success, "stub", 1);
        });
        let snap = s.wait(Duration::from_secs(10)).await;
        assert_eq!(snap.state, SessionState::Success);
        assert_eq!(snap.method, "stub");
    }
}
