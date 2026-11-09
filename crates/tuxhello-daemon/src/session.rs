//! Authentication sessions: event queues, secret prompts, and the policy-driven
//! orchestration of backends.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::{oneshot, Notify};
use tokio::task::{AbortHandle, JoinSet};
use tuxhello_policy::Effective;
use tuxhello_proto::{event, SessionState};
use zeroize::Zeroizing;

use crate::backend::{Backend, Outcome, Progress, Request};

/// Events beyond this many unread ones are dropped (oldest first), so a
/// client that never polls cannot make the daemon grow without bound.
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

struct PendingSecret {
    method: String,
    tx: oneshot::Sender<Zeroizing<String>>,
}

struct Inner {
    events: VecDeque<Event>,
    state: SessionState,
    method: String,
    assurance: u32,
    task: Option<AbortHandle>,
    secret: Option<PendingSecret>,
}

pub struct Session {
    pub id: String,
    /// Unique bus name of the client that created the session. Only that
    /// connection may wait on, answer or cancel it.
    pub owner: String,
    pub caller_uid: u32,
    inner: Mutex<Inner>,
    notify: Notify,
}

impl Session {
    pub fn new(id: String, owner: String, caller_uid: u32) -> Self {
        Session {
            id,
            owner,
            caller_uid,
            inner: Mutex::new(Inner {
                events: VecDeque::new(),
                state: SessionState::Running,
                method: String::new(),
                assurance: 0,
                task: None,
                secret: None,
            }),
            notify: Notify::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A poisoned lock means a panic happened while holding it; the data
        // is still structurally valid, so keep going rather than crash.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

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

    /// Registers a pending secret request and emits a `prompt` event.
    pub fn ask_secret(&self, method: &str, prompt: &str) -> oneshot::Receiver<Zeroizing<String>> {
        let (tx, rx) = oneshot::channel();
        self.lock().secret = Some(PendingSecret {
            method: method.to_string(),
            tx,
        });
        self.push_event(method, event::PROMPT, prompt);
        rx
    }

    /// Delivers a secret for the pending prompt. Returns false if `method`
    /// has no prompt outstanding.
    pub fn provide_secret(&self, method: &str, secret: Zeroizing<String>) -> bool {
        let pending = {
            let mut g = self.lock();
            match &g.secret {
                Some(p) if p.method == method => g.secret.take(),
                _ => None,
            }
        };
        match pending {
            Some(p) => p.tx.send(secret).is_ok(),
            None => false,
        }
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
            g.secret = None;
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
            g.secret = None;
            g.task.take()
        };
        if let Some(t) = task {
            t.abort();
        }
        self.notify.notify_one();
    }

    #[cfg(test)]
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

/// Bookkeeping for one run: what succeeded, what can no longer succeed.
struct Tally<'a> {
    effective: &'a Effective,
    nominal: HashMap<&'static str, u32>,
    succeeded: HashMap<&'static str, u32>,
    out: HashSet<&'static str>,
    any_no_match: bool,
}

impl<'a> Tally<'a> {
    fn record(&mut self, name: &'static str, outcome: Outcome) {
        match outcome {
            Outcome::Match { assurance } => {
                self.succeeded.insert(name, assurance);
            }
            Outcome::NoMatch => {
                self.any_no_match = true;
                self.out.insert(name);
            }
            Outcome::Unavailable => {
                self.out.insert(name);
            }
        }
    }

    /// Assurance achieved so far, if the policy is satisfied.
    fn satisfied(&self) -> Option<u32> {
        self.effective
            .satisfied(&|m| self.succeeded.get(m).copied())
    }

    /// Whether the policy can still be met by methods not yet ruled out.
    fn satisfiable(&self) -> bool {
        self.effective
            .satisfied(&|m| {
                self.succeeded.get(m).copied().or_else(|| {
                    if self.out.contains(m) {
                        None
                    } else {
                        self.nominal.get(m).copied()
                    }
                })
            })
            .is_some()
    }

    /// Method credited with the result: the strongest one that succeeded.
    fn credited(&self) -> String {
        let mut v: Vec<(&&str, &u32)> = self.succeeded.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        v.iter().map(|(m, _)| **m).collect::<Vec<_>>().join("+")
    }

    fn failure_state(&self) -> SessionState {
        if self.any_no_match {
            SessionState::Failure
        } else {
            SessionState::Unavailable
        }
    }
}

/// Runs the backends a policy allows. Non-interactive backends run in
/// parallel, bounded by the policy timeout; interactive ones (PIN) then run one
/// at a time. The session succeeds as soon as the policy is satisfied and
/// fails as soon as it no longer can be.
pub async fn run(
    session: Arc<Session>,
    effective: Effective,
    backends: Vec<Arc<dyn Backend>>,
    req: Request,
) {
    let mut t = Tally {
        effective: &effective,
        nominal: backends.iter().map(|b| (b.name(), b.assurance())).collect(),
        succeeded: HashMap::new(),
        out: HashSet::new(),
        any_no_match: false,
    };
    let (interactive, automatic): (Vec<_>, Vec<_>) =
        backends.into_iter().partition(|b| b.interactive());

    let done = |t: &Tally<'_>| -> bool {
        if let Some(a) = t.satisfied() {
            let m = t.credited();
            log::info!(
                "session {}: user {:?} authenticated by {m} (assurance {a}, service {:?}, class {})",
                session.id,
                req.user,
                req.service,
                t.effective.class
            );
            session.finish(SessionState::Success, &m, a);
            return true;
        }
        if !t.satisfiable() {
            let state = t.failure_state();
            log::info!(
                "session {}: user {:?} not authenticated ({}) for service {:?}",
                session.id,
                req.user,
                state.as_str(),
                req.service
            );
            session.finish(state, "", 0);
            return true;
        }
        false
    };

    // Phase 1: automatic methods in parallel.
    let mut set = JoinSet::new();
    let mut running: HashSet<&'static str> = HashSet::new();
    for b in automatic {
        let name = b.name();
        running.insert(name);
        let progress = Progress::new(session.clone(), name);
        let req = req.clone();
        set.spawn(async move { (name, b.verify(req, progress).await) });
    }
    let deadline = tokio::time::sleep(effective.timeout);
    tokio::pin!(deadline);
    while !set.is_empty() {
        tokio::select! {
            res = set.join_next() => match res {
                Some(Ok((name, outcome))) => {
                    running.remove(name);
                    log::debug!("session {}: {name} -> {outcome:?}", session.id);
                    t.record(name, outcome);
                    if done(&t) {
                        set.abort_all();
                        return;
                    }
                }
                Some(Err(e)) => {
                    if !e.is_cancelled() {
                        log::error!("session {}: backend task failed: {e}", session.id);
                    }
                }
                None => break,
            },
            _ = &mut deadline => {
                log::info!("session {}: automatic methods timed out", session.id);
                set.abort_all();
                for name in running.drain() {
                    t.record(name, Outcome::Unavailable);
                }
                break;
            }
        }
    }
    // Backends whose task failed (panicked) never reported; rule them out.
    for name in running.drain() {
        t.record(name, Outcome::Unavailable);
    }
    if done(&t) {
        return;
    }

    // Phase 2: interactive methods, one at a time.
    for b in interactive {
        let name = b.name();
        let progress = Progress::new(session.clone(), name);
        let outcome = b.verify(req.clone(), progress).await;
        log::debug!("session {}: {name} -> {outcome:?}", session.id);
        t.record(name, outcome);
        if done(&t) {
            return;
        }
    }

    // Everything ran and the policy is neither satisfied nor ruled out; this
    // can't happen with a consistent tally, but never leave a session open.
    session.finish(t.failure_state(), "", 0);
}

/// Returns a random 128-bit session id in hex.
pub fn new_session_id() -> Result<String, tuxhello_store::StoreError> {
    let mut buf = [0u8; 16];
    tuxhello_store::random_bytes(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::BoxFuture;
    use tuxhello_policy::Requirement;

    fn session() -> Session {
        Session::new("id".into(), ":1.1".into(), 1000)
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

    #[test]
    fn secrets_only_go_to_the_asking_method() {
        let s = session();
        let mut rx = s.ask_secret("pin", "PIN: ");
        assert!(!s.provide_secret("key", Zeroizing::new("1".into())));
        assert!(s.provide_secret("pin", Zeroizing::new("1234".into())));
        assert_eq!(rx.try_recv().unwrap().as_str(), "1234");
        // Only one answer per prompt.
        assert!(!s.provide_secret("pin", Zeroizing::new("5678".into())));
        let snap = s.take_snapshot();
        assert_eq!(snap.events[0].state, event::PROMPT);
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

    // --- orchestration ----------------------------------------------------

    /// Fake backend with a fixed outcome and delay.
    struct Fake {
        name: &'static str,
        assurance: u32,
        interactive: bool,
        outcome: Outcome,
        delay_ms: u64,
        ran: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Backend for Fake {
        fn name(&self) -> &'static str {
            self.name
        }
        fn assurance(&self) -> u32 {
            self.assurance
        }
        fn available(&self) -> bool {
            true
        }
        fn interactive(&self) -> bool {
            self.interactive
        }
        fn is_enrolled(&self, _: &str, _: u32) -> bool {
            true
        }
        fn verify(self: Arc<Self>, _: Request, _: Progress) -> BoxFuture<Outcome> {
            Box::pin(async move {
                self.ran.store(true, std::sync::atomic::Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
                self.outcome
            })
        }
    }

    fn fake(
        name: &'static str,
        assurance: u32,
        interactive: bool,
        outcome: Outcome,
        delay_ms: u64,
    ) -> (Arc<dyn Backend>, Arc<std::sync::atomic::AtomicBool>) {
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let b = Arc::new(Fake {
            name,
            assurance,
            interactive,
            outcome,
            delay_ms,
            ran: ran.clone(),
        });
        (b, ran)
    }

    fn eff(require: &str, min: u32, timeout_ms: u64) -> Effective {
        let req: Requirement = toml::from_str::<toml::Table>(&format!("r = {require}"))
            .unwrap()
            .remove("r")
            .unwrap()
            .try_into()
            .unwrap();
        Effective {
            class: "test".into(),
            require: req,
            min_assurance: min,
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    fn req() -> Request {
        Request {
            user: "alice".into(),
            uid: 1000,
            service: "test".into(),
        }
    }

    async fn go(
        effective: Effective,
        backends: Vec<Arc<dyn Backend>>,
    ) -> (SessionState, String, u32) {
        let s = Arc::new(session());
        run(s.clone(), effective, backends, req()).await;
        let snap = s.take_snapshot();
        (snap.state, snap.method, snap.assurance)
    }

    const M: fn(u32) -> Outcome = |a| Outcome::Match { assurance: a };

    #[tokio::test]
    async fn first_match_wins_and_interactive_is_skipped() {
        let (face, _) = fake("face", 3, false, M(3), 10);
        let (pin, pin_ran) = fake("pin", 2, true, M(2), 0);
        let r = go(
            eff(r#"{ any = ["face", "pin"] }"#, 2, 1000),
            vec![face, pin],
        )
        .await;
        assert_eq!(r, (SessionState::Success, "face".into(), 3));
        assert!(!pin_ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn falls_back_to_interactive_after_automatic_fails() {
        let (face, _) = fake("face", 3, false, Outcome::NoMatch, 10);
        let (pin, pin_ran) = fake("pin", 2, true, M(2), 0);
        let r = go(
            eff(r#"{ any = ["face", "pin"] }"#, 2, 1000),
            vec![face, pin],
        )
        .await;
        assert_eq!(r, (SessionState::Success, "pin".into(), 2));
        assert!(pin_ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn all_requires_both_factors() {
        let (fp, _) = fake("fingerprint", 3, false, M(3), 10);
        let (pin, _) = fake("pin", 2, true, M(2), 0);
        let r = go(
            eff(r#"{ all = ["fingerprint", "pin"] }"#, 2, 1000),
            vec![fp, pin],
        )
        .await;
        assert_eq!(r, (SessionState::Success, "fingerprint+pin".into(), 4));
    }

    #[tokio::test]
    async fn all_fails_fast_when_a_factor_fails() {
        let (fp, _) = fake("fingerprint", 3, false, Outcome::NoMatch, 10);
        let (pin, pin_ran) = fake("pin", 2, true, M(2), 0);
        let r = go(
            eff(r#"{ all = ["fingerprint", "pin"] }"#, 2, 1000),
            vec![fp, pin],
        )
        .await;
        assert_eq!(r.0, SessionState::Failure);
        assert!(
            !pin_ran.load(std::sync::atomic::Ordering::SeqCst),
            "no point asking"
        );
    }

    #[tokio::test]
    async fn timeout_moves_on_to_interactive() {
        let (face, _) = fake("face", 3, false, M(3), 10_000);
        let (pin, _) = fake("pin", 2, true, M(2), 0);
        let start = std::time::Instant::now();
        let r = go(eff(r#"{ any = ["face", "pin"] }"#, 2, 100), vec![face, pin]).await;
        assert_eq!(r.0, SessionState::Success);
        assert_eq!(r.1, "pin");
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn weak_match_below_min_assurance_is_not_enough() {
        let (voice, _) = fake("voice", 1, false, M(1), 10);
        let r = go(eff(r#"{ any = ["voice"] }"#, 2, 1000), vec![voice]).await;
        assert_eq!(
            r.0,
            SessionState::Unavailable,
            "can never reach min_assurance"
        );
    }

    #[tokio::test]
    async fn unavailable_only_is_unavailable_not_failure() {
        let (key, _) = fake("key", 4, false, Outcome::Unavailable, 10);
        let r = go(eff(r#"{ any = ["key"] }"#, 2, 1000), vec![key]).await;
        assert_eq!(r.0, SessionState::Unavailable);
    }
}
