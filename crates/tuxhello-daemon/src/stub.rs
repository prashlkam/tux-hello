// SPDX-FileCopyrightText: 2026 Tux Hello contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Test-only backend with a configured outcome. Compiled only with the
//! `stub-backend` feature.

use std::sync::Arc;
use std::time::Duration;

use crate::backend::{Backend, BoxFuture, Outcome, Progress, Request};
use crate::config::{StubConfig, StubOutcome};

pub struct Stub {
    outcome: StubOutcome,
    delay: Duration,
    users: Vec<String>,
    assurance: u32,
}

impl Stub {
    pub fn new(cfg: &StubConfig) -> Self {
        Stub {
            outcome: cfg.outcome,
            delay: Duration::from_millis(cfg.delay_ms),
            users: cfg.users.clone(),
            assurance: cfg.assurance,
        }
    }
}

impl Backend for Stub {
    fn name(&self) -> &'static str {
        "stub"
    }

    fn assurance(&self) -> u32 {
        self.assurance
    }

    fn available(&self) -> bool {
        true
    }

    fn is_enrolled(&self, user: &str, _uid: u32) -> bool {
        self.users.is_empty() || self.users.iter().any(|u| u == user)
    }

    fn verify(self: Arc<Self>, _req: Request, progress: Progress) -> BoxFuture<Outcome> {
        Box::pin(async move {
            progress.emit("scanning", "Stub backend: checking…");
            tokio::time::sleep(self.delay).await;
            match self.outcome {
                StubOutcome::Success => {
                    progress.emit("matched", "Stub backend: recognised");
                    Outcome::Match {
                        assurance: self.assurance(),
                    }
                }
                StubOutcome::Failure => {
                    progress.emit("no-match", "Stub backend: not recognised");
                    progress.failed_attempt();
                    Outcome::NoMatch
                }
                StubOutcome::Unavailable => Outcome::Unavailable,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{run, Session};
    use tuxhello_policy::{Effective, Requirement};
    use tuxhello_proto::SessionState;

    fn cfg(outcome: StubOutcome, users: &[&str]) -> StubConfig {
        StubConfig {
            enabled: true,
            outcome,
            delay_ms: 1,
            users: users.iter().map(|s| s.to_string()).collect(),
            assurance: 2,
            soft_key_dir: None,
        }
    }

    async fn run_with(outcome: StubOutcome) -> SessionState {
        let session = Arc::new(Session::new("t".into(), ":1.1".into(), 0));
        let backends: Vec<Arc<dyn Backend>> = vec![Arc::new(Stub::new(&cfg(outcome, &[])))];
        let effective = Effective {
            class: "other".into(),
            require: Requirement::Method("stub".into()),
            min_assurance: 2,
            timeout: Duration::from_secs(5),
        };
        let req = Request {
            user: "alice".into(),
            uid: 1000,
            service: "test".into(),
        };
        run(
            session.clone(),
            effective,
            backends,
            req,
            crate::guard::tests::test_guard(),
        )
        .await;
        session.state()
    }

    #[test]
    fn enrollment_list() {
        let s = Stub::new(&cfg(StubOutcome::Success, &["alice"]));
        assert!(s.is_enrolled("alice", 1));
        assert!(!s.is_enrolled("bob", 2));
        let all = Stub::new(&cfg(StubOutcome::Success, &[]));
        assert!(all.is_enrolled("bob", 2));
    }

    #[tokio::test]
    async fn outcomes_map_to_session_states() {
        assert_eq!(run_with(StubOutcome::Success).await, SessionState::Success);
        assert_eq!(run_with(StubOutcome::Failure).await, SessionState::Failure);
        assert_eq!(
            run_with(StubOutcome::Unavailable).await,
            SessionState::Unavailable
        );
    }
}
