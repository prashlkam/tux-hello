//! Per-user limits that span every method (PLAN.md §6.3).
//!
//! * **Rate limit.** Too many failed attempts for one user in a short time,
//!   by whatever method, and the daemon stops offering Tux Hello for that
//!   user until the window has passed. PAM then falls through to the
//!   password. Kept in memory: it is a brake, not a lockout.
//! * **Biometric lockout.** After a number of consecutive failed biometric
//!   attempts, biometrics are switched off for that user until a PIN or
//!   security key succeeds, or root resets it (`tuxhello unlock`). Persisted
//!   in the store, so a reboot does not clear it.
//!
//! The PIN has its own persistent backoff (`pin.rs`).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tuxhello_store::Store;

const METHOD: &str = "guard";
/// Internal record (ids starting with `_` are hidden from enrolment lists).
const BIOMETRIC: &str = "_biometric";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Failed attempts (all methods together) allowed per user within
    /// `window_s`. 0 switches the rate limit off.
    #[serde(default = "default_max_failures")]
    pub max_failures: u32,
    #[serde(default = "default_window")]
    pub window_s: u64,
    /// Consecutive failed biometric attempts before biometrics are switched
    /// off for the user. 0 switches the lockout off.
    #[serde(default = "default_biometric_max")]
    pub biometric_max_failures: u32,
}

fn default_max_failures() -> u32 {
    10
}
fn default_window() -> u64 {
    300
}
fn default_biometric_max() -> u32 {
    5
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            max_failures: default_max_failures(),
            window_s: default_window(),
            biometric_max_failures: default_biometric_max(),
        }
    }
}

pub struct Guard {
    cfg: LimitsConfig,
    store: Arc<Store>,
    recent: Mutex<HashMap<u32, VecDeque<Instant>>>,
}

impl Guard {
    pub fn new(cfg: LimitsConfig, store: Arc<Store>) -> Self {
        Guard {
            cfg,
            store,
            recent: Mutex::new(HashMap::new()),
        }
    }

    fn window(&self) -> Duration {
        Duration::from_secs(self.cfg.window_s)
    }

    // --- rate limit ---------------------------------------------------------

    /// If the user is rate limited, the number of seconds until they may try
    /// again.
    pub fn throttled(&self, uid: u32) -> Option<u64> {
        self.throttled_at(uid, Instant::now())
    }

    fn throttled_at(&self, uid: u32, now: Instant) -> Option<u64> {
        let max = self.cfg.max_failures as usize;
        if max == 0 {
            return None;
        }
        let window = self.window();
        let mut recent = self.recent.lock().unwrap_or_else(|p| p.into_inner());
        let q = recent.get_mut(&uid)?;
        while q.front().is_some_and(|t| now.duration_since(*t) >= window) {
            q.pop_front();
        }
        if q.is_empty() {
            recent.remove(&uid);
            return None;
        }
        if q.len() < max {
            return None;
        }
        // Allowed again once the oldest of the last `max` failures expires.
        let pivot = q[q.len() - max];
        let left = window.saturating_sub(now.duration_since(pivot));
        Some(left.as_secs().max(1))
    }

    fn note_failure_at(&self, uid: u32, now: Instant) {
        if self.cfg.max_failures == 0 {
            return;
        }
        let mut recent = self.recent.lock().unwrap_or_else(|p| p.into_inner());
        let q = recent.entry(uid).or_default();
        q.push_back(now);
        // Nothing older than the newest `max` entries can matter.
        while q.len() > self.cfg.max_failures as usize {
            q.pop_front();
        }
    }

    // --- biometric lockout --------------------------------------------------

    /// Consecutive failed biometric attempts on record. Unreadable state
    /// counts as locked rather than as zero.
    pub fn biometric_failures(&self, uid: u32) -> u32 {
        match self.store.get(uid, METHOD, BIOMETRIC) {
            Ok(None) => 0,
            Ok(Some(b)) => std::str::from_utf8(&b)
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or_else(|| {
                    log::warn!("uid {uid}: biometric lockout state unreadable; treating as locked");
                    u32::MAX
                }),
            Err(e) => {
                log::warn!(
                    "uid {uid}: cannot read biometric lockout state: {e}; treating as locked"
                );
                u32::MAX
            }
        }
    }

    pub fn biometrics_locked(&self, uid: u32) -> bool {
        let max = self.cfg.biometric_max_failures;
        max != 0 && self.biometric_failures(uid) >= max
    }

    fn set_biometric_failures(&self, uid: u32, n: u32) {
        let r = if n == 0 {
            self.store.delete(uid, METHOD, BIOMETRIC).map(|_| ())
        } else {
            self.store
                .put(uid, METHOD, BIOMETRIC, n.to_string().as_bytes())
        };
        if let Err(e) = r {
            log::error!("uid {uid}: cannot persist biometric lockout state: {e}");
        }
    }

    // --- events -------------------------------------------------------------

    /// Records one failed attempt. Returns true if the method that failed
    /// must stop now (biometrics have just been locked out).
    pub fn note_failure(&self, uid: u32, biometric: bool) -> bool {
        self.note_failure_at(uid, Instant::now());
        if !biometric || self.cfg.biometric_max_failures == 0 {
            return false;
        }
        let n = self.biometric_failures(uid).saturating_add(1);
        self.set_biometric_failures(uid, n);
        let locked = n >= self.cfg.biometric_max_failures;
        if locked {
            log::warn!(
                "uid {uid}: {n} consecutive biometric failures; biometrics are off until a \
                 PIN or security key succeeds"
            );
        }
        locked
    }

    /// Records a successful authentication. Any success ends a run of
    /// consecutive biometric failures; once biometrics are locked they are
    /// not offered, so only a non-biometric method can get here then.
    pub fn note_success(&self, uid: u32) {
        self.recent
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&uid);
        if self.biometric_failures(uid) != 0 {
            self.set_biometric_failures(uid, 0);
        }
    }

    /// Clears both limits for a user (root only; see `Manager1.ResetLockout`).
    pub fn reset(&self, uid: u32) {
        self.recent
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&uid);
        self.set_biometric_failures(uid, 0);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tuxhello_store::{KeyProvider, MasterKey, StoreError};

    struct TestKey;
    impl KeyProvider for TestKey {
        fn load_or_create(&self, _root: &std::path::Path) -> Result<MasterKey, StoreError> {
            Ok(MasterKey::from_bytes([7; 32]))
        }
        fn describe(&self) -> &'static str {
            "test"
        }
    }

    pub(crate) fn temp_store(tag: &str) -> Arc<Store> {
        let mut id = [0u8; 8];
        tuxhello_store::random_bytes(&mut id).unwrap();
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("tuxhello-guard-{tag}-{hex}"));
        Arc::new(Store::open(&dir, &TestKey).unwrap())
    }

    /// A guard with the default limits on a throwaway store.
    pub(crate) fn test_guard() -> Arc<Guard> {
        Arc::new(guard("session", LimitsConfig::default()))
    }

    fn guard(tag: &str, cfg: LimitsConfig) -> Guard {
        Guard::new(cfg, temp_store(tag))
    }

    fn cleanup(g: &Guard) {
        let _ = std::fs::remove_dir_all(g.store.root());
    }

    #[test]
    fn rate_limit_trips_and_expires() {
        let g = guard(
            "rate",
            LimitsConfig {
                max_failures: 3,
                window_s: 60,
                biometric_max_failures: 5,
            },
        );
        let t0 = Instant::now();
        g.note_failure_at(1000, t0);
        g.note_failure_at(1000, t0 + Duration::from_secs(10));
        assert_eq!(g.throttled_at(1000, t0 + Duration::from_secs(11)), None);
        g.note_failure_at(1000, t0 + Duration::from_secs(20));
        // Three failures in the window: blocked until the first one is 60 s old.
        assert_eq!(g.throttled_at(1000, t0 + Duration::from_secs(21)), Some(39));
        // Other users are unaffected.
        assert_eq!(g.throttled_at(1001, t0 + Duration::from_secs(21)), None);
        assert_eq!(g.throttled_at(1000, t0 + Duration::from_secs(60)), None);
        cleanup(&g);
    }

    #[test]
    fn success_clears_the_rate_limit() {
        let g = guard(
            "rate-ok",
            LimitsConfig {
                max_failures: 2,
                window_s: 60,
                biometric_max_failures: 0,
            },
        );
        g.note_failure(1000, false);
        g.note_failure(1000, false);
        assert!(g.throttled(1000).is_some());
        g.note_success(1000);
        assert!(g.throttled(1000).is_none());
        cleanup(&g);
    }

    #[test]
    fn zero_switches_limits_off() {
        let g = guard(
            "off",
            LimitsConfig {
                max_failures: 0,
                window_s: 60,
                biometric_max_failures: 0,
            },
        );
        for _ in 0..50 {
            assert!(!g.note_failure(1000, true));
        }
        assert!(g.throttled(1000).is_none());
        assert!(!g.biometrics_locked(1000));
        cleanup(&g);
    }

    #[test]
    fn biometrics_lock_after_consecutive_failures_and_persist() {
        let store = temp_store("bio");
        let cfg = LimitsConfig {
            max_failures: 0,
            window_s: 60,
            biometric_max_failures: 3,
        };
        let g = Guard::new(cfg.clone(), store.clone());
        assert!(!g.note_failure(1000, true));
        // A non-biometric failure does not count towards the biometric limit.
        assert!(!g.note_failure(1000, false));
        assert!(!g.note_failure(1000, true));
        assert!(!g.biometrics_locked(1000));
        assert!(g.note_failure(1000, true));
        assert!(g.biometrics_locked(1000));
        assert!(!g.biometrics_locked(1001));

        // A new daemon (same store) still sees the lockout.
        let g2 = Guard::new(cfg, store);
        assert!(g2.biometrics_locked(1000));
        // A PIN or key success lifts it.
        g2.note_success(1000);
        assert!(!g2.biometrics_locked(1000));
        assert_eq!(g2.biometric_failures(1000), 0);
        cleanup(&g2);
    }

    #[test]
    fn a_success_ends_a_run_of_failures() {
        let g = guard(
            "run",
            LimitsConfig {
                max_failures: 0,
                window_s: 60,
                biometric_max_failures: 3,
            },
        );
        g.note_failure(1000, true);
        g.note_failure(1000, true);
        g.note_success(1000);
        g.note_failure(1000, true);
        g.note_failure(1000, true);
        assert!(!g.biometrics_locked(1000));
        cleanup(&g);
    }

    #[test]
    fn unreadable_state_counts_as_locked() {
        let g = guard("corrupt", LimitsConfig::default());
        g.store
            .put(1000, METHOD, BIOMETRIC, b"not a number")
            .unwrap();
        assert!(g.biometrics_locked(1000));
        g.reset(1000);
        assert!(!g.biometrics_locked(1000));
        cleanup(&g);
    }
}
