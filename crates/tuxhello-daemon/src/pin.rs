//! PIN backend (PLAN.md §5.1), software variant: Argon2id hash in the
//! encrypted store, plus a persistent exponential-backoff lockout.
//!
//! A TPM-backed variant (PIN as the authValue of a sealed object, hardware
//! dictionary-attack lockout) will implement the same backend.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::Deserialize;
use tuxhello_proto::assurance;
use tuxhello_store::Store;
use zeroize::Zeroizing;

use crate::backend::{Backend, BoxFuture, Outcome, Progress, Request};

pub const METHOD: &str = "pin";
const RECORD: &str = "default";
/// Internal record (ids starting with `_` are hidden from enrolment lists).
const STATE: &str = "_lockout";

/// Failures allowed before the lockout starts.
const FREE_ATTEMPTS: u32 = 5;
const BASE_LOCK_S: u64 = 30;
const MAX_LOCK_S: u64 = 3600;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinConfig {
    #[serde(default = "default_min_length")]
    pub min_length: usize,
    #[serde(default = "default_true")]
    pub allow_alnum: bool,
    #[serde(default = "default_attempts")]
    pub attempts_per_session: u32,
}

fn default_min_length() -> usize {
    4
}
fn default_true() -> bool {
    true
}
fn default_attempts() -> u32 {
    3
}

impl Default for PinConfig {
    fn default() -> Self {
        PinConfig {
            min_length: default_min_length(),
            allow_alnum: default_true(),
            attempts_per_session: default_attempts(),
        }
    }
}

const MAX_LENGTH: usize = 64;

/// Checks a new PIN against the configured rules.
pub fn validate_new_pin(cfg: &PinConfig, pin: &str) -> Result<(), String> {
    let n = pin.chars().count();
    if n < cfg.min_length {
        return Err(format!(
            "PIN must be at least {} characters",
            cfg.min_length
        ));
    }
    if n > MAX_LENGTH {
        return Err(format!("PIN must be at most {MAX_LENGTH} characters"));
    }
    if pin.chars().any(|c| c.is_control()) {
        return Err("PIN must not contain control characters".into());
    }
    if !cfg.allow_alnum && !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err("PIN must contain only digits".into());
    }
    Ok(())
}

fn hasher() -> Argon2<'static> {
    // 64 MiB, 3 passes, 1 lane (PLAN.md §5.1).
    let params = Params::new(64 * 1024, 3, 1, None).expect("valid Argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Returns a PHC-format Argon2id hash of `pin`.
pub fn hash_pin(pin: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    hasher()
        .hash_password(pin.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

/// Constant-time verification against a PHC hash.
pub fn verify_pin(phc: &str, pin: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(pin.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Persistent failure counter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Lockout {
    pub failures: u32,
    pub locked_until: u64,
}

impl Lockout {
    fn encode(&self) -> Vec<u8> {
        format!("{} {}", self.failures, self.locked_until).into_bytes()
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let s = std::str::from_utf8(b).ok()?;
        let mut it = s.split_whitespace();
        Some(Lockout {
            failures: it.next()?.parse().ok()?,
            locked_until: it.next()?.parse().ok()?,
        })
    }

    /// Lock duration after the given number of consecutive failures.
    pub fn lock_seconds(failures: u32) -> u64 {
        if failures < FREE_ATTEMPTS {
            return 0;
        }
        let exp = (failures - FREE_ATTEMPTS).min(20);
        BASE_LOCK_S.saturating_mul(1u64 << exp).min(MAX_LOCK_S)
    }

    pub fn after_failure(self, now: u64) -> Self {
        let failures = self.failures.saturating_add(1);
        Lockout {
            failures,
            locked_until: now + Self::lock_seconds(failures),
        }
    }

    pub fn remaining(&self, now: u64) -> u64 {
        self.locked_until.saturating_sub(now)
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct PinBackend {
    store: Arc<Store>,
    cfg: PinConfig,
}

impl PinBackend {
    pub fn new(store: Arc<Store>, cfg: PinConfig) -> Self {
        PinBackend { store, cfg }
    }

    /// Sets (or replaces) a user's PIN and clears any lockout.
    pub fn enroll(&self, uid: u32, pin: &str) -> Result<(), String> {
        validate_new_pin(&self.cfg, pin)?;
        let phc = Zeroizing::new(hash_pin(pin)?);
        self.store
            .put(uid, METHOD, RECORD, phc.as_bytes())
            .map_err(|e| e.to_string())?;
        self.save_lockout(uid, Lockout::default())
    }

    pub fn delete(&self, uid: u32) -> Result<bool, String> {
        let _ = self.store.delete(uid, METHOD, STATE);
        self.store
            .delete(uid, METHOD, RECORD)
            .map_err(|e| e.to_string())
    }

    /// Seconds the PIN stays locked for this user (0 = not locked).
    pub fn locked_for(&self, uid: u32) -> u64 {
        if !matches!(self.store.get(uid, METHOD, RECORD), Ok(Some(_))) {
            return 0;
        }
        self.load_lockout(uid).remaining(now())
    }

    /// Clears the failure counter (root only; `Manager1.ResetLockout`).
    pub fn reset_lockout(&self, uid: u32) -> Result<(), String> {
        if !matches!(self.store.get(uid, METHOD, RECORD), Ok(Some(_))) {
            return Ok(());
        }
        self.save_lockout(uid, Lockout::default())
    }

    fn load_lockout(&self, uid: u32) -> Lockout {
        match self.store.get(uid, METHOD, STATE) {
            Ok(Some(b)) => Lockout::decode(&b).unwrap_or_else(|| {
                // Unreadable state: assume the worst rather than reset it.
                log::warn!("uid {uid}: PIN lockout state unreadable; treating as locked");
                Lockout {
                    failures: FREE_ATTEMPTS,
                    locked_until: now() + BASE_LOCK_S,
                }
            }),
            Ok(None) => Lockout::default(),
            Err(e) => {
                log::warn!("uid {uid}: cannot read PIN lockout state: {e}; treating as locked");
                Lockout {
                    failures: FREE_ATTEMPTS,
                    locked_until: now() + BASE_LOCK_S,
                }
            }
        }
    }

    fn save_lockout(&self, uid: u32, l: Lockout) -> Result<(), String> {
        self.store
            .put(uid, METHOD, STATE, &l.encode())
            .map_err(|e| e.to_string())
    }

    fn load_hash(&self, uid: u32) -> Option<Zeroizing<String>> {
        let bytes = self.store.get(uid, METHOD, RECORD).ok()??;
        String::from_utf8(bytes.to_vec()).ok().map(Zeroizing::new)
    }
}

impl Backend for PinBackend {
    fn name(&self) -> &'static str {
        METHOD
    }

    fn assurance(&self) -> u32 {
        assurance::MEDIUM
    }

    fn available(&self) -> bool {
        true
    }

    fn interactive(&self) -> bool {
        true
    }

    fn is_enrolled(&self, _user: &str, uid: u32) -> bool {
        matches!(self.store.get(uid, METHOD, RECORD), Ok(Some(_)))
    }

    fn verify(self: Arc<Self>, req: Request, progress: Progress) -> BoxFuture<Outcome> {
        Box::pin(async move {
            let uid = req.uid;
            let Some(phc) = self.load_hash(uid) else {
                return Outcome::Unavailable;
            };
            for attempt in 0..self.cfg.attempts_per_session {
                let lock = self.load_lockout(uid);
                let remaining = lock.remaining(now());
                if remaining > 0 {
                    progress.emit(
                        "locked",
                        &format!("PIN locked after too many attempts; try again in {remaining} s"),
                    );
                    return if attempt == 0 {
                        Outcome::Unavailable
                    } else {
                        Outcome::NoMatch
                    };
                }

                let prompt = if attempt == 0 {
                    "PIN (empty to skip): "
                } else {
                    "PIN: "
                };
                let Some(pin) = progress.request_secret(prompt).await else {
                    return Outcome::Unavailable;
                };
                if pin.is_empty() {
                    // The user chose to fall back to the password.
                    return if attempt == 0 {
                        Outcome::Unavailable
                    } else {
                        Outcome::NoMatch
                    };
                }

                let phc2 = phc.clone();
                let ok = tokio::task::spawn_blocking(move || verify_pin(&phc2, &pin))
                    .await
                    .unwrap_or(false);
                if ok {
                    if lock.failures != 0 {
                        let _ = self.save_lockout(uid, Lockout::default());
                    }
                    return Outcome::Match {
                        assurance: self.assurance(),
                    };
                }
                let lock = lock.after_failure(now());
                if let Err(e) = self.save_lockout(uid, lock) {
                    log::error!("uid {uid}: cannot persist PIN failure: {e}");
                }
                log::warn!(
                    "uid {uid}: wrong PIN (service {:?}, {} consecutive failures)",
                    req.service,
                    lock.failures
                );
                progress.emit("retry", "Incorrect PIN");
                progress.failed_attempt();
            }
            Outcome::NoMatch
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let h = hash_pin("2468").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
        assert!(verify_pin(&h, "2468"));
        assert!(!verify_pin(&h, "2469"));
        assert!(!verify_pin("garbage", "2468"));
    }

    #[test]
    fn hashes_are_salted() {
        assert_ne!(hash_pin("1111").unwrap(), hash_pin("1111").unwrap());
    }

    #[test]
    fn pin_rules() {
        let cfg = PinConfig::default();
        assert!(validate_new_pin(&cfg, "123").is_err());
        assert!(validate_new_pin(&cfg, "1234").is_ok());
        assert!(validate_new_pin(&cfg, "abcd").is_ok());
        assert!(validate_new_pin(&cfg, "ab\ncd").is_err());
        assert!(validate_new_pin(&cfg, &"1".repeat(65)).is_err());
        let digits = PinConfig {
            allow_alnum: false,
            ..PinConfig::default()
        };
        assert!(validate_new_pin(&digits, "12a4").is_err());
        assert!(validate_new_pin(&digits, "1234").is_ok());
    }

    #[test]
    fn lockout_schedule() {
        assert_eq!(Lockout::lock_seconds(4), 0);
        assert_eq!(Lockout::lock_seconds(5), 30);
        assert_eq!(Lockout::lock_seconds(6), 60);
        assert_eq!(Lockout::lock_seconds(7), 120);
        assert_eq!(Lockout::lock_seconds(12), 3600);
        assert_eq!(Lockout::lock_seconds(u32::MAX), 3600);
    }

    #[test]
    fn lockout_encoding_roundtrip() {
        let l = Lockout {
            failures: 7,
            locked_until: 1_800_000_000,
        };
        assert_eq!(Lockout::decode(&l.encode()), Some(l));
        assert_eq!(Lockout::decode(b"nonsense"), None);
        let after = l.after_failure(100);
        assert_eq!(after.failures, 8);
        assert_eq!(after.locked_until, 100 + 240);
        assert_eq!(after.remaining(100), 240);
        assert_eq!(after.remaining(1000), 0);
    }
}
