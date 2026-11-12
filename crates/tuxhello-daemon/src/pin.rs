//! PIN backend (PLAN.md §5.1).
//!
//! * **With a TPM:** the PIN is the auth value of a sealed TPM object. Only
//!   the TPM can tell whether a guess is right, and it limits guesses itself
//!   (dictionary-attack lockout), so a short PIN is safe even against someone
//!   who has the disk. Nothing derived from the PIN is stored.
//! * **Without:** an Argon2id hash in the encrypted store.
//!
//! Both sit behind the same persistent exponential-backoff lockout, which
//! keeps ordinary mistakes from ever reaching the TPM's own, machine-wide
//! lockout.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tuxhello_proto::assurance;
use tuxhello_store::Store;
use zeroize::Zeroizing;

use crate::backend::{Backend, BoxFuture, Outcome, Progress, Request};
use crate::config::TpmMode;

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
    /// Back new PINs with the TPM: `auto` when there is one, `require` to
    /// refuse enrolment without, `off` for Argon2id only. PINs already
    /// enrolled keep working either way.
    #[serde(default)]
    pub tpm: TpmMode,
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
            tpm: TpmMode::default(),
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

/// Hardware that can hold a PIN (the TPM; a fake in tests).
pub trait PinSealer: Send + Sync {
    /// Makes an object that opens only with `auth`, with wrong guesses
    /// limited by the hardware. Returns the blob to store.
    fn seal(&self, auth: &[u8]) -> Result<Vec<u8>, SealError>;
    /// Checks `auth` against a blob made by [`PinSealer::seal`].
    fn check(&self, blob: &[u8], auth: &[u8]) -> Result<(), SealError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(feature = "tpm"), allow(dead_code))]
pub enum SealError {
    WrongAuth,
    /// The hardware refuses further guesses for now.
    LockedOut,
    Unavailable(String),
}

/// What is stored for an enrolled PIN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinRecord {
    /// PHC-format Argon2id hash.
    Argon2(String),
    /// TPM object whose auth value is derived from the PIN and `salt`.
    Tpm { salt: [u8; 16], blob: Vec<u8> },
}

const TPM_PREFIX: &str = "tpm1$";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

impl PinRecord {
    pub fn encode(&self) -> String {
        match self {
            PinRecord::Argon2(phc) => phc.clone(),
            PinRecord::Tpm { salt, blob } => format!("{TPM_PREFIX}{}${}", hex(salt), hex(blob)),
        }
    }

    pub fn decode(s: &str) -> Option<Self> {
        if let Some(rest) = s.strip_prefix(TPM_PREFIX) {
            let (salt, blob) = rest.split_once('$')?;
            return Some(PinRecord::Tpm {
                salt: unhex(salt)?.try_into().ok()?,
                blob: unhex(blob).filter(|b| !b.is_empty())?,
            });
        }
        s.starts_with("$argon2")
            .then(|| PinRecord::Argon2(s.to_string()))
    }
}

/// The TPM auth value for a PIN. The salt keeps equal PINs of different
/// users from having equal auth values.
fn tpm_auth(salt: &[u8; 16], pin: &str) -> Zeroizing<Vec<u8>> {
    let mut h = Sha256::new();
    h.update(b"tuxhello-pin-v1\0");
    h.update(salt);
    h.update(pin.as_bytes());
    Zeroizing::new(h.finalize().to_vec())
}

/// Result of checking one PIN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinCheck {
    Right,
    Wrong,
    /// The TPM itself refuses guesses for now.
    HardwareLocked,
    /// The PIN is TPM-backed and the TPM cannot be used.
    Unavailable(String),
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
    sealer: Option<Arc<dyn PinSealer>>,
}

impl PinBackend {
    /// `sealer` is the TPM, if this machine has a usable one.
    pub fn new(store: Arc<Store>, cfg: PinConfig, sealer: Option<Arc<dyn PinSealer>>) -> Self {
        let sealer = if cfg.tpm == TpmMode::Off {
            None
        } else {
            sealer
        };
        PinBackend { store, cfg, sealer }
    }

    /// How a PIN enrolled now would be protected.
    pub fn protection(&self) -> &'static str {
        if self.sealer.is_some() {
            "tpm"
        } else {
            "software"
        }
    }

    fn new_record(&self, pin: &str) -> Result<PinRecord, String> {
        match &self.sealer {
            Some(sealer) => {
                let mut salt = [0u8; 16];
                tuxhello_store::random_bytes(&mut salt).map_err(|e| e.to_string())?;
                let blob = sealer
                    .seal(&tpm_auth(&salt, pin))
                    .map_err(|e| format!("the TPM could not store the PIN: {e:?}"))?;
                Ok(PinRecord::Tpm { salt, blob })
            }
            None if self.cfg.tpm == TpmMode::Require => {
                Err("[pin] tpm = \"require\" but this machine has no usable TPM".to_string())
            }
            None => Ok(PinRecord::Argon2(hash_pin(pin)?)),
        }
    }

    /// Sets (or replaces) a user's PIN and clears any lockout.
    pub fn enroll(&self, uid: u32, pin: &str) -> Result<(), String> {
        validate_new_pin(&self.cfg, pin)?;
        let rec = Zeroizing::new(self.new_record(pin)?.encode());
        self.store
            .put(uid, METHOD, RECORD, rec.as_bytes())
            .map_err(|e| e.to_string())?;
        self.save_lockout(uid, Lockout::default())
    }

    /// Checks one PIN against a record. Blocking (Argon2 or a TPM round trip).
    pub fn check(&self, rec: &PinRecord, pin: &str) -> PinCheck {
        match rec {
            PinRecord::Argon2(phc) => {
                if verify_pin(phc, pin) {
                    PinCheck::Right
                } else {
                    PinCheck::Wrong
                }
            }
            PinRecord::Tpm { salt, blob } => {
                let Some(sealer) = &self.sealer else {
                    return PinCheck::Unavailable("the TPM is not available".into());
                };
                match sealer.check(blob, &tpm_auth(salt, pin)) {
                    Ok(()) => PinCheck::Right,
                    Err(SealError::WrongAuth) => PinCheck::Wrong,
                    Err(SealError::LockedOut) => PinCheck::HardwareLocked,
                    Err(SealError::Unavailable(e)) => PinCheck::Unavailable(e),
                }
            }
        }
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

    fn load_record(&self, uid: u32) -> Option<PinRecord> {
        let bytes = self.store.get(uid, METHOD, RECORD).ok()??;
        let rec = PinRecord::decode(std::str::from_utf8(&bytes).ok()?);
        if rec.is_none() {
            log::warn!("uid {uid}: unreadable PIN record");
        }
        rec
    }
}

impl Backend for PinBackend {
    fn name(&self) -> &'static str {
        METHOD
    }

    fn assurance(&self) -> u32 {
        assurance::MEDIUM
    }

    /// A TPM-backed PIN is limited by hardware, so it rates one level higher
    /// (PLAN.md §5).
    fn assurance_for(&self, _user: &str, uid: u32) -> u32 {
        match self.load_record(uid) {
            Some(PinRecord::Tpm { .. }) if self.sealer.is_some() => assurance::HIGH,
            _ => self.assurance(),
        }
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
            let Some(rec) = self.load_record(uid) else {
                return Outcome::Unavailable;
            };
            if matches!(rec, PinRecord::Tpm { .. }) && self.sealer.is_none() {
                log::warn!("uid {uid}: the PIN is TPM-backed but the TPM is not available");
                return Outcome::Unavailable;
            }
            let granted = self.assurance_for(&req.user, uid);
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

                let (me, rec2) = (self.clone(), rec.clone());
                let checked = tokio::task::spawn_blocking(move || me.check(&rec2, &pin))
                    .await
                    .unwrap_or(PinCheck::Wrong);
                match checked {
                    PinCheck::Right => {
                        if lock.failures != 0 {
                            let _ = self.save_lockout(uid, Lockout::default());
                        }
                        return Outcome::Match { assurance: granted };
                    }
                    PinCheck::Wrong => {}
                    PinCheck::HardwareLocked => {
                        log::warn!("uid {uid}: the TPM is in dictionary-attack lockout");
                        progress.emit(
                            "locked",
                            "The TPM has locked PIN entry after too many wrong attempts; use your password",
                        );
                        return if attempt == 0 {
                            Outcome::Unavailable
                        } else {
                            Outcome::NoMatch
                        };
                    }
                    PinCheck::Unavailable(e) => {
                        log::warn!("uid {uid}: cannot check the PIN with the TPM: {e}");
                        return Outcome::Unavailable;
                    }
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

    /// Stands in for the TPM: the blob is the auth value itself, and three
    /// wrong guesses in a row lock it until `unlock`.
    #[derive(Default)]
    struct FakeTpm {
        failures: std::sync::Mutex<u32>,
        gone: std::sync::atomic::AtomicBool,
    }

    impl PinSealer for FakeTpm {
        fn seal(&self, auth: &[u8]) -> Result<Vec<u8>, SealError> {
            Ok(auth.to_vec())
        }
        fn check(&self, blob: &[u8], auth: &[u8]) -> Result<(), SealError> {
            if self.gone.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(SealError::Unavailable("gone".into()));
            }
            let mut f = self.failures.lock().unwrap();
            if *f >= 3 {
                return Err(SealError::LockedOut);
            }
            if blob == auth {
                Ok(())
            } else {
                *f += 1;
                Err(SealError::WrongAuth)
            }
        }
    }

    fn backend(tag: &str, mode: TpmMode, tpm: Option<Arc<FakeTpm>>) -> PinBackend {
        PinBackend::new(
            crate::guard::tests::temp_store(tag),
            PinConfig {
                tpm: mode,
                ..PinConfig::default()
            },
            tpm.map(|t| t as Arc<dyn PinSealer>),
        )
    }

    #[test]
    fn record_encoding() {
        let tpm = PinRecord::Tpm {
            salt: [3; 16],
            blob: vec![1, 2, 0xff],
        };
        assert_eq!(tpm.encode(), format!("tpm1${}$0102ff", "03".repeat(16)));
        assert_eq!(PinRecord::decode(&tpm.encode()), Some(tpm));
        let soft = PinRecord::Argon2(hash_pin("2468").unwrap());
        assert_eq!(PinRecord::decode(&soft.encode()), Some(soft));
        for bad in ["", "garbage", "tpm1$zz$00", "tpm1$0303$00", "tpm1$"] {
            assert_eq!(PinRecord::decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn tpm_backed_pin() {
        let tpm = Arc::new(FakeTpm::default());
        let b = backend("pin-tpm", TpmMode::Auto, Some(tpm.clone()));
        assert_eq!(b.protection(), "tpm");
        b.enroll(1000, "2468").unwrap();
        let rec = b.load_record(1000).unwrap();
        assert!(matches!(rec, PinRecord::Tpm { .. }));
        assert_eq!(b.assurance_for("alice", 1000), assurance::HIGH);
        assert_eq!(b.check(&rec, "2468"), PinCheck::Right);
        assert_eq!(b.check(&rec, "2469"), PinCheck::Wrong);
        // The hardware's own lockout is reported as such, not as a wrong PIN.
        assert_eq!(b.check(&rec, "0000"), PinCheck::Wrong);
        assert_eq!(b.check(&rec, "0001"), PinCheck::Wrong);
        assert_eq!(b.check(&rec, "2468"), PinCheck::HardwareLocked);
        // A TPM that went away is "unavailable", never "right".
        *tpm.failures.lock().unwrap() = 0;
        tpm.gone.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(b.check(&rec, "2468"), PinCheck::Unavailable(_)));
        let _ = std::fs::remove_dir_all(b.store.root());
    }

    #[test]
    fn equal_pins_get_different_auth_values() {
        assert_ne!(tpm_auth(&[1; 16], "2468"), tpm_auth(&[2; 16], "2468"));
        assert_ne!(tpm_auth(&[1; 16], "2468"), tpm_auth(&[1; 16], "2469"));
        assert_eq!(tpm_auth(&[1; 16], "2468").len(), 32);
    }

    #[test]
    fn software_pin_when_there_is_no_tpm_or_it_is_off() {
        let b = backend("pin-soft", TpmMode::Auto, None);
        assert_eq!(b.protection(), "software");
        b.enroll(1000, "2468").unwrap();
        let rec = b.load_record(1000).unwrap();
        assert!(matches!(rec, PinRecord::Argon2(_)));
        assert_eq!(b.assurance_for("alice", 1000), assurance::MEDIUM);
        assert_eq!(b.check(&rec, "2468"), PinCheck::Right);
        assert_eq!(b.check(&rec, "1111"), PinCheck::Wrong);
        let _ = std::fs::remove_dir_all(b.store.root());

        let off = backend("pin-off", TpmMode::Off, Some(Arc::new(FakeTpm::default())));
        assert_eq!(off.protection(), "software");
        off.enroll(1000, "2468").unwrap();
        assert!(matches!(
            off.load_record(1000).unwrap(),
            PinRecord::Argon2(_)
        ));
        let _ = std::fs::remove_dir_all(off.store.root());
    }

    #[test]
    fn require_refuses_to_enrol_without_a_tpm() {
        let b = backend("pin-req", TpmMode::Require, None);
        assert!(b.enroll(1000, "2468").unwrap_err().contains("require"));
        assert!(b.load_record(1000).is_none());
        let _ = std::fs::remove_dir_all(b.store.root());
    }

    #[test]
    fn tpm_pin_without_its_tpm_is_not_usable() {
        let store = crate::guard::tests::temp_store("pin-lost");
        let with = PinBackend::new(
            store.clone(),
            PinConfig::default(),
            Some(Arc::new(FakeTpm::default()) as Arc<dyn PinSealer>),
        );
        with.enroll(1000, "2468").unwrap();
        let without = PinBackend::new(store.clone(), PinConfig::default(), None);
        let rec = without.load_record(1000).unwrap();
        assert!(matches!(
            without.check(&rec, "2468"),
            PinCheck::Unavailable(_)
        ));
        // No hardware limit behind it any more, so no extra assurance.
        assert_eq!(without.assurance_for("alice", 1000), assurance::MEDIUM);
        let _ = std::fs::remove_dir_all(store.root());
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
