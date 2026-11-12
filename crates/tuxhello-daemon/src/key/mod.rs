//! FIDO2 security-key backend (PLAN.md §5.5).
//!
//! The device conversation goes through an [`Authenticator`]: libfido2 for
//! real keys ([`fido2`]), or a software authenticator for tests ([`soft`]).
//! Everything security-relevant about the answer (RP ID hash, user-presence
//! and user-verification flags, the signature, and the clone-detecting
//! signature counter) is checked here, in [`verify_assertion`], independently
//! of the device library.

// Without libfido2 parts of the device interface (or, without the test
// authenticator too, the whole backend) are compiled but unused.
#![cfg_attr(not(feature = "fido2"), allow(dead_code))]

#[cfg(feature = "fido2")]
pub mod fido2;
pub mod import;
#[cfg(any(test, feature = "stub-backend"))]
pub mod soft;

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tuxhello_proto::assurance;
use tuxhello_store::Store;

use crate::backend::{Backend, BoxFuture, Outcome, Progress, Request};

pub const METHOD: &str = "key";

/// COSE algorithm identifiers.
pub const COSE_ES256: i32 = -7;
pub const COSE_EDDSA: i32 = -8;

/// Authenticator-data flags.
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    /// Relying-party id the credentials are bound to.
    #[serde(default = "default_rp_id")]
    pub rp_id: String,
    /// Require user verification (the key's own PIN or fingerprint). Makes the
    /// method interactive (the key PIN is asked for) and raises its assurance
    /// from 3 to 4.
    #[serde(default)]
    pub require_uv: bool,
}

fn default_rp_id() -> String {
    "pam://tuxhello".into()
}

impl Default for KeyConfig {
    fn default() -> Self {
        KeyConfig {
            rp_id: default_rp_id(),
            require_uv: false,
        }
    }
}

// --- device abstraction -------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub path: String,
    pub product: String,
}

pub struct MakeCredential<'a> {
    pub rp_id: &'a str,
    pub user_id: &'a [u8],
    pub user_name: &'a str,
    pub client_data_hash: &'a [u8; 32],
    pub uv: bool,
}

#[derive(Debug, Clone)]
pub struct NewCredential {
    pub id: Vec<u8>,
    pub alg: i32,
    /// ES256: x||y (64 bytes) or SEC1 uncompressed (65); EdDSA: 32 bytes.
    pub public_key: Vec<u8>,
}

pub struct GetAssertion<'a> {
    pub rp_id: &'a str,
    pub client_data_hash: &'a [u8; 32],
    pub allow: &'a [Vec<u8>],
    pub uv: bool,
}

#[derive(Debug, Clone)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// None of the allowed credentials are on this key.
    NoCredentials,
    /// The key needs its PIN for this operation.
    PinRequired,
    PinInvalid,
    /// PIN or UV blocked on the key itself.
    Blocked,
    /// Nobody touched the key in time.
    Timeout,
    Cancelled,
    Other(String),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::NoCredentials => write!(f, "this key holds none of your credentials"),
            KeyError::PinRequired => write!(f, "the key requires its PIN"),
            KeyError::PinInvalid => write!(f, "wrong security key PIN"),
            KeyError::Blocked => write!(f, "the security key is blocked (too many wrong PINs)"),
            KeyError::Timeout => write!(f, "the key was not touched in time"),
            KeyError::Cancelled => write!(f, "cancelled"),
            KeyError::Other(m) => write!(f, "{m}"),
        }
    }
}

/// Lets an async task cancel a blocking device call running on another
/// thread (libfido2's `fido_dev_cancel`).
#[derive(Default)]
pub struct CancelToken {
    cancelled: AtomicBool,
    hook: Mutex<Option<Box<dyn Fn() + Send>>>,
}

impl CancelToken {
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Some(h) = self.hook.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            h();
        }
    }

    /// Installs the function that interrupts the current device call.
    /// Returns false if the token was already cancelled.
    pub fn set_hook(&self, f: Box<dyn Fn() + Send>) -> bool {
        let mut g = self.hook.lock().unwrap_or_else(|p| p.into_inner());
        *g = Some(f);
        !self.is_cancelled()
    }

    /// Removes the hook. Must be called before the device is freed.
    pub fn clear_hook(&self) {
        *self.hook.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}

/// Cancels the token when dropped, unless disarmed: dropping the async future
/// (session cancelled or timed out) stops the device waiting for a touch.
struct CancelOnDrop(Arc<CancelToken>, bool);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if !self.1 {
            self.0.cancel();
        }
    }
}

/// Talks to security keys. All calls block (they may wait for a touch).
pub trait Authenticator: Send + Sync {
    fn devices(&self) -> Vec<DeviceInfo>;
    fn make_credential(
        &self,
        dev: &DeviceInfo,
        req: &MakeCredential<'_>,
        pin: Option<&str>,
        cancel: &CancelToken,
    ) -> Result<NewCredential, KeyError>;
    fn get_assertion(
        &self,
        dev: &DeviceInfo,
        req: &GetAssertion<'_>,
        pin: Option<&str>,
        cancel: &CancelToken,
    ) -> Result<Assertion, KeyError>;
}

// --- stored records -----------------------------------------------------------

pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// One enrolled credential, stored encrypted as `key/<id>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRecord {
    pub version: u32,
    pub label: String,
    pub rp_id: String,
    pub alg: i32,
    /// Hex-encoded credential id.
    pub credential_id: String,
    /// Hex-encoded public key (see [`NewCredential::public_key`]).
    pub public_key: String,
    pub sign_count: u32,
    pub created: u64,
    pub product: String,
}

impl KeyRecord {
    fn cred_id_bytes(&self) -> Option<Vec<u8>> {
        from_hex(&self.credential_id)
    }
}

// --- verification -------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    WrongCredential,
    Malformed,
    WrongRelyingParty,
    NoUserPresence,
    NoUserVerification,
    BadSignature,
    UnsupportedAlgorithm(i32),
    /// The signature counter went backwards: the key may have been cloned.
    CounterRegression {
        stored: u32,
        got: u32,
    },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::WrongCredential => write!(f, "assertion is for another credential"),
            VerifyError::Malformed => write!(f, "malformed authenticator data"),
            VerifyError::WrongRelyingParty => write!(f, "RP ID hash mismatch"),
            VerifyError::NoUserPresence => write!(f, "user presence flag not set"),
            VerifyError::NoUserVerification => write!(f, "user verification flag not set"),
            VerifyError::BadSignature => write!(f, "signature does not verify"),
            VerifyError::UnsupportedAlgorithm(a) => write!(f, "unsupported COSE algorithm {a}"),
            VerifyError::CounterRegression { stored, got } => write!(
                f,
                "signature counter went backwards ({got} <= {stored}); possible cloned key"
            ),
        }
    }
}

fn verify_signature(
    alg: i32,
    public_key: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), VerifyError> {
    match alg {
        COSE_ES256 => {
            use p256::ecdsa::signature::Verifier;
            let sec1: Vec<u8> = match public_key.len() {
                64 => [&[0x04u8][..], public_key].concat(),
                65 => public_key.to_vec(),
                _ => return Err(VerifyError::Malformed),
            };
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|_| VerifyError::Malformed)?;
            let sig =
                p256::ecdsa::Signature::from_der(sig).map_err(|_| VerifyError::BadSignature)?;
            vk.verify(msg, &sig).map_err(|_| VerifyError::BadSignature)
        }
        COSE_EDDSA => {
            let pk: [u8; 32] = public_key.try_into().map_err(|_| VerifyError::Malformed)?;
            let vk =
                ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|_| VerifyError::Malformed)?;
            let sig =
                ed25519_dalek::Signature::from_slice(sig).map_err(|_| VerifyError::BadSignature)?;
            vk.verify_strict(msg, &sig)
                .map_err(|_| VerifyError::BadSignature)
        }
        other => Err(VerifyError::UnsupportedAlgorithm(other)),
    }
}

/// Checks an assertion against a stored record. Returns the new signature
/// counter on success.
pub fn verify_assertion(
    rec: &KeyRecord,
    client_data_hash: &[u8; 32],
    a: &Assertion,
    require_uv: bool,
) -> Result<u32, VerifyError> {
    if rec.cred_id_bytes().as_deref() != Some(&a.credential_id[..]) {
        return Err(VerifyError::WrongCredential);
    }
    let ad = &a.auth_data;
    if ad.len() < 37 {
        return Err(VerifyError::Malformed);
    }
    if ad[..32] != Sha256::digest(rec.rp_id.as_bytes())[..] {
        return Err(VerifyError::WrongRelyingParty);
    }
    let flags = ad[32];
    if flags & FLAG_UP == 0 {
        return Err(VerifyError::NoUserPresence);
    }
    if require_uv && flags & FLAG_UV == 0 {
        return Err(VerifyError::NoUserVerification);
    }
    let pk = from_hex(&rec.public_key).ok_or(VerifyError::Malformed)?;
    let msg = [&ad[..], &client_data_hash[..]].concat();
    verify_signature(rec.alg, &pk, &msg, &a.signature)?;
    let count = u32::from_be_bytes([ad[33], ad[34], ad[35], ad[36]]);
    // Keys that don't implement a counter always report 0; allow that.
    if (count != 0 || rec.sign_count != 0) && count <= rec.sign_count {
        return Err(VerifyError::CounterRegression {
            stored: rec.sign_count,
            got: count,
        });
    }
    Ok(count)
}

// --- backend ------------------------------------------------------------------

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    tuxhello_store::random_bytes(&mut b).expect("OS RNG available");
    b
}

/// Turns a user-supplied label into a record id (`[a-z0-9_-]`, no leading `_`).
pub fn label_to_id(label: &str) -> Option<String> {
    let id: String = label
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(48)
        .collect();
    (!id.is_empty() && tuxhello_store::valid_name(&id)).then_some(id)
}

pub struct KeyBackend {
    store: Arc<Store>,
    cfg: KeyConfig,
    auth: Arc<dyn Authenticator>,
}

impl KeyBackend {
    pub fn new(store: Arc<Store>, cfg: KeyConfig, auth: Arc<dyn Authenticator>) -> Self {
        KeyBackend { store, cfg, auth }
    }

    fn records(&self, uid: u32) -> Vec<(String, KeyRecord)> {
        let Ok(list) = self.store.list(uid, Some(METHOD)) else {
            return Vec::new();
        };
        list.into_iter()
            .filter_map(|r| {
                let bytes = self.store.get(uid, METHOD, &r.id).ok()??;
                let text = std::str::from_utf8(&bytes).ok()?;
                match toml::from_str::<KeyRecord>(text) {
                    Ok(rec) => Some((r.id, rec)),
                    Err(e) => {
                        log::warn!("uid {uid}: unreadable key record {}: {e}", r.id);
                        None
                    }
                }
            })
            .collect()
    }

    fn save(&self, uid: u32, id: &str, rec: &KeyRecord) -> Result<(), String> {
        let text = toml::to_string(rec).map_err(|e| e.to_string())?;
        self.store
            .put(uid, METHOD, id, text.as_bytes())
            .map_err(|e| e.to_string())
    }

    /// Registers a new credential on the first connected key. Blocks until
    /// the key is touched. Returns the record id.
    pub fn enroll(
        &self,
        uid: u32,
        user_name: &str,
        label: Option<&str>,
        pin: Option<&str>,
    ) -> Result<String, String> {
        let existing = self.records(uid);
        let id = match label {
            Some(l) => label_to_id(l).ok_or_else(|| format!("invalid label {l:?}"))?,
            None => (1..)
                .map(|n| format!("key-{n}"))
                .find(|c| existing.iter().all(|(id, _)| id != c))
                .expect("unbounded range"),
        };
        if existing.iter().any(|(eid, _)| *eid == id) {
            return Err(format!(
                "{id:?} is already enrolled; choose another --label"
            ));
        }

        let devices = self.auth.devices();
        let dev = devices
            .first()
            .ok_or_else(|| "no security key found; plug one in".to_string())?;
        if devices.len() > 1 {
            log::info!("several security keys connected; enrolling {}", dev.path);
        }
        let user_id = random32();
        let cdh = random32();
        let cancel = CancelToken::default();
        let cred = self
            .auth
            .make_credential(
                dev,
                &MakeCredential {
                    rp_id: &self.cfg.rp_id,
                    user_id: &user_id,
                    user_name,
                    client_data_hash: &cdh,
                    uv: self.cfg.require_uv,
                },
                pin.filter(|p| !p.is_empty()),
                &cancel,
            )
            .map_err(|e| e.to_string())?;

        let cred_hex = to_hex(&cred.id);
        if existing.iter().any(|(_, r)| r.credential_id == cred_hex) {
            return Err("this credential is already enrolled".into());
        }
        let rec = KeyRecord {
            version: 1,
            label: label.unwrap_or(&id).to_string(),
            rp_id: self.cfg.rp_id.clone(),
            alg: cred.alg,
            credential_id: cred_hex,
            public_key: to_hex(&cred.public_key),
            sign_count: 0,
            created: now(),
            product: dev.product.clone(),
        };
        // Reject keys whose public key we could never verify against.
        if !matches!(rec.alg, COSE_ES256 | COSE_EDDSA) {
            return Err(format!("unsupported key algorithm {}", rec.alg));
        }
        self.save(uid, &id, &rec)?;
        Ok(id)
    }
}

impl KeyBackend {
    /// Imports credentials from a pam_u2f key file (see `import.rs`).
    /// `origin` is the relying-party id pam_u2f used, `pam://<hostname>`
    /// unless it was configured otherwise. Returns the ids of the new
    /// records and a note for every credential that was left out.
    pub fn import_pam_u2f(
        &self,
        uid: u32,
        user_name: &str,
        text: &str,
        origin: &str,
    ) -> Result<(Vec<String>, Vec<String>), String> {
        if origin.is_empty() || origin.chars().any(|c| c.is_control()) {
            return Err(format!("invalid origin {origin:?}"));
        }
        let (creds, mut notes) = import::parse_pam_u2f(text, user_name);
        let mut existing = self.records(uid);
        let mut imported = Vec::new();
        for c in creds {
            let cred_hex = to_hex(&c.credential_id);
            if existing.iter().any(|(_, r)| r.credential_id == cred_hex) {
                notes.push(format!("credential {} is already enrolled", c.index));
                continue;
            }
            let id = (1..)
                .map(|n| format!("u2f-{n}"))
                .find(|cand| existing.iter().all(|(id, _)| id != cand))
                .expect("unbounded range");
            let rec = KeyRecord {
                version: 1,
                label: id.clone(),
                rp_id: origin.to_string(),
                alg: c.alg,
                credential_id: cred_hex,
                public_key: to_hex(&c.public_key),
                sign_count: 0,
                created: now(),
                product: "imported from pam_u2f".into(),
            };
            self.save(uid, &id, &rec)?;
            if c.wants_uv && !self.cfg.require_uv {
                notes.push(format!(
                    "{id}: pam_u2f required the key's PIN for this credential; Tux Hello only \
                     does with [key] require_uv = true"
                ));
            }
            existing.push((id.clone(), rec));
            imported.push(id);
        }
        Ok((imported, notes))
    }
}

impl Backend for KeyBackend {
    fn name(&self) -> &'static str {
        METHOD
    }

    fn assurance(&self) -> u32 {
        if self.cfg.require_uv {
            assurance::HARDWARE_KEY
        } else {
            assurance::HIGH
        }
    }

    fn available(&self) -> bool {
        !self.auth.devices().is_empty()
    }

    fn interactive(&self) -> bool {
        self.cfg.require_uv
    }

    fn is_enrolled(&self, _user: &str, uid: u32) -> bool {
        matches!(self.store.list(uid, Some(METHOD)), Ok(l) if !l.is_empty())
    }

    fn verify(self: Arc<Self>, req: Request, progress: Progress) -> BoxFuture<Outcome> {
        Box::pin(async move {
            let uid = req.uid;
            let records = self.records(uid);
            if records.is_empty() {
                return Outcome::Unavailable;
            }
            let pin = if self.cfg.require_uv {
                match progress
                    .request_secret("Security key PIN (empty to skip): ")
                    .await
                {
                    Some(p) if !p.is_empty() => Some(p),
                    _ => return Outcome::Unavailable,
                }
            } else {
                None
            };

            let devices = self.auth.devices();
            if devices.is_empty() {
                return Outcome::Unavailable;
            }
            progress.emit("touch", "Touch your security key");

            // A credential only answers for the relying-party id it was made
            // for. Ours all share one, but imported ones (pam_u2f) keep
            // theirs, so ask once per id. A key that holds none of a group's
            // credentials says so without waiting for a touch.
            let mut groups: Vec<(String, Vec<Vec<u8>>)> = Vec::new();
            for (_, r) in &records {
                let Some(cred) = r.cred_id_bytes() else {
                    continue;
                };
                match groups.iter_mut().find(|(rp, _)| *rp == r.rp_id) {
                    Some((_, allow)) => allow.push(cred),
                    None => groups.push((r.rp_id.clone(), vec![cred])),
                }
            }
            let attempts: Vec<(DeviceInfo, String, Vec<Vec<u8>>)> = devices
                .into_iter()
                .flat_map(|dev| {
                    groups
                        .iter()
                        .map(move |(rp, allow)| (dev.clone(), rp.clone(), allow.clone()))
                })
                .collect();

            let mut outcome = Outcome::Unavailable;
            for (dev, rp_id, allow) in attempts {
                let cancel = Arc::new(CancelToken::default());
                let mut guard = CancelOnDrop(cancel.clone(), false);
                let me = self.clone();
                let cdh = random32();
                let pin2 = pin.clone();
                let dev2 = dev.clone();
                let res = tokio::task::spawn_blocking(move || {
                    me.auth.get_assertion(
                        &dev2,
                        &GetAssertion {
                            rp_id: &rp_id,
                            client_data_hash: &cdh,
                            allow: &allow,
                            uv: me.cfg.require_uv,
                        },
                        pin2.as_deref().map(|p| p.as_str()),
                        &cancel,
                    )
                })
                .await;
                guard.1 = true;
                let res = match res {
                    Ok(r) => r,
                    Err(e) => Err(KeyError::Other(format!("device task failed: {e}"))),
                };
                match res {
                    Ok(a) => {
                        let Some((id, rec)) = records.iter().find(|(_, r)| {
                            r.cred_id_bytes().as_deref() == Some(&a.credential_id[..])
                        }) else {
                            log::warn!("uid {uid}: key answered with an unknown credential");
                            outcome = Outcome::NoMatch;
                            continue;
                        };
                        match verify_assertion(rec, &cdh, &a, self.cfg.require_uv) {
                            Ok(count) => {
                                let mut updated = rec.clone();
                                updated.sign_count = count;
                                if let Err(e) = self.save(uid, id, &updated) {
                                    log::error!("uid {uid}: cannot update key counter: {e}");
                                }
                                return Outcome::Match {
                                    assurance: self.assurance(),
                                };
                            }
                            Err(e) => {
                                log::warn!(
                                    "uid {uid}: key {id:?} rejected: {e} (service {:?})",
                                    req.service
                                );
                                progress.emit("rejected", "Security key rejected");
                                progress.failed_attempt();
                                return Outcome::NoMatch;
                            }
                        }
                    }
                    Err(KeyError::NoCredentials) => {
                        log::info!("uid {uid}: {} holds no enrolled credential", dev.path);
                        outcome = Outcome::NoMatch;
                    }
                    Err(KeyError::PinInvalid) => {
                        progress.emit("retry", "Wrong security key PIN");
                        progress.failed_attempt();
                        return Outcome::NoMatch;
                    }
                    Err(KeyError::PinRequired) => {
                        log::warn!(
                            "uid {uid}: the key requires its PIN; set [key] require_uv = true"
                        );
                        progress.emit("error", "This security key needs its PIN");
                    }
                    Err(KeyError::Cancelled) => return Outcome::Unavailable,
                    Err(e @ (KeyError::Timeout | KeyError::Blocked | KeyError::Other(_))) => {
                        log::info!("uid {uid}: {}: {e}", dev.path);
                    }
                }
            }
            if outcome == Outcome::NoMatch {
                progress.emit("rejected", "Security key not recognised");
                progress.failed_attempt();
            }
            outcome
        })
    }
}

#[cfg(test)]
mod tests {
    use super::soft::SoftAuthenticator;
    use super::*;

    fn rec_for(cred: &NewCredential, rp: &str) -> KeyRecord {
        KeyRecord {
            version: 1,
            label: "t".into(),
            rp_id: rp.into(),
            alg: cred.alg,
            credential_id: to_hex(&cred.id),
            public_key: to_hex(&cred.public_key),
            sign_count: 0,
            created: 0,
            product: "soft".into(),
        }
    }

    fn enroll(a: &SoftAuthenticator, rp: &str, alg: i32) -> NewCredential {
        a.set_alg(alg);
        let dev = &a.devices()[0];
        a.make_credential(
            dev,
            &MakeCredential {
                rp_id: rp,
                user_id: b"u",
                user_name: "alice",
                client_data_hash: &[1; 32],
                uv: false,
            },
            None,
            &CancelToken::default(),
        )
        .unwrap()
    }

    fn assert_with(
        a: &SoftAuthenticator,
        rp: &str,
        cdh: &[u8; 32],
        allow: &[Vec<u8>],
    ) -> Assertion {
        let dev = &a.devices()[0];
        a.get_assertion(
            dev,
            &GetAssertion {
                rp_id: rp,
                client_data_hash: cdh,
                allow,
                uv: false,
            },
            None,
            &CancelToken::default(),
        )
        .unwrap()
    }

    /// Runs the backend's `verify` for uid 1000 and returns the outcome.
    async fn verify_once(backend: Arc<KeyBackend>) -> Outcome {
        let session = Arc::new(crate::session::Session::new("t".into(), ":1.1".into(), 0));
        let req = Request {
            user: "alice".into(),
            uid: 1000,
            service: "test".into(),
        };
        let progress = Progress::for_request(
            session,
            METHOD,
            crate::guard::tests::test_guard(),
            &req,
            false,
        );
        backend.verify(req, progress).await
    }

    fn b64(b: &[u8]) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for chunk in b.chunks(3) {
            let v = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= chunk.len() {
                    s.push(T[((v >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    s.push('=');
                }
            }
        }
        s
    }

    /// A key registered by pam_u2f under its own origin keeps working after
    /// import, next to a key enrolled with Tux Hello's relying-party id.
    #[tokio::test]
    async fn imported_pam_u2f_key_authenticates() {
        let store = crate::guard::tests::temp_store("u2f");
        let old_key = Arc::new(SoftAuthenticator::in_memory());
        let cred = enroll(&old_key, "pam://oldhost", COSE_ES256);
        let line = format!(
            "alice:{},{},es256,+presence\n",
            b64(&cred.id),
            b64(&cred.public_key)
        );

        let backend = Arc::new(KeyBackend::new(
            store.clone(),
            KeyConfig::default(),
            old_key.clone(),
        ));
        // Imported with the wrong origin, the key's answer does not verify.
        let (ids, notes) = backend
            .import_pam_u2f(1000, "alice", &line, "pam://wronghost")
            .unwrap();
        assert_eq!(ids, vec!["u2f-1".to_string()]);
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(verify_once(backend.clone()).await, Outcome::NoMatch);
        store.delete(1000, METHOD, "u2f-1").unwrap();

        let (ids, _) = backend
            .import_pam_u2f(1000, "alice", &line, "pam://oldhost")
            .unwrap();
        assert_eq!(ids, vec!["u2f-1".to_string()]);
        assert!(matches!(
            verify_once(backend.clone()).await,
            Outcome::Match { .. }
        ));
        // Importing the same file again adds nothing.
        let (ids, notes) = backend
            .import_pam_u2f(1000, "alice", &line, "pam://oldhost")
            .unwrap();
        assert!(ids.is_empty());
        assert!(notes[0].contains("already enrolled"));

        // A natively enrolled credential on the same key (other RP id) and
        // the imported one are both usable: each is asked under its own id.
        let id = backend.enroll(1000, "alice", Some("native"), None).unwrap();
        assert_eq!(id, "native");
        store.delete(1000, METHOD, "u2f-1").unwrap();
        assert!(matches!(
            verify_once(backend.clone()).await,
            Outcome::Match { .. }
        ));
        let _ = std::fs::remove_dir_all(store.root());
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(to_hex(&[0, 1, 0xab]), "0001ab");
        assert_eq!(from_hex("0001ab").unwrap(), vec![0, 1, 0xab]);
        assert!(from_hex("abc").is_none());
        assert!(from_hex("zz").is_none());
    }

    #[test]
    fn labels_become_safe_ids() {
        assert_eq!(label_to_id("My YubiKey 5").as_deref(), Some("my-yubikey-5"));
        assert_eq!(label_to_id("  backup  ").as_deref(), Some("backup"));
        assert_eq!(label_to_id("../../etc"), Some("etc".into()));
        assert_eq!(label_to_id("___"), None);
        assert_eq!(label_to_id(""), None);
    }

    #[test]
    fn valid_assertions_verify_for_both_algorithms() {
        for alg in [COSE_ES256, COSE_EDDSA] {
            let a = SoftAuthenticator::in_memory();
            let cred = enroll(&a, "pam://t", alg);
            let rec = rec_for(&cred, "pam://t");
            let cdh = [7u8; 32];
            let asn = assert_with(&a, "pam://t", &cdh, std::slice::from_ref(&cred.id));
            assert_eq!(
                verify_assertion(&rec, &cdh, &asn, false),
                Ok(1),
                "alg {alg}"
            );
        }
    }

    #[test]
    fn rejects_tampering() {
        let a = SoftAuthenticator::in_memory();
        let cred = enroll(&a, "pam://t", COSE_ES256);
        let rec = rec_for(&cred, "pam://t");
        let cdh = [7u8; 32];
        let good = assert_with(&a, "pam://t", &cdh, std::slice::from_ref(&cred.id));

        // Different challenge (replayed assertion).
        assert_eq!(
            verify_assertion(&rec, &[8u8; 32], &good, false),
            Err(VerifyError::BadSignature)
        );
        // Flipped signature bit.
        let mut bad = good.clone();
        let n = bad.signature.len() - 1;
        bad.signature[n] ^= 1;
        assert!(verify_assertion(&rec, &cdh, &bad, false).is_err());
        // Missing user presence.
        let mut nup = good.clone();
        nup.auth_data[32] &= !FLAG_UP;
        assert_eq!(
            verify_assertion(&rec, &cdh, &nup, false),
            Err(VerifyError::NoUserPresence)
        );
        // UV demanded but absent.
        assert_eq!(
            verify_assertion(&rec, &cdh, &good, true),
            Err(VerifyError::NoUserVerification)
        );
        // Wrong credential id.
        let mut wc = good.clone();
        wc.credential_id[0] ^= 1;
        assert_eq!(
            verify_assertion(&rec, &cdh, &wc, false),
            Err(VerifyError::WrongCredential)
        );
        // Truncated.
        let mut tr = good.clone();
        tr.auth_data.truncate(20);
        assert_eq!(
            verify_assertion(&rec, &cdh, &tr, false),
            Err(VerifyError::Malformed)
        );
    }

    #[test]
    fn rejects_other_relying_party() {
        let a = SoftAuthenticator::in_memory();
        let cred = enroll(&a, "pam://t", COSE_ES256);
        let cdh = [7u8; 32];
        let asn = assert_with(&a, "pam://t", &cdh, std::slice::from_ref(&cred.id));
        let rec = rec_for(&cred, "pam://other");
        assert_eq!(
            verify_assertion(&rec, &cdh, &asn, false),
            Err(VerifyError::WrongRelyingParty)
        );
    }

    #[test]
    fn counter_must_increase() {
        let a = SoftAuthenticator::in_memory();
        let cred = enroll(&a, "pam://t", COSE_ES256);
        let mut rec = rec_for(&cred, "pam://t");
        let cdh = [7u8; 32];
        let asn = assert_with(&a, "pam://t", &cdh, std::slice::from_ref(&cred.id));
        rec.sign_count = verify_assertion(&rec, &cdh, &asn, false).unwrap();
        // The same assertion again (or a clone that is behind) is refused.
        assert_eq!(
            verify_assertion(&rec, &cdh, &asn, false),
            Err(VerifyError::CounterRegression { stored: 1, got: 1 })
        );
        let next = assert_with(&a, "pam://t", &cdh, std::slice::from_ref(&cred.id));
        assert_eq!(verify_assertion(&rec, &cdh, &next, false), Ok(2));
    }

    #[test]
    fn keys_without_counter_are_allowed() {
        let a = SoftAuthenticator::in_memory();
        a.set_counterless(true);
        let cred = enroll(&a, "pam://t", COSE_ES256);
        let rec = rec_for(&cred, "pam://t");
        let cdh = [7u8; 32];
        for _ in 0..3 {
            let asn = assert_with(&a, "pam://t", &cdh, std::slice::from_ref(&cred.id));
            assert_eq!(verify_assertion(&rec, &cdh, &asn, false), Ok(0));
        }
    }

    #[test]
    fn cancel_token_runs_hook_once_set() {
        let t = CancelToken::default();
        let hit = Arc::new(AtomicBool::new(false));
        let h = hit.clone();
        assert!(t.set_hook(Box::new(move || h.store(true, Ordering::SeqCst))));
        t.cancel();
        assert!(hit.load(Ordering::SeqCst));
        t.clear_hook();
        assert!(!t.set_hook(Box::new(|| {})), "already cancelled");
    }
}
