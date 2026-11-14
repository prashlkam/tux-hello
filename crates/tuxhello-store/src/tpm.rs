// SPDX-FileCopyrightText: 2026 Tux Hello contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! TPM 2.0 sealing (PLAN.md §5.1 and §7.2), through tpm2-tss (`tss-esapi`).
//!
//! Two things are sealed, both as data objects under a storage key that is
//! derived inside the TPM and never leaves it:
//!
//! * the store's **master key** ([`TpmKey`]), with an empty auth value and no
//!   dictionary-attack protection: a copied disk is useless without this
//!   machine's TPM;
//! * each user's **PIN object**, whose auth value is derived from the PIN and
//!   which is subject to the TPM's dictionary-attack lockout: guessing is
//!   limited by hardware even for someone who bypasses the daemon.
//!
//! The storage key is a P-256 primary key made from a fixed template in the
//! owner hierarchy, so `CreatePrimary` yields the same key every time and
//! nothing has to be persisted in the TPM. Secrets and auth values travel in
//! a salted HMAC session with parameter encryption, so they are not visible
//! on the bus between CPU and TPM.
//!
//! Every operation opens its own context: nothing is left loaded in the TPM,
//! and a suspend/resume or TPM restart cannot leave stale handles behind.

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{KeyHandle, SessionHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Auth, Digest, EccPoint, KeyedHashScheme, Private, Public, PublicBuilder,
    PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData, SymmetricDefinition,
    SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::{Context, TctiNameConf};
use zeroize::Zeroizing;

use crate::{io_err, random_bytes, write_atomic, KeyProvider, MasterKey, StoreError, KEY_LEN};

/// How tpm2-tss reaches the TPM: the kernel's resource manager.
pub const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";

const SEALED_MAGIC: &[u8; 4] = b"TPS1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpmError {
    /// No TPM, no access to it, or it refused to create the storage key.
    Unavailable(String),
    /// The auth value was wrong; the TPM has counted the failure.
    AuthFailed,
    /// The TPM is in dictionary-attack lockout and refuses to try.
    LockedOut,
    /// The blob was not made by this TPM (or is damaged).
    WrongTpm,
    Other(String),
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TpmError::Unavailable(m) => write!(f, "TPM unavailable: {m}"),
            TpmError::AuthFailed => write!(f, "wrong authorisation value"),
            TpmError::LockedOut => write!(f, "the TPM is in dictionary-attack lockout"),
            TpmError::WrongTpm => write!(f, "sealed by a different TPM, or damaged"),
            TpmError::Other(m) => write!(f, "TPM error: {m}"),
        }
    }
}

impl std::error::Error for TpmError {}

fn classify(e: tss_esapi::Error) -> TpmError {
    let kind = match &e {
        tss_esapi::Error::Tss2Error(rc) => rc.kind(),
        _ => None,
    };
    match kind {
        Some(Tss2ResponseCodeKind::AuthFail | Tss2ResponseCodeKind::BadAuth) => {
            TpmError::AuthFailed
        }
        Some(Tss2ResponseCodeKind::Lockout) => TpmError::LockedOut,
        Some(Tss2ResponseCodeKind::Integrity) => TpmError::WrongTpm,
        _ => TpmError::Other(e.to_string()),
    }
}

/// A sealed data object: the TPM's public and (encrypted) private parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

impl Sealed {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = SEALED_MAGIC.to_vec();
        for part in [&self.public, &self.private] {
            out.extend_from_slice(&(part.len() as u16).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut rest = b.strip_prefix(SEALED_MAGIC)?;
        let mut take = || -> Option<Vec<u8>> {
            let len = usize::from(u16::from_be_bytes([*rest.first()?, *rest.get(1)?]));
            let part = rest.get(2..2 + len)?.to_vec();
            rest = &rest[2 + len..];
            Some(part)
        };
        let public = take()?;
        let private = take()?;
        (rest.is_empty() && !public.is_empty() && !private.is_empty())
            .then_some(Sealed { public, private })
    }
}

/// One TPM operation at a time in this process: a TPM has very few object
/// slots, and not every way of reaching one has a resource manager in front.
static TPM_LOCK: Mutex<()> = Mutex::new(());

/// Handle to the machine's TPM.
pub struct Tpm {
    tcti: String,
}

impl fmt::Debug for Tpm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tpm").field("tcti", &self.tcti).finish()
    }
}

struct Op {
    ctx: Context,
    srk: KeyHandle,
}

impl Op {
    /// Salted HMAC session with parameter encryption in both directions.
    fn session(&mut self) -> Result<AuthSession, TpmError> {
        // StartAuthSession takes no authorisation itself.
        self.ctx.clear_sessions();
        let s = self
            .ctx
            .start_auth_session(
                Some(self.srk),
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(classify)?
            .ok_or_else(|| TpmError::Other("no session returned".into()))?;
        let (attrs, mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .with_continue_session(true)
            .build();
        self.ctx
            .tr_sess_set_attributes(s, attrs, mask)
            .map_err(classify)?;
        Ok(s)
    }

    fn end_session(&mut self, s: AuthSession) {
        self.ctx.clear_sessions();
        let _ = self.ctx.flush_context(SessionHandle::from(s).into());
    }
}

impl Drop for Op {
    fn drop(&mut self) {
        self.ctx.clear_sessions();
        let _ = self.ctx.flush_context(self.srk.into());
    }
}

impl Tpm {
    /// Connects to the TPM named by `tcti` (see [`DEFAULT_TCTI`]) and checks
    /// that the storage key can be created.
    pub fn open(tcti: &str) -> Result<Self, TpmError> {
        let tpm = Tpm {
            tcti: tcti.to_string(),
        };
        let _g = TPM_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        drop(tpm.begin()?);
        Ok(tpm)
    }

    fn begin(&self) -> Result<Op, TpmError> {
        let conf = TctiNameConf::from_str(&self.tcti)
            .map_err(|e| TpmError::Unavailable(format!("bad TCTI {:?}: {e}", self.tcti)))?;
        let mut ctx = Context::new(conf).map_err(|e| TpmError::Unavailable(e.to_string()))?;

        let attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_no_da(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()
            .map_err(classify)?;
        let ecc = PublicEccParametersBuilder::new_restricted_decryption_key(
            SymmetricDefinitionObject::AES_128_CFB,
            EccCurve::NistP256,
        )
        .build()
        .map_err(classify)?;
        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attrs)
            .with_ecc_parameters(ecc)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(classify)?;
        ctx.set_sessions((Some(AuthSession::Password), None, None));
        let srk = ctx
            .create_primary(Hierarchy::Owner, public, None, None, None, None)
            .map_err(|e| {
                TpmError::Unavailable(format!(
                    "cannot create the storage key (is an owner password set?): {e}"
                ))
            })?
            .key_handle;
        Ok(Op { ctx, srk })
    }

    /// Seals `secret` so that only this TPM, given `auth`, returns it. With
    /// `guess_limited`, wrong `auth` values count towards the TPM's
    /// dictionary-attack lockout.
    pub fn seal(
        &self,
        secret: &[u8],
        auth: &[u8],
        guess_limited: bool,
    ) -> Result<Sealed, TpmError> {
        let _g = TPM_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut op = self.begin()?;
        let attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_user_with_auth(true)
            .with_no_da(!guess_limited)
            .build()
            .map_err(classify)?;
        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attrs)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()
            .map_err(classify)?;
        let auth = Auth::try_from(auth.to_vec()).map_err(classify)?;
        let data = SensitiveData::try_from(secret.to_vec()).map_err(classify)?;

        let s = op.session()?;
        op.ctx.set_sessions((Some(s), None, None));
        let srk = op.srk;
        let created = op
            .ctx
            .create(srk, public, Some(auth), Some(data), None, None);
        op.end_session(s);
        let created = created.map_err(classify)?;
        Ok(Sealed {
            public: created.out_public.marshall().map_err(classify)?,
            private: created.out_private.to_vec(),
        })
    }

    /// Returns the sealed secret if `auth` is right.
    pub fn unseal(&self, sealed: &Sealed, auth: &[u8]) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        let _g = TPM_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut op = self.begin()?;
        let public = Public::unmarshall(&sealed.public).map_err(|_| TpmError::WrongTpm)?;
        let private = Private::try_from(sealed.private.clone()).map_err(|_| TpmError::WrongTpm)?;
        let auth = Auth::try_from(auth.to_vec()).map_err(classify)?;

        op.ctx
            .set_sessions((Some(AuthSession::Password), None, None));
        let srk = op.srk;
        let object = op.ctx.load(srk, private, public).map_err(classify)?;
        let result = (|| {
            op.ctx.tr_set_auth(object.into(), auth).map_err(classify)?;
            let s = op.session()?;
            op.ctx.set_sessions((Some(s), None, None));
            let data = op.ctx.unseal(object.into());
            op.end_session(s);
            data.map(|d| Zeroizing::new(d.to_vec())).map_err(classify)
        })();
        op.ctx.clear_sessions();
        let _ = op.ctx.flush_context(object.into());
        result
    }
}

// --- master key ----------------------------------------------------------------

const SEALED_KEY_FILE: &str = "master.key.tpm";
const FILE_KEY_FILE: &str = "master.key";

/// Whether the store at `root` already has a TPM-sealed master key.
pub fn sealed_key_exists(root: &Path) -> bool {
    root.join(SEALED_KEY_FILE).exists()
}

/// Whether the store at `root` has a master key in a plain file.
pub fn file_key_exists(root: &Path) -> bool {
    root.join(FILE_KEY_FILE).exists()
}

/// Master key sealed by the TPM (`master.key.tpm`). A copy of the disk
/// cannot decrypt the store on another machine.
///
/// If the store still has a file key (`master.key`), that key is sealed and
/// the file removed, so existing enrolments keep working.
pub struct TpmKey {
    tpm: Arc<Tpm>,
}

impl TpmKey {
    pub fn new(tpm: Arc<Tpm>) -> Self {
        TpmKey { tpm }
    }
}

fn tpm_err(e: TpmError) -> StoreError {
    StoreError::Tpm(e.to_string())
}

impl KeyProvider for TpmKey {
    fn load_or_create(&self, root: &Path) -> Result<MasterKey, StoreError> {
        let sealed_path = root.join(SEALED_KEY_FILE);
        let file_path = root.join(FILE_KEY_FILE);
        match fs::read(&sealed_path) {
            Ok(bytes) => {
                let sealed = Sealed::decode(&bytes)
                    .ok_or_else(|| StoreError::Corrupt(sealed_path.clone()))?;
                let key = self.tpm.unseal(&sealed, b"").map_err(tpm_err)?;
                let key: [u8; KEY_LEN] = key
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Corrupt(sealed_path))?;
                Ok(MasterKey(key))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let migrating = file_path.exists();
                let key = if migrating {
                    crate::FileKey.load_or_create(root)?
                } else {
                    let mut k = [0u8; KEY_LEN];
                    random_bytes(&mut k)?;
                    MasterKey(k)
                };
                let sealed = self.tpm.seal(&key.0, b"", false).map_err(tpm_err)?;
                // Prove it can be read back before anything depends on it.
                let back = self.tpm.unseal(&sealed, b"").map_err(tpm_err)?;
                if back.as_slice() != key.0 {
                    return Err(StoreError::Tpm("sealed key does not read back".into()));
                }
                write_atomic(&sealed_path, &sealed.encode(), 0o600)?;
                if migrating {
                    fs::remove_file(&file_path).map_err(io_err(&file_path))?;
                }
                Ok(key)
            }
            Err(e) => Err(StoreError::Io(sealed_path, e)),
        }
    }

    fn describe(&self) -> &'static str {
        "TPM 2.0 (sealed to this machine)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    #[test]
    fn sealed_blob_encoding() {
        let s = Sealed {
            public: vec![1, 2, 3],
            private: vec![4; 200],
        };
        let bytes = s.encode();
        assert_eq!(Sealed::decode(&bytes), Some(s));
        assert_eq!(Sealed::decode(b"nope"), None);
        assert_eq!(Sealed::decode(&bytes[..bytes.len() - 1]), None);
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(Sealed::decode(&longer), None);
    }

    #[test]
    fn missing_tpm_is_unavailable() {
        assert!(matches!(
            Tpm::open("device:/nonexistent/tpm"),
            Err(TpmError::Unavailable(_))
        ));
        assert!(matches!(
            Tpm::open("no-such-tcti"),
            Err(TpmError::Unavailable(_))
        ));
    }

    /// The tests below need a TPM; the container suite points
    /// `TUXHELLO_TEST_TCTI` at a software TPM (swtpm).
    fn test_tpm() -> Option<Arc<Tpm>> {
        let Ok(tcti) = std::env::var("TUXHELLO_TEST_TCTI") else {
            eprintln!("skipped: TUXHELLO_TEST_TCTI is not set");
            return None;
        };
        Some(Arc::new(Tpm::open(&tcti).expect("test TPM is reachable")))
    }

    fn temp_root(tag: &str) -> std::path::PathBuf {
        let mut id = [0u8; 8];
        random_bytes(&mut id).unwrap();
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        std::env::temp_dir().join(format!("tuxhello-tpm-{tag}-{hex}"))
    }

    #[test]
    fn seal_and_unseal() {
        let Some(tpm) = test_tpm() else { return };
        let sealed = tpm.seal(&[7u8; 32], b"", false).unwrap();
        assert_eq!(tpm.unseal(&sealed, b"").unwrap().as_slice(), [7u8; 32]);
        // The blob holds the secret only in encrypted form.
        assert!(!sealed.private.windows(8).any(|w| w == [7u8; 8]));
        // A damaged blob is rejected, not misread.
        let mut bad = sealed.clone();
        let n = bad.private.len();
        bad.private[n - 1] ^= 1;
        assert!(tpm.unseal(&bad, b"").is_err());
        // A second handle (a restarted daemon) reads the same blob.
        let again = Tpm::open(&std::env::var("TUXHELLO_TEST_TCTI").unwrap()).unwrap();
        assert_eq!(again.unseal(&sealed, b"").unwrap().as_slice(), [7u8; 32]);
    }

    #[test]
    fn auth_value_is_required() {
        let Some(tpm) = test_tpm() else { return };
        // Not guess-limited here, so that this test cannot put the shared
        // test TPM into lockout; the lockout itself is covered end to end
        // by the integration suite.
        let sealed = tpm.seal(b"secret", b"right", false).unwrap();
        assert_eq!(tpm.unseal(&sealed, b"right").unwrap().as_slice(), b"secret");
        assert_eq!(tpm.unseal(&sealed, b"wrong"), Err(TpmError::AuthFailed));
        assert_eq!(tpm.unseal(&sealed, b""), Err(TpmError::AuthFailed));
    }

    #[test]
    fn master_key_is_sealed_and_stable() {
        let Some(tpm) = test_tpm() else { return };
        let root = temp_root("key");
        let store = Store::open(&root, &TpmKey::new(tpm.clone())).unwrap();
        assert!(sealed_key_exists(&root));
        assert!(!file_key_exists(&root));
        store.put(1000, "pin", "default", b"hello").unwrap();
        drop(store);
        let store = Store::open(&root, &TpmKey::new(tpm)).unwrap();
        assert_eq!(
            store
                .get(1000, "pin", "default")
                .unwrap()
                .unwrap()
                .as_slice(),
            b"hello"
        );
        assert!(store.key_description().starts_with("TPM"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn file_key_is_migrated() {
        let Some(tpm) = test_tpm() else { return };
        let root = temp_root("migrate");
        let store = Store::open(&root, &crate::FileKey).unwrap();
        store.put(1000, "pin", "default", b"kept").unwrap();
        drop(store);
        assert!(file_key_exists(&root));

        let store = Store::open(&root, &TpmKey::new(tpm.clone())).unwrap();
        assert!(sealed_key_exists(&root));
        assert!(!file_key_exists(&root), "the plain key file must be gone");
        assert_eq!(
            store
                .get(1000, "pin", "default")
                .unwrap()
                .unwrap()
                .as_slice(),
            b"kept"
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn damaged_sealed_key_fails_closed() {
        let Some(tpm) = test_tpm() else { return };
        let root = temp_root("damaged");
        drop(Store::open(&root, &TpmKey::new(tpm.clone())).unwrap());
        fs::write(root.join(SEALED_KEY_FILE), b"garbage").unwrap();
        assert!(matches!(
            Store::open(&root, &TpmKey::new(tpm)),
            Err(StoreError::Corrupt(_))
        ));
        // It must not quietly start over with a new key.
        assert_eq!(fs::read(root.join(SEALED_KEY_FILE)).unwrap(), b"garbage");
        fs::remove_dir_all(&root).unwrap();
    }
}
