//! Encrypted per-user record store (PLAN.md §7).
//!
//! Layout under the root (default `/var/lib/tuxhello`, mode 0700):
//!
//! ```text
//! master.key                 32-byte master key, 0600 (file key provider)
//! users/<uid>/<method>/<id>.rec
//! ```
//!
//! Each record is `MAGIC || nonce(12) || AES-256-GCM(ciphertext+tag)`. The
//! associated data binds the record to its uid, method and id, so a record
//! copied to another user or renamed fails to decrypt.
//!
//! The master key comes from a [`KeyProvider`]. Phase 1 starts with
//! [`FileKey`]; with the `tpm` feature, [`tpm::TpmKey`] seals the key to the
//! machine's TPM instead (`master.key.tpm`).

#[cfg(feature = "tpm")]
pub mod tpm;

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const DEFAULT_ROOT: &str = "/var/lib/tuxhello";

const MAGIC: &[u8; 4] = b"THR1";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[derive(Debug)]
pub enum StoreError {
    Io(PathBuf, io::Error),
    /// Wrong key, corrupted or tampered record.
    Corrupt(PathBuf),
    InvalidName(String),
    Random(String),
    /// The TPM that seals the master key failed or is missing.
    Tpm(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io(p, e) => write!(f, "{}: {e}", p.display()),
            StoreError::Corrupt(p) => write!(f, "{}: corrupted or tampered record", p.display()),
            StoreError::InvalidName(n) => write!(f, "invalid record name {n:?}"),
            StoreError::Random(e) => write!(f, "random number generator failed: {e}"),
            StoreError::Tpm(e) => write!(f, "TPM-sealed master key: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

fn io_err(p: &Path) -> impl FnOnce(io::Error) -> StoreError + '_ {
    move |e| StoreError::Io(p.to_path_buf(), e)
}

/// Fills `buf` from the OS CSPRNG.
pub fn random_bytes(buf: &mut [u8]) -> Result<(), StoreError> {
    getrandom::fill(buf).map_err(|e| StoreError::Random(e.to_string()))
}

/// 256-bit key, wiped from memory on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        MasterKey(b)
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

/// Source of the store's master key.
pub trait KeyProvider {
    /// Returns the key, creating it on first use.
    fn load_or_create(&self, root: &Path) -> Result<MasterKey, StoreError>;
    /// Human-readable description for `tuxhello status`.
    fn describe(&self) -> &'static str;
}

/// Master key kept in a root-only file. Weaker than a TPM-sealed key: anyone
/// who can read the disk can decrypt the store (documented in PLAN.md §7.2).
pub struct FileKey;

impl KeyProvider for FileKey {
    fn load_or_create(&self, root: &Path) -> Result<MasterKey, StoreError> {
        let path = root.join("master.key");
        match fs::read(&path) {
            Ok(mut bytes) => {
                if bytes.len() != KEY_LEN {
                    bytes.zeroize();
                    return Err(StoreError::Corrupt(path));
                }
                let mut k = [0u8; KEY_LEN];
                k.copy_from_slice(&bytes);
                bytes.zeroize();
                Ok(MasterKey(k))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut k = [0u8; KEY_LEN];
                random_bytes(&mut k)?;
                write_atomic(&path, &k, 0o600)?;
                Ok(MasterKey(k))
            }
            Err(e) => Err(StoreError::Io(path, e)),
        }
    }

    fn describe(&self) -> &'static str {
        "file (no hardware protection)"
    }
}

/// Writes `data` to `path` atomically: temp file, fsync, rename, fsync dir.
fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<(), StoreError> {
    let dir = path.parent().expect("record paths have a parent");
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .map_err(io_err(&tmp))?;
        f.write_all(data).map_err(io_err(&tmp))?;
        f.sync_all().map_err(io_err(&tmp))?;
    }
    fs::rename(&tmp, path).map_err(io_err(path))?;
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

fn mkdir_private(p: &Path) -> Result<(), StoreError> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(p)
        .map_err(io_err(p))?;
    // `recursive` doesn't fix modes of directories that already existed.
    fs::set_permissions(p, fs::Permissions::from_mode(0o700)).map_err(io_err(p))
}

/// Method and record ids: `[a-z0-9_-]{1,64}`, so they are safe as file names.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn check_name(s: &str) -> Result<(), StoreError> {
    if valid_name(s) {
        Ok(())
    } else {
        Err(StoreError::InvalidName(s.to_string()))
    }
}

/// Reference to one stored record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecordRef {
    pub uid: u32,
    pub method: String,
    pub id: String,
}

pub struct Store {
    root: PathBuf,
    cipher: Aes256Gcm,
    key_description: &'static str,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store").field("root", &self.root).finish()
    }
}

impl Store {
    /// Opens (creating if needed) the store at `root`.
    pub fn open(root: &Path, keys: &dyn KeyProvider) -> Result<Self, StoreError> {
        mkdir_private(root)?;
        mkdir_private(&root.join("users"))?;
        let key = keys.load_or_create(root)?;
        let cipher = Aes256Gcm::new_from_slice(&key.0).expect("key length is 32");
        Ok(Store {
            root: root.to_path_buf(),
            cipher,
            key_description: keys.describe(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn key_description(&self) -> &'static str {
        self.key_description
    }

    fn user_dir(&self, uid: u32) -> PathBuf {
        self.root.join("users").join(uid.to_string())
    }

    fn path(&self, uid: u32, method: &str, id: &str) -> PathBuf {
        self.user_dir(uid).join(method).join(format!("{id}.rec"))
    }

    fn aad(uid: u32, method: &str, id: &str) -> Vec<u8> {
        format!("tuxhello-record-v1\0{uid}\0{method}\0{id}").into_bytes()
    }

    /// Stores (or replaces) a record.
    pub fn put(
        &self,
        uid: u32,
        method: &str,
        id: &str,
        plaintext: &[u8],
    ) -> Result<(), StoreError> {
        check_name(method)?;
        check_name(id)?;
        let dir = self.user_dir(uid).join(method);
        mkdir_private(&self.user_dir(uid))?;
        mkdir_private(&dir)?;

        let mut nonce = [0u8; NONCE_LEN];
        random_bytes(&mut nonce)?;
        let aad = Self::aad(uid, method, id);
        let path = self.path(uid, method, id);
        let ct = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| StoreError::Corrupt(path.clone()))?;
        let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        write_atomic(&path, &out, 0o600)
    }

    /// Reads a record. `Ok(None)` if it doesn't exist.
    pub fn get(
        &self,
        uid: u32,
        method: &str,
        id: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        check_name(method)?;
        check_name(id)?;
        let path = self.path(uid, method, id);
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StoreError::Io(path, e)),
        };
        if data.len() < MAGIC.len() + NONCE_LEN || &data[..MAGIC.len()] != MAGIC {
            return Err(StoreError::Corrupt(path));
        }
        let (nonce, ct) = data[MAGIC.len()..].split_at(NONCE_LEN);
        let aad = Self::aad(uid, method, id);
        let pt = self
            .cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
            .map_err(|_| StoreError::Corrupt(path))?;
        Ok(Some(Zeroizing::new(pt)))
    }

    /// Lists a user's records, optionally only for one method.
    pub fn list(&self, uid: u32, method: Option<&str>) -> Result<Vec<RecordRef>, StoreError> {
        let mut out = Vec::new();
        let udir = self.user_dir(uid);
        let methods: Vec<String> = match method {
            Some(m) => {
                check_name(m)?;
                vec![m.to_string()]
            }
            None => match fs::read_dir(&udir) {
                Ok(rd) => rd
                    .filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|n| valid_name(n))
                    .collect(),
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
                Err(e) => return Err(StoreError::Io(udir, e)),
            },
        };
        for m in methods {
            let dir = udir.join(&m);
            let rd = match fs::read_dir(&dir) {
                Ok(rd) => rd,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(StoreError::Io(dir, e)),
            };
            for e in rd.filter_map(|e| e.ok()) {
                let name = e.file_name().to_string_lossy().into_owned();
                if let Some(id) = name.strip_suffix(".rec") {
                    if valid_name(id) {
                        out.push(RecordRef {
                            uid,
                            method: m.clone(),
                            id: id.to_string(),
                        });
                    }
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// Deletes a record. Returns whether it existed.
    pub fn delete(&self, uid: u32, method: &str, id: &str) -> Result<bool, StoreError> {
        check_name(method)?;
        check_name(id)?;
        let path = self.path(uid, method, id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StoreError::Io(path, e)),
        }
    }

    /// Deletes everything stored for a user.
    pub fn delete_user(&self, uid: u32) -> Result<(), StoreError> {
        let dir = self.user_dir(uid);
        match fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::Io(dir, e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "tuxhello-store-test-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn roundtrip_and_permissions() {
        let t = TempDir::new();
        let s = Store::open(&t.0, &FileKey).unwrap();
        s.put(1000, "pin", "default", b"secret").unwrap();
        assert_eq!(
            &**s.get(1000, "pin", "default").unwrap().unwrap(),
            b"secret"
        );
        assert_eq!(s.get(1000, "pin", "other").unwrap(), None);
        assert_eq!(mode(&t.0), 0o700);
        assert_eq!(mode(&t.0.join("master.key")), 0o600);
        assert_eq!(mode(&t.0.join("users/1000/pin")), 0o700);
        assert_eq!(mode(&t.0.join("users/1000/pin/default.rec")), 0o600);
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let t = TempDir::new();
        let s = Store::open(&t.0, &FileKey).unwrap();
        s.put(1, "pin", "x", b"VERY-RECOGNISABLE").unwrap();
        let raw = fs::read(t.0.join("users/1/pin/x.rec")).unwrap();
        assert!(!raw.windows(17).any(|w| w == b"VERY-RECOGNISABLE"));
    }

    #[test]
    fn key_persists_across_opens() {
        let t = TempDir::new();
        Store::open(&t.0, &FileKey)
            .unwrap()
            .put(1, "key", "a", b"x")
            .unwrap();
        let s2 = Store::open(&t.0, &FileKey).unwrap();
        assert_eq!(&**s2.get(1, "key", "a").unwrap().unwrap(), b"x");
    }

    #[test]
    fn records_are_bound_to_uid_method_and_id() {
        let t = TempDir::new();
        let s = Store::open(&t.0, &FileKey).unwrap();
        s.put(1000, "pin", "a", b"x").unwrap();
        // Copy alice's record over to bob, and to another id.
        fs::create_dir_all(t.0.join("users/1001/pin")).unwrap();
        fs::copy(
            t.0.join("users/1000/pin/a.rec"),
            t.0.join("users/1001/pin/a.rec"),
        )
        .unwrap();
        fs::copy(
            t.0.join("users/1000/pin/a.rec"),
            t.0.join("users/1000/pin/b.rec"),
        )
        .unwrap();
        assert!(matches!(
            s.get(1001, "pin", "a"),
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(
            s.get(1000, "pin", "b"),
            Err(StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn tampering_is_detected() {
        let t = TempDir::new();
        let s = Store::open(&t.0, &FileKey).unwrap();
        s.put(1, "pin", "a", b"hello").unwrap();
        let p = t.0.join("users/1/pin/a.rec");
        let mut raw = fs::read(&p).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        fs::write(&p, &raw).unwrap();
        assert!(matches!(s.get(1, "pin", "a"), Err(StoreError::Corrupt(_))));
    }

    #[test]
    fn wrong_master_key_fails() {
        let t = TempDir::new();
        Store::open(&t.0, &FileKey)
            .unwrap()
            .put(1, "pin", "a", b"x")
            .unwrap();
        let mut k = [0u8; 32];
        random_bytes(&mut k).unwrap();
        fs::write(t.0.join("master.key"), k).unwrap();
        let s = Store::open(&t.0, &FileKey).unwrap();
        assert!(matches!(s.get(1, "pin", "a"), Err(StoreError::Corrupt(_))));
    }

    #[test]
    fn list_and_delete() {
        let t = TempDir::new();
        let s = Store::open(&t.0, &FileKey).unwrap();
        assert!(s.list(5, None).unwrap().is_empty());
        s.put(5, "key", "yubikey-1", b"a").unwrap();
        s.put(5, "key", "backup", b"b").unwrap();
        s.put(5, "pin", "default", b"c").unwrap();
        let all: Vec<String> = s
            .list(5, None)
            .unwrap()
            .into_iter()
            .map(|r| format!("{}/{}", r.method, r.id))
            .collect();
        assert_eq!(all, ["key/backup", "key/yubikey-1", "pin/default"]);
        assert_eq!(s.list(5, Some("key")).unwrap().len(), 2);
        assert!(s.delete(5, "key", "backup").unwrap());
        assert!(!s.delete(5, "key", "backup").unwrap());
        s.delete_user(5).unwrap();
        assert!(s.list(5, None).unwrap().is_empty());
    }

    #[test]
    fn rejects_path_traversal_names() {
        let t = TempDir::new();
        let s = Store::open(&t.0, &FileKey).unwrap();
        for bad in ["", "../x", "a/b", "A", ".hidden", &"x".repeat(65)] {
            assert!(s.put(1, bad, "id", b"x").is_err(), "method {bad:?}");
            assert!(s.put(1, "pin", bad, b"x").is_err(), "id {bad:?}");
        }
    }

    #[test]
    fn debug_output_redacts_key() {
        let k = MasterKey::from_bytes([7u8; 32]);
        assert_eq!(format!("{k:?}"), "MasterKey(<redacted>)");
    }
}
