//! Decides, at startup, what the TPM is used for: sealing the store's master
//! key and backing PINs (see `tuxhello_store::tpm` and `pin.rs`).

use std::sync::Arc;

use tuxhello_store::{FileKey, KeyProvider};

use crate::config::{Config, TpmMode};
use crate::pin::PinSealer;

pub struct Hardware {
    pub keys: Box<dyn KeyProvider>,
    pub pin_sealer: Option<Arc<dyn PinSealer>>,
}

/// What to do about the master key, given the configuration, what the store
/// already holds, and whether a TPM answered.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyChoice {
    File,
    /// Existing file key, TPM available, mode `auto`: left alone.
    FileKeepExisting,
    Tpm,
    Refuse(&'static str),
}

pub fn choose_key(mode: TpmMode, sealed: bool, file: bool, have_tpm: bool) -> KeyChoice {
    match (mode, sealed, have_tpm) {
        (TpmMode::Off, true, _) => KeyChoice::Refuse(
            "the store's master key is sealed by the TPM, but [store] tpm = \"off\"",
        ),
        (TpmMode::Off, false, _) => KeyChoice::File,
        // Never start over with a fresh key: that would silently drop every
        // enrolment. Passwords keep working while the daemon is down.
        (_, true, false) => {
            KeyChoice::Refuse("the store's master key is sealed by a TPM that is not available")
        }
        (_, true, true) => KeyChoice::Tpm,
        (TpmMode::Require, false, false) => {
            KeyChoice::Refuse("[store] tpm = \"require\", but there is no usable TPM")
        }
        (TpmMode::Require, false, true) => KeyChoice::Tpm,
        (TpmMode::Auto, false, true) if file => KeyChoice::FileKeepExisting,
        (TpmMode::Auto, false, true) => KeyChoice::Tpm,
        (TpmMode::Auto, false, false) => KeyChoice::File,
    }
}

#[cfg(feature = "tpm")]
mod imp {
    use super::*;
    use crate::pin::SealError;
    use tuxhello_store::tpm::{file_key_exists, sealed_key_exists, Sealed, Tpm, TpmError, TpmKey};

    struct TpmSealer(Arc<Tpm>);

    fn map(e: TpmError) -> SealError {
        match e {
            TpmError::AuthFailed => SealError::WrongAuth,
            TpmError::LockedOut => SealError::LockedOut,
            other => SealError::Unavailable(other.to_string()),
        }
    }

    impl PinSealer for TpmSealer {
        fn seal(&self, auth: &[u8]) -> Result<Vec<u8>, SealError> {
            // Nothing is ever read from the object: being able to open it
            // is the proof that the PIN was right.
            let mut filler = [0u8; 32];
            tuxhello_store::random_bytes(&mut filler)
                .map_err(|e| SealError::Unavailable(e.to_string()))?;
            self.0
                .seal(&filler, auth, true)
                .map(|s| s.encode())
                .map_err(map)
        }

        fn check(&self, blob: &[u8], auth: &[u8]) -> Result<(), SealError> {
            let sealed = Sealed::decode(blob)
                .ok_or_else(|| SealError::Unavailable("unreadable TPM PIN object".into()))?;
            self.0.unseal(&sealed, auth).map(|_| ()).map_err(map)
        }
    }

    pub fn setup(cfg: &Config) -> Result<Hardware, String> {
        let wanted = cfg.store.tpm != TpmMode::Off || cfg.pin.tpm != TpmMode::Off;
        let tpm = if wanted {
            match Tpm::open(&cfg.tpm.tcti) {
                Ok(t) => {
                    log::info!("TPM 2.0 available ({})", cfg.tpm.tcti);
                    Some(Arc::new(t))
                }
                Err(e) => {
                    log::info!("no usable TPM: {e}");
                    None
                }
            }
        } else {
            None
        };
        let root = &cfg.store.path;
        let keys: Box<dyn KeyProvider> = match choose_key(
            cfg.store.tpm,
            sealed_key_exists(root),
            file_key_exists(root),
            tpm.is_some(),
        ) {
            KeyChoice::File => Box::new(FileKey),
            KeyChoice::FileKeepExisting => {
                log::info!(
                    "the store's master key is a plain file; set [store] tpm = \"require\" to \
                     move it into the TPM"
                );
                Box::new(FileKey)
            }
            KeyChoice::Tpm => Box::new(TpmKey::new(tpm.clone().expect("checked by choose_key"))),
            KeyChoice::Refuse(why) => return Err(why.to_string()),
        };
        let pin_sealer = match cfg.pin.tpm {
            TpmMode::Off => None,
            _ => tpm.map(|t| Arc::new(TpmSealer(t)) as Arc<dyn PinSealer>),
        };
        Ok(Hardware { keys, pin_sealer })
    }
}

#[cfg(not(feature = "tpm"))]
mod imp {
    use super::*;

    pub fn setup(cfg: &Config) -> Result<Hardware, String> {
        let root = &cfg.store.path;
        let keys: Box<dyn KeyProvider> = match choose_key(
            cfg.store.tpm,
            root.join("master.key.tpm").exists(),
            root.join("master.key").exists(),
            false,
        ) {
            KeyChoice::Refuse(why) => return Err(format!("{why} (this build has no TPM support)")),
            _ => Box::new(FileKey),
        };
        Ok(Hardware {
            keys,
            pin_sealer: None,
        })
    }
}

pub use imp::setup;

#[cfg(test)]
mod tests {
    use super::*;
    use TpmMode::{Auto, Off, Require};

    #[test]
    fn master_key_choice() {
        // New store.
        assert_eq!(choose_key(Auto, false, false, true), KeyChoice::Tpm);
        assert_eq!(choose_key(Auto, false, false, false), KeyChoice::File);
        assert_eq!(choose_key(Off, false, false, true), KeyChoice::File);
        assert_eq!(choose_key(Require, false, false, true), KeyChoice::Tpm);
        assert!(matches!(
            choose_key(Require, false, false, false),
            KeyChoice::Refuse(_)
        ));
        // Existing file key: only `require` moves it.
        assert_eq!(
            choose_key(Auto, false, true, true),
            KeyChoice::FileKeepExisting
        );
        assert_eq!(choose_key(Auto, false, true, false), KeyChoice::File);
        assert_eq!(choose_key(Require, false, true, true), KeyChoice::Tpm);
        // Existing sealed key: use it, or stop. Never fall back to a new key.
        for mode in [Auto, Require] {
            assert_eq!(choose_key(mode, true, false, true), KeyChoice::Tpm);
            assert!(matches!(
                choose_key(mode, true, false, false),
                KeyChoice::Refuse(_)
            ));
        }
        for have_tpm in [true, false] {
            assert!(matches!(
                choose_key(Off, true, false, have_tpm),
                KeyChoice::Refuse(_)
            ));
        }
    }
}
