//! Software FIDO2 authenticator for tests. Compiled only for unit tests and
//! with the test-only `stub-backend` feature.
//!
//! It signs with real P-256 / Ed25519 keys, so everything the daemon checks
//! (RP ID hash, flags, signature, counter) is exercised for real. Only the
//! USB/CTAP transport is skipped.
//!
//! Directory-backed mode (for integration tests, `[stub] soft_key_dir`):
//!
//! ```text
//! <dir>/present          the key is "plugged in" while this file exists
//! <dir>/pin              the key's PIN, if it has one
//! <dir>/no-touch         simulate a user who never touches the key
//! <dir>/creds/<hex-id>   "<alg> <secret-key-hex> <rp-id> <counter>"
//! ```
//!
//! Like a real key, a credential only answers for the relying-party id it
//! was made for.
//!
//! ```text
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::{
    from_hex, to_hex, Assertion, Authenticator, CancelToken, DeviceInfo, GetAssertion, KeyError,
    MakeCredential, NewCredential, COSE_EDDSA, COSE_ES256, FLAG_UP, FLAG_UV,
};

#[derive(Clone)]
struct Cred {
    alg: i32,
    sk: [u8; 32],
    rp_id: String,
    counter: u32,
}

#[derive(Default)]
struct State {
    creds: HashMap<Vec<u8>, Cred>,
    pin: Option<String>,
    present: bool,
    no_touch: bool,
}

pub struct SoftAuthenticator {
    dir: Option<PathBuf>,
    mem: Mutex<State>,
    alg: Mutex<i32>,
    counterless: Mutex<bool>,
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    tuxhello_store::random_bytes(&mut b).expect("OS RNG");
    b
}

impl SoftAuthenticator {
    /// A present key with no PIN, kept in memory.
    #[cfg(test)]
    pub fn in_memory() -> Self {
        SoftAuthenticator {
            dir: None,
            mem: Mutex::new(State {
                present: true,
                ..State::default()
            }),
            alg: Mutex::new(COSE_ES256),
            counterless: Mutex::new(false),
        }
    }

    /// A key whose state lives in `dir` (see the module docs).
    #[cfg_attr(not(feature = "stub-backend"), allow(dead_code))]
    pub fn in_dir(dir: &Path) -> Self {
        SoftAuthenticator {
            dir: Some(dir.to_path_buf()),
            mem: Mutex::new(State::default()),
            alg: Mutex::new(COSE_ES256),
            counterless: Mutex::new(false),
        }
    }

    /// Algorithm used for new credentials.
    #[cfg(test)]
    pub fn set_alg(&self, alg: i32) {
        *self.alg.lock().unwrap() = alg;
    }

    /// Simulate a key without a signature counter (always reports 0).
    #[cfg(test)]
    pub fn set_counterless(&self, v: bool) {
        *self.counterless.lock().unwrap() = v;
    }

    fn load(&self) -> State {
        let Some(dir) = &self.dir else {
            let g = self.mem.lock().unwrap();
            return State {
                creds: g.creds.clone(),
                pin: g.pin.clone(),
                present: g.present,
                no_touch: g.no_touch,
            };
        };
        let mut s = State {
            present: dir.join("present").exists(),
            no_touch: dir.join("no-touch").exists(),
            pin: std::fs::read_to_string(dir.join("pin"))
                .ok()
                .map(|p| p.trim().to_string()),
            creds: HashMap::new(),
        };
        if let Ok(rd) = std::fs::read_dir(dir.join("creds")) {
            for e in rd.flatten() {
                let Some(id) = from_hex(&e.file_name().to_string_lossy()) else {
                    continue;
                };
                let Ok(text) = std::fs::read_to_string(e.path()) else {
                    continue;
                };
                let mut it = text.split_whitespace();
                let (Some(alg), Some(sk), Some(rp_id), Some(counter)) =
                    (it.next(), it.next(), it.next(), it.next())
                else {
                    continue;
                };
                let (Ok(alg), Some(sk), Ok(counter)) = (alg.parse(), from_hex(sk), counter.parse())
                else {
                    continue;
                };
                let Ok(sk) = <[u8; 32]>::try_from(sk) else {
                    continue;
                };
                s.creds.insert(
                    id,
                    Cred {
                        alg,
                        sk,
                        rp_id: rp_id.to_string(),
                        counter,
                    },
                );
            }
        }
        s
    }

    fn save_cred(&self, id: &[u8], c: &Cred) {
        match &self.dir {
            None => {
                self.mem
                    .lock()
                    .unwrap()
                    .creds
                    .insert(id.to_vec(), c.clone());
            }
            Some(dir) => {
                let d = dir.join("creds");
                let _ = std::fs::create_dir_all(&d);
                let _ = std::fs::write(
                    d.join(to_hex(id)),
                    format!("{} {} {} {}\n", c.alg, to_hex(&c.sk), c.rp_id, c.counter),
                );
            }
        }
    }

    fn check_pin(state: &State, pin: Option<&str>, uv: bool) -> Result<bool, KeyError> {
        match (&state.pin, pin) {
            (Some(p), Some(given)) if p == given => Ok(true),
            (Some(_), Some(_)) => Err(KeyError::PinInvalid),
            (Some(_), None) if uv => Err(KeyError::PinRequired),
            (None, Some(_)) => Err(KeyError::Other("key has no PIN set".into())),
            _ => Ok(false),
        }
    }
}

impl Authenticator for SoftAuthenticator {
    fn devices(&self) -> Vec<DeviceInfo> {
        if self.load().present {
            vec![DeviceInfo {
                path: match &self.dir {
                    Some(d) => format!("soft:{}", d.display()),
                    None => "soft:memory".into(),
                },
                product: "Tux Hello software key".into(),
            }]
        } else {
            Vec::new()
        }
    }

    fn make_credential(
        &self,
        _dev: &DeviceInfo,
        req: &MakeCredential<'_>,
        pin: Option<&str>,
        _cancel: &CancelToken,
    ) -> Result<NewCredential, KeyError> {
        let state = self.load();
        if !state.present {
            return Err(KeyError::Other("device unplugged".into()));
        }
        Self::check_pin(&state, pin, req.uv)?;
        let alg = *self.alg.lock().unwrap();
        let mut id = vec![0u8; 16];
        tuxhello_store::random_bytes(&mut id).expect("OS RNG");
        let (sk, public_key) = loop {
            let sk = random32();
            let pk = match alg {
                COSE_ES256 => match p256::ecdsa::SigningKey::from_slice(&sk) {
                    Ok(k) => k.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec(),
                    Err(_) => continue,
                },
                COSE_EDDSA => ed25519_dalek::SigningKey::from_bytes(&sk)
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
                other => return Err(KeyError::Other(format!("unsupported alg {other}"))),
            };
            break (sk, pk);
        };
        self.save_cred(
            &id,
            &Cred {
                alg,
                sk,
                rp_id: req.rp_id.to_string(),
                counter: 0,
            },
        );
        Ok(NewCredential {
            id,
            alg,
            public_key,
        })
    }

    fn get_assertion(
        &self,
        _dev: &DeviceInfo,
        req: &GetAssertion<'_>,
        pin: Option<&str>,
        cancel: &CancelToken,
    ) -> Result<Assertion, KeyError> {
        let state = self.load();
        if !state.present {
            return Err(KeyError::Other("device unplugged".into()));
        }
        let verified = Self::check_pin(&state, pin, req.uv)?;
        let Some((id, cred)) = req
            .allow
            .iter()
            .find_map(|id| state.creds.get(id).map(|c| (id.clone(), c.clone())))
            .filter(|(_, c)| c.rp_id == req.rp_id)
        else {
            return Err(KeyError::NoCredentials);
        };
        if state.no_touch {
            // Wait for a touch that never comes, like a real key, until
            // cancelled or timed out.
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(30) {
                if cancel.is_cancelled() {
                    if let Some(dir) = &self.dir {
                        let _ = std::fs::write(dir.join("was-cancelled"), "");
                    }
                    return Err(KeyError::Cancelled);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            return Err(KeyError::Timeout);
        }

        let mut cred = cred;
        if !*self.counterless.lock().unwrap() {
            cred.counter += 1;
            self.save_cred(&id, &cred);
        }
        let flags = FLAG_UP | if verified { FLAG_UV } else { 0 };
        let mut auth_data = Sha256::digest(req.rp_id.as_bytes()).to_vec();
        auth_data.push(flags);
        let count = if *self.counterless.lock().unwrap() {
            0
        } else {
            cred.counter
        };
        auth_data.extend_from_slice(&count.to_be_bytes());
        let msg = [&auth_data[..], &req.client_data_hash[..]].concat();
        let signature = match cred.alg {
            COSE_ES256 => {
                use p256::ecdsa::signature::Signer;
                let sk = p256::ecdsa::SigningKey::from_slice(&cred.sk)
                    .map_err(|e| KeyError::Other(e.to_string()))?;
                let sig: p256::ecdsa::Signature = sk.sign(&msg);
                sig.to_der().as_bytes().to_vec()
            }
            COSE_EDDSA => {
                use ed25519_dalek::Signer;
                ed25519_dalek::SigningKey::from_bytes(&cred.sk)
                    .sign(&msg)
                    .to_bytes()
                    .to_vec()
            }
            other => return Err(KeyError::Other(format!("unsupported alg {other}"))),
        };
        Ok(Assertion {
            credential_id: id,
            auth_data,
            signature,
        })
    }
}
