//! The `org.tuxhello.Manager1` D-Bus interface: enrolment and management.
//!
//! Authorisation (Phase 1):
//! * reading and deleting your own enrolments: any user;
//! * enrolling, or touching another user's data: root only. The CLI is run
//!   with `sudo`, which verifies the password. Self-enrolment through polkit
//!   (`org.tuxhello.enroll-self`, auth_self_keep) comes with the GUI.

use std::collections::HashMap;
use std::sync::Arc;

use zbus::interface;
use zbus::message::Header;
use zeroize::Zeroizing;

use crate::audit;
use crate::daemon::{caller_uid, may_act_on, Daemon, Error};
use crate::{fingerprint, pin};

pub struct ManagerService {
    d: Arc<Daemon>,
}

impl ManagerService {
    pub fn new(d: Arc<Daemon>) -> Self {
        ManagerService { d }
    }
}

fn user_name(uid: u32) -> Result<String, Error> {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .ok_or_else(|| Error::InvalidArgs(format!("no user with uid {uid}")))
}

async fn require_self_or_root(
    conn: &zbus::Connection,
    hdr: &Header<'_>,
    uid: u32,
) -> Result<u32, Error> {
    let caller = caller_uid(conn, hdr).await?;
    if may_act_on(caller, uid) {
        Ok(caller)
    } else {
        Err(Error::AccessDenied(
            "only root may manage another user's enrolments".into(),
        ))
    }
}

async fn require_root(conn: &zbus::Connection, hdr: &Header<'_>) -> Result<u32, Error> {
    let caller = caller_uid(conn, hdr).await?;
    if caller == 0 {
        Ok(caller)
    } else {
        Err(Error::AccessDenied(
            "this requires root for now; run the command with sudo".into(),
        ))
    }
}

fn audit_change(event: &str, user: &str, uid: u32, caller: u32, method: &str, id: &str) {
    audit::Record::new(event)
        .s("user", user)
        .n("uid", u64::from(uid))
        .n("caller_uid", u64::from(caller))
        .s("method", method)
        .s("id", id)
        .emit();
}

/// Records whose id starts with `_` are internal (e.g. the PIN lockout
/// counter) and not shown as enrolments.
fn is_internal(id: &str) -> bool {
    id.starts_with('_')
}

#[interface(name = "org.tuxhello.Manager1")]
impl ManagerService {
    /// Daemon information: version, store, policy directories.
    async fn get_info(&self) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("version".into(), env!("CARGO_PKG_VERSION").into());
        m.insert("store".into(), self.d.store.root().display().to_string());
        m.insert("store-key".into(), self.d.store.key_description().into());
        m.insert("pin-protection".into(), self.d.pin.protection().into());
        m.insert(
            "policy-dirs".into(),
            self.d
                .policy_dirs()
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(":"),
        );
        m
    }

    /// Lists a user's enrolments as (method, id).
    async fn list_enrollments(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        uid: u32,
    ) -> Result<Vec<(String, String)>, Error> {
        require_self_or_root(conn, &hdr, uid).await?;
        let list = self
            .d
            .store
            .list(uid, None)
            .map_err(|e| Error::Failed(e.to_string()))?;
        let mut out: Vec<(String, String)> = list
            .into_iter()
            .filter(|r| !is_internal(&r.id))
            .map(|r| (r.method, r.id))
            .collect();
        if let Some(fp) = &self.d.fingerprint {
            let name = user_name(uid)?;
            for finger in fp.enrolled_fingers(&name).await {
                out.push((fingerprint::METHOD.to_string(), finger));
            }
        }
        Ok(out)
    }

    /// Sets or replaces a user's PIN.
    async fn enroll_pin(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        uid: u32,
        pin: String,
    ) -> Result<(), Error> {
        let pin = Zeroizing::new(pin);
        let caller = require_root(conn, &hdr).await?;
        let name = user_name(uid)?;
        let backend = self.d.pin.clone();
        tokio::task::spawn_blocking(move || backend.enroll(uid, &pin))
            .await
            .map_err(|e| Error::Failed(e.to_string()))?
            .map_err(Error::InvalidArgs)?;
        log::info!("PIN enrolled for {name:?} (uid {uid}) by uid {caller}");
        audit_change("enroll", &name, uid, caller, pin::METHOD, "default");
        Ok(())
    }

    /// Registers a security key: blocks until the key is touched. `label`
    /// may be empty (an id like "key-1" is chosen); `key_pin` is the key's own
    /// PIN if it has one, else empty. Returns the enrolment id.
    async fn enroll_key(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        uid: u32,
        label: String,
        key_pin: String,
    ) -> Result<String, Error> {
        let key_pin = Zeroizing::new(key_pin);
        let caller = require_root(conn, &hdr).await?;
        let name = user_name(uid)?;
        let backend = self.d.key.clone().ok_or_else(|| {
            Error::Unavailable("security keys are not supported by this build".into())
        })?;
        let name2 = name.clone();
        let id = tokio::task::spawn_blocking(move || {
            let label = (!label.trim().is_empty()).then_some(label);
            let pin = (!key_pin.is_empty()).then(|| key_pin.as_str().to_string());
            backend.enroll(uid, &name2, label.as_deref(), pin.as_deref())
        })
        .await
        .map_err(|e| Error::Failed(e.to_string()))?
        .map_err(Error::Failed)?;
        log::info!("security key {id:?} enrolled for {name:?} (uid {uid}) by uid {caller}");
        audit_change("enroll", &name, uid, caller, crate::key::METHOD, &id);
        Ok(id)
    }

    /// Imports a user's security keys from the text of a pam_u2f key file.
    /// `origin` is the relying-party id pam_u2f used (`pam://<hostname>`
    /// unless configured otherwise). Returns the new enrolment ids and a
    /// note for each credential that was left out.
    async fn import_pam_u2f(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        uid: u32,
        text: String,
        origin: String,
    ) -> Result<(Vec<String>, Vec<String>), Error> {
        let caller = require_root(conn, &hdr).await?;
        let name = user_name(uid)?;
        if text.len() > 256 * 1024 {
            return Err(Error::InvalidArgs("key file too large".into()));
        }
        let backend = self.d.key.clone().ok_or_else(|| {
            Error::Unavailable("security keys are not supported by this build".into())
        })?;
        let (ids, notes) = backend
            .import_pam_u2f(uid, &name, &text, &origin)
            .map_err(Error::Failed)?;
        for id in &ids {
            log::info!("security key {id:?} imported from pam_u2f for {name:?} (uid {uid}) by uid {caller}");
            audit_change("enroll", &name, uid, caller, crate::key::METHOD, id);
        }
        Ok((ids, notes))
    }

    /// Deletes one enrolment. Returns whether it existed.
    async fn delete_enrollment(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        uid: u32,
        method: String,
        id: String,
    ) -> Result<bool, Error> {
        let caller = require_self_or_root(conn, &hdr, uid).await?;
        if is_internal(&id) {
            return Err(Error::InvalidArgs(format!("invalid id {id:?}")));
        }
        let existed = if method == pin::METHOD {
            self.d.pin.delete(uid).map_err(Error::Failed)?
        } else if method == fingerprint::METHOD {
            let fp = self
                .d
                .fingerprint
                .as_ref()
                .ok_or_else(|| Error::Unavailable("fingerprint support is disabled".into()))?;
            fp.delete(&user_name(uid)?, Some(&id))
                .await
                .map_err(Error::Failed)?
        } else {
            self.d
                .store
                .delete(uid, &method, &id)
                .map_err(|e| Error::InvalidArgs(e.to_string()))?
        };
        if existed {
            log::info!("deleted {method}/{id} of uid {uid} (by uid {caller})");
            audit_change(
                "delete",
                &user_name(uid).unwrap_or_default(),
                uid,
                caller,
                &method,
                &id,
            );
        }
        Ok(existed)
    }

    /// Deletes everything stored for a user.
    async fn delete_all(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        uid: u32,
    ) -> Result<(), Error> {
        let caller = require_self_or_root(conn, &hdr, uid).await?;
        self.d
            .store
            .delete_user(uid)
            .map_err(|e| Error::Failed(e.to_string()))?;
        if let Some(fp) = &self.d.fingerprint {
            if let Err(e) = fp.delete(&user_name(uid)?, None).await {
                log::warn!("uid {uid}: deleting fingerprints failed: {e}");
            }
        }
        log::info!("deleted all enrolments of uid {uid} (by uid {caller})");
        audit_change(
            "delete",
            &user_name(uid).unwrap_or_default(),
            uid,
            caller,
            "*",
            "*",
        );
        Ok(())
    }

    /// Lockout state of a user: `biometric-failures`, `biometrics-locked`
    /// (0/1), `throttled-s` and `pin-locked-s` (seconds left, 0 = not locked).
    async fn get_lockout(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        uid: u32,
    ) -> Result<HashMap<String, u64>, Error> {
        require_self_or_root(conn, &hdr, uid).await?;
        let g = &self.d.guard;
        let mut m = HashMap::new();
        m.insert(
            "biometric-failures".into(),
            u64::from(g.biometric_failures(uid)),
        );
        m.insert(
            "biometrics-locked".into(),
            u64::from(g.biometrics_locked(uid)),
        );
        m.insert("throttled-s".into(), g.throttled(uid).unwrap_or(0));
        m.insert("pin-locked-s".into(), self.d.pin.locked_for(uid));
        Ok(m)
    }

    /// Clears a user's rate limit, biometric lockout and PIN lockout. Root
    /// only: `sudo` has then verified a password, which is what "until the
    /// password succeeds" means for a daemon that never sees passwords.
    async fn reset_lockout(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        uid: u32,
    ) -> Result<(), Error> {
        let caller = require_root(conn, &hdr).await?;
        let name = user_name(uid)?;
        self.d.guard.reset(uid);
        self.d.pin.reset_lockout(uid).map_err(Error::Failed)?;
        log::info!("lockouts of {name:?} (uid {uid}) reset by uid {caller}");
        audit::Record::new("lockout.reset")
            .s("user", &name)
            .n("uid", u64::from(uid))
            .n("caller_uid", u64::from(caller))
            .emit();
        Ok(())
    }

    /// Describes the policy that applies to `uid` for a PAM service.
    async fn explain_policy(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        uid: u32,
        service: String,
    ) -> Result<HashMap<String, String>, Error> {
        require_self_or_root(conn, &hdr, uid).await?;
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .ok()
            .flatten()
            .ok_or_else(|| Error::InvalidArgs(format!("no user with uid {uid}")))?;
        let e = self.d.effective(&service, &user.name, user.gid.as_raw());
        let mut m = HashMap::new();
        m.insert("class".into(), e.class.clone());
        m.insert("require".into(), e.require.to_string());
        m.insert("min-assurance".into(), e.min_assurance.to_string());
        m.insert("timeout-s".into(), e.timeout.as_secs().to_string());
        let mut usable: Vec<String> = Vec::new();
        for b in self
            .d
            .backends
            .iter()
            .filter(|b| e.require.methods().contains(b.name()))
        {
            if b.clone().usable(user.name.clone(), uid).await {
                usable.push(format!("{}:{}", b.name(), b.assurance_for(&user.name, uid)));
            }
        }
        m.insert("usable".into(), usable.join(","));
        Ok(m)
    }
}
