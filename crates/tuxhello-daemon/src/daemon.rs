//! State shared by the D-Bus interfaces, and helpers for identifying callers.

use std::collections::HashMap;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use tuxhello_policy::{Effective, Policy, PolicyError, Requirement};
use tuxhello_store::Store;
use zbus::message::Header;
use zbus::names::BusName;
use zbus::DBusError;

use crate::backend::Backend;
use crate::config::DaemonConfig;
use crate::fingerprint::FingerprintBackend;
use crate::key::KeyBackend;
use crate::pin::PinBackend;
use crate::session::Session;

/// Errors returned over D-Bus as `org.tuxhello.Error.<Variant>`.
/// Keep the names in sync with `tuxhello_proto::error`.
#[derive(Debug, DBusError)]
#[zbus(prefix = "org.tuxhello.Error")]
pub enum Error {
    #[zbus(error)]
    ZBus(zbus::Error),
    AccessDenied(String),
    InvalidArgs(String),
    NoSuchSession(String),
    NotEnrolled(String),
    Unavailable(String),
    LimitExceeded(String),
    Failed(String),
}

pub struct Daemon {
    pub cfg: DaemonConfig,
    policy_dirs: Vec<PathBuf>,
    policy: RwLock<Arc<Policy>>,
    pub backends: Vec<Arc<dyn Backend>>,
    pub pin: Arc<PinBackend>,
    pub key: Option<Arc<KeyBackend>>,
    pub fingerprint: Option<Arc<FingerprintBackend>>,
    pub store: Arc<Store>,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
}

impl Daemon {
    pub fn new(
        cfg: DaemonConfig,
        policy_dirs: Vec<PathBuf>,
        backends: Vec<Arc<dyn Backend>>,
        pin: Arc<PinBackend>,
        key: Option<Arc<KeyBackend>>,
        fingerprint: Option<Arc<FingerprintBackend>>,
        store: Arc<Store>,
    ) -> Result<Self, PolicyError> {
        let policy = Arc::new(load_policy(&policy_dirs)?);
        Ok(Daemon {
            cfg,
            policy_dirs,
            policy: RwLock::new(policy),
            backends,
            pin,
            key,
            fingerprint,
            store,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    pub fn policy(&self) -> Arc<Policy> {
        self.policy
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn policy_dirs(&self) -> &[PathBuf] {
        &self.policy_dirs
    }

    /// Re-reads the policy files. On error the old policy stays in force.
    pub fn reload_policy(&self) -> Result<(), PolicyError> {
        let p = Arc::new(load_policy(&self.policy_dirs)?);
        *self.policy.write().unwrap_or_else(|p| p.into_inner()) = p;
        Ok(())
    }

    pub fn sessions(&self) -> MutexGuard<'_, HashMap<String, Arc<Session>>> {
        self.sessions.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The policy for one request. With the test-only stub backend loaded,
    /// "stub" is accepted as an alternative to whatever the policy requires.
    pub fn effective(&self, service: &str, user: &str, gid: u32) -> Effective {
        let mut e = self
            .policy()
            .resolve(service, user, &user_groups(user, gid));
        if self.backends.iter().any(|b| b.name() == "stub") {
            e.require = Requirement::Any {
                any: vec![Requirement::Method("stub".into()), e.require],
            };
        }
        e
    }
}

fn load_policy(dirs: &[PathBuf]) -> Result<Policy, PolicyError> {
    let refs: Vec<&Path> = dirs.iter().map(|p| p.as_path()).collect();
    Policy::load(&refs)
}

/// Names of all groups `user` belongs to (primary group included).
pub fn user_groups(user: &str, gid: u32) -> Vec<String> {
    let Ok(cuser) = CString::new(user) else {
        return Vec::new();
    };
    match nix::unistd::getgrouplist(&cuser, nix::unistd::Gid::from_raw(gid)) {
        Ok(gids) => gids
            .into_iter()
            .filter_map(|g| nix::unistd::Group::from_gid(g).ok().flatten())
            .map(|g| g.name)
            .collect(),
        Err(e) => {
            log::warn!("cannot list groups of {user:?}: {e}");
            Vec::new()
        }
    }
}

pub fn sender_name(hdr: &Header<'_>) -> Result<String, Error> {
    hdr.sender()
        .map(|s| s.as_str().to_string())
        .ok_or_else(|| Error::AccessDenied("message has no sender".into()))
}

/// Returns the UID of the process that sent `hdr`, as reported by the bus.
pub async fn caller_uid(conn: &zbus::Connection, hdr: &Header<'_>) -> Result<u32, Error> {
    let sender = hdr
        .sender()
        .ok_or_else(|| Error::AccessDenied("message has no sender".into()))?;
    let dbus = zbus::fdo::DBusProxy::new(conn).await?;
    dbus.get_connection_unix_user(BusName::Unique(sender.to_owned()))
        .await
        .map_err(|e| Error::AccessDenied(format!("cannot identify caller: {e}")))
}

/// A caller may act on itself; only root may act on others. For
/// authentication this mirrors unix_chkpwd: unprivileged screen lockers can
/// verify their own user, but cannot be used as an oracle for other accounts.
pub fn may_act_on(caller_uid: u32, target_uid: u32) -> bool {
    caller_uid == 0 || caller_uid == target_uid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_authorisation() {
        assert!(may_act_on(0, 1000));
        assert!(may_act_on(1000, 1000));
        assert!(!may_act_on(1000, 0));
        assert!(!may_act_on(1000, 1001));
    }

    #[test]
    fn root_groups_include_root() {
        assert!(user_groups("root", 0).iter().any(|g| g == "root"));
        assert!(user_groups("no-such-user-xyz", 12345).len() <= 1);
    }
}
