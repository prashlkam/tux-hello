//! The `org.tuxhello.Auth1` D-Bus interface.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tuxhello_proto::{ctx, is_remote_host, MAX_WAIT_MS};
use zbus::message::Header;
use zbus::names::BusName;
use zbus::zvariant::OwnedValue;
use zbus::{interface, DBusError};

use crate::backend::{Backend, Request};
use crate::config::DaemonConfig;
use crate::session::{self, Session};

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
}

type WaitReply = (Vec<(String, String, String)>, String, String, u32);

pub struct AuthService {
    config: DaemonConfig,
    backends: Vec<Arc<dyn Backend>>,
    sessions: Arc<Mutex<HashMap<String, Arc<Session>>>>,
}

impl AuthService {
    pub fn new(config: DaemonConfig, backends: Vec<Arc<dyn Backend>>) -> Self {
        AuthService {
            config,
            backends,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn sessions(&self) -> MutexGuard<'_, HashMap<String, Arc<Session>>> {
        self.sessions.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Finds a session and checks that the caller owns it.
    fn owned_session(&self, hdr: &Header<'_>, id: &str) -> Result<Arc<Session>, Error> {
        let sender = sender_name(hdr)?;
        let sessions = self.sessions();
        match sessions.get(id) {
            // Same error for "missing" and "not yours": don't leak session ids.
            Some(s) if s.owner == sender => Ok(s.clone()),
            _ => Err(Error::NoSuchSession(id.to_string())),
        }
    }
}

fn sender_name(hdr: &Header<'_>) -> Result<String, Error> {
    hdr.sender()
        .map(|s| s.as_str().to_string())
        .ok_or_else(|| Error::AccessDenied("message has no sender".into()))
}

/// Returns the UID of the process that sent `hdr`, as reported by the bus.
async fn caller_uid(conn: &zbus::Connection, hdr: &Header<'_>) -> Result<u32, Error> {
    let sender = hdr
        .sender()
        .ok_or_else(|| Error::AccessDenied("message has no sender".into()))?;
    let dbus = zbus::fdo::DBusProxy::new(conn).await?;
    dbus.get_connection_unix_user(BusName::Unique(sender.to_owned()))
        .await
        .map_err(|e| Error::AccessDenied(format!("cannot identify caller: {e}")))
}

fn take_string(map: &mut HashMap<String, OwnedValue>, key: &str) -> Result<Option<String>, Error> {
    match map.remove(key) {
        None => Ok(None),
        Some(v) => String::try_from(v)
            .map(Some)
            .map_err(|_| Error::InvalidArgs(format!("context key {key:?} must be a string"))),
    }
}

/// A caller may authenticate itself; only root may authenticate others.
/// This mirrors unix_chkpwd: unprivileged screen lockers can verify their
/// own user, but cannot be used as an oracle for other accounts.
fn may_authenticate(caller_uid: u32, target_uid: u32) -> bool {
    caller_uid == 0 || caller_uid == target_uid
}

#[interface(name = "org.tuxhello.Auth1")]
impl AuthService {
    /// Daemon version.
    async fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// Lists backends as (name, available, assurance).
    async fn list_backends(&self) -> Vec<(String, bool, u32)> {
        self.backends
            .iter()
            .map(|b| (b.name().to_string(), b.available(), b.assurance()))
            .collect()
    }

    /// Starts an authentication session and returns its id.
    async fn begin_auth(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        context: HashMap<String, OwnedValue>,
    ) -> Result<String, Error> {
        let mut context = context;
        let user = take_string(&mut context, ctx::USER)?
            .filter(|u| !u.is_empty())
            .ok_or_else(|| Error::InvalidArgs("missing user".into()))?;
        let service = take_string(&mut context, ctx::SERVICE)?
            .ok_or_else(|| Error::InvalidArgs("missing service".into()))?;
        let rhost = take_string(&mut context, ctx::RHOST)?;
        let _tty = take_string(&mut context, ctx::TTY)?;

        let owner = sender_name(&hdr)?;
        let caller = caller_uid(conn, &hdr).await?;

        // Unknown users get the same answer as users without enrollment.
        let target = nix::unistd::User::from_name(&user)
            .ok()
            .flatten()
            .ok_or_else(|| Error::NotEnrolled(format!("no usable method for {user}")))?;
        let target_uid = target.uid.as_raw();

        if !may_authenticate(caller, target_uid) {
            log::warn!("uid {caller} tried to authenticate as {user:?} via {service:?}: denied");
            return Err(Error::AccessDenied(
                "may only authenticate as yourself".into(),
            ));
        }
        if is_remote_host(rhost.as_deref()) {
            return Err(Error::Unavailable("not offered to remote sessions".into()));
        }

        let backends: Vec<Arc<dyn Backend>> = self
            .backends
            .iter()
            .filter(|b| b.available() && b.is_enrolled(&user))
            .cloned()
            .collect();
        if backends.is_empty() {
            return Err(Error::NotEnrolled(format!("no usable method for {user}")));
        }

        let id = session::new_session_id()
            .map_err(|e| Error::Unavailable(format!("cannot create session id: {e}")))?;
        let session = Arc::new(Session::new(id.clone(), owner, caller, user.clone()));
        {
            let mut sessions = self.sessions();
            let per_uid = sessions.values().filter(|s| s.caller_uid == caller).count();
            if sessions.len() >= self.config.max_sessions
                || per_uid >= self.config.max_sessions_per_uid
            {
                return Err(Error::LimitExceeded("too many sessions".into()));
            }
            sessions.insert(id.clone(), session.clone());
        }
        log::info!("session {id}: begin for user {user:?} service {service:?} caller uid {caller}");

        let req = Request {
            user,
            uid: target_uid,
            service,
        };
        let task = tokio::spawn(session::run(session.clone(), backends, req));
        session.set_task(task.abort_handle());

        // Hard lifetime: cancel and forget the session no matter what the
        // client does (it may have crashed or disconnected).
        let sessions = self.sessions.clone();
        let lifetime = Duration::from_secs(self.config.session_lifetime_s);
        let gc_id = id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(lifetime).await;
            let removed = sessions
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&gc_id);
            if let Some(s) = removed {
                s.cancel();
            }
        });

        Ok(id)
    }

    /// Long-polls a session: returns pending events and the current state.
    /// Returns as soon as something happened, or after `timeout_ms`.
    async fn wait(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        session_id: String,
        timeout_ms: u32,
    ) -> Result<WaitReply, Error> {
        let session = self.owned_session(&hdr, &session_id)?;
        let timeout = Duration::from_millis(u64::from(timeout_ms.min(MAX_WAIT_MS)));
        let snap = session.wait(timeout).await;
        if snap.state.is_terminal() {
            // The result has been delivered; the session is done.
            self.sessions().remove(&session_id);
        }
        Ok((
            snap.events
                .into_iter()
                .map(|e| (e.method, e.state, e.message))
                .collect(),
            snap.state.as_str().to_string(),
            snap.method,
            snap.assurance,
        ))
    }

    /// Cancels a session.
    async fn cancel(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        session_id: String,
    ) -> Result<(), Error> {
        let session = self.owned_session(&hdr, &session_id)?;
        session.cancel();
        self.sessions().remove(&session_id);
        log::info!("session {session_id}: cancelled by client");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_authorisation() {
        assert!(may_authenticate(0, 1000));
        assert!(may_authenticate(1000, 1000));
        assert!(!may_authenticate(1000, 0));
        assert!(!may_authenticate(1000, 1001));
    }
}
