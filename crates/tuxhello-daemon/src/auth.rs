//! The `org.tuxhello.Auth1` D-Bus interface (used by the PAM module).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tuxhello_proto::{ctx, is_remote_host, MAX_WAIT_MS};
use zbus::interface;
use zbus::message::Header;
use zbus::zvariant::OwnedValue;
use zeroize::Zeroizing;

use crate::audit;
use crate::backend::{Backend, Request};
use crate::daemon::{caller_uid, may_act_on, sender_name, Daemon, Error};
use crate::session::{self, Session};

type WaitReply = (Vec<(String, String, String)>, String, String, u32);

pub struct AuthService {
    d: Arc<Daemon>,
}

impl AuthService {
    pub fn new(d: Arc<Daemon>) -> Self {
        AuthService { d }
    }

    /// Finds a session and checks that the caller owns it.
    fn owned_session(&self, hdr: &Header<'_>, id: &str) -> Result<Arc<Session>, Error> {
        let sender = sender_name(hdr)?;
        match self.d.sessions().get(id) {
            // Same error for "missing" and "not yours": don't leak session ids.
            Some(s) if s.owner == sender => Ok(s.clone()),
            _ => Err(Error::NoSuchSession(id.to_string())),
        }
    }
}

fn take_string(map: &mut HashMap<String, OwnedValue>, key: &str) -> Result<Option<String>, Error> {
    match map.remove(key) {
        None => Ok(None),
        Some(v) => String::try_from(v)
            .map(Some)
            .map_err(|_| Error::InvalidArgs(format!("context key {key:?} must be a string"))),
    }
}

#[interface(name = "org.tuxhello.Auth1")]
impl AuthService {
    /// Daemon version.
    async fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// Lists backends as (name, available, assurance).
    async fn list_backends(&self) -> Vec<(String, bool, u32)> {
        self.d
            .backends
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

        if !may_act_on(caller, target_uid) {
            log::warn!("uid {caller} tried to authenticate as {user:?} via {service:?}: denied");
            return Err(Error::AccessDenied(
                "may only authenticate as yourself".into(),
            ));
        }
        if is_remote_host(rhost.as_deref()) {
            return Err(Error::Unavailable("not offered to remote sessions".into()));
        }
        let refused = |reason: &str| {
            audit::Record::new("auth.refused")
                .s("user", &user)
                .n("uid", u64::from(target_uid))
                .s("service", &service)
                .n("caller_uid", u64::from(caller))
                .s("reason", reason)
                .emit();
        };
        if let Some(secs) = self.d.guard.throttled(target_uid) {
            log::warn!(
                "user {user:?} service {service:?}: too many failed attempts,                  not offered for another {secs} s"
            );
            refused("rate-limited");
            return Err(Error::Unavailable(format!(
                "too many failed attempts; try again in {secs} s"
            )));
        }

        let effective = self.d.effective(&service, &user, target.gid.as_raw());
        let wanted = effective.require.methods();
        let biometrics_locked = self.d.guard.biometrics_locked(target_uid);
        let mut backends: Vec<Arc<dyn Backend>> = Vec::new();
        for b in self.d.backends.iter().filter(|b| wanted.contains(b.name())) {
            if b.biometric() && biometrics_locked {
                log::info!(
                    "user {user:?}: {} not offered (biometrics are locked out)",
                    b.name()
                );
                continue;
            }
            if b.clone().usable(user.clone(), target_uid).await {
                backends.push(b.clone());
            }
        }
        let nominal: HashMap<&str, u32> = backends
            .iter()
            .map(|b| (b.name(), b.assurance_for(&user, target_uid)))
            .collect();
        if effective.satisfied(&|m| nominal.get(m).copied()).is_none() {
            log::info!(
                "user {user:?} service {service:?}: enrolled methods {:?} cannot satisfy {} \
                 (class {}, min assurance {})",
                nominal.keys().collect::<Vec<_>>(),
                effective.require,
                effective.class,
                effective.min_assurance
            );
            if biometrics_locked {
                refused("biometrics-locked");
            }
            return Err(Error::NotEnrolled(format!("no usable method for {user}")));
        }

        let id = session::new_session_id()
            .map_err(|e| Error::Unavailable(format!("cannot create session id: {e}")))?;
        let session = Arc::new(Session::new(id.clone(), owner, caller));
        {
            let mut sessions = self.d.sessions();
            let per_uid = sessions.values().filter(|s| s.caller_uid == caller).count();
            if sessions.len() >= self.d.cfg.max_sessions
                || per_uid >= self.d.cfg.max_sessions_per_uid
            {
                return Err(Error::LimitExceeded("too many sessions".into()));
            }
            sessions.insert(id.clone(), session.clone());
        }
        log::info!(
            "session {id}: begin for user {user:?} service {service:?} class {} \
             (requires {}), caller uid {caller}",
            effective.class,
            effective.require
        );
        audit::Record::new("auth.begin")
            .s("session", &id)
            .s("user", &user)
            .n("uid", u64::from(target_uid))
            .s("service", &service)
            .s("class", &effective.class)
            .n("caller_uid", u64::from(caller))
            .emit();

        let req = Request {
            user,
            uid: target_uid,
            service,
        };
        let task = tokio::spawn(session::run(
            session.clone(),
            effective,
            backends,
            req,
            self.d.guard.clone(),
        ));
        session.set_task(task.abort_handle());

        // Hard lifetime: cancel and forget the session no matter what the
        // client does (it may have crashed or disconnected).
        let d = self.d.clone();
        let lifetime = Duration::from_secs(self.d.cfg.session_lifetime_s);
        let gc_id = id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(lifetime).await;
            let removed = d.sessions().remove(&gc_id);
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
            self.d.sessions().remove(&session_id);
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

    /// Answers a `prompt` event. An empty secret skips the method.
    async fn submit_secret(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        session_id: String,
        method: String,
        secret: String,
    ) -> Result<(), Error> {
        let secret = Zeroizing::new(secret);
        let session = self.owned_session(&hdr, &session_id)?;
        if session.provide_secret(&method, secret) {
            Ok(())
        } else {
            Err(Error::InvalidArgs(format!(
                "no prompt pending for {method:?}"
            )))
        }
    }

    /// Cancels a session.
    async fn cancel(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        session_id: String,
    ) -> Result<(), Error> {
        let session = self.owned_session(&hdr, &session_id)?;
        session.cancel();
        self.d.sessions().remove(&session_id);
        log::info!("session {session_id}: cancelled by client");
        Ok(())
    }
}
