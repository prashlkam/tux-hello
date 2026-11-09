//! Blocking client for `org.tuxhello.Auth1`.
//!
//! Built on libdbus (`dbus` crate) rather than zbus because this code runs
//! inside PAM host processes (sudo, greeters, screen lockers): it must not
//! spawn threads or start an async runtime. Every call has an explicit timeout.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use dbus::arg::{PropMap, RefArg, Variant};
use dbus::blocking::Connection;

pub use tuxhello_proto::SessionState;
pub use zeroize::Zeroizing;

use tuxhello_proto::{
    ctx, error, AUTH_INTERFACE, BUS_NAME, MANAGER_INTERFACE, MANAGER_PATH, MAX_WAIT_MS, OBJECT_PATH,
};

/// Timeout for short calls (`BeginAuth`, `Cancel`, ...).
const CALL_TIMEOUT: Duration = Duration::from_secs(3);
/// Slack added on top of the server-side wait time for `Wait` calls.
const WAIT_SLACK: Duration = Duration::from_secs(2);

/// Error returned by client calls.
#[derive(Debug)]
pub enum ClientError {
    /// Could not reach the system bus or the daemon is not running.
    Unreachable(String),
    /// The daemon returned one of the `org.tuxhello.Error.*` errors.
    Daemon { name: String, message: String },
    /// Any other D-Bus failure (timeouts, malformed replies, ...).
    Bus(String),
}

impl ClientError {
    /// True if the daemon said that no usable method exists for this user.
    pub fn is_unavailable(&self) -> bool {
        match self {
            ClientError::Unreachable(_) => true,
            ClientError::Daemon { name, .. } => {
                name == error::NOT_ENROLLED || name == error::UNAVAILABLE
            }
            ClientError::Bus(_) => false,
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Unreachable(m) => write!(f, "daemon unreachable: {m}"),
            ClientError::Daemon { name, message } => write!(f, "{name}: {message}"),
            ClientError::Bus(m) => write!(f, "D-Bus error: {m}"),
        }
    }
}

impl std::error::Error for ClientError {}

fn map_err(e: dbus::Error) -> ClientError {
    let name = e.name().unwrap_or("").to_string();
    let message = e.message().unwrap_or("").to_string();
    if name.starts_with(tuxhello_proto::ERROR_PREFIX) {
        ClientError::Daemon { name, message }
    } else if name == "org.freedesktop.DBus.Error.ServiceUnknown"
        || name == "org.freedesktop.DBus.Error.NameHasNoOwner"
        || name == "org.freedesktop.DBus.Error.FileNotFound"
        || name == "org.freedesktop.DBus.Error.NoServer"
        || name == "org.freedesktop.DBus.Error.Spawn.ChildExited"
        || name == "org.freedesktop.DBus.Error.Spawn.ExecFailed"
    {
        ClientError::Unreachable(format!("{name}: {message}"))
    } else {
        ClientError::Bus(format!("{name}: {message}"))
    }
}

/// A progress event emitted by a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Method that emitted the event (`face`, `fingerprint`, `stub`, ...).
    pub method: String,
    /// Machine-readable state (`scanning`, `retry`, `matched`, ...).
    pub state: String,
    /// Human-readable, already localised message suitable for PAM_TEXT_INFO.
    pub message: String,
}

impl Event {
    /// True if the daemon wants the user to type a secret (PIN).
    pub fn is_prompt(&self) -> bool {
        self.state == tuxhello_proto::event::PROMPT
    }
}

/// Result of a single `Wait` call.
#[derive(Debug, Clone)]
pub struct WaitResult {
    pub events: Vec<Event>,
    pub state: SessionState,
    /// Method that decided the outcome (empty while running).
    pub method: String,
    pub assurance: u32,
}

/// Parameters for [`Client::begin_auth`].
#[derive(Debug, Clone, Default)]
pub struct AuthContext<'a> {
    pub user: &'a str,
    pub service: &'a str,
    pub tty: Option<&'a str>,
    pub rhost: Option<&'a str>,
}

/// Information about a backend, returned by [`Client::list_backends`].
#[derive(Debug, Clone)]
pub struct BackendInfo {
    pub name: String,
    pub available: bool,
    pub assurance: u32,
}

/// Connection to the daemon on the system bus.
pub struct Client {
    conn: Connection,
}

impl Client {
    /// Opens a private connection to the system bus.
    pub fn connect() -> Result<Self, ClientError> {
        let conn = Connection::new_system().map_err(|e| {
            ClientError::Unreachable(e.message().unwrap_or("cannot connect to system bus").into())
        })?;
        Ok(Client { conn })
    }

    /// Opens a private connection to the session bus. Development only: lets
    /// the daemon and CLI be tried without root. PAM never uses this.
    pub fn connect_session() -> Result<Self, ClientError> {
        let conn = Connection::new_session().map_err(|e| {
            ClientError::Unreachable(
                e.message()
                    .unwrap_or("cannot connect to session bus")
                    .into(),
            )
        })?;
        Ok(Client { conn })
    }

    fn proxy(&self, timeout: Duration) -> dbus::blocking::Proxy<'_, &Connection> {
        self.conn.with_proxy(BUS_NAME, OBJECT_PATH, timeout)
    }

    /// Returns the daemon version string.
    pub fn version(&self) -> Result<String, ClientError> {
        let (v,): (String,) = self
            .proxy(CALL_TIMEOUT)
            .method_call(AUTH_INTERFACE, "Version", ())
            .map_err(map_err)?;
        Ok(v)
    }

    /// Lists backends known to the daemon.
    pub fn list_backends(&self) -> Result<Vec<BackendInfo>, ClientError> {
        let (list,): (Vec<(String, bool, u32)>,) = self
            .proxy(CALL_TIMEOUT)
            .method_call(AUTH_INTERFACE, "ListBackends", ())
            .map_err(map_err)?;
        Ok(list
            .into_iter()
            .map(|(name, available, assurance)| BackendInfo {
                name,
                available,
                assurance,
            })
            .collect())
    }

    /// Starts an authentication session and returns its id.
    pub fn begin_auth(&self, c: &AuthContext<'_>) -> Result<String, ClientError> {
        let mut map: PropMap = HashMap::new();
        let mut put = |k: &str, v: &str| {
            map.insert(
                k.to_string(),
                Variant(Box::new(v.to_string()) as Box<dyn RefArg>),
            );
        };
        put(ctx::USER, c.user);
        put(ctx::SERVICE, c.service);
        if let Some(tty) = c.tty {
            put(ctx::TTY, tty);
        }
        if let Some(rhost) = c.rhost {
            put(ctx::RHOST, rhost);
        }
        let (id,): (String,) = self
            .proxy(CALL_TIMEOUT)
            .method_call(AUTH_INTERFACE, "BeginAuth", (map,))
            .map_err(map_err)?;
        Ok(id)
    }

    /// Long-polls the session for events, for at most `timeout`.
    pub fn wait(&self, session: &str, timeout: Duration) -> Result<WaitResult, ClientError> {
        let ms = timeout.as_millis().min(u128::from(MAX_WAIT_MS)) as u32;
        let call_timeout = Duration::from_millis(u64::from(ms)) + WAIT_SLACK;
        let (events, state, method, assurance): (
            Vec<(String, String, String)>,
            String,
            String,
            u32,
        ) = self
            .proxy(call_timeout)
            .method_call(AUTH_INTERFACE, "Wait", (session, ms))
            .map_err(map_err)?;
        let state = SessionState::parse(&state)
            .ok_or_else(|| ClientError::Bus(format!("unknown session state {state:?}")))?;
        Ok(WaitResult {
            events: events
                .into_iter()
                .map(|(method, state, message)| Event {
                    method,
                    state,
                    message,
                })
                .collect(),
            state,
            method,
            assurance,
        })
    }

    /// Cancels a session. Errors are ignored by most callers.
    pub fn cancel(&self, session: &str) -> Result<(), ClientError> {
        self.proxy(CALL_TIMEOUT)
            .method_call::<(), _, _, _>(AUTH_INTERFACE, "Cancel", (session,))
            .map_err(map_err)
    }

    /// Answers a `prompt` event. An empty secret skips the method.
    pub fn submit_secret(
        &self,
        session: &str,
        method: &str,
        secret: &str,
    ) -> Result<(), ClientError> {
        self.proxy(CALL_TIMEOUT)
            .method_call::<(), _, _, _>(AUTH_INTERFACE, "SubmitSecret", (session, method, secret))
            .map_err(map_err)
    }

    /// Runs a whole authentication: begins a session and polls until it ends
    /// or `deadline` passes.
    ///
    /// `on_event` is called for every event. For `prompt` events
    /// ([`Event::is_prompt`]) its return value is sent back as the answer;
    /// `None` sends an empty answer, which skips that method. Time spent
    /// waiting for the user to answer a prompt does not count against
    /// `deadline`.
    ///
    /// On deadline the session is cancelled and `SessionState::Cancelled` is
    /// returned.
    pub fn authenticate(
        &self,
        c: &AuthContext<'_>,
        mut deadline: Instant,
        mut on_event: impl FnMut(&Event) -> Option<Zeroizing<String>>,
    ) -> Result<WaitResult, ClientError> {
        let id = self.begin_auth(c)?;
        let fail = |e: ClientError| {
            let _ = self.cancel(&id);
            Err(e)
        };
        loop {
            let now = Instant::now();
            if now >= deadline {
                let _ = self.cancel(&id);
                return Ok(WaitResult {
                    events: Vec::new(),
                    state: SessionState::Cancelled,
                    method: String::new(),
                    assurance: 0,
                });
            }
            let r = match self.wait(&id, deadline - now) {
                Ok(r) => r,
                Err(e) => return fail(e),
            };
            for ev in &r.events {
                if ev.is_prompt() && !r.state.is_terminal() {
                    let asked = Instant::now();
                    let answer = on_event(ev).unwrap_or_default();
                    deadline += asked.elapsed();
                    if let Err(e) = self.submit_secret(&id, &ev.method, &answer) {
                        return fail(e);
                    }
                } else {
                    on_event(ev);
                }
            }
            if r.state.is_terminal() {
                return Ok(r);
            }
        }
    }

    // --- org.tuxhello.Manager1 ---------------------------------------------

    fn manager(&self, timeout: Duration) -> dbus::blocking::Proxy<'_, &Connection> {
        self.conn.with_proxy(BUS_NAME, MANAGER_PATH, timeout)
    }

    /// Daemon information (version, store, policy directories).
    pub fn info(&self) -> Result<HashMap<String, String>, ClientError> {
        let (m,): (HashMap<String, String>,) = self
            .manager(CALL_TIMEOUT)
            .method_call(MANAGER_INTERFACE, "GetInfo", ())
            .map_err(map_err)?;
        Ok(m)
    }

    /// Lists a user's enrolments as (method, id).
    pub fn list_enrollments(&self, uid: u32) -> Result<Vec<(String, String)>, ClientError> {
        let (v,): (Vec<(String, String)>,) = self
            .manager(CALL_TIMEOUT)
            .method_call(MANAGER_INTERFACE, "ListEnrollments", (uid,))
            .map_err(map_err)?;
        Ok(v)
    }

    /// Sets or replaces a user's PIN (root only for now).
    pub fn enroll_pin(&self, uid: u32, pin: &str) -> Result<(), ClientError> {
        // Hashing with Argon2 takes a moment; allow for it.
        self.manager(Duration::from_secs(30))
            .method_call::<(), _, _, _>(MANAGER_INTERFACE, "EnrollPin", (uid, pin))
            .map_err(map_err)
    }

    /// Deletes one enrolment. Returns whether it existed.
    pub fn delete_enrollment(&self, uid: u32, method: &str, id: &str) -> Result<bool, ClientError> {
        let (b,): (bool,) = self
            .manager(CALL_TIMEOUT)
            .method_call(MANAGER_INTERFACE, "DeleteEnrollment", (uid, method, id))
            .map_err(map_err)?;
        Ok(b)
    }

    /// Deletes everything stored for a user.
    pub fn delete_all(&self, uid: u32) -> Result<(), ClientError> {
        self.manager(CALL_TIMEOUT)
            .method_call::<(), _, _, _>(MANAGER_INTERFACE, "DeleteAll", (uid,))
            .map_err(map_err)
    }

    /// Describes the effective policy for `uid` and a PAM service.
    pub fn explain_policy(
        &self,
        uid: u32,
        service: &str,
    ) -> Result<HashMap<String, String>, ClientError> {
        let (m,): (HashMap<String, String>,) = self
            .manager(CALL_TIMEOUT)
            .method_call(MANAGER_INTERFACE, "ExplainPolicy", (uid, service))
            .map_err(map_err)?;
        Ok(m)
    }
}
