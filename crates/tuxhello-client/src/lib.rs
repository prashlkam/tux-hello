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
use tuxhello_proto::{ctx, error, AUTH_INTERFACE, BUS_NAME, MAX_WAIT_MS, OBJECT_PATH};

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

    /// Runs a whole authentication: begins a session and polls until it ends
    /// or `deadline` passes. `on_event` is called for every progress event.
    ///
    /// On deadline the session is cancelled and `SessionState::Cancelled` is
    /// returned.
    pub fn authenticate(
        &self,
        c: &AuthContext<'_>,
        deadline: Instant,
        mut on_event: impl FnMut(&Event),
    ) -> Result<WaitResult, ClientError> {
        let id = self.begin_auth(c)?;
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
                Err(e) => {
                    let _ = self.cancel(&id);
                    return Err(e);
                }
            };
            for ev in &r.events {
                on_event(ev);
            }
            if r.state.is_terminal() {
                return Ok(r);
            }
        }
    }
}
