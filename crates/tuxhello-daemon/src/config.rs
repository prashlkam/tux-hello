//! Daemon configuration (`/etc/tuxhello/config.toml`).

use std::path::Path;

use serde::Deserialize;

pub const DEFAULT_PATH: &str = "/etc/tuxhello/config.toml";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub stub: StubConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    /// Hard limit for how long a session may live, in seconds.
    #[serde(default = "default_session_lifetime")]
    pub session_lifetime_s: u64,
    /// Maximum concurrent sessions per calling UID.
    #[serde(default = "default_max_sessions_per_uid")]
    pub max_sessions_per_uid: usize,
    /// Maximum concurrent sessions in total.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
}

fn default_session_lifetime() -> u64 {
    60
}
fn default_max_sessions_per_uid() -> usize {
    4
}
fn default_max_sessions() -> usize {
    64
}

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig {
            session_lifetime_s: default_session_lifetime(),
            max_sessions_per_uid: default_max_sessions_per_uid(),
            max_sessions: default_max_sessions(),
        }
    }
}

/// Configuration of the test-only stub backend. Ignored unless the daemon was
/// built with the `stub-backend` feature.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(not(feature = "stub-backend"), allow(dead_code))]
pub struct StubConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub outcome: StubOutcome,
    /// Simulated processing time.
    #[serde(default = "default_stub_delay")]
    pub delay_ms: u64,
    /// Users considered "enrolled". Empty means every user.
    #[serde(default)]
    pub users: Vec<String>,
}

fn default_stub_delay() -> u64 {
    300
}

impl Default for StubConfig {
    fn default() -> Self {
        StubConfig {
            enabled: false,
            outcome: StubOutcome::default(),
            delay_ms: default_stub_delay(),
            users: Vec::new(),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(not(feature = "stub-backend"), allow(dead_code))]
pub enum StubOutcome {
    Success,
    Failure,
    #[default]
    Unavailable,
}

impl Config {
    /// Loads the configuration. A missing file yields the defaults; a file
    /// that exists but cannot be parsed is an error (fail closed).
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_is_safe_default() {
        let c = Config::parse("").unwrap();
        assert!(!c.stub.enabled);
        assert_eq!(c.stub.outcome, StubOutcome::Unavailable);
        assert_eq!(c.daemon.session_lifetime_s, 60);
    }

    #[test]
    fn parses_stub_section() {
        let c = Config::parse(
            r#"
            [stub]
            enabled = true
            outcome = "success"
            delay_ms = 10
            users = ["alice"]
            "#,
        )
        .unwrap();
        assert!(c.stub.enabled);
        assert_eq!(c.stub.outcome, StubOutcome::Success);
        assert_eq!(c.stub.users, vec!["alice".to_string()]);
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(Config::parse("[stub]\nbogus = 1\n").is_err());
    }

    #[test]
    fn missing_file_gives_defaults() {
        let c = Config::load(Path::new("/nonexistent/tuxhello/config.toml")).unwrap();
        assert!(!c.stub.enabled);
    }
}
