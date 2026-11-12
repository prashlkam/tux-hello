//! Daemon configuration (`/etc/tuxhello/config.toml`).

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::audit::AuditConfig;
use crate::fingerprint::FingerprintConfig;
use crate::guard::LimitsConfig;
use crate::key::KeyConfig;
use crate::pin::PinConfig;

pub const DEFAULT_PATH: &str = "/etc/tuxhello/config.toml";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    #[cfg_attr(not(feature = "tpm"), allow(dead_code))]
    pub tpm: TpmConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub pin: PinConfig,
    #[serde(default)]
    pub key: KeyConfig,
    #[serde(default)]
    pub fingerprint: FingerprintConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub audit: AuditConfig,
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
    120
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

/// Whether to use the TPM for something.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TpmMode {
    /// Use it if there is one.
    #[default]
    Auto,
    /// Refuse to work without it.
    Require,
    Off,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(not(feature = "tpm"), allow(dead_code))]
pub struct TpmConfig {
    /// How tpm2-tss reaches the TPM (a TCTI name and its configuration).
    #[serde(default = "default_tcti")]
    pub tcti: String,
}

fn default_tcti() -> String {
    "device:/dev/tpmrm0".into()
}

impl Default for TpmConfig {
    fn default() -> Self {
        TpmConfig {
            tcti: default_tcti(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    /// Template store directory.
    #[serde(default = "default_store_path")]
    pub path: PathBuf,
    /// Seal the master key with the TPM. `auto` does so for a new store when
    /// a TPM is present; `require` also moves an existing file key into the
    /// TPM.
    #[serde(default)]
    pub tpm: TpmMode,
}

fn default_store_path() -> PathBuf {
    PathBuf::from(tuxhello_store::DEFAULT_ROOT)
}

impl Default for StoreConfig {
    fn default() -> Self {
        StoreConfig {
            path: default_store_path(),
            tpm: TpmMode::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Directories of `*.toml` policy files, merged in order over the
    /// built-in defaults.
    #[serde(default = "default_policy_dirs")]
    pub dirs: Vec<PathBuf>,
}

fn default_policy_dirs() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/usr/share/tuxhello/policy.d"),
        PathBuf::from("/etc/tuxhello/policy.d"),
    ]
}

impl Default for PolicyConfig {
    fn default() -> Self {
        PolicyConfig {
            dirs: default_policy_dirs(),
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
    /// Assurance reported on success.
    #[serde(default = "default_stub_assurance")]
    pub assurance: u32,
    /// Use a software FIDO2 authenticator kept in this directory instead of
    /// real security keys (see `key/soft.rs`). Independent of `enabled`.
    #[serde(default)]
    pub soft_key_dir: Option<PathBuf>,
}

fn default_stub_delay() -> u64 {
    300
}
fn default_stub_assurance() -> u32 {
    2
}

impl Default for StubConfig {
    fn default() -> Self {
        StubConfig {
            enabled: false,
            outcome: StubOutcome::default(),
            delay_ms: default_stub_delay(),
            users: Vec::new(),
            assurance: default_stub_assurance(),
            soft_key_dir: None,
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
        assert_eq!(c.daemon.session_lifetime_s, 120);
        assert_eq!(c.store.path, PathBuf::from("/var/lib/tuxhello"));
        assert_eq!(c.policy.dirs.len(), 2);
        assert_eq!(c.pin.min_length, 4);
        assert_eq!(c.key.rp_id, "pam://tuxhello");
        assert!(!c.key.require_uv);
        assert_eq!(c.tpm.tcti, "device:/dev/tpmrm0");
        assert_eq!(c.store.tpm, TpmMode::Auto);
        assert_eq!(c.pin.tpm, TpmMode::Auto);
        assert_eq!(c.limits.max_failures, 10);
        assert_eq!(c.limits.window_s, 300);
        assert_eq!(c.limits.biometric_max_failures, 5);
        assert!(c.audit.enabled);
        assert!(c.audit.file.is_none());
    }

    #[test]
    fn parses_all_sections() {
        let c = Config::parse(
            r#"
            [tpm]
            tcti = "swtpm:port=2321"
            [store]
            path = "/tmp/x"
            tpm = "require"
            [policy]
            dirs = ["/a"]
            [pin]
            min_length = 6
            allow_alnum = false
            tpm = "off"
            [key]
            rp_id = "pam://host"
            require_uv = true
            [limits]
            max_failures = 20
            window_s = 60
            biometric_max_failures = 3
            [audit]
            file = "/var/lib/tuxhello/audit.log"
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
        assert_eq!(c.store.path, PathBuf::from("/tmp/x"));
        assert_eq!(c.policy.dirs, vec![PathBuf::from("/a")]);
        assert_eq!(c.pin.min_length, 6);
        assert!(!c.pin.allow_alnum);
        assert_eq!(c.pin.tpm, TpmMode::Off);
        assert_eq!(c.store.tpm, TpmMode::Require);
        assert_eq!(c.tpm.tcti, "swtpm:port=2321");
        assert!(Config::parse("[store]\ntpm = \"maybe\"\n").is_err());
        assert_eq!(c.key.rp_id, "pam://host");
        assert!(c.key.require_uv);
        assert_eq!(c.limits.max_failures, 20);
        assert_eq!(c.limits.biometric_max_failures, 3);
        assert_eq!(
            c.audit.file,
            Some(PathBuf::from("/var/lib/tuxhello/audit.log"))
        );
    }

    /// The example shipped in packages must parse, and must show the real
    /// defaults.
    #[test]
    fn shipped_example_matches_the_defaults() {
        let c = Config::parse(include_str!("../../../data/config.toml")).unwrap();
        let d = Config::default();
        assert_eq!(c.daemon.session_lifetime_s, d.daemon.session_lifetime_s);
        assert_eq!(c.daemon.max_sessions, d.daemon.max_sessions);
        assert_eq!(c.tpm.tcti, d.tpm.tcti);
        assert_eq!(c.store.path, d.store.path);
        assert_eq!(c.store.tpm, d.store.tpm);
        assert_eq!(c.pin.min_length, d.pin.min_length);
        assert_eq!(c.pin.attempts_per_session, d.pin.attempts_per_session);
        assert_eq!(c.pin.tpm, d.pin.tpm);
        assert_eq!(c.limits.max_failures, d.limits.max_failures);
        assert_eq!(c.limits.window_s, d.limits.window_s);
        assert_eq!(
            c.limits.biometric_max_failures,
            d.limits.biometric_max_failures
        );
        assert_eq!(c.audit.enabled, d.audit.enabled);
        assert!(!c.stub.enabled);
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(Config::parse("[stub]\nbogus = 1\n").is_err());
        assert!(Config::parse("[pin]\nbogus = 1\n").is_err());
        assert!(Config::parse("[limits]\nbogus = 1\n").is_err());
        assert!(Config::parse("[audit]\nbogus = 1\n").is_err());
    }

    #[test]
    fn missing_file_gives_defaults() {
        let c = Config::load(Path::new("/nonexistent/tuxhello/config.toml")).unwrap();
        assert!(!c.stub.enabled);
    }
}
