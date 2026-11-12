//! Fingerprint backend: a client of fprintd (PLAN.md §5.3).
//!
//! We don't talk to sensors ourselves. fprintd/libfprint already support
//! hundreds of readers, store the prints (on match-on-chip sensors they never
//! leave the sensor), and are packaged everywhere. Enrolment is done with
//! fprintd's own tools (`fprintd-enroll`); this backend verifies, lists and
//! deletes.
//!
//! fprintd authorises callers with polkit. tuxhellod runs as the `tuxhello`
//! system user, which has no session, so `data/polkit/50-tuxhello-fprintd.rules`
//! grants that user `verify`, `enroll` (needed to delete prints) and
//! `setusername` (to act for the user who is logging in).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures_util::StreamExt;
use serde::Deserialize;
use tokio::sync::OnceCell;
use tuxhello_proto::assurance;
use zbus::zvariant::OwnedObjectPath;

use crate::backend::{Backend, BoxFuture, Outcome, Progress, Request};

pub const METHOD: &str = "fingerprint";

#[zbus::proxy(
    interface = "net.reactivated.Fprint.Manager",
    default_service = "net.reactivated.Fprint",
    default_path = "/net/reactivated/Fprint/Manager"
)]
trait FprintManager {
    fn get_devices(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
    fn get_default_device(&self) -> zbus::Result<OwnedObjectPath>;
}

#[zbus::proxy(
    interface = "net.reactivated.Fprint.Device",
    default_service = "net.reactivated.Fprint"
)]
trait FprintDevice {
    fn claim(&self, username: &str) -> zbus::Result<()>;
    fn release(&self) -> zbus::Result<()>;
    fn verify_start(&self, finger_name: &str) -> zbus::Result<()>;
    fn verify_stop(&self) -> zbus::Result<()>;
    fn list_enrolled_fingers(&self, username: &str) -> zbus::Result<Vec<String>>;
    fn delete_enrolled_finger(&self, finger_name: &str) -> zbus::Result<()>;
    fn delete_enrolled_fingers2(&self) -> zbus::Result<()>;

    #[zbus(signal)]
    fn verify_status(&self, result: &str, done: bool) -> zbus::Result<()>;

    #[zbus(property, name = "scan-type")]
    fn scan_type(&self) -> zbus::Result<String>;
    #[zbus(property, name = "name")]
    fn name(&self) -> zbus::Result<String>;
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FingerprintConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Assurance of a match. 3 suits match-on-chip sensors (most current
    /// laptop readers); lower it for host-matched or swipe sensors.
    #[serde(default = "default_assurance")]
    pub assurance: u32,
    /// Scans per authentication before giving up.
    #[serde(default = "default_tries")]
    pub max_tries: u32,
}

fn default_true() -> bool {
    true
}
fn default_assurance() -> u32 {
    assurance::HIGH
}
fn default_tries() -> u32 {
    3
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        FingerprintConfig {
            enabled: true,
            assurance: default_assurance(),
            max_tries: default_tries(),
        }
    }
}

/// fprintd error names we act on.
fn error_name(e: &zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, _, _) => name.to_string(),
        other => other.to_string(),
    }
}

fn is_no_prints(e: &zbus::Error) -> bool {
    error_name(e).ends_with(".NoEnrolledPrints")
}

/// Message for a non-final scan result.
fn retry_hint(result: &str) -> &'static str {
    match result {
        "verify-swipe-too-short" => "Swipe was too short, try again",
        "verify-finger-not-centered" => "Finger not centred, try again",
        "verify-remove-and-retry" => "Remove your finger and try again",
        _ => "Try again",
    }
}

pub struct FingerprintBackend {
    cfg: FingerprintConfig,
    conn: OnceCell<Option<zbus::Connection>>,
    /// Last known reader presence, for the synchronous `available()`.
    seen_device: AtomicBool,
}

/// Stops verification and releases the reader when dropped (also when the
/// session is cancelled mid-scan), so the sensor is never left claimed.
struct Claimed {
    dev: Option<FprintDeviceProxy<'static>>,
}

impl Claimed {
    async fn release(mut self) {
        if let Some(dev) = self.dev.take() {
            let _ = dev.verify_stop().await;
            let _ = dev.release().await;
        }
    }
}

impl Drop for Claimed {
    fn drop(&mut self) {
        if let Some(dev) = self.dev.take() {
            tokio::spawn(async move {
                let _ = dev.verify_stop().await;
                let _ = dev.release().await;
            });
        }
    }
}

impl FingerprintBackend {
    pub fn new(cfg: FingerprintConfig) -> Self {
        FingerprintBackend {
            cfg,
            conn: OnceCell::new(),
            seen_device: AtomicBool::new(false),
        }
    }

    async fn conn(&self) -> Option<&zbus::Connection> {
        self.conn
            .get_or_init(|| async {
                match zbus::Connection::system().await {
                    Ok(c) => Some(c),
                    Err(e) => {
                        log::warn!("fingerprint: cannot connect to the system bus: {e}");
                        None
                    }
                }
            })
            .await
            .as_ref()
    }

    async fn device(&self) -> Option<FprintDeviceProxy<'static>> {
        let conn = self.conn().await?.clone();
        let mgr = FprintManagerProxy::new(&conn).await.ok()?;
        let path = match mgr.get_default_device().await {
            Ok(p) => p,
            Err(e) => {
                log::debug!("fingerprint: no reader: {}", error_name(&e));
                self.seen_device.store(false, Ordering::Relaxed);
                return None;
            }
        };
        self.seen_device.store(true, Ordering::Relaxed);
        FprintDeviceProxy::builder(&conn)
            .path(path)
            .ok()?
            .build()
            .await
            .ok()
    }

    /// Fingers fprintd has enrolled for `user`.
    pub async fn enrolled_fingers(&self, user: &str) -> Vec<String> {
        if !self.cfg.enabled {
            return Vec::new();
        }
        let Some(dev) = self.device().await else {
            return Vec::new();
        };
        match dev.list_enrolled_fingers(user).await {
            Ok(v) => v,
            Err(e) if is_no_prints(&e) => Vec::new(),
            Err(e) => {
                log::warn!(
                    "fingerprint: listing prints of {user:?}: {}",
                    error_name(&e)
                );
                Vec::new()
            }
        }
    }

    /// Deletes one finger (or all with `None`). Returns whether anything
    /// was enrolled.
    pub async fn delete(&self, user: &str, finger: Option<&str>) -> Result<bool, String> {
        let dev = self.device().await.ok_or("no fingerprint reader")?;
        let before = self.enrolled_fingers(user).await;
        if before.is_empty() || finger.is_some_and(|f| !before.iter().any(|b| b == f)) {
            return Ok(false);
        }
        dev.claim(user).await.map_err(|e| error_name(&e))?;
        let r = match finger {
            Some(f) => dev.delete_enrolled_finger(f).await,
            None => dev.delete_enrolled_fingers2().await,
        };
        let _ = dev.release().await;
        r.map_err(|e| error_name(&e))?;
        Ok(true)
    }

    async fn verify_inner(&self, user: &str, progress: &Progress) -> Outcome {
        let Some(dev) = self.device().await else {
            return Outcome::Unavailable;
        };
        // Subscribe before starting, so no status signal is missed.
        let mut status = match dev.receive_verify_status().await {
            Ok(s) => s,
            Err(e) => {
                log::warn!("fingerprint: cannot subscribe to VerifyStatus: {e}");
                return Outcome::Unavailable;
            }
        };
        if let Err(e) = dev.claim(user).await {
            let name = error_name(&e);
            log::info!("fingerprint: cannot claim the reader for {user:?}: {name}");
            if name.ends_with(".AlreadyInUse") {
                progress.emit("busy", "Fingerprint reader is busy");
            }
            return Outcome::Unavailable;
        }
        let claimed = Claimed {
            dev: Some(dev.clone()),
        };
        let swipe = dev.scan_type().await.is_ok_and(|t| t == "swipe");
        let ask = if swipe {
            "Swipe your finger on the fingerprint reader"
        } else {
            "Touch the fingerprint reader"
        };

        let mut outcome = Outcome::Unavailable;
        'tries: for attempt in 0..self.cfg.max_tries {
            if let Err(e) = dev.verify_start("any").await {
                if !is_no_prints(&e) {
                    log::warn!("fingerprint: VerifyStart: {}", error_name(&e));
                }
                break;
            }
            progress.emit("scan", if attempt == 0 { ask } else { "Try again" });
            loop {
                let Some(sig) = status.next().await else {
                    log::warn!("fingerprint: fprintd went away");
                    break 'tries;
                };
                let Ok(args) = sig.args() else { continue };
                let (result, done) = (args.result().to_string(), *args.done());
                match result.as_str() {
                    "verify-match" => {
                        claimed.release().await;
                        return Outcome::Match {
                            assurance: self.cfg.assurance,
                        };
                    }
                    "verify-no-match" => {
                        progress.emit("no-match", "Fingerprint not recognised");
                        outcome = Outcome::NoMatch;
                        let _ = dev.verify_stop().await;
                        if progress.failed_attempt() {
                            progress.emit(
                                "locked",
                                "Too many failed attempts: fingerprint is off until you use your PIN or security key",
                            );
                            break 'tries;
                        }
                        continue 'tries;
                    }
                    "verify-retry-scan"
                    | "verify-swipe-too-short"
                    | "verify-finger-not-centered"
                    | "verify-remove-and-retry" => {
                        progress.emit("retry", retry_hint(&result));
                        if done {
                            let _ = dev.verify_stop().await;
                            continue 'tries;
                        }
                    }
                    "verify-disconnected" => {
                        log::info!("fingerprint: reader disconnected");
                        break 'tries;
                    }
                    other => {
                        log::warn!("fingerprint: verify failed: {other}");
                        break 'tries;
                    }
                }
            }
        }
        claimed.release().await;
        outcome
    }
}

impl Backend for FingerprintBackend {
    fn name(&self) -> &'static str {
        METHOD
    }

    fn assurance(&self) -> u32 {
        self.cfg.assurance
    }

    fn available(&self) -> bool {
        self.cfg.enabled && self.seen_device.load(Ordering::Relaxed)
    }

    fn biometric(&self) -> bool {
        true
    }

    fn usable(self: Arc<Self>, user: String, _uid: u32) -> BoxFuture<bool> {
        Box::pin(async move { !self.enrolled_fingers(&user).await.is_empty() })
    }

    fn verify(self: Arc<Self>, req: Request, progress: Progress) -> BoxFuture<Outcome> {
        Box::pin(async move { self.verify_inner(&req.user, &progress).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_hints() {
        assert_eq!(
            retry_hint("verify-swipe-too-short"),
            "Swipe was too short, try again"
        );
        assert_eq!(retry_hint("verify-retry-scan"), "Try again");
    }

    #[test]
    fn config_defaults() {
        let c = FingerprintConfig::default();
        assert!(c.enabled);
        assert_eq!(c.assurance, 3);
        assert_eq!(c.max_tries, 3);
    }
}
