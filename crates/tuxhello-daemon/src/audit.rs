//! Structured audit log (PLAN.md §10.2).
//!
//! One JSON object per line: who, which service, which method, the result
//! and the time. Never scores, images, audio or secrets.
//!
//! Records go to the daemon's log (journald under systemd) with the target
//! `audit`, and, if `[audit] file` is set, are also appended to that file.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Also append records to this file (created 0600). The daemon's sandbox
    /// only lets it write below its state directory.
    #[serde(default)]
    pub file: Option<PathBuf>,
}

fn default_true() -> bool {
    true
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            enabled: true,
            file: None,
        }
    }
}

struct Sink {
    enabled: bool,
    file: Option<Mutex<File>>,
}

static SINK: OnceLock<Sink> = OnceLock::new();

/// Sets up the sink. Until this is called, records only go to the log.
pub fn init(cfg: &AuditConfig) -> Result<(), String> {
    let file = match (&cfg.file, cfg.enabled) {
        (Some(path), true) => Some(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| format!("audit file {}: {e}", path.display()))?,
        )),
        _ => None,
    };
    let _ = SINK.set(Sink {
        enabled: cfg.enabled,
        file,
    });
    Ok(())
}

fn push_json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// One audit record, built field by field.
#[must_use = "call .emit()"]
pub struct Record {
    buf: String,
}

impl Record {
    /// `event` names what happened, e.g. `auth.result` or `enroll`.
    pub fn new(event: &str) -> Self {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut buf = format!("{{\"time\":{time},\"event\":");
        push_json_str(&mut buf, event);
        Record { buf }
    }

    pub fn s(mut self, key: &str, value: &str) -> Self {
        self.buf.push(',');
        push_json_str(&mut self.buf, key);
        self.buf.push(':');
        push_json_str(&mut self.buf, value);
        self
    }

    pub fn n(mut self, key: &str, value: u64) -> Self {
        self.buf.push(',');
        push_json_str(&mut self.buf, key);
        let _ = write!(self.buf, ":{value}");
        self
    }

    fn finish(mut self) -> String {
        self.buf.push('}');
        self.buf
    }

    pub fn emit(self) {
        let sink = SINK.get();
        if sink.is_some_and(|s| !s.enabled) {
            return;
        }
        let line = self.finish();
        log::info!(target: "audit", "{line}");
        if let Some(file) = sink.and_then(|s| s.file.as_ref()) {
            let mut f = file.lock().unwrap_or_else(|p| p.into_inner());
            if let Err(e) = writeln!(f, "{line}") {
                log::error!("cannot write the audit file: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_json_objects() {
        let line = Record::new("auth.result")
            .s("user", "alice")
            .n("uid", 1000)
            .s("result", "success")
            .finish();
        assert!(line.starts_with("{\"time\":"));
        assert!(line.ends_with(
            ",\"event\":\"auth.result\",\"user\":\"alice\",\"uid\":1000,\"result\":\"success\"}"
        ));
    }

    #[test]
    fn strings_are_escaped() {
        // A service or user name must not be able to forge fields or lines.
        let line = Record::new("x")
            .s("service", "a\",\"result\":\"success\nb\\\u{1}")
            .finish();
        assert!(line.contains(r#""service":"a\",\"result\":\"success\nb\\\u0001""#));
        assert_eq!(line.lines().count(), 1);
    }
}
