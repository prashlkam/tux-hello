// SPDX-FileCopyrightText: 2026 Tux Hello contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Import of `pam_u2f` key files (PLAN.md §5.5), so that people who already
//! use pam_u2f do not have to enrol their keys again.
//!
//! One line per user:
//!
//! ```text
//! alice:<cred>:<cred>...
//! ```
//!
//! where `<cred>` is
//!
//! * `KeyHandle,PublicKey,CoseType,Options` (pam_u2f 1.1 and later): standard
//!   base64 key handle and public key, `es256`/`eddsa`/`rs256`, and options
//!   such as `+presence`, `+verification`, `+pin`; or
//! * `KeyHandle,PublicKey` (older): web-safe base64 key handle and the
//!   hex-encoded SEC1 point (`04 || x || y`), always ES256.
//!
//! The credentials stay bound to pam_u2f's relying-party id (its `origin`,
//! `pam://<hostname>` by default), which is stored with each record.

use super::{COSE_EDDSA, COSE_ES256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    /// 1-based position on the user's line, for messages.
    pub index: usize,
    pub credential_id: Vec<u8>,
    pub alg: i32,
    pub public_key: Vec<u8>,
    /// pam_u2f asked for user verification (`+verification` or `+pin`).
    pub wants_uv: bool,
}

/// Decodes standard or web-safe base64, with or without padding.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Leftover bits must be zero padding, and a lone 6-bit group is invalid.
    (acc == 0 && s.len() % 4 != 1).then_some(out)
}

fn parse_cred(index: usize, field: &str) -> Result<Imported, String> {
    let parts: Vec<&str> = field.split(',').collect();
    let err = |why: &str| format!("credential {index}: {why}");
    let (kh, pk) = match parts.as_slice() {
        [kh, pk, ..] => (*kh, *pk),
        _ => return Err(err("not in pam_u2f format")),
    };
    if kh == "*" {
        return Err(err(
            "is a resident (discoverable) credential, which has no key handle to import; \
             enrol the key again with `tuxhello enroll key`",
        ));
    }
    let credential_id = base64_decode(kh)
        .filter(|b| !b.is_empty())
        .ok_or_else(|| err("unreadable key handle"))?;

    let (alg, public_key, wants_uv) = if parts.len() >= 3 {
        let opts = parts.get(3).copied().unwrap_or("");
        let wants_uv = opts.contains("+verification") || opts.contains("+pin");
        let key = base64_decode(pk).ok_or_else(|| err("unreadable public key"))?;
        match parts[2] {
            "es256" if key.len() == 64 || (key.len() == 65 && key[0] == 4) => {
                (COSE_ES256, key, wants_uv)
            }
            "eddsa" if key.len() == 32 => (COSE_EDDSA, key, wants_uv),
            "es256" | "eddsa" => return Err(err("public key has the wrong length")),
            other => {
                return Err(err(&format!(
                    "key type {other:?} is not supported (ES256 and EdDSA are)"
                )))
            }
        }
    } else {
        let key = super::from_hex(pk).ok_or_else(|| err("unreadable public key"))?;
        if key.len() != 65 || key[0] != 4 {
            return Err(err("public key is not an uncompressed P-256 point"));
        }
        (COSE_ES256, key, false)
    };
    Ok(Imported {
        index,
        credential_id,
        alg,
        public_key,
        wants_uv,
    })
}

/// Reads `user`'s credentials from the text of a pam_u2f key file. Returns
/// the usable credentials and a note for each one that cannot be imported.
pub fn parse_pam_u2f(text: &str, user: &str) -> (Vec<Imported>, Vec<String>) {
    let mut creds = Vec::new();
    let mut notes = Vec::new();
    let mut found = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(':');
        if fields.next() != Some(user) {
            continue;
        }
        found = true;
        for field in fields.filter(|f| !f.is_empty()) {
            let index = creds.len() + notes.len() + 1;
            match parse_cred(index, field) {
                Ok(c) => creds.push(c),
                Err(e) => notes.push(e),
            }
        }
    }
    if !found {
        notes.push(format!("the file has no line for user {user:?}"));
    }
    (creds, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_variants() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8").unwrap(), b"hello");
        assert_eq!(base64_decode("+/8=").unwrap(), [0xfb, 0xff]);
        assert_eq!(base64_decode("-_8").unwrap(), [0xfb, 0xff]);
        assert_eq!(base64_decode("").unwrap(), b"");
        assert!(base64_decode("a").is_none());
        assert!(base64_decode("a b=").is_none());
        // Non-zero trailing bits are not canonical.
        assert!(base64_decode("aGVsbG9=").is_none());
    }

    fn b64(b: &[u8]) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for chunk in b.chunks(3) {
            let n = chunk.len();
            let v = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= n {
                    s.push(T[((v >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    s.push('=');
                }
            }
        }
        s
    }

    #[test]
    fn new_format_lines() {
        let kh = b64(&[9u8; 48]);
        let es = b64(&[1u8; 64]);
        let ed = b64(&[2u8; 32]);
        let text = format!(
            "# comment\nbob:{kh},{es},es256,+presence\n\
             alice:{kh},{es},es256,+presence:{kh},{ed},eddsa,+presence+pin:*,{es},es256,+presence:{kh},AAAA,rs256,+presence\n"
        );
        let (creds, notes) = parse_pam_u2f(&text, "alice");
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0].alg, COSE_ES256);
        assert_eq!(creds[0].credential_id, vec![9u8; 48]);
        assert_eq!(creds[0].public_key, vec![1u8; 64]);
        assert!(!creds[0].wants_uv);
        assert_eq!(creds[1].alg, COSE_EDDSA);
        assert!(creds[1].wants_uv);
        assert_eq!(notes.len(), 2);
        assert!(notes[0].contains("resident"));
        assert!(notes[1].contains("rs256"));
    }

    #[test]
    fn old_format_lines() {
        let mut point = vec![4u8];
        point.extend([7u8; 64]);
        let text = format!("alice:{},{}\n", "CQkJCQ", super::super::to_hex(&point));
        let (creds, notes) = parse_pam_u2f(&text, "alice");
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(creds[0].credential_id, vec![9u8; 4]);
        assert_eq!(creds[0].public_key, point);
        assert_eq!(creds[0].alg, COSE_ES256);
    }

    #[test]
    fn missing_user_and_garbage() {
        let (creds, notes) = parse_pam_u2f("bob:x,y\n", "alice");
        assert!(creds.is_empty());
        assert!(notes[0].contains("no line for user"));
        let (creds, notes) = parse_pam_u2f("alice:nonsense:!!,zz\n", "alice");
        assert!(creds.is_empty());
        assert_eq!(notes.len(), 2);
    }
}
