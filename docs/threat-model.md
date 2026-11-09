# Threat model, v1

*Status: Phase 0 draft, 2026-11-09. To be revised at every phase exit and before the external audit.*

## 1. Assets

| Asset | Why it matters |
|---|---|
| A1. Ability to authenticate as a user | The core security property: unlock, `sudo`, polkit. |
| A2. Biometric templates (face/voice embeddings) | Personal data; can't be revoked like a password. |
| A3. PIN secrets, FIDO2 credential metadata | Can be used to authenticate. |
| A4. Escrowed login password (Phase 4, opt-in) | Unlocks keyrings and is equivalent to the password. |
| A5. Availability of password login | Users must never be locked out (G4). |

## 2. Trust boundaries

```
 untrusted ─┬─ physical attacker at the keyboard/camera/microphone
            ├─ remote network attacker (SSH, XRDP)
            └─ local unprivileged user / malware running as a user
 ─────────── system bus ─────────────────────────────────────────
 semi-trusted  PAM host processes (sudo, greeter, locker, polkit agent)
 ─────────── D-Bus caller credentials ───────────────────────────
 trusted       tuxhellod (runs as `tuxhello`, sandboxed)
 ─────────── socketpair (Phase 1+) ──────────────────────────────
 less trusted  backend processes (parse untrusted camera/audio/USB input)
```

## 3. Attackers and threats

| ID | Attacker | Threat | Mitigation | Status |
|---|---|---|---|---|
| T1 | Remote | Uses biometrics/PIN over SSH or RDP | The module returns `PAM_IGNORE` for non-local `PAM_RHOST` and for `sshd`/`xrdp-sesman`/`cockpit`; the daemon rejects remote `rhost` again. | **Done (P0)**, tested |
| T2 | Local user | Uses the daemon to test whether a face or voice recording matches *another* account | Non-root callers may only authenticate their own UID (from bus credentials, not from the request). | **Done (P0)**, tested |
| T3 | Local user | Snoops on or hijacks another caller's session | Session ids are 128-bit random, bound to the creator's unique bus name, and "not yours" gives the same error as "doesn't exist". | **Done (P0)** |
| T4 | Local user | Exhausts daemon resources (DoS) | Per-UID (4) and global (64) session limits, bounded event queues, hard session lifetime. | **Done (P0)**; per-UID attempt rate limiting comes in P1 |
| T5 | Anyone | Daemon bug or crash locks users out | The module falls through on every error. The integration suite covers: daemon absent, daemon killed mid-session, timeouts, not enrolled, unavailable. | **Done (P0)**, tested |
| T6 | Anyone | Module bug crashes `sudo` or the greeter | `catch_unwind` at the FFI boundary; no threads; libdbus calls with hard timeouts. | **Done (P0)** |
| T7 | Local user | Impersonates the daemon on the bus | The D-Bus policy only lets `tuxhello` and root own `org.tuxhello.Auth1`. | **Done (P0)** |
| T8 | Physical | Spoofs face (photo/screen/mask), voice (replay/TTS) or fingerprint (fake finger) | IR + liveness, digit challenge + anti-spoofing, assurance levels, and policy limits on weak methods. | P2/P4 |
| T9 | Physical | Brute-forces the PIN | Persistent exponential backoff (5 free attempts, then 30 s doubling to 1 h; survives restarts; unreadable state counts as locked); 3 attempts per session. TPM dictionary-attack lockout comes with the TPM PIN. | **Software lockout done (P1)**, tested; TPM pending |
| T10 | Offline (stolen disk) | Reads or reuses templates | AES-256-GCM records bound to (uid, method, id); Argon2id PIN hashes; files 0600 in a 0700 directory. The master key is a root-only file until the TPM-sealed key lands, so a disk image still exposes the store. | **Partial (P1)** |
| T11 | Malicious input (crafted USB or camera stream) | Exploits a parser or ML runtime bug | Backends in separate seccomp/Landlock-sandboxed processes with no network or FS write access. | P1–P5 |
| T12 | Supply chain | Tampered crates or models | `cargo-deny` in CI (P0); `cargo-vet`, reproducible builds, signed releases and model hash verification later. | Partial |
| T13 | Coercion / sleeping user | Unlocks the device with the owner's face | Attention check, `tuxhello lockdown`, password required on first login after boot. | P2/P3 |
| T14 | Misconfiguration | Admin makes `pam_tuxhello` `required`, or puts the stub backend in production | The setup tool generates `sufficient` stacks. The stub backend is a compile-time feature, off by default, and logs loudly when enabled. | Partial (P0: stub gating) |

| T15 | Local user | Enrols a PIN for themselves without knowing the password, then uses it to unlock a session someone left open | Enrolment is root-only (in practice, behind `sudo`'s password check) until polkit self-enrolment arrives. | **Done (P1)** |
| T17 | Physical | Uses a cloned or replayed security key | Fresh random challenge per login; the signature and RP ID hash are checked in Rust; a signature counter that goes backwards is refused and logged; the UP flag is required, plus UV when configured. | **Done (P1)**, tested with a software key |
| T18 | Malicious USB device | Exploits a libfido2 parsing bug | libfido2 runs inside the daemon for now; it moves into the sandboxed key-backend process (T11). Device access is limited to hidraw by the systemd unit. | Partial |
| T19 | Local user / malware | Uses the daemon's fprintd rights to read or replace other users' prints | The polkit rule only covers the `tuxhello` system account. The daemon only claims the reader for the user being authenticated, and enrolment is left to fprintd's own tools and permissions. Deleting another user's prints requires root. | **Done (P1)** |
| T16 | Local user | Reads or deletes another user's enrolments | Manager calls are limited to the caller's own UID unless root. | **Done (P1)**, tested |

## 4. Phase 0 limits (known and accepted)

- **The stub backend authenticates anyone when configured with `outcome = "success"`.** It only exists in builds made with `--features tuxhello-daemon/stub-backend`, which must never be packaged.
- There is no rate limiting on *attempts* yet, only on concurrent sessions.
- The daemon runs in-process backends; the process isolation of T11 starts in Phase 1.
- Unprivileged callers are identified by UID only. A user's own malware can authenticate as that user if the user is physically present, for example by looking at the camera. This is inherent to any biometric unlock; Windows Hello behaves the same way.
