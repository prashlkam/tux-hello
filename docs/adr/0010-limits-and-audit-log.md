# ADR 0010: Attempt limits and the audit log

- **Status:** Accepted (implemented in Phase 1)
- **Date:** 2026-11-12

## Decision

Three limits apply to failed attempts. Each backend reports every failed attempt (a wrong PIN, an unknown finger, a rejected key) through `Progress::failed_attempt()`; `guard.rs` does the counting.

| Limit | Default | Scope | Kept | Lifted by |
|---|---|---|---|---|
| Rate limit | 10 failures in 5 minutes | per user, all methods together | in memory | time, or any success |
| Biometric lockout | 5 consecutive failures | per user, biometric methods together | in the store | a PIN or security-key success, or `sudo tuxhello unlock` |
| PIN backoff (ADR 0007) | 5 free, then 30 s doubling to 1 h | per user | in the store | a correct PIN after the wait, re-enrolment, or `unlock` |

- **Rate limited** means `BeginAuth` answers `Unavailable` before any backend runs, so no prompt is shown and PAM falls through to the password at once.
- **Biometrics locked** means biometric backends are left out of the session; the PIN and security key are still offered.
- Unreadable lockout state counts as locked.
- `[limits]` in `config.toml` sets the numbers; 0 switches a limit off.

### "Until the password succeeds"

PLAN.md §6.3 says biometrics stay off until a PIN or password succeeds. The daemon cannot see a password login: `pam_tuxhello` is `sufficient`, and when it fails the stack simply continues to `pam_unix`. So the lockout is lifted by a PIN or security-key success, or by root with `tuxhello unlock` (`Manager1.ResetLockout`), where `sudo` has just verified the password. Lifting it automatically after a password login needs the module in a later PAM phase; that arrives with keyring escrow in Phase 4, which needs the same hook.

### Why the rate limit is not persistent

It is a brake on rapid guessing, not the control that bounds total guesses; the PIN backoff and the biometric lockout do that, and both are persistent. An unprivileged attacker cannot restart the daemon to clear it.

## Audit log

One JSON object per line, with the log target `audit` (journald under systemd), and optionally appended to `[audit] file` (0600):

```json
{"time":1794480000,"event":"auth.result","session":"…","user":"alice","uid":1000,"service":"sudo","class":"elevate","result":"success","method":"pin","assurance":2}
```

| Event | When |
|---|---|
| `auth.begin` | a session starts (user, service, class, caller uid) |
| `auth.attempt` | one failed attempt (method) |
| `auth.result` | a session ends: `success` (method, assurance), `failure` or `unavailable` |
| `auth.refused` | no session: `rate-limited` or `biometrics-locked` |
| `lockout.biometric`, `lockout.reset` | biometrics switched off; lockouts cleared by root |
| `enroll`, `delete` | enrolment changes (method, id, caller uid) |
| `policy.reload` | SIGHUP |

Records never contain secrets, scores, images or audio. Strings are JSON-escaped, so a crafted service or user name cannot forge a field or a line.

## Consequences

- `Manager1` gains `GetLockout(uid)` (self or root) and `ResetLockout(uid)` (root). `tuxhello list` explains any active limit; `tuxhello unlock` clears them.
- A user who keeps failing is sent to the password quickly instead of being asked again and again.
- Anyone who can attempt logins as a user can switch that user's biometrics off. They cannot lock the user out: the PIN, key and password still work.
