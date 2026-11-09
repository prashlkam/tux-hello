# ADR 0007: PIN, secret prompts, policy evaluation and the management API

- **Status:** Accepted (implemented in Phase 1, milestone 2)
- **Date:** 2026-11-09

## 1. Secret prompts over the long-poll protocol

Interactive methods (the PIN today) need the user to type something through the application's PAM conversation. The protocol gains one event state and one method; the `Wait` signature is unchanged.

```
Wait(...)  -> events: (method, "prompt", "PIN (empty to skip): ")
SubmitSecret(s session_id, s method, s secret)   # empty = skip this method
```

- The PAM module answers a `prompt` event with `PAM_PROMPT_ECHO_OFF`, sends the answer, then wipes and frees libpam's copy.
- Only the session owner may answer, and only the method that asked. A prompt accepts one answer.
- Prompts are shown even under `PAM_SILENT`, because they need an answer. Info messages are not.
- **Typing time doesn't count against the module's timeout.** The module timeout (default now 30 s) is only a safety net. The daemon applies the policy's own timeout to the automatic methods.

## 2. Orchestration: automatic first, then interactive

A PAM prompt blocks the conversation: while the user types, the application can't show "fingerprint recognised". So the daemon runs:

1. **All automatic methods in parallel** (face, fingerprint, key), bounded by the policy `timeout_s`.
2. **Then interactive methods one at a time** (PIN, or a security key's own PIN), only if the policy is still unsatisfied **and** still satisfiable.
   - They are asked **strongest first**, so a key-PIN prompt (assurance 4) comes before the account PIN (2).
   - This order stops a secret meant for one prompt from being typed into another, where it would count as a wrong account PIN and move it towards lockout. The integration suite caught this case.

After every result the daemon checks the requirement tree:

- **satisfied:** finish with success; abort the other methods.
- **no longer satisfiable** with the methods not yet ruled out: finish at once. For example, `all = [fingerprint, pin]` with a failed fingerprint never asks for the PIN.

`any` takes the strongest branch. `all` adds its members' assurance levels (capped at 4), so two weak factors can meet a bar neither meets alone. `BeginAuth` refuses up front, with `NotEnrolled` (so PAM falls through instantly), when the enrolled methods could never satisfy the policy.

## 3. Software PIN

- **Storage:** the PIN is hashed with Argon2id (m = 64 MiB, t = 3, p = 1, random salt). The PHC string is kept as an AES-256-GCM record in the store, bound to (uid, method, id).
- **Assurance:** 2. A TPM-backed PIN (Phase 1, later milestone) will be 3.
- **Lockout:** after 5 consecutive failures the PIN locks for 30 s. The lock doubles with each further failure, up to 1 h. The counter is kept in an internal store record (`pin/_lockout`), so it survives restarts. An unreadable counter counts as locked.
  - The lock relies on the system clock; the TPM variant removes that weakness.
- **Per session:** up to 3 attempts (configurable). An empty answer skips to the next PAM module (the password).
- **Resetting:** re-enrolling resets the counter. Only root can enrol.

## 4. Management API: `org.tuxhello.Manager1` at `/org/tuxhello/Manager1`

| Method | Who may call |
|---|---|
| `GetInfo() -> a{ss}` | anyone |
| `ListEnrollments(u uid) -> a(ss)` | that user, or root |
| `ExplainPolicy(u uid, s service) -> a{ss}` | that user, or root |
| `DeleteEnrollment(u uid, s method, s id) -> b` | that user, or root (removing access is always safe) |
| `DeleteAll(u uid)` | that user, or root |
| `EnrollPin(u uid, s pin)` | **root only** for now |

Enrolment needs proof of identity. In Phase 1 that proof is `sudo`: the CLI runs as root, and `sudo` has already checked the password. `tuxhello enroll pin` acts on `$SUDO_USER` by default.

Self-service enrolment through polkit (`org.tuxhello.enroll-self`, `auth_self_keep`) needs a polkit authentication agent. It arrives with the GUI (Phase 3), where an agent is always present.

## 5. Policy loading

- The daemon loads the built-in policy plus `[policy] dirs` (default `/usr/share/tuxhello/policy.d`, then `/etc/tuxhello/policy.d`) at start and on **SIGHUP**.
- A policy that fails validation is rejected: at start-up the daemon exits, so PAM falls back to the password; on reload the previous policy stays in force.

## Consequences

- A user mid-way through a PIN prompt can't be rescued by a fingerprint touch. This is the inherent PAM limitation, the same as `pam_fprintd` followed by `pam_unix`.
- `tuxhello test` and PAM behave the same way, because both go through the same client loop.
