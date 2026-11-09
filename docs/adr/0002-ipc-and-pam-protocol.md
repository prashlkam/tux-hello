# ADR 0002: IPC between the PAM module and the daemon

- **Status:** Accepted (implemented in Phase 0)
- **Date:** 2026-11-09

## Context

`pam_tuxhello.so` is loaded into processes we don't control: `sudo` (setuid), display managers, screen lockers (often unprivileged), and polkit agents. It has to:

- reach a privileged daemon on every distro, with or without systemd;
- never crash, hang, or leave threads behind in the host process;
- relay progress text ("Looking for you…") to the application's PAM conversation;
- fall back to the password on any failure.

## Decisions

### 1. Transport: D-Bus system bus

The D-Bus system bus is present on every target distro, including non-systemd ones. It gives us:

- caller identity (`GetConnectionUnixUser`), so the daemon can tell who is asking;
- bus activation, so the daemon starts on demand;
- polkit integration later, for the management API.

A raw Unix socket would need our own activation and credential plumbing on every init system.

### 2. Two D-Bus libraries, chosen per side

- **PAM module and CLI: libdbus (`dbus` crate, blocking).** It spawns no threads and starts no async runtime, and each call has a hard timeout. libdbus is already a dependency of practically every desktop system.
- **Daemon: `zbus` on tokio.** It is pure Rust, async, and has an ergonomic server-side interface macro. Threads are fine in our own process.

zbus's blocking API runs an internal executor thread. That is acceptable in the daemon, but not inside `sudo` or a greeter.

### 3. Long-polling instead of signals

The draft API in PLAN.md §14.1 used `Progress` and `Finished` **signals**. We use **long-polling** instead:

```
BeginAuth(a{sv} context)              -> s session_id
Wait(s session_id, u timeout_ms)      -> (a(sss) events, s state, s method, u assurance)
Cancel(s session_id)
Version()                             -> s
ListBackends()                        -> a(sbu)
```

`Wait` returns as soon as new events exist or the session ends. Otherwise it returns after `timeout_ms`, capped at 5 s server-side.

Why:

- **Privacy:** signals on the system bus can be observed by other clients unless they are carefully unicast and policed. A long-poll reply goes only to the caller.
- **Simplicity in the PAM module:** no match rules, no callback dispatch, just a loop of blocking calls with timeouts.
- **No lost events:** events queue in the daemon until polled. The queue is bounded at 64 events, with the oldest dropped first.

A session is **bound to the unique bus name that created it**. Any other connection gets `NoSuchSession` for that id, the same error as for a nonexistent id. Session ids are random 128-bit values. Sessions are always destroyed after `session_lifetime_s`, which defaults to 60.

### 4. Who may authenticate whom

- A caller whose UID is 0 may authenticate any user. This covers `sudo`, `su`, root-run greeters and polkit's helper.
- Any other caller may only authenticate **its own** UID. This covers unprivileged screen lockers such as `swaylock` and the CLI's `test` command.

This mirrors `unix_chkpwd` and stops local users from using the daemon as a biometric oracle against other accounts.

### 5. PAM return codes

| Situation | Return |
|---|---|
| Match | `PAM_SUCCESS` |
| Backend ran, no match | `PAM_AUTH_ERR` |
| Daemon unreachable, D-Bus error, not enrolled, unknown user, access denied, timeout, panic | `PAM_AUTHINFO_UNAVAIL` |
| Remote session (`PAM_RHOST` set to a non-local host, or service `sshd`/`xrdp-sesman`/`cockpit`) | `PAM_IGNORE` |

With `auth sufficient pam_tuxhello.so`, every code except `PAM_SUCCESS` continues to the next module, which is the password. The integration test checks this for each case, including a daemon killed in the middle of a session.

## Consequences

- Clients poll at most once per event or once per 5 s, which is negligible.
- A future GUI overlay, which needs progress for a session it doesn't own, will need a separate, owner-checked subscription API. That is deferred to Phase 3.
- PLAN.md §14.1 has been updated to match.
