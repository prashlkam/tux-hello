# ADR 0009: Fingerprint backend via fprintd

- **Status:** Accepted (implemented in Phase 1, milestone 5)
- **Date:** 2026-11-09

## Decision

Tux Hello is a **client of fprintd**, as PLAN.md §5.3 intended:
- fprintd and libfprint own the drivers and the stored prints;
- the daemon only verifies, lists and deletes;
- enrolment is fprintd's own job.

| Operation | How |
|---|---|
| Verify | `Claim(user)` → `VerifyStart("any")` → follow `VerifyStatus` signals → `VerifyStop` + `Release` |
| Enrol | `tuxhello enroll fingerprint [--finger F]` runs `fprintd-enroll`, which has good progress UI. Prints written by `fprintd-enroll` or GNOME/KDE settings are used as well. |
| List | `ListEnrolledFingers(user)`, merged into `tuxhello list` |
| Delete | `Claim(user)` → `DeleteEnrolledFinger(s)` → `Release` (`tuxhello delete fingerprint FINGER`) |

### Verification details

- **Subscribe first:** the daemon subscribes to `VerifyStatus` **before** `VerifyStart`, so no result can be missed.
- **Three tries:** up to 3 tries per authentication (`[fingerprint] max_tries`).
- **Scan problems:** "retry", "swipe too short", "not centred" and "remove and retry" show a hint and keep the same try.
- **No match:** `verify-no-match` reports "not recognised" and starts the next try.
- **The reader is never left claimed.** A drop guard sends `VerifyStop` + `Release` when the session ends for any reason: success, policy timeout, PAM timeout, or cancel. The integration suite checks that the next login works straight after a timed-out one.
- **Assurance:** 3 by default (`[fingerprint] assurance`). That suits match-on-chip sensors such as the Synaptics, Goodix and Elan readers in current laptops. Lower it for host-matched or swipe sensors. fprintd doesn't say which kind a reader is.

### Backend interface change

Whether fingerprint can be offered depends on asking fprintd, which is asynchronous. The backend trait therefore gained an async `usable(user, uid)`. Its default is `available() && is_enrolled()`, so the PIN and key backends are unchanged. `BeginAuth` and `ExplainPolicy` await it.

### Authorisation

fprintd checks callers with polkit. Its defaults allow verify only for the **active session**, and acting for another user (`setusername`) only for admins. `tuxhellod` runs as the `tuxhello` system user, which has no session.

We confirmed this in a container: that user gets `Not Authorized: net.reactivated.fprint.device.setusername` until a rule is added. `data/polkit/50-tuxhello-fprintd.rules` grants that **one account** exactly:
- `verify`;
- `setusername`, to claim the reader for the user who is logging in;
- `enroll`, which fprintd also requires for deleting prints.

Root (used in tests) is allowed by fprintd's defaults.

## Testing

- **Virtual sensor:** libfprint ships a virtual device (`FP_VIRTUAL_DEVICE=<socket>`). The container suite runs real polkitd and fprintd with it. A small C helper (`tests/integration/th-fpscan.c`) "touches" the sensor once it starts listening.
- **What it covers:**
  - enrolment through `tuxhello enroll fingerprint`;
  - listing, and policy showing fingerprint as usable;
  - a matching finger, for both a root caller and a user authenticating as itself;
  - an unknown finger rejected after 3 tries;
  - a retry hint followed by a match;
  - a policy timeout followed by a successful login (the reader was released);
  - 3 wrong fingers falling back to the PIN;
  - deletion.
- **Real hardware:** checked live against the host's fprintd with a Synaptics match-on-chip reader (`06cb:00f0`). The reader is detected and the absence of prints is reported correctly. A real-finger login still needs the user to enrol a finger.

## Not done yet

- Detecting match-on-chip readers automatically, to set assurance per device.
- The biometric lockout from PLAN.md §6.3: after 5 failed biometric attempts, require the PIN or password.
- Multiple readers: today the default device is used.
