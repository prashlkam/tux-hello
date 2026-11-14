# Tux Hello — Implementation Plan

> A Windows Hello–style multi-factor authentication framework for Linux.
> Sign in, unlock, `sudo`, and approve polkit prompts with a **PIN, face, fingerprint, voice, or hardware security key**,
> on any desktop environment / window manager and any major distribution.

*Status: planning · Drafted 2026-11-09*

---

## Table of contents

1. [Goals and non-goals](#1-goals-and-non-goals)
2. [Key design decision: PAM is the universal integration point](#2-key-design-decision-pam-is-the-universal-integration-point)
3. [Architecture](#3-architecture)
4. [Components in detail](#4-components-in-detail)
5. [Authentication methods](#5-authentication-methods)
6. [Policy engine](#6-policy-engine)
7. [Storage, secrets and the keyring problem](#7-storage-secrets-and-the-keyring-problem)
8. [Desktop environment / window manager integration](#8-desktop-environment--window-manager-integration)
9. [Distribution support and packaging](#9-distribution-support-and-packaging)
10. [Security and privacy](#10-security-and-privacy)
11. [User experience](#11-user-experience)
12. [Technology stack](#12-technology-stack)
13. [Repository layout](#13-repository-layout)
14. [Interfaces (D-Bus API, config format, CLI)](#14-interfaces)
15. [Testing strategy](#15-testing-strategy)
16. [Roadmap and milestones](#16-roadmap-and-milestones)
17. [Risks and mitigations](#17-risks-and-mitigations)
18. [Prior art](#18-prior-art)
19. [Open questions](#19-open-questions)

---

## 1. Goals and non-goals

### Goals

| # | Goal |
|---|------|
| G1 | Five authentication methods: **PIN, face, fingerprint, voice, FIDO2 security key**. |
| G2 | Works everywhere PAM works: display managers, screen lockers, `sudo`/`su`, polkit, TTY login — independent of DE/WM, X11 or Wayland. |
| G3 | Installs cleanly on Arch, Debian/Ubuntu, Fedora/RHEL, openSUSE, NixOS, Gentoo, Void, Alpine — systemd **and** non-systemd init. |
| G4 | **Never lock a user out.** The password always remains a fallback; installing/uninstalling cannot break login. |
| G5 | Configurable policy: which methods, for which services, alone or combined (e.g. `sudo` = face AND key). |
| G6 | Biometric data stays on the machine, is encrypted at rest, and is TPM-bound where a TPM exists. |
| G7 | Good UX: enrollment GUI + CLI, live feedback ("Looking for you…"), fast (< 1 s face unlock on typical hardware). |
| G8 | Extensible: new methods are plugins implementing a stable backend interface. |

### Non-goals (v1)

- Replacing the password entirely / passwordless account creation.
- Network or domain authentication (Active Directory, Kerberos, SSO). Biometrics are **disabled for remote sessions** (SSH, XRDP) by design.
- Full-disk-encryption unlock at boot (initramfs). Planned as a post-1.0 stretch goal (see §16, Phase 6).
- Mobile/phone-as-authenticator (possible future plugin via caBLE/hybrid FIDO).

---

## 2. Key design decision: PAM is the universal integration point

Every Linux login path — GDM, SDDM, LightDM, greetd, `swaylock`, `hyprlock`, `i3lock`, `sudo`, polkit agents, `login` — authenticates through **PAM** (Pluggable Authentication Modules). Building on PAM gives DE/WM independence: one module, `pam_tuxhello.so`, plugs into any of them.

Writing directly into each DE is not portable, and running biometric pipelines inside a PAM module is not safe: the module would execute inside `sudo`, the greeter, and the screen locker, with each one's privileges and lifetime. So the design splits into:

- a **thin PAM module** (small, auditable, no ML, no device access), which talks over a local socket to
- a **privileged system daemon** (`tuxhellod`), which owns the hardware, the templates and the policy, and runs each method in a **sandboxed backend process**.

The same pattern is used by `fprintd` + `pam_fprintd` and Windows Hello's Biometric Service.

---

## 3. Architecture

```
 ┌──────────────────────── Consumers (any DE / WM / CLI) ──────────────────────────┐
 │ GDM · SDDM · LightDM · greetd · ly │ swaylock · hyprlock · i3lock · kscreenlocker│
 │ gnome-shell lock · xsecurelock      │ sudo · su · polkit agents · login (TTY)    │
 └───────────────────────────────┬─────────────────────────────────────────────────┘
                                 │  PAM conversation (text prompts / info msgs)
                       ┌─────────▼──────────┐
                       │  pam_tuxhello.so   │  thin, no ML, no device I/O
                       └─────────┬──────────┘
                                 │  D-Bus system bus  (org.tuxhello.Auth1)
 ┌───────────────────┐  ┌────────▼───────────────────────────────────────┐
 │ tuxhello-gui      │  │                  tuxhellod                      │
 │ (GTK4 / KCM)      ├─►│  ┌─────────────┐ ┌────────────┐ ┌────────────┐  │
 │ tuxhello CLI/TUI  │  │  │Policy engine│ │Session mgr │ │Rate limiter│  │
 │ tuxhello-overlay  │◄─┤  └─────────────┘ └────────────┘ └────────────┘  │
 └───────────────────┘  │  ┌──────────────────────────────────────────┐   │
   (signals: progress,  │  │ Template store (encrypted; TPM-sealed key)│   │
    camera preview fd)  │  └──────────────────────────────────────────┘   │
                        └──┬──────────┬──────────┬──────────┬─────────┬───┘
                 varlink / │ socketpair (sandboxed child processes)  │
              ┌────────────▼┐ ┌───────▼─────┐ ┌──▼───────┐ ┌▼───────┐ ┌▼──────────┐
              │ backend-pin │ │ backend-face│ │backend-fp│ │b-voice │ │backend-key│
              │ Argon2/TPM2 │ │ V4L2 + ONNX │ │→ fprintd │ │ALSA+ONNX│ │ libfido2  │
              └─────────────┘ └─────────────┘ └──────────┘ └────────┘ └───────────┘
```

### Authentication flow (example: `sudo` with policy "face OR fingerprint, fallback PIN")

1. `sudo` calls `pam_authenticate()` → `pam_tuxhello.so`.
2. The module gathers context (user, PAM service, TTY, `PAM_RHOST`, whether the session is remote or a greeter) and calls `BeginAuth(context)` on `tuxhellod`.
3. The daemon resolves the policy for (user, service) → `any_of[face, fingerprint]`, `fallback: pin`.
4. The daemon starts the face and fingerprint backends **in parallel**. It emits `Progress` signals ("Looking for face…", "Touch the sensor…"). The PAM module relays them as `PAM_TEXT_INFO`.
5. The first backend to succeed wins; the others are cancelled. The daemon returns `Success` plus an assurance level.
6. If all fail, or time out, or hit a lockout: the daemon returns `NeedFallback(pin)`. The module issues a `PAM_PROMPT_ECHO_OFF` "PIN:" prompt and sends the PIN to the daemon, which verifies it.
7. If the module returns `PAM_AUTHINFO_UNAVAIL` / `PAM_IGNORE`, PAM falls through to `pam_unix` (password). **The password always works.**

---

## 4. Components in detail

### 4.1 `pam_tuxhello.so` — PAM module

- Implements `pam_sm_authenticate`, `pam_sm_setcred`, and optionally `pam_sm_open_session` (keyring hand-off, §7.3).
- Written in Rust (`cdylib`, using the `pamsm` crate) with a minimal C ABI surface. Target: under 1500 lines, no allocations in signal paths, no threads it can't join.
- Module arguments, for example `auth sufficient pam_tuxhello.so methods=face,fingerprint timeout=5 fallback=pin`. Arguments can **narrow** but never **widen** the daemon policy.
- Return codes are chosen so that failures fall through safely:
  - `PAM_SUCCESS`: authenticated.
  - `PAM_AUTH_ERR`: explicit reject (rarely used; only after a definitive PIN failure in strict stacks).
  - `PAM_AUTHINFO_UNAVAIL`: daemon unreachable, no hardware, no enrollment, remote session → next module (password).
  - `PAM_IGNORE`: disabled for this service.
- Detects remote sessions (`PAM_RHOST`, `SSH_CONNECTION`, the logind session `Remote=yes`) and refuses biometrics there.
- Handles conversation functions that can't display info messages (some lockers): it degrades to a single prompt "PIN or press Enter for face/fingerprint:".
- Cancellation: honours `SIGINT` during `sudo` and conversation aborts. Sends `Cancel()` to the daemon.

### 4.2 `tuxhellod` — system daemon

- Runs as a dedicated `tuxhello` system user. It gets device access through group membership (`video`, `audio`, `plugdev`) and udev `uaccess`-style rules. It does **not** run as root. Template storage is owned by `tuxhello:tuxhello 0700`.
- Exposes **`org.tuxhello.Auth1`** (authentication, used by PAM) and **`org.tuxhello.Manager1`** (enrollment and management, used by GUI/CLI, polkit-gated) on the D-Bus **system** bus.
- Bus activation works with or without systemd. Init service files are provided for systemd, OpenRC, runit, s6, and dinit.
- Responsibilities: policy evaluation, parallel backend orchestration, rate limiting and lockout, template encryption/decryption, audit logging, and hardware hot-plug (udev monitor).
- Caller verification: authentication sessions are bound to the calling PID/UID through `GetConnectionCredentials`. Only root-owned callers (PAM runs in a privileged context: `sudo` is setuid, greeters run as root or the greeter user) can complete `BeginAuth` for **another** user. An unprivileged user can only authenticate **as themself** (needed for unprivileged screen lockers such as `swaylock`). This mirrors `unix_chkpwd` semantics.
- Hardening (systemd unit): `ProtectSystem=strict`, `PrivateNetwork=yes`, `NoNewPrivileges=yes`, `RestrictAddressFamilies=AF_UNIX`, `SystemCallFilter=@system-service`, `DeviceAllow=` limited to `/dev/video*`, `/dev/snd/*`, `/dev/hidraw*`, `/dev/tpmrm0`. Non-systemd builds apply the same restrictions with **Landlock + seccomp** inside the daemon.

### 4.3 Backends (one sandboxed process per method)

- Spawned on demand by the daemon over a `socketpair`, using a small varlink-style JSON or bincode RPC.
- Each backend gets **only** the device fds it needs (passed by the daemon) and its model files. It has no filesystem write access, no network, and a tight seccomp filter.
- A crash or hang in a backend (for example an ONNX runtime bug) cannot take down the daemon or the PAM caller. The daemon applies a watchdog timeout.
- Stable **Backend trait/protocol**, so third parties can add methods (e.g. an iris scanner or a smartwatch proximity unlock):

```rust
trait Backend {
    fn capabilities(&self) -> Capabilities;            // devices present, assurance level, liveness support
    fn enroll(&mut self, user: Uid, sink: ProgressSink) -> Result<TemplateBlob>;
    fn verify(&mut self, user: Uid, templates: &[TemplateBlob], sink: ProgressSink, cancel: CancelToken)
        -> Result<VerifyOutcome>;                      // Match{score, liveness} | NoMatch | Unavailable
    fn delete(&mut self, user: Uid, template_id: Id) -> Result<()>;
}
```

### 4.4 Client applications

| Component | Purpose |
|---|---|
| `tuxhello` (CLI) | Enroll, list, delete, test, and set policy. Scriptable (`--json`). Works over SSH for admins (enrollment of face/voice needs local devices). |
| `tuxhello-tui` | Ratatui front end for TTY-only and WM users. |
| `tuxhello-settings` (GTK4 + libadwaita) | Primary GUI: enrollment wizards with camera preview, policy toggles. Works on any DE. |
| `kcm_tuxhello` (Qt6/QML) | Native KDE System Settings module (Phase 5). |
| `tuxhello-overlay` | Optional feedback indicator during unlock: a small "face scanning" animation. Uses `wlr-layer-shell` on Wayland compositors that support it (Sway, Hyprland, river, KDE, Wayfire), an override-redirect window on X11, and nothing on GNOME (GNOME Shell shows PAM messages natively). |
| GNOME Shell extension (optional) | Nicer lock-screen integration (face icon, status) on GNOME. |

---

## 5. Authentication methods

Each method has an **assurance level**, which the policy engine uses (higher = stronger):

| Method | Assurance | Default role | Notes |
|---|---|---|---|
| Security key (FIDO2, UV) | 4 | Primary or second factor | Phishing-resistant, hardware-backed. |
| PIN (TPM-backed) | 3 | Primary fallback | Hardware lockout makes short PINs safe. |
| Fingerprint | 3 | Primary | Match-on-chip sensors are strongest. |
| Face (IR + liveness) | 3 | Primary | RGB-only camera → level 1, opt-in only. |
| PIN (no TPM) | 2 | Fallback | Software rate limiting only. |
| Voice | 1 | Convenience / second factor only | Replay- and deepfake-prone; never allowed alone for `sudo`/polkit by default. |

### 5.1 PIN

- **Enrollment:** the user sets a PIN (default minimum 4 digits; alphanumeric allowed; complexity policy configurable). Password re-authentication is required.
- **With TPM 2.0** (preferred, as in Windows Hello):
  - A per-user TPM object is sealed with **the PIN as its `authValue`**, under the storage root key. It uses `tpm2-tss` ESAPI via the `tss-esapi` crate.
  - The TPM's **dictionary-attack lockout** enforces attempt limits in hardware, so offline brute force is impossible even with the disk image.
  - The unsealed secret also wraps the user's "keyring escrow" key (§7.3).
- **Without TPM:** Argon2id (memory 64 MiB, t=3) hash plus a per-user salt, stored in the encrypted store. Software lockout applies: 5 failures → 30 s, growing exponentially, persisted across reboots.
- PIN comparison never happens in the PAM module. The PIN is passed to the daemon over D-Bus (system bus, local only) and zeroized with `zeroize` after use.

### 5.2 Face recognition

- **Capture:** V4L2 directly (the `v4l` crate). Pipewire/portals are not used, because at the greeter there is no user session. The camera is opened only during an active auth session and released immediately.
- **IR cameras (strongly preferred):**
  - Auto-detect IR nodes by format (`GREY`/`Y8`) and udev properties. Provide a curated quirks database.
  - Integrate IR emitter activation: ship or reuse the logic from `linux-enable-ir-emitter` (UVC extension-unit control), with a guided "make my emitter blink" setup step.
- **Pipeline** (ONNX Runtime, CPU by default; optional OpenVINO / CUDA / ROCm execution providers):
  1. **Detection:** YuNet or a similar small detector (permissively licensed; see §17 licensing risk).
  2. **Alignment:** 5-point landmarks → similarity transform to 112×112.
  3. **Quality gate:** reject blur, extreme pose, occlusion, or bad exposure, with a hint to the user ("Move closer").
  4. **Liveness / anti-spoofing:**
     - IR: printed photos and screens look very different in near-IR (screens appear dark). Use an IR texture classifier.
     - Optional depth (structured light / ToF cameras, where present).
     - RGB-only: passive anti-spoof CNN plus optional active challenge (blink / turn head). Always flagged as low assurance.
  5. **Embedding:** ArcFace-style 512-d embedding (e.g. SFace / MobileFaceNet class).
  6. **Matching:** cosine similarity against enrolled embeddings. Threshold calibrated per model to a target **FAR ≤ 1:100 000** at an acceptable FRR. Choose from the best of N frames within the timeout.
- **Enrollment:** guided capture of ~15–30 frames across poses and lighting. Optional "add glasses / no glasses" appearance. Embeddings only are stored by default (no raw images); debug image capture is opt-in and local only.
- **Adaptive templates (opt-in):** after high-confidence matches, add the embedding to a rolling set, to handle beards, haircuts and ageing. Capped in size, with a minimum-confidence floor to prevent template poisoning.
- **Performance target:** < 700 ms end-to-end on a 4-core laptop CPU; < 150 MB RSS for the backend.
- **Privacy:** respect camera kill switches and the privacy LED (never drive the camera without the LED). Abort if the lid is closed (logind `LidClosed`), and skip face auth when the external-monitor/lid-closed configuration makes the camera useless.

### 5.3 Fingerprint

- **Do not reimplement drivers.** Delegate to **`fprintd` / `libfprint`** over D-Bus (`net.reactivated.Fprint`). They already support hundreds of sensors and are packaged everywhere.
- `backend-fingerprint` is an adapter: it enumerates devices, claims the device for the user, and calls `VerifyStart` / `EnrollStart`, mapping signals to tux-hello progress events.
- Conflict handling: if `pam_fprintd` is also in the stack, the setup tool offers to replace it so the two don't double-prompt.
- Match-on-chip sensors (e.g. Synaptics Prometheus, most modern Goodix/Elan with TOD drivers) are reported as assurance 3. Host-matched sensors are reported as 2.
- If fprintd is absent, the method is reported as unavailable; it is not an error.

### 5.4 Voice

- Treated honestly as the **weakest** method: modern voice cloning makes standalone voice auth unsafe. Defaults: **allowed only as a second factor or for low-risk services** (e.g. screen unlock), never `sudo` alone.
- **Capture:** ALSA directly via `cpal` (there is no user PipeWire session at the greeter). After login, it can optionally use the user's PipeWire through a portal for the overlay's level meter only. Hot-plug headsets are handled.
- **Anti-replay (text-prompted):** the daemon generates a **random 6-digit challenge** shown on screen ("Say: 4 9 1 7 3 0"). Verification requires:
  1. **ASR check:** a small offline ASR (Vosk / Whisper-tiny, digit-constrained grammar) confirms that the spoken digits match the challenge.
  2. **Speaker verification:** ECAPA-TDNN-class embedding (192-d) with cosine scoring against enrolled embeddings.
  3. **Spoof/deepfake detection:** an AASIST-class anti-spoofing model (replay and synthetic-speech detection). A low score rejects.
- VAD (Silero-class) trims silence; SNR is checked ("Too noisy, try again").
- **Enrollment:** 5–8 utterances of random digit strings, in a quiet environment.
- **Accessibility value:** useful for users who can't use a fingerprint sensor or camera. Pair it with a PIN for meaningful security.
- **The PAM conversation must be able to display the challenge.** If the conversation can't show info messages, voice is skipped for that service.

### 5.5 Security key (FIDO2 / U2F)

- `libfido2` (via FFI or the `ctap-hid-fido2` crate; decide in Phase 0). Keys are compatible with YubiKey, SoloKeys, Nitrokey, Google Titan, and platform authenticators.
- **Enrollment:** create a resident or non-resident credential with RP ID `pam://tuxhello` (configurable). Store the credential ID and public key in the store. Supports **multiple keys per user** (backup key recommended in the UI).
- **Verification:** `getAssertion` with a fresh random challenge, then verify the signature against the stored public key. Verify user presence (touch). User verification (the key's own PIN or biometric) is required when policy demands assurance 4.
- **hmac-secret extension:** used to derive a per-user wrapping key, enabling passwordless keyring unlock (§7.3) and future LUKS unlock.
- **Import:** import existing `pam_u2f` `u2f_keys` mappings, for easy migration.
- Optional (Phase 6): PIV/smartcard via PKCS#11 (`p11-kit`) for enterprise CAC cards.

---

## 6. Policy engine

### 6.1 Model

A policy is resolved by merging, from lowest to highest precedence:

1. built-in defaults,
2. `/usr/share/tuxhello/policy.d/*.toml` (vendor/distro),
3. `/etc/tuxhello/policy.d/*.toml` (admin),
4. per-user overrides (`/var/lib/tuxhello/users/<uid>/policy.toml`, editable via the GUI within admin-set bounds).

Rules match on **PAM service** (`sudo`, `polkit-1`, `gdm-password`, `sddm`, `swaylock`, …), service **class** (`login`, `unlock`, `elevate`, `other`), user/group, and session properties (local/remote, seat).

### 6.2 Expressions

```toml
[class.unlock]          # screen lockers
require = { any = ["face", "fingerprint", "pin", "key", "voice"] }
parallel = true
timeout_s = 8

[class.login]           # greeters: first login after boot
require = { any = ["face", "fingerprint", "pin", "key"] }
first_login_after_boot = "password"   # like Windows / phones: password once per boot

[class.elevate]         # sudo, polkit, su
require = { any = [
  "key",
  "fingerprint",
  "face",
  { all = ["voice", "pin"] },         # voice only as a second factor
]}
min_assurance = 3
timeout_s = 15

[service."sudo"]
inherit = "elevate"

[group."wheel".class.elevate]
require = { all = ["face", "key"] }   # example: stricter for admins
```

### 6.3 Lockout and adaptive rules

- 5 consecutive biometric failures → biometrics disabled for that user until a PIN or password succeeds (Windows behaviour).
- PIN: TPM DA lockout or software exponential backoff.
- Biometrics are disabled for 48 h of inactivity, or after admin-triggered "require password" (configurable).
- First login after boot requires the password (configurable). This is also what makes keyring unlock clean (§7.3).
- Panic switch: `tuxhello lockdown` (or a configurable hotkey hint) immediately requires the password until next password login. This is analogous to iOS "SOS lockdown".

---

## 7. Storage, secrets and the keyring problem

### 7.1 Layout

```
/etc/tuxhello/                 config.toml, policy.d/          (root:root 0644)
/usr/share/tuxhello/models/    *.onnx + SHA256SUMS + signature  (read-only)
/var/lib/tuxhello/             (tuxhello:tuxhello 0700)
  ├── store.key.sealed         TPM-sealed master key (or file-key fallback)
  └── users/<uid>/
       ├── meta.toml           enrolled methods, created/last-used timestamps
       ├── face.tmpl.enc       AES-256-GCM encrypted embeddings
       ├── voice.tmpl.enc
       ├── key.creds.enc       FIDO2 credential IDs + public keys
       ├── pin.tpm / pin.argon2.enc
       └── escrow.enc          optional keyring escrow (see 7.3)
/var/log or journald           audit log (no biometric data)
```

### 7.2 Encryption

- A per-machine **master key** encrypts all templates (AES-256-GCM, per-file nonce; the AAD binds the uid and method).
- With a TPM: the master key is sealed to the TPM with a PCR policy (optional, default **off**, because PCR-bound keys break on firmware updates; offer PCR 7 binding as an opt-in).
- Without a TPM: the master key is stored as a file (0600 `tuxhello`). This is weaker, and is documented as such. The UI shows "Hardware protection: unavailable".
- Templates are **non-portable** by design: copying `/var/lib/tuxhello` to another machine yields nothing usable.
- Backup/restore: export is supported **only for FIDO2 credential metadata and policy**, never biometric templates.

### 7.3 The keyring problem (important)

Login with a biometric or PIN means the session never sees the password. As a result, **GNOME Keyring / KWallet / KeePassXC (auto-unlock)** stay locked, and so do `ecryptfs`/`fscrypt` home directories. Windows solves this with TPM-protected credential escrow. Plan:

1. **Default (Phase 1–3):** the first login after boot requires the password (§6.3), so the keyring unlocks normally. Biometrics are used for lock-screen unlock, `sudo`, and polkit. This covers most real-world value with no new risk.
2. **Opt-in escrow (Phase 4):**
   - On a password login, `pam_tuxhello` (in the `auth` + `session` phase) offers to store the login password encrypted under a key that can only be released by a successful strong auth. The key is a TPM object whose policy requires the PIN authValue, or a FIDO2 `hmac-secret`.
   - On a later biometric or PIN login, the daemon releases the password into the PAM stack (`PAM_AUTHTOK`). `pam_gnome_keyring` / `pam_kwallet5` then unlock exactly as with a typed password.
   - Face/fingerprint alone can release the escrow only when the TPM is present **and** the template store key is TPM-sealed. This is clearly explained in the UI as a security trade-off, and is disabled by default.
   - The escrow is invalidated automatically on password change (via a `pam_sm_chauthtok` hook in the `password` stack).
3. **Future:** `systemd-homed` integration (FIDO2/PKCS#11 already supported there), and `fscrypt` protector integration.

---

## 8. Desktop environment / window manager integration

### 8.1 Integration matrix (targets for v1.0)

| Consumer | PAM service | Integration approach | Known quirks |
|---|---|---|---|
| **GDM** | `gdm-password`, `gdm-fingerprint`, `gdm-smartcard` | Add to `gdm-password`; GDM shows `PAM_TEXT_INFO` natively. Optional Shell extension for an icon. | GDM runs fingerprint as a separate parallel stack; disable `gdm-fingerprint` to avoid double prompts when using our fingerprint. |
| **GNOME lock screen** | `gdm-password` (unlock) | Same stack as above. | — |
| **SDDM** | `sddm` | Add to stack. Info messages show in most themes. | Some themes ignore info messages → overlay helps. Auth starts after pressing Enter in the password field → document "press Enter for face". |
| **KDE kscreenlocker** | `kde` | Add to stack. Plasma 6 supports a separate fingerprint/smartcard stack (`kde-fingerprint`). | Provide both `kde` and `kde-fingerprint` snippets. |
| **LightDM** (GTK/slick greeters) | `lightdm` | Add to stack; messages display. | — |
| **greetd** (tuigreet, gtkgreet, ReGreet) | `greetd` | Add to stack; greetd forwards info messages. | tuigreet shows info lines; fine. |
| **ly / lemurs / emptty** | `ly`, … | Add to stack. | Text-only; prompts degrade gracefully. |
| **swaylock / swaylock-effects** | `swaylock` | Add to stack. | PAM runs only after Enter → "press Enter (empty) to scan". Provide a `swaylock` patch/PR upstream for auto-start. |
| **hyprlock** | `hyprlock` | Add to stack. hyprlock natively runs `pam` + `fprintd` in parallel. | Disable hyprlock's own fprintd to avoid conflicts. |
| **i3lock / i3lock-color, xsecurelock, xscreensaver, gtklock, waylock** | respective | Add to stack. | Same Enter-to-start caveat; xsecurelock shows messages. |
| **sudo / su / doas*** | `sudo`, `su` | Add to stack. Terminal shows text info. | *`doas` on Linux (OpenDoas) uses PAM when built with it; document it. |
| **polkit** (GNOME, KDE, lxqt-policykit, polkit-gnome, hyprpolkitagent, mate) | `polkit-1` | Add to stack. | Agents show info messages; the overlay covers bare WMs. |
| **TTY login** | `login` | Add to stack. | Text only. |
| **SSH** | `sshd` | **Explicitly excluded.** The module returns `PAM_IGNORE` for remote sessions. | — |

### 8.2 Making "press Enter" lockers feel instant

- Problem: many lockers only call `pam_authenticate()` after the user submits input.
- Mitigations:
  1. Accept an empty submission as "start biometrics" (the module returns quickly to a PIN prompt if biometrics fail).
  2. Contribute small upstream patches ("auto-start PAM on lock") to swaylock, i3lock-color, and gtklock.
  3. Ship `tuxhello-lock-helper`. It watches logind `Lock`/`Unlock` and the `PrepareForSleep` signal and pre-warms the camera/models, cutting first-frame latency.

### 8.3 Feedback when the consumer can't show messages

`tuxhello-overlay` subscribes to the daemon's `Progress` signal for the current session (filtered by the logind session ID; only the session owner may subscribe) and shows a minimal, non-interactive indicator. It is autostarted via XDG autostart, `systemd --user`, or a WM `exec` line. The README provides snippets for Sway, Hyprland, i3, bspwm, river, and others.

### 8.4 Wayland vs X11

The core is display-server agnostic: PAM and the daemon never touch the display. Only the optional overlay and GUI have display code, and both support Wayland (including layer-shell) and X11.

---

## 9. Distribution support and packaging

### 9.1 Target distributions (CI-tested)

| Family | Versions | Package | PAM config mechanism | Init |
|---|---|---|---|---|
| Arch / EndeavourOS / Manjaro | rolling | AUR `tuxhello`, later `[extra]` | manual edit of `/etc/pam.d/*` (via our setup tool) | systemd |
| Debian / Ubuntu / Mint / Pop!_OS | Debian 13+, Ubuntu 24.04+ | `.deb`, PPA, Debian upstream submission | **`pam-auth-update`** profile in `/usr/share/pam-configs/tuxhello` | systemd |
| Fedora / RHEL / Alma / Rocky | Fedora 42+, EL 10 | `.rpm`, COPR, then Fedora official | **`authselect`** feature `with-tuxhello` (custom profile or upstream PR) | systemd |
| openSUSE Tumbleweed / Leap | TW, Leap 16 | OBS | **`pam-config`** module | systemd |
| NixOS | 25.05+ | nixpkgs + NixOS module `services.tuxhello` and `security.pam.services.<name>.tuxhello` | declarative | systemd |
| Gentoo | — | ebuild (GURU overlay, then main tree) | manual + `sys-auth/pambase` USE flag | OpenRC / systemd |
| Void | — | xbps-src template | manual | runit |
| Alpine / postmarketOS | 3.21+ | apk | manual (Linux-PAM) | OpenRC |
| Artix | — | uses Arch package plus `-openrc`/`-runit`/`-dinit`/`-s6` service packages | manual | various |

### 9.2 Packaging layout

Split packages so that headless or minimal systems don't pull in GTK:

- `tuxhello` (daemon + PAM module + CLI + PIN + key backends)
- `tuxhello-face` (face backend + models; pulls `onnxruntime`)
- `tuxhello-voice` (voice backend + models)
- `tuxhello-fingerprint` (thin adapter; depends on `fprintd`)
- `tuxhello-gtk`, `tuxhello-kcm`, `tuxhello-overlay`
- `tuxhello-openrc` / `-runit` / `-s6` / `-dinit` service files

The GUI is also available as a **Flatpak** that talks to the system daemon over D-Bus. The daemon and PAM module themselves cannot be Flatpak or Snap.

### 9.3 `tuxhello-pam-setup` — safe PAM configuration

Editing PAM by hand is the #1 way users lock themselves out, so a dedicated tool handles it:

1. Detects the distro mechanism (`pam-auth-update` / `authselect` / `pam-config` / NixOS / manual).
2. Uses the native mechanism where available; otherwise it performs a **surgical, idempotent** edit: it inserts `auth sufficient pam_tuxhello.so` before `pam_unix.so` in the selected services, marked with `# tuxhello-begin/end` markers.
3. **Before any change:** backs up `/etc/pam.d` to `/var/lib/tuxhello/pam-backup/<timestamp>/`, validates syntax, and runs a dry-run auth with `pamtester` against the password path to prove the fallback still works.
4. Detects conflicts (`pam_fprintd`, `pam_howdy`, `pam_u2f`) and offers to migrate or disable them.
5. `--rollback` restores the last backup. The package `prerm` script always removes our lines, so uninstalling restores the original stack.
6. Interactive mode lets the user choose the services (greeter, lock screen, sudo, polkit, TTY), with sensible defaults per detected DE.

### 9.4 Build system

- Cargo workspace for all Rust components, wrapped with **Meson** for installation paths (`pam_moduledir`, `dbus` system services dir, `polkit` actions, `udev` rules, `systemdsystemunitdir` via `pkg-config`). Meson is familiar to every distro packager and handles multiarch `libdir` (e.g. `/usr/lib/x86_64-linux-gnu/security` vs `/usr/lib64/security`).
- Vendored-dependencies tarball for offline distro builds (Debian, Fedora, and Gentoo policies).
- Architectures: x86_64 and aarch64 first-class; riscv64 and ppc64le best-effort (ONNX Runtime availability gates face and voice there).
- ONNX Runtime: dynamic link to the distro package when available; otherwise a bundled build in `tuxhello-face`/`-voice`. A `tract` (pure Rust) fallback execution engine is used where ONNX Runtime is unavailable, at reduced speed.
- Models are downloaded **at build time**, hash-pinned and checked against `SHA256SUMS`, and shipped in packages. There is no runtime downloading.

---

## 10. Security and privacy

### 10.1 Threat model (summary)

| Threat | Mitigation |
|---|---|
| Photo/video/mask spoof (face) | IR camera + liveness model; RGB-only marked low assurance and disallowed for `elevate` by default. |
| Replay / synthetic voice | Random digit challenge + ASR check + anti-spoof model; voice not standalone for elevation. |
| Fingerprint fake (gelatin) | Depends on sensor; prefer match-on-chip; assurance reflects it. |
| PIN brute force | TPM DA lockout / persistent exponential backoff. |
| Stolen disk / offline attack on templates | Encrypted store; TPM-sealed master key; templates unusable off-machine. |
| Malicious local user abusing the daemon | Caller UID/PID verification; users can only auth as themselves; polkit for management; rate limiting per caller. |
| Compromised backend (parser bug in image/audio/ML) | Process isolation, seccomp, Landlock, no network, no FS write; watchdog. |
| Lock-out through misconfiguration | `sufficient` (not `required`) stacking, password fallback, `PAM_AUTHINFO_UNAVAIL` on errors, setup-tool dry runs and rollback. |
| Coercion / sleeping user | "Attention" check (eyes open, looking at the screen) for face; lockdown switch; first-login-after-boot password. |
| Remote auth via biometrics | Remote sessions detected and refused. |
| Tampered models | Models are read-only, root-owned, and hash-verified at daemon start. |
| Supply chain | Reproducible builds, signed releases (Sigstore + GPG), `cargo-deny` / `cargo-vet` / `cargo-audit` in CI, SBOM published. |

### 10.2 Security engineering practices

- Rust everywhere in the trusted path; `unsafe` only in FFI shims, which are audited and fuzzed.
- `zeroize` for PINs, keys, and escrowed passwords. Memory locking (`mlock`) for secrets. Core dumps disabled (`prctl(PR_SET_DUMPABLE, 0)`).
- Fuzzing (`cargo-fuzz`) for the D-Bus message parsers, backend RPC, template deserialization, and policy parsing.
- **Independent third-party security audit before 1.0**, plus a published `SECURITY.md` with a disclosure policy.
- Audit log entries contain who, what service, which method, the result, and the time. They **never** include scores that could aid attacks, images, or audio.

### 10.3 Biometric accuracy targets (measured, published)

| Method | FAR target | FRR target | Spoof acceptance (PAD) target |
|---|---|---|---|
| Face (IR) | ≤ 0.001 % | ≤ 5 % | ≤ 1 % on print/screen attacks |
| Face (RGB) | ≤ 0.01 % | ≤ 5 % | best-effort, documented |
| Voice | ≤ 1 % | ≤ 10 % | ≤ 5 % replay/TTS (ASVspoof-style eval) |
| Fingerprint | per libfprint driver | — | — |

Benchmarks are run on public datasets, **subject to dataset licences**, plus an internally collected, consented test set. The measured results are published in the docs; the targets alone are never claimed.

### 10.4 Privacy

- No telemetry, no network access (the daemon is network-namespaced off).
- Embeddings only; raw images and audio are never stored unless debug mode is explicitly enabled by the user.
- One-click "Delete all my biometric data" (GUI and CLI). Templates are removed automatically on `userdel` (via a hook or tmpfiles cleanup of unknown UIDs).
- A clear consent screen at enrollment explains what is stored. This helps with GDPR/BIPA-sensitive enterprise deployments.

---

## 11. User experience

### 11.1 First-run flow (GUI)

1. **Welcome / consent** → 2. **Password confirmation** (polkit) → 3. **Choose methods**. Hardware is auto-detected; unavailable methods are greyed out with the reason ("No IR camera found — RGB face unlock is less secure. Enable anyway?").
4. **Set PIN** (mandatory fallback when any biometric is enrolled, as in Windows).
5. **Enroll** face (live preview + pose guidance ring) / fingerprint (finger diagram, progress per touch) / voice (read challenges) / key (insert & touch; prompt for a backup key).
6. **Where to use it**: toggles for login, lock screen, sudo, and app permissions (polkit). This calls `tuxhello-pam-setup` through polkit.
7. **Test it**: a live "try unlocking" sandbox that runs the real auth path against a test PAM service, `tuxhello-test`.

### 11.2 Unlock UX principles

- Face and fingerprint start immediately and in parallel; the PIN prompt is always reachable.
- Messages are short and consistent: "Looking for you…", "Touch fingerprint sensor", "Say 4 9 1 7 3 0", "Insert and touch your security key", "Not recognised — enter PIN".
- Total biometric timeout defaults: 8 s for unlock, 15 s for elevation.
- **Accessibility:** all GUI flows are keyboard navigable and screen-reader labelled (AT-SPI). Voice and key methods serve users who can't use a camera or fingerprint. There are high-contrast overlay variants.
- **Localisation:** gettext; prompts are translated in the daemon based on the PAM caller's locale (`LANG` from the PAM environment).

---

## 12. Technology stack

| Concern | Choice | Rationale |
|---|---|---|
| Core language | **Rust** (MSRV pinned, edition 2024) | Memory safety in a security-critical path; good FFI; single static-ish binaries. |
| PAM bindings | `pamsm` (or a hand-written minimal FFI) | Small surface; `cdylib`. |
| IPC (clients ↔ daemon) | D-Bus system bus via **`zbus`** | Standard on every distro; polkit integration; works without systemd. |
| IPC (daemon ↔ backends) | `socketpair` + length-prefixed bincode/serde | No bus exposure for internal components. |
| Async runtime | `tokio` (daemon), sync code in PAM module | The PAM module must not spawn runtime threads in host processes like `sudo`. |
| TPM | `tss-esapi` (tpm2-tss) | Standard stack; uses `/dev/tpmrm0`. |
| FIDO2 | `libfido2` FFI (preferred, mature) | Same library as `pam_u2f` and `systemd-cryptenroll`. |
| Camera | `v4l` crate + custom IR handling | Works at the greeter without a session. |
| Audio | `cpal` (ALSA backend) | Works pre-session. |
| ML inference | **ONNX Runtime** (`ort` crate) + `tract` fallback | Fast, portable, multiple hardware accelerators. |
| Image processing | `image`, `fast_image_resize`, hand-written alignment | Avoid an OpenCV dependency (heavy, packaging pain). |
| Crypto | `aes-gcm`, `argon2`, `zeroize` (RustCrypto); no TLS stack needed | Audited crates, no network code at all. |
| Polkit | `zbus` calls to `org.freedesktop.PolicyKit1` | — |
| GUI | **GTK4 + libadwaita** via `gtk4-rs`/`relm4`; **Qt6/QML KCM** later | Native on GNOME and good everywhere; KCM for KDE users. |
| TUI | `ratatui` | — |
| Overlay | `smithay-client-toolkit` (layer-shell) + `x11rb` | Minimal, no toolkit. |
| Build/install | Cargo workspace + **Meson** wrapper | Distro-friendly install paths. |
| CI | GitHub/Forgejo Actions + QEMU VM matrix | Real PAM / greeter tests need VMs. |

---

## 13. Repository layout

```
tux-hello/
├── Cargo.toml                  # workspace
├── meson.build                 # install wrapper
├── PLAN.md                     # this document
├── crates/
│   ├── tuxhello-proto/         # shared types, D-Bus interface definitions, backend RPC
│   ├── tuxhello-policy/        # policy parsing & evaluation (pure, heavily tested)
│   ├── tuxhello-store/         # encrypted template store, TPM sealing
│   ├── tuxhello-daemon/        # tuxhellod
│   ├── pam-tuxhello/           # pam_tuxhello.so (cdylib)
│   ├── tuxhello-cli/           # `tuxhello` + `tuxhello-pam-setup`
│   ├── backend-pin/
│   ├── backend-face/
│   ├── backend-fingerprint/    # fprintd adapter
│   ├── backend-voice/
│   ├── backend-key/
│   └── tuxhello-overlay/
├── gui/
│   ├── gtk/                    # tuxhello-settings (GTK4/libadwaita)
│   └── kcm/                    # Qt6/QML KDE module (Phase 5)
├── data/
│   ├── dbus/                   # bus policy + activation files
│   ├── polkit/                 # org.tuxhello.policy actions
│   ├── udev/                   # IR camera / hidraw rules, quirks hwdb
│   ├── pam/                    # pam-auth-update profile, authselect feature, pam-config module, snippets per service
│   ├── init/                   # systemd, openrc, runit, s6, dinit
│   ├── policy.d/               # default policy
│   └── models/                 # model manifest (URLs, SHA256, licences)
├── packaging/                  # PKGBUILD, debian/, tuxhello.spec, nix/, ebuild, void template, APKBUILD
├── tests/
│   ├── integration/            # pamtester-based end-to-end tests
│   ├── vm/                     # QEMU/cloud-image distro matrix, greeter automation
│   └── fixtures/               # recorded camera/audio samples (consented / synthetic)
├── bench/                      # biometric accuracy & latency benchmarks
└── docs/                       # user guide, admin guide, DE/WM integration cookbook, security whitepaper
```

---

## 14. Interfaces

### 14.1 D-Bus: `org.tuxhello.Auth1` (object `/org/tuxhello/Auth1`)

Phase 0 replaced the signal-based draft with long-polling; the reasons are in [ADR 0002](docs/adr/0002-ipc-and-pam-protocol.md). Implemented so far:

```
BeginAuth(a{sv} context) -> s session_id
    context: user, service, tty, rhost
Wait(s session_id, u timeout_ms) -> (a(sss) events, s state, s method, u assurance)
    events: (method, state, message); state: running | success | failure | unavailable | cancelled
Cancel(s session_id)
Version() -> s
ListBackends() -> a(sbu)
```

Planned additions:

```
BeginAuth context: logind_session, locale, conv_caps (can_info, can_prompt)       # Phase 1
SubmitSecret(s session_id, s kind, ay secret)    # PIN / fallback input             # Phase 1
Wait state: need_fallback | locked_out                                             # Phase 1
ReleaseEscrow(s session_id) -> ay authtok        # after success + policy; root only # Phase 4
```

### 14.2 D-Bus: `org.tuxhello.Manager1` (polkit-protected)

```
ListMethods() -> a(sbua{sv})                    # name, available, assurance, details
ListEnrollments(u uid) -> a(sssx)               # method, id, label, created
Enroll(u uid, s method, a{sv} opts) -> (o job)  # job emits Progress, PreviewFrame(h fd), Finished
DeleteEnrollment(u uid, s method, s id)
GetPolicy(u uid) -> s toml / SetUserPolicy(u uid, s toml)
Lockdown(u uid)
```

Polkit actions: `org.tuxhello.enroll-self` (auth_self_keep), `org.tuxhello.manage-others` (auth_admin), `org.tuxhello.configure-pam` (auth_admin).

### 14.3 Global config `/etc/tuxhello/config.toml`

```toml
[daemon]
log_level = "info"
audit = true

[face]
enabled = true
device = "auto"            # or "/dev/video2"
require_ir = true          # false allows RGB (low assurance)
ir_emitter = "auto"
liveness = "strict"        # strict | normal | off(not allowed for elevate)
execution_provider = "cpu" # cpu | openvino | cuda | rocm
threshold = "model-default"

[voice]
enabled = false            # opt-in
challenge_digits = 6
asr_model = "vosk-small-digits"

[key]
rp_id = "pam://tuxhello"
require_uv_for = ["elevate"]

[pin]
min_length = 4
allow_alnum = true
tpm = "auto"               # auto | require | off

[escrow]
enabled = false
```

### 14.4 CLI

```
tuxhello status                      # hardware, enrollments, policy summary, TPM state
tuxhello enroll face|fingerprint|voice|key|pin [--label NAME]
tuxhello list | delete <method> <id> | delete --all
tuxhello test [--service sudo]       # dry-run real auth path
tuxhello policy show|edit|check
tuxhello lockdown
tuxhello-pam-setup [--services gdm,sudo,polkit] [--dry-run] [--rollback] [--migrate-from howdy|fprintd|u2f]
tuxhello doctor                      # diagnose cameras, IR emitter, fprintd, TPM, PAM stacks, conflicts
```

---

## 15. Testing strategy

| Layer | Approach |
|---|---|
| Unit | Policy evaluation (property-based with `proptest`), store crypto, PIN logic, template (de)serialization. |
| Backend | Face: `v4l2loopback` virtual camera fed with recorded/synthetic sequences (real enrollees, photos-of-faces spoofs, empty frames). Voice: `snd-aloop` ALSA loopback with recorded and TTS samples. Key: virtual FIDO2 authenticator over `uhid` (e.g. `virtual-fido`-style test device). Fingerprint: `fprintd` with the libfprint **virtual-image / virtual-device** drivers. PIN/TPM: `swtpm`. |
| PAM end-to-end | `pamtester` against test services covering every return path, timeout, cancel, and daemon-down (must fall through to password!). |
| Lock-out safety | A dedicated suite: kill the daemon, corrupt the store, remove the camera, fill the disk, break the TPM. Every case **must** still allow password login. This is a release blocker. |
| Distro matrix | QEMU VMs (cloud images) for each distro in §9.1: install package → run `tuxhello-pam-setup` → automated `login`, `sudo`, `su`, greeter login via **openQA-style** screenshot/OCR automation for GDM, SDDM, LightDM, and greetd. Run nightly. |
| Lockers | Headless Sway/Hyprland (`WLR_BACKENDS=headless`) + swaylock/hyprlock; Xvfb + i3lock; driven by scripted input. |
| Fuzzing | `cargo-fuzz` targets continuously (OSS-Fuzz application once public). |
| Accuracy | `bench/` harness reporting FAR/FRR/EER, PAD metrics, and latency per release; regressions fail CI above a tolerance. |
| Hardware lab | Community-reported hardware database (`tuxhello doctor --report` produces an anonymised hardware report) + a small lab of common laptops (ThinkPad, Dell XPS, Framework, Surface) for IR camera/emitter validation. |

---

## 16. Roadmap and milestones

Estimates assume 2–3 core developers. They are indicative and not commitments.

### Phase 0 — Foundations (≈ 4 weeks)
- [x] Workspace, Meson wrapper, CI (lint, `cargo-deny`, tests, MSRV, distro containers). *Not yet compiled locally: see "Phase 0 status" below.*
- [x] Licence choice: **GPL-3.0-or-later for the whole project** ([ADR 0001](docs/adr/0001-licensing.md), decided 2026-11-12). The text is in `LICENSE`. SPDX headers on every file and `reuse lint` in CI (2026-11-14).
- [x] Spike: PAM module (libdbus) ↔ daemon (zbus) with a configurable stub backend, plus an end-to-end test using a bundled `th-pamtest` harness instead of `pamtester` ([ADR 0002](docs/adr/0002-ipc-and-pam-protocol.md), `tests/integration/pam-spike.sh`).
- [x] Decide on the FIDO2 binding ([ADR 0003](docs/adr/0003-fido2-binding.md)) and the ONNX Runtime distribution strategy ([ADR 0004](docs/adr/0004-onnx-runtime.md)).
- [ ] Model selection and **licence vetting** for face/voice models (see §17). The checklist and candidates are in [ADR 0005](docs/adr/0005-model-licensing.md); none are verified yet.
- [x] Threat model document v1 ([docs/threat-model.md](docs/threat-model.md)).

**Phase 0 status (2026-11-09):** builds warning-free with rustc 1.99, with and without the stub feature. Clippy (`-D warnings`) and rustfmt are clean. 22 unit tests pass. MSRV is 1.85 (Debian 13), enforced by the MSRV-aware resolver; `Cargo.lock` is generated. The full PAM path (real libpam, `pam_start_confdir`, a private bus standing in for the system bus) was exercised unprivileged on Arch: success, failure, unavailable, not enrolled, unknown user, remote refusal, cross-user denial, 5 s timeout, daemon SIGKILL mid-session, and the per-UID session limit all behave as designed. Not yet run: the root-only `pam-spike.sh` against the real system bus, the Meson build (Meson isn't installed locally), and CI.

**Exit criteria:** the PAM test service authenticates through the stub backend on Arch, Debian and Fedora (CI containers plus an Ubuntu runner), and falls through to the next module when the daemon is stopped, crashes, or times out.

### Phase 1 — MVP: PIN + Security key + Fingerprint (≈ 8 weeks)
- [x] Podman test containers for Arch, Debian (MSRV) and Fedora (`scripts/podman-test.sh`).
- [x] `tuxhellod` with sessions and policy engine v1 (`tuxhello-policy`: classes/services/groups/users, any/all, assurance, SIGHUP reload). Concurrent-session limits, a per-user attempt rate limit across methods, and a structured JSON audit log ([ADR 0010](docs/adr/0010-limits-and-audit-log.md)).
- [x] Encrypted store (`tuxhello-store`: AES-256-GCM). The master key is sealed by the TPM where there is one, with a file key as the fallback and migration by `[store] tpm = "require"` ([ADR 0011](docs/adr/0011-tpm.md)); tested with `swtpm` in the container suite. *Still to do:* a run on a physical TPM.
- [x] Software PIN: Argon2id, persistent lockout, `prompt`/`SubmitSecret` protocol ([ADR 0007](docs/adr/0007-pin-prompts-and-management.md)). TPM-backed PIN: the PIN is the auth value of a sealed object under the TPM's dictionary-attack lockout, assurance 3 ([ADR 0011](docs/adr/0011-tpm.md)).
- [x] FIDO2 backend: libfido2 FFI, our own assertion verification (RP hash, UP/UV, signature, clone-detecting counter), multiple keys, optional UV with the key PIN, and cancellation of untouched keys ([ADR 0008](docs/adr/0008-security-key-backend.md)). Tested in containers with a software authenticator. `tuxhello import pam-u2f` takes over keys registered with pam_u2f (both file formats), which keep pam_u2f's relying-party id. *Still to do:* a test with a physical key.
- [x] fprintd adapter backend: verify with retries and hints, the reader always released, list/delete through the daemon, enrolment via `fprintd-enroll`, and a polkit rule for the daemon's account ([ADR 0009](docs/adr/0009-fingerprint-backend.md)). Tested in containers with libfprint's virtual sensor, and checked live against a real Synaptics reader. Biometric lockout after 5 consecutive failures, lifted by a PIN or key success or `tuxhello unlock` ([ADR 0010](docs/adr/0010-limits-and-audit-log.md)). *Still to do:* a real-finger login on hardware.
- [x] CLI `status`, `enroll pin`, `list`, `delete`, `policy`, `test`, `unlock`, `import`, backed by `org.tuxhello.Manager1`; `doctor` checks the daemon, methods, TPM, PAM module, enabled services, conflicts, enrolments and lockouts, and works when the daemon is down. (`doctor --report`, the anonymised hardware report of §15, belongs with the hardware database in Phase 2.)
- [x] `tuxhello-pam-setup`: per-service edits on every distro (a marked `sufficient` block, each edit proven to be "original + block"), vendor-file overrides, backups, dry run, disable, rollback; Debian system-wide via `pam-auth-update`. Tested against the real `system-auth`/`common-auth` stacks with real password fallback on Arch, Debian and Fedora. Fedora system-wide via authselect (a `custom/tuxhello-<base>` profile with a `with-tuxhello` feature; `password-auth` untouched). openSUSE `pam-config` is a Phase 3 item, with the rest of the openSUSE work.
- [x] systemd + OpenRC service files (done in Phase 0); packages: Arch `PKGBUILD`, Debian `debian/`, RPM spec (`packaging/`), all built offline from a vendored release tarball (`scripts/dist.sh`). `scripts/podman-package.sh` builds, installs, logs in through PAM, and removes each one on Arch, Debian and Fedora; removal restores the PAM files byte for byte. One package for now: the split in §9.2 starts when the face backend brings heavy dependencies. *Still to do:* publish to the AUR, a PPA and COPR (needs a tagged release and a real maintainer address).

**Phase 1 status (2026-11-12):** every item above is implemented and green in the container suite on Arch, Debian (rustc 1.85, the MSRV) and Fedora, against each distro's real PAM stack, and the three packages build offline, install, authenticate and uninstall cleanly.

**Re-run (2026-11-14, at `d62366f`):** all green. On the host, 128 unit tests (`cargo test --workspace --all-features`) and `run-unprivileged.sh` pass. `scripts/podman-test.sh all` passes on Arch, Debian and Fedora: unit tests, the unprivileged and root integration tests (security key, fingerprint, TPM via `swtpm`, biometric lockout, lock-out safety with a damaged store) and the `tuxhello-pam-setup` tests, including `pam-auth-update` on Debian and authselect on Fedora. No failures and no skips. `scripts/podman-package.sh all` also passes: the three packages build offline, install, enrol a PIN, log in through PAM, fall through to the password, and uninstall with the PAM files restored byte for byte.

What the containers cannot show is still open, and it is what the exit criteria ask for:

- a **physical security key**, a **real finger** on a real reader, and a **physical TPM** (everything so far used a software authenticator, libfprint's virtual sensor and `swtpm`);
- a run on real **GNOME, KDE and Sway** sessions (`sudo`, polkit and the lock screen);
- CI itself: the workflow has not run since the packaging and TPM jobs were added;
- publishing the packages (AUR, PPA, COPR), which needs a tagged release and a maintainer address.

**Exit criteria:** daily-drivable for `sudo`, polkit, and the lock screen on GNOME, KDE, and Sway; the lock-out safety suite is green.

### Phase 2 — Face recognition (≈ 10 weeks)
- [ ] V4L2 capture, IR detection, emitter integration + quirks hwdb.
- [ ] Detection → alignment → quality → liveness → embedding pipeline on ONNX Runtime; `tract` fallback.
- [ ] Enrollment flow with preview frames (memfd passed to the client).
- [ ] Parallel multi-method sessions (face ‖ fingerprint, first success wins).
- [ ] Accuracy and PAD benchmark harness; threshold calibration.
- [ ] `tuxhello-lock-helper` pre-warm; `howdy` migration helper.

**Exit criteria:** IR face unlock < 1 s median on the reference laptops; FAR/PAD targets met on the test set.

### Phase 3 — GUI, overlay, broad DE/WM coverage (≈ 8 weeks)
- [ ] GTK4/libadwaita `tuxhello-settings` with the full first-run wizard.
- [ ] `tuxhello-overlay` (layer-shell + X11).
- [ ] Integration snippets and docs for every consumer in §8.1; upstream "auto-start PAM" patches for swaylock, i3lock-color, and gtklock.
- [ ] openSUSE (`pam-config`), NixOS module, Gentoo, Void, Alpine, Artix packaging; runit/s6/dinit service files.
- [ ] VM matrix with greeter automation.

**Exit criteria:** all §8.1 consumers and §9.1 distros pass the nightly matrix. **Public beta (0.9).**

### Phase 4 — Voice + keyring escrow (≈ 8 weeks)
- [ ] Voice backend: VAD, digit challenge, ASR check, ECAPA embedding, anti-spoof model; enrollment UI.
- [ ] Keyring escrow (TPM / FIDO2 `hmac-secret`), password-change invalidation, GNOME Keyring + KWallet verification.
- [ ] Adaptive face templates (opt-in).

### Phase 5 — Hardening & 1.0 (≈ 6–8 weeks)
- [ ] Sandboxing (seccomp/Landlock) finalised; fuzzing corpus matured.
- [ ] **External security audit** and remediation.
- [ ] KDE KCM; GNOME Shell extension; localisation (top 15 languages).
- [ ] Reproducible, signed releases; SBOM; distro official-repo submissions (Debian, Fedora, Arch `[extra]`, nixpkgs, Alpine).

**Exit criteria:** audit findings resolved, release notes with published accuracy numbers. **Release 1.0.**

### Phase 6 — Post-1.0 stretch
- [ ] initramfs/LUKS unlock (systemd-cryptsetup token plugin / Plymouth) using the PIN+TPM or FIDO2.
- [ ] `systemd-homed` and `fscrypt` integration.
- [ ] PIV/smartcard (PKCS#11) backend; phone-as-authenticator (FIDO hybrid).
- [ ] Depth-camera liveness; NPU execution providers (Intel NPU, AMD XDNA, Qualcomm).
- [ ] Walk-away lock (presence detection via camera/BLE), opt-in.

**Total to 1.0: ≈ 9–11 months.**

---

## 17. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| **Model licensing.** Many high-accuracy face models (e.g. InsightFace pretrained weights) are **non-commercial**; some datasets (MS-Celeb, VGGFace2) have restrictive or withdrawn licences. | Can't ship in distros. | Use only OSI/permissive-licensed models (e.g. OpenCV Zoo YuNet/SFace — verify), or **train our own** on licence-clean data. Keep a model manifest with licence metadata; legal review in Phase 0. |
| Users locked out by a PAM misconfiguration | Severe, reputational | `sufficient` stacking, the setup tool with dry-run + rollback, a lock-out safety suite as a release blocker, and prominent recovery docs (boot to TTY / live USB → `tuxhello-pam-setup --rollback`). |
| IR camera/emitter fragmentation | Face unusable on many laptops | Quirks hwdb, `tuxhello doctor`, community hardware reports, RGB fallback (low assurance). |
| Camera/mic busy (used by a video call when the lock screen appears) | Auth fails | Graceful `unavailable` → fallback to the other methods; clear message. |
| Lockers that don't show PAM info messages | Confusing UX | Overlay, upstream patches, docs. |
| ONNX Runtime packaging differences across distros | Build pain | Dynamic-or-bundled strategy + `tract` fallback. |
| Voice spoofing via AI cloning | False sense of security | Voice restricted to second factor by default; clear UI warnings. |
| Keyring escrow weakening security | Credential exposure | Opt-in, TPM/FIDO2-gated only, invalidated on password change, documented trade-offs. |
| Running in `sudo`/greeter processes | Stability issues in host processes | Thin module, no threads, strict timeouts, daemon does the heavy work. |
| Scope creep (5 methods × many DEs × many distros) | Delays | Phased roadmap; MVP ships PIN + key + fingerprint first, which reuse mature libraries. |

---

## 18. Prior art

Study, and where possible reuse, these projects:

- **Howdy**: IR face auth via PAM (Python + dlib). Lessons: IR emitter issues, Python-in-PAM fragility, slow startup → motivates our daemon design. Provide a migration path.
- **fprintd / libfprint / pam_fprintd**: the fingerprint stack we build on.
- **pam_u2f** (Yubico): FIDO2 PAM reference; import its key mappings.
- **linux-enable-ir-emitter**: IR emitter enablement for UVC cameras.
- **systemd-cryptenroll / systemd-homed**: TPM2 + FIDO2 patterns on Linux.
- **Windows Hello / Biometric Framework**: architecture model (TPM-backed PIN, ESS, lockout behaviour, password-on-first-sign-in).
- **Apple Face ID / Touch ID** security whitepapers: liveness, attention detection, lockout policies.

---

## 19. Open questions

1. ~~**Licence:** GPL-3.0 for everything vs. permissive for the PAM module/proto crates?~~ **Decided 2026-11-12:** GPL-3.0-or-later for everything ([ADR 0001](docs/adr/0001-licensing.md)).
2. **Project name:** "Tux Hello" may raise trademark questions with "Windows Hello". Consider an alternative brand early (e.g. *Kenbun*, *Visage*, *Penguard*) and run a trademark search.
3. **Daemon privileges:** dedicated user + device groups (current plan) vs. root with heavy sandboxing. Device groups (`video`, `audio`) vary by distro → needs udev ACL rules.
4. **Escrow default:** should first login after boot always require the password (safer, simpler), with escrow strictly opt-in? (Current plan: yes.)
5. **Train our own face/voice models?** The cost is data collection, consent, and compute, but it removes licensing risk entirely.
6. **Upstream collaboration:** propose `org.tuxhello.Auth1`-style hooks to GNOME/KDE lockers for richer UI (icons, method switching) rather than relying only on PAM text messages.
7. **Fingerprint:** stay a pure fprintd client, or also talk to sensors directly when fprintd lacks support? (Recommendation: pure client; contribute drivers to libfprint instead.)
