# Phase 1 hardware test plan

The container suite proves the logic. This checklist covers what containers can't: a **physical TPM**, a **physical security key**, a **real finger** on a real reader, and real **GNOME, KDE and Sway** sessions. Phase 1 is finished when every row in [Results](#results) passes (PLAN.md §16, Phase 1 exit criteria).

Work through it in order. Each section depends on the ones before it. Put each result in the table at the end and copy the summary into PLAN.md.

What you need:

- the test machine (the reference machine is EndeavourOS with a TPM 2.0 at `/dev/tpmrm0` and a Synaptics `06cb:00f0` reader);
- **two** FIDO2 security keys (a main key and a backup), or one if that's all you have;
- GNOME, KDE Plasma and Sway sessions, on this machine or a second one. Only Cinnamon and Plasma are installed on the reference machine (see [§7](#7-desktop-sessions));
- about two hours.

---

## 0. Safety net (do this first)

PAM mistakes can lock you out. The design keeps the password as a fallback everywhere, and these steps let you recover if that fails.

- [ ] Open a **root shell** in a separate terminal (`sudo -i`) and leave it open until §8 is done.
- [ ] Check that a **TTY login** works (Ctrl+Alt+F3, log in, log out). `login` is never touched in per-service mode.
- [ ] Have a **live USB** ready. Last resort: boot it, mount the root filesystem, and run `tuxhello-pam-setup rollback --root /mnt` or restore `/etc/pam.d` from the backups.
- [ ] Back up the PAM directories: `sudo tar -C /etc -czf ~/pam.d-before-tuxhello.tar.gz pam.d`.

## 1. Install

Rebuild the Arch package from the current tree, then install it:

```bash
scripts/dist.sh && scripts/podman-package.sh arch --rebuild
```

```bash
sudo pacman -U dist/tuxhello-0.0.1-1-x86_64.pkg.tar.zst
```

```bash
sudo pacman -S --needed fprintd
```

- [ ] `tuxhello doctor` reports no errors. It may warn about methods with nothing enrolled yet. **Save the full output** for the results.
- [ ] `tuxhello status` shows the daemon running. Tux Hello is not yet enabled in any PAM file.
- [ ] `sudo tuxhello-pam-setup status` lists nothing as enabled, and reports any conflicts (for example the `kde-fingerprint` stack, see §7).

## 2. Physical TPM

- [ ] `tuxhello status` reports the store's master key as **TPM-sealed**, not a file key.
- [ ] `sudo ls -l /var/lib/tuxhello` shows no plaintext key file.
- [ ] Restart the daemon (`sudo systemctl restart tuxhellod`). `tuxhello status` still reads the store.
- [ ] **Reboot.** The store still unseals after the reboot. This needs the real TPM's persistent state, which `swtpm` never really tested.
- [ ] Write down the TPM vendor and firmware: `cat /sys/class/tpm/tpm0/tpm_version_major`, plus `sudo tpm2_getcap properties-fixed | grep -A1 -E 'MANUFACTURER|FIRMWARE'` (needs `tpm2-tools`).

## 3. PIN (TPM-backed)

```bash
sudo tuxhello enroll pin
```

- [ ] `tuxhello list` shows the PIN as **TPM-backed**.
- [ ] `tuxhello test --service sudo`: the correct PIN succeeds.
- [ ] `tuxhello test --service sudo`: a wrong PIN three times fails the session, and the next attempt still works with the right PIN.
- [ ] `journalctl -u tuxhellod | grep audit` shows one JSON line per attempt, with the method, service and result.

Don't push the TPM into its dictionary-attack lockout on purpose. That lockout is machine-wide and can take hours to clear (ADR 0011).

## 4. Physical security key

```bash
sudo tuxhello enroll key --label main
```

```bash
sudo tuxhello enroll key --label backup
```

- [ ] Both keys enrol (touch each one when it blinks). `tuxhello list` shows both.
- [ ] Unplug and replug the key: it still works without root. This checks the udev rule `70-tuxhello-fido.rules` (`ls -l /dev/hidraw*` should show group `tuxhello`).
- [ ] `tuxhello test --service sudo` with **main**: a touch succeeds.
- [ ] Same with **backup**.
- [ ] With **both** plugged in: touching one succeeds, and the other stops blinking (it is cancelled).
- [ ] Not touched before the timeout (15 s for `sudo`): the session fails cleanly and the key stops blinking.
- [ ] If the key has a FIDO2 PIN and you turned UV on: the key PIN is asked for and checked.
- [ ] Write down the key model and firmware (`fido2-token -L`, then `fido2-token -I <device>`).
- [ ] *(Only if you used pam_u2f before)* `sudo tuxhello import pam-u2f` takes over those keys, and they authenticate.

## 5. Real finger

```bash
tuxhello enroll fingerprint --finger right-index-finger
```

- [ ] Enrolment finishes. `tuxhello list` shows the finger, and so does `fprintd-list $USER`.
- [ ] `tuxhello test --service sudo` with the enrolled finger succeeds.
- [ ] With a different finger it fails, and the retry hints show up ("swipe again", "centre your finger", and so on).
- [ ] Afterwards the reader is free: `fprintd-verify` works right after a Tux Hello attempt, both after a success and after a timeout.
- [ ] **Biometric lockout:** 5 wrong fingers in a row turns biometrics off. A PIN or key success turns them back on. Check this with `tuxhello status` before and after.
- [ ] Note how long a successful match takes. It should feel instant (well under 1 s after the touch).

## 6. Turn it on in PAM

```bash
sudo tuxhello-pam-setup enable --dry-run
```

```bash
sudo tuxhello-pam-setup enable
```

- [ ] The dry run shows one marked `auth sufficient pam_tuxhello.so` block for each service and nothing else. Check it before running the real `enable`.
- [ ] `tuxhello doctor` shows the enabled services with no conflicts.
- [ ] In a **new** terminal, `sudo true` offers Tux Hello. Try each method in turn: PIN, key, finger.
- [ ] Stop the daemon (`sudo systemctl stop tuxhellod`): `sudo true` goes straight to the password, with no long wait. Start it again.
- [ ] `sudo -k; sudo true` with nothing at hand: wait for the timeout, then the password prompt appears and works.

## 7. Desktop sessions

Run the same five checks in each session. Log out and back in after `enable` so the session picks up the new PAM files.

| Check | What to do |
|---|---|
| **sudo** | `sudo true` in the desktop's own terminal, using each method. |
| **polkit** | Trigger a polkit prompt (`pkexec true`, or the system settings' "unlock" button). Check what the dialog shows (the PIN prompt, "touch your key" / "scan your finger" text) and that each method works. |
| **lock screen** | Lock (Super+L or the menu), then unlock with each method. Note whether you have to press a key or type first before Tux Hello starts. |
| **fallback** | On the lock screen and in polkit, ignore Tux Hello: after the timeout the password works. |
| **suspend** | Lock, suspend, resume, unlock with the finger. The reader must still work after resume. |

**KDE Plasma (on this machine).** The lock screen uses the `kde` PAM service, and Plasma also runs its own `kde-fingerprint` stack through fprintd. Both may try to claim the reader at the same time. Record which one wins and whether fingerprint unlock works at all. If they conflict, that's a bug to fix before Phase 1 closes: either the setup tool switches off `kde-fingerprint`, or `doctor` explains the conflict.

**GNOME.** Not installed here. Use another machine or VM (a VM can't test the reader or the TPM, but it can test the PAM and UI path with the PIN, and with a key passed through over USB). GNOME's lock screen uses `gdm-password`, which `enable` only touches when you name it. Enable it with `sudo tuxhello-pam-setup enable gdm-password`, and note that this also affects the login screen.

**Sway.** Install it (`sudo pacman -S sway swaylock`) and start it from a TTY. `swaylock` doesn't start PAM until you press Enter, so press Enter on an empty field to start the Tux Hello attempt. Record whether that's usable.

**Cinnamon (bonus, not an exit criterion).** `cinnamon-screensaver` is not in Tux Hello's default service list or the policy's service map. `enable cinnamon-screensaver` should still work, and the service falls into the `other` class. Record whether it works. If it does, add it to both lists.

## 8. Remove it again

```bash
sudo tuxhello-pam-setup disable --all
```

- [ ] `diff -r` between `/etc/pam.d` and the backup from §0 shows no differences.
- [ ] Enable it again, then remove the package with it **still enabled** (`sudo pacman -R tuxhello`). `/etc/pam.d` is again byte for byte the same as the backup.
- [ ] `sudo true` and the lock screen still work with the password.
- [ ] Reinstall if you want to keep using it day to day. `/var/lib/tuxhello` survives removal, so your enrolments come back.

## 9. Daily use (exit criterion)

- [ ] Use it for at least **3 days** on your main desktop for `sudo`, polkit and unlocking. Write down every surprise, every slow unlock, every password fallback you didn't expect, and every crash (`journalctl -u tuxhellod -p warning`).

---

## Results

Fill this in as you go. ✅ pass · ❌ fail (add a note) · ⏭ not tested.

| # | Area | Arch/KDE | Cinnamon | GNOME | Sway | Notes |
|---|---|---|---|---|---|---|
| 1 | Install, `doctor` clean | | | | | |
| 2 | TPM seal, survives reboot | | — | — | — | |
| 3 | TPM-backed PIN | | — | — | — | |
| 4 | Security key: both keys, cancel, timeout | | — | — | — | |
| 5 | Real finger: match, reject, release, lockout | | — | — | — | |
| 6 | PAM enable, daemon-down fallback | | — | — | — | |
| 7a | sudo | | | | | |
| 7b | polkit | | | | | |
| 7c | lock screen | | | | | |
| 7d | password fallback | | | | | |
| 7e | suspend / resume | | | | | |
| 8 | disable / uninstall restore PAM | | — | — | — | |
| 9 | 3 days of daily use | | | | | |

Hardware used: TPM ______ · key(s) ______ · reader Synaptics 06cb:00f0 · kernel ______ · fprintd/libfprint ______
