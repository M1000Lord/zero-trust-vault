# Troubleshooting

Practical fixes for the issues you are most likely to hit. Every item here is
designed to **fail closed** — when in doubt the vault locks rather than leaking a
secret.

---

## 1. Extension integrity check failed (red `!!` badge)

**What it means.** On every startup the service worker re-hashes the packaged
extension files (`manifest.json`, `popup.html`, `popup.js`, `popup.css`,
`content.js`) and compares each SHA-256 against the map embedded in
`service_worker.js`. If any file differs, the extension shows a red `!!` badge,
the tooltip names the failing file(s), and **all secret operations are blocked**
(unlock, fill, add, update, delete, TOTP). Read-only diagnostics still work so
the popup and health dashboard can tell you exactly what failed.

This is almost always one of two things:

1. You **legitimately edited** a checked file (most common during development)
   and did not re-stamp the hash map.
2. A file was **modified on disk after install** by something other than you —
   which is exactly the tampering the check exists to catch.

**How to see the failing files.**

- Open the popup: a red banner names the failing file(s).
- Open the health dashboard (🛡): "Integrity check" shows
  `FAILED: <n>/<total>` and a "Failing files" row lists the names.
- For expected-vs-actual hashes, open `chrome://extensions` → the extension →
  "service worker" → **Inspect** → Console. Each failing file is logged on its
  own line with its expected and actual hash.
- Or run the offline verifier, which prints the same diff:

  ```powershell
  powershell -ExecutionPolicy Bypass -File tools\verify-extension-integrity.ps1
  ```

**How to fix it (if the edit was legitimate).**

```powershell
# 1. Re-stamp the hash map from the current files
powershell -ExecutionPolicy Bypass -File tools\update-extension-hashes.ps1

# 2. Confirm the stamp matches the files
powershell -ExecutionPolicy Bypass -File tools\verify-extension-integrity.ps1

# 3. Reload the extension:  chrome://extensions  ->  reload (circular arrow)
```

After reload the badge clears and the popup opens normally.

**If you did NOT edit anything**, treat it as tampering: do not enter your Hello
PIN, re-install the extension from a trusted copy, and run a malware scan.

**Do not "fix" this by disabling the integrity check.** The check is a security
control, not a nuisance. Removing it would let malware swap `popup.js` or
`content.js` for a credential-stealing version and the vault would never notice.
The correct response to a *legitimate* change is to re-stamp; the correct
response to an *illegitimate* change is to re-install.

---

## 2. "Windows Hello not ready" / Hello does not prompt

**Status strings the native host can return** (canonical casing):

| Status             | Meaning                                                        |
|--------------------|----------------------------------------------------------------|
| `Available`        | Hello is set up and usable — unlock is allowed.                |
| `DeviceNotPresent` | No biometric/PIN hardware enrolled.                            |
| `NotConfigured`    | Hello not configured for this Windows user.                    |
| `DisabledByPolicy` | Group/MDM policy blocks Hello.                                 |
| `Unavailable`      | Temporarily unusable (e.g. device busy).                       |
| `Unknown`          | Could not be determined — the popup warns but still lets you try. |

**Casing bug (fixed).** An earlier build compared the raw string against
`"Available"` with a capital A while the host returned `"available"`. That
produced a false **"Windows Hello not ready: available"** message. The popup now
normalises case-insensitively (`helloAvailabilityState()`), so `Available` and
`available` are both accepted and the false alert no longer fires.

**If Hello genuinely will not prompt:**

1. Confirm Hello works in Windows itself: Settings → Accounts → Sign-in options
   → set up a PIN or fingerprint/face.
2. Test the native host in isolation (no browser) — see `docs/INSTALL.md` for the
   standalone `getVaultStatus` call; it returns `presenceAvailability`.
3. Remember the popup is a **detached window** on purpose: Chrome's action popup
   would auto-close when the Hello dialog takes focus, so the vault opens as a
   separate window. If your vault window vanishes when Hello appears, you are
   running an old build.

---

## 3. Corrupt vault / quarantine

**What quarantine means.** If the vault's `wrappedRootKey` is missing, empty, too
short, not valid base64, or fails to unwrap, the host **never deletes or
overwrites** your vault. It first copies it to:

```
%LOCALAPPDATA%\ZeroTrustVault\quarantine\vault.corrupt.<UTC>.json
%LOCALAPPDATA%\ZeroTrustVault\quarantine\vault.corrupt.<UTC>.diagnostic.json
```

The diagnostic file contains only **non-secret** metadata (schema version, file
size, item/event/device counts, whether a recovery bundle exists, the reason
code, timestamp, code version). It never contains keys, passwords, usernames,
TOTP seeds, notes, plaintext origins, or recovery shares.

**When reset is safe (Case A).** If the corrupt vault has **no** user data (no
items, events, devices, recovery kit, or pending pairings), the host quarantines
it and creates a fresh empty vault. Unlock returns `vaultWasReset: true` with a
notice. Nothing of value is lost because there was nothing there.

**When recovery is required (Case B).** If the corrupt vault **has** user data,
the host quarantines it and returns a typed error — `VaultCorruptRecoveryRequired`
(a recovery kit exists) or `VaultCorruptNoRecovery` (none). It does **not** reset.
Recover with your recovery kit (`docs/RECOVERY.md`) or restore a backup
(`docs/BACKUP.md`). **Do not delete the quarantine copies** — they are your only
forensic artifact and may be needed for recovery.

---

## 4. Debug logs

**Where they are.** Only DEBUG builds, or a build run with the environment
variable `ZTV_DEBUG_LOG=1`, write a diagnostic file:

```
%TEMP%\ztv_diag.txt
```

Release builds are a hard no-op — they create no file. Output is passed through a
redaction backstop that masks key-like values and long base64 blobs, but the file
should still be treated as sensitive and cleaned.

**How to clean it.**

```powershell
powershell -ExecutionPolicy Bypass -File tools\clean-debug-logs.ps1
```

**Guarantee for releases.** `tools\verify-release.ps1` reads the build's
`build-info.json` and **fails** the release if `diagnosticLogging=enabled`, so a
debug-logging build can never be shipped as a release. The health dashboard also
shows "Debug logging: Disabled (release-safe)" for a clean build.

---

## See also

- `docs/INSTALL.md` — install / standalone host test
- `docs/RECOVERY.md` — recovery-kit flow
- `docs/BACKUP.md` — backup / restore
- `docs/SECURITY_MODEL.md` — why these controls exist
- `AUDIT_PACKAGE/KNOWN_LIMITATIONS.md` — what is and isn't production-complete
