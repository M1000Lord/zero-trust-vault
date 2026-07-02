# Zero-Trust Vault — Security Model

Version: v0.5.0-hardened  
Date: 2026-06-29  
Status: Active

---

## 1. Security Principles

Zero-Trust Vault (ZTV) is designed around fifteen explicit security principles. These are not aspirational; each principle maps to an architectural decision described in ARCHITECTURE.md and CRYPTO.md.

| # | Principle | Architectural Enforcement |
|---|-----------|--------------------------|
| 1 | **No master password** | Windows Hello (TPM/biometric) is the only secret-access gate. There is no password to phish, shoulder-surf, or brute-force. |
| 2 | **No plaintext in the cloud** | All sync payloads are AES-256-GCM ciphertext before leaving the device. The relay server (v2 design) is blind. |
| 3 | **No vendor backdoor** | VaultRootKey is generated on-device, TPM-wrapped. Anthropic, the developer, or any third party cannot recover it. |
| 4 | **No bulk decryption** | The native host decrypts at most one credential per fill request. There is no "export all" API in release builds. |
| 5 | **No silent autofill** | The user must interact with the extension popup and approve each fill. There is no background credential injection. |
| 6 | **No auto-submit** | The extension fills the form fields and stops. It never synthesizes a submit event or clicks a submit button. |
| 7 | **No HTTP release** | The native host rejects fill requests for origins that do not begin with `https://`. HTTP origins return an error, not a credential. |
| 8 | **No IDN release by default** | Origins containing Unicode labels (IDN/punycode) are rejected by default unless the user explicitly opts in. |
| 9 | **Fresh Windows Hello per secret** | Every credential release triggers a fresh Windows Hello prompt. A single biometric approval does not unlock a session of unlimited decryption. |
| 10 | **Server never trusted** | The blind relay is treated as an untrusted courier. All integrity protection is enforced client-side via event-chain MACs and device signatures. |
| 11 | **Extension is low-trust** | The Chrome extension (service_worker.js, popup.js) never holds a decrypted credential for longer than the duration of a single fill operation. It never stores secrets in `chrome.storage`. |
| 12 | **Native host is the security boundary** | All cryptographic operations, origin validation, rate limiting, and TOTP generation reside in the C# native host process. The extension is a UI front-end only. |
| 13 | **Content script is lowest-trust** | content.js runs in the renderer process, can be observed by the page's JavaScript, and is considered potentially compromised. It never requests secrets, never communicates with the native host, and only detects form fields. |
| 14 | **Compromised session steals at most one credential** | Because each fill requires a fresh Hello prompt, a compromised browser context cannot silently drain the vault. Maximum blast radius per session: one credential. |
| 15 | **Admin/root malware is out of scope but rate-limited** | ZTV cannot prevent a process running as Administrator or SYSTEM from reading memory after fill. However, rate limiting on the native host and the per-credential Hello gate limit the attacker's throughput to one credential per user-biometric interaction. |

---

## 2. Threat Model Table

The following 21 threats are analyzed. For each threat the table records: whether ZTV **prevents**, **reduces**, or **cannot prevent** the attack; the **residual risk** after ZTV controls are applied; and a **test case** to verify the control.

| # | Threat | ZTV Posture | Residual Risk | Test Case |
|---|--------|-------------|---------------|-----------|
| T-01 | Passive keylogger | **Prevents** — no typed master password; Windows Hello is gesture/biometric, not keystroke. | Low | Set up a keylogger on the test machine; confirm no secret material appears in keystroke log during vault unlock or fill. |
| T-02 | Infostealer targeting browser saved passwords | **Prevents** — ZTV does not use Chrome's built-in password store. Credentials are in the native host's TPM-wrapped vault, not in the browser profile directory. | Low | Scan Chrome user data directory after adding a credential; confirm no ZTV plaintext present. |
| T-03 | RAT operating inside browser (Chrome extension) | **Reduces** — a malicious extension or compromised browser context cannot directly call the native host. It can observe a fill after it occurs (DOM theft). Rate-limited to one credential per Hello. | Medium | Simulate a rogue extension trying to send `chrome.runtime.sendMessage` to ZTV's extension ID; confirm it is rejected by the allowedOrigins check in service_worker.js. |
| T-04 | Admin/root malware on the same machine | **Cannot prevent** — a process with Administrator or SYSTEM privileges can read process memory. ZTV rate-limits throughput to one credential per biometric interaction, but cannot prevent memory reading after fill. | High | (Out of scope for unit testing; document as accepted residual risk.) |
| T-05 | DOM theft after fill (page JS reads filled values) | **Cannot prevent** — once `<input>` fields are filled, the page's JavaScript can read `.value`. This is a browser architecture limitation. | Medium | After fill, open browser console and read the filled input's `.value`; confirm the value is there. Document and accept. |
| T-06 | Clipboard stealer | **Prevents** — ZTV does not copy credentials to the clipboard. Fill is done via `element.value` assignment and input event dispatch, not clipboard API. | Low | Monitor clipboard (e.g., with ClipSpy) during a fill operation; confirm nothing is placed in the clipboard. |
| T-07 | RAM dump / cold-boot attack | **Reduces** — decrypted credential is held in managed memory for the minimum time needed for fill. GC and string pinning reduce (but do not eliminate) exposure. TPM-wrapped keys are never in user-space RAM in plaintext. | Medium | Use WinPMem to capture RAM during a fill; confirm that credential bytes are not trivially discoverable at rest (accepts best-effort). |
| T-08 | Malicious Chrome extension attempting to hijack ZTV | **Reduces** — native messaging host registration limits which extension IDs can connect. The `allowed_origins` array in the host manifest is set to the single ZTV extension ID. | Low | Install a second test extension; attempt to open a native messaging channel to `com.zerotrustvault.host`; confirm connection is refused. |
| T-09 | Fake website / credential phishing | **Prevents** — exact-origin matching. The stored credential's origin (`https://host:port`) is compared via HMAC against the requesting origin. A fake domain does not match. | Low | Add a credential for `https://example.com`; visit `https://example.com.evil.net`; confirm no credential is offered. |
| T-10 | IDN homograph attack (e.g., xn--exmple-cua.com) | **Prevents by default** — origins containing non-ASCII labels are rejected by the native host unless the user has explicitly enabled IDN support. | Low | Submit a fill request with a punycode origin; confirm native host returns `ERR_IDN_REJECTED`. |
| T-11 | HTTP downgrade attack | **Prevents** — native host rejects any origin not beginning with `https://`. No credential is released over HTTP. | Low | Submit a fill request with origin `http://example.com`; confirm native host returns `ERR_HTTP_REJECTED`. |
| T-12 | Cloud server / relay server breach | **Prevents plaintext exposure** — all data stored on the relay is AES-256-GCM ciphertext. The server cannot decrypt without the TPM-held VaultRootKey. | Low (ciphertext exposed, plaintext safe) | Inspect relay storage directly; confirm all stored blobs are ciphertext with no readable credential fields. |
| T-13 | Malicious sync relay (active MITM on sync channel) | **Reduces** — event payloads are signed by the device key (ECDSA P-256). A tampered event will fail signature verification on receive. A relay that drops events will be detected by HLC gap analysis. | Medium (replay possible) | Tamper with an event payload on the relay; confirm receiving device rejects it with `ERR_SIG_INVALID`. |
| T-14 | Fake device enrollment | **Prevents (local approval path)** — approval requires a shared pairing code, a fresh Windows Hello on the already-enrolled device, **and** a matching Short Authentication String that the host recomputes over the exact signing+encryption keys it will wrap to (rejecting on `SAS_MISMATCH`). The new `DeviceId` is derived from the joiner's public signing key and the root key is wrapped to its public encryption key (RSA-OAEP-SHA256). A relay that substitutes keys yields a different SAS and is rejected. Residual: the joiner does not yet verify the signed `AddDevice` event over a live transport. | Low–Medium | Approve with a wrong SAS → confirm `SAS_MISMATCH`. Approve with the correct SAS → device enrolled. (`DeviceIdentityTests` proves a swapped key changes the SAS.) |
| T-15 | Device theft (unlocked laptop) | **Reduces** — Windows Hello (PIN/biometric) must be satisfied to unlock the vault. An attacker with a stolen machine still needs to defeat Windows Hello. | Medium (Hello defeat depends on Windows config) | Lock workstation; attempt to fill a credential; confirm Windows Hello prompt appears and blocks fill. |
| T-16 | TPM failure | **Reduces** — vault data is preserved. Recovery requires the recovery kit (3-of-5 Shamir shares). Without the recovery kit, the VaultRootKey is lost and the vault is unrecoverable. | High (if no recovery kit) | Simulate TPM key loss; confirm vault cannot be opened without recovery kit; confirm it CAN be opened with 3-of-5 shares. |
| T-17 | Motherboard replacement (TPM keys are board-bound) | Same as T-16. | High (if no recovery kit) | Same as T-16. |
| T-18 | Lost Windows user profile | **Reduces** — if the vault file at `%LOCALAPPDATA%\ZeroTrustVault\vault.json` is backed up and the recovery kit is available, recovery is possible. If the Windows profile is gone and there is no backup, data is lost. | High (if no backup + no recovery kit) | Delete Windows profile; restore vault from backup; recover using recovery kit; confirm credentials accessible. |
| T-19 | Supply-chain tampering (modified native host binary) | **Reduces** — Authenticode signature is applied at release. The installer verifies the signature thumbprint before registering the native host. A tampered binary will fail signature verification. | Medium (Developer Mode; Web Store not yet used) | Modify a byte in the native host binary; run install.ps1; confirm it aborts with signature error. |
| T-20 | Malicious extension update (future Web Store) | **Reduces** — the extension's content security policy (CSP) blocks remote code execution. Manifest V3 prohibits `eval()` and remote script loading. | Medium (not yet on Web Store) | Inspect manifest.json CSP; confirm no `unsafe-eval`, no `script-src` remote origins. |
| T-21 | Backup file theft | **Prevents plaintext exposure** — backup files are encrypted (AES-256-GCM) and MAC'd. Without the TPM-held VaultRootKey (or recovery kit), a stolen backup file is opaque ciphertext. | Low (ciphertext exposed, plaintext safe) | Copy a backup file to another machine; attempt to open it without ZTV installed; confirm it is unreadable. |
| T-22 | Shared vault revocation (remove device from shared vault) | **Prevents future access (cryptographic)** — `removeDevice` requires a fresh Hello, then generates a **new random VaultRootKey**, **re-encrypts every item** under it (`VaultRekey.RotateRoot`), recomputes origin hashes, bumps the epoch, re-wraps the new root to the local CNG/TPM key and to each remaining active device, strips the removed device's wrap, and records signed `DeviceRemoved` + `EpochRotated` events. A device holding only the old root can no longer decrypt the re-encrypted vault. Fail-closed: the vault is persisted only on full success. Residual (accepted): the removed device may retain secrets it already exfiltrated before removal — it cannot be made to forget those. Rotation also invalidates the existing recovery kit (must be re-created). | Low–Medium (cannot un-see already-read secrets) | `VaultRekeyTests`: after rotation the old root throws on decrypt and the new root succeeds. Live: remove a device; confirm `epochRotated:true`, items still readable locally, recovery-kit-invalidated notice. |

---

## 2b. Extension File Integrity

**Why it exists.** A Web Store signature protects the extension *package* at
install time, but does not protect the files on disk afterward, and unpacked
developer installs have no signature at all. Malware (or a careless edit) could
swap `popup.js` or `content.js` for a credential-stealing version. To catch this,
`service_worker.js` embeds a SHA-256 map (`INTEGRITY_HASHES`) of the five
behaviour-bearing files — `manifest.json`, `popup.html`, `popup.js`, `popup.css`,
`content.js` — and re-hashes them on every startup. The service worker itself is
excluded because it cannot hash itself.

**Fail-closed behaviour.** If any file does not match, the extension shows a red
`!!` badge, names the failing file(s) in the tooltip and popup, and **blocks all
secret operations** (unlock, fill, add, update, delete, TOTP). Only read-only
diagnostics (health, integrity status) remain reachable, so the dashboard can
explain the failure instead of failing opaquely.

**How to regenerate after a legitimate edit.**

```powershell
powershell -ExecutionPolicy Bypass -File tools\update-extension-hashes.ps1     # stamp
powershell -ExecutionPolicy Bypass -File tools\verify-extension-integrity.ps1  # verify
```

then reload the extension. The verifier reads the map the service worker will
actually enforce, so a green verify means a clean load. CI runs the same verifier
as a gate, and `build-release.ps1` stamps + verifies as part of every build.

**Why disabling it is not acceptable.** The integrity check is a tamper-detection
control. Removing or bypassing it to silence the badge would re-open exactly the
post-install code-swap attack it defends against. The correct response to a
legitimate change is to **re-stamp**; the correct response to an unexpected
failure is to **re-install from a trusted copy** — never to disable the check.
See `docs/TROUBLESHOOTING.md` §1.

---

## 3. What ZTV Does Not Claim

- ZTV is not immune to malware.  
- ZTV cannot prevent an Administrator-level process from reading memory after a fill.  
- ZTV has not undergone an independent third-party security audit as of v0.5.0.  
- ZTV running in Chrome Developer Mode does not have Web Store signing guarantees.  
- Cross-machine use requires a pre-created recovery kit; without it, machine loss means vault loss.
