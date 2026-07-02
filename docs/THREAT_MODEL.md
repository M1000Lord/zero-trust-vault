# Zero-Trust Vault — Detailed Threat Model

Version: v0.5.0-hardened  
Date: 2026-06-29

---

## Overview

This document provides per-threat technical analysis for all 22 threats identified in SECURITY_MODEL.md. Each entry describes the attack in detail, the attacker capability required, which ZTV component provides protection, what ZTV explicitly cannot prevent, and the residual risk rating.

Residual risk ratings use a simplified scale:
- **Low** — attack is effectively blocked by ZTV architecture; no realistic path to success without defeating multiple independent controls.
- **Medium** — attack is significantly limited or made more difficult; a determined attacker may partially succeed.
- **High** — ZTV provides limited protection; defense depends on OS, hardware, or external factors.

---

## T-01: Passive Keylogger

**Attack Description:**  
A keylogger (kernel driver or user-mode hook) captures all keystrokes on the system. The goal is to capture the master password or other secret typed by the user.

**Attacker Capability Required:**  
User-level or kernel-level code execution on the target machine.

**What ZTV Does:**  
ZTV has no master password. The only secret-access gate is Windows Hello (biometric gesture, PIN via secure input channel, or FIDO2). Windows Hello PIN entry goes through the Windows logon UI's isolated input method, which is not captured by standard keyloggers. Biometric (fingerprint/face) has no keystrokes.

**ZTV Component Providing Protection:**  
Principle #1 (No master password); Windows Hello as the authentication factor.

**What ZTV Cannot Prevent:**  
A kernel-level keylogger with access to the secure input channel (possible only with a compromised bootloader or kernel driver signing bypass) could hypothetically intercept a Hello PIN. This is beyond the ZTV threat scope.

**Residual Risk:** Low

**Recommended Test Case:**  
Install a user-mode keylogging tool (e.g., a test hook on `SetWindowsHookEx WH_KEYBOARD_LL`). Perform a vault unlock and fill operation. Confirm no secret string appears in the keylog output.

---

## T-02: Infostealer Targeting Browser Saved Passwords

**Attack Description:**  
An infostealer malware family (e.g., RedLine, Vidar) enumerates and exfiltrates Chrome's `Login Data` SQLite database, which contains browser-managed passwords.

**Attacker Capability Required:**  
User-level code execution. These malware families commonly operate without privilege escalation.

**What ZTV Does:**  
ZTV credentials are stored in `%LOCALAPPDATA%\ZeroTrustVault\vault.json`, encrypted with AES-256-GCM under keys protected by the Windows TPM. ZTV never writes credentials to Chrome's `Login Data` database, Chrome's `chrome.storage`, or any browser-managed storage. A standard infostealer scanning Chrome's profile directory will not find ZTV credentials.

**ZTV Component Providing Protection:**  
Native host vault storage; CRYPTO.md key hierarchy; Principle #12 (native host is security boundary).

**What ZTV Cannot Prevent:**  
An infostealer that specifically targets `vault.json` will obtain encrypted ciphertext. Without the TPM-wrapped VaultRootKey, the ciphertext is not useful. However, if the infostealer also exfiltrates the TPM-backed key by using Windows CNG APIs while running as the user (user-level CNG key access is gated by Windows Hello), this would require a Hello prompt — which would be visible to the user.

**Residual Risk:** Low

**Recommended Test Case:**  
Use a forensic tool to scan the Chrome profile directory and `%LOCALAPPDATA%` after adding a credential. Confirm that `Login Data` contains no ZTV credentials and that `vault.json` contains only ciphertext (no readable fields).

---

## T-03: Remote Access Trojan (RAT) Inside the Browser

**Attack Description:**  
A compromised extension or a RAT that has injected into the Chrome renderer attempts to communicate with the ZTV native host directly to extract credentials.

**Attacker Capability Required:**  
Extension-level or renderer-level code execution in Chrome.

**What ZTV Does:**  
The native messaging host manifest (`com.zerotrustvault.host.json`) specifies an `allowed_origins` array containing exactly one entry: `chrome-extension://<ZTV_EXTENSION_ID>/`. Any attempt by a different extension to open a native messaging channel to `com.zerotrustvault.host` is refused by Chrome's native messaging infrastructure before any ZTV code runs.

Additionally, `service_worker.js` validates that `chrome.runtime.connect` or `chrome.runtime.sendMessage` calls arrive only from the popup context or the known content script message flow. A rogue extension cannot impersonate these.

**ZTV Component Providing Protection:**  
Chrome native messaging `allowed_origins`; service_worker.js origin checks; Principle #13 (content script is lowest-trust).

**What ZTV Cannot Prevent:**  
If the ZTV extension itself is compromised (e.g., via a malicious update), the `allowed_origins` restriction does not help. DOM theft after fill (T-05) is also available to any renderer-level attacker.

**Residual Risk:** Medium (DOM theft after fill is an inherent browser limitation)

**Recommended Test Case:**  
Create a test extension with a different ID. Attempt to open a native messaging channel to `com.zerotrustvault.host`. Confirm the connection is refused with `Error: Native host has exited`. Attempt to send a `chrome.runtime.sendMessage` to the ZTV extension ID from the rogue extension; confirm it is rejected.

---

## T-04: Admin/Root Malware on the Same Machine

**Attack Description:**  
A process running as Administrator or SYSTEM uses Windows debugging APIs (`ReadProcessMemory`, `MiniDumpWriteDump`) to read the native host process memory immediately after a credential is decrypted.

**Attacker Capability Required:**  
Administrator or SYSTEM privileges on the machine.

**What ZTV Does:**  
ZTV rate-limits decryption operations. Each credential release requires a fresh Windows Hello interaction, limiting the attacker's ability to automate mass extraction. The decrypted credential is held in managed C# memory for the minimum time required. The VaultRootKey is TPM-wrapped and never appears in user-space RAM in plaintext (CNG platform keys remain in the TPM).

**ZTV Component Providing Protection:**  
Principle #15 (rate-limited); Principle #9 (fresh Hello per secret); CNG non-exportable platform keys.

**What ZTV Cannot Prevent:**  
A process with `SeDebugPrivilege` can read any user-process memory. After a decrypted string is constructed for fill, it exists in the managed heap. ZTV cannot prevent an admin-level attacker from reading it. This is accepted as out of scope: preventing admin-level attackers requires OS-level protections (Credential Guard, Secure Enclave) beyond ZTV's architecture.

**Residual Risk:** High (accepted; documented in SECURITY_MODEL.md Principle #15)

**Recommended Test Case:**  
Document and accept. Note in AUDIT_CHECKLIST.md that admin-malware resistance is not a ZTV goal. Verify rate limiting: script 10 rapid fill requests and confirm the native host requires 10 Hello prompts, not a cached session.

---

## T-05: DOM Theft After Fill

**Attack Description:**  
Page JavaScript reads the `.value` property of a password `<input>` element immediately after ZTV fills it, exfiltrating the credential to the attacker's server.

**Attacker Capability Required:**  
JavaScript execution on the target page. This is available to any script running in the page's browsing context, including third-party analytics, ad scripts, or an XSS payload.

**What ZTV Does:**  
ZTV does not fill hidden fields or off-screen elements. content.js only fills forms that are visible and have focus. ZTV dispatches input/change events realistically to avoid bypassing page-side validation, which is a normal browser behavior.

**ZTV Component Providing Protection:**  
None. DOM theft is a browser architecture limitation.

**What ZTV Cannot Prevent:**  
Once a value is in the DOM, page JavaScript can read it. ZTV cannot sandbox the page's script environment.

**Residual Risk:** Medium (inherent browser limitation; documented and accepted)

**Recommended Test Case:**  
Add a `console.log` to a test page that reads `document.querySelector('input[type=password]').value` on an `input` event. Perform a fill. Confirm the value appears in the console, documenting the inherent limitation.

---

## T-06: Clipboard Stealer

**Attack Description:**  
Malware monitors the clipboard for credential-shaped strings. The goal is to intercept passwords copied during credential management.

**Attacker Capability Required:**  
User-level code execution (`AddClipboardFormatListener` or polling `GetClipboardData`).

**What ZTV Does:**  
ZTV never places credentials on the clipboard. All fills are performed via direct DOM value assignment in content.js (`element.value = decryptedValue`) followed by synthetic `InputEvent` and `ChangeEvent` dispatch. The clipboard API is never invoked.

**ZTV Component Providing Protection:**  
content.js fill mechanism; Principle #5 (no silent autofill via clipboard).

**What ZTV Cannot Prevent:**  
If a user manually copies a credential from a ZTV-filled field (Ctrl+C), it will be on the clipboard and visible to clipboard monitors. ZTV does not prevent user-initiated clipboard use.

**Residual Risk:** Low

**Recommended Test Case:**  
Monitor the clipboard (e.g., with a test `AddClipboardFormatListener` hook) during a fill operation. Confirm that no clipboard change event fires and the clipboard content remains unchanged after fill.

---

## T-07: RAM Dump / Cold-Boot Attack

**Attack Description:**  
An attacker obtains a physical memory dump (via cold-boot, DMA attack, or forensic imaging of a running system) and searches for credential strings in the dump.

**Attacker Capability Required:**  
Physical access to the machine (cold-boot / DMA) or admin-level code execution (software memory dump).

**What ZTV Does:**  
VaultRootKey and all subkeys derived by HKDF are stored as CNG platform keys (non-exportable, hardware-backed by TPM). These keys never appear in user-space RAM in plaintext. The decrypted credential is a C# `string` or `byte[]` held briefly in managed memory; ZTV zeros these buffers (`Array.Clear` or `SecureString` where applicable) as soon as the fill response is dispatched.

**ZTV Component Providing Protection:**  
CNG platform keys (TPM-backed, non-exportable); CRYPTO.md; brief plaintext lifetime in native host.

**What ZTV Cannot Prevent:**  
The .NET GC may copy managed strings to other locations before the original is zeroed. A high-fidelity RAM dump taken at exactly the right moment could contain the credential. Fully preventing this requires OS-level mitigations (Windows Credential Guard, no managed runtime). ZTV makes a best-effort attempt to minimize the plaintext window.

**Residual Risk:** Medium

**Recommended Test Case:**  
During a fill operation, capture a live memory dump of the native host process using `ProcDump -ma`. Search the dump for the known credential string. Document findings. Accept that some exposure may exist in managed heap.

---

## T-08: Malicious Chrome Extension Attempting to Hijack ZTV

**Attack Description:**  
A malicious extension installs itself alongside ZTV and attempts to either (a) open a native messaging channel to the ZTV host, or (b) send messages to the ZTV extension to trigger unauthorized operations.

**Attacker Capability Required:**  
Extension installation (requires user interaction under Chrome's current model, or can be pushed via enterprise policy by an attacker with admin access).

**What ZTV Does:**  
(a) The native host's `allowed_origins` array contains exactly one extension ID. Any other extension's attempt to connect is refused at the Chrome native messaging layer before ZTV code is reached.  
(b) `service_worker.js` uses `chrome.runtime.onMessageExternal` only if needed, and all incoming messages are validated for their source and schema. Unrecognized senders are rejected.

**ZTV Component Providing Protection:**  
Chrome native messaging `allowed_origins`; service_worker.js message schema validation.

**What ZTV Cannot Prevent:**  
If an attacker has admin privileges and can modify the native host manifest (or reinstall it with a different `allowed_origins`), this control is defeated. Supply-chain attacks on the ZTV extension itself (T-20) could also compromise this boundary.

**Residual Risk:** Low

**Recommended Test Case:**  
Create a test extension. Attempt to call `chrome.runtime.connectNative('com.zerotrustvault.host')` from that extension. Confirm connection is refused. Attempt `chrome.runtime.sendMessage('<ZTV_ID>', {...})` and confirm the message is rejected or ignored.

---

## T-09: Fake Website / Credential Phishing

**Attack Description:**  
An attacker registers a domain similar to a target site (e.g., `examp1e.com` vs `example.com`) and attempts to receive a ZTV-autofilled credential.

**Attacker Capability Required:**  
DNS registration and a TLS certificate for the phishing domain.

**What ZTV Does:**  
The native host computes `originHash = HMAC(OriginHashKey, canonicalOrigin)` where `canonicalOrigin` is the exact string `https://host:port`. A credential stored for `https://example.com` has an originHash computed over that exact string. A fill request from `https://examp1e.com` produces a different HMAC output, so no stored credential matches, and no fill occurs.

**ZTV Component Providing Protection:**  
Native host origin validation; HMAC-based originHash (CRYPTO.md); Principle #12 (native host is security boundary).

**What ZTV Cannot Prevent:**  
If the legitimate domain itself is compromised (subdomain takeover, BGP hijack to the real IP), ZTV will offer credentials as normal — the origin matches. ZTV does not perform certificate transparency or HSTS checks beyond what Chrome already enforces.

**Residual Risk:** Low

**Recommended Test Case:**  
Add a credential for `https://example.com:443`. Submit a fill request from the extension while on `https://examp1e.com`. Confirm native host returns no credential. Confirm that `https://example.com` (correct) does return the credential.

---

## T-10: IDN Homograph Attack

**Attack Description:**  
An attacker registers an internationalized domain that looks visually identical to a target domain (e.g., `аpple.com` with Cyrillic `а` vs Latin `a`). The browser may display the Unicode form rather than the punycode form.

**Attacker Capability Required:**  
IDN domain registration for the homograph target.

**What ZTV Does:**  
The native host receives the origin from `service_worker.js`, which obtains it via `chrome.tabs.query`. If the origin string contains non-ASCII characters or if, after normalization, any label is a punycode label (`xn--`), the native host returns `ERR_IDN_REJECTED` by default. The user must explicitly opt in to IDN support in settings.

**ZTV Component Providing Protection:**  
Native host IDN detection and rejection; Principle #8 (no IDN release by default).

**What ZTV Cannot Prevent:**  
If the user enables IDN support, this protection is disabled. Also, Chrome may normalize some IDN forms to ASCII before ZTV sees them — the protection depends on the label still being detectable as non-ASCII or punycode by the time it reaches the native host.

**Residual Risk:** Low (with default settings)

**Recommended Test Case:**  
Submit a fill request with origin `https://аpple.com` (Cyrillic a) or its punycode form. Confirm native host returns `ERR_IDN_REJECTED`. Verify that with IDN opt-in enabled, the check is bypassed (and document this for the user).

---

## T-11: HTTP Downgrade Attack

**Attack Description:**  
An attacker (via network MITM or a malicious redirect) causes the browser to visit `http://example.com` instead of `https://example.com` and attempts to trigger a ZTV fill.

**Attacker Capability Required:**  
Network-level MITM capability or ability to inject a redirect into the user's browsing session.

**What ZTV Does:**  
The native host inspects the origin string before any credential lookup. If `origin.StartsWith("https://")` is false, the host returns `ERR_HTTP_REJECTED` immediately. No credential query or HMAC comparison is performed.

**ZTV Component Providing Protection:**  
Native host HTTP rejection; Principle #7 (no HTTP release).

**What ZTV Cannot Prevent:**  
ZTV relies on Chrome reporting the correct origin. A hypothetical Chrome vulnerability that spoofs the origin string would defeat this check. This is considered outside ZTV's scope.

**Residual Risk:** Low

**Recommended Test Case:**  
Visit `http://example.com` (or simulate with a local server). Trigger a fill request. Confirm native host returns `ERR_HTTP_REJECTED` before any credential lookup.

---

## T-12: Cloud Server / Relay Server Breach

**Attack Description:**  
An attacker compromises the blind relay server (database breach, server takeover) and exfiltrates all stored sync event blobs.

**Attacker Capability Required:**  
Server-side access to the relay's storage layer.

**What ZTV Does:**  
All event payloads are encrypted with AES-256-GCM before leaving the device. The relay server stores only ciphertext event blobs, device public keys (used for signature verification), and HLC timestamps. The server never holds a decryption key. A breach yields only ciphertext.

**ZTV Component Providing Protection:**  
SYNC.md blind relay model; CRYPTO.md AES-256-GCM event payload encryption; Principle #10 (server never trusted).

**What ZTV Cannot Prevent:**  
A relay breach exposes metadata: which vault IDs exist, how many events, timestamps, and device public keys. An attacker with a stolen backup and a working quantum computer could (far) future-attack the AES-256 ciphertext. This is not a credible near-term risk.

**Residual Risk:** Low (ciphertext only)

**Recommended Test Case:**  
Inspect relay storage directly. Confirm all stored entries are ciphertext blobs with no readable field names, credential data, or key material.

---

## T-13: Malicious Sync Relay (Active MITM on Sync Channel)

**Attack Description:**  
A relay operator or network-level attacker tampers with sync events in transit: modifying event payloads, replaying old events, or dropping events selectively.

**Attacker Capability Required:**  
Control of the relay server or the network path between the device and the relay.

**What ZTV Does:**  
Each event is signed with the originating device's ECDSA P-256 key (non-exportable, stored in CNG). Receiving devices verify the signature and reject events with invalid signatures (`ERR_SIG_INVALID`). Events also form a hash chain via the `previousHash` field; a gap or inconsistency in the chain is detected.

**ZTV Component Providing Protection:**  
SYNC.md event signing; event hash chain; CRYPTO.md device signing keys.

**What ZTV Cannot Prevent:**  
A relay that drops all events (denial of service) cannot be distinguished from a network partition. A replay of previously valid signed events would pass signature verification (though HLC ordering would flag out-of-sequence replays). Full replay protection requires monotonic sequence numbers checked by the receiving device, which is designed in the HLC but requires correct client-side enforcement.

**Residual Risk:** Medium (replay possible; DoS possible)

**Recommended Test Case:**  
Manually tamper with a sync event payload (modify one byte of the encrypted content). Confirm the receiving device's signature verification rejects the event. Also test: replay an old, valid event; confirm HLC ordering detects it as stale.

---

## T-14: Fake Device Enrollment

**Attack Description:**  
An attacker attempts to enroll an attacker-controlled machine into a ZTV vault to gain access to credentials.

**Attacker Capability Required:**  
Physical or network access to the target user sufficient to intercept the enrollment QR code or SAS exchange.

**What ZTV Does:**  
New device enrollment requires the user to approve the new device on an already-enrolled device by scanning a QR code or confirming a Short Authentication String (SAS). The new device's public key is added to the device graph only after this out-of-band confirmation. A device not in the device graph cannot decrypt vault events (events are encrypted to enrolled device keys).

**ZTV Component Providing Protection:**  
SYNC.md device graph; QR/SAS pairing protocol; Principle #10 (server never trusted — enrollment cannot be approved by the relay).

**What ZTV Cannot Prevent:**  
If the attacker can observe the QR code (e.g., shoulder-surfing or screen capture during enrollment), they could enroll an attacker-controlled device. This is a social engineering attack on the enrollment UX, not a ZTV architectural flaw.

**Residual Risk:** Low

**Recommended Test Case:**  
Attempt to enroll a second device without completing the QR/SAS verification step on the first device. Confirm the new device is not added to the device graph and cannot read vault events.

---

## T-15: Device Theft (Unlocked Laptop)

**Attack Description:**  
A laptop is stolen while unlocked (or briefly unattended). The attacker attempts to access the ZTV vault.

**Attacker Capability Required:**  
Physical access to an unlocked machine.

**What ZTV Does:**  
ZTV enforces a configurable session timeout (via `chrome.alarms`). After timeout, the vault is locked and a fresh Windows Hello prompt is required. The extension popup does not display credentials without Hello. The native host does not respond to fill requests without a valid Hello challenge.

**ZTV Component Providing Protection:**  
Session timeout (alarms API); per-fill Hello prompt; Principle #9 (fresh Hello per secret).

**What ZTV Cannot Prevent:**  
If the machine is stolen within the session timeout window and the session is still active, and if Windows Hello is configured with a PIN (rather than biometric), a determined attacker might attempt PIN guessing. Windows Hello's lockout policies (configured by OS, not ZTV) are the defense here. ZTV does not control Windows Hello lockout parameters.

**Residual Risk:** Medium (depends on Windows Hello lockout configuration)

**Recommended Test Case:**  
Configure a 1-minute session timeout. Wait for timeout. Attempt to trigger a fill. Confirm that Windows Hello prompt appears and that fill is blocked until Hello is satisfied.

---

## T-16: TPM Failure

**Attack Description:**  
The TPM chip fails or is reset, causing the loss of the hardware-protected VaultRootKey. The vault file remains but cannot be decrypted.

**Attacker Capability Required:**  
Hardware failure (not a deliberate attack; an operational risk).

**What ZTV Does:**  
If a recovery kit was created (3-of-5 Shamir shares over the RecoveryRootSecret), the vault can be recovered on a new machine. The recovery kit contains enough information to reconstruct the VaultRootKey equivalent on a new TPM. See RECOVERY.md for the step-by-step procedure.

**ZTV Component Providing Protection:**  
RECOVERY.md Shamir's Secret Sharing; CRYPTO.md RecoveryRootSecret derivation.

**What ZTV Cannot Prevent:**  
If no recovery kit was created before the TPM failure, the VaultRootKey is permanently lost and the vault cannot be decrypted. ZTV cannot recover from this scenario. The install wizard strongly encourages recovery kit creation before the vault is relied upon for serious use.

**Residual Risk:** High (if no recovery kit exists); Low (if recovery kit was created and securely stored)

**Recommended Test Case:**  
Simulate TPM key loss by unregistering the CNG platform key. Confirm vault cannot be opened. Restore using a recovery kit; confirm vault opens successfully after recovery.

---

## T-17: Motherboard Replacement

**Attack Description:**  
A motherboard replacement results in a new TPM module (or a reset discrete TPM), destroying the TPM-bound VaultRootKey.

**Attacker Capability Required:**  
Hardware repair scenario (not a deliberate attack).

**What ZTV Does:**  
Same as T-16. Recovery kit with 3-of-5 Shamir shares is the mitigation.

**ZTV Component Providing Protection:**  
Same as T-16.

**What ZTV Cannot Prevent:**  
Same as T-16.

**Residual Risk:** High (if no recovery kit); Low (if kit exists)

**Recommended Test Case:**  
Same as T-16.

---

## T-18: Lost Windows User Profile

**Attack Description:**  
The Windows user profile is corrupted, deleted, or lost (OS reinstall, disk failure). The vault file at `%LOCALAPPDATA%\ZeroTrustVault\vault.json` may also be lost.

**Attacker Capability Required:**  
Accidental data loss or ransomware scenario.

**What ZTV Does:**  
If the vault file is covered by a backup policy (BACKUP.md), and if the recovery kit is available, data can be recovered. The recovery process creates a new Windows profile with a new TPM key, uses the recovery kit to reconstruct the VaultRootKey, and re-encrypts the vault under the new key.

**ZTV Component Providing Protection:**  
BACKUP.md encrypted backup; RECOVERY.md recovery procedure.

**What ZTV Cannot Prevent:**  
If there is no backup of `vault.json` and no recovery kit, data is permanently lost. If the backup was encrypted and the recovery kit is also lost, the backup cannot be decrypted on a new machine.

**Residual Risk:** High (without backup + recovery kit); Low (with both)

**Recommended Test Case:**  
Delete the vault file. Restore from backup. Use recovery kit to re-key the vault on a different Windows profile. Confirm credentials are accessible.

---

## T-19: Supply-Chain Tampering (Modified Native Host Binary)

**Attack Description:**  
An attacker modifies the native host binary (`ZeroTrustVault.Host.exe`) between download and installation, inserting a backdoor that exfiltrates decrypted credentials.

**Attacker Capability Required:**  
Ability to intercept and modify the download, or access to the distribution server.

**What ZTV Does:**  
The native host binary is signed with an Authenticode certificate at release (sign.ps1). The installer (`install.ps1`) verifies the digital signature and compares the signing thumbprint against a reference value in `thumbprint.txt`. If verification fails, installation aborts. The reference thumbprint is distributed out-of-band (not in the same download package) so an attacker who modifies both the binary and the thumbprint.txt cannot trivially defeat this check.

**ZTV Component Providing Protection:**  
Authenticode signing; install.ps1 signature verification; RELEASE_CHECKLIST.md thumbprint out-of-band distribution.

**What ZTV Cannot Prevent:**  
As of v0.5.0, the extension runs in Chrome Developer Mode, not the Web Store. There is no Web Store code review or update signing. The Authenticode certificate's trustworthiness depends on the certificate authority and the key security of the signing certificate. A compromised signing key defeats this protection.

**Residual Risk:** Medium (Developer Mode; no Web Store review; CA trust required)

**Recommended Test Case:**  
Modify one byte of the native host binary. Run install.ps1. Confirm it aborts with a signature verification error before registering the native host. Confirm the original signed binary installs successfully.

---

## T-20: Malicious Extension Update

**Attack Description:**  
An attacker publishes a malicious version of the ZTV extension (via a compromised Web Store account or a Developer Mode local update) that extracts credentials.

**Attacker Capability Required:**  
Control of the extension's Web Store developer account, or local file system access in Developer Mode.

**What ZTV Does:**  
The extension's Content Security Policy (CSP) in `manifest.json` prohibits `eval()`, inline scripts, and remote script sources. Manifest V3 enforces that no remotely-fetched code can execute. The extension has no `script-src` pointing to external servers. An update that tries to load remote code at runtime is blocked by the CSP before execution.

**ZTV Component Providing Protection:**  
manifest.json CSP; MV3 restrictions; AUDIT_CHECKLIST.md CSP item.

**What ZTV Cannot Prevent:**  
A malicious update that contains the attack code locally (not fetched remotely) passes the CSP. CSP does not prevent a malicious extension from using its legitimately-granted `nativeMessaging` permission to issue crafted requests to the native host. The native host's rate limiting and per-credential Hello still apply, but a malicious extension update is a severe trust compromise.

**Residual Risk:** Medium (requires Developer Account compromise or local file access)

**Recommended Test Case:**  
Inspect `manifest.json` and verify the CSP string. Confirm no `unsafe-eval`, no `unsafe-inline`, no remote `script-src` entries. Add to AUDIT_CHECKLIST.md.

---

## T-21: Backup File Theft

**Attack Description:**  
An attacker obtains a copy of a ZTV backup file (from USB drive, backup location, or network share) and attempts to read credentials from it.

**Attacker Capability Required:**  
Physical or network access to the backup storage location.

**What ZTV Does:**  
Backup files are encrypted with AES-256-GCM under a key derived from the VaultRootKey (see BACKUP.md and CRYPTO.md). The file includes a MAC (HMAC-SHA256) over the header and ciphertext. Without the TPM-held VaultRootKey or the recovery kit, the ciphertext is opaque.

**ZTV Component Providing Protection:**  
BACKUP.md encryption; CRYPTO.md backup key derivation; HMAC integrity protection.

**What ZTV Cannot Prevent:**  
The backup exposes metadata (vaultId, checkpoint, timestamp). If the attacker also has the recovery kit shares (or can reconstruct VaultRootKey from 3 of 5 shares), the backup can be decrypted. This is intentional: the recovery kit is designed to allow exactly this recovery.

**Residual Risk:** Low (ciphertext only, without recovery kit)

**Recommended Test Case:**  
Copy a backup file to a machine that does not have ZTV installed. Attempt to read it with a hex editor and any available ZTV tooling. Confirm only the unencrypted header (vaultId, version, checkpoint) is readable and credential content is ciphertext.

---

## T-22: Shared Vault Revocation

**Attack Description:**  
A device is removed from a shared vault (e.g., an employee leaves, a device is lost). The removed device may still have previously decrypted events cached locally and may attempt to access future events.

**Attacker Capability Required:**  
Access to the removed device, which was previously authorized.

**What ZTV Does:**  
A `RemoveDevice` event is broadcast to all remaining enrolled devices. Receiving devices rotate the epoch key (see SYNC.md epoch key rotation). New events are encrypted under the new epoch key, which is not shared with the removed device. Previously delivered events that the removed device already decrypted locally cannot be un-decrypted — this is an inherent limitation of forward-secrecy without key deletion enforcement.

**ZTV Component Providing Protection:**  
SYNC.md `RemoveDevice` event; epoch key rotation; password rotation checklist (shown to user after revocation).

**What ZTV Cannot Prevent:**  
Credentials that the removed device previously decrypted are still known to that device locally. ZTV surfaces a password rotation checklist after revocation to prompt the user to change credentials that were accessible by the removed device. But ZTV cannot force a remote device to delete its local data.

**Residual Risk:** Medium (historical credential knowledge on removed device)

**Recommended Test Case:**  
Enroll two devices. Remove device B. Rotate epoch key on device A. Confirm device B cannot decrypt new events. Confirm password rotation checklist is displayed to the user on device A.
