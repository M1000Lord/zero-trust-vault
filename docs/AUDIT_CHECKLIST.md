# Zero-Trust Vault — Security Audit Checklist

Version: v0.5.0-hardened  
Date: 2026-06-29

This checklist is intended for use by an independent security auditor, a pre-release internal review, or a developer performing a targeted self-audit. Each item is a specific, testable claim about the ZTV implementation. Items are organized by component.

Status legend: [PASS] / [FAIL] / [PARTIAL] / [NOT TESTED]

---

## Section 1: Native Host (ZeroTrustVault.Host.exe)

### 1.1 Command Schema Validation

- [ ] 1.1.1 Every incoming command JSON is validated against a strict schema before any processing occurs. Unknown fields are rejected (not ignored).
- [ ] 1.1.2 The `command` field is validated against an allowlist of known command names. Unknown command names return `ERR_SCHEMA_INVALID`.
- [ ] 1.1.3 Required fields for each command type are checked to be present and of the correct type. Missing or wrongly-typed fields return `ERR_SCHEMA_INVALID`.
- [ ] 1.1.4 The `requestId` field is validated as a UUID v4 format string and echoed back in all responses.
- [ ] 1.1.5 Integer fields (e.g., `timestamp`) are bounds-checked. Extremely large or negative values do not cause crashes or undefined behavior.
- [ ] 1.1.6 String fields are length-bounded. A string exceeding the maximum allowed length causes rejection, not a buffer overflow or allocation error.

### 1.2 Origin Validation

- [ ] 1.2.1 The native host rejects any origin that does not begin with `https://`. HTTP origins return `ERR_HTTP_REJECTED` before any credential lookup.
- [ ] 1.2.2 The native host rejects origins containing non-ASCII characters in any host label (IDN detection) unless IDN opt-in is explicitly enabled. Return code: `ERR_IDN_REJECTED`.
- [ ] 1.2.3 The native host rejects origins where any host label is a punycode label (`xn--` prefix) unless IDN opt-in is explicitly enabled.
- [ ] 1.2.4 Origin matching uses HMAC-SHA256 computed over the exact canonical origin string. String equality comparison on the raw origin is not used for credential selection.
- [ ] 1.2.5 The canonical form of the origin is verified: scheme lowercase, host lowercase, port omitted if 443, no trailing slash, no path component.
- [ ] 1.2.6 A fill request for an origin with no matching credential returns `ERR_ORIGIN_NO_MATCH` — it does not return an empty credential set or a success with null fields.

### 1.3 HTTP/IDN Rejection

- [ ] 1.3.1 Test: submit `{"command":"fillRequest","origin":"http://example.com"}`. Confirm response is `{"result":"error","errorCode":"ERR_HTTP_REJECTED"}`.
- [ ] 1.3.2 Test: submit `{"command":"fillRequest","origin":"https://аpple.com"}` (Cyrillic а). Confirm `ERR_IDN_REJECTED`.
- [ ] 1.3.3 Test: submit `{"command":"fillRequest","origin":"https://xn--pple-43d.com"}` (punycode). Confirm `ERR_IDN_REJECTED`.
- [ ] 1.3.4 Test with IDN opt-in enabled: submit IDN origin. Confirm the request is processed (not rejected).

### 1.4 Rate Limiting

- [ ] 1.4.1 The native host enforces a per-origin rate limit on fill requests. Exceeding the limit returns `ERR_RATE_LIMITED`.
- [ ] 1.4.2 The rate limit applies globally (not just per-origin) to prevent an attacker who controls many origins from draining credentials faster.
- [ ] 1.4.3 The rate limiter uses an exponential backoff after repeated failures, not a fixed time window that resets completely.
- [ ] 1.4.4 Rate limit state is not persisted across native host restarts (acceptable; this is a per-session control).

### 1.5 No Development Bypass in Release Builds

- [ ] 1.5.1 The string `DEV_BYPASS` does not appear in the compiled native host assembly (`strings ZeroTrustVault.Host.exe | grep DEV_BYPASS`).
- [ ] 1.5.2 The string `devBypass` does not appear.
- [ ] 1.5.3 The string `DPAPI_FALLBACK` does not appear.
- [ ] 1.5.4 The string `TEST_KEY` does not appear.
- [ ] 1.5.5 No conditional compilation symbol that bypasses Hello authentication is defined in the Release build configuration.
- [ ] 1.5.6 The build configuration used for the release binary is confirmed to be `Release` (not `Debug`).

### 1.6 TOTP Handling

- [ ] 1.6.1 TOTP seed bytes are decrypted inside the native host process and used in-process for code generation. They are never serialized to any response that leaves the native host.
- [ ] 1.6.2 The TOTP generation response contains only the 6-digit code string and `remainingSeconds`. It does not include the seed, the HMAC intermediate value, or any keying material.
- [ ] 1.6.3 The TOTP seed byte array is explicitly zeroed (`Array.Clear` or `CryptographicOperations.ZeroMemory`) immediately after the 6-digit code is computed.
- [ ] 1.6.4 TOTP generation requires a fresh Windows Hello challenge (not a cached session approval).

### 1.7 AEAD AAD Correctness

- [ ] 1.7.1 For credential records: the AAD contains `schemaVersion`, `vaultId`, `itemId`, `originHash`, `deviceEpoch`, and `purpose = "CRED"`.
- [ ] 1.7.2 For TOTP seed records: the AAD contains the same fields with `purpose = "TOTP"`.
- [ ] 1.7.3 For metadata records: `purpose = "META"`.
- [ ] 1.7.4 For event payloads: `purpose = "EVNT"`.
- [ ] 1.7.5 For backup content: `purpose = "BACK"`.
- [ ] 1.7.6 The same `purpose` value is never reused across two different record types.
- [ ] 1.7.7 Test: modify a single byte in a stored AEAD ciphertext in vault.json. Confirm the decryption attempt returns an authentication failure (not a partial result or silent error).
- [ ] 1.7.8 Test: copy an AEAD ciphertext from one vault item slot to another. Confirm decryption fails (itemId in AAD does not match).

### 1.8 Nonce Uniqueness

- [ ] 1.8.1 Nonces are generated using `BCryptGenRandom` (or equivalent cryptographically secure random source). Nonces are never derived from counters, timestamps, or record indices.
- [ ] 1.8.2 Each nonce is stored alongside its ciphertext. The native host does not assume a fixed nonce per key.
- [ ] 1.8.3 The native host does not reuse nonces across calls under the same key (verified by: encrypt two different plaintext values and confirm the nonces differ).

### 1.9 Constant-Time Comparison

- [ ] 1.9.1 All HMAC-SHA256 MAC verification operations use `CryptographicOperations.FixedTimeEquals` (or equivalent constant-time comparison function). Standard `Array.Equals` or `==` is not used.
- [ ] 1.9.2 AES-GCM authentication tag comparison is performed by the CNG `BCryptDecrypt` function internally. The tag is not extracted and compared separately.
- [ ] 1.9.3 Shamir share checksum comparison uses constant-time comparison.
- [ ] 1.9.4 Backup MAC comparison uses constant-time comparison.

### 1.10 Shamir's Secret Sharing (3-of-5)

- [ ] 1.10.1 The threshold is exactly 3 (not 2, not 1).
- [ ] 1.10.2 The total shares generated is exactly 5.
- [ ] 1.10.3 Test: reconstruct with exactly 3 shares. Confirm success.
- [ ] 1.10.4 Test: attempt reconstruction with exactly 2 shares. Confirm failure.
- [ ] 1.10.5 The GF(256) implementation uses the AES primitive polynomial (x^8 + x^4 + x^3 + x + 1).
- [ ] 1.10.6 The SSS implementation is tested against at least one known reference test vector.
- [ ] 1.10.7 The `RecoveryRootSecret` is zeroed from memory immediately after share generation.

### 1.11 Device Signing Verification

- [ ] 1.11.1 When the native host receives a sync event, it verifies the ECDSA P-256 signature before processing the event's payload.
- [ ] 1.11.2 Signature verification uses the signing device's public key from the device graph. A public key not in the device graph causes rejection.
- [ ] 1.11.3 Events signed by a removed device (after the `RemoveDevice` event's HLC) are rejected.
- [ ] 1.11.4 Test: tamper with a byte in the event payload. Confirm `ERR_SIG_INVALID`.
- [ ] 1.11.5 Test: create a valid event signed by a key not in the device graph. Confirm rejection.

### 1.12 Event Chain Integrity

- [ ] 1.12.1 The native host verifies the `previousHash` field of each event against the SHA-256 of the previous event's canonical form.
- [ ] 1.12.2 A gap in the hash chain returns `ERR_CHAIN_BROKEN`.
- [ ] 1.12.3 The local root hash is stored encrypted and verified on load.
- [ ] 1.12.4 Test: modify the `previousHash` of an event in events.json. Confirm the native host detects and reports the chain break.

---

## Section 2: Extension

### 2.1 Content Security Policy

- [ ] 2.1.1 `manifest.json` contains a strict CSP for the extension pages (`popup.html`): no `unsafe-eval`, no `unsafe-inline`, no remote `script-src` entries.
- [ ] 2.1.2 The service worker CSP does not include `script-src` pointing to any external origin.
- [ ] 2.1.3 No `eval()`, `new Function()`, or `setTimeout(string, ...)` calls exist in any extension JavaScript file.
- [ ] 2.1.4 No remotely-fetched scripts are loaded by any extension component.

### 2.2 No Remote Code Execution

- [ ] 2.2.1 The extension does not use `chrome.scripting.executeScript` with a string source. Script injection uses file references only.
- [ ] 2.2.2 The extension does not use `fetch()` or `XMLHttpRequest` to load and execute external JavaScript.
- [ ] 2.2.3 `manifest.json` uses `"manifest_version": 3` (MV3).

### 2.3 No Secrets in Service Worker

- [ ] 2.3.1 `service_worker.js` does not store decrypted credential values in any module-level variable that persists beyond a single fill operation.
- [ ] 2.3.2 After routing the fill command to `content.js`, `service_worker.js` zeroes or replaces its reference to the credential value.
- [ ] 2.3.3 A decrypted credential value is not logged to `console.log` or any other logging mechanism.

### 2.4 No Secrets in Storage

- [ ] 2.4.1 `chrome.storage.local.set` is never called with a field containing a password, TOTP seed, or any vault key material.
- [ ] 2.4.2 `chrome.storage.sync.set` is never called with any sensitive field.
- [ ] 2.4.3 Verify by auditing all calls to `chrome.storage.local.set` in the extension source: each call contains only settings fields (timeout, preferences, etc.).

### 2.5 Exact Origin Match

- [ ] 2.5.1 The origin sent to the native host is extracted via `chrome.tabs.query` — the actual reported origin, not a value from the page's JavaScript.
- [ ] 2.5.2 The origin is not modified (lowercased, stripped, or otherwise normalized) by the extension before sending. Normalization happens in the native host.
- [ ] 2.5.3 Test: visit `https://example.com`; trigger a fill request; confirm the native host receives `https://example.com` (not `https://example.com/path` or any path-appended form).

### 2.6 Content Script Cannot Access Vault

- [ ] 2.6.1 `content.js` does not contain any call to `chrome.runtime.connectNative`.
- [ ] 2.6.2 `content.js` does not send messages that contain credential values back to `service_worker.js`. It only sends form detection notifications.
- [ ] 2.6.3 `content.js` receives fill commands with the credential value from `service_worker.js`. This is the narrowest path — the value crosses Chrome IPC. Document this as the irreducible exposure point.
- [ ] 2.6.4 `content.js` does not fill credentials into iframes whose origin differs from the top-level frame.
- [ ] 2.6.5 `content.js` does not fill credentials into iframes whose src is an HTTP URL.

### 2.7 No Auto-Submit

- [ ] 2.7.1 `content.js` does not synthesize click events on submit buttons after fill.
- [ ] 2.7.2 `content.js` does not synthesize `submit` events on form elements.
- [ ] 2.7.3 `content.js` does not use `form.submit()` after fill.
- [ ] 2.7.4 Test: perform a fill; confirm the form is not submitted automatically. The user must press Enter or click the button manually.

### 2.8 No Fill into HTTP or IDN

- [ ] 2.8.1 `service_worker.js` checks the current tab URL before initiating a fill. If the URL scheme is `http://`, the fill is aborted before contacting the native host.
- [ ] 2.8.2 The check in `service_worker.js` is a defense-in-depth measure; the native host performs the authoritative check. Both layers should independently enforce this.

### 2.9 Popup Never Sees TOTP Seed

- [ ] 2.9.1 The response from the native host for a `generateTotp` command contains only `{"totp": "123456", "remainingSeconds": 14}`. Audit the response parsing code in `service_worker.js` to confirm no seed field is present.
- [ ] 2.9.2 The popup displays only the 6-digit TOTP code. There is no UI element that could display the seed even if one were accidentally returned.

---

## Section 3: Installer

### 3.1 Signature Verification

- [ ] 3.1.1 `install.ps1` calls `Get-AuthenticodeSignature` on `ZeroTrustVault.Host.exe` and checks that `Status` equals `Valid`.
- [ ] 3.1.2 `install.ps1` compares the signing certificate's thumbprint against the reference value in `thumbprint.txt`. A thumbprint mismatch causes the script to abort before writing any registry key or file.
- [ ] 3.1.3 Test: provide a valid Authenticode signature from a different certificate (not the ZTV release cert). Confirm the thumbprint check fails.
- [ ] 3.1.4 The thumbprint comparison is a string equality check, not a prefix or substring match.

### 3.2 Registry Cleanup

- [ ] 3.2.1 `uninstall.ps1` removes the HKCU registry key for the native messaging host.
- [ ] 3.2.2 If a HKLM key was created (admin install), `uninstall.ps1` removes it when run as admin.
- [ ] 3.2.3 After uninstall, no ZTV registry keys remain under `HKCU:\Software\Google\Chrome\NativeMessagingHosts\`.

### 3.3 No Plaintext in Temp Files

- [ ] 3.3.1 `install.ps1` does not write any plaintext credential, key material, or vault content to `%TEMP%` or any other temp directory.
- [ ] 3.3.2 Log files written by the installer (`install.log`) contain only status messages, not secrets.
- [ ] 3.3.3 PowerShell `Write-Host` or `Write-Output` calls in the installer do not print credential values.

---

## Section 4: Backup

### 4.1 MAC Verification on Restore

- [ ] 4.1.1 `restore-vault.ps1` (or the native host restore path) verifies the BackupMAC before attempting any decryption.
- [ ] 4.1.2 A corrupt backup file (modified ciphertext) causes restore to fail with `ERR_BACKUP_MAC_FAILED`, not a partial restore.
- [ ] 4.1.3 Test: modify one byte in a `.ztv` backup file. Confirm restore aborts with MAC failure.

### 4.2 No Plaintext Export

- [ ] 4.2.1 There is no command or UI path that exports vault credentials in plaintext.
- [ ] 4.2.2 There is no "export to CSV" or "export to JSON" feature in release builds.
- [ ] 4.2.3 The backup file format does not include any plaintext credential field at any offset.

### 4.3 USB Opt-In

- [ ] 4.3.1 The backup script rejects removable drive paths unless `-IncludeUsb` is explicitly specified.
- [ ] 4.3.2 Test: run `backup-vault.ps1 -Destination "E:\"` without `-IncludeUsb`. Confirm rejection with a clear error message.

---

## Section 5: Recovery

### 5.1 3-of-5 Threshold

- [ ] 5.1.1 The recovery wizard requires the user to enter at least 3 shares before "Reconstruct" is available.
- [ ] 5.1.2 Entering 2 shares and clicking Reconstruct returns an error, not a partial result.
- [ ] 5.1.3 Entering 3 valid shares reconstructs the `RecoveryRootSecret` correctly (verified against a known test vector).

### 5.2 Vendor Cannot Recover

- [ ] 5.2.1 The `RecoveryRootSecret` is generated on-device and never transmitted to any server, API, or telemetry endpoint.
- [ ] 5.2.2 The native host has no built-in escrow or key recovery API.
- [ ] 5.2.3 The developer has no copy of any share or the `RecoveryRootSecret`.

### 5.3 New Device Gets New TPM Key

- [ ] 5.3.1 After recovery on a new machine, the VaultRootKey is wrapped under the new machine's TPM. The old machine's TPM key is not transferred.
- [ ] 5.3.2 The new DeviceId is derived from the new device's ECDSA P-256 key, which is different from the old device's key.
- [ ] 5.3.3 A `DeviceEnrolled` event is appended to the event log recording the new device's enrollment.

---

## Section 6: Sync

### 6.1 Event Chain Integrity

- [ ] 6.1.1 All received events are verified for signature correctness before being applied to the local vault.
- [ ] 6.1.2 The `previousHash` field is verified against the SHA-256 of the previous event.
- [ ] 6.1.3 A chain break causes the sync module to halt and alert the user, not silently skip the broken event.

### 6.2 Device Graph Verification

- [ ] 6.2.1 Events are only accepted from devices whose public key is in the device graph.
- [ ] 6.2.2 The device graph is loaded from the vault's encrypted storage, not from the relay.
- [ ] 6.2.3 A device removed via `RemoveDevice` cannot enroll itself back without approval from an existing enrolled device.

### 6.3 No Plaintext to Relay

- [ ] 6.3.1 The sync module encrypts event payloads with AES-256-GCM before writing to the relay backend.
- [ ] 6.3.2 Plaintext field values (username, password, TOTP seed) do not appear in the `encryptedPayload` field before encryption.
- [ ] 6.3.3 Test: inspect the relay storage directly. Confirm no credential fields are readable in any stored event blob.
