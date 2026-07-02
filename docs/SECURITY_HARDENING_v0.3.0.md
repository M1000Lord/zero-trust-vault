# Zero-Trust Vault — Security Hardening v0.3.0

This release implements the security fixes requested after comparing the extension against the engineering/security PDF.

## Critical changes implemented

### 1. Hello-gated KEK protection

- New vaults use `TpmHello` protection mode.
- The root vault key is wrapped by a non-exportable Microsoft Platform Crypto Provider RSA key.
- The CNG key is created with `CngUIProtectionLevels.ForceHighProtection` so private-key use is OS-gated through Windows Security / Windows Hello consent.
- Older `Tpm` vaults are still readable and are automatically migrated to `TpmHello` after a successful unlock.
- DPAPI fallback is no longer silently used for new vaults. It is only allowed if `ZTV_ALLOW_DPAPI_FALLBACK=1` is explicitly set by a developer/admin.

### 2. Release builds no longer honor dev biometric bypass

- `ZTV_DEV_BYPASS=1` is now compiled behind `#if DEBUG`.
- Release builds ignore the variable completely.
- The popup/native status can still report debug bypass when a Debug build is intentionally used.

### 3. Authenticated origin metadata

- The native host no longer trusts the stored `aad` field as authority.
- AAD is rebuilt at decrypt time from canonical context:

```text
normalizedOrigin | credentialId | encryptionVersion
```

- If the stored metadata does not match the canonical context, the record is rejected.
- If an attacker edits `normalizedOrigin` in the vault file, the record will not decrypt/list after unlock.
- Account summaries now omit records whose authenticated metadata or ciphertext fails validation.

### 4. Native session is origin-bound

- The native host now stores `_sessionOrigin` beside `_sessionId`.
- `listCredentialSummariesForOrigin`, `decryptSelectedCredentialForOrigin`, and `deleteCredential` require the request origin to equal the unlock origin.
- A valid session for one origin can no longer be reused against another origin.

### 5. Manifest least-privilege adjustment

- Removed mandatory `tabs` permission.
- Kept `tabs` as optional only.
- Main required permissions are now: `nativeMessaging`, `activeTab`, `scripting`, `storage`, `alarms`.

## Remaining non-code requirements before public/commercial use

These cannot be fully completed inside the source zip alone:

- Code-sign the native host executable and installer.
- Sign/package the browser extension release.
- Run Windows build/test on a real Windows 10/11 device with TPM + Windows Hello configured.
- Add CI with dependency scanning and release artifact hashing.
- Run external security review before giving this to real users.

## Expected immunity after this release

Approximate score if the Windows build confirms the CNG Hello-protected key works correctly:

- Stolen vault file: 90/100
- Phishing/lookalike domains: 80/100
- Malicious webpage: 60/100
- Same-user local malware: 55/100
- Admin/root malware: 5/100
- Supply-chain/malicious update: 40/100 until signing/audit exists
- Native host abuse: 80/100

Overall: around 78–82/100 as a hardened local MVP, not 100% immunity.
