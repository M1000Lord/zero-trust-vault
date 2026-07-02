# Implementation Status — v2.0.0

The sections below are a dated history (v0.3.1 through v0.5.1) and were not
kept current — the shipped version is now v2.0.0 (see manifest.json,
build-info.json, AUDIT_PACKAGE). The hardening work done since v0.5.1
(native-host caller authentication, centralized command authorization,
root-key lifetime redesign, fill/reveal path separation, vault invariant
checking, anti-rollback protection, recovery root rotation, pairing replay
protection) is tracked in KNOWN_LIMITATIONS.md rather than backfilled here.

## Completed

- MV3 extension shell.
- Popup UX with current origin, account preview after unlock, fill button, and per-site Fill + Sign in.
- Content script login-field detection and fail-closed autofill pre-checks.
- Native messaging host with strict command allowlist and JSON envelope validation.
- Local encrypted vault with AES-GCM, HKDF per credential, random salt/nonce, atomic writes.
- Windows Hello / Windows Security foreground focus shim.
- HTTP, IDN/punycode, high-risk auto-submit and suspicious DOM safeguards.
- `TpmHelloGesture` protected root-key wrapping using a non-exportable CNG/TPM key plus explicit Windows Hello user-presence before unwrap.
- Automatic migration from legacy `Tpm` and v0.3.0 `TpmHello` protection to `TpmHelloGesture` after successful unlock.
- Debug-only biometric bypass; release builds ignore `ZTV_DEV_BYPASS`.
- Canonical AAD rebuild and authenticated-metadata rejection.
- Native unlock sessions bound to the exact origin.
- Least-privilege manifest: `tabs` removed from mandatory permissions.

## Still required before real-world release

- Build on Windows 10/11 and verify the unlock flow is one prompt only: Windows Hello/fingerprint, with no second CNG key-password dialog.
- Sign native host exe and installer.
- Package/sign extension release.
- Add CI, dependency scanning, artifact hashes, and regression tests.
- External security audit.

## Security score estimate

- Current source-level hardening target: ~78–82/100 if Windows Hello gating and TPM/CNG wrapping work as expected on the target machine.
- Not immune to admin/root malware, compromised websites after submission, or malicious signed updates.


## v0.3.1 hotfix

- Removed the v0.3.0 `ForceHighProtection` behavior for newly-created KEK keys because it can ask for a separate CNG key password after fingerprint verification.
- Added `TpmHelloGesture` as the preferred protection mode.
- Added `reset-test-vault.ps1` for users who want to discard test credentials and recreate the vault cleanly.


## v0.4.0 Ultra Security Update

Implemented:
- No auto-submit path in popup/service worker/content script.
- Fresh Windows Hello approval before every credential decrypt/fill.
- Vault schema v2 with HMAC origin index and encrypted origin/label/timestamps.
- Automatic v0.3.x legacy metadata migration after successful unlock.
- Locked origin-count privacy: no saved-site enumeration before unlock.

Expected new vault record shape: `originHashB64`, `itemSaltB64`, `itemNonceB64`, `cipherB64`, `tagB64`; no plaintext `normalizedOrigin`, `maskedLabel`, `createdAt`, `updatedAt`, or `lastUsedAt` for v2 records.


## v0.5.0 production-candidate hardening

Implemented:
- New preferred `TpmHelloStrict` key-protection mode using CNG `ForceHighProtection`.
- Root vault key is no longer retained for the full unlock session; it is wiped after unlock/list, fill, save, and delete.
- Native origin normalization now uses IDN/punycode canonicalization.
- Fill is bound to the focused active tab/window and blocks if focus changes.
- Content script blocks signup, reset/change-password, and ambiguous multi-password forms.
- Popup exposes exact-origin credential deletion through the existing native Hello-gated delete command.
- Round-trip test now uses a throwaway vault and valid extension id.
- Release packager added under `tools/package-release.ps1`.

Still required before public release:
- Real-device Windows Hello/TPM validation for the one-prompt unlock/fill flow.
- Signed native host and signed installer.
- Signed/package-reviewed browser extension.
- CI, static analysis, dependency scanning, release hashes, and external audit.


## v0.5.1 Windows Hello UX correction

Implemented:
- Restored `TpmHelloGesture` as the preferred key-protection mode to avoid recurring CNG key-password prompts.
- Kept `TpmHelloStrict` readable for users who briefly tested v0.5.0 strict mode.
- Existing strict vaults migrate back to `TpmHelloGesture` after one successful unlock.
- `reset-test-vault.ps1` now backs up only `vault.json` instead of moving the installed native host folder.

Security tradeoff:
- This removes the recurring OS-enforced CNG key-password prompt and relies on the explicit Windows Hello gate plus non-exportable local key wrapping.
- This is the intended daily UX path; users who want strict CNG prompting should keep a separate hardened build and accept the extra prompt.
