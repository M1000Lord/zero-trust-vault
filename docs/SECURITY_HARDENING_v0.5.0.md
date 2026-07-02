# Zero-Trust Vault v0.5.0 - Production-Candidate Hardening

Goal: move the project from a strong prototype toward a release candidate for a narrow local-only Windows threat model.

## Implemented Changes

### 1. Strict TPM/CNG Key Protection By Default

New vaults now prefer `TpmHelloStrict`, backed by a non-exportable Microsoft Platform Crypto Provider RSA key with `CngUIProtectionLevels.ForceHighProtection`.

This restores OS-enforced protection around private-key use. The native host still performs an explicit Windows Hello user-presence check before unwrap, so credential release is dual-gated:

1. application-level fresh Windows Hello approval
2. OS/CNG high-protection key access

The previous `TpmHelloGesture` mode remains supported for legacy vaults. DEBUG builds may opt into gesture-only KEK creation for automated throwaway tests only.

### 2. Root Key Lifetime Reduction

The unwrapped root vault key is no longer kept in memory for the full 45-second session.

Unlock now:

- prompts Windows Hello
- unwraps the root key
- migrates and lists current-origin accounts
- caches only account summaries
- wipes the root key immediately

Fill/delete now unwrap fresh after another Windows Hello approval, perform one operation, then wipe the root key again.

### 3. Native IDN Canonicalization

The native host canonicalizes origins with `Uri.IdnHost`, so Unicode domains normalize to punycode before policy checks and origin hashing.

### 4. Focused-Tab Binding

The service worker now targets the active tab in the last focused normal window and blocks fill if the target tab/window is no longer focused.

### 5. Safer DOM Rejection

The content script now blocks:

- multiple visible password fields
- signup/register forms
- password reset/change forms
- `autocomplete="new-password"` fields

This avoids filling secrets into ambiguous or account-creation flows.

### 6. Credential Delete UI

The popup now exposes delete for the current exact origin. The native host requires a valid session and a fresh Windows Hello approval before deleting.

### 7. Test Safety

The native round-trip test now:

- uses a throwaway temp vault directory
- uses a valid Chrome extension id shape
- runs only against Debug builds
- uses DEBUG-only biometric and weak-KEK bypass flags
- validates add/list/decrypt/delete/lock flows

## Security Tradeoff

`TpmHelloStrict` may show a stronger Windows Security/CNG key prompt on some machines. That is intentional for this hardened candidate. If the UX is unacceptable, do not silently downgrade production builds; decide explicitly whether local-only strictness or smoother UX is the product priority.

## Remaining Release Blockers

- Real Windows Hello validation on Windows 10/11 with TPM.
- Code signing for native host and installer.
- Extension packaging/signing.
- CI with repeatable build checks.
- Dependency scanning and release artifact hashes.
- External security audit.
- Chrome Web Store privacy/security review material.
