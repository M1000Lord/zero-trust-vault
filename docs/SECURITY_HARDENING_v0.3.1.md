# Zero-Trust Vault — Security Hardening v0.3.1

This patch fixes the unwanted second Windows Security dialog shown after fingerprint verification.

## Problem fixed

v0.3.0 created the vault KEK with CNG `ForceHighProtection`.
On many Windows installations this does **not** behave like fingerprint-only Windows Hello unlock.
Instead, Windows shows a second dialog:

```text
This application needs to use a cryptographic key
Password: Enter Password
```

That password is a CNG protected-key password, not the vault password and not the fingerprint gesture.

## New behavior

v0.3.1 changes the protection flow:

1. The native host explicitly calls Windows Hello / Windows Security for one live user-presence gesture.
2. After fingerprint/PIN succeeds, the TPM/CNG wrapping key is used without creating a second key-password UI.
3. Normal unlock should now be:

```text
fingerprint / Windows Hello -> vault unlocked
```

## Code changes

- Added new preferred protection mode: `TpmHelloGesture`.
- Added new CNG key name: `ZeroTrustVaultKEK.v3.hello-gesture`.
- Removed `CngUIProtectionLevels.ForceHighProtection` from newly-created KEK keys.
- Kept the key non-exportable with Microsoft Platform Crypto Provider when available.
- Kept explicit Windows Hello verification before every root-key unwrap.
- Kept legacy v0.3.0 `TpmHello` support for existing vaults.
- Existing v0.3.0 vaults migrate to `TpmHelloGesture` after one successful legacy unlock.

## Existing v0.3.0 vaults

If your current vault was created by v0.3.0, it may still ask for the old key password once because the root key is already wrapped by the old ForceHighProtection key.

Options:

### Option A — keep existing saved credentials

Enter the old key password one final time. After successful unlock, the vault is automatically re-wrapped into `TpmHelloGesture`, and future unlocks should be fingerprint-only.

### Option B — reset test vault

If you do not care about saved test credentials, delete/rename:

```text
%LOCALAPPDATA%\ZeroTrustVault\vault.json
```

Then restart Chrome/native host and save credentials again. New vaults use `TpmHelloGesture` immediately.

## Security note

This patch prioritizes the intended UX: one Windows Hello gesture, no second CNG key-password prompt.
The native host still requires live Windows Hello before root-key unwrap, the CNG key remains non-exportable, and release builds still ignore `ZTV_DEV_BYPASS`.

This is still not a guarantee against privileged local malware or a compromised operating system.
