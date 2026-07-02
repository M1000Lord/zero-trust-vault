# External Audit Request

This project has **not** been audited by a third party. This document scopes a
prospective external review.

## Requested scope
1. Native host cryptography: AES-256-GCM usage, HKDF subkey derivation, AAD
   construction, nonce handling (`Crypto/VaultCrypto.cs`, `SubkeyDerivation.cs`).
2. TPM/CNG/Windows Hello root-key wrapping and the unlock path
   (`WindowsHello/HelloManager.cs`, `Commands/VaultCommands.cs`).
3. Corrupt-vault handling and quarantine safety (`Vault/VaultIntegrity.cs`,
   `VaultCommands.HandleCorruptVault`) — confirm no data-loss path on Case B.
4. Recovery (Shamir 3-of-5) correctness and the recovery flow
   (`Crypto/ShamirSecretSharing.cs`, `Commands/RecoveryCommands.cs`).
5. Event signing / hash chain primitives (`Sync/MeshEventCrypto.cs`,
   `CanonicalJson.cs`) — note these are primitives, not a wired engine.
6. Device identity / SAS (`Crypto/DeviceIdentity.cs`).
7. Native messaging protocol validation (`Commands/CommandRouter.cs`,
   `NativeMessaging/`) — nonce, timestamp, origin, field whitelisting.
8. Release signing + installer verification (`tools/`, `installer/`).
9. Extension CSP, permissions, integrity check, and clipboard/TOTP handling.

## What to assume is incomplete
See `KNOWN_LIMITATIONS.md`. In particular, do **not** audit multi-device sync or
device pairing as if production-complete — they are partial by design at this
milestone.

## How to build and verify
```
dotnet build  native-host/src/ZeroTrustVaultHost/ZeroTrustVaultHost.csproj -c Release
dotnet test   native-host/src/ZeroTrustVaultHost.Tests/ZeroTrustVaultHost.Tests.csproj
pwsh tools/check-forbidden-strings.ps1
pwsh tools/verify-release.ps1 -HostDir native-host/src/ZeroTrustVaultHost/bin/Release/net9.0-windows10.0.22621.0
```

## Deliverable requested from auditor
A written report with findings by severity, reproduction steps, and remediation
guidance. Until such a report exists and is linked here, the project status
remains **audit-ready, not externally audited**.
