# README for Auditor

Welcome. Start here.

## What this is
Zero-Trust Vault (ZTV) v2.0.0 — a Windows password vault built as a Chrome MV3
extension talking to a .NET 9 native host over Chrome native messaging. Every
credential release is gated by Windows Hello; secrets are AES-256-GCM encrypted
and the root key is wrapped to a non-exportable CNG/TPM key.

## Read these first, in order
1. `AUDIT_STATUS.md` — the project is **audit-ready, NOT externally audited**.
2. `KNOWN_LIMITATIONS.md` — exactly what is real vs. partial vs. not started.
3. `RESIDUAL_RISKS.md` — risks that remain with current controls.
4. `EXTERNAL_AUDIT_REQUEST.md` — requested review scope.

## Source map (native host)
- `Crypto/` — AES-GCM (`VaultCrypto`), HKDF (`SubkeyDerivation`), Shamir
  (`ShamirSecretSharing`), TOTP (`TotpGenerator`), device signing
  (`DeviceSigning`), device identity + SAS (`DeviceIdentity`).
- `WindowsHello/HelloManager.cs` — UserConsentVerifier + CNG root-key wrap.
- `Vault/` — vault model, atomic save, `VaultIntegrity` (corrupt-vault quarantine).
- `Commands/` — command router + handlers (unlock, list, fill, add, update,
  delete, TOTP, recovery, device, sync, health).
- `Sync/` — event log (`EventLogManager`), signed event primitives
  (`MeshEvent`, `MeshEventCrypto`, `CanonicalJson`).
- `Diagnostics/DiagnosticLog.cs` — release-safe, redacting logger.

## Build / test / verify
```
dotnet build native-host/src/ZeroTrustVaultHost/ZeroTrustVaultHost.csproj -c Release
dotnet test  native-host/src/ZeroTrustVaultHost.Tests/ZeroTrustVaultHost.Tests.csproj
pwsh tools/check-forbidden-strings.ps1          # flags bypasses AND known stubs
pwsh tools/verify-release.ps1 -HostDir <reldir> # diag-logging off, no bypass strings
pwsh tools/build-integrity.ps1 -Verify          # extension hashes match
```
Expected today: **177 tests pass**; `verify-release` passes on a Release build;
`check-forbidden-strings` **fails** on `DeviceCommands.cs` — that is the intended
honest signal that device pairing is not finished (see `KNOWN_LIMITATIONS.md`).

## Trust boundaries to probe
- Extension ↔ native host (native messaging): nonce/timestamp/origin/field
  validation in `CommandRouter`.
- Native host ↔ OS: CNG key non-exportability, Hello gating, file ACLs.
- Installer ↔ binary: registry path, thumbprint pinning.
