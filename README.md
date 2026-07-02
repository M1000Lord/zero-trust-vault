# Zero-Trust Vault (ZTV) — v2.0.0

Platform: Windows 10/11 · Chrome MV3 · .NET 9 · Windows Hello / TPM

Local-first Chrome MV3 credential vault with a Windows native host, Windows Hello user-presence gates, exact-origin autofill, and hardware TPM key wrapping.

This project is intentionally not a Bitwarden clone. It trades sync, sharing, broad platform support, and convenience for a narrower security posture.

---

## Security Posture

- No master password — no phishable secret.
- No cloud sync by default — v2 adds optional blind-relay sync where the server stores ciphertext only.
- No auto-submit — fill stops at the form fields; the user clicks Sign In.
- No clipboard use — fill is direct DOM value assignment.
- No broad host permission by default — the optional convenience detector requires explicit user opt-in.
- Fresh Windows Hello approval required before every credential fill — no cached session decryption.
- Non-exportable CNG platform key (TPM-backed) wraps the VaultRootKey.
- Exact-origin binding: `https://host:port` — no wildcards, no path matching.
- HTTP, punycode/IDN, cross-frame, and hidden-field fills are blocked by the native host.
- TOTP seeds are generated and zeroed inside the native host; only the 6-digit code is returned.
- 3-of-5 Shamir's Secret Sharing for cross-machine recovery without cloud key escrow.

---

## Security Pitch

| Claim | Enforcement |
|-------|------------|
| No master password to phish | Windows Hello (TPM/biometric) is the only gate |
| One credential released per fill | Native host decrypts at most one credential per Hello prompt |
| Fake websites get nothing | Exact-origin HMAC matching; no wildcards |
| HTTP sites get nothing | Native host rejects all non-HTTPS origins before any lookup |
| IDN homographs blocked | Punycode/Unicode labels rejected by default |
| Relay breach exposes only ciphertext | All sync payloads AES-256-GCM before leaving device |
| TOTP seeds never leave native host | Only the 6-digit code is returned; seed zeroed in-process |
| Developer cannot recover your vault | VaultRootKey generated on-device; developer holds no copy |

ZTV does not claim to be immune to malware. An Administrator-level process can read memory after a fill. This is documented as an accepted limitation. See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

---

## Quick Start

**Requirements:** Windows 10/11 22H2+, Chrome 127+, .NET 9 Desktop Runtime, Windows Hello configured.

```powershell
# Step 1: Load the extension in Chrome
# Open chrome://extensions → Enable Developer Mode → Load Unpacked → select extension\ directory
# Copy the 32-character Extension ID

# Step 2: Install the native host (from host\ directory, no admin required)
.\install.ps1 -ExtensionId "your32characterextensionid"

# Step 3: Reload the extension in chrome://extensions

# Step 4: Click the ZTV icon → Set Up New Vault → complete Windows Hello setup

# Step 5: Create recovery kit before adding any important credentials
# Settings → Recovery Kit → Create New Kit
```

Full guide: [docs/INSTALL.md](docs/INSTALL.md)

---

## Recommended Fill Flow

1. Open the login page in Chrome.
2. Click the ZTV toolbar icon.
3. Unlock with Windows Hello (if session has timed out).
4. Review the listed account for the exact origin shown.
5. Click **Fill**.
6. Approve Windows Hello again (fresh prompt per fill).
7. Manually click the website's Sign In button — ZTV never auto-submits.

---

## Architecture Summary

ZTV is a two-process system. All crypto, origin validation, and TOTP generation occur in the native host. The extension is a UI front-end only.

```
Chrome Extension
  service_worker.js   — UI coordinator; no secrets stored
  popup.html/js       — Credential selector; TOTP code display only
  content.js          — Form detection + fill; lowest trust; never talks to native host
        │
        │  Chrome native messaging (4-byte LE length prefix + JSON)
        │  allowed_origins: [chrome-extension://<ZTV_ID>/]
        ▼
Native Host (.NET 9) — ALL crypto here
  ZeroTrustVault.Host.exe
  AES-256-GCM         — Vault read/write (Windows CNG)
  HKDF-SHA256         — 8 subkeys from VaultRootKey
  Windows Hello/TPM   — Fresh challenge per credential
  TOTP (RFC 6238)     — Generated here; seed never leaves
  ECDSA P-256         — Event signing (sync)
  Shamir SSS (3-of-5) — Recovery kit
```

Full diagram and all data flows: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## Cryptography

- **Root key:** VaultRootKey — random 256-bit, CNG platform key (TPM-backed, non-exportable)
- **Subkeys:** 8 HKDF-SHA256 subkeys, each with a unique `info` string
- **Encryption:** AES-256-GCM via Windows CNG; 96-bit random nonce per record
- **AEAD AAD:** `schemaVersion || vaultId || itemId || originHash || deviceEpoch || purpose`
- **Origin hashing:** `HMAC-SHA256(OriginHashKey, "https://host:port")`
- **Recovery:** GF(256) Shamir's SSS, 3-of-5, AES primitive polynomial (x^8+x^4+x^3+x+1)

Full specification: [docs/CRYPTO.md](docs/CRYPTO.md)

---

## Documentation Index

| Document | Description |
|----------|-------------|
| [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) | 15 security principles; 22-threat model with posture and residual risk |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Per-threat technical analysis with attacker capability ratings |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | ASCII diagram; component responsibilities; data flows; protocol |
| [docs/CRYPTO.md](docs/CRYPTO.md) | Full cryptographic spec; key hierarchy; AAD structure; forbidden practices |
| [docs/SYNC.md](docs/SYNC.md) | MeshSync; 13 event types; HLC; hash chain; blind relay model |
| [docs/RECOVERY.md](docs/RECOVERY.md) | Recovery kit creation, storage, and step-by-step restore SOP |
| [docs/INSTALL.md](docs/INSTALL.md) | Installation guide; requirements; troubleshooting |
| [docs/UNINSTALL.md](docs/UNINSTALL.md) | Uninstall guide; flags; TPM key deletion warning |
| [docs/BACKUP.md](docs/BACKUP.md) | Backup format; manual and automated backup; restore |
| [docs/PERMISSIONS.md](docs/PERMISSIONS.md) | Every Chrome permission justified individually |
| [docs/AUDIT_CHECKLIST.md](docs/AUDIT_CHECKLIST.md) | Security audit checklist by component |
| [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) | Pre-release gate: build, scan, tests, signing, clean-VM testing |

---

## Build Instructions

### Native Host

```powershell
# Release build
dotnet build .\native-host\ZeroTrustVaultHost\ZeroTrustVaultHost.csproj -c Release

# Run all tests
dotnet test -c Release

# Syntax check extension JS (no build step required for the extension)
node --check .\extension\service_worker.js
node --check .\extension\popup.js
node --check .\extension\content.js
```

### Debug Round-Trip Test (Development Only)

```powershell
dotnet build .\native-host\ZeroTrustVaultHost\ZeroTrustVaultHost.csproj -c Debug
node .\native-host\tools\roundtrip.mjs .\native-host\ZeroTrustVaultHost\bin\Debug\net9.0-windows10.0.19041.0\ZeroTrustVaultHost.exe
```

The round-trip test uses DEBUG-only bypass flags. Release builds reject these flags — see RELEASE_CHECKLIST.md Section 2 (forbidden string scan).

---

## Project Status

| Feature | Status |
|---------|--------|
| Chrome MV3 extension | Implemented |
| C# .NET 9 native host | Implemented |
| Windows Hello / TPM key protection | Implemented |
| AES-256-GCM vault encryption | Implemented |
| TOTP generation (RFC 6238) | Implemented |
| Exact-origin HMAC matching | Implemented |
| 3-of-5 Shamir recovery kit | Implemented |
| Encrypted backup with MAC | Implemented |
| Local file relay sync | Implemented |
| Blind relay cloud sync | Designed, not yet implemented |
| Web Store distribution | Planned (v3 goal) |
| Independent security audit | Not yet performed |

---

## Honest Limitations

ZTV cannot protect against:

- Admin/root-level malware or a fully compromised Windows account reading memory after fill.
- DOM theft after fill (inherent browser limitation — any page script can read filled values).
- Screen, browser-memory, or keyboard capture after user approval.
- Compromised legitimate websites after credentials are filled.
- Malicious extension or native host updates (mitigated by Authenticode signing and Developer Mode warnings, but not eliminated).
- Data loss if both the TPM and the recovery kit are unavailable simultaneously.

An independent third-party security audit has not been performed as of v2.0.0. Do not rely on this vault for high-value credentials until the items in [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) are complete and an external audit has been conducted.

---

## License

[License placeholder — to be determined]
