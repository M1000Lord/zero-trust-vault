# Zero-Trust Vault — Pre-Release Checklist

Version: v0.5.0-hardened  
Date: 2026-06-29

This checklist must be completed and signed off before any release artifact is distributed. Each item is assigned to an owner. "Pass" means the check was completed and found satisfactory; any Fail or Partial blocks the release.

---

## Section 1: Build

- [ ] **1.1** Native host (`ZeroTrustVault.Host.exe`) is built from source in **Release** configuration, not Debug.
  - Command: `dotnet build -c Release`
  - Verify: Confirm no `[DEBUG]` symbols in binary (`dumpbin /symbols ZeroTrustVault.Host.exe | grep DEBUG`).

- [ ] **1.2** Build output is from a clean checkout of the tagged release commit. Working directory is clean (`git status` shows no modified files).

- [ ] **1.3** The build machine is a controlled environment. No developer modifications have been applied to the source tree since the tag was applied.

---

## Section 2: Forbidden String Scan

- [ ] **2.1** Forbidden string scan of the native host binary and source passes with zero matches.

  Run the following before building to scan source:
  ```powershell
  $patterns = @("DEV_BYPASS", "devBypass", "DPAPI_FALLBACK", "TEST_KEY", "skipHello", "SkipHello", "bypassAuth")
  Get-ChildItem -Recurse -Filter "*.cs" | ForEach-Object {
      $content = Get-Content $_.FullName -Raw
      foreach ($p in $patterns) {
          if ($content -match $p) {
              Write-Warning "FORBIDDEN: '$p' found in $($_.FullName)"
          }
      }
  }
  ```
  Expected output: no warnings.

- [ ] **2.2** Run the same scan on the compiled binary using `strings`:
  ```powershell
  & "C:\Program Files (x86)\Windows Kits\10\bin\x64\strings.exe" ZeroTrustVault.Host.exe | Select-String "DEV_BYPASS|devBypass|DPAPI_FALLBACK|TEST_KEY"
  ```
  Expected: no matches.

---

## Section 3: Tests

- [ ] **3.1** All native host unit tests pass in Release configuration.
  - Command: `dotnet test -c Release`
  - Expected: all tests pass, zero failures.

- [ ] **3.2** Crypto unit tests pass, including:
  - HKDF-SHA256 subkey derivation against reference vectors
  - AES-256-GCM round-trip (encrypt → decrypt → match)
  - AEAD AAD binding (tampered AAD → decrypt fails)
  - HMAC-SHA256 backup MAC verification
  - Shamir SSS reconstruction with 3-of-5 shares (against known test vector)
  - Shamir SSS failure with 2-of-5 shares

- [ ] **3.3** Origin validation tests pass:
  - HTTP origin rejected
  - IDN origin rejected (default settings)
  - Punycode origin rejected (default settings)
  - Exact-match HMAC test passes
  - Non-matching origin returns `ERR_ORIGIN_NO_MATCH`

- [ ] **3.4** TOTP generation tests pass (RFC 6238 test vectors).

---

## Section 4: Extension Integrity

- [ ] **4.1** Extension integrity hashes are rebuilt using `build-integrity.ps1`.
  - This script computes SHA-256 hashes of all extension files and updates `integrity.json`.
  - Command: `.\build-integrity.ps1 -ExtensionDir .\extension\`

- [ ] **4.2** `manifest.json` version number matches the release version tag.

- [ ] **4.3** The extension CSP in `manifest.json` is confirmed to contain no `unsafe-eval`, no `unsafe-inline`, and no remote `script-src` entries.

- [ ] **4.4** The extension does not reference any external CDN, analytics, or tracking endpoint in any `.js` or `.html` file.
  ```powershell
  Get-ChildItem -Recurse -Path .\extension\ -Include "*.js","*.html" | Select-String "cdn\.|googleapis\.|cloudflare\.|analytics\."
  ```
  Expected: no matches.

---

## Section 5: Functional Testing (Extension + Native Host)

- [ ] **5.1** Extension loaded in Chrome Developer Mode and confirmed as "Enabled" with no errors in `chrome://extensions/`.

- [ ] **5.2** Native host connected: Settings → Diagnostics → Test Native Host returns "Native host connected — version X.Y.Z".

- [ ] **5.3** Add a credential for `https://example.com`. Confirm the credential is stored (popup shows the entry).

- [ ] **5.4** Fill test: visit `https://example.com`. Open popup. Trigger fill. Confirm username and password fields are filled correctly. Confirm Windows Hello prompt appeared.

- [ ] **5.5** HTTP rejection test: visit `http://example.com`. Attempt fill. Confirm error: "Fill rejected: HTTPS required."

- [ ] **5.6** IDN rejection test: visit a punycode URL. Attempt fill. Confirm error: "Fill rejected: IDN origin not allowed."

- [ ] **5.7** TOTP test: add a TOTP seed to a credential. Open popup. Request TOTP code. Confirm a 6-digit code appears and countdown works.

- [ ] **5.8** Session timeout test: set timeout to 1 minute. Wait 1 minute 10 seconds. Attempt fill. Confirm popup shows "Vault Locked" and requires Hello.

---

## Section 6: Code Signing

- [ ] **6.1** Authenticode signature applied to `ZeroTrustVault.Host.exe` using `sign.ps1`.
  - Command: `.\sign.ps1 -BinaryPath .\ZeroTrustVault.Host.exe`

- [ ] **6.2** Signature verified after signing:
  ```powershell
  (Get-AuthenticodeSignature .\ZeroTrustVault.Host.exe).Status
  # Expected: Valid
  ```

- [ ] **6.3** Signing certificate thumbprint saved to `thumbprint.txt`.
  ```powershell
  (Get-AuthenticodeSignature .\ZeroTrustVault.Host.exe).SignerCertificate.Thumbprint | Out-File thumbprint.txt -Encoding utf8
  ```

- [ ] **6.4** `thumbprint.txt` is committed to the release repository and will be distributed out-of-band from the binary package (e.g., published on the project homepage or announcement post separately from the download link).

---

## Section 7: Release Manifest and Hashes

- [ ] **7.1** SHA-256 hashes computed for all release artifacts:
  - `ZeroTrustVault.Host.exe`
  - `ZeroTrustVault.Host.json` (native host manifest)
  - `extension.zip` (extension package)
  - `install.ps1`
  - `uninstall.ps1`

  ```powershell
  Get-ChildItem -Path .\release\ | ForEach-Object {
      $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
      "$hash  $($_.Name)"
  } | Out-File release-manifest.txt -Encoding utf8
  ```

- [ ] **7.2** `release-manifest.txt` is signed (GPG or Authenticode) and published alongside the release.

- [ ] **7.3** ZIP packages created:
  - `ztv-host-v{VERSION}-win-x64.zip` — contains `ZeroTrustVault.Host.exe`, `ZeroTrustVault.Host.json`, `install.ps1`, `uninstall.ps1`, `thumbprint.txt`
  - `ztv-extension-v{VERSION}.zip` — contains all extension files

---

## Section 8: SBOM and Dependencies

- [ ] **8.1** Software Bill of Materials (SBOM) generated:
  ```powershell
  dotnet list package --include-transitive > sbom.txt
  ```

- [ ] **8.2** SBOM reviewed for:
  - No known-vulnerable NuGet packages (check against NVD or GitHub Advisory Database)
  - No unexpected transitive dependencies added since the last release
  - All packages are from expected sources (not renamed/typosquatting packages)

---

## Section 9: Documentation

- [ ] **9.1** `CHANGELOG.md` updated with all changes since the previous release.

- [ ] **9.2** `docs/SECURITY_MODEL.md` reviewed for accuracy against the current implementation.

- [ ] **9.3** `docs/CRYPTO.md` reviewed — all algorithm parameters and key names match the implementation.

- [ ] **9.4** `docs/PERMISSIONS.md` reviewed — all permissions in `manifest.json` are documented; no undocumented permissions added.

- [ ] **9.5** `docs/INSTALL.md` verified against the actual install flow (no outdated steps).

- [ ] **9.6** `README.md` version number updated to match the release version.

---

## Section 10: Clean Environment Testing

- [ ] **10.1** Recovery flow tested on a **clean Windows VM** (no prior ZTV installation):
  - Create a vault on machine A
  - Create and export a recovery kit
  - Import 3 shares on machine B (clean VM)
  - Restore from backup file
  - Confirm credential is accessible on machine B after recovery

- [ ] **10.2** Install flow tested on a **clean Windows VM**:
  - Install .NET 9 Desktop Runtime from scratch
  - Load extension in Chrome Developer Mode
  - Run `install.ps1`
  - Add a credential
  - Perform a fill
  - Confirm all steps complete without error

- [ ] **10.3** Uninstall flow tested (without `-RemoveVault`):
  - Run `uninstall.ps1`
  - Confirm extension can no longer connect to native host
  - Confirm `vault.json` still exists
  - Reinstall and confirm vault is accessible

- [ ] **10.4** Uninstall flow tested (with `-RemoveVault -RemoveKeys`):
  - Run `uninstall.ps1 -RemoveVault -RemoveKeys`
  - Confirm `vault.json` is gone
  - Confirm CNG platform key is gone
  - Confirm reinstall creates a fresh vault (not the old one)

---

## Section 11: Out-of-Band Communication

- [ ] **11.1** The signing certificate thumbprint has been communicated to users through a channel separate from the download package (e.g., project website, announcement email, pinned post). Users can verify the thumbprint independently of the download.

- [ ] **11.2** If the signing certificate changed from the previous release, a prominent notice is included in the changelog and release announcement.

---

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Build owner | | | |
| Security reviewer | | | |
| Test lead | | | |
| Release manager | | | |

Release is **blocked** until all checklist items show [PASS] and all sign-off fields are complete.
