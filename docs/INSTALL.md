# Zero-Trust Vault — Installation Guide

Version: v0.5.0-hardened  
Date: 2026-06-29

---

## 1. Requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| Windows | 10 22H2 or Windows 11 | Home and Pro editions both supported |
| Chrome | 127 or later | Chromium-based browsers (Edge, Brave) are untested |
| .NET Desktop Runtime | 9.0 or later | Desktop Runtime, not SDK |
| Windows Hello | Configured (PIN, fingerprint, or face) | Required before vault can be used |
| TPM | 2.0 recommended | 1.2 supported; without TPM, software KSP is used (reduced security) |
| PowerShell | 5.1 or later (pre-installed on Windows 10/11) | For running install scripts |

**Windows Hello must be configured before installation.** Go to Settings → Accounts → Sign-in options and set up at least one Hello method (PIN is sufficient).

---

## 2. Step 1: Verify Prerequisites

Open PowerShell and run:

```powershell
# Check .NET 9 Desktop Runtime
dotnet --list-runtimes | Select-String "WindowsDesktop.App 9"

# Check Windows Hello (verify TPM is present)
Get-WmiObject -Namespace root\cimv2\security\microsofttpm -Class Win32_Tpm | Select-Object IsEnabled_InitialValue, IsActivated_InitialValue

# Check Chrome version
(Get-Item "C:\Program Files\Google\Chrome\Application\chrome.exe").VersionInfo.ProductVersion
```

If .NET 9 Desktop Runtime is not installed, download it from:  
`https://dotnet.microsoft.com/download/dotnet/9.0`  
Select "Windows" → "Desktop Runtime" → x64 installer.

---

## 3. Step 2: Load the Extension in Chrome

1. Open Chrome.
2. Navigate to `chrome://extensions/` in the address bar.
3. Enable **Developer mode** using the toggle in the top-right corner.
4. Click **Load unpacked**.
5. In the file picker, navigate to the `extension\` directory (the directory that contains `manifest.json`) and click **Select Folder**.
6. The ZTV extension icon (a shield with a key) appears in the Chrome toolbar.
7. **Copy the Extension ID** — it is the 32-character alphanumeric string shown below the extension name in `chrome://extensions/`. You will need it in Step 3.

The extension ID will look similar to: `abcdefghijklmnopqrstuvwxyz012345`

Note: Because ZTV is loaded in Developer Mode and is not distributed through the Chrome Web Store, Chrome will show a banner warning that "Developer mode extensions are enabled" when you open a new window. This is expected behavior for v0.5.0.

---

## 4. Step 3: Run the Native Host Installer

Open PowerShell in the `host\` directory (the directory containing `install.ps1` and `ZeroTrustVault.Host.exe`).

```powershell
.\install.ps1 -ExtensionId "abcdefghijklmnopqrstuvwxyz012345"
```

Replace the extension ID with the one you copied in Step 2.

**What install.ps1 does:**
1. Verifies the Authenticode digital signature on `ZeroTrustVault.Host.exe`. If verification fails, the script aborts and does not register the host.
2. Checks that the thumbprint matches the reference in `thumbprint.txt`. If it does not, the script aborts.
3. Copies `ZeroTrustVault.Host.exe` and `ZeroTrustVault.Host.json` to `%LOCALAPPDATA%\ZeroTrustVault\host\`.
4. Creates the native messaging host registry key:  
   `HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.zerotrustvault.host`  
   pointing to the host manifest JSON file.
5. Creates the vault directory at `%LOCALAPPDATA%\ZeroTrustVault\`.
6. Writes the install log to `%LOCALAPPDATA%\ZeroTrustVault\install.log`.

**No administrator privileges are required** — all registry keys are written under HKCU (the current user).

If the script reports a signature error, do not proceed. Verify that the binary you downloaded matches the published SHA-256 hash in the release manifest. See RELEASE_CHECKLIST.md for the hash format.

---

## 5. Step 4: Reload the Extension

After the native host is installed, reload the extension to pick up the new host registration:

1. Go to `chrome://extensions/`.
2. Find Zero-Trust Vault.
3. Click the **Reload** button (circular arrow icon) below the extension entry.

---

## 6. Step 5: Initial Vault Setup

1. Click the ZTV icon in the Chrome toolbar.
2. The popup opens and shows "Welcome to Zero-Trust Vault — New Installation".
3. Click **Set Up New Vault**.
4. Windows Hello prompt appears. Authenticate.
5. The native host:
   - Generates a `VaultId` (random UUID).
   - Generates the `VaultRootKey` (32 random bytes).
   - Creates a CNG platform key wrapping the `VaultRootKey` (TPM-backed if TPM is present).
   - Creates the vault file at `%LOCALAPPDATA%\ZeroTrustVault\vault.json`.
   - Appends the initial `CreateVault` event to the event log.
6. Vault creation confirmation is displayed with the VaultId.

---

## 7. Step 6: Create the Recovery Kit

This step is strongly recommended before you add any credentials you cannot easily replace.

1. In the popup, click **Settings** → **Recovery Kit** → **Create New Kit**.
2. Windows Hello prompt appears. Authenticate.
3. The native host generates 5 Shamir shares.
4. Follow the on-screen wizard to export and store each share (see RECOVERY.md Section 4.3 for storage recommendations).
5. Recovery kit status changes to `Created`.
6. Within 30 days, perform a recovery drill to verify the kit (see RECOVERY.md Section 8).

---

## 8. Step 7: Configure Session Timeout

1. In the popup, click **Settings** → **Session**.
2. Set the session timeout (default: 15 minutes of inactivity).
3. Optionally enable "Require Hello on every fill" for maximum security (overrides session caching).

---

## 9. Verification

After installation, verify the following:

| Check | Expected Result |
|-------|----------------|
| `chrome://extensions/` | Zero-Trust Vault is listed as "Enabled" with no errors |
| Click ZTV toolbar icon | Popup opens; shows vault status |
| Windows Hello test | Click "Test Windows Hello" in Settings; Hello prompt appears and authentication succeeds |
| Native host test | Settings → Diagnostics → Test Native Host; shows "Native host connected — version x.y.z" |
| Vault directory exists | `%LOCALAPPDATA%\ZeroTrustVault\vault.json` exists |
| TPM status | Settings → Diagnostics → TPM Status; shows "TPM 2.0 — Key stored in hardware TPM" (or software KSP warning if no TPM) |

---

## 10. What Each Permission Does

For a complete explanation of each Chrome extension permission, see PERMISSIONS.md.

Brief summary:
- `nativeMessaging`: required to communicate with the native host for all crypto operations
- `activeTab`: required to read the current tab's origin for credential matching
- `scripting`: required to inject content.js for form detection and fill
- `storage`: required for settings only (never for secrets)
- `alarms`: required for session timeout
- `tabs` and `windows`: required for popup management and fill coordination

---

## 11. Troubleshooting

### "Native host not found" or "Native host has exited"

**Symptom:** Popup shows "Cannot connect to native host" or Chrome DevTools shows the connection error.

**Causes and fixes:**
1. `install.ps1` was not run, or ran against a different extension ID than the one currently loaded.
   - Re-run `install.ps1 -ExtensionId "<current-id>"`.
   - The current ID is shown in `chrome://extensions/`.
2. The extension was reloaded and got a new ID (Developer Mode extensions can change ID if you loaded from a different path).
   - Confirm the ID in `chrome://extensions/` matches the `allowed_origins` in the host manifest: `%LOCALAPPDATA%\ZeroTrustVault\host\ZeroTrustVault.Host.json`.
3. The registry key was not created correctly.
   - Check: `Get-Item "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.zerotrustvault.host"`.
   - The default value should be the path to the host manifest JSON file.
4. .NET 9 Desktop Runtime is not installed.
   - The native host requires .NET 9. Install it and retry.

### "Windows Hello not available" or Hello prompt doesn't appear

**Symptom:** Windows Hello prompt does not appear when expected, or Settings shows "Windows Hello not configured."

**Fix:**
1. Go to Windows Settings → Accounts → Sign-in options.
2. Verify that Windows Hello PIN, fingerprint, or face recognition is configured.
3. If using a virtual machine, note that TPM passthrough may be required for Hello to function. Virtual machine support is not officially tested.

### Extension won't load ("Cannot load extension")

**Symptom:** Chrome shows an error when loading the extension.

**Cause:** The extension directory may be missing required files.

**Fix:**
1. Verify the extension directory contains: `manifest.json`, `service_worker.js`, `popup.html`, `popup.js`, `popup.css`, `content.js`.
2. Verify `manifest.json` is valid JSON: `Get-Content .\extension\manifest.json | ConvertFrom-Json`.
3. Check Chrome's error message for specific missing files or permission issues.

### "Signature verification failed" during install

**Symptom:** `install.ps1` reports that the Authenticode signature on `ZeroTrustVault.Host.exe` is invalid or untrusted.

**Fix:**
1. Verify the SHA-256 hash of the downloaded binary matches the published hash in the release manifest.
2. Do not run the installer if the hash does not match. The binary may have been tampered with.
3. Re-download from the official release source.
