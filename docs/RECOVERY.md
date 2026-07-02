# Zero-Trust Vault — Recovery Guide

Version: v0.5.0-hardened  
Date: 2026-06-29

---

## 1. What Is the Recovery Kit?

The recovery kit is the only way to restore a ZTV vault on a machine other than the one it was created on, or after a TPM failure or motherboard replacement.

The VaultRootKey is protected by the Windows TPM and cannot be exported. If the TPM is lost (hardware failure, motherboard replacement, Windows profile loss), the VaultRootKey is gone. Without the VaultRootKey, the vault cannot be decrypted.

The recovery kit solves this problem using Shamir's Secret Sharing:

- At kit creation time, a 256-bit `RecoveryRootSecret` is generated and used to derive a `RecoveryRootKey`.
- The `RecoveryRootSecret` is split into **5 shares** using 3-of-5 Shamir's Secret Sharing over GF(256).
- **Any 3 of the 5 shares** are sufficient to reconstruct the `RecoveryRootSecret` and re-derive the `RecoveryRootKey`.
- The vault is re-encrypted under the `RecoveryRootKey` on the new machine, then wrapped in the new machine's TPM.
- The original `RecoveryRootSecret` is zeroed from memory immediately after the shares are generated.

**The recovery kit is not a backup of the vault.** It is a key-recovery mechanism. You still need a copy of the encrypted `vault.json` (from a backup or from the original machine) to perform recovery.

---

## 2. Recovery Status

ZTV tracks recovery kit status and displays it in the extension popup and settings:

| Status | Meaning |
|--------|---------|
| `Not Created` | No recovery kit has been generated. **Do not rely on this vault for serious use.** |
| `Created` | A kit was generated. Shares have not been verified. |
| `Verified` | At least one successful recovery drill has been completed (share reconstruction tested). |

The recommended status before relying on the vault is `Verified`.

---

## 3. When to Create the Recovery Kit

Create the recovery kit before:
- Storing any credential you cannot easily replace.
- Relying on the vault as your primary credential store.
- Setting up sync across machines.

The install wizard prompts for recovery kit creation after initial vault setup. This step should not be skipped.

---

## 4. Creating the Recovery Kit

### 4.1 Via the Extension UI

1. Open the ZTV popup.
2. Click **Settings** → **Recovery Kit** → **Create New Kit**.
3. Windows Hello prompt will appear. Authenticate.
4. The native host generates a `RecoveryRootSecret`, splits it into 5 shares, and displays each share.
5. Follow the on-screen prompts to export each share (see Section 4.3).
6. Confirm you have stored all 5 shares by clicking through the confirmation checklist.
7. Status changes to `Created`.

### 4.2 Via PowerShell

```powershell
# Run from an elevated PowerShell or user session (no admin required)
& "$env:LOCALAPPDATA\ZeroTrustVault\tools\ztv-cli.ps1" -Command CreateRecoveryKit
```

The CLI will prompt for Windows Hello and output 5 share files to the current directory.

### 4.3 Where to Store Each Share

You have 5 shares and need 3 to recover. Distribute them so that no single location holds 3 or more shares. A recommended distribution:

| Share | Storage Location |
|-------|-----------------|
| Share 1 | Printed on paper; stored in a fireproof home safe |
| Share 2 | Encrypted USB drive; stored in a different physical location (e.g., workplace safe) |
| Share 3 | File on a second personal device (phone, second laptop) that is not regularly connected to the vault machine |
| Share 4 | Stored with a trusted person (family member, lawyer) who can be contacted in an emergency |
| Share 5 | Stored in a cloud storage service **in a password-protected archive** (the share is itself not sensitive without 2 more shares, but protecting it is prudent) |

Never store all 5 shares in the same location. Never store 3 or more shares in the same place.

---

## 5. Restoring on a New Machine (Step-by-Step)

**Prerequisites:**
- Windows 10/11 22H2 or later
- Windows Hello configured (PIN, fingerprint, or face recognition) on the new machine
- .NET 9 Desktop Runtime installed
- Chrome 127+ installed
- The encrypted vault backup file (`vault_backup_*.ztv`) from the old machine (or an export from the old machine's event log)
- At least 3 of the 5 recovery kit shares

### Step 1: Install .NET 9 Desktop Runtime

Download from https://dotnet.microsoft.com/download/dotnet/9.0 — install the "Desktop Runtime" (not SDK). Verify:

```powershell
dotnet --list-runtimes
# Should show: Microsoft.WindowsDesktop.App 9.x.x
```

### Step 2: Install the Extension in Chrome

1. Open Chrome.
2. Navigate to `chrome://extensions/`.
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked**.
5. Select the ZTV extension directory (the folder containing `manifest.json`).
6. Note the Extension ID (a 32-character string).

### Step 3: Run the Native Host Installer

```powershell
# From the directory containing install.ps1 and ZeroTrustVault.Host.exe
.\install.ps1 -ExtensionId "<your-32-char-extension-id>"
```

The installer verifies the Authenticode signature on `ZeroTrustVault.Host.exe` and registers the native messaging host. If signature verification fails, the installer aborts.

### Step 4: Open the Recovery Wizard

1. Click the ZTV icon in Chrome.
2. The popup will show "New installation — Vault not configured".
3. Click **Recover Existing Vault**.
4. The Recovery Wizard opens.

### Step 5: Provide Shamir Shares

1. The wizard prompts for shares one at a time (you need to provide at least 3).
2. Enter each share's hex string (or paste from a file), or scan the QR code printed on the share card.
3. After entering 3 shares, click **Reconstruct**.
4. The native host verifies the share checksums and reconstructs the `RecoveryRootSecret`.
5. Windows Hello prompt appears for the new machine's Hello.

### Step 6: Provide the Vault Backup File

1. Click **Browse** and select the encrypted backup file (`.ztv`).
2. The native host verifies the backup MAC.
3. The native host decrypts the backup using the recovered `RecoveryRootKey`.
4. The native host re-encrypts the vault under the new machine's TPM-wrapped VaultRootKey.
5. The new device is enrolled in the device graph (a `EnrollDevice` event is appended).

### Step 7: Verify Recovery

1. The wizard displays the count of recovered credentials.
2. Click **Verify Recovery** to attempt decrypting one credential (requires Windows Hello).
3. Confirm the credential is correct.
4. The recovery kit status changes to the new machine's kit (you should create a new recovery kit for the new machine if your shares are still with the old machine's configuration).

---

## 6. What Recovery Creates

After successful recovery:

| Item | Created or Updated |
|------|--------------------|
| New CNG platform key | Created (new machine's TPM) |
| New DeviceId | Derived from new device's signing key |
| VaultRootKey | Re-derived from RecoveryRootSecret; wrapped under new TPM |
| Device epoch | Incremented (new enrollment) |
| Device graph entry | New `EnrollDevice` event added |
| vault.json | Re-encrypted under new VaultRootKey |

---

## 7. What Recovery Cannot Do

- **Access data from removed devices.** If a device was removed from the vault (T-22) and its credentials are unknown, recovery does not restore them.
- **Bypass Windows Hello on the old machine.** Recovery creates a new key on the new machine; it does not unlock the old machine.
- **Reconstruct shares from fewer than 3 inputs.** With only 1 or 2 shares, reconstruction is cryptographically impossible.
- **Recover without a vault backup.** The recovery kit is a key-recovery mechanism, not a data backup. You need both: the recovery kit (3+ shares) and a vault backup file.
- **Recover if all 5 shares are lost.** If you have lost access to all 5 shares and the original machine's TPM is gone, the vault data is permanently unrecoverable.

---

## 8. Verifying the Recovery Kit (Recovery Drill)

It is recommended to test the recovery kit within 30 days of creation, and annually thereafter.

**Recovery drill procedure (without losing access to the current machine):**

1. Export a vault backup: `Settings → Backup → Export Now`.
2. Copy the backup file to a USB drive.
3. Open the Recovery Wizard on the same machine: `Settings → Recovery Kit → Test Recovery`.
4. Enter 3 shares when prompted.
5. Select the backup file from the USB drive.
6. Confirm credentials are visible (without triggering a full re-key, since you are on the original machine).
7. Status changes to `Verified`.

---

## 9. Recovery Kit Rotation

Rotate the recovery kit if:
- You suspect a share has been compromised.
- You have changed your share storage locations and want to regenerate clean shares.
- A trusted person holding a share is no longer trusted.

**To rotate:** `Settings → Recovery Kit → Rotate Kit`. This generates a new `RecoveryRootSecret` and invalidates all previous shares. Store the new shares using the same distribution strategy as the original kit.
