# Zero-Trust Vault — Uninstall Guide

Version: v0.5.0-hardened  
Date: 2026-06-29

---

## 1. Overview

ZTV can be fully or partially uninstalled using `uninstall.ps1`. By default, uninstallation removes the native host registration and binaries but preserves the vault file and backup files. You must explicitly opt in to deleting vault data.

**Before uninstalling:** If you intend to reinstall ZTV later on this machine, you do not need to delete your vault file. The vault file can be reused after reinstallation.

**Before uninstalling with `-RemoveKeys`:** Windows Hello keys in the TPM will be permanently deleted. There is no way to recover them after this step. If you intend to access the vault again (on any machine), ensure you have a valid recovery kit and vault backup before proceeding.

---

## 2. Standard Uninstall (Keeps Vault Data)

The default uninstall removes the native host registration, host binary, and Chrome extension without deleting vault data.

```powershell
# From the host\ directory (the directory containing uninstall.ps1)
.\uninstall.ps1
```

This performs:
1. Removes the native messaging host registry key from `HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.zerotrustvault.host`
2. Removes the host binary and manifest from `%LOCALAPPDATA%\ZeroTrustVault\host\`
3. Removes the scheduled backup task (if installed)

The following are **kept** by default:
- `%LOCALAPPDATA%\ZeroTrustVault\vault.json` — your encrypted vault
- `%LOCALAPPDATA%\ZeroTrustVault\events.json` — the encrypted event log
- `%LOCALAPPDATA%\ZeroTrustVault\backups\` — encrypted backup files

After running `uninstall.ps1`, remove the extension from Chrome:
1. Go to `chrome://extensions/`.
2. Find Zero-Trust Vault.
3. Click **Remove**.

---

## 3. Uninstall Options

### `-RemoveVault`

Deletes the vault file and event log in addition to the host registration.

```powershell
.\uninstall.ps1 -RemoveVault
```

Removes:
- `%LOCALAPPDATA%\ZeroTrustVault\vault.json`
- `%LOCALAPPDATA%\ZeroTrustVault\events.json`
- `%LOCALAPPDATA%\ZeroTrustVault\` directory (if empty after removal)

Backup files are still kept unless `-RemoveBackups` is also specified.

### `-RemoveBackups`

Deletes all encrypted backup files.

```powershell
.\uninstall.ps1 -RemoveBackups
```

Removes:
- `%LOCALAPPDATA%\ZeroTrustVault\backups\` and all files within

### `-RemoveKeys`

**Irreversible.** Deletes the Windows Hello / TPM-backed CNG platform keys for this vault.

```powershell
.\uninstall.ps1 -RemoveKeys
```

Removes:
- CNG platform key `ZeroTrustVault_Root_{VaultId}` from the system KSP or TPM
- CNG platform key `ZeroTrustVault_Device_{VaultId}_{DeviceId}` from the system KSP or TPM

**WARNING:** After `-RemoveKeys`, the vault file (if retained) cannot be decrypted on this machine. The only way to recover data is with the recovery kit and a vault backup file. If you do not have both, data will be permanently inaccessible.

### Combined Example: Full Wipe

```powershell
.\uninstall.ps1 -RemoveVault -RemoveBackups -RemoveKeys
```

This leaves nothing ZTV-related on the machine.

---

## 4. What Gets Removed (Standard Uninstall)

| Item | Location | Removed? |
|------|----------|----------|
| Native host binary | `%LOCALAPPDATA%\ZeroTrustVault\host\ZeroTrustVault.Host.exe` | Yes |
| Native host manifest | `%LOCALAPPDATA%\ZeroTrustVault\host\ZeroTrustVault.Host.json` | Yes |
| HKCU registry key | `HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.zerotrustvault.host` | Yes |
| HKLM registry key (if admin-installed) | `HKLM:\Software\Google\Chrome\NativeMessagingHosts\com.zerotrustvault.host` | Yes (only if script is run as admin) |
| Scheduled backup task | Windows Task Scheduler: `ZeroTrustVault_Backup` | Yes |
| Install log | `%LOCALAPPDATA%\ZeroTrustVault\install.log` | Yes |
| Vault file | `%LOCALAPPDATA%\ZeroTrustVault\vault.json` | No (requires `-RemoveVault`) |
| Event log | `%LOCALAPPDATA%\ZeroTrustVault\events.json` | No (requires `-RemoveVault`) |
| Backup files | `%LOCALAPPDATA%\ZeroTrustVault\backups\` | No (requires `-RemoveBackups`) |
| CNG platform keys (TPM) | Windows KSP | No (requires `-RemoveKeys`) |

---

## 5. Manual Cleanup (If Script Fails)

If `uninstall.ps1` fails or is unavailable, perform these steps manually:

### 5.1 Remove Registry Key (HKCU — No Admin Required)

```powershell
Remove-Item -Path "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.zerotrustvault.host" -Recurse -Force
```

### 5.2 Remove Registry Key (HKLM — Admin Required)

```powershell
# Only if the host was installed system-wide (requires admin)
Remove-Item -Path "HKLM:\Software\Google\Chrome\NativeMessagingHosts\com.zerotrustvault.host" -Recurse -Force
```

### 5.3 Remove Host Files

```powershell
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\ZeroTrustVault\host\"
```

### 5.4 Remove Scheduled Task

```powershell
Unregister-ScheduledTask -TaskName "ZeroTrustVault_Backup" -Confirm:$false
```

### 5.5 Remove CNG Platform Keys (Manual — Irreversible)

```powershell
# List ZTV CNG keys
& certutil -csp "Microsoft Platform Crypto Provider" -key | Select-String "ZeroTrustVault"

# Delete each key found (replace KEY_NAME with the actual key name)
$ncrypt = [System.Security.Cryptography.CngKey]::Open("KEY_NAME", [System.Security.Cryptography.CngProvider]::MicrosoftPlatformCryptoProvider)
$ncrypt.Delete()
```

Alternatively, CNG platform keys can be listed and deleted using the `ncrypt` APIs in a small C# utility, or via the `certutil` tool with the `-delkey` flag. Consult Windows documentation for the specific key names used (`ZeroTrustVault_Root_*` and `ZeroTrustVault_Device_*`).

### 5.6 Remove the Extension from Chrome

1. Go to `chrome://extensions/`.
2. Find Zero-Trust Vault.
3. Click **Remove**.

---

## 6. Verifying Uninstall

After uninstall, verify:

```powershell
# Registry key should not exist
Get-Item "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.zerotrustvault.host" -ErrorAction SilentlyContinue
# Should return nothing

# Host files should not exist (standard uninstall)
Test-Path "$env:LOCALAPPDATA\ZeroTrustVault\host\ZeroTrustVault.Host.exe"
# Should return False

# Vault file should exist (unless -RemoveVault was used)
Test-Path "$env:LOCALAPPDATA\ZeroTrustVault\vault.json"
# Should return True (standard uninstall keeps vault)
```

---

## 7. Reinstalling After Uninstall

If you kept the vault file (standard uninstall without `-RemoveVault`), reinstalling on the same machine with the same Windows profile will reconnect to the existing vault. The CNG platform key should still be present in the TPM.

If you also ran `-RemoveKeys`, reinstalling requires recovery using the recovery kit. See RECOVERY.md for the full recovery procedure.
