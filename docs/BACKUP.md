# Zero-Trust Vault — Backup Guide

Version: v0.5.0-hardened  
Date: 2026-06-29

---

## 1. Overview

ZTV backup creates an encrypted, MAC-protected copy of the vault at a point in time. Backup files use AES-256-GCM encryption under a key derived from the VaultRootKey (see CRYPTO.md Section 3, `BackupKey`). Without the VaultRootKey (or the recovery kit), a stolen backup file is opaque ciphertext.

Backup protects against:
- Accidental deletion of `vault.json`
- Disk failure
- Ransomware (if the backup is on a separate, uninfected medium)

Backup does **not** protect against:
- TPM-bound key loss on a machine change (the backup cannot be decrypted on a new machine without the recovery kit — see RECOVERY.md)
- Admin-level malware active at backup time (an admin-level process could intercept the backup before encryption)
- Loss of all backup copies

---

## 2. Backup File Format

Each backup file is a binary file with the following structure:

```
Offset  Length  Field
------  ------  -----
0       4       Magic: ASCII "ZTVB"
4       2       Format version (uint16 LE): 0x0001
6       16      VaultId (UUID bytes)
22      8       Event log checkpoint (uint64 LE): event count at backup time
30      32      BackupMAC: HMAC-SHA256(BackupMacKey, vaultId || checkpoint || ciphertext)
62      12      AES-GCM nonce (96-bit random)
74      16      AES-GCM authentication tag
90      N       AES-256-GCM ciphertext of vault.json content (plaintext length N-16 after decryption)
```

The BackupMAC is computed over:
```
vaultId (16 bytes) || checkpoint (8 bytes) || ciphertext (N bytes including nonce and tag)
```

On restore, the BackupMAC is verified before any decryption attempt. A MAC failure returns `ERR_BACKUP_MAC_FAILED` and aborts the restore.

---

## 3. Creating a Backup

### 3.1 Manual Backup via Extension UI

1. Open the ZTV popup.
2. Click **Settings** → **Backup** → **Back Up Now**.
3. Windows Hello prompt appears. Authenticate.
4. The backup file is written to the default backup directory: `%LOCALAPPDATA%\ZeroTrustVault\backups\`
5. Filename format: `vault_backup_<VaultId_prefix>_<timestamp>.ztv`
6. Confirmation shows the backup file path and SHA-256 hash of the backup file.

### 3.2 Manual Backup via PowerShell

```powershell
# Basic backup to default location
& "$env:LOCALAPPDATA\ZeroTrustVault\tools\backup-vault.ps1"

# Backup to a specific directory
& "$env:LOCALAPPDATA\ZeroTrustVault\tools\backup-vault.ps1" -Destination "D:\Backups\ZTV"

# Backup to USB drive (opt-in required)
& "$env:LOCALAPPDATA\ZeroTrustVault\tools\backup-vault.ps1" -Destination "E:\ZTVBackup" -IncludeUsb
```

The `-IncludeUsb` flag is required when the destination is a removable drive. This is an explicit opt-in to prevent accidental backup to an untrusted or unencrypted removable medium. Without `-IncludeUsb`, the script rejects removable drive paths.

The script requires Windows Hello for the backup operation.

---

## 4. Automated Backup via Windows Task Scheduler

The `install-backup-task.ps1` script creates a Windows Scheduled Task that runs the backup automatically.

```powershell
# Install the backup task with default settings (daily at 2:00 AM)
.\install-backup-task.ps1

# Install with custom schedule (every 6 hours)
.\install-backup-task.ps1 -TriggerHours 6

# Install with a USB destination (opt-in)
.\install-backup-task.ps1 -Destination "E:\ZTVBackup" -IncludeUsb
```

**Note on automated backup and Windows Hello:**  
Automated backups run under the current user's context. Because Windows Hello requires interactive authentication, automated backups use a cached backup key derived from the VaultRootKey that is unlocked when the user first logs in for the day. If the user is not logged in (machine is locked), the scheduled task will skip the backup for that cycle and log a note.

The scheduled task is registered as:  
`Task Scheduler Library → ZeroTrustVault_Backup`

---

## 5. Backup Rotation

To prevent unbounded disk usage, backup rotation is enforced:

| Parameter | Default | Override |
|-----------|---------|----------|
| Keep last N backups | 10 | `-KeepLast <N>` flag |
| Maximum backup age | 90 days | `-MaxAgeDays <N>` flag |
| Rotation policy | Delete oldest when over limit | Not configurable |

Older backups beyond the retention limit are deleted after a successful new backup is written and verified.

---

## 6. Listing and Verifying Backups

```powershell
# List all backups (shows VaultId, timestamp, size, verification status)
& "$env:LOCALAPPDATA\ZeroTrustVault\tools\restore-vault.ps1" -List

# Verify a specific backup (checks MAC without restoring)
& "$env:LOCALAPPDATA\ZeroTrustVault\tools\restore-vault.ps1" -Verify -BackupFile "vault_backup_abc123_20260629.ztv"

# Verify all backups in the default directory
& "$env:LOCALAPPDATA\ZeroTrustVault\tools\restore-vault.ps1" -VerifyAll
```

`-Verify` checks the BackupMAC only — it does not decrypt the backup content. This allows verification without a Windows Hello prompt.

---

## 7. Restoring from a Backup

**Same machine (TPM key intact):**

```powershell
# Restore the most recent backup
& "$env:LOCALAPPDATA\ZeroTrustVault\tools\restore-vault.ps1" -RestoreLatest

# Restore a specific backup file
& "$env:LOCALAPPDATA\ZeroTrustVault\tools\restore-vault.ps1" -BackupFile "vault_backup_abc123_20260629.ztv"
```

The restore process:
1. Verifies the BackupMAC.
2. Prompts for Windows Hello.
3. Decrypts the backup content.
4. Writes the decrypted vault.json to `%LOCALAPPDATA%\ZeroTrustVault\vault.json` (overwrites the existing file with confirmation prompt).
5. Reports the number of credentials restored.

**Different machine (TPM key not available):**

You cannot restore a ZTV backup on a new machine using only the backup file. You need:
1. The backup file (`.ztv`)
2. The recovery kit (at least 3 of 5 Shamir shares)

Follow the procedure in RECOVERY.md Section 5.

---

## 8. What Backup Protects Against (and Does Not)

| Scenario | Protected? | Notes |
|----------|-----------|-------|
| Accidental deletion of vault.json | Yes | Restore from backup |
| Hard disk failure | Yes (if backup is on separate media) | Backup on same disk as vault does not help |
| Ransomware encrypting vault.json | Yes (if backup on offline/separate media) | Backup on a connected drive may also be encrypted |
| Machine loss / theft | Partial | Backup file is ciphertext; need recovery kit to use on new machine |
| TPM failure / motherboard replacement | No (backup alone is insufficient) | Need recovery kit in addition to backup |
| Admin-level malware at backup time | No | A process with admin rights could intercept plaintext during backup |
| Loss of all backup copies | No | Keep multiple copies in multiple locations |

---

## 9. USB Backup Guidance

USB backup is opt-in (`-IncludeUsb` flag). When using USB backup:

- The backup file is encrypted before being written to USB. The USB drive does not need to be encrypted for the backup to be safe. However, encrypting the USB drive provides defense in depth.
- Label the USB drive clearly. Store it in a secure physical location.
- Do not use the same USB drive for both a backup and a recovery kit share. Keep them separate so that losing one USB drive does not compromise both.
- Periodically plug in the USB drive and run `-Verify` to confirm the backup file is intact and the drive is readable.
