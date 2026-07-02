<#
  Zero-Trust Vault — vault restore utility.

  Restores a vault backup created by backup-vault.ps1. The restore replaces
  your current vault file with the selected backup. Run this after a fresh
  Windows install or drive replacement.

  IMPORTANT: The vault backup can only be decrypted by Windows Hello on the
  ORIGINAL machine (where the vault was created). Restoring to a NEW machine
  will give you the encrypted file but Windows Hello will fail to unlock it
  because the TPM key no longer exists. There is currently no cross-machine
  export format — this is a deliberate security constraint (no cloud, no key escrow).

  Usage:
    # List available backups (default search in Documents):
    powershell -ExecutionPolicy Bypass -File restore-vault.ps1 -List

    # Restore the most recent backup:
    powershell -ExecutionPolicy Bypass -File restore-vault.ps1

    # Restore a specific backup file:
    powershell -ExecutionPolicy Bypass -File restore-vault.ps1 -BackupFile "D:\Backups\vault_backup_2026-06-29_12-00-00.json"
#>
param(
  [string]$BackupFile  = "",
  [string]$BackupDir   = "",
  [switch]$List
)

$ErrorActionPreference = "Stop"

if (-not $BackupDir) {
  $BackupDir = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "ZeroTrustVault\Backups"
}

$vaultFile = Join-Path $env:LOCALAPPDATA "ZeroTrustVault\vault.json"

# ---- List mode ---------------------------------------------------------------

function ListBackups {
  if (-not (Test-Path $BackupDir)) {
    Write-Host "No backup directory found at: $BackupDir"
    Write-Host "Run backup-vault.ps1 first to create backups."
    return
  }
  $backups = Get-ChildItem -Path $BackupDir -Filter "vault_backup_*.json" |
             Sort-Object LastWriteTime -Descending
  if (-not $backups) {
    Write-Host "No backups found in: $BackupDir"
    return
  }
  Write-Host "`nAvailable backups in $BackupDir :" -ForegroundColor Cyan
  foreach ($b in $backups) {
    $size = "{0:N1} KB" -f ($b.Length / 1KB)
    Write-Host ("  [{0}]  {1}  ({2})" -f $b.LastWriteTime.ToString("yyyy-MM-dd HH:mm"), $b.Name, $size)
  }
  Write-Host ""
}

if ($List) { ListBackups; exit 0 }

# ---- Pick backup file --------------------------------------------------------

if (-not $BackupFile) {
  if (-not (Test-Path $BackupDir)) {
    throw "Backup directory not found: $BackupDir`nRun backup-vault.ps1 first."
  }
  $latest = Get-ChildItem -Path $BackupDir -Filter "vault_backup_*.json" |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
  if (-not $latest) { throw "No backups found in: $BackupDir" }
  $BackupFile = $latest.FullName
  Write-Host "Using most recent backup: $BackupFile"
}

if (-not (Test-Path $BackupFile)) {
  throw "Backup file not found: $BackupFile"
}

# ---- Verify checksum (if available) ------------------------------------------

$checksumFile = "$BackupFile.sha256"
if (Test-Path $checksumFile) {
  $expected = (Get-Content $checksumFile).Split(" ")[0].Trim().ToUpper()
  $actual   = (Get-FileHash $BackupFile -Algorithm SHA256).Hash.ToUpper()
  if ($expected -ne $actual) {
    throw "SHA-256 mismatch — backup file may be corrupted or tampered.`nExpected: $expected`nActual:   $actual"
  }
  Write-Host "Checksum verified OK." -ForegroundColor Green
} else {
  Write-Warning "No .sha256 checksum file found — skipping integrity check."
}

# ---- Confirm with user -------------------------------------------------------

Write-Host ""
Write-Host "About to restore vault from backup:" -ForegroundColor Yellow
Write-Host "  Backup : $BackupFile"
Write-Host "  Target : $vaultFile"
if (Test-Path $vaultFile) {
  Write-Host "  Current vault will be overwritten." -ForegroundColor Yellow
}
$confirm = Read-Host "`nType YES to confirm restore"
if ($confirm -ne "YES") { Write-Host "Cancelled."; exit 0 }

# ---- Back up the current vault before overwriting ---------------------------

if (Test-Path $vaultFile) {
  $preRestoreBackup = "$vaultFile.pre-restore-$(Get-Date -Format 'yyyyMMdd_HHmmss').bak"
  Copy-Item $vaultFile $preRestoreBackup
  Write-Host "Current vault saved as: $preRestoreBackup"
}

# ---- Restore -----------------------------------------------------------------

$targetDir = Split-Path $vaultFile
New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
Copy-Item -LiteralPath $BackupFile -Destination $vaultFile -Force

Write-Host ""
Write-Host "Vault restored." -ForegroundColor Green
Write-Host "  Restored from : $BackupFile"
Write-Host "  Vault location: $vaultFile"
Write-Host ""
Write-Host "Open the extension, click 'Unlock with Windows Hello' to verify." -ForegroundColor Cyan
