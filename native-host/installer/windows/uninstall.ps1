<#
  Zero-Trust Vault — native host uninstaller.

  What it removes:
    - HKCU Chrome/Edge NativeMessagingHosts registry keys (always)
    - HKLM Chrome/Edge NativeMessagingHosts registry keys (if running as admin)
    - Windows Scheduled Task for automatic backup
    - Backup runner script
    - Native host binaries and manifest

  What it KEEPS by default:
    - vault.json (encrypted vault file) — use -RemoveVault to delete
    - Backup files                      — use -RemoveBackups to delete
    - Windows Hello / CNG keys          — use -RemoveKeys to delete

  Usage:
    powershell -File uninstall.ps1
    powershell -File uninstall.ps1 -RemoveVault
    powershell -File uninstall.ps1 -RemoveVault -RemoveBackups -RemoveKeys
#>
param(
  [switch]$RemoveVault,
  [switch]$RemoveBackups,
  [switch]$RemoveKeys
)

$ErrorActionPreference = "SilentlyContinue"
$hostName   = "com.zerotrust.vault"
$installDir = Join-Path $env:LOCALAPPDATA "ZeroTrustVault\host"
$vaultDir   = Join-Path $env:LOCALAPPDATA "ZeroTrustVault"
$taskName   = "ZeroTrustVaultBackup"

Write-Host ""
Write-Host "=== Zero-Trust Vault Uninstaller ===" -ForegroundColor Cyan
Write-Host ""

# ---- Check admin status -------------------------------------------------------

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
             [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
  Write-Host "  Running as standard user (HKCU registry only)." -ForegroundColor Yellow
  Write-Host "  Re-run as Administrator to also clean HKLM entries." -ForegroundColor Yellow
  Write-Host ""
}

# ---- Remove HKCU registry keys (always) ---------------------------------------

Write-Host "Removing HKCU registry entries..."
foreach ($p in @(
  "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$hostName",
  "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$hostName"
)) {
  if (Test-Path $p) {
    Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Removed: $p" -ForegroundColor Green
  }
}

# ---- Remove HKLM registry keys (if admin) ------------------------------------

if ($isAdmin) {
  Write-Host "Removing HKLM registry entries (admin)..."
  foreach ($p in @(
    "HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\$hostName",
    "HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\$hostName",
    "HKLM:\SOFTWARE\Wow6432Node\Google\Chrome\NativeMessagingHosts\$hostName",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Edge\NativeMessagingHosts\$hostName"
  )) {
    if (Test-Path $p) {
      Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue
      Write-Host "  [OK] Removed: $p" -ForegroundColor Green
    }
  }
} else {
  Write-Host "  Skipping HKLM cleanup (not admin). Manual cleanup if needed:" -ForegroundColor Yellow
  Write-Host "    HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\$hostName" -ForegroundColor DarkGray
  Write-Host "    HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\$hostName" -ForegroundColor DarkGray
}

# ---- Remove scheduled backup task --------------------------------------------

Write-Host "Removing scheduled backup task..."
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($task) {
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host "  [OK] Removed scheduled task: $taskName" -ForegroundColor Green
} else {
  Write-Host "  (No scheduled task '$taskName' found.)"
}

# Remove backup runner script if present
$runnerScript = Join-Path $vaultDir "run-backup.ps1"
if (Test-Path $runnerScript) {
  Remove-Item $runnerScript -Force -ErrorAction SilentlyContinue
  Write-Host "  [OK] Removed backup runner script." -ForegroundColor Green
}

# ---- Remove native host binaries + manifest ----------------------------------

Write-Host "Removing native host binaries..."
if (Test-Path $installDir) {
  Remove-Item -Path $installDir -Recurse -Force -ErrorAction SilentlyContinue
  Write-Host "  [OK] Removed: $installDir" -ForegroundColor Green
} else {
  Write-Host "  (Install directory not found — may already be removed.)"
}

# ---- Optional: Remove vault file ---------------------------------------------

if ($RemoveVault) {
  $vaultFile = Join-Path $vaultDir "vault.json"
  if (Test-Path $vaultFile) {
    Remove-Item $vaultFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Removed vault: $vaultFile" -ForegroundColor Yellow
  }
  $migrFile = "$vaultFile.pre-migration-backup"
  if (Test-Path $migrFile) {
    Remove-Item $migrFile -Force -ErrorAction SilentlyContinue
  }
} else {
  Write-Host "  Vault file kept: $(Join-Path $vaultDir 'vault.json')" -ForegroundColor DarkGray
  Write-Host "  (Use -RemoveVault to delete it.)" -ForegroundColor DarkGray
}

# ---- Optional: Remove backup files -------------------------------------------

if ($RemoveBackups) {
  $backupDirs = @(
    Join-Path ([Environment]::GetFolderPath("MyDocuments")) "ZeroTrustVault\Backups"
  )
  foreach ($d in $backupDirs) {
    if (Test-Path $d) {
      $count = (Get-ChildItem $d -Filter "vault_backup_*" -ErrorAction SilentlyContinue).Count
      Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue
      Write-Host "  [OK] Removed $count backup(s) from: $d" -ForegroundColor Yellow
    }
  }
} else {
  Write-Host "  Backups kept in Documents\ZeroTrustVault\Backups" -ForegroundColor DarkGray
  Write-Host "  (Use -RemoveBackups to delete them.)" -ForegroundColor DarkGray
}

# ---- Optional: Remove Windows Hello / CNG keys --------------------------------

if ($RemoveKeys) {
  Write-Host "Attempting to remove Windows Hello / CNG keys..." -ForegroundColor Yellow
  Write-Host "  WARNING: This permanently destroys your local ZTV key." -ForegroundColor Red
  Write-Host "  The vault will be inaccessible on this machine without the recovery kit." -ForegroundColor Red
  try {
    # Remove the CNG persisted key associated with ZTV
    $keyNames = [System.Security.Cryptography.CngKey]::GetAllKeys() |
                Where-Object { $_.KeyName -like "*ZeroTrustVault*" -or $_.KeyName -like "*ZTV*" }
    foreach ($k in $keyNames) {
      $k.Delete()
      Write-Host "  [OK] Deleted CNG key: $($k.KeyName)" -ForegroundColor Yellow
    }
    if (-not $keyNames) {
      Write-Host "  (No ZTV-specific CNG keys found in current user store.)"
    }
  } catch {
    Write-Warning "  CNG key removal failed: $_"
    Write-Host "  Keys may need manual removal via certmgr.msc or PowerShell as admin."
  }
} else {
  Write-Host "  Windows Hello keys kept (use -RemoveKeys to delete; destroys vault access)." -ForegroundColor DarkGray
}

# ---- Remove vault directory if empty -----------------------------------------

if (Test-Path $vaultDir) {
  $remaining = Get-ChildItem $vaultDir -Recurse -ErrorAction SilentlyContinue
  if (-not $remaining) {
    Remove-Item $vaultDir -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Removed empty vault directory: $vaultDir" -ForegroundColor Green
  }
}

# ---- Done --------------------------------------------------------------------

Write-Host ""
Write-Host "Uninstall complete." -ForegroundColor Green
Write-Host ""
if (-not $RemoveVault) {
  Write-Host "  Your encrypted vault is preserved at:" -ForegroundColor Cyan
  Write-Host "    $(Join-Path $vaultDir 'vault.json')" -ForegroundColor Cyan
  Write-Host "  It cannot be decrypted without Windows Hello on this machine" -ForegroundColor DarkGray
  Write-Host "  or the recovery kit (3-of-5 shares). Keep them safe." -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "  To remove Chrome extension: chrome://extensions → Remove" -ForegroundColor Yellow
Write-Host ""
