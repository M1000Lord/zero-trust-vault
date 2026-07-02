<#
  Zero-Trust Vault — encrypted vault backup.

  Creates a timestamped, SHA-256-verified copy of vault.json in configured
  destinations. By default backs up to your Documents folder only.

  USB backup is OPT-IN: pass -IncludeUsb to also copy to connected USB drives.
  (Previously this was automatic; explicit opt-in prevents unintended copies on
  removable media that may be left in public locations or shared machines.)

  Usage:
    powershell -File backup-vault.ps1
    powershell -File backup-vault.ps1 -IncludeUsb
    powershell -File backup-vault.ps1 -ExtraPath "\\NAS\Vault"
    powershell -File backup-vault.ps1 -Keep 14
#>
param(
  [string]$ExtraPath  = "",
  [int]$Keep          = 7,
  [switch]$IncludeUsb
)

$ErrorActionPreference = "Stop"
$vaultFile = Join-Path $env:LOCALAPPDATA "ZeroTrustVault\vault.json"

if (-not (Test-Path $vaultFile)) {
  Write-Host "No vault file found at: $vaultFile" -ForegroundColor Yellow
  Write-Host "Create your first credential to initialise the vault, then run this script again."
  exit 0
}

# ---- Health-check: valid JSON before backing up --------------------------------

try {
  $raw = [System.IO.File]::ReadAllText($vaultFile)
  $null = [System.Web.Script.Serialization.JavaScriptSerializer]::new().DeserializeObject($raw)
} catch {
  $raw = [System.IO.File]::ReadAllText($vaultFile)
  if ($raw.Trim() -notmatch '^\{' -or $raw.Trim() -notmatch '\}$') {
    Write-Error "Vault file does not appear to be valid JSON — backup aborted to avoid saving a corrupted file."
    exit 1
  }
}
Write-Host "Vault file health check passed (valid JSON)."

# ---- Build list of backup destinations ----------------------------------------

$destinations = [System.Collections.Generic.List[string]]::new()

# 1. Documents folder (always)
$docDest = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "ZeroTrustVault\Backups"
$destinations.Add($docDest)

# 2. USB drives — ONLY if explicitly requested
if ($IncludeUsb) {
  Write-Host "USB backup enabled (-IncludeUsb). Scanning for removable drives..."
  try {
    $usb = Get-WmiObject Win32_Volume -Filter "DriveType=2" -ErrorAction SilentlyContinue |
           Where-Object { $_.DriveLetter -ne $null }
    if ($usb) {
      foreach ($drive in $usb) {
        $usbPath = Join-Path $drive.DriveLetter "ZeroTrustVault\Backups"
        $destinations.Add($usbPath)
        Write-Host "  USB drive: $($drive.DriveLetter) — will back up there." -ForegroundColor Yellow
      }
    } else {
      Write-Host "  No removable USB drives detected."
    }
  } catch {
    Write-Warning "USB drive detection failed: $_"
  }
} else {
  Write-Host "(USB backup not requested. Use -IncludeUsb to copy to removable drives.)"
}

# 3. Optional extra path
if ($ExtraPath) { $destinations.Add($ExtraPath) }

# ---- Back up to all destinations ----------------------------------------------

$stamp    = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$fileName = "vault_backup_$stamp.json"
$srcHash  = (Get-FileHash $vaultFile -Algorithm SHA256).Hash.ToUpper()

Write-Host ""
$succeeded = 0
$failed    = 0

foreach ($dest in $destinations) {
  try {
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    $destFile = Join-Path $dest $fileName

    Copy-Item -LiteralPath $vaultFile -Destination $destFile

    # Verify copy is byte-for-byte identical
    $copyHash = (Get-FileHash $destFile -Algorithm SHA256).Hash.ToUpper()
    if ($copyHash -ne $srcHash) {
      Remove-Item $destFile -Force -ErrorAction SilentlyContinue
      throw "SHA-256 mismatch after copy — destination may have a write error."
    }

    # Write checksum sidecar
    "$srcHash  $fileName" | Out-File -Encoding ASCII "$destFile.sha256" -NoNewline

    Write-Host "  Backed up to : $destFile" -ForegroundColor Green
    $succeeded++

    # Rotate old backups (keep N most recent)
    $old = Get-ChildItem -Path $dest -Filter "vault_backup_*.json" |
           Sort-Object LastWriteTime -Descending |
           Select-Object -Skip $Keep
    foreach ($f in $old) {
      Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue
      $cs = "$($f.FullName).sha256"
      if (Test-Path $cs) { Remove-Item $cs -Force -ErrorAction SilentlyContinue }
    }
    if ($old.Count -gt 0) { Write-Host "    Rotated $($old.Count) old backup(s)." }

  } catch {
    Write-Warning "  Backup to '$dest' FAILED: $_"
    $failed++
  }
}

# ---- Summary -----------------------------------------------------------------

Write-Host ""
Write-Host "Backup complete: $succeeded destination(s) written, $failed failed." -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Yellow" })
Write-Host "  SHA-256  : $srcHash"
Write-Host "  Timestamp: $stamp"
Write-Host "  Keeping  : $Keep most recent backups per destination"
Write-Host ""
Write-Host "NOTE: Every backup is already AES-256-GCM encrypted." -ForegroundColor DarkGray
Write-Host "      Only Windows Hello on this machine (or recovery kit) can decrypt it." -ForegroundColor DarkGray
Write-Host "      USB copies are safe to store offsite, but keep them physically secure." -ForegroundColor DarkGray

if ($failed -gt 0) { exit 1 }
