# Reset Zero-Trust Vault test data.
# This renames only vault.json, leaving the installed native host in place.
# Use this only if you do not need the credentials saved in the current test vault.

$ErrorActionPreference = "Stop"

$vaultDir = Join-Path $env:LOCALAPPDATA "ZeroTrustVault"
$vaultPath = Join-Path $vaultDir "vault.json"
if (-not (Test-Path -LiteralPath $vaultPath)) {
    Write-Host "No ZeroTrustVault vault file found at: $vaultPath"
    exit 0
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupPath = Join-Path $vaultDir "vault.backup-$stamp.json"
Move-Item -LiteralPath $vaultPath -Destination $backupPath
Write-Host "Moved old vault file to: $backupPath"
Write-Host "Restart Chrome/native host. A new vault will be created on next save/unlock."
