<#
  Zero-Trust Vault â€” release packager.

  Produces two free distribution ZIPs:
    1. Extension ZIP â€” load unpacked in Chrome/Edge (no Web Store, no fee).
    2. Host installer ZIP â€” contains the signed native host + install.ps1.

  Both ZIPs include SHA-256 checksums.

  Usage:
    powershell -ExecutionPolicy Bypass -File package-release.ps1
    powershell -ExecutionPolicy Bypass -File package-release.ps1 -Version "0.7.0"
    powershell -ExecutionPolicy Bypass -File package-release.ps1 -Sign
#>
param(
  [string]$Version = "",
  [string]$OutDir  = "",
  [switch]$Sign
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent

# ---- Version -----------------------------------------------------------------

if (-not $Version) {
  $manifest = Get-Content (Join-Path $root "extension\manifest.json") | ConvertFrom-Json
  $Version  = $manifest.version
}
Write-Host "Version: $Version"

# ---- Output directory --------------------------------------------------------

if (-not $OutDir) { $OutDir = Join-Path $root "release\v$Version" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Write-Host "Output : $OutDir"

# ---- Syntax-check all JS files -----------------------------------------------

Write-Host "`nChecking JS syntax..."
foreach ($f in (Get-ChildItem (Join-Path $root "extension") -Filter "*.js")) {
  $out = & node --check $f.FullName 2>&1
  if ($LASTEXITCODE -ne 0) { throw "Syntax error in $($f.Name):`n$out" }
  Write-Host "  OK: $($f.Name)"
}

# ---- Sign the native host exe (free, self-signed) ----------------------------

if ($Sign) {
  Write-Host "`nSigning native host exe (free self-signed cert)..."
  $signScript = Join-Path $root "tools\sign.ps1"
  $p = Start-Process powershell.exe `
    -ArgumentList "-ExecutionPolicy Bypass -File `"$signScript`"" `
    -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "sign.ps1 failed (exit $($p.ExitCode))" }
}

# ---- Package extension (load-unpacked zip) -----------------------------------

Write-Host "`nPackaging extension..."
$extSrc = Join-Path $root "extension"
$extZip = Join-Path $OutDir "ztv-extension-v$Version.zip"
if (Test-Path $extZip) { Remove-Item $extZip -Force }

$exclude = @("*.map", "*.ts", ".DS_Store", "Thumbs.db")
$files   = Get-ChildItem -Path $extSrc -Recurse -File |
           Where-Object { $name = $_.Name; -not ($exclude | Where-Object { $name -like $_ }) }

$stagingExt = Join-Path $OutDir "staging_ext"
New-Item -ItemType Directory -Force -Path $stagingExt | Out-Null
foreach ($f in $files) {
  $rel = $f.FullName.Substring($extSrc.Length).TrimStart('\','/')
  $dst = Join-Path $stagingExt $rel
  New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
  Copy-Item $f.FullName $dst -Force
}
Compress-Archive -Path (Join-Path $stagingExt "*") -DestinationPath $extZip
Remove-Item $stagingExt -Recurse -Force

Write-Host "  $extZip"

# ---- Package native host installer -------------------------------------------

Write-Host "`nPackaging native host installer..."
$hostSrc = Join-Path $root "native-host\host"

if (Test-Path $hostSrc) {
  $hostZip   = Join-Path $OutDir "ztv-host-v$Version-windows.zip"
  if (Test-Path $hostZip) { Remove-Item $hostZip -Force }

  $stagingHost = Join-Path $OutDir "staging_host"
  New-Item -ItemType Directory -Force -Path $stagingHost | Out-Null

  $binDir = Join-Path $stagingHost "host"
  New-Item -ItemType Directory -Force -Path $binDir | Out-Null
  Copy-Item (Join-Path $hostSrc "*") $binDir -Recurse -Force

  Copy-Item (Join-Path $root "native-host\installer\windows\install.ps1") $stagingHost -Force
  Copy-Item (Join-Path $root "tools\backup-vault.ps1")  $stagingHost -Force
  Copy-Item (Join-Path $root "tools\restore-vault.ps1") $stagingHost -Force
  Copy-Item (Join-Path $root "tools\sign.ps1")          $stagingHost -Force

  $tp = Join-Path $root "tools\thumbprint.txt"
  if (Test-Path $tp) { Copy-Item $tp $stagingHost -Force; Write-Host "  Thumbprint included (signature verification enabled)." }
  else               { Write-Warning "thumbprint.txt missing â€” run sign.ps1 first for tamper detection." }

  Compress-Archive -Path (Join-Path $stagingHost "*") -DestinationPath $hostZip
  Remove-Item $stagingHost -Recurse -Force

  Write-Host "  $hostZip"
} else {
  Write-Warning "Native host binaries not found at $hostSrc â€” skipping host ZIP."
}

# ---- SHA-256 checksums -------------------------------------------------------

Write-Host "`nGenerating checksums..."
$checksumFile = Join-Path $OutDir "checksums-v$Version.sha256"
$lines = @()
foreach ($f in (Get-ChildItem $OutDir -Filter "*.zip")) {
  $hash   = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
  $lines += "$hash  $($f.Name)"
  Write-Host "  $($f.Name)  $hash"
}
$lines | Out-File -Encoding ASCII $checksumFile

# ---- Done --------------------------------------------------------------------

Write-Host ""
Write-Host "Release v$Version packaged - zero cost, no accounts needed." -ForegroundColor Green
Write-Host ""
Write-Host "HOW TO DISTRIBUTE (free):" -ForegroundColor Cyan
Write-Host "  Extension  : Share ztv-extension-v$Version.zip"
Write-Host "               Recipient unzips it, then goes to:"
Write-Host "               chrome://extensions -> Developer mode -> Load unpacked -> select the folder"
Write-Host ""
Write-Host "  Native host: Share ztv-host-v$Version-windows.zip"
Write-Host "               Recipient unzips it, then runs:"
Write-Host "               powershell -ExecutionPolicy Bypass -File install.ps1 -ExtensionId <id>"
Write-Host ""
Write-Host "  Checksums  : Publish checksums-v$Version.sha256 so recipients can verify integrity."
