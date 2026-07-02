<#
  Zero-Trust Vault Ã¢â‚¬â€ Release Builder

  Produces a signed, scanned, integrity-stamped release ZIP.

  Steps:
    1. Forbidden-string scan (fail fast)
    2. Build native host from source in Release mode
    3. Sign the exe (self-signed cert or code-signing cert)
    4. Rebuild integrity hashes (build-integrity.ps1)
    5. Generate release manifest (SHA-256 of every artifact)
    6. Package ZIP (extension + install/)
    7. Copy to output path

  Prerequisites:
    - .NET 9 SDK (dotnet build)
    - PowerShell 5.1+
    - Run build-integrity.ps1 after any extension source change

  Usage:
    powershell -File build-release.ps1
    powershell -File build-release.ps1 -Version "2.0.1"
    powershell -File build-release.ps1 -CertThumbprint "ABCDEF..."
#>
param(
  [string]$Version        = "",
  [string]$CertThumbprint = "",
  [string]$OutputDir      = (Join-Path $PSScriptRoot "..\dist"),
  [switch]$DevMode,
  [switch]$CopyToDesktop
)

$ErrorActionPreference = "Stop"
$root    = Split-Path $PSScriptRoot -Parent
$extDir  = Join-Path $root "extension"
$srcDir  = Join-Path $root "native-host\src\ZeroTrustVaultHost"
$tools   = $PSScriptRoot

Write-Host ""
Write-Host "=== Zero-Trust Vault Release Builder ===" -ForegroundColor Cyan
Write-Host ""

# ---- Detect version from manifest if not specified ----------------------------

if (-not $Version) {
  $mf = Get-Content (Join-Path $extDir "manifest.json") -Raw | ConvertFrom-Json
  $Version = $mf.version
}
Write-Host "Version: $Version"

# ---- Step 1: Forbidden string scan -------------------------------------------

Write-Host ""
Write-Host "Step 1: Forbidden string scan..."
& powershell -File (Join-Path $tools "check-forbidden-strings.ps1") -ExtensionDir $extDir
if ($LASTEXITCODE -ne 0) {
  Write-Host "RELEASE ABORTED: forbidden strings found." -ForegroundColor Red; exit 1
}

# ---- Step 2: Build native host from source ------------------------------------

Write-Host ""
Write-Host "Step 2: Building native host from source (Release)..."
$publishDir = Join-Path $root "native-host\publish\Release"
New-Item -ItemType Directory -Force -Path $publishDir | Out-Null

if (Test-Path (Join-Path $srcDir "ZeroTrustVaultHost.csproj")) {
  dotnet publish (Join-Path $srcDir "ZeroTrustVaultHost.csproj") `
    -c Release -o $publishDir --no-self-contained -r win-x64
  if ($LASTEXITCODE -ne 0) { Write-Host "Build failed." -ForegroundColor Red; exit 1 }
  Write-Host "  Build succeeded: $publishDir" -ForegroundColor Green
} else {
  Write-Warning "  Native host source not found at $srcDir Ã¢â‚¬â€ using existing binaries."
  $publishDir = Join-Path $root "native-host\installer\windows\host"
}

$exePath = Join-Path $publishDir "ZeroTrustVaultHost.exe"
if (-not (Test-Path $exePath)) { Write-Host "Exe not found: $exePath" -ForegroundColor Red; exit 1 }

# ---- Step 2b: Scan built binary for forbidden strings -------------------------

Write-Host "  Scanning built binary..."
& powershell -File (Join-Path $tools "check-forbidden-strings.ps1") -HostDir $publishDir -SkipSource
if ($LASTEXITCODE -ne 0) {
  Write-Host "RELEASE ABORTED: forbidden strings in binary." -ForegroundColor Red; exit 1
}

# ---- Step 3: Sign the exe -----------------------------------------------------

Write-Host ""
Write-Host "Step 3: Authenticode signing..."
$cert = $null
if ($CertThumbprint) {
  $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $CertThumbprint } | Select-Object -First 1
}
if (-not $cert) {
  $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {
    $_.Subject -like "*ZeroTrustVault*" -and (Get-Date) -lt $_.NotAfter
  } | Select-Object -First 1
}

if ($cert) {
  Set-AuthenticodeSignature -FilePath $exePath -Certificate $cert -TimestampServer "http://timestamp.digicert.com" | Out-Null
  $sig = Get-AuthenticodeSignature $exePath
  if ($sig.Status -eq "Valid") {
    $tp = $sig.SignerCertificate.Thumbprint
    Write-Host "  Signed. Thumbprint: $tp" -ForegroundColor Green
    $tp | Out-File (Join-Path $publishDir "thumbprint.txt") -Encoding ASCII -NoNewline
  } else {
    if ($DevMode) {
      Write-Warning "  DEV MODE: signature status is $($sig.Status). Do not ship this build."
    } else {
      Write-Host "RELEASE ABORTED: signature status is $($sig.Status)." -ForegroundColor Red
      exit 1
    }
  }
} else {
  if ($DevMode) {
    Write-Warning "  DEV MODE: no signing cert found. Exe will be unsigned; do not ship this build."
  } else {
    Write-Host "RELEASE ABORTED: no signing cert found. Provide -CertThumbprint for production." -ForegroundColor Red
    exit 1
  }
}

# ---- Step 4: Rebuild extension integrity hashes ------------------------------

Write-Host ""
Write-Host "Step 4: Stamping extension integrity hashes (update -> verify)..."
$integrityScript = Join-Path $tools "update-extension-hashes.ps1"
$verifyScript    = Join-Path $tools "verify-extension-integrity.ps1"
if (Test-Path $integrityScript) {
  & powershell -ExecutionPolicy Bypass -File $integrityScript -ExtensionDir $extDir
  if ($LASTEXITCODE -ne 0) { Write-Host "Hash stamping failed." -ForegroundColor Red; exit 1 }
  & powershell -ExecutionPolicy Bypass -File $verifyScript -ExtensionDir $extDir
  if ($LASTEXITCODE -ne 0) { Write-Host "Integrity verify failed after stamping." -ForegroundColor Red; exit 1 }
} else {
  Write-Warning "  build-integrity.ps1 not found at $integrityScript Ã¢â‚¬â€ skipping."
}

# ---- Step 5: Generate SBOM ---------------------------------------------------

Write-Host ""
Write-Host "Step 5: Generating SBOM..."
$sbomScript = Join-Path $tools "generate-sbom.ps1"
if (Test-Path $sbomScript) {
  & powershell -File $sbomScript -OutDir $publishDir
  if ($LASTEXITCODE -ne 0) { Write-Host "SBOM generation failed." -ForegroundColor Red; exit 1 }
} else {
  Write-Warning "  generate-sbom.ps1 not found at $sbomScript."
}

# ---- Step 6: Generate release manifest (SHA-256 of all artifacts) ------------

Write-Host ""
Write-Host "Step 6: Generating release manifest..."
$manifestEntries = [System.Collections.Generic.List[object]]::new()

$filesToHash = @(
  @{ file = $exePath; name = "host/ZeroTrustVaultHost.exe" }
)
foreach ($f in Get-ChildItem $extDir -File) {
  $filesToHash += @{ file = $f.FullName; name = "extension/$($f.Name)" }
}
foreach ($extra in @("SBOM.json", "DEPENDENCIES.md", "build-info.json")) {
  $p = Join-Path $publishDir $extra
  if (Test-Path $p) { $filesToHash += @{ file = $p; name = $extra } }
}

foreach ($entry in $filesToHash) {
  if (-not (Test-Path $entry.file)) { continue }
  $hash = (Get-FileHash $entry.file -Algorithm SHA256).Hash.ToLower()
  $manifestEntries.Add([pscustomobject]@{ path = $entry.name; sha256 = $hash })
}

$sourceHashInput = Get-ChildItem $root -Recurse -File |
  Where-Object {
    $_.FullName -notmatch '\\(bin|obj|publish|host|release|dist|\.git)\\' -and
    $_.Extension -in @(".cs",".js",".json",".ps1",".md",".html",".css")
  } |
  Sort-Object FullName |
  ForEach-Object { "$($_.FullName.Substring($root.Length)):$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower())" }
$sourceHashBytes = [System.Text.Encoding]::UTF8.GetBytes(($sourceHashInput -join "`n"))
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$sourceHash = [System.BitConverter]::ToString($sha256.ComputeHash($sourceHashBytes)).Replace("-","").ToLower()
$sha256.Dispose()
$sigInfo = if (Test-Path $exePath) { Get-AuthenticodeSignature $exePath } else { $null }
$certSubject = if ($sigInfo -and $sigInfo.SignerCertificate) { $sigInfo.SignerCertificate.Subject } else { $null }
$certThumbprint = if ($sigInfo -and $sigInfo.SignerCertificate) { $sigInfo.SignerCertificate.Thumbprint } else { $null }
$buildId = [guid]::NewGuid().ToString("N")

$releaseManifest = [pscustomobject]@{
  product               = "Zero-Trust Vault"
  version               = $Version
  buildId               = $buildId
  builtAt               = (Get-Date -Format "o")
  sourceHash            = $sourceHash
  certificateSubject    = $certSubject
  certificateThumbprint = $certThumbprint
  signatureStatus       = if ($sigInfo) { [string]$sigInfo.Status } else { "Missing" }
  minimumBrowserVersion = "Chrome/Edge MV3-capable"
  minimumWindowsVersion = "Windows 10 22H2"
  artifacts             = $manifestEntries
}

$manifestJson = $releaseManifest | ConvertTo-Json -Depth 5
$manifestPath = Join-Path $publishDir "release-manifest.json"
[System.IO.File]::WriteAllText($manifestPath, $manifestJson, [System.Text.UTF8Encoding]::new($false))
Write-Host "  Manifest written: $manifestPath" -ForegroundColor Green

# Compute manifest hash (for out-of-band distribution)
$manifestHash = (Get-FileHash $manifestPath -Algorithm SHA256).Hash.ToLower()
Write-Host "  Manifest SHA-256: $manifestHash" -ForegroundColor Cyan

# ---- Step 7: Package ZIP -----------------------------------------------------

Write-Host ""
Write-Host "Step 7: Packaging release ZIP..."
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$zipName    = "zero-trust-vault-v$Version.zip"
$zipPath    = Join-Path $OutputDir $zipName
$stagingDir = Join-Path $env:TEMP "ztv-release-$([guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Force -Path $stagingDir | Out-Null

try {
  # Extension folder
  Copy-Item -Path $extDir -Destination (Join-Path $stagingDir "extension") -Recurse -Force

  # Install folder
  $installDest = Join-Path $stagingDir "install"
  New-Item -ItemType Directory -Force -Path (Join-Path $installDest "host") | Out-Null
  Copy-Item -Path (Join-Path $publishDir "*.exe") -Destination (Join-Path $installDest "host") -ErrorAction SilentlyContinue
  Copy-Item -Path (Join-Path $publishDir "*.dll") -Destination (Join-Path $installDest "host") -ErrorAction SilentlyContinue
  if (Test-Path (Join-Path $publishDir "thumbprint.txt")) {
    Copy-Item (Join-Path $publishDir "thumbprint.txt") $installDest
  }
  if (Test-Path $manifestPath) {
    Copy-Item $manifestPath $installDest
  }
  foreach ($extra in @("SBOM.json", "DEPENDENCIES.md", "build-info.json")) {
    $p = Join-Path $publishDir $extra
    if (Test-Path $p) { Copy-Item $p $installDest }
  }
  Copy-Item (Join-Path $root "native-host\installer\windows\install.ps1")   $installDest -ErrorAction SilentlyContinue
  Copy-Item (Join-Path $root "native-host\installer\windows\uninstall.ps1") $installDest -ErrorAction SilentlyContinue
  Copy-Item (Join-Path $tools "backup-vault.ps1")                           $installDest -ErrorAction SilentlyContinue

  # Remove any .pdb files (no debug symbols in release)
  Get-ChildItem $stagingDir -Recurse -Filter "*.pdb" | Remove-Item -Force -ErrorAction SilentlyContinue

  if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
  Compress-Archive -Path (Join-Path $stagingDir "*") -DestinationPath $zipPath -Force
  Write-Host "  ZIP created: $zipPath" -ForegroundColor Green

} finally {
  Remove-Item $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($CopyToDesktop) {
  $desktop = Join-Path $env:USERPROFILE "OneDrive\Desktop"
  if (-not (Test-Path $desktop)) { $desktop = Join-Path $env:USERPROFILE "Desktop" }
  $desktopZip = Join-Path $desktop $zipName
  Copy-Item $zipPath $desktopZip -Force
  Write-Host "  Copied to Desktop: $desktopZip" -ForegroundColor Green
}

# ---- Summary -----------------------------------------------------------------

Write-Host ""
Write-Host "Release build complete." -ForegroundColor Green
Write-Host ""
Write-Host "  Version        : $Version"
Write-Host "  ZIP            : $zipPath"
Write-Host "  Manifest hash  : $manifestHash"
$zipSizeMb = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
Write-Host "  Size           : $zipSizeMb MB"
Write-Host ""
Write-Host "  IMPORTANT: Distribute the manifest hash out-of-band from the ZIP." -ForegroundColor Yellow
Write-Host '  Users should verify: (Get-FileHash release-manifest.json -Algorithm SHA256).Hash' -ForegroundColor Yellow
Write-Host ""
