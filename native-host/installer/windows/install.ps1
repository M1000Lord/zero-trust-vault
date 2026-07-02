<#
  Zero-Trust Vault - native host installer (Windows).

  What it does:
    1. Pre-flight: checks .NET 9 Desktop Runtime and Chrome/Edge installation
    2. Auto-detects the extension ID from your Chrome/Edge profile (no copy-paste needed)
    3. Copies the native host binary to %LOCALAPPDATA%\ZeroTrustVault\host
    4. Writes the native-messaging manifest WITHOUT a BOM (Chrome rejects BOM-prefixed JSON)
    5. Registers under HKLM (Chrome 149+ requirement) via elevated sub-process; HKCU fallback
    6. Locks vault + host directories to current user and SYSTEM only
    7. Post-install verification: exe, manifest, and registry all confirmed present

  Usage (extension ID is auto-detected if the extension is already loaded):
    powershell -ExecutionPolicy Bypass -File install.ps1

  Or specify explicitly:
    powershell -ExecutionPolicy Bypass -File install.ps1 -ExtensionId abcdefghijklmnopqrstuvwxyzabcdef
#>
param(
  [string]$ExtensionId   = "",
  [string]$Configuration = "Release",
  [switch]$DevMode
)

$ErrorActionPreference = "Stop"
$hostName   = "com.zerotrust.vault"
$projPath   = Join-Path $PSScriptRoot "..\..\ZeroTrustVaultHost\ZeroTrustVaultHost.csproj"
$bundleDir  = Join-Path $PSScriptRoot "..\..\..\install\host"
# Also try relative to this script's location (works when run from install/)
if (-not (Test-Path (Join-Path $bundleDir "ZeroTrustVaultHost.exe"))) {
  $bundleDir = Join-Path $PSScriptRoot "host"
}
$bundleExe  = Join-Path $bundleDir "ZeroTrustVaultHost.exe"
$installDir = Join-Path $env:LOCALAPPDATA "ZeroTrustVault\host"
$vaultDir   = Join-Path $env:LOCALAPPDATA "ZeroTrustVault"

Write-Host ""
Write-Host "=== Zero-Trust Vault Installer ===" -ForegroundColor Cyan
Write-Host ""

$productionMode = -not $DevMode
if ($productionMode) {
  Write-Host "Mode: production (signature and release manifest required)" -ForegroundColor Cyan
} else {
  Write-Host "Mode: DEV (verification may be relaxed; do not ship)" -ForegroundColor Yellow
}

# ---- Production package verification ---------------------------------------

$releaseManifestPath = Join-Path $PSScriptRoot "release-manifest.json"
if ($productionMode -and -not (Test-Path $releaseManifestPath)) {
  throw "release-manifest.json missing. Production installer refuses unsigned/unmanifested packages. Use -DevMode only for local development."
}

if (Test-Path $releaseManifestPath) {
  $releaseManifest = Get-Content $releaseManifestPath -Raw | ConvertFrom-Json
  $hostEntry = $releaseManifest.artifacts | Where-Object { $_.path -eq "host/ZeroTrustVaultHost.exe" } | Select-Object -First 1
  if ($hostEntry -and (Test-Path $bundleExe)) {
    $actualHash = (Get-FileHash $bundleExe -Algorithm SHA256).Hash.ToLower()
    if ($actualHash -ne $hostEntry.sha256.ToLower()) {
      throw "Native host hash mismatch against release-manifest.json. Refusing installation."
    }
    Write-Host "  Release manifest host hash: OK" -ForegroundColor Green
  } elseif ($productionMode) {
    throw "release-manifest.json does not contain host/ZeroTrustVaultHost.exe or bundled exe is missing."
  }
} elseif ($DevMode) {
  Write-Warning "  DEV MODE: release manifest missing; package hash verification skipped."
}

# ---- Pre-flight 1: .NET 9 Desktop Runtime -----------------------------------

Write-Host "Checking .NET 9 Desktop Runtime..."
$dotnetCmd = Get-Command dotnet -ErrorAction SilentlyContinue
$hasDesktop = $false
if ($dotnetCmd) {
  $runtimeList = & dotnet --list-runtimes 2>$null
  $hasDesktop  = ($runtimeList | Where-Object { $_ -like "Microsoft.WindowsDesktop.App 9.*" }).Count -gt 0
  if (-not $hasDesktop) {
    $hasCore = ($runtimeList | Where-Object { $_ -like "Microsoft.NETCore.App 9.*" }).Count -gt 0
    if ($hasCore) {
      Write-Warning ".NET 9 base runtime found but .NET 9 Desktop Runtime is missing."
    } else {
      Write-Warning ".NET 9 not found."
    }
  }
}

if (-not $hasDesktop) {
  Write-Host ""
  Write-Host "  The native host requires .NET 9 Desktop Runtime for Windows." -ForegroundColor Yellow
  Write-Host "  Download (free): https://dotnet.microsoft.com/download/dotnet/9.0" -ForegroundColor Yellow
  Write-Host "  Choose: '.NET Desktop Runtime 9.x' -> Windows x64 Installer" -ForegroundColor Yellow
  Write-Host ""
  $ans = Read-Host "  Continue anyway? (y/N)"
  if ($ans -notin @('y','Y')) { Write-Host "Installer cancelled."; exit 1 }
} else {
  Write-Host "  .NET 9 Desktop Runtime: OK" -ForegroundColor Green
}

# ---- Pre-flight 2: Chrome / Edge detection ----------------------------------

Write-Host "Checking browser installation..."
$chromePaths = @(
  "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
  "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
  "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
)
$edgePaths = @(
  "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
  "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
)
$chromeExe = $chromePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
$edgeExe   = $edgePaths   | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($chromeExe) {
  $v = (Get-Item $chromeExe -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
  Write-Host "  Chrome: $v" -ForegroundColor Green
} elseif ($edgeExe) {
  $v = (Get-Item $edgeExe -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
  Write-Host "  Edge: $v (Chrome not found, will register for Edge)" -ForegroundColor Yellow
} else {
  Write-Warning "  Neither Chrome nor Edge found. The native host will be installed but may not connect."
}

# ---- Extension ID: auto-detect from browser profile -------------------------

function Find-ExtensionId {
  $dataDirs = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
  )
  foreach ($dataDir in $dataDirs) {
    if (-not (Test-Path $dataDir)) { continue }
    $profiles = Get-ChildItem $dataDir -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^(Default|Profile \d+)$' }
    foreach ($profile in $profiles) {
      $extDir = Join-Path $profile.FullName "Extensions"
      if (-not (Test-Path $extDir)) { continue }
      foreach ($extId in Get-ChildItem $extDir -Directory -ErrorAction SilentlyContinue) {
        foreach ($ver in Get-ChildItem $extId.FullName -Directory -ErrorAction SilentlyContinue) {
          $mfPath = Join-Path $ver.FullName "manifest.json"
          if (-not (Test-Path $mfPath)) { continue }
          try {
            $mf = Get-Content $mfPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ($mf.name -eq "Zero-Trust Vault") { return $extId.Name }
          } catch {}
        }
      }
    }
  }
  return $null
}

Write-Host "Looking for Zero-Trust Vault extension in browser profiles..."
$detected = Find-ExtensionId

if ($detected) {
  Write-Host "  Detected extension ID: $detected" -ForegroundColor Green
  if (-not $ExtensionId) {
    $ExtensionId = $detected
  } elseif ($ExtensionId -ne $detected) {
    Write-Warning "  Provided ID ($ExtensionId) differs from detected ID ($detected)."
    Write-Warning "  Using provided ID. If the vault can't connect, re-run without -ExtensionId."
  }
} else {
  Write-Host "  Extension not found in browser profiles." -ForegroundColor Yellow
  if (-not $ExtensionId) {
    Write-Host ""
    Write-Host "  Load the extension in Chrome first:" -ForegroundColor Cyan
    Write-Host "    1. Go to chrome://extensions"
    Write-Host "    2. Turn on Developer mode (top-right toggle)"
    Write-Host "    3. Click 'Load unpacked' -> select the 'extension' folder"
    Write-Host "    4. Copy the 32-character extension ID shown under the name"
    Write-Host ""
    $ExtensionId = Read-Host "  Paste extension ID here"
  }
}

# Validate extension ID
if ($ExtensionId -notmatch '^[a-p]{32}$') {
  throw "Invalid extension ID '$ExtensionId' - must be 32 lowercase letters a-p. Check chrome://extensions."
}
Write-Host "  Extension ID: $ExtensionId" -ForegroundColor Green

# ---- 1. Copy native host binaries -------------------------------------------

Write-Host ""
Write-Host "Installing native host binaries..."
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

if (Test-Path -LiteralPath $bundleExe) {
  Copy-Item -Path (Join-Path $bundleDir "*") -Destination $installDir -Recurse -Force
  Write-Host "  Copied binaries to: $installDir"
} elseif (Test-Path -LiteralPath $projPath) {
  Write-Host "  Building from source (this may take a moment)..."
  dotnet publish $projPath -c $Configuration -o $installDir
  if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed (exit $LASTEXITCODE)" }
} else {
  throw @"
Native host binaries not found at: $bundleDir
Source project not found at:       $projPath
Make sure you're running install.ps1 from inside the extracted ZIP's 'install' folder.
"@
}

$exePath = Join-Path $installDir "ZeroTrustVaultHost.exe"
if (-not (Test-Path $exePath)) { throw "Native host exe missing after copy: $exePath" }

# ---- 1b. Verify exe signature (thumbprint pinning) --------------------------

$thumbprintFile = Join-Path $PSScriptRoot "thumbprint.txt"
if (-not (Test-Path $thumbprintFile)) {
  $thumbprintFile = Join-Path $PSScriptRoot "..\thumbprint.txt"
}

if (Test-Path $thumbprintFile) {
  $expected = (Get-Content $thumbprintFile -ErrorAction Stop).Trim().ToUpper()
  $sig      = Get-AuthenticodeSignature $exePath
  if ($sig.Status -ne "Valid") {
    throw "Exe signature invalid (status: $($sig.Status)) - possible tampering. Re-download from the source."
  }
  $actual = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint.ToUpper() } else { "" }
  if ($expected -ne $actual) {
    throw @"
Exe thumbprint mismatch - rejecting installation.
  Expected : $expected
  Actual   : $actual
The file may have been tampered with. Re-download from a trusted source.
"@
  }
  Write-Host "  Signature verified: thumbprint matches." -ForegroundColor Green
} else {
  if ($productionMode) {
    throw "thumbprint.txt not found. Production installer refuses to skip signature verification. Use -DevMode only for local development."
  }
  Write-Warning "  DEV MODE: thumbprint.txt not found - signature check not enforced."
}

# ---- 2. Write native-messaging manifest (no BOM) ----------------------------

$exeJson      = $exePath -replace '\\', '\\'
$manifestPath = Join-Path $installDir "$hostName.json"
$json = "{`n" +
        "  `"name`": `"$hostName`",`n" +
        "  `"description`": `"Zero-Trust Vault native host`",`n" +
        "  `"path`": `"$exeJson`",`n" +
        "  `"type`": `"stdio`",`n" +
        "  `"allowed_origins`": [ `"chrome-extension://$ExtensionId/`" ]`n" +
        "}`n"

[System.IO.File]::WriteAllText($manifestPath, $json, [System.Text.UTF8Encoding]::new($false))
Write-Host "  Manifest written (no BOM): $manifestPath"

# ---- 3. Register in HKLM via elevated sub-process ---------------------------

$regScript = @"
`$ErrorActionPreference = 'Stop'
`$hostName     = '$hostName'
`$manifestPath = '$($manifestPath -replace "'", "''")'
`$hklmPaths = @(
  "HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\`$hostName",
  "HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\`$hostName"
)
foreach (`$p in `$hklmPaths) {
  New-Item -Path `$p -Force | Out-Null
  Set-ItemProperty -Path `$p -Name '(default)' -Value `$manifestPath
}
Write-Host 'HKLM registration complete.'
"@

$elevated = $false
try {
  $tmp = Join-Path $env:TEMP "ztv_reg_$([System.IO.Path]::GetRandomFileName()).ps1"
  [System.IO.File]::WriteAllText($tmp, $regScript, [System.Text.UTF8Encoding]::new($false))
  $proc = Start-Process powershell.exe `
    -ArgumentList "-ExecutionPolicy Bypass -NonInteractive -File `"$tmp`"" `
    -Verb RunAs -Wait -PassThru -WindowStyle Hidden
  if ($proc.ExitCode -eq 0) {
    $elevated = $true
    Write-Host "  HKLM registration: OK" -ForegroundColor Green
  } else {
    Write-Warning "  Elevated process failed (exit $($proc.ExitCode)) - falling back to HKCU."
  }
} catch {
  Write-Warning "  UAC elevation declined - falling back to HKCU. ($_)"
} finally {
  if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

# ---- 4. HKCU fallback -------------------------------------------------------

$hkcuPaths = @("HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$hostName")
if (-not $elevated) {
  $hkcuPaths += "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$hostName"
}
foreach ($p in $hkcuPaths) {
  New-Item -Path $p -Force | Out-Null
  Set-ItemProperty -Path $p -Name "(default)" -Value $manifestPath
}
if (-not $elevated) {
  Write-Warning @"

  HKCU fallback used for Chrome. If the vault shows "native host not found":
    Re-run install.ps1 as Administrator, or run in an elevated PowerShell:
      New-Item 'HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\$hostName' -Force | Out-Null
      Set-ItemProperty 'HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\$hostName' '(default)' '$manifestPath'
"@
}

# ---- 5. Lock directories to current user + SYSTEM ---------------------------

$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
New-Item -ItemType Directory -Force -Path $vaultDir | Out-Null
foreach ($dir in @($vaultDir, $installDir)) {
  icacls $dir /inheritance:r /grant:r "${currentUser}:(OI)(CI)F" "SYSTEM:(OI)(CI)F" | Out-Null
}
Write-Host "  Directory permissions locked to current user."

# ---- 6. Post-install verification -------------------------------------------

Write-Host ""
Write-Host "Verifying installation..." -ForegroundColor Cyan
$ok = $true

if (Test-Path $exePath) {
  Write-Host "  [OK] Exe: $exePath" -ForegroundColor Green
} else {
  Write-Host "  [FAIL] Exe missing: $exePath" -ForegroundColor Red; $ok = $false
}

$manifestOk = $false
if (Test-Path $manifestPath) {
  try {
    $mf = Get-Content $manifestPath -Raw | ConvertFrom-Json
    $expectedOrigin = "chrome-extension://$ExtensionId/"
    $allowedOrigins = @($mf.allowed_origins)
    if ($mf.name -eq $hostName -and
        $mf.path -eq $exePath -and
        $allowedOrigins -contains $expectedOrigin) {
      $manifestOk = $true
    }
  } catch {}
}
if ($manifestOk) {
  Write-Host "  [OK] Manifest: $manifestPath" -ForegroundColor Green
} else {
  Write-Host "  [FAIL] Manifest missing or invalid: $manifestPath" -ForegroundColor Red; $ok = $false
}

$hklmKey = "HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\$hostName"
$hkcuKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$hostName"
if ((Test-Path $hklmKey) -or (Test-Path $hkcuKey)) {
  $scope = if (Test-Path $hklmKey) { "HKLM (system-wide)" } else { "HKCU (current user)" }
  Write-Host "  [OK] Registry: $scope" -ForegroundColor Green
} else {
  Write-Host "  [FAIL] Registry key not found" -ForegroundColor Red; $ok = $false
}

# ---- Done -------------------------------------------------------------------

Write-Host ""
if ($ok) {
  Write-Host "Installation complete." -ForegroundColor Green
} else {
  Write-Host "Installation finished with errors - see above." -ForegroundColor Red
  exit 1
}
Write-Host ""
Write-Host "  Extension ID : $ExtensionId"
Write-Host "  Exe          : $exePath"
Write-Host "  Manifest     : $manifestPath"
Write-Host "  Vault data   : $vaultDir"
Write-Host ""
Write-Host "Next: reload the extension at chrome://extensions, then click the vault icon." -ForegroundColor Cyan
Write-Host "      (Shortcut: navigate to chrome://extensions and press the reload button)"
