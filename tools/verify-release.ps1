<#
  Zero-Trust Vault - Release Verifier.

  Run against a built/published native host directory (and optionally a release
  manifest) to confirm the artifact is safe to ship. FAILS the moment any of
  these is true:

    * the native host was built with diagnostic logging ENABLED
      (assembly metadata ZtvDiagLogging=enabled, i.e. a Debug build)
    * a release-manifest.json is present but an artifact hash does not match
    * production mode is active and the exe is not validly Authenticode-signed
    * forbidden strings are present in the binaries

  Usage:
    powershell -ExecutionPolicy Bypass -File tools\verify-release.ps1 -HostDir <dir>
    powershell -File tools\verify-release.ps1 -HostDir <dir> -DevMode
#>
param(
  [string]$HostDir = "",
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [switch]$RequireSignature,
  [switch]$DevMode
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=== Zero-Trust Vault - Release Verifier ===" -ForegroundColor Cyan
Write-Host ""
$productionMode = -not $DevMode
if ($productionMode) {
  Write-Host "Mode: production (manifest and valid signature required)" -ForegroundColor Cyan
} else {
  Write-Host "Mode: DEV (signature/manifest relaxation allowed; do not ship)" -ForegroundColor Yellow
}

# ---- Resolve host dir --------------------------------------------------------
if (-not $HostDir) {
  $candidates = @(
    (Join-Path $RepoRoot "native-host\publish\Release"),
    (Join-Path $RepoRoot "install\host"),
    (Join-Path $RepoRoot "native-host\src\ZeroTrustVaultHost\bin\Release")
  )
  $HostDir = $candidates | Where-Object { Test-Path (Join-Path $_ "ZeroTrustVaultHost.dll") } | Select-Object -First 1
}
if (-not $HostDir -or -not (Test-Path $HostDir)) {
  Write-Host "FAIL: host directory not found. Pass -HostDir <published release dir>." -ForegroundColor Red
  exit 1
}
Write-Host "Host dir: $HostDir"

$dll = Join-Path $HostDir "ZeroTrustVaultHost.dll"
$exe = Join-Path $HostDir "ZeroTrustVaultHost.exe"
$failures = New-Object System.Collections.ArrayList

# ---- Check 1: diagnostic logging disabled ------------------------------------
# The build writes a deterministic build-info.json next to the binary. A Debug
# build records diagnosticLogging=enabled; Release records disabled.
Write-Host ""
Write-Host "Check 1: diagnostic logging build flag..."
$buildInfoPath = Join-Path $HostDir "build-info.json"
if (-not (Test-Path $dll)) {
  [void]$failures.Add("ZeroTrustVaultHost.dll not found in host dir.")
  Write-Host "  FAIL: DLL missing." -ForegroundColor Red
} elseif (-not (Test-Path $buildInfoPath)) {
  [void]$failures.Add("build-info.json missing - cannot confirm diagnostic-logging is off. Rebuild with the current csproj.")
  Write-Host "  FAIL: build-info.json not found next to the binary." -ForegroundColor Red
} else {
  $info = Get-Content $buildInfoPath -Raw | ConvertFrom-Json
  if ($info.diagnosticLogging -eq "enabled") {
    [void]$failures.Add("Native host built with diagnostic logging ENABLED ($($info.configuration) build). Rebuild -c Release.")
    Write-Host "  FAIL: diagnosticLogging=enabled (configuration=$($info.configuration))." -ForegroundColor Red
  } elseif ($info.diagnosticLogging -eq "disabled") {
    Write-Host "  OK: diagnosticLogging=disabled (configuration=$($info.configuration))." -ForegroundColor Green
  } else {
    [void]$failures.Add("build-info.json has unexpected diagnosticLogging='$($info.diagnosticLogging)'.")
    Write-Host "  FAIL: unexpected diagnosticLogging value." -ForegroundColor Red
  }
}

# ---- Check 2: release manifest hashes ----------------------------------------
Write-Host ""
Write-Host "Check 2: release manifest hash verification..."
$manifestPath = Join-Path $HostDir "release-manifest.json"
if (Test-Path $manifestPath) {
  $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
  $extDir = Join-Path $RepoRoot "extension"
  $mismatches = 0
  foreach ($a in $manifest.artifacts) {
    $artifactPath = $null
    if ($a.path -like "host/*")      { $artifactPath = Join-Path $HostDir ($a.path -replace '^host/','') }
    elseif ($a.path -like "extension/*") { $artifactPath = Join-Path $extDir ($a.path -replace '^extension/','') }
    else { $artifactPath = Join-Path $HostDir $a.path }
    if ($artifactPath -and (Test-Path $artifactPath)) {
      $actual = (Get-FileHash $artifactPath -Algorithm SHA256).Hash.ToLower()
      if ($actual -ne $a.sha256.ToLower()) {
        Write-Host "  FAIL: hash mismatch for $($a.path)" -ForegroundColor Red
        $mismatches++
      }
    } else {
      $msg = "artifact listed in manifest not found locally: $($a.path)"
      if ($productionMode) { [void]$failures.Add($msg); Write-Host "  FAIL: $msg" -ForegroundColor Red }
      else { Write-Host "  WARN: $msg" -ForegroundColor Yellow }
    }
  }
  if ($mismatches -gt 0) {
    [void]$failures.Add("$mismatches manifest hash mismatch(es).")
  } else {
    Write-Host "  OK: all present artifact hashes match the manifest." -ForegroundColor Green
  }
} else {
  if ($productionMode) {
    [void]$failures.Add("release-manifest.json missing. Production releases must include a signed release manifest.")
    Write-Host "  FAIL: release-manifest.json missing." -ForegroundColor Red
  } else {
    Write-Host "  DEV WARN: no release-manifest.json present." -ForegroundColor Yellow
  }
}

# ---- Check 3: Authenticode signature -----------------------------------------
Write-Host ""
Write-Host "Check 3: Authenticode signature..."
if (Test-Path $exe) {
  $sig = Get-AuthenticodeSignature $exe
  if ($sig.Status -eq "Valid") {
    Write-Host "  OK: valid signature ($($sig.SignerCertificate.Thumbprint))." -ForegroundColor Green
  } elseif ($RequireSignature -or $productionMode) {
    [void]$failures.Add("Exe is not validly signed (status: $($sig.Status)).")
    Write-Host "  FAIL: signature status = $($sig.Status)." -ForegroundColor Red
  } else {
    Write-Host "  DEV WARN: signature status = $($sig.Status)." -ForegroundColor Yellow
  }
} else {
  [void]$failures.Add("ZeroTrustVaultHost.exe not found.")
  Write-Host "  FAIL: exe missing." -ForegroundColor Red
}

# ---- Check 4: forbidden strings ----------------------------------------------
Write-Host ""
Write-Host "Check 4: forbidden strings in binaries..."
& powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "check-forbidden-strings.ps1") -HostDir $HostDir -SkipSource | Out-Null
if ($LASTEXITCODE -ne 0) {
  [void]$failures.Add("Forbidden strings present in binaries.")
  Write-Host "  FAIL: forbidden strings found (see check-forbidden-strings.ps1)." -ForegroundColor Red
} else {
  Write-Host "  OK: no forbidden strings in binaries." -ForegroundColor Green
}

# ---- Summary -----------------------------------------------------------------
Write-Host ""
if ($failures.Count -gt 0) {
  Write-Host "RELEASE VERIFICATION FAILED ($($failures.Count)):" -ForegroundColor Red
  foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Red }
  exit 1
} else {
  Write-Host "RELEASE VERIFICATION PASSED." -ForegroundColor Green
  exit 0
}
