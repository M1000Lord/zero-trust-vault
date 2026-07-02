<#
  Zero-Trust Vault — Forbidden String Scanner

  Scans the extension source files and native host binaries for strings that
  must never appear in production releases. Run this before packaging a release.

  Exit 0 = clean (no forbidden strings found)
  Exit 1 = forbidden strings found — do NOT release

  Usage:
    powershell -File forbidden-string-scan.ps1
    powershell -File forbidden-string-scan.ps1 -ExtensionDir ..\..\extension -HostDir ..\installer\windows\host
#>
param(
  [string]$ExtensionDir = (Join-Path $PSScriptRoot "..\extension"),
  [string]$HostDir      = (Join-Path $PSScriptRoot "..\install\host"),
  [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Strings that MUST NOT appear in any release artifact
$forbiddenStrings = @(
  "DEV_BYPASS",
  "devBypass",
  "dev-bypass",
  "dev_bypass",
  "DPAPI_FALLBACK",
  "dpapi_fallback",
  "DpapiSilentFallback",
  "TEST_KEY",
  "testKey",
  "HARDCODED_SECRET",
  "skipHello",
  "skip_hello",
  "bypassBiometric",
  "bypass_biometric",
  "DEBUG_UNLOCK",
  "debug_unlock",
  "DISABLE_INTEGRITY",
  "disable_integrity",
  "ENV_BYPASS",
  "env_bypass"
)

Write-Host ""
Write-Host "=== Zero-Trust Vault — Forbidden String Scanner ===" -ForegroundColor Cyan
Write-Host ""

$totalViolations = 0
$scannedFiles    = 0

function Scan-TextFile {
  param([string]$FilePath)

  $violations = @()
  try {
    $content = [System.IO.File]::ReadAllText($FilePath)
    foreach ($str in $forbiddenStrings) {
      if ($content -cmatch [regex]::Escape($str)) {
        $violations += $str
      }
    }
  } catch {
    Write-Warning "Could not read: $FilePath — $_"
  }
  return $violations
}

function Scan-Binary {
  param([string]$FilePath)

  $violations = @()
  try {
    # Read as bytes and convert to ASCII to catch embedded strings
    $bytes   = [System.IO.File]::ReadAllBytes($FilePath)
    $content = [System.Text.Encoding]::ASCII.GetString($bytes)
    foreach ($str in $forbiddenStrings) {
      if ($content.Contains($str)) {
        $violations += $str
      }
    }
  } catch {
    Write-Warning "Could not scan binary: $FilePath — $_"
  }
  return $violations
}

# ---- Scan extension source files ---------------------------------------------

Write-Host "Scanning extension sources: $ExtensionDir"
$extFiles = @("service_worker.js", "popup.js", "content.js", "popup.html", "manifest.json")
foreach ($f in $extFiles) {
  $path = Join-Path $ExtensionDir $f
  if (-not (Test-Path $path)) {
    Write-Host "  [SKIP] Not found: $f" -ForegroundColor DarkGray
    continue
  }
  $violations = Scan-TextFile -FilePath $path
  $scannedFiles++
  if ($violations) {
    Write-Host "  [FAIL] $f" -ForegroundColor Red
    foreach ($v in $violations) { Write-Host "         Found: '$v'" -ForegroundColor Red }
    $totalViolations += $violations.Count
  } elseif ($Verbose) {
    Write-Host "  [OK]   $f" -ForegroundColor Green
  } else {
    Write-Host "  [OK]   $f" -ForegroundColor Green
  }
}

# ---- Scan native host binaries -----------------------------------------------

if (Test-Path $HostDir) {
  Write-Host ""
  Write-Host "Scanning native host binaries: $HostDir"
  $binFiles = Get-ChildItem $HostDir -Include "*.exe","*.dll" -ErrorAction SilentlyContinue
  foreach ($bin in $binFiles) {
    $violations = Scan-Binary -FilePath $bin.FullName
    $scannedFiles++
    if ($violations) {
      Write-Host "  [FAIL] $($bin.Name)" -ForegroundColor Red
      foreach ($v in $violations) { Write-Host "         Found: '$v'" -ForegroundColor Red }
      Write-Host "         Binary contains forbidden debug strings — rebuild in Release mode." -ForegroundColor Red
      $totalViolations += $violations.Count
    } else {
      Write-Host "  [OK]   $($bin.Name)" -ForegroundColor Green
    }
  }
  if (-not $binFiles) {
    Write-Host "  (No .exe/.dll files found in host directory.)" -ForegroundColor DarkGray
  }
} else {
  Write-Host ""
  Write-Host "  Host directory not found: $HostDir" -ForegroundColor Yellow
  Write-Host "  (Build the native host from source first: dotnet publish -c Release)" -ForegroundColor Yellow
}

# ---- Summary -----------------------------------------------------------------

Write-Host ""
Write-Host "Scanned: $scannedFiles file(s)."
Write-Host ""

if ($totalViolations -gt 0) {
  Write-Host "SCAN FAILED: $totalViolations forbidden string(s) found." -ForegroundColor Red
  Write-Host "  DO NOT RELEASE until all forbidden strings are removed." -ForegroundColor Red
  Write-Host "  For native host binaries: ensure you are building with 'Release' configuration," -ForegroundColor Red
  Write-Host "  not 'Debug'. The forbidden code paths must be gated with #if DEBUG." -ForegroundColor Red
  Write-Host ""
  exit 1
} else {
  Write-Host "SCAN PASSED: No forbidden strings found. Safe to release." -ForegroundColor Green
  Write-Host ""
  exit 0
}
