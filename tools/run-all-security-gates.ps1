<#
  Zero-Trust Vault - Run All Security Gates (Section J)
  ========================================================

  Single local, CI-style entry point running every automated security gate in
  one shot. Exits non-zero if ANY gate fails, so it can be used as a release
  go/no-go check without hunting through a dozen separate scripts.

  Gates run, in order:
    1. dotnet test              - full native-host test suite
    2. node --check             - syntax-validate every extension JS file
    3. audit-extension-csp.ps1  - manifest permissions/CSP least-privilege
    4. check-forbidden-strings.ps1 - no debug/dev-bypass/placeholder strings
    5. verify-extension-integrity.ps1 - packaged extension hash consistency
    6. dependency-scan.ps1      - known-vulnerable NuGet dependency check
    7. verify-version-truth.ps1 - one canonical version across every source

  Usage:
    powershell -ExecutionPolicy Bypass -File tools\run-all-security-gates.ps1
#>
param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)
$ErrorActionPreference = "Continue"

$results = New-Object System.Collections.Specialized.OrderedDictionary

function Run-Gate($name, [scriptblock]$action) {
  Write-Host ""
  Write-Host "############################################################" -ForegroundColor Cyan
  Write-Host "# GATE: $name" -ForegroundColor Cyan
  Write-Host "############################################################" -ForegroundColor Cyan
  try {
    & $action
    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) { $exitCode = 0 } # scriptblocks that don't invoke an external exe
    $results[$name] = $exitCode
  } catch {
    Write-Host "GATE THREW: $($_.Exception.Message)" -ForegroundColor Red
    $results[$name] = 1
  }
}

Run-Gate "dotnet test (native host)" {
  Push-Location (Join-Path $RepoRoot "native-host\src")
  try { dotnet test } finally { Pop-Location }
}

Run-Gate "node --check (extension JS)" {
  Push-Location (Join-Path $RepoRoot "extension")
  try {
    $failed = $false
    Get-ChildItem -Filter *.js -File | ForEach-Object {
      node --check $_.Name
      if ($LASTEXITCODE -ne 0) { $failed = $true }
    }
    if ($failed) { $global:LASTEXITCODE = 1 } else { $global:LASTEXITCODE = 0 }
  } finally { Pop-Location }
}

Run-Gate "audit-extension-csp.ps1" {
  powershell -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "tools\audit-extension-csp.ps1")
}

Run-Gate "check-forbidden-strings.ps1" {
  powershell -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "tools\check-forbidden-strings.ps1")
}

Run-Gate "verify-extension-integrity.ps1" {
  powershell -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "tools\verify-extension-integrity.ps1")
}

Run-Gate "dependency-scan.ps1" {
  powershell -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "tools\dependency-scan.ps1")
}

Run-Gate "verify-version-truth.ps1" {
  powershell -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "tools\verify-version-truth.ps1")
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "SECURITY GATE SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$anyFailed = $false
foreach ($name in $results.Keys) {
  $code = $results[$name]
  if ($code -eq 0) {
    Write-Host ("  PASS  {0}" -f $name) -ForegroundColor Green
  } else {
    Write-Host ("  FAIL  {0}  (exit {1})" -f $name, $code) -ForegroundColor Red
    $anyFailed = $true
  }
}

Write-Host ""
if ($anyFailed) {
  Write-Host "OVERALL: FAILED - one or more gates did not pass." -ForegroundColor Red
  exit 1
}
Write-Host "OVERALL: ALL GATES PASSED." -ForegroundColor Green
exit 0
