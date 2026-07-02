<#
  Zero-Trust Vault - Dependency Vulnerability Scan
  ================================================

  Runs `dotnet list package --vulnerable --include-transitive` against the native
  host project and FAILS (exit 1) if any vulnerable package is reported. This is
  the CI supply-chain gate the security spec requires ("CI fails on critical
  issues").

  Usage:
    powershell -ExecutionPolicy Bypass -File tools\dependency-scan.ps1
    powershell -File tools\dependency-scan.ps1 -FailOnAny      # fail on any severity (default)
    powershell -File tools\dependency-scan.ps1 -MinimumSeverity High

  Exit 0 = no vulnerable packages at/above the threshold.
  Exit 1 = vulnerable package(s) found, or the scan could not run.
#>
param(
  [string]$ProjectPath = (Join-Path $PSScriptRoot "..\native-host\src\ZeroTrustVaultHost\ZeroTrustVaultHost.csproj"),
  [ValidateSet("Low","Moderate","High","Critical")]
  [string]$MinimumSeverity = "Low"
)
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=== ZTV Dependency Vulnerability Scan ===" -ForegroundColor Cyan
Write-Host "Project: $ProjectPath"
Write-Host "Minimum severity to fail: $MinimumSeverity"
Write-Host ""

# Ensure restore so the vulnerability database is consulted against resolved deps.
& dotnet restore $ProjectPath | Out-Null

$raw = & dotnet list $ProjectPath package --vulnerable --include-transitive 2>&1 | Out-String
Write-Host $raw

if ($raw -match "error|Error retrieving") {
  Write-Host "Vulnerability scan could not complete (network or NuGet error)." -ForegroundColor Red
  exit 1
}

# Rank severities.
$rank = @{ "Low" = 1; "Moderate" = 2; "High" = 3; "Critical" = 4 }
$threshold = $rank[$MinimumSeverity]

# Parse lines like: "   > PackageId   1.2.3   1.2.3   High   https://github.com/advisories/..."
$hits = New-Object System.Collections.ArrayList
foreach ($line in ($raw -split "`r?`n")) {
  $m = [regex]::Match($line, '^\s*>\s*(?<id>[A-Za-z0-9_.]+)\s+\S+\s+\S+\s+(?<sev>Low|Moderate|High|Critical)\b')
  if ($m.Success) {
    $sev = $m.Groups['sev'].Value
    if ($rank[$sev] -ge $threshold) {
      [void]$hits.Add("$($m.Groups['id'].Value) [$sev]")
    }
  }
}

Write-Host ""
if ($raw -match "no vulnerable packages") {
  Write-Host "PASSED: no vulnerable packages reported." -ForegroundColor Green
  exit 0
}

if ($hits.Count -gt 0) {
  Write-Host "DEPENDENCY SCAN FAILED: vulnerable package(s) at/above $MinimumSeverity :" -ForegroundColor Red
  $hits | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
  exit 1
}

Write-Host "PASSED: no vulnerable packages at/above $MinimumSeverity." -ForegroundColor Green
exit 0
