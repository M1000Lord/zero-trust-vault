<#
  Zero-Trust Vault - Version Truth Verification (Section Q)
  ===========================================================

  Every place a product version is claimed must agree, or docs/audit
  material silently drift out of sync with what actually shipped (exactly
  what happened here: README.md and IMPLEMENTATION_STATUS.md said v0.5.0
  while manifest.json / build-info.json / AUDIT_PACKAGE already said 2.0.0).

  Checks:
    * extension/manifest.json                              "version"
    * native-host .csproj build-info.json write targets     codeVersion literal
    * VaultManager.cs                                       CodeVersion constant
    * AUDIT_PACKAGE/AUDIT_STATUS.md                          "Code version: X"
    * AUDIT_PACKAGE/README_FOR_AUDITOR.md                    "v X.X.X"
    * README.md                                              title "v X.X.X"

  Exit 0 = all sources agree.  Exit 1 = at least one mismatch.

  Usage:
    powershell -ExecutionPolicy Bypass -File tools\verify-version-truth.ps1
#>
param(
  [string]$RepoRoot = (Join-Path $PSScriptRoot "..")
)
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=== ZTV Version Truth Verification ===" -ForegroundColor Cyan
Write-Host ""

$sources = New-Object System.Collections.Specialized.OrderedDictionary

function Get-FirstMatch($path, $pattern, $groupIndex = 1) {
  if (-not (Test-Path $path)) { return $null }
  $text = Get-Content $path -Raw
  $m = [regex]::Match($text, $pattern)
  if ($m.Success) { return $m.Groups[$groupIndex].Value }
  return $null
}

$manifestPath = Join-Path $RepoRoot "extension\manifest.json"
$sources["extension/manifest.json"] = Get-FirstMatch $manifestPath '"version"\s*:\s*"([^"]+)"'

$csprojPath = Join-Path $RepoRoot "native-host\src\ZeroTrustVaultHost\ZeroTrustVaultHost.csproj"
$csprojVersions = @()
if (Test-Path $csprojPath) {
  $text = Get-Content $csprojPath -Raw
  foreach ($m in [regex]::Matches($text, 'codeVersion&quot;:\s*&quot;([^&]+)&quot;')) {
    $csprojVersions += $m.Groups[1].Value
  }
}
$csprojVersions = @($csprojVersions | Select-Object -Unique)
$csprojKey = "ZeroTrustVaultHost.csproj (build-info targets)"
if ($csprojVersions.Count -eq 1) {
  $sources[$csprojKey] = [string]$csprojVersions[0]
} elseif ($csprojVersions.Count -eq 0) {
  $sources[$csprojKey] = $null
} else {
  $sources[$csprojKey] = "INCONSISTENT: " + ($csprojVersions -join ", ")
}

$vaultManagerPath = Join-Path $RepoRoot "native-host\src\ZeroTrustVaultHost\Vault\VaultManager.cs"
$sources["VaultManager.CodeVersion"] = Get-FirstMatch $vaultManagerPath 'CodeVersion\s*=\s*"([^"]+)"'

$auditStatusPath = Join-Path $RepoRoot "AUDIT_PACKAGE\AUDIT_STATUS.md"
$sources["AUDIT_PACKAGE/AUDIT_STATUS.md"] = Get-FirstMatch $auditStatusPath 'Code version:\s*([0-9][0-9.]*)'

$auditReadmePath = Join-Path $RepoRoot "AUDIT_PACKAGE\README_FOR_AUDITOR.md"
$sources["AUDIT_PACKAGE/README_FOR_AUDITOR.md"] = Get-FirstMatch $auditReadmePath '\bv(\d+\.\d+\.\d+)\b'

$readmePath = Join-Path $RepoRoot "README.md"
$sources["README.md (title)"] = Get-FirstMatch $readmePath '^#\s.*—\s*v(\d+\.\d+\.\d+)'

$foundVersions = @()
foreach ($key in $sources.Keys) {
  $val = $sources[$key]
  $display = if ($null -eq $val) { "(not found)" } else { $val }
  Write-Host ("  {0,-42} {1}" -f $key, $display) -ForegroundColor DarkGray
  if ($null -ne $val -and $val -notlike "INCONSISTENT:*") { $foundVersions += $val }
}

Write-Host ""

$distinct = @($foundVersions | Select-Object -Unique)
$findings = New-Object System.Collections.ArrayList

foreach ($key in $sources.Keys) {
  if ($sources[$key] -like "INCONSISTENT:*") {
    [void]$findings.Add("$key has internally inconsistent values: $($sources[$key])")
  }
}

if ($distinct.Count -gt 1) {
  [void]$findings.Add("Version sources disagree: $($distinct -join ', ')")
}

if ($findings.Count -gt 0) {
  Write-Host "VERSION TRUTH CHECK FAILED:" -ForegroundColor Red
  foreach ($f in $findings) { Write-Host "  FINDING: $f" -ForegroundColor Red }
  exit 1
}

Write-Host "VERSION TRUTH CHECK PASSED: all sources agree on v$($distinct[0])." -ForegroundColor Green
exit 0
