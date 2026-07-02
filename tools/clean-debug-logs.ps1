<#
  Zero-Trust Vault - debug log cleanup.

  Deletes the diagnostic log written by dev/debug builds (%TEMP%\ztv_diag.txt)
  and any rotated/old debug logs. Safe to run any time; no vault data is touched.

  Usage:
    powershell -ExecutionPolicy Bypass -File tools\clean-debug-logs.ps1
#>
param([switch]$Quiet)

$ErrorActionPreference = "Stop"

$targets = @(
  (Join-Path $env:TEMP "ztv_diag.txt")
)
# Also sweep any ztv_diag*.txt rotations in TEMP.
$rotations = Get-ChildItem -Path $env:TEMP -Filter "ztv_diag*.txt" -File -ErrorAction SilentlyContinue
foreach ($r in $rotations) { $targets += $r.FullName }

$targets = $targets | Sort-Object -Unique
$deleted = 0

foreach ($t in $targets) {
  if (Test-Path $t) {
    try {
      Remove-Item $t -Force
      $deleted++
      if (-not $Quiet) { Write-Host "  Deleted: $t" -ForegroundColor Green }
    } catch {
      Write-Warning "  Could not delete $t : $_"
    }
  }
}

if (-not $Quiet) {
  if ($deleted -eq 0) {
    Write-Host "No debug logs found. Nothing to clean." -ForegroundColor DarkGray
  } else {
    Write-Host "Removed $deleted debug log file(s)." -ForegroundColor Cyan
  }
}
exit 0
