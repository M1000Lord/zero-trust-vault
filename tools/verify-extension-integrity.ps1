<#
  Zero-Trust Vault - Extension Integrity Verifier
  ===============================================

  Reads the INTEGRITY_HASHES map that service_worker.js will actually enforce at
  runtime, recomputes the SHA-256 of each file on disk, and compares them. This
  is the same comparison Chrome performs on startup - run it before loading or
  shipping so drift is caught on the command line, not as a red "!!" badge.

  For every mismatch it prints the file name, the EXPECTED hash (embedded in the
  service worker) and the ACTUAL hash (current file on disk). Missing files and
  files present on disk but absent from the map are reported too.

  Usage:
    powershell -ExecutionPolicy Bypass -File tools\verify-extension-integrity.ps1
    powershell -ExecutionPolicy Bypass -File tools\verify-extension-integrity.ps1 -ExtensionDir <dir>

  Exit codes:
    0 = every enforced hash matches the file on disk
    1 = at least one mismatch / missing file / unparseable map
#>
param(
  [string]$ExtensionDir = (Join-Path $PSScriptRoot "..\extension")
)

$ErrorActionPreference = "Stop"

$swPath = Join-Path $ExtensionDir "service_worker.js"

Write-Host ""
Write-Host "=== ZTV Extension Integrity Verifier ===" -ForegroundColor Cyan
Write-Host "Extension dir: $ExtensionDir"
Write-Host ""

if (-not (Test-Path $swPath)) {
  Write-Host "FAIL: service_worker.js not found at $swPath" -ForegroundColor Red
  exit 1
}

# ---- Parse the enforced map straight out of service_worker.js -----------------
# We read what the SW will actually check, not a hard-coded list, so the verifier
# can never silently disagree with runtime enforcement.
$sw       = [System.IO.File]::ReadAllText($swPath)
$startTag = "const INTEGRITY_HASHES = "
$start    = $sw.IndexOf($startTag)
if ($start -lt 0) {
  Write-Host "FAIL: INTEGRITY_HASHES anchor not found in service_worker.js" -ForegroundColor Red
  exit 1
}
$open  = $sw.IndexOf("{", $start)
$close = $sw.IndexOf("}", $start)
if ($sw.Substring($start + $startTag.Length).TrimStart().StartsWith("null")) {
  Write-Host "FAIL: INTEGRITY_HASHES is null - hashes have never been stamped." -ForegroundColor Red
  Write-Host "Run tools\update-extension-hashes.ps1 first." -ForegroundColor Yellow
  exit 1
}
if ($open -lt 0 -or $close -lt 0 -or $close -le $open) {
  Write-Host "FAIL: could not parse INTEGRITY_HASHES object literal." -ForegroundColor Red
  exit 1
}
$body = $sw.Substring($open + 1, $close - $open - 1)

$expected = [ordered]@{}
foreach ($line in ($body -split "`n")) {
  $m = [regex]::Match($line, '"(?<f>[^"]+)"\s*:\s*"(?<h>[0-9a-fA-F]{64})"')
  if ($m.Success) { $expected[$m.Groups['f'].Value] = $m.Groups['h'].Value.ToLower() }
}

if ($expected.Count -eq 0) {
  Write-Host "FAIL: INTEGRITY_HASHES parsed but contained no entries." -ForegroundColor Red
  exit 1
}

Write-Host ("Enforced map: {0} file(s)" -f $expected.Count)
Write-Host ""

# ---- Compare each enforced entry against the file on disk ---------------------
$failures = @()
foreach ($f in $expected.Keys) {
  $path = Join-Path $ExtensionDir $f
  if (-not (Test-Path $path)) {
    Write-Host ("  {0,-16} MISSING ON DISK" -f $f) -ForegroundColor Red
    $failures += [pscustomobject]@{ file = $f; expected = $expected[$f]; actual = "(missing)" }
    continue
  }
  $actual = (Get-FileHash $path -Algorithm SHA256).Hash.ToLower()
  if ($actual -eq $expected[$f]) {
    Write-Host ("  {0,-16} OK" -f $f) -ForegroundColor Green
  } else {
    Write-Host ("  {0,-16} MISMATCH" -f $f) -ForegroundColor Red
    Write-Host ("       expected: {0}" -f $expected[$f]) -ForegroundColor DarkGray
    Write-Host ("       actual:   {0}" -f $actual) -ForegroundColor Yellow
    $failures += [pscustomobject]@{ file = $f; expected = $expected[$f]; actual = $actual }
  }
}

# ---- Warn about checked-looking files that are not in the map -----------------
$onDisk = @("manifest.json","popup.html","popup.js","popup.css","content.js")
foreach ($f in $onDisk) {
  if (-not $expected.Contains($f) -and (Test-Path (Join-Path $ExtensionDir $f))) {
    Write-Host ("  {0,-16} ON DISK BUT NOT ENFORCED" -f $f) -ForegroundColor Yellow
  }
}

Write-Host ""
if ($failures.Count -gt 0) {
  Write-Host ("INTEGRITY VERIFY FAILED: {0} file(s) differ." -f $failures.Count) -ForegroundColor Red
  Write-Host "If these edits are legitimate, run tools\update-extension-hashes.ps1 then reload." -ForegroundColor Yellow
  exit 1
}

Write-Host "INTEGRITY VERIFY PASSED: all enforced hashes match." -ForegroundColor Green
exit 0
