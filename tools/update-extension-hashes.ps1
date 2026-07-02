<#
  Zero-Trust Vault - Extension Integrity Hash Updater
  ===================================================

  Computes SHA-256 for every integrity-checked extension file and writes the
  resulting map into the INTEGRITY_HASHES object inside service_worker.js.

  This is the ONE canonical place that stamps extension hashes. Run it after
  ANY edit to a checked extension file, then reload the extension in Chrome.

  Checked files (everything that can influence behaviour or steal a secret):
      manifest.json, popup.html, popup.js, popup.css, content.js
  Excluded: service_worker.js itself (it embeds the map; it cannot hash itself).

  Guarantees:
    - Fails (exit 1) if any checked file is missing.
    - Prints a clear file -> hash summary.
    - Idempotent: running twice produces byte-identical service_worker.js.
    - Preserves the surrounding formatting (2-space indented JS object literal).

  Usage:
    powershell -ExecutionPolicy Bypass -File tools\update-extension-hashes.ps1
    powershell -ExecutionPolicy Bypass -File tools\update-extension-hashes.ps1 -Check   # dry-run, no write
    powershell -ExecutionPolicy Bypass -File tools\update-extension-hashes.ps1 -ExtensionDir <dir>

  Exit codes:
    0 = hashes written (or already current under -Check)
    1 = a checked file was missing, the SW anchor was not found, or (-Check) drift exists
#>
param(
  [string]$ExtensionDir = (Join-Path $PSScriptRoot "..\extension"),
  [switch]$Check
)

$ErrorActionPreference = "Stop"

# Single source of truth for what the runtime integrity check enforces.
$CHECKED_FILES = @("manifest.json", "popup.html", "popup.js", "popup.css", "content.js")

$swPath = Join-Path $ExtensionDir "service_worker.js"

Write-Host ""
Write-Host "=== ZTV Extension Hash Updater ===" -ForegroundColor Cyan
Write-Host "Extension dir: $ExtensionDir"
Write-Host ""

if (-not (Test-Path $swPath)) {
  Write-Host "ERROR: service_worker.js not found at $swPath" -ForegroundColor Red
  exit 1
}

# ---- Compute hashes (fail on any missing file) -------------------------------
$hashes  = [ordered]@{}
$missing = @()
foreach ($f in $CHECKED_FILES) {
  $path = Join-Path $ExtensionDir $f
  if (-not (Test-Path $path)) {
    $missing += $f
    Write-Host ("  {0,-16} MISSING" -f $f) -ForegroundColor Red
    continue
  }
  $h = (Get-FileHash $path -Algorithm SHA256).Hash.ToLower()
  $hashes[$f] = $h
  Write-Host ("  {0,-16} {1}" -f $f, $h)
}

if ($missing.Count -gt 0) {
  Write-Host ""
  Write-Host ("ERROR: {0} checked file(s) missing: {1}" -f $missing.Count, ($missing -join ", ")) -ForegroundColor Red
  Write-Host "Refusing to stamp a partial integrity map." -ForegroundColor Red
  exit 1
}

# ---- Build the replacement object literal (2-space indent, trailing comma) ----
$lines = foreach ($kv in $hashes.GetEnumerator()) {
  '  "' + $kv.Key + '": "' + $kv.Value + '",'
}
$jsObject    = "{`n" + ($lines -join "`n") + "`n}"
$replacement = "const INTEGRITY_HASHES = " + $jsObject + ";"

# ---- Locate the existing statement (pure string ops, no regex) ----------------
$content  = [System.IO.File]::ReadAllText($swPath)
$startTag = "const INTEGRITY_HASHES = "
$start    = $content.IndexOf($startTag)
if ($start -lt 0) {
  Write-Host "ERROR: 'const INTEGRITY_HASHES = ' anchor not found in service_worker.js" -ForegroundColor Red
  exit 1
}

$restFrom = $start + $startTag.Length
$nullEnd  = $content.IndexOf("null;", $restFrom)
$braceEnd = $content.IndexOf("};", $restFrom)
$stmtEnd  = -1
if ($nullEnd -ge 0 -and ($braceEnd -lt 0 -or $nullEnd -lt $braceEnd)) {
  $stmtEnd = $nullEnd + 5
} elseif ($braceEnd -ge 0) {
  $stmtEnd = $braceEnd + 2
} else {
  Write-Host "ERROR: could not locate end of INTEGRITY_HASHES statement" -ForegroundColor Red
  exit 1
}

$newContent = $content.Substring(0, $start) + $replacement + $content.Substring($stmtEnd)

# ---- Write or dry-run ---------------------------------------------------------
Write-Host ""
if ($newContent -eq $content) {
  Write-Host "service_worker.js already current - no change needed (idempotent)." -ForegroundColor Green
  exit 0
}

if ($Check) {
  Write-Host "DRIFT: service_worker.js hashes are STALE (-Check, not written)." -ForegroundColor Yellow
  Write-Host "Run without -Check to update, then reload the extension." -ForegroundColor Yellow
  exit 1
}

[System.IO.File]::WriteAllText($swPath, $newContent, [System.Text.UTF8Encoding]::new($false))
Write-Host ("service_worker.js stamped with {0} hashes." -f $CHECKED_FILES.Count) -ForegroundColor Green
Write-Host "Next: reload the extension in Chrome (chrome://extensions -> reload)," -ForegroundColor Cyan
Write-Host "      then run tools\verify-extension-integrity.ps1 to confirm." -ForegroundColor Cyan
exit 0
