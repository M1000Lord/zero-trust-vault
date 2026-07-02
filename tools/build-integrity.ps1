<#
  Zero-Trust Vault - file integrity manifest builder.

  Computes SHA-256 of all extension files except service_worker.js (which
  embeds the hashes), then patches INTEGRITY_HASHES directly into it.

  Run after every change to any extension file:
    powershell -ExecutionPolicy Bypass -File tools\build-integrity.ps1

  Then reload the extension in Chrome (chrome://extensions -> reload).
#>
param([switch]$Verify)

$ErrorActionPreference = "Stop"
$extDir = Join-Path $PSScriptRoot "..\extension"
$swPath = Join-Path $extDir "service_worker.js"

$targets = @("manifest.json","popup.html","popup.js","popup.css","content.js")

Write-Host "Computing SHA-256 hashes..."
$hashes = [ordered]@{}
foreach ($f in $targets) {
  $path = Join-Path $extDir $f
  if (-not (Test-Path $path)) { throw "File not found: $f" }
  $hashes[$f] = (Get-FileHash $path -Algorithm SHA256).Hash.ToLower()
  Write-Host ("  {0,-20} {1}" -f $f, $hashes[$f])
}

if ($Verify) {
  Write-Host "`nVerifying embedded hashes in service_worker.js..."
  $sw    = [System.IO.File]::ReadAllText($swPath)
  $allOk = $true
  foreach ($f in $targets) {
    $needle = '"' + $f + '": "'
    $idx    = $sw.IndexOf($needle)
    if ($idx -lt 0) {
      Write-Host "  NOT FOUND: $f" -ForegroundColor Yellow
      $allOk = $false
      continue
    }
    $embedded = $sw.Substring($idx + $needle.Length, 64)
    $actual   = $hashes[$f]
    if ($embedded -eq $actual) {
      Write-Host "  OK  $f"
    } else {
      Write-Host "  MISMATCH  $f" -ForegroundColor Red
      $allOk = $false
    }
  }
  if ($allOk) {
    Write-Host "`nAll hashes match." -ForegroundColor Green
  } else {
    Write-Host "`nMismatch - re-run without -Verify to update hashes." -ForegroundColor Red
    exit 1
  }
  exit 0
}

# Build the JS object literal using string concatenation only
$lines = foreach ($kv in $hashes.GetEnumerator()) {
  '  "' + $kv.Key + '": "' + $kv.Value + '",'
}
$jsObject = "{`n" + ($lines -join "`n") + "`n}"
$replacement = "const INTEGRITY_HASHES = " + $jsObject + ";"

# Patch service_worker.js using pure string operations (no regex)
$content = [System.IO.File]::ReadAllText($swPath)
$startTag = "const INTEGRITY_HASHES = "
$start = $content.IndexOf($startTag)
if ($start -lt 0) { throw "Could not find 'const INTEGRITY_HASHES' in service_worker.js" }

# Find the end of the statement: either "null;" or "};"
$restFrom  = $start + $startTag.Length
$nullEnd   = $content.IndexOf("null;", $restFrom)
$braceEnd  = $content.IndexOf("};", $restFrom)

$stmtEnd = -1
if ($nullEnd -ge 0 -and ($braceEnd -lt 0 -or $nullEnd -lt $braceEnd)) {
  $stmtEnd = $nullEnd + 5   # "null;" length = 5
} elseif ($braceEnd -ge 0) {
  $stmtEnd = $braceEnd + 2  # "};" length = 2
} else {
  throw "Could not locate end of INTEGRITY_HASHES statement"
}

$newContent = $content.Substring(0, $start) + $replacement + $content.Substring($stmtEnd)
[System.IO.File]::WriteAllText($swPath, $newContent, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "service_worker.js patched with $($targets.Count) hashes." -ForegroundColor Green
Write-Host "Reload extension in Chrome, then verify with:  powershell -File build-integrity.ps1 -Verify"
