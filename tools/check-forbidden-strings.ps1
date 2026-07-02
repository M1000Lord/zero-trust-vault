<#
  Zero-Trust Vault - Forbidden String Checker (comprehensive).

  Supersedes forbidden-string-scan.ps1 with an expanded list that also flags
  placeholder / scaffolded code so the audit picture stays honest.

  Scans:
    * extension source files (the 5 packaged files)
    * native host C# SOURCE (.cs, excluding obj/bin/Tests/tools)
    * native host RELEASE binaries (if a host dir is given/found)

  The tools/ directory and this script are excluded (they contain the search
  terms as data).

  Exit 0 = clean.  Exit 1 = at least one forbidden string found.

  Usage:
    powershell -ExecutionPolicy Bypass -File tools\check-forbidden-strings.ps1
    powershell -File tools\check-forbidden-strings.ps1 -HostDir <release host dir> -IncludeSource
#>
param(
  [string]$RepoRoot   = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$ExtensionDir = "",
  [string]$HostDir    = "",
  [switch]$SkipSource
)
$IncludeSource = -not $SkipSource

$ErrorActionPreference = "Stop"

if (-not $ExtensionDir) { $ExtensionDir = Join-Path $RepoRoot "extension" }

# Hard security bypasses (must never appear anywhere in a release).
$bypassStrings = @(
  "DEV_BYPASS", "devBypass", "dev-bypass", "dev_bypass",
  "debugUnlock", "DEBUG_UNLOCK", "debug_unlock",
  "skipHello", "skip_hello", "bypassBiometric", "bypass_biometric", "biometric bypass",
  "ALLOW_DPAPI_FALLBACK", "DPAPI_FALLBACK", "DpapiSilentFallback",
  "ZTV_DEV", "TEST_KEY", "testKey", "test root key", "HARDCODED_SECRET",
  "DISABLE_INTEGRITY", "disable_integrity", "ENV_BYPASS"
)

# Placeholder / not-production markers (flag scaffolded code honestly).
# NOTE: the bare word "placeholder" is intentionally NOT here — HTML/JS use
# legitimate `placeholder=` input attributes. We match unambiguous stub markers.
$placeholderStrings = @(
  "PLACEHOLDER_IMPL", "TODO SECURITY", "TODO: SECURITY", "STUB:",
  "Would be set during key exchange",
  "not implemented yet",
  "signature verification skipped",
  "UnknownError accepted",
  # Device-pairing stubs: the object-initializer form (trailing comma) marks an
  # unfinished key exchange where no real key material is ever wrapped/stored.
  # The statement form (e.g. `d.WrappedEpochKey = string.Empty;`) is legitimate
  # revocation/clearing and intentionally NOT matched here. The accompanying stub
  # comment "Would be set during key exchange" (above) is also caught independently.
  "WrappedEpochKey = string.Empty,",
  "PublicKeyBlob = string.Empty,"
)

Write-Host ""
Write-Host "=== Zero-Trust Vault - Forbidden String Checker ===" -ForegroundColor Cyan
Write-Host ""

$violations = New-Object System.Collections.ArrayList
$scanned = 0

function Test-Content {
  param([string]$Path, [string]$Text, [string]$Label, [string[]]$Terms)
  foreach ($term in $Terms) {
    if ($Text -match [regex]::Escape($term)) {
      [void]$violations.Add([pscustomobject]@{ File = $Label; Term = $term })
    }
  }
}

# ---- 1. Extension source (bypass strings only; HTML uses legit placeholder=) ----
$extFiles = @("service_worker.js","popup.js","content.js","popup.html","manifest.json")
foreach ($f in $extFiles) {
  $p = Join-Path $ExtensionDir $f
  if (Test-Path $p) {
    $scanned++
    Test-Content -Path $p -Text ([System.IO.File]::ReadAllText($p)) -Label "extension/$f" -Terms $bypassStrings
  }
}

# ---- 2. Native host C# source (bypass + placeholder/stub markers) ----
if ($IncludeSource) {
  $srcRoot = Join-Path $RepoRoot "native-host\src\ZeroTrustVaultHost"
  if (Test-Path $srcRoot) {
    $csFiles = Get-ChildItem $srcRoot -Recurse -Filter *.cs -File |
      Where-Object { $_.FullName -notmatch '\\(obj|bin)\\' }
    foreach ($cs in $csFiles) {
      $scanned++
      Test-Content -Path $cs.FullName -Text ([System.IO.File]::ReadAllText($cs.FullName)) `
        -Label ("src/" + $cs.Name) -Terms ($bypassStrings + $placeholderStrings)
    }
  }
}

# ---- 3. Native host release binaries ----
$hostCandidates = @()
if ($HostDir) { $hostCandidates += $HostDir }
$hostCandidates += (Join-Path $RepoRoot "install\host")
$hostCandidates += (Join-Path $RepoRoot "native-host\src\ZeroTrustVaultHost\bin\Release")
$resolvedHost = $hostCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($resolvedHost) {
  $bins = Get-ChildItem $resolvedHost -Recurse -Include *.exe,*.dll -File -ErrorAction SilentlyContinue |
          Where-Object { $_.Name -like "ZeroTrustVaultHost*" }
  foreach ($bin in $bins) {
    $scanned++
    $bytes = [System.IO.File]::ReadAllBytes($bin.FullName)
    $text  = [System.Text.Encoding]::ASCII.GetString($bytes)
    # Binaries: only the hard bypass strings matter (placeholders are comments, not compiled).
    Test-Content -Path $bin.FullName -Text $text -Label ("bin/" + $bin.Name) -Terms $bypassStrings
  }
} else {
  Write-Host "  (No release host binaries found - skipping binary scan.)" -ForegroundColor DarkGray
}

# ---- Report ----
Write-Host ""
Write-Host "Scanned $scanned file(s)."
Write-Host ""

if ($violations.Count -gt 0) {
  Write-Host "FORBIDDEN STRINGS FOUND ($($violations.Count)):" -ForegroundColor Red
  foreach ($v in $violations) {
    Write-Host ("  [{0}]  {1}" -f $v.Term, $v.File) -ForegroundColor Red
  }
  Write-Host ""
  Write-Host "DO NOT RELEASE until these are removed or the code is finished." -ForegroundColor Red
  exit 1
} else {
  Write-Host "PASSED: no forbidden strings found." -ForegroundColor Green
  exit 0
}
