<#
  Zero-Trust Vault - Extension CSP & Permission Audit
  ===================================================

  Static audit of manifest.json + extension sources for the supply-chain /
  least-privilege properties the security model promises:

    * a Content-Security-Policy is present for extension pages
    * no 'unsafe-eval' / 'unsafe-inline' / 'wasm-unsafe-eval'
    * no remote script-src (only 'self')
    * no broad host_permissions granted by default (optional-only is fine)
    * no remote-code patterns in JS (eval, new Function, remote import())
    * externally_connectable, if present, is not a wildcard

  Exit 0 = clean.  Exit 1 = at least one finding.

  Usage:
    powershell -ExecutionPolicy Bypass -File tools\audit-extension-csp.ps1
    powershell -File tools\audit-extension-csp.ps1 -ExtensionDir <dir>
#>
param(
  [string]$ExtensionDir = (Join-Path $PSScriptRoot "..\extension")
)
$ErrorActionPreference = "Stop"

$findings = New-Object System.Collections.ArrayList
function Add-Finding($msg) { [void]$findings.Add($msg); Write-Host "  FINDING: $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "=== ZTV Extension CSP & Permission Audit ===" -ForegroundColor Cyan
Write-Host ""

$manifestPath = Join-Path $ExtensionDir "manifest.json"
if (-not (Test-Path $manifestPath)) { Write-Host "manifest.json not found" -ForegroundColor Red; exit 1 }

$mf = Get-Content $manifestPath -Raw | ConvertFrom-Json

# ---- CSP ----
$csp = $null
if ($mf.content_security_policy) { $csp = $mf.content_security_policy.extension_pages }
if ([string]::IsNullOrWhiteSpace($csp)) {
  Add-Finding "No content_security_policy.extension_pages defined."
} else {
  Write-Host "  CSP: $csp" -ForegroundColor DarkGray
  if ($csp -match "unsafe-eval")        { Add-Finding "CSP allows 'unsafe-eval'." }
  if ($csp -match "unsafe-inline")      { Add-Finding "CSP allows 'unsafe-inline'." }
  if ($csp -match "wasm-unsafe-eval")   { Add-Finding "CSP allows 'wasm-unsafe-eval'." }
  if ($csp -notmatch "script-src\s+'self'") { Add-Finding "CSP script-src is not restricted to 'self'." }
  if ($csp -match "script-src[^;]*https?://") { Add-Finding "CSP script-src references a remote origin." }
  if ($csp -notmatch "object-src\s+'none'") { Add-Finding "CSP object-src is not 'none'." }
}

# ---- host_permissions (default-granted should be empty; optional is fine) ----
if ($mf.host_permissions -and $mf.host_permissions.Count -gt 0) {
  Add-Finding "host_permissions are granted by default: $($mf.host_permissions -join ', '). Prefer optional_host_permissions."
} else {
  Write-Host "  host_permissions: none granted by default (good)" -ForegroundColor DarkGray
}

# ---- optional_host_permissions must not expand beyond the reviewed baseline ----
$allowedOptionalHostPermissions = @("https://*/*")
if ($mf.optional_host_permissions) {
  $unexpected = @($mf.optional_host_permissions | Where-Object { $allowedOptionalHostPermissions -notcontains $_ })
  if ($unexpected.Count -gt 0) {
    Add-Finding "optional_host_permissions expanded beyond the reviewed baseline ($($allowedOptionalHostPermissions -join ', ')): $($unexpected -join ', ')"
  } else {
    Write-Host "  optional_host_permissions: matches reviewed baseline" -ForegroundColor DarkGray
  }
}

# ---- permissions[] must not silently grow beyond the reviewed, justified set ----
# Each of these is load-bearing for the current security model, not vestigial:
#   nativeMessaging - talk to the Windows native host at all
#   activeTab       - minimum-privilege access to the page the user is acting on
#   scripting       - inject content.js for DOM-safety-checked autofill
#   storage         - local, non-secret UI/security settings only (no credentials)
#   alarms          - MV3 service workers are non-persistent; session-timeout needs
#                     an alarm that survives worker suspension, setTimeout does not
#   tabs            - fill-binding re-validates the target tab hasn't navigated
#                     (chrome.tabs.get/query), which activeTab alone cannot do
#   windows         - refocus the correct window after a fill, and host the
#                     detached vault popup window
$allowedPermissions = @("nativeMessaging", "activeTab", "scripting", "storage", "alarms", "tabs", "windows")
if ($mf.permissions) {
  $unexpectedPerms = @($mf.permissions | Where-Object { $allowedPermissions -notcontains $_ })
  if ($unexpectedPerms.Count -gt 0) {
    Add-Finding "permissions[] contains entries beyond the reviewed, justified baseline: $($unexpectedPerms -join ', '). Any new permission needs an explicit security review and a comment in manifest.json (or this script) explaining why."
  } else {
    Write-Host "  permissions[]: matches reviewed, justified baseline ($($mf.permissions -join ', '))" -ForegroundColor DarkGray
  }
}

# ---- externally_connectable wildcard ----
if ($mf.externally_connectable -and $mf.externally_connectable.matches) {
  foreach ($m in $mf.externally_connectable.matches) {
    if ($m -eq "<all_urls>" -or $m -match "\*://\*/\*") { Add-Finding "externally_connectable allows a wildcard match: $m" }
  }
}

# ---- remote code patterns in JS ----
$jsFiles = Get-ChildItem $ExtensionDir -Filter *.js -File
foreach ($f in $jsFiles) {
  $text = [System.IO.File]::ReadAllText($f.FullName)
  # eval( and new Function( are remote-code execution vectors
  if ($text -match '(?<![A-Za-z0-9_])eval\s*\(')      { Add-Finding "$($f.Name): uses eval()." }
  if ($text -match 'new\s+Function\s*\(')              { Add-Finding "$($f.Name): uses new Function()." }
  # dynamic import of a remote URL
  if ($text -match 'import\s*\(\s*[`"'']https?://')    { Add-Finding "$($f.Name): dynamic import() of a remote URL." }
  # loading remote scripts
  if ($text -match 'importScripts\s*\(\s*[`"'']https?://') { Add-Finding "$($f.Name): importScripts() from a remote URL." }
}

Write-Host ""
if ($findings.Count -gt 0) {
  Write-Host "CSP/PERMISSION AUDIT FAILED: $($findings.Count) finding(s)." -ForegroundColor Red
  exit 1
}
Write-Host "CSP/PERMISSION AUDIT PASSED: strict CSP, least-privilege permissions, no remote code." -ForegroundColor Green
exit 0
