<#
  Zero-Trust Vault - local dev installer (convenience wrapper).

  Production install.ps1 (without -DevMode) intentionally refuses to run
  without a real release-manifest.json and a valid code-signing certificate
  thumbprint — that gate only a paid CA-issued certificate can satisfy, so for
  local development this wrapper always passes -DevMode for you.

  Usage:
    powershell -ExecutionPolicy Bypass -File install-dev.ps1
    powershell -ExecutionPolicy Bypass -File install-dev.ps1 -ExtensionId abcdefghijklmnopqrstuvwxyzabcdef
#>
param(
  [string]$ExtensionId   = "",
  [string]$Configuration = "Release"
)

$installScript = Join-Path $PSScriptRoot "install.ps1"
& powershell -ExecutionPolicy Bypass -File $installScript -ExtensionId $ExtensionId -Configuration $Configuration -DevMode
exit $LASTEXITCODE
