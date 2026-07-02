<#
  Zero-Trust Vault - self-signed code signing. Free, no cert purchase needed.
  Run once after install, then re-run whenever you update the exe.

  Usage:
    powershell -ExecutionPolicy Bypass -File sign.ps1
    powershell -ExecutionPolicy Bypass -File sign.ps1 -VerifyOnly
#>
param([switch]$VerifyOnly)

$ErrorActionPreference = "Stop"
$thumbprintFile = Join-Path $PSScriptRoot "thumbprint.txt"
$installDir     = Join-Path $env:LOCALAPPDATA "ZeroTrustVault\host"
$ExePath        = Join-Path $installDir "ZeroTrustVaultHost.exe"

if (-not (Test-Path $ExePath)) {
  throw "Exe not found at: $ExePath`nRun install.ps1 first."
}

if ($VerifyOnly) {
  $sig = Get-AuthenticodeSignature $ExePath
  Write-Host "File   : $ExePath"
  Write-Host "Status : $($sig.Status)"
  if ($sig.SignerCertificate) {
    Write-Host "Thumb  : $($sig.SignerCertificate.Thumbprint)"
  }
  if ($sig.Status -eq "Valid") {
    Write-Host "Signature valid." -ForegroundColor Green
  } else {
    Write-Host "Signature INVALID or missing." -ForegroundColor Red
  }
  exit 0
}

# Find or create a self-signed code-signing cert
$certSubject = "CN=ZeroTrustVault-LocalSigner"
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {
  $_.Subject -eq $certSubject -and
  $_.NotAfter -gt (Get-Date)
} | Sort-Object NotAfter -Descending | Select-Object -First 1

if (-not $cert) {
  Write-Host "Creating self-signed code-signing certificate (one-time)..."
  $cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $certSubject `
    -FriendlyName "Zero-Trust Vault Local Signer" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -HashAlgorithm SHA256 `
    -KeyLength 4096 `
    -NotAfter (Get-Date).AddYears(10)
  Write-Host "Certificate created: $($cert.Thumbprint)" -ForegroundColor Green
} else {
  Write-Host "Reusing existing cert: $($cert.Thumbprint)"
}

$cert.Thumbprint | Out-File -Encoding ASCII $thumbprintFile -NoNewline
Write-Host "Thumbprint saved to: $thumbprintFile"

Write-Host "Signing: $ExePath"
$result = Set-AuthenticodeSignature -FilePath $ExePath -Certificate $cert -HashAlgorithm SHA256 -TimestampServer "http://timestamp.sectigo.com"

if ($result.Status -ne "Valid") {
  Write-Warning "Timestamping failed - signing without timestamp..."
  $result = Set-AuthenticodeSignature -FilePath $ExePath -Certificate $cert -HashAlgorithm SHA256
}

if ($result.Status -ne "Valid") {
  throw "Signing failed. Authenticode status: $($result.Status)."
}

Write-Host ""
Write-Host "Signed successfully." -ForegroundColor Green
Write-Host "  Thumbprint : $($cert.Thumbprint)"
Write-Host "  Expires    : $($cert.NotAfter.ToString('yyyy-MM-dd'))"
