<#
  Rebuilds the native host in Release mode and records artifact hashes.
  This is a local reproducibility aid, not a substitute for third-party audit.
#>
param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$OutDir = (Join-Path $RepoRoot "dist")
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$project = Join-Path $RepoRoot "native-host\src\ZeroTrustVaultHost\ZeroTrustVaultHost.csproj"
$publish = Join-Path $RepoRoot "native-host\publish\Release"

dotnet publish $project -c Release -o $publish --no-self-contained -r win-x64
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed." }

$artifacts = @()
foreach ($file in Get-ChildItem $publish -File) {
  $artifacts += [pscustomobject]@{
    path = "native-host/publish/Release/$($file.Name)"
    length = $file.Length
    sha256 = (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLower()
  }
}

$report = [pscustomobject]@{
  product = "Zero-Trust Vault"
  generatedAtUtc = (Get-Date).ToUniversalTime().ToString("O")
  command = "dotnet publish native-host/src/ZeroTrustVaultHost/ZeroTrustVaultHost.csproj -c Release -o native-host/publish/Release --no-self-contained -r win-x64"
  artifacts = $artifacts
}

$path = Join-Path $OutDir "reproducible-build.json"
$report | ConvertTo-Json -Depth 5 | Out-File -Encoding UTF8 $path
Write-Host "Reproducible build report written: $path" -ForegroundColor Green
