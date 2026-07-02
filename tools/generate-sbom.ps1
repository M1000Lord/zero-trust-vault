<#
  Generates a local SBOM for Zero-Trust Vault.
  Output:
    - SBOM.json: machine-readable dependency inventory
    - DEPENDENCIES.md: human-readable summary
#>
param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$OutDir = (Join-Path $RepoRoot "dist")
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$items = New-Object System.Collections.ArrayList

function Add-Item {
  param([string]$Type, [string]$Name, [string]$Version, [string]$Path, [string]$Sha256)
  [void]$items.Add([pscustomobject]@{
    type = $Type; name = $Name; version = $Version; path = $Path; sha256 = $Sha256
  })
}

$csproj = Join-Path $RepoRoot "native-host\src\ZeroTrustVaultHost\ZeroTrustVaultHost.csproj"
if (Test-Path $csproj) {
  [xml]$xml = Get-Content $csproj
  foreach ($pkg in $xml.Project.ItemGroup.PackageReference) {
    if ($pkg.Include) {
      Add-Item "dotnet-package" $pkg.Include $pkg.Version "" ""
    }
  }
}

$extDir = Join-Path $RepoRoot "extension"
if (Test-Path $extDir) {
  foreach ($file in Get-ChildItem $extDir -File) {
    Add-Item "extension-file" $file.Name "" ("extension/" + $file.Name) `
      (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLower()
  }
}

$hostDir = Join-Path $RepoRoot "native-host\publish\Release"
if (Test-Path $hostDir) {
  foreach ($file in Get-ChildItem $hostDir -File -Include *.exe,*.dll,*.json) {
    Add-Item "native-artifact" $file.Name "" ("native-host/publish/Release/" + $file.Name) `
      (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLower()
  }
}

$sbom = [pscustomobject]@{
  product = "Zero-Trust Vault"
  generatedAtUtc = (Get-Date).ToUniversalTime().ToString("O")
  components = $items
}

$sbomPath = Join-Path $OutDir "SBOM.json"
$depsPath = Join-Path $OutDir "DEPENDENCIES.md"
$sbom | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 $sbomPath

$lines = @(
  "# Dependencies",
  "",
  "Generated: $($sbom.generatedAtUtc)",
  "",
  "| Type | Name | Version | Path | SHA-256 |",
  "| --- | --- | --- | --- | --- |"
)
foreach ($i in $items) {
  $lines += "| $($i.type) | $($i.name) | $($i.version) | $($i.path) | $($i.sha256) |"
}
$lines | Out-File -Encoding UTF8 $depsPath

Write-Host "SBOM written: $sbomPath" -ForegroundColor Green
Write-Host "Dependency summary written: $depsPath" -ForegroundColor Green
