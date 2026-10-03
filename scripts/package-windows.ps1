[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Binary,
    [Parameter(Mandatory)][string]$Output,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$Sbom,
    [Parameter(Mandatory)][string]$Dependencies,
    [Parameter(Mandatory)][string]$Licenses
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$target = 'x86_64-pc-windows-msvc'
$binary = (Resolve-Path -LiteralPath $Binary).Path
$reported = & $binary version
$expectedVersion = [regex]::Escape("daguard $Version ($target)")
if ($LASTEXITCODE -ne 0 -or $reported -notmatch $expectedVersion) {
    throw 'Binary version or target does not match the requested bundle.'
}
$bundleName = "daguard-$Version-$target"
$bundle = Join-Path $Output $bundleName
if (Test-Path -LiteralPath $bundle) {
    throw "Output bundle already exists: $bundle"
}

$directories = @(
    'config\codex', 'config\cursor', 'config\opencode', 'docs\operations',
    'integrations\opencode', 'inventory'
)
foreach ($directory in $directories) {
    New-Item -ItemType Directory -Path (Join-Path $bundle $directory) -Force | Out-Null
}
Copy-Item -LiteralPath $binary -Destination (Join-Path $bundle 'daguard.exe')
Copy-Item policy/default-policy.json (Join-Path $bundle 'default-policy.json')
Copy-Item scripts/install.ps1 (Join-Path $bundle 'install.ps1')
Copy-Item scripts/uninstall.ps1 (Join-Path $bundle 'uninstall.ps1')
Copy-Item config/codex/hooks.json (Join-Path $bundle 'config\codex\hooks.json')
Copy-Item config/cursor/hooks.json (Join-Path $bundle 'config\cursor\hooks.json')
Copy-Item config/opencode/opencode.json (Join-Path $bundle 'config\opencode\opencode.json')
Copy-Item docs/operations/windows.md (Join-Path $bundle 'docs\operations\windows.md')
Copy-Item integrations/opencode/index.js (Join-Path $bundle 'integrations\opencode\index.js')
Copy-Item integrations/opencode/package.json (Join-Path $bundle 'integrations\opencode\package.json')
Copy-Item $Sbom (Join-Path $bundle 'inventory\sbom.cdx.json')
Copy-Item $Dependencies (Join-Path $bundle 'inventory\dependencies.json')
Copy-Item $Licenses (Join-Path $bundle 'inventory\licenses.json')
Copy-Item LICENSE (Join-Path $bundle 'LICENSE')
@{ schema = 1; version = $Version; target = $target } |
    ConvertTo-Json -Compress |
    Set-Content -LiteralPath (Join-Path $bundle 'release.json') -Encoding utf8NoBOM

$manifest = foreach ($file in Get-ChildItem -LiteralPath $bundle -File -Recurse | Sort-Object FullName) {
    $relative = [IO.Path]::GetRelativePath($bundle, $file.FullName).Replace('\', '/')
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $relative"
}
$manifest | Set-Content -LiteralPath (Join-Path $bundle 'SHA256SUMS') -Encoding ascii
$archive = Join-Path $Output "$bundleName.zip"
Compress-Archive -LiteralPath $bundle -DestinationPath $archive -CompressionLevel Optimal
Get-FileHash -LiteralPath $archive -Algorithm SHA256 |
    ForEach-Object { "$($_.Hash.ToLowerInvariant())  $([IO.Path]::GetFileName($archive))" } |
    Set-Content -LiteralPath (Join-Path $Output 'SHA256SUMS.windows') -Encoding ascii
