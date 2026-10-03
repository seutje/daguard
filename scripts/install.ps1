[CmdletBinding()]
param(
    [ValidateSet('CurrentUser', 'Machine')]
    [string]$Scope = 'CurrentUser',
    [string]$Bundle = $PSScriptRoot,
    [switch]$ReplacePolicy,
    [string]$DestinationRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'A machine installation must run from an elevated PowerShell session.'
    }
}

function Get-Layout {
    if ($DestinationRoot) {
        return @{
            Bin = Join-Path $DestinationRoot 'bin'
            Config = Join-Path $DestinationRoot 'config'
            Share = Join-Path $DestinationRoot 'share'
        }
    }
    if ($Scope -eq 'Machine') {
        return @{
            Bin = Join-Path $env:ProgramFiles 'Daguard'
            Config = Join-Path $env:ProgramData 'Daguard'
            Share = Join-Path $env:ProgramFiles 'Daguard\share'
        }
    }
    if (-not $env:LOCALAPPDATA) {
        throw 'LOCALAPPDATA is required for a current-user installation.'
    }
    $root = Join-Path $env:LOCALAPPDATA 'Daguard'
    return @{
        Bin = Join-Path $root 'bin'
        Config = Join-Path $root 'config'
        Share = Join-Path $root 'share'
    }
}

function Test-BundleManifest([string]$Root) {
    $manifest = Join-Path $Root 'SHA256SUMS'
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
        throw 'Release bundle has no SHA256SUMS manifest.'
    }
    $seen = @{}
    foreach ($line in Get-Content -LiteralPath $manifest) {
        if ($line -notmatch '^([0-9a-fA-F]{64})  (.+)$') {
            throw 'Release bundle checksum manifest is invalid.'
        }
        $relative = $Matches[2].Replace('/', [IO.Path]::DirectorySeparatorChar)
        if ([IO.Path]::IsPathRooted($relative) -or $relative.Split([IO.Path]::DirectorySeparatorChar) -contains '..') {
            throw 'Release bundle checksum manifest contains an unsafe path.'
        }
        $path = Join-Path $Root $relative
        $key = $relative.ToLowerInvariant()
        if ($seen.ContainsKey($key)) {
            throw "Release bundle checksum manifest has a duplicate path: $relative"
        }
        $seen[$key] = $true
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Release bundle file is missing: $relative"
        }
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        if ($actual -ne $Matches[1]) {
            throw "Release bundle checksum mismatch: $relative"
        }
    }
    foreach ($file in Get-ChildItem -LiteralPath $Root -File -Recurse) {
        if ($file.FullName -eq $manifest) { continue }
        $relative = [IO.Path]::GetRelativePath($Root, $file.FullName)
        if (-not $seen.ContainsKey($relative.ToLowerInvariant())) {
            throw "Release bundle file is not covered by SHA256SUMS: $relative"
        }
    }
}

function Set-MachineAcl([string]$Path) {
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    & $icacls $Path '/inheritance:r' '/grant:r' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' '/T' '/C' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to apply managed ACLs to $Path"
    }
}

$Bundle = (Resolve-Path -LiteralPath $Bundle).Path
Test-BundleManifest $Bundle
if ($Scope -eq 'Machine' -and -not $DestinationRoot) {
    Assert-Administrator
}
$layout = Get-Layout
$binarySource = Join-Path $Bundle 'daguard.exe'
$policySource = Join-Path $Bundle 'default-policy.json'
if (-not (Test-Path -LiteralPath $binarySource -PathType Leaf)) {
    throw 'Release bundle does not contain daguard.exe.'
}

$version = & $binarySource version
if ($LASTEXITCODE -ne 0 -or $version -notmatch '\(x86_64-pc-windows-msvc\)') {
    throw 'Release binary is not the expected native Windows target.'
}
& $binarySource policy lint $policySource | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Bundled organization policy is invalid.'
}

foreach ($directory in $layout.Values) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}
$binaryDestination = Join-Path $layout.Bin 'daguard.exe'
$policyDestination = Join-Path $layout.Config 'policy.json'
$releaseDestination = Join-Path $layout.Config 'release.json'
$manifestDestination = Join-Path $layout.Config 'SHA256SUMS'
$pluginDestination = Join-Path $layout.Share 'opencode'
New-Item -ItemType Directory -Path $pluginDestination -Force | Out-Null

Copy-Item -LiteralPath $binarySource -Destination $binaryDestination -Force
Copy-Item -LiteralPath (Join-Path $Bundle 'release.json') -Destination $releaseDestination -Force
Copy-Item -LiteralPath (Join-Path $Bundle 'integrations\opencode\index.js') -Destination $pluginDestination -Force
Copy-Item -LiteralPath (Join-Path $Bundle 'integrations\opencode\package.json') -Destination $pluginDestination -Force
if ($ReplacePolicy -or -not (Test-Path -LiteralPath $policyDestination)) {
    Copy-Item -LiteralPath $policySource -Destination $policyDestination -Force
}

$binaryHash = (Get-FileHash -LiteralPath $binaryDestination -Algorithm SHA256).Hash.ToLowerInvariant()
$policyHash = (Get-FileHash -LiteralPath $policyDestination -Algorithm SHA256).Hash.ToLowerInvariant()
@("$binaryHash  daguard", "$policyHash  policy.json") | Set-Content -LiteralPath $manifestDestination -Encoding ascii

if ($Scope -eq 'Machine' -and -not $DestinationRoot) {
    Set-MachineAcl $layout.Bin
    Set-MachineAcl $layout.Config
}

& $binaryDestination doctor --policy $policyDestination --integrity-manifest $manifestDestination | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Installed guard diagnostics failed.'
}
Write-Output "Installed daguard to $binaryDestination"
if ($Scope -eq 'CurrentUser') {
    Write-Warning 'A current-user installation is a weaker boundary than an administrator-managed installation.'
}
