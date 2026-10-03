[CmdletBinding()]
param(
    [ValidateSet('CurrentUser', 'Machine')]
    [string]$Scope = 'CurrentUser',
    [switch]$RemovePolicy,
    [string]$DestinationRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($DestinationRoot) {
    $bin = Join-Path $DestinationRoot 'bin'
    $config = Join-Path $DestinationRoot 'config'
    $share = Join-Path $DestinationRoot 'share'
} elseif ($Scope -eq 'Machine') {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'A machine uninstall must run from an elevated PowerShell session.'
    }
    $bin = Join-Path $env:ProgramFiles 'Daguard'
    $config = Join-Path $env:ProgramData 'Daguard'
    $share = Join-Path $env:ProgramFiles 'Daguard\share'
} else {
    if (-not $env:LOCALAPPDATA) {
        throw 'LOCALAPPDATA is required for a current-user uninstall.'
    }
    $root = Join-Path $env:LOCALAPPDATA 'Daguard'
    $bin = Join-Path $root 'bin'
    $config = Join-Path $root 'config'
    $share = Join-Path $root 'share'
}

Remove-Item -LiteralPath (Join-Path $bin 'daguard.exe') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $config 'release.json') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $config 'SHA256SUMS') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $share 'opencode') -Recurse -Force -ErrorAction SilentlyContinue
if ($RemovePolicy) {
    Remove-Item -LiteralPath (Join-Path $config 'policy.json') -Force -ErrorAction SilentlyContinue
    Write-Output 'Uninstalled daguard and removed the organization policy.'
} else {
    Write-Output 'Uninstalled daguard; preserved the organization policy.'
}
