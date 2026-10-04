[CmdletBinding()]
param([Parameter(Mandatory)][string]$Bundle)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$bundle = (Resolve-Path -LiteralPath $Bundle).Path
$root = Join-Path ([IO.Path]::GetTempPath()) "daguard-windows-test-$PID"
$tampered = Join-Path ([IO.Path]::GetTempPath()) "daguard-windows-tampered-$PID"
try {
    Copy-Item -LiteralPath $bundle -Destination $tampered -Recurse
    Add-Content -LiteralPath (Join-Path $tampered 'default-policy.json') -Value ' '
    $tamperRejected = $false
    try {
        & (Join-Path $tampered 'install.ps1') -Bundle $tampered -DestinationRoot "$root-tampered"
    } catch {
        $tamperRejected = $true
    }
    if (-not $tamperRejected) { throw 'Installer accepted a tampered bundle.' }

    & (Join-Path $bundle 'install.ps1') -Bundle $bundle -DestinationRoot $root
    $binary = Join-Path $root 'bin\daguard.exe'
    $policy = Join-Path $root 'config\policy.json'
    if (-not (Test-Path -LiteralPath $binary)) { throw 'Installer did not place the binary.' }

    # An invalid preserved policy is rejected before any installed replacement.
    $before = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash
    $savedPolicy = Get-Content -LiteralPath $policy -Raw
    Set-Content -LiteralPath $policy -Value '{"schema":99}'
    $invalidRejected = $false
    try { & (Join-Path $bundle 'install.ps1') -Bundle $bundle -DestinationRoot $root } catch { $invalidRejected = $true }
    if (-not $invalidRejected -or (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -ne $before) {
        throw 'Invalid preserved policy changed the installation.'
    }
    Set-Content -LiteralPath $policy -Value $savedPolicy
    & (Join-Path $bundle 'install.ps1') -Bundle $bundle -DestinationRoot $root

    # Inject an ordinary replacement failure after staging/snapshots to verify
    # complete rollback. This test-only copy never changes shipped installer code.
    $rollbackScript = Join-Path $root 'rollback-test.ps1'
    $installer = Get-Content -LiteralPath (Join-Path $bundle 'install.ps1') -Raw
    $installer = $installer.Replace('$mutated = $true', '$mutated = $true; Remove-Item -LiteralPath $stageRelease -Force')
    Set-Content -LiteralPath $rollbackScript -Value $installer
    $inventoryBefore = @{}
    foreach ($file in Get-ChildItem -LiteralPath $root -File -Recurse) {
        if ($file.FullName -eq $rollbackScript) { continue }
        $inventoryBefore[$file.FullName] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    }
    $rollbackRejected = $false
    try { & $rollbackScript -Bundle $bundle -DestinationRoot $root -ReplacePolicy } catch { $rollbackRejected = $true }
    if (-not $rollbackRejected) { throw 'Injected replacement failure did not fail.' }
    foreach ($path in $inventoryBefore.Keys) {
        if (-not (Test-Path -LiteralPath $path) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $inventoryBefore[$path]) {
            throw 'Replacement failure did not restore every previous installed file.'
        }
    }
    if (Get-ChildItem -LiteralPath (Join-Path $root 'config') -Directory -Filter '.install-*') {
        throw 'Installer left transaction staging behind.'
    }
    Remove-Item -LiteralPath $rollbackScript

    $deny = @{
        protocol = 1; agent = 'windows-smoke'; event = 'pre_tool_use'
        cwd = 'C:\Users\Developer\Sites\drupal'
        tool = @{ native_name = 'Read'; capability = 'file_read' }
        input = @{}; facts = @{ paths = @('WEB\SITES\DEFAULT\SETTINGS.PHP') }
    } | ConvertTo-Json -Depth 8 -Compress | & $binary check --policy $policy | ConvertFrom-Json
    if ($deny.decision -ne 'deny' -or $deny.rule_id -ne 'drupal.secret.settings_php') {
        throw 'Native Windows protected-path invocation did not deny.'
    }

    $allow = @{
        tool_name = 'Shell'; tool_input = @{ command = 'git status' }
        tool_use_id = 'windows-smoke'; cwd = 'C:\Users\Developer\Sites\drupal'
    } | ConvertTo-Json -Depth 8 -Compress | & $binary --adapter cursor --event pre-tool --policy $policy | ConvertFrom-Json
    if ($allow.permission -ne 'allow') { throw 'Native Windows Cursor allow invocation failed.' }

    & (Join-Path $bundle 'uninstall.ps1') -DestinationRoot $root
    if (-not (Test-Path -LiteralPath $policy)) { throw 'Uninstall removed policy by default.' }
    & (Join-Path $bundle 'uninstall.ps1') -DestinationRoot $root -RemovePolicy
    if (Test-Path -LiteralPath $policy) { throw 'Policy was not removed when requested.' }
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath "$root-tampered" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tampered -Recurse -Force -ErrorAction SilentlyContinue
}
