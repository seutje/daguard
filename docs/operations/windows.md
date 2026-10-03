# Native Windows preview installation and validation

Native Windows is an optional preview target. The primary supported deployment
remains the WSL2 Linux build. Release CI builds and tests
`x86_64-pc-windows-msvc`, enables static CRT linkage, inspects PE imports, runs
the shared Rust suite, and exercises the packaged executable through a native
PowerShell process. This does not declare compatibility with an installed
Codex, Cursor, or OpenCode version; each managed agent version still requires a
live harmless allow/deny hook test.

## Verify and install

Verify the ZIP digest against the release-level `SHA256SUMS` and its GitHub
provenance attestation before extraction. The installer then verifies every
file against the bundle's internal `SHA256SUMS` and validates the bundled
policy with the packaged executable. It never downloads a dependency, installs
a language runtime, or compiles source.

For a current-user pilot, run:

```powershell
Expand-Archive .\daguard-<version>-x86_64-pc-windows-msvc.zip
Set-Location .\daguard-<version>-x86_64-pc-windows-msvc
.\install.ps1 -Scope CurrentUser
```

This installs beneath `%LOCALAPPDATA%\Daguard`. It is a weak boundary because
the agent normally runs as the same user.

For a machine-managed installation, start an elevated PowerShell session and
run:

```powershell
.\install.ps1 -Scope Machine
```

The executable is installed at `C:\Program Files\Daguard\daguard.exe`; policy
and installation checksums are installed below `C:\ProgramData\Daguard`. The
installer replaces inherited ACLs with full control for Administrators and
SYSTEM and read/execute access for Users. Native Windows `doctor --managed`
does not yet independently audit those ACL entries, so operators must retain
endpoint-management ACL verification as a release gate.

Existing organization policy is preserved on upgrade unless `-ReplacePolicy`
is supplied. Run the prior verified bundle's installer to roll back.

## Agent configuration

Native hook commands must quote the executable path and use native absolute
policy paths. For example:

```text
"C:\Program Files\Daguard\daguard.exe" --adapter cursor --event pre-tool --policy "C:\ProgramData\Daguard\policy.json"
```

Keep Cursor's all-tools matcher and `failClosed: true`. Codex and Cursor config
diagnostics accept quoted Windows paths. OpenCode options use the same absolute
guard and policy paths and a package path of
`C:\Program Files\Daguard\share\opencode`. After configuration, test a harmless
allow such as `git status` and a harmless denial against a nonexistent path
ending in `sites\default\settings.php`. A passing CLI invocation alone is not a
live agent compatibility claim.

## Path semantics and WSL interop

Native Windows evaluation recognizes drive-rooted paths (`C:\...`) and UNC
paths (`\\server\share\...`), resolves `.` and `..` lexically without requiring
the target to exist, rejects ambiguous drive-relative paths such as `C:foo`, and
matches policy paths case-insensitively. UNC access through
`\\wsl.localhost\Distribution\...` and legacy `\\wsl$\Distribution\...` is
treated as ordinary UNC syntax.

The guard deliberately does not translate between Windows and WSL namespaces.
`/mnt/c/...` remains a POSIX path when the guard runs in WSL; `C:\...` remains a
Windows path in the native build. Use the binary that runs in the same host
context as the agent hook. DDEV analysis remains syntactic and does not require
DDEV to be installed, but native Windows deployment is not a substitute for the
recommended host-side WSL/DDEV enforcement path.

## Uninstall

Policy is preserved by default:

```powershell
.\uninstall.ps1 -Scope CurrentUser
.\uninstall.ps1 -Scope Machine
```

Use `-RemovePolicy` only when the policy owner intends to remove mandatory
policy. Machine uninstall requires an elevated PowerShell session.
