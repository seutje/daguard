# Drupal Agent Guard

**Let coding agents work on Drupal—not around your safety boundaries.**

Drupal Agent Guard (`daguard`) is a fast native policy guard for AI coding
agents. It intercepts tool calls before execution, understands common Drupal
and DDEV workflows, and applies one deterministic security policy across Codex,
Cursor, and OpenCode.

`daguard` blocks known-dangerous operations while keeping normal development
work—custom code, cache rebuilds, diagnostics, tests, and read-only tooling—low
friction. It runs on the host, outside DDEV, and requires no language runtime or
package manager on developer machines.

## What it protects

- Secrets such as `.env`, Composer credentials, Drupal `settings.php`, and
  private keys.
- Drupal core, Composer vendor code, and contributed modules and themes from
  direct modification.
- Databases from destructive SQL and sensitive-table reads.
- Repositories from force pushes and agent-driven credential changes.
- Developer environments from privilege escalation, opaque shell escapes, and
  unsafe DDEV or Drush commands.
- Tainted sessions from sending sensitive data to network, Git, API, messaging,
  browser, or MCP sinks.

The guard uses shared analyzers for shell, DDEV, Drush, SQL, Composer, Git,
filesystem, network, and MCP operations. Agent adapters only translate native
payloads, so the same operation receives the same policy decision everywhere.

## Install on WSL

The recommended team deployment uses the verified
`daguard-<version>-x86_64-unknown-linux-musl.tar.gz` release bundle:

```bash
sha256sum --check SHA256SUMS
tar -xzf daguard-<version>-x86_64-unknown-linux-musl.tar.gz
cd daguard-<version>-x86_64-unknown-linux-musl
sudo ./install.sh --managed
```

This installs a root-owned executable and organization policy without compiling
source or installing Rust, Node.js, Python, or another runtime. Follow the
[managed rollout runbook](docs/operations/rollout.md) to verify provenance,
deploy agent configuration, test enforcement, upgrade, or roll back.

For a user-owned WSL evaluation, follow [PILOT.md](PILOT.md). That deployment is
useful for evaluation but is not a strong boundary against an agent running as
the same user.

Native macOS and Windows packages are also produced. See the
[macOS](docs/operations/macos.md) and
[Windows](docs/operations/windows.md) guides for their platform-specific support
and verification requirements.

## Configure an agent

Start from the supplied configuration for your agent:

- [Codex hooks](config/codex/hooks.json) or
  [managed Codex requirements](config/codex/managed-requirements.toml)
- [Cursor hooks](config/cursor/hooks.json)
- [OpenCode configuration](config/opencode/opencode.json)

Keep the managed absolute paths to `/usr/local/bin/daguard` and
`/etc/daguard/policy.json`, then validate the installed configuration:

```bash
daguard doctor codex /path/to/hooks.json
daguard doctor cursor /path/to/hooks.json
daguard doctor opencode /path/to/opencode.json
daguard doctor --managed --policy /etc/daguard/policy.json
```

Always finish setup with a harmless live allow/deny test in the exact agent
version being deployed. Configuration validation alone does not prove that the
host blocks a denied tool call.

## Use the CLI

```bash
daguard version
daguard capabilities
daguard explain drupal.secret.settings_php
daguard policy lint /etc/daguard/policy.json
daguard check --policy /etc/daguard/policy.json < request.json
daguard exec -- ddev drush status
daguard mcp-proxy -- /trusted/path/to/mcp-server --stdio
```

Policy precedence is:

```text
built-in protections > organization policy > project restrictions > defaults
```

Project policy may add restrictions, but it cannot weaken a built-in or
organization denial. See the [rule catalog](docs/operations/rules.md) for the
shipped decisions and stable rule IDs.

`daguard exec` and `daguard mcp-proxy` can scan, sanitize, or block tool output
before releasing it. Native post-tool hooks are metadata-only observers and do
not provide output containment. The exact guarantees and limits are documented
in [Sensitive-result containment](docs/operations/result-containment.md).

## Documentation

- [Managed rollout and operations](docs/operations/rollout.md)
- [User-owned WSL pilot](PILOT.md)
- [Rule catalog](docs/operations/rules.md)
- [Architecture and security model](DESIGN.md)
- [Development guide](DEVELOPMENT.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## Security

`daguard` is a defense-in-depth control, not an OS sandbox. Keep production
credentials out of agent environments and use managed hooks, filesystem
permissions, network controls, branch protection, and sanitized development
data alongside it.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Licensed under the [MIT License](LICENSE).

Project policies are applied only when each hook/guarded route includes
`--project-policy /absolute/path/to/.daguard/project.json`; root detection does not
discover them. Policy schema 3 supports path denies, capability/path rules, SQL
sensitive tables, result scanning and organization defaults/candidate telemetry.
See DESIGN section 14 for a loadable example and full-path glob semantics. Remove
legacy `paths.writable` configuration: it was inert and is now rejected rather
than implying a write boundary. Command/hostname allowlists remain deferred.
