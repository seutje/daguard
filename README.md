# Drupal Agent Guard

Drupal Agent Guard (`daguard`) is a security-sensitive native executable that will
intercept coding-agent tool calls and apply shared, deterministic policy before an
operation runs. Its primary deployment target is WSL2 with DDEV; Codex, Cursor,
and OpenCode are the first planned integrations.

The repository includes phases 0–8 defined in [PLAN.md](PLAN.md):
the canonical enforcement core, Codex and Cursor adapters, and bounded command
analysis for shell, DDEV, Drush, SQL, Composer, and Git operations, plus safe
local auditing, operator diagnostics, the fail-closed OpenCode v2 bridge, and a
checksummed, provenance-attested WSL release and installation flow. The architecture
and security model are specified in [DESIGN.md](DESIGN.md). Phase 8 adds bounded
JSON preflight, duplicate-key rejection, native panic denial, managed trust and
checksum checks, adversarial regression tests, and eight parser fuzz targets.
Phase 9 adds a dependency-free performance harness, WSL measurements, and
informational CI reports; team performance acceptance remains pending. See
[performance methodology](docs/performance/README.md).

## WSL installation and upgrades

The supported end-user input is the immutable
`daguard-<version>-x86_64-unknown-linux-musl.tar.gz` release bundle. Verify the
archive against the release `SHA256SUMS` before extracting it. Tagged GitHub
releases also carry GitHub build-provenance attestations; verify one with your
organization's GitHub CLI policy before trusting the enclosed checksum manifest.
The installer then verifies every bundled file and refuses a changed or missing
organization policy artifact.

For a pilot, user-owned installation:

```bash
tar -xzf daguard-<version>-x86_64-unknown-linux-musl.tar.gz
cd daguard-<version>-x86_64-unknown-linux-musl
./install.sh --user
```

This installs the executable at `~/.local/bin/daguard`, policy and release
metadata under `~/.config/daguard/`, and the OpenCode bridge under
`~/.local/share/daguard/opencode/`. A user-owned deployment is useful for a pilot
but is not a strong boundary against an agent running as that user.

For the recommended root-owned team deployment:

```bash
sudo ./install.sh --managed
```

This installs `/usr/local/bin/daguard`, `/etc/daguard/policy.json`, release
metadata, and `/usr/local/share/daguard/opencode/` with root ownership. The
installer never downloads dependencies, invokes a package manager, or compiles
source. It validates the packaged policy with the new executable before making
changes and rolls back an interrupted or failed multi-file update.

Rerun a newer verified bundle to upgrade. Existing organization policy is
preserved by default; pass `--replace-policy` only when intentionally deploying
the verified policy from that release. Binary/policy schema incompatibility is
rejected before replacement. To roll back, run the installer from the previous
verified immutable bundle; its default policy-preservation behavior keeps the
currently deployed organization policy.

Uninstall while retaining policy for a later reinstall:

```bash
./uninstall.sh --user
sudo ./uninstall.sh --managed
```

Add `--remove-policy` only when the organization policy should also be deleted.
The uninstaller reports whether policy was preserved or removed.

After a managed installation, centrally merge the shipped
`config/codex/hooks.json` or `config/codex/managed-requirements.toml` and
`config/cursor/hooks.json`, and deploy `config/opencode/opencode.json`. These
templates use absolute root-controlled executable, policy, and plugin paths.
Where the agent supports central requirements, prevent repository-local hooks
from replacing or disabling the managed hook. Validate each deployed file with
`daguard doctor <agent> <path>` and then run `daguard doctor`. User-managed pilots
must adjust the absolute paths to their user installation, remove `--managed`
from Codex/Cursor commands, set OpenCode `managed: false`, and accept the weaker
tamper boundary.

Release CI builds the pinned `x86_64-unknown-linux-musl` target in the optimized
release profile, rejects a dynamic interpreter, embeds Git/compiler/target/lock
metadata in `daguard version`, generates CycloneDX SBOM plus dependency and
license inventories, runs the installation/DDEV classification suite, creates
SHA-256 manifests, and attests the archive before publishing. DDEV is never an
installer or guard runtime dependency.

## CLI

Evaluate a canonical request from standard input or a file:

```bash
daguard check < request.json
daguard check --policy /etc/daguard/policy.json request.json
daguard check --policy /etc/daguard/policy.json \
  --project-policy .daguard/project.json request.json
```

Other core commands are:

```bash
daguard version
daguard explain drupal.secret.settings_php
daguard policy lint policy/default-policy.json
daguard policy lint --layer project .daguard/project.json
daguard doctor --policy /etc/daguard/policy.json \
  --audit-log ~/.local/state/daguard/audit.jsonl
daguard doctor codex config/codex/hooks.json
daguard doctor cursor config/cursor/hooks.json
daguard doctor opencode config/opencode/opencode.json
```

Add `--audit-log PATH` to `check` or an adapter invocation to append a
versioned JSONL event. Audit events contain allowlisted classifier metadata and SHA-256
pseudonyms for session/call IDs, never raw input, commands, paths, contents, or
decision evidence. The parent directory must already exist; on Unix, an
existing log must be a regular owner-only file. An append failure fails closed.
Rotate logs with an owner-only OS policy at a bounded size (for example 10 MiB,
five retained files); rename-and-create rotation works well because each guard
invocation reopens the configured path.

`daguard doctor` reports the executable path and target, organization-policy
validity and SHA-256, audit-directory status, WSL/DDEV detection, and Codex,
Cursor, and OpenCode integration status without executing DDEV or an agent. It
warns when the binary or mandatory policy is inside a project repository.

Policy precedence is `built-in deny > organization > project > default`, and
decision strength is `deny > ask > allow`. Project policy may add only denial
rules and deny-path patterns; it cannot set defaults, declare writable paths, or
add allow/ask rules. Missing or invalid policy passed with `--policy` is a
configuration error and never emits an allow decision.

Documented optional policy fields default safely when absent. Unknown fields are
rejected so a misspelled mandatory setting cannot silently weaken enforcement.
Organization and project policies may extend `sql.sensitive_tables` with bare
table names; built-in Drupal-sensitive tables remain protected regardless.

Shell inspection recognizes common quoting, chaining, pipelines, redirects,
`sh -c`/`bash -c`, and DDEV wrappers without executing commands. It denies
Drush evaluation, destructive SQL, force pushes, unrestricted DDEV shells,
privilege escalation, and protected-path access through recognized file
commands. Dependency-changing Composer commands, ordinary Git commit/push, and
Drush config imports/database updates produce `ask`; adapters without stable
approval support map that result to deny. Unsupported expansion, heredoc,
background, or input-redirection syntax is denied conservatively.

Exit codes are stable at this process boundary: `0` means a decision or requested
informational output was emitted, `2` is invalid CLI usage, `3` is a policy or
configuration failure, and `4` is malformed input or an internal evaluation
failure. A policy denial is a successfully evaluated decision and exits `0`.

Canonical paths are normalized lexically without requiring the target to exist.
The current version does not resolve symlink aliases; deployments must retain OS
permissions as a complementary boundary until symlink-aware behavior is designed
and tested.

## Codex integration

The Codex adapter is tested against Codex CLI 0.160.0 and the official
`PreToolUse` contract documented on 2026-10-03. Copy and centrally adapt
[`config/codex/hooks.json`](config/codex/hooks.json) for user-managed installs,
or merge [`config/codex/managed-requirements.toml`](config/codex/managed-requirements.toml)
into managed Codex requirements. Deployment examples deliberately use absolute,
root-controlled executable and mandatory-policy paths and match every supported
local tool call. Non-managed hooks must be reviewed and trusted in Codex.

The adapter maps supported Codex file tools, `apply_patch`, Bash, MCP calls, and
unknown local tools into the canonical core. It maps the currently unsupported
canonical `ask` result to `deny`; it never returns Codex's unsupported
`permissionDecision: "ask"` form.

Codex currently continues a tool call when a `PreToolUse` callback crashes,
times out, or returns malformed/unsupported output. To reduce that fail-open
surface, `daguard` converts parsing, configuration, and evaluation failures into
a small valid deny response whenever stdout remains writable. A failure before
the executable starts, forced termination, broken stdout, host rejection of the
response schema, specialized tools that bypass hooks, and hosted tools remain
outside this guarantee. Managed deployment should enable hooks and restrict
execution to managed hooks, but hooks remain a guardrail rather than an OS
sandbox. See the [official OpenAI hooks documentation](https://learn.chatgpt.com/docs/hooks).

## Cursor integration

The Cursor adapter implements the native `preToolUse` contract documented on
2026-10-03. Copy and centrally adapt
[`config/cursor/hooks.json`](config/cursor/hooks.json); keep the absolute trusted
binary and organization-policy paths, the all-tools matcher, and
`failClosed: true`. Use `daguard doctor cursor <hooks.json>` to reject examples
that omit those controls.

Cursor `Shell`, `Read`, `Write`/`Edit`, `Delete`, and `MCP:*` tools normalize to
the shared canonical model. Denial messages expose only a stable rule ID. Since
Cursor does not currently enforce `ask` for `preToolUse`, the adapter maps
canonical `ask` to `deny`. Invalid native input and evaluation failures emit a
native deny response whenever stdout remains writable.

The fixture suite is derived from the official
[Cursor Hooks documentation](https://cursor.com/docs/hooks). Cursor was not
installed in the Phase 4 development environment, so a live-tested application
version is not claimed; centrally deployed Cursor versions must run the adapter
compatibility suite before release or upgrade.

## OpenCode integration

The dependency-free bridge in
[`integrations/opencode/`](integrations/opencode/) targets OpenCode CLI v2 and
registers the supported `ctx.tool.hook("execute.before", ...)` hook. Configure
it using the object form shown in
[`config/opencode/opencode.json`](config/opencode/opencode.json), replacing the
example package, guard, and organization-policy paths with absolute trusted
installation paths. OpenCode supplies the JavaScript runtime; the bridge adds no
Node.js, npm, Bun, or other separately installed runtime requirement.

The bridge passes the unmodified tool name and arguments to
`daguard --adapter opencode --event pre-tool` without invoking a shell. It
allows execution only after a valid schema-1 `allow` response. A denial,
canonical `ask`, timeout, missing executable, non-zero exit, oversized output,
or malformed response throws from the pre-execution hook and blocks the tool.
The bridge never rewrites tool arguments and contains no Drupal policy.

The fixtures and bridge contract were checked against OpenCode CLI v2.0.22 and
the [official OpenCode v2 plugin documentation](https://opencode.ai/v2/docs/build/plugins)
on 2026-10-03. OpenCode v2's tool event does not expose a per-call working
directory, so the bridge uses the plugin instance's `ctx.location.directory`;
multi-location behavior must be retested if OpenCode changes that contract.
OpenCode Desktop was unavailable, and no desktop-version compatibility is
claimed. Run the Rust golden/parity suite, the JavaScript bridge tests, and a
live denied-tool smoke test before upgrading a managed OpenCode deployment.

## Development

Install [`rustup`](https://rustup.rs/) and clone the repository. The checked-in
`rust-toolchain.toml` selects the exact compiler and required components.

```bash
cargo build --locked
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
node --test integrations/opencode/daguard-plugin.test.js
```

`tests/release_install.sh <extracted-bundle>` exercises checksum rejection,
installation, policy decisions, upgrades, rollback, and uninstall without root.
On a WSL host with DDEV available,
`tests/wsl_ddev_live.sh <extracted-bundle>` repeats that suite with an isolated
temporary DDEV project first running and then stopped, and removes the project on
exit.

Normal end-user installation uses the packaged native executable and does not
require Rust, Cargo, Node.js, Python, or another language runtime.

Production dependencies are intentionally limited to `serde`/`serde_json` for
typed JSON, `globset` for mature path-pattern matching, and `sha2` for standard
SHA-256 audit pseudonyms and policy fingerprints. Using the established digest
implementation avoids a bespoke security primitive. Dependencies are compiled
into the binary, pinned by `Cargo.lock`, and checked by the CI vulnerability and
license jobs.

## Security

Do not report vulnerabilities in a public issue. See [SECURITY.md](SECURITY.md)
for the reporting process.

## License

Licensed under the [MIT License](LICENSE).

## Security hardening and integrity

Hook stdin and canonical request files accept at most **64 KiB**, including
whitespace. All decoders validate JSON before normalization: duplicate keys,
invalid UTF-8, truncated JSON, more than 32 levels of envelope nesting, strings
over 16 KiB, keys over 256 bytes, and excessive value counts fail closed. Tool
input additionally allows at most 16 levels and 1,024 values; fact collections
allow 128 entries. Unknown agent names and safe unknown tools remain supported.
Recognized path and command fields of unknown tools still receive shared policy
checks. Codex/Cursor retain bounded optional native metadata; the versioned
OpenCode bridge rejects unknown envelope fields.

Recoverable Rust panics produce `guard.evaluation_error` native denials, or exit
4 without a decision for canonical `check`. Panic diagnostics contain no panic
payload. Process kills, allocation failure, stack overflow, and host hook bypass
remain limitations: deploy host-level fail-closed configuration where available.

Managed hooks now pass `--managed`. This requires an explicit organization policy
and refuses binary/policy files inside projects, symlink components, non-root
ownership, or group/other-writable files or ancestor directories. Use it for the
root-owned WSL deployment, not a user pilot:

```bash
daguard doctor --managed --policy /etc/daguard/policy.json
```

`doctor` prints binary and policy SHA-256 fingerprints and compares both against
the installer's adjacent `SHA256SUMS`. Use `--integrity-manifest PATH` for a
non-standard manifest. Missing automatic manifests produce a warning; malformed
manifests, unreadable explicit manifests, and mismatches produce exit 3. Files
are hashed only by diagnostics, not every hook. An intentionally changed policy
requires an administrator to update the trusted installation manifest.

Checksums detect drift only when their baseline is trusted. User-owned binaries,
policies, and manifests can all be replaced by the same user. Managed checks do
not protect against root, a malicious local developer, filesystem replacement
races, or host configurations that bypass hooks. Request target symlinks retain
the lexical-only v1 behavior described in DESIGN.md.

## Parser fuzzing (guard developers only)

See [fuzz/README.md](fuzz/README.md) for libFuzzer targets, reviewed seed corpora,
and reproduction instructions. The fuzz-only package has a separate pinned
lockfile and does not add dependencies to the shipped guard. A bounded local run:

```bash
cargo fetch --manifest-path fuzz/Cargo.toml --locked
scripts/fuzz.sh 30
```

## Audit-only candidate pilot (Phase 10)

[The pilot runbook](docs/pilot/README.md) covers selecting developers, configuring
hooks/logging, measuring workflows, reviewing false positives and restoring full
enforcement. Policy schema 2 lets the organization owner name its own new
candidate deny/ask rules in `audit_only_rules`. All other protections, including
project policy and built-in security rules, remain enforced. There is no CLI
switch to disable mandatory enforcement. Pilot mode requires `--audit-log PATH`;
`doctor` and invocation diagnostics identify the mode. Schema-1 policies continue
to enforce every rule.

Audit events now use schema 2: `decision`/`rule_id` describe evaluated policy,
while `enforcement_decision`/`enforcement_rule_id` describe the actual canonical
response decision. `mode` distinguishes enforcing and candidate audit-only
runs. Native adapter response schemas are unchanged. The
[report template](docs/pilot/report-template.md) requires real pilot evidence;
automated synthetic replay does not establish team acceptance.
