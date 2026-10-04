# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once releases begin.

## [Unreleased]

- Require shared same-commit quality and dependency checks before release builds
  and WSL publication; pin Actions/tools and publish optional platforms independently.


### Fixed

- Supervise MCP framing and failures, correlate authorized replies, and preserve protocol schemas.

- Enforce guarded deadlines while draining inherited output pipes.

- Bound scanner work during processing and remove quadratic table/token scans.

- Block MCP blob resources regardless of MIME metadata.

- Contain truncated private keys and multiline sensitive assignments.

- Redact classified JSON keys and reject trust in input-shaped redaction markers.

- Bind session-containing routes to the trusted native agent taint namespace.

- Preserve outbound MCP identity for tools with file-operation names.

- Apply shared SQL policy to structured MCP query arguments before execution.

- Deny SQL filesystem access and unknown callable expressions.

- Align SQL comments and identifier quoting with conservative MySQL semantics.

- Normalize Drush/Composer global options and SQL client query options.

- Require protected-file exclusions for bulk searches and inspect Git object paths.

- Check mutation endpoints, protected ancestors and explicit download outputs.

- Inspect DDEV execution aliases, options and container cwd; deny destructive lifecycle operations.

- Share transparent execution-wrapper analysis across policy and taint controls.

- Reject unsupported shell expansion and grouping; retain empty arguments.

- Apply effective shell and Cursor tool working directories to protected paths.

### Changed

- Refocus the main README on installation, agent configuration, and product
  behavior, with contributor guidance moved to `DEVELOPMENT.md` and user-owned
  WSL setup kept in `PILOT.md`.

## [0.1.1] - 2026-10-04

### Fixed

- Make Phase 15 guarded-execution and MCP gateway tests deterministic across
  host environments.
- Restore native Windows compilation for guarded execution by limiting Unix
  signal handling to Unix targets.

## [0.1.0] - 2026-10-04

### Added

- Phase 15 canonical allow/sanitize/block result decisions; bounded secret,
  authentication, personal, financial, customer, and configured-field scanning;
  JSON/key-value/table sanitization with stable placeholders; guarded direct
  execution; and a newline-delimited stdio MCP response gateway.
- Phase 15 integration with metadata-only session taint and audit schema 4,
  versioned policy-schema-3 detector extensions, per-tool capability fields,
  fake-canary leakage tests, scanner fuzz coverage, and scanner benchmarks.
- Result containment is claimed only for explicitly routed `daguard exec` and
  `daguard mcp-proxy` paths. Native Codex, Cursor, and OpenCode result hooks stay
  explicitly `observe_only`.
- A direct, pinned `libc` dependency supports WSL/Linux process-group cleanup
  and signal forwarding in guarded execution without an external runtime.
- The shipped organization policy now uses schema 3 and configures common npm,
  PyPI, DigitalOcean, HashiCorp Vault, and Hugging Face token prefixes; common
  sensitive result fields; and personal-IP handling.

- Phase 14 canonical post-tool metadata for Codex, Cursor, and OpenCode;
  canonical sensitivity and interception-capability taxonomies; metadata-only
  expiring session taint with bounded cleanup and concurrency-safe atomic
  persistence; protected-path and Drupal SQL source classification; and
  deterministic outbound shell, Git/API, messaging, browser, network, and MCP
  sink classification.
- Stateful source-to-sink enforcement through
  `exfiltration.tainted_session` (deny) and
  `exfiltration.tainted_session.review` (ask), with isolation, restart, expiry,
  DDEV nesting, fake-canary leakage, and end-to-end adapter tests.
- `daguard capabilities`, post-tool deployment hooks, and audit schema 3
  metadata-only classification/sink fields. All Phase 14 post-result paths are
  explicitly `observe_only` and do not claim pre-context containment.

## [0.0.7] - 2026-10-03

### Fixed

- Check out the tagged source in the release publishing job so
  `gh release create --verify-tag` can resolve the repository and verify the
  release tag before publishing artifacts.

## [0.0.6] - 2026-10-03

### Fixed

- Treat multiline `daguard version` output as one metadata report in native
  Windows CI, packaging, and installation checks. PowerShell's collection-aware
  `-notmatch` operator previously rejected valid binaries when other output
  lines did not contain the target triple.

## [0.0.5] - 2026-10-03

### Added

- Phase 13 preview support for native x86_64 Windows, including host-independent
  drive/UNC normalization, Windows case semantics, explicit WSL UNC behavior,
  static-CRT native CI and PE inspection, ZIP packaging, PowerShell install and
  uninstall flows, and native packaged adapter smoke coverage. Live agent
  compatibility and independent managed-ACL diagnostics remain release gates.
- Phase 12 preview packaging for native Apple Silicon and Intel macOS, including
  native CI tests, portable checksums/install smoke tests, architecture checks,
  root-owned macOS installation support, and install/uninstall guidance. Live
  agent compatibility, Developer ID signing, and notarization remain explicit
  release gates rather than inferred support.
- Phase 11 managed-rollout and support documentation, including explicit
  policy/security/compatibility ownership, installation, upgrade, rollback,
  troubleshooting, a published rule catalog, and the version 1 decision not to
  implement break-glass without a concrete operational requirement.
- Release-bundle smoke coverage for every critical hard-block class and all
  destructive SQL keywords.

## [0.0.4] - 2026-10-03

### Added

- Support `*` globs in `sql.sensitive_tables`, including Drupal-prefixed table
  names, and expand the shipped policy's sensitive Drupal, Webform, Commerce,
  Profile, session, flood, and comment table coverage.

### Fixed

- Install the OpenCode v2 bridge as `index.js`, the local-directory entrypoint
  that OpenCode CLI v2.0.22 actually resolves. The previous package contained
  only `daguard-plugin.js`; OpenCode does not consult `package.json` exports for
  an absolute local plugin directory, so the bridge was never loaded.
- Apply organization and project path deny lists to recognized shell file
  operands, including nested and DDEV-wrapped commands. Recursive `/**` policy
  patterns now cover the directory root, closing directory-only search bypasses
  without requiring duplicate exact-directory patterns.

## [0.0.3] - 2026-10-03

### Fixed

- Keep the root package version in `Cargo.lock` synchronized with `Cargo.toml`
  so locked CI and release builds do not attempt to update the lockfile.
- Make the installation diagnostics test follow the Cargo package version.
- Codex permitted calls emit `{}` instead of unsupported bare `permissionDecision:
  allow` responses. Native deny/ask-to-deny responses are unchanged.
- Explicit `rg` file reads now receive built-in path checks. The existing
  `drupal.secret.settings_php` rule also protects settings files in `env/`
  layouts, including direct, traversed, nested-shell and DDEV-wrapped reads.
  Directory-only recursive searches remain a known limitation.

### Fixed

- Eliminate a CI broken-pipe race in the enforcement test helper when the guard
  rejects policy before reading stdin; retain exit-status and output assertions.

### Added

- Initial Rust project structure and engineering controls.
- Phase 1 canonical request/decision protocol, layered JSON policy validation,
  lexical path enforcement, core CLI commands, and protected-path fixtures.
- Phase 2 Codex `PreToolUse` normalization, native allow/deny rendering,
  deployment templates, configuration diagnostics, and golden fixtures.
- Phase 3 bounded shell parsing and shared DDEV, Drush, SQL, Composer, and Git
  enforcement, including protected shell-path operations and configurable
  sensitive SQL tables.
- Phase 4 Cursor `preToolUse` normalization, native fail-closed responses,
  deployment diagnostics, golden fixtures, and Codex/Cursor policy-parity tests.
- Phase 5 redacted, versioned append-only JSONL audit events; comprehensive
  installation diagnostics and policy fingerprints; and actionable core-rule
  explanations with stable fail-closed error identifiers.
- Phase 6 OpenCode v2 adapter and dependency-free pre-execution bridge, with
  fail-closed process/output handling, golden fixtures, diagnostics, and a
  shared three-agent policy-parity matrix.
- Phase 7 optimized static WSL release packaging, embedded build identity,
  SHA-256 manifests, SBOM/dependency/license inventories, GitHub provenance
  attestations, transactional user/managed installers, safe uninstall and
  rollback paths, and release-bundle integration tests.
- Phase 8 bounded JSON preflight and duplicate-key rejection, native panic
  denials, managed binary/policy trust checks, installation checksum drift
  diagnostics, adversarial regression coverage, and eight libFuzzer targets.
- Phase 9 release-process and production-module benchmarks, synthetic decision
  verification, WSL Linux-filesystem measurements, documented startup budgets,
  and informational PR/release CI performance artifacts.
- Security fixes for truncated unknown-tool path inspection, unknown-tool
  command fields, shell newlines/continuations and combined shell flags,
  DDEV argv nesting, in-place sed writes, explicit protected-file transfers,
  and malformed/executable-comment/wrapped SQL. New deny rule: `sql.ambiguous`.
- Phase 10 organization-controlled audit-only candidate rules in policy schema 2,
  required fail-closed telemetry, audit schema 2 evaluated/enforced decisions,
  explicit mode diagnostics, three-adapter regressions, and a developer pilot
  runbook/evidence template. Mandatory and project protections remain enforced;
  real developer deployment and tuning require team evidence.
