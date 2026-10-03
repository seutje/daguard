# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once releases begin.

## [Unreleased]

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
