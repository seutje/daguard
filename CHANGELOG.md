# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once releases begin.

## [Unreleased]

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
- Security fixes for truncated unknown-tool path inspection, unknown-tool
  command fields, shell newlines/continuations and combined shell flags,
  DDEV argv nesting, in-place sed writes, explicit protected-file transfers,
  and malformed/executable-comment/wrapped SQL. New deny rule: `sql.ambiguous`.
