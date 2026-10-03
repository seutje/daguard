# Drupal Agent Guard — Implementation Plan

**Project:** `daguard`
**Primary target:** WSL2 / Linux x86_64 using a packaged Rust executable
**Secondary targets:** macOS and native Windows
**Source of truth:** `DESIGN.md`
**Plan status:** Ready for implementation

---

## How to use this plan

This document is intended to be updated by the coding agent or developer performing the work.

Rules for using the checklist:

- Mark a task complete only after the implementation, tests, and relevant documentation are committed together.
- Do not mark a phase complete until its **Exit criteria** are satisfied.
- If implementation reveals that a design assumption is incorrect, update `DESIGN.md` before or together with the implementation change.
- Security-relevant behavior must be covered by automated tests before the corresponding task is checked off.
- Adapter-specific behavior must not leak policy logic into adapter code.
- Do not weaken organization policy to make a failing test pass; determine whether the rule, fixture, adapter, or test expectation is wrong.
- Prefer small pull requests that complete one coherent group of checkboxes.

---

# Phase 0 — Repository foundation and engineering controls

## 0.1 Project bootstrap

- [x] Create the Rust Cargo project with binary name `daguard`.
- [x] Add and pin `rust-toolchain.toml`.
- [x] Commit `Cargo.lock` and require locked builds in CI.
- [x] Add `.gitignore` appropriate for Rust and local test artifacts.
- [x] Add `README.md` with a concise project overview and local developer build instructions.
- [x] Add `SECURITY.md` describing how security issues should be reported.
- [x] Add `CHANGELOG.md` using a documented release format.
- [x] Add `LICENSE` or organization-approved licensing metadata.
- [x] Ensure `DESIGN.md`, `PLAN.md`, and `AGENTS.md` are present at repository root.

## 0.2 Initial source layout

- [x] Create `src/main.rs`.
- [x] Create `src/cli.rs`.
- [x] Create `src/model.rs`.
- [x] Create `src/policy.rs`.
- [x] Create `src/paths.rs`.
- [x] Create `src/shell.rs`.
- [x] Create `src/audit.rs`.
- [x] Create `src/project.rs`.
- [x] Create `src/platform.rs`.
- [x] Create `src/adapters/mod.rs`.
- [x] Create `src/adapters/codex.rs`.
- [x] Create `src/adapters/cursor.rs`.
- [x] Create `src/adapters/opencode.rs`.
- [x] Create `src/analyzers/mod.rs`.
- [x] Create analyzer modules for DDEV, Drush, SQL, Git, Composer, and network behavior.
- [x] Create `policy/default-policy.json`.
- [x] Create `tests/fixtures/`.

## 0.3 CI baseline

- [x] Add CI job for `cargo fmt --check`.
- [x] Add CI job for `cargo clippy`.
- [x] Add CI job for `cargo test --locked`.
- [x] Configure warnings policy for security-critical modules.
- [x] Add dependency vulnerability scanning.
- [x] Add dependency license inventory/checking.
- [x] Ensure CI fails when `Cargo.lock` is out of date.

### Phase 0 exit criteria

- [x] Fresh clone builds successfully with the pinned Rust toolchain.
- [x] CI runs formatting, linting, and unit-test jobs.
- [x] Repository structure matches the architecture in `DESIGN.md`.
- [x] No security policy decisions exist inside adapter modules.

---

# Phase 1 — Canonical protocol and enforcement core

Goal: establish the stable internal request/decision protocol and deterministic policy evaluation engine before implementing broad agent support.

## 1.1 Canonical request model

- [x] Define a versioned canonical request schema.
- [x] Include protocol/schema version.
- [x] Include agent identifier.
- [x] Include hook/event type.
- [x] Include session identifier when available.
- [x] Include tool/call identifier when available.
- [x] Include working directory.
- [x] Include normalized capability.
- [x] Include original tool name.
- [x] Include raw-but-bounded tool arguments required for policy analysis.
- [x] Define behavior for absent optional fields.
- [x] Define explicit representation for unknown tools/capabilities.
- [x] Ensure malformed canonical input can never implicitly become `allow`.

## 1.2 Capability model

- [x] Implement `FILE_READ` capability.
- [x] Implement `FILE_WRITE` capability.
- [x] Implement `FILE_DELETE` capability.
- [x] Implement `SHELL_EXECUTE` capability.
- [x] Implement `NETWORK_READ` capability.
- [x] Implement `NETWORK_WRITE` capability.
- [x] Implement `MCP_CALL` capability.
- [x] Implement `UNKNOWN` capability.
- [x] Document mapping rules in code comments and tests.

## 1.3 Canonical decision model

- [x] Define `allow` decision.
- [x] Define `deny` decision.
- [x] Define optional approval/ask semantic internally without requiring every adapter to support it.
- [x] Include stable rule identifier.
- [x] Include human-readable reason.
- [x] Include severity/category fields.
- [x] Include safe evidence fields that do not contain secrets.
- [x] Include policy source/layer information where useful.
- [x] Ensure deny reasons are useful to developers but do not echo sensitive input.

## 1.4 Policy loader

- [x] Implement JSON policy loading using a mature pinned parser crate.
- [x] Validate policy schema before use.
- [x] Reject unknown mandatory schema versions.
- [x] Define default behavior for unknown optional policy fields.
- [x] Fail closed when mandatory organization policy is unreadable.
- [x] Fail closed when mandatory organization policy is invalid.
- [x] Implement deterministic rule ordering.
- [x] Implement stable rule IDs.
- [x] Add `daguard policy lint` command.

## 1.5 Policy layering

- [x] Implement immutable built-in invariants.
- [x] Implement organization policy layer.
- [x] Implement optional project policy layer.
- [x] Ensure project policy may only preserve or strengthen mandatory rules.
- [x] Reject attempted weakening of organization policy.
- [x] Add tests for contradictory organization/project rules.
- [x] Document policy precedence in CLI help and README.

## 1.6 Path normalization

- [x] Normalize relative paths against request `cwd`.
- [x] Normalize `.` and `..` segments lexically before matching.
- [x] Handle repeated path separators.
- [x] Handle Linux absolute paths.
- [x] Avoid unsafe reliance on path existence for policy matching.
- [x] Define symlink handling semantics for v1.
- [x] Add traversal test cases such as `foo/../sites/default/settings.php`.
- [x] Add path matching tests for Drupal multisite layouts.

## 1.7 Critical built-in file rules

- [x] Deny read of `**/.env`.
- [x] Deny read of `**/.env.*`.
- [x] Deny read of `**/auth.json`.
- [x] Deny read of `**/composer-auth.json`.
- [x] Deny read of `**/sites/*/settings.php`.
- [x] Deny read of `**/sites/*/settings.local.php`.
- [x] Deny read of `**/*.pem`.
- [x] Deny read of `**/*.key`.
- [x] Deny write to Drupal core.
- [x] Deny write to `vendor/**`.
- [x] Deny write to contributed modules.
- [x] Deny write to contributed themes.
- [x] Allow normal custom-module and custom-theme paths unless another rule blocks them.

## 1.8 CLI shell

- [x] Implement `daguard version`.
- [x] Implement `daguard check` for fixture/manual evaluation.
- [x] Implement `daguard explain <rule-id>`.
- [x] Implement stable non-zero exit codes for guard failures.
- [x] Keep machine-readable stdout separate from diagnostic stderr where adapters require strict JSON output.

## 1.9 Enforcement-core tests

- [x] Unit test every canonical model parser.
- [x] Unit test every path-normalization primitive.
- [x] Unit test precedence between policy layers.
- [x] Unit test malformed JSON behavior.
- [x] Unit test missing-field behavior.
- [x] Unit test unknown-capability behavior.
- [x] Add fixture tests for all initial protected paths.
- [x] Verify tests never embed real credentials or real developer secrets.

### Phase 1 exit criteria

- [x] Canonical request and decision schemas are stable enough for adapters.
- [x] Initial protected file rules are enforced by the core independently of any agent.
- [x] Invalid mandatory policy fails closed.
- [x] `daguard check` can evaluate synthetic requests from stdin/files.
- [x] Test suite proves malformed input cannot result in implicit allow.

---

# Phase 2 — Codex adapter and first end-to-end enforcement path

Goal: get one agent working end-to-end before adding additional adapters.

## 2.1 Codex fixture collection

- [x] Capture sanitized representative `PreToolUse` payloads for shell execution.
- [x] Capture sanitized representative file-read payloads.
- [x] Capture sanitized representative file-write/patch payloads.
- [x] Capture sanitized MCP/function-tool payloads if exposed through the hook.
- [x] Record the Codex version used to collect each fixture.
- [x] Store fixtures without secrets or production paths.

## 2.2 Codex normalization

- [x] Parse current Codex `PreToolUse` input.
- [x] Map `tool_name` and `tool_input` into canonical request fields.
- [x] Map session/tool identifiers where available.
- [x] Map `cwd`.
- [x] Map file-oriented tools to capabilities.
- [x] Map shell-oriented tools to `SHELL_EXECUTE`.
- [x] Map unknown tools explicitly to `UNKNOWN`.
- [x] Add golden tests for every captured fixture.

## 2.3 Codex decision rendering

- [x] Render a valid allow response for supported Codex versions.
- [x] Render a valid deny response with a concise reason.
- [x] Confirm Codex actually prevents the denied tool call.
- [x] Define behavior if Codex rejects a response schema.
- [x] Treat unsupported `ask` behavior as non-security-critical until proven stable.
- [x] Add regression fixtures for Codex response parsing.

## 2.4 Codex hook configuration

- [x] Provide documented Codex hook configuration template.
- [x] Use an absolute trusted path to `daguard` in managed deployment examples.
- [x] Match all relevant tool calls rather than only shell commands.
- [x] Document known Codex fail-open/fail-closed limitations.
- [x] Add `daguard doctor` checks for Codex hook configuration where practical.

## 2.5 Codex end-to-end security tests

- [x] Verify `settings.php` read is denied.
- [x] Verify `.env` read is denied.
- [x] Verify custom module source read is allowed.
- [x] Verify custom module source write is allowed.
- [x] Verify Drupal core write is denied.
- [x] Verify malformed hook input is denied/fails safely.
- [x] Verify guard error cannot produce an explicit allow response.

### Phase 2 exit criteria

- [x] Codex invokes the packaged guard for representative tool calls.
- [x] Codex blocks protected file reads and writes based on shared core policy.
- [x] Adapter contains normalization/rendering only, not Drupal policy logic.
- [x] Golden fixture tests protect the adapter contract.

---

# Phase 3 — Shell analysis, DDEV, Drush, SQL, Composer, and Git

Goal: enforce Drupal-development semantics rather than only filesystem patterns.

## 3.1 Shell analysis foundation

- [x] Implement bounded shell tokenization suitable for policy inspection.
- [x] Do not attempt to become a full shell interpreter.
- [x] Detect command chaining with `;`.
- [x] Detect `&&` and `||`.
- [x] Detect pipelines.
- [x] Detect output redirection relevant to writes.
- [x] Detect common shell wrappers such as `sh -c` and `bash -c`.
- [x] Define conservative behavior for unsupported/ambiguous constructs.
- [x] Add adversarial tokenizer fixtures.

## 3.2 DDEV analyzer

- [x] Detect `ddev` command wrapping.
- [x] Normalize `ddev drush ...` into a Drush analysis target.
- [x] Normalize `ddev composer ...` into a Composer analysis target.
- [x] Detect `ddev exec` and analyze nested command text where possible.
- [x] Detect `ddev ssh` as a broad shell escape.
- [x] Detect database import/export operations.
- [x] Define policy for `ddev start`.
- [x] Define policy for `ddev describe`.
- [x] Add normal Drupal workflow fixtures.

## 3.3 Drush analyzer

- [x] Allow `drush cr` by default.
- [x] Allow `drush status` by default.
- [x] Allow `drush pm:list` by default.
- [x] Allow safe config-status operations.
- [x] Deny `drush php:eval`.
- [x] Deny `drush ev`.
- [x] Deny equivalent eval aliases.
- [x] Deny or policy-gate `drush sql:dump`.
- [x] Define handling for `drush sql:cli`.
- [x] Classify config import and update-db operations for approval/policy handling.
- [x] Add DDEV-wrapped Drush fixtures for every rule.

## 3.4 SQL analyzer

- [x] Identify SQL text embedded in supported Drush/DDEV commands.
- [x] Deny `INSERT`.
- [x] Deny `UPDATE`.
- [x] Deny `DELETE`.
- [x] Deny `DROP`.
- [x] Deny `ALTER`.
- [x] Deny `TRUNCATE`.
- [x] Deny `REPLACE`.
- [x] Deny `CREATE`.
- [x] Deny `GRANT`.
- [x] Deny `REVOKE`.
- [x] Define handling for read-only `SELECT`.
- [x] Detect configured sensitive Drupal tables.
- [x] Add tests for comments/case/whitespace variations.
- [x] Add tests for chained SQL statements.
- [x] Add tests for quoted strings so keywords inside values do not trivially create false positives where avoidable.

## 3.5 Composer analyzer

- [x] Allow `composer validate`.
- [x] Allow `composer audit`.
- [x] Classify `composer require`.
- [x] Classify `composer update`.
- [x] Detect script-running behavior where relevant.
- [x] Ensure the analyzer recognizes `ddev composer ...`.
- [x] Protect Composer credential files independently of Composer command policy.

## 3.6 Git analyzer

- [x] Allow `git status`.
- [x] Allow `git diff`.
- [x] Allow `git log`.
- [x] Define policy for ordinary `git commit`.
- [x] Define policy for ordinary `git push`.
- [x] Deny `git push --force`.
- [x] Deny `git push -f`.
- [x] Detect common argument-order variations for force push.
- [x] Detect credential-related Git configuration changes where practical.
- [x] Add regression tests for false positives on harmless flags containing `-f` substrings.

## 3.7 Command-security tests

- [x] Test direct dangerous commands.
- [x] Test DDEV-wrapped dangerous commands.
- [x] Test nested `bash -c` variants.
- [x] Test command chaining where a safe command precedes a denied command.
- [x] Test command chaining where a denied command precedes a safe command.
- [x] Test whitespace and quoting variations.
- [x] Test relative path traversal inside shell commands.

### Phase 3 exit criteria

- [x] Normal DDEV/Drupal workflows remain low-friction.
- [x] Arbitrary Drush evaluation is denied.
- [x] Destructive SQL is denied.
- [x] Writes to protected dependency areas are denied even through shell commands.
- [x] Force push is denied.
- [x] The shell analyzer behaves conservatively on ambiguous syntax.

---

# Phase 4 — Cursor adapter

## 4.1 Cursor fixtures

- [x] Capture sanitized `preToolUse` shell fixture.
- [x] Capture sanitized file-read fixture.
- [x] Capture sanitized file-write fixture.
- [x] Capture relevant MCP/tool fixtures.
- [ ] Record tested Cursor versions.

## 4.2 Cursor adapter implementation

- [x] Normalize Cursor input into the canonical request model.
- [x] Render Cursor allow response.
- [x] Render Cursor deny response.
- [x] Include safe user-facing denial explanation.
- [x] Configure `failClosed: true` in deployment examples.
- [x] Add golden tests for all fixture variants.

## 4.3 Cross-adapter parity tests

- [x] Run identical protected-path scenarios through Codex and Cursor adapters.
- [x] Run identical Drush scenarios through Codex and Cursor adapters.
- [x] Run identical SQL scenarios through Codex and Cursor adapters.
- [x] Assert canonical decisions are identical independent of agent.

### Phase 4 exit criteria

- [x] Cursor blocks the same mandatory cases as Codex.
- [x] Cursor fail-closed configuration is documented and tested.
- [x] No Cursor-specific policy branch exists in the policy engine unless required by a documented capability difference.

---

# Phase 5 — Audit logging, diagnostics, and operator experience

## 5.1 Audit event format

- [x] Define versioned audit event schema.
- [x] Record timestamp.
- [x] Record agent name/version when known.
- [x] Record adapter/schema version.
- [x] Record decision.
- [x] Record rule ID.
- [x] Record category/severity.
- [x] Record non-sensitive normalized operation metadata.
- [x] Record session/call IDs where safe and useful.
- [x] Do not record full raw tool input by default.
- [x] Do not record file contents.
- [x] Do not record SQL result data.
- [x] Do not record secrets/tokens/passwords.

## 5.2 Local logging

- [x] Implement local append-only audit logging where configured.
- [x] Handle missing/unwritable audit destination safely.
- [x] Ensure logging failure cannot silently transform deny into allow.
- [x] Implement bounded/log-rotation guidance.
- [x] Add redaction tests.

## 5.3 `daguard doctor`

- [x] Report executable version.
- [x] Report OS/architecture.
- [x] Report canonical binary path.
- [x] Report organization policy path/status.
- [x] Report policy schema validity.
- [x] Report policy hash.
- [x] Detect WSL where practical.
- [x] Detect DDEV availability but do not require it.
- [x] Check Codex integration where practical.
- [x] Check Cursor integration where practical.
- [x] Report that OpenCode integration checking is deferred until its Phase 6 implementation.
- [x] Warn when executable or mandatory policy is inside an agent-writable project repository.

## 5.4 Explainability

- [x] Implement rule documentation registry.
- [x] Implement `daguard explain <rule-id>`.
- [x] Include remediation/safe alternative where appropriate.
- [x] Ensure explanations do not encourage bypassing mandatory policy.

### Phase 5 exit criteria

- [x] Every deny response has a stable rule ID.
- [x] Developers can use `doctor` to diagnose installation issues.
- [x] Audit logs do not contain known secret fixtures.
- [x] A support engineer can explain a denial without reproducing the sensitive payload.

---

# Phase 6 — OpenCode integration

## 6.1 OpenCode plugin bridge

- [x] Implement minimal OpenCode plugin under `integrations/opencode/`.
- [x] Hook `tool.execute.before` or the currently supported equivalent.
- [x] Convert OpenCode input into canonical JSON.
- [x] Invoke the native `daguard` executable.
- [x] Block execution when `daguard` returns deny.
- [x] Block execution when the guard cannot be executed.
- [x] Block execution when guard output is malformed.
- [x] Avoid relying on argument mutation for security guarantees.

## 6.2 OpenCode fixtures and tests

- [x] Capture sanitized representative OpenCode hook payloads.
- [x] Add adapter golden tests.
- [x] Add plugin-level tests where practical.
- [x] Record tested OpenCode CLI versions.
- [x] Record tested OpenCode desktop behavior separately if applicable.
- [x] Document known version-specific limitations.

## 6.3 Three-agent policy parity

- [x] Build a shared scenario matrix.
- [x] Verify protected files receive the same canonical decision across all three agents.
- [x] Verify Drush decisions are identical.
- [x] Verify destructive SQL decisions are identical.
- [x] Verify force-push decisions are identical.
- [x] Verify protected writes are identical.

### Phase 6 exit criteria

- [x] Codex, Cursor, and OpenCode all use the same policy engine.
- [x] The same scenario produces the same canonical decision across all adapters.
- [x] OpenCode integration fails closed when the guard cannot produce a valid decision.

---

# Phase 7 — WSL release packaging and team installation

## 7.1 Release build

- [x] Configure `x86_64-unknown-linux-musl` release target.
- [x] Produce optimized release artifact.
- [x] Confirm executable runs on supported WSL2 Ubuntu installations without installing Rust.
- [x] Verify no unexpected dynamic third-party dependencies.
- [x] Record compiler version and target triple.
- [x] Record `Cargo.lock` hash.

## 7.2 Release metadata

- [x] Generate SHA-256 checksums.
- [x] Generate dependency inventory/SBOM.
- [x] Generate license inventory.
- [x] Include release/version metadata in `daguard version`.
- [x] Add provenance/signature mechanism selected by the team.
- [x] Verify artifacts in CI before publishing.

## 7.3 WSL installer

- [x] Create `scripts/install.sh`.
- [x] Support user-managed install to `~/.local/bin/daguard` for pilot deployments.
- [x] Support managed install to `/usr/local/bin/daguard`.
- [x] Support organization policy install to `/etc/daguard/policy.json`.
- [x] Verify binary checksum before installation.
- [x] Set appropriate file ownership and permissions.
- [x] Refuse to install organization policy from an unverified artifact.
- [x] Do not install Rust, Python, Node, or other runtime dependencies.
- [x] Do not compile source during normal installation.

## 7.4 Uninstaller and upgrade path

- [x] Create `scripts/uninstall.sh`.
- [x] Define safe upgrade procedure.
- [x] Preserve organization policy unless explicitly replacing it.
- [x] Prevent partial upgrades where binary and mandatory policy schema are incompatible.
- [x] Document rollback procedure.

## 7.5 Managed agent configuration

- [x] Provide Codex hook configuration template.
- [x] Provide Cursor hook configuration template.
- [x] Provide OpenCode plugin installation instructions.
- [x] Prefer absolute paths to trusted installed executable.
- [x] Document how central management should prevent repository-local disablement where supported.

## 7.6 WSL/DDEV integration tests

- [x] Test installation on clean WSL environment.
- [x] Test `daguard version` immediately after installation.
- [x] Test `daguard doctor` immediately after installation.
- [x] Test with DDEV stopped.
- [x] Test with DDEV running.
- [x] Test ordinary `ddev start`.
- [x] Test ordinary `ddev drush cr`.
- [x] Test blocked `ddev drush php:eval`.
- [x] Test blocked protected-file read.
- [x] Test blocked protected-file write.
- [x] Test uninstall/rollback.

### Phase 7 exit criteria

- [x] Team member can install `daguard` in WSL from release artifacts without a language runtime or compiler.
- [x] Linux release is self-contained according to the project's packaging definition.
- [x] DDEV is not required for the guard to start or evaluate policy.
- [x] Release contains checksums and SBOM.

---

# Phase 8 — Security hardening and robustness

## 8.1 Malformed and adversarial input

- [x] Define maximum accepted stdin payload size.
- [x] Reject oversized payloads safely.
- [x] Bound recursion/depth where parser/library options permit.
- [x] Test invalid UTF-8 handling where applicable.
- [x] Test truncated JSON.
- [x] Test duplicate/unexpected fields.
- [x] Test huge strings and argument arrays.
- [x] Test unknown agent/tool values.
- [x] Ensure panic does not result in an allow decision.

## 8.2 Fuzzing

- [x] Add fuzz target for canonical request decoding.
- [x] Add fuzz target for each native adapter decoder.
- [x] Add fuzz target for path normalization.
- [x] Add fuzz target for shell tokenization/analyzer.
- [x] Add fuzz target for SQL classification.
- [x] Seed fuzz corpus with real sanitized fixtures.
- [x] Add scheduled CI fuzzing or a documented manual fuzz workflow.

## 8.3 Panic/error policy

- [x] Audit `unwrap()`/`expect()` use in request-processing paths.
- [x] Remove avoidable panics from security-critical input handling.
- [x] Define top-level panic behavior.
- [x] Ensure adapter response on internal error is deny/fail-closed where the host permits.
- [x] Ensure diagnostics go to stderr, not machine-output stdout.

## 8.4 Filesystem and configuration integrity

- [x] Refuse writable-by-project mandatory policy paths in managed mode.
- [x] Detect suspicious binary location where practical.
- [x] Add `doctor` integrity checks for binary and policy hashes.
- [x] Document limits of local-user tamper protection.
- [x] Ensure project policy cannot point to arbitrary executable extensions/plugins.

## 8.5 Security regression suite

- [x] Add direct secret-read cases.
- [x] Add indirect path cases.
- [x] Add protected write cases.
- [x] Add DDEV wrapping cases.
- [x] Add destructive SQL cases.
- [x] Add exfiltration-related command cases.
- [x] Add command chaining cases.
- [x] Add shell escape cases.
- [x] Add false-positive regression cases for normal Drupal workflows.

### Phase 8 exit criteria

- [x] No known malformed-input path results in implicit allow.
- [x] Security-critical parsers have fuzz coverage.
- [x] Critical path contains no unjustified panics.
- [x] Regression suite includes both bypass attempts and normal-workflow false-positive tests.

Validation: `cargo fmt --check`, fuzz-package formatting, strict all-target/all-feature
Clippy, `cargo test --locked` (82 Rust tests), the same suite against the optimized
WSL musl target, OpenCode bridge tests, and production/fuzz dependency advisory,
license, source, and ban checks passed. All eight libFuzzer targets completed a
20-second campaign and a final regression-adjusted smoke run with AddressSanitizer
and leak checks enabled. The optimized musl binary was inspected with `file`,
`readelf`, and `ldd`: static linking, no interpreter or shared-library requirements.
Manual fuzzing and residual host/symlink/tamper limitations are documented in
`fuzz/README.md`, `README.md`, `SECURITY.md`, and `DESIGN.md`. Live agent/DDEV and
root-installed deployment acceptance were not rerun in this phase.

---

# Phase 9 — Performance and startup budget

## 9.1 Benchmark harness

- [x] Add benchmark for process startup plus trivial allow evaluation.
- [x] Add benchmark for path-rule evaluation.
- [x] Add benchmark for shell/DDEV/Drush analysis.
- [x] Add benchmark for SQL analysis.
- [x] Add benchmark for policy parsing/loading.
- [x] Capture measurements on representative WSL2 hardware.
- [x] Capture measurements with project on WSL Linux filesystem.
- [x] Optionally compare behavior from `/mnt/c` to document expected degradation.

## 9.2 Performance optimization

- [x] Keep normal invocation free of unnecessary filesystem scans.
- [x] Avoid spawning subprocesses from policy evaluation.
- [x] Avoid network access from the guard.
- [x] Avoid hashing large files on every invocation.
- [x] Avoid loading non-required project files.
- [x] Profile before adding caching or daemon complexity.

## 9.3 Performance acceptance

- [x] Agree final startup/evaluation budget with team.
- [x] Meet or revise the design's target of roughly `<5 ms` P50 startup/trivial evaluation on representative WSL hardware.
- [x] Meet or revise the design's target of roughly `<25 ms` P95 for normal policy evaluation.
- [x] Record benchmark methodology in repository documentation.
- [x] Add non-flaky performance regression monitoring where feasible.

### Phase 9 exit criteria

- [x] Guard overhead is acceptable for high-frequency agent tool usage.
- [x] No proposed optimization weakens policy correctness or auditability.

Phase 9 implementation evidence: `examples/performance.rs` benchmarks the
optimized musl process and production modules, validates synthetic decisions,
and reports nearest-rank percentiles. `docs/performance/README.md` documents
methodology, the invocation cost review, and informational CI monitoring;
`docs/performance/wsl2-linux-2026-10-03.json` records measurements from the current
WSL2 workstation with the project on ext4. All measured process cases are below
the existing design targets. No optimization or new dependency was needed.

---

# Phase 10 — Audit-only pilot and policy tuning

## 10.1 Pilot mode

- [ ] Implement or configure audit-only evaluation mode.
- [ ] Ensure audit-only mode is clearly distinguishable from enforcement mode.
- [ ] Prevent project-local policy from enabling audit-only mode when organization enforcement is mandatory.
- [ ] Log would-deny decisions without recording sensitive payload content.

Implementation note (2026-10-03): Section 10.1 support is implemented in this
change as organization-designated **candidate-rule** audit-only evaluation;
mandatory organization rules, built-ins and project rules remain enforced.
See `docs/pilot/README.md` and `docs/pilot/report-template.md` for deployment and
evidence collection. Local validation passed: `cargo fmt --check`,
`cargo clippy --all-targets --all-features -- -D warnings`, and
`cargo test --locked` (136 tests, including eight new pilot integration tests).
The implementation checkboxes remain open until the change is committed,
following this plan's checklist rule. Deployment, tuning and exit criteria
require real team pilot evidence. Synthetic tests do not constitute a developer
pilot; no real group deployment or pilot performance/compatibility measurement
was performed by this change.

CI regression follow-up (2026-10-03): The enforcement test helper now tolerates
only `BrokenPipe` when policy rejection closes stdin before the parent writes.
A large-input regression reproduced the original panic before the fix and now
verifies configuration exit code 3 with no stdout. Formatting, strict Clippy,
and the full locked Rust suite passed (137 tests). Enforcement behavior is
unchanged; Section 10.1 checkboxes retain their commit/evidence gates.

## 10.2 Pilot deployment

- [ ] Select a small representative developer group.
- [ ] Include users of Codex.
- [ ] Include users of Cursor.
- [ ] Include users of OpenCode if supported in pilot.
- [ ] Run representative Drupal/DDEV workflows.
- [ ] Collect false positives.
- [ ] Collect unknown-tool cases.
- [ ] Collect performance measurements.
- [ ] Collect adapter compatibility failures.

## 10.3 Policy tuning

Security pilot follow-up (2026-10-03): A reported VS Code command-hook failure
reproduced two gaps: unsupported bare Codex allow output and explicit `rg` reads
of settings files under `env/`. Regression tests failed before the fixes.
Codex permits now use `{}`; deny/ask rendering is unchanged. Shared shell analysis
recognizes `rg` file arguments, and `drupal.secret.settings_php` also covers
environment settings layouts. Formatting, strict all-target/all-feature Clippy,
and `cargo test --locked` passed (139 tests, including three-agent parity).
The fix is not in released v0.0.0. A patched package and a live synthetic
allow/deny retest on the exact VS Code extension version are still required.
At that point, directory-only recursive search and generic organization path
rules within shell commands remained separate follow-up work; no Phase 10
acceptance was claimed.

Security follow-up (2026-10-03): Organization and project `deny_read` /
`deny_write` patterns now apply to recognized shell path operands, including
nested and DDEV-wrapped commands. Recursive `/**` patterns include the directory
root, closing directory-only `rg` searches, while search expressions remain
distinct from paths to avoid false positives. Formatting, strict all-target /
all-feature Clippy, and the full locked suite passed (142 tests). No rule IDs,
adapter contracts, or dependencies changed.

- [x] Close directory-only recursive search and shell policy-path enforcement gaps.

- [ ] Review every false positive by rule ID.
- [ ] Add narrowly scoped exceptions only where justified.
- [x] Add missing Drupal-specific sensitive SQL tables identified by the team,
  including bounded `*` glob support for Drupal field-table families.
- [ ] Document accepted risk for operations left allowed.
- [ ] Update tests before changing enforcement semantics.

### Phase 10 exit criteria

- [ ] False-positive rate is acceptable for mandatory critical rules.
- [ ] Common Drupal/DDEV workflows are represented in regression fixtures.
- [ ] Known unknown-tool cases are classified or explicitly handled conservatively.

---

# Phase 11 — Mandatory blocking rollout

## 11.1 Critical hard blocks

- [ ] Enable mandatory denial for `settings.php`.
- [ ] Enable mandatory denial for `.env` files.
- [ ] Enable mandatory denial for private keys.
- [ ] Enable mandatory denial for protected dependency writes.
- [ ] Enable mandatory denial for Drush eval.
- [ ] Enable mandatory denial for destructive SQL.
- [ ] Enable mandatory denial for Git force push.

## 11.2 Operational readiness

- [ ] Publish installation documentation.
- [ ] Publish upgrade documentation.
- [ ] Publish rollback documentation.
- [ ] Publish rule catalog/explanations.
- [ ] Publish support/troubleshooting guidance.
- [ ] Establish ownership for policy changes.
- [ ] Establish review requirements for security-rule changes.
- [ ] Establish agent compatibility testing responsibility.

## 11.3 Break-glass decision

- [ ] Decide whether break-glass is required.
- [ ] If not required, document that decision.
- [ ] If required, define time-bounded, auditable semantics.
- [ ] Ensure break-glass cannot be triggered silently by an agent.
- [ ] Ensure break-glass events are conspicuous in audit logs.
- [ ] Add tests for break-glass expiry and scope.

### Phase 11 exit criteria

- [ ] Mandatory organization policy is deployed outside project repositories.
- [ ] Critical rules are actively blocking for pilot/production users.
- [ ] Support and rollback processes exist before broader rollout.

---

# Phase 12 — Optional macOS support

- [ ] Build `aarch64-apple-darwin` artifact.
- [ ] Test path normalization on macOS.
- [ ] Test supported agents on Apple Silicon.
- [ ] Determine whether Intel macOS is needed.
- [ ] Build/test `x86_64-apple-darwin` if required.
- [ ] Code-sign macOS artifacts if organizational distribution requires it.
- [ ] Notarize macOS artifacts if required.
- [ ] Add macOS installation/uninstallation guidance.
- [ ] Add macOS native CI smoke tests where infrastructure permits.

### Phase 12 exit criteria

- [ ] macOS support is declared only for architectures/agent versions actually tested.

---

# Phase 13 — Optional native Windows support

- [ ] Build `x86_64-pc-windows-msvc` artifact.
- [ ] Configure static CRT where appropriate.
- [ ] Implement/test drive-letter normalization.
- [ ] Implement/test UNC path handling.
- [ ] Test Windows path case semantics.
- [ ] Test WSL/Windows path interop scenarios that are explicitly supported.
- [ ] Add PowerShell installer.
- [ ] Add PowerShell uninstaller.
- [ ] Test agent hook invocation from native Windows processes.
- [ ] Document differences between native Windows and WSL deployment.

### Phase 13 exit criteria

- [ ] Native Windows support is explicitly scoped and covered by path/adapter integration tests.

---

# Phase 14 — Session taint tracking and exfiltration controls

This phase is intentionally deferred until stateless enforcement is stable.

## 14.1 Post-tool integration

- [ ] Identify supported post-tool hooks per agent.
- [ ] Define canonical post-tool event model.
- [ ] Record resource sensitivity metadata without recording returned content.
- [ ] Add adapter fixtures for post-tool events.

## 14.2 Session state

- [ ] Define session taint categories.
- [ ] Define taint lifetime.
- [ ] Define safe local state storage.
- [ ] Define cleanup/expiry behavior.
- [ ] Prevent one user's session state from affecting another user's session.
- [ ] Test crash/restart behavior.

## 14.3 Sink controls

- [ ] Identify network-capable shell commands.
- [ ] Identify network/MCP sinks.
- [ ] Block or require policy approval for outbound sinks after sensitive reads.
- [ ] Prevent raw sensitive data from entering audit records.
- [ ] Add end-to-end taint/exfiltration scenarios.

### Phase 14 exit criteria

- [ ] Stateless v1 remains usable independently.
- [ ] Taint tracking has a documented threat model and persistence model.
- [ ] Sensitive-source to outbound-sink flows are covered by integration tests.

---

# Cross-cutting requirements

These apply to every implementation phase.

## Security invariants

- [ ] The guard never treats parser failure as permission to execute.
- [ ] Mandatory organization policy cannot be weakened by repository policy.
- [ ] Adapter code does not decide Drupal security policy.
- [ ] Sensitive content is not written to logs.
- [ ] The guard performs no outbound network access during normal evaluation.
- [ ] The guard executes no user-provided shell command as part of policy analysis.
- [ ] Unknown high-risk operations are handled conservatively.
- [ ] Release artifacts are built in CI, not on end-user machines.

## Code quality

- [ ] New behavior includes tests.
- [ ] Public/internal contracts have concise documentation.
- [ ] Security-critical parsing avoids avoidable `unwrap()` and `expect()`.
- [ ] Changes pass `cargo fmt`.
- [ ] Changes pass `cargo clippy`.
- [ ] Changes pass the full relevant test suite.
- [ ] Dependency additions are justified in the pull request.
- [ ] Dependency additions are pinned via `Cargo.lock` and pass audit/license checks.

## Design alignment

- [ ] Material architecture changes update `DESIGN.md`.
- [ ] Completed implementation tasks update this `PLAN.md`.
- [ ] Changes to coding-agent expectations update `AGENTS.md`.
- [ ] Changes to user/operator behavior update `README.md` or operational documentation.

---

# v1 release gate

Do not call the project v1-ready until every applicable item below is checked.

- [ ] Distributed as a single `x86_64-unknown-linux-musl` executable.
- [ ] No Rust toolchain or language runtime required on developer workstations.
- [ ] No unexpected third-party dynamic-library dependency in the WSL artifact.
- [ ] Runs from WSL without entering DDEV.
- [ ] Codex adapter blocks protected paths.
- [ ] Cursor adapter blocks protected paths.
- [ ] OpenCode integration blocks protected paths.
- [ ] `ddev drush cr` is allowed.
- [ ] `ddev drush php:eval` is denied.
- [ ] Writes to Drupal core/vendor/contrib are denied.
- [ ] Direct and relative-path reads of `settings.php` are denied.
- [ ] Destructive SQL is denied.
- [ ] Force pushes are denied.
- [ ] Policy parse failure fails closed.
- [ ] Malformed adapter input cannot cause implicit allow.
- [ ] Audit logs contain no raw secrets or tool output.
- [ ] `daguard doctor` validates installation and target information.
- [ ] Golden tests cover all three agents.
- [ ] Mandatory policy and executable can be deployed outside project repositories.
- [ ] Installer does not compile source or install a language runtime.
- [ ] Release includes SHA-256 checksums and SBOM.
- [ ] WSL latency is within the agreed performance budget.
- [ ] Team pilot has been completed and critical false positives resolved.
- [ ] Rollback/support procedures are documented.

---

# Deferred / explicitly out of v1

Keep these unchecked unless the scope is intentionally expanded.

- [ ] Central remote policy service.
- [ ] LLM-based security classifier in the enforcement path.
- [ ] Full shell-language semantic interpretation.
- [ ] Full network payload DLP inspection.
- [ ] Centralized audit collection.
- [ ] Native GUI.
- [ ] MSI/PKG installers unless operationally justified.
- [ ] Support for additional agents beyond Codex, Cursor, and OpenCode.
