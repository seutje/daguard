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
- [x] Package the bridge at the `index.js` entrypoint resolved for an absolute
  local plugin directory by OpenCode CLI v2.0.22.

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
- [x] Document OpenCode reload plus a live denied-tool smoke test instead of
  treating configuration parsing alone as enforcement proof.
- [x] Prefer absolute paths to trusted installed executable.
- [x] Document how central management should prevent repository-local disablement where supported.

## 7.6 WSL/DDEV integration tests

- [x] Run the packaged bridge's live denied-tool smoke test in OpenCode v2.0.22
  before publishing the corrective release.
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

- [x] Select a small representative developer group.
- [x] Include users of Codex.
- [ ] Include users of Cursor.
- [x] Include users of OpenCode if supported in pilot.
- [x] Run representative Drupal/DDEV workflows.
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

- [x] Enable mandatory denial for `settings.php`.
- [x] Enable mandatory denial for `.env` files.
- [x] Enable mandatory denial for private keys.
- [x] Enable mandatory denial for protected dependency writes.
- [x] Enable mandatory denial for Drush eval.
- [x] Enable mandatory denial for destructive SQL.
- [x] Enable mandatory denial for Git force push.

## 11.2 Operational readiness

- [x] Publish installation documentation.
- [x] Publish upgrade documentation.
- [x] Publish rollback documentation.
- [x] Publish rule catalog/explanations.
- [x] Publish support/troubleshooting guidance.
- [ ] Establish ownership for policy changes.
- [x] Establish review requirements for security-rule changes.
- [ ] Establish agent compatibility testing responsibility.

## 11.3 Break-glass decision

- [x] Decide whether break-glass is required.
- [x] If not required, document that decision.
- [x] If required, define time-bounded, auditable semantics. (Not applicable.)
- [x] Ensure break-glass cannot be triggered silently by an agent. (No break-glass exists.)
- [x] Ensure break-glass events are conspicuous in audit logs. (Not applicable.)
- [x] Add tests for break-glass expiry and scope. (Not applicable.)

Implementation note (2026-10-03): All seven critical classes are built-in
denials and the packaged-release smoke test covers their installed behavior,
including every destructive SQL keyword and a nearby safe custom-code write.
The release bundle now contains the managed operations runbook and rule catalog.
Version 1 deliberately has no break-glass mechanism; rollback addresses broken
software, while exceptional operations remain human actions outside the agent.
The two deployment exit criteria below remain open until the organization
completes Phase 10, assigns named people to the documented roles in its private
operations system, deploys the root-owned policy/hooks, and records live agent
allow/deny evidence.

### Phase 11 exit criteria

- [ ] Mandatory organization policy is deployed outside project repositories.
- [ ] Critical rules are actively blocking for pilot/production users.
- [x] Support and rollback processes exist before broader rollout.

---

# Phase 12 — Optional macOS support

- [ ] Build `aarch64-apple-darwin` artifact.
- [ ] Test path normalization on macOS.
- [ ] Test supported agents on Apple Silicon.
- [x] Determine whether Intel macOS is needed. (Retain as transitional preview compatibility through the hosted-runner window.)
- [ ] Build/test `x86_64-apple-darwin` if required.
- [ ] Code-sign macOS artifacts if organizational distribution requires it.
- [ ] Notarize macOS artifacts if required.
- [x] Add macOS installation/uninstallation guidance.
- [x] Add macOS native CI smoke tests where infrastructure permits.

Implementation note (2026-10-03): Native Apple Silicon and Intel build, test,
packaging, installation, and release-attestation lanes are configured. Portable
bundle checksums and installer smoke tests cover both Darwin targets, and path
tests include native macOS layouts. This Linux development environment cannot
execute those lanes, so artifact-build, native-test, and exit-criterion boxes
remain open until CI passes. The artifacts are documented as previews; no agent
version is support-declared without a live macOS allow/deny test. Intel is kept
as transitional compatibility for existing Intel Macs and must be reassessed
before GitHub's announced August 2027 hosted Intel runner retirement. Signing
and notarization remain open pending an organizational Developer ID and
Gatekeeper distribution decision.

### Phase 12 exit criteria

- [ ] macOS support is declared only for architectures/agent versions actually tested.

---

# Phase 13 — Optional native Windows support

- [ ] Build `x86_64-pc-windows-msvc` artifact.
- [x] Configure static CRT where appropriate.
- [x] Implement/test drive-letter normalization.
- [x] Implement/test UNC path handling.
- [x] Test Windows path case semantics.
- [x] Test WSL/Windows path interop scenarios that are explicitly supported.
- [x] Add PowerShell installer.
- [x] Add PowerShell uninstaller.
- [ ] Test agent hook invocation from native Windows processes.
- [x] Document differences between native Windows and WSL deployment.

Implementation note (2026-10-03): Native Windows build, static-CRT inspection,
packaging, PowerShell installation, and synthetic native adapter smoke lanes are
configured. Host-independent tests cover drive, UNC, case-insensitive, and WSL
UNC semantics without translating path namespaces. This Linux environment
cannot execute the Windows artifact or PowerShell release test, so the artifact
build and native-process boxes remain open until CI passes. Live installed-agent
allow/deny tests remain a separate support-declaration gate. Native
`doctor --managed` does not yet inspect Windows ACL entries; machine rollout
must retain endpoint-management ACL verification.

### Phase 13 exit criteria

- [ ] Native Windows support is explicitly scoped and covered by path/adapter integration tests.

---

# Phase 14 — Session taint tracking and exfiltration controls

This phase introduces session-level sensitivity state and prevents information
obtained from sensitive resources from later being exfiltrated through
outbound-capable tools. It intentionally remains useful independently from
Phase 15.

## 14.1 Canonical post-tool event model

- [x] Identify available post-tool/result events for each supported agent.
- [x] Define an agent-agnostic canonical post-tool event model.
- [x] Include agent identifier/type.
- [x] Include session ID where available.
- [x] Include tool-use/call ID where available.
- [x] Include normalized tool/capability category.
- [x] Include relevant resource metadata.
- [x] Include result metadata such as content type and byte size where available.
- [x] Keep raw returned content out of persistent state.
- [x] Add fixtures for Codex, Cursor, and OpenCode post-tool/result events.
- [x] Add tests for missing or malformed session/call identifiers.

The model must remain agent-agnostic and forward-compatible with Phase 15.

## 14.2 Sensitivity taxonomy

Use one canonical taxonomy across static policy, resource classification,
session taint, sink policy, auditing, and the future Phase 15 scanners:

```text
credential
authentication
personal_data
financial_data
customer_data
private_content
operational_sensitive
unknown_sensitive
```

- [x] Define canonical sensitivity categories.
- [x] Document each category.
- [x] Support multiple categories on one resource or session.
- [x] Define deterministic category merging.
- [x] Define severity/priority semantics where needed.
- [x] Ensure classifications store metadata only, not sensitive values.
- [x] Ensure Phase 15 scanners reuse this exact taxonomy.

## 14.3 Sensitive source classification

Known sensitive resources are taint sources without inspecting returned
content. Filesystem sources include `.env`, Drupal `settings.php` variants,
Composer/auth credential files, private keys or certificates containing private
material, and project-defined protected files. Drupal/core/contrib SQL sources
include the existing sensitive-table set, including:

```text
sessions
users
users_field_data
users_data
user__*

comment
comment_field_data
comment__*

webform_submission
webform_submission_data
webform_submission_log

commerce_order
commerce_order__*
commerce_order_item
commerce_order_item__*

commerce_payment
commerce_payment__*
commerce_payment_method
commerce_payment_method__*

profile
profile_field_data
profile_revision
profile_field_revision
profile__*
profile_revision__*

commerce_shipment
commerce_shipment__*

watchdog
flood
```

- [x] Define sensitive-source classification independently from sink classification.
- [x] Reuse existing path policy.
- [x] Reuse existing SQL sensitive-table matching.
- [x] Map known sensitive resources to one or more canonical sensitivity categories.
- [x] Support project-configured sensitive resources.
- [x] Support future Phase 15 dynamic detections as additional taint sources.
- [x] Add Drupal/DDEV-oriented fixtures.
- [x] Ensure source classification never requires logging raw resource contents.

## 14.4 Session taint state

- [x] Define canonical session taint representation.
- [x] Support multiple simultaneous sensitivity categories.
- [x] Define taint lifetime.
- [x] Define expiry behavior.
- [x] Define cleanup behavior.
- [x] Define crash/restart behavior.
- [x] Define concurrency/locking behavior.
- [x] Prevent cross-user or cross-session contamination.
- [x] Define behavior when an agent does not provide a stable session ID.
- [x] Define behavior when sessions reconnect or reuse identifiers.
- [x] Store classifications and metadata only.
- [x] Never store raw secret, PII, financial, or customer values.
- [x] Add isolation tests.
- [x] Add expiry tests.
- [x] Add restart tests.

An acceptable state shape contains category metadata only, for example:

```json
{
  "session": "abc123",
  "taints": ["credential", "personal_data"]
}
```

State designs that persist detected values are prohibited.

## 14.5 Sink classification

Outbound sinks include `curl`, `wget`, generic HTTP clients, SSH, SCP, SFTP,
remote `rsync`, `git push`, `gh api`, other API clients, email tools,
chat/messaging tools, issue-tracker submission tools, browser upload/network
tools, outbound MCP tools, and arbitrary network-capable shell execution.

- [x] Define canonical sink categories.
- [x] Distinguish local-only operations from outbound sinks.
- [x] Identify network-capable shell commands.
- [x] Identify outbound MCP capabilities.
- [x] Identify git/API submission paths.
- [x] Account for common wrappers and command nesting.
- [x] Consider DDEV commands that invoke network-capable processes inside containers.
- [x] Keep sink detection deterministic and conservative.
- [x] Add sink-classification tests.

## 14.6 Source → taint → sink enforcement

```text
sensitive source
      ↓
classification
      ↓
session taint
      ↓
later outbound sink
      ↓
policy decision
```

- [x] Mark a session with sensitivity categories after access to known sensitive sources.
- [x] Merge new classifications with existing taint state.
- [x] Evaluate current session taint before outbound sink execution.
- [x] Define policy for block vs explicit approval.
- [x] Treat credential/authentication taint more restrictively than ordinary operational metadata.
- [x] Define conservative handling of `unknown_sensitive`.
- [x] Ensure future Phase 15 sanitization does not automatically clear taint.
- [x] Add end-to-end source → taint → sink integration tests.

Representative flows include:

```text
settings.php
→ credential/authentication
→ outbound HTTP
→ deny

webform_submission_data
→ personal_data
→ Slack/email/external HTTP
→ deny or explicit approval

commerce_order
→ customer_data/financial_data
→ outbound upload
→ deny or explicit approval
```

## 14.7 Audit safety

- [x] Never persist raw tool results.
- [x] Never persist raw sensitive values.
- [x] Never include sensitive values in allow/deny reasons.
- [x] Never include raw sensitive data in panic/error output.
- [x] Never include raw sensitive data in debug/tracing output.
- [x] Audit only classification, rule/source IDs, decisions, sizes, timestamps, and safe metadata.
- [x] Add fake-canary tests for audit leakage.
- [x] Test malformed/error paths for accidental raw payload serialization.

## 14.8 Adapter security capability model

Use these canonical interception-capability categories:

```text
native_replace
guarded_execution
mcp_proxy
observe_only
unsupported
```

- [x] Define canonical interception-capability categories.
- [x] Model capabilities per agent and tool category.
- [x] Do not assume every tool in one agent has the same behavior.
- [x] Document what `observe_only` means.
- [x] Explicitly state that `observe_only` cannot provide pre-context containment.
- [x] Add adapter capability fixtures/tests when Phase 14 is implemented.
- [x] Keep security capability separate from ordinary policy decisions.

### Phase 14 exit criteria

- [x] Stateless enforcement remains independently usable.
- [x] Session taint has a documented threat model.
- [x] Persistence/lifetime/cleanup semantics are documented and tested.
- [x] Sensitive-source → outbound-sink scenarios are covered.
- [x] Raw sensitive content is never stored in session state.
- [x] Audit logs cannot contain raw sensitive content.
- [x] Canonical sensitivity categories are established for reuse by Phase 15.
- [x] Adapter/tool interception capabilities are explicitly represented.
- [x] Phase 14 remains useful on `observe_only` integrations.

---

# Phase 15 — Sensitive-output containment and pre-context redaction

This phase prevents protected raw tool output from reaching model context when
technically enforceable. It builds on the taxonomy and state model from Phase
14.

## 15.1 Pre-context security boundary

- [x] Define `pre-context interception` formally.
- [x] Document the difference between post-tool observation and safe pre-context replacement.
- [ ] Verify actual behavior for every supported agent/tool combination before claiming support.
- [x] Classify each path as `native_replace`, `guarded_execution`, `mcp_proxy`, `observe_only`, or `unsupported`.
- [x] Never claim containment for `observe_only`.
- [x] Fail closed for policy-designated sensitive operations when no safe interception path exists.
- [x] Pin or document minimum tested agent versions.
- [x] Treat upstream hook-semantics changes as security-critical compatibility changes.

Required architecture:

```text
tool
  ↓
raw result
  ↓
daguard interception
  ├── ALLOW
  ├── SANITIZE
  └── BLOCK
  ↓
safe result only
  ↓
agent/model
```

This observe-only sequence is insufficient:

```text
tool
→ raw result
→ model
→ post-tool observer
```

## 15.2 Result decision model

- [x] Define canonical `ALLOW`, `SANITIZE`, and `BLOCK` result-decision types.
- [x] `ALLOW` forwards raw output only when policy permits.
- [x] `SANITIZE` forwards transformed output only.
- [x] `BLOCK` discards raw output and emits a safe synthetic result.
- [x] Make sanitization failure become `BLOCK`.
- [x] Make scanner/parser failures fail closed for protected operations.
- [x] Never return original and sanitized content together.
- [x] Never include matched sensitive values in reasons or errors.

## 15.3 Secret detection engine

- [x] Detect PEM/private key blocks.
- [x] Detect JWTs.
- [x] Detect Bearer/Authorization credentials.
- [x] Detect database URLs with embedded credentials.
- [x] Detect password/secret/token assignments.
- [x] Detect common API-token formats.
- [x] Detect GitHub/GitLab tokens.
- [x] Detect major cloud-provider credentials where safely recognizable.
- [x] Detect Stripe/payment-provider token formats.
- [x] Detect Slack-style tokens.
- [x] Detect OAuth access/refresh-token patterns.
- [x] Detect cookie/session values where structured context supports classification.
- [x] Detect Drupal password/hash fields where schema context makes detection reliable.
- [x] Support organization/project-specific secret patterns.
- [x] Consider optional conservative entropy-based detection.
- [x] Support multiline matching.
- [x] Handle split/chunk boundaries.
- [x] Enforce strict runtime and memory bounds.
- [x] Complete a regex safety review.

Detector findings contain category, detector ID, offsets, and confidence, but
must not duplicate matched values into persistent objects or logs.

## 15.4 Personal and sensitive-data detection

- [x] Detect email addresses.
- [x] Detect phone numbers.
- [x] Detect IP addresses where configured as personal data.
- [x] Detect payment card numbers with Luhn validation.
- [x] Detect IBANs with checksum validation.
- [x] Detect dates of birth only with adequate context.
- [x] Detect structured postal-address data.
- [x] Classify configured sensitive field/column names.
- [x] Classify Drupal user/account output.
- [x] Classify Webform submission output.
- [x] Classify Commerce order/customer/profile output.
- [x] Classify Commerce payment/payment-method output.
- [x] Classify comment author metadata.
- [x] Support site-specific/custom field classifications.

Prefer structured evidence such as a `mail` column plus an email-shaped value,
or a `pass` column, over loose matching of arbitrary values.

```text
column "mail" + email-shaped value
→ high confidence personal_data

column "pass"
→ credential

column "billing_address"
→ personal_data/customer_data
```

## 15.5 Structured sanitization

- [x] Support plain text.
- [x] Support JSON.
- [x] Support nested JSON.
- [x] Support SQL/table-formatted output.
- [x] Support key/value output.
- [x] Support dotenv-like output.
- [x] Support common CLI table output.
- [x] Preserve safe structural context.
- [x] Preserve keys and column names when safe.
- [x] Redact values rather than dropping whole records where practical.
- [x] Define canonical placeholders.
- [x] Merge overlapping detections safely.
- [x] Preserve valid UTF-8.
- [x] Preserve valid JSON when input JSON is valid.
- [x] Define malformed-input fallback behavior.

Canonical placeholders should include:

```text
[REDACTED:CREDENTIAL]
[REDACTED:PERSONAL_DATA]
[REDACTED:FINANCIAL_DATA]
[REDACTED:CUSTOMER_DATA]
```

## 15.6 Guarded shell execution

Plan a guarded path for agents that cannot replace native output:

```text
agent
  ↓
daguard exec -- command args...
  ↓
child process
  ↓
private stdout/stderr capture
  ↓
scan / sanitize / block
  ↓
safe output only
  ↓
agent
```

- [x] Define `daguard exec -- ...` behavior.
- [x] Avoid shell interpolation unless explicitly required.
- [x] Capture stdout and stderr privately.
- [x] Scan both streams before release.
- [x] Preserve exit status semantics where practical.
- [x] Handle signals.
- [x] Handle timeouts.
- [x] Bound output size.
- [x] Define large-output behavior.
- [x] Avoid raw-output temporary files.
- [x] Define streaming behavior that cannot leak early chunks before a verdict.
- [x] Plan DDEV-specific tests.
- [x] Plan Drush SQL-result tests.
- [x] Plan stderr-secret leakage tests.
- [x] Plan Composer/Git diagnostic leakage tests.

## 15.7 Sensitive-file containment

- [x] Keep direct `deny_read` protections for known secret files.
- [x] Do not weaken pre-tool denial merely because redaction exists.
- [x] Route any future sanitized file reads through guarded reads.
- [x] Scan before exposing content.
- [x] Treat redaction as defense in depth, not permission to read unnecessary secrets.
- [x] Plan tests for `.env`, Drupal settings files, private keys, and Composer auth files.

## 15.8 SQL result containment

- [x] Reuse Phase 14 sensitive-table classifications.
- [x] Add optional sensitive-column classification.
- [x] Prefer pre-execution deny where results should never be exposed.
- [x] Route permitted sensitive SQL queries through guarded execution/result inspection.
- [x] Apply structured column-level redaction where possible.
- [x] Handle aliases.
- [x] Handle joins.
- [x] Handle Drupal table prefixes.
- [x] Handle DDEV/Drush SQL commands.
- [x] Block when safe sanitization cannot be established.
- [x] Plan tests covering `users` and `users_field_data`.
- [x] Plan tests covering `sessions`.
- [x] Plan tests covering Webform submissions and comments.
- [x] Plan tests covering Commerce orders, payments, and payment methods.
- [x] Plan tests covering profiles.
- [x] Plan tests covering ordinary nonsensitive node queries.

## 15.9 MCP response gateway

```text
agent
→ daguard MCP gateway
→ upstream MCP server
→ raw MCP response
→ daguard scan/sanitize/block
→ safe MCP result
→ agent
```

- [x] Intercept MCP requests.
- [x] Apply existing pre-tool policy.
- [x] Forward approved requests.
- [x] Capture responses before returning them.
- [x] Recursively inspect textual and structured content.
- [x] Sanitize supported result types.
- [x] Block unsupported sensitive binary/attachment output.
- [x] Preserve MCP protocol correctness.
- [x] Never return raw and sanitized content together.
- [x] Feed detected classifications into Phase 14 taint state.
- [x] Add planned end-to-end tests.

## 15.10 Integration with Phase 14

- [x] Map detected credentials to `credential` taint.
- [x] Map authentication material to `authentication` taint.
- [x] Map detected PII to `personal_data` taint.
- [x] Map Commerce/customer output to appropriate customer/financial taints.
- [x] Ensure sanitization does not implicitly remove taint.
- [x] Allow a blocked result to taint the session when the operation accessed protected data.
- [x] Reuse the exact Phase 14 taxonomy without duplicate classification concepts.

## 15.11 Canary leakage tests

- [x] Add deterministic fake credential canaries.
- [x] Add deterministic fake personal-data canaries.
- [x] Use reserved/example domains for test emails.
- [x] Cover direct sensitive-file paths.
- [x] Cover guarded-shell paths.
- [x] Cover SQL-result paths.
- [x] Cover MCP-response paths.
- [x] Cover stderr paths.
- [x] Cover audit-log paths.
- [x] Cover error-message paths.
- [x] Cover chunk/split-secret cases.
- [x] Cover ANSI escapes.
- [x] Cover JSON escaping.
- [x] Cover Unicode.
- [x] Cover overlapping matches.
- [x] Cover oversized/truncated output.
- [ ] Verify model context/transcripts where technically testable.

## 15.12 Resource and performance limits

- [x] Define maximum scan size.
- [x] Define scan time budget.
- [x] Define memory budget.
- [x] Define oversized-result behavior.
- [x] Fail closed for protected operations when full scanning cannot complete.
- [x] Avoid catastrophic regular expressions.
- [x] Benchmark common DDEV/Drupal commands.
- [x] Benchmark large SQL results.
- [x] Plan fuzzing of scanners.
- [x] Plan fuzzing of redaction-range merging.
- [x] Plan fuzzing of structured sanitizers.

## 15.13 Agent/tool capability matrix

Model these fields per agent and tool class: pre-call deny, input rewrite,
pre-context output replacement, guarded-execution support, security mode, and
minimum tested version. Cover Codex, Cursor, and OpenCode shell, file-read, MCP,
native edit/patch, and custom/plugin tool families as applicable.

```text
Codex: shell, file read, MCP, patch/edit, custom/local tools
Cursor: shell, file read, MCP, native tools
OpenCode: shell, file read, MCP, plugin/custom tools
```

- [x] Populate capability assumptions only from tested/documented behavior.
- [x] Treat upstream behavior changes as security-relevant.
- [x] Never silently downgrade to `observe_only`.
- [x] Plan compatibility tests for agent updates.

### Phase 15 exit criteria

- [x] Every supported agent/tool path has an explicit interception classification.
- [ ] Integrations claiming containment prove raw canaries do not reach model context.
- [x] Secret scanning is deterministic and bounded.
- [x] PII scanning has documented confidence/false-positive behavior.
- [x] Structured sanitization preserves safe useful context.
- [x] Protected-result scanner failure fails closed.
- [x] Oversized protected output fails closed.
- [x] Audit/error paths cannot leak canary values.
- [x] Sensitive SQL output can be denied or safely contained.
- [x] MCP responses can be sanitized or blocked before agent delivery.
- [x] Phase 15 detections feed Phase 14 taint state.
- [x] Existing stateless and Phase 14 features remain independently usable.

Implementation note (2026-10-04): Phase 15 adds the versioned result-decision
model, bounded deterministic scanner and structured sanitizers, policy-schema-3
detector extensions, `daguard exec`, a newline-delimited stdio MCP gateway,
metadata-only taint/audit integration, capability-schema-2 records, leakage
tests, scanner fuzz coverage, and result benchmarks. Native Codex, Cursor, and
OpenCode post-tool hooks remain explicitly `observe_only`; no native replacement
claim was introduced. The three live-integration checkboxes above remain open
until configured agent versions prove with transcript inspection that a raw
canary cannot bypass the routed guarded-execution/MCP boundary. Cursor remains
version-unverified. Repository tests prove only the guard/proxy output contract.
An optimized WSL2 smoke run measured 4.1 µs P95 for a common JSON result and
8.5 ms P95 for a 512 KiB synthetic SQL table after the standard 20 warmups
(three recorded samples); representative release benchmarking remains part of
the existing performance process.

Local validation passed `cargo fmt --check`, strict all-target/all-feature
Clippy, `cargo test --locked` (83 unit, 39 enforcement-core, 9 hardening, 3
Phase 14, 8 Phase 15, and 71 example-harness tests), fuzz-crate formatting and
locked compilation, a 101,816-execution bounded result-scanner fuzz smoke run,
and `cargo deny check` for advisories, bans, licenses, and sources.

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

# Audit remediation (2026-10-04)

- [x] A01: Paths use the initial working directory after execution context changes.
- [x] A02: Unsupported shell expansion and grouping are accepted as literal words.
- [x] A03: Common wrappers bypass both command and sink analysis.
- [x] A04: DDEV aliases and options lose the nested execution target.
- [x] A05: Filesystem mutation analysis misses destinations and affected descendants.
- [x] A06: Bulk reads and alternate representations bypass sensitive file rules.
- [x] A07: Value-taking and attached command options bypass semantic rules.
- [x] A08: SQL lexical assumptions differ from the target database grammar.
- [x] A09: SELECT is treated as read only even when it has filesystem effects.
- [x] A10: Structured MCP SQL bypasses pre execution SQL protection.
- [x] A11: Codex loses MCP transport identity for file named tools.
- [ ] A12: Guarded execution and MCP use separate taint namespaces from the agent.
- [ ] A13: Classified JSON objects can retain sensitive keys.
- [ ] A14: Incomplete private keys and multiline assignments are released.
- [ ] A15: MCP blob resources bypass binary blocking when MIME metadata is absent or textual.
- [ ] A16: Scanner runtime is measured after work rather than bounded during work.
- [ ] A17: Guarded execution timeout does not bound pipe draining.
- [ ] A18: MCP scanning does not preserve protocol metadata or full lifecycle behavior.
- [ ] A19: Release publication is independent of required security checks.
- [ ] A20: The architectural policy example cannot be loaded and writable is inert.
- [ ] A21: Fuzzing mostly checks crashes rather than security properties.
- [ ] A22: State directory permissions change before symlink validation.
