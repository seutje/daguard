# AGENTS.md

## Purpose

This repository implements **Drupal Agent Guard (`daguard`)**, a security-sensitive Rust executable that intercepts coding-agent tool calls and decides whether they should be allowed or denied before execution.

The primary deployment environment is **WSL2 + DDEV**, with Codex, Cursor, and OpenCode as the first supported agent integrations. The production artifact is a packaged native Rust executable with no separately installed runtime dependencies on developer machines.

Before making changes, read:

1. `DESIGN.md` — architecture and security model.
2. `PLAN.md` — phased implementation checklist and release gates.
3. `SECURITY.md` — once present, project security/reporting guidance.

`DESIGN.md` is the architectural source of truth. If implementation needs to diverge materially, update the design in the same change rather than silently introducing a new architecture.

---

## Core security invariants

These rules are mandatory unless `DESIGN.md` is intentionally revised through review.

1. **Fail closed for security-critical uncertainty.**
   - Invalid mandatory policy must not become allow.
   - Malformed adapter input must not become allow.
   - Internal parsing errors must not become allow.
   - Unknown high-risk operations must be handled conservatively.

2. **Adapters are translators, not policy engines.**
   - Codex, Cursor, and OpenCode adapters may parse native payloads, normalize them, and render native responses.
   - Drupal, Drush, SQL, Git, filesystem, DDEV, Composer, and network policy belongs in shared core/analyzer modules.
   - The same normalized request should receive the same canonical decision regardless of agent.

3. **Mandatory organization policy cannot be weakened by repository policy.**
   - Project-local configuration may strengthen controls.
   - Project-local configuration must not override mandatory deny rules.

4. **Never execute the proposed tool call while analyzing it.**
   - Do not spawn the user's command to determine what it does.
   - Do not invoke shells to parse shell syntax.
   - Do not connect to a database to classify SQL.
   - Do not perform outbound HTTP/network requests during normal evaluation.

5. **Do not log sensitive content.**
   - Never log file contents.
   - Never log passwords, tokens, API keys, cookies, private keys, or credentials.
   - Never log database query results.
   - Avoid logging complete raw tool payloads.
   - Prefer rule IDs and bounded, non-sensitive metadata.

6. **Developer-machine deployment remains runtime-independent.**
   - Do not add a Python, Node.js, Java, .NET, Ruby, PHP, or other runtime requirement for the guard.
   - Normal installation must not require Cargo or compilation.
   - Rust crates are build-time dependencies compiled into the release binary; dependency additions must be justified, pinned, audited, and license-checked.

7. **WSL is the primary platform.**
   - Do not compromise WSL/Linux correctness to simplify optional macOS or Windows support.
   - Keep platform-specific behavior isolated behind platform/path abstractions.
   - Do not assume the repository is stored under `/mnt/c`; preferred WSL paths are under the Linux filesystem.

8. **DDEV is an analyzed execution target, not a runtime dependency.**
   - `daguard` must function when DDEV is absent or stopped.
   - DDEV-specific behavior belongs in the DDEV analyzer.

---

## Architectural boundaries

Keep the repository modular.

Expected responsibilities:

- `main.rs`: process entry point only; do not accumulate policy logic here.
- `cli.rs`: CLI argument parsing and command dispatch.
- `model.rs`: canonical request/decision/event models.
- `policy.rs`: policy loading, validation, precedence, rule evaluation orchestration.
- `paths.rs`: path normalization/matching primitives.
- `shell.rs`: bounded shell tokenization and shell-level classification helpers.
- `project.rs`: project detection and project-policy discovery.
- `platform.rs`: OS-specific behavior and path/platform helpers.
- `audit.rs`: safe audit-event construction and output.
- `analyzers/*`: shared semantic analyzers such as DDEV, Drush, SQL, Git, Composer, and network.
- `adapters/*`: native agent payload parsing and response rendering only.
- `integrations/opencode/*`: minimal OpenCode bridge/plugin code.

Do not turn `main.rs`, an adapter, or one analyzer into a cross-cutting catch-all.

---

## Canonical protocol rules

The internal canonical request and decision formats are security contracts.

When modifying them:

- version schema changes explicitly;
- maintain golden fixtures for all affected adapters;
- do not silently reinterpret existing fields;
- distinguish absent, unknown, and invalid values where that affects safety;
- bound untrusted strings/collections where reasonable;
- keep response reasons useful but non-sensitive;
- preserve stable rule IDs once released unless there is a strong migration reason.

Agent-native payload fields may change over time. Treat each adapter as a versioned compatibility boundary and add fixtures from supported agent versions.

---

## Stateful and result-containment security

Phase 14 owns the shared sensitivity taxonomy, metadata-only session taint,
source/sink classification, and exfiltration controls. Phase 15 must reuse that
exact taxonomy for result scanning and containment.

- Never log or persist raw sensitive tool results.
- Never copy matched secrets or PII into errors, snapshots, tracing, audit
  records, or test failure messages.
- Keep raw scanner input ephemeral and in memory where practical.
- Never treat an observe-only post hook as an output-containment boundary.
- Never silently downgrade a supported safe integration path to `observe_only`.
- Sanitization or scanner failure for protected content must fail closed.
- Redaction does not justify weakening pre-tool deny rules; prefer preventing
  unnecessary sensitive access over reading and then redacting.
- Treat adapter interception and result-delivery semantic changes as
  security-critical compatibility changes.
- Use only deterministic fake canaries in leakage tests; never use real
  credentials or personal data.
- Result-scanner changes require leakage tests for normal, error, audit, and
  tracing paths.
- Never claim a stronger guarantee than the tested agent/tool integration can
  enforce.

---

## Policy semantics

Policy evaluation must be deterministic and explainable.

Use stable rule identifiers such as:

```text
drupal.secret.settings_php
filesystem.write.core
shell.drush.eval
sql.mutation.delete
git.force_push
```

A decision should be explainable in terms of:

- the matched rule;
- the policy layer;
- the capability/operation;
- a concise human-readable reason;
- safe, bounded evidence.

Avoid vague security rules such as "looks suspicious" in the mandatory enforcement path.

The initial mandatory rules are intentionally narrow. Do not expand broad deny behavior without adding representative normal-workflow tests to prevent unnecessary developer friction.

---

## Protected operations

At minimum, preserve coverage for the following unless the design is explicitly revised.

### Sensitive reads

Deny reads of patterns including:

```text
**/.env
**/.env.*
**/auth.json
**/composer-auth.json
**/sites/*/settings.php
**/sites/*/settings.local.php
**/*.pem
**/*.key
```

### Protected writes

Deny writes to:

```text
**/web/core/**
**/core/**
**/vendor/**
**/web/modules/contrib/**
**/web/themes/contrib/**
```

Normal custom-code work should remain low-friction:

```text
web/modules/custom/**
web/themes/custom/**
```

unless another rule specifically blocks the operation.

### Dangerous commands

Maintain mandatory blocking for at least:

```text
sudo ...
drush php:eval ...
drush ev ...
git push --force ...
git push -f ...
```

and their DDEV-wrapped equivalents where applicable.

### SQL mutation

Maintain blocking for destructive/mutating SQL classes including:

```text
INSERT
UPDATE
DELETE
DROP
ALTER
TRUNCATE
REPLACE
CREATE
GRANT
REVOKE
```

SQL analysis must be shared across adapters.

---

## Shell parsing guidance

Shell input is hostile, irregular, and difficult to parse perfectly.

The v1 shell analyzer is intentionally bounded. It should recognize enough structure to protect known boundaries without pretending to implement POSIX/Bash semantics completely.

When working on shell handling:

- detect common chaining/operators such as `;`, `&&`, `||`, pipes, and relevant redirects;
- inspect nested `sh -c` / `bash -c` forms conservatively;
- normalize DDEV wrapping before semantic analyzers where possible;
- do not invoke a real shell for parsing;
- do not overfit rules only to one whitespace or argument order;
- add adversarial fixtures for quoting and chaining;
- if syntax is too ambiguous to classify safely, prefer conservative handling for high-risk operations.

Any change to tokenization should run the entire Drush, DDEV, SQL, Git, and filesystem command regression suite.

---

## Path handling guidance

Do not compare raw paths naïvely.

Path-related security code should account for:

- relative paths;
- `.` and `..` segments;
- repeated separators;
- normalized working directory;
- Drupal multisite layouts;
- Linux absolute paths;
- platform-specific semantics behind explicit abstractions.

Do not require the target path to exist before applying lexical security rules. A future write to a protected path must still be recognized.

Symlink semantics are security-sensitive. If changing them, add explicit tests and update `DESIGN.md` when behavior changes materially.

---

## Adapter rules

### Codex

- Treat current `PreToolUse` payloads as untrusted input.
- Keep fixture coverage for supported Codex versions.
- Render native allow/deny output exactly as expected by the tested version.
- Do not rely on unstable approval semantics for mandatory security boundaries.
- Document known host fail-open limitations; do not hide them with optimistic assumptions.

### Cursor

- Prefer deployment with fail-closed hook configuration where supported.
- Preserve golden fixtures for native payload and response formats.
- Do not add Cursor-only Drupal policy behavior.

### OpenCode

- Keep the JavaScript/TypeScript integration bridge minimal.
- The plugin's job is to serialize the request, invoke `daguard`, parse the result, and block on deny/error.
- Do not duplicate policy logic in the plugin.
- Do not rely on argument rewriting as a security boundary.
- Guard execution failure or malformed guard output should block the proposed operation.

---

## Error handling

Security-critical request processing should use explicit `Result`-based error handling.

Avoid `unwrap()` and `expect()` on untrusted input paths unless an invariant is both local and proven by construction. If you add one, justify it in code comments or structure the code so the panic cannot be reached by external input.

At process boundaries:

- machine-readable adapter output belongs on stdout;
- diagnostics belong on stderr;
- internal errors must not emit syntactically valid `allow` decisions;
- exit codes should be stable and documented where scripts depend on them.

---

## Dependencies

This is a security product. Keep the dependency graph deliberately small.

Before adding a Rust crate:

1. Confirm the standard library or an existing dependency cannot reasonably solve the need.
2. Prefer mature, maintained crates with clear provenance.
3. Avoid large framework dependencies for small utilities.
4. Commit the resulting `Cargo.lock` change.
5. Ensure vulnerability and license checks pass.
6. Mention the dependency and reason in the pull-request summary.

Do **not** hand-roll JSON, cryptographic primitives, hashing algorithms, or signature formats merely to claim zero Cargo dependencies. The deployment promise is zero separately installed runtime dependencies, not zero build-time crates.

---

## Tests required for security changes

Every policy/security behavior change must include tests.

Use the smallest appropriate combination of:

- unit tests for pure functions;
- fixture tests for policies;
- golden tests for adapters;
- integration tests for end-to-end decisions;
- fuzz tests for parsers/tokenizers;
- WSL/DDEV integration tests for release behavior.

For every new deny rule, add:

1. at least one direct positive match;
2. at least one evasive/variant form if applicable;
3. at least one nearby safe operation that must remain allowed.

For bug fixes involving a bypass, first add a regression test that reproduces the bypass, then fix it.

Never commit real secrets into tests. Use clearly synthetic values.

---

## Required local validation before marking work complete

For normal Rust changes, run at least:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
```

Run narrower tests during iteration, but the final change should pass the relevant full suite.

For parser/analyzer changes, also run the affected fixture/golden tests.

For release/packaging changes, validate the WSL `x86_64-unknown-linux-musl` artifact and inspect its runtime linkage as described in `DESIGN.md`.

Do not claim a task complete when required commands were not run. State what was and was not verified.

---

## Performance guidance

The guard may execute before every agent tool call, so startup cost matters.

Avoid:

- network access;
- subprocess spawning;
- recursive project scans;
- expensive hashing on every call;
- loading unrelated project files;
- heavyweight logging initialization.

Prefer simple, deterministic, in-process evaluation.

Do not trade correctness for micro-optimizations without benchmark evidence. Measure on representative WSL hardware before introducing caches, persistent daemons, or complex shared state.

---

## WSL and DDEV guidance

Primary assumptions:

```text
Windows workstation
└── WSL2 Linux
    ├── daguard
    ├── coding agent(s)
    ├── Drupal checkout
    └── DDEV / Docker
```

The guard runs on the WSL host side before a command enters DDEV.

When adding DDEV behavior:

- preserve operation when DDEV is not installed;
- recognize nested commands without executing them;
- keep DDEV handling in the DDEV analyzer;
- add tests for both direct commands and `ddev ...` wrappers.

Normal commands such as these should remain usable unless team policy intentionally changes:

```text
ddev start
ddev describe
ddev drush cr
ddev drush status
ddev composer validate
ddev composer audit
git status
git diff
```

---

## Release and packaging rules

The supported production release is built in CI.

For the primary WSL release:

- target `x86_64-unknown-linux-musl`;
- publish a single native executable plus policy/install metadata;
- publish SHA-256 checksums;
- publish an SBOM/dependency inventory;
- inspect the Linux artifact for unexpected dynamic third-party dependencies;
- record Git SHA, Rust compiler version, `Cargo.lock` hash, and target triple.

Do not modify installation scripts so they run `cargo install` or install a language runtime on developer workstations.

Optional macOS and native Windows support must not delay or destabilize the WSL implementation unless the project owner changes priorities.

---

## Updating project documents

Update documentation as part of the same change when applicable:

- `DESIGN.md`: architecture, threat model, supported behavior, deployment model, policy semantics.
- `PLAN.md`: check completed tasks and add newly discovered work.
- `AGENTS.md`: coding-agent rules and repository-working conventions.
- `README.md`: developer/operator usage.
- `CHANGELOG.md`: user-visible release changes.
- `SECURITY.md`: vulnerability/reporting/security-support policy.

Do not mark a `PLAN.md` checkbox complete merely because code exists. Tests and required documentation must also be complete.

---

## Change discipline

When implementing a task:

1. Identify the relevant `PLAN.md` checkbox(es).
2. Read the corresponding `DESIGN.md` sections.
3. Make the smallest coherent change.
4. Add or update tests.
5. Run required validation.
6. Update documentation if behavior/contracts changed.
7. Check off completed tasks in `PLAN.md` only after verification.

If a requested change would weaken a mandatory security invariant, do not quietly implement the weakening. Surface the conflict clearly in the change summary and update the design only when the project owner explicitly chooses the new policy.

---

## Pull-request / change summary expectations

For substantial changes, include:

- what changed;
- which `PLAN.md` tasks were completed;
- security implications;
- new or changed rule IDs;
- adapter compatibility implications;
- tests run;
- known limitations or follow-up work;
- any new dependencies and why they were needed.

For security bug fixes, describe the class of bypass without placing real secrets or exploit payloads from private environments into the repository.

---

## Definition of done

A task is done only when:

- implementation matches `DESIGN.md`;
- security invariants are preserved;
- tests cover the behavior;
- formatting/linting/tests pass;
- documentation is updated where needed;
- relevant `PLAN.md` checkbox(es) are checked;
- no real secret or sensitive customer/developer data was added to source, tests, logs, or fixtures.
