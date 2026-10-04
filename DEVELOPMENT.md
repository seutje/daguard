# Developing Drupal Agent Guard

This guide is for contributors working on `daguard` itself. End users should
install a packaged release as described in [README.md](README.md); they do not
need a Rust toolchain or any of the developer tools below.

## Start here

Before changing code, read:

1. [DESIGN.md](DESIGN.md) for the architecture, threat model, and security
   contracts.
2. [PLAN.md](PLAN.md) for the implementation checklist and outstanding work.
3. [AGENTS.md](AGENTS.md) for repository working conventions.
4. [SECURITY.md](SECURITY.md) for private vulnerability reporting.

`DESIGN.md` is the architectural source of truth. Update it in the same change
when implementation intentionally changes a security boundary or contract.

## Tooling

Install [rustup](https://rustup.rs/) and clone the repository. The checked-in
`rust-toolchain.toml` selects Rust 1.99.0, rustfmt, Clippy, and the primary
`x86_64-unknown-linux-musl` target.

Node.js is needed only to run the OpenCode bridge tests. `cargo-deny`,
`cargo-audit`, `cargo-cyclonedx`, and `cargo-fuzz` are specialist contributor or
CI tools; none is a runtime dependency of the packaged guard.

Build and run the main validation suite from the repository root:

```bash
cargo build --locked
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
node --test integrations/opencode/daguard-plugin.test.js
```

## Source layout

The main boundaries are:

- `src/cli.rs`: argument parsing and command dispatch.
- `src/model.rs`: canonical request and decision contracts.
- `src/policy.rs`: policy loading, validation, precedence, and orchestration.
- `src/paths.rs` and `src/shell.rs`: bounded normalization and parsing.
- `src/analyzers/`: shared DDEV, Drush, SQL, Git, Composer, and network policy.
- `src/adapters/`: Codex, Cursor, and OpenCode translation only.
- `src/scanner.rs`, `src/result.rs`, and `src/sensitivity.rs`: result inspection,
  sanitization, and the shared sensitivity taxonomy.
- `src/guarded.rs` and `src/mcp.rs`: pre-context output containment paths.
- `src/state.rs`, `src/sink.rs`, and `src/audit.rs`: metadata-only session state,
  sink decisions, and safe audit events.
- `integrations/opencode/`: the minimal dependency-free OpenCode bridge.
- `tests/fixtures/`: sanitized compatibility and regression fixtures.

Keep policy out of adapters and process-entry code. The guard must classify
requests in process without executing proposed commands, invoking a shell as a
parser, querying a database, or making network requests.

## Testing security changes

Every policy or security behavior change needs tests. For a new denial, cover a
direct match, an evasive or variant form where applicable, and a nearby safe
operation. A bypass fix should first gain a regression that reproduces the
bypass.

Use only deterministic synthetic values in fixtures and leakage tests. Never
commit credentials, private payloads, customer data, raw tool results, or
developer-specific paths.

Parser and analyzer changes should run the complete related regression suite,
not only a narrow unit test. Before handing off a normal Rust change, run at
least:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
```

Also run the OpenCode bridge test when its adapter, configuration, or JavaScript
bridge changes.

## Specialized validation

Parser fuzzing uses a separate package and lockfile. Its prerequisites, targets,
and safe corpus workflow are documented in [fuzz/README.md](fuzz/README.md).

Performance measurements use the dependency-free Rust example described in
[docs/performance/README.md](docs/performance/README.md). Measure before adding
caching, a daemon, or lifecycle complexity.

Release and installer changes should validate the packaged artifact with:

```bash
tests/release_install.sh <extracted-bundle>
```

On a WSL host with DDEV available, use:

```bash
tests/wsl_ddev_live.sh <extracted-bundle>
```

The live harness creates an isolated temporary DDEV project, tests with DDEV
running and stopped, and removes the project on exit. Platform-specific release
requirements are documented in the [macOS](docs/operations/macos.md) and
[Windows](docs/operations/windows.md) guides.

## Dependencies and releases

Production dependencies are deliberately small and pinned by `Cargo.lock`.
They provide typed JSON, path-pattern matching, SHA-256, and Unix process/signal
handling; all are compiled into the native executable. Before adding a crate,
confirm existing code or the standard library cannot reasonably provide the
functionality, document why the crate is needed, and run vulnerability, license,
source, and dependency-policy checks.

Production artifacts are built in CI, not on end-user workstations. The release
workflow builds and tests native packages, records build identity, inspects
runtime linkage, generates checksums and inventories, and publishes provenance
attestations. See [DESIGN.md](DESIGN.md) for the complete packaging contract.

## Documentation and review

Update documentation in the same change when behavior or contracts move:

- `DESIGN.md` for architecture, threat model, or security semantics.
- `PLAN.md` for verified implementation work and newly discovered tasks.
- `README.md` for user-facing product or CLI behavior.
- Operational guides for deployment, containment, rules, or platform support.
- `CHANGELOG.md` for user-visible changes.

Security-sensitive changes require an independent review. Summaries should call
out security implications, changed rule IDs, adapter compatibility, tests run,
known limitations, and any new dependency with its justification.
