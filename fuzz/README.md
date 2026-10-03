# Parser fuzzing

This developer-only package builds LLVM libFuzzer targets against the exact
production source modules. It exposes no public runtime guard API and is not
packaged with the native executable. `libfuzzer-sys = 0.4.13` is the only new
fuzz engine dependency; its LLVM NCSA license exception is scoped to fuzz/deny.toml.
The guard's production dependency graph is unchanged.

Prerequisites: cargo-fuzz, a nightly Rust toolchain, and a native C++ compiler.
These are guard-development tools, never requirements on developer machines
consuming the packaged guard. Install prerequisites explicitly; scripts do not
install anything or modify system security settings.

From the repository root:

```bash
cargo fetch --manifest-path fuzz/Cargo.toml --locked
cargo +nightly fuzz build
scripts/fuzz.sh 30
```

The script runs each target for 30 seconds with AddressSanitizer and libFuzzer's
leak checks enabled, a 64 KiB + 1 maximum input length, a five-second per-input
timeout, and a 2 GiB memory limit. Longer manual campaigns (for example 600 seconds
per target) are recommended before parser changes are released. Bounded smoke
runs are coverage checks, not proof that no vulnerabilities remain. Builds run
offline after the explicit locked dependency fetch.

Targets:

| Target | Boundary covered |
| --- | --- |
| canonical | Canonical decoding, validation, policy evaluation |
| codex | Native decoding, normalization, evaluation, rendering |
| cursor | Native decoding, normalization, evaluation, rendering |
| opencode | Versioned bridge decoding, evaluation, rendering |
| path | Lexical normalization, idempotence, glob compilation |
| shell | Tokenization and shared semantic evaluation, including wrappers |
| sql | SQL lexical classification with synthetic sensitive tables |
| policy | Organization and project policy decoding and validation |

Tracked corpus seeds copy existing sanitized adapter/request/policy fixtures and
include synthetic traversal, chaining, SQL, transfer, and duplicate-key cases.
The script copies reviewed seeds to a temporary corpus; generated inputs never
silently enter the tracked corpus. Failed inputs remain in ignored
`fuzz/artifacts/<target>/`; inspect them for sensitive content before turning a
minimal reproduction into a regression test or reviewed seed. Do not commit
captured private tool payloads.

A single target or failure can be run manually:

```bash
cargo +nightly fuzz run shell /tmp/daguard-shell-corpus -- -max_total_time=600 -max_len=65537
cargo +nightly fuzz run shell fuzz/artifacts/shell/crash-<hash>
cargo +nightly fuzz tmin shell fuzz/artifacts/shell/crash-<hash>
```

If LeakSanitizer reports a ptrace/sandbox permission failure, run the same command
in a normal developer terminal or with approved sandbox escalation. Do not change
global ptrace settings or disable sanitizer checks to conceal the failure.

Dependency checks:

```bash
cargo deny --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml --locked check advisories licenses sources bans
cargo fmt --manifest-path fuzz/Cargo.toml --check
```
