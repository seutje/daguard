# Drupal Agent Guard

Drupal Agent Guard (`daguard`) is a security-sensitive native executable that will
intercept coding-agent tool calls and apply shared, deterministic policy before an
operation runs. Its primary deployment target is WSL2 with DDEV; Codex, Cursor,
and OpenCode are the first planned integrations.

The repository includes the Phase 1 enforcement core defined in [PLAN.md](PLAN.md):
versioned canonical requests, deterministic layered policy, lexical path
normalization, and immutable protection for the initial sensitive read and
managed-code write boundaries. Agent-native adapters are introduced in later
phases. The architecture and security model are specified in
[DESIGN.md](DESIGN.md).

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
daguard doctor codex config/codex/hooks.json
```

Policy precedence is `built-in deny > organization > project > default`, and
decision strength is `deny > ask > allow`. Project policy may add only denial
rules and deny-path patterns; it cannot set defaults, declare writable paths, or
add allow/ask rules. Missing or invalid policy passed with `--policy` is a
configuration error and never emits an allow decision.

Documented optional policy fields default safely when absent. Unknown fields are
rejected so a misspelled mandatory setting cannot silently weaken enforcement.

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

## Development

Install [`rustup`](https://rustup.rs/) and clone the repository. The checked-in
`rust-toolchain.toml` selects the exact compiler and required components.

```bash
cargo build --locked
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
```

Normal end-user installation will use a packaged native executable and will not
require Rust or Cargo.

Production dependencies are intentionally limited to `serde`/`serde_json` for
typed JSON and `globset` for mature path-pattern matching. They are compiled into
the binary, pinned by `Cargo.lock`, and checked by the CI vulnerability and
license jobs.

## Security

Do not report vulnerabilities in a public issue. See [SECURITY.md](SECURITY.md)
for the reporting process.

## License

Licensed under the [MIT License](LICENSE).
