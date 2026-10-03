# Drupal Agent Guard

Drupal Agent Guard (`daguard`) is a security-sensitive native executable that will
intercept coding-agent tool calls and apply shared, deterministic policy before an
operation runs. Its primary deployment target is WSL2 with DDEV; Codex, Cursor,
and OpenCode are the first planned integrations.

The repository is currently at the Phase 0 foundation defined in [PLAN.md](PLAN.md).
The executable does not enforce policy yet. The architecture and security model
are specified in [DESIGN.md](DESIGN.md).

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

## Security

Do not report vulnerabilities in a public issue. See [SECURITY.md](SECURITY.md)
for the reporting process.

## License

Licensed under the [MIT License](LICENSE).
