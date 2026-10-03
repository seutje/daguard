# OpenCode fixture provenance

These sanitized fixtures represent the OpenCode v2 `execute.before` event as
serialized by `integrations/opencode/daguard-plugin.js`. They were checked
against OpenCode CLI v2.0.22 and the official v2 plugin documentation on
2026-10-03. OpenCode v2 exposes `event.tool`, `event.input`, `event.sessionID`,
and `event.id`; the bridge supplies the plugin location as `cwd`.

OpenCode Desktop was not available in the Phase 6 development environment, so
no desktop-version compatibility is claimed. Before an OpenCode upgrade, rerun
the Rust golden tests, the bridge tests, and a live denied-tool smoke test.
