# Cursor hook fixtures

These synthetic, sanitized fixtures follow Cursor's native `preToolUse` and
`postToolUse` input
and response contract in the official Cursor Hooks documentation retrieved on
2026-10-04. They contain no production paths, credentials, or captured user
content; the post-tool fixture uses only a deterministic fake canary.

Cursor is not installed in the development environment used for Phase 4, so no
specific Cursor application version is claimed as live-tested. Before release,
run the compatibility suite against the centrally deployed Cursor version and
record that version here.
