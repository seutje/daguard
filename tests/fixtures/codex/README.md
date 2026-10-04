# Codex hook fixtures

These sanitized fixtures target Codex CLI `0.160.0` and the official
`PreToolUse` and `PostToolUse` command-hook contracts retrieved on 2026-10-04 from:

<https://learn.chatgpt.com/docs/hooks>

Identifiers and paths are synthetic. The fixtures contain no transcript data,
credentials, production paths, or real tool output. The post-tool fixture uses
a deterministic fake canary to prove raw result omission. The local function-tool
fixture represents the documented generic local-tool hook path; availability of
individual tool names depends on the Codex surface and configuration.

Live denial was verified on 2026-10-03 with Codex CLI 0.160.0 by supplying the
hook through the invocation configuration layer and requesting one synthetic
`apply_patch` add under `web/core`. Codex reported the
`filesystem.write.core` denial, and the target file did not exist afterward.
The complementary custom-module patch completed without a hook-schema error,
The earlier interpretation that this confirmed the bare native allow response
is withdrawn: a VS Code deployment reported that bare
`permissionDecision: "allow"` is unsupported. Safe-call output now uses `{}`,
which leaves host permission checks unchanged. Deny output is unchanged. The
corrected safe-call response and deny interception must be live-tested on the
participant's exact IDE extension version; no such live verification is claimed
for this fix. Regression fixtures cover the exact empty-object response and
synthetic explicit `rg` reads of environment settings files.
