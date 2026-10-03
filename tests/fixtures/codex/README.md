# Codex hook fixtures

These sanitized fixtures target Codex CLI `0.160.0` and the official
`PreToolUse` command-hook contract retrieved on 2026-10-03 from:

<https://learn.chatgpt.com/docs/hooks>

Identifiers and paths are synthetic. The fixtures contain no transcript data,
credentials, production paths, or real tool output. The local function-tool
fixture represents the documented generic local-tool hook path; availability of
individual tool names depends on the Codex surface and configuration.

Live denial was verified on 2026-10-03 with Codex CLI 0.160.0 by supplying the
hook through the invocation configuration layer and requesting one synthetic
`apply_patch` add under `web/core`. Codex reported the
`filesystem.write.core` denial, and the target file did not exist afterward.
The complementary custom-module patch completed without a hook-schema error,
confirming the native allow response as well.
