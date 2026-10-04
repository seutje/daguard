# Sensitive-result containment

Phase 15 adds a separate boundary after a tool runs and before its output is
released to an agent. A path is **pre-context intercepting** only when daguard
receives the complete raw result privately, decides `allow`, `sanitize`, or
`block`, and releases at most one safe body before the agent/model can receive
it. Seeing a result in `PostToolUse`, `postToolUse`, or `execute.after` after the
host has delivered it is observation, not containment.

## Supported boundaries

The native result hooks tested or documented for Codex CLI 0.160.0, OpenCode
2.0.22, and the currently unverified Cursor application path remain
`observe_only`. They update Phase 14 metadata-only taint but make no
non-disclosure claim. `daguard capabilities` emits the versioned per-agent/tool
matrix, including pre-call denial, input rewrite, output replacement, guarded
execution, MCP proxy, security mode, and minimum tested version. An agent update
must rerun live compatibility/canary tests; a previously safe path must never be
silently changed to `observe_only`.

Two opt-in paths provide a real containment boundary:

- `daguard exec [OPTIONS] -- COMMAND [ARG ...]` directly spawns an approved
  command without shell interpolation, privately captures stdout and stderr,
  scans both completely, and only then releases safe output. A shell is used
  only when it is itself the explicitly requested command.
- `daguard mcp-proxy [OPTIONS] -- SERVER [ARG ...]` mediates newline-delimited
  JSON-RPC MCP traffic, applies the existing pre-tool policy to requests,
  recursively sanitizes textual/structured responses, and blocks malformed,
  oversized, or unsupported binary/attachment results.

Agents do not use those paths automatically. Operators must configure a shell
tool to invoke `daguard exec`, or configure an MCP server command through
`daguard mcp-proxy`, before claiming containment. Native file-read tools remain
observe-only; known sensitive files continue to be denied before execution and
are not made readable merely because a scanner exists.

Examples:

```bash
daguard exec -- ddev drush status
daguard exec --timeout-seconds 60 -- ddev drush sql:query \
  'SELECT nid, title FROM node_field_data LIMIT 10'
daguard mcp-proxy -- /trusted/path/to/mcp-server --stdio
daguard inspect-result --policy /etc/daguard/policy.json < synthetic-result.txt
```

`exec` preserves an ordinary child exit code after safe release. Timeout uses
124; blocked/unscannable output uses 125. It buffers before release, creates no
raw temporary file, and never streams an unverified prefix. On Unix the child is
placed in a dedicated process group; the guard forwards `SIGINT`, `SIGTERM`, and
`SIGHUP`, and timeout/cleanup kills the complete group. The default timeout is
30 seconds and may be set from 1 through 3600 seconds.

The MCP proxy currently supports the newline-delimited JSON-RPC transport used
by stdio MCP servers. It does not claim compatibility with HTTP/SSE or
Content-Length-framed transports. Batched client requests are rejected rather
than forwarded without per-call policy; batched responses are scanned as one
structured result. Server stderr is buffered and sanitized before release. A
malformed response becomes a safe JSON-RPC error.

## Native replacement compatibility experiments

The current upstream [Codex hook contract](https://learn.chatgpt.com/docs/hooks)
describes blocking feedback that replaces a completed result, including distinct
behavior for nested code-mode calls. The [OpenCode v2 tool hooks](https://opencode.ai/v2/docs/build/plugins)
permit completed-result mutation. These are candidate APIs; daguard still
declares native hooks `observe_only` until actual-host containment is proven.

Run each experiment in a separate synthetic workspace and conversation, with
no production credentials or personal data. A producer returns a deterministic
fake password marker; the hook returns only static blocking feedback or a
sanitized replacement. Keep native file reads, shell calls, MCP replies and
custom tools separate because their delivery semantics may differ.

| Candidate | Required variations | Evidence needed |
|---|---|---|
| Codex `PostToolUse` block | Ordinary call, nested code-mode promise, producer error, callback crash/timeout, malformed response | Raw fake marker absent from model requests, running script results and model-visible transcript; failure paths block delivery. |
| OpenCode v2 completed-result mutation | Text, structured result, producer error, multiple hooks, callback failure | Only replacement reaches model requests/transcript; original metadata, error bodies and later hooks cannot reintroduce the marker. |
| Cursor | Exact installed API and version | Establish a synchronous replacement contract first; observe-only hooks are insufficient. |

Record host/build/version, tool category, effective immutable configuration,
guard/policy hashes and pass/fail metadata. Check private test transcripts in
memory; commit only bounded marker-absence results and sanitized failure reasons.
Inspect audit/tracing/error paths too. A model saying it did not see a marker,
or an observer receiving a result, does not prove non-delivery. Do not enable
native replacement or check Phase 15 transcript gates until these cases pass.

## Scanner contract and limits

Each stdout stream, stderr stream, standalone result, or MCP message is limited
to 1 MiB. A scan has a one-second fail-closed budget and at most 256 findings.
Guarded stdout and stderr may therefore retain about 2 MiB of raw bytes in
memory, plus bounded sanitizer/JSON working storage; the design working-memory
budget is 32 MiB per invocation. Oversize, invalid UTF-8, malformed JSON that
looks structured, finding overflow, time-budget exhaustion, or sanitization
failure becomes `block`. Raw scanner input stays in process memory and is never
accepted by audit/state APIs.

Detection uses finite byte scans—no backtracking regular expressions—and covers
PEM private keys, JWTs, Authorization/Bearer values, credential-bearing database
URLs, password/secret/token assignments, GitHub/GitLab, AWS, Stripe, Slack, and
OAuth token forms. It recognizes email, context-labelled phone/date/address
values, configured personal IP addresses, Luhn-valid payment cards, checksum-
valid IBANs, Drupal account/authentication fields, Webform/comment fields, and
Commerce customer/payment fields. ANSI sequences are removed for matching while
offsets remain tied to the original output; complete buffering covers matches
split across producer chunks. Entropy-only detection was considered and is
disabled because its false-positive rate is not acceptable without stronger
context.

JSON is parsed recursively and reserialized as valid JSON. Plain text,
dotenv/key-value output, pipe/tabular SQL/CLI output, and ANSI-decorated output
preserve safe context while values are replaced with canonical category
placeholders. Overlapping ranges are merged before redaction. Findings contain
only detector ID, Phase 14 category, offsets, and confidence—never the matched
value.

Policy schema 3 can add `result.secret_prefixes`,
`result.sensitive_fields` (mapped to an existing Phase 14 category), and
`result.ip_addresses_are_personal`. Project policy may add these controls; it
cannot remove organization detectors. Generic email/IP recognition is medium
confidence and may produce false positives. Structured field matches, validated
financial formats, and recognizable credential formats are high confidence.
Unknown representations can still evade detection, so sensitive source denials
remain the primary control.

The shipped schema-3 policy enables personal-IP handling and adds common npm,
PyPI, DigitalOcean, HashiCorp Vault, and Hugging Face token prefixes. It also
classifies common identity, customer, account, order, and case-reference fields.
Organizations should review these defaults for their data model and add local
prefixes or field names rather than placing actual sensitive values in policy.

The optimized Phase 15 smoke benchmark on the 2026-10-04 WSL2 development host
measured a 4.1 µs P95 common JSON result scan and an 8.5 ms P95 scan/sanitize of
a 512 KiB synthetic SQL table (three recorded samples after 20 warmups). These
are development evidence, not a cross-machine release gate; rerun the existing
performance harness on representative team hardware.

## Taint and audit behavior

Detected categories use the exact Phase 14 taxonomy. Sanitized and blocked
results both taint a supplied session because the underlying operation accessed
the protected value. Audit schema 4 records only result decision metadata,
source/detector IDs, categories, pseudonymous session IDs, and exit codes. It
cannot accept a raw or sanitized body. Use deterministic fake
canaries and reserved domains such as `example.test` for compatibility tests.

Before declaring an agent/version supported, run a live guarded-shell and MCP
canary test and inspect the actual model transcript. Repository tests prove the
guard process and proxy output do not contain raw canaries; they cannot prove a
host route was configured or that a vendor did not bypass it.

Session-bound exec/MCP routes require a trusted host-provided pair:
`--integration-agent codex|cursor|opencode --session-id ID`. The state and audit
identity matches native hooks, preserving isolation between unrelated agents.
Supplying only one flag fails closed. Host tool definitions must pin the agent,
session, state directory and policy outside model-controlled arguments; a model
must never choose these values. Without the pair a route is standalone and makes
no conversation-wide taint claim. Native shell analysis unwraps daguard exec
commands so wrapping a transfer does not hide its sink from pre-tool checks.

MCP stdio supervision uses bounded reader queues (four frames), 64 pending
requests, safe bounded IDs and JSON-RPC 2.0 single-object envelopes. Replies must
match an authorized request ID; method and metadata-only source classifications
are retained until completion. Known sensitive-source replies are blocked.
Tools/resources/prompts/completions apply outbound policy; initialize, ping,
listing, logging controls and supported notifications use validated metadata
rules. JSON Schema labels remain intact, while secret-bearing metadata, defaults
and examples cannot be safely rewritten and cause blocking.

Unknown client methods, batches, server sampling/elicitation requests and
unsupported notifications are denied. Server ping requests are correlated with
client replies. Cancellation keeps bounded tombstones and discards late replies;
IDs cannot be reused while their tombstones remain. Partial/oversized frames,
unsolicited replies, reader failures and expired outstanding requests terminate
the gateway even when the client stays connected. `--timeout-seconds` bounds
requests, partial frames and shutdown (default 30 seconds). Idle live sessions
without outstanding work are allowed. Linux upstream pipe writes are nonblocking
and timed. Stderr remains private until upstream completion, with a total
1 MiB lifetime cap; overflow terminates the gateway rather than closing only
its diagnostic pipe. OS metadata writes/downstream output backpressure and
portable blocking-reader threads remain platform limits. No live vendor-agent
containment certification is implied by these synthetic protocol tests.

The supervised MCP route currently requires Unix; native Windows fails explicitly
with unsupported instead of using a blocking forwarding fallback.
