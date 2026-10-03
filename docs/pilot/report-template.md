# Pilot evidence template

Status: NOT RUN. Replace placeholders only with measured or reviewed facts.
Keep this report local until the organization approves sharing its summary.

- Pilot owner / reviewers: [roles or approved aliases]
- Window / participating developer count: [dates, count]
- Agents and exact versions / number of participants: [Codex, Cursor, OpenCode]
- Guard release / Git SHA / policy SHA-256 / policy mode: [verified values]
- Environment: [WSL distribution, architecture, Linux filesystem or mounted drive]
- Accepted false-positive threshold / minimum coverage / latency budget: [agreed values]

| Workflow | Agent/version | Runs reviewed | Result | Safe reproduction reference |
| --- | --- | ---: | --- | --- |
| Custom module/theme read and edit | pending | 0 | Not run | pending |
| DDEV lifecycle and describe | pending | 0 | Not run | pending |
| Drush cache rebuild/status and multisite work | pending | 0 | Not run | pending |
| Composer validate/audit | pending | 0 | Not run | pending |
| Git status/diff | pending | 0 | Not run | pending |
| Test/static-analysis tools | pending | 0 | Not run | pending |
| Host prevents synthetic protected read/write | pending | 0 | Not run | pending |

| Rule ID | Reviewed denies/would-denies | Confirmed false positives | Disposition / synthetic regression |
| --- | ---: | ---: | --- |
| pending | 0 | 0 | Unreviewed |

- Unknown tools: [approved tool names, capabilities, safe synthetic fixtures,
  classification or explicit conservative handling; no raw arguments]
- Compatibility failures: [host/version, missing interception/schema/timeout,
  safe reproduction and resolution]
- Performance: [release identity, samples, P50/P95/P99, audit/managed settings,
  guard measurements versus host overhead, reference to local sanitized artifact]
- Added sensitive paths/tables: [approved synthetic pattern/table references and tests]
- Accepted risks: [operation, rationale, owner, review date; no blanket exemption]
- Final review: [each exit criterion's evidence, unresolved follow-ups, reviewers]
- Enforcement restoration: [policy hash, doctor mode, integrity baseline updated,
  hook allow/deny verification]
