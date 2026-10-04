# Phase 10 pilot runbook

Phase 10 needs real developers and supported agent hosts. Automated fixture
replay demonstrates classifier behavior; it cannot establish a team false-positive
rate or prove a host actually prevented execution. Keep Phase 10 deployment,
tuning and exit checkboxes open until the team records that evidence.

## Prepare the pilot

The pilot owner should choose a small group covering Codex, Cursor and, if used,
OpenCode, Drupal multisite work, custom modules/themes, and ordinary DDEV tasks.
Record the installed agent versions, guard release/build identity, policy hash,
WSL distribution, and whether the checkout is on the Linux filesystem. Use
synthetic development data and exclude production credentials. Agree on the
pilot duration, minimum workflow coverage, acceptable false-positive rate, and
latency budget before collecting results. Existing performance budgets are in
[the benchmark methodology](../performance/README.md).

Use a CI-built static WSL release containing this change. Follow the existing
[installation instructions](../../README.md) and agent templates. The pilot
never installs a compiler or another language runtime on workstations. Set up
an owner-only local audit directory, for example:

```bash
install -d -m 700 ~/.local/state/daguard
```

The shipped schema-1 policy remains fully enforcing. To observe a **new candidate
organization rule**, the policy owner copies the existing organization policy,
changes `schema` to `2`, adds the candidate to `rules`, and lists its ID in
`audit_only_rules`. Preserve all existing mandatory settings. For example, these
are the additional fields/rule in a synthetic policy, not a replacement for the
shipped policy:

```json
{
  "schema": 2,
  "audit_only_rules": ["pilot.candidate.custom_write"],
  "rules": [{
    "id": "pilot.candidate.custom_write",
    "description": "Candidate restriction on a synthetic custom module.",
    "effect": "deny",
    "severity": "medium",
    "match": {
      "capabilities": ["file_write"],
      "paths": ["**/web/modules/custom/pilot/**"]
    }
  }]
}
```

Only named, non-built-in organization deny/ask rules can be observed. Every
other organization rule, every project rule, path deny lists, unknown-tool
defaults, configured sensitive SQL tables, and built-in protections stay enforced.
A schema-1 policy cannot opt in; project policy cannot opt in. Invalid/duplicate
candidate IDs fail validation. There is no CLI or environment switch that turns
off mandatory protection. This deliberately supports audit-only **candidate
rules**, not unrestricted execution of would-be mandatory denials.

Lint the resulting policy and inspect its mode before deploying:

```bash
/usr/local/bin/daguard policy lint /etc/daguard/policy.json
/usr/local/bin/daguard doctor --managed --policy /etc/daguard/policy.json \
  --audit-log ~/.local/state/daguard/audit.jsonl
```

For a user-scoped pilot use the installed user binary/policy and omit `--managed`.
User-scoped files do not provide managed tamper protection. A trusted administrator
must install changes to managed policy and update the installation integrity
manifest as described in the existing installation guidance.

Add `--audit-log` with an **absolute path** to each Codex/Cursor hook invocation.
For OpenCode set the bridge option `auditLog` to the same absolute destination;
the bridge already forwards it to the guard. Keep existing fail-closed settings,
trusted binary/policy paths, and all-tool matchers. Missing or unwritable logging
blocks a pilot invocation. Each invocation reports candidate audit-only mode on
stderr; `doctor` reports the mode; machine-readable native responses keep their
existing schemas. OpenCode may not display guard stderr, so verify its log and
`doctor` output explicitly.

## Run and record workflows

Each participant should use their actual agent for representative tasks:

- Read and edit synthetic custom module/theme code; read core APIs for reference.
- Run `git status`, `git diff`, `ddev start`, `ddev describe`, `ddev drush cr`,
  `ddev drush status`, `ddev composer validate`, and `ddev composer audit`.
- Exercise their normal test/static-analysis tools and multisite paths.
- In an isolated synthetic checkout, request a protected-file read and protected
  write and confirm the host prevents execution. Use the existing host-version
  fixture guidance; a classifier deny alone does not prove interception.
- Record unknown tools, erroneous denials, missing hooks, malformed responses,
  timeouts, and other compatibility failures by rule ID and host version.

Do not execute destructive commands merely to test blocking. Existing regression
fixtures cover command and SQL mutation classification without executing them.
Use [the live WSL/DDEV harness](../../tests/wsl_ddev_live.sh) only as documented,
and record live tests separately from synthetic classification.

Audit schema 3 retains the schema-2 `mode`, evaluated `decision`/`rule_id`, and actual
canonical `enforcement_decision`/`enforcement_rule_id`. A would-deny candidate
allowed to execute has `decision: deny` and `enforcement_decision: allow`.
If a mandatory deny also matches, `enforcement_decision` remains `deny`.
Canonical `ask` is rendered as native deny by current adapters. Logs retain only
the winning evaluated and enforced rule, not every matching candidate. They omit
commands, paths, content, reasons, evidence and raw identifiers. Mixed retained
schema-1/schema-2/schema-3 logs must be interpreted by their schema version.

The log cannot determine whether a denial was a false positive, identify an
unknown tool's name, measure host latency, or identify the installed agent version
when that version is absent from the payload. Collect those facts separately
using the [report template](report-template.md). Never copy raw tool input,
file contents, SQL rows, credentials, private paths, or transcripts into reports.
Locally reproduce issues with synthetic examples instead. Keep logs owner-only,
rotate them as documented, and collect/share only approved summaries.

Measure latency with the existing release benchmark harness. It measures guard
classification, not actual DDEV execution or host-hook overhead; separately
record host timeouts/latency and the deployed audit/managed configuration. The
Phase 9 reference measurement is not evidence of this group's pilot performance.

## Review and finish

Review every reported false positive by rule ID. Distinguish expected security
denials from ordinary safe work that was incorrectly blocked. Use an agreed
denominator: reviewed erroneous denials divided by reviewed deny/would-deny
operations, with counts and workflow coverage reported alongside it. A small
zero-failure sample alone is not acceptance evidence.

For each reproduced problem, add a failing synthetic regression before changing
policy or analyzer behavior. Include a variant and a nearby safe case. Candidate
rules can be refined or removed by their owner; project policy cannot weaken
mandatory rules. Built-in protections must not be bypassed to improve metrics.
Add team-identified sensitive tables to `sql.sensitive_tables` and sensitive
paths to the enforcing deny lists, with tests. Record the owner and accepted risk
for operations intentionally left allowed. Follow SECURITY.md for private issues.

At pilot end, the policy owner removes the accepted IDs from `audit_only_rules`
(or removes the field entirely), lints the policy, updates the trusted integrity
baseline, checks `doctor` reports enforcement, and verifies the hooks with
synthetic allow/deny requests. Unaccepted candidates are revised or removed.
Proceed to Phase 11 only after real group coverage, reviewed false positives,
unknown-tool handling, performance, and host compatibility meet the agreed gates.
Do not declare this phase complete from automated tests alone.
