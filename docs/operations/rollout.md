# Managed WSL rollout and support

This runbook is for the organization operator deploying Drupal Agent Guard to
WSL developers. Do not begin the mandatory rollout until the Phase 10 pilot has
recorded acceptable false positives, unknown-tool handling, performance, and
adapter compatibility for the versions the organization will deploy.

## Responsibilities and change control

The deploying organization must assign people to these roles before rollout:

| Role | Responsibility |
|---|---|
| Policy owner | Own `/etc/daguard/policy.json`, accept pilot results and approve rollout or rollback. |
| Security reviewer | Review every change to built-in rules, mandatory policy, policy precedence, adapters, shell/path parsing, and managed hook templates. |
| Release operator | Verify provenance and checksums, install or roll back immutable bundles, and retain the previous verified bundle. |
| Agent compatibility owner | Run fixture, bridge, and live allow/deny tests before a centrally managed Codex, Cursor, or OpenCode upgrade. |
| Support owner | Triage denials by rule ID, gather sanitized reproductions, and escalate policy changes to the policy owner. |

One person may hold more than one role, but the author of a security-rule change
must not be its only reviewer. A security-rule change requires approval from the
policy owner and an independent security reviewer. It must include a direct
match, an evasive variant where applicable, and a nearby safe-operation test.
Emergency changes follow the same review requirement; use rollback when review
cannot be completed safely.

Record the assigned people and escalation channel in the organization's private
operations system. Do not put personal contact details or private incident data
in the release bundle.

## Installation

1. Obtain the versioned
   `daguard-<version>-x86_64-unknown-linux-musl.tar.gz`, release `SHA256SUMS`,
   and GitHub provenance attestation from the trusted release channel.
2. Verify the attestation against the expected repository and workflow identity,
   then verify the archive with `sha256sum --check SHA256SUMS`.
3. Extract the archive and inspect its `release.json`, inventories, and bundled
   documentation.
4. Install the root-owned binary and policy:

   ```bash
   sudo ./install.sh --managed
   ```

5. Centrally deploy the relevant templates under `config/`. Keep their absolute
   `/usr/local/bin/daguard` and `/etc/daguard/policy.json` paths and prevent
   repository configuration from replacing the managed hooks where the agent
   supports that control.
6. For each configured adapter, run its `daguard doctor <adapter> <path>` check.
   Then run:

   ```bash
   daguard doctor --managed --policy /etc/daguard/policy.json
   ```

7. Run one harmless allowed operation and one harmless denied read of a
   nonexistent path ending in `sites/default/settings.php` through the live
   agent. A configuration parse or `doctor` result alone does not prove that the
   agent blocks tool execution.
8. Record the release version, policy fingerprint, agent versions, test result,
   operator, and time in the organization's deployment record.

The managed layout is `/usr/local/bin/daguard`, `/etc/daguard/`, and
`/usr/local/share/daguard/opencode/`. These paths must remain root-owned and not
group/other-writable. Audit logs remain developer-owned and must not contain raw
commands, paths, payloads, or secrets.

## Upgrade

Keep the current and previous verified immutable bundles. Review release notes,
policy changes, adapter compatibility, and the rule catalog before upgrading.
Run the full automated suite and live compatibility checks for centrally
deployed agent versions. Then run the newer bundle's installer:

```bash
sudo ./install.sh --managed
```

The existing mandatory policy is preserved by default. Use
`--replace-policy` only after the policy owner approves the bundled policy as a
separate security change. Repeat `doctor` and live allow/deny tests after every
upgrade. Stop rollout on any hook bypass, unexpected allow, integrity error, or
adapter incompatibility.

## Rollback

Rollback is the response to a broken release or adapter integration. It is not
a mechanism for bypassing a denial.

1. Stop the rollout and preserve sanitized diagnostics and audit metadata.
2. Re-run `install.sh --managed` from the previous verified immutable bundle.
   The installed organization policy is preserved unless the policy owner has
   separately approved restoring a previous policy with `--replace-policy`.
3. Re-deploy the matching agent templates if their contract changed.
4. Run managed `doctor` checks and live allow/deny tests.
5. Record the rollback and affected release/agent versions.

If no known-good combination can enforce the hooks, disable the affected
agent's tool execution or withdraw that agent version from managed use. Do not
switch mandatory rules to audit-only to restore availability.

## Support and troubleshooting

Start with the non-sensitive rule ID and these commands:

```bash
daguard version
daguard explain RULE_ID
daguard doctor --managed --policy /etc/daguard/policy.json
```

For adapter failures, run the adapter-specific `doctor` check and compare the
installed agent version with the tested versions in the main README. Confirm
that the hook covers all tools, uses absolute managed paths, and is fail closed
where supported. For integrity failures, compare fingerprints with the trusted
deployment record; do not regenerate a manifest merely to silence the error.

For a suspected false positive, capture only the rule ID, guard/agent versions,
capability, and a minimal synthetic reproduction. Never collect the protected
file, raw secret, complete payload, database result, or private command. The
support owner sends the sanitized case to the policy owner. Policy changes use
the review and regression requirements above.

Security vulnerabilities follow `SECURITY.md`, not the ordinary support path.

## Break-glass decision

Version 1 deliberately has no break-glass mechanism. The current rollout has no
concrete operational requirement that justifies bypassing mandatory controls,
and an agent-accessible environment variable, file, CLI flag, or project policy
would weaken the boundary. There is therefore no bypass token, override command,
or silent exception path to document or test.

Human operators use the rollback process for software failures and perform a
blocked operation manually outside the agent when it is legitimately required.
Adding break-glass later is an architectural and security-contract change: it
requires an explicit owner decision, a `DESIGN.md` update, time-bounded and
scoped authorization, conspicuous audit events, and expiry/scope tests before
implementation.
