# Rule catalog

Rule IDs are stable support and audit identifiers. `daguard explain <rule-id>`
is the authoritative installed explanation for registered core rules. Deny is
stronger than ask, and adapters without stable approval support render ask as a
deny. Organization and project policies may add IDs; their descriptions belong
in the organization's private policy catalog.

## Mandatory rollout rules

| Rule ID | Effect | Severity | Meaning |
|---|---|---|---|
| `drupal.secret.env` | deny | critical | Read of `.env` or `.env.*`. |
| `composer.secret.auth_json` | deny | critical | Read of Composer authentication files. |
| `drupal.secret.settings_php` | deny | critical | Read of Drupal or environment `settings.php` files. |
| `filesystem.secret.private_key` | deny | critical | Read of `.pem` or `.key` private-key material. |
| `filesystem.write.core` | deny | high | Write to Drupal core. |
| `filesystem.write.vendor` | deny | high | Write to Composer vendor code. |
| `filesystem.write.contrib_module` | deny | high | Write to a contributed module. |
| `filesystem.write.contrib_theme` | deny | high | Write to a contributed theme. |
| `shell.drush.eval` | deny | critical | Drush PHP evaluation, including aliases and DDEV wrappers. |
| `sql.mutation.<keyword>` | deny | critical | SQL `insert`, `update`, `delete`, `drop`, `alter`, `truncate`, `replace`, `create`, `grant`, or `revoke`. |
| `git.force_push` | deny | high | Git force push, including `-f` and `--force=<value>`. |

These protections are built in and cannot be placed in organization
`audit_only_rules` or weakened by project policy.

## Other registered core rules

| Rule ID | Effect | Meaning |
|---|---|---|
| `shell.nesting_limit` | deny | Nested shell wrappers exceed bounded analysis. |
| `shell.ambiguous` | deny | Shell syntax cannot be classified safely. |
| `shell.privilege_escalation` | deny | Privilege escalation such as `sudo`. |
| `shell.language_eval` | deny | Uninspectable arbitrary language evaluation. |
| `shell.drush.sql_dump` | deny | Drush database dump. |
| `shell.drush.sql_cli` | deny | Interactive Drush SQL. |
| `drush.mutation.review` | ask | State-changing Drush operation needs review. |
| `ddev.shell_escape` | deny | Unrestricted DDEV shell. |
| `ddev.database_transfer` | deny | DDEV database import or export. |
| `ddev.sql.interactive` | deny | Interactive DDEV SQL. |
| `sql.ambiguous` | deny | SQL is malformed, unsupported, or too large. |
| `sql.read.sensitive_table` | deny | Read of a built-in or configured sensitive table. |
| `git.credential_config` | deny | Agent-driven Git credential configuration. |
| `git.write.review` | ask | Git commit or ordinary push needs review. |
| `composer.dependencies.modify` | ask | Composer dependency mutation needs review. |
| `composer.scripts.execute` | ask | Composer script execution needs review. |

## Policy and guard rules

Organization and project file-pattern denials use
`organization.path.deny_read`, `organization.path.deny_write`,
`project.path.deny_read`, and `project.path.deny_write`. Custom policy rules use
the stable ID defined in that policy. Normal successful fall-through uses
`default.no_matching_rule` internally.

Recoverable internal failures rendered through a native adapter use
`guard.evaluation_error`. Malformed canonical input exits with status 4, while
policy and managed-installation configuration failures exit with status 3;
neither path emits an allow decision. Investigate configuration or input
compatibility rather than adding an exception.
