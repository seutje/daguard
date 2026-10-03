# Security Policy

## Supported versions

Drupal Agent Guard has not reached its first release. Until a supported release
is published, security fixes are made on the default branch only.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's **Report a
vulnerability** feature in the repository Security tab. Do not open a public
issue or include secrets, credentials, customer data, or private exploit payloads
in a report.

Include a concise description, affected version or commit, security impact, and
minimal synthetic reproduction details. Maintainers will acknowledge the report,
coordinate remediation and disclosure, and request additional information when
needed.

If private vulnerability reporting is unavailable, contact the repository owner
through an established private organizational channel and ask for a secure
reporting route. Do not send vulnerability details over a public channel.

## Enforcement and tamper limits

Managed WSL hooks require root-controlled binary/policy paths outside projects;
`doctor` can compare installed hashes to a trusted installation manifest. A
user-owned pilot does not provide equivalent tamper protection. Neither mode
protects against root, malicious local users controlling agent configuration,
hook bypass, or all filesystem replacement races. Request path matching remains
lexical in v1, so symlink aliases require OS permissions. See DESIGN.md for the
full threat model and host fail-open limitations.

Recoverable panics and malformed input produce native deny responses. Process
termination and allocation/stack failures depend on host fail-closed behavior.
Parser fuzzing and synthetic security regression tests are documented in
[fuzz/README.md](fuzz/README.md); keep private reproductions out of public corpora.
