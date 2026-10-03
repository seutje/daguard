# macOS preview installation and validation

Native macOS packages are built and smoke-tested in CI for Apple Silicon and
Intel. They remain **preview artifacts**, not declared supported agent
integrations, until the organization records live allow/deny tests for each
agent version and architecture it intends to deploy.

Intel packages are retained as a transitional compatibility artifact for team
members who still use Intel Macs. Reassess that need before GitHub's hosted
Intel macOS runner reaches its announced end of availability in August 2027.

## Install or upgrade

Obtain the archive matching `uname -m` from the trusted release channel:

```text
arm64  -> daguard-<version>-aarch64-apple-darwin.tar.gz
x86_64 -> daguard-<version>-x86_64-apple-darwin.tar.gz
```

Verify the release provenance and the archive entry in `SHA256SUMS` before
extracting it. The bundled installer verifies every extracted file and rejects
an archive for the wrong architecture.

For a user-owned preview:

```bash
tar -xzf daguard-<version>-<target>.tar.gz
cd daguard-<version>-<target>
./install.sh --user
```

This uses `~/.local/bin/daguard`, `~/.config/daguard/`, and
`~/.local/share/daguard/`. Add `~/.local/bin` to the agent's `PATH` if needed.
The user-owned layout is not a strong boundary against an agent running as the
same account.

For a root-owned managed preview:

```bash
sudo ./install.sh --managed
```

This uses `/usr/local/bin/daguard`, `/etc/daguard/`, and
`/usr/local/share/daguard/`, owned by `root:wheel`. Existing policy is preserved
unless `--replace-policy` is explicitly supplied. No Homebrew package or
language runtime is installed or required.

Deploy the same absolute-path hook templates as Linux. Then run the applicable
adapter diagnostic and:

```bash
/usr/local/bin/daguard doctor --managed --policy /etc/daguard/policy.json
```

For every claimed agent version, use a disposable project to verify one
ordinary allowed operation and one harmless denied read of a nonexistent path
ending in `sites/default/settings.php`. Record the macOS version, hardware
architecture, guard artifact, agent version, and results. CI adapter fixtures
do not replace this live enforcement test.

The release workflow does not perform Developer ID signing or Apple
notarization because no organizational signing identity or distribution policy
is configured. Before broad managed distribution, the release owner must decide
whether Gatekeeper policy requires both, provision secrets through the trusted
release environment, and verify the signed/notarized archive on a clean Mac.

## Uninstall

Preserve organization policy by default:

```bash
./uninstall.sh --user
sudo ./uninstall.sh --managed
```

Add `--remove-policy` only when the policy owner intends to delete the installed
policy. The uninstaller removes the binary, release metadata, checksum baseline,
and OpenCode bridge; it does not edit agent configuration. Remove centrally
deployed hooks separately so they cannot continue invoking a missing guard.
