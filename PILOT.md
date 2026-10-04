# Non-managed WSL pilot

This setup installs `daguard` in the WSL user's home directory. It is suitable
for a pilot, but it is not a strong security boundary: an agent running as the
same user can modify the binary, policy, or hook configuration.

## Install

Use a verified `x86_64-unknown-linux-musl` release bundle inside WSL:

```bash
sha256sum --check SHA256SUMS
tar -xzf daguard-<version>-x86_64-unknown-linux-musl.tar.gz
cd daguard-<version>-x86_64-unknown-linux-musl
./install.sh --user
install -d -m 700 ~/.local/state/daguard
```

The binary, policy, and OpenCode plugin are installed under `~/.local/bin`,
`~/.config/daguard`, and `~/.local/share/daguard`. In the examples below,
replace `USER` with your WSL username; hooks require absolute paths and do not
expand `~` or environment variables. Merge these entries with existing agent
configuration instead of overwriting unrelated settings.

## Codex

Add to `~/.codex/hooks.json` and approve the non-managed hook when Codex asks:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "*",
      "hooks": [{
        "type": "command",
        "command": "/home/USER/.local/bin/daguard --adapter codex --event pre-tool --policy /home/USER/.config/daguard/policy.json --audit-log /home/USER/.local/state/daguard/audit.jsonl",
        "timeout": 5
      }]
    }],
    "PostToolUse": [{
      "matcher": "*",
      "hooks": [{
        "type": "command",
        "command": "/home/USER/.local/bin/daguard --adapter codex --event post-tool --policy /home/USER/.config/daguard/policy.json --audit-log /home/USER/.local/state/daguard/audit.jsonl",
        "timeout": 5
      }]
    }]
  }
}
```

## Cursor

Add to `~/.cursor/hooks.json`:

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [{
      "command": "/home/USER/.local/bin/daguard --adapter cursor --event pre-tool --policy /home/USER/.config/daguard/policy.json --audit-log /home/USER/.local/state/daguard/audit.jsonl",
      "matcher": "*",
      "timeout": 5,
      "failClosed": true
    }],
    "postToolUse": [{
      "command": "/home/USER/.local/bin/daguard --adapter cursor --event post-tool --policy /home/USER/.config/daguard/policy.json --audit-log /home/USER/.local/state/daguard/audit.jsonl",
      "matcher": "*",
      "timeout": 5,
      "failClosed": true
    }]
  }
}
```

## OpenCode

Add to `~/.config/opencode/opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [{
    "package": "/home/USER/.local/share/daguard/opencode",
    "options": {
      "guard": "/home/USER/.local/bin/daguard",
      "policy": "/home/USER/.config/daguard/policy.json",
      "auditLog": "/home/USER/.local/state/daguard/audit.jsonl",
      "timeoutMs": 5000,
      "managed": false
    }
  }]
}
```

Reload OpenCode after changing its configuration.

## Verify

```bash
~/.local/bin/daguard doctor \
  --policy ~/.config/daguard/policy.json \
  --audit-log ~/.local/state/daguard/audit.jsonl
```

Then test one harmless allowed operation and a read of a nonexistent path ending
in `sites/default/settings.php`. The latter must be blocked with rule
`drupal.secret.settings_php` before the agent attempts the read. Do not use a
real secret or destructive command for testing.
