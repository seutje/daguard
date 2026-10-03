#!/bin/sh
set -eu

bundle=${1:-}
[ -d "$bundle" ] || { echo "usage: release_install.sh BUNDLE_DIRECTORY" >&2; exit 2; }
bundle=$(CDPATH= cd -- "$bundle" && pwd)
work=$(mktemp -d)
cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

file_mode() {
    if stat -c '%a' "$1" >/dev/null 2>&1; then
        stat -c '%a' "$1"
    else
        stat -f '%Lp' "$1"
    fi
}

prefix=$work/user
"$bundle/install.sh" --user --bundle "$bundle" --user-prefix "$prefix"
binary=$prefix/bin/daguard
policy=$prefix/config/daguard/policy.json
[ -x "$binary" ]
[ -r "$policy" ]
[ -f "$prefix/share/daguard/opencode/index.js" ]
[ -f "$bundle/docs/operations/rollout.md" ]
[ -f "$bundle/docs/operations/rules.md" ]
[ "$(file_mode "$binary")" = 755 ]
[ "$(file_mode "$policy")" = 600 ]
expected_target=$(sed -n 's/.*"target":"\([^"]*\)".*/\1/p' "$bundle/release.json")
[ -n "$expected_target" ]
"$binary" version | grep -F "($expected_target)"
jq -e '.plugins | (length == 1 and (.[0].package | type == "string"))' \
    "$bundle/config/opencode/opencode.json" >/dev/null
opencode_config=$work/opencode.json
jq --arg package "$prefix/share/daguard/opencode" \
    --arg guard "$binary" \
    --arg policy "$policy" \
    '.plugins[0].package = $package |
     .plugins[0].options.guard = $guard |
     .plugins[0].options.policy = $policy |
     .plugins[0].options.managed = false' \
    "$bundle/config/opencode/opencode.json" > "$opencode_config"
"$binary" doctor opencode "$opencode_config"
"$binary" doctor --policy "$policy" \
    --audit-log "$prefix/config/daguard/audit.jsonl" \
    --opencode-config "$opencode_config"

evaluate_shell() {
    command=$1
    expected=$2
    jq -n --arg command "$command" '{
        protocol: 1,
        agent: "release-test",
        event: "pre_tool_use",
        cwd: "/workspace/project",
        tool: {native_name: "shell", capability: "shell_execute"},
        input: {},
        facts: {command: $command}
    }' | "$binary" check --policy "$policy" - | jq -e --arg expected "$expected" '.decision == $expected' >/dev/null
}

evaluate_path() {
    capability=$1
    path=$2
    expected_rule=$3
    jq -n --arg capability "$capability" --arg path "$path" '{
        protocol: 1,
        agent: "release-test",
        event: "pre_tool_use",
        cwd: "/workspace/project",
        tool: {native_name: "file", capability: $capability},
        input: {},
        facts: {paths: [$path]}
    }' | "$binary" check --policy "$policy" - | jq -e --arg rule "$expected_rule" '.decision == "deny" and .rule_id == $rule' >/dev/null
}

evaluate_path_decision() {
    capability=$1
    path=$2
    expected=$3
    jq -n --arg capability "$capability" --arg path "$path" '{
        protocol: 1,
        agent: "release-test",
        event: "pre_tool_use",
        cwd: "/workspace/project",
        tool: {native_name: "file", capability: $capability},
        input: {},
        facts: {paths: [$path]}
    }' | "$binary" check --policy "$policy" - | jq -e --arg expected "$expected" '.decision == $expected' >/dev/null
}

# DDEV is not installed or started in this clean test environment. Wrapped
# commands must still be classified without invoking it.
evaluate_shell 'ddev start' allow
evaluate_shell 'ddev drush cr' allow
evaluate_shell 'ddev drush php:eval "print(1)"' deny
evaluate_path file_read web/sites/default/settings.php drupal.secret.settings_php
evaluate_path file_read .env.local drupal.secret.env
evaluate_path file_read keys/synthetic.key filesystem.secret.private_key
evaluate_path file_write web/core/lib/Drupal.php filesystem.write.core
evaluate_path file_write vendor/example/package.php filesystem.write.vendor
evaluate_path file_write web/modules/contrib/example/example.module filesystem.write.contrib_module
evaluate_path file_write web/themes/contrib/example/example.info.yml filesystem.write.contrib_theme
evaluate_path_decision file_write web/modules/custom/example/example.module allow
evaluate_shell 'git push --force origin main' deny

for keyword in INSERT UPDATE DELETE DROP ALTER TRUNCATE REPLACE CREATE GRANT REVOKE; do
    evaluate_shell "ddev mysql -e '$keyword synthetic_table'" deny
done

# Merely finding DDEV must not change decisions or cause the guard to invoke it.
mkdir -p "$work/fake-bin"
printf '%s\n' '#!/bin/sh' 'exit 99' > "$work/fake-bin/ddev"
chmod 0755 "$work/fake-bin/ddev"
PATH="$work/fake-bin:$PATH" "$binary" doctor --policy "$policy" --audit-log "$prefix/config/daguard/audit.jsonl" | grep -F '[OK] ddev available:'
PATH="$work/fake-bin:$PATH" evaluate_shell 'ddev drush cr' allow

# A corrupt upgrade is rejected before any installed file is replaced.
before=$(hash_file "$binary")
tampered=$work/tampered
cp -R "$bundle" "$tampered"
printf 'tampered' >> "$tampered/daguard"
if "$tampered/install.sh" --user --bundle "$tampered" --user-prefix "$prefix"; then
    echo "tampered release unexpectedly installed" >&2
    exit 1
fi
after=$(hash_file "$binary")
[ "$before" = "$after" ]

# A normal upgrade preserves the installed organization policy by default.
policy_before=$(hash_file "$policy")
"$bundle/install.sh" --user --bundle "$bundle" --user-prefix "$prefix"
policy_after=$(hash_file "$policy")
[ "$policy_before" = "$policy_after" ]

"$bundle/uninstall.sh" --user --user-prefix "$prefix"
[ ! -e "$binary" ]
[ -f "$policy" ]
"$bundle/install.sh" --user --bundle "$bundle" --user-prefix "$prefix"

# Exercise root-layout paths without writing to the host filesystem.
managed_root=$work/managed-root
"$bundle/install.sh" --managed --destdir "$managed_root" --bundle "$bundle"
[ -x "$managed_root/usr/local/bin/daguard" ]
[ -f "$managed_root/etc/daguard/policy.json" ]
[ "$(file_mode "$managed_root/usr/local/bin/daguard")" = 755 ]
[ "$(file_mode "$managed_root/etc/daguard/policy.json")" = 644 ]
"$bundle/uninstall.sh" --managed --destdir "$managed_root"
[ -f "$managed_root/etc/daguard/policy.json" ]
