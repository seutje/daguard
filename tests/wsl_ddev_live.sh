#!/bin/sh
set -eu

bundle=${1:-}
[ -d "$bundle" ] || { echo "usage: wsl_ddev_live.sh BUNDLE_DIRECTORY" >&2; exit 2; }
grep -qi microsoft /proc/sys/kernel/osrelease || { echo "daguard: live test requires WSL" >&2; exit 1; }
command -v ddev >/dev/null || { echo "daguard: live test requires DDEV" >&2; exit 1; }

bundle=$(CDPATH= cd -- "$bundle" && pwd)
repository=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
project=daguard-compat-$(basename "$work" | tr '[:upper:].' '[:lower:]-')
configured=false
cleanup() {
    if [ "$configured" = true ]; then
        (cd "$work/project" && ddev delete -Oy) >/dev/null 2>&1 || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$work/project/web/modules/custom"
printf 'synthetic-public-fixture\n' > "$work/project/web/modules/custom/fixture.txt"
(
    cd "$work/project"
    ddev config --project-name "$project" --project-type php --docroot web --omit-containers db,ddev-ssh-agent
)
configured=true
(
    cd "$work/project"
    ddev start
    ddev describe -j | jq -e '.raw.status == "running"' >/dev/null
)

# These compatibility probes execute only literal public fixture operations.
# Mandatory deny cases remain classification-only; no database is needed.
assert_decision() {
    command=$1
    expected=$2
    jq -n --arg cwd "$work/project" --arg command "$command" '{
        protocol: 1, agent: "ddev-compatibility", event: "pre_tool_use", cwd: $cwd,
        tool: {native_name: "shell", capability: "shell_execute"}, input: {}, facts: {command: $command}
    }' | "$bundle/daguard" check --policy "$bundle/default-policy.json" - | jq -e --arg expected "$expected" '.decision == $expected' >/dev/null
}
probe_index=0
assert_output() {
    probe_index=$((probe_index + 1))
    expected=$1
    shift
    actual=$(cd "$work/project" && "$@")
    [ "$actual" = "$expected" ] || { echo "DDEV compatibility mismatch at public fixture probe $probe_index" >&2; exit 1; }
}
assert_decision 'ddev exec pwd' allow
assert_output /var/www/html ddev exec pwd
assert_decision 'ddev . -s web -d /var/www/html/web/modules/custom cat fixture.txt' allow
assert_output synthetic-public-fixture ddev . -s web -d /var/www/html/web/modules/custom cat fixture.txt
assert_decision "ddev exec --raw --dir=/var/www/html printf '%s' 'literal \$value'" allow
assert_output 'literal $value' ddev exec --raw --dir=/var/www/html printf '%s' 'literal $value'
assert_decision "ddev exec --dir=/var/www/html printf '%s' 'one two'" allow
assert_output 'one two' ddev exec --dir=/var/www/html printf '%s' 'one two'
assert_decision "ddev exec --raw=true --dir /var/www/html printf '%s' '--service=db'" allow
assert_output '--service=db' ddev exec --raw=true --dir /var/www/html printf '%s' '--service=db'
assert_decision "ddev exec echo '\$(cat .env)'" deny
assert_decision "ddev exec echo 'safe;cat' .env" deny
assert_decision 'ddev exec --dir /var/www/html/web/core touch synthetic.php' deny

# DDEV can override its default cwd independently of the host shell cwd.
printf '\nworking_dir:\n  web: /var/www/html/web/modules/custom\n' >> "$work/project/.ddev/config.yaml"
(cd "$work/project" && ddev restart)
assert_output /var/www/html/web/modules/custom ddev exec pwd
assert_decision 'ddev exec cat fixture.txt' deny
assert_decision 'ddev exec --raw --dir=/var/www/html/web/modules/custom cat fixture.txt' allow
assert_output synthetic-public-fixture ddev exec --raw --dir=/var/www/html/web/modules/custom cat fixture.txt

# Verify lifecycle independence with the complete packaged install suite.
"$repository/tests/release_install.sh" "$bundle"
(cd "$work/project" && ddev stop)
"$repository/tests/release_install.sh" "$bundle"
echo 'WSL/DDEV literal argument, alias, flags and working-directory compatibility passed.'
