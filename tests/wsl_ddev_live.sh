#!/bin/sh
set -eu

bundle=${1:-}
[ -d "$bundle" ] || { echo "usage: wsl_ddev_live.sh BUNDLE_DIRECTORY" >&2; exit 2; }
grep -qi microsoft /proc/sys/kernel/osrelease || { echo "daguard: live test requires WSL" >&2; exit 1; }
command -v ddev >/dev/null || { echo "daguard: live test requires DDEV" >&2; exit 1; }

work=$(mktemp -d)
project=daguard-phase7-$$
cleanup() {
    ddev delete -Oy "$project" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$work/project/web"
(
    cd "$work/project"
    ddev config --project-name "$project" --project-type php --docroot web
    ddev start
    ddev describe -j | grep -F '"status":"running"'
)

# Run the complete release/install policy suite while DDEV is live. The guard
# must classify DDEV commands without consulting or changing that live state.
tests/release_install.sh "$bundle"

ddev stop "$project"
tests/release_install.sh "$bundle"
