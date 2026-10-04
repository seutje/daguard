#!/bin/sh
# Developer-only fuzzing. Copies reviewed fixtures so generated inputs stay local.
set -eu
seconds=${1:-30}
case "$seconds" in ''|*[!0-9]*) echo "usage: fuzz.sh [SECONDS_PER_TARGET]" >&2; exit 2;; esac
[ "$seconds" -gt 0 ] || { echo "seconds must be positive" >&2; exit 2; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
export CARGO_NET_OFFLINE=true
cargo +nightly fuzz build
for target in canonical codex cursor opencode path shell sql policy result_scanner; do
    mkdir "$work/$target"
    cp fuzz/corpus/"$target"/* "$work/$target/"
    cargo +nightly fuzz run "$target" "$work/$target" -- \
        -max_total_time="$seconds" -max_len=65537 -timeout=5 -rss_limit_mb=2048
done
