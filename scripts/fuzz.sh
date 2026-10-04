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
    max_len=65537
    if [ "$target" = result_scanner ]; then
        max_len=1048577
        # Exercise the boundary immediately; tiny seeds need not grow to 1 MiB.
        dd if=/dev/zero bs=1048576 count=1 2>/dev/null | tr '\000' a > "$work/$target/at-limit"
        cp "$work/$target/at-limit" "$work/$target/over-limit"
        printf a >> "$work/$target/over-limit"
    fi
    cargo +nightly fuzz run "$target" "$work/$target" -- \
        -max_total_time="$seconds" -max_len="$max_len" -timeout=5 -rss_limit_mb=2048
done
