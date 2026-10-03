#!/bin/sh
set -eu

usage() {
    echo "usage: uninstall.sh [--user|--managed] [--remove-policy] [--destdir DIR] [--user-prefix DIR]" >&2
    exit 2
}

mode=user
remove_policy=false
destdir=
user_prefix=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --user) mode=user; shift ;;
        --managed) mode=managed; shift ;;
        --remove-policy) remove_policy=true; shift ;;
        --destdir|--user-prefix)
            [ "$#" -ge 2 ] || usage
            key=$1
            value=$2
            shift 2
            case "$key" in
                --destdir) destdir=$value ;;
                --user-prefix) user_prefix=$value ;;
            esac
            ;;
        *) usage ;;
    esac
done

if [ "$mode" = managed ]; then
    [ -z "$user_prefix" ] || usage
    bin_dir=$destdir/usr/local/bin
    config_dir=$destdir/etc/daguard
    share_dir=$destdir/usr/local/share/daguard
    if [ -z "$destdir" ] && [ "$(id -u)" -ne 0 ]; then
        echo "daguard: managed uninstall must be run as root" >&2
        exit 1
    fi
else
    [ -z "$destdir" ] || usage
    if [ -n "$user_prefix" ]; then
        prefix=$user_prefix
        bin_dir=$prefix/bin
        config_dir=$prefix/config/daguard
        share_dir=$prefix/share/daguard
    else
        : "${HOME:?daguard: HOME is required for a user uninstall}"
        bin_dir=$HOME/.local/bin
        config_dir=$HOME/.config/daguard
        share_dir=$HOME/.local/share/daguard
    fi
fi

rm -f "$bin_dir/daguard" "$config_dir/version.json" "$config_dir/SHA256SUMS"
rm -rf "$share_dir/opencode"
if [ "$remove_policy" = true ]; then
    rm -f "$config_dir/policy.json"
    echo "removed organization policy: $config_dir/policy.json"
else
    echo "preserved organization policy: $config_dir/policy.json"
fi
rmdir "$config_dir" "$share_dir" 2>/dev/null || true
echo "uninstalled daguard from $bin_dir/daguard"
