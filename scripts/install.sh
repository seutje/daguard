#!/bin/sh
set -eu

usage() {
    echo "usage: install.sh [--user|--managed] [--bundle DIR] [--replace-policy] [--destdir DIR] [--user-prefix DIR]" >&2
    exit 2
}

mode=user
bundle=
replace_policy=false
destdir=
user_prefix=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --user) mode=user; shift ;;
        --managed) mode=managed; shift ;;
        --replace-policy) replace_policy=true; shift ;;
        --bundle|--destdir|--user-prefix)
            [ "$#" -ge 2 ] || usage
            key=$1
            value=$2
            shift 2
            case "$key" in
                --bundle) bundle=$value ;;
                --destdir) destdir=$value ;;
                --user-prefix) user_prefix=$value ;;
            esac
            ;;
        *) usage ;;
    esac
done

case "$(uname -s)" in Linux) ;; *) echo "daguard: this installer supports Linux/WSL only" >&2; exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) ;; *) echo "daguard: this bundle requires x86_64 Linux" >&2; exit 1 ;; esac

if [ -z "$bundle" ]; then
    script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    bundle=$script_dir
fi
bundle=$(CDPATH= cd -- "$bundle" && pwd)
[ -f "$bundle/SHA256SUMS" ] || { echo "daguard: bundle is missing SHA256SUMS" >&2; exit 1; }
(
    cd "$bundle"
    sha256sum --check --strict SHA256SUMS
)
[ -x "$bundle/daguard" ] || { echo "daguard: verified bundle has no executable" >&2; exit 1; }

if [ "$mode" = managed ]; then
    [ -z "$user_prefix" ] || usage
    bin_dir=$destdir/usr/local/bin
    config_dir=$destdir/etc/daguard
    share_dir=$destdir/usr/local/share/daguard
    dir_mode=0755
    file_mode=0644
    if [ -z "$destdir" ] && [ "$(id -u)" -ne 0 ]; then
        echo "daguard: managed installation must be run as root" >&2
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
        : "${HOME:?daguard: HOME is required for a user installation}"
        bin_dir=$HOME/.local/bin
        config_dir=$HOME/.config/daguard
        share_dir=$HOME/.local/share/daguard
    fi
    dir_mode=0700
    file_mode=0600
fi

mkdir -p "$bin_dir" "$config_dir" "$share_dir"
chmod "$dir_mode" "$config_dir" "$share_dir"
if [ "$mode" = managed ] && [ -z "$destdir" ]; then
    chown root:root "$config_dir" "$share_dir"
fi

policy=$config_dir/policy.json
policy_source=$bundle/default-policy.json
if [ -f "$policy" ] && [ "$replace_policy" = false ]; then
    policy_source=$policy
fi
"$bundle/daguard" policy lint "$policy_source" >/dev/null
"$bundle/daguard" version >/dev/null

binary_tmp=$(mktemp "$bin_dir/.daguard.XXXXXX")
metadata_tmp=$(mktemp "$config_dir/.version.XXXXXX")
checksums_tmp=$(mktemp "$config_dir/.checksums.XXXXXX")
plugin_tmp=$(mktemp -d "$share_dir/.opencode.XXXXXX")
rollback_dir=$(mktemp -d "$config_dir/.rollback.XXXXXX")
policy_tmp=
mutated=false
snapshot() {
    source_path=$1
    backup_name=$2
    if [ -e "$source_path" ]; then
        cp -Rp "$source_path" "$rollback_dir/$backup_name"
    else
        : > "$rollback_dir/$backup_name.absent"
    fi
}
restore() {
    destination=$1
    backup_name=$2
    rm -rf "$destination"
    if [ ! -f "$rollback_dir/$backup_name.absent" ]; then
        cp -Rp "$rollback_dir/$backup_name" "$destination"
    fi
}
cleanup() {
    rm -f "$binary_tmp" "$metadata_tmp" "$checksums_tmp"
    [ -z "$policy_tmp" ] || rm -f "$policy_tmp"
    rm -rf "$plugin_tmp"
    if [ "$mutated" = true ]; then
        restore "$bin_dir/daguard" binary
        restore "$config_dir/version.json" metadata
        restore "$config_dir/SHA256SUMS" checksums
        restore "$config_dir/policy.json" policy
        restore "$share_dir/opencode" plugin
    fi
    rm -rf "$rollback_dir"
}
trap cleanup EXIT HUP INT TERM

install -m 0755 "$bundle/daguard" "$binary_tmp"
install -m "$file_mode" "$bundle/release.json" "$metadata_tmp"
install -m 0644 "$bundle/integrations/opencode/index.js" "$plugin_tmp/index.js"
install -m 0644 "$bundle/integrations/opencode/package.json" "$plugin_tmp/package.json"
if [ ! -f "$policy" ] || [ "$replace_policy" = true ]; then
    policy_tmp=$(mktemp "$config_dir/.policy.XXXXXX")
    install -m "$file_mode" "$bundle/default-policy.json" "$policy_tmp"
fi

snapshot "$bin_dir/daguard" binary
snapshot "$config_dir/version.json" metadata
snapshot "$config_dir/SHA256SUMS" checksums
snapshot "$config_dir/policy.json" policy
snapshot "$share_dir/opencode" plugin
mutated=true
mv -f "$binary_tmp" "$bin_dir/daguard"
binary_tmp=
rm -rf "$share_dir/opencode"
mv "$plugin_tmp" "$share_dir/opencode"
plugin_tmp=
if [ -n "$policy_tmp" ]; then
    mv -f "$policy_tmp" "$policy"
    policy_tmp=
fi
{
    printf '%s  %s\n' "$(sha256sum "$bin_dir/daguard" | awk '{print $1}')" daguard
    printf '%s  %s\n' "$(sha256sum "$policy" | awk '{print $1}')" policy.json
} > "$checksums_tmp"
chmod "$file_mode" "$checksums_tmp"
mv -f "$metadata_tmp" "$config_dir/version.json"
metadata_tmp=
mv -f "$checksums_tmp" "$config_dir/SHA256SUMS"
checksums_tmp=
chmod "$file_mode" "$policy" "$config_dir/version.json" "$config_dir/SHA256SUMS"
chmod "$dir_mode" "$share_dir/opencode"
if [ "$mode" = managed ] && [ -z "$destdir" ]; then
    chown root:root "$bin_dir/daguard" "$policy" "$config_dir/version.json" \
        "$config_dir/SHA256SUMS" "$share_dir/opencode"
    chown -R root:root "$share_dir/opencode"
fi
mutated=false
rm -rf "$rollback_dir"
trap - EXIT HUP INT TERM

echo "installed daguard to $bin_dir/daguard"
echo "organization policy: $policy"
if [ "$mode" = user ]; then
    echo "user-managed installation is a weaker boundary than root-owned managed installation" >&2
fi
"$bin_dir/daguard" doctor --policy "$policy" --audit-log "$config_dir/audit.jsonl"
