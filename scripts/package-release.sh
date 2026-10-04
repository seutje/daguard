#!/bin/sh
set -eu

usage() {
    echo "usage: package-release.sh --binary PATH --output DIR --version VERSION --target TARGET --sbom PATH --dependencies PATH --licenses PATH" >&2
    exit 2
}

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

binary=
output=
version=
target=
sbom=
dependencies=
licenses=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary|--output|--version|--target|--sbom|--dependencies|--licenses)
            [ "$#" -ge 2 ] || usage
            key=$1
            value=$2
            shift 2
            case "$key" in
                --binary) binary=$value ;;
                --output) output=$value ;;
                --version) version=$value ;;
                --target) target=$value ;;
                --sbom) sbom=$value ;;
                --dependencies) dependencies=$value ;;
                --licenses) licenses=$value ;;
            esac
            ;;
        *) usage ;;
    esac
done

[ -f "$binary" ] && [ -f "$sbom" ] && [ -f "$dependencies" ] && [ -f "$licenses" ] || usage
case "$version" in
    ''|*[!0-9A-Za-z.+-]*) usage ;;
esac
case "$target" in
    x86_64-unknown-linux-musl|aarch64-apple-darwin|x86_64-apple-darwin) ;;
    *) usage ;;
esac

bundle_name=daguard-$version-$target
bundle=$output/$bundle_name
"$binary" version | grep -F "daguard $version ($target)" >/dev/null || {
    echo "daguard: binary version or target does not match release bundle" >&2
    exit 1
}
[ ! -e "$bundle" ] || { echo "daguard: output bundle already exists: $bundle" >&2; exit 1; }
mkdir -p "$bundle/config/codex" "$bundle/config/cursor" "$bundle/config/opencode" \
    "$bundle/docs/operations" "$bundle/integrations/opencode" "$bundle/inventory"

install -m 0755 "$binary" "$bundle/daguard"
install -m 0644 policy/default-policy.json "$bundle/default-policy.json"
install -m 0755 scripts/install.sh "$bundle/install.sh"
install -m 0755 scripts/uninstall.sh "$bundle/uninstall.sh"
install -m 0644 config/codex/hooks.json "$bundle/config/codex/hooks.json"
install -m 0644 config/codex/managed-requirements.toml "$bundle/config/codex/managed-requirements.toml"
install -m 0644 config/cursor/hooks.json "$bundle/config/cursor/hooks.json"
install -m 0644 config/opencode/opencode.json "$bundle/config/opencode/opencode.json"
install -m 0644 docs/operations/rollout.md "$bundle/docs/operations/rollout.md"
install -m 0644 docs/operations/rules.md "$bundle/docs/operations/rules.md"
install -m 0644 docs/operations/macos.md "$bundle/docs/operations/macos.md"
install -m 0644 integrations/opencode/index.js "$bundle/integrations/opencode/index.js"
install -m 0644 integrations/opencode/package.json "$bundle/integrations/opencode/package.json"
install -m 0644 "$sbom" "$bundle/inventory/sbom.cdx.json"
install -m 0644 "$dependencies" "$bundle/inventory/dependencies.json"
install -m 0644 "$licenses" "$bundle/inventory/licenses.json"
install -m 0644 LICENSE "$bundle/LICENSE"
install -m 0644 SECURITY.md "$bundle/SECURITY.md"
install -m 0644 docs/operations/result-containment.md "$bundle/docs/operations/result-containment.md"
printf '{"schema":1,"version":"%s","target":"%s"}\n' "$version" "$target" > "$bundle/release.json"

(
    cd "$bundle"
    find . -type f ! -path ./SHA256SUMS | LC_ALL=C sort | while IFS= read -r path; do
        printf '%s  %s\n' "$(hash_file "$path")" "$path"
    done > SHA256SUMS
)
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
    tar --sort=name --mtime="@${SOURCE_DATE_EPOCH:-0}" --owner=0 --group=0 --numeric-owner \
        -C "$output" -czf "$output/$bundle_name.tar.gz" "$bundle_name"
else
    COPYFILE_DISABLE=1 tar -C "$output" -czf "$output/$bundle_name.tar.gz" "$bundle_name"
fi
(
    cd "$output"
    printf '%s  %s\n' "$(hash_file "$bundle_name.tar.gz")" "$bundle_name.tar.gz" > SHA256SUMS
)
