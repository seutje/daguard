#!/bin/sh
set -eu

usage() {
    echo "usage: package-release.sh --binary PATH --output DIR --version VERSION --sbom PATH --dependencies PATH --licenses PATH" >&2
    exit 2
}

binary=
output=
version=
sbom=
dependencies=
licenses=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary|--output|--version|--sbom|--dependencies|--licenses)
            [ "$#" -ge 2 ] || usage
            key=$1
            value=$2
            shift 2
            case "$key" in
                --binary) binary=$value ;;
                --output) output=$value ;;
                --version) version=$value ;;
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

target=x86_64-unknown-linux-musl
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
install -m 0644 integrations/opencode/index.js "$bundle/integrations/opencode/index.js"
install -m 0644 integrations/opencode/package.json "$bundle/integrations/opencode/package.json"
install -m 0644 "$sbom" "$bundle/inventory/sbom.cdx.json"
install -m 0644 "$dependencies" "$bundle/inventory/dependencies.json"
install -m 0644 "$licenses" "$bundle/inventory/licenses.json"
install -m 0644 LICENSE "$bundle/LICENSE"
printf '{"schema":1,"version":"%s","target":"%s"}\n' "$version" "$target" > "$bundle/release.json"

(
    cd "$bundle"
    find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
)
tar --sort=name --mtime="@${SOURCE_DATE_EPOCH:-0}" --owner=0 --group=0 --numeric-owner \
    -C "$output" -czf "$output/$bundle_name.tar.gz" "$bundle_name"
(
    cd "$output"
    sha256sum "$bundle_name.tar.gz" > SHA256SUMS
)
