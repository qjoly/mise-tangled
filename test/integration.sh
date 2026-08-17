#!/usr/bin/env bash
# Installs a real artifact from tangled. Needs network and a reachable appview.
set -euo pipefail

REPO='tangled:did:plc:wshs7t2adsemcrrd4snkeqli/core'
VERSION='1.2.0-alpha'
# sha256 of appview-v1.2.0-alpha-x86_64-linux, also carried by its blob CID
APPVIEW_SHA='059ac19e4b04acaa25cd9181d72444e5579181d31e3355bd5745b6995f284ed7'

PLUGIN_DIR=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export MISE_USE_VERSIONS_HOST=0

uninstall() { mise uninstall "$REPO@$VERSION" >/dev/null 2>&1 || true; }

sha256_of() { # macOS has no sha256sum
    if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

install_with() { # $1 = extra tool options, appended to the version
    rm -rf "$WORK/proj"
    mkdir -p "$WORK/proj"
    printf '[tools]\n"%s" = { version = "%s"%s }\n' "$REPO" "$VERSION" "$1" >"$WORK/proj/mise.toml"
    (cd "$WORK/proj" && mise trust >/dev/null && mise install)
}

mise plugin link --force tangled "$PLUGIN_DIR"
mise cache clear >/dev/null

echo '== listing versions (tags, getRepo, listArtifacts, collaborators)'
mise ls-remote "$REPO" >/dev/null

uninstall
if [ "$(uname -s)-$(uname -m)" = "Linux-x86_64" ]; then
    echo '== auto pick on linux/amd64 takes the shortest match, appview'
    install_with ', bin = "appview"'
else
    echo "== auto pick needs Linux-x86_64, naming the asset instead on $(uname -s)-$(uname -m)"
    install_with ', asset = "appview-v{version}-x86_64-linux", bin = "appview"'
fi
BIN=$(cd "$WORK/proj" && mise which appview)
test -x "$BIN"
test "$(sha256_of "$BIN")" = "$APPVIEW_SHA"

echo '== an explicit asset takes the other artifact of the same tag'
uninstall
install_with ', asset = "knotserver-v{version}-x86_64-linux", bin = "knotserver"'
test -x "$(cd "$WORK/proj" && mise which knotserver)"

echo '== an artifact uploaded by a non-collaborator DID is refused'
uninstall
if install_with ', asset = "test"' 2>"$WORK/err"; then
    echo 'FAIL: the artifact of a stranger was installed'
    exit 1
fi
grep -q "no artifact named 'test'" "$WORK/err"

uninstall
echo 'integration ok'
