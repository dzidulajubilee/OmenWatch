#!/bin/bash
# Build OmenWatch packages.
#   ./build.sh deb     -> dist/omenwatch_<ver>_amd64.deb   (dpkg-deb, no extra tools)
#   ./build.sh all     -> the same (kept so existing scripts and `make package` work)
#
# Version comes from pyproject.toml — the single source of truth. Bump it
# there and every package format picks it up automatically; nothing else
# to edit.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="${VERSION:-$(python3 -c "import tomllib; print(tomllib.load(open('$ROOT/pyproject.toml','rb'))['project']['version'])")}"
# Debian sorts "2.0.0b1" after "2.0.0"; "2.0.0~b1" sorts before it, as a beta should.
DEB_VERSION="$(echo "$VERSION" | sed -E 's/(a|b|rc)([0-9]+)$/~\1\2/')"
DIST="$ROOT/dist"
mkdir -p "$DIST"

build_deb() {
    echo "==> Building .deb ${DEB_VERSION}"
    local pkgroot
    pkgroot="$(mktemp -d)"
    mkdir -p "$pkgroot/DEBIAN" "$pkgroot/opt/omenwatch" "$pkgroot/etc/systemd/system" "$pkgroot/usr/share/pixmaps"

    cp -r "$ROOT/omenwatch" "$pkgroot/opt/omenwatch/"
    cp -r "$ROOT/frontend" "$pkgroot/opt/omenwatch/"
    cp -r "$ROOT/config" "$pkgroot/opt/omenwatch/"
    cp "$ROOT/pyproject.toml" "$pkgroot/opt/omenwatch/"
    cp "$ROOT/README.md" "$pkgroot/opt/omenwatch/"
    if [ -d "$ROOT/installer/wheelhouse" ]; then
        cp -r "$ROOT/installer/wheelhouse" "$pkgroot/opt/omenwatch/wheelhouse"
    fi
    cp "$ROOT/installer/deb/omenwatch.service" "$pkgroot/etc/systemd/system/"
    cp "$ROOT/icons/omenwatch.svg" "$pkgroot/usr/share/pixmaps/omenwatch.svg"
    find "$pkgroot/opt/omenwatch" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

    sed "s/^Version:.*/Version: ${DEB_VERSION}/" "$ROOT/installer/deb/DEBIAN/control" > "$pkgroot/DEBIAN/control"
    cp "$ROOT/installer/deb/postinstall.sh" "$pkgroot/DEBIAN/postinst"
    cp "$ROOT/installer/deb/preremove.sh" "$pkgroot/DEBIAN/prerm"
    cp "$ROOT/installer/deb/postremove.sh" "$pkgroot/DEBIAN/postrm"
    chmod 755 "$pkgroot/DEBIAN/postinst" "$pkgroot/DEBIAN/prerm" "$pkgroot/DEBIAN/postrm"
    find "$pkgroot" -type d -exec chmod 755 {} \;

    dpkg-deb --build --root-owner-group "$pkgroot" "$DIST/omenwatch_${DEB_VERSION}_amd64.deb"
    rm -rf "$pkgroot"
    echo "==> Built $DIST/omenwatch_${DEB_VERSION}_amd64.deb"
}

case "${1:-all}" in
    deb) build_deb ;;
    all) build_deb ;;
    *) echo "usage: $0 [deb|all]"; exit 1 ;;
esac
