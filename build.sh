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
VERSION="${VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/pyproject.toml" | head -n 1)}"
# Debian sorts "2.0.0b1" after "2.0.0"; "2.0.0~b1" sorts before it, as a beta should.
DEB_VERSION="$(echo "$VERSION" | sed -E 's/(a|b|rc)([0-9]+)$/~\1\2/')"
DIST="$ROOT/dist"
mkdir -p "$DIST"

# 2.0 ships its own Python (python-build-standalone), so the package needs no
# python3/python3-venv from the system and installs the same way on every
# Ubuntu release, old or new. Pinned by version and checksum.
PY_BUILD="cpython-3.13.18+20261026-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
PY_URL="https://github.com/astral-sh/python-build-standalone/releases/download/20261026/${PY_BUILD/+/%2B}"
PY_SHA256="df15fe60d3ff55bf9dcf25824b5572756bb8816ff93865a273d3301d7066a8b7"
CACHE="$ROOT/installer/.cache"

fetch_python() {
    mkdir -p "$CACHE"
    local tarball="$CACHE/$PY_BUILD"
    if [ ! -f "$tarball" ] || ! echo "$PY_SHA256  $tarball" | sha256sum -c --quiet - 2>/dev/null; then
        echo "==> Downloading $PY_BUILD" >&2
        curl -fsSL --retry 3 -o "$tarball.part" "$PY_URL"
        echo "$PY_SHA256  $tarball.part" | sha256sum -c --quiet -
        mv "$tarball.part" "$tarball"
    fi
    echo "$tarball"
}

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

    # Bundled Python with the dependencies installed into it from the
    # committed wheelhouse: no network and no pip at install time.
    local tarball py site
    tarball="$(fetch_python)"
    tar -xzf "$tarball" -C "$pkgroot/opt/omenwatch"   # -> opt/omenwatch/python
    py="$pkgroot/opt/omenwatch/python/bin/python3"
    mapfile -t deps < <("$py" -c "import tomllib; print('\\n'.join(tomllib.load(open('$ROOT/pyproject.toml','rb'))['project']['dependencies']))")
    "$py" -m pip install --quiet --no-index --find-links="$ROOT/installer/wheelhouse" \
        --no-warn-script-location --disable-pip-version-check "${deps[@]}"
    site="$("$py" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
    echo "/opt/omenwatch" > "$site/omenwatch.pth"   # the app, without PYTHONPATH
    "$py" -m pip uninstall --quiet -y pip
    # Scripts pip wrote point at this build directory; only the interpreter is used.
    find "$pkgroot/opt/omenwatch/python/bin" -mindepth 1 ! -name 'python3' ! -name 'python3.13' -delete
    rm -rf "$pkgroot/opt/omenwatch/python/share" "$pkgroot/opt/omenwatch/python/include"
    cp "$ROOT/installer/deb/omenwatch.service" "$pkgroot/etc/systemd/system/"
    cp "$ROOT/icons/omenwatch.svg" "$pkgroot/usr/share/pixmaps/omenwatch.svg"
    find "$pkgroot/opt/omenwatch" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
    # Compile once here: /opt/omenwatch is read-only to the service.
    "$py" -m compileall -q -j0 -s "$pkgroot" -p / "$pkgroot/opt/omenwatch" >/dev/null

    sed "s/^Version:.*/Version: ${DEB_VERSION}/" "$ROOT/installer/deb/DEBIAN/control" > "$pkgroot/DEBIAN/control"
    cp "$ROOT/installer/deb/postinstall.sh" "$pkgroot/DEBIAN/postinst"
    cp "$ROOT/installer/deb/preremove.sh" "$pkgroot/DEBIAN/prerm"
    cp "$ROOT/installer/deb/postremove.sh" "$pkgroot/DEBIAN/postrm"
    chmod 755 "$pkgroot/DEBIAN/postinst" "$pkgroot/DEBIAN/prerm" "$pkgroot/DEBIAN/postrm"
    find "$pkgroot" -type d -exec chmod 755 {} \;
    chmod -R go-w "$pkgroot"   # the Python tarball ships group-writable files
    echo "Installed-Size: $(du -sk --exclude=DEBIAN "$pkgroot" | cut -f1)" >> "$pkgroot/DEBIAN/control"

    dpkg-deb --build --root-owner-group "$pkgroot" "$DIST/omenwatch_${DEB_VERSION}_amd64.deb"
    rm -rf "$pkgroot"
    echo "==> Built $DIST/omenwatch_${DEB_VERSION}_amd64.deb"
}

case "${1:-all}" in
    deb) build_deb ;;
    all) build_deb ;;
    *) echo "usage: $0 [deb|all]"; exit 1 ;;
esac
