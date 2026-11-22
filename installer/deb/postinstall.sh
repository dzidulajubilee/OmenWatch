#!/bin/sh
set -e

# OmenWatch was called Pantomath before 2.0. Installing this package removes
# the pantomath package (Conflicts/Replaces), which keeps its data and its
# HTTPS setup: move them to OmenWatch's names, once, before anything else.
migrate_from_pantomath() {
    systemctl stop pantomath.service 2>/dev/null || true
    systemctl disable pantomath.service 2>/dev/null || true

    if [ -d /var/lib/pantomath ] && [ ! -e /var/lib/omenwatch ]; then
        mv /var/lib/pantomath /var/lib/omenwatch
        for suffix in "" -wal -shm; do
            if [ -e "/var/lib/omenwatch/pantomath.db$suffix" ]; then
                mv "/var/lib/omenwatch/pantomath.db$suffix" "/var/lib/omenwatch/omenwatch.db$suffix"
            fi
        done
        echo "Moved Pantomath's data to /var/lib/omenwatch."
    fi

    # What `pantomath-admin setup-https` set up: certificate, nginx site,
    # nginx's default site it switched off, and the loopback-only override.
    for ext in crt key; do
        if [ -e "/etc/nginx/ssl/pantomath.$ext" ] && [ ! -e "/etc/nginx/ssl/omenwatch.$ext" ]; then
            mv "/etc/nginx/ssl/pantomath.$ext" "/etc/nginx/ssl/omenwatch.$ext"
        fi
    done
    nginx_changed=no
    if [ -e /etc/nginx/sites-available/pantomath ]; then
        sed 's/pantomath/omenwatch/g; s/Pantomath/OmenWatch/g' /etc/nginx/sites-available/pantomath \
            > /etc/nginx/sites-available/omenwatch
        rm -f /etc/nginx/sites-available/pantomath
        if [ -e /etc/nginx/sites-enabled/pantomath ] || [ -L /etc/nginx/sites-enabled/pantomath ]; then
            rm -f /etc/nginx/sites-enabled/pantomath
            ln -sf /etc/nginx/sites-available/omenwatch /etc/nginx/sites-enabled/omenwatch
        fi
        nginx_changed=yes
    fi
    for dir in /etc/nginx/sites-available /etc/nginx/sites-enabled; do
        if [ -e "$dir/default.disabled-by-pantomath" ] || [ -L "$dir/default.disabled-by-pantomath" ]; then
            mv "$dir/default.disabled-by-pantomath" "$dir/default.disabled-by-omenwatch"
        fi
    done
    if [ "$nginx_changed" = yes ] && command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1; then
        systemctl reload nginx 2>/dev/null || true
    fi
    if [ -f /etc/systemd/system/pantomath.service.d/override.conf ]; then
        mkdir -p /etc/systemd/system/omenwatch.service.d
        sed 's/pantomath/omenwatch/g; s/PANTOMATH/OMENWATCH/g' /etc/systemd/system/pantomath.service.d/override.conf \
            > /etc/systemd/system/omenwatch.service.d/override.conf
        rm -rf /etc/systemd/system/pantomath.service.d
    fi
}
if [ -d /var/lib/pantomath ] || [ -e /etc/nginx/sites-available/pantomath ]; then
    migrate_from_pantomath
fi

# Dedicated system user
if ! id -u omenwatch >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin omenwatch
fi

# Data directory (SQLite lives here, separate from the app code)
mkdir -p /var/lib/omenwatch
chown -R omenwatch:omenwatch /var/lib/omenwatch
# Pantomath's service account owned nothing else.
if id -u pantomath >/dev/null 2>&1; then
    userdel pantomath 2>/dev/null || true
fi

# Isolated Python venv
if [ ! -d /opt/omenwatch/venv ]; then
    python3 -m venv /opt/omenwatch/venv
fi

# setuptools reuses /opt/omenwatch/build between installs, so a module deleted
# in a newer release would otherwise stay in the copy omenwatch-admin runs.
# Clear its leftovers before building and again afterwards.
clean_build() {
    rm -rf /opt/omenwatch/build /opt/omenwatch/*.egg-info
}
clean_build

# Install the dependencies, then the app itself with --force-reinstall: pip
# skips an app whose version number is unchanged (a rebuilt package, a
# hotfix), which would leave the previous code in place.
pip_install() {
    /opt/omenwatch/venv/bin/pip install --quiet "$@"
}
install_offline() {
    pip_install --no-index --find-links=/opt/omenwatch/wheelhouse /opt/omenwatch \
        && pip_install --no-index --find-links=/opt/omenwatch/wheelhouse --no-deps --force-reinstall /opt/omenwatch
}
install_online() {
    pip_install --upgrade pip \
        && pip_install /opt/omenwatch \
        && pip_install --no-deps --force-reinstall /opt/omenwatch
}

# Prefer the wheelhouse bundled in the package — this box may have no route
# to pypi.org (air-gapped / restricted-egress hosts like IDS sensors are a
# real deployment target for this tool), so don't require internet access
# for something as basic as installing the app. Fall back to a normal
# networked pip install if the wheelhouse wasn't shipped, or if it has no
# wheels for this Python (e.g. a Python newer than the one the package was
# built against).
if [ -d /opt/omenwatch/wheelhouse ] && [ -n "$(ls -A /opt/omenwatch/wheelhouse 2>/dev/null)" ] && install_offline; then
    :
else
    echo "Offline install from the bundled wheelhouse was not possible; installing from the Python package index instead." >&2
    clean_build
    install_online
fi
clean_build

# Only the data directory belongs to the service user. The code stays owned
# by root: root runs it whenever an admin uses `sudo omenwatch-admin`, so the
# service account must not be able to rewrite it.
chown -R root:root /opt/omenwatch

# Without this, omenwatch-admin only exists at /opt/omenwatch/venv/bin/
# and needs its full path typed out every time — not what anyone
# expects from a command meant to be run occasionally, by hand, on a
# real terminal (reset-settings-password, setup-https).
ln -sf /opt/omenwatch/venv/bin/omenwatch-admin /usr/local/bin/omenwatch-admin

# Where the dashboard answers: once `omenwatch-admin setup-https` has run and
# the service is restricted to 127.0.0.1, only the HTTPS address works.
HOST=$(hostname -f 2>/dev/null || hostname)
if [ -e /etc/nginx/sites-enabled/omenwatch ]; then
    DASHBOARD_URL="https://$HOST"
else
    DASHBOARD_URL="http://$HOST:7373"
fi

systemctl daemon-reload
systemctl enable omenwatch.service
systemctl stop omenwatch.service 2>/dev/null || true
# First run (0.8.1): create the one-time setup code before the service
# starts, so it can be shown below. Prints nothing on an install that
# already has a Settings password. Run as the service user so the database
# files stay owned by it.
SETUP_CODE=$(runuser -u omenwatch -- env OMENWATCH_DB=/var/lib/omenwatch/omenwatch.db \
    /opt/omenwatch/venv/bin/omenwatch-admin setup-code --bare 2>/dev/null || true)
systemctl start omenwatch.service

echo ""
echo "OmenWatch installed."
echo "Dashboard: $DASHBOARD_URL"
echo "No sources are pre-loaded — add your feeds from the UI."
echo "Data: /var/lib/omenwatch/omenwatch.db (dashboard), /var/lib/omenwatch/ioc.db (IOC database)"
echo "Logs: journalctl -u omenwatch -f"
echo "Admin commands: omenwatch-admin --help (e.g. 'omenwatch-admin setup-https' for HTTPS via nginx)"
echo ""
if [ -n "$SETUP_CODE" ]; then
    HOST=$(hostname -f 2>/dev/null || hostname)
    echo "==================== First-time setup ===================="
    echo "  Open $DASHBOARD_URL and enter this setup code on the"
    echo "  Welcome screen to create the Settings password:"
    echo ""
    echo "      $SETUP_CODE"
    echo ""
    echo "  Nobody can set OmenWatch up without it. Show it again with:"
    echo "      sudo omenwatch-admin setup-code"
    if [ ! -e /etc/nginx/sites-enabled/omenwatch ]; then
        echo "  Tip: run 'sudo omenwatch-admin setup-https' first, so the"
        echo "  password is never sent over plain HTTP."
    fi
    echo "=========================================================="
    echo ""
fi
