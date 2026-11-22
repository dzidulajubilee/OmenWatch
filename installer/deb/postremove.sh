#!/bin/sh
set -e

NGINX_AVAILABLE=/etc/nginx/sites-available
NGINX_ENABLED=/etc/nginx/sites-enabled

case "$1" in
    remove|purge)
        # Everything the postinst built outside the package's own file list
        # (dpkg only removes files it installed). Nothing here is user data.
        rm -rf /opt/omenwatch/python /opt/omenwatch/venv /opt/omenwatch/build /opt/omenwatch/*.egg-info
        rm -f /usr/local/bin/omenwatch-admin
        rmdir /opt/omenwatch 2>/dev/null || true
        systemctl daemon-reload || true
        ;;
    *)
        # upgrade / failed-upgrade / abort-*: the new version is (being) put in
        # place, so leave its Python and the admin command alone.
        systemctl daemon-reload || true
        ;;
esac

if [ "$1" = "purge" ]; then
    # Undo what `omenwatch-admin setup-https` did, so the machine isn't left
    # with an nginx site proxying to a service that no longer exists (502)
    # and with nginx's own default site still switched off.
    changed_nginx=no
    if [ -e "$NGINX_ENABLED/omenwatch" ] || [ -L "$NGINX_ENABLED/omenwatch" ] || [ -e "$NGINX_AVAILABLE/omenwatch" ]; then
        rm -f "$NGINX_ENABLED/omenwatch" "$NGINX_AVAILABLE/omenwatch"
        changed_nginx=yes
    fi
    for disabled in "$NGINX_AVAILABLE/default.disabled-by-omenwatch" "$NGINX_ENABLED/default.disabled-by-omenwatch"; do
        if [ -e "$disabled" ] || [ -L "$disabled" ]; then
            if [ ! -e "$NGINX_ENABLED/default" ] && [ ! -L "$NGINX_ENABLED/default" ]; then
                mv "$disabled" "$NGINX_ENABLED/default"
            else
                rm -f "$disabled"
            fi
            changed_nginx=yes
        fi
    done
    rm -f /etc/nginx/ssl/omenwatch.crt /etc/nginx/ssl/omenwatch.key
    rmdir /etc/nginx/ssl 2>/dev/null || true
    # The loopback-only override would leave a reinstalled service unreachable.
    rm -f /etc/systemd/system/omenwatch.service.d/override.conf
    rmdir /etc/systemd/system/omenwatch.service.d 2>/dev/null || true
    systemctl daemon-reload || true
    if [ "$changed_nginx" = yes ] && command -v nginx >/dev/null 2>&1; then
        if nginx -t >/dev/null 2>&1; then
            systemctl reload nginx 2>/dev/null || true
        fi
    fi

    rm -rf /var/lib/omenwatch
    userdel omenwatch 2>/dev/null || true
fi

exit 0
