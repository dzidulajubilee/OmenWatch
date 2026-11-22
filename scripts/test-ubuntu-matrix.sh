#!/bin/bash
# Install a built .deb on every supported Ubuntu release, each in a fresh LXD
# system container (real systemd), and check that it works.
#
#   scripts/test-ubuntu-matrix.sh dist/omenwatch_<version>_amd64.deb [release ...]
#
# Run it on a machine with LXD (`sudo snap install lxd && sudo lxd init --auto`).
# For each release: install with apt, wait for the service, check the
# dashboard answers, the admin command runs and the log has no traceback;
# reinstall the same package (the upgrade path); purge and check nothing is
# left behind. Prints one line per release and exits non-zero if any failed.
set -uo pipefail

DEB="${1:?usage: $0 path/to/omenwatch.deb [release ...]}"
shift
RELEASES=("${@:-20.04 22.04 24.04 25.10 26.04 26.10}")
read -r -a RELEASES <<< "${RELEASES[*]}"
LXC="${LXC:-sudo lxc}"
NAME_PREFIX="omenwatch-matrix"
failures=0

run() { $LXC exec "$1" -- sh -c "$2"; }

check_release() {
    local release="$1" name="$NAME_PREFIX-${1//./-}"
    $LXC delete -f "$name" >/dev/null 2>&1
    if ! $LXC launch "ubuntu:$release" "$name" >/dev/null 2>&1; then
        echo "SKIP  $release  (no image)"
        return 0
    fi
    # Wait for systemd and the network.
    run "$name" 'for i in $(seq 60); do systemctl is-system-running 2>/dev/null | grep -qE "running|degraded" && exit 0; sleep 1; done; exit 1'
    $LXC file push "$DEB" "$name/root/omenwatch.deb" >/dev/null

    local step result="PASS" detail=""
    for step in \
        "install:DEBIAN_FRONTEND=noninteractive apt-get install -y -q /root/omenwatch.deb >/root/install.log 2>&1" \
        "service:for i in \$(seq 30); do curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:7373/ | grep -qE '^(200|30.)$' && exit 0; sleep 1; done; exit 1" \
        "admin:omenwatch-admin --help >/dev/null" \
        "log:! journalctl -u omenwatch --no-pager | grep -q Traceback" \
        "reinstall:DEBIAN_FRONTEND=noninteractive apt-get install -y -q --reinstall /root/omenwatch.deb >/root/reinstall.log 2>&1 && sleep 3 && systemctl is-active -q omenwatch" \
        "purge:apt-get purge -y -q omenwatch >/root/purge.log 2>&1 && [ ! -e /opt/omenwatch ] && [ ! -e /var/lib/omenwatch ] && [ ! -e /usr/local/bin/omenwatch-admin ] && ! id omenwatch 2>/dev/null"
    do
        if ! run "$name" "${step#*:}"; then
            result="FAIL"
            detail="at ${step%%:*}"
            run "$name" 'tail -5 /root/install.log /root/reinstall.log /root/purge.log 2>/dev/null; journalctl -u omenwatch -n 15 --no-pager 2>/dev/null' | sed 's/^/      /'
            break
        fi
    done
    local os
    os="$(run "$name" '. /etc/os-release; echo "$PRETTY_NAME"' 2>/dev/null)"
    echo "$result  $release  ($os) $detail"
    [ "$result" = PASS ] || failures=$((failures + 1))
    $LXC delete -f "$name" >/dev/null 2>&1
}

for release in "${RELEASES[@]}"; do
    check_release "$release"
done
exit "$failures"
