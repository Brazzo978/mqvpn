#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# Explicit root-only bootstrap. No credential is written to stdout or a log.
set -eu
umask 077
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_SERVER=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
[ "$(id -u)" -eq 0 ] || { echo "Run as root" >&2; exit 1; }
[ -f /etc/os-release ] || { echo "Unsupported OS" >&2; exit 1; }
. /etc/os-release
case "$ID" in debian|ubuntu) ;; *) echo "Only Debian/Ubuntu are supported" >&2; exit 1 ;; esac
for command in bash python3 systemctl openssl qrencode iperf3 curl iptables ip6tables ip sysctl tar sha256sum; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "Missing prerequisite: $command (install from your signed distro packages)" >&2
        exit 1
    }
done
python3 "$SCRIPT_DIR/mqvpn_provision.py" preflight "$@"
if [ ! -x /usr/local/bin/mqvpn ] || [ ! -f /etc/mqvpn/server.conf ]; then
    # The pinned-v0.17.0 installer currently prints its global admin key.
    # Capture it in process memory only; never relay or persist its stdout.
    if ! installer_output=$(bash "$PROJECT_SERVER/install-mqvpn-0.17.0-poc.sh" --subnet 10.88.0.0/24 --enable-control 9090 --start 2>&1); then
        unset installer_output
        echo "MQVPN v0.17.0 install failed; output withheld because it may contain the admin key" >&2
        exit 1
    fi
    unset installer_output
fi
(cd "$PROJECT_SERVER/management" && sh ./install.sh >/dev/null)
(cd "$PROJECT_SERVER/iperf" && sh ./install.sh >/dev/null)
python3 "$SCRIPT_DIR/mqvpn_provision.py" init "$@"
echo "Provisioning complete. The QR is a credential: scan privately, then close this terminal."