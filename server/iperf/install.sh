#!/bin/sh
set -eu
test "$(id -u)" -eq 0
test -f /etc/mqvpn/server.conf
command -v iperf3 >/dev/null || { apt-get update; apt-get install -y iperf3; }
install -m 0644 mqvpn-iperf.service /etc/systemd/system/mqvpn-iperf.service
systemctl daemon-reload
systemctl enable --now mqvpn-iperf.service
systemctl is-active --quiet mqvpn-iperf.service
