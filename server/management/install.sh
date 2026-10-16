#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
set -eu
# Run from this directory as root after mqvpn-server has been installed.
test "$(id -u)" -eq 0
test -f /etc/mqvpn/server.conf
install -d -m 0755 /usr/local/libexec
install -m 0755 mqvpn_management.py /usr/local/libexec/mqvpn-management.py
install -m 0644 mqvpn-management.service /etc/systemd/system/mqvpn-management.service
python3 - <<'PY'
import importlib.util
from pathlib import Path
spec = importlib.util.spec_from_file_location("mqvpn_management", "/usr/local/libexec/mqvpn-management.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
path = Path("/etc/mqvpn/server.conf")
raw, _, _ = module.read_config(path)
lines, sections, entries = module.config_entries(raw)
listen = entries.get(("control", "listen"))
if listen and listen[1] != "127.0.0.1:9090":
    raise SystemExit("Existing [Control] Listen differs; review manually")
if not listen:
    suffix = "\r\n" if b"\r\n" in raw else "\n"
    if "control" in sections:
        lines.insert(sections["control"] + 1, "Listen = 127.0.0.1:9090" + suffix)
        updated = "".join(lines).encode("utf-8")
    else:
        updated = raw + (b"" if raw.endswith(b"\n") else suffix.encode()) + ("[Control]" + suffix + "Listen = 127.0.0.1:9090" + suffix).encode()
    module.atomic_write(path, updated)
    print("Enabled native control API on 127.0.0.1:9090")
PY
systemctl daemon-reload
systemctl restart mqvpn-server.service
systemctl is-active --quiet mqvpn-server.service
systemctl enable --now mqvpn-management.service
systemctl is-active --quiet mqvpn-management.service
