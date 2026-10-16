#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
"""Root-only, persistent per-user MQVPN provisioning for the Android PoC."""
import argparse
import base64
try:
    import fcntl
except ImportError:  # Windows unit tests; deployment is Linux only.
    fcntl = None
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CONFIG = Path("/etc/mqvpn/server.conf")
PROFILES = Path("/etc/mqvpn/profiles")
LOCK = Path("/run/lock/mqvpn-provision.lock")
SERVICE = "mqvpn-server.service"
MANAGEMENT_SERVICE = "mqvpn-management.service"
NAME_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
HOST_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}\Z")
SECTION_RE = re.compile(r"^\s*\[([^]]+)\]\s*(?:[#;].*)?$")
ENTRY_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*?)\s*$")
MAX_USERS = 64


class ProvisionError(Exception):
    pass


def atomic_write(path, content):
    """Private file replacement with fsync; never leave keys in a world-readable temp."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    old = path.stat() if path.exists() else None
    fd, temporary = tempfile.mkstemp(prefix=".mqvpn-provision-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            os.fchmod(out.fileno(), 0o600)
            if old is not None and hasattr(os, "fchown"):
                os.fchown(out.fileno(), old.st_uid, old.st_gid)
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
        if hasattr(os, "O_DIRECTORY"):
            directory = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def parse_config(raw):
    try:
        lines = raw.decode("utf-8").splitlines(keepends=True)
    except UnicodeError as exc:
        raise ProvisionError("server config is not UTF-8") from exc
    section = None
    sections = {}
    entries = {}
    users = {}
    user_lines = {}
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        match = SECTION_RE.match(line)
        if match:
            section = match.group(1).lower()
            if section in sections and section in ("interface", "auth", "control"):
                raise ProvisionError("duplicate server config section")
            sections[section] = index
            continue
        match = ENTRY_RE.match(line)
        if not match or section is None:
            continue
        key, value = match.group(1).lower(), match.group(2).strip()
        if section == "auth" and key == "user":
            if ":" not in value:
                raise ProvisionError("malformed [Auth] User entry")
            name, psk = value.split(":", 1)
            if not name or not psk or name in users or len(name.encode()) > 63 or len(psk.encode()) > 255:
                raise ProvisionError("invalid or duplicate [Auth] User entry")
            users[name] = psk
            user_lines[name] = index
        else:
            entry = (section, key)
            if entry in entries and entry in (("interface", "listen"), ("auth", "key"),
                                               ("control", "listen")):
                raise ProvisionError("duplicate server config key")
            entries[entry] = value
    if "auth" not in sections or "interface" not in sections:
        raise ProvisionError("server config needs [Auth] and [Interface]")
    return lines, sections, entries, users, user_lines


def render_user(raw, name, psk):
    lines, sections, _, users, user_lines = parse_config(raw)
    if psk is None:
        if name not in users:
            raise ProvisionError("user not found")
        del lines[user_lines[name]]
    else:
        if name in users:
            raise ProvisionError("user already exists")
        if len(users) >= MAX_USERS:
            raise ProvisionError("MQVPN supports at most 64 configured users")
        newline = "\r\n" if b"\r\n" in raw else "\n"
        lines.insert(sections["auth"] + 1, f"User = {name}:{psk}{newline}")
    return "".join(lines).encode("utf-8")


def validate_tunnel_subnet(raw):
    _, _, entries, _, _ = parse_config(raw)
    if entries.get(("interface", "subnet")) != "10.88.0.0/24":
        raise ProvisionError("this phone setup requires Subnet = 10.88.0.0/24; existing config left unchanged")


def config_port(raw):
    validate_tunnel_subnet(raw)
    _, _, entries, _, _ = parse_config(raw)
    listen = entries.get(("interface", "listen"), "")
    try:
        port = int(listen.rsplit(":", 1)[1])
    except (IndexError, ValueError) as exc:
        raise ProvisionError("invalid [Interface] Listen") from exc
    if not 1 <= port <= 65535:
        raise ProvisionError("invalid MQVPN port")
    if entries.get(("control", "listen")) != "127.0.0.1:9090":
        raise ProvisionError("native control API must listen on 127.0.0.1:9090")
    return port


def valid_host(value, label):
    if not isinstance(value, str) or not value or len(value) > 253 or any(c in value for c in "/:@?#% "):
        raise ProvisionError(f"invalid {label}")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if not HOST_RE.fullmatch(value) or ".." in value:
            raise ProvisionError(f"invalid {label}")
    return value


def profile_uri(profile):
    data = json.dumps(profile, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(data) > 16 * 1024:
        raise ProvisionError("profile exceeds importer limit")
    return "mqvpn://profile?data=" + base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def show_qr(profile):
    if not sys.stdout.isatty():
        raise ProvisionError("QR output requires an interactive terminal")
    if not shutil.which("qrencode"):
        raise ProvisionError("qrencode is required to display a QR")
    uri = profile_uri(profile)
    # Never place the secret URI in argv, logs, or a public URL; qrencode reads stdin.
    subprocess.run(["qrencode", "-t", "ANSIUTF8", "-m", "1"], input=uri + "\n",
                   text=True, check=True)


def native_users(host="127.0.0.1", port=9090):
    with socket.create_connection((host, port), timeout=2) as connection:
        connection.settimeout(2)
        connection.sendall(b'{"cmd":"list_users"}\n')
        response = connection.makefile("rb").readline(8193)
    if not response.endswith(b"\n") or len(response) > 8192:
        raise ProvisionError("invalid native control response")
    value = json.loads(response)
    users = value.get("users")
    if value.get("ok") is not True or not isinstance(users, list) or not all(isinstance(u, str) for u in users):
        raise ProvisionError("native user listing unavailable")
    return set(users)


class Provisioner:
    def __init__(self, config=CONFIG, profiles=PROFILES, runner=None, control=None):
        self.config = Path(config)
        self.profiles = Path(profiles)
        self.runner = runner or self._systemctl
        self.control = control or native_users
        self.backup = self.config.with_name(self.config.name + ".provision-backup")

    @staticmethod
    def _systemctl(*args):
        return subprocess.run(["systemctl", *args], check=False, capture_output=True,
                              timeout=30).returncode == 0

    def _read(self):
        raw = self.config.read_bytes()
        parse_config(raw)
        if os.name == "posix" and self.config.stat().st_mode & 0o077:
            raise ProvisionError("server config must be private (chmod 600)")
        return raw

    def _runtime(self, expected):
        if not self.runner("restart", SERVICE) or not self.runner("is-active", "--quiet", SERVICE):
            return False
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            try:
                if self.control() == expected:
                    return True
            except (OSError, ValueError, ProvisionError):
                pass
            time.sleep(0.2)
        return False

    def _apply(self, before, after, expected):
        if self.backup.exists():
            raise ProvisionError("pending provision backup; run recover before changing users")
        # Stop the other config writer before inspecting its state or writing.
        # This also waits for any in-flight management request to exit.
        if not self.runner("stop", MANAGEMENT_SERVICE):
            raise ProvisionError("could not pause management service")
        changed = False
        try:
            if self.config.read_bytes() != before:
                raise ProvisionError("server config changed concurrently; retry")
            state_path = Path("/var/lib/mqvpn-management/state.json")
            if state_path.exists():
                state = json.loads(state_path.read_text(encoding="utf-8"))
                if state.get("status") == "pending":
                    raise ProvisionError("server management update pending; retry after recovery")
            atomic_write(self.backup, before)
            atomic_write(self.config, after)
            changed = True
            if not self._runtime(expected):
                raise ProvisionError("server restart or native user verification failed")
            if not self.runner("start", MANAGEMENT_SERVICE) or not self.runner(
                    "is-active", "--quiet", MANAGEMENT_SERVICE):
                raise ProvisionError("management service did not restart")
        except Exception as exc:
            if changed:
                atomic_write(self.config, before)
                restored = self._runtime(set(parse_config(before)[3]))
            else:
                restored = True
            management_up = self.runner("start", MANAGEMENT_SERVICE)
            if restored and management_up:
                self.backup.unlink(missing_ok=True)
                raise ProvisionError("change failed; previous server configuration restored") from exc
            raise ProvisionError("change failed; rollback or management restart failed; backup retained") from exc
        self.backup.unlink(missing_ok=True)
    def recover(self):
        if not self.backup.exists():
            return "No pending backup."
        before = self.backup.read_bytes()
        parse_config(before)
        atomic_write(self.config, before)
        if not self._runtime(set(parse_config(before)[3])):
            raise ProvisionError("recovery restart/verification failed; backup retained")
        self.backup.unlink()
        return "Recovered previous server configuration."

    def metadata(self):
        path = self.profiles / "metadata.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        required = {"version", "serverAddress", "serverPort", "tlsServerName", "insecure",
                    "controlAddress", "controlPort", "iperfHost", "iperfPort"}
        if not isinstance(data, dict) or set(data) != required or data["version"] != 1:
            raise ProvisionError("invalid profile metadata")
        return data

    def init(self, server_address, tls_name, insecure):
        raw = self._read()
        port = config_port(raw)
        valid_host(server_address, "server address")
        if tls_name:
            valid_host(tls_name, "TLS server name")
        if not insecure:
            if not tls_name:
                raise ProvisionError("TLS server name required unless --insecure is explicit")
            cert = self.config.parent / "server.crt"
            result = subprocess.run(["openssl", "verify", "-verify_hostname", tls_name,
                                     "-CApath", "/etc/ssl/certs", str(cert)],
                                    capture_output=True, check=False, timeout=10)
            if result.returncode:
                raise ProvisionError("server certificate is not CA-trusted for TLS server name")
        data = {"version": 1, "serverAddress": server_address, "serverPort": port,
                "tlsServerName": tls_name, "insecure": bool(insecure),
                "controlAddress": "10.88.0.1", "controlPort": 9443,
                "iperfHost": "10.88.0.1", "iperfPort": 5201}
        path = self.profiles / "metadata.json"
        if path.exists():
            if self.metadata() != data:
                raise ProvisionError("existing profile metadata differs; review before changing endpoint")
        else:
            atomic_write(path, json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
        return data

    def _profile_path(self, name):
        if not NAME_RE.fullmatch(name):
            raise ProvisionError("name must match [a-z][a-z0-9_-]{0,31}")
        return self.profiles / f"{name}.json"

    def _profile(self, name, key):
        data = self.metadata()
        profile = {"version": 1, "name": name, "serverAddress": data["serverAddress"],
                   "serverPort": data["serverPort"], "tlsServerName": data["tlsServerName"],
                   "authKey": key, "mtu": 1280, "controlAddress": data["controlAddress"],
                   "controlPort": data["controlPort"], "iperfHost": data["iperfHost"],
                   "iperfPort": data["iperfPort"], "serverControlAllowed": False, "insecure": data["insecure"]}
        profile_uri(profile)
        return profile

    def add(self, name):
        path = self._profile_path(name)
        before = self._read()
        config_port(before)
        users = parse_config(before)[3]
        if name in users:
            if not path.exists():
                raise ProvisionError("existing user is not managed by this provisioner")
            profile = self.export(name)
            return profile, False
        if path.exists():
            raise ProvisionError("stale profile exists; review it before adding user")
        key = secrets.token_urlsafe(32)
        profile = self._profile(name, key)
        after = render_user(before, name, key)
        atomic_write(path, json.dumps(profile, sort_keys=True, separators=(",", ":")).encode())
        try:
            self._apply(before, after, set(users) | {name})
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return profile, True

    def revoke(self, name):
        path = self._profile_path(name)
        before = self._read()
        users = parse_config(before)[3]
        if name not in users:
            path.unlink(missing_ok=True)
            return False
        if not path.exists():
            raise ProvisionError("user is not managed by this provisioner")
        after = render_user(before, name, None)
        self._apply(before, after, set(users) - {name})
        path.unlink(missing_ok=True)
        return True

    def export(self, name):
        path = self._profile_path(name)
        before = self._read()
        users = parse_config(before)[3]
        if name not in users or not path.exists():
            raise ProvisionError("active managed profile not found")
        profile = json.loads(path.read_text(encoding="utf-8"))
        if profile.get("name") != name or not hmac.compare_digest(profile.get("authKey", ""), users[name]):
            raise ProvisionError("profile and server credential differ")
        profile_uri(profile)
        return profile

    def list_users(self):
        users = parse_config(self._read())[3]
        return [(name, (self.profiles / f"{name}.json").exists()) for name in sorted(users)]


def preflight(args):
    if os.geteuid() != 0:
        raise ProvisionError("run as root")
    valid_host(args.server_address, "server address")
    if args.tls_server_name:
        valid_host(args.tls_server_name, "TLS server name")
    if not args.insecure and not args.tls_server_name:
        raise ProvisionError("provide --tls-server-name or explicitly choose --insecure for a PoC")
    if not NAME_RE.fullmatch(args.name):
        raise ProvisionError("invalid profile name")
    required = ["systemctl", "openssl", "qrencode", "iperf3", "python3"]
    missing = [cmd for cmd in required if not shutil.which(cmd)]
    if missing:
        raise ProvisionError("missing dependencies: " + ", ".join(missing))
    if args.config.exists():
        validate_tunnel_subnet(args.config.read_bytes())
    if args.show_qr and not sys.stdout.isatty():
        raise ProvisionError("--show-qr requires an interactive terminal")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=CONFIG, help=argparse.SUPPRESS)
    parser.add_argument("--profiles-dir", type=Path, default=PROFILES, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "init"):
        item = sub.add_parser(command)
        item.add_argument("--name", required=True)
        item.add_argument("--server-address", required=True)
        item.add_argument("--tls-server-name", default="")
        item.add_argument("--insecure", action="store_true")
        item.add_argument("--show-qr", action="store_true")
    item = sub.add_parser("add")
    item.add_argument("name")
    item.add_argument("--show-qr", action="store_true")
    sub.add_parser("list")
    item = sub.add_parser("revoke")
    item.add_argument("name")
    item = sub.add_parser("export")
    item.add_argument("name")
    item.add_argument("--show-qr", action="store_true", required=True)
    sub.add_parser("recover")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        raise ProvisionError("run as root")
    if args.command == "preflight":
        preflight(args)
        print("Preflight OK.")
        return
    provisioner = Provisioner(args.config, args.profiles_dir)
    lock = LOCK
    lock.parent.mkdir(exist_ok=True, parents=True)
    with open(lock, "a+b") as fd:
        fcntl.flock(fd, fcntl.LOCK_EX)
        if args.command == "init":
            preflight(args)
            provisioner.init(args.server_address, args.tls_server_name, args.insecure)
            profile, created = provisioner.add(args.name)
            print("Profile created." if created else "Profile already exists.")
            if args.show_qr:
                show_qr(profile)
        elif args.command == "add":
            if args.show_qr and (not sys.stdout.isatty() or not shutil.which("qrencode")):
                raise ProvisionError("QR display needs a TTY and qrencode")
            profile, created = provisioner.add(args.name)
            print("Profile created." if created else "Profile already exists.")
            if args.show_qr:
                show_qr(profile)
        elif args.command == "list":
            for name, managed in provisioner.list_users():
                print(f"{name}\t{'managed' if managed else 'external'}")
        elif args.command == "revoke":
            print("User revoked." if provisioner.revoke(args.name) else "User already absent.")
        elif args.command == "export":
            show_qr(provisioner.export(args.name))
        elif args.command == "recover":
            print(provisioner.recover())


if __name__ == "__main__":
    try:
        main()
    except (ProvisionError, OSError, ValueError, subprocess.TimeoutExpired,
            subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        # Never print exception arguments from subprocess commands carrying profile data.
        print(f"Provisioning failed: {exc if isinstance(exc, ProvisionError) else type(exc).__name__}", file=sys.stderr)
        sys.exit(1)