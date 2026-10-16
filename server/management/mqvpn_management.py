#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
"""Authenticated mqvpn settings service, reachable only through the VPN."""
import argparse
try:
    import fcntl
except ImportError:  # Windows unit tests.
    fcntl = None
import hashlib
import hmac
import json
import os
import re
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from pathlib import Path

SCHEDULERS = ("wlb", "minrtt", "wlb_udp_pin", "backup_fec")
CC = ("bbr2", "bbr", "cubic")
FIELDS = {"scheduler": ("Multipath", "Scheduler"),
          "cc": ("Multipath", "CC"), "mtu": ("Interface", "MTU")}
DEFAULTS = {"scheduler": "wlb", "cc": "bbr2", "mtu": 1382}
MAX_REQUEST = 4096
MAX_AGE = 60
PROVISION_LOCK = Path("/run/lock/mqvpn-provision.lock")
SECTION_RE = re.compile(r"^\s*\[([^]]+)\]\s*(?:[#;].*)?$")
KEY_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*?)\s*$")


class RequestError(Exception):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RequestError("duplicate JSON field")
        result[key] = value
    return result


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def config_entries(raw):
    lines = raw.decode("utf-8").splitlines(keepends=True)
    section = None
    entries = {}
    sections = {}
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped[0] in "#;":
            continue
        match = SECTION_RE.match(line)
        if match:
            section = match.group(1).lower()
            if section in sections and section in {"interface", "auth", "multipath", "control"}:
                raise RequestError("duplicate config section")
            sections[section] = index
            continue
        match = KEY_RE.match(line)
        if match and section:
            key = (section, match.group(1).lower())
            if key in entries and key in {("auth", "key"), ("control", "listen"),
                                          ("interface", "mtu"), ("multipath", "scheduler"),
                                          ("multipath", "cc")}:
                raise RequestError("duplicate config key")
            entries[key] = (index, match.group(2).strip())
    return lines, sections, entries


def read_config(path):
    raw = Path(path).read_bytes()
    _, _, entries = config_entries(raw)
    auth = entries.get(("auth", "key"))
    if not auth or not auth[1] or auth[1].startswith("<"):
        raise RequestError("Auth Key unavailable")
    desired = dict(DEFAULTS)
    for field, (section, key) in FIELDS.items():
        entry = entries.get((section.lower(), key.lower()))
        if entry:
            desired[field] = entry[1]
    if desired["mtu"] == "0":
        desired["mtu"] = DEFAULTS["mtu"]
    else:
        try:
            desired["mtu"] = int(desired["mtu"])
        except (TypeError, ValueError):
            raise RequestError("invalid configured MTU")
    return raw, auth[1].encode("utf-8"), desired


def render_config(raw, desired):
    lines, sections, entries = config_entries(raw)
    newline = "\r\n" if b"\r\n" in raw else "\n"
    for field, (section, key) in FIELDS.items():
        location = entries.get((section.lower(), key.lower()))
        if location:
            lines[location[0]] = f"{key} = {desired[field]}{newline}"
        else:
            if section.lower() not in sections:
                raise RequestError(f"missing [{section}] section")
            lines.insert(sections[section.lower()] + 1,
                         f"{key} = {desired[field]}{newline}")
            lines, sections, entries = config_entries("".join(lines).encode("utf-8"))
    return "".join(lines).encode("utf-8")


def atomic_write(path, content):
    path = Path(path)
    old_stat = path.stat() if path.exists() else None
    fd, temp_name = tempfile.mkstemp(prefix=".mqvpn-management-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), (old_stat.st_mode & 0o777) if old_stat else 0o600)
            if old_stat and hasattr(os, "fchown"):
                os.fchown(stream.fileno(), old_stat.st_uid, old_stat.st_gid)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
        if hasattr(os, "O_DIRECTORY"):
            directory_fd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def validate_desired(value, fec_enabled):
    if not isinstance(value, dict) or set(value) != set(FIELDS):
        raise RequestError("desired requires exactly scheduler, cc, mtu")
    if type(value["scheduler"]) is not str or value["scheduler"] not in SCHEDULERS:
        raise RequestError("unsupported scheduler")
    if value["scheduler"] == "backup_fec" and not fec_enabled:
        raise RequestError("backup_fec requires confirmed FEC support")
    if type(value["cc"]) is not str or value["cc"] not in CC:
        raise RequestError("unsupported congestion control")
    if type(value["mtu"]) is not int or not 1280 <= value["mtu"] <= 9000:
        raise RequestError("MTU must be 1280..9000")
    return value


def control_build_info(host="127.0.0.1", port=9090):
    try:
        with socket.create_connection((host, port), timeout=1.5) as sock:
            sock.settimeout(1.5)
            sock.sendall(b'{"cmd":"get_build_info"}\n')
            response = sock.makefile("rb").readline(4097)
            if len(response) > 4096 or not response.endswith(b"\n"):
                return None
            value = json.loads(response)
            return value if value.get("ok") is True else None
    except (OSError, ValueError, TypeError, AttributeError):
        return None


class Management:
    def __init__(self, config, state_path, runner=None, control=None,
                 restart_grace_sec=2.0, provision_lock=PROVISION_LOCK):
        if not 0 <= restart_grace_sec <= 10:
            raise ValueError("restart grace must be 0..10 seconds")
        self.restart_grace_sec = restart_grace_sec
        self.config = Path(config)
        self.state_path = Path(state_path)
        self.backup_path = self.config.with_name(self.config.name + ".management-backup")
        self.provision_lock = Path(provision_lock)
        self.provision_lock_fd = None
        self.runner = runner or self._run
        self.control = control or control_build_info
        self.lock = threading.RLock()
        self.nonces = {}
        self.pending = False
        self.state = self._read_state()
        if self.state.get("status") == "pending":
            try:
                atomic_write(self.config, self.backup_path.read_bytes())
                recovered = self.runner("systemctl", "restart", "mqvpn-server.service")
                self.state = {"status": "failed", "applied": None,
                              "error": "interrupted apply rolled back" if recovered
                                       else "interrupted apply; rollback restart failed"}
                if recovered:
                    self.backup_path.unlink(missing_ok=True)
            except OSError:
                self.state = {"status": "unknown", "applied": None,
                              "error": "interrupted apply; rollback failed"}
            self._save_state()
        read_config(self.config)  # Fail closed before opening a socket.

    def _lock_provision(self):
        if fcntl is None:
            return
        self.provision_lock.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = open(self.provision_lock, "a+b")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except Exception:
            fd.close()
            raise
        self.provision_lock_fd = fd

    def _unlock_provision(self):
        fd = self.provision_lock_fd
        self.provision_lock_fd = None
        if fd is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
            fd.close()
    def _read_state(self):
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {"status": "unknown", "applied": None, "error": None}
        except (OSError, ValueError, TypeError, AttributeError):
            return {"status": "unknown", "applied": None, "error": None}

    def _save_state(self):
        self.state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".mqvpn-state-", dir=self.state_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                os.fchmod(stream.fileno(), 0o600)
                json.dump(self.state, stream, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.state_path)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    @staticmethod
    def _run(*command):
        result = subprocess.run(command, capture_output=True, timeout=30,
                                check=False)
        return result.returncode == 0

    def snapshot(self):
        _, _, desired = read_config(self.config)
        build = self.control()
        observed = build.get("scheduler") if isinstance(build, dict) else None
        fec = isinstance(build, dict) and build.get("fec_enabled") == 1
        status = self.state.get("status", "unknown")
        if status == "applied" and self.state.get("applied") != desired:
            status = "unknown"
        if status == "applied" and observed != desired["scheduler"]:
            status = "unknown"
        return {"ok": True, "capabilities": {
                    "scheduler": list(SCHEDULERS if fec else SCHEDULERS[:-1]),
                    "cc": list(CC), "mtu": {"min": 1280, "max": 9000}},
                "desired": desired, "applied": self.state.get("applied"),
                "observedScheduler": observed, "status": status,
                "requiresReconnect": status == "pending",
                "error": self.state.get("error") if status in ("failed", "unknown") else None}

    def authenticate(self, request):
        common = {"version", "op", "ts", "nonce", "mac"}
        if not isinstance(request, dict) or set(request) not in (common, common | {"desired"}):
            raise RequestError("invalid request fields")
        if type(request["version"]) is not int or request["version"] != 1:
            raise RequestError("unsupported version")
        if type(request["op"]) is not str or request["op"] not in ("get", "set"):
            raise RequestError("unsupported operation")
        if (request["op"] == "set") != ("desired" in request):
            raise RequestError("invalid operation fields")
        timestamp, nonce, mac = request["ts"], request["nonce"], request["mac"]
        if type(timestamp) is not int or abs(time.time() - timestamp) > MAX_AGE:
            raise RequestError("timestamp outside allowed window")
        if type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{32}", nonce):
            raise RequestError("invalid nonce")
        if type(mac) is not str or not re.fullmatch(r"[0-9a-f]{64}", mac):
            raise RequestError("invalid MAC")
        _, key, _ = read_config(self.config)
        signed = dict(request)
        del signed["mac"]
        expected = hmac.new(key, canonical(signed), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, mac):
            raise RequestError("authentication failed")
        now = time.time()
        self.nonces = {item: expiry for item, expiry in self.nonces.items() if expiry > now}
        if nonce in self.nonces:
            raise RequestError("replayed request")
        if len(self.nonces) >= 4096:
            raise RequestError("request replay cache full")
        self.nonces[nonce] = now + 2 * MAX_AGE
        return request["op"]

    def handle(self, request):
        with self.lock:
            op = self.authenticate(request)
            if op == "get":
                return self.snapshot(), None
            if self.pending:
                raise RequestError("configuration change already pending")
            self._lock_provision()
            try:
                return self._prepare_set(request)
            finally:
                if not self.pending:
                    self._unlock_provision()

    def _prepare_set(self, request):
        raw, _, before = read_config(self.config)
        build = self.control()
        if build is None:
            raise RequestError("local control API unavailable")
        fec = build.get("fec_enabled") == 1
        desired = validate_desired(request["desired"], fec)
        observed = build.get("scheduler") if isinstance(build, dict) else None
        if desired == before and self.state.get("status") == "applied" and self.state.get("applied") == before and observed == desired["scheduler"]:
            return self.snapshot(), None
        updated = render_config(raw, desired)
        old_state = self.state
        try:
            atomic_write(self.backup_path, raw)
            self.state = {"status": "pending", "applied": old_state.get("applied"),
                          "error": None}
            self._save_state()
            atomic_write(self.config, updated)
        except OSError:
            atomic_write(self.config, raw)
            self.state = old_state
            self._save_state()
            self.backup_path.unlink(missing_ok=True)
            raise
        self.pending = True
        response = {"ok": True, "capabilities": {
                    "scheduler": list(SCHEDULERS if fec else SCHEDULERS[:-1]),
                    "cc": list(CC), "mtu": {"min": 1280, "max": 9000}},
                    "desired": desired, "applied": old_state.get("applied"),
                    "observedScheduler": observed, "status": "pending",
                    "requiresReconnect": True, "error": None}
        return response, (raw, desired, before)

    def apply(self, rollback):
        raw, desired, before = rollback
        time.sleep(self.restart_grace_sec)  # Let the SET reply cross a slow VPN path.
        try:
            if not self.runner("systemctl", "restart", "mqvpn-server.service"):
                raise RuntimeError("server restart failed")
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                if self.runner("systemctl", "is-active", "--quiet", "mqvpn-server.service"):
                    build = self.control()
                    if build is not None:
                        if build.get("scheduler") == desired["scheduler"]:
                            break
                time.sleep(0.3)
            else:
                raise RuntimeError("server failed post-restart validation")
            with self.lock:
                self.state = {"status": "applied", "applied": desired, "error": None}
                self._save_state()
            try:
                self.backup_path.unlink(missing_ok=True)
            except OSError:
                pass
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            try:
                atomic_write(self.config, raw)
                recovered = self.runner("systemctl", "restart", "mqvpn-server.service")
                error = "apply failed; previous configuration restored" if recovered else \
                        "apply failed; rollback restart failed"
                if recovered:
                    try:
                        self.backup_path.unlink(missing_ok=True)
                    except OSError:
                        pass
            except (OSError, RuntimeError):
                error = "apply failed; rollback failed"
            with self.lock:
                self.state = {"status": "failed",
                              "applied": None,
                              "error": error}
                self._save_state()
        finally:
            with self.lock:
                self.pending = False
                self._unlock_provision()


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        try:
            line = self.rfile.readline(MAX_REQUEST + 1)
            if not line.endswith(b"\n") or len(line) > MAX_REQUEST:
                raise RequestError("request too large or incomplete")
            request = json.loads(line.decode("utf-8"), object_pairs_hook=unique_object)
            response, pending = self.server.manager.handle(request)
        except (RequestError, ValueError, UnicodeError, OSError) as error:
            response, pending = {"ok": False, "error": str(error)}, None
        try:
            self.wfile.write(canonical(response) + b"\n")
            self.wfile.flush()
        except OSError:
            pass  # A radio disconnect must not strand an accepted SET.
        finally:
            if pending:
                threading.Thread(target=self.server.manager.apply, args=(pending,),
                                 daemon=True).start()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address, manager):
        self.manager = manager
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", choices=["10.88.0.1"], default="10.88.0.1")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--config", default="/etc/mqvpn/server.conf")
    parser.add_argument("--state", default="/var/lib/mqvpn-management/state.json")
    parser.add_argument("--restart-grace-sec", type=float, default=2.0)
    args = parser.parse_args()
    manager = Management(args.config, args.state,
                         restart_grace_sec=args.restart_grace_sec)
    with Server((args.bind, args.port), manager) as server:
        server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
