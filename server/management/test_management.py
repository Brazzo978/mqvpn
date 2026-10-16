# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
import hashlib
import hmac
import importlib.util
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "mqvpn_management", Path(__file__).with_name("mqvpn_management.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

CONFIG = b"""# untouched comment
[Interface]
Listen = 0.0.0.0:443
Subnet = 10.88.0.0/24
[Auth]
Key = test-only-key
[Multipath]
Scheduler = wlb
CC = bbr2
[TLS]
Cert = /etc/mqvpn/cert.pem
Key = /etc/mqvpn/key.pem
"""


class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = Path(self.temp.name) / "server.conf"
        self.config.write_bytes(CONFIG)
        self.state = Path(self.temp.name) / "state.json"
        self.active_scheduler = "wlb"
        self.restart_count = 0
        self.fail_next_restart = False
        self.manager = m.Management(self.config, self.state,
                                    runner=self.run_command, control=self.control,
                                    restart_grace_sec=0,
                                    provision_lock=Path(self.temp.name) / "provision.lock")
        self.addCleanup(self.manager._unlock_provision)

    def control(self):
        return {"ok": True, "scheduler": self.active_scheduler, "fec_enabled": 0}

    def run_command(self, *parts):
        if "restart" in parts:
            self.restart_count += 1
            if self.fail_next_restart:
                self.fail_next_restart = False
                return False
            _, _, desired = m.read_config(self.config)
            self.active_scheduler = desired["scheduler"]
        return True

    def signed(self, op, desired=None):
        request = {"version": 1, "op": op, "ts": int(time.time()),
                   "nonce": f"{time.time_ns():032x}"[-32:]}
        if desired is not None:
            request["desired"] = desired
        request["mac"] = hmac.new(b"test-only-key", m.canonical(request),
                                  hashlib.sha256).hexdigest()
        return request

    def test_default_restart_grace_is_two_seconds(self):
        manager = m.Management(self.config, self.state,
                               runner=self.run_command, control=self.control)
        self.assertEqual(2.0, manager.restart_grace_sec)

    def test_signed_get_replay_and_tamper(self):
        request = self.signed("get")
        response, pending = self.manager.handle(request)
        self.assertTrue(response["ok"])
        self.assertIsNone(pending)
        self.assertEqual("unknown", response["status"])
        with self.assertRaisesRegex(m.RequestError, "replayed"):
            self.manager.handle(request)
        altered = self.signed("get")
        altered["ts"] -= 1
        with self.assertRaisesRegex(m.RequestError, "authentication failed"):
            self.manager.handle(altered)

    def test_initial_equal_set_still_verifies_and_noop_after_applied(self):
        desired = dict(m.DEFAULTS)
        response, pending = self.manager.handle(self.signed("set", desired))
        self.assertEqual("pending", response["status"])
        self.assertTrue(response["requiresReconnect"])
        self.assertIsNotNone(pending)
        self.manager.apply(pending)
        self.assertEqual(1, self.restart_count)
        response, pending = self.manager.handle(self.signed("set", desired))
        self.assertEqual("applied", response["status"])
        self.assertIsNone(pending)
        self.assertEqual(1, self.restart_count)

    def test_update_preserves_auth_tls_and_observes_scheduler(self):
        desired = {"scheduler": "minrtt", "cc": "cubic", "mtu": 1400}
        response, pending = self.manager.handle(self.signed("set", desired))
        self.assertEqual("pending", response["status"])
        self.manager.apply(pending)
        response, _ = self.manager.handle(self.signed("get"))
        self.assertEqual("applied", response["status"])
        self.assertEqual(desired, response["applied"])
        self.assertEqual("minrtt", response["observedScheduler"])
        content = self.config.read_bytes()
        self.assertIn(b"Key = test-only-key", content)
        self.assertIn(b"Cert = /etc/mqvpn/cert.pem", content)
        self.assertIn(b"# untouched comment", content)

    def test_failed_restart_rolls_back(self):
        self.fail_next_restart = True
        desired = {"scheduler": "minrtt", "cc": "cubic", "mtu": 1400}
        _, pending = self.manager.handle(self.signed("set", desired))
        self.manager.apply(pending)
        self.assertEqual(CONFIG, self.config.read_bytes())
        response, _ = self.manager.handle(self.signed("get"))
        self.assertEqual("failed", response["status"])
        self.assertEqual(2, self.restart_count)

    def test_rejects_unknown_fields_unsupported_values_and_duplicate_json(self):
        desired = {"scheduler": "wlb", "cc": "none", "mtu": 1382}
        with self.assertRaisesRegex(m.RequestError, "unsupported congestion"):
            self.manager.handle(self.signed("set", desired))
        desired = dict(m.DEFAULTS, extra=True)
        with self.assertRaisesRegex(m.RequestError, "exactly"):
            self.manager.handle(self.signed("set", desired))
        with self.assertRaisesRegex(m.RequestError, "duplicate"):
            json.loads('{"op":"get","op":"set"}', object_pairs_hook=m.unique_object)




    def test_set_keeps_two_native_users_and_admin_key(self):
        raw = CONFIG.replace(b"Key = test-only-key\n",
                             b"Key = test-only-key\nUser = alice:alice-psk\nUser = bob:bob-psk\n")
        self.config.write_bytes(raw)
        desired = {"scheduler": "minrtt", "cc": "cubic", "mtu": 1400}
        _, pending = self.manager.handle(self.signed("set", desired))
        self.manager.apply(pending)
        content = self.config.read_bytes()
        self.assertIn(b"Key = test-only-key", content)
        self.assertEqual(1, content.count(b"User = alice:alice-psk"))
        self.assertEqual(1, content.count(b"User = bob:bob-psk"))
    def test_repeatable_unmanaged_sections_survive_edit(self):
        raw = CONFIG + b"[ReorderRule]\nProto = udp\nPort = 443\n" + \
              b"[ReorderRule]\nProto = udp\nPort = 53\n"
        rendered = m.render_config(raw, {"scheduler": "minrtt", "cc": "cubic", "mtu": 1400})
        self.assertEqual(2, rendered.count(b"[ReorderRule]"))
        self.assertIn(b"Port = 443", rendered)
        self.assertIn(b"Port = 53", rendered)

    def test_interrupted_apply_recovers_backup_on_start(self):
        desired = {"scheduler": "minrtt", "cc": "cubic", "mtu": 1400}
        _, pending = self.manager.handle(self.signed("set", desired))
        self.assertIsNotNone(pending)
        self.assertTrue(self.manager.backup_path.exists())
        self.assertNotEqual(CONFIG, self.config.read_bytes())
        # A killed process releases its flock; emulate that before recovery.
        self.manager._unlock_provision()
        recovered = m.Management(self.config, self.state,
                                 runner=self.run_command, control=self.control)
        self.assertEqual(CONFIG, self.config.read_bytes())
        self.assertEqual("failed", recovered.state["status"])
        self.assertFalse(recovered.backup_path.exists())

    def test_disconnected_client_still_schedules_apply(self):
        from io import BytesIO
        from types import SimpleNamespace
        started = threading.Event()
        self.manager.apply = lambda pending: started.set()
        handler = object.__new__(m.Handler)
        handler.server = SimpleNamespace(manager=self.manager)
        handler.connection = SimpleNamespace(settimeout=lambda _: None)
        handler.rfile = BytesIO(m.canonical(self.signed("set", dict(m.DEFAULTS))) + b"\n")

        class BrokenWriter:
            def write(self, _):
                raise BrokenPipeError()
            def flush(self):
                raise BrokenPipeError()

        handler.wfile = BrokenWriter()
        handler.handle()
        self.assertTrue(started.wait(1))

    def test_tcp_framing_and_hmac(self):
        with m.Server(("127.0.0.1", 0), self.manager) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            with socket.create_connection(server.server_address, timeout=2) as client:
                client.sendall(m.canonical(self.signed("get")) + b"\n")
                response = json.loads(client.makefile("rb").readline())
            server.shutdown()
        self.assertTrue(response["ok"])
        self.assertEqual("wlb", response["desired"]["scheduler"])


if __name__ == "__main__":
    unittest.main()
