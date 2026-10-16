#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
import base64
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("mqvpn_provision", Path(__file__).with_name("mqvpn_provision.py"))
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)

CONFIG = ("[Interface]\nListen = 0.0.0.0:443\nSubnet = 10.88.0.0/24\n"
          "[TLS]\nCert = /etc/mqvpn/server.crt\nKey = /etc/mqvpn/server.key\n"
          "[Auth]\nKey = global-admin-key\nMaxClients = 64\n"
          "[Control]\nListen = 127.0.0.1:9090\n")


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "server.conf"
        self.config.write_text(CONFIG, encoding="utf-8")
        self.config.chmod(0o600)
        self.profiles = self.root / "profiles"
        self.calls = []

        def run(*args):
            self.calls.append(args)
            return True

        self.provision = module.Provisioner(self.config, self.profiles, run,
            lambda: set(module.parse_config(self.config.read_bytes())[3]))
        self.provision.init("vpn.example.test", "", True)

    def test_add_export_revoke_and_idempotency(self):
        profile, created = self.provision.add("phone1")
        self.assertTrue(created)
        self.assertEqual(profile["name"], "phone1")
        self.assertEqual(profile["serverAddress"], "vpn.example.test")
        self.assertEqual(profile["serverPort"], 443)
        self.assertEqual(profile["authKey"], module.parse_config(self.config.read_bytes())[3]["phone1"])
        self.assertNotIn(":", profile["authKey"])
        self.assertFalse(profile["serverControlAllowed"])
        self.assertTrue(profile["insecure"])
        self.assertEqual(profile["mtu"], 1280)
        uri = module.profile_uri(profile)
        self.assertTrue(uri.startswith("mqvpn://profile?data="))
        encoded = uri.split("data=", 1)[1]
        decoded = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual(decoded, profile)
        self.assertNotIn("global-admin-key", uri)
        self.assertEqual(self.provision.add("phone1"), (profile, False))
        self.assertTrue(self.provision.revoke("phone1"))
        self.assertFalse(self.provision.revoke("phone1"))
        with self.assertRaises(module.ProvisionError):
            self.provision.export("phone1")
        self.assertNotIn("phone1", module.parse_config(self.config.read_bytes())[3])
        self.assertFalse((self.profiles / "phone1.json").exists())

    def test_two_users_are_independent(self):
        one, _ = self.provision.add("alice")
        two, _ = self.provision.add("bob")
        self.assertNotEqual(one["authKey"], two["authKey"])
        self.provision.revoke("alice")
        self.assertEqual(self.provision.export("bob"), two)
        self.assertEqual(self.provision.list_users(), [("bob", True)])

    def test_failed_restart_restores_config_without_leaking_profile(self):
        before = self.config.read_bytes()
        count = 0
        def run(*args):
            nonlocal count
            if args == ("restart", module.SERVICE):
                count += 1
                return count > 1
            return True
        self.provision.runner = run
        with self.assertRaisesRegex(module.ProvisionError, "restored"):
            self.provision.add("alice")
        self.assertEqual(self.config.read_bytes(), before)
        self.assertFalse((self.profiles / "alice.json").exists())
        self.assertFalse(self.provision.backup.exists())

    def test_wrong_subnet_rejected_before_profiles_or_services_change(self):
        wrong = CONFIG.replace("10.88.0.0/24", "10.0.0.0/24")
        self.config.write_text(wrong, encoding="utf-8")
        self.calls.clear()
        with self.assertRaisesRegex(module.ProvisionError, "10.88.0.0/24"):
            self.provision.init("vpn.example.test", "", True)
        with self.assertRaises(module.ProvisionError):
            self.provision.add("alice")
        self.assertEqual(self.config.read_text(encoding="utf-8"), wrong)
        self.assertEqual(self.calls, [])
        self.assertFalse((self.profiles / "alice.json").exists())

    def test_bootstrap_passes_the_companion_subnet_to_installer(self):
        setup = Path(__file__).with_name("setup.sh").read_text(encoding="utf-8")
        self.assertIn("--subnet 10.88.0.0/24 --enable-control 9090 --start", setup)

    def test_validation_rejects_ambiguous_config_and_names(self):
        with self.assertRaises(module.ProvisionError):
            self.provision.add("../../bad")
        with self.assertRaises(module.ProvisionError):
            module.parse_config((CONFIG + "[Auth]\nUser = bob:key\n").encode())
        with self.assertRaises(module.ProvisionError):
            module.parse_config(CONFIG.replace("MaxClients = 64", "User = bob:key\nUser = bob:other\nMaxClients = 64").encode())
        self.assertEqual(module.render_user(CONFIG.encode(), "a", "key").count(b"User = a:key"), 1)


if __name__ == "__main__":
    unittest.main()