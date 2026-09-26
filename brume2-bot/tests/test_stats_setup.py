#!/usr/bin/env python3
"""Statistics migration invariants and transaction failure regression tests."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
try:
    import requests
except ImportError:
    # Tests do not make Telegram/network calls or instantiate HTTP sessions.
    sys.modules["requests"] = types.ModuleType("requests")
import install_user_stats as setup


EXISTING_ID = "11111111-1111-4111-8111-111111111111"
PEOPLE = ["alice", "bob", "carol"]


def fixture():
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "vmess-tls", "listen": "0.0.0.0", "port": 443, "protocol": "vmess",
            "settings": {"clients": [{"id": EXISTING_ID, "alterId": 0, "security": "auto"}]},
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {
                "certificates": [{"certificateFile": "/etc/xray/certs/server.crt", "keyFile": "/etc/xray/certs/server.key"}]}},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "routing": {"rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}]},
    }


class MigrationTests(unittest.TestCase):
    def test_add_people_preserves_shared_uuid_and_transport(self):
        original = fixture()
        untouched = copy.deepcopy(original)
        result = setup.prepare_config(original, PEOPLE)
        self.assertEqual(original, untouched)
        clients = result["inbounds"][0]["settings"]["clients"]
        self.assertEqual([item["email"] for item in clients], ["shared", *PEOPLE])
        self.assertEqual(clients[0]["id"], EXISTING_ID)
        self.assertEqual(len({item["id"] for item in clients}), 4)
        self.assertTrue(all(item["level"] == 0 for item in clients))
        for name in ("streamSettings", "sniffing", "listen", "port", "protocol", "tag"):
            self.assertEqual(result["inbounds"][0][name], original["inbounds"][0][name])
        self.assertEqual(result["routing"], original["routing"])
        self.assertEqual(result["outbounds"], original["outbounds"])
        self.assertEqual(result["api"]["listen"], "127.0.0.1:10085")
        self.assertEqual(result["api"]["services"], ["StatsService"])

    def test_repeated_migration_is_idempotent_and_never_rotates(self):
        first = setup.prepare_config(fixture(), PEOPLE)
        with mock.patch.object(setup.uuid, "uuid4", side_effect=AssertionError("unexpected UUID creation")):
            second = setup.prepare_config(first, PEOPLE)
        self.assertEqual(first, second)

    def test_preserves_existing_levels_system_policy_and_other_flags(self):
        original = fixture()
        original["inbounds"][0]["settings"]["clients"][0].update(email="family-shared", level=4)
        original["policy"] = {"system": {"statsInboundUplink": True, "statsOutboundDownlink": False},
                              "levels": {"4": {"handshake": 6, "connIdle": 60, "statsUserUplink": False}}}
        result = setup.prepare_config(original, PEOPLE)
        self.assertEqual(result["policy"]["system"], original["policy"]["system"])
        self.assertEqual(result["policy"]["levels"]["4"]["handshake"], 6)
        self.assertEqual(result["policy"]["levels"]["4"]["connIdle"], 60)
        self.assertEqual(result["inbounds"][0]["settings"]["clients"][0]["level"], 4)
        for level in ("0", "4"):
            for flag in ("statsUserUplink", "statsUserDownlink", "statsUserOnline"):
                self.assertIs(result["policy"]["levels"][level][flag], True)

    def test_multiple_inbounds_keep_original_ids_and_reality_settings(self):
        original = fixture()
        original["inbounds"].append({"tag": "reality", "listen": "0.0.0.0", "port": 9443,
                                    "protocol": "vless", "settings": {"decryption": "none", "clients": [
                                        {"id": "22222222-2222-4222-8222-222222222222", "flow": "xtls-rprx-vision"}]},
                                    "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                                        "privateKey": "DUMMY_PRIVATE_SECRET_1234567890000000000000000",
                                        "dest": "example.com:443", "serverNames": ["example.com"], "shortIds": ["12345678"]}}})
        result = setup.prepare_config(original, PEOPLE)
        ids = []
        labels = []
        for before, after in zip(original["inbounds"], result["inbounds"]):
            self.assertEqual(before["settings"]["clients"][0]["id"], after["settings"]["clients"][0]["id"])
            self.assertEqual(before["streamSettings"], after["streamSettings"])
            self.assertEqual(len(after["settings"]["clients"]), 4)
            ids.extend(item["id"] for item in after["settings"]["clients"])
            labels.extend(item["email"] for item in after["settings"]["clients"])
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(labels), len(set(labels)))
        self.assertEqual(result, setup.prepare_config(result, PEOPLE))

    def test_preserves_existing_routed_api_services_and_routing(self):
        original = fixture()
        original["api"] = {"tag": "existing-api", "services": ["HandlerService"]}
        original["inbounds"].append({"tag": "api-in", "listen": "127.0.0.1", "port": 10085,
                                    "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}})
        original["routing"]["rules"].insert(0, {"type": "field", "inboundTag": ["api-in"], "outboundTag": "existing-api"})
        result = setup.prepare_config(original)
        self.assertEqual(result["api"], {"tag": "existing-api", "services": ["HandlerService", "StatsService"]})
        self.assertEqual(result["routing"], original["routing"])
        self.assertEqual(result["inbounds"][1], original["inbounds"][1])

    def test_legacy_users_key_is_preserved_and_readable(self):
        original = fixture()
        settings = original["inbounds"][0]["settings"]
        settings["users"] = settings.pop("clients")
        result = setup.prepare_config(original, PEOPLE)
        self.assertNotIn("clients", result["inbounds"][0]["settings"])
        self.assertEqual(len(setup.stats.configured_users(result)), 4)

    def test_relabels_unsafe_and_duplicate_emails_without_changing_ids(self):
        original = fixture()
        clients = original["inbounds"][0]["settings"]["clients"]
        clients[0]["email"] = EXISTING_ID
        clients.append({"id": "22222222-2222-4222-8222-222222222222", "email": "Dan"})
        clients.append({"id": "33333333-3333-4333-8333-333333333333", "email": "alice"})
        result = setup.prepare_config(original)
        updated = result["inbounds"][0]["settings"]["clients"]
        self.assertEqual([item["id"] for item in clients], [item["id"] for item in updated])
        self.assertEqual(len(updated), len({item["email"].casefold() for item in updated}))
        self.assertNotIn(EXISTING_ID, [item["email"] for item in updated])

    def test_invalid_policy_and_public_api_are_refused(self):
        for change in (lambda cfg: cfg.update(policy=[]),
                       lambda cfg: cfg.update(api={"listen": "0.0.0.0:10085", "services": []}),
                       lambda cfg: cfg["inbounds"][0]["settings"]["clients"][0].update(level=True)):
            original = fixture()
            change(original)
            before = copy.deepcopy(original)
            with self.assertRaises(setup.SetupError):
                setup.prepare_config(original, PEOPLE)
            self.assertEqual(original, before)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.config_path = self.directory / "config.json"
        self.original = fixture()
        self.original_bytes = ("// original comment retained on rollback\n" + json.dumps(self.original, indent=2) + "\n").encode()
        self.config_path.write_bytes(self.original_bytes)
        self.digest = hashlib.sha256(self.original_bytes).hexdigest()
        self.events = []
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(mock.patch.multiple(setup.bot, XRAY_CONFIG=self.config_path,
                                                     BACKUP_DIR=self.directory / "backups",
                                                     LOCK_FILE=self.directory / "lock"))
        self.stack.enter_context(mock.patch.object(setup.bot, "health_snapshot", return_value={"running": True, "missing_ports": []}))
        self.validation = self.stack.enter_context(mock.patch.object(setup.bot, "validate_config_path", side_effect=self.validate))
        self.restart = self.stack.enter_context(mock.patch.object(setup.bot, "restart_and_verify", side_effect=self.start))
        self.verify = self.stack.enter_context(mock.patch.object(setup, "verify_stats", return_value=[
            setup.stats.UserStats("shared", 0, 0, "n/a", True)]))
        real_backup = setup.bot.backup_current_config
        def backup(action, digest):
            self.events.append("backup")
            return real_backup(action, digest)
        self.stack.enter_context(mock.patch.object(setup.bot, "backup_current_config", side_effect=backup))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def tearDown(self):
        self.stack.close()
        self.temp.cleanup()

    def validate(self, path):
        self.events.append("validate-candidate" if Path(path) != self.config_path else "validate-live")

    def start(self, config):
        self.events.append("restart")
        self.assertEqual(setup.bot.parse_xray_bytes(self.config_path.read_bytes()), config)

    def test_success_validates_before_backup_and_preserves_backup_bytes(self):
        setup.apply_config(PEOPLE, self.digest)
        self.assertLess(self.events.index("validate-candidate"), self.events.index("backup"))
        self.assertLess(self.events.index("backup"), self.events.index("restart"))
        backups = list((self.directory / "backups").iterdir())
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), self.original_bytes)
        self.assertEqual(self.config_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
        installed = json.loads(self.config_path.read_text())
        self.assertEqual(installed["inbounds"][0]["settings"]["clients"][0]["id"], EXISTING_ID)

    def test_repeat_apply_verifies_api_without_backup_or_restart(self):
        ready = setup.prepare_config(self.original, PEOPLE)
        self.config_path.write_text(json.dumps(ready))
        setup.apply_config(PEOPLE)
        self.restart.assert_not_called()
        self.verify.assert_called_once()
        self.assertFalse((self.directory / "backups").exists())

    def test_expected_hash_rejects_changed_config_before_any_validation(self):
        with self.assertRaisesRegex(setup.SetupError, "changed since inspection"):
            setup.apply_config(PEOPLE, "0" * 64)
        self.validation.assert_not_called()
        self.restart.assert_not_called()
        self.assertEqual(self.config_path.read_bytes(), self.original_bytes)

    def test_candidate_validation_failure_does_not_install_or_restart(self):
        def validation(path):
            if Path(path) != self.config_path:
                raise setup.bot.OperationError("candidate invalid")
        self.validation.side_effect = validation
        with self.assertRaises(setup.bot.OperationError):
            setup.apply_config(PEOPLE, self.digest)
        self.restart.assert_not_called()
        self.assertEqual(self.config_path.read_bytes(), self.original_bytes)
        self.assertFalse((self.directory / "backups").exists())
        self.assertFalse(list(self.directory.glob(".config.json.candidate.*")))

    def test_failed_restart_restores_exact_bytes_and_restarts_original(self):
        calls = []
        def restart(config):
            calls.append(copy.deepcopy(config))
            if len(calls) == 1:
                raise setup.bot.OperationError("candidate start failure")
            self.assertEqual(self.config_path.read_bytes(), self.original_bytes)
        self.restart.side_effect = restart
        with self.assertRaisesRegex(setup.SetupError, "previous config restored and Xray healthy"):
            setup.apply_config(PEOPLE, self.digest)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1], self.original)
        self.assertEqual(self.config_path.read_bytes(), self.original_bytes)

    def test_failed_api_verification_rolls_back(self):
        self.verify.side_effect = setup.stats.APIError("API unavailable")
        with self.assertRaisesRegex(setup.SetupError, "previous config restored"):
            setup.apply_config(PEOPLE, self.digest)
        self.assertEqual(self.restart.call_count, 2)
        self.assertEqual(self.config_path.read_bytes(), self.original_bytes)

    def test_failed_rollback_is_explicit(self):
        self.restart.side_effect = setup.bot.OperationError("start failure secret details")
        with self.assertRaisesRegex(setup.SetupError, "rollback needs immediate inspection") as caught:
            setup.apply_config(PEOPLE, self.digest)
        self.assertNotIn("secret details", str(caught.exception))
        self.assertEqual(self.config_path.read_bytes(), self.original_bytes)


if __name__ == "__main__":
    unittest.main()
