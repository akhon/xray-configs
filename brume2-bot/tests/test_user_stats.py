#!/usr/bin/env python3
"""Regression checks for privacy, API failure handling, filtering and online semantics."""

import importlib.util
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest


MODULE = Path(__file__).resolve().parents[1] / "src" / "xray_user_stats.py"
spec = importlib.util.spec_from_file_location("xray_user_stats", MODULE)
stats = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = stats
spec.loader.exec_module(stats)


def configuration():
    return {
        "policy": {"levels": {"0": {"statsUserOnline": True}}},
        "inbounds": [
            {"protocol": "vmess", "settings": {"clients": [
                {"id": "11111111-1111-4111-8111-111111111111", "email": "alice-vmess"},
                {"id": "22222222-2222-4222-8222-222222222222", "email": "bob-vmess"}]}},
            {"protocol": "vless", "settings": {"clients": [
                {"id": "33333333-3333-4333-8333-333333333333", "email": "alice-vless"}]},
             "streamSettings": {"realitySettings": {"privateKey": "DUMMY_PRIVATE_SECRET_MUST_NOT_LEAK_1234567890"}}},
        ],
    }


class FixtureAPI:
    def __init__(self, traffic=None, online=None, traffic_failure=None):
        self.traffic = traffic if traffic is not None else {"stat": []}
        self.online = online if online is not None else {}
        self.traffic_failure = traffic_failure
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        if argv[2] == "statsquery":
            if self.traffic_failure:
                return types.SimpleNamespace(returncode=1, stdout="", stderr=self.traffic_failure)
            payload = self.traffic
        else:
            label = argv[argv.index("-email") + 1]
            payload = self.online.get(label)
            if payload is None:
                return types.SimpleNamespace(returncode=1, stdout="", stderr="rpc error: code = NotFound")
        return types.SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")


class StatsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config_path = Path(self.temp.name) / "config.json"
        self.config = configuration()
        self.write_config()

    def tearDown(self):
        self.temp.cleanup()

    def write_config(self):
        self.config_path.write_text(json.dumps(self.config))

    def render(self, api, user=None, compact=True):
        return stats.render_summary(user, compact=compact, config_path=self.config_path, runner=api)

    def test_traffic_read_once_and_never_reset(self):
        api = FixtureAPI(traffic={"stat": [
            {"name": "user>>>alice-vless>>>traffic>>>uplink", "value": "1024"},
            {"name": "user>>>alice-vless>>>traffic>>>downlink", "value": 2048},
            {"name": "user>>>not-configured>>>traffic>>>uplink", "value": "999999"},
        ]})
        result = self.render(api, "alice-vless", compact=False)
        self.assertIn("1.0 KiB", result)
        self.assertIn("2.0 KiB", result)
        self.assertIn("3.0 KiB", result)
        self.assertNotIn("Missing traffic counters", result)
        self.assertNotIn("not-configured", result)
        queries = [call for call in api.calls if call[2] == "statsquery"]
        self.assertEqual(len(queries), 1)
        self.assertEqual(queries[0][4:6], ["-pattern", "user>>>"])
        self.assertFalse(any("reset" in arg.lower() for call in api.calls for arg in call))

    def test_person_filter_and_exact_precedence(self):
        result = self.render(FixtureAPI(), "ALICE")
        self.assertIn("alice-vmess", result)
        self.assertIn("alice-vless", result)
        self.assertNotIn("bob-vmess", result)
        self.config["inbounds"][0]["settings"]["clients"].append({"id": "dummy", "email": "alice"})
        self.write_config()
        result = self.render(FixtureAPI(), "alice")
        self.assertIn("alice |", result)
        self.assertNotIn("alice-vmess", result)

    def test_no_arbitrary_substring_match(self):
        with self.assertRaises(stats.UserNotFound):
            self.render(FixtureAPI(), "aria")

    def test_filter_error_does_not_echo_supplied_secret(self):
        supplied = "11111111-1111-4111-8111-111111111111"
        with self.assertRaises(stats.UserNotFound) as caught:
            self.render(FixtureAPI(), supplied)
        self.assertNotIn(supplied, str(caught.exception))

    def test_online_is_recent_activity_and_never_reveals_ip(self):
        now = int(time.time())
        api = FixtureAPI(online={
            "alice-vless": {"name": "user>>>alice-vless>>>online", "ips": {"198.51.100.10": now - 3}},
            "alice-vmess": {"name": "user>>>alice-vmess>>>online", "ips": {"203.0.113.11": now - 90}},
        })
        result = self.render(api)
        self.assertIn("alice-vless | online*: recent", result)
        self.assertIn("alice-vmess | online*: none", result)
        self.assertIn("bob-vmess | online*: n/a", result)
        self.assertNotIn("198.51.100", result)
        self.assertNotIn("203.0.113", result)
        self.assertIn("not active sessions", result)

    def test_online_disabled_avoids_online_api(self):
        self.config["policy"]["levels"]["0"]["statsUserOnline"] = False
        self.write_config()
        api = FixtureAPI()
        self.assertIn("n/a", self.render(api))
        self.assertTrue(all(call[2] == "statsquery" for call in api.calls))

    def test_legacy_users_key_is_supported(self):
        settings = self.config["inbounds"][0]["settings"]
        settings["users"] = settings.pop("clients")
        self.write_config()
        self.assertIn("alice-vmess", self.render(FixtureAPI()))

    def test_ambiguous_users_and_clients_is_rejected(self):
        self.config["inbounds"][0]["settings"]["users"] = []
        self.write_config()
        with self.assertRaises(stats.ConfigError):
            self.render(FixtureAPI())

    def test_malformed_online_response_is_unavailable_not_offline(self):
        api = FixtureAPI(online={"alice-vless": {}})
        self.assertIn("online*: n/a", self.render(api, "alice-vless"))

    def test_missing_traffic_shows_zero_and_explicit_note(self):
        result = self.render(FixtureAPI())
        self.assertIn("up 0 B | down 0 B | total 0 B", result)
        self.assertIn("Missing traffic counters", result)

    def test_api_failure_is_not_a_successful_zero_report(self):
        api = FixtureAPI(traffic_failure="secret_token and privateKey with raw API detail")
        with self.assertRaises(stats.APIError) as caught:
            self.render(api)
        self.assertNotIn("secret", str(caught.exception))
        self.assertIn("unavailable", str(caught.exception))

    def test_timeout_is_sanitized(self):
        def failing_runner(argv):
            raise subprocess.TimeoutExpired(argv, 5, output="TOP_SECRET")
        with self.assertRaises(stats.APIError) as caught:
            self.render(failing_runner)
        self.assertNotIn("TOP_SECRET", str(caught.exception))

    def test_private_values_as_labels_are_redacted(self):
        clients = self.config["inbounds"][0]["settings"]["clients"]
        clients[0]["email"] = clients[0]["id"]
        clients[1]["email"] = "DUMMY_PRIVATE_SECRET_MUST_NOT_LEAK_1234567890"
        self.write_config()
        result = self.render(FixtureAPI())
        self.assertNotIn(clients[0]["id"], result)
        self.assertNotIn(clients[1]["email"], result)
        self.assertIn("user-01", result)
        self.assertIn("user-02", result)

    def test_alias_does_not_collide_with_real_label(self):
        clients = self.config["inbounds"][0]["settings"]["clients"]
        clients[0]["email"] = clients[0]["id"]
        clients[1]["email"] = "user-01"
        self.write_config()
        rows = stats.collect_stats(config_path=self.config_path, runner=FixtureAPI())
        labels = [row.label for row in rows]
        self.assertEqual(len(labels), len(set(labels)))
        self.assertIn("user-02", labels)

    def test_jsonc_comments_preserve_url_strings(self):
        document = json.dumps(self.config)
        self.config_path.write_text("// comment\n/* comment */\n" + document + "\n# comment")
        self.assertIn("alice-vless", self.render(FixtureAPI()))
        self.assertEqual(json.loads(stats._jsonc('{"url":"https://example.com/a#b"}'))["url"],
                         "https://example.com/a#b")

    def test_duplicate_config_keys_rejected_without_raw_content(self):
        self.config_path.write_text('{"SECRET_DUPLICATE":1,"SECRET_DUPLICATE":2}')
        with self.assertRaises(stats.ConfigError) as caught:
            self.render(FixtureAPI())
        self.assertNotIn("SECRET_DUPLICATE", str(caught.exception))

    def test_invalid_counters_are_missing_not_negative_or_arbitrary_text(self):
        api = FixtureAPI(traffic={"stat": [
            {"name": "user>>>alice-vless>>>traffic>>>uplink", "value": "TOP_SECRET"},
            {"name": "user>>>alice-vless>>>traffic>>>downlink", "value": -100},
        ]})
        result = self.render(api, "alice-vless")
        self.assertIn("up 0 B | down 0 B | total 0 B", result)
        self.assertNotIn("TOP_SECRET", result)
        self.assertNotIn("-100", result)

    def test_compact_output_remains_telegram_sized(self):
        rows = [stats.UserStats("user-%03d" % index, 1024, 2048, "n/a", False) for index in range(100)]
        result = stats.format_summary(rows)
        self.assertLess(len(result), 3500)
        self.assertIn("more users", result)
        self.assertIn("user-099", stats.format_summary(rows, compact=False))

    def test_cli_argument_errors_do_not_echo_secret(self):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit):
            stats.main(["--SECRET_ARGUMENT"])
        self.assertNotIn("SECRET_ARGUMENT", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
