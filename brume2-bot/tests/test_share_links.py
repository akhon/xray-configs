import base64
import copy
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock
from urllib.parse import parse_qs, unquote, urlsplit


if "requests" not in sys.modules:
    sys.modules["requests"] = types.ModuleType("requests")

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "share_link_bot", ROOT / "src" / "xray_telegram_bot.py"
)
BOT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BOT
SPEC.loader.exec_module(BOT)


class ShareLinksTest(unittest.TestCase):
    def setUp(self):
        self.config = json.loads(
            (ROOT / "tests" / "fixtures" / "xray_config.example.json").read_text()
        )
        for inbound in self.config["inbounds"]:
            inbound["settings"]["clients"][0]["email"] = "alice"
        self.certificate = {
            "subjectAltName": (("DNS", "example.com"),),
        }

    def documents(self, address="192.0.2.1", user_filter=None):
        with mock.patch.object(BOT.Path, "read_text", return_value=(
            "-----BEGIN CERTIFICATE-----\nZmFrZSBsZWFm\n-----END CERTIFICATE-----\n"
        )), mock.patch.object(BOT.ssl._ssl, "_test_decode_cert", return_value=self.certificate):
            profiles = json.loads(BOT.build_streisand_document(self.config, address, user_filter))
            links = BOT.build_share_links_document(self.config, address, user_filter).splitlines()
        return profiles, links

    def assert_link_matches_json(self, profile, link):
        outbound = profile["outbounds"][0]
        destination = outbound["settings"]["vnext"][0]
        user = destination["users"][0]
        stream = outbound["streamSettings"]
        if outbound["protocol"] == "vmess":
            self.assertTrue(link.startswith("vmess://"))
            decoded = json.loads(base64.b64decode(link[len("vmess://"):], validate=True))
            tls = stream["tlsSettings"]
            self.assertEqual(decoded["v"], "2")
            self.assertEqual(decoded["ps"], profile["remarks"])
            self.assertEqual(decoded["add"], destination["address"])
            self.assertEqual(decoded["port"], str(destination["port"]))
            self.assertEqual(decoded["id"], user["id"])
            self.assertEqual(decoded["aid"], str(user["alterId"]))
            self.assertEqual(decoded["scy"], user["security"])
            self.assertEqual(decoded["net"], stream["network"])
            self.assertEqual(decoded["type"], "none")
            self.assertEqual(decoded["tls"], stream["security"])
            self.assertEqual(decoded["sni"], tls["serverName"])
            self.assertEqual(decoded["alpn"], ",".join(tls.get("alpn", [])))
            self.assertEqual(decoded["fp"], tls["fingerprint"])
            self.assertEqual(decoded["pcs"], tls["pinnedPeerCertSha256"])
            self.assertEqual(decoded["insecure"], "0")
            self.assertEqual(decoded["host"], "")
            self.assertEqual(decoded["path"], "")
        else:
            parsed = urlsplit(link)
            decoded = parse_qs(parsed.query, keep_blank_values=True)
            reality = stream["realitySettings"]
            self.assertEqual(parsed.scheme, "vless")
            self.assertEqual(unquote(parsed.username), user["id"])
            self.assertEqual(parsed.hostname, destination["address"])
            self.assertEqual(parsed.port, destination["port"])
            self.assertEqual(unquote(parsed.fragment), profile["remarks"])
            self.assertEqual(decoded["encryption"], [user["encryption"]])
            self.assertEqual(decoded["security"], [stream["security"]])
            self.assertEqual(decoded["type"], [stream["network"]])
            self.assertEqual(decoded["headerType"], ["none"])
            self.assertEqual(decoded["spx"], [reality["spiderX"]])
            for share_field, json_field in (
                ("sni", "serverName"), ("fp", "fingerprint"),
                ("pbk", "publicKey"), ("sid", "shortId"),
            ):
                self.assertEqual(decoded[share_field], [reality[json_field]])
            self.assertEqual(decoded.get("flow"), [user["flow"]] if user.get("flow") else None)
        for forbidden in ("privateKey", "serverNames", "certificateFile", "keyFile", "bot_token"):
            self.assertNotIn(forbidden, json.dumps(decoded))
        return decoded

    def test_share_links_match_json_and_exclude_server_private_fields(self):
        profiles, links = self.documents()
        self.assertEqual(len(profiles), 2)
        self.assertEqual(len(links), len(profiles))
        private_key = self.config["inbounds"][1]["streamSettings"]["realitySettings"]["privateKey"]
        for profile, link in zip(profiles, links):
            decoded = self.assert_link_matches_json(profile, link)
            self.assertNotIn(private_key, link)
            self.assertNotIn(private_key, json.dumps(decoded))

    def test_ipv6_and_utf8_profile_names_round_trip(self):
        profiles, _links = self.documents("2001:db8::7")
        for profile in profiles:
            profile["remarks"] = "Brume 2 – Alice / 中文 + ?"
        with mock.patch.object(BOT, "build_streisand_document", return_value=json.dumps(profiles)):
            links = BOT.build_share_links_document(self.config, "2001:db8::7").splitlines()
        self.assertIn("@[2001:db8::7]:9443?", links[0])
        self.assertNotIn(" ", links[0])
        self.assertIn("%E4%B8%AD%E6%96%87", links[0])
        for profile, link in zip(profiles, links):
            self.assert_link_matches_json(profile, link)

    def test_user_filter_exports_only_matching_credentials_and_optional_vless(self):
        self.config["inbounds"] = self.config["inbounds"][:1]
        other = copy.deepcopy(self.config["inbounds"][0]["settings"]["clients"][0])
        other.update(id="33333333-3333-4333-8333-333333333333", email="bob")
        self.config["inbounds"][0]["settings"]["clients"].append(other)
        profiles, links = self.documents(user_filter="bob")
        self.assertEqual(len(links), 1)
        decoded = self.assert_link_matches_json(profiles[0], links[0])
        self.assertEqual(decoded["id"], other["id"])
        for invalid in ("missing", "../alice", "alice bob", other["id"]):
            with self.assertRaises(BOT.UserError):
                self.documents(user_filter=invalid)

    def test_flow_is_omitted_when_not_configured(self):
        self.config["inbounds"][1]["settings"]["clients"][0].pop("flow")
        profiles, links = self.documents()
        self.assert_link_matches_json(profiles[0], links[0])
        self.assertNotIn("flow", parse_qs(urlsplit(links[0]).query))


class ShareLinksHandlerTest(unittest.TestCase):
    def setUp(self):
        self.bot = BOT.Bot.__new__(BOT.Bot)
        self.bot.settings = BOT.Settings("test-placeholder", frozenset({100}), frozenset({200}))
        self.bot.telegram = mock.Mock()
        self.bot.bot_username = "test_bot"
        self.message = {
            "chat": {"id": 100}, "from": {"id": 200}, "message_id": 1,
            "text": "/links alice",
        }

    def test_authorized_handler_sends_text_attachment_and_pin_guidance(self):
        cfg = {"fixture": True}
        with mock.patch.object(BOT, "load_xray_config", return_value=cfg), \
                mock.patch.object(BOT, "get_public_ip", return_value="192.0.2.1"), \
                mock.patch.object(BOT, "build_share_links_document", return_value="vmess://test\n") as builder:
            self.bot.handle_message(self.message)
        builder.assert_called_once_with(cfg, "192.0.2.1", "alice")
        call = self.bot.telegram.send_document.call_args.args
        self.assertEqual(call[:3], (100, "brume2-streisand-links.txt", "vmess://test\n"))
        self.assertIn("/streisand [label] JSON", call[3])
        self.assertIn("keep TLS verification enabled", call[3])
        self.assertEqual(call[4], "text/plain")

    def test_unlisted_chat_or_user_cannot_export(self):
        with mock.patch.object(BOT, "load_xray_config") as load:
            for changed in ({"chat": {"id": 999}}, {"from": {"id": 999}}):
                self.bot.handle_message(dict(self.message, **changed))
        load.assert_not_called()
        self.bot.telegram.send_document.assert_not_called()
        self.bot.telegram.send_message.assert_not_called()

    def test_multiple_arguments_are_rejected_without_export(self):
        self.message["text"] = "/links alice bob"
        with mock.patch.object(BOT, "load_xray_config") as load:
            self.bot.handle_message(self.message)
        load.assert_not_called()
        self.bot.telegram.send_document.assert_not_called()
        self.assertIn("Usage: /links", self.bot.telegram.send_message.call_args.args[1])


if __name__ == "__main__":
    unittest.main()
