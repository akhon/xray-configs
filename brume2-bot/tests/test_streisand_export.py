import importlib.util
import hashlib
import json
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


if "requests" not in sys.modules:
    requests_stub = types.ModuleType("requests")

    class RequestException(Exception):
        pass

    class Session:
        pass

    requests_stub.RequestException = RequestException
    requests_stub.Session = Session
    sys.modules["requests"] = requests_stub


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "xray_telegram_bot",
    ROOT / "src" / "xray_telegram_bot.py",
)
BOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOT)


class StreisandExportTest(unittest.TestCase):
    def test_generates_two_safe_xray_json_profiles(self):
        fixture_path = ROOT / "tests" / "fixtures" / "xray_config.example.json"
        config = json.loads(fixture_path.read_text(encoding="utf-8"))
        fake_certificate = {
            "subject": ((('commonName', 'example.com'),),),
            "issuer": ((('commonName', 'example.com'),),),
            "subjectAltName": (("DNS", "example.com"),),
        }

        with mock.patch.object(BOT.Path, "read_text", return_value=(
            "-----BEGIN CERTIFICATE-----\nZmFrZSBsZWFm\n-----END CERTIFICATE-----\n"
            "-----BEGIN CERTIFICATE-----\nZmFrZSBjYQ==\n-----END CERTIFICATE-----\n"
        )), mock.patch.object(
            BOT.ssl._ssl,
            "_test_decode_cert",
            return_value=fake_certificate,
        ):
            document = BOT.build_streisand_document(config, "192.0.2.1")

        profiles = json.loads(document)
        tls = profiles[1]["outbounds"][0]["streamSettings"]["tlsSettings"]
        self.assertEqual(tls["pinnedPeerCertSha256"], hashlib.sha256(b"fake leaf").hexdigest())
        self.assertNotIn("allowInsecure", tls)
        self.assertEqual(len(profiles), 2)
        self.assertEqual(
            [profile["outbounds"][0]["protocol"] for profile in profiles],
            ["vless", "vmess"],
        )
        self.assertEqual(
            [
                profile["outbounds"][0]["settings"]["vnext"][0]["port"]
                for profile in profiles
            ],
            [9443, 443],
        )
        self.assertNotIn(config["inbounds"][1]["streamSettings"]["realitySettings"]["privateKey"], document)
        for forbidden in (
            '"privateKey"',
            '"serverNames"',
            '"certificateFile"',
            '"keyFile"',
            '"bot_token"',
        ):
            self.assertNotIn(forbidden, document)


if __name__ == "__main__":
    unittest.main()
