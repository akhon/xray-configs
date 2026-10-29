import hashlib
import json
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import hysteria_profiles as profiles


class DynamicEndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.cert = Path(__file__).parent / 'fixtures/hysteria-test-certificate.txt'
        self.pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.cert.read_text())).hexdigest()
        self.config = root / 'server.json'
        self.config.write_text(json.dumps({
            'listen': '0.0.0.0:443', 'tls': {'cert': str(self.cert), 'key': '/unread-private.key'},
            'auth': {'type': 'userpass', 'userpass': {'alice': 'example-password'}}}))
        self.metadata = root / 'client-meta.json'
        for name, value in [('HYSTERIA_CONFIG', self.config), ('DEFAULT_LABELS', root / 'labels.json'),
                            ('DEFAULT_CLIENT_META', self.metadata)]:
            p = patch.object(profiles, name, value); p.start(); self.addCleanup(p.stop)

    def test_dynamic_address_keeps_verified_certificate_identity_and_pin(self):
        self.metadata.write_text(json.dumps({'tls_server_name': '203.0.113.10',
                                            'endpoint': '192.0.2.99', 'pin': 'ignored-untrusted-cache'}))
        document = json.loads(profiles.build_document('198.51.100.20', 'alice'))[0]
        outbound, = document['outbounds']
        self.assertEqual(outbound['settings']['address'], '198.51.100.20')
        self.assertEqual(outbound['streamSettings']['tlsSettings']['serverName'], '203.0.113.10')
        self.assertEqual(outbound['streamSettings']['tlsSettings']['pinnedPeerCertSha256'], self.pin)
        uri = urlsplit(profiles.build_links_document('198.51.100.20', 'alice').strip())
        self.assertEqual(uri.hostname, '198.51.100.20')
        self.assertEqual(parse_qs(uri.query), {'sni': ['203.0.113.10'], 'pinSHA256': [self.pin], 'pcs': [self.pin]})

    def test_default_still_requires_address_in_certificate(self):
        self.assertIn('203.0.113.10', profiles.build_document('203.0.113.10', 'alice'))
        with self.assertRaises(profiles.ProfileError):
            profiles.build_document('198.51.100.20', 'alice')

    def test_informational_endpoint_never_changes_tls_identity(self):
        self.metadata.write_text(json.dumps({'endpoint': '203.0.113.10'}))
        with self.assertRaises(profiles.ProfileError):
            profiles.build_document('198.51.100.20', 'alice')

    def test_invalid_or_mismatched_identity_is_rejected(self):
        for name in ['198.51.100.99', '', 'example.com', '203.0.113.10\ninsecure=1', 1, True, None]:
            with self.subTest(name=name):
                self.metadata.write_text(json.dumps({'tls_server_name': name}))
                with self.assertRaises(profiles.ProfileError):
                    profiles.build_document('198.51.100.20', 'alice')

    def test_corrupt_metadata_fails_closed(self):
        for data in ['broken', '[]', '{"tls_server_name":"203.0.113.10","tls_server_name":"198.51.100.20"}']:
            self.metadata.write_text(data)
            with self.assertRaises(profiles.ProfileError):
                profiles.build_document('198.51.100.20', 'alice')

    def test_expired_certificate_is_rejected_with_explicit_identity(self):
        self.metadata.write_text('{"tls_server_name":"203.0.113.10"}')
        with patch.object(profiles.time, 'time', return_value=4102444800):
            with self.assertRaises(profiles.ProfileError):
                profiles.build_document('198.51.100.20', 'alice')


if __name__ == '__main__':
    unittest.main()
