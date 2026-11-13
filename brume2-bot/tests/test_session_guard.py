import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import hysteria_session_guard as guard
import test_dynamic_endpoint as fixtures
import hysteria_profiles as profiles


class SessionGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = Path(self.temp.name) / 'config.json'
        self.config.write_text('{"maxSessionsPerUser":2}')

    def test_stock_binary_is_rejected_before_exec(self):
        result = subprocess.CompletedProcess([], 0, b'Version:\tv2.12.3\n')
        with patch.object(guard.subprocess, 'run', return_value=result), patch.object(guard.os, 'execv') as execute:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(guard.main(['--config', str(self.config)]), 1)
            execute.assert_not_called()

    def test_patched_binary_executes_original_server_arguments(self):
        result = subprocess.CompletedProcess([], 0, b'Version:\tcustom\nFeatures:\tmaxSessionsPerUser/v1\n')
        with patch.object(guard.subprocess, 'run', return_value=result), patch.object(guard.os, 'execv') as execute:
            self.assertEqual(guard.main(['--config', str(self.config)]), 0)
            execute.assert_called_once_with('/usr/bin/hysteria', ['/usr/bin/hysteria', 'server', '--config',
                str(self.config), '--disable-update-check', '--log-level', 'warn', '--log-format', 'json'])

    def test_invalid_settings_fail_closed(self):
        for value in [-1, True, 1.5, '2', None, 2147483648]:
            self.config.write_text(json.dumps({'maxSessionsPerUser': value}))
            with self.subTest(value=value), self.assertRaises(ValueError):
                guard.check(self.config, '/unused')
        for data in ['[]', 'broken', '{"maxSessionsPerUser":2,"maxSessionsPerUser":0}']:
            self.config.write_text(data)
            with self.assertRaises(ValueError):
                guard.check(self.config, '/unused')

    def test_no_limit_preserves_stock_behavior(self):
        for value in [{}, {'maxSessionsPerUser': 0}]:
            self.config.write_text(json.dumps(value))
            with patch.object(guard.subprocess, 'run') as version:
                guard.check(self.config, '/unused')
                version.assert_not_called()

    def test_version_failure_prevents_exec(self):
        with patch.object(guard.subprocess, 'run', side_effect=subprocess.TimeoutExpired('version', 10)):
            with patch.object(guard.os, 'execv') as execute, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(guard.main(['--config', str(self.config)]), 1)
                execute.assert_not_called()


class SessionExportTests(unittest.TestCase):
    def test_session_limit_preserves_export(self):
        # Reuse the public certificate fixture and synthetic configuration setup.
        case = fixtures.DynamicEndpointTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        before = profiles.build_links_document('203.0.113.10', 'alice')
        config = json.loads(case.config.read_text())
        for value in [0, 2, 10]:
            config['maxSessionsPerUser'] = value
            case.config.write_text(json.dumps(config))
            self.assertEqual(profiles.build_links_document('203.0.113.10', 'alice'), before)
        for value in [-1, True, '2', None, 1.5]:
            config['maxSessionsPerUser'] = value
            case.config.write_text(json.dumps(config))
            with self.assertRaises(profiles.ProfileError):
                profiles.build_links_document('203.0.113.10', 'alice')
