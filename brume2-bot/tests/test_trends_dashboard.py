import datetime as dt
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import vpn_usage_history as history
import vpn_usage_trends as trends
import vpn_history_export as export
import vpn_user_stats as summary
import hysteria_user_stats as hy
spec = importlib.util.spec_from_file_location('dashboard', Path(__file__).resolve().parents[1] / 'dashboard/server.py')
dash = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dash)


def sample(t, amount, epoch='a', private=0):
    return (t, epoch, {'shared': {'label': 'shared', 'up': amount, 'down': amount},
                      'private-a': {'label': 'different-alias', 'up': private, 'down': 0}}, False)


class TrendTests(unittest.TestCase):
    def setUp(self):
        self.start = dt.datetime(2026, 10, 19, 14, tzinfo=history.UTC)
        self.end = self.start + dt.timedelta(seconds=60)
        t = self.start.timestamp()
        self.samples = [sample(t-604800, 100), sample(t-604740, 200), sample(t, 1000), sample(t+60, 1200)]
    def build(self, samples=None, **kwargs):
        with patch.object(history, 'read_samples', return_value={'Hysteria 2': self.samples if samples is None else samples}):
            return trends.build_trends(self.start, self.end, **kwargs)
    def test_equal_elapsed_windows_and_percent(self):
        d = self.build(excluded_users={'private-a'})
        p = d['protocols'][0]
        self.assertEqual(p['current']['bytes'], 400)
        self.assertEqual(p['previous']['bytes'], 200)
        self.assertEqual(p['comparison'], {'status':'comparable', 'percent':100.0})
        self.assertEqual(dt.datetime.fromisoformat(d['previous_end'])-dt.datetime.fromisoformat(d['previous_start']), dt.timedelta(seconds=60))
    def test_incomplete_prior_no_percent(self):
        p = self.build(self.samples[2:])['protocols'][0]
        self.assertIsNone(p['previous']['bytes'])
        self.assertEqual(p['comparison']['status'], 'incomplete')
        self.assertIsNone(p['comparison']['percent'])
        self.assertIn('неполная история', trends.render_trends(self.build(self.samples[2:])))
    def test_reset_no_percent(self):
        samples = self.samples[:3] + [sample(self.end.timestamp(), 20, 'b')]
        p = self.build(samples)['protocols'][0]
        self.assertEqual(p['current']['bytes'], 40)
        self.assertIsNone(p['comparison']['percent'])
    def test_gap_no_percent(self):
        self.end += dt.timedelta(seconds=180)
        samples = self.samples[:3] + [sample(self.end.timestamp(), 1200)]
        self.assertIsNone(self.build(samples)['protocols'][0]['comparison']['percent'])
    def test_zero_baseline_is_not_infinite(self):
        self.assertEqual(trends.compare(1, 0, True), {'status':'new_usage', 'percent':None})
        self.assertEqual(trends.compare(0, 0, True), {'status':'unchanged', 'percent':0.0})
    def test_raw_id_filters_hide_aliases(self):
        shared = json.dumps(self.build(excluded_users={'PRIVATE-A'}))
        private = self.build(included_users={'PRIVATE-A'})
        self.assertNotIn('different-alias', shared)
        self.assertNotIn('private-a', shared)
        self.assertEqual([r['account'] for r in private['protocols'][0]['users']], ['private-a'])
    def test_label_filter_uses_stable_account(self):
        rows = self.build(label_filter='different-alias')['protocols'][0]['users']
        self.assertEqual([r['account'] for r in rows], ['private-a'])
    def test_missing_days_null_and_partial_today(self):
        days = self.build(self.samples[2:])['protocols'][0]['days']
        self.assertIsNone(days[0]['bytes'])
        self.assertEqual(days[-1]['end'], self.end.isoformat())
        self.assertFalse(days[-1]['complete'])
        self.assertEqual(days[-1]['bytes'], 400)
    def test_midnight_does_not_add_empty_day(self):
        self.end = self.start.replace(hour=0) + dt.timedelta(days=1)
        days = self.build()['protocols'][0]['days']
        self.assertEqual(days[-1]['date'], '2026-10-19')
        self.assertEqual(len(days), 7)
    def test_summary_survives_history_failure(self):
        with patch.object(trends, 'current_trends', side_effect=OSError('sensitive details')):
            result=summary.render_summary(vmess_enabled=False, hysteria_collector=lambda **kw: [])
        self.assertIn('Тренд недоступен', result)
        self.assertNotIn('sensitive details', result)
    def test_weekly_and_private_include_trend(self):
        with tempfile.TemporaryDirectory() as tmp:
            for text in [history.render_report(self.end, Path(tmp)/'missing', False),
                         history.render_current_week(self.end, Path(tmp)/'missing', ['private-a'])]:
                self.assertIn('Тренд:', text)
                self.assertIn('INCOMPLETE HISTORY', text)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)
        self.config = self.path/'settings.json'
        self.config.write_text(json.dumps({'bot_token':'DO-NOT-EXPORT', 'private_owner_id':12345,
            'private_hysteria_users':['private-a'], 'vmess_enabled':False}))
        self.db = self.path/'router.sqlite3'
        t = time.time()-120
        for s in [sample(t, 100), sample(t+60, 200)]:
            history.sample_once(self.db, lambda s=s: [(s[0], 'Hysteria 2', s[1], s[2], 0)])
    def tearDown(self):
        self.tmp.cleanup()
    def payload(self, since=0):
        return export.export(since, self.db, self.config)
    def test_export_read_only_no_secrets(self):
        before=self.db.read_bytes();payload=self.payload()
        self.assertNotIn('DO-NOT-EXPORT', json.dumps(payload))
        self.assertNotIn('12345', json.dumps(payload))
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(len(payload['rows']), 2)
        self.assertEqual(len(self.payload(payload['rows'][1][0])['rows']), 1)
    def test_invalid_cursors(self):
        for cursor in [-1, float('nan'), float('inf')]:
            with self.assertRaises(ValueError): self.payload(cursor)
    def test_validate_rejects_injected_counter_fields(self):
        payload=self.payload();payload['rows'][0][3]['shared']['secret']='bad'
        with self.assertRaises(ValueError):dash.validate(payload)
    def test_archive_idempotent_stale_preserved_and_persistent(self):
        a=dash.Archive(self.path/'mac', 'router-alias')
        with patch.object(dash.subprocess, 'run', return_value=Mock(stdout=json.dumps(self.payload()).encode())) as call:
            a.sync();a.sync()
            self.assertIn('BatchMode=yes', call.call_args.args[0])
        snapshot=a.snapshot();self.assertEqual(snapshot['data']['samples'], 2)
        self.assertEqual([u['account'] for u in snapshot['data']['scopes']['private']['protocols'][0]['users']], ['private-a'])
        self.assertNotIn('different-alias', json.dumps(snapshot['data']['scopes']['shared']))
        with patch.object(dash.subprocess, 'run', side_effect=RuntimeError('secret stderr')):a.sync()
        self.assertEqual(a.snapshot()['data'], snapshot['data'])
        self.assertIn('недоступна', a.snapshot()['sync_error'])
        self.assertNotIn('secret stderr', json.dumps(a.snapshot()))
        self.assertEqual(a.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(a.meta_path.stat().st_mode & 0o777, 0o600)
        b=dash.Archive(self.path/'mac', 'router-alias')
        self.assertEqual(b.snapshot()['data'], snapshot['data'])
    def test_http_loopback_host_origin_and_no_file_access(self):
        archive=Mock();archive.snapshot.return_value={'data':None}
        server=ThreadingHTTPServer(('127.0.0.1', 0), dash.handler_for(archive, 0))
        port=server.server_address[1];server.RequestHandlerClass=dash.handler_for(archive, port)
        thread=threading.Thread(target=server.serve_forever, daemon=True);thread.start()
        try:
            for path, headers, expected in [('/',{},200),('/api/usage',{},200),('/../server.py',{},404),
                ('/server.py',{},404),('/api/usage',{'Host':'attacker.example'},403),
                ('/api/usage',{'Origin':'https://attacker.example'},403)]:
                conn=HTTPConnection('127.0.0.1',port,timeout=3);conn.request('GET',path,headers=headers);res=conn.getresponse()
                self.assertEqual(res.status,expected)
                if expected==200:self.assertEqual(res.getheader('Cache-Control'),'no-store')
                res.read();conn.close()
        finally:server.shutdown();server.server_close();thread.join()

if __name__=='__main__':unittest.main()
