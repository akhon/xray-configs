import contextlib
import importlib.util
import datetime as dt
import io
import json
from pathlib import Path
import sys
import tempfile
import hashlib
import ssl
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import hysteria_profiles as hp
import vpn_usage_history as hist
import xray_stats_report as report
import xray_telegram_bot as bot
from vpn_qr import qr_png


def sample(t, up, down=0, epoch='a', error=False):
    return (t, epoch, {'alice': {'label': 'alice', 'up': up, 'down': down}}, error)


class HistoryTests(unittest.TestCase):
    def test_baseline_is_not_cumulative(self):
        r=hist.summarize([sample(20,10000),sample(80,10100)],0,100)
        self.assertEqual(r['totals']['alice']['up'],100)
        self.assertTrue(r['reasons'])
    def test_complete_delta(self):
        r=hist.summarize([sample(0,1000,100),sample(60,1100,150)],0,60)
        self.assertEqual(r['totals']['alice']['up'],100)
        self.assertEqual(r['totals']['alice']['down'],50)
        self.assertFalse(r['reasons'])
    def test_restart_higher_counter(self):
        r=hist.summarize([sample(0,100),sample(60,200,epoch='b')],0,60)
        self.assertEqual(r['totals']['alice']['up'],200)
        self.assertTrue(r['reasons'])
    def test_counter_reset_direction_independent(self):
        r=hist.summarize([sample(0,100,100),sample(60,20,110)],0,60)
        self.assertEqual((r['totals']['alice']['up'],r['totals']['alice']['down']),(20,10))
        self.assertTrue(r['reasons'])
    def test_repeated_reset(self):
        r=hist.summarize([sample(0,100),sample(60,10),sample(120,2),sample(180,20)],0,180)
        self.assertEqual(r['totals']['alice']['up'],30)
    def test_boundary_allocation_conserves_bytes(self):
        s=[sample(0,100),sample(60,201)]
        a=hist.summarize(s,0,30); b=hist.summarize(s,30,60)
        self.assertEqual(a['totals']['alice']['up']+b['totals']['alice']['up'],101)
        self.assertTrue(a['estimated'])
    def test_reset_across_boundary_not_misattributed(self):
        r=hist.summarize([sample(0,100),sample(60,20,epoch='b')],0,30)
        self.assertEqual(r['totals']['alice']['up'],0)
        self.assertTrue(any('omitted' in s for s in r['reasons']))
    def test_gap_marked(self):
        r=hist.summarize([sample(0,100),sample(600,200)],0,600)
        self.assertEqual(r['totals']['alice']['up'],100)
        self.assertTrue(r['reasons'])
    def test_api_failure_recovers_delta_and_marks(self):
        r=hist.summarize([sample(0,100),sample(60,0,error=True),sample(120,200)],0,120)
        self.assertEqual(r['totals']['alice']['up'],100)
        self.assertTrue(r['reasons'])
    def test_empty_is_unknown_not_zero(self):
        r=hist.summarize([],0,60)
        self.assertFalse(r['totals']); self.assertTrue(r['reasons'])
    def test_history_outside_period_has_no_inverted_coverage(self):
        for samples in [[sample(200,100)], [sample(200,100),sample(260,200)],
                        [sample(-120,100),sample(-60,200)]]:
            r=hist.summarize(samples,0,60)
            self.assertIsNone(r['coverage'])
            self.assertEqual(r['totals'],{})
            self.assertTrue(r['reasons'])

    def test_user_add_is_baseline(self):
        a=sample(0,100); b=sample(60,200)
        b[2]['new']={'label':'new','up':999,'down':999}
        r=hist.summarize([a,b],0,60)
        self.assertEqual(r['totals']['new']['up'],0); self.assertTrue(r['reasons'])
    def test_utc_week_boundary(self):
        for when, end in [('2026-10-26T13:59:59+00:00','2026-10-19T14:00:00+00:00'),
                          ('2026-10-26T14:00:00+00:00','2026-10-26T14:00:00+00:00'),
                          ('2026-10-26T09:00:00-05:00','2026-10-26T14:00:00+00:00')]:
            a,b=hist.period(dt.datetime.fromisoformat(when)); self.assertEqual(b.isoformat(),end)
            self.assertEqual(b-a,dt.timedelta(days=7))
    def test_persistent_history_and_readonly(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'history.sqlite3'
            for s in [sample(0,100),sample(60,140),sample(120,200)]:
                hist.sample_once(p,lambda s=s:[(s[0],'Hysteria 2',s[1],s[2],int(s[3]))])
            before=p.read_bytes()
            data=hist.read_samples(p,30,90)
            self.assertEqual(len(data['Hysteria 2']),3)
            self.assertEqual(hist.summarize(data['Hysteria 2'],30,90)['totals']['alice']['up'],50)
            self.assertEqual(p.read_bytes(),before)
            self.assertEqual(p.stat().st_mode & 0o777,0o600)
    def test_backwards_clock_preserves_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'history.sqlite3'
            hist.sample_once(p,lambda:[(100,'Hysteria 2','a',{},0)])
            with self.assertRaises(hist.HistoryError):
                hist.sample_once(p,lambda:[(90,'Hysteria 2','a',{},0)])
            db=hist.connect(p)
            try:
                self.assertEqual(db.execute('SELECT count(*) FROM samples').fetchone()[0],1)
            finally:
                db.close()
    def test_report_dates_and_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            text=hist.render_report(dt.datetime(2026,10,26,14,tzinfo=hist.UTC),Path(tmp)/'absent',False)
            self.assertIn('2026-10-19 14:00:00 UTC -> 2026-10-26 14:00:00 UTC',text)
            self.assertIn('INCOMPLETE HISTORY',text); self.assertIn('Usage unavailable',text)


class BotTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.config=Path(self.tmp.name)/'config.json'; self.labels=Path(self.tmp.name)/'labels.json'
        self.cert=(Path(__file__).parent/'fixtures'/'hysteria-test-certificate.txt').read_text()
        self.certfile=Path(self.tmp.name)/'server.crt';self.certfile.write_text(self.cert)
        self.config.write_text(json.dumps({'listen':'0.0.0.0:443','tls':{'cert':str(self.certfile),'key':'/test.key'},
           'auth':{'type':'userpass','userpass':{'alice':'Secret-A-123','PrIvAtE-A':'Secret-G-456'}}}))
        self.labels.write_text(json.dumps({'PrIvAtE-A':'private-alias'}))
        self.patchers=[patch.object(hist,'sample_once',return_value=True),patch.object(hp,'HYSTERIA_CONFIG',self.config),patch.object(hp,'DEFAULT_LABELS',self.labels),
            patch.object(hp,'_certificate_pin',return_value=hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.cert)).hexdigest()),patch.object(bot,'get_public_ip',return_value='203.0.113.10')]
        for p in self.patchers: p.start()
        self.b=bot.Bot(bot.Settings('123456:fake',frozenset({-1}),frozenset({2}),False,
            private_hysteria_users=frozenset({'private-a','private-b'})))
        self.b.telegram=Mock()
    def tearDown(self):
        for p in reversed(self.patchers): p.stop()
        self.tmp.cleanup()
    def message(self,text,chat=-1,user=2):
        return {'text':text,'chat':{'id':chat,'type':'supergroup'},'from':{'id':user},'message_id':99}
    def test_authorized_qr_is_locally_generated(self):
        self.b.handle_message(self.message('/qr alice'))
        self.b.telegram.send_photo.assert_called_once()
        data=self.b.telegram.send_photo.call_args.args[2]
        self.assertTrue(data.startswith(b'\x89PNG'))
        self.b.telegram.send_document.assert_not_called()
    @unittest.skipUnless(importlib.util.find_spec('zxingcpp'), 'Decoder verified on Mac')
    def test_qr_decodes_exact_uri(self):
        import zxingcpp
        from PIL import Image
        link=hp.build_links_document('203.0.113.10','alice').strip()
        decoded=zxingcpp.read_barcode(Image.open(io.BytesIO(qr_png(link))))
        self.assertEqual(decoded.text,link)
    def test_unauthorized_chat_no_reply_or_export(self):
        self.b.handle_message(self.message('/qr alice',chat=3)); self.b.telegram.assert_not_called()
        self.assertEqual(self.b.telegram.mock_calls,[])
    def test_unauthorized_sender_no_reply_or_export(self):
        self.b.handle_message(self.message('/qr alice',user=3)); self.assertEqual(self.b.telegram.mock_calls,[])
    def test_missing_sender_rejected(self):
        m=self.message('/qr alice'); del m['from']; self.b.handle_message(m)
        self.assertEqual(self.b.telegram.mock_calls,[])
    def test_wrong_bot_suffix_ignored(self):
        self.b.bot_username='ourbot'; self.b.handle_message(self.message('/qr@otherbot alice'))
        self.assertEqual(self.b.telegram.mock_calls,[])
    def test_invalid_arguments(self):
        for text in ['/qr','/qr alice bob','/qr ../../etc','/qr absent']:
            self.b.telegram.reset_mock(); self.b.handle_message(self.message(text))
            self.b.telegram.send_photo.assert_not_called(); self.b.telegram.send_message.assert_called_once()
    def test_private_alias_blocked_for_all_exports(self):
        for command in ['/qr','/hysteria','/hylinks']:
            for user in ['private-a','PrIvAtE-A','private-alias']:
                self.b.telegram.reset_mock(); self.b.handle_message(self.message(command+' '+user))
                self.b.telegram.send_photo.assert_not_called(); self.b.telegram.send_document.assert_not_called()
                self.assertNotIn('Secret-G-456',str(self.b.telegram.mock_calls))
    def test_bulk_exports_exclude_private_account(self):
        for command in ['/hysteria','/hylinks']:
            self.b.telegram.reset_mock(); self.b.handle_message(self.message(command))
            self.b.telegram.send_document.assert_called_once()
            content=self.b.telegram.send_document.call_args.args[2]
            self.assertIn('alice',content); self.assertNotIn('Secret-G-456',content)
            self.assertNotIn('PrIvAtE-A',content)
    def test_existing_export_unchanged(self):
        before=self.config.read_bytes()
        self.b.handle_message(self.message('/hysteria alice'))
        self.assertIn('Secret-A-123',self.b.telegram.send_document.call_args.args[2])
        self.assertEqual(self.config.read_bytes(),before)
    def test_no_user_creation_command(self):
        before=self.config.read_bytes()
        self.b.handle_message(self.message('/adduser newcomer'))
        self.assertEqual(self.config.read_bytes(),before)
        self.b.telegram.send_photo.assert_not_called(); self.b.telegram.send_document.assert_not_called()
    def test_local_private_export_still_available(self):
        self.assertIn('Secret-G-456',hp.build_document('203.0.113.10','private-alias'))
    def test_help_and_feature_flag_preserved(self):
        self.b.handle_message(self.message('/help'))
        self.assertIn('/qr user',self.b.telegram.send_message.call_args.args[1])
        self.b.handle_message(self.message('/restart'))
        self.assertIn('disabled',self.b.telegram.send_message.call_args.args[1])
    def test_hiddify_qr_contains_trusted_certificate(self):
        self.b.handle_message(self.message('/qr alice hiddify'))
        self.b.telegram.send_photo.assert_called_once()
        data=self.b.telegram.send_photo.call_args.args[2]
        self.assertTrue(data.startswith(b'\x89PNG'))
        document=json.loads(hp.build_hiddify_document('203.0.113.10','alice'))
        tls=document['outbounds'][0]['tls']
        self.assertEqual(tls['certificate'],[self.cert])
        self.assertFalse(tls.get('insecure',False))

    @unittest.skipUnless(importlib.util.find_spec('zxingcpp'), 'Decoder verified on Mac')
    def test_hiddify_qr_decodes_exact_json(self):
        import zxingcpp
        from PIL import Image
        document=hp.build_hiddify_document('203.0.113.10','alice')
        decoded=zxingcpp.read_barcode(Image.open(io.BytesIO(qr_png(document,'hiddify'))))
        self.assertEqual(decoded.text,document)

    def test_hiddify_private_user_and_unauthorized_blocked(self):
        for text in ['/qr private-alias hiddify','/qr private-a hiddify','/qr missing hiddify']:
            self.b.telegram.reset_mock();self.b.handle_message(self.message(text))
            self.b.telegram.send_photo.assert_not_called()
            self.assertNotIn('Secret-G-456',str(self.b.telegram.mock_calls))
        self.b.telegram.reset_mock()
        self.b.handle_message(self.message('/qr alice hiddify',user=3))
        self.assertEqual(self.b.telegram.mock_calls,[])

    def test_hiddify_certificate_race_rejected(self):
        with patch.object(hp,'_certificate_pin',return_value='0'*64):
            with self.assertRaises(hp.ProfileError):
                hp.build_hiddify_document('203.0.113.10','alice')

    def test_hiddify_qr_rejects_insecure_and_multiple_users(self):
        document=json.loads(hp.build_hiddify_document('203.0.113.10','alice'))
        document['outbounds'][0]['tls']['insecure']=True
        with self.assertRaises(ValueError):qr_png(json.dumps(document),'hiddify')
        del document['outbounds'][0]['tls']['insecure']
        document['outbounds'].append(document['outbounds'][0])
        with self.assertRaises(ValueError):qr_png(json.dumps(document),'hiddify')

    def test_photo_request_multipart(self):
        client=bot.TelegramClient('fake'); client.request=Mock()
        client.send_photo(1,'qr.png',b'png','caption',99)
        self.assertEqual(client.request.call_args.args[0],'sendPhoto')
        self.assertEqual(client.request.call_args.kwargs['files']['photo'],('qr.png',b'png','image/png'))


class ReportTests(unittest.TestCase):
    def test_dry_run_never_sends_or_collects_or_writes(self):
        with patch.object(bot,'load_settings',return_value=bot.Settings('fake',frozenset({-1}),frozenset({2}))), \
             patch.object(hist,'render_report',return_value='test report'), patch.object(hist,'sample_once') as collect, \
             patch.object(bot,'TelegramClient') as telegram, patch.object(bot,'atomic_write_json') as write, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(report.send_weekly_report(dry_run=True),0)
            collect.assert_not_called(); telegram.assert_not_called(); write.assert_not_called()
    def test_delivery_dedup_and_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(report,'PRIVATE_CONFIG_FILE',Path(tmp)/'no-route.json'),patch.object(report,'STATE_FILE',Path(tmp)/'state.json'),patch.object(report,'LOCK_FILE',Path(tmp)/'lock'), \
                 patch.object(bot,'load_settings',return_value=bot.Settings('fake',frozenset({1,2}),frozenset({3}),False)), \
                 patch.object(hist,'sample_once',return_value=True),patch.object(hist,'render_report',return_value='weekly'), \
                 patch.object(bot,'TelegramClient') as tc,contextlib.redirect_stdout(io.StringIO()):
                now=dt.datetime(2026,10,26,14,tzinfo=hist.UTC)
                self.assertEqual(report.send_weekly_report(now=now),0)
                self.assertEqual(tc.return_value.send_message.call_count,2)
                self.assertEqual(report.send_weekly_report(now=now),0)
                self.assertEqual(tc.return_value.send_message.call_count,2)
    def test_failed_delivery_retries_only_failed_chat(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(report,'PRIVATE_CONFIG_FILE',Path(tmp)/'no-route.json'),patch.object(report,'STATE_FILE',Path(tmp)/'state.json'),patch.object(report,'LOCK_FILE',Path(tmp)/'lock'), \
                 patch.object(bot,'load_settings',return_value=bot.Settings('fake',frozenset({1,2}),frozenset({3}),False)), \
                 patch.object(hist,'sample_once',return_value=True),patch.object(hist,'render_report',return_value='weekly'), \
                 patch.object(bot,'TelegramClient') as tc,contextlib.redirect_stdout(io.StringIO()):
                now=dt.datetime(2026,10,26,14,tzinfo=hist.UTC)
                tc.return_value.send_message.side_effect=[None,bot.TelegramError('failed')]
                self.assertEqual(report.send_weekly_report(now=now),1)
                tc.return_value.send_message.side_effect=None
                self.assertEqual(report.send_weekly_report(now=now),0)
                self.assertEqual(tc.return_value.send_message.call_count,3)
                self.assertEqual(tc.return_value.send_message.call_args.args[0],2)


if __name__=='__main__':
    unittest.main(verbosity=2)
