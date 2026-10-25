import contextlib,datetime as dt,io,json,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
from test_hysteria_history import bot,hist,report
import test_hysteria_history as base
import hysteria_user_stats as hy
import vpn_user_stats as vs

class PrivateExports(base.BotTests):
    def setUp(self):
        super().setUp()
        cfg=json.loads(self.config.read_text());cfg['auth']['userpass']['PrIvAtE-B']='Secret-L-789';self.config.write_text(json.dumps(cfg))
        labels=json.loads(self.labels.read_text());labels['PrIvAtE-B']='private-private-b';self.labels.write_text(json.dumps(labels))
    def test_private_b_all_exports_blocked(self):
        for command in ['/qr','/qr {} hiddify','/hysteria','/hylinks']:
            for name in ['private-b','PrIvAtE-B','private-private-b']:
                text=command.format(name) if '{}' in command else command+' '+name
                self.b.telegram.reset_mock();self.b.handle_message(self.message(text))
                self.b.telegram.send_photo.assert_not_called();self.b.telegram.send_document.assert_not_called()
                self.assertNotIn('Secret-L-789',str(self.b.telegram.mock_calls))
        for command in ['/hysteria','/hylinks']:
            self.b.telegram.reset_mock();self.b.handle_message(self.message(command))
            data=self.b.telegram.send_document.call_args.args[2]
            self.assertIn('Secret-A-123',data);self.assertNotIn('Secret-L-789',data)
    def test_stats_filters_raw_accounts_and_aliases(self):
        cfg=json.loads(self.config.read_text());cfg['trafficStats']={'listen':'127.0.0.1:18081','secret':'fake'};self.config.write_text(json.dumps(cfg))
        original_collect=hy.collect_stats
        def collect(**kwargs):
            return original_collect(config_path=self.config,labels_path=self.labels,requester=lambda *a:{},**kwargs)
        with patch.object(hy,'collect_stats',side_effect=collect):
            self.b.handle_message(self.message('/stats'))
            text=self.b.telegram.send_message.call_args.args[1]
            self.assertIn('alice',text);self.assertNotIn('private-alias',text);self.assertNotIn('private-private-b',text)
            for name in ['private-a','PrIvAtE-A','private-alias','private-b','PrIvAtE-B','private-private-b']:
                self.b.telegram.reset_mock();self.b.handle_message(self.message('/stats '+name))
                self.assertIn('not found',self.b.telegram.send_message.call_args.args[1])

class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        p=Path(self.tmp.name)
        self.settings=bot.Settings('fake',frozenset({-100}),frozenset({123}),False,123,frozenset({'private-a','private-b'}))
        self.route={'version':1,'chat_id':123,'username':'owner_example'}
        self.now=dt.datetime(2026,10,26,14,tzinfo=hist.UTC)
        self.tc=Mock();self.tc.request.return_value={'id':123,'type':'private','username':'owner_example'}
        (p/'route.json').write_text(json.dumps(self.route))
        patches=[patch.object(report,'STATE_FILE',p/'state.json'),patch.object(report,'LOCK_FILE',p/'lock'),patch.object(report,'PRIVATE_CONFIG_FILE',p/'route.json'),patch.object(bot,'load_settings',return_value=self.settings),patch.object(bot,'TelegramClient',return_value=self.tc),patch.object(hist,'sample_once',return_value=True),patch.object(hist,'render_report',side_effect=lambda *a,**kw: 'private-a+private-b' if kw.get('included_users') else 'dan+maria+kate')]
        for item in patches:item.start();self.addCleanup(item.stop)
    def send(self,**kw):
        with contextlib.redirect_stdout(io.StringIO()):return report.send_weekly_report(now=self.now,**kw)
    def test_routing_dedup_and_reverification(self):
        self.assertEqual(self.send(),0)
        self.assertEqual([c.args for c in self.tc.send_message.call_args_list],[(-100,'dan+maria+kate'),(123,'private-a+private-b')])
        self.tc.request.assert_called_once_with('getChat',data={'chat_id':'123'})
        self.assertEqual(self.send(),0);self.assertEqual(self.tc.send_message.call_count,2)
    def test_private_recipient_mismatch_blocks_only_private_and_retries(self):
        self.tc.request.return_value={'id':123,'type':'private','username':'someone_else'}
        self.assertEqual(self.send(),1);self.tc.send_message.assert_called_once_with(-100,'dan+maria+kate')
        self.tc.request.return_value={'id':123,'type':'private','username':'owner_example'}
        self.assertEqual(self.send(),0);self.assertEqual(self.tc.send_message.call_count,2)
        self.assertEqual(self.tc.send_message.call_args.args,(123,'private-a+private-b'))
    def test_failed_private_delivery_not_marked_sent(self):
        self.tc.send_message.side_effect=[None,bot.TelegramError('fail')]
        self.assertEqual(self.send(),1)
        self.tc.send_message.side_effect=None
        self.assertEqual(self.send(),0);self.assertEqual(self.tc.send_message.call_count,3)
        self.assertEqual(self.tc.send_message.call_args.args,(123,'private-a+private-b'))
    def test_private_only_never_sends_group(self):
        self.assertEqual(self.send(private_only=True),0);self.tc.send_message.assert_called_once_with(123,'private-a+private-b')
    def test_bad_route_rejected_before_any_send(self):
        report.PRIVATE_CONFIG_FILE.write_text(json.dumps({**self.route,'chat_id':456}))
        with self.assertRaises(report.ReportError):self.send()
        self.tc.send_message.assert_not_called()
    def test_private_chat_cannot_be_group(self):
        self.tc.request.return_value={'id':123,'type':'group','username':'owner_example'}
        self.assertEqual(self.send(private_only=True),1);self.tc.send_message.assert_not_called()

class HistoryFilterTests(unittest.TestCase):
    def test_private_and_general_totals_use_raw_ids(self):
        end=dt.datetime(2026,10,26,14,tzinfo=hist.UTC);start=end-dt.timedelta(days=7)
        a,b=start.timestamp(),end.timestamp()
        def counters(n):return {'private-a':{'label':'G alias','up':n,'down':2*n},'private-b':{'label':'L alias','up':2*n,'down':3*n},'hy2-test':{'label':'dan','up':3*n,'down':4*n}}
        source={'Hysteria 2':[(a,'epoch',counters(1000),False),(b,'epoch',counters(1100),False)]}
        with patch.object(hist,'read_samples',return_value=source):
            general=hist.render_report(end,enabled=False,excluded_users={'private-a','private-b'})
            private=hist.render_report(end,enabled=False,included_users={'private-a','private-b'})
        self.assertIn('dan | up 300 B',general);self.assertNotIn('G alias',general);self.assertNotIn('L alias',general)
        self.assertIn('G alias | up 100 B',private);self.assertIn('L alias | up 200 B',private);self.assertNotIn('dan',private)
        self.assertIn('2026-10-19 14:00:00 UTC -> 2026-10-26 14:00:00 UTC',private)
    def test_partial_week_and_missing_history_explicit(self):
        a=dt.datetime(2026,10,19,14,tzinfo=hist.UTC);b=dt.datetime(2026,10,25,6,tzinfo=hist.UTC)
        with patch.object(hist,'read_samples',return_value={}):
            msg=hist.render_report(enabled=False,included_users={'private-a','private-b'},interval=(a,b))
        self.assertIn('partial reporting week',msg);self.assertIn('INCOMPLETE HISTORY',msg);self.assertIn('Users: private-a, private-b',msg)

if __name__=='__main__':unittest.main(verbosity=2)
