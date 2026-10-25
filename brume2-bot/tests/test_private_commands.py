import copy
import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import xray_telegram_bot as bot
import vpn_usage_history as hist

OWNER=123
GROUP=-100
PRIVATE=frozenset({'private-a','private-b'})

def message(text='/stats',chat=OWNER,user=OWNER,kind='private',**extra):
    return {'text':text,'chat':{'id':chat,'type':kind},'from':{'id':user,'is_bot':False},**extra}

class PrivateCommands(unittest.TestCase):
    def setUp(self):
        self.b=bot.Bot(bot.Settings('fake',frozenset({GROUP}),frozenset({OWNER,456}),False,OWNER,PRIVATE))
        self.b.telegram=Mock()
    def test_access_matrix_rejects_all_other_private_and_group_sources(self):
        invalid=[message(chat=456,user=456),message(chat=789,user=789),message(user=456),
            message(chat=GROUP,user=789,kind='supergroup'),message(chat=-200,kind='supergroup'),
            message(chat=GROUP,kind='channel'),message(chat=GROUP,kind='private'),message(kind='supergroup'),
            message(kind=None),message(chat=str(OWNER)),message(user=str(OWNER)),message(user=True),
            message(sender_chat={'id':GROUP})]
        bot_sender=message();bot_sender['from']['is_bot']=True;invalid.append(bot_sender)
        missing_sender=message();del missing_sender['from'];invalid.append(missing_sender)
        for payload in invalid:
            for command in ['/start','/help','/stats','/ip','/status','/qr alice hiddify','/hysteria','/hylinks','/restart']:
                self.b.telegram.reset_mock();payload['text']=command
                self.b.handle_message(payload)
                self.assertEqual(self.b.telegram.mock_calls,[],(payload,command))
    def test_owner_and_existing_group_members_are_accepted(self):
        for payload in [message(),message(chat=GROUP,kind='supergroup'),message(chat=GROUP,user=456,kind='supergroup')]:
            self.assertTrue(self.b.authorized(payload))
    def test_current_week_is_delta_and_contains_only_private_users(self):
        start=dt.datetime(2026,10,26,14,tzinfo=hist.UTC);now=start+dt.timedelta(seconds=60)
        def counters(n):return {'private-a':{'label':'private-a','up':n,'down':n*2},
           'private-b':{'label':'private-b','up':n*3,'down':n*4},'alice':{'label':'alice','up':n*5,'down':n*6}}
        source={'Hysteria 2':[(start.timestamp(),'epoch',counters(10000),False),(now.timestamp(),'epoch',counters(10100),False)]}
        with patch.object(bot,'utc_now',return_value=now),patch.object(hist,'sample_once',return_value=True) as sample,patch.object(hist,'read_samples',return_value=source):
            self.b.handle_message(message())
            text=self.b.telegram.send_message.call_args.args[1]
            self.assertIn('private-a | up 100 B',text);self.assertIn('private-b | up 300 B',text)
            self.assertNotIn('alice',text);self.assertIn('2026-10-26 14:00:00 UTC -> 2026-10-26 14:01:00 UTC',text)
            sample.assert_called_once()
            self.b.handle_message(message('/stats private-b'))
            text=self.b.telegram.send_message.call_args.args[1]
            self.assertIn('private-b',text);self.assertNotIn('private-a',text)
    def test_private_filter_cannot_select_general_users(self):
        with patch.object(hist,'sample_once') as sample:
            self.b.handle_message(message('/stats alice'));sample.assert_not_called()
        self.assertIn('Only configured private users',self.b.telegram.send_message.call_args.args[1])
    def test_sample_failure_still_returns_incomplete_history(self):
        with patch.object(hist,'sample_once',side_effect=RuntimeError('SECRET')),patch.object(hist,'render_current_week',return_value='observed usage'):
            self.b.handle_message(message())
        text=self.b.telegram.send_message.call_args.args[1]
        self.assertIn('INCOMPLETE HISTORY',text);self.assertIn('observed usage',text);self.assertNotIn('SECRET',text)
    def test_common_commands_are_available_to_owner(self):
        with patch.object(bot,'get_public_ip',return_value='203.0.113.1'),patch.object(bot,'hysteria_health_snapshot',return_value={'service':'running','stats_available':True}):
            for command,expected in [('/start','/qr'),('/help','Monday 14:00 UTC'),('/ip','203.0.113.1'),('/status','running')]:
                self.b.telegram.reset_mock();self.b.handle_message(message(command))
                self.assertIn(expected,self.b.telegram.send_message.call_args.args[1])
        for command,method,args in [('/hysteria alice','send_hysteria_profile',(OWNER,'alice')),('/hylinks alice','send_hysteria_links',(OWNER,'alice')),('/qr alice hiddify','command_qr',(OWNER,None,['alice','hiddify']))]:
            with patch.object(self.b,method) as call:
                self.b.handle_message(message(command));call.assert_called_once_with(*args)
    def test_group_stats_remains_shared_and_excludes_private_users(self):
        import vpn_user_stats
        with patch.object(vpn_user_stats,'render_summary',return_value='shared stats') as render,patch.object(hist,'sample_once') as sample:
            self.b.handle_message(message(chat=GROUP,kind='supergroup'))
            render.assert_called_once_with(None,compact=True,vmess_enabled=False,excluded_hysteria_users=PRIVATE)
            sample.assert_not_called()
    def test_menus_are_scoped_and_describe_private_stats(self):
        self.assertEqual(self.b.menu_targets(),[(GROUP,False),(OWNER,True)])
        private=bot.telegram_commands(False,True);group=bot.telegram_commands(False,False)
        self.assertEqual([c['command'] for c in private],[c['command'] for c in group])
        self.assertNotEqual(next(c['description'] for c in private if c['command']=='stats'),next(c['description'] for c in group if c['command']=='stats'))
        self.assertNotIn('private-a',bot.help_text())
    def test_exact_week_boundary_is_new_empty_week(self):
        now=dt.datetime(2026,10,26,14,tzinfo=hist.UTC)
        with patch.object(hist,'read_samples') as read:
            text=hist.render_current_week(now,included_users=PRIVATE);read.assert_not_called()
        self.assertIn('No time has elapsed',text);self.assertNotIn('2026-10-19',text)
    def test_monday_before_reporting_boundary_stays_in_previous_week(self):
        now=dt.datetime(2026,10,26,13,59,tzinfo=hist.UTC)
        with patch.object(hist,'read_samples',return_value={}):text=hist.render_current_week(now,included_users=PRIVATE)
        self.assertIn('2026-10-19 14:00:00 UTC -> 2026-10-26 13:59:00 UTC',text)

class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'settings.json'
        self.raw={'bot_token':'123456:'+('X'*30),'allowed_chat_ids':[GROUP],'allowed_user_ids':[OWNER,456],
                  'private_owner_id':OWNER,'private_hysteria_users':['private-a','private-b'],'vmess_enabled':False}
    def load(self):
        self.path.write_text(json.dumps(self.raw))
        with patch.object(bot,'BOT_CONFIG',self.path):return bot.load_settings()
    def test_parameters_are_loaded_without_hardcoded_accounts(self):
        self.raw['private_hysteria_users']=['CUSTOM-A','custom-b'];s=self.load()
        self.assertEqual(s.private_hysteria_users,frozenset({'custom-a','custom-b'}));self.assertEqual(s.private_owner_id,OWNER)
    def test_unsafe_ids_and_open_allowlists_fail_closed(self):
        changes=[('allowed_chat_ids',[OWNER]),('allowed_chat_ids',[-1.0]),('allowed_chat_ids',['-100']),
            ('allowed_user_ids',[]),('allowed_user_ids',[True]),('allowed_user_ids',[0]),('allowed_user_ids',['123']),
            ('private_owner_id',4567),('private_owner_id',True),('private_hysteria_users',[]),('private_hysteria_users',['../bad'])]
        original=copy.deepcopy(self.raw)
        for field,value in changes:
            self.raw=copy.deepcopy(original);self.raw[field]=value
            with self.assertRaises(bot.OperationError,msg=field):self.load()
    def test_private_access_disabled_unless_configured(self):
        del self.raw['private_owner_id'];s=self.load();b=bot.Bot(s)
        self.assertFalse(b.authorized(message()));self.assertTrue(b.authorized(message(chat=GROUP,kind='supergroup')))

class CertificateNameTests(unittest.TestCase):
    def test_hostname_matcher_rejects_mismatch_and_prefers_san(self):
        cert={"subjectAltName": (("DNS", "example.com"),),
              "subject": ((("commonName", "different.example"),),)}
        bot.match_certificate_hostname(cert, "example.com")
        for name in ["different.example", "badexample.com", "example.com.evil.test"]:
            with self.assertRaises(ValueError):bot.match_certificate_hostname(cert, name)
    def test_hostname_matcher_preserves_common_name_only_certificate(self):
        cert={"subject": ((("commonName", "example.com"),),)}
        bot.match_certificate_hostname(cert, "example.com")

if __name__=='__main__':unittest.main()
