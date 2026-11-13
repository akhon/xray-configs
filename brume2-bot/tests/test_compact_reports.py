import datetime as dt
import json
import unittest
from unittest.mock import patch, Mock
from test_hysteria_history import hist, bot


class CompactReportTests(unittest.TestCase):
    def test_retired_private_account_keeps_week_usage_across_restart(self):
        start = dt.datetime(2026, 10, 19, 14, tzinfo=hist.UTC)
        t = start.timestamp()
        def row(name, count):
            return {'label': name, 'up': count, 'down': count}
        source = {'Hysteria 2': [
            (t, 'old', {'retired': row('former', 1000), 'shared': row('other', 3000)}, False),
            (t+50, 'old', {'retired': row('former', 1030), 'shared': row('other', 3040)}, False),
            (t+51, 'new', {'shared': row('other', 10)}, False),
            (t+60, 'new', {'shared': row('other', 15)}, False)]}
        with patch.object(hist, 'read_samples', return_value=source):
            args = {'interval': (start, start+dt.timedelta(seconds=60)), 'enabled': False}
            owner = hist.render_report(included_users={'retired'}, **args)
            group = hist.render_report(excluded_users={'retired'}, **args)
        self.assertRegex(owner, r'former\s+30 B\s+30 B\s+60 B\s+—')
        self.assertRegex(group, r'other\s+55 B\s+55 B\s+110 B\s+—')
        self.assertNotIn('former', group)
        self.assertNotIn('other', owner)
        for text in [owner, group]:
            self.assertEqual(len(text.splitlines()), 3)
            self.assertIn('неполные данные', text.splitlines()[0])

    def test_telegram_table_entity_preserves_literal_text_and_utf16_offsets(self):
        first = '📅 даты UTC'
        body = 'Кто   Всего\nA<&>  10 B'
        client = bot.TelegramClient('fake')
        client.request = Mock()
        client.send_message(42, first+'\n'+body, 7, table=True)
        data = client.request.call_args.kwargs['data']
        self.assertEqual(data['text'], first+'\n'+body)
        self.assertEqual(json.loads(data['entities']), [{'type':'pre',
            'offset':len((first+'\n').encode('utf-16-le'))//2,
            'length':len(body.encode('utf-16-le'))//2}])
        self.assertEqual(json.loads(data['reply_parameters']), {'message_id':7})
