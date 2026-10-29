"""Read-only, like-for-like usage comparisons and UTC daily buckets.

Never calculate a percentage from incomplete history or use missing values as zero.
The same data model feeds Telegram reports and the optional local dashboard.
"""
import datetime as dt

import vpn_usage_history as history
from xray_user_stats import human_bytes

WEEK = dt.timedelta(days=7)


def _selected_samples(samples, included=None, excluded=(), label_filter=None):
    included = None if included is None else {u.casefold() for u in included}
    excluded = {u.casefold() for u in excluded}
    result = [(t, epoch, {key: row for key, row in counters.items()
               if key.casefold() not in excluded and (included is None or key.casefold() in included)}, error)
              for t, epoch, counters, error in samples]
    if label_filter is not None:
        # Resolve the newest label to stable account IDs before comparing history.
        latest = next((c for _, _, c, error in reversed(result) if not error), {})
        query = label_filter.casefold()
        exact = {key for key, row in latest.items() if row['label'].casefold() == query}
        selected = exact or {key for key, row in latest.items() if row['label'].casefold().startswith(query + '-')}
        result = [(t, epoch, {k: v for k, v in c.items() if k in selected}, error)
                  for t, epoch, c, error in result]
    return result


def _summary(samples, start, end):
    result = history.summarize(samples, start.timestamp(), end.timestamp())
    rows = result['totals']
    return {'rows': rows, 'complete': not result['reasons'], 'reasons': sorted(result['reasons']),
            'estimated': result['estimated'],
            'bytes': sum(row['up'] + row['down'] for row in rows.values()) if rows else None,
            'up': sum(row['up'] for row in rows.values()) if rows else None,
            'down': sum(row['down'] for row in rows.values()) if rows else None}


def compare(current, previous, complete):
    if not complete or current is None or previous is None:
        return {'status': 'incomplete', 'percent': None}
    if previous == 0:
        return {'status': 'unchanged' if current == 0 else 'new_usage', 'percent': 0.0 if current == 0 else None}
    return {'status': 'comparable', 'percent': 100.0 * (current - previous) / previous}


def build_trends(start, end, path=history.DB_FILE, enabled=False, included_users=None,
                 excluded_users=(), label_filter=None):
    if start.tzinfo is None or end.tzinfo is None or end < start:
        raise history.HistoryError('Invalid trend interval')
    start, end = start.astimezone(history.UTC), end.astimezone(history.UTC)
    prior_start, prior_end = start - WEEK, end - WEEK
    # Seven UTC dates ending with the current partial day, or seven whole days
    # when the interval ends exactly at midnight.
    day_end = end if end.time() != dt.time() else end - dt.timedelta(microseconds=1)
    day_start = day_end.replace(hour=0, minute=0, second=0, microsecond=0) - dt.timedelta(days=6)
    source = history.read_samples(path, min(prior_start, day_start).timestamp(), end.timestamp())
    protocols = ['Hysteria 2'] + (['Xray'] if enabled else [])
    data = {'start': start.isoformat(), 'end': end.isoformat(),
            'previous_start': prior_start.isoformat(), 'previous_end': prior_end.isoformat(), 'protocols': []}
    for protocol in protocols:
        samples = _selected_samples(source.get(protocol, []),
            included_users if protocol == 'Hysteria 2' else None,
            excluded_users if protocol == 'Hysteria 2' else (), label_filter)
        current = _summary(samples, start, end)
        previous = _summary(samples, prior_start, prior_end)
        rows = []
        for key in sorted(set(current['rows']) | set(previous['rows'])):
            c, p = current['rows'].get(key), previous['rows'].get(key)
            cbytes = c['up'] + c['down'] if c else None
            pbytes = p['up'] + p['down'] if p else None
            rows.append({'account': key, 'label': (c or p)['label'], 'current': cbytes, 'previous': pbytes,
                         'up': c['up'] if c else None, 'down': c['down'] if c else None,
                         **compare(cbytes, pbytes, current['complete'] and previous['complete'])})
        days = []
        for offset in range(7):
            left = day_start + dt.timedelta(days=offset)
            right = min(left + dt.timedelta(days=1), end)
            summary = _summary(samples, left, right)
            days.append({'date': left.strftime('%Y-%m-%d'), 'start': left.isoformat(), 'end': right.isoformat(),
                         'bytes': summary['bytes'], 'up': summary['up'], 'down': summary['down'],
                         'complete': summary['complete'], 'estimated': summary['estimated'],
                         'reasons': summary['reasons']})
        data['protocols'].append({'name': protocol, 'current': current, 'previous': previous, 'users': rows,
            'comparison': compare(current['bytes'], previous['bytes'], current['complete'] and previous['complete']),
            'days': days})
    return data


def current_trends(now=None, **kwargs):
    now = now or dt.datetime.now(history.UTC)
    return build_trends(history.period(now)[1], now, **kwargs)


def _date(value):
    return dt.datetime.fromisoformat(value).strftime('%d.%m.%Y %H:%M')


def render_trends(data, include_days=True):
    lines = ['Тренд: одинаковый отрезок двух недель (UTC)',
             '%s–%s ↔ %s–%s' % tuple(_date(data[k]) for k in ('start','end','previous_start','previous_end'))]
    for protocol in data['protocols']:
        lines.append(protocol['name'])
        for row in protocol['users']:
            current = 'нет данных' if row['current'] is None else human_bytes(row['current'])
            previous = 'нет данных' if row['previous'] is None else human_bytes(row['previous'])
            if row['status'] == 'incomplete':
                change = 'сравнение недоступно: неполная история'
            elif row['status'] == 'new_usage':
                change = 'появился трафик (ранее 0)'
            else:
                change = '%+.1f%%' % row['percent']
            lines.append('%s: %s / ранее %s; %s' % (row['label'], current, previous, change))
        if not protocol['users']:
            lines.append('Недостаточно истории для сравнения.')
        if include_days:
            daily = []
            for day in protocol['days']:
                value = '—' if day['bytes'] is None else ('≈' if not day['complete'] else '') + human_bytes(day['bytes'])
                daily.append(day['date'][8:10] + '.' + day['date'][5:7] + ' ' + value)
            lines.append('По дням UTC: ' + ' · '.join(daily))
    lines.append('— нет данных; ≈ неполные наблюдения. Последний день — до правой границы отчёта.')
    return '\n'.join(lines)
