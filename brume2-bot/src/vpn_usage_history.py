#!/usr/bin/env python3
"""RAM-only minute samples and UTC Monday-14:00 reporting intervals.

Counters are never cleared. First observations are baselines, not weekly usage.
Restarts and decreasing counters add only post-reset counters and flag lost tails.
Interpolation at week boundaries is disclosed; unobserved resets cannot be recovered.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import sys
import time

DB_FILE = Path('/tmp/vpn-usage/history.sqlite3')
RETENTION_DAYS = 21
MAX_GAP = 150
UTC = dt.timezone.utc


class HistoryError(Exception):
    pass


def period(now=None):
    now = now or dt.datetime.now(UTC)
    if now.tzinfo is None:
        raise HistoryError('Report time must include a timezone')
    now = now.astimezone(UTC)
    end = (now - dt.timedelta(days=now.weekday())).replace(hour=14, minute=0, second=0, microsecond=0)
    if end > now:
        end -= dt.timedelta(days=7)
    return end - dt.timedelta(days=7), end


def process_epoch(name):
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    epochs = []
    for path in Path('/proc').glob('[0-9]*'):
        try:
            if (path / 'comm').read_text().strip() == name:
                args = (path / 'cmdline').read_bytes().split(b'\0')
                if name == 'hysteria' and b'server' not in args:
                    continue
                if name == 'xray' and b'/etc/xray/config.json' not in args:
                    continue
                # The comm field can contain spaces; fields after its final ')' start at #3.
                ticks = (path / 'stat').read_text().rsplit(')', 1)[1].split()[19]
                epochs.append('%s:%s' % (path.name, ticks))
        except (OSError, IndexError):
            continue
    if len(epochs) != 1:
        raise HistoryError('Service epoch unavailable or ambiguous')
    return boot + ':' + epochs[0]


def live_hysteria():
    import hysteria_user_stats as hy
    cfg = hy._load_config(hy.DEFAULT_CONFIG)
    users = hy.configured_users(cfg, hy._load_labels(hy.DEFAULT_LABELS))
    data = hy._request('/traffic', hy._api_secret(cfg))
    counters = {}
    for user in users:
        value = data.get(user.counter_label)
        if value is None and user.counter_label not in data:
            value = {'tx': 0, 'rx': 0}  # A never-used account has no API entry.
        if not isinstance(value, dict) or any(type(value.get(k)) is not int or value[k] < 0 for k in ('tx', 'rx')):
            raise HistoryError('Invalid traffic sample')
        counters[user.counter_label] = {'label': user.label, 'up': value['tx'], 'down': value['rx']}
    return counters


def live_xray():
    import xray_user_stats as xr
    # Keep the legacy backend when explicitly enabled. Its collector is read-only.
    return {r.label: {'label': r.label, 'up': r.uplink, 'down': r.downlink}
            for r in xr.collect_stats()}


def collect_live():
    from vpn_features import load_vmess_enabled
    backends = [('Hysteria 2', 'hysteria', live_hysteria)]
    if load_vmess_enabled():
        backends.append(('Xray', 'xray', live_xray))
    samples = []
    for protocol, process, reader in backends:
        try:
            epoch = process_epoch(process)
            counters = reader()
            if process_epoch(process) != epoch:
                raise HistoryError('Service restarted during sampling')
            samples.append((time.time(), protocol, epoch, counters, 0))
        except Exception:
            samples.append((time.time(), protocol, '', {}, 1))
    return samples


def connect(path=DB_FILE, readonly=False):
    path = Path(path)
    if readonly:
        if not path.exists():
            return None
        db = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=20)
    else:
        if path.is_symlink():
            raise HistoryError('History path must not be a symlink')
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(path), os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        os.fchmod(fd, 0o600)
        os.close(fd)
        db = sqlite3.connect(str(path), timeout=20)
        db.execute('PRAGMA synchronous=FULL')
        db.execute('CREATE TABLE IF NOT EXISTS samples (t REAL NOT NULL, protocol TEXT NOT NULL, '
                   'epoch TEXT NOT NULL, counters TEXT NOT NULL, error INTEGER NOT NULL, PRIMARY KEY(protocol,t))')
        db.commit()
    return db


def sample_once(path=DB_FILE, collector=None):
    db = connect(path)
    try:
        # Serialize collection itself, so a cron and report sample cannot commit out of order.
        db.execute('BEGIN IMMEDIATE')
        samples = (collector or collect_live)()
        for stamp, protocol, epoch, counters, error in samples:
            latest = db.execute('SELECT MAX(t) FROM samples WHERE protocol=?', (protocol,)).fetchone()[0]
            if latest is not None and stamp <= latest:
                raise HistoryError('Clock moved backwards; history preserved')
            db.execute('INSERT INTO samples VALUES (?,?,?,?,?)',
                       (stamp, protocol, epoch, json.dumps(counters, separators=(',', ':')), error))
        if samples:
            cutoff = min(s[0] for s in samples) - RETENTION_DAYS * 86400
            db.execute('DELETE FROM samples WHERE t < ?', (cutoff,))
        db.commit()
        return not any(s[4] for s in samples)
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def read_samples(path, start, end):
    db = connect(path, readonly=True)
    if db is None:
        return {}
    try:
        output = {}
        for protocol, in db.execute('SELECT DISTINCT protocol FROM samples'):
            before = db.execute('SELECT MAX(t) FROM samples WHERE protocol=? AND t<=?', (protocol, start)).fetchone()[0]
            after = db.execute('SELECT MIN(t) FROM samples WHERE protocol=? AND t>=?', (protocol, end)).fetchone()[0]
            rows = db.execute('SELECT t,epoch,counters,error FROM samples WHERE protocol=? AND t>=? AND t<=? ORDER BY t',
                              (protocol, before if before is not None else start, after if after is not None else end)).fetchall()
            output[protocol] = [(t, epoch, json.loads(payload), bool(error)) for t, epoch, payload, error in rows]
        return output
    finally:
        db.close()


def summarize(samples, start, end):
    """Pure interval accounting; always retains observed lower bounds after resets."""
    totals, reasons = {}, set()
    good = [s for s in samples if not s[3]]
    if len(good) < 2 or good[-1][0] <= start or good[0][0] >= end:
        return {'totals': {}, 'reasons': {'no recoverable history in this period'},
                'estimated': False, 'coverage': None}
    first, last = good[0][0], good[-1][0]
    if first > start:
        reasons.add('collection started after period start')
    if last < end:
        reasons.add('missing period-end sample')
    if any(s[3] and start <= s[0] <= end for s in samples):
        reasons.add('API unavailable during collection')
    estimated = False
    for t, epoch, counters, error in good:
        if start <= t <= end:
            for key, value in counters.items():
                totals.setdefault(key, {'label': value['label'], 'up': 0, 'down': 0})
    for previous, current in zip(good, good[1:]):
        t0, epoch0, c0, _ = previous
        t1, epoch1, c1, _ = current
        left, right = max(start, t0), min(end, t1)
        if right <= left:
            continue
        elapsed = t1 - t0
        if elapsed > MAX_GAP:
            reasons.add('sampling gap over 150 seconds')
        fraction = (right-left)/elapsed
        boundary = left != t0 or right != t1
        estimated |= boundary
        reset = epoch0 != epoch1
        if reset:
            reasons.add('service restart: pre-reset tail unavailable')
        for key in set(c0) | set(c1):
            if key not in c0 or key not in c1:
                reasons.add('user added/removed: partial user history')
                continue
            old, new = c0[key], c1[key]
            total = totals.setdefault(key, {'label': new['label'], 'up': 0, 'down': 0})
            for direction in ('up', 'down'):
                lowered = new[direction] < old[direction]
                if lowered and not reset:
                    reasons.add('counter reset: pre-reset tail unavailable')
                delta = new[direction] if reset or lowered else new[direction] - old[direction]
                if (reset or lowered) and boundary:
                    # Reset time is unknown; do not attribute post-reset bytes to a different week.
                    reasons.add('reset crosses reporting boundary: interval omitted')
                    continue
                # Cumulative rounding preserves the total across adjacent reporting weeks.
                total[direction] += round(delta * (right-t0)/elapsed) - round(delta * (left-t0)/elapsed)
    return {'totals': totals, 'reasons': reasons, 'estimated': estimated,
            'coverage': (max(start, first), min(end, last))}


def stamp(value):
    return dt.datetime.fromtimestamp(value, UTC).strftime('%Y-%m-%d %H:%M:%S')


def render_report(now=None, path=DB_FILE, enabled=None, included_users=None, excluded_users=(), interval=None):
    from xray_user_stats import human_bytes
    from vpn_features import load_vmess_enabled
    start, end = period(now) if interval is None else interval
    if start.tzinfo is None or end.tzinfo is None or end <= start:
        raise HistoryError("Invalid reporting interval")
    a, b = start.timestamp(), end.timestamp()
    included = None if included_users is None else {u.casefold() for u in included_users}
    excluded = {u.casefold() for u in excluded_users}
    protocols = ['Hysteria 2']
    if load_vmess_enabled() if enabled is None else enabled:
        protocols.append('Xray')
    source = read_samples(path, a, b)
    lines = ['Weekly VPN usage' if interval is None else 'VPN usage — partial reporting week',
             'Period: %s UTC -> %s UTC (end exclusive)' % (stamp(a), stamp(b))]
    if included is not None:
        lines.append('Users: ' + ', '.join(sorted(included)))
    for protocol in protocols:
        samples = source.get(protocol, [])
        if protocol == 'Hysteria 2':
            # Filter raw account IDs before accounting, including aliases and history.
            samples = [(t, epoch, {key: row for key, row in counters.items()
                        if key.casefold() not in excluded
                        and (included is None or key.casefold() in included)}, error)
                       for t, epoch, counters, error in samples]
        result = summarize(samples, a, b)
        lines.extend(['', protocol + ' — ' + ('INCOMPLETE HISTORY' if result['reasons'] else 'sampled weekly usage')])
        if result['coverage']:
            lines.append('Observed: %s -> %s UTC' % tuple(stamp(t) for t in result['coverage']))
        if result['reasons']:
            lines.append('Reasons: ' + '; '.join(sorted(result['reasons'])) + '.')
            lines.append('Only observed usage is shown; missing traffic is unknown.')
        if result['estimated']:
            lines.append('Week-boundary allocation is estimated between adjacent samples.')
        rows = sorted(result['totals'].values(), key=lambda row: row['label'].casefold())
        if not rows:
            lines.append('Usage unavailable; no recoverable readings for this period.')
        for row in rows:
            lines.append('%s | up %s | down %s | total %s' %
                         (row['label'], human_bytes(row['up']), human_bytes(row['down']), human_bytes(row['up']+row['down'])))
    lines.extend(['', 'One-minute counter deltas; resets never count prior cumulative traffic.',
                  'An API reset entirely between samples may be undetectable.'])
    from vpn_usage_trends import build_trends, render_trends
    trends = build_trends(start, end, path=path, enabled='Xray' in protocols,
                          included_users=included_users, excluded_users=excluded_users)
    lines.extend(['', render_trends(trends)])
    message = '\n'.join(lines)
    if len(message) > 3800:
        message = message[:3630].rsplit('\n', 1)[0] + '\nAdditional rows omitted; full history remains on the router.'
    return message


def render_current_week(now=None, path=DB_FILE, included_users=()):
    now = now or dt.datetime.now(UTC)
    start = period(now)[1]
    if now == start:
        return ("VPN usage — current reporting week\n"
                "Period: %s UTC -> %s UTC (end exclusive)\n"
                "Users: %s\nNo time has elapsed in this reporting week."
                % (stamp(start.timestamp()), stamp(now.timestamp()), ", ".join(sorted(included_users))))
    return render_report(now, path=path, enabled=False, included_users=included_users,
                         interval=(start, now))


def main():
    parser = argparse.ArgumentParser(description='Record traffic counters locally, without Telegram.')
    parser.parse_args()
    try:
        if not sample_once():
            print('Usage sample incomplete: a backend is unavailable.', file=sys.stderr)
            return 1
        return 0
    except Exception:
        print('Usage collection failed; existing history preserved.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
