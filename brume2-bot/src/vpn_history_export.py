#!/usr/bin/env python3
"""Export counters over SSH; restore a bounded RAM cache from Mac-owned history."""
import argparse
import json
import math
from pathlib import Path
import sys
import time

import vpn_usage_history as history
import vpn_history_transfer as transfer


def export(since=0.0, path=history.DB_FILE, settings_path=Path('/etc/xray/telegram_bot.json')):
    if not math.isfinite(since) or since < 0:
        raise ValueError('Invalid cursor')
    settings = json.loads(settings_path.read_text())
    private = settings.get('private_hysteria_users', [])
    if not isinstance(private, list) or not all(isinstance(u, str) for u in private):
        raise ValueError('Invalid private scope')
    db = history.connect(path, readonly=True)
    rows = []
    if db is not None:
        try:
            rows = db.execute('SELECT t,protocol,epoch,counters,error FROM samples WHERE t>=? '
                              'ORDER BY t,protocol LIMIT 5000', (since,)).fetchall()
        finally:
            db.close()
    return {'version': 1, 'boot_id': transfer.boot_id(), 'private_users': private,
            'vmess_enabled': settings.get('vmess_enabled', False),
            'rows': [[t, p, epoch, json.loads(c), error] for t, p, epoch, c, error in rows],
            'more': len(rows) == 5000}


def restore(payload, path=history.DB_FILE):
    if not isinstance(payload, dict) or set(payload) != {'version', 'boot_id', 'rows'} or payload['version'] != 1:
        raise ValueError('Invalid restore payload')
    expected = transfer.valid_boot_id(payload['boot_id'])
    if expected != transfer.boot_id():
        raise ValueError('Router restarted during transfer')
    rows = transfer.validate_rows(payload['rows'])
    cutoff = time.time() - history.RETENTION_DAYS * 86400
    db = history.connect(path)
    inserted = 0
    try:
        db.execute('BEGIN IMMEDIATE')
        for t, protocol, epoch, counters, error in rows:
            if t < cutoff:
                continue
            old = db.execute('SELECT epoch,counters,error FROM samples WHERE protocol=? AND t=?',
                             (protocol, t)).fetchone()
            if old:
                if (old[0], json.loads(old[1]), old[2]) != (epoch, counters, error):
                    raise ValueError('Conflicting historical reading')
                continue
            db.execute('INSERT INTO samples VALUES (?,?,?,?,?)',
                       (t, protocol, epoch, json.dumps(counters, separators=(',', ':')), error))
            inserted += 1
        if transfer.boot_id() != expected:
            raise ValueError('Router restarted during transfer')
        db.execute('DELETE FROM samples WHERE t < ?', (cutoff,))
        db.commit()
        return {'ok': True, 'boot_id': expected, 'inserted': inserted}
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--since', type=float, default=0.0)
    mode.add_argument('--restore', action='store_true', help='Restore only counter rows to the RAM cache from stdin')
    args = parser.parse_args()
    try:
        if args.restore:
            raw = sys.stdin.buffer.read(transfer.MAX_BYTES + 1)
            if len(raw) > transfer.MAX_BYTES:
                raise ValueError('Restore too large')
            result = restore(json.loads(raw))
        else:
            result = export(args.since)
        print(json.dumps(result, separators=(',', ':'), allow_nan=False))
        return 0
    except Exception:
        print('History export unavailable.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
