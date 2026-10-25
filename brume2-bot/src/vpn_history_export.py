#!/usr/bin/env python3
"""Export only counters and their scope over SSH, without copying configuration."""
import argparse
import json
import math
from pathlib import Path
import sys

import vpn_usage_history as history


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
    return {'version': 1, 'private_users': private, 'vmess_enabled': settings.get('vmess_enabled', False),
            'rows': [[t, p, epoch, json.loads(c), error] for t, p, epoch, c, error in rows],
            'more': len(rows) == 5000}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--since', type=float, default=0.0)
    args = parser.parse_args()
    try:
        print(json.dumps(export(args.since), separators=(',', ':'), allow_nan=False))
        return 0
    except Exception:
        print('History export unavailable.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
