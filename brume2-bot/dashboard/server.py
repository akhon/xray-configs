#!/usr/bin/env python3
"""Loopback dashboard and incremental SSH archive. No third-party packages required."""
import argparse
import datetime as dt
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import vpn_usage_history as history
import vpn_usage_trends as trends

ASSETS = Path(__file__).resolve().parent


def validate(payload):
    if not isinstance(payload, dict) or payload.get('version') != 1:
        raise ValueError('Unknown export format')
    if type(payload.get('more')) is not bool or type(payload.get('vmess_enabled')) is not bool:
        raise ValueError('Invalid flags')
    users = payload.get('private_users')
    if not isinstance(users, list) or len(users) > 10000 or not all(isinstance(u, str) and 0 < len(u) < 129 for u in users):
        raise ValueError('Invalid scope')
    rows = payload.get('rows')
    if not isinstance(rows, list) or len(rows) > 5000:
        raise ValueError('Invalid row count')
    for row in rows:
        if not isinstance(row, list) or len(row) != 5:
            raise ValueError('Invalid row')
        t, protocol, epoch, counters, error = row
        if type(t) not in (int, float) or not math.isfinite(t) or not 0 <= t <= time.time() + 300:
            raise ValueError('Invalid timestamp')
        if protocol not in ('Hysteria 2', 'Xray') or not isinstance(epoch, str) or len(epoch) > 200:
            raise ValueError('Invalid source')
        if type(error) is not int or error not in (0, 1) or not isinstance(counters, dict):
            raise ValueError('Invalid counters')
        for key, value in counters.items():
            if not isinstance(key, str) or not 0 < len(key) < 129 or not isinstance(value, dict):
                raise ValueError('Invalid account')
            if set(value) != {'label', 'up', 'down'} or not isinstance(value['label'], str) or len(value['label']) > 200:
                raise ValueError('Invalid label')
            if any(type(value[d]) is not int or not 0 <= value[d] < 2**63 for d in ('up', 'down')):
                raise ValueError('Invalid counter')
    return payload


class Archive:
    def __init__(self, directory, host):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        self.path = self.directory / 'usage.sqlite3'
        self.meta_path = self.directory / 'sync.json'
        self.host = host
        self.lock = threading.Lock()
        self.data = None
        self.error = None
        self.meta = json.loads(self.meta_path.read_text()) if self.meta_path.exists() else {}
        db = history.connect(self.path)
        db.close()
        self.rebuild()

    def rebuild(self):
        db = history.connect(self.path, readonly=True)
        try:
            first, last, count = db.execute('SELECT MIN(t),MAX(t),COUNT(*) FROM samples').fetchone()
        finally:
            db.close()
        if not last or 'private_users' not in self.meta:
            return
        now = dt.datetime.fromtimestamp(min(last, time.time()), history.UTC)
        private = self.meta['private_users']
        data = {'as_of': now.isoformat(), 'history_start': dt.datetime.fromtimestamp(first, history.UTC).isoformat(),
                'samples': count, 'scopes': {
                    'shared': trends.current_trends(now, path=self.path, excluded_users=private,
                                                   enabled=self.meta.get('vmess_enabled', False)),
                    'private': trends.current_trends(now, path=self.path, included_users=private, enabled=False)}}
        with self.lock:
            self.data = data

    def sync(self):
        db = history.connect(self.path)
        try:
            cursor = db.execute('SELECT MAX(t) FROM samples').fetchone()[0] or 0.0
            # One row overlaps on each sync. Idempotent inserts recover interrupted transfers.
            for _ in range(100):
                result = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                    '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2', self.host,
                    '/usr/bin/python3 /usr/bin/vpn_history_export.py --since %.17g' % cursor],
                    capture_output=True, timeout=45, check=True)
                if len(result.stdout) > 16 * 1024 * 1024:
                    raise ValueError('Export too large')
                payload = validate(json.loads(result.stdout))
                for t, protocol, epoch, counters, error in payload['rows']:
                    db.execute('INSERT OR IGNORE INTO samples VALUES (?,?,?,?,?)',
                               (t, protocol, epoch, json.dumps(counters, separators=(',', ':')), error))
                db.commit()
                previous = cursor
                cursor = max([cursor] + [row[0] for row in payload['rows']])
                if not payload['more']:
                    break
                if cursor <= previous:
                    raise ValueError('Cursor did not advance')
            else:
                raise ValueError('Archive catch-up limit reached')
            self.meta = {k: payload[k] for k in ('private_users', 'vmess_enabled')}
            self.meta['last_sync'] = dt.datetime.now(history.UTC).isoformat()
            temporary = self.meta_path.with_suffix('.tmp')
            fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as stream:
                json.dump(self.meta, stream)
            os.replace(temporary, self.meta_path)
            self.rebuild()
            with self.lock:
                self.error = None
        except Exception:
            db.rollback()
            with self.lock:
                self.error = 'Связь с роутером недоступна. Показан последний сохранённый снимок.'
            # Do not expose SSH stderr or any configuration/exception text through HTTP.
        finally:
            db.close()

    def snapshot(self):
        with self.lock:
            return {'data': self.data, 'sync_error': self.error, 'last_sync': self.meta.get('last_sync')}


def handler_for(archive, port):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hosts = {'127.0.0.1:%d' % port, 'localhost:%d' % port}
            origin = self.headers.get('Origin')
            if self.headers.get('Host') not in hosts or (origin and origin not in {'http://' + h for h in hosts}):
                self.send_error(403)
                return
            if self.path == '/api/usage':
                body = json.dumps(archive.snapshot(), ensure_ascii=False, allow_nan=False).encode()
                mime = 'application/json; charset=utf-8'
            elif self.path in ('/', '/app.js', '/style.css'):
                filename = {'/': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css'}[self.path]
                body = (ASSETS / filename).read_bytes()
                mime = {'/': 'text/html', '/app.js': 'text/javascript', '/style.css': 'text/css'}[self.path] + '; charset=utf-8'
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-host', required=True, help='Existing SSH alias or user@host')
    parser.add_argument('--data-dir', required=True, type=Path)
    parser.add_argument('--port', type=int, default=8765)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@:-]*', args.ssh_host) or not 1024 <= args.port <= 65535:
        parser.error('Invalid SSH destination or port')
    os.umask(0o077)
    archive = Archive(args.data_dir, args.ssh_host)
    server = ThreadingHTTPServer(('127.0.0.1', args.port), handler_for(archive, args.port))
    stop = threading.Event()

    def collect():
        while not stop.is_set():
            archive.sync()
            stop.wait(60)

    threading.Thread(target=collect, daemon=True).start()
    print('Dashboard: http://127.0.0.1:%d' % args.port, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()


if __name__ == '__main__':
    main()
