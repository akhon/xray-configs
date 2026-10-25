#!/usr/bin/env python3
"""Read-only Hysteria 2 userpass statistics, using only the standard library.

Hysteria v2.12.3 reports tx/rx from the CLIENT perspective: tx is upload.
The API's /online value counts authenticated Hysteria client connections, not
proxy streams or distinct people. We never request counter clearing.
"""

import argparse
import http.client
import json
import sys
from pathlib import Path

from xray_user_stats import (
    APIError, ConfigError, StatsError, User, UserNotFound, UserStats,
    _counter, _safe_label, _secrets, human_bytes, select_users,
)


DEFAULT_CONFIG = "/etc/hysteria2/config.json"
DEFAULT_LABELS = "/etc/hysteria2/user-labels.json"
API_HOST = "127.0.0.1"
API_PORT = 18081
API_TIMEOUT = 3
MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_LABEL_BYTES = 64 * 1024
MAX_API_BYTES = 1024 * 1024
MAX_USERS = 1024
MAX_API_USERS = 4096


class NotInstalled(StatsError):
    """Only a missing configuration means this optional backend is absent."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError()


def _decode(payload):
    return json.loads(payload.decode("utf-8-sig"), object_pairs_hook=_unique_object,
                      parse_constant=_reject_constant)


def _load_config(config_path):
    try:
        with Path(config_path).open("rb") as stream:
            payload = stream.read(MAX_CONFIG_BYTES + 1)
        if len(payload) > MAX_CONFIG_BYTES:
            raise ValueError()
        config = _decode(payload)
        if not isinstance(config, dict):
            raise ValueError()
        return config
    except FileNotFoundError:
        raise NotInstalled("Hysteria 2 is not configured.") from None
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise ConfigError("Cannot read or parse the Hysteria 2 configuration.") from None


def _load_labels(labels_path):
    try:
        with Path(labels_path).open("rb") as stream:
            payload = stream.read(MAX_LABEL_BYTES + 1)
        if len(payload) > MAX_LABEL_BYTES:
            raise ValueError()
        labels = _decode(payload)
        if not isinstance(labels, dict) or len(labels) > MAX_USERS:
            raise ValueError()
        return labels
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise ConfigError("Cannot read or parse the Hysteria 2 user labels.") from None


def configured_users(config, labels=None):
    auth = config.get("auth")
    if not isinstance(auth, dict) or auth.get("type") != "userpass":
        raise ConfigError("Hysteria 2 statistics require userpass authentication.")
    accounts = auth.get("userpass")
    if not isinstance(accounts, dict) or len(accounts) > MAX_USERS:
        raise ConfigError("Hysteria 2 user configuration is invalid.")
    # Passwords are dictionary VALUES, not fields named 'password'. Do not let
    # an accidentally copied password become a visible user label.
    secrets = _secrets(config)
    if any(not isinstance(password, str) or not password for password in accounts.values()):
        raise ConfigError("Hysteria 2 user configuration is invalid.")
    secrets.update(accounts.values())
    raw_users = []
    seen = set()
    for raw in accounts:
        if not isinstance(raw, str) or not raw or len(raw) > 512 or ":" in raw:
            raise ConfigError("Hysteria 2 user configuration is invalid.")
        # Exact v2.12.3 UserPassAuthenticator lowercases both configuration keys
        # and authenticated names before using that name as the counter ID.
        counter_label = raw.lower()
        if counter_label in seen:
            raise ConfigError("Hysteria 2 user labels are ambiguous.")
        seen.add(counter_label)
        raw_users.append(counter_label)
    labels = labels if labels is not None else {}
    if not isinstance(labels, dict):
        raise ConfigError("Hysteria 2 user label mapping is invalid.")
    aliases = {}
    for raw, alias in labels.items():
        if (not isinstance(raw, str) or raw.lower() not in seen
                or raw.lower() in aliases or not _safe_label(alias, secrets)):
            raise ConfigError("Hysteria 2 user label mapping is invalid.")
        aliases[raw.lower()] = alias
    visible = [aliases.get(raw, raw) for raw in raw_users]
    safe_visible = [label.casefold() for label in visible if _safe_label(label, secrets)]
    if len(safe_visible) != len(set(safe_visible)):
        raise ConfigError("Hysteria 2 user labels are ambiguous.")
    reserved = set(safe_visible)
    users = []
    alias_index = 0
    for raw in raw_users:
        label = aliases.get(raw, raw)
        if not _safe_label(label, secrets):
            while True:
                alias_index += 1
                label = "user-%02d" % alias_index
                if label.casefold() not in reserved:
                    reserved.add(label.casefold())
                    break
        users.append(User(label, raw, True))
    return sorted(users, key=lambda user: user.label.casefold())


def _api_secret(config):
    settings = config.get("trafficStats")
    if not isinstance(settings, dict) or settings.get("listen") != "%s:%d" % (API_HOST, API_PORT):
        raise ConfigError("Hysteria 2 statistics must use the dedicated loopback API.")
    secret = settings.get("secret")
    if (not isinstance(secret, str) or not 1 <= len(secret) <= 512
            or any(ord(char) < 33 or ord(char) > 126 for char in secret)):
        raise ConfigError("Hysteria 2 statistics API authentication is not configured safely.")
    return secret


def _request(path, secret):
    """Fixed loopback HTTP only: no URL input, proxy environment, or redirects."""
    if path not in ("/traffic", "/online"):
        raise APIError("Hysteria 2 statistics API request is invalid.")
    connection = None
    try:
        connection = http.client.HTTPConnection(API_HOST, API_PORT, timeout=API_TIMEOUT)
        connection.connect()
        if connection.sock.getpeername()[0] != API_HOST:
            raise ValueError()
        connection.request("GET", path, headers={"Authorization": secret, "Accept": "application/json"})
        response = connection.getresponse()
        # Do not follow redirects, especially not with an Authorization header.
        if response.status != 200:
            raise ValueError()
        length = response.getheader("Content-Length")
        if length is not None and (not length.isascii() or not length.isdigit()
                                   or int(length) > MAX_API_BYTES):
            raise ValueError()
        payload = response.read(MAX_API_BYTES + 1)
        if len(payload) > MAX_API_BYTES:
            raise ValueError()
        value = _decode(payload)
        if not isinstance(value, dict) or len(value) > MAX_API_USERS:
            raise ValueError()
        return value
    except (OSError, http.client.HTTPException, UnicodeError, ValueError, RecursionError):
        raise APIError("Hysteria 2 statistics API is unavailable or returned invalid data.") from None
    finally:
        if connection is not None:
            connection.close()


def collect_stats(user_filter=None, config_path=DEFAULT_CONFIG, labels_path=DEFAULT_LABELS, requester=None, excluded_users=()):
    """Return sanitized UserStats rows; failed traffic API is never a zero report."""
    config = _load_config(config_path)
    excluded = {name.casefold() for name in excluded_users}
    users = select_users([user for user in configured_users(config, _load_labels(labels_path))
                          if user.counter_label.casefold() not in excluded], user_filter)
    if not users:
        return []
    secret = _api_secret(config)
    request = requester or _request
    traffic = request("/traffic", secret)
    if not isinstance(traffic, dict) or len(traffic) > MAX_API_USERS:
        raise APIError("Hysteria 2 statistics API returned invalid counter data.")
    try:
        online = request("/online", secret)
        if not isinstance(online, dict) or len(online) > MAX_API_USERS:
            online = None
    except APIError:
        online = None
    rows = []
    for user in users:
        counters = traffic.get(user.counter_label, {})
        if not isinstance(counters, dict):
            counters = {}
        uplink, downlink = _counter(counters.get("tx")), _counter(counters.get("rx"))
        connections = _counter(online.get(user.counter_label, 0)) if online is not None else None
        rows.append(UserStats(user.label, uplink or 0, downlink or 0,
                              str(connections) if connections is not None else "n/a",
                              uplink is None or downlink is None))
    return rows


def format_summary(rows, compact=True):
    if not rows:
        return "No Hysteria 2 users are configured."
    lines = ["Hysteria 2 users (traffic since restart/API reset)"]
    if compact:
        for index, row in enumerate(rows):
            line = "%s | connections*: %s | up %s | down %s | total %s" % (
                row.label, row.online, human_bytes(row.uplink), human_bytes(row.downlink),
                human_bytes(row.uplink + row.downlink))
            if sum(len(item) + 1 for item in lines) + len(line) > 3000:
                lines.append("%d more users; use /stats <label>." % (len(rows) - index))
                break
            lines.append(line)
    else:
        width = max(4, max(len(row.label) for row in rows))
        template = "%%-%ds  %%-12s  %%10s  %%10s  %%10s" % width
        lines.append(template % ("User", "Connections*", "Uplink", "Downlink", "Total"))
        for row in rows:
            lines.append(template % (row.label, row.online, human_bytes(row.uplink),
                                     human_bytes(row.downlink), human_bytes(row.uplink + row.downlink)))
    lines.append("Connections*: active Hysteria client connections, not unique people or proxy streams; n/a = unavailable.")
    if any(row.missing_traffic for row in rows):
        lines.append("Missing traffic counters are shown as 0 (normal before first traffic).")
    return "\n".join(lines)


def render_summary(user_filter=None, compact=True, **kwargs):
    return format_summary(collect_stats(user_filter=user_filter, **kwargs), compact=compact)


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "Error: Use hysteria-user-stats [user-label or person].\n")


def main(argv=None):
    parser = _ArgumentParser(description="Read Hysteria 2 user traffic without resetting counters.")
    parser.add_argument("user", nargs="?")
    args = parser.parse_args(argv)
    try:
        print(render_summary(args.user, compact=False))
    except StatsError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 1
    except Exception:
        print("Error: Cannot read Hysteria 2 user statistics.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
