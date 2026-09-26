#!/usr/bin/env python3
"""Read-only, secret-safe Xray per-user statistics (Python standard library only)."""

import argparse
import concurrent.futures
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


DEFAULT_CONFIG = "/etc/xray/config.json"
DEFAULT_XRAY = "/usr/bin/xray"
DEFAULT_SERVER = "127.0.0.1:10085"
MAX_CONFIG_BYTES = 4 * 1024 * 1024
RECENT_SECONDS = 20
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
TOKEN_RE = re.compile(r"\d{6,12}:[A-Za-z0-9_-]{25,}")
KEY_RE = re.compile(r"[A-Za-z0-9_+/=-]{32,}")
LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@+-]{0,63}\Z")


class StatsError(Exception):
    """Safe to show to a CLI or Telegram user; never contains raw subprocess data."""


class ConfigError(StatsError):
    pass


class APIError(StatsError):
    pass


class UserNotFound(StatsError):
    pass


@dataclass(frozen=True)
class User:
    label: str
    counter_label: str
    online_enabled: bool


@dataclass(frozen=True)
class UserStats:
    label: str
    uplink: int
    downlink: int
    online: str
    missing_traffic: bool


def _jsonc(text):
    output = []
    index = 0
    quoted = escaped = line = block = False
    while index < len(text):
        char = text[index]
        following = text[index + 1:index + 2]
        if line:
            line = char not in "\r\n"
            output.append(" " if line else char)
        elif block:
            if char == "*" and following == "/":
                output.extend("  ")
                index += 1
                block = False
            else:
                output.append(char if char in "\r\n" else " ")
        elif quoted:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
            output.append(char)
        elif char == "#" or (char == "/" and following == "/"):
            line = True
            output.append(" ")
        elif char == "/" and following == "*":
            block = True
            output.extend("  ")
            index += 1
        else:
            output.append(char)
        index += 1
    if quoted or block:
        raise ConfigError("Cannot parse the Xray configuration.")
    return "".join(output)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError("Xray configuration contains duplicate keys.")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ConfigError("Xray configuration contains an invalid number.")


def _load_config(config_path):
    try:
        with Path(config_path).open("rb") as stream:
            payload = stream.read(MAX_CONFIG_BYTES + 1)
        if len(payload) > MAX_CONFIG_BYTES:
            raise ConfigError("Xray configuration is too large.")
        config = json.loads(_jsonc(payload.decode("utf-8-sig")),
                            object_pairs_hook=_unique_object,
                            parse_constant=_reject_constant)
        if not isinstance(config, dict):
            raise ConfigError("Xray configuration must be an object.")
        return config
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise ConfigError("Cannot read or parse the Xray configuration.") from None


def _secrets(config):
    values = set()
    secret_fields = {"id", "uuid", "privatekey", "password", "token", "bot_token", "secret"}
    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if str(key).lower() in secret_fields and isinstance(item, str) and item:
                    values.add(item)
                else:
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
    visit(config)
    return values


def _safe_label(label, secrets):
    return (isinstance(label, str) and LABEL_RE.fullmatch(label) is not None
            and not UUID_RE.search(label) and not TOKEN_RE.search(label)
            and not KEY_RE.search(label)
            and not any(secret.casefold() in label.casefold() for secret in secrets))


def configured_users(config):
    """Return current VMess/VLESS users; unsafe/missing labels get harmless aliases."""
    secrets = _secrets(config)
    policy = config.get("policy", {})
    levels = policy.get("levels", {}) if isinstance(policy, dict) else {}
    if not isinstance(levels, dict):
        levels = {}
    pending = {}
    unlabelled_count = 0
    inbounds = config.get("inbounds", [])
    if not isinstance(inbounds, list):
        raise ConfigError("Xray inbound configuration is invalid.")
    for inbound in inbounds:
        if not isinstance(inbound, dict) or inbound.get("protocol") not in ("vmess", "vless"):
            continue
        settings = inbound.get("settings", {})
        if not isinstance(settings, dict):
            raise ConfigError("Xray client configuration is invalid.")
        if settings.get("clients") is not None and settings.get("users") is not None:
            raise ConfigError("Xray client configuration is ambiguous.")
        clients = settings.get("clients")
        if clients is None:
            clients = settings.get("users", [])
        if not isinstance(clients, list):
            raise ConfigError("Xray client configuration is invalid.")
        for client in clients:
            if not isinstance(client, dict):
                raise ConfigError("Xray client configuration is invalid.")
            raw = client.get("email")
            # Empty/missing labels have no usable per-user API counter.
            if not isinstance(raw, str) or not raw:
                unlabelled_count += 1
                raw = ""
                key = ("unlabelled", unlabelled_count)
            else:
                key = ("label", raw)
            level = levels.get(str(client.get("level", 0)), {})
            enabled = isinstance(level, dict) and level.get("statsUserOnline") is True
            previous = pending.get(key)
            pending[key] = (raw, enabled or (previous[1] if previous else False))
    reserved = {raw.casefold() for raw, _ in pending.values() if _safe_label(raw, secrets)}
    users = []
    alias_index = 0
    for raw, online_enabled in pending.values():
        label = raw
        if not _safe_label(raw, secrets):
            while True:
                alias_index += 1
                label = "user-%02d" % alias_index
                if label.casefold() not in reserved:
                    reserved.add(label.casefold())
                    break
        users.append(User(label, raw, online_enabled))
    return sorted(users, key=lambda user: user.label.casefold())


def select_users(users, user_filter=None):
    """Match a visible label, then a case-insensitive '<person>-' prefix."""
    if user_filter is None:
        return list(users)
    if not isinstance(user_filter, str) or not LABEL_RE.fullmatch(user_filter):
        raise UserNotFound("No matching user label. Use /stats to list available labels.")
    needle = user_filter.casefold()
    exact = [user for user in users if user.label.casefold() == needle]
    selected = exact or [user for user in users if user.label.casefold().startswith(needle + "-")]
    if not selected:
        raise UserNotFound("No matching user label. Use /stats to list available labels.")
    return selected


def _run(argv):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, timeout=5, check=False)


def _query(runner, argv, mandatory):
    try:
        result = runner(argv)
        if result.returncode != 0:
            raise ValueError()
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError, RecursionError):
        if mandatory:
            raise APIError("Xray statistics API is unavailable or returned invalid data.") from None
        return None


def _counter(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= 2**64 - 1 else None
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,20}", value):
        converted = int(value)
        return converted if converted <= 2**64 - 1 else None
    return None


def collect_stats(user_filter=None, config_path=DEFAULT_CONFIG, xray_bin=DEFAULT_XRAY,
                  server=DEFAULT_SERVER, runner=None):
    """Read counters without resetting them; return UserStats objects, never secrets."""
    users = select_users(configured_users(_load_config(config_path)), user_filter)
    if not users:
        return []
    runner = runner or _run
    traffic = _query(runner, [xray_bin, "api", "statsquery", "--server=" + server,
                             "-pattern", "user>>>", "-timeout", "3"], True)
    stats = traffic.get("stat", [])
    if not isinstance(stats, list):
        raise APIError("Xray statistics API returned invalid counter data.")
    counters = {}
    for stat in stats:
        if isinstance(stat, dict) and isinstance(stat.get("name"), str):
            count = _counter(stat.get("value", 0))
            if count is not None:
                counters[stat["name"]] = count

    def online_activity(user):
        if not user.online_enabled or not user.counter_label:
            return "n/a"
        response = _query(runner, [xray_bin, "api", "statsonlineiplist", "--server=" + server,
                                  "-email", user.counter_label, "-timeout", "3"], False)
        if response is None or response.get("name") != "user>>>%s>>>online" % user.counter_label:
            return "n/a"
        ips = response.get("ips", {})
        if not isinstance(ips, dict):
            return "n/a"
        timestamps = [_counter(value) for value in ips.values()]
        if any(value is None for value in timestamps):
            return "n/a"
        now = time.time()
        if any(now - RECENT_SECONDS <= value <= now + 5 for value in timestamps):
            return "recent"
        return "none"

    # At most four short local API calls run concurrently; source IPs are discarded.
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(users))) as pool:
        online = list(pool.map(online_activity, users))
    results = []
    for user, activity in zip(users, online):
        up_key = "user>>>%s>>>traffic>>>uplink" % user.counter_label
        down_key = "user>>>%s>>>traffic>>>downlink" % user.counter_label
        results.append(UserStats(user.label, counters.get(up_key, 0), counters.get(down_key, 0),
                                 activity, up_key not in counters or down_key not in counters))
    return results


def human_bytes(value):
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB")
    count = float(value)
    for unit in units:
        if count < 1024 or unit == units[-1]:
            return ("%d B" % value) if unit == "B" else ("%.1f %s" % (count, unit))
        count /= 1024


def format_summary(rows, compact=True):
    """Format sanitized UserStats rows; compact output stays below Telegram's limit."""
    if not rows:
        return "No VMess/VLESS users are configured."
    if compact:
        lines = ["Xray users (traffic since restart)"]
        for index, row in enumerate(rows):
            line = "%s | online*: %s | up %s | down %s | total %s" % (
                row.label, row.online, human_bytes(row.uplink), human_bytes(row.downlink),
                human_bytes(row.uplink + row.downlink))
            if sum(len(item) + 1 for item in lines) + len(line) > 3100:
                lines.append("%d more users; use /stats <label> or /stats <person>." % (len(rows) - index))
                break
            lines.append(line)
    else:
        width = max(4, max(len(row.label) for row in rows))
        template = "%%-%ds  %%-7s  %%10s  %%10s  %%10s" % width
        lines = ["Xray users (traffic since restart)",
                 template % ("User", "Online*", "Uplink", "Downlink", "Total")]
        for row in rows:
            lines.append(template % (row.label, row.online, human_bytes(row.uplink),
                                     human_bytes(row.downlink), human_bytes(row.uplink + row.downlink)))
    lines.append("Online*: recent request activity (~20s), not active sessions; n/a = unavailable.")
    if any(row.missing_traffic for row in rows):
        lines.append("Missing traffic counters are shown as 0 (normal before first traffic).")
    return "\n".join(lines)


def render_summary(user_filter=None, compact=True, **kwargs):
    """Telegram entry point. Raises only safe StatsError subclasses on normal failures."""
    return format_summary(collect_stats(user_filter=user_filter, **kwargs), compact=compact)


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "Error: Use xray-user-stats [user-label or person].\n")


def main(argv=None):
    parser = _ArgumentParser(description="Read Xray user traffic and recent activity without resetting counters.")
    parser.add_argument("user", nargs="?", help="exact label or person prefix (for example alice)")
    args = parser.parse_args(argv)
    try:
        print(render_summary(args.user, compact=False))
    except StatsError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 1
    except Exception:
        # Do not leak unexpected exception details from configuration/API responses.
        print("Error: Cannot read Xray user statistics.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
