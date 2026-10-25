#!/usr/bin/env python3
"""Independent Xray and Hysteria statistics; never combine restart epochs."""

import argparse
import sys

import hysteria_user_stats as hysteria
import xray_user_stats as xray
from vpn_features import FeatureError, load_vmess_enabled, parse_vmess_enabled
from xray_user_stats import StatsError, UserNotFound, human_bytes


MAX_COMPACT_CHARS = 7400


def _compact_section(name, rows):
    if not rows:
        return "%s: no users configured." % name
    is_hysteria = name == "Hysteria 2"
    activity = "connections*" if is_hysteria else "online*"
    footer = ("Connections*: active client connections, not unique people/proxy streams; n/a = unavailable."
              if is_hysteria else "Online*: recent request activity (~20s), not active sessions; n/a = unavailable.")
    lines = [name + " users"]
    if any(row.missing_traffic for row in rows):
        footer += "\nMissing traffic counters = 0 (normal before first traffic)."
    # Separate equal-sized budgets keep one busy backend from hiding the other.
    budget = 1500 - len(footer) - 80
    for index, row in enumerate(rows):
        line = "%s | %s: %s | up %s | down %s | total %s" % (
            row.label, activity, row.online, human_bytes(row.uplink), human_bytes(row.downlink),
            human_bytes(row.uplink + row.downlink))
        if sum(len(item) + 1 for item in lines) + len(line) > budget:
            lines.append("%d more users; use /stats <label>." % (len(rows) - index))
            break
        lines.append(line)
    lines.append(footer)
    return "\n".join(lines)


def render_summary(user_filter=None, compact=True, xray_collector=None, hysteria_collector=None,
                   vmess_enabled=None, excluded_hysteria_users=(), trend_now=None):
    """Return partial results on backend errors; only truly absent Hysteria is omitted.

    Exports StatsError for the existing Telegram caller. A failed backend is marked
    unavailable, never rendered as zero traffic, and never hides the healthy one.
    """
    try:
        enabled = (load_vmess_enabled() if vmess_enabled is None else
                   parse_vmess_enabled({"vmess_enabled": vmess_enabled}))
    except FeatureError:
        raise StatsError("Cannot read valid VPN feature settings.") from None
    sections = []
    matched = failed = False
    backends = []
    if enabled:
        backends.append(("Xray", xray_collector or xray.collect_stats, xray.format_summary))
    backends.append(("Hysteria 2", hysteria_collector or hysteria.collect_stats, hysteria.format_summary))
    for name, collector, formatter in backends:
        try:
            kwargs = {"user_filter": user_filter}
            if name == "Hysteria 2" and excluded_hysteria_users:
                kwargs["excluded_users"] = excluded_hysteria_users
            rows = collector(**kwargs)
            matched = matched or bool(rows)
            sections.append(_compact_section(name, rows) if compact else formatter(rows, compact=False))
        except hysteria.NotInstalled:
            if name != "Hysteria 2" or not enabled:
                sections.append("%s: statistics unavailable (configuration missing)." % name)
                failed = True
        except UserNotFound:
            continue
        except Exception:
            # Never echo even supposedly safe exception text from a backend. This
            # also protects the healthy backend from unexpected parsing failures.
            sections.append("%s: statistics unavailable (check service, configuration and local API)." % name)
            failed = True
    if user_filter is not None and not matched and not failed:
        raise UserNotFound("No matching user label. Use /stats to list available labels.")
    sections.append(
        "Traffic is since each service restart/API reset, not a weekly delta. Protocol totals are separate."
        if enabled else "Traffic is since the Hysteria service restart/API reset, not a weekly delta.")
    from vpn_usage_trends import current_trends, render_trends
    try:
        sections.append(render_trends(current_trends(now=trend_now, enabled=enabled,
            excluded_users=excluded_hysteria_users, label_filter=user_filter)))
    except Exception:
        sections.append('Тренд недоступен: не удалось прочитать историю. Текущие счётчики показаны выше.')
    result = "\n\n".join(sections)
    if compact and len(result) > MAX_COMPACT_CHARS:
        raise StatsError("Statistics summary is too large; filter by user label.")
    return result


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "Error: Use vpn-user-stats [user-label or person].\n")


def main(argv=None):
    parser = _ArgumentParser(description="Read Hysteria 2 stats and opt-in legacy Xray stats.")
    parser.add_argument("user", nargs="?")
    args = parser.parse_args(argv)
    try:
        print(render_summary(args.user, compact=False))
    except StatsError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 1
    except Exception:
        print("Error: Cannot read VPN user statistics.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
