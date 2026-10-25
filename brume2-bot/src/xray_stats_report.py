#!/usr/bin/env python3
"""Send usage for the completed Monday-14:00 UTC week to the existing allowlist.

Persistent samples are collected separately every minute. Delivery deduplication
remains per chat and scheduled UTC week. Dry runs never send or write state.
"""

import argparse
import datetime
import fcntl
import json
import os
import re
from pathlib import Path
import sys


STATE_FILE = Path("/etc/xray/telegram_stats_report_state.json")
LOCK_FILE = Path("/var/lock/xray-stats-report.lock")
MAX_STATE_BYTES = 256 * 1024
PRIVATE_CONFIG_FILE = Path("/etc/xray/telegram_stats_private.json")


class ReportError(Exception):
    pass


def report_time(now=None):
    current = now or datetime.datetime.now(datetime.timezone.utc)
    if current.tzinfo is None:
        raise ReportError("Report time must include a timezone")
    current = current.astimezone(datetime.timezone.utc)
    from vpn_usage_history import period
    _start, end = period(current)
    iso = end.isocalendar()
    return current, "%04d-W%02d" % (iso[0], iso[1])


def read_state():
    try:
        descriptor = os.open(str(STATE_FILE), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return {"version": 1, "sent": {}}
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            payload = handle.read(MAX_STATE_BYTES + 1)
        if len(payload) > MAX_STATE_BYTES:
            raise ValueError()
        state = json.loads(payload.decode("utf-8"))
        if not isinstance(state, dict) or state.get("version") != 1:
            raise ValueError()
        sent = state.get("sent")
        if not isinstance(sent, dict):
            raise ValueError()
        for chat, weeks in sent.items():
            if not isinstance(chat, str) or str(int(chat)) != chat or not isinstance(weeks, dict):
                raise ValueError()
            for week, timestamp in weeks.items():
                if (not isinstance(week, str) or len(week) != 8
                        or not week[:4].isdigit() or week[4:6] != "-W"
                        or not week[6:].isdigit() or not 1 <= int(week[6:]) <= 53
                        or not isinstance(timestamp, str)):
                    raise ValueError()
        return state
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        raise ReportError("Cannot read the delivery state; no report was sent") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def load_private_route(settings):
    try:
        payload = PRIVATE_CONFIG_FILE.read_bytes()
    except FileNotFoundError:
        return None
    try:
        if len(payload) > 4096:
            raise ValueError()
        route = json.loads(payload)
        if (not isinstance(route, dict) or route.get("version") != 1
                or type(route.get("chat_id")) is not int or route["chat_id"] <= 0
                or route["chat_id"] not in settings.allowed_user_ids
                or route["chat_id"] != settings.private_owner_id
                or not isinstance(route.get("username"), str)
                or not re.fullmatch(r"[A-Za-z0-9_]{5,32}", route["username"])):
            raise ValueError()
        return route
    except (ValueError, TypeError, KeyError):
        raise ReportError("Invalid private statistics recipient; no reports sent") from None


def verify_private_recipient(telegram, route):
    chat = telegram.request("getChat", data={"chat_id": str(route["chat_id"])})
    if (not isinstance(chat, dict) or chat.get("id") != route["chat_id"]
            or chat.get("type") != "private"
            or str(chat.get("username", "")).casefold() != route["username"].casefold()):
        raise ReportError("Private statistics recipient verification failed")


def report_text(stats, now, private=False, settings=None):
    import xray_telegram_bot as bot
    settings = settings or bot.load_settings()
    private_users = settings.private_hysteria_users
    if private:
        if not private_users:
            raise ReportError("Private statistics users are not configured")
        return stats.render_report(now, enabled=False, included_users=private_users)
    return stats.render_report(now, excluded_users=private_users)


def send_weekly_report(dry_run=False, force=False, now=None, private_only=False):
    import xray_telegram_bot as bot
    import vpn_usage_history as stats

    now, week = report_time(now)
    if dry_run:
        print(report_text(stats, now, private=private_only))
        return 0

    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        str(LOCK_FILE), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("Weekly report skipped: another report process is running.")
            return 0
        settings = bot.load_settings()
        state = read_state()
        route = load_private_route(settings)
        chats = {chat: False for chat in settings.allowed_chat_ids} if not private_only else {}
        if route:
            # A private recipient gets only the private report, even if later allowlisted.
            chats[route["chat_id"]] = True
        elif private_only:
            raise ReportError("Private statistics recipient is not configured")
        pending = [(chat, private) for chat, private in sorted(chats.items())
                   if force or week not in state["sent"].get(str(chat), {})]
        if not pending:
            print("Weekly report skipped: already delivered this UTC week.")
            return 0
        if not stats.sample_once():
            print("Weekly report: current usage sample is incomplete.")
        telegram = bot.TelegramClient(settings.bot_token)
        failures = delivered = 0
        for chat, private in pending:
            try:
                if private:
                    verify_private_recipient(telegram, route)
                message = report_text(stats, now, private=private, settings=settings)
                telegram.send_message(chat, message)
            except Exception:
                failures += 1
                continue
            weeks = state["sent"].setdefault(str(chat), {})
            weeks[week] = now.isoformat(timespec="seconds")
            # Keep enough history to tolerate clock adjustments without unbounded growth.
            state["sent"][str(chat)] = {
                key: weeks[key] for key in sorted(weeks, reverse=True)[:104]
            }
            try:
                bot.atomic_write_json(STATE_FILE, state, 0o600)
            except Exception:
                raise ReportError(
                    "Report sent but delivery state could not be saved; check before retrying"
                ) from None
            delivered += 1
        print("Weekly report: %d delivered; %d failed." % (delivered, failures))
        return 1 if failures else 0
    finally:
        os.close(descriptor)


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "Usage: xray_stats_report.py [--dry-run] [--force] [--private]\n")


def main(argv=None):
    parser = SafeArgumentParser(description="Send completed-week VPN usage to Telegram.")
    parser.add_argument("--dry-run", action="store_true", help="print a report without Telegram or state writes")
    parser.add_argument("--force", action="store_true", help="send even if this UTC week was already delivered")
    parser.add_argument("--private", action="store_true", help="only the private-account report")
    args = parser.parse_args(argv)
    try:
        return send_weekly_report(dry_run=args.dry_run, force=args.force, private_only=args.private)
    except ReportError as exc:
        print("Error: %s." % exc, file=sys.stderr)
    except Exception:
        # Never print raw exceptions from settings, API responses, or Telegram.
        print("Error: Weekly VPN statistics report failed.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
