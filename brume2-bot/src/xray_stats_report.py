#!/usr/bin/env python3
"""Send a weekly Xray snapshot to the existing Telegram chat allowlist.

Schedule this command with cron. Counters are cumulative since Xray restarted,
not a delta for the preceding week. Confirmed deliveries are deduplicated per
chat and UTC ISO week. Telegram does not provide idempotency keys: a connection
failure after Telegram accepts a message can leave delivery uncertain.
"""

import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import sys


STATE_FILE = Path("/etc/xray/telegram_stats_report_state.json")
LOCK_FILE = Path("/var/lock/xray-stats-report.lock")
MAX_STATE_BYTES = 256 * 1024


class ReportError(Exception):
    pass


def report_time(now=None):
    current = now or datetime.datetime.now(datetime.timezone.utc)
    if current.tzinfo is None:
        raise ReportError("Report time must include a timezone")
    current = current.astimezone(datetime.timezone.utc)
    iso = current.isocalendar()
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


def report_text(stats, now):
    summary = stats.render_summary(None, compact=True)
    message = (
        "Weekly Xray statistics\n"
        "Snapshot: %s UTC\n"
        "Traffic totals are since the latest Xray restart, not a seven-day delta.\n\n%s"
        % (now.strftime("%Y-%m-%d %H:%M"), summary)
    )
    # One Telegram message avoids partial delivery of a multi-message report.
    if len(message) > 3800:
        prefix = message[:3650].rsplit("\n", 1)[0]
        message = prefix + "\nMore users omitted; use /stats <user> for an individual summary."
    return message


def send_weekly_report(dry_run=False, force=False, now=None):
    import xray_telegram_bot as bot
    import xray_user_stats as stats

    now, week = report_time(now)
    if dry_run:
        print(report_text(stats, now))
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
        chats = sorted(settings.allowed_chat_ids)
        pending = [chat for chat in chats
                   if force or week not in state["sent"].get(str(chat), {})]
        if not pending:
            print("Weekly report skipped: already delivered this UTC week.")
            return 0
        message = report_text(stats, now)
        telegram = bot.TelegramClient(settings.bot_token)
        failures = delivered = 0
        for chat in pending:
            try:
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
        self.exit(2, "Usage: xray_stats_report.py [--dry-run] [--force]\n")


def main(argv=None):
    parser = SafeArgumentParser(description="Send a weekly Xray statistics snapshot to Telegram.")
    parser.add_argument("--dry-run", action="store_true", help="print a report without Telegram or state writes")
    parser.add_argument("--force", action="store_true", help="send even if this UTC week was already delivered")
    args = parser.parse_args(argv)
    try:
        return send_weekly_report(dry_run=args.dry_run, force=args.force)
    except ReportError as exc:
        print("Error: %s." % exc, file=sys.stderr)
    except Exception:
        # Never print raw exceptions from settings, API responses, or Telegram.
        print("Error: Weekly Xray statistics report failed.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
