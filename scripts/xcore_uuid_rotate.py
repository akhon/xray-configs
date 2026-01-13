#!/usr/bin/env python3

import json
import uuid
import subprocess
import datetime
from pathlib import Path

# NOTE: This version keeps the exact same logic as the original:
# - Every ROTATION_INTERVAL_DAYS: generate + add a new UUID, restart service, notify Telegram
# - Every run: remove UUIDs older than GRACE_PERIOD_DAYS, restart service if changed, notify Telegram
# - State is stored locally in STATE_FILE so reboots are safe

# ================== SETTINGS ==================

XRAY_CONFIG = "/etc/xray/config.json"
STATE_FILE = "/etc/xcore/uuid_state.json"
XRAY_SERVICE = "xray"

TELEGRAM_BOT_TOKEN = "BOT:TOKEN"
TELEGRAM_CHAT_ID = "CHAT_OR_CHANNEL_ID"

ROTATION_INTERVAL_DAYS = 30
GRACE_PERIOD_DAYS = 14

# ================== HELPERS ==================

def now():
    # UTC timestamp (stable across timezones)
    return datetime.datetime.utcnow()

def load_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return default

def save_json(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def restart_xray():
    # OpenWrt init script restart
    subprocess.run(["/etc/init.d/" + XRAY_SERVICE, "restart"], check=False)

def telegram_send(text):
    """
    Sends a Telegram message using curl.
    This avoids requiring python3-requests on OpenWrt.
    """
    # Use --data-urlencode to preserve newlines and special characters
    subprocess.run(
        [
            "curl", "-s",
            "-X", "POST",
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            "-d", f"chat_id={TELEGRAM_CHAT_ID}",
            "--data-urlencode", f"text={text}",
            "-d", "parse_mode=Markdown",
        ],
        check=False
    )

# ================== XRAY CONFIG ==================

def load_xray_config():
    with open(XRAY_CONFIG, "r") as f:
        return json.load(f)

def save_xray_config(cfg):
    with open(XRAY_CONFIG, "w") as f:
        json.dump(cfg, f, indent=2)

def get_clients(cfg):
    # Keep original assumption: clients live here
    return cfg["inbounds"][0]["settings"]["clients"]

def add_uuid(cfg, new_uuid):
    # Append a new client record
    get_clients(cfg).append({"id": new_uuid})

def remove_uuid(cfg, old_uuid):
    # Filter out the UUID
    clients = get_clients(cfg)
    cfg["inbounds"][0]["settings"]["clients"] = [
        c for c in clients if c.get("id") != old_uuid
    ]

# ================== MAIN LOGIC ==================

def main():
    state = load_json(STATE_FILE, {
        "active": [],          # list of {uuid, created, expires}
        "last_rotation": None  # ISO timestamp
    })

    cfg = load_xray_config()
    clients = get_clients(cfg)
    current_uuids = {c["id"] for c in clients if "id" in c}

    now_ts = now()

    # ---- Step 1: Add a new UUID on schedule ----
    if (not state["last_rotation"]) or \
       ((now_ts - datetime.datetime.fromisoformat(state["last_rotation"])).days >= ROTATION_INTERVAL_DAYS):

        new_uuid = str(uuid.uuid4())
        add_uuid(cfg, new_uuid)

        created = now_ts
        expires = created + datetime.timedelta(days=GRACE_PERIOD_DAYS)

        state["active"].append({
            "uuid": new_uuid,
            "created": created.isoformat(),
            "expires": expires.isoformat()
        })
        state["last_rotation"] = created.isoformat()

        save_xray_config(cfg)
        restart_xray()

        telegram_send(
            "🆕 *New UUID added*\n\n"
            f"`{new_uuid}`\n\n"
            f"📅 Created (UTC): {created.date()}\n"
            f"⏳ Old UUID removal date (UTC): {expires.date()}"
        )

    # ---- Step 2: Remove expired UUIDs (grace period passed) ----
    changed = False
    still_active = []

    for entry in state["active"]:
        exp = datetime.datetime.fromisoformat(entry["expires"])

        if now_ts >= exp:
            old_uuid = entry["uuid"]
            if old_uuid in current_uuids:
                remove_uuid(cfg, old_uuid)
                changed = True

                telegram_send(
                    "🗑 *UUID removed*\n\n"
                    f"`{old_uuid}`\n"
                    f"📅 Removed (UTC): {now_ts.date()}"
                )
        else:
            still_active.append(entry)

    if changed:
        save_xray_config(cfg)
        restart_xray()

    state["active"] = still_active
    save_json(STATE_FILE, state)

if __name__ == "__main__":
    main()
