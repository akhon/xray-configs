#!/usr/bin/env python3

import json
import uuid
import subprocess
import datetime
from pathlib import Path

# ================== SETTINGS ==================

XRAY_CONFIG = "/etc/xray/config.json"
STATE_FILE = "/etc/xray/uuid_state.json"
XRAY_SERVICE = "xray"

TELEGRAM_BOT_TOKEN = "PUT_YOUR_BOT_TOKEN_HERE"
TELEGRAM_CHAT_ID = "PUT_YOUR_CHANNEL_ID_HERE"

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
    # Assumption: UUIDs live here
    return cfg["inbounds"][0]["settings"]["clients"]

def add_uuid(cfg, new_uuid):
    get_clients(cfg).append({"id": new_uuid})

def remove_uuid(cfg, old_uuid):
    clients = get_clients(cfg)
    cfg["inbounds"][0]["settings"]["clients"] = [
        c for c in clients if c.get("id") != old_uuid
    ]

# ================== MAIN LOGIC ==================

def main():
    state = load_json(STATE_FILE, {
        "current_uuid": None,
        "pending_removals": [],   # list of {uuid, remove_at}
        "last_rotation": None
    })

    cfg = load_xray_config()
    clients = get_clients(cfg)
    current_uuids = [c["id"] for c in clients if "id" in c]
    current_set = set(current_uuids)

    now_ts = now()

    # Bootstrap: if state has no current_uuid, infer it from config
    # (use the last UUID in clients[] as "current")
    if not state["current_uuid"] and current_uuids:
        state["current_uuid"] = current_uuids[-1]
        save_json(STATE_FILE, state)

    # ---- Step 1: Scheduled rotation -> add new UUID, schedule old "current" for removal ----
    do_rotate = False
    if not state["last_rotation"]:
        do_rotate = True
    else:
        last = datetime.datetime.fromisoformat(state["last_rotation"])
        if (now_ts - last).days >= ROTATION_INTERVAL_DAYS:
            do_rotate = True

    if do_rotate:
        new_uuid = str(uuid.uuid4())
        add_uuid(cfg, new_uuid)

        created = now_ts
        remove_at = created + datetime.timedelta(days=GRACE_PERIOD_DAYS)

        old_uuid = state.get("current_uuid")
        # Schedule removal ONLY for the old current UUID
        if old_uuid and old_uuid != new_uuid:
            state["pending_removals"].append({
                "uuid": old_uuid,
                "remove_at": remove_at.isoformat()
            })

        state["current_uuid"] = new_uuid
        state["last_rotation"] = created.isoformat()

        save_xray_config(cfg)
        restart_xray()

        msg = (
            "🆕 *New UUID added*\n\n"
            f"`{new_uuid}`\n\n"
            f"📅 Created (UTC): {created.date()}\n"
        )
        if old_uuid:
            msg += f"⏳ Old UUID will be removed (UTC): {remove_at.date()}\n"
        telegram_send(msg)

    # ---- Step 2: Remove UUIDs that are explicitly scheduled for removal ----
    changed = False
    still_pending = []

    for entry in state["pending_removals"]:
        ra = datetime.datetime.fromisoformat(entry["remove_at"])
        u = entry["uuid"]

        if now_ts >= ra:
            # Never remove the current UUID, even if somehow scheduled
            if u == state.get("current_uuid"):
                still_pending.append(entry)
                continue

            if u in current_set:
                remove_uuid(cfg, u)
                changed = True
                telegram_send(
                    "🗑 *UUID removed*\n\n"
                    f"`{u}`\n"
                    f"📅 Removed (UTC): {now_ts.date()}"
                )
        else:
            still_pending.append(entry)

    if changed:
        save_xray_config(cfg)
        restart_xray()

    state["pending_removals"] = still_pending
    save_json(STATE_FILE, state)

if __name__ == "__main__":
    main()
