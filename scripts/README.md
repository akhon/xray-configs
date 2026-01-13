# Xcore UUID Rotation Script (OpenWrt)

This repository contains Xcore/Xray configuration files and a **UUID rotation helper script** designed for OpenWrt-based systems.

The script automates secure UUID rotation for VLESS/Xcore setups, with Telegram notifications and zero credentials stored in the repository.

---

## What the Script Does

- Generates a **new UUID every N days** (default: 30)
- Adds the new UUID to the Xcore/Xray config
- Restarts the Xcore/Xray service
- Keeps **old and new UUIDs active in parallel** for a grace period (default: 14 days)
- Removes the old UUID after the grace period
- Restarts the service again
- Sends **Telegram notifications** for:
  - UUID creation
  - UUID removal
- Persists state locally so reboots are safe

---

## Intended Environment

- OpenWrt
- Xcore or Xray (VLESS)
- JSON-based config (`clients[].id`)
- Cron available

The script is intentionally lightweight and compatible with:
- `python3-light`
- `curl` (for Telegram)

---

## Files

```text
scripts/
  xcore_uuid_rotate.py   # rotation script (no credentials)
/etc/xray/config.json   # actual runtime config
/etc/xcore/uuid_state.json  # generated runtime state (not in git)
```

---

## Installing Dependencies (OpenWrt)

```sh
opkg update
opkg install python3-light python3-requests
```

Verify:

```sh
python3 - <<'EOF'
import uuid
print(uuid.uuid4())
EOF
```

---

## Configuration

Before running, edit the script and set:

```python
XRAY_CONFIG = "/etc/xray/config.json"
XRAY_SERVICE = "xray"

TELEGRAM_BOT_TOKEN = "PUT_YOUR_TOKEN_HERE"
TELEGRAM_CHAT_ID = "PUT_CHAT_OR_CHANNEL_ID_HERE"

ROTATION_INTERVAL_DAYS = 30
GRACE_PERIOD_DAYS = 14
```

---

## How to Create a Telegram Bot (Bot Token)

1. Open Telegram and start a chat with **@BotFather**
2. Run:
   ```
   /start
   ```
3. Create a new bot:
   ```
   /newbot
   ```
4. Choose:
   - Display name (any)
   - Username (must end with `bot`)

BotFather will return a **Bot Token**:

```text
123456789:AAExxxxxxxxxxxxxxxxxxxxx
```

Keep it secret.

---

## How to Get Chat ID (Private Chat)

### Option A — via Telegram API

1. Send any message to your bot
2. Open in browser:

```
https://api.telegram.org/bot<BOT_TOKEN>/getUpdates
```

3. Find:

```json
"chat": {
  "id": 123456789,
  "type": "private"
}
```

Use the `id` value.

### Option B — via @userinfobot

- Open **@userinfobot**
- It will reply with your numeric ID

---

## How to Get Channel ID

1. Create a Telegram channel
2. Add your bot to the channel
3. Grant the bot **Administrator** permissions (Post Messages is enough)
4. Post any message to the channel
5. Open:

```
https://api.telegram.org/bot<BOT_TOKEN>/getUpdates
```

You will see:

```json
"chat": {
  "id": -1001234567890,
  "type": "channel"
}
```

Use the **negative ID** (`-100...`).

---

## Running the Script

Manual run:

```sh
python3 /usr/bin/xcore_uuid_rotate.py
```

---

## Cron Setup (Recommended)

Run once per day — the script decides if action is needed.

```sh
crontab -e
```

```cron
15 3 * * * /usr/bin/xcore_uuid_rotate.py
```

---

## UUID Rotation Timeline

| Day | Action |
|----|------|
| 0 | New UUID added |
| 0–14 | Old + new UUIDs valid |
| 14 | Old UUID removed |
| 30 | Next rotation |

---

## Security Notes

- No credentials are stored in git
- State file is local-only
- Telegram messages contain UUIDs — treat channel/chat as sensitive
- Consider restricting the bot to your chat ID

---

## Customization Ideas

- Multiple inbounds support
- Per-client UUID mapping
- Dry-run mode
- VPS-based external rotation
- Reality / SNI metadata in notifications

---

## License

MIT (or repository default)

---

## Disclaimer

This script modifies live Xcore/Xray configuration files.
Test carefully before production use.
