# Brume 2 Xray Telegram bot

An allowlisted Telegram bot for OpenWrt, with Streisand JSON export, per-user Xray statistics, and scheduled Telegram reports. This directory contains source code and synthetic examples only; it does not contain a router backup or usable connection credentials.

## Supported configuration

- Python 3.9 or newer, with `requests` for Telegram and public-IP lookups.
- A working Xray service at `/etc/init.d/xray`, executable at `/usr/bin/xray`, and JSON/JSONC configuration at `/etc/xray/config.json`.
- One VMess-over-TLS inbound on port `443` and optionally one VLESS+REALITY inbound on `9443`.
- For statistics, a loopback StatsService at `127.0.0.1:10085`. Xray `25.12.8` supports the traffic and recent-activity APIs used here.

The bot manages an existing Xray installation. It does not install Xray or create a missing REALITY inbound. Names such as `alice`, `bob`, and `carol` below are examples.

## Files and installation

| Source | Router destination |
| --- | --- |
| `src/xray_telegram_bot.py` | `/usr/bin/xray_telegram_bot.py` |
| `src/xray_user_stats.py` | `/usr/bin/xray_user_stats.py` |
| `src/xray_stats_report.py` | `/usr/bin/xray_stats_report.py` |
| `bin/xray-user-stats` | `/usr/bin/xray-user-stats` |
| `openwrt/etc/init.d/xray-telegram-bot` | `/etc/init.d/xray-telegram-bot` |

Install Python, `python3-requests`, and a CA certificate bundle using the packages supplied by your OpenWrt firmware. For local development, install `requirements.txt`.

Create `/etc/xray/telegram_bot.json` locally on the router using `examples/telegram_bot.example.json` as a template. Replace its sentinel values:

- `bot_token`: the BotFather token.
- `allowed_chat_ids`: a nonempty list of accepted Telegram chat IDs.
- `allowed_user_ids`: users accepted inside allowed chats. An empty list permits every user in an allowed chat; use explicit IDs for group chats.

Keep this populated configuration on the router. Then set permissions and check the installation:

```sh
chmod 600 /etc/xray/telegram_bot.json /etc/xray/config.json
chmod 700 /usr/bin/xray_telegram_bot.py /usr/bin/xray_user_stats.py
chmod 700 /usr/bin/xray_stats_report.py /usr/bin/xray-user-stats
chmod 755 /etc/init.d/xray-telegram-bot
python3 /usr/bin/xray_telegram_bot.py --self-test
/etc/init.d/xray-telegram-bot enable
/etc/init.d/xray-telegram-bot restart
```

The repository's legacy `scripts/` rotation helper is a separate workflow; it is not part of this installation.

## Commands

| Telegram command | Behavior |
| --- | --- |
| `/ip` | Show the router's public IP. |
| `/stats [label]` | Show traffic and recent activity for all users or a selected user. |
| `/streisand [label]` | Send selected client profiles as a JSON document. |
| `/rotate` then `/rotate confirm` | Rotate all managed UUIDs, including shared profiles, after confirmation. |
| `/restart` | Validate and restart Xray; report listener health. |
| `/target hostname` | Check and update the REALITY target/SNI when configured. |
| `/tlsping hostname` | Return a concise Xray TLS check. |
| `/status` | Show listener health and REALITY status. |
| `/help` | Show command help. |

Commands require the configured chat/user allowlists. Stale mutating updates are rejected. UUID rotation invalidates earlier client exports.

CLI examples:

```sh
xray-user-stats
xray-user-stats alice
```

Stats filters first match an exact label, then labels with the requested person's prefix, such as `alice-vmess` and `alice-vless`. The JSON exporter uses an exact configured label.

## Enabling statistics and individual users

Run the migration helper from a staged copy of this directory on the router. It defaults to a dry run:

```sh
python3 tools/install_user_stats.py
```

Optionally add separate credentials for example users while retaining existing UUIDs:

```sh
python3 tools/install_user_stats.py --add-users alice bob carol
sha256sum /etc/xray/config.json
python3 tools/install_user_stats.py --apply --add-users alice bob carol \
  --expected-config-sha256 REPLACE_WITH_INSPECTED_SHA256
```

The helper assigns safe unique labels, adds `level: 0` when absent, and enables upload/download/recent-activity statistics for level zero and other used levels. It preserves other policy settings, including `policy.system`. A single previously unlabeled credential becomes `shared`; each added user receives a new credential. People sharing one UUID remain one statistical identity until they switch to separate profiles.

An existing API configuration is retained and checked. When none exists, the helper adds a direct loopback-only StatsService listener, without changing routing. A conflicting or non-loopback API configuration needs inspection before proceeding. Never forward the API port externally.

Before applying, the helper validates the candidate with Xray and verifies that the live config still matches the inspected hash. It creates a verified backup, writes atomically, restarts Xray, and checks listeners and the StatsService API. Failure restores the original bytes and restarts the previous configuration. Repeating a completed migration does not rotate existing UUIDs or restart Xray unnecessarily.

## Statistics semantics

Counters are read without resetting them. Upload/download totals are cumulative since Xray restarted, not daily or weekly deltas.

- `recent`: request activity in approximately the last 20 seconds.
- `none`: the activity API is available, but reports no recent request.
- `n/a`: activity information is unavailable.
- Missing traffic counters appear as zero, which is normal before first use.

Recent activity is not an active-session count; long-lived streams can appear inactive. Statistics output omits UUIDs, keys, tokens, and source IPs. Missing or unsafe labels receive harmless display aliases; duplicate configured emails share an Xray counter. API failures are reported distinctly from zero traffic.

## Streisand JSON export

Exports are JSON arrays of complete Xray client profiles. Each configured client has its own entry. VMess profiles pin the installed leaf TLS certificate using `pinnedPeerCertSha256`; they do not enable `allowInsecure`. Regenerate those profiles after replacing the server certificate.

REALITY exports include its public client parameters when configured. Server private keys, server-only targets, certificate/key file paths, and bot tokens are excluded. Generated JSON nevertheless contains active client UUIDs and endpoint details: treat it as credential material and keep it out of Git.

## Weekly reports

`xray_stats_report.py` sends a snapshot to the existing chat allowlist. For a router using UTC, this cron example runs each Monday at 14:00 UTC:

```cron
0 14 * * 1 /usr/bin/python3 /usr/bin/xray_stats_report.py 2>&1 | logger -t xray-user-stats
```

Use the router's timezone when choosing the cron expression. The message states that counters are since the latest Xray restart, not a seven-day delta. Successful delivery is deduplicated per chat and UTC ISO week in `/etc/xray/telegram_stats_report_state.json`.

```sh
python3 /usr/bin/xray_stats_report.py --dry-run
python3 /usr/bin/xray_stats_report.py --force
```

`--dry-run` prints a sanitized preview without sending or writing state. `--force` bypasses deduplication. A network timeout after Telegram accepts a message can leave delivery uncertain, so exactly-once delivery is not guaranteed.

## Public repository hygiene

Keep live Xray/bot configs, client exports, SSH/TLS keys, certificates, router backups, polling/report state, and private deployment records outside this repository. The ignore files cover common filenames, but cannot protect files that are already tracked or secrets copied into arbitrary source files.

Fixtures contain conspicuous non-production UUIDs and a synthetic test key. Never deploy fixtures or example settings unchanged. Code reports operational failures without raw exception/configuration contents.

## Tests

From this directory:

```sh
python3 -m unittest discover -s tests -v
```

The suite covers export mapping and secret exclusion, API error handling, filtering, recent-activity semantics, migration invariants, backup/atomic apply, and rollback. Tests use synthetic values and temporary files; they do not query the router or Telegram. Before deployment, also run the on-router `--self-test` and validate exported profiles with the intended client core.
