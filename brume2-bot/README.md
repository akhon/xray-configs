# Brume 2 VPN Telegram bot

An OpenWrt bot for an existing Hysteria 2 server, with optional legacy Xray support. It provides local QR generation, certificate-verified client exports, weekly traffic accounting with a Mac archive and RAM-only router cache, usage trends, a local dashboard, and private owner commands. This package contains source and synthetic configuration examples; it is not a router backup.

## Runtime and installation

The deployed target uses Python 3.9 and Hysteria 2.12.3. The Python suite is also checked on 3.14. Install Python, `requests`, and a CA bundle using your firmware packages. `requirements.txt` describes the Python dependencies; QR generation uses Segno 1.6.6 locally and never calls a QR website. On the deployed router Segno is vendored at `/usr/lib/vpn-qr`; installing the same version in Python's normal import path also works.

| Source | Router destination |
| --- | --- |
| All `src/*.py` | `/usr/bin/` |
| `bin/*-user-stats` | `/usr/bin/` |
| `openwrt/etc/init.d/xray-telegram-bot` | `/etc/init.d/xray-telegram-bot` |
| `openwrt/etc/init.d/hysteria2` | `/etc/init.d/hysteria2` (when setting up Hysteria) |

Inspect the running installation first. Back up the affected scripts, configuration, crontab and delivery state; use SQLite's backup API for an active history database. Stage and test new files before atomically replacing them. Stop the bot during a coordinated code/settings upgrade, run its self-test, then start it; restore the original files and menus if validation fails. A bot-only change does not require restarting Hysteria.

```sh
chmod 700 /usr/bin/xray_telegram_bot.py /usr/bin/xray_stats_report.py
chmod 700 /usr/bin/hysteria_profiles.py /usr/bin/hysteria_user_stats.py
chmod 700 /usr/bin/vpn_features.py /usr/bin/vpn_qr.py /usr/bin/vpn_usage_history.py
chmod 700 /usr/bin/vpn_usage_trends.py /usr/bin/vpn_history_export.py /usr/bin/vpn_history_transfer.py
chmod 700 /usr/bin/vpn_user_stats.py /usr/bin/xray_user_stats.py /usr/bin/*-user-stats
chmod 600 /etc/xray/telegram_bot.json /etc/xray/telegram_stats_private.json
chmod 600 /etc/hysteria2/config.json
python3 /usr/bin/xray_telegram_bot.py --self-test
/etc/init.d/xray-telegram-bot enable
/etc/init.d/xray-telegram-bot restart
```

Only chmod a private-route file if you configured it. Do not replace an existing VPN server configuration with the example or deploy example credentials. Merge the two entries in `examples/cron.example` into the existing crontab, keeping any unrelated entries. Those times require the router's cron timezone to be UTC.

## Configuration and access control

Create `/etc/xray/telegram_bot.json` from `examples/telegram_bot.example.json`. The zero IDs and token sentinel intentionally fail validation. Populate these fields on the router:

- `bot_token`: BotFather token, never committed to Git.
- `allowed_chat_ids`: nonempty list of **negative group/supergroup IDs**. Private IDs do not belong here.
- `allowed_user_ids`: nonempty list of positive sender IDs accepted in those groups. An empty list is rejected; anonymous administrators, channel senders and bot senders cannot issue commands.
- `private_owner_id`: one positive owner ID, also present in `allowed_user_ids`. Omit or set to `null` to disable private commands. Group membership never grants private access.
- `private_hysteria_users`: Hysteria account IDs, independent of display aliases. These accounts are excluded from every Telegram credential export and all group statistics; their traffic goes only to the owner. Configure a nonempty list before enabling private access.
- `vmess_enabled`: JSON boolean, default `false`. Legacy VMess/Xray commands are explicitly opt-in.

Private commands require `chat.type == private` and both chat ID and sender ID to equal `private_owner_id`. Group commands require an allowlisted group **and** an allowlisted human sender. Missing or malformed identities fail closed. Rejected messages receive no reply. Other people can still open the bot's Telegram page or send messages, but the bot does not process those messages.

Use numerical IDs for authorization. A Telegram username can change and is not an authorization credential. Command menus are registered only for configured groups and the owner; the handler still checks every incoming message. Clear any obsolete broad or per-chat menus when migrating an existing installation. Menu visibility is not access control.

## Hysteria server configuration

`examples/hysteria2-server.example.json` shows the deployed server structure with replacement passwords. Install it only after filling the parameters and reviewing your existing server. The traffic API must remain `127.0.0.1:18081` with a nonempty secret; never forward that port. The ACL blocks private, loopback, multicast and reserved destinations. Replace the documentation address `203.0.113.10/32` with the server's actual public address to block proxying back to the server itself; review your own additional reserved/management ranges.

The profile exporter currently targets an IP endpoint. By default, the installed public certificate must be valid and have that IP in its SAN. If the public IP changes, set `tls_server_name` in `/etc/hysteria2/client-meta.json` to the existing certificate's IP SAN (see `examples/hysteria2-client-meta.example.json`). Exports then use the current public IP for the connection and the configured IP for TLS verification, preserving the certificate and pin. Invalid or mismatched TLS identities still fail closed. The stored `endpoint`, if present, is informational; bot exports discover the public address independently. Keep the TLS private key on the server. Optional display aliases live in `/etc/hysteria2/user-labels.json`, using `examples/hysteria2-user-labels.example.json` as a template. Private-account filtering always uses raw account IDs, so changing an alias cannot expose credentials.

Adding accounts remains an administrator operation outside Telegram. Preserve existing accounts, validate a staged server configuration, back up, and sample counters immediately before and after any required restart. The bot has no account-creation command.

## Commands

| Command | Owner's private chat | Existing authorized group |
| --- | --- | --- |
| `/stats` | Current reporting-week traffic and trends for the configured private accounts | Shared accounts' counters since service restart/API reset, plus weekly trends |
| `/stats account` | One of the configured private accounts | Existing shared-account filter |
| `/ip` | Current public IP | Same |
| `/status` | Hysteria service and local stats API health | Same |
| `/hysteria [label]` | Pinned Xray-format Hysteria client JSON | Same |
| `/hylinks [label]` | Hysteria share links | Same |
| `/qr label` | Existing shared account's URI QR | Same |
| `/start`, `/help` | Help with private statistics semantics | Shared command help |

The credential-export commands exclude `private_hysteria_users` even in the owner's chat and in bulk exports. Private users' profiles must be delivered separately through an authorized private channel outside Telegram.

QRs contain standard `hysteria2://` links with a profile name and the `pinSHA256`/`pcs` certificate-pin parameters. The client must preserve the pin. Native Hysteria additionally needs the trusted server CA certificate; keep TLS verification enabled. Pinned Xray-format JSON remains available via `/hysteria`. Import behavior depends on the client and version.

CLI `hysteria-user-stats`, `vpn-user-stats`, and `xray-user-stats` remain administrator tools and show since-restart counters. Hysteria connections count authenticated client connections, not unique people or proxy streams. Xray recent activity is approximately a 20-second indicator, not a session count.

## Current-week and weekly history

`vpn_usage_history.py` stores one-minute readings only in `/tmp/vpn-usage/history.sqlite3`, mode 0600, retained for 21 days. On the target OpenWrt system `/tmp` is tmpfs (RAM); verify the mount before deployment. The Mac holds the durable archive. Routine collection and cache restoration do not write traffic history to router flash. Configuration and the small weekly delivery-deduplication state remain persistent. It never clears the service counters. A first observation is a baseline, not usage. Process epochs and decreasing counters detect resets; only observed deltas and post-reset bytes are counted. The pre-reset tail is unknown and is explicitly marked incomplete. A reset entirely between two samples may be undetectable.

The reporting week is **Monday 14:00 UTC through the next Monday 14:00 UTC**, end exclusive. This preserves the existing report schedule; it is not a midnight-based calendar week. The private `/stats` command takes a fresh sample and reports from the current reporting-week start to the request time. It labels partial history, exact dates, sampling gaps, additions/removals and unavailable counters. A failed fresh read can still return the recorded history with an incomplete warning. Allocation across a boundary between samples is estimated and disclosed.

Weekly reports cover the **completed** reporting week. They send shared accounts only to `allowed_chat_ids`. To send private accounts to the owner, create `/etc/xray/telegram_stats_private.json` using its example:

- `chat_id` must equal `private_owner_id` and be an explicitly allowed sender.
- `username` is the owner's current Telegram username without `@`.
- The sender verifies the returned private chat ID, type and username before each weekly private delivery. A mismatch prevents that private delivery.
- The owner must press **Start** in a private chat first; Telegram otherwise rejects delivery.

Successful weekly delivery is deduplicated per chat/report week in `/etc/xray/telegram_stats_report_state.json`. A failed recipient remains eligible for a later run; the script does not add a background retry schedule. An uncertain network timeout or failure to persist state after Telegram accepts a message can produce duplicates on retry.

```sh
python3 /usr/bin/xray_stats_report.py --dry-run
python3 /usr/bin/xray_stats_report.py --dry-run --private
python3 /usr/bin/xray_stats_report.py --private
```

Dry runs do not send, sample or write delivery state. `--private` restricts the run to the owner's completed-week report; `--force` bypasses successful-delivery deduplication. Cron stays at Monday 14:00 UTC. Keep the Mac archive across upgrades. The router cache survives bot/VPN restarts but is lost when the router reboots; recovery from the Mac is described below. Missing historical traffic cannot be reconstructed from a cumulative counter.

## Trends and the local Mac dashboard

Both automatic weekly reports and interactive statistics append a comparison with the **same elapsed interval one week earlier**. Completed weekly reports compare two complete reporting weeks. The owner and group scopes remain separate. Percentages are withheld when either interval has incomplete history, resets, missing samples or missing users; a zero prior interval is reported explicitly instead of dividing by zero. The daily view covers seven UTC dates, ending at the report cutoff. A partial latest day is labeled; absent history remains unknown, never zero. The group command retains the original since-restart counters above the separate weekly trend section.

The router keeps a bounded 21-day cache in RAM, enough for the current and previous reporting weeks. No USB drive is required and there are no periodic traffic-history writes to internal flash. The optional Mac dashboard copies only counter readings, labels, process epochs and scope metadata over existing SSH. It does not copy bot configuration, authentication credentials, certificates or private keys. Pulling readings is read-only. The Mac also restores recent archived readings to RAM after a router reboot. Both operations use existing SSH; the minute sampling schedule is unchanged.

Install `src/vpn_history_export.py` and `src/vpn_history_transfer.py` alongside the other router modules, then run on the Mac with an existing SSH alias:

```sh
python3 dashboard/server.py --ssh-host router-alias --data-dir "$HOME/Library/Application Support/BrumeTraffic"
```

Open `http://127.0.0.1:8765`. The server binds only to loopback, rejects unexpected Host/Origin headers, serves an explicit route allowlist and uses no third-party web assets. SSH uses BatchMode and the Mac's existing configuration/agent; ensure host-key trust is already set up interactively. There is no browser terminal or command execution endpoint. Never change the binding to a public interface without adding authentication.

The process synchronizes approximately every minute. Its SQLite archive (0600 inside a 0700 directory) deduplicates incremental readings and retains them without pruning. Initial catch-up is paginated; interrupted transfers can be retried. Scope metadata is refreshed from the router on each successful sync. A changed router boot ID triggers restoration of up to 21 days from the Mac to RAM. Restoration is paginated, idempotent, validates counter-only fields, refuses conflicting readings, checks the boot ID before committing and leaves newer samples intact. A failed restoration is retried and shown separately from successful Mac archival. Old readings remain available while SSH is unavailable, with a stale-data warning and exact last observation time. Every graph and total uses the same accounting rules as Telegram. The shared view excludes private accounts by raw ID; the private view includes only the configured accounts.

Keep the process running to collect on the Mac. After laptop sleep or shutdown, it catches up from the RAM cache. A router reboot before synchronization can permanently lose unarchived readings; an absence beyond 21 days can also leave gaps. The bot can still answer and send weekly reports from RAM while the Mac is offline, but an empty or partial cache is explicitly marked incomplete. No startup service is installed by this command; configure a local login service if unattended Mac archival is needed. Closing the process stops local HTTP and synchronization, but the router's collection, private commands and weekly reports continue independently. Protect the Mac archive as private traffic metadata. The dashboard does not transmit it to any cloud service.

### Migrating an existing flash database

Before switching paths, inspect the deployed scripts and mount table. Keep an installation backup, snapshot the active SQLite database using its backup API, transfer that history snapshot to the Mac over SSH and verify row counts/content hashes there. Seed the new RAM database from the snapshot, deploy all dependent modules together and run the bot self-test and scoped report checks without restarting the VPN. Preserve the original cron schedule and delivery state. Capture any final samples written to the old database before retiring it.

Only remove the old active flash database after the Mac archive and RAM cache have been checked against it. If validation fails, restore the original scripts and database path, preserving the transferred archive. Keep installation backups separate from active history; never copy SSH/TLS private keys into the archive. Restoring RAM does not make lost pre-reset traffic recoverable, and a weekly report already marked delivered is not silently re-sent when more history becomes available.

## Optional legacy Xray support

Set `vmess_enabled: true` only for an existing Xray setup. The old `/streisand`, `/links`, `/rotate`, `/restart`, `/target`, and `/tlsping` commands retain their checks; they are rejected when disabled. UUID rotation still requires confirmation and stale mutating updates are rejected.

The supported legacy topology has VMess/TLS on 443 and optional VLESS/REALITY on 9443, with StatsService on loopback 10085. `tools/install_user_stats.py` remains a separate administrator migration utility: it can add synthetic/example user labels, configure stats and preserve existing UUIDs, using backup, validation and rollback. It defaults to dry run. The repository's `scripts/` rotation helper is another separate workflow. Neither helper is exposed as Telegram user creation.

## Tests and publishing

```sh
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -v
```

For QR decoding checks on a supported desktop Python, also install `requirements-test.txt`. Decoder tests are skipped where `zxing-cpp` is unavailable and are run on the desktop; encoding is still checked on OpenWrt. Tests use temporary files, synthetic accounts/certificates and mocked Telegram replies, without calling the live server. The synthetic public test certificate is not trusted by any production installation; its private key is not in the repository.

Before deployment run the router self-test and command-handler checks. Before publishing, review the full diff and scan the publishable tree against real secret values **on the router**, without copying those values into Git or logs. Keep live configuration, client exports/QRs, TLS/SSH keys, tokens, certificates, personal IDs, router backups, history and deployment records outside this public repository. Ignore rules are a guardrail, not a substitute for inspecting the diff.
