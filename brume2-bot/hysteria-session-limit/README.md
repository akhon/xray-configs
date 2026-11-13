# Per-account session limit

This is an independently maintained patch to Hysteria **v2.12.3**, upstream commit `e1366b173ccf5706e1e4630fe8aa654a4b574085`. It adds the top-level server setting `"maxSessionsPerUser": 2`. This is **not an upstream setting**; stock binaries can ignore it. The supplied service wrapper refuses to run a stock binary when a positive limit is configured.

The limit applies to every authenticated account, including future accounts. Reservations are serialized before successful authentication and released by connection teardown. Repeated authentication on one connection does not consume another slot. A third session is refused through the normal authentication-failure path; existing sessions remain connected. Invalid credentials cannot reserve a slot. The existing userpass authenticator canonicalizes account names, so changing capitalization does not bypass the limit.

The unit is an authenticated QUIC session, not a physical device, public IP, or TCP/UDP proxy stream. Two apps on one device can consume both slots; a router sharing one tunnel remains one session. All protocol-compatible clients are subject to the limit. A disconnected or sleeping device can occupy its slot until QUIC detects the lost connection (the existing idle timeout is 30 seconds). A clean disconnect normally releases it promptly. The cap is per server process, not distributed across multiple servers. Missing/zero means unlimited; negative values fail validation. Counts exist only in RAM and require no polling or history writes.

## Build and checks

Requirements: Git and Docker (Linux ARM64 / Apple Silicon). Run from this directory:

```sh
./build.sh /tmp/hysteria-session-limit-build
```

The script fetches the exact commit, applies the checked-in patch, runs core and CLI tests plus password/userpass authentication tests with the race detector, then builds a static Linux ARM64 binary using Go 1.26.8 in the pinned official container image. It writes the binary and SHA-256 digest to the specified directory. Build metadata identifies it as `v2.12.3-session-limit.1` with the capability marker `maxSessionsPerUser/v1`. No live credentials or router keys are needed.

Tests cover concurrent admission, independent/canonical account IDs, wrong credentials, multiple proxy streams, slot release, interrupted authentication, repeated authentication on one session, and unlimited configuration. The existing core suite also exercises TCP and UDP forwarding. The patch synchronizes cleanup in an upstream traffic-logger test: Testify must not reflect over captured stream statistics while the server is still updating them. The unrelated HTTP-auth test requires Python/Flask and is outside this build's checks; the deployed authentication mode is userpass.

## Install, upgrade and rollback

1. Inspect the live installation. Back up the binary, server configuration, init script and changed Python modules with restricted permissions. Keep SSH and TLS private keys in place; do not include them in backups.
2. Test the candidate on separate loopback server/stats ports with a differently named executable, so the collector does not mistake it for production. Verify two accepted/third refused, independent accounts, release/reconnect and forwarding. Temporary client configurations belong in RAM with mode 0600.
3. Install `src/hysteria_session_guard.py`, updated `src/hysteria_profiles.py`, and `openwrt/etc/init.d/hysteria2` together. Stage the binary, preserve all server settings and add `maxSessionsPerUser: 2`. The wrapper runs for both service starts and supervised respawns, then replaces itself with the server process. Starting the binary directly bypasses this upgrade guard.
4. Take a fresh history sample, stop the service, atomically install and start. This causes a brief VPN reconnect. Sample again so the collector records the new process epoch and marks the unknown pre-reset tail. Restart the bot to load the compatible exporter. Do not clear stats counters manually or alter the report schedule.
5. Verify installed hashes, service health, admission/forwarding, unchanged credentials/certificate, bot authorization/export restrictions, and weekly statistics/collection. On failure, restore the backed-up binary, config, init and modules together, restart, sample and verify. Do not overwrite new history with a stale database.

Keep the guard and patch with future upgrades. Rebase and test before installing a new Hysteria release; a stock replacement will fail closed while the cap is enabled. Setting the cap to zero intentionally disables it. Rolling back both original binary and original config also removes the cap. No Telegram command changes the limit or creates users.
