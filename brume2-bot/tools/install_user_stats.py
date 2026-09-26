#!/usr/bin/env python3
"""Configure user statistics on the router, with validated atomic apply and rollback."""

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import sys
import uuid
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parent
if not (SOURCE_DIR / "xray_telegram_bot.py").exists():
    SOURCE_DIR = SOURCE_DIR.parent / "src"
sys.path.insert(0, str(SOURCE_DIR))
import xray_telegram_bot as bot
import xray_user_stats as stats


class SetupError(Exception):
    pass


def prepare_config(original, add_users=()):
    candidate = copy.deepcopy(original)
    inbounds = candidate.get("inbounds", [])
    selected = [(i, inbound) for i, inbound in enumerate(inbounds)
                if inbound.get("protocol") in ("vmess", "vless")]
    if not selected:
        raise SetupError("No VMess/VLESS inbound is configured.")
    used = set()
    original_clients = []
    for index, inbound in selected:
        clients = bot.inbound_user_list(inbound)
        if not clients:
            raise SetupError("A VPN inbound has no client to preserve.")
        for client_index, client in enumerate(clients):
            before = copy.deepcopy(client)
            label = client.get("email")
            if not stats._safe_label(label, stats._secrets(original)) or label.casefold() in used:
                prefix = "shared" if len(selected) == 1 and len(clients) == 1 else "%s-%02d" % (inbound["protocol"], index + 1)
                label = prefix if client_index == 0 else "%s-%02d" % (prefix, client_index + 1)
                suffix = 1
                while label.casefold() in used:
                    suffix += 1
                    label = "%s-%02d" % (prefix, suffix)
                client["email"] = label
            used.add(label.casefold())
            client.setdefault("level", 0)
            original_clients.append((index, client_index, before))

    for name in add_users:
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,23}", name):
            raise SetupError("New user names must be short lowercase labels.")
        for index, inbound in selected:
            label = name if len(selected) == 1 else "%s-%s-%d" % (name, inbound["protocol"], index + 1)
            if label.casefold() in used:
                continue
            clients = bot.inbound_user_list(inbound)
            client = copy.deepcopy(clients[0])
            client["id"] = str(uuid.uuid4())
            client["email"] = label
            client["level"] = 0
            clients.append(client)
            used.add(label.casefold())

    for index, client_index, before in original_clients:
        after = copy.deepcopy(bot.inbound_user_list(inbounds[index])[client_index])
        for field in ("email", "level"):
            after.pop(field, None)
            before.pop(field, None)
        if after != before:
            raise SetupError("An existing client credential would change.")

    candidate.setdefault("stats", {})
    if not isinstance(candidate["stats"], dict):
        raise SetupError("The existing stats setting is invalid.")
    policy = candidate.setdefault("policy", {})
    if not isinstance(policy, dict):
        raise SetupError("The existing policy is invalid.")
    levels = policy.setdefault("levels", {})
    if not isinstance(levels, dict):
        raise SetupError("The existing policy levels are invalid.")
    level_zero = levels.setdefault("0", {})
    if not isinstance(level_zero, dict):
        raise SetupError("Policy level zero is invalid.")
    level_zero.update(statsUserUplink=True, statsUserDownlink=True, statsUserOnline=True)
    for _index, inbound in selected:
        for client in bot.inbound_user_list(inbound):
            level = client.get("level", 0)
            if type(level) is not int or level < 0:
                raise SetupError("A client has an invalid policy level.")
            level_policy = levels.setdefault(str(level), {})
            if not isinstance(level_policy, dict):
                raise SetupError("A policy level is invalid.")
            level_policy.update(statsUserUplink=True, statsUserDownlink=True, statsUserOnline=True)

    # Keep a working existing API transport. This installation has no API; direct
    # loopback listen is supported by Xray 25.12.8 and needs no routing changes.
    api = candidate.get("api")
    if api is None:
        if any(item.get("port") == 10085 for item in inbounds):
            raise SetupError("Port 10085 already has an inbound; inspect its API route first.")
        api_tag = "user-stats-api"
        existing_tags = {item.get("tag") for item in candidate.get("outbounds", [])}
        if api_tag in existing_tags:
            raise SetupError("The statistics API tag is already in use.")
        candidate["api"] = {"tag": api_tag, "listen": "127.0.0.1:10085", "services": ["StatsService"]}
    else:
        if not isinstance(api, dict) or not isinstance(api.get("services"), list):
            raise SetupError("Existing API configuration needs inspection.")
        if "StatsService" not in api["services"]:
            api["services"].append("StatsService")
        if api.get("listen") not in (None, "", "127.0.0.1:10085"):
            raise SetupError("Existing API listen address needs inspection.")

    # Only stats, policy level flags, API setup and client labels/new entries may change.
    before_projection = copy.deepcopy(original)
    after_projection = copy.deepcopy(candidate)
    for projection in (before_projection, after_projection):
        for field in ("stats", "policy", "api"):
            projection.pop(field, None)
        for index, _inbound in selected:
            key = bot.inbound_user_key(projection["inbounds"][index])
            projection["inbounds"][index]["settings"].pop(key)
    if before_projection != after_projection:
        raise SetupError("An unrelated Xray setting would change.")
    if (original.get("policy") or {}).get("system") != (candidate.get("policy") or {}).get("system"):
        raise SetupError("System statistics policy would change.")
    return candidate


def verify_stats(config_path):
    rows = stats.collect_stats(config_path=str(config_path))
    if not rows:
        raise SetupError("Statistics returned no configured users.")
    return rows


def apply_config(add_users, expected_hash=None):
    lock = bot.xray_lock()
    temporary = None
    try:
        original_bytes = bot.XRAY_CONFIG.read_bytes()
        digest = hashlib.sha256(original_bytes).hexdigest()
        if expected_hash and digest != expected_hash:
            raise SetupError("Xray config changed since inspection; refusing to overwrite it.")
        original = bot.parse_xray_bytes(original_bytes)
        bot.validate_config_path(bot.XRAY_CONFIG)
        baseline = bot.health_snapshot(original)
        if not baseline["running"] or baseline["missing_ports"]:
            raise SetupError("Current Xray listeners are unhealthy.")
        candidate = prepare_config(original, add_users)
        if candidate == original:
            verify_stats(bot.XRAY_CONFIG)
            print("Statistics already configured; no restart needed.")
            return
        payload = (json.dumps(candidate, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        temporary = bot.candidate_file(payload)
        bot.validate_config_path(temporary)
        if hashlib.sha256(bot.XRAY_CONFIG.read_bytes()).hexdigest() != digest:
            raise SetupError("Xray config changed during preparation.")
        backup = bot.backup_current_config("user-stats", digest)
        if hashlib.sha256(bot.XRAY_CONFIG.read_bytes()).hexdigest() != digest:
            raise SetupError("Xray config changed after backup.")
        try:
            os.replace(str(temporary), str(bot.XRAY_CONFIG))
            temporary = None
            bot.fsync_directory(bot.XRAY_CONFIG.parent)
            bot.validate_config_path(bot.XRAY_CONFIG)
            bot.restart_and_verify(candidate)
            rows = verify_stats(bot.XRAY_CONFIG)
        except Exception:
            try:
                bot.atomic_write(bot.XRAY_CONFIG, original_bytes, 0o600)
                bot.validate_config_path(bot.XRAY_CONFIG)
                bot.restart_and_verify(original)
                if hashlib.sha256(bot.XRAY_CONFIG.read_bytes()).hexdigest() != digest:
                    raise SetupError("Restored bytes do not match.")
            except Exception:
                raise SetupError("Statistics setup failed; rollback needs immediate inspection.") from None
            raise SetupError("Statistics setup failed; previous config restored and Xray healthy.") from None
        print("Statistics enabled; original credentials preserved; backup=" + str(backup))
        print(stats.format_summary(rows, compact=False))
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        lock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="validate, back up, apply and restart")
    parser.add_argument("--add-users", nargs="*", default=[], help="add individual profiles without replacing existing UUIDs")
    parser.add_argument("--expected-config-sha256", help="refuse to apply if the inspected config changed")
    args = parser.parse_args()
    try:
        if args.apply:
            apply_config(args.add_users, args.expected_config_sha256)
        else:
            candidate = prepare_config(bot.load_xray_config(), args.add_users)
            print("Dry run: labels=" + ", ".join(user.label for user in stats.configured_users(candidate)))
            print("No files changed. Use --apply after inspecting the plan.")
    except (SetupError, bot.OperationError, stats.StatsError) as exc:
        print("Setup failed: " + str(exc), file=sys.stderr)
        return 1
    except Exception:
        print("Setup failed unexpectedly; secret details suppressed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
