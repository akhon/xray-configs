#!/usr/bin/env python3

import argparse
import base64
import copy
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import requests


VERSION = "1.2.0"

XRAY_CONFIG = Path("/etc/xray/config.json")
BOT_CONFIG = Path("/etc/xray/telegram_bot.json")
OFFSET_FILE = Path("/etc/xray/telegram_bot.offset")
BACKUP_DIR = Path("/etc/xray/backups")
LOCK_FILE = Path("/var/lock/xray-telegram-bot.lock")
BOT_PROCESS_LOCK = Path("/var/run/xray-telegram-bot.pidlock")
UUID_STATE_FILE = Path("/etc/xray/uuid_state.json")

XRAY_BIN = "/usr/bin/xray"
XRAY_SERVICE = "/etc/init.d/xray"

TOKEN_RE = re.compile(r"[0-9]{6,12}:[A-Za-z0-9_-]{25,}")
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
COMMAND_RE = re.compile(
    r"^/([A-Za-z0-9_]{1,32})(?:@([A-Za-z0-9_]{5,32}))?(?:[ \t]+([^\r\n]*))?$"
)
PROFILE_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@+-]{0,63}$")


class UserError(Exception):
    pass


class OperationError(Exception):
    pass


class TelegramError(Exception):
    pass


class TransactionError(OperationError):
    def __init__(self, message, rollback_ok=None):
        super().__init__(message)
        self.rollback_ok = rollback_ok


@dataclass(frozen=True)
class Settings:
    bot_token: str
    allowed_chat_ids: frozenset
    allowed_user_ids: frozenset


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def log(event, detail=""):
    line = "%s %s" % (utc_now().isoformat(timespec="seconds"), event)
    if detail:
        clean = TOKEN_RE.sub("[REDACTED_TOKEN]", str(detail))
        clean = re.sub(
            r'("?privateKey"?\s*[:=]\s*["\']?)[A-Za-z0-9_+/-]{30,}',
            r"\1[REDACTED]",
            clean,
            flags=re.IGNORECASE,
        )
        line += " " + clean.replace("\n", " ")[:300]
    print(line, flush=True)


def fsync_directory(path):
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def atomic_write(path, payload, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".%s." % path.name, dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, str(path))
        os.chmod(str(path), mode)
        fsync_directory(path.parent)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def atomic_write_json(path, value, mode=0o600):
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    atomic_write(path, payload, mode)


def strip_jsonc(text):
    output = []
    index = 0
    in_string = False
    escaped = False
    line_comment = False
    block_comment = False
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if char in "\r\n":
                line_comment = False
                output.append(char)
            else:
                output.append(" ")
            index += 1
            continue
        if block_comment:
            if char == "*" and following == "/":
                output.extend((" ", " "))
                index += 2
                block_comment = False
            else:
                output.append(char if char in "\r\n" else " ")
                index += 1
            continue
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
        elif char == "#":
            line_comment = True
            output.append(" ")
            index += 1
        elif char == "/" and following == "/":
            line_comment = True
            output.extend((" ", " "))
            index += 2
        elif char == "/" and following == "*":
            block_comment = True
            output.extend((" ", " "))
            index += 2
        else:
            output.append(char)
            index += 1
    if in_string or block_comment:
        raise OperationError("Xray configuration contains an unterminated string or comment")
    return "".join(output)


def reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise OperationError("Xray configuration contains a duplicate object key")
        value[key] = item
    return value


def reject_nonfinite(value):
    raise OperationError("Xray configuration contains a non-finite number: %s" % value)


def parse_xray_bytes(payload):
    if len(payload) > 4 * 1024 * 1024:
        raise OperationError("Xray configuration is unexpectedly large")
    try:
        text = payload.decode("utf-8-sig")
        value = json.loads(
            strip_jsonc(text),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperationError("Xray configuration cannot be parsed") from exc
    if not isinstance(value, dict):
        raise OperationError("Xray configuration root is not an object")
    return value


def load_xray_config():
    try:
        return parse_xray_bytes(XRAY_CONFIG.read_bytes())
    except OSError as exc:
        raise OperationError("Cannot read the Xray configuration") from exc


def load_settings():
    try:
        raw = json.loads(BOT_CONFIG.read_text(encoding="utf-8"))
    except Exception as exc:
        raise OperationError("Cannot read the Telegram bot settings") from exc

    token = raw.get("bot_token")
    chats = raw.get("allowed_chat_ids")
    users = raw.get("allowed_user_ids", [])
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        raise OperationError("Telegram bot token is missing or malformed")
    if not isinstance(chats, list) or not chats:
        raise OperationError("Telegram chat allowlist is empty")
    if not isinstance(users, list):
        raise OperationError("Telegram user allowlist is malformed")
    try:
        chat_ids = frozenset(int(item) for item in chats)
        user_ids = frozenset(int(item) for item in users)
    except (TypeError, ValueError) as exc:
        raise OperationError("Telegram allowlist contains a non-numeric ID") from exc
    return Settings(token, chat_ids, user_ids)


def inbound_user_list(inbound):
    settings = inbound.get("settings")
    if not isinstance(settings, dict):
        return None
    clients = settings.get("clients")
    users = settings.get("users")
    if clients is not None and users is not None:
        raise OperationError("An Xray inbound ambiguously contains both clients and users")
    selected = clients if clients is not None else users
    if selected is None:
        return None
    if not isinstance(selected, list):
        raise OperationError("An Xray inbound user list is malformed")
    return selected


def inbound_user_key(inbound):
    settings = inbound.get("settings") or {}
    clients = settings.get("clients")
    users = settings.get("users")
    if clients is not None and users is not None:
        raise OperationError("An Xray inbound ambiguously contains both clients and users")
    if clients is not None:
        return "clients"
    if users is not None:
        return "users"
    return None


def topology_signature(cfg):
    result = []
    for inbound in cfg.get("inbounds", []):
        stream = inbound.get("streamSettings") or {}
        result.append(
            (
                inbound.get("protocol"),
                inbound.get("listen"),
                inbound.get("port"),
                stream.get("network"),
                stream.get("security"),
            )
        )
    return result


def primary_inbounds(cfg):
    matches = {"vmess": [], "vless": []}
    for index, inbound in enumerate(cfg.get("inbounds", [])):
        if not isinstance(inbound, dict):
            continue
        stream = inbound.get("streamSettings") or {}
        if (
            inbound.get("protocol") == "vmess"
            and inbound.get("port") == 443
            and stream.get("security") == "tls"
        ):
            matches["vmess"].append((index, inbound))
        if (
            inbound.get("protocol") == "vless"
            and inbound.get("port") == 9443
            and stream.get("security") == "reality"
        ):
            matches["vless"].append((index, inbound))
    if len(matches["vmess"]) != 1 or len(matches["vless"]) > 1:
        raise OperationError(
            "Expected one VMess+TLS inbound on 443 and at most one VLESS+REALITY inbound on 9443"
        )
    return matches


def required_reality_inbound(cfg):
    matches = primary_inbounds(cfg)["vless"]
    if not matches:
        raise UserError("VLESS+REALITY is not configured on this router")
    return matches[0]


def assert_required_topology(cfg):
    inbounds = cfg.get("inbounds")
    if not isinstance(inbounds, list):
        raise OperationError("Xray inbounds are missing")
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            raise OperationError("An Xray inbound is malformed")
    primary_inbounds(cfg)


def json_diff_paths(before, after, path=""):
    if type(before) is not type(after):
        return {path or "/"}
    if isinstance(before, dict):
        changed = set()
        keys = set(before).union(after)
        for key in keys:
            child = (path + "/" + str(key).replace("~", "~0").replace("/", "~1"))
            if key not in before or key not in after:
                changed.add(child)
            else:
                changed.update(json_diff_paths(before[key], after[key], child))
        return changed
    if isinstance(before, list):
        if len(before) != len(after):
            return {path or "/"}
        changed = set()
        for index, (left, right) in enumerate(zip(before, after)):
            changed.update(json_diff_paths(left, right, path + "/" + str(index)))
        return changed
    return set() if before == after else {path or "/"}


def expected_ports(cfg):
    ports = set()
    for inbound in cfg.get("inbounds", []):
        port = inbound.get("port")
        if isinstance(port, int) and 0 < port <= 65535:
            ports.add(port)
    if not ports:
        raise OperationError("No numeric Xray inbound ports were found")
    return ports


def listening_socket_ports():
    sockets = {}
    for proc_path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(proc_path, "r", encoding="ascii") as handle:
                next(handle, None)
                for line in handle:
                    fields = line.split()
                    if len(fields) < 10 or fields[3] != "0A":
                        continue
                    port_hex = fields[1].rsplit(":", 1)[-1]
                    sockets[fields[9]] = int(port_hex, 16)
        except (OSError, ValueError):
            continue
    return sockets


def xray_process_ids():
    result = []
    proc_root = Path("/proc")
    for item in proc_root.iterdir():
        if not item.name.isdigit():
            continue
        try:
            argv = (item / "cmdline").read_bytes().split(b"\0")
            decoded = [part.decode("utf-8", "replace") for part in argv if part]
        except OSError:
            continue
        if not decoded or os.path.basename(decoded[0]) != "xray" or "run" not in decoded:
            continue
        if str(XRAY_CONFIG) not in decoded:
            continue
        result.append(int(item.name))
    return sorted(result)


def xray_owned_listening_ports(pids):
    socket_ports = listening_socket_ports()
    owned_inodes = set()
    for pid in pids:
        fd_dir = Path("/proc") / str(pid) / "fd"
        try:
            entries = list(fd_dir.iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                target = os.readlink(str(entry))
            except OSError:
                continue
            match = re.fullmatch(r"socket:\[(\d+)\]", target)
            if match:
                owned_inodes.add(match.group(1))
    return {socket_ports[inode] for inode in owned_inodes if inode in socket_ports}


def service_running():
    try:
        proc = subprocess.run(
            [XRAY_SERVICE, "status"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0 and "running" in (proc.stdout or "").lower()


def health_snapshot(cfg):
    wanted = expected_ports(cfg)
    pids = xray_process_ids()
    present = xray_owned_listening_ports(pids)
    return {
        "running": service_running() and bool(pids),
        "pids": pids,
        "expected_ports": sorted(wanted),
        "listening_ports": sorted(wanted.intersection(present)),
        "missing_ports": sorted(wanted.difference(present)),
    }


def wait_for_xray(cfg, timeout=10):
    deadline = time.monotonic() + timeout
    stable = 0
    last = None
    stable_pids = None
    while time.monotonic() < deadline:
        last = health_snapshot(cfg)
        if last["running"] and not last["missing_ports"]:
            current_pids = tuple(last["pids"])
            if current_pids == stable_pids:
                stable += 1
            else:
                stable_pids = current_pids
                stable = 1
            if stable >= 5:
                return last
        else:
            stable = 0
            stable_pids = None
        time.sleep(0.75)
    return last or health_snapshot(cfg)


def validate_config_path(path):
    try:
        proc = subprocess.run(
            [XRAY_BIN, "run", "-test", "-format", "json", "-config", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise OperationError("Xray configuration validation timed out") from exc
    except OSError as exc:
        raise OperationError("Xray validation command could not start") from exc
    if proc.returncode != 0:
        raise OperationError("Xray rejected the candidate configuration")


def restart_and_verify(cfg):
    try:
        proc = subprocess.run(
            [XRAY_SERVICE, "restart"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise OperationError("Xray restart timed out") from exc
    except OSError as exc:
        raise OperationError("Xray restart command could not start") from exc
    if proc.returncode != 0:
        raise OperationError("Xray restart command failed")
    health = wait_for_xray(cfg)
    if not health["running"] or health["missing_ports"]:
        raise OperationError("Xray did not return with every configured listener")
    return health


def xray_lock():
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    handle = open(LOCK_FILE, "a+")
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    return handle


def bot_process_lock():
    BOT_PROCESS_LOCK.parent.mkdir(parents=True, exist_ok=True)
    handle = open(BOT_PROCESS_LOCK, "a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        handle.close()
        raise OperationError("Another bot process is already running") from exc
    return handle


def backup_current_config(action, expected_hash):
    BACKUP_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(str(BACKUP_DIR), 0o700)
    safe_action = re.sub(r"[^a-z0-9_-]", "_", action.lower())[:32]
    stamp = utc_now().strftime("%Y%m%dT%H%M%S.%fZ")
    destination = BACKUP_DIR / ("config.json.%s.%s" % (stamp, safe_action))
    with open(XRAY_CONFIG, "rb") as source, open(destination, "xb") as target:
        os.chmod(str(destination), 0o600)
        shutil.copyfileobj(source, target)
        target.flush()
        os.fsync(target.fileno())
    if hashlib.sha256(destination.read_bytes()).hexdigest() != expected_hash:
        destination.unlink()
        raise OperationError("Xray configuration backup verification failed")
    fsync_directory(BACKUP_DIR)
    return destination


def candidate_file(payload):
    fd, name = tempfile.mkstemp(prefix=".config.json.candidate.", suffix=".json", dir=str(XRAY_CONFIG.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(name)
        except OSError:
            pass
        raise
    return Path(name)


def transactional_update(action, mutate, expected_original_hash=None):
    lock_handle = xray_lock()
    candidate_path = None
    try:
        original_bytes = XRAY_CONFIG.read_bytes()
        original_hash = hashlib.sha256(original_bytes).hexdigest()
        if expected_original_hash is not None and original_hash != expected_original_hash:
            raise OperationError("Xray configuration changed after the preview was prepared")
        original = parse_xray_bytes(original_bytes)
        assert_required_topology(original)
        original_signature = topology_signature(original)
        validate_config_path(XRAY_CONFIG)
        baseline = health_snapshot(original)
        if not baseline["running"] or baseline["missing_ports"]:
            raise OperationError("Xray baseline health check failed; refusing to mutate")

        candidate = copy.deepcopy(original)
        result = mutate(candidate)
        allowed_paths = set(result.pop("_allowed_paths", []))
        assert_required_topology(candidate)
        if topology_signature(candidate) != original_signature:
            raise OperationError("The requested edit unexpectedly changed Xray listener topology")

        changes = json_diff_paths(original, candidate)
        if not changes:
            raise UserError("The requested value is already active")
        if not allowed_paths or any(
            not any(path == allowed or path.startswith(allowed + "/") for allowed in allowed_paths)
            for path in changes
        ):
            raise OperationError("The candidate changed an unexpected Xray setting")

        payload = (
            json.dumps(candidate, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        ).encode("utf-8")
        candidate_path = candidate_file(payload)
        validate_config_path(candidate_path)

        if hashlib.sha256(XRAY_CONFIG.read_bytes()).hexdigest() != original_hash:
            raise OperationError("Xray configuration changed during the operation; refusing to overwrite it")
        backup_current_config(action, original_hash)
        if hashlib.sha256(XRAY_CONFIG.read_bytes()).hexdigest() != original_hash:
            raise OperationError("Xray configuration changed after backup; refusing to overwrite it")
        try:
            os.replace(str(candidate_path), str(XRAY_CONFIG))
            candidate_path = None
            fsync_directory(XRAY_CONFIG.parent)
            validate_config_path(XRAY_CONFIG)
        except Exception as install_error:
            rollback_ok = False
            try:
                atomic_write(XRAY_CONFIG, original_bytes, 0o600)
                validate_config_path(XRAY_CONFIG)
                restored_hash = hashlib.sha256(XRAY_CONFIG.read_bytes()).hexdigest()
                restored_health = health_snapshot(original)
                rollback_ok = (
                    restored_hash == original_hash
                    and restored_health["running"]
                    and not restored_health["missing_ports"]
                )
            except Exception:
                rollback_ok = False
            raise TransactionError(
                "The candidate could not be installed and verified",
                rollback_ok=rollback_ok,
            ) from install_error

        try:
            health = restart_and_verify(candidate)
        except Exception as restart_error:
            rollback_ok = False
            try:
                atomic_write(XRAY_CONFIG, original_bytes, 0o600)
                validate_config_path(XRAY_CONFIG)
                restart_and_verify(original)
                rollback_ok = hashlib.sha256(XRAY_CONFIG.read_bytes()).hexdigest() == original_hash
            except Exception:
                rollback_ok = False
            raise TransactionError(
                "The new configuration failed to start",
                rollback_ok=rollback_ok,
            ) from restart_error

        return result, health, candidate
    finally:
        if candidate_path is not None:
            try:
                candidate_path.unlink()
            except OSError:
                pass
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        lock_handle.close()


def rotate_ids(candidate, planned_replacements=None):
    replacements = {} if planned_replacements is None else dict(planned_replacements)
    counts = {"vmess": 0, "vless": 0}
    new_by_protocol = {"vmess": [], "vless": []}
    allowed_paths = []
    matches = primary_inbounds(candidate)
    for protocol in ("vmess", "vless"):
        if not matches[protocol]:
            continue
        inbound_index, inbound = matches[protocol][0]
        users = inbound_user_list(inbound)
        key = inbound_user_key(inbound)
        if not users or key is None:
            raise OperationError("Primary %s inbound has no clients" % protocol.upper())
        for user_index, user in enumerate(users):
            if not isinstance(user, dict) or not isinstance(user.get("id"), str):
                raise OperationError("An Xray client entry has no string ID")
            old_id = user["id"]
            try:
                parsed = uuid.UUID(old_id)
            except ValueError as exc:
                raise OperationError("An Xray client ID is not a UUID") from exc
            if str(parsed) != old_id.lower():
                raise OperationError("An Xray client ID is not in canonical UUID form")
            if planned_replacements is not None and old_id not in replacements:
                raise OperationError("Xray client IDs changed after the rotation preview")
            new_id = replacements.setdefault(old_id, str(uuid.uuid4()))
            try:
                if str(uuid.UUID(new_id)) != new_id.lower():
                    raise ValueError
            except ValueError as exc:
                raise OperationError("Planned replacement ID is not a canonical UUID") from exc
            if new_id.lower() == old_id.lower():
                raise OperationError("Planned replacement UUID is unchanged")
            user["id"] = new_id
            counts[protocol] += 1
            new_by_protocol[protocol].append(new_id)
            allowed_paths.append(
                "/inbounds/%d/settings/%s/%d/id" % (inbound_index, key, user_index)
            )
    if len(set(replacements.values())) != len(replacements):
        raise OperationError("Planned replacement UUIDs are not unique")
    return {
        "counts": counts,
        "new_ids": new_by_protocol,
        "_replacements": replacements,
        "_allowed_paths": allowed_paths,
    }


def update_reality_target(candidate, hostname):
    inbound_index, inbound = required_reality_inbound(candidate)
    stream = inbound.get("streamSettings") or {}
    reality = stream.get("realitySettings")
    if not isinstance(reality, dict):
        raise OperationError("REALITY settings are missing")
    if "target" in reality and "dest" in reality and reality["target"] != reality["dest"]:
        raise OperationError("REALITY target and dest aliases disagree")
    destination_keys = [key for key in ("target", "dest") if key in reality]
    if not destination_keys:
        destination_keys = ["target"]
    allowed_paths = []
    for destination_key in destination_keys:
        reality[destination_key] = hostname + ":443"
        allowed_paths.append(
            "/inbounds/%d/streamSettings/realitySettings/%s"
            % (inbound_index, destination_key)
        )
    reality["serverNames"] = [hostname]
    allowed_paths.append(
        "/inbounds/%d/streamSettings/realitySettings/serverNames" % inbound_index
    )
    return {
        "hostname": hostname,
        "updated_inbounds": 1,
        "_allowed_paths": allowed_paths,
    }


def sync_legacy_uuid_state(cfg):
    try:
        _index, vmess = primary_inbounds(cfg)["vmess"][0]
        users = inbound_user_list(vmess) or []
        ids = [entry.get("id") for entry in users if isinstance(entry, dict) and entry.get("id")]
        if not ids:
            return
        current_ids = set(ids)
        old = {}
        if UUID_STATE_FILE.exists():
            old = json.loads(UUID_STATE_FILE.read_text(encoding="utf-8"))
        pending = [
            item
            for item in old.get("pending_removals", [])
            if isinstance(item, dict) and item.get("uuid") in current_ids
        ]
        shared_id = next(
            (entry["id"] for entry in users if isinstance(entry, dict)
             and entry.get("email") == "shared" and entry.get("id") in current_ids),
            ids[0],
        )
        state = {
            "current_uuid": shared_id,
            "pending_removals": pending,
            "last_rotation": utc_now().replace(tzinfo=None).isoformat(),
        }
        atomic_write_json(UUID_STATE_FILE, state, 0o600)
    except Exception as exc:
        log("legacy-state-sync-failed", type(exc).__name__)


def restart_current_config():
    lock_handle = xray_lock()
    try:
        cfg = load_xray_config()
        assert_required_topology(cfg)
        validate_config_path(XRAY_CONFIG)
        return restart_and_verify(cfg)
    finally:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        lock_handle.close()


def normalize_hostname(raw):
    candidate = raw.strip().lower().rstrip(".")
    if not candidate or len(candidate) > 253:
        raise UserError("Hostname is empty or too long")
    if "://" in candidate or "/" in candidate or ":" in candidate:
        raise UserError("Provide a hostname only, without a scheme, path, or port")
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UserError("Hostname cannot be converted to IDNA") from exc
    try:
        ipaddress.ip_address(candidate)
        raise UserError("Provide a public DNS hostname, not an IP address")
    except ValueError:
        pass
    labels = candidate.split(".")
    if len(labels) < 2 or any(not HOST_LABEL_RE.fullmatch(label) for label in labels):
        raise UserError("Hostname syntax is invalid")
    return candidate


def resolve_public_hostname(hostname):
    try:
        answers = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UserError("Hostname did not resolve") from exc
    addresses = sorted({item[4][0] for item in answers})
    if not addresses:
        raise UserError("Hostname did not resolve")
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise UserError("Hostname returned an invalid address") from exc
        if not parsed.is_global:
            raise UserError("Hostname resolves to a non-public address")
    return addresses


def run_tls_ping(hostname):
    hostname = normalize_hostname(hostname)
    addresses = resolve_public_hostname(hostname)
    try:
        proc = subprocess.run(
            [XRAY_BIN, "tls", "ping", hostname],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=45,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise UserError("TLS check timed out") from exc
    except OSError as exc:
        raise OperationError("Xray TLS checker could not start") from exc
    output = proc.stdout or ""
    return {
        "hostname": hostname,
        "addresses": addresses,
        "returncode": proc.returncode,
        "output": output,
        "summary": summarize_tls_ping(hostname, output, proc.returncode),
    }


def section_value(section, label):
    match = re.search(r"^%s:\s*(.+?)\s*$" % re.escape(label), section, re.MULTILINE)
    return match.group(1).strip() if match else None


def summarize_tls_ping(hostname, output, returncode):
    using_ip = section_value(output, "Using IP") or "resolved"
    without = ""
    with_sni = ""
    marker_without = re.search(r"Pinging without SNI(.*?)(?=Pinging with SNI|\Z)", output, re.S)
    marker_with = re.search(r"Pinging with SNI(.*)\Z", output, re.S)
    if marker_without:
        without = marker_without.group(1)
    if marker_with:
        with_sni = marker_with.group(1)

    def describe(section):
        if "Handshake succeeded" not in section:
            return "failed"
        version = section_value(section, "TLS Version") or "unknown TLS"
        pq = section_value(section, "TLS Post-Quantum key exchange")
        chain = section_value(section, "Certificate chain's total length")
        fields = ["OK", version]
        if pq:
            fields.append("PQ " + ("yes" if pq.lower() == "true" else "no"))
        if chain:
            fields.append("chain " + chain.split()[0] + " B")
        return ", ".join(fields)

    return (
        "TLS check: %s\nResolved endpoint: %s\nWithout SNI: %s\nWith SNI: %s\nCommand status: %s"
        % (
            hostname,
            using_ip,
            describe(without),
            describe(with_sni),
            "OK" if returncode == 0 else "failed",
        )
    )


def verify_tls13_certificate(hostname):
    context = ssl.create_default_context()
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["h2", "http/1.1"])
    try:
        with socket.create_connection((hostname, 443), timeout=12) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as wrapped:
                version = wrapped.version()
    except (OSError, ssl.SSLError) as exc:
        raise UserError("Verified TLS 1.3 handshake failed for that hostname") from exc
    if version != "TLSv1.3":
        raise UserError("Target did not negotiate TLS 1.3")


def preflight_reality_target(hostname):
    result = run_tls_ping(hostname)
    with_sni = re.search(r"Pinging with SNI(.*)\Z", result["output"], re.S)
    section = with_sni.group(1) if with_sni else ""
    if result["returncode"] != 0 or "Handshake succeeded" not in section:
        raise UserError("Xray TLS check with SNI did not succeed")
    if section_value(section, "TLS Version") != "TLS 1.3":
        raise UserError("REALITY target must negotiate TLS 1.3 with SNI")
    verify_tls13_certificate(result["hostname"])
    return result


def get_public_ip():
    services = (
        "https://api.ipify.org",
        "https://checkip.amazonaws.com",
        "https://icanhazip.com",
    )
    found = []
    session = requests.Session()
    session.trust_env = False
    for url in services:
        try:
            response = session.get(
                url,
                timeout=(4, 8),
                headers={"User-Agent": "brume-xray-bot/%s" % VERSION},
            )
            response.raise_for_status()
            value = response.text.strip().split()[0]
            parsed = ipaddress.ip_address(value)
            if parsed.is_global:
                found.append(str(parsed))
        except Exception:
            continue
    if not found:
        raise OperationError("Could not determine the public IP from external services")
    unique = set(found)
    if len(unique) != 1:
        raise OperationError("External IP services returned conflicting results")
    return found[0]


def x25519_public_key(private_key):
    try:
        padding = "=" * ((4 - len(private_key) % 4) % 4)
        scalar = bytearray(base64.urlsafe_b64decode(private_key + padding))
    except Exception as exc:
        raise OperationError("REALITY private key encoding is invalid") from exc
    if len(scalar) != 32:
        raise OperationError("REALITY private key has an unexpected length")
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    k = int.from_bytes(scalar, "little")
    prime = 2 ** 255 - 19
    x1 = 9
    x2, z2 = 1, 0
    x3, z3 = 9, 1
    swap = 0

    def cswap(bit, left, right):
        mask = -bit
        delta = mask & (left ^ right)
        return left ^ delta, right ^ delta

    for bit_index in range(254, -1, -1):
        bit = (k >> bit_index) & 1
        swap ^= bit
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = bit
        a = (x2 + z2) % prime
        aa = (a * a) % prime
        b = (x2 - z2) % prime
        bb = (b * b) % prime
        e = (aa - bb) % prime
        c = (x3 + z3) % prime
        d = (x3 - z3) % prime
        da = (d * a) % prime
        cb = (c * b) % prime
        x3 = ((da + cb) ** 2) % prime
        z3 = (x1 * ((da - cb) ** 2)) % prime
        x2 = (aa * bb) % prime
        z2 = (e * (aa + 121665 * e)) % prime
    x2, x3 = cswap(swap, x2, x3)
    z2, z3 = cswap(swap, z2, z3)
    public = (x2 * pow(z2, prime - 2, prime)) % prime
    encoded = base64.urlsafe_b64encode(public.to_bytes(32, "little")).decode("ascii")
    return encoded.rstrip("=")


def profile_client(inbound, client_index):
    users = inbound_user_list(inbound) or []
    if not 0 <= client_index < len(users):
        raise OperationError("The selected inbound client is missing")
    user = users[client_index]
    if not isinstance(user, dict) or not isinstance(user.get("id"), str):
        raise OperationError("The selected inbound client has no string ID")
    try:
        canonical_id = str(uuid.UUID(user["id"]))
    except (ValueError, TypeError) as exc:
        raise OperationError("An inbound client ID is not a UUID") from exc
    if canonical_id != user["id"].lower():
        raise OperationError("An inbound client ID is not canonical")
    label = user.get("email") or "%s-%d" % (inbound["protocol"], client_index + 1)
    if not isinstance(label, str) or not PROFILE_LABEL_RE.fullmatch(label) or UUID_RE.search(label):
        raise OperationError("An inbound client label is unsafe to export")
    return user, canonical_id, label


def reality_profile(cfg, client_index=0):
    _index, inbound = required_reality_inbound(cfg)
    stream = inbound.get("streamSettings") or {}
    user, canonical_id, label = profile_client(inbound, client_index)
    reality = stream.get("realitySettings") or {}
    names = reality.get("serverNames") or []
    short_ids = reality.get("shortIds") or []
    private_key = reality.get("privateKey")
    port = inbound.get("port")
    if len(names) < 1 or len(short_ids) < 1 or not isinstance(private_key, str):
        raise OperationError("REALITY client parameters are incomplete")
    short_id = short_ids[0]
    if not isinstance(short_id, str) or len(short_id) > 16 or len(short_id) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", short_id):
        raise OperationError("REALITY short ID is malformed")
    public_key = x25519_public_key(private_key)
    try:
        decoded_key = base64.urlsafe_b64decode(public_key + "=")
    except Exception as exc:
        raise OperationError("Derived REALITY public key is malformed") from exc
    if len(decoded_key) != 32:
        raise OperationError("Derived REALITY public key has an unexpected length")
    return {
        "id": canonical_id,
        "label": label,
        "flow": user.get("flow", ""),
        "port": port,
        "sni": names[0],
        "short_id": short_id,
        "public_key": public_key,
    }


def vmess_profile(cfg, client_index=0):
    _index, inbound = primary_inbounds(cfg)["vmess"][0]
    user, canonical_id, label = profile_client(inbound, client_index)
    stream = inbound.get("streamSettings") or {}
    if stream.get("network", "tcp") not in ("tcp", "raw"):
        raise OperationError("VMess export supports only the configured TCP transport")
    header = (stream.get("tcpSettings") or stream.get("rawSettings") or {}).get("header") or {}
    if header.get("type", "none") != "none":
        raise OperationError("VMess export does not support this TCP header configuration")
    tls = stream.get("tlsSettings") or {}
    certificates = tls.get("certificates") or []
    if not certificates or not isinstance(certificates[0], dict):
        raise OperationError("VMess TLS certificate is missing")
    certificate_file = certificates[0].get("certificateFile")
    if not isinstance(certificate_file, str):
        raise OperationError("VMess TLS certificate path is missing")
    try:
        decoded = ssl._ssl._test_decode_cert(certificate_file)
    except Exception as exc:
        raise OperationError("VMess TLS certificate could not be decoded") from exc
    try:
        certificate_pem = Path(certificate_file).read_text(encoding="ascii")
        leaf_match = re.search(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            certificate_pem,
            flags=re.DOTALL,
        )
        if not leaf_match:
            raise ValueError("leaf certificate PEM block is missing")
        leaf_der = ssl.PEM_cert_to_DER_cert(leaf_match.group(0))
        pinned_peer_cert_sha256 = hashlib.sha256(leaf_der).hexdigest()
    except (OSError, UnicodeError, ValueError) as exc:
        raise OperationError("VMess TLS certificate fingerprint could not be derived") from exc

    candidates = []
    configured_sni = tls.get("serverName")
    if isinstance(configured_sni, str) and configured_sni:
        candidates.append(configured_sni)
    fallbacks = inbound.get("fallbacks") or []
    if fallbacks and isinstance(fallbacks[0], dict):
        destination = fallbacks[0].get("dest")
        if isinstance(destination, str):
            candidates.append(destination.rsplit(":", 1)[0])
    for san_kind, san_value in decoded.get("subjectAltName", ()):
        if san_kind == "DNS" and "*" not in san_value:
            candidates.append(san_value)
    for relative_name in decoded.get("subject", ()):
        for key, value in relative_name:
            if key == "commonName" and "*" not in value:
                candidates.append(value)

    sni = ""
    for candidate in candidates:
        try:
            normalized = normalize_hostname(candidate)
            ssl.match_hostname(decoded, normalized)
            sni = normalized
            break
        except Exception:
            continue
    if not sni:
        raise OperationError("No usable VMess SNI matches the installed certificate")

    return {
        "id": canonical_id,
        "label": label,
        "port": inbound.get("port"),
        "security": user.get("security", "auto"),
        "alter_id": user.get("alterId", 0),
        "network": stream.get("network", "tcp"),
        "sni": sni,
        "alpn": tls.get("alpn") or [],
        "pinned_peer_cert_sha256": pinned_peer_cert_sha256,
    }


def build_streisand_document(cfg, address, user_filter=None):
    if user_filter is not None and (
        not isinstance(user_filter, str)
        or not PROFILE_LABEL_RE.fullmatch(user_filter)
        or UUID_RE.search(user_filter)
    ):
        raise UserError("Use a configured user label, for example /streisand alice")
    matches = primary_inbounds(cfg)
    try:
        endpoint = str(ipaddress.ip_address(address))
    except ValueError as exc:
        raise OperationError("Streisand endpoint is not a public IP address") from exc

    def local_inbounds():
        return [
            {
                "tag": "socks",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
            },
            {
                "tag": "http",
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
                "settings": {},
            },
        ]

    profiles = []
    for protocol in ("vless", "vmess"):
        if not matches[protocol]:
            continue
        _index, inbound = matches[protocol][0]
        clients = inbound_user_list(inbound) or []
        if not clients:
            raise OperationError("An exportable inbound has no clients")
        seen_labels = set()
        for client_index in range(len(clients)):
            _user, _client_id, label = profile_client(inbound, client_index)
            if label in seen_labels:
                raise OperationError("User labels must be unique within each inbound")
            seen_labels.add(label)
            if user_filter is not None and label != user_filter:
                continue
            if protocol == "vless":
                profile = reality_profile(cfg, client_index)
                client_user = {"id": profile["id"], "encryption": "none"}
                if profile["flow"]:
                    client_user["flow"] = profile["flow"]
                client_stream = {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "serverName": profile["sni"],
                        "fingerprint": "chrome",
                        "publicKey": profile["public_key"],
                        "shortId": profile["short_id"],
                        "spiderX": "/",
                    },
                }
                description = "VLESS REALITY"
            else:
                profile = vmess_profile(cfg, client_index)
                client_user = {
                    "id": profile["id"],
                    "alterId": profile["alter_id"],
                    "security": profile["security"],
                }
                client_tls = {
                    "serverName": profile["sni"],
                    "fingerprint": "chrome",
                    "pinnedPeerCertSha256": profile["pinned_peer_cert_sha256"],
                }
                if profile["alpn"]:
                    client_tls["alpn"] = profile["alpn"]
                client_stream = {
                    "network": profile["network"],
                    "security": "tls",
                    "tlsSettings": client_tls,
                }
                if profile["network"] == "tcp":
                    client_stream["tcpSettings"] = {"header": {"type": "none"}}
                description = "VMess TLS"
            outbound = {
                "tag": "proxy",
                "protocol": protocol,
                "settings": {
                    "vnext": [{
                        "address": endpoint,
                        "port": profile["port"],
                        "users": [client_user],
                    }]
                },
                "streamSettings": client_stream,
            }
            profiles.append({
                "remarks": "Brume 2 - %s - %s" % (label, description),
                "log": {"loglevel": "warning"},
                "inbounds": local_inbounds(),
                "outbounds": [outbound],
                "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
                "routing": {"domainStrategy": "AsIs", "rules": []},
            })
    if not profiles:
        raise UserError("No profile matches that user label")

    forbidden_keys = {
        "privatekey",
        "target",
        "dest",
        "servernames",
        "certificatefile",
        "keyfile",
        "bot_token",
    }

    def reject_server_only_fields(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).lower() in forbidden_keys:
                    raise OperationError("Streisand export contains a server-only field")
                reject_server_only_fields(child)
        elif isinstance(value, list):
            for child in value:
                reject_server_only_fields(child)

    reject_server_only_fields(profiles)
    document = json.dumps(profiles, ensure_ascii=False, indent=2) + "\n"
    for _index, reality_inbound in matches["vless"]:
        server_private_key = (
            ((reality_inbound.get("streamSettings") or {}).get("realitySettings") or {}).get("privateKey")
        )
        if isinstance(server_private_key, str) and server_private_key and server_private_key in document:
            raise OperationError("Streisand export contains the REALITY private key")
    return document


class TelegramClient:
    def __init__(self, token):
        self.base_url = "https://api.telegram.org/bot%s/" % token
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({"User-Agent": "brume-xray-bot/%s" % VERSION})

    def request(self, method, data=None, files=None, timeout=(10, 20)):
        try:
            response = self.session.post(
                self.base_url + method,
                data=data or {},
                files=files,
                timeout=timeout,
            )
        except requests.RequestException as exc:
            raise TelegramError("Telegram API connection failed") from exc
        try:
            body = response.json()
        except ValueError as exc:
            raise TelegramError("Telegram API returned a non-JSON response") from exc
        if response.status_code != 200 or body.get("ok") is not True:
            raise TelegramError("Telegram API rejected %s (HTTP %s)" % (method, response.status_code))
        return body.get("result")

    def get_me(self):
        return self.request("getMe", timeout=(8, 12))

    def get_webhook_info(self):
        return self.request("getWebhookInfo", timeout=(8, 12))

    def get_updates(self, offset, timeout_seconds):
        return self.request(
            "getUpdates",
            data={
                "offset": str(offset),
                "timeout": str(timeout_seconds),
                "allowed_updates": json.dumps(["message"]),
            },
            timeout=(10, timeout_seconds + 12),
        )

    def send_message(self, chat_id, text, reply_to=None):
        chunks = []
        remaining = str(text)
        while remaining:
            if len(remaining) <= 3900:
                chunks.append(remaining)
                break
            split_at = remaining.rfind("\n", 0, 3900)
            if split_at < 1000:
                split_at = 3900
            chunks.append(remaining[:split_at])
            remaining = remaining[split_at:].lstrip("\n")
        for index, chunk in enumerate(chunks or [""]):
            payload = {"chat_id": str(chat_id), "text": chunk}
            if reply_to is not None and index == 0:
                payload["reply_parameters"] = json.dumps({"message_id": reply_to})
            self.request("sendMessage", data=payload)

    def send_document(self, chat_id, name, content, caption="", mime_type="application/octet-stream"):
        self.request(
            "sendDocument",
            data={"chat_id": str(chat_id), "caption": caption},
            files={"document": (name, content.encode("utf-8"), mime_type)},
            timeout=(10, 30),
        )


HELP_TEXT = """Brume 2 Xray commands

/ip — show the router's current public IP
/streisand [user] — export configured client profiles as JSON
/stats [user] — show per-user traffic and online status when available
/rotate — begin safe VMess/VLESS UUID rotation
/restart — validate and restart Xray
/target hostname — validate and switch the REALITY target/SNI
/tlsping hostname — run a concise Xray TLS check
/status — show Xray listener health
/help — show this help

UUID rotation requires a second /rotate confirm command within two minutes."""


class Bot:
    def __init__(self, settings):
        self.settings = settings
        self.telegram = TelegramClient(settings.bot_token)
        self.stop_event = threading.Event()
        self.pending_rotations = {}
        self.bot_username = None

    def authorized(self, message):
        chat = message.get("chat") or {}
        sender = message.get("from") or {}
        try:
            chat_id = int(chat.get("id"))
        except (TypeError, ValueError):
            return False
        if chat_id not in self.settings.allowed_chat_ids:
            return False
        if self.settings.allowed_user_ids:
            try:
                user_id = int(sender.get("id"))
            except (TypeError, ValueError):
                return False
            if user_id not in self.settings.allowed_user_ids:
                return False
        return True

    def parse_command(self, message):
        text = message.get("text")
        if not isinstance(text, str):
            return None
        match = COMMAND_RE.fullmatch(text.strip())
        if not match:
            return None
        suffix = match.group(2)
        if suffix and (not self.bot_username or suffix.lower() != self.bot_username.lower()):
            return None
        command = "/" + match.group(1).lower()
        argument_text = match.group(3) or ""
        return command, argument_text.split()

    def is_mutating_message(self, message):
        if not self.authorized(message):
            return False
        parsed = self.parse_command(message)
        if not parsed:
            return False
        command, arguments = parsed
        return command in ("/restart", "/target") or (
            command == "/rotate" and arguments == ["confirm"]
        )

    def send_profile(self, chat_id, caption, user_filter=None):
        cfg = load_xray_config()
        document = build_streisand_document(cfg, get_public_ip(), user_filter)
        self.telegram.send_document(
            chat_id,
            "brume2-streisand.json",
            document,
            caption,
            "application/json",
        )

    def command_status(self, chat_id, reply_to):
        cfg = load_xray_config()
        status = health_snapshot(cfg)
        target = "not configured"
        if primary_inbounds(cfg)["vless"]:
            target = reality_profile(cfg)["sni"]
        self.telegram.send_message(
            chat_id,
            "Xray: %s\nListeners: %s\nREALITY SNI: %s"
            % (
                "running" if status["running"] and not status["missing_ports"] else "unhealthy",
                ", ".join(str(item) for item in status["listening_ports"]) or "none",
                target,
            ),
            reply_to,
        )

    def command_stats(self, chat_id, reply_to, arguments):
        if len(arguments) > 1 or (arguments and (
            not PROFILE_LABEL_RE.fullmatch(arguments[0]) or UUID_RE.search(arguments[0])
        )):
            raise UserError("Usage: /stats [user label]")
        try:
            import xray_user_stats
        except ImportError as exc:
            raise OperationError("The statistics helper is not installed") from exc
        try:
            summary = xray_user_stats.render_summary(
                arguments[0] if arguments else None, compact=True
            )
        except xray_user_stats.StatsError:
            raise UserError("Statistics are unavailable or the user label was not found")
        self.telegram.send_message(chat_id, summary, reply_to)

    def command_rotate(self, message, arguments):
        chat_id = int(message["chat"]["id"])
        message_id = message.get("message_id")
        sender_id = int((message.get("from") or {}).get("id", 0))
        key = (chat_id, sender_id)
        if arguments != ["confirm"]:
            self.pending_rotations[key] = time.monotonic() + 120
            self.telegram.send_message(
                chat_id,
                "This replaces every current VMess/VLESS client UUID. Existing profiles will stop working. Send /rotate confirm within two minutes to continue.",
                message_id,
            )
            return
        expires = self.pending_rotations.pop(key, 0)
        if expires < time.monotonic():
            raise UserError("Rotation confirmation is missing or expired; send /rotate first")
        self.telegram.send_message(chat_id, "Preparing and validating the replacement profile…", message_id)
        public_ip = get_public_ip()
        original_bytes = XRAY_CONFIG.read_bytes()
        original_hash = hashlib.sha256(original_bytes).hexdigest()
        preview = parse_xray_bytes(original_bytes)
        assert_required_topology(preview)
        preview_result = rotate_ids(preview)
        prospective_document = build_streisand_document(preview, public_ip)
        self.telegram.send_document(
            chat_id,
            "brume2-streisand-next.json",
            prospective_document,
            "Prospective profile; Xray will change only after this file is delivered",
            "application/json",
        )
        planned = preview_result["_replacements"]
        result, health, cfg = transactional_update(
            "uuid-rotation",
            lambda candidate: rotate_ids(candidate, planned),
            expected_original_hash=original_hash,
        )
        sync_legacy_uuid_state(cfg)
        self.telegram.send_message(
            chat_id,
            "UUID rotation succeeded. Xray was validated and restarted; listeners %s are healthy. Rotated VMess clients: %d; VLESS clients: %d."
            % (
                ", ".join(str(item) for item in health["listening_ports"]),
                result["counts"]["vmess"],
                result["counts"]["vless"],
            ),
        )

    def command_restart(self, chat_id, reply_to):
        self.telegram.send_message(chat_id, "Validating and restarting Xray…", reply_to)
        health = restart_current_config()
        self.telegram.send_message(
            chat_id,
            "Xray restarted successfully. Healthy listeners: %s"
            % ", ".join(str(item) for item in health["listening_ports"]),
        )

    def command_target(self, chat_id, reply_to, arguments):
        if len(arguments) != 1:
            raise UserError("Usage: /target hostname")
        required_reality_inbound(load_xray_config())
        hostname = normalize_hostname(arguments[0])
        self.telegram.send_message(chat_id, "Checking %s before changing Xray…" % hostname, reply_to)
        preflight = preflight_reality_target(hostname)
        public_ip = get_public_ip()
        original_bytes = XRAY_CONFIG.read_bytes()
        original_hash = hashlib.sha256(original_bytes).hexdigest()
        preview = parse_xray_bytes(original_bytes)
        assert_required_topology(preview)
        update_reality_target(preview, hostname)
        prospective_document = build_streisand_document(preview, public_ip)
        self.telegram.send_document(
            chat_id,
            "brume2-streisand-next.json",
            prospective_document,
            "Prospective profile; REALITY will change only after this file is delivered",
            "application/json",
        )
        result, health, cfg = transactional_update(
            "reality-target",
            lambda candidate: update_reality_target(candidate, hostname),
            expected_original_hash=original_hash,
        )
        self.telegram.send_message(
            chat_id,
            "REALITY target changed to %s:443. Xray was validated and restarted; listeners %s are healthy.\n\n%s"
            % (
                result["hostname"],
                ", ".join(str(item) for item in health["listening_ports"]),
                preflight["summary"],
            ),
        )

    def handle_message(self, message):
        if not self.authorized(message):
            return
        parsed = self.parse_command(message)
        if not parsed:
            return
        command, arguments = parsed
        chat_id = int(message["chat"]["id"])
        reply_to = message.get("message_id")

        mutating = command in ("/restart", "/target") or (
            command == "/rotate" and arguments == ["confirm"]
        )
        message_date = message.get("date")
        if mutating and (
            not isinstance(message_date, int) or message_date < int(time.time()) - 300
        ):
            self.telegram.send_message(
                chat_id,
                "Stale mutating command rejected; send it again while the bot is online.",
                reply_to,
            )
            return

        try:
            if command in ("/start", "/help"):
                self.telegram.send_message(chat_id, HELP_TEXT, reply_to)
            elif command == "/ip":
                self.telegram.send_message(chat_id, "Public IP: %s" % get_public_ip(), reply_to)
            elif command == "/streisand":
                if len(arguments) > 1:
                    raise UserError("Usage: /streisand [user label]")
                self.send_profile(
                    chat_id, "Current Streisand profiles", arguments[0] if arguments else None
                )
            elif command == "/stats":
                self.command_stats(chat_id, reply_to, arguments)
            elif command == "/rotate":
                self.command_rotate(message, arguments)
            elif command == "/restart":
                self.command_restart(chat_id, reply_to)
            elif command == "/target":
                self.command_target(chat_id, reply_to, arguments)
            elif command in ("/tlsping", "/tls"):
                if len(arguments) != 1:
                    raise UserError("Usage: /tlsping hostname")
                result = run_tls_ping(arguments[0])
                self.telegram.send_message(chat_id, result["summary"], reply_to)
            elif command == "/status":
                self.command_status(chat_id, reply_to)
            else:
                self.telegram.send_message(chat_id, "Unknown command. Use /help.", reply_to)
        except UserError as exc:
            self.telegram.send_message(chat_id, "Request rejected: %s" % str(exc), reply_to)
        except TransactionError as exc:
            if exc.rollback_ok is True:
                detail = "The previous configuration was restored and Xray is healthy."
            elif exc.rollback_ok is False:
                detail = "Rollback could not be verified; inspect Xray immediately."
            else:
                detail = "No configuration change was committed."
            self.telegram.send_message(chat_id, "Xray change failed. %s" % detail, reply_to)
            log("xray-transaction-failed", "rollback=%s" % exc.rollback_ok)
        except OperationError as exc:
            self.telegram.send_message(chat_id, "Operation failed: %s" % str(exc), reply_to)
            log("operation-failed", type(exc).__name__)
        except TelegramError:
            log("telegram-reply-failed")
        except Exception as exc:
            try:
                self.telegram.send_message(chat_id, "Operation failed unexpectedly; no secret details were logged.", reply_to)
            except Exception:
                pass
            log("unexpected-command-error", type(exc).__name__)

    def initial_offset(self):
        if OFFSET_FILE.exists():
            try:
                return max(0, int(OFFSET_FILE.read_text(encoding="ascii").strip()))
            except (OSError, ValueError):
                pass
        updates = self.telegram.get_updates(-1, 0)
        offset = 0
        if updates:
            offset = max(int(update.get("update_id", -1)) for update in updates) + 1
        atomic_write(OFFSET_FILE, (str(offset) + "\n").encode("ascii"), 0o600)
        return offset

    def run(self):
        startup_backoff = 2
        while not self.stop_event.is_set():
            try:
                identity = self.telegram.get_me()
                self.bot_username = (identity or {}).get("username")
                webhook = self.telegram.get_webhook_info() or {}
                if webhook.get("url"):
                    raise OperationError(
                        "Telegram webhook is configured; refusing to start long polling"
                    )
                offset = self.initial_offset()
                break
            except TelegramError:
                log("telegram-startup-check-failed")
                self.stop_event.wait(startup_backoff)
                startup_backoff = min(startup_backoff * 2, 60)
        else:
            return
        log("bot-started", "version=%s" % VERSION)
        backoff = 2
        while not self.stop_event.is_set():
            try:
                updates = self.telegram.get_updates(offset, 25)
                backoff = 2
                offset_dirty = False
                for update in sorted(updates, key=lambda item: int(item.get("update_id", -1))):
                    update_id = int(update.get("update_id", -1))
                    message = update.get("message")
                    preadvanced = False
                    if isinstance(message, dict) and self.is_mutating_message(message) and update_id >= offset:
                        offset = update_id + 1
                        atomic_write(OFFSET_FILE, (str(offset) + "\n").encode("ascii"), 0o600)
                        preadvanced = True
                    if isinstance(message, dict):
                        self.handle_message(message)
                    if not preadvanced and update_id >= offset:
                        offset = update_id + 1
                        offset_dirty = True
                if offset_dirty:
                    atomic_write(OFFSET_FILE, (str(offset) + "\n").encode("ascii"), 0o600)
            except TelegramError:
                log("telegram-poll-failed")
                self.stop_event.wait(backoff)
                backoff = min(backoff * 2, 30)
            except Exception as exc:
                log("poll-loop-error", type(exc).__name__)
                self.stop_event.wait(backoff)
                backoff = min(backoff * 2, 30)
        log("bot-stopped")


def self_test():
    settings = load_settings()
    if not settings.allowed_chat_ids:
        raise OperationError("Chat allowlist is empty")
    cfg = load_xray_config()
    assert_required_topology(cfg)
    validate_config_path(XRAY_CONFIG)
    matches = primary_inbounds(cfg)
    document = build_streisand_document(cfg, "192.0.2.1")
    parsed = json.loads(document)
    expected_clients = []
    for protocol in ("vless", "vmess"):
        for _inbound_index, inbound in matches[protocol]:
            for client_index in range(len(inbound_user_list(inbound) or [])):
                _user, client_id, _label = profile_client(inbound, client_index)
                expected_clients.append((protocol, client_id))
    if not isinstance(parsed, list) or len(parsed) != len(expected_clients):
        raise OperationError("Streisand JSON profile count does not match the configured clients")
    exported_clients = [
        (item["outbounds"][0]["protocol"], item["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"])
        for item in parsed
    ]
    if exported_clients != expected_clients:
        raise OperationError("Streisand JSON does not match the configured clients")
    if settings.bot_token in document:
        raise OperationError("Streisand JSON contains the bot token")
    print("self-test ok version=%s" % VERSION)


def notify_ready():
    settings = load_settings()
    telegram = TelegramClient(settings.bot_token)
    cfg = load_xray_config()
    health = health_snapshot(cfg)
    text = (
        "Brume 2 Xray bot is updated and running.\n"
        "Xray status: %s; listeners: %s\n"
        "Use /help to see the available commands."
        % (
            "healthy" if health["running"] and not health["missing_ports"] else "needs attention",
            ", ".join(str(item) for item in health["listening_ports"]) or "none",
        )
    )
    for chat_id in settings.allowed_chat_ids:
        telegram.send_message(chat_id, text)
    print("notification sent")


def main():
    parser = argparse.ArgumentParser(description="Telegram control bot for Brume 2 Xray")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--notify-ready", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.notify_ready:
        notify_ready()
        return

    settings = load_settings()
    process_lock = bot_process_lock()
    bot = Bot(settings)

    def stop(_signum, _frame):
        bot.stop_event.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        bot.run()
    finally:
        fcntl.flock(process_lock.fileno(), fcntl.LOCK_UN)
        process_lock.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        log("fatal", type(exc).__name__)
        sys.exit(1)
