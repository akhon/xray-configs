"""Shared, fail-closed feature switches for the bot and scheduled/CLI stats."""

import json
from pathlib import Path


BOT_CONFIG = Path("/etc/xray/telegram_bot.json")
MAX_SETTINGS_BYTES = 64 * 1024


class FeatureError(ValueError):
    pass


def parse_vmess_enabled(settings):
    """Legacy Xray functionality is opt-in; never coerce strings or integers."""
    if not isinstance(settings, dict):
        raise FeatureError("VPN feature settings are invalid.")
    enabled = settings.get("vmess_enabled", False)
    if type(enabled) is not bool:
        raise FeatureError("vmess_enabled must be a JSON boolean.")
    return enabled


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError()


def load_vmess_enabled(config_path=None):
    """Missing settings disable VMess; malformed/unreadable settings fail safely.

    Read only the feature switch. Tokens and allowlists are never returned,
    printed, or included in error messages.
    """
    try:
        with Path(config_path if config_path is not None else BOT_CONFIG).open("rb") as handle:
            payload = handle.read(MAX_SETTINGS_BYTES + 1)
        if len(payload) > MAX_SETTINGS_BYTES:
            raise ValueError()
        settings = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object,
                              parse_constant=_reject_constant)
        return parse_vmess_enabled(settings)
    except FileNotFoundError:
        return False
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise FeatureError("Cannot read valid VPN feature settings.") from None
