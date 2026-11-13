#!/usr/bin/env python3
"""Refuse to start an unpatched server when per-account limits are configured."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

FEATURE = "maxSessionsPerUser/v1"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate configuration key")
        result[key] = value
    return result


def check(config, binary):
    with Path(config).open("rb") as source:
        data = source.read(4 * 1024 * 1024 + 1)
    if len(data) > 4 * 1024 * 1024:
        raise ValueError("configuration too large")
    settings = json.loads(data, object_pairs_hook=unique_object)
    if not isinstance(settings, dict):
        raise ValueError("invalid configuration")
    limit = settings.get("maxSessionsPerUser", 0)
    if type(limit) is not int or not 0 <= limit <= 2147483647:
        raise ValueError("invalid session limit")
    if limit:
        result = subprocess.run([str(binary), "version"], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=10, check=True)
        features = [line.split(":", 1)[1].strip() for line in result.stdout.decode("utf-8").splitlines()
                    if line.startswith("Features:")]
        if features != [FEATURE]:
            raise ValueError("server lacks required session-limit support")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/hysteria2/config.json")
    parser.add_argument("--binary", default="/usr/bin/hysteria")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        check(args.config, args.binary)
        if not args.check_only:
            # exec preserves procd supervision and Hysteria's process identity.
            os.execv(args.binary, [args.binary, "server", "--config", args.config,
                                  "--disable-update-check", "--log-level", "warn", "--log-format", "json"])
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Hysteria startup refused: invalid configuration or missing session-limit support.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
