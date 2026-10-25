"""Pinned Streisand/Xray JSON export for the supported Hysteria 2 setup.

This module never prints credentials. The returned document contains selected
client passwords and must only be delivered to an authorized administrator.
Unknown transport/TLS options fail closed rather than producing a guessed
client configuration. Existing VMess/REALITY export is intentionally separate.
"""

import hashlib
import ipaddress
import json
from pathlib import Path
import re
import ssl
import time
from urllib.parse import quote, urlencode


HYSTERIA_CONFIG = Path("/etc/hysteria2/config.json")
DEFAULT_LABELS = Path("/etc/hysteria2/user-labels.json")
MAX_CONFIG_BYTES = 1024 * 1024
MAX_LABEL_BYTES = 64 * 1024
MAX_CERT_BYTES = 128 * 1024
MAX_USERS = 256
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@+-]{0,63}$")
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
TOKEN_RE = re.compile(r"\d{6,12}:[A-Za-z0-9_-]{25,}")
KEY_RE = re.compile(r"[A-Za-z0-9_+/=-]{32,}")
CERT_RE = re.compile(r"\A\s*(-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----)")


class ProfileError(Exception):
    """Safe, non-secret export failure."""


def _read_bounded(path, maximum):
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("size")
        return data
    except (OSError, ValueError, TypeError) as exc:
        raise ProfileError("Hysteria profile source is unavailable or invalid") from exc


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_constant(_value):
    raise ValueError("non-finite JSON value")


def load_config(path=None, maximum=MAX_CONFIG_BYTES):
    try:
        config = json.loads(
            _read_bounded(path or HYSTERIA_CONFIG, maximum),
            object_pairs_hook=_unique_object, parse_constant=_reject_constant,
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProfileError("Hysteria configuration is invalid") from exc
    if not isinstance(config, dict):
        raise ProfileError("Hysteria configuration is invalid")
    return config


def _label_ok(label):
    return (isinstance(label, str) and LABEL_RE.fullmatch(label) and not UUID_RE.search(label)
            and not TOKEN_RE.search(label) and not KEY_RE.search(label))


def _user_labels(users, labels_path=None, extra_secrets=()):
    path = Path(labels_path) if labels_path is not None else DEFAULT_LABELS
    try:
        aliases = load_config(path, MAX_LABEL_BYTES) if path.exists() else {}
    except OSError as exc:
        raise ProfileError("Hysteria user labels are unavailable") from exc
    # Hysteria's userpass authenticator treats account IDs case-insensitively.
    normalized = {account.lower() for account in users}
    if len(normalized) != len(users):
        raise ProfileError("Hysteria account IDs must be unique")
    normalized_aliases = {}
    for account, alias in aliases.items():
        key = account.lower()
        if key not in normalized or key in normalized_aliases:
            raise ProfileError("Hysteria user labels are invalid")
        normalized_aliases[key] = alias
    labels = {account: normalized_aliases.get(account.lower(), account.lower()) for account in users}
    forbidden = {value.casefold() for value in list(users.values()) + list(extra_secrets) if isinstance(value, str) and value}
    if any(not _label_ok(label) or any(secret in label.casefold() for secret in forbidden)
           for label in labels.values()):
        raise ProfileError("Hysteria user labels are invalid")
    if len({label.casefold() for label in labels.values()}) != len(labels):
        raise ProfileError("Hysteria user labels must be unique")
    return labels


def _server_parameters(config):
    # These are the deployed, tested server options. New transport options need
    # explicit exporter support before they can be enabled safely.
    if set(config) - {"listen", "tls", "auth", "acl", "trafficStats"}:
        raise ProfileError("Hysteria export does not support the configured server options")
    tls = config.get("tls")
    if not isinstance(tls, dict) or set(tls) != {"cert", "key"}:
        raise ProfileError("Hysteria export requires the supported certificate TLS setup")
    if not all(isinstance(tls[key], str) and Path(tls[key]).is_absolute() for key in ("cert", "key")):
        raise ProfileError("Hysteria certificate configuration is invalid")
    listen = config.get("listen")
    if not isinstance(listen, str):
        raise ProfileError("Hysteria listener is invalid")
    try:
        host, port_text = listen.rsplit(":", 1)
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        ipaddress.ip_address(host)
        if not re.fullmatch(r"[0-9]{1,5}", port_text):
            raise ValueError("port")
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise ValueError("port")
    except ValueError as exc:
        raise ProfileError("Hysteria listener is invalid") from exc
    auth = config.get("auth")
    if not isinstance(auth, dict) or set(auth) != {"type", "userpass"} or auth.get("type") != "userpass":
        raise ProfileError("Hysteria export requires userpass authentication")
    users = auth["userpass"]
    if not isinstance(users, dict) or not 1 <= len(users) <= MAX_USERS:
        raise ProfileError("Hysteria user configuration is invalid")
    for label, password in users.items():
        if not _label_ok(label) or not isinstance(password, str) or not 1 <= len(password) <= 1024:
            raise ProfileError("Hysteria user configuration is invalid")
        if any(ord(character) < 32 or ord(character) == 127 for character in password):
            raise ProfileError("Hysteria user configuration is invalid")
    return port, tls["cert"], users


def _certificate_pin(path, endpoint):
    try:
        original = _read_bounded(path, MAX_CERT_BYTES)
        match = CERT_RE.match(original.decode("ascii"))
        if not match:
            raise ValueError("leaf")
        leaf = ssl.PEM_cert_to_DER_cert(match.group(1))
        certificate = ssl._ssl._test_decode_cert(str(path))
        if _read_bounded(path, MAX_CERT_BYTES) != original:
            raise ValueError("certificate changed")
        # Require an actual IP SAN: a matching CN is not a substitute.
        addresses = [ipaddress.ip_address(value) for kind, value in certificate.get("subjectAltName", ())
                     if kind == "IP Address"]
        if endpoint not in addresses:
            raise ValueError("endpoint does not match IP SAN")
        now = time.time()
        if not ssl.cert_time_to_seconds(certificate["notBefore"]) <= now < ssl.cert_time_to_seconds(certificate["notAfter"]):
            raise ValueError("validity")
        return hashlib.sha256(leaf).hexdigest()
    except (OSError, ValueError, TypeError, UnicodeError, KeyError, ssl.SSLError) as exc:
        raise ProfileError("Hysteria certificate is unavailable, expired, or does not match the public IP") from exc


def build_document(address, user_filter=None, config_path=None, labels_path=None, excluded_users=()):
    """Return a JSON array for all users, or one exact case-sensitive label.

    The caller obtains the current public IP independently. An IP change that
    does not match the certificate SAN fails safely; insecure TLS is never used.
    """
    try:
        endpoint = ipaddress.ip_address(address)
    except (ValueError, TypeError) as exc:
        raise ProfileError("Hysteria export requires a valid public IP") from exc
    if user_filter is not None and not _label_ok(user_filter):
        raise ProfileError("Use a configured Hysteria user label")
    config = load_config(config_path)
    port, certificate_path, users = _server_parameters(config)
    traffic = config.get("trafficStats", {})
    labels = _user_labels(users, labels_path, (traffic.get("secret"),) if isinstance(traffic, dict) else ())
    excluded = {account.lower() for account in excluded_users}
    selected = [account for account in users if account.lower() not in excluded
                and (user_filter is None or labels[account] == user_filter)]
    if not selected:
        raise ProfileError("Hysteria user label was not found")
    selected.sort(key=lambda account: labels[account])
    pin = _certificate_pin(certificate_path, endpoint)
    profiles = []
    for account in selected:
        label = labels[account]
        profiles.append({
            "remarks": "Brume 2 - %s - Hysteria 2" % label,
            "log": {"loglevel": "warning"},
            "inbounds": [
                {"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
                 "settings": {"auth": "noauth", "udp": True}},
                {"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http", "settings": {}},
            ],
            "outbounds": [{
                "tag": "proxy", "protocol": "hysteria",
                "settings": {"version": 2, "address": str(endpoint), "port": port},
                "streamSettings": {
                    "network": "hysteria", "security": "tls",
                    "tlsSettings": {"serverName": str(endpoint), "alpn": ["h3"], "pinnedPeerCertSha256": pin},
                    "hysteriaSettings": {"version": 2, "auth": account + ":" + users[account]},
                },
            }],
            "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
            "routing": {"domainStrategy": "AsIs", "rules": []},
        })
    return json.dumps(profiles, indent=2, allow_nan=False) + "\n"


def build_links_document(address, user_filter=None, config_path=None, labels_path=None, excluded_users=()):
    """Derive private Hysteria 2 import links from the validated JSON export.

    ``pcs`` is an Xray-importer extension for the certificate pin; ``pinSHA256``
    is the Hysteria spelling. Neither guarantees that a particular mobile
    importer preserves the pin. These links intentionally omit ``insecure``:
    a native Hysteria client still needs CA trust for a self-signed certificate.
    Use the pinned JSON when the importing client cannot preserve the pin.
    """
    try:
        profiles = json.loads(build_document(address, user_filter, config_path, labels_path, excluded_users))
        if not isinstance(profiles, list) or not 1 <= len(profiles) <= MAX_USERS:
            raise ValueError("profiles")
        links = []
        for profile in profiles:
            outbound, = profile["outbounds"]
            destination = outbound["settings"]
            stream = outbound["streamSettings"]
            tls = stream["tlsSettings"]
            transport = stream["hysteriaSettings"]
            # Do not silently discard future transport or TLS options.
            if (outbound["protocol"] != "hysteria"
                    or set(destination) != {"version", "address", "port"}
                    or destination["version"] != 2
                    or set(stream) != {"network", "security", "tlsSettings", "hysteriaSettings"}
                    or stream["network"] != "hysteria" or stream["security"] != "tls"
                    or set(transport) != {"version", "auth"} or transport["version"] != 2
                    or set(tls) != {"serverName", "alpn", "pinnedPeerCertSha256"}
                    or tls["alpn"] != ["h3"]):
                raise ValueError("unsupported profile")
            endpoint = ipaddress.ip_address(destination["address"])
            if tls["serverName"] != str(endpoint):
                raise ValueError("server name")
            port = destination["port"]
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("port")
            pin = tls["pinnedPeerCertSha256"]
            if not isinstance(pin, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", pin):
                raise ValueError("certificate pin")
            auth = transport["auth"]
            account, password = auth.split(":", 1)
            if (not account or not password
                    or any(ord(character) < 32 or ord(character) == 127 for character in auth)):
                raise ValueError("authentication")
            label = profile["remarks"]
            if (not isinstance(label, str) or not label
                    or any(ord(character) < 32 or ord(character) == 127 for character in label)):
                raise ValueError("label")
            authority = "[%s]" % endpoint if endpoint.version == 6 else str(endpoint)
            query = urlencode({"sni": str(endpoint), "pinSHA256": pin, "pcs": pin}, quote_via=quote)
            links.append("hysteria2://%s:%s@%s:%s/?%s#%s" % (
                quote(account, safe=""), quote(password, safe=""), authority, port,
                query, quote(label, safe=""),
            ))
        return "\n".join(links) + "\n"
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise ProfileError("Hysteria profile cannot be safely exported as a link") from exc


def build_hiddify_document(address, user_filter=None, config_path=None, labels_path=None, excluded_users=()):
    """Self-contained sing-box/Hiddify profile, with the verified public certificate.

    Hiddify's Hysteria URI importer drops pinSHA256/pcs. Inline CA trust avoids
    requiring an extra certificate file and keeps TLS verification enabled.
    """
    profiles = json.loads(build_document(address, user_filter, config_path, labels_path, excluded_users))
    config = load_config(config_path)
    _port, certificate_path, _users = _server_parameters(config)
    try:
        match = CERT_RE.match(_read_bounded(certificate_path, MAX_CERT_BYTES).decode("ascii"))
        if not match:
            raise ValueError("certificate")
        certificate = match.group(1).strip() + "\n"
        pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()
        outbounds = []
        for profile in profiles:
            outbound, = profile["outbounds"]
            stream = outbound["streamSettings"]
            tls = stream["tlsSettings"]
            if pin != tls["pinnedPeerCertSha256"]:
                raise ValueError("certificate changed during export")
            outbounds.append({
                "type": "hysteria2", "tag": profile["remarks"] + " - Hiddify",
                "server": outbound["settings"]["address"], "server_port": outbound["settings"]["port"],
                "password": stream["hysteriaSettings"]["auth"],
                "tls": {"enabled": True, "server_name": tls["serverName"], "certificate": [certificate]},
            })
        return json.dumps({"outbounds": outbounds}, separators=(",", ":"), allow_nan=False)
    except (ValueError, KeyError, TypeError, UnicodeError) as exc:
        raise ProfileError("Hiddify profile cannot be safely exported") from exc
