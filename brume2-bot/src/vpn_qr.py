"""Offline QR encoding. No network requests, subprocesses, or temporary secrets."""
import io
import json
import sys

# Pinned, vendored Segno 1.6.6; isolated from the router's system packages.
VENDOR_PATH = '/usr/lib/vpn-qr'
if VENDOR_PATH not in sys.path:
    sys.path.insert(0, VENDOR_PATH)


def qr_png(link, payload_format="uri", profile_title=None):
    if (not isinstance(link, str) or len(link.encode('utf-8')) > 2000
            or '\n' in link or '\r' in link):
        raise ValueError('Invalid QR payload')
    if payload_format == "uri":
        if not link.startswith("hysteria2://"):
            raise ValueError("Invalid URI payload")
    elif payload_format == "hiddify":
        try:
            document = json.loads(link)
            outbound, = document["outbounds"]
            tls = outbound["tls"]
            if (set(document) != {"outbounds"} or outbound["type"] != "hysteria2"
                    or tls.get("enabled") is not True or tls.get("insecure", False) is not False
                    or not tls.get("certificate")):
                raise ValueError()
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ValueError("Invalid Hiddify payload") from None
    else:
        raise ValueError("Unknown QR format")
    if profile_title is not None:
        if (payload_format != "hiddify" or not isinstance(profile_title, str)
                or not 1 <= len(profile_title) <= 128
                or any(ord(c) < 32 or ord(c) == 127 for c in profile_title)):
            raise ValueError("Invalid profile title")
        # Hiddify reads this metadata before passing JSONC to its core.
        link = "// profile-title: " + profile_title + "\n" + link
        if len(link.encode("utf-8")) > 2000:
            raise ValueError("QR payload too large")
    import segno
    output = io.BytesIO()
    segno.make_qr(link, error='m').save(output, kind='png', scale=8, border=4)
    return output.getvalue()
