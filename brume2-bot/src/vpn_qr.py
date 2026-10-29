"""Offline QR encoding. No network requests, subprocesses, or temporary secrets."""
import io
import sys

# Pinned, vendored Segno 1.6.6; isolated from the router's system packages.
VENDOR_PATH = '/usr/lib/vpn-qr'
if VENDOR_PATH not in sys.path:
    sys.path.insert(0, VENDOR_PATH)


def qr_png(link):
    if (not isinstance(link, str) or len(link.encode('utf-8')) > 2000
            or '\n' in link or '\r' in link or not link.startswith("hysteria2://")):
        raise ValueError('Invalid Hysteria 2 URI payload')
    import segno
    output = io.BytesIO()
    segno.make_qr(link, error='m').save(output, kind='png', scale=8, border=4)
    return output.getvalue()
