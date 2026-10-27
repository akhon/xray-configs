"""Bounded traffic-only interchange shared by the RAM cache and Mac archive."""
import math
import time
import uuid
from pathlib import Path

MAX_ROWS = 5000
MAX_BYTES = 16 * 1024 * 1024


def boot_id():
    return str(uuid.UUID(Path('/proc/sys/kernel/random/boot_id').read_text().strip()))


def valid_boot_id(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError('Invalid boot ID')
    return value


def validate_rows(rows):
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise ValueError('Invalid row count')
    for row in rows:
        if not isinstance(row, list) or len(row) != 5:
            raise ValueError('Invalid row')
        t, protocol, epoch, counters, error = row
        if type(t) not in (int, float) or not math.isfinite(t) or not 0 <= t <= time.time() + 300:
            raise ValueError('Invalid timestamp')
        if protocol not in ('Hysteria 2', 'Xray') or not isinstance(epoch, str) or len(epoch) > 200:
            raise ValueError('Invalid source')
        if type(error) is not int or error not in (0, 1) or not isinstance(counters, dict):
            raise ValueError('Invalid counters')
        for key, value in counters.items():
            if not isinstance(key, str) or not 0 < len(key) < 129 or not isinstance(value, dict):
                raise ValueError('Invalid account')
            if set(value) != {'label', 'up', 'down'} or not isinstance(value['label'], str) or len(value['label']) > 200:
                raise ValueError('Invalid label')
            if any(type(value[d]) is not int or not 0 <= value[d] < 2**63 for d in ('up', 'down')):
                raise ValueError('Invalid counter')
    return rows
