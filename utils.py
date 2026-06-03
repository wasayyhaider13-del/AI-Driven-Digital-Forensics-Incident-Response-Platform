"""
utils.py — Log Save/Load Utilities
Handles datetime serialization so JSON never crashes on visit_time_dt objects.
"""
import json
import os
import datetime
import config


class _DTEncoder(json.JSONEncoder):
    """Serialize datetime objects to ISO strings."""
    def default(self, obj):
        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        return super().default(obj)


def save_logs(events):
    """Save classified events to disk, safely handling datetime objects."""
    os.makedirs("logs", exist_ok=True)
    clean = []
    for e in events:
        row = {}
        for k, v in e.items():
            if isinstance(v, (datetime.datetime, datetime.date)):
                row[k] = v.isoformat()
            else:
                row[k] = v
        clean.append(row)
    with open(config.LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(clean, f, indent=4, cls=_DTEncoder)


def load_logs():
    """Load classified events from disk."""
    if not os.path.exists(config.LOG_FILE):
        return []
    try:
        with open(config.LOG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return []