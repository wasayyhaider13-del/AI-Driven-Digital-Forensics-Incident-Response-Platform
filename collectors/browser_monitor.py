"""
collectors/browser_monitor.py — Chrome History Forensic Collector
==================================================================
EDR Collector Agent: Locates, copies, and extracts history records
from the Chrome SQLite database, resolving DB locking issues.
"""

import os
import sys
import shutil
import sqlite3
import datetime
import tempfile
from typing import List, Dict

import config

def _chrome_history_path() -> str:
    """Return the OS-specific path to Chrome's History SQLite file."""
    if sys.platform == "win32":
        return os.path.expandvars(
            r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History"
        )
    elif sys.platform == "darwin":
        return os.path.expanduser(
            "~/Library/Application Support/Google/Chrome/Default/History"
        )
    else:  # Linux
        return os.path.expanduser(
            "~/.config/google-chrome/Default/History"
        )

def _chrome_ts_to_dt(chrome_ts: int) -> datetime.datetime:
    """Convert Chrome microsecond timestamp (since 1601) to datetime."""
    epoch_delta = datetime.timedelta(microseconds=chrome_ts)
    chrome_epoch = datetime.datetime(1601, 1, 1)
    return chrome_epoch + epoch_delta

def extract_chrome_history(limit: int = None) -> List[Dict]:
    """
    Extract browser history from Chrome's SQLite database.
    """
    limit = limit or getattr(config, "CHROME_HISTORY_LIMIT", 200)
    db_path = _chrome_history_path()

    if not os.path.exists(db_path):
        print(f"[BROWSER MONITOR] Chrome history not found at: {db_path}")
        return []

    # Copy to temp file to avoid locks
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        shutil.copy2(db_path, tmp_path)

        conn = sqlite3.connect(tmp_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT url, title, last_visit_time, visit_count
            FROM   urls
            ORDER  BY last_visit_time DESC
            LIMIT  ?
        """, (limit,))

        records: List[Dict] = []
        for url, title, raw_ts, visit_count in cursor.fetchall():
            try:
                dt = _chrome_ts_to_dt(raw_ts)
            except (OverflowError, OSError, ValueError):
                dt = datetime.datetime.utcnow()

            records.append({
                "url":           url or "",
                "title":         title or "",
                "visit_time":    dt.strftime("%Y-%m-%d %H:%M:%S"),
                "visit_time_dt": dt,
                "visit_count":   visit_count or 1,
                "raw_ts":        raw_ts,
                "event_type":    "Browser",
                "source":        "chrome_history"
            })

        conn.close()
        print(f"[BROWSER MONITOR] Extracted {len(records)} records from Chrome history.")
        return records

    except sqlite3.Error as exc:
        print(f"[BROWSER MONITOR ERROR] SQLite error: {exc}")
        return []

    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

if __name__ == "__main__":
    rows = extract_chrome_history(limit=5)
    print(f"Extracted: {len(rows)} records.")
