"""
extractor.py — Chromium Browser History Extractor
Reads SQLite history from Chrome or Edge (whichever is available).
"""

import os
import sys
import shutil
import sqlite3
import datetime
import tempfile
from typing import List, Dict, Tuple

import config


def _browser_history_paths() -> List[Tuple[str, str]]:
    """Return (path, browser_name) pairs to try, in priority order."""
    if sys.platform == "win32":
        return [
            (os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History"), "Chrome"),
            (os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History"), "Edge"),
        ]
    if sys.platform == "darwin":
        return [
            (os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/History"), "Chrome"),
            (os.path.expanduser("~/Library/Application Support/Microsoft Edge/Default/History"), "Edge"),
        ]
    return [
        (os.path.expanduser("~/.config/google-chrome/Default/History"), "Chrome"),
        (os.path.expanduser("~/.config/microsoft-edge/Default/History"), "Edge"),
    ]


def _chrome_history_path() -> str:
    """Return first available browser History SQLite path."""
    for path, _ in _browser_history_paths():
        if os.path.exists(path):
            return path
    return _browser_history_paths()[0][0]


def _chrome_ts_to_dt(chrome_ts: int) -> datetime.datetime:
    """Convert Chromium microsecond timestamp (since 1601) to datetime."""
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=chrome_ts)


def _read_history_db(db_path: str, browser: str, limit: int) -> List[Dict]:
    """Read history records from a copied SQLite database."""
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
                dt = datetime.datetime.now(datetime.timezone.utc)

            records.append({
                "url":           url or "",
                "title":         title or "",
                "visit_time":    dt.strftime("%Y-%m-%d %H:%M:%S"),
                "visit_time_dt": dt,
                "visit_count":   visit_count or 1,
                "raw_ts":        raw_ts,
                "browser":       browser,
            })

        conn.close()
        print(f"[EXTRACTOR] Extracted {len(records)} records from {browser} history.")
        return records

    except sqlite3.Error as exc:
        print(f"[EXTRACTOR ERROR] SQLite error ({browser}): {exc}")
        return []

    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def extract_chrome_history(limit: int = None) -> List[Dict]:  # type: ignore
    """
    Extract browser history from Chrome or Edge SQLite database.

    Returns list of record dicts with keys:
      url, title, visit_time, visit_time_dt, visit_count, raw_ts, browser
    """
    limit = limit or getattr(config, "CHROME_HISTORY_LIMIT", 200)

    for db_path, browser in _browser_history_paths():
        if not os.path.exists(db_path):
            continue
        records = _read_history_db(db_path, browser, limit)
        if records:
            return records

    tried = ", ".join(p for p, _ in _browser_history_paths())
    print(f"[EXTRACTOR] No browser history found. Checked: {tried}")
    return []


if __name__ == "__main__":
    rows = extract_chrome_history(limit=10)
    for r in rows:
        print(r["visit_time"], r.get("browser", "?"), r["url"][:80])
    print(f"\nTotal: {len(rows)}")
