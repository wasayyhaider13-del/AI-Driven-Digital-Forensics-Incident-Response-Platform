import os
import time
import signal
import datetime
import hashlib
import sqlite3
from typing import List, Dict, Optional

try:
    import schedule
except ImportError:
    import sys
    print("[ERROR] 'schedule' module not found. Install it with: pip install schedule")
    sys.exit(1)

try:
    from colorama import Fore, Style, init
except ImportError:
    import sys
    print("[ERROR] 'colorama' module not found. Install it with: pip install colorama")
    sys.exit(1)

import config
from extractor import extract_chrome_history
from timeline import reconstruct_timeline
from ioc_detector import detect_iocs
from llm_classifier import classify_all_events
from alerter import send_alerts
from utils import save_logs

init(autoreset=True)


# ── Persistent Storage (NO MEMORY LEAK) ─────────────────────────────

DB_PATH = "monitor_state.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS seen (
            hash TEXT PRIMARY KEY
        )
    """)
    conn.commit()
    conn.close()


def is_seen(h: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM seen WHERE hash=?", (h,))
    row = cur.fetchone()
    conn.close()
    return row is not None


def mark_seen(h: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO seen(hash) VALUES (?)", (h,))
    conn.commit()
    conn.close()


# ── State ───────────────────────────────────────────────────────────

class MonitorState:
    def __init__(self, interval: int):
        self.interval = interval
        self.running = True
        self.scan_count = 0
        self.total_events = 0
        self.total_flagged = 0
        self.total_alerts = 0
        self.last_scan = "Never"
        self.is_running = False


def record_hash(url: str, ts) -> str:
    return hashlib.sha256(f"{url}|{ts}".encode()).hexdigest()


# ── Dashboard ───────────────────────────────────────────────────────

def render(state: MonitorState):
    os.system("cls" if os.name == "nt" else "clear")

    print(Fore.CYAN + "═" * 60)
    print(" DFIR REAL-TIME MONITOR (UPGRADED)")
    print(Fore.CYAN + "═" * 60)

    print(f"Last Scan   : {state.last_scan}")
    print(f"Scan #      : {state.scan_count}")
    print(f"Events      : {state.total_events}")
    print(f"Flagged     : {state.total_flagged}")
    print(f"Alerts      : {state.total_alerts}")

    print(Fore.CYAN + "═" * 60)
    print(f"Next scan in {state.interval}s | Ctrl+C to stop")
    print(Fore.CYAN + "═" * 60)


# ── Scan Pipeline ───────────────────────────────────────────────────

def run_scan(state: MonitorState):

    if state.is_running:
        return

    state.is_running = True
    try:
        state.scan_count += 1
        now = datetime.datetime.now().strftime("%H:%M:%S")

        print(f"\n[SCAN] #{state.scan_count} @ {now}")

        # 1. Extract
        try:
            records = extract_chrome_history()
        except Exception as e:
            print(f"[ERROR] Extract failed: {e}")
            return

        if not records:
            state.last_scan = now
            render(state)
            return

        # 2. Dedup using SQLite
        new_records = []
        for r in records:
            h = record_hash(r.get("url", ""), r.get("raw_ts", ""))

            if not is_seen(h):
                mark_seen(h)
                new_records.append(r)

        if not new_records:
            state.last_scan = now
            render(state)
            return

        # 3. Timeline
        try:
            timeline = reconstruct_timeline(new_records)
        except Exception as e:
            print(f"[ERROR] Timeline: {e}")
            return

        state.total_events += len(timeline)

        # 4. IOC Detection
        try:
            flagged = detect_iocs(timeline)
        except Exception as e:
            print(f"[ERROR] IOC: {e}")
            flagged = []

        state.total_flagged += len(flagged)

        # 5. LLM Classification
        try:
            classified = classify_all_events(flagged) if flagged else []
        except Exception as e:
            print(f"[ERROR] LLM: {e}")
            classified = []

        # 6. Save Logs for Dashboard
        try:
            save_logs(classified)
            print(f"[LOGS] Saved {len(classified)} events to disk.")
        except Exception as e:
            print(f"[ERROR] Save Logs: {e}")

        # 7. Alerts
        try:
            sent = send_alerts(classified)
        except Exception as e:
            print(f"[ERROR] Alerts: {e}")
            sent = 0

        state.total_alerts += sent

        # 8. Dashboard update
        state.last_scan = now
        render(state)

    finally:
        state.is_running = False


# ── Main ────────────────────────────────────────────────────────────

def start_monitor(interval: Optional[int] = None):

    interval = interval or config.SCAN_INTERVAL_SECONDS
    state = MonitorState(interval)

    init_db()

    def shutdown(sig, frame):
        state.running = False
        print("\n[MONITOR] Shutting down safely...")

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print(f"[MONITOR] Started | Interval: {interval}s")

    run_scan(state)

    schedule.every(interval).seconds.do(lambda: run_scan(state))

    while state.running:
        schedule.run_pending()
        time.sleep(1)

    print(
        f"[DONE] Events={state.total_events} "
        f"Flagged={state.total_flagged} "
        f"Alerts={state.total_alerts}"
    )


if __name__ == "__main__":
    start_monitor()