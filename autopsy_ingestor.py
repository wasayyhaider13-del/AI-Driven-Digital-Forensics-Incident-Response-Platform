"""
autopsy_ingestor.py — Autopsy Forensic Export Ingestor
========================================================
Reads CSV or XLSX exports from Autopsy (open-source DFIR platform
by Basis Technology) and converts them into IOC-ready pipeline records.

Supports:
  - Autopsy "Web History" CSV/XLSX exports
  - Autopsy "Tagged Files" XLSX exports
  - Generic browser history CSVs
  - Auto-detects column names (Autopsy versions vary)

How to export from Autopsy:
  1. Open Autopsy → Open your case / disk image
  2. Tools → Generate Report
  3. Choose "Excel/CSV" → select "Web History" or "Recent Activity"
  4. Save and pass path here

Install dependency: pip install openpyxl
"""

import os
import io
import datetime
from typing import List, Dict, Optional
from urllib.parse import urlparse

try:
    import pandas as pd
    _HAS_PANDAS = True
except ImportError:
    _HAS_PANDAS = False

try:
    import openpyxl
    _HAS_OPENPYXL = True
except ImportError:
    _HAS_OPENPYXL = False

# ── Column name variants across Autopsy versions ──────────────────────────────
POSSIBLE_URL_COLS   = ["URL","url","Domain","Url","Web Address","Address","Source File",
                        "File","Path","Location"]
POSSIBLE_TIME_COLS  = ["Date/Time","Timestamp","Last Accessed","Date Accessed",
                        "Access Time","datetime","Date","Modified Time","Created Time",
                        "Accessed Time","Changed Time"]
POSSIBLE_TITLE_COLS = ["Title","Page Title","title","Description","Comment","Tag"]
POSSIBLE_COUNT_COLS = ["Visit Count","Frequency","Count","visit_count","Hits"]

SUSPICIOUS_TLDS     = [".onion",".xyz",".tk",".ml",".cf",".ga",".cc",".to",".su"]
SUSPICIOUS_KEYWORDS = ["phishing","payload","exploit","c2","botnet","shell",
                       "malware","darkweb","ransomware","keylogger","stealer",
                       "dropper","rat","mimikatz","cobalt","metasploit"]


def _pick_col(cols: List[str], candidates: List[str]) -> Optional[str]:
    """Return first matching column from candidates list."""
    for c in candidates:
        if c in cols:
            return c
    # case-insensitive fallback
    cols_lower = {c.lower(): c for c in cols}
    for c in candidates:
        if c.lower() in cols_lower:
            return cols_lower[c.lower()]
    return None


def _score_url(url: str):
    """Return (severity, reason) for a URL."""
    url_lower = url.lower()
    reasons   = []
    severity  = "LOW"
    try:
        hostname = urlparse(url).hostname or ""
    except Exception:
        hostname = ""

    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            reasons.append(f"Suspicious TLD: {tld}")
            severity = "MEDIUM"
            break

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url_lower:
            reasons.append(f"Suspicious keyword: '{kw}'")
            severity = "HIGH"
            break

    return severity, (" | ".join(reasons) if reasons else "Autopsy forensic record")


def _parse_timestamp(raw: str) -> datetime.datetime:
    """Try multiple timestamp formats used by Autopsy."""
    for fmt in ["%Y-%m-%d %H:%M:%S","%Y-%m-%dT%H:%M:%S","%m/%d/%Y %H:%M:%S",
                "%d/%m/%Y %H:%M:%S","%Y-%m-%d %H:%M:%S.%f","%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d","%d/%m/%Y","%m/%d/%Y"]:
        try:
            return datetime.datetime.strptime(str(raw).strip(), fmt)
        except ValueError:
            continue
    return datetime.datetime.utcnow()


def _df_to_records(df, source_label: str = "autopsy") -> List[Dict]:
    """Convert any DataFrame into IOC-ready pipeline records."""
    if df is None or df.empty:
        return []

    cols      = list(df.columns)
    url_col   = _pick_col(cols, POSSIBLE_URL_COLS)
    time_col  = _pick_col(cols, POSSIBLE_TIME_COLS)
    title_col = _pick_col(cols, POSSIBLE_TITLE_COLS)
    count_col = _pick_col(cols, POSSIBLE_COUNT_COLS)

    if not url_col:
        print(f"[AUTOPSY] No URL column found. Columns: {cols}")
        return []
    if not time_col:
        # Use current time if no timestamp column
        print(f"[AUTOPSY] No timestamp column — using current time. Columns: {cols}")

    records = []
    for _, row in df.iterrows():
        try:
            url = str(row[url_col]).strip()
            if not url or url.lower() in ("nan","none","","n/a"):
                continue

            raw_t = str(row[time_col]).strip() if time_col else ""
            dt    = _parse_timestamp(raw_t) if raw_t and raw_t.lower() not in ("nan","none","") \
                    else datetime.datetime.utcnow()

            title = str(row[title_col]).strip() if title_col else ""
            if title.lower() in ("nan","none"): title = ""

            count = 1
            if count_col:
                try: count = int(float(str(row[count_col])))
                except: count = 1

            severity, reason = _score_url(url)

            records.append({
                "url":           url,
                "title":         title or url,
                "visit_time":    dt.strftime("%Y-%m-%d %H:%M:%S"),
                "visit_time_dt": dt,
                "visit_count":   count,
                "raw_ts":        int(dt.timestamp()),
                "severity":      severity,
                "matched_rule":  "AUTOPSY_IMPORT",
                "reason":        reason,
                "source":        source_label,
            })
        except Exception:
            continue

    return records


def _load_xlsx(file_path: str) -> List[Dict]:
    """
    Load an Autopsy XLSX export. Tries all sheets and returns
    records from whichever sheet has real URL data.
    """
    if not _HAS_OPENPYXL:
        print("[AUTOPSY] openpyxl not installed. Run: pip install openpyxl")
        return []

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        xl = pd.ExcelFile(io.BytesIO(data), engine="openpyxl")
        all_records = []

        for sheet in xl.sheet_names:
            try:
                df = xl.parse(sheet)
                if df.empty: continue
                recs = _df_to_records(df, source_label=f"autopsy_xlsx:{sheet}")
                if recs:
                    print(f"[AUTOPSY] Sheet '{sheet}': {len(recs)} records")
                    all_records.extend(recs)
            except Exception as e:
                print(f"[AUTOPSY] Sheet '{sheet}' error: {e}")
                continue

        return all_records

    except Exception as e:
        print(f"[AUTOPSY ERROR] Cannot read XLSX: {e}")
        return []


def _load_csv(file_path: str) -> List[Dict]:
    """Load a plain CSV export."""
    for enc in ["utf-8", "latin-1", "cp1252"]:
        try:
            df = pd.read_csv(file_path, encoding=enc, on_bad_lines="skip")
            return _df_to_records(df, source_label="autopsy_csv")
        except UnicodeDecodeError:
            continue
        except Exception as e:
            print(f"[AUTOPSY ERROR] {e}")
            return []
    return []


# ── Main entry point ──────────────────────────────────────────────────────────

def load_autopsy_data(file_path: str = "autopsy_data.csv") -> List[Dict]:
    """
    Load an Autopsy CSV or XLSX export and return IOC-ready pipeline records.

    Automatically detects file format (CSV or Excel/XLSX).
    Returns empty list if file not found or has no usable data.

    Args:
        file_path: Path to Autopsy export file (.csv or .xlsx)

    Returns:
        List of IOC-ready record dicts compatible with detect_iocs()
    """
    print(f"[AUTOPSY] Loading: {file_path}")

    if not os.path.exists(file_path):
        print(f"[AUTOPSY] File not found: {file_path}")
        print("[AUTOPSY] Export from Autopsy: Tools → Generate Report → Excel/CSV → Web History")
        return []

    if not _HAS_PANDAS:
        print("[AUTOPSY] pandas not installed. Run: pip install pandas")
        return []

    # Detect format by reading magic bytes (PK = ZIP = XLSX)
    with open(file_path, "rb") as f:
        magic = f.read(4)

    is_xlsx = magic[:2] == b"PK"

    if is_xlsx:
        print("[AUTOPSY] Detected Excel (.xlsx) format")
        records = _load_xlsx(file_path)
    else:
        print("[AUTOPSY] Detected CSV format")
        records = _load_csv(file_path)

    if not records:
        print("[AUTOPSY] No records found. The Autopsy export may be empty "
              "(case has no data sources, or no web history was found).")
        print("[AUTOPSY] For demo purposes, use: create_demo_csv()")
        return []

    high = sum(1 for r in records if r["severity"]=="HIGH")
    med  = sum(1 for r in records if r["severity"]=="MEDIUM")
    low  = sum(1 for r in records if r["severity"]=="LOW")
    print(f"[AUTOPSY] Loaded {len(records)} records — HIGH:{high} MEDIUM:{med} LOW:{low}")
    return records


def create_demo_csv(path: str = "autopsy_demo.csv") -> str:
    """
    Create a realistic demo Autopsy CSV export for presentations.
    Use this when you don't have a real Autopsy case to demonstrate.
    """
    import csv
    rows = [
        ["URL","Title","Date/Time","Visit Count"],
        ["https://google.com","Google Search","2026-04-29 09:00:00",5],
        ["https://github.com","GitHub","2026-04-29 09:15:00",3],
        ["http://evil-c2.onion/panel","C2 Panel","2026-04-29 02:30:00",15],
        ["https://phish-bank.ru/login","Banking Login","2026-04-29 02:45:00",3],
        ["https://malware-drop.xyz/payload.exe","Payload Download","2026-04-29 02:50:00",1],
        ["https://stackoverflow.com","Stack Overflow","2026-04-29 10:00:00",8],
        ["http://botnet.cc/cmd","Botnet Command","2026-04-29 03:00:00",22],
        ["https://youtube.com","YouTube","2026-04-29 11:00:00",4],
        ["https://cred-steal.tk/harvest","Credential Harvester","2026-04-29 03:15:00",7],
        ["https://mail.google.com","Gmail","2026-04-29 12:00:00",6],
        ["https://grabify.link/abc123","IP Logger","2026-04-29 03:30:00",2],
        ["https://docs.python.org","Python Docs","2026-04-29 13:00:00",9],
        ["http://ransomware-c2.io/beacon","Ransomware C2","2026-04-29 03:45:00",45],
        ["https://reddit.com","Reddit","2026-04-29 14:00:00",11],
        ["http://iplogger.org/track","IP Logger","2026-04-29 04:00:00",3],
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(rows)
    print(f"[AUTOPSY] Demo CSV created: {path}")
    return path


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "autopsy_data.csv"

    # If file doesn't exist or is empty, create demo
    recs = load_autopsy_data(path)
    if not recs:
        print("\n[AUTOPSY] Creating demo CSV for testing...")
        demo_path = create_demo_csv()
        recs = load_autopsy_data(demo_path)

    print(f"\nTotal : {len(recs)}")
    for r in recs[:5]:
        print(f"  [{r['severity']}] {r['url'][:60]} — {r['reason'][:50]}")