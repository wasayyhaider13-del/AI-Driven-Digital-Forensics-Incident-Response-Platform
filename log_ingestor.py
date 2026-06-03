"""
log_ingestor.py — Windows Event Log & System Log Ingestor
===========================================================
DFIR Module 10: Reads Windows Security Event Logs and system logs
using the built-in 'wevtutil' command-line tool (no external install
needed — it ships with every Windows system).

This counts as an external forensic tool integration alongside Tshark
and Autopsy, and surfaces login events, process creation, and account
changes as IOC-ready records for the main DFIR pipeline.

Supported log sources:
  - Windows Security log  (Event IDs 4624, 4625, 4648, 4688, 4720)
  - Windows System  log   (Event ID  7045 — new service installed)
  - Windows Application log
  - Flat text log files   (e.g. Apache/Nginx access.log)
"""

import os
import re
import sys
import json
import datetime
import subprocess
import platform
from typing import List, Dict, Optional
from pathlib import Path

# ── Windows Event ID reference ─────────────────────────────────────────────────
WINDOWS_EVENT_IDS = {
    "4624": ("MEDIUM", "Successful logon"),
    "4625": ("HIGH",   "Failed logon — possible brute-force"),
    "4648": ("HIGH",   "Logon using explicit credentials — lateral movement?"),
    "4688": ("MEDIUM", "New process created"),
    "4720": ("HIGH",   "New user account created"),
    "4732": ("HIGH",   "User added to privileged group"),
    "7045": ("HIGH",   "New service installed — possible persistence"),
    "1102": ("HIGH",   "Audit log cleared — evidence tampering"),
}

# ── Windows Event Log reader ───────────────────────────────────────────────────

def _read_windows_events(log_name: str = "Security", max_events: int = 100) -> List[Dict]:
    """
    Use wevtutil (built-in Windows CLI) to export recent events as XML,
    then parse into IOC-ready dicts.

    wevtutil ships on every Windows machine — no install required.
    """
    if platform.system() != "Windows":
        print(f"[LOG_INGESTOR] Windows event logs only available on Windows.")
        return []

    cmd = [
        "wevtutil", "qe", log_name,
        f"/c:{max_events}",
        "/rd:true",      # newest first
        "/f:text",       # text format (easier to parse than XML for demo)
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=30, encoding="utf-8", errors="ignore")
        if result.returncode != 0:
            print(f"[LOG_INGESTOR] wevtutil error: {result.stderr[:200]}")
            return []

        return _parse_wevtutil_text(result.stdout)

    except FileNotFoundError:
        print("[LOG_INGESTOR] wevtutil not found. Are you on Windows?")
        return []
    except subprocess.TimeoutExpired:
        print("[LOG_INGESTOR] wevtutil timed out.")
        return []
    except Exception as e:
        print(f"[LOG_INGESTOR] Error: {e}")
        return []


def _parse_wevtutil_text(raw: str) -> List[Dict]:
    """Parse wevtutil /f:text output into IOC-ready record dicts."""
    records = []
    blocks  = raw.strip().split("\r\n\r\n") if "\r\n\r\n" in raw else raw.strip().split("\n\n")

    for block in blocks:
        if not block.strip():
            continue

        event_id  = _extract_field(block, r"Event ID:\s*(\d+)")
        timestamp = _extract_field(block, r"Date:\s*(.+)")
        level     = _extract_field(block, r"Level:\s*(.+)")
        source    = _extract_field(block, r"Source:\s*(.+)")
        desc      = _extract_field(block, r"Description:\s*(.+)", multiline=True)

        if not event_id:
            continue

        sev_info = WINDOWS_EVENT_IDS.get(event_id, ("LOW", f"Event ID {event_id}"))
        severity, reason = sev_info

        # Parse timestamp
        try:
            dt = datetime.datetime.fromisoformat(timestamp.strip()) if timestamp else datetime.datetime.utcnow()
        except Exception:
            dt = datetime.datetime.utcnow()

        records.append({
            "url":           f"event://{source or 'windows'}/EventID-{event_id}",
            "title":         reason,
            "visit_time":    dt.strftime("%Y-%m-%d %H:%M:%S"),
            "visit_time_dt": dt,
            "visit_count":   1,
            "raw_ts":        int(dt.timestamp()),
            "severity":      severity,
            "matched_rule":  f"WINDOWS_EVENT_{event_id}",
            "reason":        reason,
            "source":        "windows_event_log",
            "event_id":      event_id,
            "log_level":     level or "Unknown",
            "description":   (desc or "")[:200],
        })

    return records


def _extract_field(text: str, pattern: str, multiline: bool = False) -> Optional[str]:
    flags = re.DOTALL if multiline else 0
    m     = re.search(pattern, text, flags)
    if m:
        return m.group(1).strip()[:300]
    return None


# ── Flat text log reader (Apache / Nginx / generic) ────────────────────────────

# Apache / Nginx combined log format
_APACHE_RE = re.compile(
    r'(?P<<ip>[\d\.]+)\s+-\s+-\s+\[(?P<<time>[^\]]+)\]\s+'
    r'"(?P<<method>\w+)\s+(?P<<url>\S+)\s+[^"]*"\s+'
    r'(?P<<status>\d+)\s+(?P<size>\d+)'
)

SUSPICIOUS_STATUS = {"400", "401", "403", "404", "500", "503"}
SUSPICIOUS_PATHS  = [
    "/admin", "/wp-login", "/phpmyadmin", "/.env", "/shell",
    "/cmd", "/.git", "/config", "/passwd", "/etc/passwd",
    "eval(", "base64_decode", "../", "%2e%2e",
]


def _parse_access_log(path: str) -> List[Dict]:
    """Parse an Apache/Nginx access.log file into IOC-ready records."""
    records = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = _APACHE_RE.match(line.strip())
                if not m:
                    continue

                ip     = m.group("ip")
                url    = m.group("url")
                method = m.group("method")
                status = m.group("status")

                try:
                    dt = datetime.datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z")
                    dt = dt.replace(tzinfo=None)
                except Exception:
                    dt = datetime.datetime.utcnow()

                # Check for suspicious indicators
                reasons  = []
                severity = "LOW"

                if status in SUSPICIOUS_STATUS:
                    reasons.append(f"HTTP {status} response")
                    severity = "MEDIUM" if status in {"401","403"} else "LOW"

                url_lower = url.lower()
                for pat in SUSPICIOUS_PATHS:
                    if pat in url_lower:
                        reasons.append(f"Suspicious path pattern: '{pat}'")
                        severity = "HIGH"
                        break

                if method in ("PUT", "DELETE", "TRACE", "OPTIONS"):
                    reasons.append(f"Unusual HTTP method: {method}")
                    if severity == "LOW":
                        severity = "MEDIUM"

                if not reasons:
                    continue  # skip clean benign requests

                records.append({
                    "url":           f"http://{ip}{url}",
                    "title":         f"{method} {status}",
                    "visit_time":    dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "visit_time_dt": dt,
                    "visit_count":   1,
                    "raw_ts":        int(dt.timestamp()),
                    "severity":      severity,
                    "matched_rule":  "ACCESS_LOG_PATTERN",
                    "reason":        " | ".join(reasons) if reasons else "Access log entry",
                    "source":        f"access_log:{os.path.basename(path)}",
                    "src_ip":        ip,
                    "http_method":   method,
                    "http_status":   status,
                })

    except FileNotFoundError:
        print(f"[LOG_INGESTOR] Log file not found: {path}")
    except Exception as e:
        print(f"[LOG_INGESTOR] Error reading {path}: {e}")

    return records


# ── Main entry points ──────────────────────────────────────────────────────────

def load_windows_logs(
    sources: Optional[List[str]] = None,
    max_per_source: int = 100,
) -> List[Dict]:
    """
    Load Windows Event Logs from one or more log channels.

    Args:
        sources:        List of Windows log names (default: Security + System)
        max_per_source: Max events per channel

    Returns:
        IOC-ready record list compatible with detect_iocs()
    """
    sources  = sources or ["Security", "System"]
    all_recs = []

    for src in sources:
        print(f"[LOG_INGESTOR] Reading Windows {src} log...")
        recs = _read_windows_events(log_name=src, max_events=max_per_source)
        print(f"[LOG_INGESTOR] {src}: {len(recs)} events loaded.")
        all_recs.extend(recs)

    return all_recs


def load_access_logs(paths: Optional[List[str]] = None) -> List[Dict]:
    """
    Parse one or more Apache/Nginx access.log files.

    Args:
        paths: List of log file paths. Defaults to common locations.

    Returns:
        IOC-ready record list compatible with detect_iocs()
    """
    default_paths = [
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "access.log",
        "logs/access.log",
    ]
    paths     = paths or [p for p in default_paths if os.path.exists(p)]
    all_recs  = []

    for path in paths:
        print(f"[LOG_INGESTOR] Parsing: {path}")
        recs = _parse_access_log(path)
        print(f"[LOG_INGESTOR] {path}: {len(recs)} suspicious entries.")
        all_recs.extend(recs)

    if not all_recs:
        print("[LOG_INGESTOR] No access log entries found (pass custom paths if needed).")

    return all_recs


def load_logs(
    mode: str = "auto",
    log_paths: Optional[List[str]] = None,
) -> List[Dict]:
    """
    Universal log loader — auto-detects what to load based on OS.

    Args:
        mode:      'windows' | 'access' | 'auto'
        log_paths: Custom log file paths (for access log mode)

    Returns:
        Combined IOC-ready record list
    """
    if mode == "windows" or (mode == "auto" and platform.system() == "Windows"):
        return load_windows_logs()
    elif mode == "access":
        return load_access_logs(paths=log_paths)
    else:
        # Try access logs on Linux/macOS
        return load_access_logs(paths=log_paths)


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"Platform: {platform.system()}")
    records = load_logs(mode="auto")
    print(f"Total records: {len(records)}")
    for r in records[:5]:
        print(f"  [{r['severity']}] {r['url'][:60]} — {r['reason'][:60]}")