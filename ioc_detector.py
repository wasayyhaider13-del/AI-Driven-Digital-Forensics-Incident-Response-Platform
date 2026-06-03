"""
ioc_detector.py — IOC Detection Engine
========================================
DFIR Module 4: Applies rule-based detection logic to timeline events
to surface Indicators of Compromise (IOCs). Each matched event is
annotated with severity, matched rule, and a human-readable reason,
then written to a dated flagged-events log.

Detection categories:
  1. Suspicious keywords in URL or page title
  2. Suspicious TLDs / known malicious domains
  3. Behavioural patterns (rapid re-visits, off-hours, bulk downloads)
  4. Encoded payloads in URLs (Base64, hex blobs)
"""

import os
import re
import json
import base64
import datetime
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse, unquote

from colorama import Fore, Style

import config

# ── Rule definitions ───────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS: List[str] = [
    "phishing", "payload", "exploit", "exploit-kit", "darkweb", "dark-web",
    "onion", "rat", "keylogger", "c2", "c&c", "botnet", "shell", "webshell",
    "backdoor", "ransomware", "cryptominer", "miner", "stealer", "infostealer",
    "dropper", "loader", "stager", "malware", "virus", "trojan",
    "mimikatz", "metasploit", "cobalt", "empire", "covenant", "sliver",
    "credential", "passwd", "passwd.txt", "dump", "lsass",
    "pastebin.com/raw", "ghostbin", "hastebin",
    "ngrok", "serveo", "localxpose",
]

SUSPICIOUS_TLDS: List[str] = [
    ".onion", ".xyz", ".tk", ".ml", ".cf", ".ga", ".gq",
    ".top", ".pw", ".cc", ".to", ".su", ".ws",
]

KNOWN_MALICIOUS_DOMAINS: List[str] = [
    "bit.ly", "tinyurl.com", "is.gd", "v.gd", "ow.ly",
    "0x00.la", "iplogger.org", "grabify.link",
]

DOWNLOAD_EXTENSIONS: List[str] = [
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".zip", ".rar", ".7z", ".gz", ".tar",
    ".iso", ".img",
    ".doc", ".docm", ".xlsm", ".xls", ".pptm",
    ".pdf",
]

RAPID_VISIT_THRESHOLD      = 5
RAPID_VISIT_WINDOW_MINUTES = 60

# Colour map used by dashboard and terminal output
COLOR_MAP = {
    "HIGH":    Fore.RED,
    "MEDIUM":  Fore.YELLOW,
    "LOW":     Fore.CYAN,
    "DEFAULT": Fore.WHITE,
}


# ── Individual detection rules ─────────────────────────────────────────────────

def _check_keywords(url: str, title: str) -> Optional[Tuple[str, str, str]]:
    combined = (url + " " + title).lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in combined:
            severity = "HIGH" if kw in {
                "c2", "c&c", "botnet", "shell", "webshell",
                "keylogger", "rat", "payload", "exploit",
            } else "MEDIUM"
            return severity, f"Suspicious keyword '{kw}' found in URL/title", "KEYWORD_MATCH"
    return None


def _check_tld_and_domain(url: str) -> Optional[Tuple[str, str, str]]:
    try:
        hostname = urlparse(url).hostname or ""
    except Exception:
        return None

    for bad in KNOWN_MALICIOUS_DOMAINS:
        if hostname == bad or hostname.endswith("." + bad):
            return "HIGH", f"Known malicious/abuse domain: {hostname}", "MALICIOUS_DOMAIN"

    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            return "MEDIUM", f"Suspicious TLD '{tld}' in hostname: {hostname}", "SUSPICIOUS_TLD"

    return None


def _check_off_hours(visit_time_str: str) -> Optional[Tuple[str, str, str]]:
    try:
        dt    = datetime.datetime.fromisoformat(visit_time_str)
        hour  = dt.hour
        start = config.OFF_HOURS_START
        end   = config.OFF_HOURS_END
        if start <= hour < end:
            return (
                "MEDIUM",
                f"Off-hours activity at {dt.strftime('%H:%M')} UTC "
                f"(window: {start:02d}:00–{end:02d}:00 UTC)",
                "OFF_HOURS_ACCESS",
            )
    except Exception:
        pass
    return None


def _check_bulk_downloads(url: str) -> Optional[Tuple[str, str, str]]:
    try:
        path = urlparse(url).path.lower()
        for ext in DOWNLOAD_EXTENSIONS:
            if path.endswith(ext):
                severity = "HIGH" if ext in {".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs"} else "MEDIUM"
                return severity, f"URL targets dangerous file type: '{ext}'", "DOWNLOAD_DETECTED"
    except Exception:
        pass
    return None


def _check_encoded_url(url: str) -> Optional[Tuple[str, str, str]]:
    decoded = unquote(url)

    for match in re.compile(r"[A-Za-z0-9+/=]{32,}").finditer(decoded):
        candidate = match.group()
        try:
            text = base64.b64decode(candidate + "==").decode("utf-8", errors="ignore")
            if any(t in text for t in ["/bin/", "cmd.exe", "powershell", "wget ", "curl ", "http://", "https://"]):
                return (
                    "HIGH",
                    f"Possible Base64-encoded payload in URL: '{candidate[:40]}...'",
                    "ENCODED_PAYLOAD",
                )
        except Exception:
            pass

    if re.compile(r"(?:0x)?[0-9a-fA-F]{16,}").search(decoded):
        return "LOW", "Hex-encoded string detected in URL — possible obfuscation", "HEX_PATTERN"

    return None


def _check_rapid_revisit(
    record: Dict,
    visit_index: Dict[str, List[datetime.datetime]],
) -> Optional[Tuple[str, str, str]]:
    url = record.get("url", "")
    try:
        dt = datetime.datetime.fromisoformat(record.get("visit_time", ""))
    except Exception:
        return None

    visit_index.setdefault(url, [])
    window_start = dt - datetime.timedelta(minutes=RAPID_VISIT_WINDOW_MINUTES)
    visit_index[url] = [t for t in visit_index[url] if t >= window_start]
    visit_index[url].append(dt)

    count = len(visit_index[url])
    if count >= RAPID_VISIT_THRESHOLD:
        return (
            "HIGH",
            f"Rapid re-visit: {count}× in {RAPID_VISIT_WINDOW_MINUTES} min (C2 beacon pattern)",
            "RAPID_REVISIT",
        )
    return None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _severity_rank(sev: str) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3}.get(sev, 0)


def _save_flagged_log(flagged: List[Dict]) -> None:
    today    = datetime.date.today().strftime("%Y%m%d")
    log_path = os.path.join(config.LOGS_DIR, f"flagged_{today}.json")

    serialisable = []
    for rec in flagged:
        out = {k: (v.isoformat() if isinstance(v, datetime.datetime) else v)
               for k, v in rec.items()}
        serialisable.append(out)

    try:
        with open(log_path, "w", encoding="utf-8") as fh:
            json.dump(
                {"generated_at": datetime.datetime.utcnow().isoformat() + "Z",
                 "total_flagged": len(flagged),
                 "events": serialisable},
                fh, indent=2, ensure_ascii=False,
            )
        print(f"{Fore.GREEN}[IOC]{Style.RESET_ALL} Flagged log → {log_path}")
    except IOError as exc:
        print(f"{Fore.RED}[IOC ERROR]{Style.RESET_ALL} Could not write log: {exc}")


# ── Main entry point ───────────────────────────────────────────────────────────

def detect_iocs(timeline: List[Dict]) -> List[Dict]:
    """
    Run all IOC detection rules over a reconstructed timeline.

    Returns the subset of events that matched at least one rule,
    each annotated with severity, reason, matched_rule, and all_matches.
    """
    if not timeline:
        print(f"{Fore.YELLOW}[IOC] No timeline events to analyse.{Style.RESET_ALL}")
        return []

    flagged: List[Dict] = []
    visit_index: Dict[str, List[datetime.datetime]] = {}

    for record in timeline:
        url   = record.get("url", "")
        title = record.get("title", "")
        ts    = record.get("visit_time", "")

        hits: List[Tuple[str, str, str]] = []

        for fn, args in [
            (_check_keywords,      (url, title)),
            (_check_tld_and_domain, (url,)),
            (_check_off_hours,      (ts,)),
            (_check_bulk_downloads, (url,)),
            (_check_encoded_url,    (url,)),
        ]:
            result = fn(*args)
            if result:
                hits.append(result)

        rr = _check_rapid_revisit(record, visit_index)
        if rr:
            hits.append(rr)

        if hits:
            hits.sort(key=lambda h: _severity_rank(h[0]), reverse=True)
            top_sev, top_reason, top_rule = hits[0]

            flagged.append({
                **record,
                "severity":     top_sev,
                "reason":       top_reason,
                "matched_rule": top_rule,
                "all_matches":  [{"severity": s, "reason": r, "rule": rl} for s, r, rl in hits],
            })

            colour = COLOR_MAP.get(top_sev, Fore.WHITE)
            print(f"{colour}[IOC {top_sev}]{Style.RESET_ALL} {top_rule} | {url[:70]}")

    high   = sum(1 for f in flagged if f["severity"] == "HIGH")
    medium = sum(1 for f in flagged if f["severity"] == "MEDIUM")
    low    = sum(1 for f in flagged if f["severity"] == "LOW")

    print(
        f"\n{Fore.CYAN}[IOC SUMMARY]{Style.RESET_ALL} "
        f"{len(flagged)}/{len(timeline)} events flagged — "
        f"{Fore.RED}HIGH:{high}{Style.RESET_ALL}  "
        f"{Fore.YELLOW}MEDIUM:{medium}{Style.RESET_ALL}  "
        f"{Fore.CYAN}LOW:{low}{Style.RESET_ALL}"
    )

    _save_flagged_log(flagged)
    return flagged


# ── CLI self-test ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_records = [
        {
            "url": "http://evil-c2.onion/payload.exe",
            "title": "C2 Panel",
            "visit_time": "2024-06-01T02:30:00",
            "visit_time_dt": datetime.datetime(2024, 6, 1, 2, 30),
            "visit_count": 15,
            "raw_ts": 1,
        },
        {
            "url": "https://www.google.com/search?q=python",
            "title": "Python - Google Search",
            "visit_time": "2024-06-01T09:00:00",
            "visit_time_dt": datetime.datetime(2024, 6, 1, 9, 0),
            "visit_count": 1,
            "raw_ts": 2,
        },
    ]
    results = detect_iocs(test_records)
    print(f"\nFlagged: {len(results)}")