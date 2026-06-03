"""
core/detection_engine.py — Core EDR Detection Engine
=====================================================
Integrates legacy rule-based keyword/TLD/off-hours checks with
custom YARA signature scanning and Sigma behavioral rule analysis.
Saves EDR events and alerts directly to the persistent SQLite database.
"""

import datetime
from urllib.parse import urlparse, unquote
import re
import base64
from typing import List, Dict, Any, Tuple, Optional

from sqlalchemy.orm import Session
from core.db import get_session, Event, Alert
from core.yara_engine import get_yara_engine
from core.sigma_engine import get_sigma_engine
import config

# ── Heuristic constants ───────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "phishing", "payload", "exploit", "onion", "rat", "keylogger", "c2", "botnet",
    "shell", "webshell", "backdoor", "ransomware", "cryptominer", "mimikatz",
    "metasploit", "cobalt", "sliver", "credential", "lsass"
]

SUSPICIOUS_TLDS = [".onion", ".xyz", ".tk", ".ml", ".cf", ".cc", ".to", ".su"]
KNOWN_MALICIOUS_DOMAINS = ["bit.ly", "tinyurl.com", "iplogger.org", "grabify.link"]
DOWNLOAD_EXTENSIONS = [".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".dll", ".zip"]

RAPID_VISIT_THRESHOLD = 5
RAPID_VISIT_WINDOW_MINUTES = 60

# ── Individual Detection Evaluators ───────────────────────────────────────────

def _check_keywords(url: str, title: str) -> Optional[Tuple[str, str, str]]:
    combined = (url + " " + title).lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in combined:
            sev = "HIGH" if kw in ("c2", "botnet", "shell", "webshell", "rat", "mimikatz", "sliver") else "MEDIUM"
            return sev, f"Suspicious keyword '{kw}' found in title/url", "KEYWORD_MATCH"
    return None

def _check_tlds(url: str) -> Optional[Tuple[str, str, str]]:
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return None
    for bad in KNOWN_MALICIOUS_DOMAINS:
        if host == bad or host.endswith("." + bad):
            return "HIGH", f"Known malicious/abuse redirect domain: {host}", "MALICIOUS_DOMAIN"
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            return "MEDIUM", f"Suspicious top-level TLD '{tld}': {host}", "SUSPICIOUS_TLD"
    return None

def _check_off_hours(visit_time_str: str) -> Optional[Tuple[str, str, str]]:
    try:
        dt = datetime.datetime.fromisoformat(visit_time_str)
        hour = dt.hour
        if config.OFF_HOURS_START <= hour < config.OFF_HOURS_END:
            return "MEDIUM", f"Off-hours administrative activity: {dt.strftime('%H:%M')} UTC", "OFF_HOURS_ACCESS"
    except Exception:
        pass
    return None

def _check_downloads(url: str) -> Optional[Tuple[str, str, str]]:
    try:
        path = urlparse(url).path.lower()
        for ext in DOWNLOAD_EXTENSIONS:
            if path.endswith(ext):
                sev = "HIGH" if ext in (".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".dll") else "MEDIUM"
                return sev, f"Dangerous binary or script download targeted: '{ext}'", "DOWNLOAD_DETECTED"
    except Exception:
        pass
    return None

def _check_encoded(url: str) -> Optional[Tuple[str, str, str]]:
    decoded = unquote(url)
    # Search Base64 patterns
    for match in re.compile(r"[A-Za-z0-9+/=]{32,}").finditer(decoded):
        cand = match.group()
        try:
            txt = base64.b64decode(cand + "==").decode("utf-8", errors="ignore")
            if any(t in txt for t in ["cmd.exe", "powershell", "wget", "curl", "http://", "https://"]):
                return "HIGH", f"Potential base64-encoded command string in URL: '{cand[:25]}...'", "ENCODED_PAYLOAD"
        except Exception:
            pass
    return None


class DetectionEngine:
    def __init__(self):
        self.yara = get_yara_engine()
        self.sigma = get_sigma_engine()

    def analyze_timeline(self, raw_events: List[Dict[str, Any]], session: Session = None) -> List[Event]:
        """
        Analyze a list of events using YARA, Sigma, and heuristic rules.
        Saves matched Event and Alert ORM records into SQLite database.
        
        Returns database-committed Event objects.
        """
        db_session = session or get_session()
        flagged_events: List[Event] = []
        visit_index: Dict[str, List[datetime.datetime]] = {}
        
        try:
            for item in raw_events:
                url = item.get("url", "")
                title = item.get("title", "")
                ts_str = item.get("visit_time", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
                
                # Setup base Event
                ev_type = item.get("event_type", "Browser")
                severity = item.get("severity", "LOW")
                rule = item.get("matched_rule", "NONE")
                reason = item.get("reason", "EDR Capture Log")
                
                hits: List[Tuple[str, str, str]] = []
                
                # 1. Run legacy Heuristics
                for fn, args in [
                    (_check_keywords, (url, title)),
                    (_check_tlds, (url,)),
                    (_check_off_hours, (ts_str,)),
                    (_check_downloads, (url,)),
                    (_check_encoded, (url,))
                ]:
                    res = fn(*args)
                    if res:
                        hits.append(res)
                        
                # 2. Run YARA signature scanner if it represents a file download or memory page
                if ev_type in ("File", "Memory") or url.startswith("file://") or url.endswith((".exe", ".dll", ".ps1")):
                    yara_hits = self.yara.scan_buffer(url.encode("utf-8") + title.encode("utf-8"))
                    for yh in yara_hits:
                        hits.append((yh["severity"], yh["description"], f"YARA_{yh['rule']}"))
                        
                # 3. Run Sigma Engine if it has process command-line arguments
                p_name = item.get("process_name", "")
                cmd = item.get("cmdline", "")
                if p_name or cmd:
                    sig_hits = self.sigma.evaluate_process(p_name, cmd)
                    for sh in sig_hits:
                        hits.append((sh["severity"], sh["description"], sh["rule_id"]))
                        
                # 4. Check for rapid re-visits (beaconing)
                if ev_type == "Browser" and url:
                    try:
                        dt = datetime.datetime.fromisoformat(ts_str)
                        visit_index.setdefault(url, [])
                        visit_index[url] = [t for t in visit_index[url] if t >= dt - datetime.timedelta(minutes=RAPID_VISIT_WINDOW_MINUTES)]
                        visit_index[url].append(dt)
                        if len(visit_index[url]) >= RAPID_VISIT_THRESHOLD:
                            hits.append(("HIGH", f"Rapid re-visits: {len(visit_index[url])}x in {RAPID_VISIT_WINDOW_MINUTES} min", "RAPID_REVISIT"))
                    except Exception:
                        pass
                        
                # If matches were triggered, upgrade severity and details
                if hits:
                    hits.sort(key=lambda h: {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(h[0], 0), reverse=True)
                    severity, reason, rule = hits[0]
                    
                # Threat score calculation
                t_score = {"CRITICAL": 95, "HIGH": 80, "MEDIUM": 45, "LOW": 15}.get(severity, 10)
                
                # Check for duplications in DB to avoid logging the same event twice
                existing = db_session.query(Event).filter(Event.url_or_path == url, Event.matched_rule == rule).first()
                if existing:
                    flagged_events.append(existing)
                    continue

                # Add to DB
                try:
                    dt_obj = datetime.datetime.fromisoformat(ts_str)
                except Exception:
                    dt_obj = datetime.datetime.utcnow()
                    
                new_event = Event(
                    timestamp=dt_obj,
                    event_type=ev_type,
                    title=title,
                    url_or_path=url,
                    details=reason,
                    severity=severity,
                    matched_rule=rule,
                    threat_score=t_score,
                    src_ip=item.get("src_ip", "192.168.0.143"),
                    dst_ip=item.get("dst_ip"),
                    dst_port=item.get("dst_port"),
                    host=item.get("domain") or urlparse(url).hostname,
                    protocol=item.get("protocol"),
                    process_name=p_name,
                    process_id=item.get("process_id"),
                    parent_process_id=item.get("parent_process_id"),
                    cmdline=cmd,
                    source=item.get("source", "EDR_Capture")
                )
                db_session.add(new_event)
                db_session.commit()
                flagged_events.append(new_event)
                
                # If critical/high/medium, trigger database Alert
                if severity in ("CRITICAL", "HIGH", "MEDIUM"):
                    new_alert = Alert(
                        rule_name=rule,
                        severity=severity,
                        status="Active",
                        details=reason,
                        event_id=new_event.id,
                        timestamp=dt_obj
                    )
                    db_session.add(new_alert)
                    db_session.commit()
                    
            print(f"[DETECTION] Evaluated EDR timeline. Created {len(flagged_events)} event record(s).")
            return flagged_events
            
        except Exception as e:
            db_session.rollback()
            print(f"[DETECTION ERROR] Evaluation failed: {e}")
            return []
        finally:
            if session is None:
                db_session.close()

# Singleton instance
_detection_engine = None

def get_detection_engine() -> DetectionEngine:
    global _detection_engine
    if _detection_engine is None:
        _detection_engine = DetectionEngine()
    return _detection_engine

if __name__ == "__main__":
    from core.db import init_db
    init_db()
    det = get_detection_engine()
    raw = [
        {"url": "https://malware-drop.xyz/sliver_beacon.exe", "title": "Sliver Implant Drop", "event_type": "Browser"},
        {"url": "https://google.com", "title": "Search", "event_type": "Browser"}
    ]
    res = det.analyze_timeline(raw)
    for r in res:
        print(f"[{r.severity}] {r.url_or_path} -> rule: {r.matched_rule}")
