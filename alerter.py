"""
alerter.py — Automated Alert System
=====================================
DFIR Module 6: Sends HTML email alerts via Gmail SMTP for any event
classified as SUSPICIOUS or MALICIOUS. Implements deduplication to
prevent notification fatigue, and logs all sent alerts to an audit file.
"""

import os
import json
import socket
import hashlib
import smtplib
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict

from colorama import Fore, Style

import config

ALERTS_LOG_PATH = os.path.join(config.LOGS_DIR, "alerts.log")


# ── Deduplication ─────────────────────────────────────────────────────────────

def _load_sent_hashes() -> Dict[str, str]:
    sent: Dict[str, str] = {}
    if not os.path.exists(ALERTS_LOG_PATH):
        return sent
    try:
        with open(ALERTS_LOG_PATH, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    sent[entry["url_hash"]] = entry["sent_at"]
                except (json.JSONDecodeError, KeyError):
                    pass
    except IOError:
        pass
    return sent


def _url_hash(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def _is_duplicate(url: str, sent_hashes: Dict[str, str]) -> bool:
    h = _url_hash(url)
    if h not in sent_hashes:
        return False
    try:
        last_sent = datetime.datetime.fromisoformat(sent_hashes[h])
        age       = datetime.datetime.utcnow() - last_sent.replace(tzinfo=None)
        return age < datetime.timedelta(hours=config.ALERT_DEDUP_HOURS)
    except Exception:
        return False


def _record_sent_alert(url: str, event: Dict) -> None:
    entry = {
        "url_hash":       _url_hash(url),
        "url":            url,
        "severity":       event.get("severity", "UNKNOWN"),
        "classification": event.get("llm", {}).get("classification", "UNKNOWN"),
        "sent_at":        datetime.datetime.utcnow().isoformat(),
    }
    try:
        with open(ALERTS_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except IOError as exc:
        print(f"{Fore.RED}[ALERTER ERROR]{Style.RESET_ALL} Could not write alerts log: {exc}")


# ── HTML email builder ─────────────────────────────────────────────────────────

def _build_html_body(event: Dict, hostname: str) -> str:
    llm        = event.get("llm", {})
    severity   = event.get("severity", "UNKNOWN")
    sev_colour = {"HIGH": "#d32f2f", "MEDIUM": "#f57c00", "LOW": "#0288d1"}.get(severity, "#555")
    cls        = llm.get("classification", "UNKNOWN")
    cls_colour = {"MALICIOUS": "#d32f2f", "SUSPICIOUS": "#f57c00", "BENIGN": "#388e3c"}.get(cls, "#555")

    def row(label, value):
        return (f"<tr>"
                f"<td style='padding:6px 12px;font-weight:bold;color:#555;white-space:nowrap'>{label}</td>"
                f"<td style='padding:6px 12px;word-break:break-all'>{value}</td>"
                f"</tr>")

    rows_event = "".join([
        row("URL",          event.get("url", "N/A")),
        row("Page Title",   event.get("title", "N/A")),
        row("Visit Time",   str(event.get("visit_time", "N/A")) + " UTC"),
        row("Visit Count",  str(event.get("visit_count", 1))),
        row("Matched Rule", event.get("matched_rule", "N/A")),
        row("IOC Reason",   event.get("reason", "N/A")),
    ])

    rows_llm = "".join([
        row("Classification",     f"<span style='color:{cls_colour};font-weight:bold'>{cls}</span>"),
        row("Confidence",         f"{llm.get('confidence', 0)}%"),
        row("Threat Type",        llm.get("threat_type") or "N/A"),
        row("Explanation",        llm.get("explanation", "N/A")),
        row("Recommended Action", llm.get("recommended_action", "N/A")),
    ])

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;background:#f5f5f5;margin:0;padding:20px">
  <div style="max-width:720px;margin:0 auto;background:#fff;border-radius:8px;
              box-shadow:0 2px 8px rgba(0,0,0,.15);overflow:hidden">
    <div style="background:{sev_colour};padding:20px 30px">
      <h1 style="color:#fff;margin:0;font-size:20px">🚨 DFIR Alert — {severity} Threat Detected</h1>
      <p style="color:rgba(255,255,255,.85);margin:6px 0 0">
        Host: <strong>{hostname}</strong> &nbsp;|&nbsp;
        Detected: {datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC
      </p>
    </div>
    <div style="padding:24px 30px">
      <h2 style="color:#333;font-size:16px;margin:0 0 12px">📋 Browser Event Details</h2>
      <table style="width:100%;border-collapse:collapse;background:#fafafa;border-radius:6px">{rows_event}</table>
      <h2 style="color:#333;font-size:16px;margin:24px 0 12px">🤖 AI Threat Classification</h2>
      <table style="width:100%;border-collapse:collapse;background:#fafafa;border-radius:6px">{rows_llm}</table>
      <p style="color:#999;font-size:12px;margin-top:30px;border-top:1px solid #eee;padding-top:16px">
        Generated by DFIR Sentinel · This alert is automated — verify independently before acting.
      </p>
    </div>
  </div>
</body></html>"""


# ── SMTP sender ────────────────────────────────────────────────────────────────

def _send_email(subject: str, html_body: str) -> bool:
    if not all([config.GMAIL_SENDER, config.GMAIL_APP_PASSWORD, config.GMAIL_RECIPIENT]):
        print(f"{Fore.YELLOW}[ALERTER] Gmail not configured — skipping send.{Style.RESET_ALL}")
        return False

    msg            = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = config.GMAIL_SENDER
    msg["To"]      = config.GMAIL_RECIPIENT
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(config.GMAIL_SENDER, config.GMAIL_APP_PASSWORD)
            server.sendmail(config.GMAIL_SENDER, [config.GMAIL_RECIPIENT], msg.as_bytes())
        return True
    except smtplib.SMTPAuthenticationError:
        print(f"{Fore.RED}[ALERTER ERROR]{Style.RESET_ALL} Gmail auth failed. Use an App Password.")
        return False
    except Exception as exc:
        print(f"{Fore.RED}[ALERTER ERROR]{Style.RESET_ALL} {exc}")
        return False


# ── Main dispatcher ────────────────────────────────────────────────────────────

def send_alerts(classified_events: List[Dict]) -> int:
    """
    Send email alerts for SUSPICIOUS / MALICIOUS events.
    Returns the number of alerts successfully sent.
    """
    if not classified_events:
        print(f"{Fore.YELLOW}[ALERTER] No events to alert on.{Style.RESET_ALL}")
        return 0

    hostname    = socket.gethostname()
    sent_hashes = _load_sent_hashes()
    alerts_sent = 0
    trigger     = {"SUSPICIOUS", "MALICIOUS"}

    for event in classified_events:
        llm    = event.get("llm", {})
        cls    = llm.get("classification", "UNKNOWN")
        sev    = event.get("severity", "UNKNOWN")
        url    = event.get("url", "")

        if cls not in trigger:
            continue

        if _is_duplicate(url, sent_hashes):
            print(f"{Fore.CYAN}[ALERTER] Dedup skip: {url[:60]}{Style.RESET_ALL}")
            continue

        subject = f"🚨 [{sev}] DFIR Alert — {cls} Threat on {hostname}"
        success = _send_email(subject, _build_html_body(event, hostname))

        if success:
            alerts_sent += 1
            sent_hashes[_url_hash(url)] = datetime.datetime.utcnow().isoformat()
            _record_sent_alert(url, event)
            print(f"{Fore.GREEN}[ALERTER] ✓ Alert sent:{Style.RESET_ALL} [{sev}] {cls} | {url[:60]}")
        else:
            print(f"{Fore.RED}[ALERTER] ✗ Failed: {url[:60]}{Style.RESET_ALL}")

    print(f"{Fore.CYAN}[ALERTER]{Style.RESET_ALL} {alerts_sent} alert(s) sent.")
    return alerts_sent


# ── CLI self-test ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_events = [{
        "url":         "http://evil-c2.onion/payload.exe",
        "title":       "C2 Panel",
        "visit_time":  "2024-06-01T02:30:00",
        "visit_count": 15,
        "severity":    "HIGH",
        "reason":      "Keyword 'c2' found in URL",
        "matched_rule":"KEYWORD_MATCH",
        "llm": {
            "classification":     "MALICIOUS",
            "confidence":         97,
            "threat_type":        "C2 Communication",
            "explanation":        "URL + .onion TLD = C2 infrastructure.",
            "recommended_action": "Isolate host immediately.",
        },
    }]
    print(f"Alerts sent: {send_alerts(test_events)}")