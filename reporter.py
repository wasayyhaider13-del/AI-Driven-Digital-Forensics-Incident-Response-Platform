"""
reporter.py — Incident Report Generator
=========================================
DFIR Module 7: Loads the latest flagged events and alert log,
computes a risk score, and exports both an HTML and PDF report.
"""

import os
import glob
import json
import datetime
from typing import List, Dict

from colorama import Fore, Style
try:
    from fpdf import FPDF
    _HAS_FPDF = True
except ImportError:
    _HAS_FPDF = False
    print("[REPORTER] fpdf2 not installed. PDF generation disabled. Run: pip install fpdf2")

import config


# ── Load Logs ─────────────────────────────────────────────────────────────────

def _load_latest_log(prefix: str) -> List[Dict]:
    pattern = os.path.join(config.LOGS_DIR, f"{prefix}_*.json")
    files   = sorted(glob.glob(pattern), reverse=True)
    if not files:
        return []
    with open(files[0], "r", encoding="utf-8") as f:
        return json.load(f).get("events", [])


def _load_alerts() -> List[Dict]:
    path = os.path.join(config.LOGS_DIR, "alerts.log")
    if not os.path.exists(path):
        return []
    alerts = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return alerts


# ── Risk Scoring ──────────────────────────────────────────────────────────────

def _risk_score(events: List[Dict]) -> int:
    score = 0
    for e in events:
        sev = e.get("severity", "")
        if   sev == "HIGH":   score += 10
        elif sev == "MEDIUM": score += 5
        elif sev == "LOW":    score += 2
    return min(score, 100)


def _risk_label(score: int) -> str:
    if   score >= 75: return "CRITICAL"
    elif score >= 50: return "HIGH"
    elif score >= 25: return "MEDIUM"
    else:             return "LOW"


# ── HTML Report ───────────────────────────────────────────────────────────────

def _generate_html(events: List[Dict], alerts: List[Dict],
                   path: str, score: int, label: str) -> None:
    label_colour = {
        "CRITICAL": "#b71c1c", "HIGH": "#e65100",
        "MEDIUM":   "#1565c0", "LOW":  "#1b5e20",
    }.get(label, "#333")

    rows = ""
    for e in events:
        sev = e.get("severity", "")
        row_colour = {
            "HIGH": "#fff3f3", "MEDIUM": "#fff8e1", "LOW": "#f1f8e9"
        }.get(sev, "#fff")
        rows += f"""
        <tr style="background:{row_colour}">
            <td>{e.get('visit_time', '')}</td>
            <td style="word-break:break-all">{e.get('url', '')}</td>
            <td><b>{sev}</b></td>
            <td>{e.get('matched_rule', 'N/A')}</td>
            <td>{e.get('llm', {}).get('classification', 'N/A')}</td>
            <td>{e.get('llm', {}).get('confidence', 'N/A')}%</td>
        </tr>"""

    alert_rows = ""
    for a in alerts:
        alert_rows += f"""
        <tr>
            <td>{a.get('sent_at', '')}</td>
            <td style="word-break:break-all">{a.get('url', '')}</td>
            <td>{a.get('severity', '')}</td>
            <td>{a.get('classification', '')}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>DFIR Sentinel — Incident Report</title>
    <style>
        body   {{ font-family: Arial, sans-serif; background: #f5f5f5; padding: 24px; }}
        h1     {{ color: #1a237e; }}
        h2     {{ color: #333; border-bottom: 2px solid #ddd; padding-bottom: 6px; }}
        .badge {{ display:inline-block; padding:4px 12px; border-radius:4px;
                  font-weight:bold; color:#fff; background:{label_colour}; font-size:1.1rem; }}
        table  {{ border-collapse: collapse; width: 100%; background: #fff;
                  border-radius:6px; overflow:hidden; margin-bottom:24px; }}
        th, td {{ padding: 10px 14px; border: 1px solid #e0e0e0; font-size:.9rem; }}
        th     {{ background: #1a237e; color: #fff; text-align:left; }}
        .meta  {{ background:#fff; border-radius:6px; padding:16px; margin-bottom:20px;
                  border-left:4px solid {label_colour}; }}
    </style>
</head>
<body>
    <h1>🔍 DFIR Sentinel — Incident Report</h1>
    <div class="meta">
        <p><b>Generated:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><b>Total Events:</b> {len(events)} &nbsp;|&nbsp;
           <b>Alerts Sent:</b> {len(alerts)}</p>
        <p><b>Overall Risk Score:</b>
           <span class="badge">{score} / 100 — {label}</span></p>
    </div>

    <h2>📋 Flagged Events</h2>
    <table>
        <tr>
            <th>Time (UTC)</th><th>URL</th><th>Severity</th>
            <th>Rule</th><th>Classification</th><th>Confidence</th>
        </tr>
        {rows if rows else '<tr><td colspan="6">No flagged events.</td></tr>'}
    </table>

    <h2>🚨 Alert History</h2>
    <table>
        <tr><th>Sent At</th><th>URL</th><th>Severity</th><th>Classification</th></tr>
        {alert_rows if alert_rows else '<tr><td colspan="4">No alerts sent.</td></tr>'}
    </table>

    <p style="color:#999;font-size:.8rem;margin-top:30px">
        Generated by DFIR Sentinel v2.0 · Automated report — verify independently.
    </p>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


# ── PDF Report ────────────────────────────────────────────────────────────────

def _generate_pdf(events: List[Dict], alerts: List[Dict],
                  path: str, score: int, label: str) -> None:
    """
    Generate a PDF report using fpdf2.

    NOTE: fpdf2 requires ln=True on cell() calls to advance to the next line,
    otherwise every cell overwrites the same position.
    """
    if not _HAS_FPDF:
        print("[REPORTER] Skipping PDF — fpdf2 not installed.")
        return

    pdf = FPDF()
    pdf.add_page()

    # ── Title ──
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "DFIR Sentinel - Incident Report", ln=True)

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 7, f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC", ln=True)
    pdf.cell(0, 7, f"Risk Score: {score} / 100  ({label})", ln=True)
    pdf.cell(0, 7, f"Total Events: {len(events)}   Alerts Sent: {len(alerts)}", ln=True)
    pdf.ln(4)

    # ── Flagged Events ──
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Flagged Events", ln=True)
    pdf.set_font("Helvetica", "", 8)

    if events:
        # Header row
        pdf.set_fill_color(26, 35, 126)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(30, 7,  "Time",           border=1, fill=True)
        pdf.cell(80, 7,  "URL",            border=1, fill=True)
        pdf.cell(20, 7,  "Severity",       border=1, fill=True)
        pdf.cell(30, 7,  "Rule",           border=1, fill=True)
        pdf.cell(30, 7,  "Classification", border=1, fill=True, ln=True)
        pdf.set_text_color(0, 0, 0)

        for e in events[:50]:   # cap at 50 rows for PDF readability
            sev = e.get("severity", "")
            if   sev == "HIGH":   pdf.set_fill_color(255, 235, 235)
            elif sev == "MEDIUM": pdf.set_fill_color(255, 248, 225)
            else:                 pdf.set_fill_color(255, 255, 255)

            ts  = str(e.get("visit_time", ""))[:16]
            url = str(e.get("url", ""))[:45]
            cls = str(e.get("llm", {}).get("classification", "N/A"))
            rl  = str(e.get("matched_rule", "N/A"))[:18]

            pdf.cell(30, 6, ts,  border=1, fill=True)
            pdf.cell(80, 6, url, border=1, fill=True)
            pdf.cell(20, 6, sev, border=1, fill=True)
            pdf.cell(30, 6, rl,  border=1, fill=True)
            pdf.cell(30, 6, cls, border=1, fill=True, ln=True)
    else:
        pdf.cell(0, 7, "No flagged events.", ln=True)

    pdf.ln(6)

    # ── Alert History ──
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Alert History", ln=True)
    pdf.set_font("Helvetica", "", 8)

    if alerts:
        pdf.set_fill_color(26, 35, 126)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(45, 7, "Sent At",        border=1, fill=True)
        pdf.cell(90, 7, "URL",            border=1, fill=True)
        pdf.cell(25, 7, "Severity",       border=1, fill=True)
        pdf.cell(30, 7, "Classification", border=1, fill=True, ln=True)
        pdf.set_text_color(0, 0, 0)

        for a in alerts[:30]:
            pdf.set_fill_color(255, 255, 255)
            pdf.cell(45, 6, str(a.get("sent_at", ""))[:22],     border=1, fill=True)
            pdf.cell(90, 6, str(a.get("url", ""))[:50],         border=1, fill=True)
            pdf.cell(25, 6, str(a.get("severity", "")),          border=1, fill=True)
            pdf.cell(30, 6, str(a.get("classification", "N/A")), border=1, fill=True, ln=True)
    else:
        pdf.cell(0, 7, "No alerts sent.", ln=True)

    pdf.output(path)


# ── Main entry point ──────────────────────────────────────────────────────────

def generate_report() -> str:
    """
    Load latest logs, compute risk, generate HTML + PDF reports.
    Returns the HTML report path.
    """
    print(f"{Fore.CYAN}[REPORT]{Style.RESET_ALL} Generating report...")

    os.makedirs(config.REPORTS_DIR, exist_ok=True)

    events = _load_latest_log("flagged")
    alerts = _load_alerts()
    score  = _risk_score(events)
    label  = _risk_label(score)
    date   = datetime.datetime.now().strftime("%Y%m%d_%H%M")

    html_path = os.path.join(config.REPORTS_DIR, f"report_{date}.html")
    pdf_path  = os.path.join(config.REPORTS_DIR, f"report_{date}.pdf")

    _generate_html(events, alerts, html_path, score, label)
    _generate_pdf(events,  alerts, pdf_path,  score, label)

    print(f"{Fore.GREEN}[DONE]{Style.RESET_ALL}")
    print(f"  HTML : {html_path}")
    print(f"  PDF  : {pdf_path}")
    print(f"  Risk : {score}/100 ({label})")

    return html_path


if __name__ == "__main__":
    generate_report()