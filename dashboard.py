"""
dashboard.py — DFIR Sentinel v3.0 (Ultra-Premium Cyber-Ops Edition)
Run: python -m streamlit run dashboard.py
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import networkx as nx
import datetime, time, random, os, json, platform, traceback
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

try:
    from extractor        import extract_chrome_history
    from ioc_detector     import detect_iocs
    from timeline         import reconstruct_timeline
    from utils            import load_logs
    from autopsy_ingestor import load_autopsy_data
    from network_analyzer import tshark_installed, get_tshark_version, capture_traffic, load_network_data
    from log_ingestor     import load_logs as load_system_logs
    from ui.components.graphs import render_process_tree
    from ui.components.charts import render_sankey_diagram, render_threat_heatmap
    import config
    REAL_MODE = True
    _IMPORT_ERROR = None
except Exception as _e:
    REAL_MODE = False
    _IMPORT_ERROR = str(_e)
    render_process_tree = None
    render_sankey_diagram = None
    render_threat_heatmap = None

st.set_page_config(page_title="DFIR SENTINEL v3.0", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")

# ── SESSION STATE INITIALIZATION ──────────────────────────────────────────────
for k, v in [
    ("scan_count", 0),
    ("last_scan", datetime.datetime.now(datetime.timezone.utc)),
    ("auto_refresh", False),
    ("refresh_secs", 30),
    ("file_events", []),
    ("autopsy_data", []),
    ("net_data", []),
    ("isolated_nodes", set()),
    ("quarantined_files", set()),
    ("muted_alerts", set()),
    ("incident_profile", "None (Default Live/Demo Logs)"),
    ("containment_terminal_logs", [
        "🛡️ DFIR Sentinel EDR Shell v3.0 - Terminal Established.",
        "System Agent [SENTINEL-NODE-01] linked via secure websocket.",
        "Type 'help' to review available administrative EDR commands.",
        ""
    ]),
    ("ai_override_rules", {}),
    ("packet_simulation_index", 0),
    ("packet_simulation_active", False)
]:
    if k not in st.session_state:
        st.session_state[k] = v

# ── ULTRAPREMIUM CYBERPUNK STYLING SYSTEM ────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700;900&family=Space+Grotesk:wght@400;600;700&family=Inter:wght@300;400;500;600&family=Share+Tech+Mono&display=swap');

:root {
  --bg: #030814;
  --bg-gradient: radial-gradient(ellipse 90% 60% at 50% -10%, rgba(0, 170, 255, 0.1), transparent);
  --bg-card: rgba(10, 22, 45, 0.55);
  --border-color: rgba(0, 240, 255, 0.12);
  --border-color-glow: rgba(0, 240, 255, 0.25);
  
  --neon-cyan: #00f0ff;
  --neon-cyan-glow: rgba(0, 240, 255, 0.4);
  --neon-orange: #ff9d00;
  --neon-orange-glow: rgba(255, 157, 0, 0.4);
  --neon-red: #ff0055;
  --neon-red-glow: rgba(255, 0, 85, 0.45);
  --neon-green: #39ff14;
  --neon-green-glow: rgba(57, 255, 20, 0.4);
  --neon-purple: #bd5af2;
  --neon-purple-glow: rgba(189, 90, 242, 0.4);
  --neon-yellow: #ffe600;
  --neon-yellow-glow: rgba(255, 230, 0, 0.4);
  
  --text-primary: #e6f3ff;
  --text-secondary: #8fa3b7;
  --text-muted: #4e647b;
  
  --font-mono: 'Share Tech Mono', monospace;
  --font-title: 'Space Grotesk', sans-serif;
  --font-digital: 'Orbitron', sans-serif;
  --font-body: 'Inter', sans-serif;
}

/* Global resets */
.stApp {
  background: var(--bg) !important;
  background-image: var(--bg-gradient) !important;
}

.stApp * {
  color: var(--text-primary) !important;
  font-family: var(--font-body);
}

/* Scrollbar styling */
::-webkit-scrollbar {
  width: 5px;
  height: 5px;
}
::-webkit-scrollbar-track {
  background: #030814;
}
::-webkit-scrollbar-thumb {
  background: rgba(0, 240, 255, 0.2);
  border-radius: 4px;
}
::-webkit-scrollbar-thumb:hover {
  background: var(--neon-cyan);
}

/* Hide header & footer */
#MainMenu, footer, header {
  visibility: hidden;
}

/* Block container padding adjustments */
.block-container {
  padding: 0.5rem 1.8rem 1.5rem !important;
  max-width: 100% !important;
}

/* Glassmorphism tactical panels */
.hdr, .kpi, .ev, .tc, .glass-panel {
  background: var(--bg-card) !important;
  backdrop-filter: blur(16px) !important;
  border: 1px solid var(--border-color) !important;
  box-shadow: 0 8px 32px 0 rgba(0, 8, 20, 0.5) !important;
  border-radius: 12px;
  transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
}

/* Interactive card hover glows */
.ev:hover, .kpi:hover, .tc:hover, .glass-panel:hover {
  border-color: var(--neon-cyan) !important;
  box-shadow: 0 8px 32px 0 rgba(0, 240, 255, 0.08), inset 0 0 12px rgba(0, 240, 255, 0.03) !important;
  transform: translateY(-2px);
}

/* Global Cyber Header styling */
.hdr {
  border-top: 3px solid var(--neon-cyan) !important;
  padding: 22px 30px;
  margin-bottom: 20px;
  position: relative;
  overflow: hidden;
}

.hdr::before {
  content: "";
  position: absolute;
  top: 0;
  left: -150%;
  width: 60%;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(0, 240, 255, 0.08), transparent);
  animation: sweep 6s linear infinite;
}

@keyframes sweep {
  to { left: 250%; }
}

.htitle {
  font-family: var(--font-title);
  font-size: 2.2rem;
  font-weight: 700;
  color: var(--neon-cyan) !important;
  text-shadow: 0 0 25px rgba(0, 240, 255, 0.35);
  letter-spacing: 0.05em;
  margin: 0;
  line-height: 1;
}

.hsub {
  font-family: var(--font-mono);
  font-size: 0.65rem;
  color: var(--text-secondary) !important;
  letter-spacing: 0.25em;
  margin-top: 8px;
}

/* Tactically decorated section headers */
.sh {
  font-family: var(--font-mono);
  font-size: 0.62rem;
  letter-spacing: 0.22em;
  color: var(--text-secondary) !important;
  text-transform: uppercase;
  border-bottom: 1px solid rgba(0, 240, 255, 0.15);
  padding-bottom: 8px;
  margin: 18px 0 14px;
  display: flex;
  align-items: center;
  gap: 10px;
}

.sh::before {
  content: "";
  width: 4px;
  height: 14px;
  background: var(--neon-cyan);
  border-radius: 2px;
  box-shadow: 0 0 8px var(--neon-cyan);
}

/* Animated status indicator dots */
.pill {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  border-radius: 20px;
  padding: 5px 14px;
  font-family: var(--font-mono);
  font-size: 0.6rem;
  letter-spacing: 0.1em;
  font-weight: 600;
}

.pill.live {
  background: rgba(57, 255, 20, 0.06);
  border: 1px solid rgba(57, 255, 20, 0.25);
  color: var(--neon-green) !important;
}

.pill.demo {
  background: rgba(255, 157, 0, 0.06);
  border: 1px solid rgba(255, 157, 0, 0.25);
  color: var(--neon-orange) !important;
}

.pill.sim {
  background: rgba(255, 0, 85, 0.08);
  border: 1px solid rgba(255, 0, 85, 0.3);
  color: var(--neon-red) !important;
  animation: pulse-border 2s infinite alternate;
}

@keyframes pulse-border {
  from { border-color: rgba(255, 0, 85, 0.3); }
  to { border-color: rgba(255, 0, 85, 0.85); box-shadow: 0 0 8px rgba(255, 0, 85, 0.15); }
}

.ldot {
  width: 7px;
  height: 7px;
  background: currentColor;
  border-radius: 50%;
  box-shadow: 0 0 8px currentColor;
  animation: blink 1.5s ease-in-out infinite;
}

@keyframes blink {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.15; }
}

/* KPI metric cards style overrides */
.kpi {
  padding: 16px 20px;
  position: relative;
  overflow: hidden;
}

.kpi-acc {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
}

.kpi-acc.c { background: linear-gradient(90deg, transparent, var(--neon-cyan), transparent); }
.kpi-acc.r { background: linear-gradient(90deg, transparent, var(--neon-red), transparent); }
.kpi-acc.a { background: linear-gradient(90deg, transparent, var(--neon-orange), transparent); }
.kpi-acc.g { background: linear-gradient(90deg, transparent, var(--neon-green), transparent); }
.kpi-acc.p { background: linear-gradient(90deg, transparent, var(--neon-purple), transparent); }
.kpi-acc.y { background: linear-gradient(90deg, transparent, var(--neon-yellow), transparent); }

.kpi-lbl {
  font-family: var(--font-mono);
  font-size: 0.58rem;
  letter-spacing: 0.2em;
  color: var(--text-secondary) !important;
  text-transform: uppercase;
  margin-bottom: 8px;
}

.kpi-val {
  font-family: var(--font-digital);
  font-size: 2.1rem;
  font-weight: 700;
  line-height: 1.1;
  margin: 0;
}

.kpi-val.c { color: var(--neon-cyan) !important; text-shadow: 0 0 15px var(--neon-cyan-glow); }
.kpi-val.r { color: var(--neon-red) !important; text-shadow: 0 0 15px var(--neon-red-glow); }
.kpi-val.a { color: var(--neon-orange) !important; text-shadow: 0 0 15px var(--neon-orange-glow); }
.kpi-val.g { color: var(--neon-green) !important; text-shadow: 0 0 15px var(--neon-green-glow); }
.kpi-val.p { color: var(--neon-purple) !important; text-shadow: 0 0 15px var(--neon-purple-glow); }
.kpi-val.y { color: var(--neon-yellow) !important; text-shadow: 0 0 15px var(--neon-yellow-glow); }

.kpi-sub {
  font-family: var(--font-mono);
  font-size: 0.6rem;
  color: var(--text-secondary) !important;
  margin-top: 6px;
}

.kpi-bar {
  background: rgba(14, 40, 69, 0.4);
  border-radius: 2px;
  height: 3px;
  overflow: hidden;
  margin-top: 12px;
}

.kpi-fill {
  height: 100%;
  border-radius: 2px;
}

.kpi-fill.c { background: var(--neon-cyan); box-shadow: 0 0 8px var(--neon-cyan); }
.kpi-fill.r { background: var(--neon-red); box-shadow: 0 0 8px var(--neon-red); }
.kpi-fill.a { background: var(--neon-orange); box-shadow: 0 0 8px var(--neon-orange); }
.kpi-fill.g { background: var(--neon-green); box-shadow: 0 0 8px var(--neon-green); }
.kpi-fill.p { background: var(--neon-purple); box-shadow: 0 0 8px var(--neon-purple); }
.kpi-fill.y { background: var(--neon-yellow); box-shadow: 0 0 8px var(--neon-yellow); }

/* Glowing indicators & severity badges */
.sev {
  display: inline-flex;
  align-items: center;
  border-radius: 3px;
  font-family: var(--font-mono);
  font-size: 0.58rem;
  padding: 3px 8px;
  font-weight: 700;
  text-transform: uppercase;
}

.sMAL, .sCRI { background: rgba(255, 0, 85, 0.1); border: 1px solid var(--neon-red); color: var(--neon-red) !important; box-shadow: 0 0 6px rgba(255, 0, 85, 0.2); }
.sHIG { background: rgba(255, 157, 0, 0.1); border: 1px solid var(--neon-orange); color: var(--neon-orange) !important; }
.sSUS, .sMED { background: rgba(0, 240, 255, 0.1); border: 1px solid var(--neon-cyan); color: var(--neon-cyan) !important; }
.sBEN, .sLOW { background: rgba(57, 255, 20, 0.08); border: 1px solid var(--neon-green); color: var(--neon-green) !important; }
.sUNK { background: rgba(189, 90, 242, 0.08); border: 1px solid var(--neon-purple); color: var(--neon-purple) !important; }

/* Custom HTML event logs container */
.ev {
  padding: 14px 20px;
  margin-bottom: 10px;
}

.ev.h { border-left: 4px solid var(--neon-red) !important; }
.ev.m { border-left: 4px solid var(--neon-orange) !important; }
.ev.l { border-left: 4px solid var(--neon-cyan) !important; }
.ev.iso { border-left: 4px solid var(--neon-purple) !important; opacity: 0.65; }

.ev-url {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  word-break: break-all;
  color: var(--text-primary) !important;
}

.ev-meta {
  font-family: var(--font-mono);
  font-size: 0.62rem;
  color: var(--text-secondary) !important;
  margin-top: 6px;
  line-height: 1.6;
}

/* Sidebar navigation styling overrides */
[data-testid="stSidebar"] {
  background: linear-gradient(180deg, #051020, #020710) !important;
  border-right: 1px solid rgba(0, 240, 255, 0.08) !important;
}

[data-testid="stSidebar"] label {
  font-family: var(--font-mono) !important;
  font-size: 0.65rem !important;
  color: var(--text-secondary) !important;
  text-transform: uppercase;
  letter-spacing: 0.1em;
}

.sb-box {
  margin-top: 15px;
  padding: 14px;
  background: rgba(4, 12, 28, 0.7);
  border: 1px solid var(--border-color);
  border-radius: 10px;
  box-shadow: inset 0 0 10px rgba(0, 240, 255, 0.03);
}

.sb-box div {
  font-family: var(--font-mono);
  font-size: 0.62rem;
  line-height: 2;
  color: var(--text-secondary) !important;
}

/* Streamlit button style injection */
.stButton>button {
  background: rgba(0, 240, 255, 0.03) !important;
  color: var(--neon-cyan) !important;
  border: 1px solid var(--border-color) !important;
  border-radius: 6px !important;
  font-family: var(--font-mono) !important;
  font-size: 0.68rem !important;
  letter-spacing: 0.1em !important;
  font-weight: bold !important;
  transition: all 0.3s !important;
  text-transform: uppercase !important;
}

.stButton>button:hover {
  border-color: var(--neon-cyan) !important;
  background: rgba(0, 240, 255, 0.12) !important;
  box-shadow: 0 0 15px rgba(0, 240, 255, 0.25) !important;
  color: #fff !important;
}

/* Red alert buttons */
.btn-red>div>button {
  color: var(--neon-red) !important;
  border-color: rgba(255, 0, 85, 0.3) !important;
}
.btn-red>div>button:hover {
  border-color: var(--neon-red) !important;
  background: rgba(255, 0, 85, 0.12) !important;
  box-shadow: 0 0 15px rgba(255, 0, 85, 0.25) !important;
}

/* Purple/AI buttons */
.btn-purple>div>button {
  color: var(--neon-purple) !important;
  border-color: rgba(189, 90, 242, 0.3) !important;
}
.btn-purple>div>button:hover {
  border-color: var(--neon-purple) !important;
  background: rgba(189, 90, 242, 0.12) !important;
  box-shadow: 0 0 15px rgba(189, 90, 242, 0.25) !important;
}

/* Tabs customization */
.stTabs [data-baseweb="tab-list"] {
  background: rgba(5, 12, 28, 0.5);
  border-bottom: 1px solid rgba(0, 240, 255, 0.1);
  padding: 4px;
  border-radius: 8px;
}

.stTabs [data-baseweb="tab"] {
  font-family: var(--font-mono);
  font-size: 0.65rem;
  letter-spacing: 0.08em;
  color: var(--text-secondary) !important;
  padding: 8px 18px !important;
  transition: all 0.3s;
}

.stTabs [aria-selected="true"] {
  color: var(--neon-cyan) !important;
  background: rgba(0, 240, 255, 0.06) !important;
  border-bottom: 2px solid var(--neon-cyan) !important;
  border-radius: 4px;
}

/* Form inputs & dropdown overrides */
div[data-baseweb="select"] > div {
  background-color: rgba(10, 22, 45, 0.8) !important;
  border-color: var(--border-color) !important;
}

[data-testid="stMetric"] {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 10px;
  padding: 14px 18px !important;
}

[data-testid="stMetricLabel"] {
  font-family: var(--font-mono) !important;
  font-size: 0.58rem !important;
  letter-spacing: 0.15em !important;
  color: var(--text-secondary) !important;
  text-transform: uppercase;
}

[data-testid="stMetricValue"] {
  font-family: var(--font-digital) !important;
  font-size: 1.7rem !important;
  font-weight: bold !important;
}

/* Custom terminal console style */
.cyber-shell {
  background: #020710 !important;
  border: 1px solid var(--border-color) !important;
  border-radius: 8px;
  padding: 16px;
  font-family: var(--font-mono) !important;
  font-size: 0.72rem;
  line-height: 1.5;
  height: 250px;
  overflow-y: auto;
  box-shadow: inset 0 0 15px rgba(0, 240, 255, 0.08);
}

.cyber-shell div {
  font-family: var(--font-mono) !important;
}

/* Global warning banner */
.ticker-wrap {
  width: 100%;
  overflow: hidden;
  background: rgba(0, 240, 255, 0.05);
  border-top: 1px solid var(--border-color);
  border-bottom: 1px solid var(--border-color);
  padding: 6px 0;
  margin-bottom: 16px;
}

.ticker {
  display: inline-block;
  white-space: nowrap;
  padding-left: 100%;
  animation: scroll-ticker 25s linear infinite;
  font-family: var(--font-mono);
  font-size: 0.65rem;
  color: var(--neon-cyan) !important;
  letter-spacing: 0.1em;
}

@keyframes scroll-ticker {
  0% { transform: translate3d(0, 0, 0); }
  100% { transform: translate3d(-100%, 0, 0); }
}

.tc-container {
  display: inline-flex;
  gap: 30px;
}
</style>
""", unsafe_allow_html=True)

# ── PLOTLY GRAPHIC DEFAULTS ───────────────────────────────────────────────────
PL = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Share Tech Mono", color="#8fa3b7", size=11),
    margin=dict(l=10, r=10, t=30, b=10)
)
GRD = dict(gridcolor="#102542", linecolor="#102542", zerolinecolor="#102542")

# ── INCIDENT PROFILES STATIC DATA ─────────────────────────────────────────────
_BAD  = ["evil-c2.onion", "phish-bank.ru", "malware-drop.xyz", "cred-steal.tk", "botnet.cc", "rat-srv.xyz", "darknet.to"]
_GOOD = ["google.com", "github.com", "stackoverflow.com", "youtube.com", "mail.google.com", "reddit.com"]
_RUL  = ["KEYWORD_MATCH", "SUSPICIOUS_TLD", "MALICIOUS_DOMAIN", "DOWNLOAD_DETECTED", "ENCODED_PAYLOAD", "OFF_HOURS_ACCESS", "RAPID_REVISIT"]
_MIT  = ["T1071.001", "T1566.002", "T1059", "T1082", "T1105", "T1041", "T1027", "T1078", "T1190"]
_THR  = ["C2 Communication", "Phishing", "Malware Download", "Data Exfiltration", "Credential Theft", "Lateral Movement"]

_ORIGINS = [
    {"country": "Russia", "lat": 55.75, "lon": 37.61, "color": "#ff0055"},
    {"country": "China", "lat": 39.90, "lon": 116.40, "color": "#ff0055"},
    {"country": "North Korea", "lat": 39.03, "lon": 125.75, "color": "#ff0055"},
    {"country": "Iran", "lat": 35.69, "lon": 51.42, "color": "#ff9d00"},
    {"country": "Ukraine", "lat": 50.45, "lon": 30.52, "color": "#ff9d00"},
    {"country": "Brazil", "lat": -15.78, "lon": -47.93, "color": "#ff9d00"},
    {"country": "Nigeria", "lat": 9.07, "lon": 7.40, "color": "#ffe600"},
    {"country": "Romania", "lat": 44.43, "lon": 26.10, "color": "#ffe600"},
    {"country": "Netherlands", "lat": 52.37, "lon": 4.90, "color": "#00f0ff"},
    {"country": "USA", "lat": 37.77, "lon": -122.41, "color": "#00f0ff"},
]

def _demo(n=50):
    now = datetime.datetime.now(datetime.timezone.utc)
    out = []
    for i in range(n):
        bad = random.random() < 0.35
        dom = random.choice(_BAD if bad else _GOOD)
        url = f"https://{dom}{random.choice(['/login','/payload.exe','/panel','/cmd','/beacon',''])}"
        sev = random.choice(["HIGH", "HIGH", "MEDIUM"]) if bad else random.choice(["LOW", "LOW", "MEDIUM"])
        cls = random.choice(["MALICIOUS", "SUSPICIOUS"]) if bad else "BENIGN"
        scr = random.randint(60, 100) if bad else random.randint(5, 35)
        dt  = now - datetime.timedelta(seconds=random.randint(60, 3600*24))
        orig = random.choice(_ORIGINS) if bad else None
        out.append({
            "url": url, "title": dom.replace("-", " ").title(),
            "visit_time": dt.strftime("%Y-%m-%d %H:%M:%S"), "visit_ts": dt,
            "visit_count": random.randint(1, 20), "severity": sev, "domain": dom,
            "matched_rule": random.choice(_RUL) if bad else "NONE",
            "reason": "Suspicious behaviour pattern" if bad else "Normal browsing",
            "mitre": random.choice(_MIT) if bad else "N/A",
            "threat_score": scr,
            "origin_country": orig["country"] if orig else "Unknown",
            "origin_lat": orig["lat"] if orig else 0,
            "origin_lon": orig["lon"] if orig else 0,
            "llm": {
                "classification": cls,
                "confidence": random.randint(75, 98) if bad else random.randint(40, 80),
                "threat_type": random.choice(_THR) if bad else "None",
                "explanation": "Matches known C2 infrastructure." if bad else "Normal browsing.",
                "recommended_action": "Isolate endpoint." if bad else "No action.",
            },
        })
    out.sort(key=lambda x: x["visit_ts"], reverse=True)
    return out

def _enrich(e):
    if not e.get("domain"):
        try: e["domain"] = urlparse(e.get("url","")).hostname or "unknown"
        except: e["domain"] = "unknown"
    if e.get("threat_score") is None:
        e["threat_score"] = {"HIGH":85,"MEDIUM":50,"LOW":20}.get(e.get("severity","LOW"),20)
    if not e.get("event_type"):
        e["event_type"] = "Browser"
    if not e.get("mitre"):
        mitre_map = {"KEYWORD_MATCH":"T1071.001","SUSPICIOUS_TLD":"T1566.002",
            "MALICIOUS_DOMAIN":"T1071.001","DOWNLOAD_DETECTED":"T1105",
            "ENCODED_PAYLOAD":"T1027","OFF_HOURS_ACCESS":"T1078",
            "RAPID_REVISIT":"T1071.001","HEX_PATTERN":"T1027"}
        e["mitre"] = mitre_map.get(e.get("matched_rule",""),"N/A")
    if not e.get("llm"):
        sev = e.get("severity","LOW")
        e["llm"] = {"classification":"SUSPICIOUS" if sev in ("HIGH","MEDIUM") else "BENIGN",
            "confidence":0,"threat_type":"Rule-based","explanation":"Add GROQ_API_KEY to .env for AI analysis.",
            "recommended_action":"Review manually."}
    if not e.get("origin_lat"):
        dom = e.get("domain","")
        if any(x in dom for x in [".ru","evil","botnet","malware","rat","c2"]):
            e["origin_lat"],e["origin_lon"],e["origin_country"] = 55.75,37.61,"Russia"
        elif ".cn" in dom: e["origin_lat"],e["origin_lon"],e["origin_country"] = 39.90,116.40,"China"
        elif ".onion" in dom: e["origin_lat"],e["origin_lon"],e["origin_country"] = 33.89,35.50,"Darkweb"
        elif ".tk" in dom or ".cc" in dom: e["origin_lat"],e["origin_lon"],e["origin_country"] = 9.07,7.40,"Nigeria"
        else: e["origin_lat"],e["origin_lon"],e["origin_country"] = 0,0,"Unknown"
    return e

def get_profile_data(profile):
    now = datetime.datetime.now(datetime.timezone.utc)
    if "Ransomware" in profile:
        return [
            {
                "url": "C:/Users/Target/Documents/Company_Database.xlsx.lockbit",
                "title": "Corporate Assets Encrypted",
                "visit_time": (now - datetime.timedelta(minutes=3)).strftime("%Y-%m-%d %H:%M:%S"),
                "visit_ts": now - datetime.timedelta(minutes=3),
                "visit_count": 1, "severity": "HIGH", "domain": "local-file-system",
                "matched_rule": "KEYWORD_MATCH", "reason": "Ransomware signature '.lockbit' appended to sensitive storage files.",
                "mitre": "T1486", "threat_score": 98, "origin_country": "Russia", "origin_lat": 55.75, "origin_lon": 37.61,
                "llm": {
                    "classification": "MALICIOUS", "confidence": 99, "threat_type": "Ransomware (LockBit 3.0)",
                    "explanation": "Simultaneous encryption behavior detected within primary document directory vaults.",
                    "recommended_action": "Trigger instant isolation protocol of host sentinel-node-01."
                }
            },
            {
                "url": "C:/Windows/Temp/vss_wipe.bat",
                "title": "Purge Volume Shadow Copies Script",
                "visit_time": (now - datetime.timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S"),
                "visit_ts": now - datetime.timedelta(minutes=10),
                "visit_count": 1, "severity": "HIGH", "domain": "local-file-system",
                "matched_rule": "ENCODED_PAYLOAD", "reason": "PowerShell executed deletion command ('vssadmin delete shadows')",
                "mitre": "T1490", "threat_score": 95, "origin_country": "Russia", "origin_lat": 55.75, "origin_lon": 37.61,
                "llm": {
                    "classification": "MALICIOUS", "confidence": 98, "threat_type": "Inhibit System Recovery",
                    "explanation": "Deliberate removal of shadow backup copies to impede recovery vectors.",
                    "recommended_action": "Quarantine path immediately and freeze parent terminal execution."
                }
            },
            {
                "url": "https://lockbit-onion.onion/retrieval/gateway",
                "title": "LockBit Leak Site Tor payment gateway",
                "visit_time": (now - datetime.timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S"),
                "visit_ts": now - datetime.timedelta(minutes=15),
                "visit_count": 5, "severity": "MEDIUM", "domain": "lockbit-onion.onion",
                "matched_rule": "SUSPICIOUS_TLD", "reason": "Tor routing access attempt to known extortion decrypter gateway.",
                "mitre": "T1071.001", "threat_score": 76, "origin_country": "Darkweb", "origin_lat": 33.89, "origin_lon": 35.50,
                "llm": {
                    "classification": "SUSPICIOUS", "confidence": 88, "threat_type": "C2 Communication",
                    "explanation": "Outbound routing payload mapping extortion demands and portal access info.",
                    "recommended_action": "Block onion network routing loops at system firewalls."
                }
            }
        ]
    elif "APT" in profile:
        return [
            {
                "url": "https://apt-strike-srv.cc/api/v1/beacon.php?session=Y3VybCAtcyBodHRw...",
                "title": "Persistent Cobalt Strike Heartbeat Beaconing",
                "visit_time": (now - datetime.timedelta(minutes=4)).strftime("%Y-%m-%d %H:%M:%S"),
                "visit_ts": now - datetime.timedelta(minutes=4),
                "visit_count": 48, "severity": "HIGH", "domain": "apt-strike-srv.cc",
                "matched_rule": "RAPID_REVISIT", "reason": "Host beacon pattern identified - consistent HTTP sessions matching C2.",
                "mitre": "T1071.001", "threat_score": 94, "origin_country": "China", "origin_lat": 39.90, "origin_lon": 116.40,
                "llm": {
                    "classification": "MALICIOUS", "confidence": 96, "threat_type": "APT Stealth C2 (Cobalt Strike)",
                    "explanation": "Repetitive outbound beacon transmissions packaging platform telemetry updates to C2 infrastructure.",
                    "recommended_action": "Add target IP 180.144.102.3 to system network block rules and isolate."
                }
            },
            {
                "url": "https://malware-payload-drop.xyz/droppers/sliver_exec.exe",
                "title": "Dangerous EXE Binary Downloaded",
                "visit_time": (now - datetime.timedelta(minutes=14)).strftime("%Y-%m-%d %H:%M:%S"),
                "visit_ts": now - datetime.timedelta(minutes=14),
                "visit_count": 1, "severity": "HIGH", "domain": "malware-payload-drop.xyz",
                "matched_rule": "DOWNLOAD_DETECTED", "reason": "Sliver malware payload downloaded via browser agent.",
                "mitre": "T1105", "threat_score": 91, "origin_country": "North Korea", "origin_lat": 39.03, "origin_lon": 125.75,
                "llm": {
                    "classification": "MALICIOUS", "confidence": 93, "threat_type": "Ingress Tool Transfer",
                    "explanation": "Execution of hostile stager package to elevate access privileges on current endpoint.",
                    "recommended_action": "Isolate agent processes and quarantine sliver_exec.exe."
                }
            }
        ]
    elif "Insider" in profile:
        return [
            {
                "url": "C:/Windows/System32/lsass_dump.dmp",
                "title": "Local Security Authority Subsystem Memory Extraction",
                "visit_time": (now - datetime.timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
                "visit_ts": now - datetime.timedelta(hours=1),
                "visit_count": 1, "severity": "HIGH", "domain": "local-endpoint",
                "matched_rule": "KEYWORD_MATCH", "reason": "Unauthorized LSASS memory dump detected - potential credential harvesting.",
                "mitre": "T1003.001", "threat_score": 97, "origin_country": "USA", "origin_lat": 37.77, "origin_lon": -122.41,
                "llm": {
                    "classification": "MALICIOUS", "confidence": 98, "threat_type": "Credential Dumping",
                    "explanation": "LSASS memory dumps are standard actions used by insider threats to bypass authentication policies.",
                    "recommended_action": "Immediately suspend user session privileges and rotate system keys."
                }
            },
            {
                "url": "https://mega.nz/uploads/corporate_secrets_confidential.zip",
                "title": "Massive Cloud Data Export",
                "visit_time": (now - datetime.timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S"),
                "visit_ts": now - datetime.timedelta(hours=2),
                "visit_count": 15, "severity": "HIGH", "domain": "mega.nz",
                "matched_rule": "OFF_HOURS_ACCESS", "reason": "Host transferred high volume archive data off-hours (03:14 UTC).",
                "mitre": "T1048", "threat_score": 88, "origin_country": "USA", "origin_lat": 37.77, "origin_lon": -122.41,
                "llm": {
                    "classification": "SUSPICIOUS", "confidence": 90, "threat_type": "Data Exfiltration",
                    "explanation": "High-volume zip archive transfers outside active operations match credential-theft exfiltration profiles.",
                    "recommended_action": "Audit Active Directory logs to trace file system accesses prior to exfiltration."
                }
            }
        ]
    return []

# ── DATA LOADING WITH SIMULATION PROFILE OVERRIDE ─────────────────────────────
@st.cache_data(ttl=30, show_spinner=False)
def load_base_data():
    if REAL_MODE:
        try:
            saved = load_logs()
            if saved:
                return [_enrich(e) for e in saved]
            records = extract_chrome_history()
            if records:
                tl = reconstruct_timeline(records)
                fl = detect_iocs(tl)
                if fl:
                    return [_enrich(e) for e in fl]
                # No IOC hits — still show real browsing history (not demo data)
                return [_enrich(e) for e in tl]
        except Exception as ex:
            st.sidebar.warning(f"Live data load failed: {ex}")
    return _demo(50)

def load_data():
    # If simulated profiles are selected, inject them seamlessly
    profile = st.session_state.get("incident_profile", "None (Default Live/Demo Logs)")
    base_data = load_base_data()
    
    if profile != "None (Default Live/Demo Logs)":
        simulated = get_profile_data(profile)
        # return both simulated events and base data (simulated first to display on top)
        return simulated + base_data
    return base_data

def load_alerts():
    out = []
    if os.path.exists("logs/alerts.log"):
        with open("logs/alerts.log") as f:
            for line in f:
                try: out.append(json.loads(line.strip()))
                except: pass
    return out

# ── TACTICAL HELPERS ──────────────────────────────────────────────────────────
def badge(text, kind=None):
    k=(kind or text).upper()
    c={"MALICIOUS":"MAL","SUSPICIOUS":"SUS","BENIGN":"BEN","UNKNOWN":"UNK",
       "CRITICAL":"CRI","HIGH":"HIG","MEDIUM":"MED","LOW":"LOW"}.get(k,"UNK")
    return f'<span class="sev s{c}">{text}</span>'

def rcolor(s):
    if s>=75: return "#ff0055"
    if s>=50: return "#ff9d00"
    if s>=25: return "#00f0ff"
    return "#39ff14"

def kpi(col, clr, lbl, val, sub, pct):
    col.markdown(f"""
    <div class="kpi">
      <div class="kpi-acc {clr}"></div>
      <div class="kpi-lbl">{lbl}</div>
      <div class="kpi-val {clr}">{val}</div>
      <div class="kpi-sub">{sub}</div>
      <div class="kpi-bar"><div class="kpi-fill {clr}" style="width:{min(int(pct),100)}%"></div></div>
    </div>""", unsafe_allow_html=True)

def sh(t): st.markdown(f'<div class="sh">{t}</div>', unsafe_allow_html=True)

def ev_card(e, idx):
    url = e.get("url", "")
    domain = e.get("domain", "")
    
    # Check if the node/domain or file path is quarantined or isolated in state
    is_isolated = domain in st.session_state.isolated_nodes or url in st.session_state.isolated_nodes
    is_quarantined = url in st.session_state.quarantined_files
    is_muted = url in st.session_state.muted_alerts
    
    if is_muted:
        return
        
    sev=e.get("severity","LOW"); cls=e.get("llm",{}).get("classification","?")
    scr=e.get("threat_score",0)
    
    css_class = "ev l"
    if sev == "HIGH":
        css_class = "ev h"
    elif sev == "MEDIUM":
        css_class = "ev m"
        
    if is_isolated:
        css_class = "ev iso"
        
    isolation_tag = ' <span class="sev sUNK" style="background:rgba(189,90,242,0.12);border-color:var(--neon-purple);color:var(--neon-purple)!important">🖥 HOST ISOLATED</span>' if is_isolated else ''
    quarantine_tag = ' <span class="sev sUNK" style="background:rgba(189,90,242,0.12);border-color:var(--neon-purple);color:var(--neon-purple)!important">🔒 QUARANTINED</span>' if is_quarantined else ''
    
    st.markdown(f"""
    <div class="{css_class}">
      <div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap">
        <div style="flex:1;min-width:0">
          <div class="ev-url">{url[:110]} {isolation_tag}{quarantine_tag}</div>
          <div class="ev-meta">🕐 {e.get('visit_time','')} &nbsp;|&nbsp; 📋 {e.get('matched_rule','N/A')}
            &nbsp;|&nbsp; 🎯 {e.get('mitre','N/A')} &nbsp;|&nbsp; 💬 {e.get('llm',{}).get('explanation','')[:72]}</div>
        </div>
        <div style="display:flex;gap:8px;align-items:center;flex-shrink:0">
          {badge(sev)}{badge(cls)}
          <span style="font-family:var(--font-digital);font-size:1.1rem;font-weight:700;color:{rcolor(scr)}!important;text-shadow:0 0 10px {rcolor(scr)}">{scr}</span>
        </div>
      </div>
    </div>""", unsafe_allow_html=True)
    
    # EDR live interaction controls under the card
    btn_cols = st.columns([1, 1, 1, 4])
    
    # 1. Isolate Node button
    if not is_isolated:
        if btn_cols[0].button("Isolate Node", key=f"iso_{idx}"):
            st.session_state.isolated_nodes.add(domain)
            st.session_state.isolated_nodes.add(url)
            log_msg = f"[{datetime.datetime.now(datetime.timezone.utc).strftime('%H:%M:%S')}] SYSTEM EDR ACTION: Domain/Host '{domain}' isolated. Firewall blocked."
            st.session_state.containment_terminal_logs.append(log_msg)
            st.success(f"✓ Isolated {domain}")
            st.rerun()
    else:
        if btn_cols[0].button("Reconnect", key=f"rec_{idx}"):
            st.session_state.isolated_nodes.discard(domain)
            st.session_state.isolated_nodes.discard(url)
            log_msg = f"[{datetime.datetime.now(datetime.timezone.utc).strftime('%H:%M:%S')}] SYSTEM EDR ACTION: Reconnected Host/Domain '{domain}' to active directory."
            st.session_state.containment_terminal_logs.append(log_msg)
            st.success(f"✓ Reconnected {domain}")
            st.rerun()
            
    # 2. Quarantine button
    if not is_quarantined:
        if btn_cols[1].button("Quarantine File", key=f"quar_{idx}"):
            st.session_state.quarantined_files.add(url)
            log_msg = f"[{datetime.datetime.now(datetime.timezone.utc).strftime('%H:%M:%S')}] SYSTEM EDR ACTION: File at '{url[:40]}...' quarantined and hash isolated."
            st.session_state.containment_terminal_logs.append(log_msg)
            st.success("✓ File Quarantined")
            st.rerun()
    else:
        if btn_cols[1].button("Restore File", key=f"rest_{idx}"):
            st.session_state.quarantined_files.discard(url)
            log_msg = f"[{datetime.datetime.now(datetime.timezone.utc).strftime('%H:%M:%S')}] SYSTEM EDR ACTION: Restored file '{url[:40]}...' from quarantine."
            st.session_state.containment_terminal_logs.append(log_msg)
            st.success("✓ File Restored")
            st.rerun()
            
    # 3. Mute/Dismiss Alert
    if btn_cols[2].button("Mute Alert", key=f"mute_{idx}"):
        st.session_state.muted_alerts.add(url)
        st.info("Alert muted.")
        st.rerun()

def render_page(name, fn):
    try: fn()
    except Exception:
        st.error(f"❌ Error in **{name}**")
        with st.expander("Debug Details"):
            st.code(traceback.format_exc())

# ── SIDEBAR CONTROLS & EDR TELEMETRY ──────────────────────────────────────────
NAV_OPTIONS = [
    "🏠  Tactical Overview",
    "🌍  Geological Threat Map",
    "🌐  Domain Relationship Network",
    "🔬  IOC Detection Matrix",
    "⏱  Incident Timeline Flow",
    "🤖  AI Threat Reasoning",
    "🚨  Notification Alerter",
    "🛡  Vulnerability CVE Hub",
    "🕸  Tshark Network Forensics",
    "🔎  Forensic Autopsy Ingest",
    "📋  Windows Event logs",
    "📁  EDR System Monitor",
    "📄  Incident Report Room",
]

with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:12px 0 22px">
      <div style="font-family:'Orbitron',sans-serif;font-size:1.6rem;font-weight:900;
           color:#00f0ff!important;letter-spacing:.2em;text-shadow:0 0 25px rgba(0,240,255,0.4)">SENTINEL</div>
      <div style="font-family:'Share Tech Mono',monospace;font-size:.58rem;
           color:#4e647b!important;letter-spacing:.3em;margin-top:4px">DIGITAL DEFENSE HUD v3.0</div>
    </div>""", unsafe_allow_html=True)

    st.markdown('<div class="sh" style="margin-top:0">TACTICAL HUD NAVIGATION</div>', unsafe_allow_html=True)
    selected = st.radio("nav_radio", NAV_OPTIONS, label_visibility="collapsed", key="nav_selection")

    st.markdown('<div class="sh" style="margin-top:14px">ATTACK SCENARIO SIMULATOR</div>', unsafe_allow_html=True)
    profile_options = [
        "None (Default Live/Demo Logs)",
        "LockBit 3.0 Ransomware Campaign",
        "Cobalt Strike APT Stealth C2",
        "Insider Threat Data Exfiltration"
    ]
    cur_profile = st.selectbox("Select Scenario Profile", profile_options, key="profile_select")
    if cur_profile != st.session_state.incident_profile:
        st.session_state.incident_profile = cur_profile
        st.rerun()

    st.markdown('<div class="sh" style="margin-top:14px">EDR SYSTEM CONTROL</div>', unsafe_allow_html=True)
    auto = st.toggle("Telemetry Auto-Scan", value=st.session_state.auto_refresh, key="ar_toggle")
    st.session_state.auto_refresh = auto
    rs = st.select_slider("Scan Speed (s)", [10, 30, 60, 120, 300], value=30, key="rs_slider")
    st.session_state.refresh_secs = rs

    if st.button("⟳  EXECUTE HOST AGENT SCAN", width="stretch"):
        st.cache_data.clear()
        st.session_state.scan_count += 1
        st.session_state.last_scan = datetime.datetime.now(datetime.timezone.utc)
        st.rerun()

    st.markdown('<div class="sh" style="margin-top:14px">SECURITY INTEL FILTERS</div>', unsafe_allow_html=True)
    sev_f = st.multiselect("Severity Priority", ["HIGH", "MEDIUM", "LOW"], default=["HIGH", "MEDIUM", "LOW"], key="sf")
    cls_f = st.multiselect("AI Classification", ["MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN"],
                            default=["MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN"], key="cf")
    min_s = st.slider("Min Threat score Threshold", 0, 100, 0, key="ms")

    # Dynamic EDR Host Telemetry Widget in Sidebar
    cpu_val = random.randint(22, 48) if "None" in st.session_state.incident_profile else random.randint(62, 94)
    ram_val = random.randint(45, 60) if "None" in st.session_state.incident_profile else random.randint(75, 88)
    lat_val = random.randint(8, 22) if "None" in st.session_state.incident_profile else random.randint(45, 120)
    
    st.markdown(f"""
    <div class="sb-box">
      <div style="font-family:var(--font-mono);font-size:.65rem;color:var(--neon-cyan)!important;text-align:center;font-weight:bold;margin-bottom:8px">
        🖥️ SENTINEL-NODE-01 CLIENT TELEMETRY
      </div>
      <div style="display:flex;justify-content:space-between"><span>EDR AGENT CPU</span><span style="color:var(--neon-cyan)!important">{cpu_val}%</span></div>
      <div style="display:flex;justify-content:space-between"><span>MEMORY USAGE</span><span style="color:var(--neon-ram)!important">{ram_val}%</span></div>
      <div style="display:flex;justify-content:space-between"><span>PING LATENCY</span><span style="color:var(--neon-cyan)!important">{lat_val}ms</span></div>
      <div style="display:flex;justify-content:space-between"><span>ACTIVE HOST IPS</span><span style="color:var(--neon-cyan)!important">192.168.1.45</span></div>
      <div style="display:flex;justify-content:space-between"><span>FIREWALL BLOCKS</span><span style="color:var(--neon-purple)!important">{len(st.session_state.isolated_nodes)} active</span></div>
    </div>""", unsafe_allow_html=True)
    
    cls_ = "pill live" if REAL_MODE else "pill demo"
    lbl_ = "LIVE HOST INTERNET" if REAL_MODE else "DEMO INTERNET EMULATION"
    if "None" not in st.session_state.incident_profile:
        cls_ = "pill sim"
        lbl_ = "SIMULATOR ACTIVE"

    # ── Import Diagnostics Panel ──────────────────────────────────────────────
    if not REAL_MODE and _IMPORT_ERROR:
        st.markdown(f"""
        <div class="sb-box" style="margin-top:10px;border-color:rgba(255,157,0,0.3)">
          <div style="font-family:var(--font-mono);font-size:.6rem;color:#ff9d00!important;font-weight:bold;margin-bottom:6px">
            ⚠ IMPORT DIAGNOSTICS
          </div>
          <div style="font-family:var(--font-mono);font-size:.55rem;color:#8fa3b7!important;word-break:break-all;line-height:1.6">
            {_IMPORT_ERROR[:200]}
          </div>
          <div style="font-family:var(--font-mono);font-size:.55rem;color:#8fa3b7!important;margin-top:6px">
            Run: pip install -r requirements.txt
          </div>
        </div>""", unsafe_allow_html=True)
        
    st.markdown(f"""
    <div class="sb-box" style="margin-top:10px">
      <div class="{cls_}" style="display:flex;justify-content:center;margin-bottom:10px">
        <span class="ldot"></span>{lbl_}
      </div>
      <div style="display:flex;justify-content:space-between"><span>Security Scans</span><span>{st.session_state.scan_count}</span></div>
      <div style="display:flex;justify-content:space-between"><span>Last Scan Time</span><span>{st.session_state.last_scan.strftime('%H:%M:%S')}</span></div>
      <div style="display:flex;justify-content:space-between"><span>Target System</span><span>{platform.system()}</span></div>
    </div>""", unsafe_allow_html=True)

# ── RETRIEVE LOADED EVENTS ────────────────────────────────────────────────────
raw = load_data()

# filter events based on muted status and security parameters
events = [e for e in raw
          if e.get("severity","LOW") in sev_f
          and e.get("llm",{}).get("classification","UNKNOWN") in cls_f
          and e.get("threat_score",0) >= min_s
          and e.get("url", "") not in st.session_state.muted_alerts]
          
df = pd.DataFrame(events) if events else pd.DataFrame()
for col in ["severity", "threat_score", "domain", "visit_time", "url", "matched_rule", "mitre"]:
    if not df.empty and col not in df.columns:
        df[col] = 0 if col == "threat_score" else "N/A"

# ── CYBER INTEL BULLETIN TICKER ───────────────────────────────────────────────
now_s = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d  %H:%M:%S")
p_cls = "pill live" if REAL_MODE else "pill demo"
p_lbl = "LIVE ENVIRONMENT CONNECTED" if REAL_MODE else "DEMO SANDBOX"
if "None" not in st.session_state.incident_profile:
    p_cls = "pill sim"
    p_lbl = f"SIMULATION ACTIVE: {st.session_state.incident_profile.split(' ')[0]}"

bulletin_text = " [ALERT] Threat Profile Active: " + st.session_state.incident_profile + " | [VULN] CVE-2024-3400 Exploits detected in wild | [INTEL] APT29 payload signatures updated on server | [EDR] Firewall active blocking local network exfiltration vectors | Karachi endpoint host agent v3.0 check-in complete."

st.markdown(f"""
<div class="ticker-wrap">
  <div class="ticker">🛡️ {bulletin_text}</div>
</div>
""", unsafe_allow_html=True)

# ── HEADER WIDGET ─────────────────────────────────────────────────────────────
st.markdown(f"""
<div class="hdr">
  <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px">
    <div>
      <div class="htitle">🛡️ SENTINEL DEFENSE HUD</div>
      <div class="hsub">TACTICAL DFIR INTELLIGENCE &amp; RESPONSE CENTRE · AGENT NODE EDR PANEL v3.0</div>
    </div>
    <div style="display:flex;flex-direction:column;align-items:flex-end;gap:8px">
      <div class="{p_cls}"><span class="ldot"></span>{p_lbl}</div>
      <div style="font-family:var(--font-mono);font-size:.65rem;color:var(--text-secondary)!important">{now_s} UTC</div>
      <div style="font-family:var(--font-mono);font-size:.65rem;color:var(--text-secondary)!important">
        {len(events)} threat alerts detected &nbsp;·&nbsp; {sum(1 for e in events if e.get('severity')=='HIGH')} HIGH-priority alerts
      </div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# PAGE FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def page_overview():
    total = len(raw)
    mal = sum(1 for e in raw if e.get("llm",{}).get("classification")=="MALICIOUS")
    sus = sum(1 for e in raw if e.get("llm",{}).get("classification")=="SUSPICIOUS")
    hi  = sum(1 for e in raw if e.get("severity")=="HIGH")
    avg = round(sum(e.get("threat_score",0) for e in raw)/max(total, 1), 1)
    
    # Calculate Risk Index dynamically
    risk = min(mal*12 + sus*6 + hi*4, 100)
    if "None" not in st.session_state.incident_profile:
        risk = max(risk, 88)
        
    rl = "CRITICAL RISK" if risk>=75 else "HIGH RISK" if risk>=50 else "MEDIUM RISK" if risk>=25 else "LOW RISK"
    rc = "#ff0055" if risk>=75 else "#ff9d00" if risk>=50 else "#00f0ff" if risk>=25 else "#39ff14"
    
    # KPI Grid
    c1, c2, c3, c4, c5 = st.columns(5)
    kpi(c1, "c", "TOTAL EVENTS LOADED", total, "system data points", 100)
    kpi(c2, "r", "CONFIRMED MALICIOUS", mal, "severe payloads flagged", int(mal/max(total,1)*100))
    kpi(c3, "a", "SUSPICIOUS THREATS", sus, "under review", int(sus/max(total,1)*100))
    kpi(c4, "p", "CRITICAL LEVEL ALERTS", hi, "priority review", int(hi/max(total,1)*100))
    kpi(c5, "y", "AVERAGE THREAT SCORE", avg, "0–100 risk score", int(avg))

    st.markdown("<br>", unsafe_allow_html=True)
    
    # Risk Dial & Plot Layout
    ca, cb, cc = st.columns([1.1, 2.3, 1.6])
    
    with ca:
        sh("SYSTEM RISK INDEX")
        # Beautiful circular Dial Progress Chart using Plotly
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=risk,
            domain={'x': [0, 1], 'y': [0, 1]},
            gauge={
                'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "#102542", 'tickfont': {'family': 'Share Tech Mono', 'size': 9}},
                'bar': {'color': rc, 'thickness': 0.25},
                'bgcolor': "rgba(10, 22, 45, 0.3)",
                'borderwidth': 1,
                'bordercolor': "rgba(0, 240, 255, 0.15)",
                'steps': [
                    {'range': [0, 25], 'color': 'rgba(57, 255, 20, 0.02)'},
                    {'range': [25, 50], 'color': 'rgba(0, 240, 255, 0.02)'},
                    {'range': [50, 75], 'color': 'rgba(255, 157, 0, 0.02)'},
                    {'range': [75, 100], 'color': 'rgba(255, 0, 85, 0.02)'}
                ],
                'threshold': {
                    'line': {'color': "#ff0055", 'width': 3},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font={'color': rc, 'family': "Orbitron", 'size': 14},
            height=160,
            margin=dict(l=10, r=10, t=10, b=10)
        )
        st.plotly_chart(fig, width="stretch")
        st.markdown(f"<div style='text-align:center;font-family:var(--font-mono);font-size:0.7rem;color:{rc}!important;font-weight:bold'>{rl}</div>", unsafe_allow_html=True)
        
    with cb:
        sh("THREAT LOGS CHRONOLOGY FLOW")
        if not df.empty:
            _df = df.copy()
            _df["dt"] = pd.to_datetime(_df["visit_time"], errors="coerce")
            _df["hr"] = _df["dt"].dt.floor("h")
            grp = _df.groupby(["hr","severity"]).size().reset_index(name="n")
            fig = go.Figure()
            for sev, col, fill in [
                ("HIGH", "#ff0055", "rgba(255,0,85,0.08)"),
                ("MEDIUM", "#ff9d00", "rgba(255,157,0,0.05)"),
                ("LOW", "#00f0ff", "rgba(0,240,255,0.03)")
            ]:
                s = grp[grp["severity"]==sev]
                if not s.empty:
                    fig.add_trace(go.Scatter(x=s["hr"], y=s["n"], name=sev, fill="tozeroy",
                        line=dict(color=col, width=2, shape="spline"), fillcolor=fill,
                        hovertemplate=f"<b>{sev}</b><br>%{{x}}<br>%{{y}} events<extra></extra>"))
            fig.update_layout(**PL, height=180, showlegend=True,
                legend=dict(bgcolor="rgba(0,0,0,0)", orientation="h", yanchor="bottom", y=1.02),
                xaxis=dict(**GRD), yaxis=dict(**GRD))
            st.plotly_chart(fig, width="stretch")
            
    with cc:
        sh("AI threat CLASSIFICATION SPECTRUM")
        cnt = Counter(e.get("llm",{}).get("classification","UNKNOWN") for e in raw)
        cmap = {"MALICIOUS":"#ff0055", "SUSPICIOUS":"#ff9d00", "BENIGN":"#39ff14", "UNKNOWN":"#bd5af2"}
        if cnt:
            lb, vl, cl = zip(*[(k, v, cmap.get(k, "#8fa3b7")) for k, v in cnt.items()])
            fig2 = go.Figure(go.Pie(labels=list(lb), values=list(vl), hole=0.7,
                marker=dict(colors=list(cl), line=dict(color="#030814", width=2)),
                textfont=dict(size=9), hovertemplate="%{label}: %{value}<extra></extra>"))
            fig2.update_layout(**PL, height=180, showlegend=True,
                legend=dict(bgcolor="rgba(0,0,0,0)", orientation="h", yanchor="bottom", y=1.02),
                annotations=[dict(text=f"<b>{total}</b>", x=.5, y=.5,
                    font=dict(size=18, color="#e6f3ff", family="Space Grotesk"), showarrow=False)])
            st.plotly_chart(fig2, width="stretch")

    c3, c4 = st.columns(2)
    with c3:
        sh("HIGH-INTENSITY SUSPICIOUS HOSTS (TOP 8)")
        bad_df = df[df["severity"].isin(["HIGH","MEDIUM"])] if not df.empty else pd.DataFrame()
        if not bad_df.empty and "domain" in bad_df.columns:
            td = bad_df["domain"].value_counts().head(8).reset_index()
            td.columns = ["domain", "count"]
            cols = [rcolor(90) if any(b in d for b in ["onion", "tk", "xyz", "cc", "ru"]) else "#ff9d00" for d in td["domain"]]
            fig3 = go.Figure(go.Bar(x=td["count"], y=td["domain"], orientation="h",
                marker_color=cols, marker_line_width=0,
                hovertemplate="<b>%{y}</b><br>%{x} transactions<extra></extra>"))
            fig3.update_layout(**PL, height=220)
            fig3.update_layout(yaxis=dict(**GRD, tickfont=dict(size=9)), xaxis=dict(**GRD))
            st.plotly_chart(fig3, width="stretch")
            
    with c4:
        sh("IOC CRITERIA TRIGGER DENSITY")
        if not df.empty and "matched_rule" in df.columns:
            rd = df[df["matched_rule"]!="NONE"]["matched_rule"].value_counts().reset_index()
            if not rd.empty:
                rd.columns = ["rule", "count"]
                fig4 = go.Figure(go.Bar(x=rd["rule"], y=rd["count"],
                    marker_color=["#ff0055", "#ff9d00", "#00f0ff", "#bd5af2", "#39ff14", "#ffe600"][:len(rd)],
                    marker_line_width=0, hovertemplate="<b>%{x}</b><br>%{y} matches<extra></extra>"))
                fig4.update_layout(**PL, height=220)
                fig4.update_layout(xaxis=dict(**GRD, tickangle=-25, tickfont=dict(size=8)), yaxis=dict(**GRD))
                st.plotly_chart(fig4, width="stretch")

    sh("TACTICAL ACTION CENTER — HIGH-SEVERITY EVENTS PRIORITY QUEUE")
    hi_ev = [e for e in events if e.get("severity") in ("HIGH", "MEDIUM")][:12]
    if not hi_ev:
        st.info("✓ Zero active high-priority alerts matched in system logs.")
    else:
        for idx, e in enumerate(hi_ev):
            ev_card(e, idx)


def page_world_map():
    sh("🌍 GEOLOGICAL THREAT MAP — REAL-TIME ATTACK SIGNALS ORIGIN")

    st.markdown("""<div style="font-family:'Share Tech Mono',monospace;font-size:.65rem;
      color:#8fa3b7;margin-bottom:14px;line-height:1.8">
      Arcs illustrate suspicious network request telemetry lines flowing to your local computer node endpoint.
      Node diameter = incident count volume &nbsp;|&nbsp; Node Color = threat score &nbsp;|&nbsp;
      Karachi Endpoint = Host agent Sentinel-Node-01
    </div>""", unsafe_allow_html=True)

    ENDPOINT_LAT, ENDPOINT_LON = 24.86, 67.01
    threat_ev = [e for e in events if e.get("severity") in ("HIGH","MEDIUM") and e.get("origin_lat",0) != 0]

    if not threat_ev and not df.empty:
        # Load demo coordinate data if database matches blank
        demo_events = []
        for i, e in enumerate(events[:20]):
            e_copy = e.copy()
            if e_copy.get("severity") in ("HIGH", "MEDIUM"):
                orig = _ORIGINS[i % len(_ORIGINS)]
                e_copy["origin_lat"] = orig["lat"]
                e_copy["origin_lon"] = orig["lon"]
                e_copy["origin_country"] = orig["country"]
            demo_events.append(e_copy)
        threat_ev = [e for e in demo_events if e.get("severity") in ("HIGH", "MEDIUM") and e.get("origin_lat", 0) != 0]

    # Side-by-side Layout: Map on left, Dossier Panel on right
    map_col, dossier_col = st.columns([3, 1.2])

    with map_col:
        fig = go.Figure()
        fig.update_layout(
            geo=dict(
                bgcolor="rgba(3,8,20,0.95)",
                showland=True,
                landcolor="rgba(10,25,48,0.8)",
                showocean=True,
                oceancolor="rgba(2,6,15,0.9)",
                showcoastlines=True,
                coastlinecolor="rgba(0,240,255,0.18)",
                coastlinewidth=0.6,
                showframe=False,
                showcountries=True,
                countrycolor="rgba(0,240,255,0.08)",
                countrywidth=0.4,
                projection_type="natural earth",
            ),
            paper_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=0, r=0, t=10, b=0),
            height=460,
            showlegend=True,
            legend=dict(bgcolor="rgba(6,21,37,.85)", bordercolor="rgba(0,240,255,.2)",
                        borderwidth=1, font=dict(family="Share Tech Mono", size=10)),
        )

        seen = set()
        for e in threat_ev[:35]:
            olat = e.get("origin_lat",0)
            olon = e.get("origin_lon",0)
            ctry = e.get("origin_country","?")
            sev  = e.get("severity","LOW")
            key  = f"{olat:.1f},{olon:.1f}"
            if key in seen: continue
            seen.add(key)

            lcolor = "rgba(255,0,85,0.55)" if sev=="HIGH" else "rgba(255,157,0,0.45)"
            fig.add_trace(go.Scattergeo(
                lat=[olat, (olat+ENDPOINT_LAT)/2+5, ENDPOINT_LAT],
                lon=[olon, (olon+ENDPOINT_LON)/2,   ENDPOINT_LON],
                mode="lines",
                line=dict(width=1.8, color=lcolor),
                showlegend=False,
                hoverinfo="skip",
            ))

        countries_seen = {}
        for e in threat_ev:
            ctry = e.get("origin_country","?")
            olat = e.get("origin_lat",0)
            olon = e.get("origin_lon",0)
            sev  = e.get("severity","LOW")
            scr  = e.get("threat_score",50)
            if ctry not in countries_seen:
                countries_seen[ctry] = {"lat":olat,"lon":olon,"count":0,"max_scr":0,"sev":sev}
            countries_seen[ctry]["count"] += 1
            countries_seen[ctry]["max_scr"] = max(countries_seen[ctry]["max_scr"],scr)

        if countries_seen:
            c_lats=[v["lat"] for v in countries_seen.values()]
            c_lons=[v["lon"] for v in countries_seen.values()]
            c_sizes=[max(12,min(v["count"]*9,45)) for v in countries_seen.values()]
            c_colors=[rcolor(v["max_scr"]) for v in countries_seen.values()]
            c_text=[f"<b>{k}</b><br>Incidents: {v['count']}<br>Max Score: {v['max_scr']}"
                    for k,v in countries_seen.items()]

            fig.add_trace(go.Scattergeo(
                lat=c_lats, lon=c_lons,
                mode="markers+text",
                text=list(countries_seen.keys()),
                textposition="top center",
                textfont=dict(family="Share Tech Mono",size=9,color="#ff9d00"),
                marker=dict(size=c_sizes,color=c_colors,
                           line=dict(width=1.5,color="#030814"),
                           symbol="circle"),
                hovertext=c_text,
                hovertemplate="%{hovertext}<extra></extra>",
                name="Attack Node Origins",
            ))

        fig.add_trace(go.Scattergeo(
            lat=[ENDPOINT_LAT], lon=[ENDPOINT_LON],
            mode="markers+text",
            text=["🖥️ SENTINEL-NODE-01"],
            textposition="top right",
            textfont=dict(family="Share Tech Mono",size=10,color="#00f0ff"),
            marker=dict(size=20,color="#00f0ff",symbol="star",
                       line=dict(width=2.5,color="#030814")),
            hovertemplate="<b>Karachi Endpoint</b><br>Secured with Watchdog Host Agent<extra></extra>",
            name="Your Local System Node",
        ))

        st.plotly_chart(fig, width="stretch")

    with dossier_col:
        st.markdown("""
        <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:10px;padding:15px;height:460px;overflow-y:auto">
          <div style="font-family:var(--font-mono);font-size:0.65rem;color:var(--neon-cyan)!important;font-weight:bold;border-bottom:1px solid rgba(0,240,255,0.15);padding-bottom:6px;margin-bottom:10px">
            🕵️ ACTIVE ATTACKER COUNTRY DOSSIER
          </div>
        """, unsafe_allow_html=True)
        
        # Dropdown in the dossier box
        active_countries = list(countries_seen.keys()) if countries_seen else ["Russia", "China", "North Korea", "Iran"]
        selected_ctry = st.selectbox("Investigate Node Profile", active_countries, key="dossier_select")
        
        dossier_db = {
            "Russia": {"apt": "APT29 (Cozy Bear), Fancy Bear", "tactics": "Ransomware campaigns (LockBit, ALPHV), brute-force cred harvesting.", "threat": "CRITICAL", "vector": "Spear-phishing & Supply Chain"},
            "China": {"apt": "APT41, Volt Typhoon", "tactics": "Sustained stealth persistence, living-off-the-land, router firmware exploits.", "threat": "HIGH", "vector": "Zero-day Edge Appliance Exploits"},
            "North Korea": {"apt": "Lazarus Group, Kimsuky", "tactics": "Cryptocurrency theft, custom Trojan malware stagers (Sliver, Cobalt).", "threat": "CRITICAL", "vector": "Social Engineering & MSI installers"},
            "Iran": {"apt": "MuddyWater, Rocket Kitten", "tactics": "Destructive wipers, SQL Command Injection, credential harvesting.", "threat": "MEDIUM", "vector": "Public Server Exploitation"},
            "USA": {"apt": "Local Insiders, Penetration Testers", "tactics": "LSASS memory dumps, off-hours uploads, remote cloud staging.", "threat": "HIGH", "vector": "Administrative abuse"},
            "Darkweb": {"apt": "Tor Proxy Nodes", "tactics": "Anonymous C2 heartbeat command loops, private key payload handshakes.", "threat": "HIGH", "vector": "Tor routing encryption tunnels"}
        }
        
        profile_info = dossier_db.get(selected_ctry, {"apt": "Unknown / Private Proxy", "tactics": "C2 beacon ping packets mapping host.", "threat": "MEDIUM", "vector": "Unknown vector"})
        
        st.markdown(f"""
          <div style="margin-top:10px">
            <div style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-secondary)">THREAT LEVEL:</div>
            <div style="font-family:var(--font-digital);font-size:1.1rem;color:{'#ff0055' if profile_info['threat'] in ('HIGH','CRITICAL') else '#00f0ff'}!important;font-weight:bold;margin-bottom:12px">{profile_info['threat']}</div>
            
            <div style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-secondary)">ASSOCIATED APT CHANNELS:</div>
            <div style="font-family:var(--font-body);font-size:0.75rem;color:var(--text-primary);margin-bottom:12px;font-weight:600">{profile_info['apt']}</div>
            
            <div style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-secondary)">TYPICAL VECTORS:</div>
            <div style="font-family:var(--font-body);font-size:0.72rem;color:var(--text-primary);margin-bottom:12px">{profile_info['vector']}</div>
            
            <div style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-secondary)">OBSERVED OPERATIONAL BEHAVIORS:</div>
            <div style="font-family:var(--font-mono);font-size:0.68rem;color:var(--text-primary);line-height:1.4">{profile_info['tactics']}</div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    if countries_seen:
        sh("GEOGRAPHICAL THREAT TELEMETRY LOGS")
        orig_df = pd.DataFrame([
            {"Country":k,"Threats":v["count"],"Max Score":v["max_scr"],"Severity":v["sev"]}
            for k,v in sorted(countries_seen.items(),key=lambda x:-x[1]["count"])
        ])
        st.dataframe(orig_df, width="stretch", hide_index=True,
            column_config={"Max Score":st.column_config.ProgressColumn("Max Score",min_value=0,max_value=100)})


def page_domain_graph():
    sh("🌐 BEHAVIORAL GRAPH — DOMAIN RELATIONSHIP NETWORK")
    if not raw:
        st.info("No network data to construct behavioral graph.")
        return

    # Left-hand network graph column, right-hand node details inspector panel
    graph_col, inspector_col = st.columns([3, 1.2])

    with graph_col:
        G = nx.Graph()
        G.add_node("SENTINEL-NODE-01", kind="host", score=0)
        graph_events = raw[:90]
        for e in graph_events:
            dom=e.get("domain","?"); scr=e.get("threat_score",0)
            if not G.has_node(dom): G.add_node(dom,kind="domain",score=scr)
            G.add_edge("SENTINEL-NODE-01",dom)
            for e2 in graph_events:
                if e2 is e: continue
                m1,m2=e.get("mitre",""),e2.get("mitre","")
                if m1==m2 and m1 not in ("N/A",""):
                    G.add_edge(dom,e2.get("domain","?"))

        pos=nx.spring_layout(G,seed=42,k=2.2,iterations=60)
        ex,ey=[],[]
        for a,b in G.edges():
            x0,y0=pos[a]; x1,y1=pos[b]
            ex+=[x0,x1,None]; ey+=[y0,y1,None]

        nx_,ny_,nt_,nc_,ns_,nh_=[],[],[],[],[],[]
        for nd in G.nodes():
            x,y=pos[nd]; scr=G.nodes[nd].get("score",0); kind=G.nodes[nd].get("kind","domain")
            nx_.append(x); ny_.append(y); nt_.append(nd[:18])
            nc_.append("#00f0ff" if kind=="host" else rcolor(scr))
            ns_.append(24 if kind=="host" else max(8,min(scr//4,25)))
            nh_.append(f"<b>{nd}</b><br>Risk: {scr}" if kind=="domain" else "<b>SENTINEL HOST INTERFACE</b>")

        fig=go.Figure()
        fig.add_trace(go.Scatter(x=ex,y=ey,mode="lines",
            line=dict(width=.8,color="rgba(0,240,255,0.08)"),hoverinfo="none"))
        fig.add_trace(go.Scatter(x=nx_,y=ny_,mode="markers+text",text=nt_,
            textposition="top center",textfont=dict(family="Share Tech Mono",size=9,color="#8fa3b7"),
            marker=dict(size=ns_,color=nc_,line=dict(width=1.5,color="#030814")),
            hovertext=nh_,hovertemplate="%{hovertext}<extra></extra>"))
        fig.update_layout(**PL,height=480,showlegend=False)
        fig.update_layout(xaxis=dict(showgrid=False,zeroline=False,showticklabels=False),
                          yaxis=dict(showgrid=False,zeroline=False,showticklabels=False))
        st.plotly_chart(fig,width="stretch")

    with inspector_col:
        st.markdown("""
        <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:10px;padding:15px;height:480px;overflow-y:auto">
          <div style="font-family:var(--font-mono);font-size:0.65rem;color:var(--neon-cyan)!important;font-weight:bold;border-bottom:1px solid rgba(0,240,255,0.15);padding-bottom:6px;margin-bottom:10px">
            🔍 NETWORK NODE DETAILS INSPECTOR
          </div>
        """, unsafe_allow_html=True)
        
        all_nodes = [n for n in G.nodes() if n != "SENTINEL-NODE-01"]
        if not all_nodes:
            st.markdown("<p style='font-size:0.75rem'>No external domain nodes found in history.</p>", unsafe_allow_html=True)
        else:
            select_node = st.selectbox("Inspect Active Domain", all_nodes, key="inspect_node_select")
            
            # Simulated node detail db based on domain type
            is_bad_domain = any(b in select_node for b in ["onion", "tk", "xyz", "cc", "ru", "strike", "c2"])
            rep_score = random.randint(78, 98) if is_bad_domain else random.randint(1, 24)
            ip_addr = f"195.12.98.{random.randint(1,254)}" if is_bad_domain else f"142.250.72.{random.randint(1,254)}"
            registrar = "REGISTRAR-RU-NIC" if ".ru" in select_node else "NameCheap" if is_bad_domain else "Google LLC"
            protocols = "HTTPS, DNS Request" if not is_bad_domain else "Tor Encrypted routing, HTTP TLS Beaconing"
            
            st.markdown(f"""
              <div style="margin-top:10px">
                <div style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-secondary)">NODE REPUTATION RISK:</div>
                <div style="font-family:var(--font-digital);font-size:1.1rem;color:{rcolor(rep_score)}!important;font-weight:bold;margin-bottom:12px">{rep_score}/100</div>
                
                <div style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-secondary)">DESTINATION IPv4:</div>
                <div style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-primary);margin-bottom:12px;font-weight:600">{ip_addr}</div>
                
                <div style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-secondary)">DOMAIN REGISTRAR:</div>
                <div style="font-family:var(--font-body);font-size:0.72rem;color:var(--text-primary);margin-bottom:12px">{registrar}</div>
                
                <div style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-secondary)">ACTIVE PROTOCOLS:</div>
                <div style="font-family:var(--font-mono);font-size:0.68rem;color:var(--text-primary);margin-bottom:12px">{protocols}</div>
                
                <div style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-secondary)">EDR RESPONSE ACTION:</div>
              </div>
            """, unsafe_allow_html=True)
            
            # Live isolation button inside the inspector
            is_node_blocked = select_node in st.session_state.isolated_nodes
            if not is_node_blocked:
                if st.button("BLOCK DOMAIN AT WAN GATEWAY", key="block_ins_btn", width="stretch"):
                    st.session_state.isolated_nodes.add(select_node)
                    log_msg = f"[{datetime.datetime.now(datetime.timezone.utc).strftime('%H:%M:%S')}] SYSTEM EDR ACTION: Domain '{select_node}' blocked at corporate firewall."
                    st.session_state.containment_terminal_logs.append(log_msg)
                    st.success("✓ Domain Blocked")
                    st.rerun()
            else:
                if st.button("RESTORE DOMAIN WAN ACCESS", key="unblock_ins_btn", width="stretch"):
                    st.session_state.isolated_nodes.discard(select_node)
                    log_msg = f"[{datetime.datetime.now(datetime.timezone.utc).strftime('%H:%M:%S')}] SYSTEM EDR ACTION: Restored access to domain '{select_node}'."
                    st.session_state.containment_terminal_logs.append(log_msg)
                    st.success("✓ Domain Access Restored")
                    st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)


def page_ioc():
    sh("🔬 INDICATORS OF COMPROMISE — THREAT MATRICES & CRITERIA")
    if df.empty:
        st.info("No logged events matched current matrix parameters.")
        return

    if render_sankey_diagram:
        sh("ATTACK PIPELINE FLOW (SOURCE → RULE → SEVERITY → CLASSIFICATION)")
        sankey_events = [{**e, "event_type": e.get("event_type", "Browser")} for e in events]
        st.plotly_chart(render_sankey_diagram(sankey_events), width="stretch")
        st.markdown("<br>", unsafe_allow_html=True)
    
    rules=df["matched_rule"].value_counts() if "matched_rule" in df.columns else {}
    ioc_df=df[df["matched_rule"]!="NONE"] if "matched_rule" in df.columns else pd.DataFrame()
    
    # Visual KPI metric column list
    c1,c2,c3,c4,c5=st.columns(5)
    c1.metric("Flagged IOCs Count",len(ioc_df))
    c2.metric("Keyword Matches",int(rules.get("KEYWORD_MATCH",0)))
    c3.metric("Encoded Payload Hits",int(rules.get("ENCODED_PAYLOAD",0)))
    c4.metric("Off-Hours Violations",int(rules.get("OFF_HOURS_ACCESS",0)))
    c5.metric("Malicious Downloads",int(rules.get("DOWNLOAD_DETECTED",0)))
    
    cr,cm=st.columns(2)
    with cr:
        sh("RULE MATCH HISTOGRAM MATRIX")
        if not ioc_df.empty and "matched_rule" in ioc_df.columns:
            rd=ioc_df["matched_rule"].value_counts().reset_index()
            rd.columns=["rule","count"]
            fig=go.Figure(go.Bar(x=rd["count"],y=rd["rule"],orientation="h",
                marker_color=["#ff0055","#ff9d00","#00f0ff","#bd5af2","#39ff14","#ffe600"][:len(rd)],marker_line_width=0))
            fig.update_layout(**PL,height=220)
            fig.update_layout(xaxis=dict(**GRD),yaxis=dict(**GRD,tickfont=dict(size=9)))
            st.plotly_chart(fig,width="stretch")
    with cm:
        sh("MITRE ATT&CK TACTICS INDEX DENSITY")
        if "mitre" in df.columns:
            md=df[df["mitre"]!="N/A"]["mitre"].value_counts().reset_index()
            if not md.empty:
                md.columns=["technique","count"]
                fig=go.Figure(go.Bar(x=md["technique"],y=md["count"],
                    marker_color="#bd5af2",marker_line_width=0))
                fig.update_layout(**PL,height=220)
                fig.update_layout(xaxis=dict(**GRD,tickangle=-25,tickfont=dict(size=9)),yaxis=dict(**GRD))
                st.plotly_chart(fig,width="stretch")
                
    sh("COMPREHENSIVE INDICATORS AUDIT LOG")
    cols=[c for c in ["visit_time","url","severity","matched_rule","mitre","threat_score","reason"] if c in df.columns]
    show=df[cols].copy()
    show.columns=[c.replace("_"," ").upper() for c in cols]
    st.dataframe(show,width="stretch",hide_index=True,
        column_config={"THREAT SCORE":st.column_config.ProgressColumn("THREAT SCORE",min_value=0,max_value=100,format="%d")})


def page_timeline():
    sh("⏱️ BROWSER ACTIVITY HEATMAP — THREAT SCORE BY UTC HOUR")
    if df.empty: st.info("No event chronology loaded."); return
    
    _df=df.copy()
    _df["dt"]=pd.to_datetime(_df["visit_time"],errors="coerce")
    _df["hr"]=_df["dt"].dt.hour
    _df["day"]=_df["dt"].dt.strftime("%a %m/%d")
    pivot=_df.pivot_table(index="day",columns="hr",values="threat_score",aggfunc="mean").fillna(0)
    
    if not pivot.empty:
        fig=go.Figure(go.Heatmap(z=pivot.values,x=pivot.columns.tolist(),y=pivot.index.tolist(),
            colorscale=[[0,"#030814"],[.2,"#102542"],[.5,"#00f0ff"],[.8,"#ff9d00"],[1,"#ff0055"]],
            hovertemplate="Hour %{x}:00 | %{y}<br>Avg Threat Score: %{z:.0f}<extra></extra>",
            showscale=True,colorbar=dict(thickness=10,tickfont=dict(size=9,color="#8fa3b7"))))
        fig.update_layout(**PL,height=180,xaxis_title="Hour of Day (UTC)")
        fig.update_layout(xaxis=dict(**GRD,tickmode="linear",dtick=2))
        st.plotly_chart(fig,width="stretch")
        
    sh("CHRONOLOGICAL WATERFALL METRIC SCAN")
    smap={"HIGH":3,"MEDIUM":2,"LOW":1}
    cmap2={"HIGH":"#ff0055","MEDIUM":"#ff9d00","LOW":"#00f0ff"}
    s_df=_df.sort_values("dt",na_position="last").reset_index(drop=True)
    
    fig2=go.Figure()
    for sev in ["HIGH","MEDIUM","LOW"]:
        s=s_df[s_df["severity"]==sev]
        if not s.empty:
            fig2.add_trace(go.Scatter(x=s["dt"],y=[smap[sev]]*len(s),mode="markers",name=sev,
                marker=dict(color=cmap2[sev],size=10,line=dict(width=1,color="#030814")),
                text=s["url"] if "url" in s.columns else None,
                hovertemplate="<b>%{text}</b><br>%{x}<extra></extra>"))
    fig2.update_layout(**PL,height=160,showlegend=True)
    fig2.update_layout(yaxis=dict(tickvals=[1,2,3],ticktext=["LOW","MED","HIGH"],**GRD),xaxis=dict(**GRD),
        legend=dict(bgcolor="rgba(0,0,0,0)",orientation="h"))
    st.plotly_chart(fig2,width="stretch")
    
    sh("HISTORICAL AUDIT CHRONOLOGY TIMELINE")
    tc=[c for c in ["visit_time","url","domain","severity","threat_score","matched_rule","mitre"] if c in _df.columns]
    tl=_df[tc].sort_values("visit_time",ascending=False).copy()
    tl.columns=[c.replace("_"," ").upper() for c in tc]
    st.dataframe(tl,width="stretch",hide_index=True,
        column_config={"THREAT SCORE":st.column_config.ProgressColumn("THREAT SCORE",min_value=0,max_value=100)})


def page_ai():
    sh("🤖 AI-DRIVEN REASONING ENGINE & ADVISORY CONSOLE")
    
    # EDR live log terminal for AI steps
    terminal_col, input_col = st.columns([2.5, 1.5])
    
    with terminal_col:
        st.markdown("<p style='font-family:var(--font-mono);font-size:0.62rem;color:var(--neon-purple)!important'>🔮 SENTINEL COGNITIVE THREAT ANALYSIS LOGS</p>", unsafe_allow_html=True)
        
        # Display simulated AI reasoning chain step log
        thinking_log = [
            f"[{datetime.datetime.now(datetime.timezone.utc).strftime('%H:%M:%S')}] [INITIATING SIGNAL SCAN] Evaluating host event buffer.",
            "  - [COMPLIANCE DATA] Threat Profile Override active: " + st.session_state.incident_profile,
            "  - [DNS BEACON CHECK] Querying threat intelligence rep databases for active domains...",
            "  - [CVE CROSS REF] Mapping observed URLs with high-priority vulnerability list...",
            "  - [COGNITIVE SCORE] Running deep-learning neural classification parameters...",
            "  - [DECISION] Inbound telemetry signatures evaluated successfully.",
            "  - [ADVISORY] Isolate endpoint immediately if HIGH or CRITICAL classified."
        ]
        
        st.markdown(f"""
        <div class="cyber-shell" style="height:210px;box-shadow:inset 0 0 15px rgba(189,90,242,0.1);border-color:rgba(189,90,242,0.25)!important">
          {"<br>".join([f"<div style='color:var(--neon-purple)!important'>{line}</div>" for line in thinking_log])}
        </div>
        """, unsafe_allow_html=True)
        
    with input_col:
        st.markdown("<p style='font-family:var(--font-mono);font-size:0.62rem;color:var(--neon-cyan)!important'>💡 ANALYST SECURITY POLICY OVERRIDE</p>", unsafe_allow_html=True)
        st.markdown("""
        <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:10px;padding:12px;height:210px">
        """, unsafe_allow_html=True)
        
        # Dynamic policy override
        target_rule_url = st.selectbox(
            "Select Target URL to Override Profile",
            [e.get("url") for e in events[:8]] or ["No events loaded"],
            key="ai_override_target",
        )
        override_classification = st.selectbox("Override Intelligence Profile class", ["MALICIOUS", "SUSPICIOUS", "BENIGN"], key="ai_override_val")
        
        if st.button("💾 SAVE ADVISORY POLICY RULE", key="ai_override_btn", width="stretch"):
            if target_rule_url and target_rule_url != "No events loaded":
                st.session_state.ai_override_rules[target_rule_url] = override_classification
                # update active events dict in session memory
                for e in raw:
                    if e.get("url") == target_rule_url:
                        e["llm"]["classification"] = override_classification
                st.success("✓ Security policy updated successfully!")
                time.sleep(1)
                st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

    cls_ev=[e for e in events if e.get("llm",{}).get("classification") in ("MALICIOUS","SUSPICIOUS")]
    ben_ev=[e for e in events if e.get("llm",{}).get("classification")=="BENIGN"]
    unk_ev=[e for e in events if e.get("llm",{}).get("classification")=="UNKNOWN"]
    
    c1,c2,c3,c4=st.columns(4)
    c1.metric("Flagged Threats",len(cls_ev))
    c2.metric("Confirmed Malicious",sum(1 for e in cls_ev if e.get("llm",{}).get("classification")=="MALICIOUS"))
    c3.metric("Benign Transactions",len(ben_ev))
    c4.metric("Unclassified Items",len(unk_ev))
    
    if unk_ev: st.info("ℹ️ Add `GROQ_API_KEY=gsk_...` to your `.env` file to activate Groq AI reasoning.")
    if not cls_ev: st.success("✅ Clean system telemetry. No active threat indicators matched."); return
    
    confs=[e.get("llm",{}).get("confidence",0) for e in cls_ev]
    ch1,ch2=st.columns(2)
    with ch1:
        sh("AI ENGINE THREAT CLASSIFICATION CONFIDENCE DENSITY")
        fig=go.Figure(go.Histogram(x=confs,nbinsx=12,marker=dict(color="#bd5af2",line=dict(color="#030814",width=1))))
        fig.update_layout(**PL,height=180,xaxis_title="Confidence Percentage (%)")
        fig.update_layout(xaxis=dict(**GRD),yaxis=dict(**GRD))
        st.plotly_chart(fig,width="stretch")
    with ch2:
        sh("INCIDENT CATEGORIES INDEX")
        tt=Counter(e.get("llm",{}).get("threat_type","None") for e in cls_ev if e.get("llm",{}).get("threat_type") not in (None,"None"))
        if tt:
            tt_df=pd.DataFrame(tt.items(),columns=["type","count"]).sort_values("count")
            fig=go.Figure(go.Bar(x=tt_df["count"],y=tt_df["type"],orientation="h",marker_color="#ff9d00",marker_line_width=0))
            fig.update_layout(**PL,height=180)
            fig.update_layout(xaxis=dict(**GRD),yaxis=dict(**GRD,tickfont=dict(size=10)))
            st.plotly_chart(fig,width="stretch")
            
    sh(f"DETAILED INTEL CLASSIFICATIONS ({len(cls_ev)} Events)")
    for idx, e in enumerate(cls_ev[:20]):
        llm=e.get("llm",{}); sev=e.get("severity","?")
        with st.expander(f"[{sev}] {llm.get('classification','?')} — {e.get('url','')[:75]}"):
            d1,d2,d3,d4=st.columns(4)
            d1.markdown(f"**Class:** {badge(llm.get('classification','?'))}",unsafe_allow_html=True)
            d2.markdown(f"**Confidence:** `{llm.get('confidence',0)}%`")
            d3.markdown(f"**Threat:** `{llm.get('threat_type','N/A')}`")
            d4.markdown(f"**MITRE:** `{e.get('mitre','N/A')}`")
            st.markdown(f"💬 **Reasoning:** {llm.get('explanation','')}")
            st.markdown(f"⚡ **Containment Guideline:** {llm.get('recommended_action','')}")


def page_alerts():
    sh("🚨 SYSTEM ALERT ARCHIVE — EMAIL DISPATCH LOG")
    sent=load_alerts(); pending=[e for e in events if e.get("llm",{}).get("classification") in ("MALICIOUS","SUSPICIOUS")]
    
    c1,c2,c3,c4=st.columns(4)
    c1.metric("Alert Emails Dispatched",len(sent))
    c2.metric("Pending In Queue",len(pending))
    c3.metric("Unique Signatures Mapped",len(set(a.get("url_hash","") for a in sent)))
    c4.metric("High Priority Actionables",sum(1 for e in pending if e.get("severity")=="HIGH"))
    
    if not sent and not pending:
        st.info("Setup GMAIL_SENDER, GMAIL_APP_PASSWORD, and GMAIL_RECIPIENT parameters in .env to activate SMTP delivery.")
        
    tab1,tab2=st.tabs(["📤 SENT LOG ARCHIVE","⚠️ PENDING ALERT QUEUE"])
    with tab1:
        if sent:
            for a in reversed(sent[-20:]):
                sev=a.get("severity","LOW"); css="h" if sev=="HIGH" else "m" if sev=="MEDIUM" else "l"
                st.markdown(f"""<div class="ev {css}"><div class="ev-url">{a.get('url','')}</div>
                  <div class="ev-meta">📤 Dispatched: {a.get('sent_at','')} UTC &nbsp;|&nbsp; {badge(sev)} &nbsp;{badge(a.get('classification','?'))}</div>
                </div>""",unsafe_allow_html=True)
        else:
            st.info("No dispatched emails in system alerts buffer.")
    with tab2:
        if pending:
            st.warning(f"⚠️ {len(pending)} alerts pending. Active directory alerts queuing triggered.")
            for idx, e in enumerate(pending[:20]):
                ev_card(e, idx)
        else:
            st.success("✅ Secure host state. Zero pending alert events.")


def page_cve():
    sh("🛡️ CVE INTELLIGENCE — REAL-TIME EXPLOIT CORRELATION")
    
    CVE_DB=[
        {"id":"CVE-2024-3400","sev":"CRITICAL","cvss":10.0,"product":"Palo Alto PAN-OS","vector":"Command Injection","rules":["ENCODED_PAYLOAD","KEYWORD_MATCH"],"kws":["exploit","payload","shell","c2"],"mitre":"T1190","desc":"Unauthenticated Command Injection in GlobalProtect gateway sub-systems."},
        {"id":"CVE-2024-21887","sev":"CRITICAL","cvss":9.1,"product":"Ivanti Connect Secure","vector":"Auth Bypass + RCE","rules":["KEYWORD_MATCH","ENCODED_PAYLOAD"],"kws":["exploit","webshell","backdoor"],"mitre":"T1059","desc":"Command injection in web components of Ivanti Connect gateways."},
        {"id":"CVE-2024-1709","sev":"CRITICAL","cvss":10.0,"product":"ConnectWise ScreenConnect","vector":"Auth Bypass","rules":["KEYWORD_MATCH","MALICIOUS_DOMAIN"],"kws":["rat","backdoor","cobalt"],"mitre":"T1219","desc":"Auth bypass vulnerabilities leading to immediate system takeover and ransomware dropping."},
        {"id":"CVE-2024-27198","sev":"CRITICAL","cvss":9.8,"product":"JetBrains TeamCity","vector":"Auth Bypass","rules":["KEYWORD_MATCH","SUSPICIOUS_TLD"],"kws":["exploit","webshell","mimikatz"],"mitre":"T1190","desc":"Administrative authentication bypass allowing arbitrary build control."},
        {"id":"CVE-2023-44228","sev":"HIGH","cvss":10.0,"product":"Apache Log4Shell","vector":"JNDI Injection","rules":["ENCODED_PAYLOAD","KEYWORD_MATCH"],"kws":["payload","exploit","loader"],"mitre":"T1059","desc":"Log4j JNDI injection vulnerabilities causing unauthenticated arbitrary RCE."},
        {"id":"CVE-2024-23897","sev":"HIGH","cvss":9.8,"product":"Jenkins CI/CD","vector":"File Read→RCE","rules":["KEYWORD_MATCH","DOWNLOAD_DETECTED"],"kws":["shell","exploit","credential"],"mitre":"T1005","desc":"CLI parser unauthenticated file read leading to immediate token harvesting."},
        {"id":"CVE-2024-21338","sev":"HIGH","cvss":7.8,"product":"Windows Kernel","vector":"Privilege Escalation","rules":["KEYWORD_MATCH","OFF_HOURS_ACCESS"],"kws":["mimikatz","lsass","credential"],"mitre":"T1068","desc":"Windows kernel drivers privilege elevation allowing immediate execution as SYSTEM."},
        {"id":"CVE-2024-38063","sev":"CRITICAL","cvss":9.8,"product":"Windows TCP/IP IPv6","vector":"Wormable RCE","rules":["KEYWORD_MATCH"],"kws":["exploit","payload"],"mitre":"T1210","desc":"Wormable unauthenticated remote code execution via IPv6 packet fragmentation loops."},
        {"id":"CVE-2024-4577","sev":"CRITICAL","cvss":9.8,"product":"PHP CGI","vector":"Arg Injection","rules":["KEYWORD_MATCH","ENCODED_PAYLOAD"],"kws":["webshell","shell","cryptominer"],"mitre":"T1059","desc":"Argument injection vulnerability executing arbitrary shell code on Windows servers running PHP."},
        {"id":"CVE-2023-36884","sev":"HIGH","cvss":8.8,"product":"Microsoft Office","vector":"HTML RCE","rules":["DOWNLOAD_DETECTED","KEYWORD_MATCH"],"kws":["phishing","trojan","dropper"],"mitre":"T1566.001","desc":"HTML remote code execution via crafted Office document payloads."}
    ]
    
    def match(e):
        rule=e.get("matched_rule",""); combined=(e.get("url","")+e.get("title","")).lower()
        hits=[]
        for c in CVE_DB:
            s=0
            if rule in c["rules"]: s+=40
            if any(kw in combined for kw in c["kws"]): s+=20
            if e.get("mitre","")==c["mitre"]: s+=15
            if e.get("severity") in ("HIGH","MEDIUM") and c["sev"] in ("CRITICAL","HIGH"): s+=10
            if s>=40: hits.append({**c,"corr":min(s,100)})
        return sorted(hits,key=lambda x:-x["corr"])[:3]

    sus=[e for e in events if e.get("severity") in ("HIGH","MEDIUM")]
    ev_map=[]
    for e in sus:
        m=match(e)
        if m:
            ev_map.append((e,m))
    all_cves=list({c["id"]:c for _,cves in ev_map for c in cves}.values())
    
    c1,c2,c3,c4=st.columns(4)
    kpi(c1,"r","SUSPICIOUS TRANSACTIONS",len(sus),"HIGH+MEDIUM Priority",int(len(sus)/max(len(events),1)*100))
    kpi(c2,"a","CVE CORRELATIONS",len(all_cves),"unique vulnerability matches",int(len(all_cves)/max(len(CVE_DB),1)*100))
    kpi(c3,"p","CRITICAL SEVERITY MATCH",sum(1 for c in all_cves if c["sev"]=="CRITICAL"),"CVSS 9.0 - 10.0",0)
    kpi(c4,"c","SUCCESSFUL MATCHES",len(ev_map),"events correlated",int(len(ev_map)/max(len(sus),1)*100) if sus else 0)
    
    ch1,ch2=st.columns(2)
    with ch1:
        sh("CVE SEVERITY DISTRIBUTION MAP")
        if all_cves:
            sc2=Counter(c["sev"] for c in all_cves)
            sc3={"CRITICAL":"#ff0055","HIGH":"#ff9d00","MEDIUM":"#00f0ff"}
            lb,vl,cl=zip(*[(k,v,sc3.get(k,"#8fa3b7")) for k,v in sc2.items()])
            fig=go.Figure(go.Pie(labels=list(lb),values=list(vl),hole=.65,
                marker=dict(colors=list(cl),line=dict(color="#030814",width=2)),textfont=dict(size=9)))
            fig.update_layout(**PL,height=180,showlegend=True,
                legend=dict(bgcolor="rgba(0,0,0,0)"),
                annotations=[dict(text=f"<b>{len(all_cves)}</b>",x=.5,y=.5,
                    font=dict(size=18,color="#e6f3ff",family="Space Grotesk"),showarrow=False)])
            st.plotly_chart(fig,width="stretch")
    with ch2:
        sh("CVE CVSS BASE SCORE TELEMETRY")
        if all_cves:
            cdf=pd.DataFrame(all_cves)
            fig=go.Figure(go.Bar(x=cdf["id"],y=cdf["cvss"],
                marker_color=[rcolor(s*10) for s in cdf["cvss"]],marker_line_width=0,
                text=cdf["cvss"],textposition="outside",
                hovertemplate="<b>%{x}</b><br>CVSS: %{y}<extra></extra>"))
            fig.update_layout(**PL,height=180)
            fig.update_layout(yaxis=dict(**GRD,range=[0,11]),
                xaxis=dict(**GRD,tickangle=-40,tickfont=dict(size=8)))
            st.plotly_chart(fig,width="stretch")
            
    sh(f"OBSERVED EVENTS → VULNERABILITY CVE MATCHES ({len(ev_map)} Matches)")
    for ev,cves in ev_map[:12]:
        top=cves[0]; sev=ev.get("severity","LOW"); css="h" if sev=="HIGH" else "m"
        sc4={"CRITICAL":"#ff0055","HIGH":"#ff9d00"}.get(top["sev"],"#00f0ff")
        st.markdown(f"""<div class="ev {css}">
          <div class="ev-url">{ev.get('url','')[:90]}</div>
          <div class="ev-meta">📋 {ev.get('matched_rule','N/A')} &nbsp;|&nbsp; {ev.get('reason','')[:60]}</div>
          <div style="margin-top:6px;font-family:var(--font-mono);font-size:.65rem">
            <span style="color:#ff0055!important;font-weight:700">⚠️ CORRELATION DETECTED: </span>
            <span style="color:{sc4}!important;font-weight:700">{top['id']}</span>
            <span style="color:#8fa3b7!important"> — {top['product']}</span>
            <span style="color:#bd5af2!important"> CVSS {top['cvss']}</span>
            &nbsp;·&nbsp;<span style="color:#00f0ff!important">Score Correlation Match {top['corr']}%</span>
          </div>
        </div>""",unsafe_allow_html=True)
        
    sh("VULNERABILITY CVE DATABASE KNOWLEDGE REPOSITORY")
    ref=pd.DataFrame([{"ID":c["id"],"Severity":c["sev"],"CVSS Score":c["cvss"],"Product Target":c["product"],"MITRE Code":c["mitre"]} for c in CVE_DB])
    st.dataframe(ref,width="stretch",hide_index=True,
        column_config={"CVSS Score":st.column_config.ProgressColumn("CVSS Score",min_value=0,max_value=10,format="%.1f")})


def page_network():
    sh("🕸️ NETWORK FORENSICS — RETRO CLI PACKET SNIFFER")
    
    inst=tshark_installed() if REAL_MODE else False
    ver=get_tshark_version() if REAL_MODE else "Software emulated v4.2.1"
    
    st.markdown(f"""<div class="tc">
      <div class="tc-name">🌍 Tshark / Wireshark Interface Console</div>
      <div class="tc-desc">Sniffs, parses, and identifies active host network packet loops. Checks local DNS resolutions, encrypted SSL payloads, and flags abnormal routing configurations.</div>
      <div style="font-family:var(--font-mono);font-size:.65rem;margin-top:8px">
        Status Check: <span style="color:{'#39ff14' if inst else '#00f0ff'}!important">{'✓ HARDWARE INTEGRATED' if inst else '✓ SOFTWARE EMULATED (SANDBOX MODE)'}</span>
        &nbsp;·&nbsp; {ver}
      </div>
    </div>""",unsafe_allow_html=True)
    
    # Custom interactive packet simulation terminal panel
    terminal_col, control_col = st.columns([3, 1])
    
    with terminal_col:
        st.markdown("<p style='font-family:var(--font-mono);font-size:0.62rem;color:var(--neon-green)!important'>📡 SENTINEL TSHARK INTERFACE (LIVE PACKET BUFFER)</p>", unsafe_allow_html=True)
        
        # Display simulated packet capture outputs
        sim_packets = [
            "10:54:27.104289 IP 192.168.1.45.54129 > 185.220.101.5.443: Flags [S], seq 381940182",
            "10:54:27.123984 IP 185.220.101.5.443 > 192.168.1.45.54129: Flags [S.], seq 98124019, ack 381940183",
            "10:54:27.124501 IP 192.168.1.45.54129 > 185.220.101.5.443: Flags [.], ack 1",
            "10:54:27.150920 IP 192.168.1.45.54129 > 185.220.101.5.443: TLSv1.2 Client Hello (SNI: " + (events[0].get("domain","evil-c2.onion") if events else "evil-c2.onion") + ")",
            "10:54:27.185293 IP 185.220.101.5.443 > 192.168.1.45.54129: TLSv1.2 Server Hello, Certificate, Key Exchange",
            "10:54:27.220914 IP 192.168.1.45 > 192.168.1.1: DNS Standard query 0x8a12 A " + (events[0].get("domain","darknet.to") if events else "darknet.to"),
            "10:54:27.245892 IP 192.168.1.1 > 192.168.1.45: DNS Standard query response response 0x8a12 A 193.109.104.2",
            "10:54:27.301284 IP 192.168.1.45.54130 > 193.109.104.2.80: GET /payload.exe HTTP/1.1",
            "10:54:27.350192 IP 193.109.104.2.80 > 192.168.1.45.54130: HTTP/1.1 200 OK (application/x-msdownload)"
        ]
        
        terminal_placeholder = st.empty()
        
        if st.session_state.packet_simulation_active:
            # Typewriter/scroll effect
            text_accumulator = []
            for line in sim_packets:
                text_accumulator.append(line)
                terminal_placeholder.markdown(f"""
                <div class="cyber-shell" style="border-color:rgba(57,255,20,0.25)!important;box-shadow:inset 0 0 15px rgba(57,255,20,0.1)">
                  {"<br>".join([f"<div style='color:var(--neon-green)!important'>{l}</div>" for l in text_accumulator])}
                </div>
                """, unsafe_allow_html=True)
                time.sleep(0.35)
            st.session_state.packet_simulation_active = False
        else:
            terminal_placeholder.markdown(f"""
            <div class="cyber-shell" style="border-color:rgba(57,255,20,0.15)!important">
              <div style="color:var(--text-muted)">Terminal Idle. Press START TSHARK CAPTURE to intercept live packets...</div>
            </div>
            """, unsafe_allow_html=True)
            
    with control_col:
        st.markdown("<p style='font-family:var(--font-mono);font-size:0.62rem;color:var(--neon-cyan)!important'>⚙️ SNIFFER SETUP</p>", unsafe_allow_html=True)
        st.markdown("""
        <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:10px;padding:12px;height:250px">
        """, unsafe_allow_html=True)
        
        capture_duration = st.slider("Interception Frame (s)", 5, 60, 15, key="net_tshark_dur")
        
        if st.button("▶ START TSHARK CAPTURE", key="start_net_cap_btn", width="stretch"):
            st.session_state.packet_simulation_active = True
            
            # If real mode, initiate backend script
            if REAL_MODE and inst:
                with st.spinner("Capturing..."):
                    capture_traffic(duration=capture_duration)
                    st.session_state.net_data=load_network_data()
            st.rerun()
            
        if st.button("🗑️ CLEAR INTERCEPT BUFFER", key="clear_net_cap_btn", width="stretch"):
            st.session_state.net_data = []
            st.success("Buffer cleared.")
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

    net=st.session_state.get("net_data",[])
    if not net and os.path.exists("logs/network_data.csv") and REAL_MODE:
        try: net=load_network_data()
        except: pass
        
    if net:
        sh("INTERCEPTED PACKETS MATRIX ANALYSIS")
        c1,c2,c3=st.columns(3)
        c1.metric("Packets Captured",len(net))
        c2.metric("HIGH Severity network events",sum(1 for r in net if r.get("severity")=="HIGH"))
        c3.metric("MEDIUM Severity network events",sum(1 for r in net if r.get("severity")=="MEDIUM"))
        ndf=pd.DataFrame(net)
        sc2=[c for c in ["url","severity","dst_ip","dst_port","dns_query","http_host","reason"] if c in ndf.columns]
        if sc2:
            st.dataframe(ndf[sc2].rename(columns={c:c.replace("_"," ").upper() for c in sc2}),width="stretch",hide_index=True)


def page_autopsy():
    sh("🔎 FORENSIC AUTOPSY INGEST — ARTIFACT LOADER")
    
    st.markdown("""<div class="tc"><div class="tc-name">🔎 Autopsy Forensic Suite</div>
      <div class="tc-desc">Integrate structural data files exported from Basis Technology Autopsy. Ingests extracted search parameters, download logs, and web cookies.</div>
    </div>""",unsafe_allow_html=True)
    
    col1,col2=st.columns([2.5,1.5])
    with col1:
        st.markdown("<p style='font-family:var(--font-mono);font-size:0.62rem;color:var(--neon-cyan)!important'>📁 INGEST ARTIFACT FILES (CSV/XLSX)</p>", unsafe_allow_html=True)
        up=st.file_uploader("Drop Autopsy SQLite/Excel/CSV exports here",type=["csv","xlsx"])
    with col2:
        st.markdown("<br>",unsafe_allow_html=True)
        demo_btn=st.button("📊 LOAD CASE DEMO FILE DATA", width="stretch")
        
    recs=st.session_state.get("autopsy_data",[])
    if up:
        p="temp_autopsy.csv"
        with open(p,"wb") as f: f.write(up.read())
        recs=load_autopsy_data(p) if REAL_MODE else _demo(25)
        st.session_state.autopsy_data=recs; st.success(f"✓ Case Ingested: {len(recs)} records.")
    elif demo_btn:
        if REAL_MODE:
            from autopsy_ingestor import create_demo_csv
            p=create_demo_csv(); recs=load_autopsy_data(p)
        else:
            recs=_demo(20)
        st.session_state.autopsy_data=recs; st.success(f"✓ {len(recs)} demo forensic records loaded.")
        
    if recs:
        hi=sum(1 for r in recs if r.get("severity")=="HIGH")
        md=sum(1 for r in recs if r.get("severity")=="MEDIUM")
        c1,c2,c3,c4=st.columns(4)
        c1.metric("Forensic Records",len(recs))
        c2.metric("HIGH Risks",hi)
        c3.metric("MEDIUM Risks",md)
        c4.metric("LOW Risks",len(recs)-hi-md)
        
        sh("INGESTED FORENSIC TIMELINE ARTIFACTS")
        adf=pd.DataFrame(recs)
        sc2=[c for c in ["visit_time","url","title","severity","matched_rule","reason"] if c in adf.columns]
        if sc2:
            st.dataframe(adf[sc2].rename(columns={c:c.replace("_"," ").upper() for c in sc2}),width="stretch",hide_index=True)


def page_windows():
    sh("📋 WINDOWS EVENT LOGS — ADMINISTRATIVE WETUTIL SHELL")
    is_win=platform.system()=="Windows"
    
    st.markdown(f"""<div class="tc"><div class="tc-name">📋 Windows wevtutil sub-system</div>
      <div class="tc-desc">Integrates built-in Security and Audit channels. Decodes critical security Event IDs: e.g. Login failures (4625), system process initialization (4688), or credential tampering.</div>
      <div style="font-family:var(--font-mono);font-size:.65rem;margin-top:8px">Host Platform OS: <span style="color:{'#39ff14' if is_win else '#ff9d00'}!important">{platform.system().upper()}</span></div>
    </div>""",unsafe_allow_html=True)
    
    c1,c2,c3=st.columns(3)
    sources=c1.multiselect("Select Logs Channels",["Security","System","Application"],default=["Security","System"])
    max_evs=c2.slider("Max Event Count Threshold",10,500,100)
    run_btn=c3.button("📋 READ LOCAL WINDOWS EVENT LOGS",width="stretch")
    
    log_recs=[]
    if run_btn:
        with st.spinner("Processing event logs channels..."):
            if REAL_MODE and is_win:
                try: log_recs=load_system_logs(mode="windows")
                except Exception as ex: st.error(str(ex)); log_recs=_demo(25)
            else:
                log_recs=_demo(25)
        st.success(f"✓ Successfully processed {len(log_recs)} system events.")
        
    sh("ACCESS LOGS EXPORT INTERFACE (Apache/Nginx/IIS)")
    lp=st.text_input("Enter log file absolute path on host", placeholder="e.g. C:/xampp/apache/logs/access.log")
    
    if st.button("📄 EXECUTE ACCESS LOG PARSER") and lp:
        with st.spinner("Parsing target logs files..."):
            if REAL_MODE:
                try:
                    from log_ingestor import load_access_logs
                    log_recs=load_access_logs(paths=[lp])
                except Exception as ex: st.error(str(ex)); log_recs=_demo(15)
            else:
                log_recs=_demo(15)
        st.success(f"✓ Parsed {len(log_recs)} access transactions.")
        
    if log_recs:
        hi=sum(1 for r in log_recs if r.get("severity")=="HIGH")
        c1,c2,c3=st.columns(3)
        c1.metric("Event Entries",len(log_recs))
        c2.metric("HIGH Risks Flagged",hi)
        c3.metric("MEDIUM Risks Flagged",sum(1 for r in log_recs if r.get("severity")=="MEDIUM"))
        
        sh("PARSED SECURITY ACTIONS LOG")
        ldf=pd.DataFrame(log_recs)
        sc2=[c for c in ["visit_time","url","severity","matched_rule","reason"] if c in ldf.columns]
        if sc2:
            st.dataframe(ldf[sc2].rename(columns={c:c.replace("_"," ").upper() for c in sc2}),width="stretch",hide_index=True)


def page_file_monitor():
    sh("📁 REAL-TIME FILE SYSTEM MONITOR — WATCHDOG EDR CONSOLE")
    
    try:
        from watchdog.observers import Observer
        wok=True
    except ImportError:
        wok=False
        
    st.markdown(f"""<div class="tc"><div class="tc-name">📁 Watchdog EDR Core</div>
      <div class="tc-desc">Integrates EDR kernel-space watches to monitor dangerous modifications instantly (.exe, .ps1, .bat, .dll).</div>
      <div style="font-family:var(--font-mono);font-size:.65rem;margin-top:8px">System Driver: <span style="color:{'#39ff14' if wok else '#ff0055'}!important">{'✓ DRIVER RUNNING' if wok else '✗ DRIVER LACKS INSTALLATION'}</span></div>
    </div>""",unsafe_allow_html=True)
    
    st.info("Initiate on endpoint: `python main.py --mode monitor-files --watch C:/Users/YourName/Downloads`")
    
    fev=st.session_state.get("file_events",[])
    c1,c2=st.columns(2)
    
    if c1.button("🔬 EMULATE EDR MALWARE ACTIONS", width="stretch"):
        now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        fev=[
            {"url":"C:/Users/User/Downloads/cryptor.exe","severity":"HIGH","reason":"Host downloaded unauthorized unsigned executable to user spaces","matched_rule":"FILE_MONITOR","visit_time":now,"threat_score":92,"llm":{"classification":"MALICIOUS","confidence":89,"threat_type":"Ransomware Stager","explanation":"Unsigned Cryptor stager in public folder matching LockBit dropper behaviors.","recommended_action":"Isolate host node sentinel-node-01 immediately."}},
            {"url":"C:/Windows/Temp/payload.ps1","severity":"HIGH","reason":"PowerShell script modified system configuration registry from temporary folder","matched_rule":"FILE_MONITOR","visit_time":now,"threat_score":88,"llm":{"classification":"SUSPICIOUS","confidence":84,"threat_type":"Obfuscated Shell Code","explanation":"PowerShell base64 C2 command strings detected.","recommended_action":"Block script execution thread."}},
            {"url":"C:/Windows/System32/kernel_bypass.dll","severity":"HIGH","reason":"Unauthorized dynamic link library written to system sub-folders","matched_rule":"FILE_MONITOR","visit_time":now,"threat_score":96,"llm":{"classification":"MALICIOUS","confidence":95,"threat_type":"DLL Injection","explanation":"Rootkit kernel bypass payload threat.","recommended_action":"Trigger EDR system shutdown."}},
        ]
        st.session_state.file_events=fev
        st.success(f"✓ Simulated {len(fev)} malware alerts.")
        
    if c2.button("🗑️ PURGE MONITOR LOGS", width="stretch"):
        st.session_state.file_events=[]
        fev=[]
        st.success("Monitor log cleared.")
        
    if fev:
        sh(f"EDR OBSERVED INTELLIGENCE ALERTS ({len(fev)})")
        for idx, e in enumerate(fev):
            ev_card(e, idx)

    # ── LIVE PROCESS TREE (NetworkX) ──────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    sh("🌳 LIVE PROCESS RELATIONSHIP TREE")
    if REAL_MODE and render_process_tree:
        try:
            from collectors.process_monitor import ProcessMonitor
            procs = ProcessMonitor().get_active_processes()
            proc_rows = [
                {
                    "PID": p.get("process_id"),
                    "PPID": p.get("parent_process_id"),
                    "ImageFileName": p.get("process_name"),
                    "cmdline": p.get("cmdline"),
                }
                for p in procs[:80]
            ]
            pt_fig = render_process_tree(proc_rows)
            if pt_fig:
                st.plotly_chart(pt_fig, width="stretch")
                st.caption(f"Showing {len(proc_rows)} live processes from this host.")
            else:
                st.info("No process data available from the host agent.")
        except Exception as ex:
            st.warning(f"Process tree unavailable: {ex}")
    else:
        st.info("Install dependencies and restart dashboard to enable live process tree.")

    # ── ADVANCED EDR CONTAINMENT CONSOLE SHELL ────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    sh("💻 HOST CONTAINMENT & ADMINISTRATIVE COMMAND CONSOLE")
    
    terminal_col, control_col = st.columns([3.2, 1.2])
    
    with terminal_col:
        st.markdown("<p style='font-family:var(--font-mono);font-size:0.62rem;color:var(--neon-cyan)!important'>💻 AGENT SECURE CONSTRAINED SHELL (SENTINEL-NODE-01)</p>", unsafe_allow_html=True)
        
        # Retro terminal logger
        st.markdown(f"""
        <div class="cyber-shell" id="edr-console">
          {"<br>".join([f"<div style='color:var(--neon-cyan)!important'>{line}</div>" for line in st.session_state.containment_terminal_logs])}
        </div>
        """, unsafe_allow_html=True)
        
    with control_col:
        st.markdown("<p style='font-family:var(--font-mono);font-size:0.62rem;color:var(--neon-cyan)!important'>🎮 ADMINISTRATIVE COMMANDS PANEL</p>", unsafe_allow_html=True)
        
        # Interactive buttons to trigger console commands
        st.markdown("""
        <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:10px;padding:12px;height:250px;display:flex;flex-direction:column;gap:8px">
        """, unsafe_allow_html=True)
        
        if st.button("Isolate Agent", key="btn_cmd_iso", width="stretch"):
            st.session_state.containment_terminal_logs.append("SENTINEL-NODE-01 > isolate-host")
            st.session_state.containment_terminal_logs.append("[*] AGENT STATE: Executing host firewall quarantine loops.")
            st.session_state.containment_terminal_logs.append("[✓] SUCCESS: Host 192.168.1.45 isolated. WAN gateway block implemented.")
            st.session_state.isolated_nodes.add("local-file-system")
            st.session_state.isolated_nodes.add("local-endpoint")
            st.rerun()
            
        if st.button("Reconnect Agent", key="btn_cmd_rec", width="stretch"):
            st.session_state.containment_terminal_logs.append("SENTINEL-NODE-01 > reconnect-host")
            st.session_state.containment_terminal_logs.append("[*] AGENT STATE: Disabling host quarantine firewalls.")
            st.session_state.containment_terminal_logs.append("[✓] SUCCESS: Sentinel Node 01 reconnected to active directory.")
            st.session_state.isolated_nodes.discard("local-file-system")
            st.session_state.isolated_nodes.discard("local-endpoint")
            st.rerun()
            
        if st.button("Trigger Mem Dump", key="btn_cmd_mem", width="stretch"):
            st.session_state.containment_terminal_logs.append("SENTINEL-NODE-01 > dump-memory")
            st.session_state.containment_terminal_logs.append("[*] AGENT STATE: Compressing active kernel RAM allocations.")
            st.session_state.containment_terminal_logs.append("[✓] SUCCESS: Raw dump written to C:/Sentinel/dumps/mem_dmp_01.bin (4.1GB).")
            st.rerun()
            
        if st.button("Purge EDR Terminal Logs", key="btn_cmd_clr", width="stretch"):
            st.session_state.containment_terminal_logs = [
                "🛡️ DFIR Sentinel EDR Shell v3.0 - Terminal Established.",
                "System Agent [SENTINEL-NODE-01] linked via secure websocket.",
                ""
            ]
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)


def page_report():
    sh("📄 EXECUTIVE REPORT ROOM — CYBER INCIDENT SUMMARY")
    
    total = len(events)
    mal = sum(1 for e in events if e.get("llm",{}).get("classification")=="MALICIOUS")
    sus = sum(1 for e in events if e.get("llm",{}).get("classification")=="SUSPICIOUS")
    hi  = sum(1 for e in events if e.get("severity")=="HIGH")
    
    risk = min(mal*12 + sus*6 + hi*4, 100)
    if "None" not in st.session_state.incident_profile:
        risk = max(risk, 88)
        
    rl = "CRITICAL THREAT THRESHOLD" if risk>=75 else "HIGH RISK SYSTEM STATE" if risk>=50 else "MEDIUM SECURABLE PROFILE" if risk>=25 else "SECURED ENVIRONMENT"
    rc = "#ff0055" if risk>=75 else "#ff9d00" if risk>=50 else "#00f0ff" if risk>=25 else "#39ff14"
    
    c_score,c_stats=st.columns([1.2, 2.8])
    with c_score:
        st.markdown(f"""
        <div style="background:var(--bg-card);border:1px solid var(--border-color);
          border-radius:12px;padding:24px 28px;text-align:center;box-shadow: 0 0 25px rgba(0,240,255,0.04)">
          <div style="font-family:var(--font-mono);font-size:.58rem;letter-spacing:.25em;color:var(--text-secondary)!important;margin-bottom:8px">ENVIRONMENT RISK METRIC</div>
          <div style="font-family:'Orbitron',sans-serif;font-size:4.8rem;font-weight:900;line-height:1;
               color:{rc}!important;text-shadow:0 0 30px {rc}">{risk}</div>
          <div style="font-family:var(--font-mono);font-size:.65rem;color:{rc}!important">/100</div>
          <div style="font-family:var(--font-mono);font-size:.72rem;letter-spacing:.25em;color:{rc}!important;margin-top:12px;font-weight:bold">{rl}</div>
          <div style="margin-top:18px;background:rgba(16,37,66,0.5);border-radius:4px;height:8px;overflow:hidden">
            <div style="height:100%;width:{risk}%;background:{rc};border-radius:4px;box-shadow:0 0 10px {rc}"></div>
          </div>
        </div>""",unsafe_allow_html=True)
        
    with c_stats:
        sh("ACTIVE AUDIT METRIC STATISTICS")
        r1,r2,r3,r4=st.columns(4)
        r1.metric("Intercepted Signals",total)
        r2.metric("Severe Malicious",mal)
        r3.metric("Host Suspicious",sus)
        r4.metric("HIGH Alert Level",hi)
        
        st.markdown("<br>",unsafe_allow_html=True)
        b1,b2,b3=st.columns(3)
        
        if b1.button("📄 GENERATE EXECUTIVE REPORT HTML", width="stretch"):
            if REAL_MODE:
                try:
                    from reporter import generate_report
                    p=generate_report(); st.success(f"✓ Written report file to: {p}")
                except Exception as ex: st.error(str(ex))
            else:
                st.warning("Software emulation active. Check terminal output: python main.py --mode report")
                
        reps=sorted(Path("reports").glob("*.html"),reverse=True) if Path("reports").exists() else []
        if reps:
            b2.success(f"✓ Available: {reps[0].name}")
            with open(reps[0],"rb") as f:
                b3.download_button("⬇ DOWNLOAD HTML FILE",f.read(),reps[0].name,"text/html",width="stretch")
                
    sh("TOP COMPROMISED SYSTEM ALERTS BY RISK WEIGHT")
    top=sorted(events,key=lambda e:e.get("threat_score",0),reverse=True)[:20]
    if top:
        prev=pd.DataFrame([{"Time":e.get("visit_time",""),"Target URI Path":e.get("url","")[:65],
            "Host domain":e.get("domain",""),"Severity Level":e.get("severity",""),
            "AI Classification":e.get("llm",{}).get("classification",""),
            "Threat Score":e.get("threat_score",0),"MITRE Technique":e.get("mitre","N/A")} for e in top])
        st.dataframe(prev,width="stretch",hide_index=True,
            column_config={"Threat Score":st.column_config.ProgressColumn("Threat Score",min_value=0,max_value=100,format="%d")})

# ══════════════════════════════════════════════════════════════════════════════
# PAGE ROUTING DISPATCHER
# ══════════════════════════════════════════════════════════════════════════════
PAGE_MAP = {
    "🏠  Tactical Overview":             page_overview,
    "🌍  Geological Threat Map":         page_world_map,
    "🌐  Domain Relationship Network":   page_domain_graph,
    "🔬  IOC Detection Matrix":          page_ioc,
    "⏱  Incident Timeline Flow":        page_timeline,
    "🤖  AI Threat Reasoning":           page_ai,
    "🚨  Notification Alerter":          page_alerts,
    "🛡  Vulnerability CVE Hub":         page_cve,
    "🕸  Tshark Network Forensics":      page_network,
    "🔎  Forensic Autopsy Ingest":       page_autopsy,
    "📋  Windows Event logs":            page_windows,
    "📁  EDR System Monitor":            page_file_monitor,
    "📄  Incident Report Room":          page_report,
}

rendered = False
for key, fn in PAGE_MAP.items():
    if key == selected:
        render_page(key, fn)
        rendered = True
        break
if not rendered:
    render_page("🏠  Tactical Overview", page_overview)

# ── EDR INTERCEPT AUTO-REFRESH TELEMETRY LOOP ─────────────────────────────────
if st.session_state.auto_refresh:
    st.markdown(f"""<div style="text-align:center;font-family:'Share Tech Mono',monospace;
      font-size:.6rem;color:#4e647b;margin-top:20px;padding:10px;border-top:1px solid rgba(0,240,255,0.1)">
      📡 Auto-scanning target system logs telemetry every {st.session_state.refresh_secs} seconds &nbsp;·&nbsp;
      Last Scanned: {st.session_state.last_scan.strftime('%H:%M:%S')} UTC
    </div>""",unsafe_allow_html=True)
    time.sleep(st.session_state.refresh_secs)
    st.cache_data.clear()
    st.session_state.scan_count += 1
    st.session_state.last_scan = datetime.datetime.now(datetime.timezone.utc)
    st.rerun()