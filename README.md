# 🛡️ DFIR Sentinel — AI-Driven Digital Forensics & Incident Response Platform

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red?style=for-the-badge&logo=streamlit)
![Groq](https://img.shields.io/badge/Groq-LLaMA_3.3_70B-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-3.0-cyan?style=for-the-badge)

**A production-grade DFIR & EDR platform integrating Autopsy, Tshark, Volatility 3, and AI classification into a unified 13-page Streamlit Cyber-Ops portal.**

*Computer Science — 6th Semester Capstone Project | DHA Suffa University | 2025–2026*

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration-env)
- [Usage](#-usage)
- [Dashboard Pages](#-dashboard-pages)
- [Tool Integrations](#-tool-integrations)
- [Detection Engine](#-detection-engine)
- [Project Structure](#-project-structure)
- [Team](#-team)

---

## 🔍 Overview

DFIR Sentinel solves the #1 SOC problem — **alert fatigue from disconnected tools** — by consolidating:

- 🌐 **Browser forensics** (Chrome/Edge SQLite history)
- 📡 **Network traffic** (Tshark live capture + PCAP analysis)
- 🧠 **Memory forensics** (Volatility 3 RAM dump analysis)
- 📋 **OS event logs** (Windows wevtutil + Apache/Nginx access logs)
- 🔎 **Disk forensics** (Autopsy CSV/XLSX case exports)

...into a **single AI-powered pipeline** that detects, classifies, correlates, and reports threats automatically.

---

## ✨ Features

| Feature | Detail |
|---|---|
| **17-Module Pipeline** | 7-stage architecture: Ingest → Timeline → Detect → Enrich → Correlate → AI Triage → Action |
| **4-Tier AI Chain** | Groq LLaMA 3.3 70B → Ollama → OpenAI GPT-4o-mini → Rule Engine fallback |
| **8 IOC Rule Categories** | KEYWORD_MATCH, SUSPICIOUS_TLD, MALICIOUS_DOMAIN, DOWNLOAD_DETECTED, ENCODED_PAYLOAD, HEX_PATTERN, OFF_HOURS_ACCESS, RAPID_REVISIT |
| **YARA + Sigma** | Signature scanning + MITRE ATT&CK behavioral rule engine |
| **5 Threat Intel APIs** | VirusTotal, AbuseIPDB, Shodan, URLHaus, AlienVault OTX |
| **13-Page Dashboard** | Full Streamlit Cyber-Ops portal with EDR controls |
| **Attack Simulators** | LockBit 3.0 Ransomware, Cobalt Strike APT, Insider Threat |
| **Auto Reports** | HTML + PDF incident reports with risk scoring |
| **Live EDR Controls** | Host isolation, file quarantine, alert muting, AI policy override |
| **CVE Correlation** | 10 high-priority CVEs mapped with CVSS scoring |

---

## 🏗️ Architecture

```
[Data Sources]
    │
    ├── Chrome/Edge SQLite ──────────────────────────┐
    ├── Tshark Live Capture / PCAP ──────────────────┤
    ├── Windows Event Logs (wevtutil) ───────────────┤
    ├── Autopsy CSV/XLSX Exports ───────────────────►│  [Unified Timeline]
    ├── Volatility 3 RAM Dumps ────────────────────── ┤  (SHA-256 dedup,
    └── File System Events (Watchdog) ───────────────┘   chronological sort)
                                                              │
                                                              ▼
                                              [Detection Engine]
                                         ┌────────────────────────────┐
                                         │  8-Rule Heuristic Engine   │
                                         │  YARA Signature Scanner    │
                                         │  Sigma Behavioral Rules    │
                                         └──────────┬─────────────────┘
                                                    │
                                                    ▼
                                    [Threat Intelligence Enrichment]
                                    VirusTotal │ AbuseIPDB │ Shodan
                                    URLHaus    │ AlienVault OTX
                                    SQLite Cache (12h TTL)
                                                    │
                                                    ▼
                                        [AI Classification]
                                    Groq LLaMA 3.3 70B (primary)
                                         → Ollama (local)
                                         → OpenAI GPT-4o-mini
                                         → Rule Engine (offline)
                                                    │
                                                    ▼
                              [Action Layer]
                    ┌─────────────────────────────────────┐
                    │  Gmail SMTP Alerts                   │
                    │  n8n Webhook Notifications           │
                    │  HTML + PDF Reports (fpdf2)          │
                    │  Streamlit Dashboard (13 pages)      │
                    └─────────────────────────────────────┘
```

---

## 📦 Prerequisites

| Requirement | Version | Required? |
|---|---|---|
| Python | 3.10+ | ✅ Yes |
| pip | Latest | ✅ Yes |
| Groq API Key | Free tier | ✅ Recommended |
| Git | Latest | ✅ Yes |
| Tshark / Wireshark | 4.x | ⚠️ Optional (network capture) |
| Autopsy | 4.x | ⚠️ Optional (disk forensics) |
| Volatility 3 | 2.x | ⚠️ Optional (memory forensics) |
| Ollama | Latest | ⚠️ Optional (local LLM) |

> **Note:** The platform runs fully without optional tools — it degrades gracefully with simulation modes.

---

## ⚙️ Installation

### Step 1 — Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/dfir-sentinel.git
cd dfir-sentinel
```

### Step 2 — Create a Virtual Environment (Recommended)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

> **Note:** `yara-python`, `scikit-learn`, `pyshark`, and `volatility3` are optional. If they fail to install, the platform uses built-in fallbacks automatically.

### Step 4 — Configure Environment (see next section)

### Step 5 — Launch Dashboard

```bash
python -m streamlit run dashboard.py
```

The dashboard will open at **http://localhost:8501**

---

## 🔧 Configuration (.env)

Create a `.env` file in the project root directory:

```env
# ── Scan Settings ──────────────────────────────────────
SCAN_INTERVAL_SECONDS=30
CHROME_HISTORY_LIMIT=200

# ── AI Provider (Priority: Groq → Ollama → OpenAI) ────
GROQ_API_KEY=gsk_your_groq_key_here
GROQ_MODEL=llama-3.3-70b-versatile

# ── Local LLM (Optional) ───────────────────────────────
USE_OLLAMA=false
OLLAMA_BASE_URL=http://localhost:11434/v1
OLLAMA_MODEL=llama3

# ── OpenAI Fallback (Optional) ─────────────────────────
OPENAI_API_KEY=sk_your_openai_key_here

# ── Threat Intelligence APIs (Optional) ───────────────
VIRUSTOTAL_API_KEY=your_vt_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
SHODAN_API_KEY=your_shodan_key
URLHAUS_API_KEY=your_urlhaus_key
ALIENVAULT_API_KEY=your_otx_key

# ── Email Alerts (Optional) ───────────────────────────
GMAIL_SENDER=your_email@gmail.com
GMAIL_APP_PASSWORD=your_16_char_app_password
GMAIL_RECIPIENT=recipient@email.com
ALERT_DEDUP_HOURS=6

# ── IOC Detection ─────────────────────────────────────
OFF_HOURS_START=0
OFF_HOURS_END=5
```

> ⚠️ **Never commit your `.env` file to GitHub.** It is already in `.gitignore`.

### Getting a Free Groq API Key

1. Go to [console.groq.com](https://console.groq.com)
2. Sign up for a free account
3. Navigate to **API Keys** → **Create API Key**
4. Copy the key starting with `gsk_` into your `.env`

---

## 🚀 Usage

### Option A — Interactive Dashboard (Recommended)

```bash
python -m streamlit run dashboard.py
```

**Dashboard Demo Flow:**
1. Open browser at `http://localhost:8501`
2. Click **"EXECUTE HOST AGENT SCAN"** in the sidebar
3. Switch to **Attack Scenario Simulator** → Select "LockBit 3.0 Ransomware Campaign"
4. Navigate through all 13 pages
5. Go to **Incident Report Room** → Generate HTML + PDF Report

---

### Option B — Command Line Interface

```bash
# Scan live browser history (Chrome/Edge)
python main.py --mode scan

# Continuous monitoring every 30 seconds
python main.py --mode live --interval 30

# Live network packet capture (requires Tshark)
python main.py --mode network --duration 15

# Ingest Autopsy forensic export
python main.py --mode autopsy --file autopsy_demo.csv

# Read Windows Event Logs (Windows only)
python main.py --mode logs

# Real-time file system watchdog
python main.py --mode monitor-files --watch C:\Users\Public

# Generate HTML + PDF incident report
python main.py --mode report
```

---

## 📊 Dashboard Pages

| # | Page | Features |
|---|---|---|
| 01 | 🏠 Tactical Overview | KPI metrics, risk dial gauge, threat timeline, classification donut |
| 02 | 🌍 Geo Threat Map | Plotly globe, attack arc lines, country dossier panel |
| 03 | 🌐 Domain Graph Network | NetworkX behavioral graph, node inspector, block controls |
| 04 | 🔬 IOC Detection Matrix | Sankey pipeline diagram, rule histogram, MITRE ATT&CK density |
| 05 | ⏱️ Incident Timeline Flow | UTC heatmap, waterfall scatter chart, chronological audit table |
| 06 | 🤖 AI Threat Reasoning | LLM analysis terminal, confidence histogram, policy override |
| 07 | 🚨 Notification Alerter | Sent alert archive, pending queue, email dispatch log |
| 08 | 🛡️ Vulnerability CVE Hub | CVE correlation engine, CVSS scoring, event-to-CVE matching |
| 09 | 🕸️ Tshark Network Forensics | Packet simulation terminal, capture controls, packet matrix |
| 10 | 🔎 Forensic Autopsy Ingest | File upload, demo CSV loader, timeline artifact viewer |
| 11 | 📋 Windows Event Logs | wevtutil interface, access log parser, event matrix table |
| 12 | 📁 EDR System Monitor | Process tree, file events, containment shell, command panel |
| 13 | 📄 Incident Report Room | Risk score display, HTML/PDF generation, download button |

---

## 🔧 Tool Integrations

### Autopsy (Disk Forensics)
```bash
# Export from Autopsy: Tools → Generate Report → Excel/CSV → Web History
python main.py --mode autopsy --file your_autopsy_export.csv

# Or use the built-in demo
python autopsy_ingestor.py  # auto-creates demo CSV
```

### Tshark (Network Forensics)
```bash
# Install Wireshark (includes Tshark): https://www.wireshark.org/download.html
# Run as Administrator on Windows

python main.py --mode network --duration 15
```

### Volatility 3 (Memory Forensics)
```bash
# Install: pip install volatility3
# Then analyze a RAM dump:
python integrations/volatility_integration.py --dump memory.raw
```

### wevtutil (Windows Event Logs)
```bash
# Built-in to Windows — no install needed
# Run as Administrator:
python main.py --mode logs
```

---

## 🎯 Detection Engine

### IOC Rule Categories
| Rule | Severity | Trigger |
|---|---|---|
| `KEYWORD_MATCH` | HIGH/MEDIUM | 35+ malware keywords in URL/title |
| `SUSPICIOUS_TLD` | MEDIUM | .onion .xyz .tk .ml .cc .to .su |
| `MALICIOUS_DOMAIN` | HIGH | grabify.link, iplogger.org, etc. |
| `DOWNLOAD_DETECTED` | HIGH/MEDIUM | .exe .msi .ps1 .bat .vbs .dll |
| `ENCODED_PAYLOAD` | HIGH | Base64 >32 chars with shell commands |
| `HEX_PATTERN` | LOW | Hex-encoded strings in URL |
| `OFF_HOURS_ACCESS` | MEDIUM | Activity in 00:00–05:00 UTC window |
| `RAPID_REVISIT` | HIGH | ≥5 visits/URL within 60 minutes (C2 beacon) |

---

## 📁 Project Structure

```
dfir-sentinel/
│
├── main.py                     # CLI entry point (7 modes)
├── dashboard.py                # Streamlit 13-page portal
├── config.py                   # Centralised .env config loader
├── requirements.txt            # Python dependencies
├── .env                        # API keys (NOT committed to git)
├── .gitignore                  # Excludes .env, logs, __pycache__
│
├── core/
│   ├── llm_client.py           # AI provider selection & client init
│   ├── ai_engine.py            # AI classification logic
│   ├── yara_engine.py          # YARA signature scanner
│   ├── sigma_engine.py         # Sigma behavioral rule engine
│   ├── threat_intel.py         # 5-API threat intelligence + cache
│   └── correlation_engine.py   # Event grouping → Incident Cases
│
├── extractor.py                # Chrome/Edge SQLite browser history
├── autopsy_ingestor.py         # Autopsy CSV/XLSX forensic ingestor
├── network_analyzer.py         # Tshark live capture + PCAP analysis
├── log_ingestor.py             # Windows Event Log + web server logs
├── timeline.py                 # Dedup, sort, JSON persistence
├── ioc_detector.py             # 8-category IOC rule engine
├── llm_classifier.py           # Groq → Ollama → OpenAI → Rules chain
├── alerter.py                  # Gmail SMTP + deduplication + audit
├── reporter.py                 # HTML + PDF report generation
├── monitor.py                  # Scheduled scan loop (SQLite state)
├── utils.py                    # Log save/load utilities
│
├── integrations/
│   └── volatility_integration.py  # Volatility 3 memory forensics
│
├── ui/
│   └── components/
│       ├── graphs.py           # Process tree (NetworkX)
│       └── charts.py          # Sankey diagram, threat heatmap
│
├── yara_rules/                 # .yar signature files
├── sigma_rules/                # Sigma .yml rule files
├── logs/                       # Runtime logs (git-ignored)
├── reports/                    # Generated HTML/PDF reports
├── database/                   # SQLite case database
├── autopsy_demo.csv            # Demo Autopsy export for testing
└── README.md                   # This file
```

---

## 👥 Team

| Member | Role | Modules |
|---|---|---|
| Wasay (Lead) | Architecture & AI Integration | config.py, llm_classifier.py, core/llm_client.py, core/ai_engine.py |
| Member 2 | Detection Engine | ioc_detector.py, core/yara_engine.py, core/sigma_engine.py |
| Member 3 | Data Ingestion | extractor.py, autopsy_ingestor.py, network_analyzer.py, log_ingestor.py |
| Member 4 | Dashboard & Reports | dashboard.py, reporter.py, alerter.py |

---

## 📄 License

This project is submitted as an academic capstone project at DHA Suffa University, Karachi.

---

<div align="center">

**DFIR Sentinel v3.0** — Built with Python, Streamlit, Groq AI, and ❤️

*DHA Suffa University | Computer Science | 6th Semester | 2025–2026*

</div>