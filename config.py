"""
config.py — Centralised Configuration
All secrets loaded from .env — never hardcoded.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ── Scan ─────────────────────────────────────────────────────
SCAN_INTERVAL_SECONDS: int = int(os.getenv("SCAN_INTERVAL_SECONDS", "30"))

# ── Paths ────────────────────────────────────────────────────
LOGS_DIR:         str = os.getenv("LOGS_DIR",         "logs")
REPORTS_DIR:      str = os.getenv("REPORTS_DIR",      "reports")
CASES_DIR:        str = os.getenv("CASES_DIR",        "cases")
YARA_RULES_DIR:   str = os.getenv("YARA_RULES_DIR",   "yara_rules")
SIGMA_RULES_DIR:  str = os.getenv("SIGMA_RULES_DIR",  "sigma_rules")
MEM_DUMPS_DIR:    str = os.getenv("MEM_DUMPS_DIR",    "memory_dumps")
PCAPS_DIR:        str = os.getenv("PCAPS_DIR",        "pcaps")
DATABASE_DIR:     str = os.getenv("DATABASE_DIR",     "database")

LOG_FILE:    str = os.path.join(LOGS_DIR, "events.json")
DB_FILE:     str = os.path.join(DATABASE_DIR, "dfir_sentinel.db")
DB_URL:      str = f"sqlite:///{DB_FILE}"

# Create all folders
for folder in [LOGS_DIR, REPORTS_DIR, CASES_DIR, YARA_RULES_DIR, SIGMA_RULES_DIR, MEM_DUMPS_DIR, PCAPS_DIR, DATABASE_DIR]:
    os.makedirs(folder, exist_ok=True)

# ── LLM Providers (priority: Groq → Ollama → OpenAI) ─────────
GROQ_API_KEY:  str = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL:    str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
LLM_MODEL:      str = os.getenv("LLM_MODEL", "gpt-4o-mini")

# ── Ollama (local LLM) ───────────────────────────────────────
USE_OLLAMA:      bool = os.getenv("USE_OLLAMA", "false").lower() == "true"
OLLAMA_BASE_URL: str  = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
OLLAMA_MODEL:    str  = os.getenv("OLLAMA_MODEL", "llama3")

# ── Gmail Alerter ────────────────────────────────────────────
GMAIL_SENDER:       str = os.getenv("GMAIL_SENDER",       "")
GMAIL_APP_PASSWORD: str = os.getenv("GMAIL_APP_PASSWORD", "")
GMAIL_RECIPIENT:    str = os.getenv("GMAIL_RECIPIENT",    "")
ALERT_DEDUP_HOURS:  int = int(os.getenv("ALERT_DEDUP_HOURS", "6"))

# ── IOC Detection ────────────────────────────────────────────
OFF_HOURS_START:      int = int(os.getenv("OFF_HOURS_START",      "0"))
OFF_HOURS_END:        int = int(os.getenv("OFF_HOURS_END",        "5"))
CHROME_HISTORY_LIMIT: int = int(os.getenv("CHROME_HISTORY_LIMIT", "200"))

# ── Threat Intel APIs ────────────────────────────────────────
VIRUSTOTAL_API_KEY:  str = os.getenv("VIRUSTOTAL_API_KEY",  "")
ABUSEIPDB_API_KEY:   str = os.getenv("ABUSEIPDB_API_KEY",   "")
SHODAN_API_KEY:      str = os.getenv("SHODAN_API_KEY",      "")
URLHAUS_API_KEY:     str = os.getenv("URLHAUS_API_KEY",     "")
ALIENVAULT_API_KEY:  str = os.getenv("ALIENVAULT_API_KEY",  "")