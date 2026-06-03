"""
core/sigma_engine.py — Sigma Behavioral Rules Engine
======================================================
Correlates command-line prompts, registry events, and file patterns
against standardized Sigma behavior profiles to identify advanced attack techniques.
"""

import os
import re
from typing import List, Dict, Any, Optional

import config

class SigmaEngine:
    def __init__(self):
        # Create directories for custom rule exports
        os.makedirs(config.SIGMA_RULES_DIR, exist_ok=True)
        self._write_default_rules()

    def _write_default_rules(self):
        """Create sample .yml Sigma files for display in the dashboard."""
        sample_path = os.path.join(config.SIGMA_RULES_DIR, "powershell_obfuscation.yml")
        if not os.path.exists(sample_path):
            rule = """
title: Suspicious PowerShell Obfuscated Command Line
id: 48fa2409-cf8a-4424-9b2f-45b73641215b
status: experimental
description: Detects powershell execution containing base64 encoded arguments or bypass scripts
author: DFIR Sentinel
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - ' -enc'
            - ' -encodedcommand'
            - ' -nop'
            - ' -w hidden'
    condition: selection
fields:
    - CommandLine
falsepositives:
    - Administrative setup scripts
level: high
"""
            try:
                with open(sample_path, "w", encoding="utf-8") as f:
                    f.write(rule)
            except Exception:
                pass

    def evaluate_process(self, process_name: str, cmdline: str) -> List[Dict[str, Any]]:
        """Evaluate a process creation event against EDR Sigma rules."""
        matches = []
        cmdline_lower = cmdline.lower()
        proc_lower = process_name.lower()

        # 1. PowerShell Obfuscation (T1027)
        if "powershell" in proc_lower or "pwsh" in proc_lower:
            if any(term in cmdline_lower for term in [" -enc ", " -encodedcommand ", " -w hidden ", " -nop "]):
                matches.append({
                    "rule_id": "SIGMA_PS_OBFUSCATION",
                    "title": "PowerShell Obfuscated Execution",
                    "severity": "HIGH",
                    "mitre": "T1027",
                    "description": "PowerShell executed with obfuscation flags (e.g. -enc, -w hidden, -nop)."
                })

        # 2. LSASS Access / Credential Dumping (T1003)
        if any(term in cmdline_lower for term in ["mimikatz", "sekurlsa", "lsadump", "procdump"]) or \
           ("rundll32" in proc_lower and "comsvcs" in cmdline_lower and "lsass" in cmdline_lower):
            matches.append({
                "rule_id": "SIGMA_CREDENTIAL_DUMP",
                "title": "Credential Dumping via LSASS Tampering",
                "severity": "CRITICAL",
                "mitre": "T1003",
                "description": "Process command-line references Mimikatz commands or attempts lsass memory dumping."
            })

        # 3. LOLBin Abuse (T1105 / T1218)
        if "certutil" in proc_lower and any(term in cmdline_lower for term in ["-urlcache", "-split", "http"]):
            matches.append({
                "rule_id": "SIGMA_LOLBIN_CERTUTIL_DOWNLOAD",
                "title": "LOLBin certutil.exe Download Activity",
                "severity": "HIGH",
                "mitre": "T1105",
                "description": "Certutil utility abused to download external payloads bypassing traditional controls."
            })
            
        if "regsvr32" in proc_lower and "scrobj.dll" in cmdline_lower and "http" in cmdline_lower:
            matches.append({
                "rule_id": "SIGMA_LOLBIN_REGSVR32_SCRIPLET",
                "title": "Regsvr32 Remote Scriptlet Abuse (Squiblydoo)",
                "severity": "HIGH",
                "mitre": "T1218.010",
                "description": "Regsvr32 utilized to execute remote scriptlets hosted on external domains."
            })

        return matches

    def evaluate_file_integrity(self, path: str) -> List[Dict[str, Any]]:
        """Evaluate file monitor events to detect suspicious drops or ransomware."""
        matches = []
        path_lower = path.lower()

        # 1. Ransomware spike patterns (T1486)
        if any(path_lower.endswith(ext) for ext in [".locked", ".crypto", ".onion", ".aes", ".ransom"]):
            matches.append({
                "rule_id": "SIGMA_RANSOMWARE_ENCRYPTION",
                "title": "Ransomware File Encryption Detected",
                "severity": "CRITICAL",
                "mitre": "T1486",
                "description": "File created or renamed with standard ransomware encryption extension."
            })

        # 2. Executables in temp space (T1105)
        if any(folder in path_lower for folder in ["\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\"]) and \
           any(path_lower.endswith(ext) for ext in [".exe", ".bat", ".ps1", ".vbs"]):
            matches.append({
                "rule_id": "SIGMA_EXEC_IN_TEMP",
                "title": "Executable Drop in Temporary Workspace",
                "severity": "HIGH",
                "mitre": "T1105",
                "description": "Binary or scripting executable file dropped in volatile system Temp folders."
            })

        return matches

# Singleton instance
_sigma_engine = None

def get_sigma_engine() -> SigmaEngine:
    global _sigma_engine
    if _sigma_engine is None:
        _sigma_engine = SigmaEngine()
    return _sigma_engine

if __name__ == "__main__":
    engine = get_sigma_engine()
    results = engine.evaluate_process("powershell.exe", "powershell.exe -enc SUVY...")
    print("Sigma Matches:")
    for r in results:
        print(f"  - [{r['severity']}] {r['title']} (MITRE: {r['mitre']})")
