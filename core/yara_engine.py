"""
core/yara_engine.py — YARA Signature Scanner
=============================================
Matches files or memory buffers against YARA signature rules.
Gracefully degrades to regular expression matching if yara-python is missing.
"""

import os
import re
from typing import List, Dict, Any, Optional

try:
    import yara
    _HAS_YARA = True
except ImportError:
    _HAS_YARA = False

import config

# ── Fallback Rules ─────────────────────────────────────────────────────────────

# Hardcoded signature matching rules for fallback EDR scan
FALLBACK_RULES = {
    "Sliver_Implant": [
        rb"sliver-client", rb"Sliver\s+Implant", rb"Go\s+build\s+ID", rb"pb\.(?:Sliver|Envelope)"
    ],
    "Cobalt_Strike": [
        rb"beacon\.(?:x64|x86)\.dll", rb"ReflectiveLoader", rb"MSSE-[\d]+-server", rb"CS_Beacon"
    ],
    "Mimikatz": [
        rb"mimikatz", rb"sekurlsa::logonpasswords", rb"lsadump::sam", rb"wdigest\.dll", rb"privilege::debug"
    ],
    "Generic_Webshell": [
        rb"eval\(\$_POST", rb"system\(\$_GET", rb"shell_exec\(", rb"base64_decode\(\$_"
    ]
}


class YaraEngine:
    def __init__(self):
        self.rules = None
        self.rules_compiled = False
        self.yara_enabled = _HAS_YARA
        
        # Ensure rules directory exists
        os.makedirs(config.YARA_RULES_DIR, exist_ok=True)
        
        # Write default rules if folder is empty
        self._write_default_rules()
        
        # Attempt compiling
        if self.yara_enabled:
            self._compile_rules()

    def _write_default_rules(self):
        """Create sample .yar files for SOC demonstration."""
        sample_rule_path = os.path.join(config.YARA_RULES_DIR, "threat_rules.yar")
        if not os.path.exists(sample_rule_path):
            rules_content = """
rule Sliver_Implant {
    meta:
        description = "Detects Sliver C2 Implant"
        author = "DFIR Sentinel"
        severity = "CRITICAL"
    strings:
        $s1 = "sliver-client" ascii
        $s2 = "pb.Sliver" ascii
    condition:
        any of them
}

rule Mimikatz_LSASS {
    meta:
        description = "Detects Mimikatz Credential Dumping tool"
        author = "DFIR Sentinel"
        severity = "HIGH"
    strings:
        $m1 = "sekurlsa::logonpasswords" ascii wide
        $m2 = "lsadump::sam" ascii wide
        $m3 = "mimikatz" ascii wide nocase
    condition:
        any of them
}

rule Generic_Webshell {
    meta:
        description = "Detects typical PHP Webshell patterns"
        author = "DFIR Sentinel"
        severity = "HIGH"
    strings:
        $php1 = "eval($_POST" ascii nocase
        $php2 = "system($_GET" ascii nocase
        $php3 = "shell_exec(" ascii nocase
    condition:
        any of them
}
"""
            try:
                with open(sample_rule_path, "w", encoding="utf-8") as f:
                    f.write(rules_content)
            except Exception:
                pass

    def _compile_rules(self):
        """Compile all .yar rules in rule directory."""
        try:
            yar_files = {}
            for file in os.listdir(config.YARA_RULES_DIR):
                if file.endswith(".yar") or file.endswith(".yara"):
                    path = os.path.join(config.YARA_RULES_DIR, file)
                    yar_files[file] = path
            
            if yar_files:
                self.rules = yara.compile(filepaths=yar_files)
                self.rules_compiled = True
                print(f"[YARA] Successfully compiled {len(yar_files)} YARA rule file(s).")
            else:
                self.yara_enabled = False
        except Exception as e:
            print(f"[YARA ERROR] Failed to compile rules: {e}")
            self.yara_enabled = False

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a file path on disk."""
        if not os.path.exists(file_path):
            return []
            
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            return self.scan_buffer(data, source_name=os.path.basename(file_path))
        except Exception as e:
            print(f"[YARA ERROR] Could not read file {file_path}: {e}")
            return []

    def scan_buffer(self, data: bytes, source_name: str = "memory_buffer") -> List[Dict[str, Any]]:
        """Scan a byte buffer."""
        matches = []
        
        # Try real YARA first
        if self.yara_enabled and self.rules_compiled and self.rules:
            try:
                yara_matches = self.rules.match(data=data)
                for m in yara_matches:
                    matches.append({
                        "rule": m.rule,
                        "severity": m.meta.get("severity", "HIGH"),
                        "description": m.meta.get("description", f"Matched signature rule: {m.rule}"),
                        "source": source_name,
                        "engine": "YARA C-Library"
                    })
                return matches
            except Exception as e:
                print(f"[YARA ERROR] Match failed: {e}. Falling back to Regex scanner.")
                
        # Regex Fallback matches
        for rule_name, patterns in FALLBACK_RULES.items():
            for pat in patterns:
                if re.search(pat, data, re.IGNORECASE):
                    sev = "CRITICAL" if "Sliver" in rule_name or "Cobalt" in rule_name else "HIGH"
                    matches.append({
                        "rule": rule_name,
                        "severity": sev,
                        "description": f"Regex match for threat signature: {rule_name}",
                        "source": source_name,
                        "engine": "EDR Regex Fallback Engine"
                    })
                    break # match rule once per buffer
                    
        return matches

# Singleton instance
_yara_engine = None

def get_yara_engine() -> YaraEngine:
    global _yara_engine
    if _yara_engine is None:
        _yara_engine = YaraEngine()
    return _yara_engine

if __name__ == "__main__":
    engine = get_yara_engine()
    test_buffer = b"Sliver C2 implant initialized. Spawning pb.Sliver process."
    results = engine.scan_buffer(test_buffer)
    print(f"Scan Results (Yara enabled={engine.yara_enabled}):")
    for r in results:
        print(f"  - [{r['severity']}] {r['rule']} via {r['engine']}")
