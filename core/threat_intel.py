"""
core/threat_intel.py — Threat Intelligence Caching Manager
============================================================
Handles threat reputation lookups for IP addresses, URLs, domains, and file hashes.
Integrates VT, AbuseIPDB, Shodan, and URLHaus, using a local thread-safe cache.
"""

import threading
import datetime
from typing import Dict, Any, Optional

import config
from integrations.virustotal_api import get_vt_reputation
from integrations.abuseipdb_api import get_abuse_ip_reputation
from integrations.shodan_api import get_shodan_reputation
from integrations.urlhaus_api import get_urlhaus_reputation

class ThreatIntelManager:
    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def lookup(self, value: str, ioc_type: str) -> Dict[str, Any]:
        """
        Check local cache for the IOC value. If missed, performs live integration lookup.
        
        Args:
            value: IP, URL, Domain, MD5, or SHA256 string
            ioc_type: 'IP' | 'URL' | 'Domain' | 'SHA256' | 'MD5'
            
        Returns:
            Dict containing reputation details (severity, malware_family, score, source)
        """
        val_clean = value.strip().lower()
        
        with self._lock:
            # 1. Check cache first
            if val_clean in self._cache:
                entry = self._cache[val_clean]
                # Check cache expiry (default 12 hours)
                age = datetime.datetime.utcnow() - entry["cached_at"]
                if age < datetime.timedelta(hours=12):
                    return entry["data"]

        # 2. Cache Miss — Query appropriate threat intelligence API
        data = self._execute_api_queries(val_clean, ioc_type)
        
        # 3. Cache the result
        with self._lock:
            self._cache[val_clean] = {
                "cached_at": datetime.datetime.utcnow(),
                "data": data
            }
            
        return data

    def _execute_api_queries(self, value: str, ioc_type: str) -> Dict[str, Any]:
        """Queries standard wrappers, falling back to mock lookups if keys are absent."""
        severity = "LOW"
        score = 0
        malware_family = "Unknown"
        details = "Static analysis indicates normal record."
        source = "Local Sandbox Cache"

        if ioc_type == "IP":
            # Try AbuseIPDB
            res = get_abuse_ip_reputation(value)
            if res and res.get("reputation_score", 0) > 0:
                severity = res["severity"]
                score = res["reputation_score"]
                malware_family = res.get("malware_family", "Suspicious IP")
                details = res.get("details", "")
                source = "AbuseIPDB"
            else:
                # Try Shodan
                shodan_res = get_shodan_reputation(value)
                if shodan_res and shodan_res.get("ports"):
                    severity = "MEDIUM"
                    score = 45
                    details = f"Exposed Ports: {shodan_res['ports']}. OS: {shodan_res.get('os', 'Unknown')}"
                    source = "Shodan"

        elif ioc_type in ("Domain", "URL"):
            # Try URLHaus first
            urlhaus_res = get_urlhaus_reputation(value)
            if urlhaus_res and urlhaus_res.get("blacklisted"):
                severity = "HIGH"
                score = 85
                malware_family = urlhaus_res.get("malware_family", "Web Malware")
                details = urlhaus_res.get("details", "")
                source = "URLHaus"
            else:
                # Fallback to VirusTotal
                vt_res = get_vt_reputation(value)
                if vt_res and vt_res.get("reputation_score", 0) > 0:
                    severity = vt_res["severity"]
                    score = vt_res["reputation_score"]
                    malware_family = vt_res.get("malware_family", "Malicious Link")
                    details = vt_res.get("details", "")
                    source = "VirusTotal"

        elif ioc_type in ("SHA256", "MD5"):
            # Query VirusTotal
            vt_res = get_vt_reputation(value)
            if vt_res and vt_res.get("reputation_score", 0) > 0:
                severity = vt_res["severity"]
                score = vt_res["reputation_score"]
                malware_family = vt_res.get("malware_family", "Unknown Malware")
                details = vt_res.get("details", "")
                source = "VirusTotal"

        # Heuristic matching if all live integrations yielded nothing or were mocked
        if score == 0:
            # Local regex heuristic engine
            if any(term in value for term in ["evil", "botnet", "malware", "rat", "c2"]):
                severity = "HIGH"
                score = 92
                malware_family = "Sliver/CobaltStrike Command & Control"
                details = "Flagged via local domain/keyword matching signature rules."
                source = "EDR Heuristics"
            elif ".ru" in value or ".su" in value or ".tk" in value or ".onion" in value:
                severity = "HIGH"
                score = 80
                malware_family = "Suspicious TLD/Region Host"
                details = "Flagged due to anomalous top-level domain."
                source = "EDR Heuristics"

        return {
            "value": value,
            "type": ioc_type,
            "severity": severity,
            "reputation_score": score,
            "malware_family": malware_family,
            "details": details,
            "lookup_source": source
        }

# Singleton instance
_manager = None

def get_threat_intel_manager() -> ThreatIntelManager:
    global _manager
    if _manager is None:
        _manager = ThreatIntelManager()
    return _manager

if __name__ == "__main__":
    mgr = get_threat_intel_manager()
    print("Testing VT lookup:")
    res = mgr.lookup("evil-c2.onion", "Domain")
    print(res)
