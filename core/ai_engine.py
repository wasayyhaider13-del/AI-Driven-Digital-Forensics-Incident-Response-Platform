"""
core/ai_engine.py — AI Threat Analysis and Triage Engine
==========================================================
Utilizes OpenAI GPT or local Ollama LLMs to provide forensic insights,
explaining threats, scoring confidence, and suggesting immediate response triages.
"""

import json
import time
import re
from typing import Dict, List, Optional, Tuple

import config
from colorama import Fore, Style

# ── Local Backup Engine (Static Analysis) ──────────────────────────────────────

def _get_static_analysis(event: Dict) -> Dict[str, Any]:
    """Generates precise static heuristic explanations when LLM is unavailable."""
    rule = event.get("matched_rule", "NONE")
    sev = event.get("severity", "LOW")
    
    classification = "SUSPICIOUS" if sev in ("HIGH", "MEDIUM") else "BENIGN"
    if rule in ("YARA_SLIVER_IMPLANT", "SIGMA_CREDENTIAL_DUMP", "MALICIOUS_DOMAIN"):
        classification = "MALICIOUS"
        
    explanations = {
        "DOWNLOAD_DETECTED": "High-risk executable binary downloaded over standard HTTP ports.",
        "POWERSHELL_SUSPICIOUS_ARGS": "PowerShell command execution utilizes encoded commands or hidden parameters, a common obfuscation technique.",
        "BEACONING_TCP_HIGH_PORT": "Repetitive connection attempts detected contacting an administrative TCP port. Signature matches C2 beaconing.",
        "PROCESS_INJECTION_MALFIND": "Volatility malfind identified injected DLL strings or execution page permissions in system memory processes.",
        "USB_INSERTION": "USB mass storage insertion detected on administrative workstation.",
        "SIGMA_CREDENTIAL_DUMP": "Sigma rule detected attempts to tamper with security accounts database (LSASS) using PowerShell or comsvcs.",
        "YARA_SLIVER_IMPLANT": "YARA signature matched the memory signature footprint of a Go-compiled Sliver C2 implant."
    }
    
    recommendations = {
        "CRITICAL": "Isolate the endpoint from the network space immediately, dump memory using Volatility, and cancel credentials.",
        "HIGH": "Kill the associated process, place the file in quarantine, and inspect external proxy logs.",
        "MEDIUM": "Inspect Windows security logs for associated lateral activities.",
        "LOW": "Monitor log streams for subsequent repeats."
    }
    
    explanation = explanations.get(rule, f"Flagged indicator matching {rule} under heuristic evaluation.")
    reco = recommendations.get(sev, "Perform standard manual forensic review.")
    
    return {
        "classification": classification,
        "confidence": 75 if classification != "BENIGN" else 45,
        "threat_type": rule.replace("SIGMA_", "").replace("YARA_", "").replace("_", " "),
        "explanation": explanation,
        "recommended_action": reco
    }


# ── Client Builder ─────────────────────────────────────────────────────────────

def _build_client():
    """Create standard OpenAI/Ollama client wrapper."""
    try:
        from openai import OpenAI
    except ImportError:
        return None

    if config.USE_OLLAMA:
        return OpenAI(api_key="ollama", base_url=config.OLLAMA_BASE_URL)

    if not config.OPENAI_API_KEY:
        return None

    return OpenAI(api_key=config.OPENAI_API_KEY)


def _active_model() -> str:
    return config.OLLAMA_MODEL if config.USE_OLLAMA else config.LLM_MODEL


def _build_prompt(event: Dict) -> str:
    return f"""You are a senior SOC analyst and EDR classifier. Analyze this endpoint forensic log event and respond strictly with a valid JSON.

Event Context:
- Event Source: {event.get('source', 'EDR')}
- Type:         {event.get('event_type', 'System')}
- Indicator:    {event.get('url', 'N/A')}
- Description:  {event.get('details', 'N/A')}
- Severity:     {event.get('severity', 'LOW')}
- Rule Matched: {event.get('matched_rule', 'N/A')}
- Reason:       {event.get('reason', 'N/A')}

Your JSON output structure must have precisely these keys:
{{
  "classification": "BENIGN" or "SUSPICIOUS" or "MALICIOUS",
  "confidence": 0-100,
  "threat_type": "Specific category (e.g. Command & Control, Credential Dumping, Webshell)",
  "explanation": "One sentence cybersecurity explanation",
  "recommended_action": "One sentence specific immediate response recommendation"
}}"""


# ── Main Entry Points ──────────────────────────────────────────────────────────

_api_auth_failed = False  # Track API auth status globally to avoid slow redundant lookups

def classify_event(event: Dict) -> Dict:
    """
    Classify a single forensic event. 
    Gracefully uses static heuristic fallback if API key is invalid/missing.
    """
    global _api_auth_failed
    
    if _api_auth_failed:
        event["llm"] = _get_static_analysis(event)
        return event
        
    client = _build_client()
    if client is None:
        event["llm"] = _get_static_analysis(event)
        return event

    for attempt in range(2):
        try:
            response = client.chat.completions.create(
                model=_active_model(),
                messages=[{"role": "user", "content": _build_prompt(event)}],
                temperature=0.1,
                max_tokens=200,
            )
            text = response.choices[0].message.content.strip()
            
            # Clean markdown JSON fences
            if "```" in text:
                text = re.sub(r"```(?:json)?\n?", "", text).strip().rstrip("`")
                
            result = json.loads(text)
            
            # Validate structure
            result.setdefault("classification", "UNKNOWN")
            result.setdefault("confidence", 50)
            result.setdefault("threat_type", event.get("matched_rule", "Generic"))
            result.setdefault("explanation", "Forensic match analyzed via active AI models.")
            result.setdefault("recommended_action", "Audit via administrative channels.")
            
            event["llm"] = result
            return event
            
        except Exception as e:
            err_str = str(e)
            if "rate_limit" in err_str.lower() or "429" in err_str:
                time.sleep(1)
            elif "401" in err_str or "api_key" in err_str.lower() or "authentication" in err_str.lower():
                print(f"[AI ENGINE] API Key invalid/expired. Fast-failing to Local EDR Heuristics.")
                _api_auth_failed = True
                break
            else:
                break
                
    # Heuristic fallback
    event["llm"] = _get_static_analysis(event)
    return event


def classify_all_events(events: List[Dict]) -> List[Dict]:
    """Classify multiple events, falling back gracefully to static rules."""
    results = []
    for e in events:
        results.append(classify_event(e))
    return results


def run_ai_consultation(prompt: str) -> str:
    """Allows an investigator to ask arbitrary questions regarding incidents/cases."""
    global _api_auth_failed
    
    if _api_auth_failed or not config.OPENAI_API_KEY:
        return ("**[AI ENGINE] Local Mode Active**\n\n"
                "I am currently operating in **Local Heuristics Mode** because no valid `OPENAI_API_KEY` was found in the `.env` settings.\n\n"
                "Here are standard triage recommendations for active investigations:\n"
                "1. **Host Isolation:** Isolate endpoints expressing C2 beaconing on port 4444 or Tor exit nodes immediately.\n"
                "2. **Memory Analysis:** Run `windows.malfind` and `windows.pslist` on system memory dumps via Volatility to track code injections.\n"
                "3. **Hash Reputation:** Check SHA256 file hashes against VirusTotal or AbuseIPDB blocklists.")

    client = _build_client()
    if not client:
        return "AI Client could not be constructed."
        
    try:
        response = client.chat.completions.create(
            model=_active_model(),
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=600,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"AI Query failed: {e}"


if __name__ == "__main__":
    test_ev = {
        "matched_rule": "YARA_SLIVER_IMPLANT",
        "severity": "CRITICAL",
        "details": "Injected thread found in lsass.exe virtual space."
    }
    res = classify_event(test_ev)
    print("AI Analysis:", res["llm"])
