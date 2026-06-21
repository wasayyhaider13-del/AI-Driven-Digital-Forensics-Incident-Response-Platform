"""
llm_classifier.py — AI Threat Classification
Priority: Groq → Ollama → OpenAI → rule-based fallback.
"""
import json
import time
import re
from typing import Dict, List

from colorama import Fore, Style
import config
from core.llm_client import build_llm_client, active_llm_model, get_llm_provider

_MALICIOUS_RULES = {
    "MALICIOUS_DOMAIN", "ENCODED_PAYLOAD", "DOWNLOAD_DETECTED",
}
_SUSPICIOUS_RULES = {
    "KEYWORD_MATCH", "SUSPICIOUS_TLD", "OFF_HOURS_ACCESS",
    "RAPID_REVISIT", "HEX_PATTERN", "FILE_MONITOR",
}


def _rule_based_classify(event: Dict) -> Dict:
    """Deterministic classification when LLM is unavailable or fails."""
    sev = event.get("severity", "LOW")
    rule = event.get("matched_rule", "NONE")
    reason = event.get("reason", "")

    if rule in _MALICIOUS_RULES or sev == "HIGH":
        classification = "MALICIOUS" if rule in _MALICIOUS_RULES else "SUSPICIOUS"
        confidence = 88 if classification == "MALICIOUS" else 72
        threat_type = {
            "MALICIOUS_DOMAIN": "Known Malicious Infrastructure",
            "ENCODED_PAYLOAD": "Obfuscated Payload",
            "DOWNLOAD_DETECTED": "Malware Download",
            "KEYWORD_MATCH": "Suspicious Keyword Match",
            "SUSPICIOUS_TLD": "Suspicious Top-Level Domain",
            "OFF_HOURS_ACCESS": "Off-Hours Activity",
            "RAPID_REVISIT": "Automated Beaconing Pattern",
            "FILE_MONITOR": "Suspicious File Activity",
        }.get(rule, "Suspicious Network Activity")
        explanation = reason or f"Rule {rule} triggered at {sev} severity."
        action = (
            "Isolate endpoint and investigate immediately."
            if classification == "MALICIOUS"
            else "Review event and monitor for recurrence."
        )
    elif rule in _SUSPICIOUS_RULES or sev == "MEDIUM":
        classification = "SUSPICIOUS"
        confidence = 65
        threat_type = "Anomalous Browsing Behaviour"
        explanation = reason or f"Rule {rule} matched with medium confidence."
        action = "Review flagged URL and correlate with other host telemetry."
    else:
        classification = "BENIGN"
        confidence = 80
        threat_type = "None"
        explanation = reason or "Normal browsing activity within baseline parameters."
        action = "No action required."

    return {
        "classification": classification,
        "confidence": confidence,
        "threat_type": threat_type,
        "explanation": explanation,
        "recommended_action": action,
        "source": "rule_engine",
    }


def _build_client():
    """Build LLM client. Returns (client, provider) or (None, 'none')."""
    client, provider = build_llm_client()
    if client is None:
        print(f"{Fore.YELLOW}[LLM] No GROQ_API_KEY configured — using rule-based classification.{Style.RESET_ALL}")
        return None, "none"
    labels = {"groq": "Groq", "ollama": "Ollama", "openai": "OpenAI"}
    print(f"{Fore.CYAN}[LLM] Using {labels.get(provider, provider)} ({active_llm_model()}){Style.RESET_ALL}")
    return client, provider


def _parse_llm_json(text: str) -> Dict:
    text = text.strip()
    if "```" in text:
        text = re.sub(r"```(?:json)?\n?", "", text).strip().rstrip("`")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{[^{}]*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group())
        raise


def _build_prompt(event: Dict) -> str:
    return f"""You are a cybersecurity analyst. Analyze this browser event and respond ONLY with valid JSON.

URL:      {event.get('url', 'N/A')}
Title:    {event.get('title', 'N/A')}
Time:     {event.get('visit_time', 'N/A')}
Severity: {event.get('severity', 'N/A')}
Rule:     {event.get('matched_rule', 'N/A')}
Reason:   {event.get('reason', 'N/A')}

Return exactly this JSON structure:
{{
  "classification": "BENIGN or SUSPICIOUS or MALICIOUS",
  "confidence": 0-100,
  "threat_type": "brief threat category or None",
  "explanation": "one sentence explanation",
  "recommended_action": "one sentence action"
}}"""


def classify_event(client, event: Dict, provider: str = "groq") -> Dict:
    """Classify a single event with retry on rate limit."""
    for attempt in range(3):
        try:
            response = client.chat.completions.create(
                model=active_llm_model(),
                messages=[{"role": "user", "content": _build_prompt(event)}],
                temperature=0.1,
                max_tokens=200,
            )
            text = response.choices[0].message.content or ""
            result = _parse_llm_json(text)
            result.setdefault("classification", "UNKNOWN")
            result.setdefault("confidence", 0)
            result.setdefault("threat_type", "Unknown")
            result.setdefault("explanation", "No explanation provided.")
            result.setdefault("recommended_action", "Manual review required.")
            result["source"] = provider
            event["llm"] = result
            print(
                f"{Fore.GREEN}[LLM]{Style.RESET_ALL} "
                f"{result['classification']} ({result['confidence']}%) | {event['url'][:55]}"
            )
            return event

        except Exception as e:
            err_str = str(e)
            if "rate_limit" in err_str.lower() or "429" in err_str:
                wait = 2 ** attempt
                print(f"{Fore.YELLOW}[LLM] Rate limit — retrying in {wait}s...{Style.RESET_ALL}")
                time.sleep(wait)
            elif any(x in err_str.lower() for x in ("invalid_api_key", "incorrect api key", "401", "authentication", "403")):
                print(f"{Fore.YELLOW}[LLM] {provider} auth failed — switching to rule-based engine.{Style.RESET_ALL}")
                raise
            elif "json" in err_str.lower():
                print(f"{Fore.YELLOW}[LLM] JSON parse error — using rule engine for this event.{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.YELLOW}[LLM] Error: {err_str[:80]} — using rule engine.{Style.RESET_ALL}")
                break

    event["llm"] = _rule_based_classify(event)
    return event


def classify_all_events(events: List[Dict]) -> List[Dict]:
    """Classify all events. Groq first; falls back to rule engine on failure."""
    if not events:
        print(f"{Fore.YELLOW}[LLM] No events to classify.{Style.RESET_ALL}")
        return []

    client, provider = _build_client()
    if client is None:
        print(f"{Fore.CYAN}[LLM] Rule-based classification for {len(events)} events.{Style.RESET_ALL}")
        for e in events:
            e["llm"] = _rule_based_classify(e)
        return events

    results = []
    use_rules_only = False
    for i, e in enumerate(events):
        if use_rules_only:
            e["llm"] = _rule_based_classify(e)
            results.append(e)
            continue
        try:
            results.append(classify_event(client, e, provider))
        except Exception:
            use_rules_only = True
            e["llm"] = _rule_based_classify(e)
            results.append(e)

        if not use_rules_only and i < len(events) - 1:
            time.sleep(0.15)  # Groq has generous limits; shorter delay

    if use_rules_only:
        for e in events[len(results):]:
            e["llm"] = _rule_based_classify(e)
            results.append(e)

    classified = sum(1 for r in results if r.get("llm", {}).get("classification") != "UNKNOWN")
    malicious = sum(1 for r in results if r.get("llm", {}).get("classification") == "MALICIOUS")
    suspicious = sum(1 for r in results if r.get("llm", {}).get("classification") == "SUSPICIOUS")
    engine = "rule_engine" if use_rules_only else provider
    print(
        f"{Fore.CYAN}[LLM]{Style.RESET_ALL} Done ({engine}): "
        f"{classified}/{len(results)} classified | MALICIOUS:{malicious} SUSPICIOUS:{suspicious}"
    )
    return results
