"""
llm_classifier.py — AI Threat Classification
Classifies browser events using OpenAI or Ollama.
Gracefully skips if no API key configured.
"""
import json
import time
import re
from typing import Dict, List, Optional

from colorama import Fore, Style
import config


def _build_client():
    """Build OpenAI client. Returns None if no key configured."""
    try:
        from openai import OpenAI
    except ImportError:
        print(f"{Fore.RED}[LLM] openai not installed. Run: pip install openai{Style.RESET_ALL}")
        return None

    if config.USE_OLLAMA:
        print(f"{Fore.CYAN}[LLM] Using Ollama @ {config.OLLAMA_BASE_URL}{Style.RESET_ALL}")
        return OpenAI(api_key="ollama", base_url=config.OLLAMA_BASE_URL)

    if not config.OPENAI_API_KEY:
        print(f"{Fore.YELLOW}[LLM] No OPENAI_API_KEY in .env — skipping AI classification.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[LLM] Add OPENAI_API_KEY=sk-... to your .env file.{Style.RESET_ALL}")
        return None

    from openai import OpenAI
    return OpenAI(api_key=config.OPENAI_API_KEY)


def _active_model() -> str:
    return config.OLLAMA_MODEL if config.USE_OLLAMA else config.LLM_MODEL


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


def classify_event(client, event: Dict) -> Dict:
    """Classify a single event with retry on rate limit."""
    for attempt in range(3):
        try:
            from openai import RateLimitError
            response = client.chat.completions.create(
                model=_active_model(),
                messages=[{"role": "user", "content": _build_prompt(event)}],
                temperature=0.1,
                max_tokens=200,
            )
            text = response.choices[0].message.content.strip()

            # Strip markdown fences
            if "```" in text:
                text = re.sub(r"```(?:json)?\n?", "", text).strip().rstrip("`")

            result = json.loads(text)

            # Validate required fields
            result.setdefault("classification", "UNKNOWN")
            result.setdefault("confidence", 0)
            result.setdefault("threat_type", "Unknown")
            result.setdefault("explanation", "No explanation provided.")
            result.setdefault("recommended_action", "Manual review required.")

            event["llm"] = result
            print(f"{Fore.GREEN}[LLM]{Style.RESET_ALL} {result['classification']} ({result['confidence']}%) | {event['url'][:55]}")
            return event

        except Exception as e:
            err_str = str(e)
            if "rate_limit" in err_str.lower() or "429" in err_str:
                wait = 2 ** attempt
                print(f"{Fore.YELLOW}[LLM] Rate limit — retrying in {wait}s...{Style.RESET_ALL}")
                time.sleep(wait)
            elif "json" in err_str.lower():
                print(f"{Fore.YELLOW}[LLM] JSON parse error — skipping.{Style.RESET_ALL}")
                break
            elif "invalid_api_key" in err_str.lower() or "incorrect api key" in err_str.lower() or "401" in err_str or "authentication" in err_str.lower():
                print(f"{Fore.RED}[LLM] Authentication failed: {err_str[:80]}{Style.RESET_ALL}")
                raise e
            else:
                print(f"{Fore.RED}[LLM] Error: {err_str[:80]}{Style.RESET_ALL}")
                break

    # Fallback
    sev = event.get("severity", "LOW")
    event["llm"] = {
        "classification":     "SUSPICIOUS" if sev in ("HIGH", "MEDIUM") else "BENIGN",
        "confidence":         0,
        "threat_type":        "Unclassified",
        "explanation":        "LLM classification failed — manual review recommended.",
        "recommended_action": "Investigate manually.",
    }
    return event


def classify_all_events(events: List[Dict]) -> List[Dict]:
    """
    Classify all events using LLM.
    If no API key → marks all as UNKNOWN and returns immediately (no crash).
    """
    if not events:
        print(f"{Fore.YELLOW}[LLM] No events to classify.{Style.RESET_ALL}")
        return []

    client = _build_client()

    # No client = no API key — graceful degradation
    if client is None:
        print(f"{Fore.YELLOW}[LLM] Skipping classification — no API key.{Style.RESET_ALL}")
        for e in events:
            sev = e.get("severity", "LOW")
            e["llm"] = {
                "classification":     "SUSPICIOUS" if sev in ("HIGH", "MEDIUM") else "BENIGN",
                "confidence":         0,
                "threat_type":        "Rule-based detection only",
                "explanation":        "Add OPENAI_API_KEY to .env for AI analysis.",
                "recommended_action": "Review flagged events manually.",
            }
        return events

    results = []
    api_failed = False
    for i, e in enumerate(events):
        if api_failed:
            sev = e.get("severity", "LOW")
            e["llm"] = {
                "classification":     "SUSPICIOUS" if sev in ("HIGH", "MEDIUM") else "BENIGN",
                "confidence":         0,
                "threat_type":        "Rule-based detection only (API key invalid)",
                "explanation":        "LLM classification skipped due to authentication failure.",
                "recommended_action": "Review flagged events manually.",
            }
            results.append(e)
            continue

        try:
            results.append(classify_event(client, e))
        except Exception as ex:
            print(f"{Fore.RED}[LLM] Disabling AI classification due to API key error: {str(ex)[:80]}{Style.RESET_ALL}")
            api_failed = True
            sev = e.get("severity", "LOW")
            e["llm"] = {
                "classification":     "SUSPICIOUS" if sev in ("HIGH", "MEDIUM") else "BENIGN",
                "confidence":         0,
                "threat_type":        "Rule-based detection only (API key invalid)",
                "explanation":        "LLM classification failed — manual review recommended.",
                "recommended_action": "Investigate manually.",
            }
            results.append(e)

        if not api_failed and i < len(events) - 1:
            time.sleep(0.3)  # rate limiting

    classified  = sum(1 for r in results if r.get("llm", {}).get("classification") != "UNKNOWN")
    malicious   = sum(1 for r in results if r.get("llm", {}).get("classification") == "MALICIOUS")
    suspicious  = sum(1 for r in results if r.get("llm", {}).get("classification") == "SUSPICIOUS")
    print(f"{Fore.CYAN}[LLM]{Style.RESET_ALL} Done: {classified}/{len(results)} classified | MALICIOUS:{malicious} SUSPICIOUS:{suspicious}")
    return results