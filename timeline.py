"""
timeline.py — Timeline Reconstructor
======================================
DFIR Module 3: Sorts browser artifacts chronologically, deduplicates
entries, color-codes output to the terminal, and persists the timeline
as a JSON log file for downstream analysis.

DFIR Principle: A reliable timeline is the backbone of any incident
reconstruction — every event must be ordered and deduplicated before
IOC analysis.
"""

import os
import json
import hashlib
import datetime
from typing import List, Dict

from colorama import init, Fore, Style

import config

# Initialise colorama (autoreset saves us writing Style.RESET_ALL every line)
init(autoreset=True)

# Colour map: severity/category → terminal colour
COLOR_MAP = {
    "HIGH":    Fore.RED,
    "MEDIUM":  Fore.YELLOW,
    "LOW":     Fore.CYAN,
    "DEFAULT": Fore.WHITE,
}


def _make_dedup_hash(record: Dict) -> str:
    """
    Build a SHA-256 fingerprint for a browsing record.

    We hash URL + raw Chrome timestamp so that:
      - The same page loaded at the same microsecond is deduplicated.
      - Revisiting the same page at a different time is preserved.

    This matches how forensic tools distinguish re-visits from duplicate
    rows caused by database journal replay.
    """
    key = f"{record.get('url', '')}|{record.get('raw_ts', '')}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _sort_and_deduplicate(records: List[Dict]) -> List[Dict]:
    """
    Sort records by visit_time_dt (oldest first) and remove duplicates.

    Returns a new list — original data is never mutated.
    """
    seen_hashes = set()
    unique = []

    for rec in records:
        h = _make_dedup_hash(rec)
        if h not in seen_hashes:
            seen_hashes.add(h)
            unique.append({**rec, "_hash": h})  # attach hash for reference

    # Sort ascending — chronological order matches investigator mental model
    unique.sort(key=lambda r: r.get("visit_time_dt", datetime.datetime.min))

    return unique


def _format_record_for_display(idx: int, rec: Dict) -> str:
    """
    Format a single timeline entry for terminal display.

    Example output:
      [0042] 2024-06-01 02:14:33 UTC  [×3]  evil-site.onion — Malware Download
    """
    ts  = rec.get("visit_time", "Unknown time")
    url = rec.get("url", "")
    title = rec.get("title", "(no title)")
    count = rec.get("visit_count", 1)

    # Truncate long URLs for readability
    display_url = url if len(url) <= 80 else url[:77] + "..."

    return (
        f"[{idx:04d}] "
        f"{Fore.GREEN}{ts}{Style.RESET_ALL}  "
        f"{Fore.BLUE}[×{count}]{Style.RESET_ALL}  "
        f"{display_url} — {Fore.CYAN}{title}{Style.RESET_ALL}"
    )


def _get_timeline_log_path() -> str:
    """Build the dated JSON log path: logs/timeline_YYYYMMDD.json"""
    today = datetime.date.today().strftime("%Y%m%d")
    return os.path.join(config.LOGS_DIR, f"timeline_{today}.json")


def _serialize_record(rec: Dict) -> Dict:
    """
    Prepare a record dict for JSON serialisation.

    datetime objects are not JSON-serialisable by default — convert to ISO strings.
    """
    out = {}
    for k, v in rec.items():
        if isinstance(v, datetime.datetime):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out


def reconstruct_timeline(records: List[Dict]) -> List[Dict]:
    """
    Main entry point for MODULE 3.

    Steps:
      1. Sort and deduplicate the raw artifact records.
      2. Print a colour-coded timeline to the terminal.
      3. Persist the full timeline to a dated JSON log file.

    Args:
        records: Raw list of dicts from extractor.extract_chrome_history()

    Returns:
        Sorted, deduplicated list of record dicts (with _hash field added).
    """
    if not records:
        print(f"{Fore.YELLOW}[TIMELINE] No records to process.{Style.RESET_ALL}")
        return []

    # ── Step 1: Sort & deduplicate ──────────────────────────────────────────
    timeline = _sort_and_deduplicate(records)

    duplicates_removed = len(records) - len(timeline)
    print(
        f"{Fore.CYAN}[TIMELINE]{Style.RESET_ALL} "
        f"Processed {len(records)} records → "
        f"{Fore.GREEN}{len(timeline)} unique events{Style.RESET_ALL} "
        f"({Fore.YELLOW}{duplicates_removed} duplicates removed{Style.RESET_ALL})"
    )

    # ── Step 2: Terminal display ────────────────────────────────────────────
    print()
    print(Fore.WHITE + "═" * 90)
    print(Fore.WHITE + "  BROWSER ACTIVITY TIMELINE" + Style.RESET_ALL)
    print(Fore.WHITE + "═" * 90)

    # Show at most 200 lines on terminal to avoid flooding large histories
    display_limit = 200
    for idx, rec in enumerate(timeline[:display_limit]):
        print(_format_record_for_display(idx + 1, rec))

    if len(timeline) > display_limit:
        print(
            f"{Fore.YELLOW}  … {len(timeline) - display_limit} more events "
            f"(see JSON log for full timeline){Style.RESET_ALL}"
        )

    print(Fore.WHITE + "═" * 90 + Style.RESET_ALL)

    # ── Step 3: Persist to JSON log ─────────────────────────────────────────
    log_path = _get_timeline_log_path()
    serialisable = [_serialize_record(r) for r in timeline]

    os.makedirs(config.LOGS_DIR, exist_ok=True)
    try:
        with open(log_path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
                    "total_events": len(timeline),
                    "events": serialisable,
                },
                fh,
                indent=2,
                ensure_ascii=False,
            )
        print(
            f"{Fore.GREEN}[TIMELINE]{Style.RESET_ALL} "
            f"Timeline saved → {log_path}"
        )
    except IOError as exc:
        print(f"{Fore.RED}[TIMELINE ERROR]{Style.RESET_ALL} Could not write log: {exc}")

    return timeline


# ── CLI self-test ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    from extractor import extract_chrome_history

    artifacts = extract_chrome_history(limit=500)
    timeline  = reconstruct_timeline(artifacts)
    print(f"\nFinal timeline length: {len(timeline)}")
