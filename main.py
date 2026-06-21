"""
main.py — DFIR Sentinel Entry Point
Modes: scan | live | report | network | autopsy | logs | monitor-files
"""

import os
import sys
import argparse
import datetime
from colorama import Fore, Style, init

if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════╗
║  🔍  DFIR SENTINEL — Real-Time Browser Forensics     ║
║      AI-Driven Incident Response Platform v2.0       ║
╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""


def _print_banner() -> None:
    print(BANNER)
    # FIX: use timezone.utc for Python 3.9+ compatibility
    print(f"  Start : {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n")


# ── Modes ─────────────────────────────────────────────────────────────────────

def run_scan() -> None:
    from extractor      import extract_chrome_history
    from timeline       import reconstruct_timeline
    from ioc_detector   import detect_iocs
    from llm_classifier import classify_all_events
    from alerter        import send_alerts
    from utils          import save_logs

    print(f"{Fore.CYAN}[MAIN] Mode: SCAN{Style.RESET_ALL}\n")
    records = extract_chrome_history()
    if not records:
        print(f"{Fore.YELLOW}[MAIN] No browser history found.{Style.RESET_ALL}")
        return

    timeline   = reconstruct_timeline(records)
    flagged    = detect_iocs(timeline)
    classified = classify_all_events(flagged) if flagged else []
    save_logs(classified)
    alerts     = send_alerts(classified)

    print(f"\n{Fore.GREEN}[MAIN] Scan complete.{Style.RESET_ALL}")
    print(f"  Extracted  : {len(records)}")
    print(f"  Flagged    : {len(flagged)}")
    print(f"  Classified : {len(classified)}")
    print(f"  Alerts     : {alerts}")


def run_live(interval: int) -> None:
    from monitor import start_monitor
    print(f"{Fore.CYAN}[MAIN] Mode: LIVE ({interval}s){Style.RESET_ALL}\n")
    start_monitor(interval=interval)


def run_report() -> None:
    from reporter import generate_report
    print(f"{Fore.CYAN}[MAIN] Mode: REPORT{Style.RESET_ALL}\n")
    path = generate_report()
    print(f"\n{Fore.GREEN}[MAIN] Report → {path}{Style.RESET_ALL}")


def run_network(duration: int = 10) -> None:
    from network_analyzer import capture_traffic, load_network_data
    from ioc_detector     import detect_iocs
    from llm_classifier   import classify_all_events
    from alerter          import send_alerts
    from utils            import save_logs

    print(f"{Fore.CYAN}[MAIN] Mode: NETWORK ({duration}s){Style.RESET_ALL}\n")
    capture_traffic(duration=duration)
    records = load_network_data()
    if not records:
        print(f"{Fore.YELLOW}[MAIN] No network data.{Style.RESET_ALL}")
        return
    flagged    = detect_iocs(records)
    classified = classify_all_events(flagged) if flagged else []
    save_logs(classified)
    alerts     = send_alerts(classified)
    print(f"\n{Fore.GREEN}[MAIN] Network scan complete.{Style.RESET_ALL}")
    print(f"  Packets:{len(records)}  Flagged:{len(flagged)}  Alerts:{alerts}")


def run_autopsy(file_path: str = "autopsy_data.csv") -> None:
    from autopsy_ingestor import load_autopsy_data
    from ioc_detector     import detect_iocs
    from llm_classifier   import classify_all_events
    from alerter          import send_alerts
    from utils            import save_logs

    print(f"{Fore.CYAN}[MAIN] Mode: AUTOPSY — {file_path}{Style.RESET_ALL}\n")
    records = load_autopsy_data(file_path)
    if not records:
        print(f"{Fore.YELLOW}[MAIN] No Autopsy data.{Style.RESET_ALL}")
        return
    flagged    = detect_iocs(records)
    classified = classify_all_events(flagged) if flagged else []
    save_logs(classified)
    alerts     = send_alerts(classified)
    print(f"\n{Fore.GREEN}[MAIN] Autopsy complete.{Style.RESET_ALL}")
    print(f"  Records:{len(records)}  Flagged:{len(flagged)}  Alerts:{alerts}")


def run_logs() -> None:
    from log_ingestor   import load_logs
    from ioc_detector   import detect_iocs
    from llm_classifier import classify_all_events
    from alerter        import send_alerts
    from utils          import save_logs

    print(f"{Fore.CYAN}[MAIN] Mode: LOGS (Windows Event Log){Style.RESET_ALL}\n")
    records = load_logs()
    if not records:
        print(f"{Fore.YELLOW}[MAIN] No log records.{Style.RESET_ALL}")
        return
    flagged    = detect_iocs(records)
    classified = classify_all_events(flagged) if flagged else []
    save_logs(classified)
    alerts     = send_alerts(classified)
    print(f"\n{Fore.GREEN}[MAIN] Log scan complete.{Style.RESET_ALL}")
    print(f"  Records:{len(records)}  Flagged:{len(flagged)}  Alerts:{alerts}")


def run_monitor_files(path: str = ".") -> None:
    """Real-time file system monitoring using watchdog."""
    try:
        from watchdog.observers import Observer
        from watchdog.events    import FileSystemEventHandler
    except ImportError:
        print(f"{Fore.RED}[MAIN] Install watchdog: pip install watchdog{Style.RESET_ALL}")
        return

    from alerter import send_alerts

    class ThreatHandler(FileSystemEventHandler):
        SUSPICIOUS_EXTS = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".dll", ".msi"}

        def on_created(self, event):
            if event.is_directory:
                return
            ext = os.path.splitext(event.src_path)[1].lower()
            if ext in self.SUSPICIOUS_EXTS:
                print(f"{Fore.RED}[WATCHDOG] Suspicious file created: {event.src_path}{Style.RESET_ALL}")
                send_alerts([{
                    "url":      event.src_path,
                    "title":    "Suspicious File Created",
                    "visit_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "visit_count": 1,
                    "severity": "HIGH",
                    "matched_rule": "FILE_MONITOR",
                    "reason":   f"Suspicious file extension {ext} created",
                    "llm": {
                        "classification":     "SUSPICIOUS",
                        "confidence":         85,
                        "threat_type":        "Malicious File",
                        "explanation":        f"File with extension {ext} created on disk.",
                        "recommended_action": "Investigate and quarantine if needed.",
                    }
                }])

        def on_modified(self, event):
            if not event.is_directory:
                print(f"{Fore.YELLOW}[WATCHDOG] Modified: {event.src_path}{Style.RESET_ALL}")

    print(f"{Fore.CYAN}[MAIN] Mode: FILE MONITOR — watching: {path}{Style.RESET_ALL}")
    print("Press Ctrl+C to stop.\n")

    observer = Observer()
    observer.schedule(ThreatHandler(), path=path, recursive=True)
    observer.start()
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


# ── CLI ───────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dfir",
        description="DFIR Sentinel v2.0",
        epilog=(
            "Examples:\n"
            "  python main.py --mode scan\n"
            "  python main.py --mode live --interval 30\n"
            "  python main.py --mode report\n"
            "  python main.py --mode network --duration 15\n"
            "  python main.py --mode autopsy --file autopsy_data.csv\n"
            "  python main.py --mode logs\n"
            "  python main.py --mode monitor-files --watch C:/Users\n"
            "  streamlit run dashboard.py\n"
        ),
    )
    p.add_argument("--mode", choices=["scan","live","report","network","autopsy","logs","monitor-files"],
                   default="scan")
    p.add_argument("--interval", type=int,  default=None,              metavar="SECONDS")
    p.add_argument("--duration", type=int,  default=10,                metavar="SECONDS")
    p.add_argument("--file",     type=str,  default="autopsy_data.csv",metavar="PATH")
    p.add_argument("--watch",    type=str,  default=".",               metavar="PATH")
    return p


# os imported at top of file

def main() -> None:
    _print_banner()
    args = _build_parser().parse_args()

    import config
    interval = args.interval or config.SCAN_INTERVAL_SECONDS

    try:
        if   args.mode == "scan":           run_scan()
        elif args.mode == "live":           run_live(interval=interval)
        elif args.mode == "report":         run_report()
        elif args.mode == "network":        run_network(duration=args.duration)
        elif args.mode == "autopsy":        run_autopsy(file_path=args.file)
        elif args.mode == "logs":           run_logs()
        elif args.mode == "monitor-files":  run_monitor_files(path=args.watch)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[MAIN] Stopped.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as exc:
        print(f"\n{Fore.RED}[MAIN] Fatal: {exc}{Style.RESET_ALL}")
        raise


if __name__ == "__main__":
    main()