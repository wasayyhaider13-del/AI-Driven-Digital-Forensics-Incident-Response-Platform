"""
network_analyzer.py — Tshark Network Forensics Module
=======================================================
DFIR External Tool: Uses Tshark (Wireshark CLI) to capture live
network traffic and convert it into IOC-ready records for the pipeline.

Tshark is a real industry-standard forensic tool used by SOC analysts.
Install: https://www.wireshark.org/download.html

Usage:
    from network_analyzer import capture_traffic, load_network_data
"""

import os
import sys
import csv
import shutil
import subprocess
import platform
import datetime
from typing import List, Dict, Optional

if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

OUTPUT_FILE = "logs/network_data.csv"
os.makedirs("logs", exist_ok=True)


# ── Tool detection ─────────────────────────────────────────────────────────────

def _find_tshark() -> Optional[str]:
    """Return path to tshark binary, or None if not installed."""
    # Check PATH
    path = shutil.which("tshark")
    if path:
        return path

    # Common Windows install locations
    if platform.system() == "Windows":
        for candidate in [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]:
            if os.path.exists(candidate):
                return candidate

    return None


def tshark_installed() -> bool:
    """Returns True if tshark is available on this system."""
    return _find_tshark() is not None


def get_tshark_version() -> str:
    """Return tshark version string for display in dashboard."""
    tshark = _find_tshark()
    if not tshark:
        return "Not installed"
    try:
        r = subprocess.run([tshark, "--version"], capture_output=True, text=True, timeout=5)
        return r.stdout.split("\n")[0].strip()
    except Exception as e:
        return f"Error: {e}"


def _get_default_interface() -> str:
    """Auto-detect first available network interface."""
    tshark = _find_tshark()
    if not tshark:
        return "1"
    try:
        r = subprocess.run([tshark, "-D"], capture_output=True, text=True, timeout=5)
        lines = [l.strip() for l in r.stdout.strip().split("\n") if l.strip()]
        if lines:
            # Format: "1. \Device\NPF_{GUID} (Ethernet)" — grab just the number
            return lines[0].split(".")[0].strip()
    except Exception:
        pass
    return "1"


# ── Live capture ───────────────────────────────────────────────────────────────

def capture_traffic(duration: int = 10, interface: str = None) -> bool:
    """
    Capture live network traffic using Tshark and save to CSV.

    Args:
        duration:  Seconds to capture (default 10)
        interface: Network interface. None = auto-detect.

    Returns:
        True on success, False on failure.
    """
    tshark = _find_tshark()

    if not tshark:
        print(
            "[NETWORK] Tshark not found.\n"
            "  -> Download from: https://www.wireshark.org/download.html\n"
            "  -> Tick 'Install TShark' during Wireshark setup.\n"
            "  -> Then restart VS Code so PATH updates take effect."
        )
        return False

    iface = interface or _get_default_interface()
    print(f"[NETWORK] Tshark {get_tshark_version()}")
    print(f"[NETWORK] Capturing on interface '{iface}' for {duration}s...")

    cmd = [
        tshark,
        "-i", iface,
        "-a", f"duration:{duration}",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "http.host",
        "-e", "dns.qry.name",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "_ws.col.Protocol",
        "-E", "header=y",          # ← FIXED: include CSV header row
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=f",
    ]

    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            result = subprocess.run(
                cmd, stdout=f, stderr=subprocess.PIPE,
                text=True, timeout=duration + 20,
            )

        if result.returncode not in (0, 1):  # tshark returns 1 on Ctrl+C
            print(f"[NETWORK] Tshark exited with code {result.returncode}")
            if result.stderr:
                print(f"[NETWORK] stderr: {result.stderr[:300]}")

        # Count captured lines
        try:
            with open(OUTPUT_FILE) as f:
                lines = sum(1 for _ in f) - 1  # subtract header
            print(f"[NETWORK] Capture complete — {max(lines,0)} packets.")
        except Exception:
            pass

        return True

    except PermissionError:
        print(
            "[NETWORK] Permission denied.\n"
            "  -> Windows: Run VS Code as Administrator.\n"
            "  -> Linux/Mac: Run with sudo."
        )
        return False
    except subprocess.TimeoutExpired:
        print("[NETWORK] Tshark capture timed out.")
        return False
    except Exception as e:
        print(f"[NETWORK] Capture failed: {e}")
        return False


# ── PCAP file analysis ─────────────────────────────────────────────────────────

def analyze_pcap(pcap_path: str) -> List[Dict]:
    """
    Analyze an existing .pcap / .pcapng file.
    Returns IOC-ready records for the pipeline.
    """
    tshark = _find_tshark()
    if not tshark:
        print("[NETWORK] Tshark not installed — cannot analyze PCAP.")
        return []

    if not os.path.exists(pcap_path):
        print(f"[NETWORK] PCAP not found: {pcap_path}")
        return []

    pcap_csv = pcap_path + "_parsed.csv"
    cmd = [
        tshark, "-r", pcap_path,
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "http.host",
        "-e", "dns.qry.name",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "_ws.col.Protocol",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
    ]

    try:
        with open(pcap_csv, "w", encoding="utf-8") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL,
                           timeout=60, text=True)
        records = _csv_to_records(pcap_csv)
        print(f"[NETWORK] PCAP analyzed — {len(records)} network records.")
        return records
    except Exception as e:
        print(f"[NETWORK] PCAP analysis failed: {e}")
        return []
    finally:
        if os.path.exists(pcap_csv):
            os.remove(pcap_csv)


# ── CSV → records ──────────────────────────────────────────────────────────────

# Suspicious destination ports
SUSPICIOUS_PORTS = {"4444","1337","31337","8080","9999","6667","6697","23","2323","445","139"}

# Suspicious DNS/host keywords
SUSPICIOUS_HOST_KW = ["onion","c2","botnet","malware","payload","exploit","darkweb","shell"]


def _csv_to_records(csv_path: str) -> List[Dict]:
    """
    Read tshark CSV output and convert to IOC-ready pipeline records.
    Skips rows with no meaningful data. Adds severity + reason.
    """
    records = []

    if not os.path.exists(csv_path):
        return []

    try:
        with open(csv_path, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            now    = datetime.datetime.utcnow()

            for row in reader:
                src_ip   = (row.get("ip.src")                              or "").strip().strip('"')
                dst_ip   = (row.get("ip.dst")                              or "").strip().strip('"')
                tcp_port = (row.get("tcp.dstport")                         or "").strip().strip('"')
                udp_port = (row.get("udp.dstport")                         or "").strip().strip('"')
                http_hst = (row.get("http.host")                           or "").strip().strip('"')
                dns_q    = (row.get("dns.qry.name")                        or "").strip().strip('"')
                tls_sni  = (row.get("tls.handshake.extensions_server_name")or "").strip().strip('"')
                protocol = (row.get("_ws.col.Protocol")                    or "").strip().strip('"')

                dst_port = tcp_port or udp_port
                host     = http_hst or tls_sni or dns_q

                # Skip rows with no useful data
                if not any([dst_ip, host, dns_q]):
                    continue

                # Score severity
                reasons  = []
                severity = "LOW"

                if dst_port in SUSPICIOUS_PORTS:
                    reasons.append(f"Suspicious port {dst_port}")
                    severity = "HIGH"

                host_lower = host.lower()
                for kw in SUSPICIOUS_HOST_KW:
                    if kw in host_lower:
                        reasons.append(f"Suspicious host keyword: '{kw}'")
                        severity = "HIGH"
                        break

                if host.endswith(".onion"):
                    reasons.append("Tor .onion domain contacted")
                    severity = "HIGH"
                elif any(host.endswith(t) for t in [".xyz",".tk",".cc",".to",".su"]):
                    reasons.append(f"Suspicious TLD in host: {host}")
                    if severity == "LOW":
                        severity = "MEDIUM"

                records.append({
                    "url":           f"net://{dst_ip}:{dst_port}" if not host else f"net://{host}",
                    "title":         f"{protocol} · {host or dst_ip}",
                    "visit_time":    now.strftime("%Y-%m-%d %H:%M:%S"),
                    "visit_time_dt": now,
                    "visit_count":   1,
                    "raw_ts":        int(now.timestamp()),
                    "severity":      severity,
                    "matched_rule":  "NETWORK_CAPTURE" if not reasons else "NETWORK_IOC",
                    "reason":        " | ".join(reasons) if reasons else "Network traffic",
                    "source":        "tshark",
                    "src_ip":        src_ip,
                    "dst_ip":        dst_ip,
                    "dst_port":      dst_port,
                    "http_host":     http_hst,
                    "dns_query":     dns_q,
                    "tls_sni":       tls_sni,
                    "protocol":      protocol,
                })

    except Exception as e:
        print(f"[NETWORK] CSV parse error: {e}")

    return records


def load_network_data() -> List[Dict]:
    """
    Load previously captured network data from logs/network_data.csv.
    Returns IOC-ready records for the pipeline.
    """
    if not os.path.exists(OUTPUT_FILE):
        print("[NETWORK] No capture file found. Run capture_traffic() first.")
        return []

    records = _csv_to_records(OUTPUT_FILE)
    print(f"[NETWORK] Loaded {len(records)} network records from {OUTPUT_FILE}.")
    return records


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"Tshark installed : {tshark_installed()}")
    print(f"Version          : {get_tshark_version()}")

    if tshark_installed():
        print("\nRunning 5-second live capture...")
        ok = capture_traffic(duration=5)
        if ok:
            recs = load_network_data()
            print(f"Records loaded : {len(recs)}")
            high = [r for r in recs if r["severity"]=="HIGH"]
            print(f"HIGH severity  : {len(high)}")
    else:
        print("\nInstall Tshark: https://www.wireshark.org/download.html")
        print("Tick 'Install TShark' during the Wireshark installer.")
