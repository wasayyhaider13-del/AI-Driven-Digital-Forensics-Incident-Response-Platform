"""
core/correlation_engine.py — Threat Correlation Engine
=========================================================
Stitches together distinct EDR events (Process spawning, Network beacons,
YARA matches) occurring on the same host/IP within time boundaries
into singular unified SOC Incident Cases.
"""

import datetime
import json
from typing import List, Dict, Any

from sqlalchemy.orm import Session
from core.db import get_session, Event, Incident, Alert

class CorrelationEngine:
    def __init__(self, time_window_minutes: int = 60):
        self.time_window = datetime.timedelta(minutes=time_window_minutes)

    def run_correlation(self, session: Session = None) -> List[Incident]:
        """
        Query recent high-priority Events and correlate them into Incidents.
        Events are grouped if they occur within 1 hour and share:
          - The same EDR endpoint / source IP, OR
          - Malicious/Suspicious classification.
        """
        db_session = session or get_session()
        new_incidents = []
        
        try:
            # 1. Fetch all events from the past 24 hours that are flagged (matched a rule)
            cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=1)
            flagged_events = db_session.query(Event).filter(
                Event.timestamp >= cutoff,
                Event.matched_rule != "NONE"
            ).order_by(Event.timestamp.asc()).all()
            
            if not flagged_events:
                return []
                
            # 2. Correlate events based on sliding time-window and matching endpoints
            groups: List[List[Event]] = []
            for ev in flagged_events:
                added = False
                for g in groups:
                    # Check if ev fits into this group (close in time to group member and matches endpoint/src_ip)
                    matched_member = False
                    for member in g:
                        time_diff = abs(ev.timestamp - member.timestamp)
                        if time_diff <= self.time_window:
                            # Match IP or host or process name similarity
                            if ev.src_ip == member.src_ip or ev.host == member.host or \
                               (ev.process_name and ev.process_name == member.process_name):
                                matched_member = True
                                break
                    if matched_member:
                        g.append(ev)
                        added = True
                        break
                if not added:
                    groups.append([ev])
                    
            # 3. Create or update Incident records for each group
            for g in groups:
                # We only create incidents for groups containing high-severity threat matches,
                # or groups containing multiple medium matches.
                has_high = any(e.severity in ("HIGH", "CRITICAL") for e in g)
                if not (has_high or len(g) >= 2):
                    continue
                    
                event_ids = ",".join(str(e.id) for e in sorted(g, key=lambda x: x.timestamp))
                
                # Check if this group is already associated with an existing Incident
                # (shares at least one event ID)
                existing = None
                for member in g:
                    match = db_session.query(Incident).filter(
                        Incident.associated_events.like(f"%{member.id}%")
                    ).first()
                    if match:
                        existing = match
                        break
                        
                if existing:
                    # Update existing incident
                    current_ids = set(int(x) for x in existing.associated_events.split(",") if x)
                    new_ids = set(e.id for e in g)
                    merged_ids = sorted(list(current_ids.union(new_ids)))
                    existing.associated_events = ",".join(str(i) for i in merged_ids)
                    existing.updated_at = datetime.datetime.utcnow()
                    
                    # Update severity if needed
                    g_sev = "CRITICAL" if any(e.severity == "CRITICAL" for e in g) else \
                            "HIGH" if any(e.severity == "HIGH" for e in g) else "MEDIUM"
                    if existing.severity != "CRITICAL":
                        existing.severity = g_sev
                        
                    # Add correlation log note
                    notes = existing.get_notes()
                    already_noted = any("new events correlated" in n["text"].lower() for n in notes)
                    if not already_noted:
                        notes.append({
                            "time": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
                            "author": "Correlation Engine",
                            "text": f"Correlated {len(new_ids - current_ids)} new events into this incident."
                        })
                        existing.set_notes(notes)
                        
                    db_session.commit()
                else:
                    # Create new Incident
                    g_sev = "CRITICAL" if any(e.severity == "CRITICAL" for e in g) else \
                            "HIGH" if any(e.severity == "HIGH" for e in g) else "MEDIUM"
                            
                    t_types = list(set(e.matched_rule for e in g if e.matched_rule != "NONE"))
                    title_rule = t_types[0] if t_types else "Suspicious Event Pattern"
                    
                    summary = f"Multi-layered EDR threat pattern matching {title_rule}. Flagged elements: " + \
                              ", ".join(e.title for e in g)
                              
                    new_case = Incident(
                        case_name=f"Incident Case SOC-{datetime.datetime.utcnow().strftime('%Y%m%d')}-{g[0].id:03d}: {title_rule} Campaign",
                        status="Open",
                        analyst_name="Unassigned",
                        created_at=datetime.datetime.utcnow(),
                        updated_at=datetime.datetime.utcnow(),
                        description=summary,
                        associated_events=event_ids,
                        severity=g_sev,
                        notes=json.dumps([
                            {
                                "time": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
                                "author": "Correlation Engine",
                                "text": f"Incident auto-created. Grouped {len(g)} related threat events."
                            }
                        ])
                    )
                    db_session.add(new_case)
                    db_session.commit()
                    new_incidents.append(new_case)
                    
            print(f"[CORRELATION] Completed EDR grouping. Active incidents: {len(new_incidents)} new.")
            return new_incidents
            
        except Exception as e:
            db_session.rollback()
            print(f"[CORRELATION ERROR] Correlation failed: {e}")
            return []
        finally:
            if session is None:
                db_session.close()

# Singleton instance
_correlation_engine = None

def get_correlation_engine() -> CorrelationEngine:
    global _correlation_engine
    if _correlation_engine is None:
        _correlation_engine = CorrelationEngine()
    return _correlation_engine

if __name__ == "__main__":
    from core.db import init_db
    init_db()
    core = get_correlation_engine()
    res = core.run_correlation()
    print("Active Correlated Cases:", len(res))
