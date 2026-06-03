"""
core/risk_scoring.py — EDR Risk Scoring Engine
================================================
Calculates system exposure score (0-100), severity levels,
and threat stats based on active database events and alerts.
"""

from typing import Dict, Any, List
from sqlalchemy.orm import Session
from core.db import Event, Alert, Incident, get_session

def calculate_risk_score(session: Session = None) -> Dict[str, Any]:
    """
    Calculate dynamic SOC risk score (0-100) based on active alerts.
    
    Formula:
      - Critical alerts (CRITICAL severity or threat_score >= 90): weight 25
      - High alerts (HIGH severity or threat_score >= 70): weight 15
      - Medium alerts (MEDIUM severity): weight 5
      - Low alerts (LOW severity): weight 1
      - Capped at 100. If no sessions, defaults to 0.
    """
    db_session = session or get_session()
    try:
        events = db_session.query(Event).all()
        alerts = db_session.query(Alert).filter(Alert.status == "Active").all()
        incidents = db_session.query(Incident).filter(Incident.status != "Resolved").all()
        
        tot_events = len(events)
        tot_alerts = len(alerts)
        tot_incidents = len(incidents)
        
        # Count severities
        cri = sum(1 for a in alerts if a.severity == "CRITICAL" or a.severity == "HIGH" and (a.event and a.event.threat_score >= 90))
        high = sum(1 for a in alerts if a.severity == "HIGH" and not (a.event and a.event.threat_score >= 90))
        med = sum(1 for a in alerts if a.severity == "MEDIUM")
        low = sum(1 for a in alerts if a.severity == "LOW")
        
        # Calculate exposure weight
        raw_score = (cri * 25) + (high * 15) + (med * 5) + (low * 1)
        risk_index = min(max(raw_score, 0), 100)
        
        # Categorize
        if risk_index >= 75:
            level = "CRITICAL"
            color = "#FF2D55" # Red
        elif risk_index >= 50:
            level = "HIGH"
            color = "#FF9500" # Orange
        elif risk_index >= 25:
            level = "MEDIUM"
            color = "#FFD60A" # Yellow
        else:
            level = "LOW"
            color = "#30D158" # Green
            
        return {
            "risk_score": risk_index,
            "risk_level": level,
            "risk_color": color,
            "total_events": tot_events,
            "active_alerts": tot_alerts,
            "active_incidents": tot_incidents,
            "critical_count": cri,
            "high_count": high,
            "medium_count": med,
            "low_count": low
        }
    except Exception as e:
        print(f"[RISK SCORING ERROR] Fail: {e}")
        return {
            "risk_score": 0, "risk_level": "LOW", "risk_color": "#30D158",
            "total_events": 0, "active_alerts": 0, "active_incidents": 0,
            "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0
        }
    finally:
        if session is None:
            db_session.close()

if __name__ == "__main__":
    from core.db import init_db
    init_db()
    stats = calculate_risk_score()
    print("Risk Exposure Analytics:", stats)
