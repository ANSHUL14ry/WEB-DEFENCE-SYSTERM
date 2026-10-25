from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Dict, Any
from database import get_db, check_db_connection
from config import settings
import datetime

router = APIRouter(prefix="/api/v1/system", tags=["System"])

@router.get("/status")
def get_system_status(request: Request, db: Session = Depends(get_db)) -> Dict[str, Any]:
    db_ok = check_db_connection()
    events_count = 0
    waf_events_count = 0
    security_events_count = 0
    risk_assessments_count = 0
    agent_shield_assessments_count = 0
    recent_events = []
    
    if db_ok:
        try:
            res = db.execute(text("SELECT COUNT(*) FROM system_events")).scalar()
            events_count = int(res) if res is not None else 0

            res_waf = db.execute(text("SELECT COUNT(*) FROM waf_events")).scalar()
            waf_events_count = int(res_waf) if res_waf is not None else 0

            res_sec = db.execute(text("SELECT COUNT(*) FROM security_events")).scalar()
            security_events_count = int(res_sec) if res_sec is not None else 0

            res_risk = db.execute(text("SELECT COUNT(*) FROM risk_assessments")).scalar()
            risk_assessments_count = int(res_risk) if res_risk is not None else 0

            res_as = db.execute(text("SELECT COUNT(*) FROM agent_shield_assessments")).scalar()
            agent_shield_assessments_count = int(res_as) if res_as is not None else 0
            
            rows = db.execute(text(
                "SELECT service_name, event_type, severity, details, created_at "
                "FROM system_events ORDER BY created_at DESC LIMIT 5"
            )).fetchall()
            
            for row in rows:
                recent_events.append({
                    "service_name": row[0],
                    "event_type": row[1],
                    "severity": row[2],
                    "details": row[3],
                    "created_at": row[4].isoformat() if row[4] else None
                })
        except Exception:
            pass

    return {
        "status": "operational",
        "platform": "AEGIS Ω",
        "tagline": "Detect. Predict. Deceive. Contain.",
        "version": settings.AEGIS_VERSION,
        "request_id": request.headers.get("x-request-id", "none"),
        "trace_id": request.headers.get("x-trace-id", "none"),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "services": {
            "gateway": {
                "status": "operational",
                "type": "Nginx Ingress Gateway",
                "role": "Hardened Reverse Proxy, Tracing, Security Headers & Structured Logs",
                "version": "Phase 2 Active"
            },
            "database": {"status": "connected" if db_ok else "degraded", "type": "PostgreSQL", "role": "State & Telemetry Store"},
            "api": {"status": "healthy", "type": "FastAPI Core", "role": "Control Plane & REST API"},
            "origin": {"status": "reachable", "type": "Protected Application", "role": "Upstream Workload"},
            "waf": {
                "status": "operational",
                "type": f"{settings.WAF_ENGINE} + {settings.CRS_VERSION}",
                "role": "Real Application Firewall, CRS Inspection & Threat Blocking",
                "mode": settings.WAF_MODE,
                "version": "Phase 3 Active"
            },
            "pipeline": {
                "status": "operational",
                "type": "Security Event Engine & WebSocket Broadcaster",
                "role": "Event Ingestion, Deduplication, Correlation & Live Streaming",
                "version": "Phase 4 Active"
            },
            "risk_engine": {
                "status": "operational",
                "type": "Deterministic Scorer (0-100)",
                "role": "Explainable Threat Scoring & Temporal Signal Weighting",
                "version": "Phase 5 Active"
            },
            "agent_shield": {
                "status": "operational",
                "type": "Behavioral Automation & Sequence Analyzer",
                "role": "Deterministic Automation Indicators & Attack Progression Detection",
                "version": "Phase 6 Active"
            },
            "honeypot": {"status": "scheduled", "type": "Isolated Decoy Environment", "role": "Phase 8 Milestone"}
        },
        "metrics": {
            "system_events_count": events_count,
            "waf_events_count": waf_events_count,
            "security_events_count": security_events_count,
            "risk_assessments_count": risk_assessments_count,
            "agent_shield_assessments_count": agent_shield_assessments_count,
            "recent_events": recent_events
        }
    }
