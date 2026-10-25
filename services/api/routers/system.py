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
    recent_events = []
    
    if db_ok:
        try:
            res = db.execute(text("SELECT COUNT(*) FROM system_events")).scalar()
            events_count = int(res) if res is not None else 0

            res_waf = db.execute(text("SELECT COUNT(*) FROM waf_events")).scalar()
            waf_events_count = int(res_waf) if res_waf is not None else 0
            
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
            "agent_shield": {"status": "scheduled", "type": "Behavioral Engine", "role": "Phase 6 Milestone"},
            "risk_engine": {"status": "scheduled", "type": "Deterministic Scorer", "role": "Phase 5 Milestone"},
            "honeypot": {"status": "scheduled", "type": "Isolated Decoy Environment", "role": "Phase 8 Milestone"}
        },
        "metrics": {
            "system_events_count": events_count,
            "waf_events_count": waf_events_count,
            "recent_events": recent_events
        }
    }
