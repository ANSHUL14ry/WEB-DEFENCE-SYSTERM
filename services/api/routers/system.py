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
    policy_decisions_count = 0
    deception_sessions_count = 0
    verifications_count = 0
    verified_mitigations_count = 0
    source_profiles_count = 0
    mitre_mappings_count = 0
    network_observations_count = 0
    network_events_count = 0
    network_enforcements_count = 0
    network_anomalies_count = 0
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

            res_policy = db.execute(text("SELECT COUNT(*) FROM policy_decisions")).scalar()
            policy_decisions_count = int(res_policy) if res_policy is not None else 0

            res_deception = db.execute(text("SELECT COUNT(*) FROM deception_sessions")).scalar()
            deception_sessions_count = int(res_deception) if res_deception is not None else 0

            res_ver = db.execute(text("SELECT COUNT(*) FROM verification_results")).scalar()
            verifications_count = int(res_ver) if res_ver is not None else 0

            res_ver_ok = db.execute(text("SELECT COUNT(*) FROM verification_results WHERE result = 'VERIFIED'")).scalar()
            verified_mitigations_count = int(res_ver_ok) if res_ver_ok is not None else 0

            res_sp = db.execute(text("SELECT COUNT(*) FROM source_profiles")).scalar()
            source_profiles_count = int(res_sp) if res_sp is not None else 0

            res_mm = db.execute(text("SELECT COUNT(*) FROM mitre_mappings")).scalar()
            mitre_mappings_count = int(res_mm) if res_mm is not None else 0

            res_no = db.execute(text("SELECT COUNT(*) FROM network_observations")).scalar()
            network_observations_count = int(res_no) if res_no is not None else 0

            res_ne = db.execute(text("SELECT COUNT(*) FROM network_events")).scalar()
            network_events_count = int(res_ne) if res_ne is not None else 0

            res_nenf = db.execute(text("SELECT COUNT(*) FROM network_enforcements WHERE status = 'ACTIVE'")).scalar()
            network_enforcements_count = int(res_nenf) if res_nenf is not None else 0

            res_nanom = db.execute(text("SELECT COUNT(*) FROM network_anomalies WHERE severity IN ('ANOMALOUS', 'CRITICAL')")).scalar()
            network_anomalies_count = int(res_nanom) if res_nanom is not None else 0
            
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
            "policy_engine": {
                "status": "operational",
                "type": "Deterministic Rule Evaluator",
                "role": "Precedence-Based Security Decisions & Deception Qualification",
                "version": "Phase 7 Active"
            },
            "deception_engine": {
                "status": "operational",
                "type": "Isolated Decoy Environment",
                "role": "Adaptive Deception & Honeypot Routing",
                "version": "Phase 8 Active"
            },
            "verification_engine": {
                "status": "operational",
                "type": "Response Verification & Telemetry Proof Engine",
                "role": "Deterministic Mitigation Verification & Origin Protection Proof",
                "version": "Phase 9 Active"
            },
            "network_defense": {
                "status": "operational",
                "type": "Suricata IDS/IPS & Network Behavior Correlator",
                "role": "Real-time EVE Network Threat Feed, IPS Enforcement & DDoS Anomaly Radar",
                "version": "Phase 11 Active"
            },
            "threat_intel": {
                "status": "operational",
                "type": "Attacker Intelligence & Threat Context Engine",
                "role": "GeoIP, ASN, Reputation, Client Fingerprinting & MITRE Mapping",
                "version": "Phase 10 Active"
            },
            "honeypot": {"status": "operational", "type": "Isolated Decoy Environment", "role": "Phase 8 Active"}
        },
        "metrics": {
            "system_events_count": events_count,
            "waf_events_count": waf_events_count,
            "security_events_count": security_events_count,
            "risk_assessments_count": risk_assessments_count,
            "agent_shield_assessments_count": agent_shield_assessments_count,
            "policy_decisions_count": policy_decisions_count,
            "deception_sessions_count": deception_sessions_count,
            "verifications_count": verifications_count,
            "verified_mitigations_count": verified_mitigations_count,
            "source_profiles_count": source_profiles_count,
            "mitre_mappings_count": mitre_mappings_count,
            "network_observations_count": network_observations_count,
            "network_events_count": network_events_count,
            "network_enforcements_count": network_enforcements_count,
            "network_anomalies_count": network_anomalies_count,
            "recent_events": recent_events
        }
    }
