from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Dict, Any, List, Optional
import datetime
from database import get_db
from config import settings

router = APIRouter(prefix="/api/v1", tags=["WAF"])

class WafEventCreate(BaseModel):
    request_id: str
    trace_id: Optional[str] = None
    action: str = Field(default="BLOCK", description="BLOCK or DETECT")
    severity_label: str = Field(default="CRITICAL", description="CRITICAL, HIGH, MEDIUM, LOW")
    rule_id: int
    rule_tag: Optional[str] = None
    rule_message: str
    severity: int = 0
    engine: str = "coraza-v3"
    http_method: Optional[str] = None
    uri: Optional[str] = None
    client_ip: Optional[str] = None
    anomaly_score: int = 0
    matched_data: Optional[str] = None
    raw_details: Dict[str, Any] = {}

class WafEventResponse(BaseModel):
    id: str
    request_id: str
    trace_id: Optional[str]
    action: str
    severity_label: str
    rule_id: int
    rule_tag: Optional[str]
    rule_message: str
    engine: str
    http_method: Optional[str]
    uri: Optional[str]
    client_ip: Optional[str]
    anomaly_score: int
    created_at: str

@router.get("/waf/status")
def get_waf_status(db: Session = Depends(get_db)):
    """Retrieve operational status, engine version, and active rulesets of the WAF layer."""
    events_count = 0
    try:
        res = db.execute(text("SELECT COUNT(*) FROM waf_events")).scalar()
        events_count = int(res) if res is not None else 0
    except Exception:
        pass

    return {
        "status": "operational",
        "engine": settings.WAF_ENGINE,
        "crs_version": settings.CRS_VERSION,
        "mode": settings.WAF_MODE,
        "rulesets": [
            "REQUEST-901-INITIALIZATION",
            "REQUEST-911-METHOD-ENFORCEMENT",
            "REQUEST-913-SCANNER-DETECTION",
            "REQUEST-920-PROTOCOL-ENFORCEMENT",
            "REQUEST-930-APPLICATION-ATTACK-LFI",
            "REQUEST-931-APPLICATION-ATTACK-RFI",
            "REQUEST-932-APPLICATION-ATTACK-RCE",
            "REQUEST-933-APPLICATION-ATTACK-PHP",
            "REQUEST-941-APPLICATION-ATTACK-XSS",
            "REQUEST-942-APPLICATION-ATTACK-SQLI",
            "REQUEST-949-BLOCKING-EVALUATION"
        ],
        "events_count": events_count,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

@router.post("/internal/waf/events", status_code=status.HTTP_201_CREATED)
def record_waf_event(event: WafEventCreate, db: Session = Depends(get_db)):
    """Internal ingestion endpoint for Coraza WAF security events."""
    try:
        insert_query = text("""
            INSERT INTO waf_events (
                request_id, trace_id, action, severity_label, rule_id, rule_tag,
                rule_message, severity, engine, http_method, uri, client_ip,
                anomaly_score, matched_data, raw_details, created_at
            ) VALUES (
                :request_id, :trace_id, :action, :severity_label, :rule_id, :rule_tag,
                :rule_message, :severity, :engine, :http_method, :uri, :client_ip,
                :anomaly_score, :matched_data, CAST(:raw_details AS jsonb), CURRENT_TIMESTAMP
            ) RETURNING id, created_at
        """)
        
        import json
        result = db.execute(insert_query, {
            "request_id": event.request_id,
            "trace_id": event.trace_id,
            "action": event.action,
            "severity_label": event.severity_label,
            "rule_id": event.rule_id,
            "rule_tag": event.rule_tag,
            "rule_message": event.rule_message,
            "severity": event.severity,
            "engine": event.engine,
            "http_method": event.http_method,
            "uri": event.uri,
            "client_ip": event.client_ip,
            "anomaly_score": event.anomaly_score,
            "matched_data": event.matched_data,
            "raw_details": json.dumps(event.raw_details)
        })
        db.commit()
        row = result.fetchone()
        event_id = str(row[0]) if row else "unknown"
        created_at = row[1].isoformat() if row and row[1] else datetime.datetime.now(datetime.timezone.utc).isoformat()

        return {
            "status": "persisted",
            "id": event_id,
            "request_id": event.request_id,
            "action": event.action,
            "rule_id": event.rule_id,
            "created_at": created_at
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to persist WAF event: {str(e)}")

@router.get("/waf/events", response_model=List[Dict[str, Any]])
def list_waf_events(
    limit: int = Query(default=50, ge=1, le=500),
    action: Optional[str] = None,
    severity: Optional[str] = None,
    rule_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """Retrieve normalized WAF detection events for the SOC Dashboard."""
    query_str = """
        SELECT id, request_id, trace_id, action, severity_label, rule_id,
               rule_tag, rule_message, engine, http_method, uri, client_ip,
               anomaly_score, created_at
        FROM waf_events
        WHERE 1=1
    """
    params: Dict[str, Any] = {"limit": limit}

    if action:
        query_str += " AND action = :action"
        params["action"] = action
    if severity:
        query_str += " AND severity_label = :severity"
        params["severity"] = severity
    if rule_id:
        query_str += " AND rule_id = :rule_id"
        params["rule_id"] = rule_id

    query_str += " ORDER BY created_at DESC LIMIT :limit"

    try:
        rows = db.execute(text(query_str), params).fetchall()
        events = []
        for r in rows:
            events.append({
                "id": str(r[0]),
                "request_id": r[1],
                "trace_id": r[2],
                "action": r[3],
                "severity_label": r[4],
                "rule_id": r[5],
                "rule_tag": r[6],
                "rule_message": r[7],
                "engine": r[8],
                "http_method": r[9],
                "uri": r[10],
                "client_ip": r[11],
                "anomaly_score": r[12],
                "created_at": r[13].isoformat() if r[13] else None
            })
        return events
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database query error: {str(e)}")

@router.get("/waf/events/{request_id}")
def get_waf_event_by_request_id(request_id: str, db: Session = Depends(get_db)):
    """Retrieve WAF detection event(s) associated with a specific request_id."""
    query_str = """
        SELECT id, request_id, trace_id, action, severity_label, rule_id,
               rule_tag, rule_message, engine, http_method, uri, client_ip,
               anomaly_score, created_at, raw_details
        FROM waf_events
        WHERE request_id = :request_id
        ORDER BY created_at DESC
    """
    try:
        rows = db.execute(text(query_str), {"request_id": request_id}).fetchall()
        if not rows:
            raise HTTPException(status_code=404, detail=f"No WAF events found for request_id {request_id}")
        
        events = []
        for r in rows:
            events.append({
                "id": str(r[0]),
                "request_id": r[1],
                "trace_id": r[2],
                "action": r[3],
                "severity_label": r[4],
                "rule_id": r[5],
                "rule_tag": r[6],
                "rule_message": r[7],
                "engine": r[8],
                "http_method": r[9],
                "uri": r[10],
                "client_ip": r[11],
                "anomaly_score": r[12],
                "created_at": r[13].isoformat() if r[13] else None,
                "raw_details": r[14]
            })
        return {"request_id": request_id, "count": len(events), "events": events}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database query error: {str(e)}")
