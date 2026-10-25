"""
AEGIS Ω — Risk Engine API Router
Provides internal risk evaluation endpoints, risk assessment query, and aggregated statistics.
"""

from typing import Dict, Any, List, Optional
import json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from database import get_db
from risk_engine.service import assess_event_risk
from risk_engine.evaluator import evaluate_risk
from broadcaster import broadcaster

router = APIRouter(prefix="/api/v1", tags=["Risk Engine"])


def row_to_risk_dict(row: Any) -> Dict[str, Any]:
    """Convert database row to structured Risk Assessment dict."""
    signals_data = row.signals if isinstance(row.signals, list) else (json.loads(row.signals) if row.signals else [])
    return {
        "assessment_id": row.assessment_id,
        "request_id": row.request_id,
        "trace_id": row.trace_id,
        "session_id": row.session_id,
        "risk_score": row.risk_score,
        "severity": row.severity,
        "confidence": float(row.confidence) if row.confidence is not None else 1.0,
        "signals": signals_data,
        "engine_version": row.engine_version,
        "created_at": row.created_at.isoformat() if hasattr(row.created_at, "isoformat") else str(row.created_at)
    }


@router.post("/internal/risk/assess")
async def evaluate_risk_on_demand(payload: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Internal on-demand risk assessment API.
    Evaluates event payload, persists assessment, and broadcasts update to dashboard clients.
    """
    if "request_id" not in payload or "trace_id" not in payload:
        raise HTTPException(status_code=422, detail="Missing required request_id or trace_id")

    assessment = assess_event_risk(payload, db)
    if not assessment:
        raise HTTPException(status_code=500, detail="Failed to assess risk")

    # Broadcast live over WebSocket
    risk_broadcast = {
        "event_type": "RISK_SCORE_UPDATE",
        "assessment_id": assessment["assessment_id"],
        "request_id": assessment["request_id"],
        "trace_id": assessment["trace_id"],
        "risk_score": assessment["risk_score"],
        "severity": assessment["severity"],
        "signals": assessment["signals"],
        "engine_version": assessment["engine_version"],
        "timestamp": assessment["created_at"]
    }
    await broadcaster.broadcast(risk_broadcast)

    return assessment


@router.get("/risk/stats")
def get_risk_stats(db: Session = Depends(get_db)):
    """
    Aggregated live risk engine statistics directly from PostgreSQL.
    No hard-coded or fabricated metrics. Returns real zeros when empty.
    """
    query = text("""
        SELECT 
            COUNT(*) as total_assessments,
            COALESCE(AVG(risk_score), 0) as average_risk_score,
            COUNT(*) FILTER (WHERE severity = 'CRITICAL') as critical_count,
            COUNT(*) FILTER (WHERE severity = 'HIGH') as high_count,
            COUNT(*) FILTER (WHERE severity = 'MEDIUM') as medium_count,
            COUNT(*) FILTER (WHERE severity = 'LOW') as low_count
        FROM risk_assessments;
    """)

    row = db.execute(query).fetchone()

    # Fetch latest 5 assessments for timeline
    latest_query = text("""
        SELECT assessment_id, request_id, trace_id, session_id,
               risk_score, severity, confidence, signals,
               engine_version, created_at
        FROM risk_assessments
        ORDER BY created_at DESC
        LIMIT 5;
    """)
    latest_rows = db.execute(latest_query).fetchall()

    return {
        "total_assessments": row.total_assessments if row else 0,
        "average_risk_score": round(float(row.average_risk_score), 1) if row else 0.0,
        "critical_count": row.critical_count if row else 0,
        "high_count": row.high_count if row else 0,
        "medium_count": row.medium_count if row else 0,
        "low_count": row.low_count if row else 0,
        "latest_assessments": [row_to_risk_dict(r) for r in latest_rows]
    }


@router.get("/risk/request/{request_id}")
def get_risk_by_request_id(request_id: str, db: Session = Depends(get_db)):
    """Retrieve risk assessment for a specific request ID."""
    query = text("""
        SELECT assessment_id, request_id, trace_id, session_id,
               risk_score, severity, confidence, signals,
               engine_version, created_at
        FROM risk_assessments
        WHERE request_id = :request_id
        ORDER BY created_at DESC;
    """)
    rows = db.execute(query, {"request_id": request_id}).fetchall()
    return [row_to_risk_dict(r) for r in rows]


@router.get("/risk/trace/{trace_id}")
def get_risk_by_trace_id(trace_id: str, db: Session = Depends(get_db)):
    """Retrieve all risk assessments across a request chain (trace ID)."""
    query = text("""
        SELECT assessment_id, request_id, trace_id, session_id,
               risk_score, severity, confidence, signals,
               engine_version, created_at
        FROM risk_assessments
        WHERE trace_id = :trace_id
        ORDER BY created_at DESC;
    """)
    rows = db.execute(query, {"trace_id": trace_id}).fetchall()
    return [row_to_risk_dict(r) for r in rows]


@router.get("/risk/{assessment_id}")
def get_single_risk_assessment(assessment_id: str, db: Session = Depends(get_db)):
    """Retrieve a single specific risk assessment."""
    query = text("""
        SELECT assessment_id, request_id, trace_id, session_id,
               risk_score, severity, confidence, signals,
               engine_version, created_at
        FROM risk_assessments
        WHERE assessment_id = :assessment_id;
    """)
    row = db.execute(query, {"assessment_id": assessment_id}).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Risk assessment not found")
    return row_to_risk_dict(row)


@router.get("/risk")
def list_risk_assessments(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Paginated list of risk assessments."""
    conditions = []
    params: Dict[str, Any] = {"limit": limit, "offset": offset}

    if severity:
        conditions.append("severity = :severity")
        params["severity"] = severity.upper()

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    count_query = text(f"SELECT COUNT(*) FROM risk_assessments {where_clause}")
    total = db.execute(count_query, params).scalar() or 0

    select_query = text(f"""
        SELECT assessment_id, request_id, trace_id, session_id,
               risk_score, severity, confidence, signals,
               engine_version, created_at
        FROM risk_assessments
        {where_clause}
        ORDER BY created_at DESC
        LIMIT :limit OFFSET :offset;
    """)

    rows = db.execute(select_query, params).fetchall()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "assessments": [row_to_risk_dict(r) for r in rows]
    }
