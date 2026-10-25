"""
AEGIS Ω — AgentShield API Router
Provides behavioral analysis endpoints, assessment queries, timeline drilldowns,
and aggregated automation statistics.
"""

from typing import Dict, Any, List, Optional
import json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from database import get_db
from agent_shield.service import assess_event_behavior
from agent_shield.analyzer import analyze_behavior
from agent_shield.config import agent_shield_settings
from broadcaster import broadcaster

router = APIRouter(prefix="/api/v1", tags=["AgentShield"])


def row_to_agent_shield_dict(row: Any) -> Dict[str, Any]:
    """Convert database row to structured AgentShield Assessment dict."""
    signals_data = row.signals if isinstance(row.signals, list) else (json.loads(row.signals) if row.signals else [])
    stages_data = row.attack_stages if isinstance(row.attack_stages, list) else (json.loads(row.attack_stages) if row.attack_stages else [])
    return {
        "assessment_id": row.assessment_id,
        "request_id": row.request_id,
        "trace_id": row.trace_id,
        "session_id": row.session_id,
        "agent_shield_score": row.agent_shield_score,
        "severity": row.severity,
        "confidence": float(row.confidence) if row.confidence is not None else 1.0,
        "signals": signals_data,
        "attack_stages": stages_data,
        "behavior_summary": row.behavior_summary,
        "engine_version": row.engine_version,
        "disclaimer": agent_shield_settings.TECHNICAL_DISCLAIMER,
        "created_at": row.created_at.isoformat() if hasattr(row.created_at, "isoformat") else str(row.created_at)
    }


@router.post("/internal/agent-shield/analyze")
async def analyze_behavior_on_demand(payload: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Internal on-demand AgentShield behavioral analysis API.
    Evaluates event payload, persists assessment, and broadcasts update to dashboard clients.
    """
    if "request_id" not in payload or "trace_id" not in payload:
        raise HTTPException(status_code=422, detail="Missing required request_id or trace_id")

    assessment = assess_event_behavior(payload, db)
    if not assessment:
        raise HTTPException(status_code=500, detail="Failed to assess behavioral automation")

    # Broadcast live over WebSocket
    as_broadcast = {
        "event_type": "AGENTSHIELD_SIGNAL",
        "assessment_id": assessment["assessment_id"],
        "request_id": assessment["request_id"],
        "trace_id": assessment["trace_id"],
        "agent_shield_score": assessment["agent_shield_score"],
        "severity": assessment["severity"],
        "confidence": assessment["confidence"],
        "signals": assessment["signals"],
        "attack_stages": assessment["attack_stages"],
        "attack_timeline": assessment["attack_timeline"],
        "behavior_summary": assessment["behavior_summary"],
        "engine_version": assessment["engine_version"],
        "disclaimer": assessment["disclaimer"],
        "timestamp": assessment.get("timestamp")
    }
    await broadcaster.broadcast(as_broadcast)

    return assessment


@router.get("/agent-shield/stats")
@router.get("/agentshield/stats", include_in_schema=False)
def get_agent_shield_stats(db: Session = Depends(get_db)):
    """
    Aggregated live AgentShield statistics directly from PostgreSQL.
    No hard-coded or fabricated metrics. Returns real zeros when empty.
    """
    query = text("""
        SELECT 
            COUNT(*) as total_assessments,
            COALESCE(AVG(agent_shield_score), 0) as average_agent_shield_score,
            COUNT(*) FILTER (WHERE severity = 'CRITICAL') as critical_count,
            COUNT(*) FILTER (WHERE severity = 'HIGH') as high_count,
            COUNT(*) FILTER (WHERE severity = 'MEDIUM') as medium_count,
            COUNT(*) FILTER (WHERE severity = 'LOW') as low_count
        FROM agent_shield_assessments;
    """)

    row = db.execute(query).fetchone()

    # Fetch latest 5 assessments for timeline
    latest_query = text("""
        SELECT assessment_id, request_id, trace_id, session_id,
               agent_shield_score, severity, confidence, signals,
               attack_stages, behavior_summary, engine_version, created_at
        FROM agent_shield_assessments
        ORDER BY created_at DESC
        LIMIT 5;
    """)
    latest_rows = db.execute(latest_query).fetchall()

    return {
        "total_assessments": row.total_assessments if row else 0,
        "average_agent_shield_score": round(float(row.average_agent_shield_score), 1) if row else 0.0,
        "critical_count": row.critical_count if row else 0,
        "high_count": row.high_count if row else 0,
        "medium_count": row.medium_count if row else 0,
        "low_count": row.low_count if row else 0,
        "recent_assessments": [row_to_agent_shield_dict(r) for r in latest_rows],
        "disclaimer": agent_shield_settings.TECHNICAL_DISCLAIMER
    }


@router.get("/agent-shield/request/{request_id}")
def get_assessments_by_request_id(request_id: str, db: Session = Depends(get_db)):
    """Fetch all AgentShield assessments associated with a specific request_id."""
    query = text("""
        SELECT assessment_id, request_id, trace_id, session_id,
               agent_shield_score, severity, confidence, signals,
               attack_stages, behavior_summary, engine_version, created_at
        FROM agent_shield_assessments
        WHERE request_id = :req_id
        ORDER BY created_at DESC;
    """)
    rows = db.execute(query, {"req_id": request_id}).fetchall()
    return [row_to_agent_shield_dict(r) for r in rows]


@router.get("/agent-shield/trace/{trace_id}")
def get_assessments_by_trace_id(trace_id: str, db: Session = Depends(get_db)):
    """Fetch all AgentShield assessments associated with a correlation trace_id."""
    query = text("""
        SELECT assessment_id, request_id, trace_id, session_id,
               agent_shield_score, severity, confidence, signals,
               attack_stages, behavior_summary, engine_version, created_at
        FROM agent_shield_assessments
        WHERE trace_id = :trace_id
        ORDER BY created_at DESC;
    """)
    rows = db.execute(query, {"trace_id": trace_id}).fetchall()
    return [row_to_agent_shield_dict(r) for r in rows]


@router.get("/agent-shield/{assessment_id}")
def get_assessment_by_id(assessment_id: str, db: Session = Depends(get_db)):
    """Fetch an individual AgentShield assessment record by its unique assessment_id."""
    query = text("""
        SELECT assessment_id, request_id, trace_id, session_id,
               agent_shield_score, severity, confidence, signals,
               attack_stages, behavior_summary, engine_version, created_at
        FROM agent_shield_assessments
        WHERE assessment_id = :aid
        LIMIT 1;
    """)
    row = db.execute(query, {"aid": assessment_id}).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="AgentShield assessment not found")
    return row_to_agent_shield_dict(row)


@router.get("/agent-shield")
def list_agent_shield_assessments(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Paginated list of AgentShield assessments with optional severity filter."""
    if severity:
        query = text("""
            SELECT assessment_id, request_id, trace_id, session_id,
                   agent_shield_score, severity, confidence, signals,
                   attack_stages, behavior_summary, engine_version, created_at
            FROM agent_shield_assessments
            WHERE severity = :sev
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset;
        """)
        rows = db.execute(query, {"sev": severity.upper(), "limit": limit, "offset": offset}).fetchall()
    else:
        query = text("""
            SELECT assessment_id, request_id, trace_id, session_id,
                   agent_shield_score, severity, confidence, signals,
                   attack_stages, behavior_summary, engine_version, created_at
            FROM agent_shield_assessments
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset;
        """)
        rows = db.execute(query, {"limit": limit, "offset": offset}).fetchall()

    return {
        "limit": limit,
        "offset": offset,
        "count": len(rows),
        "assessments": [row_to_agent_shield_dict(r) for r in rows],
        "disclaimer": agent_shield_settings.TECHNICAL_DISCLAIMER
    }
