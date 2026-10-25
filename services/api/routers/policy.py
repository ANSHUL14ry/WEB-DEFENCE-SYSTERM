"""
AEGIS Ω — Policy Engine API Router
Provides policy evaluation endpoints, decision history queries, and aggregated statistics.
"""

from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db
from policy_engine.config import policy_settings
from policy_engine.models import PolicyContext, PolicyDecision
from policy_engine.evaluator import evaluate_policy
from policy_engine.service import evaluate_and_record_policy
from policy_engine.repository import (
    get_policy_decision_by_id,
    get_policy_decisions_by_request_id,
    get_policy_decisions_by_trace_id,
    get_policy_stats,
    list_policy_decisions
)
from broadcaster import broadcaster

router = APIRouter(prefix="/api/v1", tags=["Policy Engine"])


@router.post("/internal/policy/evaluate")
async def evaluate_policy_on_demand(payload: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Internal on-demand policy evaluation endpoint.
    Evaluates trusted context against deterministic rules, persists decision,
    and broadcasts POLICY_DECISION to dashboard clients.
    """
    if "request_id" not in payload or "trace_id" not in payload:
        raise HTTPException(status_code=422, detail="Missing required request_id or trace_id")

    decision = evaluate_and_record_policy(payload, db)
    if not decision:
        raise HTTPException(status_code=500, detail="Failed to evaluate security policy")

    # Broadcast live over WebSocket
    policy_broadcast = {
        "event_type": "POLICY_DECISION",
        "decision_id": decision["decision_id"],
        "request_id": decision["request_id"],
        "trace_id": decision["trace_id"],
        "decision": decision["decision"],
        "decision_reason": decision["decision_reason"],
        "reasons": decision["reasons"],
        "matched_rules": decision["matched_rules"],
        "risk_score": decision.get("risk_score"),
        "risk_severity": decision.get("risk_severity"),
        "agent_shield_score": decision.get("agent_shield_score"),
        "agent_shield_severity": decision.get("agent_shield_severity"),
        "terminal": decision["terminal"],
        "policy_version": decision["policy_version"],
        "timestamp": decision.get("created_at")
    }
    await broadcaster.broadcast(policy_broadcast)

    return decision


@router.get("/policy/stats")
def get_stats(db: Session = Depends(get_db)):
    """
    Returns aggregated live policy decision statistics from PostgreSQL.
    No hard-coded numbers; returns real counts.
    """
    return get_policy_stats(db)


@router.get("/policy/request/{request_id}")
def get_decisions_by_request(request_id: str, db: Session = Depends(get_db)):
    """Retrieves all policy decisions for a given request_id."""
    return get_policy_decisions_by_request_id(db, request_id)


@router.get("/policy/trace/{trace_id}")
def get_decisions_by_trace(trace_id: str, db: Session = Depends(get_db)):
    """Retrieves all policy decisions across a correlation trace_id."""
    return get_policy_decisions_by_trace_id(db, trace_id)


@router.get("/policy/{decision_id}")
def get_decision(decision_id: str, db: Session = Depends(get_db)):
    """Retrieves an individual policy decision record by decision_id."""
    decision = get_policy_decision_by_id(db, decision_id)
    if not decision:
        raise HTTPException(status_code=404, detail="Policy decision not found")
    return decision


@router.get("/policy")
def list_decisions(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    decision: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Paginated list of policy decisions with optional decision filter."""
    return list_policy_decisions(db, limit=limit, offset=offset, decision_filter=decision)
