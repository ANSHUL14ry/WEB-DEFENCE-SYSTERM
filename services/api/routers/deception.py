"""
AEGIS Ω — Deception Subsystem API Router
Exposes deception execution, decoy proxying, session auditing, and real-time telemetry streaming.
"""

from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from database import get_db
from deception.models import (
    DeceptionExecutionRequest,
    DeceptionInteractionRequest,
    DeceptionStats
)
from deception.service import (
    execute_deception_routing,
    interact_with_decoy
)
from deception.repository import (
    get_session_by_id,
    get_session_events,
    list_deception_sessions,
    list_deception_events,
    get_deception_stats,
    update_session_status
)
from broadcaster import broadcaster

router = APIRouter(prefix="/api/v1", tags=["Deception Engine"])


@router.post("/internal/deception/execute")
async def execute_deception(
    req: DeceptionExecutionRequest,
    db: Session = Depends(get_db)
):
    """
    Internal execution endpoint for policy-qualified deception routing.
    Only allows traffic if decision == DECEIVE_ELIGIBLE and NOT waf_blocked.
    """
    result = execute_deception_routing(req, db)

    # Invariant: If denied or blocked, return appropriate status
    if result.get("status") == "DENIED":
        if "WAF_BLOCKED_TERMINAL" in result.get("reason", ""):
            # WAF terminal invariant enforcement
            return result
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=result.get("reason", "Deception denied.")
        )

    # Broadcast event live to SOC Dashboard
    await broadcaster.broadcast({
        "event_type": "DECEPTION_EVENT",
        "sub_type": "SESSION_INITIALIZED",
        "session_id": result.get("session_id"),
        "request_id": req.request_id,
        "trace_id": req.trace_id,
        "initial_risk_score": req.initial_risk_score,
        "initial_agent_shield_score": req.initial_agent_shield_score,
        "status": result.get("status"),
        "origin_reached": False,
        "timestamp": result.get("session", {}).get("created_at")
    })

    return result


@router.post("/internal/deception/interact")
async def interact_decoy(
    req: DeceptionInteractionRequest,
    db: Session = Depends(get_db)
):
    """
    Handles subsequent interaction requests into the decoy under an active session.
    """
    result = interact_with_decoy(req, db)
    if "error" in result:
        err_code = result.get("error")
        if err_code == "SESSION_NOT_FOUND":
            raise HTTPException(status_code=404, detail="Deception session not found.")
        elif err_code == "SESSION_EXPIRED":
            raise HTTPException(status_code=410, detail="Deception session has expired.")
        elif err_code == "SESSION_LIMIT_EXCEEDED":
            raise HTTPException(status_code=429, detail="Maximum session requests exceeded.")
        else:
            raise HTTPException(status_code=502, detail=result.get("message", "Decoy interaction error."))

    # Broadcast event live to SOC Dashboard
    ev = result.get("event", {})
    await broadcaster.broadcast({
        "event_type": "DECEPTION_EVENT",
        "sub_type": ev.get("event_type", "INTERACTION"),
        "session_id": req.session_id,
        "route": req.route,
        "method": req.method,
        "origin_reached": False,
        "timestamp": ev.get("created_at")
    })

    return result


@router.post("/internal/deception/terminate/{session_id}")
async def terminate_session(
    session_id: str,
    db: Session = Depends(get_db)
):
    """Manually terminates an active deception session."""
    session = get_session_by_id(db, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found.")

    update_session_status(db, session_id, "TERMINATED")

    await broadcaster.broadcast({
        "event_type": "DECEPTION_EVENT",
        "sub_type": "DECEPTION_SESSION_ENDED",
        "session_id": session_id,
        "status": "TERMINATED"
    })

    return {"status": "SUCCESS", "session_id": session_id, "new_status": "TERMINATED"}


@router.get("/deception/stats")
def get_stats(db: Session = Depends(get_db)):
    """Retrieves real aggregated deception stats for the SOC Dashboard."""
    return get_deception_stats(db)


@router.get("/deception/sessions")
def get_sessions(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Retrieves paginated deception sessions."""
    return list_deception_sessions(db, limit=limit, offset=offset, status=status)


@router.get("/deception/session/{session_id}")
def get_session(session_id: str, db: Session = Depends(get_db)):
    """Retrieves an individual deception session."""
    session = get_session_by_id(db, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Deception session not found.")
    return session


@router.get("/deception/session/{session_id}/events")
def get_events_for_session(session_id: str, db: Session = Depends(get_db)):
    """Retrieves the chronological evidence timeline for a specific deception session."""
    session = get_session_by_id(db, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Deception session not found.")
    return get_session_events(db, session_id)


@router.get("/deception/events")
def get_all_events(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Retrieves paginated deception evidence events across all sessions."""
    return list_deception_events(db, limit=limit, offset=offset, event_type=event_type)
