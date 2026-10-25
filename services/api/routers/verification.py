"""
AEGIS Ω — Response Verification Subsystem API Router
Exposes verification evaluation, receipts querying, telemetry proof retrieval,
and live mitigation WebSocket events.
"""

from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from database import get_db
from verification.models import (
    VerificationEvaluateRequest,
    VerificationResultRecord,
    VerificationStats
)
from verification.service import (
    evaluate_and_record_verification,
    get_verification_by_id,
    get_verification_by_request_id,
    get_verification_by_trace_id,
    list_verification_results,
    get_verification_stats
)
from broadcaster import broadcaster

router = APIRouter(prefix="/api/v1", tags=["Response Verification Engine"])


@router.post("/internal/verification/evaluate")
async def evaluate_verification(
    req: VerificationEvaluateRequest,
    db: Session = Depends(get_db)
):
    """
    Evaluates mitigation verification for a request/trace against deterministic security invariants,
    persists the machine-verifiable proof receipt, and broadcasts live WebSocket telemetry.
    """
    result = evaluate_and_record_verification(req, db)

    # Determine broadcast event type
    res_status = result.get("result", "INCONCLUSIVE")
    if res_status == "VERIFIED":
        event_name = "MITIGATION_VERIFIED"
    elif res_status == "FAILED":
        event_name = "MITIGATION_FAILED"
    else:
        event_name = "MITIGATION_INCONCLUSIVE"

    # Broadcast live to connected SOC Dashboards
    await broadcaster.broadcast({
        "event_type": event_name,
        "verification_id": result.get("verification_id"),
        "request_id": result.get("request_id"),
        "trace_id": result.get("trace_id"),
        "verification_type": result.get("verification_type"),
        "expected_action": result.get("expected_action"),
        "actual_action": result.get("actual_action"),
        "result": res_status,
        "confidence": result.get("confidence"),
        "origin_reached": result.get("actual_origin_access"),
        "origin_request_count": result.get("origin_request_count"),
        "deception_session_id": result.get("deception_session_id"),
        "proof": result.get("proof"),
        "timestamp": result.get("created_at")
    })

    return result


@router.get("/verification")
def list_verifications(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    result: Optional[str] = Query(None, description="Filter by VERIFIED, FAILED, or INCONCLUSIVE"),
    db: Session = Depends(get_db)
):
    """List recent response verification receipts with optional status filtering."""
    results = list_verification_results(db, limit=limit, offset=offset, result_filter=result)
    return {
        "verifications": results,
        "total": len(results),
        "limit": limit,
        "offset": offset
    }


@router.get("/verification/stats")
def get_stats(db: Session = Depends(get_db)):
    """Retrieve aggregate verification metrics and proof breakdown for SOC overview."""
    return get_verification_stats(db)


@router.get("/verification/{verification_id}")
def get_verification(
    verification_id: str,
    db: Session = Depends(get_db)
):
    """Retrieve a single verification receipt by unique verification ID."""
    result = get_verification_by_id(db, verification_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Verification receipt '{verification_id}' not found."
        )
    return result


@router.get("/verification/request/{request_id}")
def get_verification_by_req(
    request_id: str,
    db: Session = Depends(get_db)
):
    """Retrieve verification receipt for a specific request ID."""
    result = get_verification_by_request_id(db, request_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No verification receipt found for request '{request_id}'."
        )
    return result


@router.get("/verification/trace/{trace_id}")
def get_verifications_by_tr(
    trace_id: str,
    db: Session = Depends(get_db)
):
    """Retrieve all verification receipts associated with a trace chain."""
    return get_verification_by_trace_id(db, trace_id)


@router.get("/verification/{verification_id}/proof")
def get_verification_proof(
    verification_id: str,
    db: Session = Depends(get_db)
):
    """Retrieve structured cryptographic and telemetry-backed proof object for audit."""
    result = get_verification_by_id(db, verification_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Verification receipt '{verification_id}' not found."
        )
    return {
        "verification_id": result["verification_id"],
        "request_id": result["request_id"],
        "trace_id": result["trace_id"],
        "result": result["result"],
        "confidence": result["confidence"],
        "expected_action": result["expected_action"],
        "actual_action": result["actual_action"],
        "origin_reached": result["actual_origin_access"],
        "origin_request_count": result["origin_request_count"],
        "deception_session_id": result["deception_session_id"],
        "evidence_events": result["evidence_count"],
        "database_access": result["database_access_detected"],
        "proof": result["proof"],
        "failure_reason": result["failure_reason"],
        "engine_version": result["engine_version"],
        "created_at": result["created_at"]
    }
