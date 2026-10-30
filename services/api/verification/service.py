"""
AEGIS Ω — Phase 9 Response Verification Service
Orchestrates context aggregation from security pipeline, evaluates deterministic rules,
sanitizes evidence, and persists verification receipts.
"""

from typing import Dict, Any, Optional
import logging
from sqlalchemy.orm import Session
from sqlalchemy import text

from verification.models import (
    VerificationEvaluateRequest,
    VerificationContext,
    ProofObject
)
from verification.evaluator import evaluate_mitigation_verification
from verification.repository import (
    save_verification_result,
    get_verification_by_id,
    get_verification_by_request_id,
    get_verification_by_trace_id,
    list_verification_results,
    get_verification_stats
)

logger = logging.getLogger("aegis.verification.service")


def evaluate_and_record_verification(
    req: VerificationEvaluateRequest,
    db: Session
) -> Dict[str, Any]:
    """
    Main entry point for evaluating mitigation verification.
    Enriches context from existing database telemetry if not explicitly supplied,
    evaluates deterministic rules, sanitizes evidence, and records proof.
    """
    policy_decision = req.policy_decision
    policy_decision_id = req.policy_decision_id
    session_id = req.session_id
    waf_blocked = req.waf_blocked
    waf_action = req.waf_action
    origin_reached = req.origin_reached
    origin_request_count = req.origin_request_count or 0
    deception_session_id = req.deception_session_id
    evidence_count = req.evidence_count or 0
    database_access_detected = req.database_access_detected or False
    http_status = req.http_status

    # 1. Enrich from policy_decisions table if not provided
    if not policy_decision or not policy_decision_id:
        try:
            row = db.execute(
                text("""
                    SELECT decision_id, decision, terminal, session_id
                    FROM policy_decisions
                    WHERE request_id = :req_id OR trace_id = :trace_id
                    ORDER BY created_at DESC LIMIT 1
                """),
                {"req_id": req.request_id, "trace_id": req.trace_id}
            ).fetchone()
            if row:
                policy_decision_id = policy_decision_id or row[0]
                policy_decision = policy_decision or row[1]
                session_id = session_id or row[3]
        except Exception as e:
            logger.debug(f"Could not query policy_decisions: {e}")

    # 2. Enrich from security_events table for WAF detection / action
    if not waf_blocked:
        try:
            row = db.execute(
                text("""
                    SELECT action, status, metadata
                    FROM security_events
                    WHERE (request_id = :req_id OR trace_id = :trace_id)
                      AND component = 'waf'
                    ORDER BY created_at DESC LIMIT 1
                """),
                {"req_id": req.request_id, "trace_id": req.trace_id}
            ).fetchone()
            if row and row[0] == "BLOCK":
                waf_blocked = True
                waf_action = "BLOCK"
        except Exception as e:
            logger.debug(f"Could not query security_events for WAF: {e}")

    # 3. Enrich from deception_sessions table
    if not deception_session_id:
        try:
            row = db.execute(
                text("""
                    SELECT session_id, interaction_count, evidence_count, origin_reached
                    FROM deception_sessions
                    WHERE request_id = :req_id OR trace_id = :trace_id
                    ORDER BY created_at DESC LIMIT 1
                """),
                {"req_id": req.request_id, "trace_id": req.trace_id}
            ).fetchone()
            if row:
                deception_session_id = row[0]
                evidence_count = max(evidence_count, row[2] or 0)
                if origin_reached is None:
                    origin_reached = bool(row[3])
        except Exception as e:
            logger.debug(f"Could not query deception_sessions: {e}")

    # If origin_reached is still None, deduce from context
    if origin_reached is None:
        if waf_blocked or policy_decision in ["BLOCK", "CONTAIN", "DECEIVE_ELIGIBLE"]:
            origin_reached = False
            origin_request_count = 0
        elif policy_decision == "ALLOW":
            origin_reached = True
            origin_request_count = max(1, origin_request_count)
        else:
            origin_reached = False

    # Construct context
    ctx = VerificationContext(
        request_id=req.request_id,
        trace_id=req.trace_id,
        session_id=session_id,
        policy_decision_id=policy_decision_id,
        policy_decision=policy_decision,
        waf_blocked=waf_blocked,
        waf_action=waf_action,
        http_status=http_status,
        origin_reached=origin_reached,
        origin_request_count=origin_request_count,
        deception_session_id=deception_session_id,
        evidence_count=evidence_count,
        database_access_detected=database_access_detected,
        decoy_failed=req.decoy_failed or False,
        has_sufficient_telemetry=req.has_sufficient_telemetry if req.has_sufficient_telemetry is not None else True,
        telemetry_corrupted=req.telemetry_corrupted or False,
        network_enforcement_action=req.network_enforcement_action,
        network_mitigation_verified=req.network_mitigation_verified,
        metadata=req.metadata
    )

    # Deterministic evaluation
    proof_obj = evaluate_mitigation_verification(ctx)

    # Sanitize any proof strings before persistence
    sanitized_proof = []
    for item in proof_obj.proof:
        # Prevent any accidental secret or bearer token leakage
        sanitized = str(item)
        for sensitive in ["password", "token", "secret", "authorization", "bearer"]:
            if sensitive in sanitized.lower() and "=" in sanitized:
                sanitized = "[REDACTED_SENSITIVE_DATA]"
        sanitized_proof.append(sanitized)
    proof_obj.proof = sanitized_proof

    # Persist in DB
    result_dict = save_verification_result(db, proof_obj)
    return result_dict
