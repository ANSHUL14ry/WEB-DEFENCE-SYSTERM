"""
AEGIS Ω — Phase 9 Response Verification Database Repository
Manages persistence and retrieval of verification receipts and telemetry proofs.
"""

from typing import Dict, Any, List, Optional
import json
import logging
from sqlalchemy.orm import Session
from sqlalchemy import text

from verification.models import ProofObject

logger = logging.getLogger("aegis.verification.repository")


def save_verification_result(db: Session, proof: ProofObject) -> Dict[str, Any]:
    """Persist or update verification result idempotently."""
    try:
        # Check if already verified for this request_id
        existing = db.execute(
            text("SELECT verification_id FROM verification_results WHERE request_id = :req_id"),
            {"req_id": proof.request_id}
        ).fetchone()

        if existing:
            v_id = existing[0]
            db.execute(
                text("""
                    UPDATE verification_results
                    SET trace_id = :trace_id,
                        session_id = :session_id,
                        policy_decision_id = :policy_id,
                        verification_type = :v_type,
                        expected_action = :exp_act,
                        actual_action = :act_act,
                        expected_origin_access = :exp_orig,
                        actual_origin_access = :act_orig,
                        origin_request_count = :orig_cnt,
                        deception_session_id = :dec_id,
                        evidence_count = :ev_cnt,
                        database_access_detected = :db_acc,
                        result = :res,
                        confidence = :conf,
                        proof = :proof,
                        failure_reason = :fail_rsn,
                        engine_version = :ver
                    WHERE verification_id = :v_id
                """),
                {
                    "v_id": v_id,
                    "trace_id": proof.trace_id,
                    "session_id": proof.session_id,
                    "policy_id": proof.policy_decision_id,
                    "v_type": proof.verification_type,
                    "exp_act": proof.expected_action,
                    "act_act": proof.actual_action,
                    "exp_orig": proof.expected_origin_access,
                    "act_orig": proof.actual_origin_access,
                    "orig_cnt": proof.origin_request_count,
                    "dec_id": proof.deception_session_id,
                    "ev_cnt": proof.evidence_events,
                    "db_acc": proof.database_access,
                    "res": proof.result,
                    "conf": proof.confidence,
                    "proof": json.dumps(proof.proof),
                    "fail_rsn": proof.failure_reason,
                    "ver": proof.engine_version
                }
            )
            db.commit()
            return get_verification_by_id(db, v_id)  # type: ignore

        db.execute(
            text("""
                INSERT INTO verification_results (
                    verification_id, request_id, trace_id, session_id,
                    policy_decision_id, verification_type, expected_action,
                    actual_action, expected_origin_access, actual_origin_access,
                    origin_request_count, deception_session_id, evidence_count,
                    database_access_detected, result, confidence, proof,
                    failure_reason, engine_version, created_at
                ) VALUES (
                    :v_id, :req_id, :trace_id, :session_id,
                    :policy_id, :v_type, :exp_act,
                    :act_act, :exp_orig, :act_orig,
                    :orig_cnt, :dec_id, :ev_cnt,
                    :db_acc, :res, :conf, :proof,
                    :fail_rsn, :ver, :created_at
                )
            """),
            {
                "v_id": proof.verification_id,
                "req_id": proof.request_id,
                "trace_id": proof.trace_id,
                "session_id": proof.session_id,
                "policy_id": proof.policy_decision_id,
                "v_type": proof.verification_type,
                "exp_act": proof.expected_action,
                "act_act": proof.actual_action,
                "exp_orig": proof.expected_origin_access,
                "act_orig": proof.actual_origin_access,
                "orig_cnt": proof.origin_request_count,
                "dec_id": proof.deception_session_id,
                "ev_cnt": proof.evidence_events,
                "db_acc": proof.database_access,
                "res": proof.result,
                "conf": proof.confidence,
                "proof": json.dumps(proof.proof),
                "fail_rsn": proof.failure_reason,
                "ver": proof.engine_version,
                "created_at": proof.created_at
            }
        )
        db.commit()
        return get_verification_by_id(db, proof.verification_id)  # type: ignore
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to persist verification result: {e}")
        raise


def _row_to_dict(row: Any) -> Dict[str, Any]:
    proof_val = row[16]
    if isinstance(proof_val, str):
        try:
            proof_val = json.loads(proof_val)
        except Exception:
            proof_val = []

    return {
        "verification_id": row[0],
        "request_id": row[1],
        "trace_id": row[2],
        "session_id": row[3],
        "policy_decision_id": row[4],
        "verification_type": row[5],
        "expected_action": row[6],
        "actual_action": row[7],
        "expected_origin_access": row[8],
        "actual_origin_access": row[9],
        "origin_request_count": row[10],
        "deception_session_id": row[11],
        "evidence_count": row[12],
        "database_access_detected": row[13],
        "result": row[14],
        "confidence": float(row[15]) if row[15] is not None else 1.0,
        "proof": proof_val if isinstance(proof_val, list) else [],
        "failure_reason": row[17],
        "engine_version": row[18],
        "created_at": row[19].isoformat() if row[19] else None
    }


def get_verification_by_id(db: Session, verification_id: str) -> Optional[Dict[str, Any]]:
    row = db.execute(
        text("""
            SELECT verification_id, request_id, trace_id, session_id,
                   policy_decision_id, verification_type, expected_action,
                   actual_action, expected_origin_access, actual_origin_access,
                   origin_request_count, deception_session_id, evidence_count,
                   database_access_detected, result, confidence, proof,
                   failure_reason, engine_version, created_at
            FROM verification_results
            WHERE verification_id = :v_id
        """),
        {"v_id": verification_id}
    ).fetchone()
    if not row:
        return None
    return _row_to_dict(row)


def get_verification_by_request_id(db: Session, request_id: str) -> Optional[Dict[str, Any]]:
    row = db.execute(
        text("""
            SELECT verification_id, request_id, trace_id, session_id,
                   policy_decision_id, verification_type, expected_action,
                   actual_action, expected_origin_access, actual_origin_access,
                   origin_request_count, deception_session_id, evidence_count,
                   database_access_detected, result, confidence, proof,
                   failure_reason, engine_version, created_at
            FROM verification_results
            WHERE request_id = :req_id
            ORDER BY created_at DESC LIMIT 1
        """),
        {"req_id": request_id}
    ).fetchone()
    if not row:
        return None
    return _row_to_dict(row)


def get_verification_by_trace_id(db: Session, trace_id: str) -> List[Dict[str, Any]]:
    rows = db.execute(
        text("""
            SELECT verification_id, request_id, trace_id, session_id,
                   policy_decision_id, verification_type, expected_action,
                   actual_action, expected_origin_access, actual_origin_access,
                   origin_request_count, deception_session_id, evidence_count,
                   database_access_detected, result, confidence, proof,
                   failure_reason, engine_version, created_at
            FROM verification_results
            WHERE trace_id = :trace_id
            ORDER BY created_at DESC
        """),
        {"trace_id": trace_id}
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def list_verification_results(
    db: Session,
    limit: int = 50,
    offset: int = 0,
    result_filter: Optional[str] = None
) -> List[Dict[str, Any]]:
    if result_filter:
        rows = db.execute(
            text("""
                SELECT verification_id, request_id, trace_id, session_id,
                       policy_decision_id, verification_type, expected_action,
                       actual_action, expected_origin_access, actual_origin_access,
                       origin_request_count, deception_session_id, evidence_count,
                       database_access_detected, result, confidence, proof,
                       failure_reason, engine_version, created_at
                FROM verification_results
                WHERE result = :res
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
            """),
            {"res": result_filter, "limit": limit, "offset": offset}
        ).fetchall()
    else:
        rows = db.execute(
            text("""
                SELECT verification_id, request_id, trace_id, session_id,
                       policy_decision_id, verification_type, expected_action,
                       actual_action, expected_origin_access, actual_origin_access,
                       origin_request_count, deception_session_id, evidence_count,
                       database_access_detected, result, confidence, proof,
                       failure_reason, engine_version, created_at
                FROM verification_results
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
            """),
            {"limit": limit, "offset": offset}
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_verification_stats(db: Session) -> Dict[str, Any]:
    """Calculate aggregate verification metrics for dashboard and API."""
    total = db.execute(text("SELECT COUNT(*) FROM verification_results")).scalar() or 0
    verified = db.execute(
        text("SELECT COUNT(*) FROM verification_results WHERE result = 'VERIFIED'")
    ).scalar() or 0
    failed = db.execute(
        text("SELECT COUNT(*) FROM verification_results WHERE result = 'FAILED'")
    ).scalar() or 0
    inconclusive = db.execute(
        text("SELECT COUNT(*) FROM verification_results WHERE result = 'INCONCLUSIVE'")
    ).scalar() or 0

    percentage = round((verified / total * 100.0), 1) if total > 0 else 100.0

    recent_rows = db.execute(
        text("""
            SELECT verification_id, request_id, trace_id, session_id,
                   policy_decision_id, verification_type, expected_action,
                   actual_action, expected_origin_access, actual_origin_access,
                   origin_request_count, deception_session_id, evidence_count,
                   database_access_detected, result, confidence, proof,
                   failure_reason, engine_version, created_at
            FROM verification_results
            ORDER BY created_at DESC
            LIMIT 10
        """)
    ).fetchall()

    return {
        "total_verifications": int(total),
        "verified_count": int(verified),
        "failed_count": int(failed),
        "inconclusive_count": int(inconclusive),
        "verified_percentage": percentage,
        "recent_verifications": [_row_to_dict(r) for r in recent_rows]
    }
