"""
AEGIS Ω — Policy Engine Database Repository
Encapsulates SQL persistence and retrieval operations for the policy_decisions table.
"""

from typing import Dict, Any, List, Optional
import json
import logging
from sqlalchemy import text
from sqlalchemy.orm import Session
from policy_engine.models import PolicyDecision
from policy_engine.config import policy_settings

logger = logging.getLogger("aegis.policy_repository")


def row_to_policy_dict(row: Any) -> Dict[str, Any]:
    """Converts a database row into a structured policy decision dictionary."""
    reasons_data = row.reasons if isinstance(row.reasons, list) else (json.loads(row.reasons) if row.reasons else [])
    rules_data = row.matched_rules if isinstance(row.matched_rules, list) else (json.loads(row.matched_rules) if row.matched_rules else [])

    return {
        "decision_id": row.decision_id,
        "event_id": row.event_id,
        "request_id": row.request_id,
        "trace_id": row.trace_id,
        "session_id": row.session_id,
        "risk_assessment_id": row.risk_assessment_id,
        "agent_shield_assessment_id": row.agent_shield_assessment_id,
        "risk_score": row.risk_score,
        "risk_severity": row.risk_severity,
        "risk_confidence": float(row.risk_confidence) if row.risk_confidence is not None else None,
        "agent_shield_score": row.agent_shield_score,
        "agent_shield_severity": row.agent_shield_severity,
        "agent_shield_confidence": float(row.agent_shield_confidence) if row.agent_shield_confidence is not None else None,
        "decision": row.decision,
        "decision_reason": row.decision_reason,
        "explanation": row.decision_reason,
        "reasons": reasons_data,
        "matched_rules": rules_data,
        "rule_matched": rules_data[0] if rules_data else "",
        "rule_evaluation_chain": rules_data,
        "terminal": row.terminal,
        "policy_version": row.policy_version,
        "created_at": row.created_at.isoformat() if hasattr(row.created_at, "isoformat") else str(row.created_at)
    }


def save_policy_decision(db: Session, decision: PolicyDecision) -> Dict[str, Any]:
    """Persists a calculated policy decision into the PostgreSQL policy_decisions table."""
    insert_sql = text("""
        INSERT INTO policy_decisions (
            decision_id, event_id, request_id, trace_id, session_id,
            risk_assessment_id, agent_shield_assessment_id,
            risk_score, risk_severity, risk_confidence,
            agent_shield_score, agent_shield_severity, agent_shield_confidence,
            decision, decision_reason, reasons, matched_rules,
            terminal, policy_version, created_at
        ) VALUES (
            :decision_id, :event_id, :request_id, :trace_id, :session_id,
            :risk_assessment_id, :agent_shield_assessment_id,
            :risk_score, :risk_severity, :risk_confidence,
            :agent_shield_score, :agent_shield_severity, :agent_shield_confidence,
            :decision, :decision_reason, CAST(:reasons AS jsonb), CAST(:matched_rules AS jsonb),
            :terminal, :policy_version, CURRENT_TIMESTAMP
        )
        RETURNING decision_id, created_at;
    """)

    result = db.execute(insert_sql, {
        "decision_id": decision.decision_id,
        "event_id": decision.event_id,
        "request_id": decision.request_id,
        "trace_id": decision.trace_id,
        "session_id": decision.session_id,
        "risk_assessment_id": decision.risk_assessment_id,
        "agent_shield_assessment_id": decision.agent_shield_assessment_id,
        "risk_score": decision.risk_score,
        "risk_severity": decision.risk_severity,
        "risk_confidence": decision.risk_confidence,
        "agent_shield_score": decision.agent_shield_score,
        "agent_shield_severity": decision.agent_shield_severity,
        "agent_shield_confidence": decision.agent_shield_confidence,
        "decision": decision.decision,
        "decision_reason": decision.decision_reason,
        "reasons": json.dumps(decision.reasons),
        "matched_rules": json.dumps(decision.matched_rules),
        "terminal": decision.terminal,
        "policy_version": decision.policy_version
    })
    db.commit()

    row = result.fetchone()
    record = decision.model_dump()
    if row and hasattr(row, "created_at") and row.created_at:
        record["created_at"] = row.created_at.isoformat() if hasattr(row.created_at, "isoformat") else str(row.created_at)
    record["explanation"] = decision.decision_reason
    record["rule_matched"] = decision.matched_rules[0] if decision.matched_rules else ""
    record["rule_evaluation_chain"] = decision.matched_rules
    return record


def get_policy_decision_by_id(db: Session, decision_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single policy decision by unique decision_id."""
    query = text("""
        SELECT decision_id, event_id, request_id, trace_id, session_id,
               risk_assessment_id, agent_shield_assessment_id,
               risk_score, risk_severity, risk_confidence,
               agent_shield_score, agent_shield_severity, agent_shield_confidence,
               decision, decision_reason, reasons, matched_rules,
               terminal, policy_version, created_at
        FROM policy_decisions
        WHERE decision_id = :did
        LIMIT 1;
    """)
    row = db.execute(query, {"did": decision_id}).fetchone()
    if not row:
        return None
    return row_to_policy_dict(row)


def get_policy_decisions_by_request_id(db: Session, request_id: str) -> List[Dict[str, Any]]:
    """Retrieves all policy decisions associated with a request_id."""
    query = text("""
        SELECT decision_id, event_id, request_id, trace_id, session_id,
               risk_assessment_id, agent_shield_assessment_id,
               risk_score, risk_severity, risk_confidence,
               agent_shield_score, agent_shield_severity, agent_shield_confidence,
               decision, decision_reason, reasons, matched_rules,
               terminal, policy_version, created_at
        FROM policy_decisions
        WHERE request_id = :req_id
        ORDER BY created_at DESC;
    """)
    rows = db.execute(query, {"req_id": request_id}).fetchall()
    return [row_to_policy_dict(r) for r in rows]


def get_policy_decisions_by_trace_id(db: Session, trace_id: str) -> List[Dict[str, Any]]:
    """Retrieves all policy decisions associated with a correlation trace_id."""
    query = text("""
        SELECT decision_id, event_id, request_id, trace_id, session_id,
               risk_assessment_id, agent_shield_assessment_id,
               risk_score, risk_severity, risk_confidence,
               agent_shield_score, agent_shield_severity, agent_shield_confidence,
               decision, decision_reason, reasons, matched_rules,
               terminal, policy_version, created_at
        FROM policy_decisions
        WHERE trace_id = :trace_id
        ORDER BY created_at DESC;
    """)
    rows = db.execute(query, {"trace_id": trace_id}).fetchall()
    return [row_to_policy_dict(r) for r in rows]


def get_policy_stats(db: Session) -> Dict[str, Any]:
    """Calculates aggregated live policy decision statistics from PostgreSQL."""
    query = text("""
        SELECT 
            COUNT(*) as total_decisions,
            COUNT(*) FILTER (WHERE decision = 'ALLOW') as allow_count,
            COUNT(*) FILTER (WHERE decision = 'MONITOR') as monitor_count,
            COUNT(*) FILTER (WHERE decision = 'RATE_LIMIT') as rate_limit_count,
            COUNT(*) FILTER (WHERE decision = 'BLOCK') as block_count,
            COUNT(*) FILTER (WHERE decision = 'CONTAIN') as contain_count,
            COUNT(*) FILTER (WHERE decision = 'DECEIVE_ELIGIBLE') as deceive_eligible_count
        FROM policy_decisions;
    """)
    row = db.execute(query).fetchone()

    # Latest 5 decisions for dashboard timeline
    latest_query = text("""
        SELECT decision_id, event_id, request_id, trace_id, session_id,
               risk_assessment_id, agent_shield_assessment_id,
               risk_score, risk_severity, risk_confidence,
               agent_shield_score, agent_shield_severity, agent_shield_confidence,
               decision, decision_reason, reasons, matched_rules,
               terminal, policy_version, created_at
        FROM policy_decisions
        ORDER BY created_at DESC
        LIMIT 5;
    """)
    latest_rows = db.execute(latest_query).fetchall()

    return {
        "total_decisions": row.total_decisions if row else 0,
        "allow_count": row.allow_count if row else 0,
        "monitor_count": row.monitor_count if row else 0,
        "rate_limit_count": row.rate_limit_count if row else 0,
        "block_count": row.block_count if row else 0,
        "contain_count": row.contain_count if row else 0,
        "deceive_eligible_count": row.deceive_eligible_count if row else 0,
        "recent_decisions": [row_to_policy_dict(r) for r in latest_rows],
        "disclaimer": policy_settings.DECEPTION_DISCLAIMER
    }


def list_policy_decisions(
    db: Session,
    limit: int = 50,
    offset: int = 0,
    decision_filter: Optional[str] = None
) -> Dict[str, Any]:
    """Retrieves paginated policy decisions with optional decision filter."""
    if decision_filter:
        query = text("""
            SELECT decision_id, event_id, request_id, trace_id, session_id,
                   risk_assessment_id, agent_shield_assessment_id,
                   risk_score, risk_severity, risk_confidence,
                   agent_shield_score, agent_shield_severity, agent_shield_confidence,
                   decision, decision_reason, reasons, matched_rules,
                   terminal, policy_version, created_at
            FROM policy_decisions
            WHERE decision = :dec
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset;
        """)
        rows = db.execute(query, {"dec": decision_filter.upper(), "limit": limit, "offset": offset}).fetchall()
    else:
        query = text("""
            SELECT decision_id, event_id, request_id, trace_id, session_id,
                   risk_assessment_id, agent_shield_assessment_id,
                   risk_score, risk_severity, risk_confidence,
                   agent_shield_score, agent_shield_severity, agent_shield_confidence,
                   decision, decision_reason, reasons, matched_rules,
                   terminal, policy_version, created_at
            FROM policy_decisions
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset;
        """)
        rows = db.execute(query, {"limit": limit, "offset": offset}).fetchall()

    return {
        "limit": limit,
        "offset": offset,
        "count": len(rows),
        "decisions": [row_to_policy_dict(r) for r in rows],
        "disclaimer": policy_settings.DECEPTION_DISCLAIMER
    }
