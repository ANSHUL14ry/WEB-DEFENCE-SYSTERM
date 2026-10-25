"""
AEGIS Ω — Policy Engine Service Layer
Coordinates trusted context extraction, deterministic rule evaluation, database persistence,
and failure-safe orchestration.
"""

from datetime import datetime, timezone
import json
import logging
import uuid
from typing import Dict, Any, Optional
from sqlalchemy import text
from sqlalchemy.orm import Session

from policy_engine.config import policy_settings
from policy_engine.models import PolicyContext, PolicyDecision
from policy_engine.evaluator import evaluate_policy
from policy_engine.repository import save_policy_decision

logger = logging.getLogger("aegis.policy_engine")


def evaluate_and_record_policy(
    event_data: Dict[str, Any],
    db: Session,
    risk_data: Optional[Dict[str, Any]] = None,
    agent_shield_data: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, Any]]:
    """
    Evaluates trusted security context against deterministic policy rules,
    persists the resulting decision, and returns the decision record.
    Strict failure-safety guarantee: policy evaluation errors never disrupt event ingestion or WAF.
    """
    try:
        req_id = event_data.get("request_id") or "unknown-req"
        trace_id = event_data.get("trace_id") or f"trace-{req_id}"
        session_id = event_data.get("session_id")
        event_id = event_data.get("event_id")

        comp = str(event_data.get("component") or "").lower()
        act = str(event_data.get("action") or "").upper()
        status_val = str(event_data.get("status") or "").upper()
        metadata = event_data.get("metadata") or {}
        req_info = event_data.get("request") or {}
        method = req_info.get("method") or event_data.get("method") or "GET"
        uri = req_info.get("uri") or event_data.get("endpoint") or event_data.get("uri") or "/"
        waf_act = str(event_data.get("waf_action") or act or "").upper()

        # 1. Determine if transaction was blocked at WAF layer (Mandatory Invariant)
        is_waf_blocked = (
            waf_act == "BLOCK" or
            act == "BLOCK" or 
            status_val == "BLOCKED" or 
            (comp == "coraza" and act in ("BLOCK", "DROP")) or
            bool(metadata.get("waf_blocked")) or
            bool(event_data.get("waf_blocked"))
        )

        # 2. Resolve trusted Risk Intelligence
        risk_score = None
        risk_sev = None
        risk_conf = None
        risk_aid = None
        risk_signals = []

        if risk_data:
            risk_score = int(risk_data["risk_score"]) if risk_data.get("risk_score") is not None else None
            risk_sev = risk_data.get("severity") or risk_data.get("risk_severity")
            risk_conf = float(risk_data["confidence"]) if risk_data.get("confidence") is not None else 1.0
            risk_aid = risk_data.get("assessment_id")
            risk_signals = risk_data.get("signals") or []
        elif event_data.get("risk_score") is not None or event_data.get("risk_severity") is not None:
            risk_score = int(event_data["risk_score"]) if event_data.get("risk_score") is not None else None
            risk_sev = event_data.get("risk_severity")
            risk_conf = float(event_data["risk_confidence"]) if event_data.get("risk_confidence") is not None else 1.0
            risk_aid = event_data.get("risk_assessment_id")
            risk_signals = event_data.get("risk_signals") or event_data.get("signals") or []
        else:
            # Look up recent risk assessment from database
            risk_row = db.execute(text("""
                SELECT assessment_id, risk_score, severity, confidence, signals
                FROM risk_assessments
                WHERE request_id = :req_id OR trace_id = :trace_id
                ORDER BY created_at DESC
                LIMIT 1;
            """), {"req_id": req_id, "trace_id": trace_id}).fetchone()
            if risk_row:
                risk_aid = risk_row.assessment_id
                risk_score = int(risk_row.risk_score) if risk_row.risk_score is not None else None
                risk_sev = risk_row.severity
                risk_conf = float(risk_row.confidence) if risk_row.confidence is not None else 1.0
                risk_signals = risk_row.signals if isinstance(risk_row.signals, list) else (json.loads(risk_row.signals) if risk_row.signals else [])

        # 3. Resolve trusted AgentShield Behavioral Intelligence
        as_score = None
        as_sev = None
        as_conf = None
        as_aid = None
        as_signals = []
        as_stages = []

        if agent_shield_data:
            as_score = int(agent_shield_data["agent_shield_score"]) if agent_shield_data.get("agent_shield_score") is not None else None
            as_sev = agent_shield_data.get("severity") or agent_shield_data.get("agent_shield_severity")
            as_conf = float(agent_shield_data["confidence"]) if agent_shield_data.get("confidence") is not None else 1.0
            as_aid = agent_shield_data.get("assessment_id")
            as_signals = agent_shield_data.get("signals") or []
            as_stages = agent_shield_data.get("attack_stages") or []
        elif event_data.get("agent_shield_score") is not None or event_data.get("agent_shield_severity") is not None:
            as_score = int(event_data["agent_shield_score"]) if event_data.get("agent_shield_score") is not None else None
            as_sev = event_data.get("agent_shield_severity")
            as_conf = float(event_data["agent_shield_confidence"]) if event_data.get("agent_shield_confidence") is not None else 1.0
            as_aid = event_data.get("agent_shield_assessment_id")
            as_signals = event_data.get("agent_shield_signals") or event_data.get("signals") or []
            as_stages = event_data.get("agent_shield_stages") or []
        else:
            # Look up recent AgentShield assessment from database
            as_row = db.execute(text("""
                SELECT assessment_id, agent_shield_score, severity, confidence, signals, attack_stages
                FROM agent_shield_assessments
                WHERE request_id = :req_id OR trace_id = :trace_id
                ORDER BY created_at DESC
                LIMIT 1;
            """), {"req_id": req_id, "trace_id": trace_id}).fetchone()
            if as_row:
                as_aid = as_row.assessment_id
                as_score = int(as_row.agent_shield_score) if as_row.agent_shield_score is not None else None
                as_sev = as_row.severity
                as_conf = float(as_row.confidence) if as_row.confidence is not None else 1.0
                as_signals = as_row.signals if isinstance(as_row.signals, list) else (json.loads(as_row.signals) if as_row.signals else [])
                as_stages = as_row.attack_stages if isinstance(as_row.attack_stages, list) else (json.loads(as_row.attack_stages) if as_row.attack_stages else [])

        # 4. Count correlated events in temporal window for velocity evaluation
        corr_count = db.execute(text("""
            SELECT COUNT(*)
            FROM security_events
            WHERE trace_id = :trace_id
              AND timestamp >= NOW() - INTERVAL '60 seconds';
        """), {"trace_id": trace_id}).scalar() or 0

        # 5. Assemble trusted PolicyContext
        context = PolicyContext(
            request_id=req_id,
            trace_id=trace_id,
            event_id=event_id,
            session_id=session_id,
            risk_assessment_id=risk_aid,
            risk_score=risk_score,
            risk_severity=risk_sev,
            risk_confidence=risk_conf,
            risk_signals=risk_signals,
            agent_shield_assessment_id=as_aid,
            agent_shield_score=as_score,
            agent_shield_severity=as_sev,
            agent_shield_confidence=as_conf,
            agent_shield_signals=as_signals,
            agent_shield_stages=as_stages,
            waf_action=waf_act or act or "NONE",
            waf_blocked=is_waf_blocked,
            endpoint=uri,
            request_method=method,
            security_event_type=event_data.get("event_type"),
            correlated_event_count=int(corr_count)
        )

        # 6. Execute deterministic policy evaluation
        decision: PolicyDecision = evaluate_policy(context)
        decision.decision_id = f"pd-{uuid.uuid4().hex[:16]}"
        decision.created_at = datetime.now(timezone.utc).isoformat()

        # 7. Persist to policy_decisions table
        saved_record = save_policy_decision(db, decision)

        logger.info(
            f"Policy Decision for {req_id}: {decision.decision} | "
            f"Reason: {decision.decision_reason} | Terminal: {decision.terminal} | "
            f"Matched Rules: {decision.matched_rules}"
        )

        return saved_record

    except Exception as e:
        logger.error(f"Policy Engine evaluation failure (failure-safe): {e}", exc_info=True)
        db.rollback()
        return None
