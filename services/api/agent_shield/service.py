"""
AEGIS Ω — AgentShield Service
Coordinates temporal correlation queries, behavioral analysis, PostgreSQL persistence,
and real-time WebSocket broadcasting.
Strict failure-safety guarantee: behavioral analysis errors never disrupt security event ingestion.
"""

from datetime import datetime, timezone
import json
import logging
import uuid
from typing import Dict, Any, Optional, List
from sqlalchemy import text
from sqlalchemy.orm import Session

from agent_shield.config import agent_shield_settings
from agent_shield.analyzer import analyze_behavior
from agent_shield.models import AgentShieldResult
from broadcaster import broadcaster

logger = logging.getLogger("aegis.agent_shield")


def assess_event_behavior(event_data: Dict[str, Any], db: Session) -> Optional[Dict[str, Any]]:
    """
    Evaluates an ingested security event against correlated activity in the temporal window.
    Persists AgentShield assessment and broadcasts AGENTSHIELD_SIGNAL to dashboard clients.
    Guaranteed failure-safe: exceptions are logged and never bubble up.
    """
    try:
        req_id = event_data.get("request_id", "unknown-req")
        trace_id = event_data.get("trace_id", f"trace-{req_id}")
        session_id = event_data.get("session_id")

        # Query historical events in temporal correlation window (60s default)
        # Correlates across request chain (trace_id) or explicit session_id
        historical_query = text("""
            SELECT event_id, event_type, timestamp, request_id, trace_id,
                   severity, action, component, source_ip, method, uri, metadata
            FROM security_events
            WHERE (trace_id = :trace_id OR (:session_id IS NOT NULL AND session_id = :session_id))
              AND timestamp >= NOW() - INTERVAL '60 seconds'
              AND request_id != :req_id
            ORDER BY timestamp ASC
            LIMIT :max_limit;
        """)

        rows = db.execute(historical_query, {
            "trace_id": trace_id,
            "session_id": session_id,
            "req_id": req_id,
            "max_limit": agent_shield_settings.MAX_HISTORICAL_EVENTS_LIMIT
        }).fetchall()

        historical_events: List[Dict[str, Any]] = []
        for r in rows:
            meta = r.metadata if isinstance(r.metadata, dict) else (json.loads(r.metadata) if r.metadata else {})
            historical_events.append({
                "event_id": r.event_id,
                "event_type": r.event_type,
                "timestamp": r.timestamp.isoformat() if hasattr(r.timestamp, "isoformat") else str(r.timestamp),
                "request_id": r.request_id,
                "trace_id": r.trace_id,
                "severity": r.severity,
                "action": r.action,
                "component": r.component,
                "source_ip": r.source_ip,
                "request": {"method": r.method, "uri": r.uri},
                "metadata": meta
            })

        # Calculate deterministic behavioral assessment
        result: AgentShieldResult = analyze_behavior(event_data, historical_events)

        assessment_id = f"as-{uuid.uuid4().hex[:16]}"
        result.assessment_id = assessment_id

        signals_payload = [s.model_dump() for s in result.signals]
        stages_payload = result.attack_stages

        # Persist into agent_shield_assessments table
        insert_sql = text("""
            INSERT INTO agent_shield_assessments (
                assessment_id, request_id, trace_id, session_id,
                agent_shield_score, severity, confidence, signals,
                attack_stages, behavior_summary, engine_version, created_at
            ) VALUES (
                :assessment_id, :request_id, :trace_id, :session_id,
                :agent_shield_score, :severity, :confidence, CAST(:signals AS jsonb),
                CAST(:attack_stages AS jsonb), :behavior_summary, :engine_version, CURRENT_TIMESTAMP
            )
            RETURNING assessment_id;
        """)

        db.execute(insert_sql, {
            "assessment_id": assessment_id,
            "request_id": req_id,
            "trace_id": trace_id,
            "session_id": session_id,
            "agent_shield_score": result.agent_shield_score,
            "severity": result.severity,
            "confidence": result.confidence,
            "signals": json.dumps(signals_payload),
            "attack_stages": json.dumps(stages_payload),
            "behavior_summary": result.behavior_summary,
            "engine_version": result.engine_version
        })
        db.commit()

        assessment_record = {
            "assessment_id": assessment_id,
            "request_id": req_id,
            "trace_id": trace_id,
            "session_id": session_id,
            "agent_shield_score": result.agent_shield_score,
            "severity": result.severity,
            "confidence": result.confidence,
            "signals": signals_payload,
            "attack_stages": stages_payload,
            "attack_timeline": [t.model_dump() for t in result.attack_timeline],
            "behavior_summary": result.behavior_summary,
            "engine_version": result.engine_version,
            "disclaimer": result.disclaimer,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        logger.info(
            f"Assessed AgentShield for {req_id}: Score {result.agent_shield_score} ({result.severity}) | "
            f"Signals: {len(signals_payload)} | Stages: {len(stages_payload)}"
        )

        return assessment_record
    except Exception as e:
        logger.error(f"Error evaluating AgentShield for event {event_data.get('event_id')}: {e}", exc_info=True)
        db.rollback()
        return None
