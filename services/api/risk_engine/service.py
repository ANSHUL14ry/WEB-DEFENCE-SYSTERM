"""
AEGIS Ω — Risk Engine Service
Coordinates temporal correlation query, deterministic scoring, PostgreSQL persistence,
and real-time WebSocket broadcasting.
Designed with strict failure-safety: risk errors never disrupt security event processing.
"""

from datetime import datetime, timezone
import json
import logging
import uuid
from typing import Dict, Any, Optional, List
from sqlalchemy import text
from sqlalchemy.orm import Session

from risk_engine.config import risk_settings
from risk_engine.evaluator import evaluate_risk, RiskAssessmentResult
from broadcaster import broadcaster

logger = logging.getLogger("aegis.risk_engine")


def assess_event_risk(event_data: Dict[str, Any], db: Session) -> Optional[Dict[str, Any]]:
    """
    Evaluates an ingested security event against correlated activity in the temporal window.
    Persists risk assessment and broadcasts updates to dashboard clients.
    Guaranteed failure-safe: exceptions are logged and never bubble up.
    """
    try:
        req_id = event_data.get("request_id", "unknown-req")
        trace_id = event_data.get("trace_id", f"trace-{req_id}")
        session_id = event_data.get("session_id")
        source = event_data.get("source", {}) or {}
        source_ip = source.get("ip") or event_data.get("source_ip", "unknown")

        # Query historical events in temporal correlation window (default 60s)
        # Correlates across request chain (trace_id) or explicit session_id
        historical_query = text("""
            SELECT event_id, event_type, timestamp, request_id, trace_id,
                   severity, action, component, source_ip, method, uri, metadata
            FROM security_events
            WHERE (trace_id = :trace_id OR (:session_id IS NOT NULL AND session_id = :session_id))
              AND timestamp >= NOW() - INTERVAL '60 seconds'
              AND request_id != :req_id
            ORDER BY timestamp DESC
            LIMIT :max_limit;
        """)

        rows = db.execute(historical_query, {
            "trace_id": trace_id,
            "session_id": session_id,
            "req_id": req_id,
            "max_limit": risk_settings.MAX_HISTORICAL_EVENTS_LIMIT
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

        # Calculate deterministic risk assessment
        result: RiskAssessmentResult = evaluate_risk(event_data, historical_events)

        assessment_id = f"risk-{uuid.uuid4().hex[:16]}"
        signals_payload = [s.model_dump() for s in result.signals]

        # Persist into risk_assessments table
        insert_sql = text("""
            INSERT INTO risk_assessments (
                assessment_id, request_id, trace_id, session_id,
                risk_score, severity, confidence, signals,
                engine_version, created_at
            ) VALUES (
                :assessment_id, :request_id, :trace_id, :session_id,
                :risk_score, :severity, :confidence, CAST(:signals AS jsonb),
                :engine_version, CURRENT_TIMESTAMP
            )
            RETURNING assessment_id;
        """)

        db.execute(insert_sql, {
            "assessment_id": assessment_id,
            "request_id": req_id,
            "trace_id": trace_id,
            "session_id": session_id,
            "risk_score": result.risk_score,
            "severity": result.severity,
            "confidence": result.confidence,
            "signals": json.dumps(signals_payload),
            "engine_version": result.engine_version
        })
        db.commit()

        assessment_record = {
            "assessment_id": assessment_id,
            "request_id": req_id,
            "trace_id": trace_id,
            "session_id": session_id,
            "risk_score": result.risk_score,
            "severity": result.severity,
            "confidence": result.confidence,
            "signals": signals_payload,
            "engine_version": result.engine_version,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        logger.info(
            f"Assessed Risk for {req_id}: Score {result.risk_score} ({result.severity}) | "
            f"Signals: {len(signals_payload)} | Version: {result.engine_version}"
        )

        return assessment_record

    except Exception as e:
        logger.error(f"Risk evaluation error for event (failure-safe): {e}")
        db.rollback()
        return None
