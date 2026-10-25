"""
AEGIS Ω — Deception Subsystem Database Repository
PostgreSQL persistence and querying layer for deception_sessions and deception_events tables.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Dict, Any, List, Optional
from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger("aegis.deception_repository")


def row_to_session_dict(row: Any) -> Dict[str, Any]:
    """Converts a database session row into a structured dictionary."""
    return {
        "session_id": row.session_id,
        "request_id": row.request_id,
        "trace_id": row.trace_id,
        "policy_decision_id": row.policy_decision_id,
        "source_identifier_hash": row.source_identifier_hash,
        "client_ip": row.client_ip,
        "initial_risk_score": row.initial_risk_score,
        "initial_agent_shield_score": row.initial_agent_shield_score,
        "entry_reason": row.entry_reason,
        "status": row.status,
        "interaction_count": row.interaction_count,
        "evidence_count": row.evidence_count,
        "origin_reached": row.origin_reached,
        "started_at": row.started_at.isoformat() if hasattr(row.started_at, "isoformat") else str(row.started_at),
        "ended_at": row.ended_at.isoformat() if hasattr(row.ended_at, "isoformat") and row.ended_at else None,
        "last_interaction_at": row.last_interaction_at.isoformat() if hasattr(row.last_interaction_at, "isoformat") and row.last_interaction_at else None,
        "expires_at": row.expires_at.isoformat() if hasattr(row.expires_at, "isoformat") and row.expires_at else None,
        "created_at": row.created_at.isoformat() if hasattr(row.created_at, "isoformat") else str(row.created_at)
    }


def row_to_event_dict(row: Any) -> Dict[str, Any]:
    """Converts a database event row into a structured dictionary."""
    risk_ctx = row.risk_context if isinstance(row.risk_context, dict) else (json.loads(row.risk_context) if row.risk_context else {})
    meta = row.metadata if isinstance(row.metadata, dict) else (json.loads(row.metadata) if row.metadata else {})

    return {
        "event_id": row.event_id,
        "session_id": row.session_id,
        "request_id": row.request_id,
        "trace_id": row.trace_id,
        "event_type": row.event_type,
        "route": row.route,
        "method": row.method,
        "source_identifier_hash": row.source_identifier_hash,
        "response_status": row.response_status,
        "endpoint_category": row.endpoint_category,
        "user_agent_classification": row.user_agent_classification,
        "request_size": row.request_size,
        "risk_context": risk_ctx,
        "metadata": meta,
        "created_at": row.created_at.isoformat() if hasattr(row.created_at, "isoformat") else str(row.created_at)
    }


def create_session(db: Session, session_data: Dict[str, Any]) -> Dict[str, Any]:
    """Inserts a new deception session record into PostgreSQL."""
    insert_sql = text("""
        INSERT INTO deception_sessions (
            session_id, request_id, trace_id, policy_decision_id,
            source_identifier_hash, client_ip, initial_risk_score,
            initial_agent_shield_score, entry_reason, status,
            interaction_count, evidence_count, origin_reached,
            started_at, expires_at, created_at
        ) VALUES (
            :session_id, :request_id, :trace_id, :policy_decision_id,
            :source_identifier_hash, :client_ip, :initial_risk_score,
            :initial_agent_shield_score, :entry_reason, :status,
            :interaction_count, :evidence_count, :origin_reached,
            :started_at, :expires_at, CURRENT_TIMESTAMP
        )
        RETURNING *;
    """)

    result = db.execute(insert_sql, {
        "session_id": session_data["session_id"],
        "request_id": session_data["request_id"],
        "trace_id": session_data["trace_id"],
        "policy_decision_id": session_data.get("policy_decision_id"),
        "source_identifier_hash": session_data["source_identifier_hash"],
        "client_ip": session_data.get("client_ip"),
        "initial_risk_score": session_data.get("initial_risk_score"),
        "initial_agent_shield_score": session_data.get("initial_agent_shield_score"),
        "entry_reason": session_data.get("entry_reason"),
        "status": session_data.get("status", "ACTIVE"),
        "interaction_count": session_data.get("interaction_count", 0),
        "evidence_count": session_data.get("evidence_count", 0),
        "origin_reached": False, # Strict isolation flag
        "started_at": session_data.get("started_at", datetime.now(timezone.utc)),
        "expires_at": session_data.get("expires_at")
    })
    db.commit()
    row = result.fetchone()
    return row_to_session_dict(row)


def get_session_by_id(db: Session, session_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a deception session by primary key."""
    query = text("SELECT * FROM deception_sessions WHERE session_id = :sid LIMIT 1;")
    row = db.execute(query, {"sid": session_id}).fetchone()
    return row_to_session_dict(row) if row else None


def get_active_session_by_trace(db: Session, trace_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves the most recent ACTIVE deception session for a given trace_id."""
    query = text("""
        SELECT * FROM deception_sessions
        WHERE trace_id = :trace_id AND status = 'ACTIVE' AND expires_at > CURRENT_TIMESTAMP
        ORDER BY created_at DESC
        LIMIT 1;
    """)
    row = db.execute(query, {"trace_id": trace_id}).fetchone()
    return row_to_session_dict(row) if row else None


def update_session_status(db: Session, session_id: str, new_status: str) -> bool:
    """Updates the status of a deception session (e.g. TERMINATED or EXPIRED)."""
    update_sql = text("""
        UPDATE deception_sessions
        SET status = :new_status, ended_at = CURRENT_TIMESTAMP
        WHERE session_id = :sid;
    """)
    result = db.execute(update_sql, {"new_status": new_status, "sid": session_id})
    db.commit()
    return result.rowcount > 0


def increment_session_counts(db: Session, session_id: str) -> None:
    """Increments interaction_count and evidence_count, updating last_interaction_at."""
    update_sql = text("""
        UPDATE deception_sessions
        SET interaction_count = interaction_count + 1,
            evidence_count = evidence_count + 1,
            last_interaction_at = CURRENT_TIMESTAMP
        WHERE session_id = :sid;
    """)
    db.execute(update_sql, {"sid": session_id})
    db.commit()


def create_deception_event(db: Session, event_data: Dict[str, Any]) -> Dict[str, Any]:
    """Persists a captured evidence event into the deception_events table."""
    insert_sql = text("""
        INSERT INTO deception_events (
            event_id, session_id, request_id, trace_id, event_type,
            route, method, source_identifier_hash, response_status,
            endpoint_category, user_agent_classification, request_size,
            risk_context, metadata, created_at
        ) VALUES (
            :event_id, :session_id, :request_id, :trace_id, :event_type,
            :route, :method, :source_identifier_hash, :response_status,
            :endpoint_category, :user_agent_classification, :request_size,
            CAST(:risk_context AS jsonb), CAST(:metadata AS jsonb), CURRENT_TIMESTAMP
        )
        RETURNING *;
    """)

    result = db.execute(insert_sql, {
        "event_id": event_data["event_id"],
        "session_id": event_data["session_id"],
        "request_id": event_data["request_id"],
        "trace_id": event_data["trace_id"],
        "event_type": event_data["event_type"],
        "route": event_data["route"],
        "method": event_data.get("method", "GET"),
        "source_identifier_hash": event_data.get("source_identifier_hash"),
        "response_status": event_data.get("response_status", 200),
        "endpoint_category": event_data.get("endpoint_category", "UNKNOWN"),
        "user_agent_classification": event_data.get("user_agent_classification", "standard"),
        "request_size": event_data.get("request_size", 0),
        "risk_context": json.dumps(event_data.get("risk_context") or {}),
        "metadata": json.dumps(event_data.get("metadata") or {})
    })
    db.commit()
    row = result.fetchone()
    return row_to_event_dict(row)


def get_session_events(db: Session, session_id: str) -> List[Dict[str, Any]]:
    """Retrieves all evidence events for a session ordered chronologically."""
    query = text("""
        SELECT * FROM deception_events
        WHERE session_id = :sid
        ORDER BY created_at ASC;
    """)
    rows = db.execute(query, {"sid": session_id}).fetchall()
    return [row_to_event_dict(r) for r in rows]


def list_deception_sessions(db: Session, limit: int = 50, offset: int = 0, status: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves paginated deception sessions."""
    if status:
        query = text("""
            SELECT * FROM deception_sessions
            WHERE status = :status
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset;
        """)
        rows = db.execute(query, {"status": status, "limit": limit, "offset": offset}).fetchall()
    else:
        query = text("""
            SELECT * FROM deception_sessions
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset;
        """)
        rows = db.execute(query, {"limit": limit, "offset": offset}).fetchall()
    return [row_to_session_dict(r) for r in rows]


def list_deception_events(db: Session, limit: int = 50, offset: int = 0, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves paginated deception evidence events."""
    if event_type:
        query = text("""
            SELECT * FROM deception_events
            WHERE event_type = :event_type
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset;
        """)
        rows = db.execute(query, {"event_type": event_type, "limit": limit, "offset": offset}).fetchall()
    else:
        query = text("""
            SELECT * FROM deception_events
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset;
        """)
        rows = db.execute(query, {"limit": limit, "offset": offset}).fetchall()
    return [row_to_event_dict(r) for r in rows]


def get_deception_stats(db: Session) -> Dict[str, Any]:
    """Returns aggregated real metrics for the SOC deception panel."""
    # Count sessions by status
    status_query = text("""
        SELECT 
            COUNT(*) as total,
            COUNT(*) FILTER (WHERE status = 'ACTIVE' AND expires_at > CURRENT_TIMESTAMP) as active,
            COUNT(*) FILTER (WHERE status = 'TERMINATED') as terminated,
            COUNT(*) FILTER (WHERE status = 'EXPIRED' OR (status = 'ACTIVE' AND expires_at <= CURRENT_TIMESTAMP)) as expired,
            COUNT(*) FILTER (WHERE status = 'DENIED') as denied
        FROM deception_sessions;
    """)
    stats_row = db.execute(status_query).fetchone()

    # Total evidence events
    ev_count = db.execute(text("SELECT COUNT(*) FROM deception_events;")).scalar() or 0

    recent_sessions = list_deception_sessions(db, limit=5)
    recent_events = list_deception_events(db, limit=8)

    return {
        "total_sessions": stats_row.total if stats_row else 0,
        "active_sessions": stats_row.active if stats_row else 0,
        "terminated_sessions": stats_row.terminated if stats_row else 0,
        "expired_sessions": stats_row.expired if stats_row else 0,
        "denied_sessions": stats_row.denied if stats_row else 0,
        "total_evidence_events": ev_count,
        "recent_sessions": recent_sessions,
        "recent_events": recent_events,
        "disclaimer": "Decoy environment operates on a dedicated isolated Docker network without access to production database, host filesystem, or real origin application."
    }
