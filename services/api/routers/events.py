"""
AEGIS Ω — Normalized Security Event Pipeline Router
Handles internal event ingestion, deduplication, correlation, querying, and live WebSocket streaming.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
import uuid
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import text
from sqlalchemy.orm import Session

from database import get_db
from models.events import (
    SecurityEventCreate,
    SecurityEventResponse,
    SourceInfo,
    RequestInfo,
    sanitize_value
)
from broadcaster import broadcaster
from risk_engine.service import assess_event_risk

logger = logging.getLogger("aegis.event_pipeline")

router = APIRouter(prefix="/api/v1", tags=["events"])


def row_to_event_dict(row: Any) -> Dict[str, Any]:
    """Format a database row into a normalized event dict."""
    meta = row.metadata if isinstance(row.metadata, dict) else (json.loads(row.metadata) if row.metadata else {})
    return {
        "event_id": row.event_id,
        "event_type": row.event_type,
        "timestamp": row.timestamp.isoformat() if hasattr(row.timestamp, "isoformat") else str(row.timestamp),
        "request_id": row.request_id,
        "trace_id": row.trace_id,
        "session_id": row.session_id,
        "source": {
            "ip": row.source_ip or "unknown",
            "user_agent": row.user_agent
        },
        "request": {
            "method": row.method or "GET",
            "uri": row.uri or "/"
        },
        "severity": row.severity,
        "action": row.action,
        "component": row.component,
        "status": row.status,
        "metadata": meta,
        "created_at": row.created_at.isoformat() if hasattr(row.created_at, "isoformat") else str(row.created_at)
    }


@router.post("/internal/events")
async def ingest_security_event(event: SecurityEventCreate, db: Session = Depends(get_db)):
    """
    Internal Event Ingestion API.
    Validates, sanitizes, deduplicates, persists into PostgreSQL, and broadcasts to live dashboards.
    """
    now = datetime.now(timezone.utc)
    ts = event.timestamp or now

    # Deterministic event ID for deduplication if not provided
    if not event.event_id:
        rule_or_tag = event.metadata.get("rule_id", event.event_type)
        ts_sec = int(ts.timestamp())
        raw_sig = f"{event.request_id}:{event.component}:{rule_or_tag}:{ts_sec}"
        event_id = hashlib.sha256(raw_sig.encode()).hexdigest()[:32]
    else:
        event_id = event.event_id

    # Sanitize sensitive fields
    sanitized_metadata = sanitize_value(event.metadata)
    sanitized_uri = sanitize_value(event.request.uri)

    insert_query = text("""
        INSERT INTO security_events (
            event_id, event_type, timestamp, request_id, trace_id,
            session_id, severity, action, component, status,
            source_ip, user_agent, method, uri, metadata, created_at
        ) VALUES (
            :event_id, :event_type, :timestamp, :request_id, :trace_id,
            :session_id, :severity, :action, :component, :status,
            :source_ip, :user_agent, :method, :uri, CAST(:metadata AS jsonb), CURRENT_TIMESTAMP
        )
        ON CONFLICT (event_id) DO NOTHING
        RETURNING event_id;
    """)

    try:
        result = db.execute(insert_query, {
            "event_id": event_id,
            "event_type": event.event_type,
            "timestamp": ts,
            "request_id": event.request_id,
            "trace_id": event.trace_id,
            "session_id": event.session_id,
            "severity": event.severity,
            "action": event.action,
            "component": event.component,
            "status": event.status,
            "source_ip": event.source.ip,
            "user_agent": event.source.user_agent,
            "method": event.request.method,
            "uri": sanitized_uri,
            "metadata": json.dumps(sanitized_metadata)
        })
        db.commit()

        inserted_row = result.fetchone()
        is_new = inserted_row is not None

        normalized_event = {
            "event_id": event_id,
            "event_type": event.event_type,
            "timestamp": ts.isoformat(),
            "request_id": event.request_id,
            "trace_id": event.trace_id,
            "session_id": event.session_id,
            "source": {"ip": event.source.ip, "user_agent": event.source.user_agent},
            "request": {"method": event.request.method, "uri": sanitized_uri},
            "severity": event.severity,
            "action": event.action,
            "component": event.component,
            "status": event.status,
            "metadata": sanitized_metadata,
            "created_at": now.isoformat()
        }

        # Broadcast live to connected dashboard WebSocket clients if new
        if is_new:
            await broadcaster.broadcast(normalized_event)
            logger.info(f"Ingested & broadcast security event [{event.event_type}] {event_id} ({event.severity})")

            # Phase 5: Automatic Risk Engine Evaluation (Failure-Safe)
            try:
                risk_assessment = assess_event_risk(normalized_event, db)
                if risk_assessment:
                    risk_update = {
                        "event_type": "RISK_SCORE_UPDATE",
                        "assessment_id": risk_assessment["assessment_id"],
                        "request_id": risk_assessment["request_id"],
                        "trace_id": risk_assessment["trace_id"],
                        "risk_score": risk_assessment["risk_score"],
                        "severity": risk_assessment["severity"],
                        "confidence": risk_assessment["confidence"],
                        "signals": risk_assessment["signals"],
                        "engine_version": risk_assessment["engine_version"],
                        "timestamp": risk_assessment["created_at"]
                    }
                    await broadcaster.broadcast(risk_update)
            except Exception as risk_err:
                logger.error(f"Automatic risk evaluation failed (failure-safe): {risk_err}")

            return {"status": "ingested", "event_id": event_id, "is_new": True}
        else:
            logger.debug(f"Duplicate event skipped: {event_id}")
            return {"status": "duplicate_skipped", "event_id": event_id, "is_new": False}

    except Exception as e:
        db.rollback()
        logger.error(f"Failed to ingest security event: {e}")
        raise HTTPException(status_code=500, detail="Database persistence failed")


@router.get("/events")
def list_events(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    component: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Paginated security event search with multi-field filtering.
    """
    conditions = []
    params: Dict[str, Any] = {"limit": limit, "offset": offset}

    if severity:
        conditions.append("severity = :severity")
        params["severity"] = severity.upper()

    if event_type:
        conditions.append("event_type = :event_type")
        params["event_type"] = event_type.upper()

    if component:
        conditions.append("component = :component")
        params["component"] = component.lower()

    if action:
        conditions.append("action = :action")
        params["action"] = action.upper()

    if search:
        conditions.append("(request_id ILIKE :search OR trace_id ILIKE :search OR uri ILIKE :search)")
        params["search"] = f"%{search}%"

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    count_query = text(f"SELECT COUNT(*) FROM security_events {where_clause}")
    total = db.execute(count_query, params).scalar() or 0

    select_query = text(f"""
        SELECT event_id, event_type, timestamp, request_id, trace_id,
               session_id, severity, action, component, status,
               source_ip, user_agent, method, uri, metadata, created_at
        FROM security_events
        {where_clause}
        ORDER BY timestamp DESC
        LIMIT :limit OFFSET :offset
    """)

    rows = db.execute(select_query, params).fetchall()
    events = [row_to_event_dict(r) for r in rows]

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": events
    }


@router.get("/events/stats")
def get_event_stats(db: Session = Depends(get_db)):
    """
    Real-time aggregated statistics directly from the database.
    No hard-coded or fabricated metrics. Returns exact zeros when empty.
    """
    stats_query = text("""
        SELECT 
            COUNT(*) as total_events,
            COUNT(*) FILTER (WHERE action = 'BLOCK') as waf_blocks,
            COUNT(*) FILTER (WHERE severity = 'HIGH') as high_severity,
            COUNT(*) FILTER (WHERE severity = 'CRITICAL') as critical_severity,
            COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours') as events_24h
        FROM security_events;
    """)

    row = db.execute(stats_query).fetchone()

    # Breakdown by type
    type_query = text("""
        SELECT event_type, COUNT(*) as count 
        FROM security_events 
        GROUP BY event_type;
    """)
    type_rows = db.execute(type_query).fetchall()
    by_type = {r.event_type: r.count for r in type_rows}

    # Breakdown by severity
    sev_query = text("""
        SELECT severity, COUNT(*) as count 
        FROM security_events 
        GROUP BY severity;
    """)
    sev_rows = db.execute(sev_query).fetchall()
    by_severity = {r.severity: r.count for r in sev_rows}

    return {
        "total_events": row.total_events if row else 0,
        "waf_blocks": row.waf_blocks if row else 0,
        "high_severity": row.high_severity if row else 0,
        "critical_severity": row.critical_severity if row else 0,
        "events_24h": row.events_24h if row else 0,
        "by_type": by_type,
        "by_severity": by_severity
    }


@router.get("/events/request/{request_id}")
def get_events_by_request_id(request_id: str, db: Session = Depends(get_db)):
    """Retrieve all correlated security events for a specific request ID."""
    query = text("""
        SELECT event_id, event_type, timestamp, request_id, trace_id,
               session_id, severity, action, component, status,
               source_ip, user_agent, method, uri, metadata, created_at
        FROM security_events
        WHERE request_id = :request_id
        ORDER BY timestamp ASC;
    """)
    rows = db.execute(query, {"request_id": request_id}).fetchall()
    return [row_to_event_dict(r) for r in rows]


@router.get("/events/trace/{trace_id}")
def get_events_by_trace_id(trace_id: str, db: Session = Depends(get_db)):
    """Retrieve all correlated security events across a request chain (trace ID)."""
    query = text("""
        SELECT event_id, event_type, timestamp, request_id, trace_id,
               session_id, severity, action, component, status,
               source_ip, user_agent, method, uri, metadata, created_at
        FROM security_events
        WHERE trace_id = :trace_id
        ORDER BY timestamp ASC;
    """)
    rows = db.execute(query, {"trace_id": trace_id}).fetchall()
    return [row_to_event_dict(r) for r in rows]


@router.get("/events/{event_id}")
def get_single_event(event_id: str, db: Session = Depends(get_db)):
    """Retrieve details for a single specific security event."""
    query = text("""
        SELECT event_id, event_type, timestamp, request_id, trace_id,
               session_id, severity, action, component, status,
               source_ip, user_agent, method, uri, metadata, created_at
        FROM security_events
        WHERE event_id = :event_id;
    """)
    row = db.execute(query, {"event_id": event_id}).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Security event not found")
    return row_to_event_dict(row)


@router.websocket("/ws/events")
async def security_events_websocket(websocket: WebSocket):
    """
    Real-time WebSocket endpoint for SOC dashboard live telemetry streaming.
    Clients receive new normalized security events instantaneously.
    """
    await broadcaster.connect(websocket)
    try:
        # Keep connection open and respond to ping/heartbeats
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await broadcaster.disconnect(websocket)
    except Exception as e:
        logger.debug(f"WebSocket closed with exception: {e}")
        await broadcaster.disconnect(websocket)
