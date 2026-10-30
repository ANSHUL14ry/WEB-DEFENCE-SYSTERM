"""
AEGIS Ω — Network Defense PostgreSQL Database Repository (Phase 11)
Handles persistence and querying for network_events, network_enforcements,
network_anomalies, and attack_stories.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Dict, Any, List, Optional
from sqlalchemy import text
from sqlalchemy.orm import Session
from network_defense.models import (
    NormalizedNetworkEvent,
    NetworkEnforcementRecord,
    NetworkAnomalyReport,
    AttackStoryModel
)

logger = logging.getLogger("aegis.network_defense.repository")


def save_network_event(db: Session, event: NormalizedNetworkEvent) -> None:
    """Insert normalized network event into PostgreSQL."""
    stmt = text("""
        INSERT INTO network_events (
            event_id, sensor, sensor_event_id, event_type, source_ip, destination_ip,
            source_port, destination_port, protocol, severity, signature, signature_id,
            category, raw_reference, request_id, trace_id, network_risk_score,
            mitre_technique_id, enforcement_action, raw_metadata, timestamp, created_at
        ) VALUES (
            :event_id, :sensor, :sensor_event_id, :event_type, :source_ip, :destination_ip,
            :source_port, :destination_port, :protocol, :severity, :signature, :signature_id,
            :category, :raw_reference, :request_id, :trace_id, :network_risk_score,
            :mitre_technique_id, :enforcement_action, CAST(:raw_metadata AS jsonb),
            :timestamp, CURRENT_TIMESTAMP
        )
        ON CONFLICT (event_id) DO NOTHING;
    """)
    try:
        db.execute(stmt, {
            "event_id": event.event_id,
            "sensor": event.sensor,
            "sensor_event_id": event.sensor_event_id,
            "event_type": event.event_type,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "source_port": event.source_port,
            "destination_port": event.destination_port,
            "protocol": event.protocol,
            "severity": event.severity,
            "signature": event.signature,
            "signature_id": event.signature_id,
            "category": event.category,
            "raw_reference": event.raw_reference,
            "request_id": event.request_id,
            "trace_id": event.trace_id,
            "network_risk_score": event.network_risk_score,
            "mitre_technique_id": event.mitre_technique_id,
            "enforcement_action": event.enforcement_action,
            "raw_metadata": json.dumps(event.raw_metadata),
            "timestamp": event.timestamp
        })
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to persist network_event {event.event_id}: {e}")


def save_enforcement_record(db: Session, rec: NetworkEnforcementRecord) -> None:
    """Save or update IPS enforcement state in PostgreSQL."""
    stmt = text("""
        INSERT INTO network_enforcements (
            enforcement_id, source_ip, action, status, rate_limit_rps,
            duration_seconds, reason, trigger_event_id, network_risk_score,
            expires_at, created_at, released_at, audit_metadata
        ) VALUES (
            :enforcement_id, :source_ip, :action, :status, :rate_limit_rps,
            :duration_seconds, :reason, :trigger_event_id, :network_risk_score,
            :expires_at, :created_at, :released_at, CAST(:audit_metadata AS jsonb)
        )
        ON CONFLICT (enforcement_id) DO UPDATE SET
            status = EXCLUDED.status,
            released_at = EXCLUDED.released_at,
            audit_metadata = EXCLUDED.audit_metadata;
    """)
    try:
        db.execute(stmt, {
            "enforcement_id": rec.enforcement_id,
            "source_ip": rec.source_ip,
            "action": rec.action,
            "status": rec.status,
            "rate_limit_rps": rec.rate_limit_rps,
            "duration_seconds": rec.duration_seconds,
            "reason": rec.reason,
            "trigger_event_id": rec.trigger_event_id,
            "network_risk_score": rec.network_risk_score,
            "expires_at": rec.expires_at,
            "created_at": rec.created_at,
            "released_at": rec.released_at,
            "audit_metadata": json.dumps(rec.audit_metadata)
        })
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to persist network enforcement {rec.enforcement_id}: {e}")


def save_anomaly_report(db: Session, report: NetworkAnomalyReport) -> None:
    """Persist anomaly evaluation into PostgreSQL."""
    stmt = text("""
        INSERT INTO network_anomalies (
            anomaly_id, anomaly_type, severity, source_ip, destination_ip,
            metric_name, current_value, baseline_value, deviation_factor,
            mitigation_recommendation, details, created_at
        ) VALUES (
            :anomaly_id, :anomaly_type, :severity, :source_ip, :destination_ip,
            :metric_name, :current_value, :baseline_value, :deviation_factor,
            :mitigation_recommendation, CAST(:details AS jsonb), CURRENT_TIMESTAMP
        )
        ON CONFLICT (anomaly_id) DO NOTHING;
    """)
    try:
        db.execute(stmt, {
            "anomaly_id": report.anomaly_id,
            "anomaly_type": report.anomaly_type,
            "severity": report.severity,
            "source_ip": report.source_ip,
            "destination_ip": report.destination_ip,
            "metric_name": report.metric_name,
            "current_value": report.current_value,
            "baseline_value": report.baseline_value,
            "deviation_factor": report.deviation_factor,
            "mitigation_recommendation": report.mitigation_recommendation,
            "details": json.dumps(report.details)
        })
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to persist network anomaly {report.anomaly_id}: {e}")


def list_recent_network_events(db: Session, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    stmt = text("""
        SELECT event_id, sensor, event_type, source_ip, destination_ip,
               source_port, destination_port, protocol, severity, signature,
               category, network_risk_score, mitre_technique_id, enforcement_action,
               raw_metadata, timestamp, created_at
        FROM network_events
        ORDER BY timestamp DESC LIMIT :limit OFFSET :offset;
    """)
    rows = db.execute(stmt, {"limit": limit, "offset": offset}).fetchall()
    return [
        {
            "event_id": r[0],
            "sensor": r[1],
            "event_type": r[2],
            "source_ip": r[3],
            "destination_ip": r[4],
            "source_port": r[5],
            "destination_port": r[6],
            "protocol": r[7],
            "severity": r[8],
            "signature": r[9],
            "category": r[10],
            "network_risk_score": r[11],
            "mitre_technique_id": r[12],
            "enforcement_action": r[13],
            "metadata": r[14] if isinstance(r[14], dict) else (json.loads(r[14]) if r[14] else {}),
            "timestamp": r[15].isoformat() if hasattr(r[15], "isoformat") else str(r[15]),
            "created_at": r[16].isoformat() if hasattr(r[16], "isoformat") else str(r[16])
        }
        for r in rows
    ]


def get_network_defense_stats(db: Session) -> Dict[str, Any]:
    """Retrieve statistical aggregates for the Network Defense dashboard."""
    total_events = db.execute(text("SELECT COUNT(*) FROM network_events")).scalar() or 0
    alerts_count = db.execute(text("SELECT COUNT(*) FROM network_events WHERE event_type = 'ALERT'")).scalar() or 0
    active_enforcements = db.execute(text("SELECT COUNT(*) FROM network_enforcements WHERE status = 'ACTIVE'")).scalar() or 0
    anomalies_count = db.execute(text("SELECT COUNT(*) FROM network_anomalies WHERE severity IN ('ANOMALOUS', 'CRITICAL')")).scalar() or 0

    # Top sources
    top_src_rows = db.execute(text("""
        SELECT source_ip, COUNT(*) as cnt
        FROM network_events
        GROUP BY source_ip
        ORDER BY cnt DESC LIMIT 5;
    """)).fetchall()

    # Protocol distribution
    proto_rows = db.execute(text("""
        SELECT protocol, COUNT(*) as cnt
        FROM network_events
        GROUP BY protocol
        ORDER BY cnt DESC LIMIT 5;
    """)).fetchall()

    return {
        "total_network_events": total_events,
        "ids_alerts_count": alerts_count,
        "active_enforcements_count": active_enforcements,
        "anomalies_detected": anomalies_count,
        "top_sources": [{"ip": r[0], "count": r[1]} for r in top_src_rows],
        "protocol_distribution": {r[0] or "TCP": r[1] for r in proto_rows}
    }
