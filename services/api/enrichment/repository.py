"""
Database Repository for Attacker Intelligence, Source Profiles, Network Recon, and MITRE tables.
"""

from datetime import datetime, timezone
import json
import logging
from typing import List, Dict, Any, Optional
from sqlalchemy import text
from sqlalchemy.orm import Session
from enrichment.models import (
    GeoIPContext,
    ThreatIntelResult,
    ClientFingerprint,
    MitreMapping,
    NetworkObservationCreate
)

logger = logging.getLogger("aegis.enrichment.repository")


def upsert_source_profile(
    db: Session,
    source_ip: str,
    fingerprint: Optional[ClientFingerprint] = None,
    geoip: Optional[GeoIPContext] = None,
    threat_intel: Optional[ThreatIntelResult] = None,
    user_agent: Optional[str] = None
) -> None:
    """Insert or update an observed attacker/source profile in PostgreSQL."""
    if not source_ip:
        return

    fp_str = fingerprint.fingerprint if fingerprint else None
    is_priv = geoip.is_private if geoip else False
    country = geoip.country if geoip else None
    country_code = geoip.country_code if geoip else None
    region = geoip.region if geoip else None
    city = geoip.city if geoip else None
    lat = geoip.latitude if geoip else None
    lon = geoip.longitude if geoip else None
    tz = geoip.timezone if geoip else None
    asn = geoip.asn if geoip else None
    org = geoip.organization if geoip else None
    isp = geoip.isp if geoip else None

    rep_status = threat_intel.status if threat_intel else "UNKNOWN"
    rep_provider = threat_intel.provider if threat_intel else None
    rep_checked = datetime.now(timezone.utc) if (threat_intel and threat_intel.checked_at) else None

    stmt = text("""
        INSERT INTO source_profiles (
            source_ip, client_fingerprint, user_agent, is_private,
            country, country_code, region, city, latitude, longitude, timezone,
            asn, organization, isp, first_seen, last_seen, request_count,
            reputation_status, reputation_provider, reputation_checked_at
        ) VALUES (
            :source_ip, :client_fingerprint, :user_agent, :is_private,
            :country, :country_code, :region, :city, :latitude, :longitude, :timezone,
            :asn, :organization, :isp, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1,
            :reputation_status, :reputation_provider, :reputation_checked_at
        )
        ON CONFLICT (source_ip) DO UPDATE SET
            last_seen = CURRENT_TIMESTAMP,
            request_count = source_profiles.request_count + 1,
            client_fingerprint = COALESCE(EXCLUDED.client_fingerprint, source_profiles.client_fingerprint),
            user_agent = COALESCE(EXCLUDED.user_agent, source_profiles.user_agent),
            country = COALESCE(EXCLUDED.country, source_profiles.country),
            country_code = COALESCE(EXCLUDED.country_code, source_profiles.country_code),
            asn = COALESCE(EXCLUDED.asn, source_profiles.asn),
            organization = COALESCE(EXCLUDED.organization, source_profiles.organization),
            isp = COALESCE(EXCLUDED.isp, source_profiles.isp),
            reputation_status = COALESCE(EXCLUDED.reputation_status, source_profiles.reputation_status),
            reputation_provider = COALESCE(EXCLUDED.reputation_provider, source_profiles.reputation_provider);
    """)

    try:
        db.execute(stmt, {
            "source_ip": source_ip,
            "client_fingerprint": fp_str,
            "user_agent": user_agent,
            "is_private": is_priv,
            "country": country,
            "country_code": country_code,
            "region": region,
            "city": city,
            "latitude": lat,
            "longitude": lon,
            "timezone": tz,
            "asn": asn,
            "organization": org,
            "isp": isp,
            "reputation_status": rep_status,
            "reputation_provider": rep_provider,
            "reputation_checked_at": rep_checked
        })
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to upsert source_profile for {source_ip}: {e}")


def save_mitre_mapping(db: Session, mapping: MitreMapping) -> None:
    """Persist a verified MITRE mapping into PostgreSQL."""
    stmt = text("""
        INSERT INTO mitre_mappings (
            mapping_id, technique_id, technique_name, tactic,
            evidence_event_ids, confidence, reason, request_id, trace_id, source_ip, created_at
        ) VALUES (
            :mapping_id, :technique_id, :technique_name, :tactic,
            CAST(:evidence_event_ids AS jsonb), :confidence, :reason, :request_id, :trace_id, :source_ip, CURRENT_TIMESTAMP
        )
        ON CONFLICT (mapping_id) DO NOTHING;
    """)
    try:
        db.execute(stmt, {
            "mapping_id": mapping.mapping_id,
            "technique_id": mapping.technique_id,
            "technique_name": mapping.technique_name,
            "tactic": mapping.tactic,
            "evidence_event_ids": json.dumps(mapping.evidence_event_ids),
            "confidence": mapping.confidence,
            "reason": mapping.reason,
            "request_id": mapping.request_id,
            "trace_id": mapping.trace_id,
            "source_ip": mapping.source_ip
        })
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to persist mitre mapping {mapping.mapping_id}: {e}")


def save_network_observation(db: Session, obs: NetworkObservationCreate, observation_id: str) -> None:
    """Save an external network reconnaissance sensor observation (Zeek / Suricata)."""
    stmt = text("""
        INSERT INTO network_observations (
            observation_id, sensor, event_type, source_ip,
            destination_ip, destination_port, protocol,
            ports_observed, connection_count, scan_indicator,
            confidence, metadata, created_at
        ) VALUES (
            :observation_id, :sensor, :event_type, :source_ip,
            :destination_ip, :destination_port, :protocol,
            :ports_observed, :connection_count, :scan_indicator,
            :confidence, CAST(:metadata AS jsonb), CURRENT_TIMESTAMP
        )
        ON CONFLICT (observation_id) DO NOTHING;
    """)
    try:
        db.execute(stmt, {
            "observation_id": observation_id,
            "sensor": obs.sensor,
            "event_type": obs.event_type,
            "source_ip": obs.source_ip,
            "destination_ip": obs.destination_ip,
            "destination_port": obs.destination_port,
            "protocol": obs.protocol,
            "ports_observed": obs.ports_observed,
            "connection_count": obs.connection_count,
            "scan_indicator": obs.scan_indicator,
            "confidence": obs.confidence,
            "metadata": json.dumps(obs.metadata)
        })
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to save network observation {observation_id}: {e}")


def get_source_profile_by_ip(db: Session, source_ip: str) -> Optional[Dict[str, Any]]:
    """Retrieve full profile, risk history, and MITRE mappings for an IP."""
    stmt = text("""
        SELECT * FROM source_profiles WHERE source_ip = :source_ip LIMIT 1;
    """)
    res = db.execute(stmt, {"source_ip": source_ip}).fetchone()
    if not res:
        return None

    # Fetch associated MITRE mappings
    m_stmt = text("""
        SELECT * FROM mitre_mappings WHERE source_ip = :source_ip ORDER BY created_at DESC LIMIT 20;
    """)
    m_rows = db.execute(m_stmt, {"source_ip": source_ip}).fetchall()
    mitre_list = []
    for r in m_rows:
        ev = r.evidence_event_ids if isinstance(r.evidence_event_ids, list) else (json.loads(r.evidence_event_ids) if r.evidence_event_ids else [])
        mitre_list.append({
            "mapping_id": r.mapping_id,
            "technique_id": r.technique_id,
            "technique_name": r.technique_name,
            "tactic": r.tactic,
            "evidence_event_ids": ev,
            "confidence": float(r.confidence) if r.confidence else 1.0,
            "reason": r.reason,
            "request_id": r.request_id,
            "trace_id": r.trace_id,
            "source_ip": r.source_ip,
            "created_at": r.created_at.isoformat() if hasattr(r.created_at, "isoformat") else str(r.created_at)
        })

    # Fetch latest risk assessment if available
    risk_stmt = text("""
        SELECT ra.risk_score, ra.severity, ra.signals
        FROM security_events se
        JOIN risk_assessments ra ON se.request_id = ra.request_id
        WHERE se.source_ip = :source_ip
        ORDER BY ra.created_at DESC LIMIT 1;
    """)
    risk_row = db.execute(risk_stmt, {"source_ip": source_ip}).fetchone()

    # Fetch latest AgentShield assessment if available
    as_stmt = text("""
        SELECT asa.agent_shield_score, asa.attack_stages, asa.signals
        FROM security_events se
        JOIN agent_shield_assessments asa ON se.request_id = asa.request_id
        WHERE se.source_ip = :source_ip
        ORDER BY asa.created_at DESC LIMIT 1;
    """)
    as_row = db.execute(as_stmt, {"source_ip": source_ip}).fetchone()

    # Fetch latest policy decision if available
    pd_stmt = text("""
        SELECT pd.decision
        FROM security_events se
        JOIN policy_decisions pd ON se.request_id = pd.request_id
        WHERE se.source_ip = :source_ip
        ORDER BY pd.created_at DESC LIMIT 1;
    """)
    pd_row = db.execute(pd_stmt, {"source_ip": source_ip}).fetchone()

    # Determine observed behaviors
    behaviors = []
    if as_row and as_row.signals:
        raw_sig = as_row.signals if isinstance(as_row.signals, list) else json.loads(as_row.signals)
        behaviors.extend([s.get("type", str(s)) if isinstance(s, dict) else str(s) for s in raw_sig])

    return {
        "source_ip": res.source_ip,
        "client_fingerprint": res.client_fingerprint,
        "user_agent": res.user_agent,
        "is_private": res.is_private,
        "country": res.country,
        "country_code": res.country_code,
        "region": res.region,
        "city": res.city,
        "latitude": float(res.latitude) if res.latitude else None,
        "longitude": float(res.longitude) if res.longitude else None,
        "timezone": res.timezone,
        "asn": res.asn,
        "organization": res.organization,
        "isp": res.isp,
        "first_seen": res.first_seen.isoformat() if hasattr(res.first_seen, "isoformat") else str(res.first_seen),
        "last_seen": res.last_seen.isoformat() if hasattr(res.last_seen, "isoformat") else str(res.last_seen),
        "request_count": res.request_count or 1,
        "session_count": res.session_count or 0,
        "reputation_status": res.reputation_status or "UNKNOWN",
        "reputation_provider": res.reputation_provider,
        "reputation_checked_at": res.reputation_checked_at.isoformat() if res.reputation_checked_at else None,
        "mitre_mappings": mitre_list,
        "observed_behaviors": behaviors,
        "defense_status": "CONTAINED" if (pd_row and pd_row.decision in ("BLOCK", "DECEIVE_ELIGIBLE")) else "OBSERVED",
        "latest_risk_score": risk_row.risk_score if risk_row else None,
        "latest_agentshield_score": as_row.agent_shield_score if as_row else None,
        "latest_policy_decision": pd_row.decision if pd_row else None
    }


def list_source_profiles(db: Session, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """List source profiles with most recently active first."""
    stmt = text("""
        SELECT * FROM source_profiles ORDER BY last_seen DESC LIMIT :limit OFFSET :offset;
    """)
    rows = db.execute(stmt, {"limit": limit, "offset": offset}).fetchall()
    return [
        {
            "source_ip": r.source_ip,
            "client_fingerprint": r.client_fingerprint,
            "user_agent": r.user_agent,
            "is_private": r.is_private,
            "country": r.country,
            "country_code": r.country_code,
            "asn": r.asn,
            "organization": r.organization,
            "first_seen": r.first_seen.isoformat() if hasattr(r.first_seen, "isoformat") else str(r.first_seen),
            "last_seen": r.last_seen.isoformat() if hasattr(r.last_seen, "isoformat") else str(r.last_seen),
            "request_count": r.request_count or 1,
            "reputation_status": r.reputation_status or "UNKNOWN",
            "reputation_provider": r.reputation_provider
        }
        for r in rows
    ]


def list_mitre_mappings(db: Session, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """List all persisted MITRE ATT&CK mappings."""
    stmt = text("""
        SELECT * FROM mitre_mappings ORDER BY created_at DESC LIMIT :limit OFFSET :offset;
    """)
    rows = db.execute(stmt, {"limit": limit, "offset": offset}).fetchall()
    return [
        {
            "mapping_id": r.mapping_id,
            "technique_id": r.technique_id,
            "technique_name": r.technique_name,
            "tactic": r.tactic,
            "evidence_event_ids": r.evidence_event_ids if isinstance(r.evidence_event_ids, list) else (json.loads(r.evidence_event_ids) if r.evidence_event_ids else []),
            "confidence": float(r.confidence) if r.confidence else 1.0,
            "reason": r.reason,
            "request_id": r.request_id,
            "trace_id": r.trace_id,
            "source_ip": r.source_ip,
            "created_at": r.created_at.isoformat() if hasattr(r.created_at, "isoformat") else str(r.created_at)
        }
        for r in rows
    ]


def list_network_observations(db: Session, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """List network sensor observations."""
    stmt = text("""
        SELECT * FROM network_observations ORDER BY created_at DESC LIMIT :limit OFFSET :offset;
    """)
    rows = db.execute(stmt, {"limit": limit, "offset": offset}).fetchall()
    return [
        {
            "observation_id": r.observation_id,
            "sensor": r.sensor,
            "event_type": r.event_type,
            "source_ip": r.source_ip,
            "destination_ip": r.destination_ip,
            "destination_port": r.destination_port,
            "protocol": r.protocol,
            "ports_observed": r.ports_observed,
            "connection_count": r.connection_count,
            "scan_indicator": r.scan_indicator,
            "confidence": float(r.confidence) if r.confidence else 1.0,
            "metadata": r.metadata if isinstance(r.metadata, dict) else (json.loads(r.metadata) if r.metadata else {}),
            "created_at": r.created_at.isoformat() if hasattr(r.created_at, "isoformat") else str(r.created_at)
        }
        for r in rows
    ]
