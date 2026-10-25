"""
Orchestration service for Attacker Intelligence, Threat Context, and MITRE Mapping.
Failure-safe: Enrichment failures never crash the event ingestion pipeline.
"""

from datetime import datetime, timezone
import logging
import uuid
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session

from enrichment.models import (
    GeoIPContext,
    ThreatIntelResult,
    ClientFingerprint,
    TLSFingerprint,
    MitreMapping,
    NetworkObservationCreate
)
from enrichment.geoip import lookup_geoip
from enrichment.fingerprint import generate_client_fingerprint, get_tls_fingerprint
from enrichment.threat_intel import get_threat_intel_provider
from enrichment.mitre import map_mitre_techniques
from enrichment.repository import (
    upsert_source_profile,
    save_mitre_mapping,
    save_network_observation,
    get_source_profile_by_ip
)
from broadcaster import broadcaster

logger = logging.getLogger("aegis.enrichment.service")


async def enrich_security_event(
    event: Dict[str, Any],
    db: Session,
    risk_assessment: Optional[Dict[str, Any]] = None,
    agent_shield: Optional[Dict[str, Any]] = None,
    policy_decision: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Enrich an ingested security event with GeoIP, client fingerprint, threat intel, and MITRE mappings.
    Safe and isolated: Returns gracefully on any partial failure.
    """
    source_ip = event.get("source", {}).get("ip") if isinstance(event.get("source"), dict) else event.get("source_ip")
    user_agent = event.get("source", {}).get("user_agent") if isinstance(event.get("source"), dict) else event.get("user_agent")
    meta = event.get("metadata") or {}
    headers = meta.get("headers") if isinstance(meta.get("headers"), dict) else {}

    # 1. GeoIP & ASN
    try:
        geoip_ctx = lookup_geoip(source_ip or "")
    except Exception as e:
        logger.warning(f"GeoIP lookup error: {e}")
        geoip_ctx = GeoIPContext(is_private=True, display_label="UNKNOWN")

    # 2. HTTP Client & TLS Fingerprint
    try:
        http_fp = generate_client_fingerprint(
            headers=headers,
            user_agent=user_agent,
            http_version=event.get("request", {}).get("http_version", "HTTP/1.1")
        )
    except Exception as e:
        logger.warning(f"Fingerprinting error: {e}")
        http_fp = ClientFingerprint(fingerprint="unknown", method="SHA256")

    tls_fp = get_tls_fingerprint(headers)

    # 3. IP Reputation & Threat Intelligence
    try:
        ti_provider = get_threat_intel_provider()
        ti_result = ti_provider.lookup_ip(source_ip or "")
    except Exception as e:
        logger.warning(f"Threat intel error: {e}")
        ti_result = ThreatIntelResult(indicator=source_ip or "unknown", status="NOT AVAILABLE")

    # 4. Deterministic MITRE ATT&CK Mapping (Strict evidence check)
    mitre_list: List[MitreMapping] = []
    try:
        mitre_list = map_mitre_techniques(
            event=event,
            risk_assessment=risk_assessment,
            agent_shield=agent_shield,
            policy_decision=policy_decision
        )
        for m in mitre_list:
            save_mitre_mapping(db, m)
    except Exception as e:
        logger.warning(f"MITRE mapping error: {e}")

    # 5. Persist / Update Source Profile in DB
    try:
        if source_ip and source_ip.lower() not in ("unknown", ""):
            upsert_source_profile(
                db=db,
                source_ip=source_ip,
                fingerprint=http_fp,
                geoip=geoip_ctx,
                threat_intel=ti_result,
                user_agent=user_agent
            )
    except Exception as e:
        logger.error(f"Source profile update failed: {e}")

    # 6. Broadcast Real-Time Updates via WebSocket
    try:
        # Broadcast SOURCE_ENRICHED
        await broadcaster.broadcast({
            "event_type": "SOURCE_ENRICHED",
            "source_ip": source_ip,
            "is_private": geoip_ctx.is_private,
            "display_label": geoip_ctx.display_label,
            "country": geoip_ctx.country,
            "asn": geoip_ctx.asn,
            "fingerprint": http_fp.fingerprint[:16],
            "reputation_status": ti_result.status,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

        # Broadcast MITRE_TECHNIQUE_MAPPED if any new techniques mapped
        for m in mitre_list:
            await broadcaster.broadcast({
                "event_type": "MITRE_TECHNIQUE_MAPPED",
                "mapping_id": m.mapping_id,
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "tactic": m.tactic,
                "confidence": m.confidence,
                "reason": m.reason,
                "evidence_event_ids": m.evidence_event_ids,
                "source_ip": source_ip,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
    except Exception as e:
        logger.debug(f"WebSocket broadcast error in enrichment: {e}")

    return {
        "geoip": geoip_ctx.model_dump(),
        "asn": {
            "asn": geoip_ctx.asn,
            "organization": geoip_ctx.organization,
            "isp": geoip_ctx.isp
        },
        "reputation": ti_result.model_dump(),
        "threat_intelligence": [ti_result.model_dump()] if ti_result.status != "NOT_CONFIGURED" else [],
        "fingerprint": {
            "client": http_fp.model_dump(),
            "tls": tls_fp.model_dump()
        },
        "network_sensor": None,
        "mitre": [m.model_dump() for m in mitre_list]
    }


async def ingest_network_observation_event(
    obs: NetworkObservationCreate,
    db: Session
) -> Dict[str, Any]:
    """
    Ingest a network observation from Zeek or Suricata sensor.
    Stores in DB, checks for reconnaissance scan patterns, and broadcasts to SOC.
    """
    obs_id = f"netobs-{uuid.uuid4().hex[:12]}"
    save_network_observation(db, obs, obs_id)

    # MITRE ATT&CK check for network reconnaissance
    synthetic_event = {
        "event_id": obs_id,
        "event_type": "NETWORK_RECON_DETECTED",
        "source": {"ip": obs.source_ip},
        "source_ip": obs.source_ip,
        "metadata": {
            "sensor": obs.sensor,
            "event_type": obs.event_type,
            "ports_observed": obs.ports_observed
        }
    }
    mitre_list = map_mitre_techniques(
        event=synthetic_event,
        network_observation={
            "observation_id": obs_id,
            "sensor": obs.sensor,
            "event_type": obs.event_type
        }
    )
    for m in mitre_list:
        save_mitre_mapping(db, m)

    # Upsert source profile
    geoip_ctx = lookup_geoip(obs.source_ip)
    upsert_source_profile(
        db=db,
        source_ip=obs.source_ip,
        geoip=geoip_ctx,
        user_agent=f"Sensor: {obs.sensor} ({obs.event_type})"
    )

    # Broadcast NETWORK_RECON_DETECTED
    recon_payload = {
        "event_type": "NETWORK_RECON_DETECTED",
        "observation_id": obs_id,
        "sensor": obs.sensor,
        "recon_type": obs.event_type,
        "source_ip": obs.source_ip,
        "destination_ip": obs.destination_ip,
        "destination_port": obs.destination_port,
        "ports_observed": obs.ports_observed,
        "connection_count": obs.connection_count,
        "scan_indicator": obs.scan_indicator,
        "confidence": obs.confidence,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    await broadcaster.broadcast(recon_payload)

    return recon_payload
