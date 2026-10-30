"""
AEGIS Ω — Network Defense Orchestration Service (Phase 11)
Coordinates parsing, risk evaluation, policy decisions, IPS enforcement,
anomaly detection, and live WebSocket streaming.
"""

from datetime import datetime, timezone
import logging
from typing import Dict, Any, Optional
from sqlalchemy import text
from sqlalchemy.orm import Session

from network_defense.models import (
    NormalizedNetworkEvent,
    NetworkRiskAssessment,
    EnforcementAction
)
from network_defense.network_risk.evaluator import evaluate_network_risk
from network_defense.network_policy.policy import evaluate_network_policy
from network_defense.enforcement.adapter import get_enforcement_adapter
from network_defense.anomaly.detector import get_anomaly_detector
from network_defense.repository import (
    save_network_event,
    save_enforcement_record,
    save_anomaly_report
)
from enrichment.mitre import map_mitre_techniques
from enrichment.repository import save_mitre_mapping, upsert_source_profile
from enrichment.geoip import lookup_geoip
from broadcaster import broadcaster

logger = logging.getLogger("aegis.network_defense.service")


async def process_incoming_network_event(
    event: NormalizedNetworkEvent,
    db: Session
) -> Dict[str, Any]:
    """
    Complete pipeline processing for a normalized network event.
    """
    src_ip = event.source_ip

    # 1. Fetch historical counts for this IP for risk context
    recent_cnt = db.execute(
        text("SELECT COUNT(*) FROM network_events WHERE source_ip = :ip"),
        {"ip": src_ip}
    ).scalar() or 0

    unique_ports = db.execute(
        text("SELECT COUNT(DISTINCT destination_port) FROM network_events WHERE source_ip = :ip"),
        {"ip": src_ip}
    ).scalar() or 1

    # Check if this IP triggered any application WAF blocks recently
    waf_corr = (db.execute(
        text("SELECT COUNT(*) FROM security_events WHERE source_ip = :ip AND event_type IN ('WAF_BLOCK', 'WAF_DETECTION')"),
        {"ip": src_ip}
    ).scalar() or 0) > 0

    # 2. Evaluate Network Risk
    risk_assessment: NetworkRiskAssessment = evaluate_network_risk(
        event=event,
        recent_events_count=recent_cnt + 1,
        unique_ports_count=unique_ports + (1 if event.destination_port else 0),
        has_http_waf_correlation=waf_corr
    )
    event.network_risk_score = risk_assessment.network_risk_score

    # 3. MITRE ATT&CK Mapping (Evidence-Backed)
    synth_sec_event = {
        "event_id": event.event_id,
        "event_type": "NETWORK_ALERT" if event.event_type == "ALERT" else "NETWORK_RECON_DETECTED",
        "source": {"ip": event.source_ip},
        "source_ip": event.source_ip,
        "metadata": {
            "signature": event.signature,
            "category": event.category,
            "destination_port": event.destination_port,
            "ports_observed": str(event.destination_port or ""),
            "rule_id": str(event.signature_id or "")
        }
    }
    net_obs = {
        "observation_id": event.event_id,
        "sensor": event.sensor,
        "event_type": event.event_type
    }
    mitre_list = map_mitre_techniques(synth_sec_event, network_observation=net_obs)
    for m in mitre_list:
        save_mitre_mapping(db, m)
        if not event.mitre_technique_id:
            event.mitre_technique_id = m.technique_id

    # 4. Evaluate Network Policy
    action, policy_reason = evaluate_network_policy(
        network_risk_score=risk_assessment.network_risk_score,
        waf_blocked=waf_corr
    )
    event.enforcement_action = action.value

    # 5. Persist Normalized Event
    save_network_event(db, event)

    # 6. Execute IPS Enforcement via Adapter
    adapter = get_enforcement_adapter()
    if action == EnforcementAction.BLOCK:
        enf_rec = adapter.block(src_ip, reason=policy_reason, trigger_event_id=event.event_id)
    elif action == EnforcementAction.TEMP_BLOCK:
        enf_rec = adapter.temporary_block(src_ip, duration_seconds=300, reason=policy_reason, trigger_event_id=event.event_id)
    elif action == EnforcementAction.RATE_LIMIT:
        enf_rec = adapter.rate_limit(src_ip, rps=10, duration_seconds=300, reason=policy_reason, trigger_event_id=event.event_id)
    else:
        enf_rec = adapter.observe(src_ip, reason=policy_reason, trigger_event_id=event.event_id)

    enf_rec.network_risk_score = risk_assessment.network_risk_score
    save_enforcement_record(db, enf_rec)

    # 7. Anomaly Detector
    anomaly_detector = get_anomaly_detector()
    anomaly_detector.record_connection(src_ip)
    # Estimate instantaneous rate based on recent frequency
    est_rate = float(recent_cnt + 1)
    anomaly_report = anomaly_detector.analyze_traffic(
        current_event_rate=est_rate,
        source_ip=src_ip,
        destination_ip=event.destination_ip
    )
    if anomaly_report.severity in ("ANOMALOUS", "CRITICAL"):
        save_anomaly_report(db, anomaly_report)

    # 8. Update Source Profile in PostgreSQL
    geoip_ctx = lookup_geoip(src_ip)
    upsert_source_profile(
        db=db,
        source_ip=src_ip,
        geoip=geoip_ctx,
        user_agent=f"Sensor: {event.sensor} ({event.signature or event.event_type})"
    )

    # 9. Real-time WebSocket Notifications
    ws_payload = {
        "event_type": "NETWORK_EVENT_INGESTED",
        "event_id": event.event_id,
        "sensor": event.sensor,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "protocol": event.protocol,
        "port": event.destination_port,
        "signature": event.signature or event.event_type,
        "severity": event.severity,
        "network_risk_score": event.network_risk_score,
        "mitre_technique_id": event.mitre_technique_id,
        "enforcement_action": event.enforcement_action,
        "timestamp": event.timestamp,
        "data": {
            "source_ip": event.source_ip,
            "event_id": event.event_id,
            "sensor": event.sensor,
            "severity": event.severity,
            "signature": event.signature or event.event_type
        }
    }
    await broadcaster.broadcast(ws_payload)

    if action in (EnforcementAction.BLOCK, EnforcementAction.TEMP_BLOCK, EnforcementAction.RATE_LIMIT):
        await broadcaster.broadcast({
            "event_type": "NETWORK_ENFORCEMENT_ACTION",
            "enforcement_id": enf_rec.enforcement_id,
            "source_ip": src_ip,
            "action": enf_rec.action,
            "status": enf_rec.status,
            "reason": enf_rec.reason,
            "expires_at": enf_rec.expires_at,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    if anomaly_report.severity in ("ANOMALOUS", "CRITICAL"):
        await broadcaster.broadcast({
            "event_type": "NETWORK_ANOMALY_DETECTED",
            "anomaly_id": anomaly_report.anomaly_id,
            "severity": anomaly_report.severity,
            "source_ip": src_ip,
            "deviation_factor": anomaly_report.deviation_factor,
            "recommendation": anomaly_report.mitigation_recommendation,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    return {
        "status": "processed",
        "event_id": event.event_id,
        "network_risk": risk_assessment.model_dump(),
        "policy_action": action.value,
        "enforcement": enf_rec.model_dump(),
        "anomaly": anomaly_report.model_dump()
    }
