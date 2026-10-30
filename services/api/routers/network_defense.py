import json
"""
AEGIS Ω — Network Defense REST Router (Phase 11)
Exposes endpoints for Network IDS telemetry, IPS enforcement, DoS anomalies,
unified attack stories, and controlled demonstration triggers.
"""

from datetime import datetime, timezone
import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Header
from sqlalchemy.orm import Session

from database import get_db
from network_defense.models import (
    NormalizedNetworkEvent,
    NetworkEnforcementRequest,
    EnforcementAction
)
from network_defense.config import netdef_settings
from network_defense.suricata_adapter.adapter import get_suricata_adapter
from network_defense.network_parser.parser import parse_eve_record
from network_defense.enforcement.adapter import get_enforcement_adapter
from network_defense.anomaly.detector import get_anomaly_detector
from network_defense.correlation.attack_story import build_attack_story_for_ip
from network_defense.repository import (
    list_recent_network_events,
    get_network_defense_stats
)
from network_defense.service import process_incoming_network_event

logger = logging.getLogger("aegis.network_defense.router")

router = APIRouter(prefix="/api/v1/network-defense", tags=["network-defense"])


@router.get("/status")
def get_network_defense_status(db: Session = Depends(get_db)):
    """Retrieve operational status, sensor health, and statistical summary."""
    suricata = get_suricata_adapter()
    stats = get_network_defense_stats(db)
    adapter = get_enforcement_adapter()
    active_enforcements = adapter.list_active()
    detector = get_anomaly_detector()

    return {
        "status": "operational",
        "subsystem": "AEGIS Real Network Defense (Phase 11)",
        "sensor": {
            "name": suricata.sensor_name,
            "status": suricata.get_status(),
            "eve_log_path": suricata.eve_path
        },
        "sensor_status": suricata.get_status(),
        "sensor_name": suricata.sensor_name,
        "enforcement_mode": netdef_settings.ENFORCEMENT_MODE,
        "active_enforcements_count": len(active_enforcements),
        "traffic_baseline_rps": round(detector.baseline.average_rate, 2),
        "stats": stats
    }


@router.get("/events")
def list_network_events(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Retrieve normalized network events (IDS alerts, flows, anomalies)."""
    events = list_recent_network_events(db, limit=limit, offset=offset)
    return {
        "status": "success",
        "count": len(events),
        "events": events
    }


@router.get("/enforcements")
def list_enforcements():
    """Retrieve currently active IPS blocks and rate-limits."""
    adapter = get_enforcement_adapter()
    return {
        "status": "success",
        "enforcements": [e.model_dump() for e in adapter.list_active()]
    }


@router.post("/enforce")
def apply_enforcement(req: NetworkEnforcementRequest):
    """Apply manual or policy-driven IPS enforcement action."""
    adapter = get_enforcement_adapter()
    if req.action == EnforcementAction.BLOCK:
        rec = adapter.block(req.source_ip, reason=req.reason, trigger_event_id=req.trigger_event_id)
    elif req.action == EnforcementAction.TEMP_BLOCK:
        rec = adapter.temporary_block(
            req.source_ip,
            duration_seconds=req.duration_seconds or 300,
            reason=req.reason,
            trigger_event_id=req.trigger_event_id
        )
    elif req.action == EnforcementAction.RATE_LIMIT:
        rec = adapter.rate_limit(
            req.source_ip,
            rps=req.rate_limit_rps or 10,
            duration_seconds=req.duration_seconds or 300,
            reason=req.reason,
            trigger_event_id=req.trigger_event_id
        )
    else:
        rec = adapter.observe(req.source_ip, reason=req.reason, trigger_event_id=req.trigger_event_id)

    return {
        "status": "applied",
        "enforcement": rec.model_dump()
    }


@router.post("/release/{source_ip}")
def release_enforcement(source_ip: str, reason: str = Query("Admin manual release")):
    """Release an active network block or rate-limit for an IP."""
    adapter = get_enforcement_adapter()
    rec = adapter.release(source_ip, reason=reason)
    if not rec:
        raise HTTPException(status_code=404, detail=f"No active enforcement found for IP: {source_ip}")
    return {
        "status": "released",
        "enforcement": rec.model_dump()
    }


@router.get("/attack-story/{source_ip}")
def get_attack_story(source_ip: str, db: Session = Depends(get_db)):
    """Retrieve reconstructed unified multi-stage attack story for an IP."""
    story = build_attack_story_for_ip(db, source_ip)
    if not story:
        raise HTTPException(status_code=404, detail=f"No telemetry available to build attack story for {source_ip}")
    return {
        "status": "success",
        "story": story.model_dump()
    }


@router.post("/ingest-eve")
async def ingest_suricata_eve_record(
    eve_payload: Dict[str, Any],
    db: Session = Depends(get_db)
):
    """Ingest raw Suricata EVE JSON dictionary directly."""
    if "eve_line" in eve_payload:
        raw_val = eve_payload["eve_line"]
        if isinstance(raw_val, str):
            try:
                eve_payload = json.loads(raw_val)
            except Exception:
                pass
        elif isinstance(raw_val, dict):
            eve_payload = raw_val

    norm_event = parse_eve_record(eve_payload, sensor_name=netdef_settings.SURICATA_SENSOR_NAME)
    if not norm_event:
        raise HTTPException(status_code=422, detail="Invalid EVE JSON record: missing valid src_ip or malformed structure.")

    result = await process_incoming_network_event(norm_event, db)
    return result


@router.post("/demo/trigger")
async def trigger_demo_scenario(
    scenario: str = Query(..., description="NORMAL_TRAFFIC, NETWORK_RECON, WEB_ATTACK, AUTOMATED_ATTACK_CHAIN, TRAFFIC_ANOMALY, FULL_ADAPTIVE_DEFENSE"),
    db: Session = Depends(get_db)
):
    """
    Trigger controlled, safe local demonstration attack scenarios against AEGIS.
    Generates synthetic sensor events strictly within container boundary.
    """
    valid_scenarios = (
        "NORMAL_TRAFFIC", "NETWORK_RECON", "WEB_ATTACK",
        "AUTOMATED_ATTACK_CHAIN", "TRAFFIC_ANOMALY", "FULL_ADAPTIVE_DEFENSE"
    )
    if scenario not in valid_scenarios:
        raise HTTPException(status_code=400, detail=f"Invalid scenario. Must be one of: {valid_scenarios}")

    now_iso = datetime.now(timezone.utc).isoformat()
    demo_ip = "192.168.1.185"

    results = []
    if scenario in ("NORMAL_TRAFFIC", "FULL_ADAPTIVE_DEFENSE"):
        ev1 = NormalizedNetworkEvent(
            event_id=f"demo-flow-{datetime.now().timestamp()}",
            sensor="suricata",
            event_type="FLOW",
            source_ip="192.168.1.50",
            destination_ip="192.168.1.10",
            source_port=52344,
            destination_port=80,
            protocol="TCP",
            severity="INFO",
            signature="Suricata Standard TCP Flow",
            timestamp=now_iso
        )
        r1 = await process_incoming_network_event(ev1, db)
        results.append({"step": "NORMAL_TRAFFIC", "result": r1})

    if scenario in ("NETWORK_RECON", "AUTOMATED_ATTACK_CHAIN", "FULL_ADAPTIVE_DEFENSE"):
        ev2 = NormalizedNetworkEvent(
            event_id=f"demo-recon-{datetime.now().timestamp()}",
            sensor="suricata",
            event_type="ALERT",
            source_ip=demo_ip,
            destination_ip="192.168.1.10",
            source_port=44210,
            destination_port=22,
            protocol="TCP",
            severity="HIGH",
            signature="AEGIS-SCAN High Velocity TCP SYN Port Sweep",
            signature_id=2001001,
            category="attempted-recon",
            timestamp=now_iso
        )
        r2 = await process_incoming_network_event(ev2, db)
        results.append({"step": "NETWORK_RECON", "result": r2})

    if scenario in ("TRAFFIC_ANOMALY", "FULL_ADAPTIVE_DEFENSE"):
        detector = get_anomaly_detector()
        anom = detector.analyze_traffic(current_event_rate=125.0, source_ip=demo_ip)
        results.append({"step": "TRAFFIC_ANOMALY", "result": anom.model_dump()})

    return {
        "status": "SUCCESS",
        "scenario": scenario,
        "demo_ip": demo_ip,
        "results": results
    }
