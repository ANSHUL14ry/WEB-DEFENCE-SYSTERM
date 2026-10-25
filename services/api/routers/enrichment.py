"""
AEGIS Ω — Attacker Intelligence & Threat Context Router (Phase 10)
Exposes source profiles, MITRE ATT&CK mappings, network reconnaissance sensor observations,
and internal sensor ingestion endpoints.
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db
from enrichment.models import (
    SourceProfileResponse,
    NetworkObservationCreate,
    MitreMapping
)
from enrichment.repository import (
    get_source_profile_by_ip,
    list_source_profiles,
    list_mitre_mappings,
    list_network_observations
)
from enrichment.service import (
    enrich_security_event,
    ingest_network_observation_event
)

router = APIRouter(prefix="/api/v1/enrichment", tags=["enrichment"])


@router.get("/source-profiles")
def get_source_profiles(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """List observed attacker/client source profiles."""
    profiles = list_source_profiles(db, limit=limit, offset=offset)
    return {
        "status": "success",
        "count": len(profiles),
        "profiles": profiles
    }


@router.get("/source-profile/{ip}")
def get_single_source_profile(ip: str, db: Session = Depends(get_db)):
    """Retrieve full attacker intelligence details, reputation, and MITRE evidence for a specific IP."""
    profile = get_source_profile_by_ip(db, ip.strip())
    if not profile:
        raise HTTPException(status_code=404, detail=f"Source profile not found for IP: {ip}")
    return {
        "status": "success",
        "profile": profile
    }


@router.get("/mitre")
def get_mitre_mappings(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """List deterministic MITRE ATT&CK technique mappings with evidence."""
    mappings = list_mitre_mappings(db, limit=limit, offset=offset)
    return {
        "status": "success",
        "count": len(mappings),
        "mappings": mappings
    }


@router.get("/network-observations")
def get_network_observations(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """List external network sensor (Zeek / Suricata) reconnaissance observations."""
    observations = list_network_observations(db, limit=limit, offset=offset)
    return {
        "status": "success",
        "count": len(observations),
        "observations": observations
    }


@router.post("/internal/network-event")
async def ingest_network_sensor_event(
    obs: NetworkObservationCreate,
    db: Session = Depends(get_db)
):
    """
    Ingest external sensor telemetry (Zeek / Suricata).
    Labels sensor source explicitly without claiming AEGIS WAF inspected raw packets.
    """
    result = await ingest_network_observation_event(obs, db)
    return {
        "status": "ingested",
        "sensor": obs.sensor,
        "observation": result
    }


@router.post("/internal/enrich")
async def enrich_event_manual(
    event_data: Dict[str, Any],
    db: Session = Depends(get_db)
):
    """On-demand event enrichment test endpoint."""
    enriched = await enrich_security_event(event_data, db)
    return {
        "status": "enriched",
        "enrichment": enriched
    }
