"""
Pydantic data models for Attacker Intelligence, Threat Context, and MITRE Mapping.
"""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class GeoIPContext(BaseModel):
    is_private: bool = False
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    isp: Optional[str] = None
    display_label: str = "UNKNOWN"


class ThreatIntelResult(BaseModel):
    indicator: str
    indicator_type: str = "ip"
    status: str = "NOT_CONFIGURED"  # NOT_CONFIGURED, UNKNOWN, CLEAN, SUSPICIOUS, MALICIOUS
    provider: Optional[str] = None
    confidence: Optional[float] = None
    category: Optional[str] = None
    source_reference: Optional[str] = None
    checked_at: Optional[str] = None


class ClientFingerprint(BaseModel):
    fingerprint: str
    method: str = "SHA256"
    user_agent: Optional[str] = None
    accept: Optional[str] = None
    accept_language: Optional[str] = None
    accept_encoding: Optional[str] = None
    http_version: Optional[str] = "HTTP/1.1"
    sanitized: bool = True


class TLSFingerprint(BaseModel):
    status: str = "NOT AVAILABLE AT CURRENT TERMINATION POINT"
    fingerprint: Optional[str] = None
    method: Optional[str] = None
    observed_at: Optional[str] = None


class MitreMapping(BaseModel):
    mapping_id: Optional[str] = None
    technique_id: str
    technique_name: str
    tactic: str
    evidence_event_ids: List[str] = Field(default_factory=list)
    confidence: float
    reason: str
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    source_ip: Optional[str] = None
    created_at: Optional[str] = None


class NetworkObservationCreate(BaseModel):
    sensor: str  # e.g. "zeek", "suricata"
    event_type: str  # e.g. "port_scan", "service_probe", "network_connection"
    source_ip: str
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    ports_observed: Optional[str] = None
    connection_count: int = 1
    scan_indicator: Optional[str] = None
    confidence: Optional[float] = 1.0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SourceProfileResponse(BaseModel):
    source_ip: str
    client_fingerprint: Optional[str] = None
    user_agent: Optional[str] = None
    is_private: bool = False
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    isp: Optional[str] = None
    first_seen: str
    last_seen: str
    request_count: int = 1
    session_count: int = 0
    reputation_status: str = "UNKNOWN"
    reputation_provider: Optional[str] = None
    reputation_checked_at: Optional[str] = None
    mitre_mappings: List[MitreMapping] = Field(default_factory=list)
    observed_behaviors: List[str] = Field(default_factory=list)
    defense_status: str = "OBSERVED"
    latest_risk_score: Optional[int] = None
    latest_agentshield_score: Optional[int] = None
    latest_policy_decision: Optional[str] = None
