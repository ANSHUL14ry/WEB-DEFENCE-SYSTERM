"""
AEGIS Ω — Normalized Security Event Model & Taxonomy
Provides unified typed schemas, severity mappings, and credential sanitization for Phase 4.
"""

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator


class EventSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EventType(str, Enum):
    # Active Phase 4 Event Types
    GATEWAY_REQUEST = "GATEWAY_REQUEST"
    WAF_DETECTION = "WAF_DETECTION"
    WAF_BLOCK = "WAF_BLOCK"
    ORIGIN_REQUEST = "ORIGIN_REQUEST"
    SYSTEM_EVENT = "SYSTEM_EVENT"
    
    # Reserved Event Types (Phases 5-10)
    AGENTSHIELD_SIGNAL = "AGENTSHIELD_SIGNAL"
    RISK_SCORE_UPDATE = "RISK_SCORE_UPDATE"
    POLICY_DECISION = "POLICY_DECISION"
    DECEPTION_EVENT = "DECEPTION_EVENT"
    MITIGATION_EVENT = "MITIGATION_EVENT"
    NETWORK_RECON_DETECTED = "NETWORK_RECON_DETECTED"
    THREAT_INTELLIGENCE_UPDATE = "THREAT_INTELLIGENCE_UPDATE"
    SOURCE_ENRICHED = "SOURCE_ENRICHED"
    MITRE_TECHNIQUE_MAPPED = "MITRE_TECHNIQUE_MAPPED"
    REPUTATION_UPDATED = "REPUTATION_UPDATED"
    # Phase 11 Network Defense
    NETWORK_EVENT_INGESTED = "NETWORK_EVENT_INGESTED"
    NETWORK_ENFORCEMENT_ACTION = "NETWORK_ENFORCEMENT_ACTION"
    NETWORK_ANOMALY_DETECTED = "NETWORK_ANOMALY_DETECTED"
    ATTACK_STORY_UPDATE = "ATTACK_STORY_UPDATE"


class EventAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    OBSERVED = "OBSERVED"
    ALERT = "ALERT"


class EventStatus(str, Enum):
    DETECTED = "DETECTED"
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    OBSERVED = "OBSERVED"
    FAILED = "FAILED"
    # Note: 'VERIFIED' is reserved strictly for Phase 9 Response Verification


class EventComponent(str, Enum):
    CORAZA = "coraza"
    GATEWAY = "gateway"
    ORIGIN = "origin"
    SYSTEM = "system"
    # Future components: agentshield, risk_engine, policy_engine, honeypot


class SourceInfo(BaseModel):
    ip: Optional[str] = "unknown"
    user_agent: Optional[str] = None


class RequestInfo(BaseModel):
    method: str = "GET"
    uri: str = "/"


# Sensitive keys for sanitization
SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "access_token",
    "authorization", "api_key", "apikey", "cookie", "set-cookie",
    "private_key", "client_secret"
}

SENSITIVE_URI_PATTERN = re.compile(
    r'(?i)(password|token|secret|key|access_token|auth)=([^&]+)'
)


def sanitize_value(val: Any) -> Any:
    """Recursively strip credentials, tokens, and authorization secrets."""
    if isinstance(val, dict):
        cleaned = {}
        for k, v in val.items():
            if str(k).lower() in SENSITIVE_KEYS:
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = sanitize_value(v)
        return cleaned
    elif isinstance(val, list):
        return [sanitize_value(item) for item in val]
    elif isinstance(val, str):
        return SENSITIVE_URI_PATTERN.sub(r'\1=[REDACTED]', val)
    return val


def map_waf_severity(raw: Optional[str]) -> str:
    """Map Coraza / ModSecurity / CRS rule severities to standard EventSeverity."""
    if not raw:
        return EventSeverity.HIGH.value
    raw_upper = str(raw).strip().upper()
    if raw_upper in ["CRITICAL", "EMERGENCY", "ALERT", "5"]:
        return EventSeverity.CRITICAL.value
    elif raw_upper in ["ERROR", "HIGH", "4"]:
        return EventSeverity.HIGH.value
    elif raw_upper in ["WARNING", "MEDIUM", "WARN", "3"]:
        return EventSeverity.MEDIUM.value
    elif raw_upper in ["NOTICE", "LOW", "2"]:
        return EventSeverity.LOW.value
    elif raw_upper in ["INFO", "DEBUG", "1"]:
        return EventSeverity.INFO.value
    return EventSeverity.HIGH.value


class SecurityEventCreate(BaseModel):
    event_id: Optional[str] = None
    event_type: str
    timestamp: Optional[datetime] = None
    request_id: str
    trace_id: str
    session_id: Optional[str] = None
    source: SourceInfo = Field(default_factory=SourceInfo)
    request: RequestInfo = Field(default_factory=RequestInfo)
    severity: str = EventSeverity.INFO.value
    action: str = EventAction.OBSERVED.value
    component: str = EventComponent.SYSTEM.value
    status: str = EventStatus.DETECTED.value
    metadata: Dict[str, Any] = Field(default_factory=dict)
    enrichment: Optional[Dict[str, Any]] = Field(default=None)

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, v: str) -> str:
        valid_types = {e.value for e in EventType}
        v_upper = v.upper()
        if v_upper not in valid_types:
            raise ValueError(f"Invalid event_type: {v}. Must be one of {valid_types}")
        return v_upper

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid_sevs = {s.value for s in EventSeverity}
        v_upper = v.upper()
        if v_upper not in valid_sevs:
            raise ValueError(f"Invalid severity: {v}. Must be one of {valid_sevs}")
        return v_upper

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        valid_acts = {a.value for a in EventAction}
        v_upper = v.upper()
        if v_upper not in valid_acts:
            raise ValueError(f"Invalid action: {v}. Must be one of {valid_acts}")
        return v_upper

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        valid_stats = {s.value for s in EventStatus}
        v_upper = v.upper()
        if v_upper == "VERIFIED":
            raise ValueError("Status 'VERIFIED' is reserved for Phase 9 Response Verification")
        if v_upper not in valid_stats:
            raise ValueError(f"Invalid status: {v}. Must be one of {valid_stats}")
        return v_upper

    @field_validator("metadata")
    @classmethod
    def sanitize_metadata(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        return sanitize_value(v)


class SecurityEventResponse(BaseModel):
    event_id: str
    event_type: str
    timestamp: str
    request_id: str
    trace_id: str
    session_id: Optional[str] = None
    source: SourceInfo
    request: RequestInfo
    severity: str
    action: str
    component: str
    status: str
    metadata: Dict[str, Any]
    enrichment: Optional[Dict[str, Any]] = None
    created_at: str
