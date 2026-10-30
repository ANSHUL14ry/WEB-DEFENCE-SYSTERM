"""
AEGIS Ω — Pydantic Schemas for Network Defense Subsystem (Phase 11)
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field


class NetworkEventType(str, Enum):
    ALERT = "ALERT"
    FLOW = "FLOW"
    HTTP = "HTTP"
    DNS = "DNS"
    TLS = "TLS"
    ANOMALY = "ANOMALY"


class EnforcementAction(str, Enum):
    OBSERVE = "OBSERVE"
    RATE_LIMIT = "RATE_LIMIT"
    TEMP_BLOCK = "TEMP_BLOCK"
    BLOCK = "BLOCK"


class AnomalySeverity(str, Enum):
    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    ANOMALOUS = "ANOMALOUS"
    CRITICAL = "CRITICAL"


class AnomalyMitigation(str, Enum):
    NONE = "NONE"
    LOCAL_MITIGATION_ACTIVE = "LOCAL_MITIGATION_ACTIVE"
    UPSTREAM_DDOS_RECOMMENDED = "UPSTREAM_DDOS_RECOMMENDED"


class NetworkRiskSignal(BaseModel):
    name: str
    score: int
    reason: str
    weight: float = 1.0

    def __getitem__(self, item: str) -> Any:
        if item in ("signal", "name"):
            return self.name
        elif item == "score":
            return self.score
        elif item == "reason":
            return self.reason
        return getattr(self, item, None)


class NetworkRiskAssessment(BaseModel):
    source_ip: str
    network_risk_score: int = Field(ge=0, le=100)
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float = 1.0
    signals: List[NetworkRiskSignal] = Field(default_factory=list)
    explanation: str
    created_at: str


class NormalizedNetworkEvent(BaseModel):
    event_id: str
    sensor: str = "suricata"  # suricata, zeek, simulated
    sensor_event_id: Optional[str] = None
    event_type: str = "ALERT"
    source_ip: str
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    severity: str = "INFO"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    signature: Optional[str] = None
    signature_id: Optional[int] = None
    category: Optional[str] = None
    raw_reference: Optional[str] = None
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    network_risk_score: int = 0
    mitre_technique_id: Optional[str] = None
    enforcement_action: str = "OBSERVE"
    raw_metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str
    created_at: Optional[str] = None
    @property
    def dest_ip(self) -> Optional[str]:
        return self.destination_ip

    @property
    def is_active(self) -> bool:
        return self.status == "ACTIVE" and self.action != "OBSERVE"

    @property
    def dest_port(self) -> Optional[int]:
        return self.destination_port

    @property
    def mitre_technique(self) -> Optional[str]:
        return self.mitre_technique_id

    @property
    def bytes_in(self) -> Optional[int]:
        return self.raw_metadata.get("flow", {}).get("bytes_toserver")

    @property
    def bytes_out(self) -> Optional[int]:
        return self.raw_metadata.get("flow", {}).get("bytes_toclient")

    @property
    def packets_in(self) -> Optional[int]:
        return self.raw_metadata.get("flow", {}).get("pkts_toserver")

    @property
    def packets_out(self) -> Optional[int]:
        return self.raw_metadata.get("flow", {}).get("pkts_toclient")

    @property
    def flow_duration_ms(self) -> float:
        return float(self.raw_metadata.get("flow", {}).get("age", 0)) * 1000.0

    @property
    def http_method(self) -> Optional[str]:
        return self.raw_metadata.get("http", {}).get("http_method")

    @property
    def http_uri(self) -> Optional[str]:
        return self.raw_metadata.get("http", {}).get("url")

    @property
    def http_user_agent(self) -> Optional[str]:
        return self.raw_metadata.get("http", {}).get("http_user_agent")

    @property
    def http_status(self) -> Optional[int]:
        return self.raw_metadata.get("http", {}).get("status")


class NetworkEnforcementRequest(BaseModel):
    source_ip: str
    action: EnforcementAction
    duration_seconds: Optional[int] = 300
    rate_limit_rps: Optional[int] = 10
    reason: str
    trigger_event_id: Optional[str] = None


class NetworkEnforcementRecord(BaseModel):
    enforcement_id: str
    source_ip: str
    action: str
    status: str = "ACTIVE"  # ACTIVE, EXPIRED, RELEASED
    rate_limit_rps: Optional[int] = None
    duration_seconds: Optional[int] = None
    reason: str
    trigger_event_id: Optional[str] = None
    network_risk_score: Optional[int] = None
    expires_at: Optional[str] = None
    created_at: str
    released_at: Optional[str] = None
    audit_metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def ttl_seconds(self) -> Optional[int]:
        return self.duration_seconds

    @property
    def is_active(self) -> bool:
        return self.status == "ACTIVE" and self.action != "OBSERVE" and self.released_at is None


class NetworkAnomalyReport(BaseModel):
    anomaly_id: str
    anomaly_type: str  # BURST_RATE, FLOW_SPIKE, DEST_CONCENTRATION, PORT_SCAN, PROTOCOL_ANOMALY
    severity: str  # NORMAL, ELEVATED, ANOMALOUS, CRITICAL
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    metric_name: str
    current_value: float
    baseline_value: float
    deviation_factor: float
    mitigation_recommendation: str  # LOCAL_MITIGATION_ACTIVE, UPSTREAM_DDOS_RECOMMENDED, NONE
    details: Dict[str, Any] = Field(default_factory=dict)
    created_at: str


class AttackStoryStage(BaseModel):
    stage_id: str
    category: str  # NETWORK, WEB, AGENT, POLICY, DECEPTION, VERIFICATION
    label: str
    timestamp: str
    severity: str
    detail: str
    evidence_id: Optional[str] = None


class AttackStoryModel(BaseModel):
    story_id: str
    source_ip: str
    start_time: str
    end_time: Optional[str] = None
    stages: List[AttackStoryStage] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    highest_risk_score: int = 0
    highest_agentshield_score: int = 0
    highest_network_risk_score: int = 0
    final_policy_decision: Optional[str] = None
    origin_untouched: bool = True
    mitigation_verified: bool = False
    status: str = "ACTIVE"
    created_at: str
