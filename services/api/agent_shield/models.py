"""
AEGIS Ω — AgentShield Pydantic Models
Defines typed models for behavioral signals, attack stage items, and assessment outputs.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from agent_shield.config import agent_shield_settings


class AgentShieldSignal(BaseModel):
    name: str = Field(..., description="Unique machine-readable signal identifier")
    score: int = Field(..., description="Points contribution to AgentShield score")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Sanitized metrics proving the signal")
    reason: str = Field(..., description="Human-readable explanation of observed behavioral pattern")


class AttackStageItem(BaseModel):
    stage: str = Field(..., description="Stage name (e.g. RECON, ENDPOINT_DISCOVERY, API_ENUMERATION, AUTH_PROBING, WAF_TRIGGER)")
    timestamp: str = Field(..., description="ISO 8601 timestamp of observed activity")
    method: str = Field("GET", description="HTTP method")
    uri: str = Field("/", description="Sanitized URI path")
    detail: str = Field("", description="Contextual note describing event")


class AgentShieldResult(BaseModel):
    assessment_id: Optional[str] = Field(None, description="Unique assessment identifier (as-...)")
    request_id: str = Field(..., description="Request ID associated with current event")
    trace_id: str = Field(..., description="Correlation trace ID")
    session_id: Optional[str] = Field(None, description="Session ID if established")
    agent_shield_score: int = Field(..., ge=0, le=100, description="Normalized score 0-100")
    severity: str = Field(..., description="Severity classification: LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Deterministic confidence metric")
    signals: List[AgentShieldSignal] = Field(default_factory=list, description="Triggered behavioral signals")
    attack_stages: List[str] = Field(default_factory=list, description="Ordered list of observed attack stages")
    attack_timeline: List[AttackStageItem] = Field(default_factory=list, description="Detailed timeline of correlated stage progression")
    behavior_summary: str = Field(..., description="Defensive behavioral analysis summary")
    engine_version: str = Field(default=agent_shield_settings.ENGINE_VERSION, description="Subsystem version")
    disclaimer: str = Field(default=agent_shield_settings.TECHNICAL_DISCLAIMER, description="Non-AI identity disclaimer")
