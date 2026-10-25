"""
AEGIS Ω — Deception Subsystem Pydantic Models
Data schemas for deception sessions, interaction events, routing requests, and stats.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class DeceptionExecutionRequest(BaseModel):
    request_id: str = Field(..., description="Unique transaction ID")
    trace_id: str = Field(..., description="Correlation trace ID")
    policy_decision_id: Optional[str] = Field(None, description="Linked policy decision ID")
    policy_decision: str = Field(..., description="Policy decision (must be DECEIVE_ELIGIBLE)")
    waf_blocked: bool = Field(False, description="True if transaction was dropped by WAF")
    waf_action: Optional[str] = Field(None, description="WAF action: ALLOW, BLOCK, NONE")
    initial_risk_score: Optional[int] = Field(None, ge=0, le=100)
    initial_agent_shield_score: Optional[int] = Field(None, ge=0, le=100)
    client_ip: Optional[str] = Field(None)
    user_agent: Optional[str] = Field(None)
    target_route: Optional[str] = Field("/", description="Target HTTP route in decoy")
    method: Optional[str] = Field("GET", description="HTTP method")
    headers: Optional[Dict[str, str]] = Field(default_factory=dict)
    body: Optional[Any] = Field(None)


class DeceptionInteractionRequest(BaseModel):
    session_id: str = Field(..., description="Active deception session ID")
    route: str = Field(..., description="Target route within the isolated decoy")
    method: str = Field("GET", description="HTTP method")
    request_id: Optional[str] = Field(None)
    trace_id: Optional[str] = Field(None)
    headers: Optional[Dict[str, str]] = Field(default_factory=dict)
    body: Optional[Any] = Field(None)


class DeceptionSessionRecord(BaseModel):
    session_id: str
    request_id: str
    trace_id: str
    policy_decision_id: Optional[str] = None
    source_identifier_hash: str
    client_ip: Optional[str] = None
    initial_risk_score: Optional[int] = None
    initial_agent_shield_score: Optional[int] = None
    entry_reason: Optional[str] = None
    status: str # ACTIVE, TERMINATED, EXPIRED, DENIED
    interaction_count: int = 0
    evidence_count: int = 0
    origin_reached: bool = False
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    last_interaction_at: Optional[str] = None
    expires_at: Optional[str] = None
    created_at: Optional[str] = None


class DeceptionEventRecord(BaseModel):
    event_id: str
    session_id: str
    request_id: str
    trace_id: str
    event_type: str
    route: str
    method: str
    source_identifier_hash: Optional[str] = None
    response_status: int = 200
    endpoint_category: Optional[str] = None
    user_agent_classification: Optional[str] = None
    request_size: int = 0
    risk_context: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[str] = None


class DeceptionStats(BaseModel):
    total_sessions: int
    active_sessions: int
    terminated_sessions: int
    expired_sessions: int
    denied_sessions: int
    total_evidence_events: int
    recent_sessions: List[Dict[str, Any]] = Field(default_factory=list)
    recent_events: List[Dict[str, Any]] = Field(default_factory=list)
    disclaimer: str = Field(
        default="Decoy environment operates on a dedicated isolated Docker network without access to production database, host filesystem, or real origin application."
    )
