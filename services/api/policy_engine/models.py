"""
AEGIS Ω — Policy Engine Pydantic Models
Defines strongly typed schemas for policy input context, policy decisions, and rule evaluations.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from policy_engine.config import policy_settings


class PolicyContext(BaseModel):
    request_id: str = Field(..., description="Unique HTTP transaction identifier")
    trace_id: str = Field(..., description="Correlation trace identifier")
    event_id: Optional[str] = Field(None, description="Triggering security event ID")
    session_id: Optional[str] = Field(None, description="Optional established session identifier")
    
    # Trusted Risk Intelligence
    risk_assessment_id: Optional[str] = Field(None, description="Risk assessment ID")
    risk_score: Optional[int] = Field(None, ge=0, le=100, description="Risk score 0-100")
    risk_severity: Optional[str] = Field(None, description="Risk severity: LOW, MEDIUM, HIGH, CRITICAL")
    risk_confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Risk confidence")
    risk_signals: List[Any] = Field(default_factory=list, description="Decomposed risk signals")

    # Trusted AgentShield Behavioral Intelligence
    agent_shield_assessment_id: Optional[str] = Field(None, description="AgentShield assessment ID")
    agent_shield_score: Optional[int] = Field(None, ge=0, le=100, description="AgentShield automation score 0-100")
    agent_shield_severity: Optional[str] = Field(None, description="AgentShield severity: LOW, MEDIUM, HIGH, CRITICAL")
    agent_shield_confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="AgentShield confidence")
    agent_shield_signals: List[Any] = Field(default_factory=list, description="Observed behavioral signals")
    agent_shield_stages: List[str] = Field(default_factory=list, description="Observed attack lifecycle stages")

    # Trusted WAF & Ingress Context
    waf_action: Optional[str] = Field(None, description="WAF action: ALLOW, BLOCK, OBSERVED, NONE")
    waf_blocked: bool = Field(False, description="True if transaction was dropped by WAF")
    endpoint: Optional[str] = Field(None, description="Sanitized endpoint path")
    endpoint_sensitivity: Optional[str] = Field(None, description="Endpoint sensitivity tier")
    request_method: Optional[str] = Field("GET", description="HTTP method")
    security_event_type: Optional[str] = Field(None, description="Normalized event type")
    correlated_event_count: int = Field(0, description="Total correlated events in temporal window")


class PolicyDecision(BaseModel):
    decision_id: Optional[str] = Field(None, description="Unique policy decision ID (pd-...)")
    request_id: str = Field(..., description="Request identifier")
    trace_id: str = Field(..., description="Trace identifier")
    session_id: Optional[str] = Field(None, description="Session identifier")
    event_id: Optional[str] = Field(None, description="Security event identifier")

    risk_assessment_id: Optional[str] = Field(None, description="Linked risk assessment ID")
    agent_shield_assessment_id: Optional[str] = Field(None, description="Linked AgentShield assessment ID")

    risk_score: Optional[int] = Field(None, description="Evaluated risk score")
    risk_severity: Optional[str] = Field(None, description="Evaluated risk severity")
    risk_confidence: Optional[float] = Field(None, description="Evaluated risk confidence")

    agent_shield_score: Optional[int] = Field(None, description="Evaluated AgentShield score")
    agent_shield_severity: Optional[str] = Field(None, description="Evaluated AgentShield severity")
    agent_shield_confidence: Optional[float] = Field(None, description="Evaluated AgentShield confidence")

    decision: str = Field(..., description="Policy decision: ALLOW, MONITOR, RATE_LIMIT, BLOCK, CONTAIN, DECEIVE_ELIGIBLE")
    decision_reason: str = Field(..., description="Primary reason for the policy determination")
    explanation: Optional[str] = Field(None, description="Human readable explanation")
    reasons: List[str] = Field(default_factory=list, description="Detailed explanatory reasons")
    matched_rules: List[str] = Field(default_factory=list, description="Ordered list of matched policy rule identifiers")
    rule_matched: Optional[str] = Field(None, description="Primary rule matched")
    rule_evaluation_chain: List[str] = Field(default_factory=list, description="Complete chain of evaluated/matched rules")
    terminal: bool = Field(False, description="True if decision is terminal (e.g. WAF block drops packet)")
    policy_version: str = Field(default=policy_settings.POLICY_VERSION, description="Policy Engine version")
    created_at: Optional[str] = Field(None, description="ISO 8601 creation timestamp")
