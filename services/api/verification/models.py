"""
AEGIS Ω — Phase 9 Response Verification & Telemetry Proof Pydantic Models
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import datetime


class VerificationContext(BaseModel):
    model_config = {"extra": "allow"}
    """Normalized evidence context consumed by the deterministic evaluator."""
    request_id: str
    trace_id: str
    session_id: Optional[str] = None
    policy_decision_id: Optional[str] = None
    policy_decision: Optional[str] = None  # ALLOW, BLOCK, DECEIVE_ELIGIBLE, etc.
    waf_blocked: bool = False
    waf_action: str = "NONE"
    http_status: Optional[int] = None
    origin_reached: bool = False
    origin_request_count: int = 0
    deception_session_id: Optional[str] = None
    evidence_count: int = 0
    database_access_detected: bool = False
    decoy_failed: bool = False
    has_sufficient_telemetry: bool = True
    telemetry_corrupted: bool = False
    network_enforcement_action: Optional[str] = None
    network_mitigation_verified: Optional[bool] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ProofObject(BaseModel):
    model_config = {"extra": "allow"}
    """Structured, verifiable proof record demonstrating origin protection."""
    verification_id: str
    request_id: str
    trace_id: str
    session_id: Optional[str] = None
    policy_decision_id: Optional[str] = None
    verification_type: str
    expected_action: str
    actual_action: str
    expected_origin_access: bool
    actual_origin_access: bool
    origin_request_count: int
    deception_session_id: Optional[str] = None
    evidence_events: int = 0
    database_access: bool = False
    result: str  # VERIFIED, FAILED, INCONCLUSIVE
    confidence: float = 1.00
    proof: List[str] = Field(default_factory=list)
    failure_reason: Optional[str] = None
    engine_version: str = "verification-v1"
    created_at: str
    @property
    def verification_status(self) -> str:
        return self.result

    @property
    def proof_points(self) -> List[Dict[str, str]]:
        return [{"rule": p, "detail": p} for p in self.proof]


class VerificationEvaluateRequest(BaseModel):
    """API request payload to evaluate and record a mitigation verification."""
    request_id: str
    trace_id: str
    session_id: Optional[str] = None
    policy_decision_id: Optional[str] = None
    policy_decision: Optional[str] = None
    waf_blocked: bool = False
    waf_action: str = "NONE"
    http_status: Optional[int] = None
    origin_reached: Optional[bool] = None
    origin_request_count: Optional[int] = 0
    deception_session_id: Optional[str] = None
    evidence_count: Optional[int] = 0
    database_access_detected: Optional[bool] = False
    decoy_failed: Optional[bool] = False
    has_sufficient_telemetry: Optional[bool] = True
    telemetry_corrupted: Optional[bool] = False
    network_enforcement_action: Optional[str] = None
    network_mitigation_verified: Optional[bool] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class VerificationResultRecord(BaseModel):
    """API representation of a persisted verification result."""
    verification_id: str
    request_id: str
    trace_id: str
    session_id: Optional[str] = None
    policy_decision_id: Optional[str] = None
    verification_type: str
    expected_action: str
    actual_action: str
    expected_origin_access: bool
    actual_origin_access: bool
    origin_request_count: int
    deception_session_id: Optional[str] = None
    evidence_count: int
    database_access_detected: bool
    result: str
    confidence: float
    proof: List[str]
    failure_reason: Optional[str] = None
    engine_version: str
    created_at: str


class VerificationStats(BaseModel):
    """Aggregate statistics for SOC dashboard."""
    total_verifications: int
    verified_count: int
    failed_count: int
    inconclusive_count: int
    verified_percentage: float
    recent_verifications: List[VerificationResultRecord] = Field(default_factory=list)
    disclaimer: str = (
        "Mitigation proofs are mathematically evaluated from deterministic "
        "PostgreSQL telemetry, network access logs, and decoy telemetry. "
        "No AI heuristics are involved in verification validation."
    )
