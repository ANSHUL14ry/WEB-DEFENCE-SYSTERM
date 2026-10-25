"""
AEGIS Ω — Phase 9 Response Verification & Telemetry Proof Engine
"""

from verification.config import (
    ENGINE_VERSION,
    RESULT_VERIFIED,
    RESULT_FAILED,
    RESULT_INCONCLUSIVE
)
from verification.models import (
    VerificationContext,
    ProofObject,
    VerificationEvaluateRequest,
    VerificationResultRecord,
    VerificationStats
)
from verification.evaluator import evaluate_mitigation_verification
from verification.service import (
    evaluate_and_record_verification,
    get_verification_by_id,
    get_verification_by_request_id,
    get_verification_by_trace_id,
    list_verification_results,
    get_verification_stats
)

__all__ = [
    "ENGINE_VERSION",
    "RESULT_VERIFIED",
    "RESULT_FAILED",
    "RESULT_INCONCLUSIVE",
    "VerificationContext",
    "ProofObject",
    "VerificationEvaluateRequest",
    "VerificationResultRecord",
    "VerificationStats",
    "evaluate_mitigation_verification",
    "evaluate_and_record_verification",
    "get_verification_by_id",
    "get_verification_by_request_id",
    "get_verification_by_trace_id",
    "list_verification_results",
    "get_verification_stats"
]
