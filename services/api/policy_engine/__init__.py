"""
AEGIS Ω — Policy Engine Package Entrypoint
Exposes primary decision evaluators, service orchestration, configuration, and models.
"""

from policy_engine.config import policy_settings
from policy_engine.models import PolicyContext, PolicyDecision
from policy_engine.evaluator import evaluate_policy
from policy_engine.service import evaluate_and_record_policy
from policy_engine.repository import (
    save_policy_decision,
    get_policy_decision_by_id,
    get_policy_decisions_by_request_id,
    get_policy_decisions_by_trace_id,
    get_policy_stats,
    list_policy_decisions
)

__all__ = [
    "policy_settings",
    "PolicyContext",
    "PolicyDecision",
    "evaluate_policy",
    "evaluate_and_record_policy",
    "save_policy_decision",
    "get_policy_decision_by_id",
    "get_policy_decisions_by_request_id",
    "get_policy_decisions_by_trace_id",
    "get_policy_stats",
    "list_policy_decisions"
]
