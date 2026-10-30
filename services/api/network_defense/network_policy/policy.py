"""
AEGIS Ω — Network Policy Decision Engine (Phase 11)
Determines defensive action (OBSERVE, RATE_LIMIT, TEMP_BLOCK, BLOCK)
unifying Network Risk, Web Risk, and AgentShield while preserving all security invariants.
"""

import logging
from typing import Dict, Any, Optional, Tuple
from network_defense.models import EnforcementAction

logger = logging.getLogger("aegis.network_defense.policy")


def evaluate_network_policy(
    network_risk_score: int,
    web_risk_score: Optional[int] = None,
    agentshield_score: Optional[int] = None,
    waf_blocked: bool = False,
    is_terminal: bool = False
) -> Tuple[EnforcementAction, str]:
    """
    Evaluate deterministic network enforcement policy.
    Invariants:
    - If WAF or Gateway has terminally blocked the request, enforce BLOCK.
    - Risk >= 75 or critical combination -> BLOCK.
    - Risk >= 50 -> TEMP_BLOCK.
    - Risk >= 25 -> RATE_LIMIT.
    - Otherwise -> OBSERVE.
    """
    # Invariant: Terminal WAF block takes absolute precedence
    if waf_blocked or is_terminal:
        return (
            EnforcementAction.BLOCK,
            "Terminal application WAF violation: immediate network-level BLOCK enforced."
        )

    # Calculate unified threat level
    effective_net_risk = network_risk_score
    effective_web_risk = web_risk_score or 0
    effective_as_score = agentshield_score or 0

    max_combined = max(effective_net_risk, effective_web_risk, effective_as_score)

    if max_combined >= 75:
        return (
            EnforcementAction.BLOCK,
            f"Critical threat severity ({max_combined}/100): network isolation and full BLOCK enforced."
        )
    elif max_combined >= 50 or (effective_net_risk >= 40 and effective_as_score >= 40):
        return (
            EnforcementAction.TEMP_BLOCK,
            f"High threat severity ({max_combined}/100): temporary network quarantine enforced."
        )
    elif max_combined >= 25:
        return (
            EnforcementAction.RATE_LIMIT,
            f"Medium threat severity ({max_combined}/100): network traffic rate-limiting enforced."
        )

    return (
        EnforcementAction.OBSERVE,
        "Low threat profile: passive network observation active."
    )


class PolicyDecisionResult:
    def __init__(self, action: str, matched_rule: str, is_terminal: bool = False):
        self.action = action
        self.matched_rule = matched_rule
        self.is_terminal = is_terminal

class NetworkPolicyEvaluator:
    """Unified adaptive network + application policy decision evaluator."""
    def evaluate(
        self,
        network_risk_score: int,
        web_risk_score: Optional[int] = None,
        agentshield_score: Optional[int] = None,
        waf_blocked: bool = False,
        deception_eligible: bool = False
    ) -> PolicyDecisionResult:
        if waf_blocked:
            return PolicyDecisionResult(
                action="BLOCK",
                matched_rule="TERMINAL_WAF_BLOCK_INVARIANT",
                is_terminal=True
            )
        
        effective_net = network_risk_score
        effective_web = web_risk_score or 0
        effective_as = agentshield_score or 0
        max_threat = max(effective_net, effective_web, effective_as)

        if deception_eligible and max_threat >= 70:
            return PolicyDecisionResult(
                action="DECEIVE",
                matched_rule="RULE_UNIFIED_ADAPTIVE_DECEPTION",
                is_terminal=False
            )
        
        action_enum, reason = evaluate_network_policy(
            network_risk_score=network_risk_score,
            web_risk_score=web_risk_score,
            agentshield_score=agentshield_score,
            waf_blocked=waf_blocked
        )
        return PolicyDecisionResult(
            action=action_enum.value if hasattr(action_enum, "value") else str(action_enum),
            matched_rule="RULE_NETWORK_DEFENSE_THRESHOLD",
            is_terminal=action_enum == EnforcementAction.BLOCK
        )
