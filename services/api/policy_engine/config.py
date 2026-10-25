"""
AEGIS Ω — Policy Engine Configuration
Centralized decision constants, risk and AgentShield severity mappings, and policy rule definitions.
Eliminates magic strings and scattered conditions across the decision subsystem.
"""

from typing import Set


class PolicyEngineConfig:
    # Subsystem version for auditability & traceability
    POLICY_VERSION: str = "policy-v1"

    # Core Policy Decisions
    DECISION_ALLOW: str = "ALLOW"
    DECISION_MONITOR: str = "MONITOR"
    DECISION_RATE_LIMIT: str = "RATE_LIMIT"
    DECISION_BLOCK: str = "BLOCK"
    DECISION_CONTAIN: str = "CONTAIN"
    DECISION_DECEIVE_ELIGIBLE: str = "DECEIVE_ELIGIBLE"

    VALID_DECISIONS: Set[str] = {
        DECISION_ALLOW,
        DECISION_MONITOR,
        DECISION_RATE_LIMIT,
        DECISION_BLOCK,
        DECISION_CONTAIN,
        DECISION_DECEIVE_ELIGIBLE
    }

    # Risk Score Boundaries
    RISK_LOW_MAX: int = 24
    RISK_MEDIUM_MAX: int = 49
    RISK_HIGH_MAX: int = 74
    RISK_CRITICAL_MIN: int = 75

    # AgentShield Thresholds for Deception Eligibility
    AGENT_SHIELD_HIGH_MIN: int = 50
    AGENT_SHIELD_CRITICAL_MIN: int = 75

    # Rate Limit Velocity Threshold
    RATE_LIMIT_VELOCITY_THRESHOLD: int = 3

    # Terminal Decision Reasons
    REASON_WAF_BLOCKED_TERMINAL: str = "WAF_BLOCKED_TERMINAL"

    # Explicit Deception Invariant Disclaimer
    DECEPTION_DISCLAIMER: str = (
        "Phase 7 evaluates policy decisions and determines deception eligibility only (DECEIVE_ELIGIBLE). "
        "No honeypots, decoy redirects, or active deception mechanisms are executed in Phase 7."
    )


policy_settings = PolicyEngineConfig()
