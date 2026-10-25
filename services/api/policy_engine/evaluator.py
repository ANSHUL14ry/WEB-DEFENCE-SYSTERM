"""
AEGIS Ω — Deterministic Policy Evaluator
Pure mathematical rule evaluation engine determining security policy decisions.
Zero side-effects, zero ML hallucination, strictly ordered precedence.
"""

from typing import List, Set, Any
from policy_engine.config import policy_settings
from policy_engine.models import PolicyContext, PolicyDecision


def evaluate_policy(context: PolicyContext) -> PolicyDecision:
    """
    Evaluates trusted security context against strict, deterministic policy rules.
    Guarantees that identical inputs yield identical decisions every time.
    """
    matched_rules: List[str] = []
    reasons: List[str] = []

    # =========================================================================
    # RULE 1 — WAF TERMINAL BLOCK (Mandatory Invariant)
    # =========================================================================
    # If the WAF has already dropped a request, it is in a terminal state.
    # The policy engine must NEVER convert it to ALLOW, CONTAIN, or DECEIVE_ELIGIBLE.
    if context.waf_blocked or (context.waf_action and context.waf_action.upper() == "BLOCK"):
        matched_rules.append("RULE_1_WAF_TERMINAL_BLOCK")
        reasons.extend([
            "WAF rule match resulted in drop at ingress gateway",
            "Terminal state enforced: request dropped before reaching application layer",
            "Zero deception bypass permitted: blocked attack packets cannot be redirected to decoys",
            "Origin isolation verified: 0 attack requests reached upstream workload"
        ])
        decision_str = policy_settings.DECISION_BLOCK
        reason_str = f"{policy_settings.REASON_WAF_BLOCKED_TERMINAL}: Request dropped by WAF; terminal state precludes deception eligibility or origin access."
        return PolicyDecision(
            request_id=context.request_id,
            trace_id=context.trace_id,
            session_id=context.session_id,
            event_id=context.event_id,
            risk_assessment_id=context.risk_assessment_id,
            agent_shield_assessment_id=context.agent_shield_assessment_id,
            risk_score=context.risk_score,
            risk_severity=context.risk_severity,
            risk_confidence=context.risk_confidence,
            agent_shield_score=context.agent_shield_score,
            agent_shield_severity=context.agent_shield_severity,
            agent_shield_confidence=context.agent_shield_confidence,
            decision=decision_str,
            decision_reason=reason_str,
            explanation=reason_str,
            reasons=reasons,
            matched_rules=matched_rules,
            rule_matched="WAF_BLOCKED_TERMINAL",
            rule_evaluation_chain=list(matched_rules),
            terminal=True,
            policy_version=policy_settings.POLICY_VERSION
        )

    # =========================================================================
    # RULE 2 — HIGH RISK + HIGH/CRITICAL AGENTSHIELD (DECEPTION ELIGIBILITY)
    # =========================================================================
    # When traffic demonstrates high/critical security risk AND exhibits high/critical
    # automated or agentic attack characteristics without being terminally dropped by WAF,
    # the request qualifies for future decoy containment.
    is_high_risk = context.risk_severity in ("HIGH", "CRITICAL") or (context.risk_score is not None and context.risk_score >= 50)
    is_high_agentic = context.agent_shield_severity in ("HIGH", "CRITICAL") or (context.agent_shield_score is not None and context.agent_shield_score >= policy_settings.AGENT_SHIELD_HIGH_MIN)

    if is_high_risk and is_high_agentic and not context.waf_blocked:
        matched_rules.extend(["RULE_2_DECEPTION_ELIGIBILITY", "HIGH_RISK_QUALIFIED", "AGENTSHIELD_AUTOMATION_CONFIRMED"])
        reasons.extend([
            f"Elevated risk score ({context.risk_score}) with {context.risk_severity} severity",
            f"AgentShield identified characteristics consistent with systematic automated/agentic workflows (Score: {context.agent_shield_score}, Severity: {context.agent_shield_severity})",
            "Request reached policy evaluation stage and is eligible for future decoy diversion in Phase 8",
            "Deception eligibility granted (Phase 8 execution pending; no active honeypot engaged in Phase 7)"
        ])
        decision_str = policy_settings.DECISION_DECEIVE_ELIGIBLE
        reason_str = "High risk combined with high-confidence automated/agentic behavior detected. Request is eligible for containment and future deception (Phase 8 execution pending; no active honeypot engaged in Phase 7)."
        return PolicyDecision(
            request_id=context.request_id,
            trace_id=context.trace_id,
            session_id=context.session_id,
            event_id=context.event_id,
            risk_assessment_id=context.risk_assessment_id,
            agent_shield_assessment_id=context.agent_shield_assessment_id,
            risk_score=context.risk_score,
            risk_severity=context.risk_severity,
            risk_confidence=context.risk_confidence,
            agent_shield_score=context.agent_shield_score,
            agent_shield_severity=context.agent_shield_severity,
            agent_shield_confidence=context.agent_shield_confidence,
            decision=decision_str,
            decision_reason=reason_str,
            explanation=reason_str,
            reasons=reasons,
            matched_rules=matched_rules,
            rule_matched="RULE_2_DECEPTION_ELIGIBILITY",
            rule_evaluation_chain=list(matched_rules),
            terminal=False,
            policy_version=policy_settings.POLICY_VERSION
        )

    # =========================================================================
    # RULE 3 — CRITICAL SECURITY ACTIVITY (BLOCK)
    # =========================================================================
    if context.risk_severity == "CRITICAL" or (context.risk_score is not None and context.risk_score >= policy_settings.RISK_CRITICAL_MIN):
        matched_rules.append("RULE_3_CRITICAL_SECURITY_BLOCK")
        reasons.extend([
            f"Critical risk score ({context.risk_score}/100) exceeds safe operational baseline",
            "Critical security vulnerability violation identified",
            "Enforcing immediate threat drop policy"
        ])
        decision_str = policy_settings.DECISION_BLOCK
        reason_str = f"Critical risk score ({context.risk_score}) exceeds safe operational baseline. Dropping malicious transaction."
        return PolicyDecision(
            request_id=context.request_id,
            trace_id=context.trace_id,
            session_id=context.session_id,
            event_id=context.event_id,
            risk_assessment_id=context.risk_assessment_id,
            agent_shield_assessment_id=context.agent_shield_assessment_id,
            risk_score=context.risk_score,
            risk_severity=context.risk_severity,
            risk_confidence=context.risk_confidence,
            agent_shield_score=context.agent_shield_score,
            agent_shield_severity=context.agent_shield_severity,
            agent_shield_confidence=context.agent_shield_confidence,
            decision=decision_str,
            decision_reason=reason_str,
            explanation=reason_str,
            reasons=reasons,
            matched_rules=matched_rules,
            rule_matched="RULE_3_CRITICAL_SECURITY_BLOCK",
            rule_evaluation_chain=list(matched_rules),
            terminal=True,
            policy_version=policy_settings.POLICY_VERSION
        )

    # =========================================================================
    # RULE 4 — HIGH SECURITY RISK (BLOCK)
    # =========================================================================
    if context.risk_severity == "HIGH" or (context.risk_score is not None and context.risk_score >= 50):
        matched_rules.append("RULE_4_HIGH_RISK_BLOCK")
        reasons.extend([
            f"High threat severity ({context.risk_score}/100)",
            "Insufficient AgentShield evidence for decoy routing",
            "Enforcing standard threat block policy"
        ])
        decision_str = policy_settings.DECISION_BLOCK
        reason_str = f"High threat risk ({context.risk_score}) without sufficient behavioral automation indicators for deception qualification; dropping request."
        return PolicyDecision(
            request_id=context.request_id,
            trace_id=context.trace_id,
            session_id=context.session_id,
            event_id=context.event_id,
            risk_assessment_id=context.risk_assessment_id,
            agent_shield_assessment_id=context.agent_shield_assessment_id,
            risk_score=context.risk_score,
            risk_severity=context.risk_severity,
            risk_confidence=context.risk_confidence,
            agent_shield_score=context.agent_shield_score,
            agent_shield_severity=context.agent_shield_severity,
            agent_shield_confidence=context.agent_shield_confidence,
            decision=decision_str,
            decision_reason=reason_str,
            explanation=reason_str,
            reasons=reasons,
            matched_rules=matched_rules,
            rule_matched="RULE_4_HIGH_RISK_BLOCK",
            rule_evaluation_chain=list(matched_rules),
            terminal=True,
            policy_version=policy_settings.POLICY_VERSION
        )

    # =========================================================================
    # RULE 5 — MEDIUM RISK (VELOCITY / REPEATED ACTIVITY RATE LIMIT vs MONITOR)
    # =========================================================================
    if context.risk_severity == "MEDIUM" or (context.risk_score is not None and 25 <= context.risk_score <= 49):
        # Inspect for high velocity or repeated probing evidence
        velocity_signals: Set[str] = {
            "request_velocity", "repeated_activity_elevated", 
            "authentication_probing", "endpoint_probing", "repeated_probing"
        }
        all_signals = context.risk_signals + context.agent_shield_signals
        observed_signal_names: Set[str] = set()
        for s in all_signals:
            if isinstance(s, dict):
                name = s.get("name") or s.get("signal_name") or ""
                if name:
                    observed_signal_names.add(str(name))
            elif isinstance(s, str):
                observed_signal_names.add(s)

        has_velocity = bool(velocity_signals & observed_signal_names) or context.correlated_event_count >= policy_settings.RATE_LIMIT_VELOCITY_THRESHOLD

        if has_velocity:
            matched_rules.append("RULE_5A_MEDIUM_RISK_RATE_LIMIT")
            reasons.extend([
                f"Medium threat score ({context.risk_score}/100)",
                f"Elevated request frequency observed ({context.correlated_event_count} events in window)",
                "Enforcing temporary rate throttle"
            ])
            decision_str = policy_settings.DECISION_RATE_LIMIT
            reason_str = f"Medium risk ({context.risk_score}) with elevated request velocity or repeated probing activity; rate limiting applied."
            rule_name = "RULE_5A_MEDIUM_RISK_RATE_LIMIT"
        else:
            matched_rules.append("RULE_5B_MEDIUM_RISK_MONITOR")
            reasons.extend([
                f"Medium threat score ({context.risk_score}/100)",
                "No abnormal velocity detected",
                "Active SOC telemetry observation enabled"
            ])
            decision_str = policy_settings.DECISION_MONITOR
            reason_str = f"Medium risk ({context.risk_score}) within acceptable threshold; tagging session for active telemetry observation."
            rule_name = "RULE_5B_MEDIUM_RISK_MONITOR"

        return PolicyDecision(
            request_id=context.request_id,
            trace_id=context.trace_id,
            session_id=context.session_id,
            event_id=context.event_id,
            risk_assessment_id=context.risk_assessment_id,
            agent_shield_assessment_id=context.agent_shield_assessment_id,
            risk_score=context.risk_score,
            risk_severity=context.risk_severity,
            risk_confidence=context.risk_confidence,
            agent_shield_score=context.agent_shield_score,
            agent_shield_severity=context.agent_shield_severity,
            agent_shield_confidence=context.agent_shield_confidence,
            decision=decision_str,
            decision_reason=reason_str,
            explanation=reason_str,
            reasons=reasons,
            matched_rules=matched_rules,
            rule_matched=rule_name,
            rule_evaluation_chain=list(matched_rules),
            terminal=False,
            policy_version=policy_settings.POLICY_VERSION
        )

    # =========================================================================
    # RULE 6 — LOW RISK (STANDARD LEGITIMATE TRAFFIC)
    # =========================================================================
    if context.risk_severity == "LOW" or (context.risk_score is not None and context.risk_score <= policy_settings.RISK_LOW_MAX):
        matched_rules.append("RULE_6_LOW_RISK_ALLOW")
        reasons.extend([
            f"Low risk score ({context.risk_score if context.risk_score is not None else 0}/100) within safe operational baseline",
            "Clean traffic telemetry verified",
            "Permitting standard origin forwarding"
        ])
        decision_str = policy_settings.DECISION_ALLOW
        reason_str = f"Low risk score ({context.risk_score if context.risk_score is not None else 0}) within normal operational parameters. Permitting upstream origin forwarding."
        return PolicyDecision(
            request_id=context.request_id,
            trace_id=context.trace_id,
            session_id=context.session_id,
            event_id=context.event_id,
            risk_assessment_id=context.risk_assessment_id,
            agent_shield_assessment_id=context.agent_shield_assessment_id,
            risk_score=int(context.risk_score) if context.risk_score is not None else 0,
            risk_severity="LOW",
            risk_confidence=context.risk_confidence or 1.0,
            agent_shield_score=int(context.agent_shield_score) if context.agent_shield_score is not None else 0,
            agent_shield_severity=context.agent_shield_severity or "LOW",
            agent_shield_confidence=context.agent_shield_confidence or 1.0,
            decision=decision_str,
            decision_reason=reason_str,
            explanation=reason_str,
            reasons=reasons,
            matched_rules=matched_rules,
            rule_matched="RULE_6_LOW_RISK_ALLOW",
            rule_evaluation_chain=list(matched_rules),
            terminal=False,
            policy_version=policy_settings.POLICY_VERSION
        )

    # =========================================================================
    # RULE 7 — UNKNOWN / INSUFFICIENT DATA (CONSERVATIVE FALLBACK)
    # =========================================================================
    # Never blindly default unverified or incomplete context to ALLOW.
    matched_rules.extend(["RULE_7_CONSERVATIVE_FALLBACK", "RULE_7_UNKNOWN_DATA_CONSERVATIVE_MONITOR"])
    reasons.extend([
        "Insufficient telemetry context to verify clean traffic",
        "Conservative defense fallback engaged",
        "Session flagged for active monitoring"
    ])
    decision_str = policy_settings.DECISION_MONITOR
    reason_str = "Incomplete or unknown security context; conservatively assigning MONITOR status. Never defaulting unverified traffic to ALLOW."
    return PolicyDecision(
        request_id=context.request_id,
        trace_id=context.trace_id,
        session_id=context.session_id,
        event_id=context.event_id,
        risk_assessment_id=context.risk_assessment_id,
        agent_shield_assessment_id=context.agent_shield_assessment_id,
        risk_score=context.risk_score,
        risk_severity=context.risk_severity,
        risk_confidence=context.risk_confidence,
        agent_shield_score=context.agent_shield_score,
        agent_shield_severity=context.agent_shield_severity,
        agent_shield_confidence=context.agent_shield_confidence,
        decision=decision_str,
        decision_reason=reason_str,
        explanation=reason_str,
        reasons=reasons,
        matched_rules=matched_rules,
        rule_matched="RULE_7_CONSERVATIVE_FALLBACK",
        rule_evaluation_chain=list(matched_rules),
        terminal=False,
        policy_version=policy_settings.POLICY_VERSION
    )
