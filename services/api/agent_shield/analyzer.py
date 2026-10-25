"""
AEGIS Ω — AgentShield Behavioral Analyzer
Orchestrates deterministic signal extraction, score calculation, severity tiering,
and defensive behavioral summary generation.
"""

from typing import Dict, Any, List, Optional
from agent_shield.config import agent_shield_settings
from agent_shield.models import AgentShieldResult
from agent_shield.signals import extract_behavioral_signals


def get_behavior_severity(score: int) -> str:
    """Map deterministic score to standardized behavior severity level."""
    if score >= agent_shield_settings.THRESHOLD_CRITICAL_MIN:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    return "LOW"


def generate_behavior_summary(severity: str, stages: List[str]) -> str:
    """Generates technically defensible, non-hallucinatory behavioral summary."""
    if severity == "CRITICAL":
        return "Activity shows characteristics consistent with highly automated and systematic attack behavior."
    elif severity == "HIGH":
        stage_desc = f" across stages: {' -> '.join(stages)}" if stages else ""
        return f"Elevated behavioral automation indicators detected{stage_desc}."
    elif severity == "MEDIUM":
        return "Moderate automation patterns detected; potential scripted reconnaissance observed."
    return "Standard interactive traffic pattern; low automation indicators."


def analyze_behavior(
    target_event: Dict[str, Any],
    historical_events: Optional[List[Dict[str, Any]]] = None
) -> AgentShieldResult:
    """
    Deterministic behavioral analysis engine.
    Produces identical results for identical inputs.
    """
    historical = historical_events or []
    req_id = target_event.get("request_id") or "unknown-req"
    trace_id = target_event.get("trace_id") or f"trace-{req_id}"
    session_id = target_event.get("session_id")

    # Extract behavioral signals, stages, and timeline
    signals, observed_stages, attack_timeline = extract_behavioral_signals(target_event, historical)

    # Calculate bounded score
    raw_total = sum(s.score for s in signals)
    final_score = min(
        agent_shield_settings.SCORE_MAX,
        max(agent_shield_settings.SCORE_MIN, raw_total)
    )

    severity = get_behavior_severity(final_score)

    # Deterministic Confidence Calculation
    if not signals:
        confidence = 0.50
    else:
        confidence = round(min(1.0, 0.40 + (0.12 * len(signals))), 2)

    behavior_summary = generate_behavior_summary(severity, observed_stages)

    return AgentShieldResult(
        request_id=req_id,
        trace_id=trace_id,
        session_id=session_id,
        agent_shield_score=final_score,
        severity=severity,
        confidence=confidence,
        signals=signals,
        attack_stages=observed_stages,
        attack_timeline=attack_timeline,
        behavior_summary=behavior_summary,
        engine_version=agent_shield_settings.ENGINE_VERSION,
        disclaimer=agent_shield_settings.TECHNICAL_DISCLAIMER
    )
