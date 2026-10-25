"""
AEGIS Ω — Deterministic Risk Evaluator
Calculates explainable risk scores (0-100) and severity rankings from real security telemetry.
Independent from external AI APIs; 100% reproducible and testable.
"""

from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from pydantic import BaseModel, Field
from risk_engine.config import risk_settings
from risk_engine.sensitivity import classify_endpoint_sensitivity


class RiskSignal(BaseModel):
    name: str
    score: int
    reason: str


class RiskAssessmentResult(BaseModel):
    risk_score: int
    severity: str
    confidence: float
    signals: List[RiskSignal]
    engine_version: str = risk_settings.ENGINE_VERSION


def get_severity_for_score(score: int) -> str:
    """Map deterministic score to standardized severity level."""
    if score >= risk_settings.THRESHOLD_CRITICAL_MIN:
        return "CRITICAL"
    elif score >= risk_settings.THRESHOLD_HIGH_MAX - 24: # >= 50
        return "HIGH"
    elif score >= risk_settings.THRESHOLD_MEDIUM_MAX - 24: # >= 25
        return "MEDIUM"
    return "LOW"


def evaluate_risk(
    target_event: Dict[str, Any],
    historical_events: Optional[List[Dict[str, Any]]] = None
) -> RiskAssessmentResult:
    """
    Deterministic scoring engine.
    Produces identical scores for identical inputs.
    """
    signals: List[RiskSignal] = []
    historical = historical_events or []

    # 1. WAF Severity Signal
    target_sev = str(target_event.get("severity", "INFO")).upper()
    comp = str(target_event.get("component", "")).lower()
    act = str(target_event.get("action", "")).upper()

    if comp == "coraza" or "WAF" in str(target_event.get("event_type", "")):
        if target_sev == "CRITICAL":
            signals.append(RiskSignal(
                name="waf_severity",
                score=risk_settings.WEIGHT_WAF_CRITICAL,
                reason="Critical-severity WAF rule violation detected"
            ))
        elif target_sev == "HIGH":
            signals.append(RiskSignal(
                name="waf_severity",
                score=risk_settings.WEIGHT_WAF_HIGH,
                reason="High-severity WAF detection observed"
            ))
        elif target_sev == "MEDIUM":
            signals.append(RiskSignal(
                name="waf_severity",
                score=risk_settings.WEIGHT_WAF_MEDIUM,
                reason="Medium-severity WAF anomaly observed"
            ))
        elif target_sev == "LOW":
            signals.append(RiskSignal(
                name="waf_severity",
                score=risk_settings.WEIGHT_WAF_LOW,
                reason="Low-severity WAF notification observed"
            ))

    # 2. Known High-Risk Attack Signature (CRS Rules)
    meta = target_event.get("metadata", {}) or {}
    rule_id = meta.get("rule_id", 0)
    try:
        rule_num = int(rule_id)
    except (ValueError, TypeError):
        rule_num = 0

    if rule_num > 0:
        for r_min, r_max, r_desc in risk_settings.ATTACK_RULE_RANGES:
            if r_min <= rule_num <= r_max:
                signals.append(RiskSignal(
                    name="known_attack_rule",
                    score=risk_settings.WEIGHT_KNOWN_ATTACK_RULE,
                    reason=f"Matched OWASP CRS attack signature (Rule {rule_num}: {r_desc})"
                ))
                break

    # 3. Anomaly Score Threshold Exceeded
    anomaly_score = meta.get("anomaly_score", 0)
    try:
        anomaly_val = int(anomaly_score)
    except (ValueError, TypeError):
        anomaly_val = 0

    if anomaly_val >= 5:
        signals.append(RiskSignal(
            name="elevated_anomaly_score",
            score=risk_settings.WEIGHT_ANOMALY_SCORE_ELEVATED,
            reason=f"CRS transaction anomaly score exceeded baseline threshold (score: {anomaly_val})"
        ))

    # 4. Target Endpoint Sensitivity
    req_data = target_event.get("request", {}) or {}
    target_uri = req_data.get("uri") or target_event.get("uri", "/")
    sens_level, sens_weight, sens_reason = classify_endpoint_sensitivity(target_uri)
    if sens_weight > 0:
        signals.append(RiskSignal(
            name="endpoint_sensitivity",
            score=sens_weight,
            reason=sens_reason
        ))

    # 5. Temporal Window: Repeated Activity
    if len(historical) >= 4:
        signals.append(RiskSignal(
            name="repeated_activity_elevated",
            score=risk_settings.WEIGHT_REPEATED_ACTIVITY_ELEVATED,
            reason=f"Elevated activity: {len(historical)} correlated events recorded within 60s temporal window"
        ))
    elif len(historical) >= 2:
        signals.append(RiskSignal(
            name="repeated_activity_moderate",
            score=risk_settings.WEIGHT_REPEATED_ACTIVITY_MODERATE,
            reason=f"Repeated activity: {len(historical)} correlated events recorded within 60s temporal window"
        ))

    # 6. Temporal Window: Request Velocity
    if len(historical) >= 5:
        signals.append(RiskSignal(
            name="request_velocity",
            score=risk_settings.WEIGHT_HIGH_VELOCITY,
            reason=f"Rapid request velocity: {len(historical)} requests executed in close sequence"
        ))

    # 7. Endpoint Enumeration / Probing Progression
    visited_uris = set()
    for ev in historical:
        h_req = ev.get("request", {}) or {}
        h_uri = h_req.get("uri") or ev.get("uri", "")
        if h_uri:
            path = urlparse(h_uri).path
            if path:
                visited_uris.add(path)
    if target_uri:
        visited_uris.add(urlparse(target_uri).path)

    if len(visited_uris) >= 3:
        signals.append(RiskSignal(
            name="endpoint_probing",
            score=risk_settings.WEIGHT_PROBING_MULTIPLE_ENDPOINTS,
            reason=f"Endpoint enumeration observed: {len(visited_uris)} distinct URI paths probed across trace chain"
        ))

    # Sum raw scores & cap at 100
    raw_total = sum(s.score for s in signals)
    final_score = min(risk_settings.SCORE_MAX, max(risk_settings.SCORE_MIN, raw_total))
    severity = get_severity_for_score(final_score)

    # Deterministic Confidence Calculation
    if len(signals) == 0:
        confidence = 0.50
    else:
        confidence = round(min(1.0, 0.50 + (0.10 * len(signals))), 2)

    return RiskAssessmentResult(
        risk_score=final_score,
        severity=severity,
        confidence=confidence,
        signals=signals,
        engine_version=risk_settings.ENGINE_VERSION
    )
