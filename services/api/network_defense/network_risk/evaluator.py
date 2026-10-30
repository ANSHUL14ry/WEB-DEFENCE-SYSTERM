"""
AEGIS Ω — Network Risk Engine (Phase 11)
Calculates deterministic, explainable network threat scores (0-100) based on observed network behavior.
"""

from datetime import datetime, timezone
import logging
from typing import Dict, Any, List, Optional
from network_defense.models import NetworkRiskAssessment, NetworkRiskSignal, NormalizedNetworkEvent

logger = logging.getLogger("aegis.network_defense.risk")


def map_network_severity(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    return "LOW"


def evaluate_network_risk(
    event: NormalizedNetworkEvent,
    recent_events_count: int = 1,
    unique_ports_count: int = 1,
    has_http_waf_correlation: bool = False
) -> NetworkRiskAssessment:
    """
    Evaluate deterministic network risk score (0-100) for a network event and source IP.
    Returns fully explainable signal breakdown.
    """
    signals: List[NetworkRiskSignal] = []
    base_score = 0

    sig_name = (event.signature or "").lower()
    cat_name = (event.category or "").lower()
    dest_port = event.destination_port or 0

    # Signal 1: Suricata Alert Severity
    if event.severity == "CRITICAL":
        signals.append(NetworkRiskSignal(
            name="SURICATA_CRITICAL_ALERT",
            score=75,
            reason=f"Suricata flagged critical exploit signature: {event.signature or 'Unknown'}"
        ))
        base_score += 75
    elif event.severity == "HIGH":
        signals.append(NetworkRiskSignal(
            name="SURICATA_HIGH_ALERT",
            score=50,
            reason=f"Suricata raised high-severity detection: {event.signature or 'Unknown'}"
        ))
        base_score += 50
    elif event.severity == "MEDIUM":
        signals.append(NetworkRiskSignal(
            name="SURICATA_MEDIUM_ALERT",
            score=15,
            reason="Suricata flagged suspicious network traffic anomaly"
        ))
        base_score += 15

    # Signal 2: Port Scanning / Reconnaissance Activity
    if unique_ports_count >= 3 or "scan" in sig_name or "sweep" in sig_name or "recon" in cat_name:
        scan_score = 35 if unique_ports_count >= 5 else 20
        signals.append(NetworkRiskSignal(
            name="PORT_SCAN_ACTIVITY",
            score=scan_score,
            reason=f"Observed multi-port probing behavior across {unique_ports_count} destination ports"
        ))
        base_score += scan_score

    # Signal 3: Connection Burst Rate
    if recent_events_count >= 15:
        burst_score = 25 if recent_events_count >= 30 else 15
        signals.append(NetworkRiskSignal(
            name="CONNECTION_RATE_SPIKE",
            score=burst_score,
            reason=f"Observed high-frequency burst of {recent_events_count} network events in rapid window"
        ))
        base_score += burst_score

    # Signal 4: Destination Concentration on Sensitive Administrative Ports
    if dest_port in (22, 23, 3389, 5432, 27017, 6379, 8080):
        signals.append(NetworkRiskSignal(
            name="SENSITIVE_PORT_TARGETING",
            score=15,
            reason=f"Direct probing targeting sensitive administrative or service port ({dest_port})"
        ))
        base_score += 15

    # Signal 5: Protocol Anomaly
    if event.event_type == "ANOMALY" or "anomaly" in sig_name:
        signals.append(NetworkRiskSignal(
            name="PROTOCOL_ANOMALY",
            score=20,
            reason="Observed protocol decoding deviation or malformed stream behavior"
        ))
        base_score += 20

    # Signal 6: Correlation with Application / WAF Attack
    if has_http_waf_correlation:
        signals.append(NetworkRiskSignal(
            name="HTTP_ATTACK_CORRELATION",
            score=25,
            reason="Network behavior strongly correlated with concurrent application-layer WAF exploit triggers"
        ))
        base_score += 25

    # Deterministic clamping 0-100
    final_score = min(max(base_score, 0), 100)
    severity = map_network_severity(final_score)

    if not signals:
        signals.append(NetworkRiskSignal(
            name="BASELINE_TRAFFIC",
            score=0,
            reason="Traffic parameters within acceptable baseline thresholds"
        ))
        explanation = "Normal network flow within acceptable baseline parameters."
    else:
        explanation = f"Network risk score {final_score}/100 ({severity}) driven by {len(signals)} observed telemetry signals."

    return NetworkRiskAssessment(
        source_ip=event.source_ip,
        network_risk_score=final_score,
        severity=severity,
        confidence=1.0,
        signals=signals,
        explanation=explanation,
        created_at=datetime.now(timezone.utc).isoformat()
    )


class NetworkRiskEvaluator:
    """Class wrapper for deterministic network risk evaluation."""
    def evaluate(
        self,
        event: NormalizedNetworkEvent,
        recent_events_count: int = 1,
        unique_ports_count: int = 1,
        has_http_waf_correlation: bool = False
    ) -> NetworkRiskAssessment:
        return evaluate_network_risk(
            event=event,
            recent_events_count=recent_events_count,
            unique_ports_count=unique_ports_count,
            has_http_waf_correlation=has_http_waf_correlation
        )
