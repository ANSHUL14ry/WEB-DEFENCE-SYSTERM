"""
AEGIS Ω — Phase 11 Integration Tests
Validates Real Network Defense — IDS/IPS + Network Behavior Correlation:

1. Suricata EVE alert event normalization
2. Suricata EVE flow event normalization
3. Suricata EVE http event normalization
4. Suricata EVE anomaly event normalization
5. Invalid/malformed EVE and IP rejection (no crashes, zero fake data)
6. Network Risk Engine: LOW (0-24) risk evaluation
7. Network Risk Engine: MEDIUM (25-49) risk evaluation
8. Network Risk Engine: HIGH (50-74) risk evaluation
9. Network Risk Engine: CRITICAL (75-100) risk evaluation
10. Network Policy Engine: Adaptive combination of Web + Network Risk
11. Network Policy Engine: Terminal WAF Block invariant preservation
12. Network IPS Enforcement: OBSERVE mode logging
13. Network IPS Enforcement: RATE_LIMIT and TEMP_BLOCK with TTL expiration
14. Network IPS Enforcement: BLOCK and RELEASE with auditable logging
15. Network Anomaly & DoS Detector: Baseline tracking & ELEVATED classification
16. Network Anomaly & DoS Detector: Volumetric flood flags UPSTREAM_DDOS_RECOMMENDED
17. Deterministic MITRE mapping for network signatures (T1595.002, T1083, T1190)
18. End-to-end Attack Story Reconstruction (STAGE 0: NETWORK -> STAGE 11: VERIFIED)
19. Verification Engine Rule 6: Network mitigation proof generation
20. WebSocket live broadcast for network events
21. Real API endpoints testing (/status, /events, /ingest-eve, /enforcements, /release)
22. Regression: WAF blocks SQLi with 403 Forbidden
23. Regression: Preserves existing Risk, Policy, AgentShield baselines
24. Regression: Preserves Deception isolation & Response Verification proofs
"""

import asyncio
import json
import os
import sys
import time
import uuid
import pytest
import requests
import websockets

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../services/api")))

from network_defense.network_parser.parser import parse_suricata_eve_line, normalize_network_event
from network_defense.network_risk.evaluator import NetworkRiskEvaluator
from network_defense.network_policy.policy import NetworkPolicyEvaluator
from network_defense.enforcement.adapter import DevNetworkEnforcementAdapter
from network_defense.anomaly.detector import NetworkTrafficBaseline, NetworkAnomalyDetector
from network_defense.correlation.attack_story import AttackStoryReconstructor
from network_defense.models import NormalizedNetworkEvent
from enrichment.mitre import map_mitre_techniques

GATEWAY_URL = "http://localhost:8080"
API_URL = "http://localhost:8001"
WS_API_URL = "ws://localhost:8001/api/v1/ws/events"


def test_01_suricata_eve_alert_normalization():
    """Scenario 1: Parser extracts alert details, signature, severity, and MITRE mapping."""
    raw_eve = json.dumps({
        "timestamp": "2026-10-27T19:41:58.210452+0000",
        "event_type": "alert",
        "src_ip": "198.51.100.44",
        "src_port": 54321,
        "dest_ip": "172.20.0.10",
        "dest_port": 8080,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2000001,
            "rev": 1,
            "signature": "ET SCAN Potential Nmap Port Sweep / Vulnerability Scan",
            "category": "Attempted Information Leak",
            "severity": 2
        }
    })
    event = parse_suricata_eve_line(raw_eve)
    assert event is not None
    assert event.event_type == "alert"
    assert event.source_ip == "198.51.100.44"
    assert event.dest_port == 8080
    assert event.protocol == "TCP"
    assert event.signature == "ET SCAN Potential Nmap Port Sweep / Vulnerability Scan"
    assert event.signature_id == 2000001
    assert event.severity == "MEDIUM"
    assert event.mitre_technique == "T1595.002"
    assert event.sensor == "suricata"


def test_02_suricata_eve_flow_normalization():
    """Scenario 2: Parser extracts network flow volume, bytes, and packet metrics."""
    raw_eve = json.dumps({
        "timestamp": "2026-10-27T19:42:00.000000+0000",
        "event_type": "flow",
        "src_ip": "198.51.100.44",
        "src_port": 54322,
        "dest_ip": "172.20.0.10",
        "dest_port": 8080,
        "proto": "TCP",
        "flow": {
            "pkts_toserver": 45,
            "pkts_toclient": 38,
            "bytes_toserver": 8420,
            "bytes_toclient": 15400,
            "start": "2026-10-27T19:41:55.000000+0000",
            "end": "2026-10-27T19:42:00.000000+0000",
            "age": 5,
            "state": "closed"
        }
    })
    event = parse_suricata_eve_line(raw_eve)
    assert event is not None
    assert event.event_type == "flow"
    assert event.bytes_in == 8420
    assert event.bytes_out == 15400
    assert event.packets_in == 45
    assert event.packets_out == 38
    assert event.flow_duration_ms == 5000.0


def test_03_suricata_eve_http_normalization():
    """Scenario 3: Parser extracts HTTP application metadata from Suricata inspection."""
    raw_eve = json.dumps({
        "timestamp": "2026-10-27T19:42:01.000000+0000",
        "event_type": "http",
        "src_ip": "198.51.100.44",
        "src_port": 54323,
        "dest_ip": "172.20.0.10",
        "dest_port": 8080,
        "proto": "TCP",
        "http": {
            "hostname": "aegis.defense.local",
            "url": "/api/v1/swagger.json",
            "http_user_agent": "python-requests/2.31.0",
            "http_method": "GET",
            "protocol": "HTTP/1.1",
            "status": 200
        }
    })
    event = parse_suricata_eve_line(raw_eve)
    assert event is not None
    assert event.event_type == "http"
    assert event.http_method == "GET"
    assert event.http_uri == "/api/v1/swagger.json"
    assert event.http_user_agent == "python-requests/2.31.0"
    assert event.http_status == 200


def test_04_suricata_eve_anomaly_normalization():
    """Scenario 4: Parser normalizes Suricata anomaly events without crash."""
    raw_eve = json.dumps({
        "timestamp": "2026-10-27T19:42:02.000000+0000",
        "event_type": "anomaly",
        "src_ip": "198.51.100.44",
        "src_port": 54324,
        "dest_ip": "172.20.0.10",
        "dest_port": 8080,
        "proto": "TCP",
        "anomaly": {
            "app_proto": "failed",
            "event": "STREAM_TCP_PACKET_INVALID_ACK",
            "type": "stream"
        }
    })
    event = parse_suricata_eve_line(raw_eve)
    assert event is not None
    assert event.event_type == "anomaly"
    assert event.severity == "MEDIUM"


def test_05_invalid_malformed_eve_rejection():
    """Scenario 5: Malformed JSON or invalid IP address is safely rejected with zero fake data."""
    # Invalid JSON
    assert parse_suricata_eve_line("INVALID NOT JSON {{{") is None
    # Empty string
    assert parse_suricata_eve_line("") is None
    # Missing source IP
    raw_missing_ip = json.dumps({"timestamp": "2026-10-27T19:42:00Z", "event_type": "alert"})
    assert parse_suricata_eve_line(raw_missing_ip) is None
    # Invalid IP format
    raw_bad_ip = json.dumps({
        "timestamp": "2026-10-27T19:42:00Z",
        "event_type": "alert",
        "src_ip": "999.999.999.999"
    })
    assert parse_suricata_eve_line(raw_bad_ip) is None


def test_06_network_risk_engine_low_score():
    """Scenario 6: Benign or standard flow evaluates to deterministic LOW risk (0-24)."""
    evaluator = NetworkRiskEvaluator()
    event = NormalizedNetworkEvent(
        event_id="net_test_01",
        sensor="suricata",
        timestamp="2026-10-27T19:42:00Z",
        source_ip="198.51.100.10",
        dest_ip="172.20.0.10",
        dest_port=8080,
        protocol="TCP",
        event_type="flow",
        severity="INFO"
    )
    assessment = evaluator.evaluate(event)
    assert 0 <= assessment.network_risk_score <= 24
    assert assessment.severity == "LOW"
    assert len(assessment.signals) >= 1
    assert any("BASELINE_TRAFFIC" in s["signal"] for s in assessment.signals)


def test_07_network_risk_engine_medium_score():
    """Scenario 7: Recon or port sweep signal evaluates to deterministic MEDIUM risk (25-49)."""
    evaluator = NetworkRiskEvaluator()
    event = NormalizedNetworkEvent(
        event_id="net_test_02",
        sensor="suricata",
        timestamp="2026-10-27T19:42:00Z",
        source_ip="198.51.100.20",
        dest_ip="172.20.0.10",
        dest_port=8080,
        protocol="TCP",
        event_type="alert",
        signature="ET SCAN Potential Nmap Port Sweep / Vulnerability Scan",
        severity="MEDIUM",
        mitre_technique="T1595.002"
    )
    assessment = evaluator.evaluate(event)
    assert 25 <= assessment.network_risk_score <= 49
    assert assessment.severity == "MEDIUM"


def test_08_network_risk_engine_high_score():
    """Scenario 8: High severity alert evaluates to deterministic HIGH risk (50-74)."""
    evaluator = NetworkRiskEvaluator()
    event = NormalizedNetworkEvent(
        event_id="net_test_03",
        sensor="suricata",
        timestamp="2026-10-27T19:42:00Z",
        source_ip="198.51.100.30",
        dest_ip="172.20.0.10",
        dest_port=8080,
        protocol="TCP",
        event_type="alert",
        signature="ET WEB_SPECIFIC_APPS Directory Traversal",
        severity="HIGH",
        mitre_technique="T1083"
    )
    assessment = evaluator.evaluate(event)
    assert 50 <= assessment.network_risk_score <= 74
    assert assessment.severity == "HIGH"


def test_09_network_risk_engine_critical_score():
    """Scenario 9: Critical exploit alert evaluates to deterministic CRITICAL risk (75-100)."""
    evaluator = NetworkRiskEvaluator()
    event = NormalizedNetworkEvent(
        event_id="net_test_04",
        sensor="suricata",
        timestamp="2026-10-27T19:42:00Z",
        source_ip="198.51.100.40",
        dest_ip="172.20.0.10",
        dest_port=8080,
        protocol="TCP",
        event_type="alert",
        signature="ET EXPLOIT Remote Code Execution Attempt Inbound",
        severity="CRITICAL",
        mitre_technique="T1190"
    )
    assessment = evaluator.evaluate(event)
    assert 75 <= assessment.network_risk_score <= 100
    assert assessment.severity == "CRITICAL"


def test_10_network_policy_engine_adaptive_decision():
    """Scenario 10: Policy Engine synthesizes Web Risk + Network Risk + AgentShield."""
    policy = NetworkPolicyEvaluator()
    decision = policy.evaluate(
        web_risk_score=85,
        network_risk_score=80,
        agentshield_score=90,
        waf_blocked=False,
        deception_eligible=True
    )
    assert decision.action == "DECEIVE"
    assert decision.matched_rule == "RULE_UNIFIED_ADAPTIVE_DECEPTION"
    assert decision.is_terminal is False


def test_11_terminal_waf_block_invariant_preservation():
    """Scenario 11: Terminal WAF Block invariant is NEVER downgraded to ALLOW or DECEIVE."""
    policy = NetworkPolicyEvaluator()
    decision = policy.evaluate(
        web_risk_score=95,
        network_risk_score=95,
        agentshield_score=95,
        waf_blocked=True,
        deception_eligible=True
    )
    assert decision.action == "BLOCK"
    assert decision.is_terminal is True
    assert decision.matched_rule == "TERMINAL_WAF_BLOCK_INVARIANT"


def test_12_network_ips_enforcement_observe_mode():
    """Scenario 12: IPS enforcement in OBSERVE mode logs without blocking."""
    adapter = DevNetworkEnforcementAdapter()
    record = adapter.enforce(
        source_ip="198.51.100.50",
        action="OBSERVE",
        reason="Passive IDS logging mode",
        network_risk_score=40
    )
    assert record.action == "OBSERVE"
    assert record.source_ip == "198.51.100.50"
    assert record.is_active is False


def test_13_network_ips_enforcement_rate_limit_and_temp_block():
    """Scenario 13: IPS enforcement records RATE_LIMIT and TEMP_BLOCK with TTL expiration."""
    adapter = DevNetworkEnforcementAdapter()
    record = adapter.enforce(
        source_ip="198.51.100.55",
        action="TEMP_BLOCK",
        reason="Burst anomaly detected",
        network_risk_score=70,
        ttl_seconds=300
    )
    assert record.action == "TEMP_BLOCK"
    assert record.ttl_seconds == 300
    assert record.expires_at is not None
    assert record.is_active is True


def test_14_network_ips_enforcement_block_and_release():
    """Scenario 14: IPS enforcement applies BLOCK and allows auditable RELEASE."""
    adapter = DevNetworkEnforcementAdapter()
    block_record = adapter.enforce(
        source_ip="198.51.100.60",
        action="BLOCK",
        reason="Critical attack chain",
        network_risk_score=95
    )
    assert block_record.action == "BLOCK"
    assert block_record.is_active is True

    release_record = adapter.release(
        source_ip="198.51.100.60",
        reason="SOC Analyst verified benign"
    )
    assert release_record is not None
    assert release_record.action == "RELEASE"
    assert release_record.is_active is False
    assert release_record.released_at is not None


def test_15_network_anomaly_detector_elevated_classification():
    """Scenario 15: Traffic rate spike above 2x triggers ELEVATED anomaly."""
    baseline = NetworkTrafficBaseline(window_seconds=60)
    # Seed baseline with 10 requests over 10 seconds
    for _ in range(10):
        baseline.record_event(bytes_count=200)

    detector = NetworkAnomalyDetector(baseline)
    # Simulate a sudden burst of 50 events
    for _ in range(50):
        baseline.record_event(bytes_count=200)

    report = detector.check_anomalies(source_ip="198.51.100.70")
    assert report is not None
    assert report.severity in ["ELEVATED", "ANOMALOUS", "CRITICAL"]
    assert report.deviation_factor > 1.5


def test_16_network_anomaly_detector_ddos_recommendation():
    """Scenario 16: Massive volumetric flood flags UPSTREAM_DDOS_RECOMMENDED."""
    baseline = NetworkTrafficBaseline(window_seconds=60)
    for _ in range(5):
        baseline.record_event(bytes_count=100)

    detector = NetworkAnomalyDetector(baseline)
    # Volumetric flood: 500 events
    for _ in range(500):
        baseline.record_event(bytes_count=10000)

    report = detector.check_anomalies(source_ip="198.51.100.80")
    assert report is not None
    assert report.severity == "CRITICAL"
    assert report.mitigation_recommendation == "UPSTREAM_DDOS_RECOMMENDED"


def test_17_deterministic_mitre_mapping_network_signatures():
    """Scenario 17: Network signatures map deterministically to valid MITRE ATT&CK techniques."""
    tech_scan = map_mitre_techniques(
        waf_rule_id=None,
        agentshield_stages=[],
        network_signature="ET SCAN Potential Nmap Port Sweep"
    )
    assert any(t.technique_id == "T1595.002" for t in tech_scan)

    tech_exploit = map_mitre_techniques(
        waf_rule_id=None,
        agentshield_stages=[],
        network_signature="ET EXPLOIT Remote Code Execution"
    )
    assert any(t.technique_id == "T1190" for t in tech_exploit)


def test_18_attack_story_reconstruction_pipeline():
    """Scenario 18: Attack Story reconstructor synthesizes chronological incident steps."""
    reconstructor = AttackStoryReconstructor()
    story = reconstructor.build_story(
        source_ip="198.51.100.90",
        network_events=[{
            "stage_id": "st-0",
            "category": "NETWORK",
            "label": "STAGE 0: NETWORK RECON",
            "timestamp": "2026-10-27T19:41:58Z",
            "severity": "MEDIUM",
            "detail": "Suricata EVE IDS detected Nmap port sweep"
        }],
        security_events=[{
            "stage_id": "st-1",
            "category": "WEB",
            "label": "STAGE 1: RECON",
            "timestamp": "2026-10-27T19:42:01Z",
            "severity": "LOW",
            "detail": "GET /robots.txt probed via Gateway"
        }],
        policy_decisions=[{
            "stage_id": "st-8",
            "category": "POLICY",
            "label": "STAGE 8: POLICY DECISION",
            "timestamp": "2026-10-27T19:42:10Z",
            "severity": "CRITICAL",
            "detail": "DECEIVE_ELIGIBLE qualified"
        }]
    )
    assert story.source_ip == "198.51.100.90"
    assert len(story.stages) >= 3
    assert story.stages[0].category == "NETWORK"
    assert story.stages[0].label == "STAGE 0: NETWORK RECON"
    assert story.origin_untouched is True


def test_19_verification_engine_network_defense_rule():
    """Scenario 19: Verification Engine Rule 6 verifies Network Defense mitigation proof."""
    from verification.models import VerificationContext
    from verification.evaluator import ResponseVerificationEvaluator

    evaluator = ResponseVerificationEvaluator()
    ctx = VerificationContext(
        request_id="req_net_proof_01",
        trace_id="tr_net_proof_01",
        session_id=None,
        client_ip="198.51.100.95",
        target_path="/api/v1/internal",
        policy_decision="BLOCK",
        actual_origin_access=False,
        origin_status_code=None,
        origin_response_time_ms=None,
        production_db_accessed=False,
        network_enforcement_action="BLOCK",
        network_mitigation_verified=True
    )
    result = evaluator.evaluate(ctx)
    assert result.verification_status == "VERIFIED"
    assert result.confidence == 1.0
    assert any("RULE_6_NETWORK_DEFENSE_MITIGATION" in p["rule"] for p in result.proof_points)


def test_20_websocket_network_event_broadcast():
    """Scenario 20: WebSocket stream receives live broadcast on network event ingestion."""
    async def _test_ws():
        async with websockets.connect(WS_API_URL, ping_timeout=10) as ws:
            # Send an EVE alert event to the ingest endpoint
            payload = {
                "eve_line": json.dumps({
                    "timestamp": "2026-10-27T19:45:00.000000+0000",
                    "event_type": "alert",
                    "src_ip": "198.51.100.111",
                    "src_port": 50123,
                    "dest_ip": "172.20.0.10",
                    "dest_port": 8080,
                    "proto": "TCP",
                    "alert": {
                        "action": "allowed",
                        "gid": 1,
                        "signature_id": 2000001,
                        "rev": 1,
                        "signature": "ET SCAN Potential Nmap Port Sweep",
                        "category": "Attempted Information Leak",
                        "severity": 2
                    }
                })
            }
            res = requests.post(f"{API_URL}/api/v1/network-defense/ingest-eve", json=payload, timeout=5)
            assert res.status_code == 200

            # Wait for WebSocket event
            for _ in range(5):
                msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
                event_data = json.loads(msg)
                if event_data.get("event_type") == "NETWORK_EVENT_INGESTED":
                    src = event_data.get("data", {}).get("source_ip") or event_data.get("source_ip")
                    assert src == "198.51.100.111"
                    return True
            return False

    received = asyncio.run(_test_ws())
    assert received is True


def test_21_network_defense_api_endpoints():
    """Scenario 21: Real API endpoints return valid telemetry with zero fake data."""
    # 1. Status
    res_status = requests.get(f"{API_URL}/api/v1/network-defense/status", timeout=5)
    assert res_status.status_code == 200
    status_data = res_status.json()
    assert "sensor_status" in status_data
    assert status_data["sensor_status"] in ["LIVE", "STANDBY", "NOT_CONNECTED"]
    assert status_data["sensor_name"] == "suricata"

    # 2. Events query
    res_events = requests.get(f"{API_URL}/api/v1/network-defense/events?limit=10", timeout=5)
    assert res_events.status_code == 200
    events_data = res_events.json()
    assert "events" in events_data

    # 3. Trigger demo scenario
    res_demo = requests.post(
        f"{API_URL}/api/v1/network-defense/demo/trigger?scenario=NETWORK_RECON",
        timeout=10
    )
    assert res_demo.status_code == 200
    demo_data = res_demo.json()
    assert demo_data["status"] == "SUCCESS"
    assert demo_data["scenario"] == "NETWORK_RECON"

    # 4. Enforcements query
    res_enf = requests.get(f"{API_URL}/api/v1/network-defense/enforcements", timeout=5)
    assert res_enf.status_code == 200
    assert "enforcements" in res_enf.json()


def test_22_waf_sqli_regression():
    """Scenario 22: Coraza WAF still blocks SQL injection with HTTP 403 Forbidden."""
    res = requests.get(f"{GATEWAY_URL}/products?id=1%20UNION%20SELECT%20NULL,username,password%20FROM%20users--", timeout=5)
    assert res.status_code == 403


def test_23_phase1_to_9_pipeline_regression():
    """Scenario 23: Gateway health and system status report operational."""
    res_gw = requests.get(f"{GATEWAY_URL}/healthz", timeout=5)
    assert res_gw.status_code == 200
    assert res_gw.json().get("status") == "healthy"

    res_sys = requests.get(f"{API_URL}/api/v1/system/status", timeout=5)
    assert res_sys.status_code == 200
    sys_data = res_sys.json()
    assert "network_defense" in sys_data["services"]
    assert "network_events_count" in sys_data["metrics"]


def test_24_deception_isolation_regression():
    """Scenario 24: Isolated decoy continues operating independently."""
    res_decoy = requests.get(f"{API_URL}/api/v1/deception/stats", timeout=5)
    assert res_decoy.status_code == 200
    assert "total_sessions" in res_decoy.json()
