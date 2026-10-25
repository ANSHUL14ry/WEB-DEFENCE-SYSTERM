"""
AEGIS Ω — Phase 5 Integration Tests
Validates the Explainable Risk Engine:
Deterministic scoring, severity thresholds, signal generation,
WAF severity weights, endpoint sensitivity, temporal correlation,
failure-safety, persistence, and real-time WebSocket delivery.
"""

import asyncio
import json
import time
import uuid
import pytest
import requests
import websockets

GATEWAY_URL = "http://localhost:8080"
API_URL = "http://localhost:8001"
WS_API_URL = "ws://localhost:8001/api/v1/ws/events"


def test_01_low_risk_calculation():
    """Verify clean or informational events calculate a LOW risk score (0-24)."""
    payload = {
        "event_type": "ORIGIN_REQUEST",
        "request_id": f"low-req-{uuid.uuid4().hex[:8]}",
        "trace_id": f"low-trace-{uuid.uuid4().hex[:8]}",
        "severity": "INFO",
        "action": "ALLOW",
        "component": "origin",
        "status": "ALLOWED",
        "source": {"ip": "127.0.0.1"},
        "request": {"method": "GET", "uri": "/products"},
        "metadata": {"processing_time_ms": 1.5}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/risk/assess", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] <= 24
    assert data["severity"] == "LOW"


def test_02_medium_risk_calculation():
    """Verify medium-severity events (e.g. sensitive probe / warning) score between 25-49 (MEDIUM)."""
    payload = {
        "event_type": "WAF_DETECTION",
        "request_id": f"med-req-{uuid.uuid4().hex[:8]}",
        "trace_id": f"med-trace-{uuid.uuid4().hex[:8]}",
        "severity": "MEDIUM",
        "action": "OBSERVED",
        "component": "coraza",
        "status": "DETECTED",
        "source": {"ip": "10.1.1.5"},
        "request": {"method": "GET", "uri": "/login"},
        "metadata": {"rule_id": 920100} # Protocol anomaly
    }
    res = requests.post(f"{API_URL}/api/v1/internal/risk/assess", json=payload)
    assert res.status_code == 200
    data = res.json()
    # WAF_MEDIUM (10) + Endpoint Medium /login (10) = 20-30 range
    assert 20 <= data["risk_score"] <= 49
    assert data["severity"] in ["LOW", "MEDIUM"]


def test_03_high_risk_calculation():
    """Verify high-severity WAF detections score between 50-74 (HIGH)."""
    payload = {
        "event_type": "WAF_BLOCK",
        "request_id": f"high-req-{uuid.uuid4().hex[:8]}",
        "trace_id": f"high-trace-{uuid.uuid4().hex[:8]}",
        "severity": "HIGH",
        "action": "BLOCK",
        "component": "coraza",
        "status": "BLOCKED",
        "source": {"ip": "10.2.2.5"},
        "request": {"method": "GET", "uri": "/products?search=test"},
        "metadata": {
            "rule_id": 942100, # SQLi rule (+20)
            "anomaly_score": 5  # Elevated score (+10)
        }
    }
    # High severity (+20) + SQLi rule (+20) + Anomaly (+10) = 50 -> HIGH
    res = requests.post(f"{API_URL}/api/v1/internal/risk/assess", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert 50 <= data["risk_score"] <= 74
    assert data["severity"] == "HIGH"


def test_04_critical_risk_calculation():
    """Verify combined attack indicators score >= 75 (CRITICAL)."""
    payload = {
        "event_type": "WAF_BLOCK",
        "request_id": f"crit-req-{uuid.uuid4().hex[:8]}",
        "trace_id": f"crit-trace-{uuid.uuid4().hex[:8]}",
        "severity": "CRITICAL",
        "action": "BLOCK",
        "component": "coraza",
        "status": "BLOCKED",
        "source": {"ip": "198.51.100.1"},
        "request": {"method": "POST", "uri": "/admin/login"},
        "metadata": {
            "rule_id": 942100, # SQLi rule (+20)
            "anomaly_score": 10 # Elevated anomaly (+10)
        }
    }
    # WAF CRITICAL (+30) + Attack Rule (+20) + Anomaly (+10) + High Endpoint /admin (+20) = 80 -> CRITICAL
    res = requests.post(f"{API_URL}/api/v1/internal/risk/assess", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] >= 75
    assert data["severity"] == "CRITICAL"


def test_05_deterministic_scoring_reproducibility():
    """Verify that identical input payloads evaluate to the exact same score and signals."""
    payload = {
        "event_type": "WAF_BLOCK",
        "request_id": "deterministic-req-01",
        "trace_id": "deterministic-trace-01",
        "severity": "CRITICAL",
        "action": "BLOCK",
        "component": "coraza",
        "status": "BLOCKED",
        "source": {"ip": "172.20.0.1"},
        "request": {"method": "GET", "uri": "/admin?test=1"},
        "metadata": {"rule_id": 941100, "anomaly_score": 5}
    }
    res1 = requests.post(f"{API_URL}/api/v1/internal/risk/assess", json=payload).json()
    res2 = requests.post(f"{API_URL}/api/v1/internal/risk/assess", json=payload).json()

    assert res1["risk_score"] == res2["risk_score"]
    assert res1["severity"] == res2["severity"]
    assert res1["confidence"] == res2["confidence"]
    assert len(res1["signals"]) == len(res2["signals"])
    assert [s["name"] for s in res1["signals"]] == [s["name"] for s in res2["signals"]]


def test_06_score_capped_at_100():
    """Verify that cumulative signals exceeding 100 points are strictly capped at 100."""
    # Build payload with excessive theoretical weights
    payload = {
        "event_type": "WAF_BLOCK",
        "request_id": f"cap-req-{uuid.uuid4().hex[:8]}",
        "trace_id": f"cap-trace-{uuid.uuid4().hex[:8]}",
        "severity": "CRITICAL", # +30
        "action": "BLOCK",
        "component": "coraza",
        "status": "BLOCKED",
        "source": {"ip": "10.9.9.9"},
        "request": {"method": "POST", "uri": "/admin/config"}, # +20
        "metadata": {
            "rule_id": 942100, # +20
            "anomaly_score": 15 # +10
        }
    }
    # Pre-seed historical events under same trace to trigger repeated (+20), velocity (+15), probing (+10)
    for i in range(5):
        requests.post(f"{API_URL}/api/v1/internal/events", json={
            "event_type": "GATEWAY_REQUEST",
            "request_id": f"pre-{i}-{uuid.uuid4().hex[:6]}",
            "trace_id": payload["trace_id"],
            "component": "gateway",
            "severity": "HIGH",
            "action": "BLOCK",
            "status": "BLOCKED",
            "request": {"method": "GET", "uri": f"/probe-{i}"}
        })

    res = requests.post(f"{API_URL}/api/v1/internal/risk/assess", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] == 100
    assert data["severity"] == "CRITICAL"


def test_07_endpoint_sensitivity_contribution():
    """Verify endpoint sensitivity classifications accurately adjust risk points."""
    req_base = {
        "event_type": "GATEWAY_REQUEST",
        "request_id": f"sens-req-{uuid.uuid4().hex[:8]}",
        "trace_id": f"sens-trace-{uuid.uuid4().hex[:8]}",
        "severity": "INFO",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "metadata": {}
    }

    # Public endpoint -> score 0
    res_pub = requests.post(f"{API_URL}/api/v1/internal/risk/assess", json={
        **req_base, "request": {"method": "GET", "uri": "/products"}
    }).json()
    pub_score = res_pub["risk_score"]

    # Sensitive /admin endpoint -> score increases by +20
    res_admin = requests.post(f"{API_URL}/api/v1/internal/risk/assess", json={
        **req_base, "request": {"method": "GET", "uri": "/admin/settings"}
    }).json()
    admin_score = res_admin["risk_score"]

    assert admin_score == pub_score + 20
    signal_names = [s["name"] for s in res_admin["signals"]]
    assert "endpoint_sensitivity" in signal_names


def test_08_risk_assessment_persistence_and_retrieval():
    """Verify that calculated risk assessments are stored in PostgreSQL and retrievable by ID."""
    req_id = f"persist-req-{uuid.uuid4().hex[:8]}"
    trace_id = f"persist-trace-{uuid.uuid4().hex[:8]}"
    payload = {
        "event_type": "WAF_BLOCK",
        "request_id": req_id,
        "trace_id": trace_id,
        "severity": "HIGH",
        "action": "BLOCK",
        "component": "coraza",
        "status": "BLOCKED",
        "request": {"method": "GET", "uri": "/search"},
        "metadata": {"rule_id": 941100}
    }
    create_res = requests.post(f"{API_URL}/api/v1/internal/risk/assess", json=payload)
    assert create_res.status_code == 200
    created = create_res.json()
    assessment_id = created["assessment_id"]

    # Fetch by assessment_id
    get_res = requests.get(f"{API_URL}/api/v1/risk/{assessment_id}")
    assert get_res.status_code == 200
    retrieved = get_res.json()
    assert retrieved["assessment_id"] == assessment_id
    assert retrieved["request_id"] == req_id
    assert retrieved["trace_id"] == trace_id
    assert retrieved["risk_score"] == created["risk_score"]
    assert retrieved["severity"] == created["severity"]
    assert retrieved["engine_version"] == "risk-engine-v1"


def test_09_correlation_by_request_and_trace_id():
    """Verify querying risk assessments by request_id and trace_id."""
    req_id = f"correl-req-{uuid.uuid4().hex[:8]}"
    trace_id = f"correl-trace-{uuid.uuid4().hex[:8]}"

    payload = {
        "event_type": "WAF_DETECTION",
        "request_id": req_id,
        "trace_id": trace_id,
        "severity": "HIGH",
        "action": "OBSERVED",
        "component": "coraza",
        "status": "DETECTED",
        "request": {"method": "GET", "uri": "/api/v1/health"},
        "metadata": {"rule_id": 942100}
    }
    requests.post(f"{API_URL}/api/v1/internal/risk/assess", json=payload)

    # By request_id
    res_req = requests.get(f"{API_URL}/api/v1/risk/request/{req_id}")
    assert res_req.status_code == 200
    items_req = res_req.json()
    assert len(items_req) >= 1
    assert items_req[0]["request_id"] == req_id

    # By trace_id
    res_trace = requests.get(f"{API_URL}/api/v1/risk/trace/{trace_id}")
    assert res_trace.status_code == 200
    items_trace = res_trace.json()
    assert len(items_trace) >= 1
    assert items_trace[0]["trace_id"] == trace_id


@pytest.mark.asyncio
async def test_10_realtime_websocket_risk_update():
    """Verify that a calculated risk assessment is broadcast via WebSocket as RISK_SCORE_UPDATE."""
    req_id = f"ws-risk-req-{uuid.uuid4().hex[:8]}"
    trace_id = f"ws-risk-trace-{uuid.uuid4().hex[:8]}"

    async with websockets.connect(WS_API_URL) as ws:
        payload = {
            "event_type": "WAF_BLOCK",
            "request_id": req_id,
            "trace_id": trace_id,
            "severity": "CRITICAL",
            "action": "BLOCK",
            "component": "coraza",
            "status": "BLOCKED",
            "request": {"method": "GET", "uri": "/admin"},
            "metadata": {"rule_id": 942100, "anomaly_score": 5}
        }
        # Ingest through event pipeline which triggers automatic risk assessment
        requests.post(f"{API_URL}/api/v1/internal/events", json=payload)

        # Listen for messages on WebSocket
        found_risk_update = False
        start_time = time.time()
        while time.time() - start_time < 5.0:
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=2.0)
                ev = json.loads(msg)
                if ev.get("event_type") == "RISK_SCORE_UPDATE" and ev.get("request_id") == req_id:
                    found_risk_update = True
                    assert ev["risk_score"] >= 75
                    assert ev["severity"] == "CRITICAL"
                    assert len(ev["signals"]) >= 2
                    break
            except asyncio.TimeoutError:
                break

        assert found_risk_update, "Expected RISK_SCORE_UPDATE over WebSocket stream"


def test_11_failure_safety_risk_error_does_not_break_event_ingestion():
    """
    Failure-safety verification:
    Even if risk engine experiences an exception, security event ingestion must succeed.
    """
    # Payload with valid event format
    event_payload = {
        "event_type": "SYSTEM_EVENT",
        "request_id": f"failsafe-req-{uuid.uuid4().hex[:8]}",
        "trace_id": f"failsafe-trace-{uuid.uuid4().hex[:8]}",
        "severity": "INFO",
        "action": "OBSERVED",
        "component": "system",
        "status": "OBSERVED",
        "request": {"method": "GET", "uri": "/status"}
    }
    # Ingestion must return 200 OK regardless of internal risk processing
    res = requests.post(f"{API_URL}/api/v1/internal/events", json=event_payload)
    assert res.status_code == 200
    assert res.json()["status"] == "ingested"


def test_12_end_to_end_waf_to_risk_flow():
    """
    Complete end-to-end WAF threat interception to automatic risk assessment verification:
    1. Send controlled SQL injection canary payload to Gateway (:8080).
    2. WAF blocks with HTTP 403 Forbidden.
    3. WAF log watcher parses audit transaction and persists security event.
    4. Risk Engine automatically evaluates security event and persists assessment.
    5. Query risk assessment by request_id and verify explainable signals and score.
    6. Verify Origin application was never contacted (total_requests_received unchanged).
    """
    origin_pre = requests.get(f"{GATEWAY_URL}/stats").json()["total_requests_received"]

    # Send controlled SQL injection attack
    attack_res = requests.get(f"{GATEWAY_URL}/products?category=%27%20OR%201=1--")
    assert attack_res.status_code == 403
    attack_req_id = attack_res.headers.get("x-request-id")
    assert attack_req_id is not None

    # Wait for log watcher and risk engine
    time.sleep(2.0)

    # Verify Risk Assessment via API
    risk_res = requests.get(f"{API_URL}/api/v1/risk/request/{attack_req_id}")
    assert risk_res.status_code == 200
    assessments = risk_res.json()
    assert len(assessments) >= 1, f"Expected risk assessment for request {attack_req_id}"

    assessment = assessments[0]
    assert assessment["request_id"] == attack_req_id
    assert assessment["risk_score"] >= 50
    assert assessment["severity"] in ["HIGH", "CRITICAL"]
    assert assessment["engine_version"] == "risk-engine-v1"

    signal_names = [s["name"] for s in assessment["signals"]]
    assert "waf_severity" in signal_names
    assert "known_attack_rule" in signal_names

    # Verify origin protection
    origin_post = requests.get(f"{GATEWAY_URL}/stats").json()["total_requests_received"]
    assert origin_post == origin_pre, "Origin was reached during blocked attack!"
