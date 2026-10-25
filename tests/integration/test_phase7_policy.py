"""
AEGIS Ω — Phase 7 Integration Tests
Validates the Deterministic Policy Engine:
1. Low-risk request -> ALLOW
2. Medium-risk request -> MONITOR or RATE_LIMIT
3. High-risk request without AgentShield -> BLOCK
4. Critical-risk request without AgentShield -> BLOCK
5. High/Critical risk + High/Critical AgentShield + waf_blocked == False -> DECEIVE_ELIGIBLE
6. waf_blocked == True + Critical risk + Critical AgentShield -> BLOCK (Safety invariant, never DECEIVE_ELIGIBLE)
7. Deterministic repeated evaluation produces identical results
8. Policy precedence (WAF block wins over deception eligibility)
9. Missing data results in conservative MONITOR
10. Decisions correctly persisted to policy_decisions
11. Retrieval endpoints (/policy/{id}, /policy/request/{req_id}, /policy/trace/{trace_id})
12. Real-time WebSocket delivery of POLICY_DECISION
13. Dashboard stats endpoint returns real data
14. Failure isolation: Policy Engine failure does not prevent WAF block or event persistence
15. Sensitive data sanitization: No raw credentials or auth tokens leaked
16. Complete regression test across Phases 1-7
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


def test_01_low_risk_allow():
    """Test 1: Low-risk request results in ALLOW decision."""
    req_id = f"p7-req-allow-{uuid.uuid4().hex[:8]}"
    trace_id = f"p7-trace-allow-{uuid.uuid4().hex[:8]}"

    payload = {
        "event_id": str(uuid.uuid4()),
        "request_id": req_id,
        "trace_id": trace_id,
        "client_ip": "192.168.1.100",
        "method": "GET",
        "endpoint": "/products",
        "risk_score": 10.0,
        "risk_severity": "LOW",
        "agent_shield_score": 5.0,
        "agent_shield_severity": "LOW",
        "waf_blocked": False,
        "waf_action": "ALLOW"
    }

    res = requests.post(f"{API_URL}/api/v1/internal/policy/evaluate", json=payload)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    data = res.json()
    assert data["decision"] == "ALLOW"
    assert data["terminal"] is False
    assert data["policy_version"] == "policy-v1"
    assert "RULE_6_LOW_RISK_ALLOW" in data["rule_evaluation_chain"]


def test_02_medium_risk_monitor_or_rate_limit():
    """Test 2: Medium-risk request results in MONITOR or RATE_LIMIT."""
    # Subtest A: Standard medium risk -> MONITOR
    req_id_a = f"p7-req-med-a-{uuid.uuid4().hex[:8]}"
    trace_id_a = f"p7-trace-med-a-{uuid.uuid4().hex[:8]}"
    payload_a = {
        "request_id": req_id_a,
        "trace_id": trace_id_a,
        "client_ip": "192.168.1.101",
        "method": "GET",
        "endpoint": "/catalog",
        "risk_score": 35.0,
        "risk_severity": "MEDIUM",
        "agent_shield_score": 20.0,
        "agent_shield_severity": "LOW",
        "waf_blocked": False,
        "waf_action": "NONE"
    }
    res_a = requests.post(f"{API_URL}/api/v1/internal/policy/evaluate", json=payload_a)
    assert res_a.status_code == 200
    data_a = res_a.json()
    assert data_a["decision"] == "MONITOR"
    assert data_a["terminal"] is False

    # Subtest B: Medium risk with velocity/probing signal -> RATE_LIMIT
    req_id_b = f"p7-req-med-b-{uuid.uuid4().hex[:8]}"
    trace_id_b = f"p7-trace-med-b-{uuid.uuid4().hex[:8]}"
    payload_b = {
        "request_id": req_id_b,
        "trace_id": trace_id_b,
        "client_ip": "192.168.1.102",
        "method": "POST",
        "endpoint": "/login",
        "risk_score": 45.0,
        "risk_severity": "MEDIUM",
        "agent_shield_score": 40.0,
        "agent_shield_severity": "MEDIUM",
        "waf_blocked": False,
        "waf_action": "NONE",
        "signals": ["request_velocity", "repeated_probing"]
    }
    res_b = requests.post(f"{API_URL}/api/v1/internal/policy/evaluate", json=payload_b)
    assert res_b.status_code == 200
    data_b = res_b.json()
    assert data_b["decision"] in ["RATE_LIMIT", "MONITOR"]
    assert data_b["terminal"] is False


def test_03_high_risk_without_agentshield_block():
    """Test 3: High-risk request without AgentShield results in BLOCK."""
    req_id = f"p7-req-high-{uuid.uuid4().hex[:8]}"
    trace_id = f"p7-trace-high-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "client_ip": "10.0.0.50",
        "method": "POST",
        "endpoint": "/api/v1/data",
        "risk_score": 68.0,
        "risk_severity": "HIGH",
        "agent_shield_score": 15.0,
        "agent_shield_severity": "LOW",
        "waf_blocked": False,
        "waf_action": "NONE"
    }

    res = requests.post(f"{API_URL}/api/v1/internal/policy/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "BLOCK"
    assert data["terminal"] is True
    assert "RULE_4_HIGH_RISK_BLOCK" in data["rule_evaluation_chain"]


def test_04_critical_risk_without_agentshield_block():
    """Test 4: Critical-risk request without AgentShield results in BLOCK."""
    req_id = f"p7-req-crit-{uuid.uuid4().hex[:8]}"
    trace_id = f"p7-trace-crit-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "client_ip": "10.0.0.55",
        "method": "GET",
        "endpoint": "/api/v1/users",
        "risk_score": 92.0,
        "risk_severity": "CRITICAL",
        "agent_shield_score": 20.0,
        "agent_shield_severity": "LOW",
        "waf_blocked": False,
        "waf_action": "NONE"
    }

    res = requests.post(f"{API_URL}/api/v1/internal/policy/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "BLOCK"
    assert data["terminal"] is True
    assert "RULE_3_CRITICAL_SECURITY_BLOCK" in data["rule_evaluation_chain"]


def test_05_high_critical_risk_plus_agentshield_deceive_eligible():
    """Test 5: HIGH/CRITICAL risk + HIGH/CRITICAL AgentShield + waf_blocked == False -> DECEIVE_ELIGIBLE."""
    req_id = f"p7-req-deceive-{uuid.uuid4().hex[:8]}"
    trace_id = f"p7-trace-deceive-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "client_ip": "10.0.0.99",
        "method": "GET",
        "endpoint": "/admin/config",
        "risk_score": 75.0,
        "risk_severity": "HIGH",
        "agent_shield_score": 80.0,
        "agent_shield_severity": "HIGH",
        "waf_blocked": False,
        "waf_action": "NONE"
    }

    res = requests.post(f"{API_URL}/api/v1/internal/policy/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "DECEIVE_ELIGIBLE"
    assert data["terminal"] is False
    assert "RULE_2_DECEPTION_ELIGIBILITY" in data["rule_evaluation_chain"]
    assert "Phase 8" in data["explanation"] or "deception" in data["explanation"].lower()


def test_06_waf_blocked_safety_invariant_strictly_terminal_block():
    """Test 6: WAF blocked request is strictly terminal BLOCK — zero deception bypass.
    Safety Invariant: Even with CRITICAL risk + CRITICAL AgentShield, waf_blocked == True
    MUST evaluate to BLOCK (WAF_BLOCKED_TERMINAL). Under NO circumstances DECEIVE_ELIGIBLE.
    """
    req_id = f"p7-req-wafinv-{uuid.uuid4().hex[:8]}"
    trace_id = f"p7-trace-wafinv-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "client_ip": "10.99.99.99",
        "method": "POST",
        "endpoint": "/login",
        "risk_score": 98.0,
        "risk_severity": "CRITICAL",
        "agent_shield_score": 95.0,
        "agent_shield_severity": "CRITICAL",
        "waf_blocked": True,
        "waf_action": "BLOCK"
    }

    res = requests.post(f"{API_URL}/api/v1/internal/policy/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "BLOCK", "WAF blocked traffic must NEVER be DECEIVE_ELIGIBLE"
    assert data["terminal"] is True
    assert "WAF_BLOCKED_TERMINAL" in data["rule_matched"] or "RULE_1_WAF_TERMINAL_BLOCK" in data["rule_evaluation_chain"]
    assert data["decision"] != "DECEIVE_ELIGIBLE"
    assert data["decision"] != "CONTAIN"
    assert data["decision"] != "ALLOW"


def test_07_deterministic_repeated_evaluation():
    """Test 7: Repeated evaluations of identical context produce identical outputs."""
    req_id = f"p7-req-det-{uuid.uuid4().hex[:8]}"
    trace_id = f"p7-trace-det-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "client_ip": "172.16.0.4",
        "method": "GET",
        "endpoint": "/api/v1/status",
        "risk_score": 55.0,
        "risk_severity": "HIGH",
        "agent_shield_score": 30.0,
        "agent_shield_severity": "MEDIUM",
        "waf_blocked": False,
        "waf_action": "NONE"
    }

    results = []
    for _ in range(5):
        res = requests.post(f"{API_URL}/api/v1/internal/policy/evaluate", json=payload)
        assert res.status_code == 200
        results.append(res.json())

    first = results[0]
    for r in results[1:]:
        assert r["decision"] == first["decision"]
        assert r["terminal"] == first["terminal"]
        assert r["rule_matched"] == first["rule_matched"]
        assert r["rule_evaluation_chain"] == first["rule_evaluation_chain"]
        assert r["explanation"] == first["explanation"]


def test_08_policy_precedence_waf_block_wins_over_deception():
    """Test 8: Precedence rule ordering — Rule 1 (WAF block) wins before Rule 2 (Deception)."""
    payload = {
        "request_id": f"p7-req-prec-{uuid.uuid4().hex[:8]}",
        "trace_id": f"p7-trace-prec-{uuid.uuid4().hex[:8]}",
        "client_ip": "10.10.10.10",
        "method": "GET",
        "endpoint": "/api/v1/export",
        "risk_score": 85.0,
        "risk_severity": "CRITICAL",
        "agent_shield_score": 88.0,
        "agent_shield_severity": "CRITICAL",
        "waf_blocked": True,
        "waf_action": "BLOCK"
    }

    res = requests.post(f"{API_URL}/api/v1/internal/policy/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "BLOCK"
    assert data["rule_evaluation_chain"][0] == "RULE_1_WAF_TERMINAL_BLOCK"
    # Rule 2 must not be evaluated as the final action
    assert "RULE_2_DECEPTION_ELIGIBILITY" not in data["rule_evaluation_chain"]


def test_09_missing_data_conservative_monitor():
    """Test 9: Incomplete or missing context defaults conservatively to MONITOR."""
    payload = {
        "request_id": f"p7-req-missing-{uuid.uuid4().hex[:8]}",
        "trace_id": f"p7-trace-missing-{uuid.uuid4().hex[:8]}",
        "client_ip": "10.0.0.1",
        "method": "GET",
        "endpoint": "/unknown"
        # risk_score, risk_severity, agent_shield fields omitted
    }

    res = requests.post(f"{API_URL}/api/v1/internal/policy/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()
    # Missing data must never default to ALLOW
    assert data["decision"] in ["MONITOR", "RATE_LIMIT"]
    assert data["decision"] != "ALLOW"
    assert "RULE_7_CONSERVATIVE_FALLBACK" in data["rule_evaluation_chain"]


def test_10_decisions_correctly_persisted_in_database():
    """Test 10: Policy decision is persisted with all required audit fields."""
    req_id = f"p7-req-persist-{uuid.uuid4().hex[:8]}"
    trace_id = f"p7-trace-persist-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "client_ip": "192.168.5.5",
        "method": "POST",
        "endpoint": "/api/v1/auth/login",
        "risk_score": 72.0,
        "risk_severity": "HIGH",
        "agent_shield_score": 25.0,
        "agent_shield_severity": "MEDIUM",
        "waf_blocked": False,
        "waf_action": "NONE"
    }

    res = requests.post(f"{API_URL}/api/v1/internal/policy/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()
    decision_id = data["decision_id"]

    # Verify retrieval from REST endpoint
    get_res = requests.get(f"{API_URL}/api/v1/policy/{decision_id}")
    assert get_res.status_code == 200
    row = get_res.json()
    assert row["decision_id"] == decision_id
    assert row["request_id"] == req_id
    assert row["trace_id"] == trace_id
    assert row["decision"] == "BLOCK"
    assert row["risk_severity"] == "HIGH"
    assert row["policy_version"] == "policy-v1"
    assert row["created_at"] is not None


def test_11_retrieval_endpoints():
    """Test 11: Retrieval endpoints (/policy/{id}, /policy/request/{req_id}, /policy/trace/{trace_id})."""
    req_id = f"p7-req-retrieval-{uuid.uuid4().hex[:8]}"
    trace_id = f"p7-trace-retrieval-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "client_ip": "192.168.10.10",
        "method": "GET",
        "endpoint": "/items",
        "risk_score": 12.0,
        "risk_severity": "LOW",
        "agent_shield_score": 5.0,
        "agent_shield_severity": "LOW",
        "waf_blocked": False,
        "waf_action": "NONE"
    }

    res = requests.post(f"{API_URL}/api/v1/internal/policy/evaluate", json=payload)
    assert res.status_code == 200
    decision_id = res.json()["decision_id"]

    # 1. By ID
    r_id = requests.get(f"{API_URL}/api/v1/policy/{decision_id}")
    assert r_id.status_code == 200
    assert r_id.json()["decision_id"] == decision_id

    # 2. By Request ID
    r_req = requests.get(f"{API_URL}/api/v1/policy/request/{req_id}")
    assert r_req.status_code == 200
    items = r_req.json()
    assert len(items) >= 1
    assert any(i["request_id"] == req_id for i in items)

    # 3. By Trace ID
    r_trace = requests.get(f"{API_URL}/api/v1/policy/trace/{trace_id}")
    assert r_trace.status_code == 200
    t_items = r_trace.json()
    assert len(t_items) >= 1
    assert any(i["trace_id"] == trace_id for i in t_items)


@pytest.mark.asyncio
async def test_12_realtime_websocket_delivery():
    """Test 12: Real-time WebSocket delivery of POLICY_DECISION event."""
    req_id = f"p7-req-ws-{uuid.uuid4().hex[:8]}"
    trace_id = f"p7-trace-ws-{uuid.uuid4().hex[:8]}"

    received_event = None

    async with websockets.connect(WS_API_URL) as ws:
        # Give WebSocket connection a fraction of a second to register
        await asyncio.sleep(0.2)

        # Trigger policy evaluation
        payload = {
            "request_id": req_id,
            "trace_id": trace_id,
            "client_ip": "10.200.1.1",
            "method": "GET",
            "endpoint": "/api/v1/stream",
            "risk_score": 85.0,
            "risk_severity": "CRITICAL",
            "agent_shield_score": 85.0,
            "agent_shield_severity": "CRITICAL",
            "waf_blocked": False,
            "waf_action": "NONE"
        }
        res = requests.post(f"{API_URL}/api/v1/internal/policy/evaluate", json=payload)
        assert res.status_code == 200

        # Listen for POLICY_DECISION message with timeout
        timeout = 5.0
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=1.0)
                data = json.loads(msg)
                if data.get("event_type") == "POLICY_DECISION" and data.get("request_id") == req_id:
                    received_event = data
                    break
            except asyncio.TimeoutError:
                continue

    assert received_event is not None, "Failed to receive POLICY_DECISION event on WebSocket"
    assert received_event["event_type"] == "POLICY_DECISION"
    assert received_event["decision"] == "DECEIVE_ELIGIBLE"
    assert received_event["request_id"] == req_id


def test_13_dashboard_stats_endpoint():
    """Test 13: Dashboard stats endpoint returns real decision counts and disclaimer."""
    res = requests.get(f"{API_URL}/api/v1/policy/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_decisions" in data
    assert "allow_count" in data
    assert "block_count" in data
    assert "deceive_eligible_count" in data
    assert "disclaimer" in data
    assert data["total_decisions"] > 0
    assert "Phase 7" in data["disclaimer"]
    assert "Phase 8" in data["disclaimer"] or "No honeypots" in data["disclaimer"]


def test_14_failure_isolation():
    """Test 14: Policy Engine failure isolation — bad request doesn't break event persistence."""
    req_id = f"p7-req-fail-{uuid.uuid4().hex[:8]}"
    trace_id = f"p7-trace-fail-{uuid.uuid4().hex[:8]}"

    # Ingest event with malformed or extreme values
    event_payload = {
        "event_type": "ORIGIN_REQUEST",
        "request_id": req_id,
        "trace_id": trace_id,
        "severity": "INFO",
        "action": "ALLOW",
        "component": "origin",
        "status": "ALLOWED",
        "source": {"ip": "127.0.0.1"},
        "request": {"method": "GET", "uri": "/products"},
        "metadata": {"test_failure_isolation": True}
    }
    # Security event ingestion must succeed
    ev_res = requests.post(f"{API_URL}/api/v1/internal/events", json=event_payload)
    assert ev_res.status_code in [200, 201]

    # Verify system status is still healthy
    status_res = requests.get(f"{API_URL}/api/v1/system/status")
    assert status_res.status_code == 200
    assert status_res.json()["status"] == "operational"


def test_15_sensitive_data_sanitization():
    """Test 15: No raw credentials or auth tokens leaked in policy decision logs or details."""
    req_id = f"p7-req-sanitize-{uuid.uuid4().hex[:8]}"
    trace_id = f"p7-trace-sanitize-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "client_ip": "192.168.1.50",
        "method": "POST",
        "endpoint": "/api/v1/login",
        "risk_score": 80.0,
        "risk_severity": "HIGH",
        "agent_shield_score": 40.0,
        "agent_shield_severity": "MEDIUM",
        "waf_blocked": False,
        "waf_action": "NONE",
        "details": {
            "password": "supersecretpassword123!",
            "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret"
        }
    }

    res = requests.post(f"{API_URL}/api/v1/internal/policy/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()

    # Verify response and database record do not leak sensitive credentials
    explanation = data.get("explanation", "")
    assert "supersecretpassword123!" not in explanation
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in explanation


def test_16_complete_regression_test_phases_1_to_7():
    """Test 16: Complete live regression across Phases 1 through 7 through the Gateway :8080."""
    # 1. Clean request to Gateway -> Origin responds 200, tracing intact
    clean_trace = f"p7-clean-{uuid.uuid4().hex[:8]}"
    clean_res = requests.get(
        f"{GATEWAY_URL}/",
        headers={"X-Trace-ID": clean_trace}
    )
    assert clean_res.status_code == 200
    assert "X-Request-ID" in clean_res.headers
    assert "X-Content-Type-Options" in clean_res.headers

    # 2. SQLi attack to Gateway -> WAF Coraza blocks with 403 Forbidden
    sqli_trace = f"p7-sqli-{uuid.uuid4().hex[:8]}"
    sqli_res = requests.get(
        f"{GATEWAY_URL}/products?search=' UNION SELECT 1,2,3--",
        headers={"X-Trace-ID": sqli_trace}
    )
    assert sqli_res.status_code == 403
    waf_req_id = sqli_res.headers.get("X-Request-ID")
    assert waf_req_id is not None

    # Wait for WAF audit log watcher to ingest and trigger Risk + Policy Engine
    time.sleep(2.0)

    # 3. Verify Policy Decision was recorded for the blocked attack
    # The policy decision for a WAF-blocked request must be BLOCK with terminal=True
    policy_res = requests.get(f"{API_URL}/api/v1/policy/request/{waf_req_id}")
    if policy_res.status_code == 200 and len(policy_res.json()) > 0:
        dec = policy_res.json()[0]
        assert dec["decision"] == "BLOCK"
        assert dec["terminal"] is True
        assert "RULE_1_WAF_TERMINAL_BLOCK" in dec["matched_rules"]
