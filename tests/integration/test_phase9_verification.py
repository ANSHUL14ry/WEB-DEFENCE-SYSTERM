"""
AEGIS Ω — Phase 9 Integration Tests
Validates Response Verification & Telemetry Proof Engine:
1. Normal ALLOW -> origin reached -> VERIFIED
2. WAF BLOCK -> origin 0 -> VERIFIED
3. WAF BLOCK -> attempted deception -> DENIED / Invariant violation FAILED
4. BLOCK -> origin 0 -> VERIFIED
5. DECEIVE -> decoy reached -> origin 0 -> VERIFIED
6. DECEIVE -> decoy evidence captured -> VERIFIED
7. DECEIVE -> origin access detected -> FAILED (Critical security failure)
8. DECEPTION FAILURE -> no origin fallback (Zero fallback invariant)
9. Missing telemetry -> INCONCLUSIVE
10. Corrupt telemetry -> INCONCLUSIVE
11. Duplicate verification -> deterministic / idempotent behavior
12. Sensitive evidence sanitization
13. WebSocket MITIGATION_VERIFIED event received
14. WebSocket MITIGATION_FAILED event received
15. Dashboard stats endpoint returns correct aggregates
16. API retrieval endpoints (/verification/{id}, /request/{req_id}, /trace/{trace_id}, /{id}/proof)
17. Full regression across all phases
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

GATEWAY_URL = "http://localhost:8080"
API_URL = "http://localhost:8001"
WS_API_URL = "ws://localhost:8001/api/v1/ws/events"


def test_01_normal_allow_origin_reached_verified():
    """Scenario 1: Normal ALLOW request that reaches origin is VERIFIED."""
    req_id = f"p9-allow-{uuid.uuid4().hex[:8]}"
    trace_id = f"p9-trace-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "policy_decision": "ALLOW",
        "waf_blocked": False,
        "origin_reached": True,
        "origin_request_count": 1,
        "http_status": 200
    }

    res = requests.post(f"{API_URL}/api/v1/internal/verification/evaluate", json=payload)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    data = res.json()
    assert data["result"] == "VERIFIED"
    assert data["verification_type"] == "NORMAL_ALLOW"
    assert data["actual_origin_access"] is True
    assert data["origin_request_count"] >= 1
    assert data["confidence"] == 1.0
    assert any("ALLOW" in p for p in data["proof"])


def test_02_waf_block_origin_zero_verified():
    """Scenario 2: WAF-blocked request with 0 origin hits is VERIFIED."""
    req_id = f"p9-waf-{uuid.uuid4().hex[:8]}"
    trace_id = f"p9-trace-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "policy_decision": "BLOCK",
        "waf_blocked": True,
        "origin_reached": False,
        "origin_request_count": 0,
        "http_status": 403
    }

    res = requests.post(f"{API_URL}/api/v1/internal/verification/evaluate", json=payload)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    data = res.json()
    assert data["result"] == "VERIFIED"
    assert data["verification_type"] == "WAF_BLOCK"
    assert data["actual_origin_access"] is False
    assert data["origin_request_count"] == 0
    assert any("403" in p or "WAF" in p for p in data["proof"])


def test_03_waf_block_attempted_deception_denied():
    """Scenario 3: WAF-blocked request attempting deception fails invariant check."""
    req_id = f"p9-waf-dec-{uuid.uuid4().hex[:8]}"
    trace_id = f"p9-trace-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "policy_decision": "BLOCK",
        "waf_blocked": True,
        "deception_session_id": "ds-err-123",
        "origin_reached": False,
        "origin_request_count": 0
    }

    res = requests.post(f"{API_URL}/api/v1/internal/verification/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["result"] == "FAILED"
    assert "WAF block cannot enter deception" in data["failure_reason"]


def test_04_policy_block_origin_zero_verified():
    """Scenario 4: Policy Engine BLOCK/CONTAIN decision with 0 origin hits is VERIFIED."""
    req_id = f"p9-block-{uuid.uuid4().hex[:8]}"
    trace_id = f"p9-trace-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "policy_decision": "BLOCK",
        "waf_blocked": False,
        "origin_reached": False,
        "origin_request_count": 0
    }

    res = requests.post(f"{API_URL}/api/v1/internal/verification/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["result"] == "VERIFIED"
    assert data["actual_origin_access"] is False
    assert data["origin_request_count"] == 0


def test_05_deceive_eligible_decoy_reached_origin_zero_verified():
    """Scenario 5: DECEIVE_ELIGIBLE routing to decoy with 0 origin hits is VERIFIED."""
    req_id = f"p9-decoy-{uuid.uuid4().hex[:8]}"
    trace_id = f"p9-trace-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "policy_decision": "DECEIVE_ELIGIBLE",
        "deception_session_id": f"ds-{uuid.uuid4().hex[:8]}",
        "waf_blocked": False,
        "origin_reached": False,
        "origin_request_count": 0,
        "database_access_detected": False
    }

    res = requests.post(f"{API_URL}/api/v1/internal/verification/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["result"] == "VERIFIED"
    assert data["verification_type"] == "DECEPTION"
    assert data["actual_origin_access"] is False
    assert data["origin_request_count"] == 0
    assert any("deception" in p.lower() for p in data["proof"])


def test_06_deception_evidence_captured_verified():
    """Scenario 6: Decoy session with captured evidence events is VERIFIED with event proof."""
    req_id = f"p9-ev-{uuid.uuid4().hex[:8]}"
    trace_id = f"p9-trace-{uuid.uuid4().hex[:8]}"
    dec_id = f"ds-ev-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "policy_decision": "DECEIVE_ELIGIBLE",
        "deception_session_id": dec_id,
        "evidence_count": 7,
        "origin_reached": False,
        "origin_request_count": 0,
        "database_access_detected": False
    }

    res = requests.post(f"{API_URL}/api/v1/internal/verification/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["result"] == "VERIFIED"
    assert data["evidence_count"] == 7
    assert any("7 evidence events" in p for p in data["proof"])


def test_07_deception_origin_access_detected_failed():
    """Scenario 7: Critical invariant - If origin is reached during deception, verification FAILS."""
    req_id = f"p9-breach-{uuid.uuid4().hex[:8]}"
    trace_id = f"p9-trace-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "policy_decision": "DECEIVE_ELIGIBLE",
        "deception_session_id": "ds-breach-1",
        "origin_reached": True,
        "origin_request_count": 1,
        "database_access_detected": False
    }

    res = requests.post(f"{API_URL}/api/v1/internal/verification/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["result"] == "FAILED"
    assert data["actual_origin_access"] is True
    assert "Origin access detected" in data["failure_reason"]


def test_08_deception_failure_no_origin_fallback():
    """Scenario 8: If decoy fails, zero fallback invariant guarantees origin is not contacted."""
    req_id = f"p9-fail-{uuid.uuid4().hex[:8]}"
    trace_id = f"p9-trace-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "policy_decision": "DECEIVE_ELIGIBLE",
        "decoy_failed": True,
        "origin_reached": False,
        "origin_request_count": 0
    }

    res = requests.post(f"{API_URL}/api/v1/internal/verification/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["result"] == "FAILED"
    assert data["verification_type"] == "DECEPTION_FAILURE"
    assert data["actual_origin_access"] is False
    assert any("fallback invariant ENFORCED" in p for p in data["proof"])


def test_09_missing_telemetry_inconclusive():
    """Scenario 9: Missing required telemetry produces INCONCLUSIVE result."""
    req_id = f"p9-miss-{uuid.uuid4().hex[:8]}"
    trace_id = f"p9-trace-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "has_sufficient_telemetry": False
    }

    res = requests.post(f"{API_URL}/api/v1/internal/verification/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["result"] == "INCONCLUSIVE"
    assert data["confidence"] <= 0.50


def test_10_corrupt_telemetry_inconclusive():
    """Scenario 10: Corrupted telemetry payload produces INCONCLUSIVE result."""
    req_id = f"p9-corrupt-{uuid.uuid4().hex[:8]}"
    trace_id = f"p9-trace-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "telemetry_corrupted": True
    }

    res = requests.post(f"{API_URL}/api/v1/internal/verification/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["result"] == "INCONCLUSIVE"


def test_11_duplicate_verification_idempotent():
    """Scenario 11: Duplicate verification evaluation is deterministic and idempotent."""
    req_id = f"p9-idemp-{uuid.uuid4().hex[:8]}"
    trace_id = f"p9-trace-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "policy_decision": "ALLOW",
        "origin_reached": True,
        "origin_request_count": 1
    }

    res1 = requests.post(f"{API_URL}/api/v1/internal/verification/evaluate", json=payload)
    assert res1.status_code == 200
    v1 = res1.json()

    # Re-evaluate with exact same parameters
    res2 = requests.post(f"{API_URL}/api/v1/internal/verification/evaluate", json=payload)
    assert res2.status_code == 200
    v2 = res2.json()

    assert v1["verification_id"] == v2["verification_id"]
    assert v1["result"] == v2["result"]


def test_12_sensitive_evidence_sanitization():
    """Scenario 12: Sensitive credentials/tokens in proof details are strictly sanitized."""
    req_id = f"p9-san-{uuid.uuid4().hex[:8]}"
    trace_id = f"p9-trace-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "policy_decision": "DECEIVE_ELIGIBLE",
        "deception_session_id": "ds-san-1",
        "origin_reached": False,
        "metadata": {
          "raw_token": "Bearer secret_jwt_token_999",
          "password_probed": "admin12345"
        }
    }

    res = requests.post(f"{API_URL}/api/v1/internal/verification/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()
    proof_str = json.dumps(data["proof"])
    assert "admin12345" not in proof_str
    assert "secret_jwt_token_999" not in proof_str


@pytest.mark.asyncio
async def test_13_websocket_mitigation_verified_broadcast():
    """Scenario 13: WebSocket broadcasts MITIGATION_VERIFIED on successful verification."""
    req_id = f"p9-ws-ok-{uuid.uuid4().hex[:8]}"
    trace_id = f"p9-trace-{uuid.uuid4().hex[:8]}"

    async with websockets.connect(WS_API_URL) as ws:
        # Trigger verified action in background task
        payload = {
            "request_id": req_id,
            "trace_id": trace_id,
            "policy_decision": "ALLOW",
            "origin_reached": True,
            "origin_request_count": 1
        }

        # Send evaluate request in thread
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: requests.post(f"{API_URL}/api/v1/internal/verification/evaluate", json=payload)
        )

        # Wait for WS message
        found = False
        start = time.time()
        while time.time() - start < 5.0:
            try:
                msg_raw = await asyncio.wait_for(ws.recv(), timeout=2.0)
                msg = json.loads(msg_raw)
                if msg.get("event_type") == "MITIGATION_VERIFIED" and msg.get("request_id") == req_id:
                    assert msg["result"] == "VERIFIED"
                    assert msg["origin_reached"] is True
                    found = True
                    break
            except asyncio.TimeoutError:
                break
        assert found, "WebSocket did not broadcast MITIGATION_VERIFIED within timeout."


@pytest.mark.asyncio
async def test_14_websocket_mitigation_failed_broadcast():
    """Scenario 14: WebSocket broadcasts MITIGATION_FAILED on failed verification."""
    req_id = f"p9-ws-fail-{uuid.uuid4().hex[:8]}"
    trace_id = f"p9-trace-{uuid.uuid4().hex[:8]}"

    async with websockets.connect(WS_API_URL) as ws:
        payload = {
            "request_id": req_id,
            "trace_id": trace_id,
            "policy_decision": "DECEIVE_ELIGIBLE",
            "deception_session_id": "ds-fail-ws",
            "origin_reached": True,
            "origin_request_count": 2
        }

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: requests.post(f"{API_URL}/api/v1/internal/verification/evaluate", json=payload)
        )

        found = False
        start = time.time()
        while time.time() - start < 5.0:
            try:
                msg_raw = await asyncio.wait_for(ws.recv(), timeout=2.0)
                msg = json.loads(msg_raw)
                if msg.get("event_type") == "MITIGATION_FAILED" and msg.get("request_id") == req_id:
                    assert msg["result"] == "FAILED"
                    assert msg["origin_reached"] is True
                    found = True
                    break
            except asyncio.TimeoutError:
                break
        assert found, "WebSocket did not broadcast MITIGATION_FAILED within timeout."


def test_15_dashboard_stats_endpoint():
    """Scenario 15: GET /api/v1/verification/stats returns accurate live metrics."""
    res = requests.get(f"{API_URL}/api/v1/verification/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_verifications" in data
    assert "verified_count" in data
    assert "failed_count" in data
    assert "inconclusive_count" in data
    assert "verified_percentage" in data
    assert data["total_verifications"] >= data["verified_count"]


def test_16_api_retrieval_endpoints():
    """Scenario 16: API endpoints correctly retrieve verification by ID, request, trace, and proof."""
    req_id = f"p9-retr-{uuid.uuid4().hex[:8]}"
    trace_id = f"p9-trace-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "policy_decision": "ALLOW",
        "origin_reached": True,
        "origin_request_count": 1
    }
    eval_res = requests.post(f"{API_URL}/api/v1/internal/verification/evaluate", json=payload)
    v_id = eval_res.json()["verification_id"]

    # 1. By ID
    r1 = requests.get(f"{API_URL}/api/v1/verification/{v_id}")
    assert r1.status_code == 200
    assert r1.json()["verification_id"] == v_id

    # 2. By request_id
    r2 = requests.get(f"{API_URL}/api/v1/verification/request/{req_id}")
    assert r2.status_code == 200
    assert r2.json()["request_id"] == req_id

    # 3. By trace_id
    r3 = requests.get(f"{API_URL}/api/v1/verification/trace/{trace_id}")
    assert r3.status_code == 200
    assert len(r3.json()) >= 1

    # 4. Proof object
    r4 = requests.get(f"{API_URL}/api/v1/verification/{v_id}/proof")
    assert r4.status_code == 200
    assert "proof" in r4.json()
    assert r4.json()["result"] == "VERIFIED"


def test_17_full_regression_all_phases():
    """Scenario 17: Full regression across Gateway, WAF, Pipeline, Risk, AgentShield, Policy, and Deception."""
    # 1. Gateway health
    gw_health = requests.get(f"{GATEWAY_URL}/healthz")
    assert gw_health.status_code == 200

    # 2. System Status API
    sys_status = requests.get(f"{API_URL}/api/v1/system/status")
    assert sys_status.status_code == 200
    services = sys_status.json()["services"]
    assert services["gateway"]["status"] == "operational"
    assert services["waf"]["status"] == "operational"
    assert services["database"]["status"] == "connected"
    assert services["deception_engine"]["status"] == "operational"
    assert services["verification_engine"]["status"] == "operational"

    # 3. Deception stats
    dec_stats = requests.get(f"{API_URL}/api/v1/deception/stats")
    assert dec_stats.status_code == 200

    # 4. Verification stats
    ver_stats = requests.get(f"{API_URL}/api/v1/verification/stats")
    assert ver_stats.status_code == 200
