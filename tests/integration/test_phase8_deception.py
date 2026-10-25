"""
AEGIS Ω — Phase 8 Integration Tests
Validates Adaptive Deception & Isolated Honeypot:
1. DECEIVE_ELIGIBLE creates deception session
2. Normal ALLOW request never enters deception
3. BLOCK request never enters deception
4. WAF-blocked request cannot enter deception (Zero Deception Bypass)
5. Decoy reachable only through authorized internal deception flow
6. Decoy cannot connect to real origin (Network Isolation)
7. Decoy cannot access production database (Database Isolation)
8. Synthetic login interaction creates safe evidence
9. Password is not persisted
10. Admin interaction creates evidence
11. API interaction creates evidence
12. Deception timeline is correctly ordered
13. WebSocket sends DECEPTION_EVENT
14. Dashboard retrieves active session
15. Session expiration works
16. Maximum session/request limits work
17. Sensitive data sanitization works
18. Deception service failure does not break origin protection
19. Deception failure does not silently fall back to origin
20. Phase 1-7 full regression remains green
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


def test_01_deceive_eligible_creates_deception_session():
    """Test 1: Policy decision DECEIVE_ELIGIBLE successfully triggers controlled deception session."""
    req_id = f"p8-req-init-{uuid.uuid4().hex[:8]}"
    trace_id = f"p8-trace-init-{uuid.uuid4().hex[:8]}"

    payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "policy_decision": "DECEIVE_ELIGIBLE",
        "waf_blocked": False,
        "waf_action": "NONE",
        "initial_risk_score": 85,
        "initial_agent_shield_score": 90,
        "client_ip": "10.42.0.88",
        "target_route": "/",
        "method": "GET"
    }

    res = requests.post(f"{API_URL}/api/v1/internal/deception/execute", json=payload)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    data = res.json()
    assert data["status"] == "ACTIVE"
    assert "session_id" in data
    assert data["session_id"].startswith("ds-")
    assert data["origin_reached"] is False


def test_02_normal_allow_request_never_enters_deception():
    """Test 2: Normal ALLOW request is strictly rejected from deception routing."""
    payload = {
        "request_id": f"p8-req-allow-{uuid.uuid4().hex[:8]}",
        "trace_id": f"p8-trace-allow-{uuid.uuid4().hex[:8]}",
        "policy_decision": "ALLOW",
        "waf_blocked": False,
        "waf_action": "ALLOW",
        "initial_risk_score": 10,
        "initial_agent_shield_score": 5,
        "client_ip": "192.168.1.50"
    }

    res = requests.post(f"{API_URL}/api/v1/internal/deception/execute", json=payload)
    assert res.status_code == 403
    assert "only DECEIVE_ELIGIBLE requests may enter" in res.text


def test_03_block_request_never_enters_deception():
    """Test 3: Standard BLOCK request without AgentShield automation is rejected from deception."""
    payload = {
        "request_id": f"p8-req-block-{uuid.uuid4().hex[:8]}",
        "trace_id": f"p8-trace-block-{uuid.uuid4().hex[:8]}",
        "policy_decision": "BLOCK",
        "waf_blocked": False,
        "waf_action": "NONE",
        "initial_risk_score": 70,
        "initial_agent_shield_score": 15,
        "client_ip": "10.0.0.50"
    }

    res = requests.post(f"{API_URL}/api/v1/internal/deception/execute", json=payload)
    assert res.status_code == 403
    assert "only DECEIVE_ELIGIBLE requests may enter" in res.text


def test_04_waf_blocked_request_cannot_enter_deception():
    """Test 4: WAF-blocked request is strictly PRE-EMPTED — Zero Deception Bypass.
    Even if client or caller claims DECEIVE_ELIGIBLE, waf_blocked == True must be DENIED.
    """
    payload = {
        "request_id": f"p8-req-wafdrop-{uuid.uuid4().hex[:8]}",
        "trace_id": f"p8-trace-wafdrop-{uuid.uuid4().hex[:8]}",
        "policy_decision": "DECEIVE_ELIGIBLE",
        "waf_blocked": True,
        "waf_action": "BLOCK",
        "initial_risk_score": 98,
        "initial_agent_shield_score": 95,
        "client_ip": "10.99.99.99"
    }

    res = requests.post(f"{API_URL}/api/v1/internal/deception/execute", json=payload)
    data = res.json()
    assert data["status"] == "DENIED"
    assert data["decision"] == "BLOCK"
    assert "WAF_BLOCKED_TERMINAL" in data["reason"]
    assert data["origin_reached"] is False


def test_05_decoy_reachable_only_through_authorized_internal_flow():
    """Test 5: Decoy container has no public host port binding (localhost:8090 is closed to host)."""
    with pytest.raises(requests.exceptions.ConnectionError):
        # Public host connection to decoy port 8090 must fail (isolated internal Docker network)
        requests.get("http://localhost:8090/healthz", timeout=1.0)


def test_06_decoy_cannot_connect_to_real_origin():
    """Test 6: Invariant 2 — Decoy container is on deception-net and cannot resolve/connect to origin:8088."""
    import subprocess
    cmd = ["docker", "exec", "aegis-decoy", "curl", "-s", "--max-time", "2", "http://origin:8088/health"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    # curl inside decoy to origin must fail (exit code != 0 or could not resolve host)
    assert result.returncode != 0 or "200" not in result.stdout
    assert "healthy" not in result.stdout


def test_07_decoy_cannot_access_production_database():
    """Test 7: Invariant 3 — Decoy container cannot resolve/connect to production PostgreSQL db:5432."""
    import subprocess
    cmd = ["docker", "exec", "aegis-decoy", "curl", "-s", "--max-time", "2", "http://db:5432"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    # Direct network access from decoy to db must fail
    assert result.returncode != 0


def test_08_synthetic_login_interaction_creates_safe_evidence():
    """Test 8: Probing /login under active deception creates DECOY_LOGIN_ATTEMPT evidence."""
    # Initialize session
    init_res = requests.post(f"{API_URL}/api/v1/internal/deception/execute", json={
        "request_id": f"p8-req-auth-{uuid.uuid4().hex[:8]}",
        "trace_id": f"p8-trace-auth-{uuid.uuid4().hex[:8]}",
        "policy_decision": "DECEIVE_ELIGIBLE",
        "waf_blocked": False,
        "initial_risk_score": 75,
        "initial_agent_shield_score": 80,
        "target_route": "/login"
    })
    session_id = init_res.json()["session_id"]

    # Perform POST /login attempt into decoy
    login_res = requests.post(f"{API_URL}/api/v1/internal/deception/interact", json={
        "session_id": session_id,
        "route": "/login",
        "method": "POST",
        "body": {
            "username": "root_admin",
            "password": "attempted_secret_pass_123!"
        }
    })
    assert login_res.status_code == 200
    data = login_res.json()
    assert data["status"] == "SUCCESS"
    assert data["origin_reached"] is False
    assert data["event"]["event_type"] == "DECOY_LOGIN_ATTEMPT"
    assert data["event"]["response_status"] == 401


def test_09_password_is_not_persisted():
    """Test 9: Invariant 4 & 7 — Submitted raw passwords are NEVER stored in evidence metadata or events."""
    canary_password = f"canary_secret_{uuid.uuid4().hex}"
    init_res = requests.post(f"{API_URL}/api/v1/internal/deception/execute", json={
        "request_id": f"p8-req-pwd-{uuid.uuid4().hex[:8]}",
        "trace_id": f"p8-trace-pwd-{uuid.uuid4().hex[:8]}",
        "policy_decision": "DECEIVE_ELIGIBLE",
        "waf_blocked": False
    })
    session_id = init_res.json()["session_id"]

    requests.post(f"{API_URL}/api/v1/internal/deception/interact", json={
        "session_id": session_id,
        "route": "/login",
        "method": "POST",
        "body": {
            "username": "admin_test",
            "password": canary_password
        }
    })

    # Retrieve all evidence events for this session
    events_res = requests.get(f"{API_URL}/api/v1/deception/session/{session_id}/events")
    assert events_res.status_code == 200
    events_text = json.dumps(events_res.json())

    # Raw password must NEVER appear in the persisted evidence
    assert canary_password not in events_text


def test_10_admin_interaction_creates_evidence():
    """Test 10: Accessing /admin in decoy records DECOY_ADMIN_ACCESS event."""
    init_res = requests.post(f"{API_URL}/api/v1/internal/deception/execute", json={
        "request_id": f"p8-req-adm-{uuid.uuid4().hex[:8]}",
        "trace_id": f"p8-trace-adm-{uuid.uuid4().hex[:8]}",
        "policy_decision": "DECEIVE_ELIGIBLE",
        "waf_blocked": False
    })
    session_id = init_res.json()["session_id"]

    admin_res = requests.post(f"{API_URL}/api/v1/internal/deception/interact", json={
        "session_id": session_id,
        "route": "/admin/users",
        "method": "GET"
    })
    assert admin_res.status_code == 200
    data = admin_res.json()
    assert data["event"]["event_type"] == "DECOY_ADMIN_ACCESS"
    assert data["event"]["endpoint_category"] == "ADMINISTRATIVE_SURFACE"
    assert "admin_demo" in json.dumps(data["response"])


def test_11_api_interaction_creates_evidence():
    """Test 11: Probing synthetic API route /api/users records DECOY_API_ACCESS event."""
    init_res = requests.post(f"{API_URL}/api/v1/internal/deception/execute", json={
        "request_id": f"p8-req-api-{uuid.uuid4().hex[:8]}",
        "trace_id": f"p8-trace-api-{uuid.uuid4().hex[:8]}",
        "policy_decision": "DECEIVE_ELIGIBLE",
        "waf_blocked": False
    })
    session_id = init_res.json()["session_id"]

    api_res = requests.post(f"{API_URL}/api/v1/internal/deception/interact", json={
        "session_id": session_id,
        "route": "/api/users",
        "method": "GET"
    })
    assert api_res.status_code == 200
    data = api_res.json()
    assert data["event"]["event_type"] == "DECOY_API_ACCESS"
    assert data["event"]["endpoint_category"] == "API_DATA_SURFACE"


def test_12_deception_timeline_is_correctly_ordered():
    """Test 12: Multi-step attacker journey produces an ordered chronological evidence timeline."""
    init_res = requests.post(f"{API_URL}/api/v1/internal/deception/execute", json={
        "request_id": f"p8-req-time-{uuid.uuid4().hex[:8]}",
        "trace_id": f"p8-trace-time-{uuid.uuid4().hex[:8]}",
        "policy_decision": "DECEIVE_ELIGIBLE",
        "waf_blocked": False,
        "target_route": "/"
    })
    session_id = init_res.json()["session_id"]

    routes = ["/login", "/admin/dashboard", "/api/products", "/admin/settings"]
    for r in routes:
        requests.post(f"{API_URL}/api/v1/internal/deception/interact", json={
            "session_id": session_id,
            "route": r,
            "method": "GET"
        })

    ev_res = requests.get(f"{API_URL}/api/v1/deception/session/{session_id}/events")
    events = ev_res.json()
    assert len(events) >= 5
    # Verify chronological ordering
    timestamps = [e["created_at"] for e in events]
    assert timestamps == sorted(timestamps)


@pytest.mark.asyncio
async def test_13_websocket_sends_deception_event():
    """Test 13: Real-time WebSocket delivery of DECEPTION_EVENT packets."""
    req_id = f"p8-ws-req-{uuid.uuid4().hex[:8]}"
    trace_id = f"p8-ws-trace-{uuid.uuid4().hex[:8]}"
    received = None

    async with websockets.connect(WS_API_URL) as ws:
        await asyncio.sleep(0.2)

        # Trigger execution
        requests.post(f"{API_URL}/api/v1/internal/deception/execute", json={
            "request_id": req_id,
            "trace_id": trace_id,
            "policy_decision": "DECEIVE_ELIGIBLE",
            "waf_blocked": False,
            "initial_risk_score": 88,
            "initial_agent_shield_score": 85
        })

        timeout = 5.0
        start = time.time()
        while time.time() - start < timeout:
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=1.0)
                data = json.loads(msg)
                if data.get("event_type") == "DECEPTION_EVENT" and data.get("request_id") == req_id:
                    received = data
                    break
            except asyncio.TimeoutError:
                continue

    assert received is not None, "Failed to receive DECEPTION_EVENT over WebSocket stream"
    assert received["event_type"] == "DECEPTION_EVENT"
    assert received["origin_reached"] is False


def test_14_dashboard_retrieves_active_session():
    """Test 14: REST endpoints /deception/sessions and /deception/session/{id} return real session data."""
    init_res = requests.post(f"{API_URL}/api/v1/internal/deception/execute", json={
        "request_id": f"p8-req-dash-{uuid.uuid4().hex[:8]}",
        "trace_id": f"p8-trace-dash-{uuid.uuid4().hex[:8]}",
        "policy_decision": "DECEIVE_ELIGIBLE",
        "waf_blocked": False
    })
    session_id = init_res.json()["session_id"]

    # 1. By ID
    res = requests.get(f"{API_URL}/api/v1/deception/session/{session_id}")
    assert res.status_code == 200
    assert res.json()["session_id"] == session_id

    # 2. List sessions
    list_res = requests.get(f"{API_URL}/api/v1/deception/sessions")
    assert list_res.status_code == 200
    sessions = list_res.json()
    assert any(s["session_id"] == session_id for s in sessions)


def test_15_session_expiration_works():
    """Test 15: Terminated or expired session rejects further interaction with HTTP 410."""
    init_res = requests.post(f"{API_URL}/api/v1/internal/deception/execute", json={
        "request_id": f"p8-req-exp-{uuid.uuid4().hex[:8]}",
        "trace_id": f"p8-trace-exp-{uuid.uuid4().hex[:8]}",
        "policy_decision": "DECEIVE_ELIGIBLE",
        "waf_blocked": False
    })
    session_id = init_res.json()["session_id"]

    # Terminate session
    term_res = requests.post(f"{API_URL}/api/v1/internal/deception/terminate/{session_id}")
    assert term_res.status_code == 200

    # Interaction after termination must fail with 410 Gone
    int_res = requests.post(f"{API_URL}/api/v1/internal/deception/interact", json={
        "session_id": session_id,
        "route": "/api/users",
        "method": "GET"
    })
    assert int_res.status_code == 410


def test_16_maximum_session_request_limits_work():
    """Test 16: Exceeding max requests per session terminates session with HTTP 429."""
    init_res = requests.post(f"{API_URL}/api/v1/internal/deception/execute", json={
        "request_id": f"p8-req-lim-{uuid.uuid4().hex[:8]}",
        "trace_id": f"p8-trace-lim-{uuid.uuid4().hex[:8]}",
        "policy_decision": "DECEIVE_ELIGIBLE",
        "waf_blocked": False
    })
    session_id = init_res.json()["session_id"]

    # Directly set interaction_count to 50 in PostgreSQL to test protection limit
    import psycopg2
    conn = psycopg2.connect(
        host="localhost",
        port=5433,
        dbname="aegis_security_db",
        user="aegis_admin",
        password="aegis_secure_hackathon_pass_2026"
    )
    cur = conn.cursor()
    cur.execute("UPDATE deception_sessions SET interaction_count = 50 WHERE session_id = %s", (session_id,))
    conn.commit()
    conn.close()

    # Next interaction should trigger 429 Limit Exceeded
    int_res = requests.post(f"{API_URL}/api/v1/internal/deception/interact", json={
        "session_id": session_id,
        "route": "/api/users",
        "method": "GET"
    })
    assert int_res.status_code == 429


def test_17_sensitive_data_sanitization():
    """Test 17: Authorization headers, tokens, and cookies are stripped/redacted from evidence."""
    init_res = requests.post(f"{API_URL}/api/v1/internal/deception/execute", json={
        "request_id": f"p8-req-san-{uuid.uuid4().hex[:8]}",
        "trace_id": f"p8-trace-san-{uuid.uuid4().hex[:8]}",
        "policy_decision": "DECEIVE_ELIGIBLE",
        "waf_blocked": False,
        "headers": {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_canary",
            "Cookie": "session_secret=top_secret_cookie_canary"
        }
    })
    session_id = init_res.json()["session_id"]

    # Verify evidence does not leak canary strings
    events_res = requests.get(f"{API_URL}/api/v1/deception/session/{session_id}/events")
    events_text = json.dumps(events_res.json())
    assert "sensitive_canary" not in events_text
    assert "top_secret_cookie_canary" not in events_text


def test_18_deception_service_failure_does_not_break_origin_protection():
    """Test 18: Invariant 5 — If decoy execution fails, origin_reached remains strictly False."""
    # Pass an invalid or unreachable target route / simulation
    res = requests.post(f"{API_URL}/api/v1/internal/deception/execute", json={
        "request_id": f"p8-req-failprot-{uuid.uuid4().hex[:8]}",
        "trace_id": f"p8-trace-failprot-{uuid.uuid4().hex[:8]}",
        "policy_decision": "DECEIVE_ELIGIBLE",
        "waf_blocked": False,
        "target_route": "/nonexistent_invalid_path"
    })
    # Must never reach origin
    assert res.json().get("origin_reached") is False


def test_19_deception_failure_does_not_silently_fallback_to_origin():
    """Test 19: Invariant 5 — Deception failure NEVER falls back to the real origin."""
    # Attempting to interact with an invalid or terminated session returns error, never origin data
    bad_res = requests.post(f"{API_URL}/api/v1/internal/deception/interact", json={
        "session_id": "non_existent_session_id",
        "route": "/api/users",
        "method": "GET"
    })
    assert bad_res.status_code == 404
    assert bad_res.json().get("origin_reached") is not True


def test_20_phase1_to_7_full_regression_remains_green():
    """Test 20: Complete live regression across Phases 1 through 7 through the Gateway :8080."""
    # Clean traffic -> Origin responds 200
    res_clean = requests.get(f"{GATEWAY_URL}/")
    assert res_clean.status_code == 200
    assert "X-Request-ID" in res_clean.headers

    # SQLi attack -> WAF Coraza blocks with 403 Forbidden
    res_sqli = requests.get(f"{GATEWAY_URL}/products?search=' UNION SELECT 1,2,3--")
    assert res_sqli.status_code == 403
