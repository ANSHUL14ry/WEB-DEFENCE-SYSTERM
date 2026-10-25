"""
AEGIS Ω — Phase 4 Integration Tests
Validates the Normalized Security Event Pipeline, Telemetry Ingestion,
Deduplication, Correlation, Pagination, Filtering, Sensitive Sanitization,
WebSocket Real-Time Delivery, and End-to-End WAF-to-Pipeline flow.
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
WS_GATEWAY_URL = "ws://localhost:8080/api/v1/ws/events"


def test_01_event_schema_validation():
    """Verify that malformed events are strictly rejected and valid events pass."""
    # 1. Invalid event_type
    bad_payload = {
        "event_type": "TOTALLY_FAKE_TYPE",
        "request_id": "test-req-01",
        "trace_id": "test-trace-01",
        "component": "system"
    }
    res = requests.post(f"{API_URL}/api/v1/internal/events", json=bad_payload)
    assert res.status_code == 422, f"Expected 422 for invalid event_type, got {res.status_code}"

    # 2. Invalid severity
    bad_severity = {
        "event_type": "SYSTEM_EVENT",
        "request_id": "test-req-02",
        "trace_id": "test-trace-02",
        "component": "system",
        "severity": "UNKNOWN_SEV"
    }
    res = requests.post(f"{API_URL}/api/v1/internal/events", json=bad_severity)
    assert res.status_code == 422, f"Expected 422 for invalid severity, got {res.status_code}"

    # 3. Status 'VERIFIED' is rejected (reserved strictly for Phase 9)
    bad_status = {
        "event_type": "SYSTEM_EVENT",
        "request_id": "test-req-03",
        "trace_id": "test-trace-03",
        "component": "system",
        "status": "VERIFIED"
    }
    res = requests.post(f"{API_URL}/api/v1/internal/events", json=bad_status)
    assert res.status_code == 422, f"Expected 422 for reserved VERIFIED status, got {res.status_code}"


def test_02_event_persistence_and_retrieval():
    """Verify that a valid normalized security event is persisted in PostgreSQL and retrievable."""
    test_id = f"test-ev-{uuid.uuid4().hex[:12]}"
    req_id = f"req-{uuid.uuid4().hex[:12]}"
    trace_id = f"trace-{uuid.uuid4().hex[:12]}"

    payload = {
        "event_id": test_id,
        "event_type": "GATEWAY_REQUEST",
        "request_id": req_id,
        "trace_id": trace_id,
        "severity": "LOW",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "source": {"ip": "192.168.1.100", "user_agent": "Mozilla/5.0 AEGIS-Test"},
        "request": {"method": "GET", "uri": "/api/v1/status"},
        "metadata": {"custom_tag": "phase4_verification"}
    }

    # Ingest event
    res = requests.post(f"{API_URL}/api/v1/internal/events", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ingested"
    assert data["event_id"] == test_id
    assert data["is_new"] is True

    # Retrieve single event
    get_res = requests.get(f"{API_URL}/api/v1/events/{test_id}")
    assert get_res.status_code == 200
    ev = get_res.json()
    assert ev["event_id"] == test_id
    assert ev["event_type"] == "GATEWAY_REQUEST"
    assert ev["request_id"] == req_id
    assert ev["trace_id"] == trace_id
    assert ev["severity"] == "LOW"
    assert ev["action"] == "ALLOW"
    assert ev["component"] == "gateway"
    assert ev["status"] == "ALLOWED"
    assert ev["metadata"]["custom_tag"] == "phase4_verification"


def test_03_event_deduplication():
    """Verify that ingesting the identical event ID is safely deduplicated."""
    test_id = f"dedup-{uuid.uuid4().hex[:12]}"
    payload = {
        "event_id": test_id,
        "event_type": "SYSTEM_EVENT",
        "request_id": "req-dedup-01",
        "trace_id": "trace-dedup-01",
        "component": "system",
        "severity": "INFO",
        "action": "OBSERVED",
        "status": "OBSERVED",
        "source": {"ip": "127.0.0.1"},
        "request": {"method": "GET", "uri": "/system/test"},
        "metadata": {"attempt": 1}
    }

    # First ingestion -> is_new: True
    res1 = requests.post(f"{API_URL}/api/v1/internal/events", json=payload)
    assert res1.status_code == 200
    assert res1.json()["status"] == "ingested"
    assert res1.json()["is_new"] is True

    # Duplicate ingestion -> is_new: False, status: duplicate_skipped
    res2 = requests.post(f"{API_URL}/api/v1/internal/events", json=payload)
    assert res2.status_code == 200
    assert res2.json()["status"] == "duplicate_skipped"
    assert res2.json()["is_new"] is False


def test_04_request_id_correlation():
    """Verify multi-event correlation grouping under the same request_id."""
    req_id = f"correl-req-{uuid.uuid4().hex[:10]}"
    trace_id = f"correl-trace-{uuid.uuid4().hex[:10]}"

    # Event 1: WAF detection
    ev1 = {
        "event_id": f"ev1-{uuid.uuid4().hex[:8]}",
        "event_type": "WAF_DETECTION",
        "request_id": req_id,
        "trace_id": trace_id,
        "component": "coraza",
        "severity": "HIGH",
        "action": "BLOCK",
        "status": "DETECTED",
        "source": {"ip": "10.0.0.5"},
        "request": {"method": "POST", "uri": "/login"},
        "metadata": {"rule_id": 942100}
    }
    # Event 2: WAF block enforcement
    ev2 = {
        "event_id": f"ev2-{uuid.uuid4().hex[:8]}",
        "event_type": "WAF_BLOCK",
        "request_id": req_id,
        "trace_id": trace_id,
        "component": "coraza",
        "severity": "CRITICAL",
        "action": "BLOCK",
        "status": "BLOCKED",
        "source": {"ip": "10.0.0.5"},
        "request": {"method": "POST", "uri": "/login"},
        "metadata": {"rule_id": 942100, "anomaly_score": 5}
    }

    requests.post(f"{API_URL}/api/v1/internal/events", json=ev1)
    requests.post(f"{API_URL}/api/v1/internal/events", json=ev2)

    # Query correlated request events
    res = requests.get(f"{API_URL}/api/v1/events/request/{req_id}")
    assert res.status_code == 200
    correlated = res.json()
    assert len(correlated) == 2
    types = [e["event_type"] for e in correlated]
    assert "WAF_DETECTION" in types
    assert "WAF_BLOCK" in types
    assert all(e["request_id"] == req_id for e in correlated)


def test_05_trace_id_correlation():
    """Verify multi-request correlation across a request-chain (trace_id)."""
    common_trace_id = f"trace-chain-{uuid.uuid4().hex[:10]}"
    req1 = f"step1-{uuid.uuid4().hex[:8]}"
    req2 = f"step2-{uuid.uuid4().hex[:8]}"

    payload1 = {
        "event_id": f"step1-ev-{uuid.uuid4().hex[:8]}",
        "event_type": "GATEWAY_REQUEST",
        "request_id": req1,
        "trace_id": common_trace_id,
        "component": "gateway",
        "severity": "INFO",
        "action": "ALLOW",
        "status": "ALLOWED",
        "request": {"method": "GET", "uri": "/page1"}
    }
    payload2 = {
        "event_id": f"step2-ev-{uuid.uuid4().hex[:8]}",
        "event_type": "GATEWAY_REQUEST",
        "request_id": req2,
        "trace_id": common_trace_id,
        "component": "gateway",
        "severity": "INFO",
        "action": "ALLOW",
        "status": "ALLOWED",
        "request": {"method": "GET", "uri": "/page2"}
    }

    requests.post(f"{API_URL}/api/v1/internal/events", json=payload1)
    requests.post(f"{API_URL}/api/v1/internal/events", json=payload2)

    res = requests.get(f"{API_URL}/api/v1/events/trace/{common_trace_id}")
    assert res.status_code == 200
    chain = res.json()
    assert len(chain) == 2
    req_ids = {e["request_id"] for e in chain}
    assert req1 in req_ids
    assert req2 in req_ids


def test_06_event_pagination():
    """Verify limit and offset pagination on security events endpoint."""
    res = requests.get(f"{API_URL}/api/v1/events?limit=2&offset=0")
    assert res.status_code == 200
    data = res.json()
    assert data["limit"] == 2
    assert data["offset"] == 0
    assert "total" in data
    assert len(data["events"]) <= 2

    # Offset pagination
    res_offset = requests.get(f"{API_URL}/api/v1/events?limit=2&offset=1")
    assert res_offset.status_code == 200
    data_offset = res_offset.json()
    assert data_offset["offset"] == 1


def test_07_event_filtering():
    """Verify server-side filtering by severity and event_type."""
    unique_marker = f"filter-{uuid.uuid4().hex[:8]}"
    payload = {
        "event_id": f"filter-ev-{uuid.uuid4().hex[:8]}",
        "event_type": "SYSTEM_EVENT",
        "request_id": f"filter-req-{unique_marker}",
        "trace_id": f"filter-trace-{unique_marker}",
        "component": "system",
        "severity": "CRITICAL",
        "action": "ALERT",
        "status": "DETECTED",
        "request": {"method": "POST", "uri": f"/system/{unique_marker}"}
    }
    requests.post(f"{API_URL}/api/v1/internal/events", json=payload)

    # Filter by severity
    res_sev = requests.get(f"{API_URL}/api/v1/events?severity=CRITICAL")
    assert res_sev.status_code == 200
    events_sev = res_sev.json()["events"]
    assert all(e["severity"] == "CRITICAL" for e in events_sev)

    # Filter by event_type
    res_type = requests.get(f"{API_URL}/api/v1/events?event_type=SYSTEM_EVENT")
    assert res_type.status_code == 200
    events_type = res_type.json()["events"]
    assert all(e["event_type"] == "SYSTEM_EVENT" for e in events_type)


def test_08_sensitive_field_sanitization():
    """Verify that passwords, tokens, and authorization headers are never persisted or exposed."""
    sensitive_ev_id = f"sanitize-ev-{uuid.uuid4().hex[:8]}"
    payload = {
        "event_id": sensitive_ev_id,
        "event_type": "SYSTEM_EVENT",
        "request_id": "sanitize-req-01",
        "trace_id": "sanitize-trace-01",
        "component": "system",
        "severity": "INFO",
        "action": "OBSERVED",
        "status": "OBSERVED",
        "request": {
            "method": "POST",
            "uri": "/auth/login?token=super_secret_token_12345&password=my_secret_pass"
        },
        "metadata": {
            "password": "plain_password_here",
            "token": "secret_jwt_token_here",
            "authorization": "Bearer secret_bearer_token",
            "api_key": "secret_api_key_value",
            "nested": {
                "secret": "top_secret_code",
                "safe_value": "hello_world"
            }
        }
    }

    requests.post(f"{API_URL}/api/v1/internal/events", json=payload)

    # Fetch persisted event
    res = requests.get(f"{API_URL}/api/v1/events/{sensitive_ev_id}")
    assert res.status_code == 200
    ev = res.json()

    # Verify URI query sanitization
    assert "token=[REDACTED]" in ev["request"]["uri"]
    assert "password=[REDACTED]" in ev["request"]["uri"]
    assert "super_secret_token_12345" not in ev["request"]["uri"]

    # Verify metadata credential sanitization
    meta = ev["metadata"]
    assert meta["password"] == "[REDACTED]"
    assert meta["token"] == "[REDACTED]"
    assert meta["authorization"] == "[REDACTED]"
    assert meta["api_key"] == "[REDACTED]"
    assert meta["nested"]["secret"] == "[REDACTED]"
    assert meta["nested"]["safe_value"] == "hello_world"


@pytest.mark.asyncio
async def test_09_realtime_websocket_stream():
    """Verify real-time delivery of ingested security events over WebSocket."""
    ws_event_id = f"ws-ev-{uuid.uuid4().hex[:8]}"
    req_id = f"ws-req-{uuid.uuid4().hex[:8]}"

    async with websockets.connect(WS_API_URL) as ws:
        # Ingest an event via API
        payload = {
            "event_id": ws_event_id,
            "event_type": "SYSTEM_EVENT",
            "request_id": req_id,
            "trace_id": f"trace-{req_id}",
            "component": "system",
            "severity": "MEDIUM",
            "action": "ALERT",
            "status": "DETECTED",
            "request": {"method": "GET", "uri": "/ws-live-test"}
        }
        post_res = requests.post(f"{API_URL}/api/v1/internal/events", json=payload)
        assert post_res.status_code == 200

        # Receive streamed event over WebSocket
        msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
        event_received = json.loads(msg)
        assert event_received["event_id"] == ws_event_id
        assert event_received["event_type"] == "SYSTEM_EVENT"
        assert event_received["request_id"] == req_id
        assert event_received["severity"] == "MEDIUM"


def test_10_waf_to_pipeline_end_to_end():
    """
    End-to-end WAF threat interception and pipeline normalization verification.
    1. Send controlled SQLi attack via Ingress Gateway (:8080).
    2. Gateway -> Coraza WAF blocks with HTTP 403.
    3. WAF log watcher ingests audit transaction.
    4. Pipeline normalizes event into 'security_events' with rule 942100.
    5. Origin request log remains untouched (Origin Isolation).
    """
    # 1. Reset origin stats
    requests.post(f"{API_URL}/api/v1/internal/events")  # Ensure API is warm
    origin_stats_before = requests.get(f"{GATEWAY_URL}/stats").json()["total_requests_received"]

    # 2. Send controlled SQL injection canary payload
    attack_res = requests.get(f"{GATEWAY_URL}/products?category=%27%20OR%201=1--")
    assert attack_res.status_code == 403, f"Expected 403 from WAF, got {attack_res.status_code}"
    attack_req_id = attack_res.headers.get("x-request-id")
    assert attack_req_id is not None

    # 3. Allow watcher brief window to tail Coraza audit log
    time.sleep(1.5)

    # 4. Verify event in security_events pipeline
    correl_res = requests.get(f"{API_URL}/api/v1/events/request/{attack_req_id}")
    assert correl_res.status_code == 200
    events = correl_res.json()
    assert len(events) >= 1, f"Expected correlated security event for request {attack_req_id}"

    waf_block_event = events[0]
    assert waf_block_event["event_type"] in ["WAF_BLOCK", "WAF_DETECTION"]
    assert waf_block_event["action"] == "BLOCK"
    assert waf_block_event["status"] == "BLOCKED"
    assert waf_block_event["component"] == "coraza"
    assert waf_block_event["metadata"]["rule_id"] == 942100

    # 5. Verify Origin was NOT reached during the attack
    origin_stats_after = requests.get(f"{GATEWAY_URL}/stats").json()["total_requests_received"]
    assert origin_stats_after == origin_stats_before, (
        f"Origin request count increased from {origin_stats_before} to {origin_stats_after} during blocked attack!"
    )


def test_11_origin_event_correlation():
    """Verify that a legitimate request reaching origin generates a correlated ORIGIN_REQUEST event."""
    client_req_id = f"legit-flow-{uuid.uuid4().hex[:12]}"
    headers = {"X-Request-ID": client_req_id}

    # Legitimate request to /products
    res = requests.get(f"{GATEWAY_URL}/products", headers=headers)
    assert res.status_code == 200
    propagated_req_id = res.headers.get("x-request-id")
    assert propagated_req_id == client_req_id

    # Allow async origin telemetry to reach pipeline
    time.sleep(1.0)

    # Check correlated origin event in pipeline
    correl_res = requests.get(f"{API_URL}/api/v1/events/request/{client_req_id}")
    assert correl_res.status_code == 200
    events = correl_res.json()
    assert len(events) >= 1

    origin_ev = next((e for e in events if e["component"] == "origin"), None)
    assert origin_ev is not None, "Expected ORIGIN_REQUEST security event"
    assert origin_ev["event_type"] == "ORIGIN_REQUEST"
    assert origin_ev["action"] == "ALLOW"
    assert origin_ev["status"] == "ALLOWED"
    assert origin_ev["request_id"] == client_req_id
    assert "response_status" in origin_ev["metadata"]
    assert origin_ev["metadata"]["response_status"] == 200


def test_12_event_stats_live_counters():
    """Verify aggregated event statistics return valid real data without fabrication."""
    res = requests.get(f"{API_URL}/api/v1/events/stats")
    assert res.status_code == 200
    stats = res.json()
    assert "total_events" in stats
    assert "waf_blocks" in stats
    assert "high_severity" in stats
    assert "critical_severity" in stats
    assert "events_24h" in stats
    assert "by_type" in stats
    assert "by_severity" in stats
    assert isinstance(stats["total_events"], int)
    assert stats["total_events"] >= 0
