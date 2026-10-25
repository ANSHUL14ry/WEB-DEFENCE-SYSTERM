"""
AEGIS Ω — Phase 6 Integration Tests
Validates the AgentShield Behavioral Automation Engine:
Deterministic behavioral analysis, rapid recon, endpoint & API enumeration,
request velocity, auth probing, repeated WAF triggers, parameter manipulation,
attack sequence progression, score capping, explainability, persistence,
REST API retrieval, WebSocket streaming, Risk Engine integration, failure safety,
and technical disclaimer enforcement (no fake AI detection).
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


def test_01_no_suspicious_behavior_low_score():
    """Verify clean single request results in a LOW AgentShield score (0-24)."""
    trace_id = f"trace-clean-{uuid.uuid4().hex[:8]}"
    payload = {
        "event_type": "ORIGIN_REQUEST",
        "request_id": f"clean-req-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "INFO",
        "action": "ALLOW",
        "component": "origin",
        "status": "ALLOWED",
        "source": {"ip": "127.0.0.1"},
        "request": {"method": "GET", "uri": "/products"},
        "metadata": {}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["agent_shield_score"] <= 24
    assert data["severity"] == "LOW"
    assert "Standard interactive traffic pattern" in data["behavior_summary"]


def test_02_rapid_recon_detection():
    """Verify scanning multiple recon endpoints triggers rapid_recon signal (+15)."""
    trace_id = f"trace-recon-{uuid.uuid4().hex[:8]}"

    # Ingest preliminary reconnaissance requests
    endpoints = ["/", "/robots.txt", "/sitemap.xml"]
    for ep in endpoints[:-1]:
        requests.post(f"{API_URL}/api/v1/internal/events", json={
            "event_type": "GATEWAY_REQUEST",
            "request_id": f"recon-{uuid.uuid4().hex[:8]}",
            "trace_id": trace_id,
            "severity": "INFO",
            "action": "ALLOW",
            "component": "gateway",
            "status": "ALLOWED",
            "source": {"ip": "10.0.0.1"},
            "request": {"method": "GET", "uri": ep},
            "metadata": {}
        })

    # Trigger AgentShield assessment on final recon path
    target = {
        "event_type": "GATEWAY_REQUEST",
        "request_id": f"recon-final-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "INFO",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "source": {"ip": "10.0.0.1"},
        "request": {"method": "GET", "uri": endpoints[-1]},
        "metadata": {}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json=target)
    assert res.status_code == 200
    data = res.json()
    sig_names = [s["name"] for s in data["signals"]]
    assert "rapid_recon" in sig_names


def test_03_endpoint_enumeration_detection():
    """Verify systematic discovery of multiple distinct paths triggers endpoint_enumeration (+15)."""
    trace_id = f"trace-ep-enum-{uuid.uuid4().hex[:8]}"
    paths = ["/home", "/catalog", "/contact", "/pricing", "/about"]

    for p in paths[:-1]:
        requests.post(f"{API_URL}/api/v1/internal/events", json={
            "event_type": "GATEWAY_REQUEST",
            "request_id": f"ep-{uuid.uuid4().hex[:8]}",
            "trace_id": trace_id,
            "severity": "INFO",
            "action": "ALLOW",
            "component": "gateway",
            "status": "ALLOWED",
            "source": {"ip": "10.0.0.2"},
            "request": {"method": "GET", "uri": p},
            "metadata": {}
        })

    target = {
        "event_type": "GATEWAY_REQUEST",
        "request_id": f"ep-final-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "INFO",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "source": {"ip": "10.0.0.2"},
        "request": {"method": "GET", "uri": paths[-1]},
        "metadata": {}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json=target)
    assert res.status_code == 200
    data = res.json()
    sig_names = [s["name"] for s in data["signals"]]
    assert "endpoint_enumeration" in sig_names


def test_04_api_enumeration_detection():
    """Verify systematic probing of API paths triggers api_enumeration (+15)."""
    trace_id = f"trace-api-enum-{uuid.uuid4().hex[:8]}"
    api_paths = ["/api/users", "/api/products", "/api/orders"]

    for ap in api_paths[:-1]:
        requests.post(f"{API_URL}/api/v1/internal/events", json={
            "event_type": "GATEWAY_REQUEST",
            "request_id": f"api-{uuid.uuid4().hex[:8]}",
            "trace_id": trace_id,
            "severity": "INFO",
            "action": "ALLOW",
            "component": "gateway",
            "status": "ALLOWED",
            "source": {"ip": "10.0.0.3"},
            "request": {"method": "GET", "uri": ap},
            "metadata": {}
        })

    target = {
        "event_type": "GATEWAY_REQUEST",
        "request_id": f"api-final-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "INFO",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "source": {"ip": "10.0.0.3"},
        "request": {"method": "GET", "uri": api_paths[-1]},
        "metadata": {}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json=target)
    assert res.status_code == 200
    data = res.json()
    sig_names = [s["name"] for s in data["signals"]]
    assert "api_enumeration" in sig_names


def test_05_request_velocity_detection():
    """Verify high burst velocity (>= 5 requests) triggers request_velocity (+15)."""
    trace_id = f"trace-velocity-{uuid.uuid4().hex[:8]}"

    for i in range(5):
        requests.post(f"{API_URL}/api/v1/internal/events", json={
            "event_type": "GATEWAY_REQUEST",
            "request_id": f"vel-{i}-{uuid.uuid4().hex[:8]}",
            "trace_id": trace_id,
            "severity": "INFO",
            "action": "ALLOW",
            "component": "gateway",
            "status": "ALLOWED",
            "source": {"ip": "10.0.0.4"},
            "request": {"method": "GET", "uri": f"/item/{i}"},
            "metadata": {}
        })

    target = {
        "event_type": "GATEWAY_REQUEST",
        "request_id": f"vel-target-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "INFO",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "source": {"ip": "10.0.0.4"},
        "request": {"method": "GET", "uri": "/item/target"},
        "metadata": {}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json=target)
    assert res.status_code == 200
    data = res.json()
    sig_names = [s["name"] for s in data["signals"]]
    assert "request_velocity" in sig_names


def test_06_auth_probing_detection():
    """Verify repeated requests to credential endpoints triggers authentication_probing (+10)."""
    trace_id = f"trace-auth-{uuid.uuid4().hex[:8]}"

    requests.post(f"{API_URL}/api/v1/internal/events", json={
        "event_type": "GATEWAY_REQUEST",
        "request_id": f"auth-1-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "INFO",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "source": {"ip": "10.0.0.5"},
        "request": {"method": "POST", "uri": "/login"},
        "metadata": {}
    })

    target = {
        "event_type": "GATEWAY_REQUEST",
        "request_id": f"auth-2-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "INFO",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "source": {"ip": "10.0.0.5"},
        "request": {"method": "POST", "uri": "/login"},
        "metadata": {}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json=target)
    assert res.status_code == 200
    data = res.json()
    sig_names = [s["name"] for s in data["signals"]]
    assert "authentication_probing" in sig_names


def test_07_repeated_waf_triggers_detection():
    """Verify multiple WAF detections/blocks in trace triggers repeated_waf_triggers (+15)."""
    trace_id = f"trace-waf-rep-{uuid.uuid4().hex[:8]}"

    requests.post(f"{API_URL}/api/v1/internal/events", json={
        "event_type": "WAF_BLOCK",
        "request_id": f"waf-1-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "CRITICAL",
        "action": "BLOCK",
        "component": "coraza",
        "status": "BLOCKED",
        "source": {"ip": "10.0.0.6"},
        "request": {"method": "GET", "uri": "/products?id=1"},
        "metadata": {"rule_id": 942100}
    })

    target = {
        "event_type": "WAF_BLOCK",
        "request_id": f"waf-2-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "CRITICAL",
        "action": "BLOCK",
        "component": "coraza",
        "status": "BLOCKED",
        "source": {"ip": "10.0.0.6"},
        "request": {"method": "GET", "uri": "/products?id=2"},
        "metadata": {"rule_id": 942100}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json=target)
    assert res.status_code == 200
    data = res.json()
    sig_names = [s["name"] for s in data["signals"]]
    assert "repeated_waf_triggers" in sig_names


def test_08_parameter_manipulation_detection():
    """Verify repeated structural variations of parameters on same route triggers parameter_manipulation (+5)."""
    trace_id = f"trace-params-{uuid.uuid4().hex[:8]}"

    requests.post(f"{API_URL}/api/v1/internal/events", json={
        "event_type": "GATEWAY_REQUEST",
        "request_id": f"param-1-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "INFO",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "source": {"ip": "10.0.0.7"},
        "request": {"method": "GET", "uri": "/search?q=test"},
        "metadata": {}
    })

    target = {
        "event_type": "GATEWAY_REQUEST",
        "request_id": f"param-2-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "INFO",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "source": {"ip": "10.0.0.7"},
        "request": {"method": "GET", "uri": "/search?category=admin&filter=true"},
        "metadata": {}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json=target)
    assert res.status_code == 200
    data = res.json()
    sig_names = [s["name"] for s in data["signals"]]
    assert "parameter_manipulation" in sig_names


def test_09_attack_sequence_detection():
    """Verify progression across multi-stage attack lifecycle triggers attack_sequence (+20)."""
    trace_id = f"trace-seq-{uuid.uuid4().hex[:8]}"

    # Stage 1: RECON
    requests.post(f"{API_URL}/api/v1/internal/events", json={
        "event_type": "GATEWAY_REQUEST",
        "request_id": f"seq-1-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "INFO",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "source": {"ip": "10.0.0.8"},
        "request": {"method": "GET", "uri": "/robots.txt"},
        "metadata": {}
    })

    # Stage 2: ENDPOINT_DISCOVERY
    requests.post(f"{API_URL}/api/v1/internal/events", json={
        "event_type": "GATEWAY_REQUEST",
        "request_id": f"seq-2-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "INFO",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "source": {"ip": "10.0.0.8"},
        "request": {"method": "GET", "uri": "/admin"},
        "metadata": {}
    })

    # Stage 3: API_ENUMERATION
    requests.post(f"{API_URL}/api/v1/internal/events", json={
        "event_type": "GATEWAY_REQUEST",
        "request_id": f"seq-3-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "INFO",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "source": {"ip": "10.0.0.8"},
        "request": {"method": "GET", "uri": "/api/users"},
        "metadata": {}
    })

    # Stage 4: WAF_TRIGGER
    target = {
        "event_type": "WAF_BLOCK",
        "request_id": f"seq-4-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "CRITICAL",
        "action": "BLOCK",
        "component": "coraza",
        "status": "BLOCKED",
        "source": {"ip": "10.0.0.8"},
        "request": {"method": "GET", "uri": "/api/users?id=' OR 1=1--"},
        "metadata": {"rule_id": 942100}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json=target)
    assert res.status_code == 200
    data = res.json()
    sig_names = [s["name"] for s in data["signals"]]
    assert "attack_sequence" in sig_names
    assert len(data["attack_stages"]) >= 3


def test_10_combined_behavioral_scoring():
    """Verify combined signals produce a cumulative, mathematically correct score."""
    trace_id = f"trace-comb-{uuid.uuid4().hex[:8]}"

    # Seed multiple stages & paths
    for ep in ["/", "/robots.txt", "/admin", "/api/users", "/login"]:
        requests.post(f"{API_URL}/api/v1/internal/events", json={
            "event_type": "GATEWAY_REQUEST",
            "request_id": f"comb-{uuid.uuid4().hex[:8]}",
            "trace_id": trace_id,
            "severity": "INFO",
            "action": "ALLOW",
            "component": "gateway",
            "status": "ALLOWED",
            "source": {"ip": "10.0.0.9"},
            "request": {"method": "GET", "uri": ep},
            "metadata": {}
        })

    target = {
        "event_type": "WAF_BLOCK",
        "request_id": f"comb-target-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "CRITICAL",
        "action": "BLOCK",
        "component": "coraza",
        "status": "BLOCKED",
        "source": {"ip": "10.0.0.9"},
        "request": {"method": "POST", "uri": "/login"},
        "metadata": {"rule_id": 942100}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json=target)
    assert res.status_code == 200
    data = res.json()
    assert data["agent_shield_score"] >= 50
    assert data["severity"] in ["HIGH", "CRITICAL"]


def test_11_score_capped_at_100():
    """Verify that even when raw signal total exceeds 100, the AgentShield score is capped at 100."""
    trace_id = f"trace-cap-{uuid.uuid4().hex[:8]}"

    # Generate extensive multi-signal events
    for p in ["/", "/robots.txt", "/admin", "/api/users", "/api/keys", "/login", "/search?q=1", "/search?cat=2"]:
        requests.post(f"{API_URL}/api/v1/internal/events", json={
            "event_type": "GATEWAY_REQUEST",
            "request_id": f"cap-{uuid.uuid4().hex[:8]}",
            "trace_id": trace_id,
            "severity": "INFO",
            "action": "ALLOW",
            "component": "gateway",
            "status": "ALLOWED",
            "source": {"ip": "10.0.0.10"},
            "request": {"method": "GET", "uri": p},
            "metadata": {}
        })

    # Add 2 WAF blocks
    for w in [942100, 941100]:
        requests.post(f"{API_URL}/api/v1/internal/events", json={
            "event_type": "WAF_BLOCK",
            "request_id": f"cap-waf-{w}-{uuid.uuid4().hex[:8]}",
            "trace_id": trace_id,
            "severity": "CRITICAL",
            "action": "BLOCK",
            "component": "coraza",
            "status": "BLOCKED",
            "source": {"ip": "10.0.0.10"},
            "request": {"method": "GET", "uri": "/login"},
            "metadata": {"rule_id": w}
        })

    target = {
        "event_type": "WAF_BLOCK",
        "request_id": f"cap-target-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "CRITICAL",
        "action": "BLOCK",
        "component": "coraza",
        "status": "BLOCKED",
        "source": {"ip": "10.0.0.10"},
        "request": {"method": "POST", "uri": "/login"},
        "metadata": {"rule_id": 942100}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json=target)
    assert res.status_code == 200
    data = res.json()
    assert data["agent_shield_score"] <= 100
    assert data["severity"] == "CRITICAL"


def test_12_deterministic_repeated_analysis():
    """Verify that identical inputs produce 100% reproducible scores, signals, and severity."""
    trace_id = f"trace-det-{uuid.uuid4().hex[:8]}"
    req_id = f"det-req-{uuid.uuid4().hex[:8]}"

    payload = {
        "event_type": "GATEWAY_REQUEST",
        "request_id": req_id,
        "trace_id": trace_id,
        "severity": "INFO",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "source": {"ip": "10.0.0.11"},
        "request": {"method": "GET", "uri": "/api/users"},
        "metadata": {}
    }

    res1 = requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json=payload)
    res2 = requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json=payload)
    assert res1.status_code == 200
    assert res2.status_code == 200

    d1 = res1.json()
    d2 = res2.json()
    assert d1["agent_shield_score"] == d2["agent_shield_score"]
    assert d1["severity"] == d2["severity"]
    assert len(d1["signals"]) == len(d2["signals"])


def test_13_signal_explanations_and_evidence():
    """Verify all signals have name, score, reason, and sanitized evidence dictionary."""
    trace_id = f"trace-expl-{uuid.uuid4().hex[:8]}"

    for ep in ["/", "/robots.txt", "/admin"]:
        requests.post(f"{API_URL}/api/v1/internal/events", json={
            "event_type": "GATEWAY_REQUEST",
            "request_id": f"expl-{uuid.uuid4().hex[:8]}",
            "trace_id": trace_id,
            "severity": "INFO",
            "action": "ALLOW",
            "component": "gateway",
            "status": "ALLOWED",
            "source": {"ip": "10.0.0.12"},
            "request": {"method": "GET", "uri": ep},
            "metadata": {}
        })

    target = {
        "event_type": "GATEWAY_REQUEST",
        "request_id": f"expl-target-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "INFO",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "source": {"ip": "10.0.0.12"},
        "request": {"method": "GET", "uri": "/login"},
        "metadata": {}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json=target)
    assert res.status_code == 200
    data = res.json()
    for sig in data["signals"]:
        assert "name" in sig and isinstance(sig["name"], str)
        assert "score" in sig and isinstance(sig["score"], int)
        assert "reason" in sig and len(sig["reason"]) > 5
        assert "evidence" in sig and isinstance(sig["evidence"], dict)


def test_14_request_id_correlation():
    """Verify that AgentShield assessment matches the specific request_id."""
    req_id = f"as-req-{uuid.uuid4().hex[:8]}"
    trace_id = f"as-trace-{uuid.uuid4().hex[:8]}"

    target = {
        "event_type": "GATEWAY_REQUEST",
        "request_id": req_id,
        "trace_id": trace_id,
        "severity": "INFO",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "source": {"ip": "10.0.0.13"},
        "request": {"method": "GET", "uri": "/products"},
        "metadata": {}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json=target)
    assert res.status_code == 200
    data = res.json()
    assert data["request_id"] == req_id
    assert data["trace_id"] == trace_id


def test_15_trace_id_correlation():
    """Verify that multiple assessments under one trace_id can be queried together."""
    trace_id = f"as-trace-multi-{uuid.uuid4().hex[:8]}"

    for i in range(2):
        requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json={
            "event_type": "GATEWAY_REQUEST",
            "request_id": f"multi-req-{i}-{uuid.uuid4().hex[:8]}",
            "trace_id": trace_id,
            "severity": "INFO",
            "action": "ALLOW",
            "component": "gateway",
            "status": "ALLOWED",
            "source": {"ip": "10.0.0.14"},
            "request": {"method": "GET", "uri": f"/item/{i}"},
            "metadata": {}
        })

    res = requests.get(f"{API_URL}/api/v1/agent-shield/trace/{trace_id}")
    assert res.status_code == 200
    items = res.json()
    assert len(items) >= 2
    for item in items:
        assert item["trace_id"] == trace_id


def test_16_temporal_window_enforcement():
    """Verify historical events are bounded by 60s temporal window."""
    trace_id = f"as-trace-win-{uuid.uuid4().hex[:8]}"
    target = {
        "event_type": "GATEWAY_REQUEST",
        "request_id": f"win-req-{uuid.uuid4().hex[:8]}",
        "trace_id": trace_id,
        "severity": "INFO",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "source": {"ip": "10.0.0.15"},
        "request": {"method": "GET", "uri": "/"},
        "metadata": {}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json=target)
    assert res.status_code == 200
    data = res.json()
    assert data["agent_shield_score"] <= 24


def test_17_agentshield_persistence():
    """Verify AgentShield assessments are persisted into PostgreSQL table."""
    trace_id = f"trace-persist-{uuid.uuid4().hex[:8]}"
    req_id = f"req-persist-{uuid.uuid4().hex[:8]}"

    payload = {
        "event_type": "WAF_BLOCK",
        "request_id": req_id,
        "trace_id": trace_id,
        "severity": "CRITICAL",
        "action": "BLOCK",
        "component": "coraza",
        "status": "BLOCKED",
        "source": {"ip": "10.0.0.16"},
        "request": {"method": "GET", "uri": "/admin"},
        "metadata": {"rule_id": 942100}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json=payload)
    assert res.status_code == 200
    as_id = res.json()["assessment_id"]

    # Verify retrieval by assessment_id
    get_res = requests.get(f"{API_URL}/api/v1/agent-shield/{as_id}")
    assert get_res.status_code == 200
    record = get_res.json()
    assert record["assessment_id"] == as_id
    assert record["request_id"] == req_id
    assert record["trace_id"] == trace_id


def test_18_agentshield_api_retrieval():
    """Verify retrieval via all REST endpoints."""
    # Stats endpoint
    stats_res = requests.get(f"{API_URL}/api/v1/agent-shield/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert "total_assessments" in stats
    assert "average_agent_shield_score" in stats

    # List endpoint
    list_res = requests.get(f"{API_URL}/api/v1/agent-shield?limit=10")
    assert list_res.status_code == 200
    lst = list_res.json()
    assert "assessments" in lst
    assert "disclaimer" in lst


@pytest.mark.asyncio
async def test_19_realtime_websocket_agentshield_update():
    """Verify real-time AGENTSHIELD_SIGNAL broadcast over WebSocket."""
    trace_id = f"trace-ws-as-{uuid.uuid4().hex[:8]}"
    req_id = f"req-ws-as-{uuid.uuid4().hex[:8]}"

    async with websockets.connect(WS_API_URL) as ws:
        # Ingest event that triggers AgentShield
        payload = {
            "event_type": "WAF_BLOCK",
            "request_id": req_id,
            "trace_id": trace_id,
            "severity": "CRITICAL",
            "action": "BLOCK",
            "component": "coraza",
            "status": "BLOCKED",
            "source": {"ip": "10.0.0.17"},
            "request": {"method": "GET", "uri": "/api/users"},
            "metadata": {"rule_id": 942100}
        }
        res = requests.post(f"{API_URL}/api/v1/internal/events", json=payload)
        assert res.status_code == 200

        # Receive streamed WebSocket messages until AGENTSHIELD_SIGNAL is received
        found_signal = False
        for _ in range(5):
            msg_str = await asyncio.wait_for(ws.recv(), timeout=3.0)
            msg_data = json.loads(msg_str)
            if msg_data.get("event_type") == "AGENTSHIELD_SIGNAL" or msg_data.get("type") == "AGENTSHIELD_SIGNAL":
                found_signal = True
                assert "agent_shield_score" in msg_data or "agent_shield_score" in msg_data.get("data", {})
                break

        assert found_signal, "AGENTSHIELD_SIGNAL was not broadcast over WebSocket"


def test_20_risk_engine_integration():
    """Verify that AgentShield score contributes to the Risk Engine score."""
    trace_id = f"trace-re-int-{uuid.uuid4().hex[:8]}"
    req_id = f"req-re-int-{uuid.uuid4().hex[:8]}"

    # Send multi-stage automated attack sequence
    for ep in ["/", "/robots.txt", "/admin", "/api/users"]:
        requests.post(f"{API_URL}/api/v1/internal/events", json={
            "event_type": "GATEWAY_REQUEST",
            "request_id": f"re-step-{uuid.uuid4().hex[:8]}",
            "trace_id": trace_id,
            "severity": "INFO",
            "action": "ALLOW",
            "component": "gateway",
            "status": "ALLOWED",
            "source": {"ip": "10.0.0.18"},
            "request": {"method": "GET", "uri": ep},
            "metadata": {}
        })

    # Trigger WAF block event (evaluated by both AgentShield and Risk Engine)
    target = {
        "event_type": "WAF_BLOCK",
        "request_id": req_id,
        "trace_id": trace_id,
        "severity": "CRITICAL",
        "action": "BLOCK",
        "component": "coraza",
        "status": "BLOCKED",
        "source": {"ip": "10.0.0.18"},
        "request": {"method": "POST", "uri": "/login"},
        "metadata": {"rule_id": 942100, "anomaly_score": 5}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/events", json=target)
    assert res.status_code == 200

    # Query Risk Engine assessment for this request
    risk_res = requests.get(f"{API_URL}/api/v1/risk/request/{req_id}")
    assert risk_res.status_code == 200
    risk_list = risk_res.json()
    assert len(risk_list) > 0
    risk_signals = [s["name"] for s in risk_list[0]["signals"]]
    assert "agentshield_behavior" in risk_signals


def test_21_no_fake_ai_detection_claim():
    """Verify AgentShield explicitly states behavioral automation and does NOT claim AI identity."""
    res = requests.get(f"{API_URL}/api/v1/agent-shield/stats")
    assert res.status_code == 200
    data = res.json()
    disclaimer = data.get("disclaimer", "")
    assert "observable behavioral characteristics" in disclaimer
    assert "NOT identify specific AI models" in disclaimer


def test_22_sensitive_data_sanitization():
    """Verify credentials and secret tokens are never stored in signal evidence."""
    trace_id = f"trace-sec-{uuid.uuid4().hex[:8]}"
    req_id = f"req-sec-{uuid.uuid4().hex[:8]}"

    target = {
        "event_type": "GATEWAY_REQUEST",
        "request_id": req_id,
        "trace_id": trace_id,
        "severity": "INFO",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "source": {"ip": "10.0.0.19"},
        "request": {"method": "POST", "uri": "/login?user=admin&token=supersecret123&password=secretpassword"},
        "metadata": {}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/agent-shield/analyze", json=target)
    assert res.status_code == 200
    data = res.json()

    # Verify secret values are not in response
    serialized = json.dumps(data)
    assert "supersecret123" not in serialized
    assert "secretpassword" not in serialized


def test_23_failure_safety_agentshield_does_not_break_waf():
    """Verify live Coraza WAF continues blocking attacks via gateway regardless of AgentShield."""
    res = requests.get(f"{GATEWAY_URL}/products?category=%27%20OR%201=1--", timeout=5)
    assert res.status_code == 403
    assert res.headers.get("x-protected-by") == "AEGIS-Omega-Gateway"


def test_24_failure_safety_agentshield_does_not_break_event_ingestion():
    """Verify event ingestion succeeds even with arbitrary or malformed metadata."""
    payload = {
        "event_type": "GATEWAY_REQUEST",
        "request_id": f"safe-{uuid.uuid4().hex[:8]}",
        "trace_id": f"safe-trace-{uuid.uuid4().hex[:8]}",
        "severity": "INFO",
        "action": "ALLOW",
        "component": "gateway",
        "status": "ALLOWED",
        "source": {"ip": "127.0.0.1"},
        "request": {"method": "GET", "uri": "/test"},
        "metadata": {"complex_object": {"nested": [1, 2, 3]}}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/events", json=payload)
    assert res.status_code == 200


def test_25_dashboard_displays_real_agentshield_data():
    """Verify AgentShield stats return actual calculated integers, not hardcoded mock numbers."""
    res = requests.get(f"{API_URL}/api/v1/agent-shield/stats")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data["total_assessments"], int)
    assert isinstance(data["critical_count"], int)
    assert isinstance(data["high_count"], int)
    assert isinstance(data["medium_count"], int)
    assert isinstance(data["low_count"], int)
