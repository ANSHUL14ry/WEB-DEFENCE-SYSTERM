"""
AEGIS Ω — Source IP Preservation & Anti-Spoofing Integration Tests
Validates:
1. Direct client IP extraction at AEGIS Ingress Gateway boundary
2. Anti-spoofing: Malicious X-Forwarded-For header rejected and overwritten
3. Anti-spoofing: Malicious X-Real-IP header rejected and overwritten
4. WAF blocked SQLi attack preserves client IP, blocks with 403, and isolates origin
5. Normal request preserves client IP and reaches origin
6. Zero-Container-Leak: WAF event source.ip never leaks internal container IP (172.18.0.7)
"""

import time
import uuid
import pytest
import requests

GATEWAY_URL = "http://localhost:8080"
API_URL = "http://localhost:8001"
ORIGIN_URL = "http://localhost:8088"


def test_01_malicious_x_forwarded_for_spoofing_rejected():
    """
    Test B: An attacker supplying 'X-Forwarded-For: 1.2.3.4' must NOT cause AEGIS
    to record 1.2.3.4 as the real attacker. Ingress Gateway must overwrite it.
    """
    attack_req_id = f"spoof-xff-{uuid.uuid4().hex[:10]}"
    spoofed_ip = "1.2.3.4"
    headers = {
        "X-Request-ID": attack_req_id,
        "X-Forwarded-For": spoofed_ip,
        "User-Agent": "Aegis-Spoof-Tester/1.0"
    }

    # Send controlled attack through public gateway
    res = requests.get(
        f"{GATEWAY_URL}/products?search=%27%20OR%201=1--",
        headers=headers,
        timeout=5
    )
    assert res.status_code == 403, f"Expected 403 from WAF, got {res.status_code}"

    # Allow watcher window to ingest audit log
    time.sleep(1.5)

    # Fetch correlated security event from pipeline
    correl_res = requests.get(f"{API_URL}/api/v1/events/request/{attack_req_id}")
    assert correl_res.status_code == 200
    events = correl_res.json()
    assert len(events) >= 1, f"Expected correlated security event for {attack_req_id}"

    event = events[0]
    recorded_ip = event["source"]["ip"]

    # Critical Assertion: Spoofed IP must NEVER be recorded
    assert recorded_ip != spoofed_ip, (
        f"CRITICAL VULNERABILITY: Attacker spoofed IP '{spoofed_ip}' was accepted as source.ip!"
    )
    # Critical Assertion: Internal gateway container IP (172.18.0.7) must NOT be recorded
    assert recorded_ip != "172.18.0.7", (
        "Internal gateway container IP 172.18.0.7 was erroneously recorded as source.ip!"
    )
    assert event["action"] == "BLOCK"
    assert event["component"] == "coraza"


def test_02_malicious_x_real_ip_spoofing_rejected():
    """
    Test C: An attacker supplying 'X-Real-IP: 5.6.7.8' must NOT cause AEGIS
    to record 5.6.7.8 as the real attacker. Ingress Gateway must overwrite it.
    """
    attack_req_id = f"spoof-xrip-{uuid.uuid4().hex[:10]}"
    spoofed_ip = "5.6.7.8"
    headers = {
        "X-Request-ID": attack_req_id,
        "X-Real-IP": spoofed_ip,
        "User-Agent": "Aegis-Spoof-Tester/1.0"
    }

    # Send controlled attack through public gateway
    res = requests.get(
        f"{GATEWAY_URL}/products?search=%27%20OR%201=1--",
        headers=headers,
        timeout=5
    )
    assert res.status_code == 403

    time.sleep(1.5)

    correl_res = requests.get(f"{API_URL}/api/v1/events/request/{attack_req_id}")
    assert correl_res.status_code == 200
    events = correl_res.json()
    assert len(events) >= 1

    event = events[0]
    recorded_ip = event["source"]["ip"]

    # Critical Assertion: Spoofed IP must NEVER be recorded
    assert recorded_ip != spoofed_ip, (
        f"CRITICAL VULNERABILITY: Attacker spoofed IP '{spoofed_ip}' was accepted as source.ip!"
    )
    assert recorded_ip != "172.18.0.7"
    assert event["action"] == "BLOCK"


def test_03_waf_blocked_sqli_preserves_client_ip_and_isolates_origin():
    """
    Test D: WAF blocked SQLi attack records real client IP, blocks with 403,
    and guarantees origin was never touched.
    """
    stats_before = requests.get(f"{ORIGIN_URL}/stats").json()["total_requests_received"]
    attack_req_id = f"sqli-block-{uuid.uuid4().hex[:10]}"

    headers = {"X-Request-ID": attack_req_id}
    res = requests.get(
        f"{GATEWAY_URL}/products?search=%27%20OR%201=1--",
        headers=headers,
        timeout=5
    )
    assert res.status_code == 403
    assert res.headers.get("X-Protected-By") == "AEGIS-Omega-Gateway"

    time.sleep(1.5)

    # Verify Origin isolation
    stats_after = requests.get(f"{ORIGIN_URL}/stats").json()["total_requests_received"]
    recent_requests = requests.get(f"{ORIGIN_URL}/stats").json().get("recent_requests", [])
    recent_ids = [r["request_id"] for r in recent_requests]

    assert attack_req_id not in recent_ids, "Attack request reached Origin!"
    assert stats_after == stats_before, "Origin request count increased during attack!"

    # Verify WAF telemetry
    correl_res = requests.get(f"{API_URL}/api/v1/events/request/{attack_req_id}")
    assert correl_res.status_code == 200
    events = correl_res.json()
    assert len(events) >= 1

    ev = events[0]
    assert ev["action"] == "BLOCK"
    assert ev["status"] == "BLOCKED"
    assert ev["component"] == "coraza"
    assert ev["metadata"]["rule_id"] == 942100
    assert ev["source"]["ip"] != "172.18.0.7", "Leaked gateway container IP as client IP!"


def test_04_normal_request_flow_reaches_origin():
    """
    Test E: Normal legitimate request through AEGIS Gateway passes to ApexMart origin
    and preserves correlation headers.
    """
    legit_req_id = f"norm-flow-{uuid.uuid4().hex[:10]}"
    headers = {"X-Request-ID": legit_req_id}

    res = requests.get(f"{GATEWAY_URL}/products", headers=headers, timeout=5)
    assert res.status_code == 200
    assert res.headers.get("X-Protected-By") == "AEGIS-Omega-Gateway"
    assert res.headers.get("X-Request-ID") == legit_req_id

    data = res.json()
    assert data["service"] == "origin"
    assert data["count"] == 32


def test_05_unknown_ip_fallback():
    """
    Test F: When client IP is truly unavailable or only internal container socket IP
    is present without trusted ingress headers, parser returns UNKNOWN.
    """
    import sys
    import os
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../services/api")))
    from waf_log_watcher import resolve_trusted_client_ip

    # Case 1: Only internal docker container IP present in tx['client_ip'], no headers
    tx_container_only = {"client_ip": "172.18.0.7"}
    headers_empty = {}
    resolved = resolve_trusted_client_ip(tx_container_only, headers_empty)
    assert resolved == "UNKNOWN", f"Expected 'UNKNOWN' for internal container IP, got '{resolved}'"

    # Case 2: Ingress header present with real LAN IP
    tx_normal = {"client_ip": "172.18.0.7"}
    headers_with_ingress = {
        "x-original-client-ip": ["192.168.30.215"],
        "x-real-ip": ["192.168.30.215"]
    }
    resolved_real = resolve_trusted_client_ip(tx_normal, headers_with_ingress)
    assert resolved_real == "192.168.30.215"
