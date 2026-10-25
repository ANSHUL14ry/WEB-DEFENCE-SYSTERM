import pytest
import requests
import time
import re

GATEWAY_URL = "http://localhost:8080"
API_URL = "http://localhost:8001"

def test_01_waf_service_running_and_crs_loaded():
    """Verify that Coraza WAF is operational with OWASP CRS rules loaded."""
    res = requests.get(f"{GATEWAY_URL}/api/v1/waf/status", timeout=5)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "operational"
    assert "Coraza" in data["engine"]
    assert "OWASP CRS" in data["crs_version"]
    assert data["mode"] == "BLOCK"
    assert "REQUEST-942-APPLICATION-ATTACK-SQLI" in data["rulesets"]
    assert "REQUEST-941-APPLICATION-ATTACK-XSS" in data["rulesets"]
    assert "REQUEST-930-APPLICATION-ATTACK-LFI" in data["rulesets"]

def test_02_normal_request_allowed_to_origin():
    """Verify that clean, legitimate traffic is permitted through Coraza WAF to the Origin."""
    # Reset stats on origin
    requests.post(f"{GATEWAY_URL}/reset-stats", timeout=5)
    
    custom_id = "clean-req-audit-998811"
    headers = {"X-Request-ID": custom_id}
    res = requests.get(f"{GATEWAY_URL}/products", headers=headers, timeout=5)
    assert res.status_code == 200
    data = res.json()
    assert data["service"] == "origin"
    assert data["request_id"] == custom_id
    assert data["count"] >= 3

    # Check origin stats
    stats_res = requests.get(f"{GATEWAY_URL}/stats", timeout=5)
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_requests_received"] >= 1
    # Verify our request ID was logged at the origin
    origin_req_ids = [r["request_id"] for r in stats["recent_requests"]]
    assert custom_id in origin_req_ids

def test_03_sqli_attack_blocked_by_crs():
    """Verify that SQL Injection pattern triggers OWASP CRS rule and is BLOCKED with HTTP 403."""
    sqli_req_id = "sqli-attack-probe-001"
    headers = {"X-Request-ID": sqli_req_id}
    # Classic SQLi canary payload
    res = requests.get(f"{GATEWAY_URL}/products?id=%27%20OR%20%271%27=%271", headers=headers, timeout=5)
    
    assert res.status_code == 403
    assert res.headers.get("X-Protected-By") == "AEGIS-Omega-Gateway"
    assert res.headers.get("X-Request-ID") == sqli_req_id
    
    data = res.json()
    assert data["error"] == "request_blocked"
    assert data["status"] == 403
    assert data["request_id"] == sqli_req_id

def test_04_xss_attack_blocked_by_crs():
    """Verify that Cross-Site Scripting (XSS) pattern triggers OWASP CRS and is BLOCKED."""
    xss_req_id = "xss-attack-probe-002"
    headers = {"X-Request-ID": xss_req_id}
    res = requests.get(f"{GATEWAY_URL}/products?search=%3Cscript%3Ealert(document.domain)%3C/script%3E", headers=headers, timeout=5)
    
    assert res.status_code == 403
    data = res.json()
    assert data["error"] == "request_blocked"
    assert data["status"] == 403
    assert data["request_id"] == xss_req_id

def test_05_path_traversal_attack_blocked_by_crs():
    """Verify that Path Traversal (LFI) pattern triggers OWASP CRS and is BLOCKED."""
    lfi_req_id = "lfi-attack-probe-003"
    headers = {"X-Request-ID": lfi_req_id}
    res = requests.get(f"{GATEWAY_URL}/products?file=../../../../etc/passwd", headers=headers, timeout=5)
    
    assert res.status_code == 403
    data = res.json()
    assert data["error"] == "request_blocked"
    assert data["status"] == 403
    assert data["request_id"] == lfi_req_id

def test_06_origin_protection_verified():
    """CRITICAL: Verify that the origin server NEVER received any of the blocked attack requests."""
    stats_res = requests.get(f"{GATEWAY_URL}/stats", timeout=5)
    assert stats_res.status_code == 200
    stats = stats_res.json()
    origin_req_ids = [r["request_id"] for r in stats["recent_requests"]]
    
    # None of the malicious request IDs must have reached origin
    assert "sqli-attack-probe-001" not in origin_req_ids
    assert "xss-attack-probe-002" not in origin_req_ids
    assert "lfi-attack-probe-003" not in origin_req_ids

def test_07_waf_event_persisted_in_database():
    """Verify that Coraza WAF security events were ingested and persisted into PostgreSQL."""
    # Allow background log watcher up to 2 seconds to ingest
    time.sleep(1.5)
    
    res = requests.get(f"{GATEWAY_URL}/api/v1/waf/events", timeout=5)
    assert res.status_code == 200
    events = res.json()
    assert len(events) >= 1
    
    # Check that events have normalized security schema
    sample = events[0]
    assert "request_id" in sample
    assert "trace_id" in sample
    assert sample["action"] in ["BLOCK", "DETECT"]
    assert sample["engine"] == "coraza-v3"
    assert sample["rule_id"] > 0
    assert "rule_message" in sample

def test_08_public_response_does_not_leak_internals():
    """Verify that 403 error response does not expose internal paths, CRS rule IDs, or Docker addresses."""
    res = requests.get(f"{GATEWAY_URL}/products?id=%27%20OR%201=1--", timeout=5)
    assert res.status_code == 403
    text = res.text
    # Must NOT reveal internal rule paths
    assert "/opt/coraza" not in text
    assert "REQUEST-942" not in text
    assert "172.18." not in text
    assert "caddy" not in text.lower()
    # Must be valid clean JSON
    data = res.json()
    assert data["error"] == "request_blocked"
    assert "message" in data

def test_09_internal_event_ingestion_api():
    """Verify internal WAF event ingestion endpoint accepts and stores security telemetry."""
    test_event = {
        "request_id": "test-manual-ingest-001",
        "trace_id": "trace-test-manual-ingest-001",
        "action": "BLOCK",
        "severity_label": "HIGH",
        "rule_id": 942100,
        "rule_tag": "attack-sqli",
        "rule_message": "Manual test injection detection",
        "severity": 2,
        "engine": "coraza-v3",
        "http_method": "POST",
        "uri": "/login",
        "client_ip": "127.0.0.1",
        "anomaly_score": 5,
        "raw_details": {"canary": True}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/waf/events", json=test_event, timeout=5)
    assert res.status_code == 201
    assert res.json()["status"] == "persisted"
    assert res.json()["request_id"] == "test-manual-ingest-001"
