import pytest
import requests
import json
import re

GATEWAY_URL = "http://localhost:8080"
API_URL = "http://localhost:8001"

def test_01_request_id_generated_when_missing():
    """Verify that Gateway generates a 32-character hex Request ID when none is provided by client."""
    res = requests.get(f"{GATEWAY_URL}/", timeout=5)
    assert res.status_code == 200
    assert "X-Request-ID" in res.headers
    req_id = res.headers["X-Request-ID"]
    # Default Nginx $request_id is a 32-character hexadecimal string
    assert re.match(r"^[a-f0-9]{32}$", req_id)
    # Origin must receive the exact same request ID
    data = res.json()
    assert data["request_id"] == req_id

def test_02_valid_request_id_preserved():
    """Verify that a valid client-supplied X-Request-ID is preserved and propagated."""
    custom_id = "audit-req-sec-987654321"
    headers = {"X-Request-ID": custom_id}
    res = requests.get(f"{GATEWAY_URL}/", headers=headers, timeout=5)
    assert res.status_code == 200
    assert res.headers.get("X-Request-ID") == custom_id
    data = res.json()
    assert data["request_id"] == custom_id

def test_03_malformed_request_id_sanitized():
    """Verify that a malformed or malicious X-Request-ID is rejected and replaced by a fresh Gateway ID."""
    malicious_id = "<script>alert('xss')</script>"
    headers = {"X-Request-ID": malicious_id}
    res = requests.get(f"{GATEWAY_URL}/", headers=headers, timeout=5)
    assert res.status_code == 200
    # Must NOT return or forward the malicious ID
    assert res.headers.get("X-Request-ID") != malicious_id
    # Must have generated a safe 32-character hex ID
    assert re.match(r"^[a-f0-9]{32}$", res.headers.get("X-Request-ID"))
    data = res.json()
    assert data["request_id"] != malicious_id
    assert data["request_id"] == res.headers.get("X-Request-ID")

def test_04_trace_id_generation_and_propagation():
    """Verify that X-Trace-ID is generated and propagated to origin."""
    res = requests.get(f"{GATEWAY_URL}/", timeout=5)
    assert res.status_code == 200
    assert "X-Trace-ID" in res.headers
    trace_id = res.headers["X-Trace-ID"]
    assert trace_id.startswith("trace-")
    data = res.json()
    assert data["trace_id"] == trace_id

def test_05_client_trace_id_preserved():
    """Verify that a valid client-supplied X-Trace-ID is safely preserved."""
    client_trace = "sec-trace-chain-alpha-001"
    headers = {"X-Trace-ID": client_trace}
    res = requests.get(f"{GATEWAY_URL}/", headers=headers, timeout=5)
    assert res.status_code == 200
    assert res.headers.get("X-Trace-ID") == client_trace
    data = res.json()
    assert data["trace_id"] == client_trace

def test_06_security_headers_present():
    """Verify that standard defensive security headers are injected by the Gateway."""
    res = requests.get(f"{GATEWAY_URL}/", timeout=5)
    assert res.status_code == 200
    headers = res.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert "strict-origin-when-cross-origin" in headers.get("Referrer-Policy", "")
    assert "geolocation=()" in headers.get("Permissions-Policy", "")
    assert "default-src 'self'" in headers.get("Content-Security-Policy", "")
    assert headers.get("X-Protected-By") == "AEGIS-Omega-Gateway"

def test_07_request_body_size_limit_enforced():
    """Verify that requests exceeding client_max_body_size (10MB) receive HTTP 413 JSON error."""
    # Send 11MB dummy payload
    oversized_payload = b"A" * (11 * 1024 * 1024)
    headers = {"Content-Type": "application/octet-stream"}
    res = requests.post(f"{GATEWAY_URL}/echo", data=oversized_payload, headers=headers, timeout=15)
    assert res.status_code == 413
    data = res.json()
    assert data["error"] == "Payload Too Large"
    assert data["status"] == 413
    assert "request_id" in data

def test_08_supported_http_methods():
    """Verify that Gateway supports and proxies standard HTTP methods: GET, POST, PUT, DELETE, OPTIONS, HEAD."""
    # 1. GET
    res_get = requests.get(f"{GATEWAY_URL}/products", timeout=5)
    assert res_get.status_code == 200
    assert res_get.json()["count"] >= 3

    # 2. POST
    test_body = {"probe": "health_check", "scanner": "test_suite"}
    res_post = requests.post(f"{GATEWAY_URL}/echo", json=test_body, timeout=5)
    assert res_post.status_code == 200
    post_data = res_post.json()
    assert post_data["method"] == "POST"
    assert post_data["received_payload"] == test_body

    # 3. PUT
    update_body = {"price": 549.0}
    res_put = requests.put(f"{GATEWAY_URL}/products/1", json=update_body, timeout=5)
    assert res_put.status_code == 200
    assert res_put.json()["method"] == "PUT"

    # 4. DELETE
    res_delete = requests.delete(f"{GATEWAY_URL}/products/1", timeout=5)
    assert res_delete.status_code == 200
    assert res_delete.json()["method"] == "DELETE"

    # 5. HEAD
    res_head = requests.head(f"{GATEWAY_URL}/", timeout=5)
    assert res_head.status_code == 200
    assert "X-Request-ID" in res_head.headers

    # 6. OPTIONS
    res_options = requests.options(f"{GATEWAY_URL}/", timeout=5)
    assert res_options.status_code in [200, 204]

def test_09_unsupported_http_method_rejected():
    """Verify that unsupported/arbitrary HTTP verbs receive controlled HTTP 405 JSON response."""
    res = requests.request("PURGE", f"{GATEWAY_URL}/", timeout=5)
    assert res.status_code == 405
    data = res.json()
    assert data["error"] == "Method Not Allowed"
    assert data["status"] == 405
    assert "request_id" in data

def test_10_gateway_health_independent():
    """Verify Gateway /healthz responds directly and independently without proxying upstream."""
    res = requests.get(f"{GATEWAY_URL}/healthz", timeout=5)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["service"] == "aegis-gateway"
    assert data["version"] in ["0.2.0", "0.3.0"]

def test_11_api_routing_and_tracing_functional():
    """Verify that /api/ routes continue to be cleanly proxied and traced."""
    res = requests.get(f"{GATEWAY_URL}/api/v1/system/status", timeout=5)
    assert res.status_code == 200
    data = res.json()
    assert data["platform"] == "AEGIS Ω"
    assert "X-Request-ID" in res.headers
    assert data["request_id"] == res.headers["X-Request-ID"]
    assert "trace_id" in data
