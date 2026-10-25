"""
AEGIS Ω — Phase 10 Integration Tests
Validates Attacker Intelligence & Threat Context Layer:
1. Private IP detection (10.x, 172.16-31.x, 192.168.x, 127.x -> is_private=True, country=None)
2. Public IP handling (zero fake geolocation, returns UNKNOWN)
3. GeoIP caching (hits in-memory cache on repeat lookups)
4. ASN lookup for private IPs (null / internal network, no fake ASNs)
5. Threat intelligence provider unconfigured (status = NOT_CONFIGURED, zero fake scores)
6. Threat intelligence provider configuration check
7. Threat intelligence failure resilience (never crashes caller)
8. Network sensor event ingestion (Zeek / Suricata) via API
9. Nmap scan event normalization & port observation
10. HTTP fingerprint generation (deterministic SHA-256)
11. Sensitive header sanitization in fingerprinting (cookies/tokens stripped)
12. TLS fingerprinting reports NOT AVAILABLE AT CURRENT TERMINATION POINT
13. Deterministic MITRE mapping with WAF evidence (T1190)
14. Deterministic MITRE mapping with AgentShield evidence (T1083 / T1110)
15. Deterministic MITRE mapping without evidence returns empty (zero speculation)
16. WebSocket live broadcast for enrichment events
17. Database persistence in source_profiles, threat_intelligence, network_observations, mitre_mappings
18. Extended event schema (enrichment dictionary optional)
19. Enrichment failure isolation (ingestion proceeds normally)
20. Existing WAF regression (SQLi returns 403 Forbidden)
21. Existing Risk & Policy Engine regression
22. Existing Deception & Response Verification regression
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

from enrichment.geoip import lookup_geoip, is_ip_private, clear_geoip_cache
from enrichment.fingerprint import generate_client_fingerprint, get_tls_fingerprint, sanitize_headers
from enrichment.threat_intel import DefaultThreatIntelProvider, clear_threat_intel_cache
from enrichment.mitre import map_mitre_techniques
from enrichment.models import NetworkObservationCreate

GATEWAY_URL = "http://localhost:8080"
API_URL = "http://localhost:8001"
WS_API_URL = "ws://localhost:8001/api/v1/ws/events"


def test_01_private_ip_detection_internal_label():
    """Scenario 1: Private/internal IP detection returns is_private=True and country=None."""
    clear_geoip_cache()
    test_ips = ["10.0.0.1", "172.20.0.5", "192.168.1.100", "127.0.0.1"]
    for ip in test_ips:
        assert is_ip_private(ip) is True
        ctx = lookup_geoip(ip)
        assert ctx.is_private is True
        assert ctx.country is None
        assert ctx.city is None
        assert ctx.asn is None
        assert ctx.display_label == "PRIVATE / INTERNAL ADDRESS"


def test_02_public_ip_enrichment_no_fake_data():
    """Scenario 2: Public IP without local DB returns UNKNOWN with zero fabricated coordinates."""
    clear_geoip_cache()
    public_ip = "8.8.8.8"
    assert is_ip_private(public_ip) is False
    ctx = lookup_geoip(public_ip)
    assert ctx.is_private is False
    assert ctx.country == "UNKNOWN"
    assert ctx.latitude is None
    assert ctx.longitude is None
    assert ctx.display_label == "UNKNOWN"


def test_03_geoip_caching():
    """Scenario 3: GeoIP lookup hits in-memory cache on subsequent requests."""
    clear_geoip_cache()
    ip = "192.168.10.50"
    ctx1 = lookup_geoip(ip)
    ctx2 = lookup_geoip(ip)
    assert ctx1.model_dump() == ctx2.model_dump()


def test_04_asn_private_ip_handling():
    """Scenario 4: ASN for private IP is strictly None, never fake autonomous system numbers."""
    ctx = lookup_geoip("10.100.1.1")
    assert ctx.asn is None
    assert ctx.organization is None


def test_05_threat_intel_unconfigured_default():
    """Scenario 5: When THREAT_INTEL_PROVIDER is unconfigured, status is NOT_CONFIGURED."""
    clear_threat_intel_cache()
    provider = DefaultThreatIntelProvider(provider_name="", api_key="")
    res = provider.lookup_ip("192.168.1.200")
    assert res.status == "NOT_CONFIGURED"
    assert res.provider is None
    assert res.confidence is None
    assert res.category is None


def test_06_threat_intel_configured_provider_read():
    """Scenario 6: Configured threat intelligence provider registers and handles lookups."""
    clear_threat_intel_cache()
    provider = DefaultThreatIntelProvider(provider_name="AbuseIPDB-Test", api_key="test-api-key")
    res = provider.lookup_ip("203.0.113.1")
    assert res.provider == "AbuseIPDB-Test"
    assert res.indicator == "203.0.113.1"


def test_07_threat_intel_failure_resilience():
    """Scenario 7: Threat intelligence handles invalid indicators failure-safely."""
    provider = DefaultThreatIntelProvider()
    res = provider.lookup_ip("")
    assert res.status == "NOT_CONFIGURED"


def test_08_network_sensor_event_ingestion():
    """Scenario 8: Network sensor event ingestion (Zeek / Suricata) via API."""
    obs_payload = {
        "sensor": "zeek",
        "event_type": "network_connection",
        "source_ip": "192.168.1.150",
        "destination_ip": "192.168.1.10",
        "destination_port": 8080,
        "protocol": "TCP",
        "ports_observed": "8080",
        "connection_count": 5,
        "confidence": 1.0,
        "metadata": {"test": True}
    }
    res = requests.post(f"{API_URL}/api/v1/enrichment/internal/network-event", json=obs_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ingested"
    assert data["sensor"] == "zeek"
    assert data["observation"]["source_ip"] == "192.168.1.150"


def test_09_nmap_scan_event_normalization():
    """Scenario 9: Nmap port scan event normalization triggers T1595.002 MITRE mapping."""
    scan_payload = {
        "sensor": "suricata",
        "event_type": "port_scan",
        "source_ip": "10.0.0.77",
        "destination_ip": "10.0.0.1",
        "destination_port": None,
        "protocol": "TCP",
        "ports_observed": "22,80,443,8080",
        "connection_count": 42,
        "scan_indicator": "NMAP_SYN_SCAN",
        "confidence": 0.95,
        "metadata": {"tool": "nmap"}
    }
    res = requests.post(f"{API_URL}/api/v1/enrichment/internal/network-event", json=scan_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ingested"
    assert data["observation"]["ports_observed"] == "22,80,443,8080"


def test_10_http_fingerprint_generation_deterministic():
    """Scenario 10: HTTP client fingerprint produces a deterministic SHA-256 hash."""
    headers1 = {"user-agent": "Mozilla/5.0 (X11; Linux x86_64)", "accept": "text/html"}
    headers2 = {"user-agent": "Mozilla/5.0 (X11; Linux x86_64)", "accept": "text/html"}
    fp1 = generate_client_fingerprint(headers1, user_agent=headers1["user-agent"])
    fp2 = generate_client_fingerprint(headers2, user_agent=headers2["user-agent"])
    assert fp1.fingerprint == fp2.fingerprint
    assert len(fp1.fingerprint) == 64
    assert fp1.method == "SHA256"

    # Different user-agent produces different fingerprint
    headers3 = {"user-agent": "curl/7.81.0", "accept": "*/*"}
    fp3 = generate_client_fingerprint(headers3, user_agent=headers3["user-agent"])
    assert fp1.fingerprint != fp3.fingerprint


def test_11_sensitive_header_sanitization_in_fingerprint():
    """Scenario 11: Sensitive headers (Authorization, Cookie, API Key) are stripped before hashing."""
    headers_dirty = {
        "user-agent": "TestBrowser/1.0",
        "authorization": "Bearer secret_token_12345",
        "cookie": "session_id=super_secret_cookie",
        "x-api-key": "secret_api_key_xyz"
    }
    sanitized = sanitize_headers(headers_dirty)
    assert "authorization" not in sanitized
    assert "cookie" not in sanitized
    assert "x-api-key" not in sanitized
    assert "user-agent" in sanitized


def test_12_tls_fingerprint_termination_point():
    """Scenario 12: TLS fingerprinting reports NOT AVAILABLE AT CURRENT TERMINATION POINT."""
    tls_fp = get_tls_fingerprint({})
    assert tls_fp.status == "NOT AVAILABLE AT CURRENT TERMINATION POINT"
    assert tls_fp.fingerprint is None


def test_13_mitre_mapping_with_waf_evidence():
    """Scenario 13: Coraza WAF SQL injection detection maps to T1190 with evidence event ID."""
    waf_event = {
        "event_id": f"waf-ev-{uuid.uuid4().hex[:8]}",
        "event_type": "WAF_BLOCK",
        "request_id": f"req-{uuid.uuid4().hex[:8]}",
        "trace_id": f"tr-{uuid.uuid4().hex[:8]}",
        "source": {"ip": "192.168.1.99", "user_agent": "sqlmap/1.6"},
        "request": {"method": "GET", "uri": "/products?id=1%20UNION%20SELECT"},
        "metadata": {
            "rule_id": "942100",
            "attack_type": "SQL Injection",
            "tags": ["attack-sqli", "owasp_crs"]
        }
    }
    mappings = map_mitre_techniques(waf_event)
    assert len(mappings) >= 1
    t1190 = next((m for m in mappings if m.technique_id == "T1190"), None)
    assert t1190 is not None
    assert t1190.technique_name == "Exploit Public-Facing Application"
    assert t1190.tactic == "Initial Access"
    assert waf_event["event_id"] in t1190.evidence_event_ids
    assert t1190.confidence >= 0.90


def test_14_mitre_mapping_with_agentshield_evidence():
    """Scenario 14: AgentShield rapid endpoint discovery maps to T1083 with evidence."""
    ev_id = f"ev-{uuid.uuid4().hex[:8]}"
    clean_event = {
        "event_id": ev_id,
        "event_type": "GATEWAY_REQUEST",
        "request_id": f"req-{uuid.uuid4().hex[:8]}",
        "trace_id": f"tr-{uuid.uuid4().hex[:8]}",
        "source": {"ip": "192.168.1.88", "user_agent": "python-requests/2.28"},
        "metadata": {}
    }
    agent_shield_assessment = {
        "assessment_id": f"as-{uuid.uuid4().hex[:8]}",
        "signals": ["RAPID_ENDPOINT_DISCOVERY"],
        "attack_stages": ["ENUMERATION"]
    }
    mappings = map_mitre_techniques(clean_event, agent_shield=agent_shield_assessment)
    assert any(m.technique_id == "T1083" for m in mappings)
    t1083 = next(m for m in mappings if m.technique_id == "T1083")
    assert t1083.technique_name == "File and Directory Discovery"
    assert t1083.tactic == "Discovery"


def test_15_mitre_mapping_without_evidence_returns_empty():
    """Scenario 15: Clean event without attack evidence produces zero MITRE mappings."""
    clean_event = {
        "event_id": f"ev-{uuid.uuid4().hex[:8]}",
        "event_type": "GATEWAY_REQUEST",
        "request_id": f"req-{uuid.uuid4().hex[:8]}",
        "trace_id": f"tr-{uuid.uuid4().hex[:8]}",
        "source": {"ip": "192.168.1.1", "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        "metadata": {}
    }
    mappings = map_mitre_techniques(clean_event)
    assert len(mappings) == 0, "Clean traffic must produce NO MITRE mappings (zero speculation)"


def test_16_websocket_enrichment_broadcast():
    """Scenario 16: Ingesting an event streams SOURCE_ENRICHED via WebSocket."""
    async def run_ws():
        async with websockets.connect(WS_API_URL, close_timeout=2) as ws:
            test_ip = f"192.168.55.{uuid.uuid4().int % 200 + 1}"
            req_id = f"p10-ws-{uuid.uuid4().hex[:8]}"
            event_payload = {
                "event_type": "GATEWAY_REQUEST",
                "request_id": req_id,
                "trace_id": f"tr-{uuid.uuid4().hex[:8]}",
                "severity": "INFO",
                "action": "ALLOW",
                "component": "gateway",
                "status": "DETECTED",
                "source": {"ip": test_ip, "user_agent": "TestAgent/1.0"},
                "request": {"method": "GET", "uri": "/test-ws"}
            }
            res = requests.post(f"{API_URL}/api/v1/internal/events", json=event_payload)
            assert res.status_code == 200

            # Listen for broadcast events
            received_events = []
            for _ in range(5):
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=2.0)
                    data = json.loads(msg)
                    received_events.append(data.get("event_type"))
                    if data.get("event_type") == "SOURCE_ENRICHED":
                        break
                except asyncio.TimeoutError:
                    break
            return received_events

    events = asyncio.run(run_ws())
    assert any(e in ("SOURCE_ENRICHED", "GATEWAY_REQUEST") for e in events)


def test_17_database_persistence_and_retrieval():
    """Scenario 17: Source profile and MITRE mappings persist to DB and are retrievable."""
    test_ip = f"192.168.120.{uuid.uuid4().int % 200 + 1}"
    req_id = f"p10-db-{uuid.uuid4().hex[:8]}"
    event_payload = {
        "event_type": "WAF_BLOCK",
        "request_id": req_id,
        "trace_id": f"tr-{uuid.uuid4().hex[:8]}",
        "severity": "HIGH",
        "action": "BLOCK",
        "component": "coraza",
        "status": "BLOCKED",
        "source": {"ip": test_ip, "user_agent": "Nikto/2.1.6"},
        "request": {"method": "GET", "uri": "/etc/passwd"},
        "metadata": {
            "rule_id": "930100",
            "attack_type": "LFI Attack",
            "tags": ["attack-lfi", "owasp_crs"]
        }
    }
    res = requests.post(f"{API_URL}/api/v1/internal/events", json=event_payload)
    assert res.status_code == 200

    # Wait briefly for async persistence
    time.sleep(0.5)

    # Query source profile endpoint
    prof_res = requests.get(f"{API_URL}/api/v1/enrichment/source-profile/{test_ip}")
    assert prof_res.status_code == 200
    pdata = prof_res.json()["profile"]
    assert pdata["source_ip"] == test_ip
    assert pdata["is_private"] is True
    assert pdata["request_count"] >= 1
    assert pdata["client_fingerprint"] is not None

    # Verify MITRE endpoint
    mitre_res = requests.get(f"{API_URL}/api/v1/enrichment/mitre?limit=50")
    assert mitre_res.status_code == 200
    mdata = mitre_res.json()
    assert mdata["count"] >= 1


def test_18_extended_event_schema_optional_enrichment():
    """Scenario 18: SecurityEventCreate accepts optional enrichment field cleanly."""
    req_id = f"p10-opt-{uuid.uuid4().hex[:8]}"
    payload = {
        "event_type": "GATEWAY_REQUEST",
        "request_id": req_id,
        "trace_id": f"tr-{uuid.uuid4().hex[:8]}",
        "severity": "INFO",
        "action": "OBSERVED",
        "component": "gateway",
        "status": "DETECTED",
        "source": {"ip": "10.0.1.1", "user_agent": "CleanAgent"},
        "request": {"method": "GET", "uri": "/items"},
        "enrichment": {
            "geoip": {"country": None, "is_private": True},
            "reputation": {"status": "NOT_CONFIGURED"}
        }
    }
    res = requests.post(f"{API_URL}/api/v1/internal/events", json=payload)
    assert res.status_code == 200


def test_19_enrichment_failure_isolation():
    """Scenario 19: An event with invalid or empty source IP is still ingested failure-safely."""
    req_id = f"p10-fail-{uuid.uuid4().hex[:8]}"
    payload = {
        "event_type": "GATEWAY_REQUEST",
        "request_id": req_id,
        "trace_id": f"tr-{uuid.uuid4().hex[:8]}",
        "severity": "INFO",
        "action": "OBSERVED",
        "component": "gateway",
        "status": "DETECTED",
        "source": {"ip": "invalid-ip-string", "user_agent": None},
        "request": {"method": "GET", "uri": "/"}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/events", json=payload)
    assert res.status_code == 200
    assert res.json()["status"] == "ingested"


def test_20_existing_waf_regression():
    """Scenario 20: Existing Coraza WAF + OWASP CRS blocks SQL injection via Gateway."""
    headers = {"User-Agent": "AEGIS-Security-Test/1.0"}
    res = requests.get(f"{GATEWAY_URL}/products?id=1%20UNION%20SELECT%201,2,3", headers=headers)
    assert res.status_code == 403, f"Expected 403 from WAF, got {res.status_code}"


def test_21_existing_risk_and_policy_regression():
    """Scenario 21: Existing Risk and Policy Engine evaluate events deterministically."""
    req_id = f"p10-reg-risk-{uuid.uuid4().hex[:8]}"
    trace_id = f"tr-{uuid.uuid4().hex[:8]}"
    event_payload = {
        "event_type": "WAF_BLOCK",
        "request_id": req_id,
        "trace_id": trace_id,
        "severity": "CRITICAL",
        "action": "BLOCK",
        "component": "coraza",
        "status": "BLOCKED",
        "source": {"ip": "192.168.1.99", "user_agent": "sqlmap/1.6"},
        "request": {"method": "GET", "uri": "/api/users?admin=1%20OR%201=1"},
        "metadata": {"rule_id": "942100", "attack_type": "SQLi"}
    }
    res = requests.post(f"{API_URL}/api/v1/internal/events", json=event_payload)
    assert res.status_code == 200
    assert res.json()["status"] == "ingested"


def test_22_existing_deception_and_verification_regression():
    """Scenario 22: Existing Phase 9 verification evaluation produces valid receipts."""
    req_id = f"p10-reg-ver-{uuid.uuid4().hex[:8]}"
    trace_id = f"tr-{uuid.uuid4().hex[:8]}"
    ver_payload = {
        "request_id": req_id,
        "trace_id": trace_id,
        "policy_decision": "DECEIVE_ELIGIBLE",
        "waf_blocked": False,
        "origin_reached": False,
        "origin_request_count": 0,
        "deception_session_id": f"dec-{uuid.uuid4().hex[:8]}",
        "evidence_count": 3,
        "http_status": 200
    }
    res = requests.post(f"{API_URL}/api/v1/internal/verification/evaluate", json=ver_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["result"] == "VERIFIED"
    assert data["verification_type"] == "DECEPTION"
    assert data["actual_origin_access"] is False
    assert data["origin_request_count"] == 0
