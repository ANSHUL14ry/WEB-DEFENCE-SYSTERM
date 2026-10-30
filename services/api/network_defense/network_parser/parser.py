"""
AEGIS Ω — Suricata EVE JSON & Sensor Telemetry Normalization Parser (Phase 11)
Validates provenance, sanitizes sensitive credentials, and normalizes into AEGIS event taxonomy.
"""

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import logging
from typing import Dict, Any, Optional
from network_defense.models import NormalizedNetworkEvent

logger = logging.getLogger("aegis.network_defense.parser")

SENSITIVE_PATTERNS = {"password", "token", "secret", "cookie", "authorization", "key", "api_key"}


def is_valid_ip(ip_str: Optional[str]) -> bool:
    """Verify string is a valid IPv4 or IPv6 address."""
    if not ip_str:
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def sanitize_network_payload(data: Any) -> Any:
    """Recursively redact sensitive tokens from raw network payloads and headers."""
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if str(k).lower() in SENSITIVE_PATTERNS:
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = sanitize_network_payload(v)
        return cleaned
    elif isinstance(data, list):
        return [sanitize_network_payload(item) for item in data]
    return data


def map_suricata_severity(raw_severity: Any, alert_obj: Optional[Dict[str, Any]] = None) -> str:
    """
    Map Suricata alert severity integer (1=high, 2=med, 3=low, 4=info)
    or custom tag to AEGIS CRITICAL/HIGH/MEDIUM/LOW/INFO taxonomy.
    """
    try:
        val = int(raw_severity)
        if val == 1:
            sig = str(alert_obj.get("signature", "")).lower() if alert_obj else ""
            if any(term in sig for term in ("exploit", "cve", "sql injection", "rce", "dos")):
                return "CRITICAL"
            return "HIGH"
        elif val == 2:
            return "MEDIUM"
        elif val == 3:
            return "LOW"
        elif val == 4:
            return "INFO"
    except (ValueError, TypeError):
        pass

    raw_str = str(raw_severity).strip().upper()
    if raw_str in ("CRITICAL", "1"):
        return "CRITICAL"
    elif raw_str in ("HIGH", "2"):
        return "HIGH"
    elif raw_str in ("MEDIUM", "3"):
        return "MEDIUM"
    elif raw_str in ("LOW", "4"):
        return "LOW"
    return "INFO"


def parse_eve_record(eve_data: Dict[str, Any], sensor_name: str = "suricata") -> Optional[NormalizedNetworkEvent]:
    """
    Parse a raw Suricata EVE JSON dictionary into a typed, normalized AEGIS network event.
    Rejects malformed records without valid IPs.
    """
    if not isinstance(eve_data, dict):
        return None

    src_ip = eve_data.get("src_ip")
    if not is_valid_ip(src_ip):
        logger.debug(f"Rejected EVE record with invalid src_ip: {src_ip}")
        return None

    dest_ip = eve_data.get("dest_ip")
    src_port = eve_data.get("src_port")
    dest_port = eve_data.get("dest_port")
    proto = str(eve_data.get("proto", "TCP")).upper()
    raw_event_type = str(eve_data.get("event_type", "alert")).lower()

    # Timestamp
    raw_ts = eve_data.get("timestamp")
    if raw_ts:
        try:
            ts_str = str(raw_ts)
        except Exception:
            ts_str = datetime.now(timezone.utc).isoformat()
    else:
        ts_str = datetime.now(timezone.utc).isoformat()

    # Alert details
    alert_obj = eve_data.get("alert") or {}
    signature = alert_obj.get("signature") or eve_data.get("signature")
    signature_id = alert_obj.get("signature_id") or eve_data.get("signature_id")
    category = alert_obj.get("category") or eve_data.get("category")
    raw_sev = alert_obj.get("severity") or eve_data.get("severity") or ("MEDIUM" if raw_event_type == "anomaly" else "INFO")
    severity = map_suricata_severity(raw_sev, alert_obj)

    # Correlation IDs (from HTTP metadata if present)
    http_meta = eve_data.get("http") or {}
    req_id = (
        http_meta.get("http_headers", {}).get("x-request-id") or
        eve_data.get("request_id")
    )
    trace_id = (
        http_meta.get("http_headers", {}).get("x-trace-id") or
        eve_data.get("trace_id")
    )

    # Deterministic event_id
    flow_id = eve_data.get("flow_id", "")
    pcap_cnt = eve_data.get("pcap_cnt", "")
    mitre_tech_id = None
    if signature:
        try:
            from enrichment.mitre import map_mitre_techniques
            m = map_mitre_techniques(waf_rule_id=None, agentshield_stages=[], network_signature=signature)
            if m:
                mitre_tech_id = m[0].technique_id
        except Exception:
            pass

    sig_hash = hashlib.sha256(f"{src_ip}:{dest_ip}:{raw_event_type}:{flow_id}:{pcap_cnt}:{ts_str}".encode()).hexdigest()[:32]
    event_id = f"netev-{sig_hash}"

    sanitized_metadata = sanitize_network_payload(eve_data)

    return NormalizedNetworkEvent(
        event_id=event_id,
        sensor=sensor_name,
        sensor_event_id=str(flow_id) if flow_id else event_id,
        event_type=raw_event_type,
        source_ip=src_ip.strip(),
        destination_ip=dest_ip.strip() if dest_ip else None,
        source_port=int(src_port) if src_port is not None else None,
        destination_port=int(dest_port) if dest_port is not None else None,
        protocol=proto,
        severity=severity,
        signature=signature,
        signature_id=int(signature_id) if signature_id is not None else None,
        category=category,
        raw_reference=f"sid:{signature_id}" if signature_id else (category or raw_event_type),
        request_id=str(req_id) if req_id else None,
        trace_id=str(trace_id) if trace_id else None,
        network_risk_score=0,
        mitre_technique_id=mitre_tech_id,
        enforcement_action="OBSERVE",
        raw_metadata=sanitized_metadata,
        timestamp=ts_str,
        created_at=datetime.now(timezone.utc).isoformat()
    )



def parse_suricata_eve_line(line: str, sensor_name: str = "suricata") -> Optional[NormalizedNetworkEvent]:
    """Parse a single JSON-encoded line from Suricata eve.json into a NormalizedNetworkEvent."""
    if not line or not isinstance(line, str):
        return None
    try:
        data = json.loads(line.strip())
        return parse_eve_record(data, sensor_name=sensor_name)
    except Exception:
        return None

normalize_network_event = parse_eve_record
