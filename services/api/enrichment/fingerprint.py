"""
Deterministic HTTP client fingerprinting and TLS inspection reporter.
Sanitizes sensitive headers (cookies, auth tokens, secrets) before hashing.
Reports 'NOT AVAILABLE AT CURRENT TERMINATION POINT' for TLS when handshake is terminated at the Gateway.
"""

import hashlib
import logging
from typing import Dict, Any, Optional
from enrichment.models import ClientFingerprint, TLSFingerprint
from enrichment.config import ti_settings

logger = logging.getLogger("aegis.enrichment.fingerprint")


def sanitize_headers(headers: Dict[str, Any]) -> Dict[str, str]:
    """Strip all credential tokens, cookies, auth headers, and API keys."""
    cleaned = {}
    for k, v in headers.items():
        k_lower = str(k).strip().lower()
        if k_lower in ti_settings.SENSITIVE_HEADERS:
            continue
        cleaned[k_lower] = str(v)
    return cleaned


def generate_client_fingerprint(
    headers: Optional[Dict[str, Any]] = None,
    user_agent: Optional[str] = None,
    http_version: Optional[str] = "HTTP/1.1"
) -> ClientFingerprint:
    """
    Generate a deterministic SHA-256 HTTP client fingerprint from normalized request headers.
    Sensitive tokens (cookies, authorization, API keys) are strictly sanitized out before hashing.
    """
    raw_headers = headers or {}
    safe_headers = sanitize_headers(raw_headers)

    ua = (user_agent or safe_headers.get("user-agent") or "").strip()
    accept = safe_headers.get("accept", "").strip()
    accept_lang = safe_headers.get("accept-language", "").strip()
    accept_enc = safe_headers.get("accept-encoding", "").strip()
    proto = (http_version or "HTTP/1.1").strip().upper()

    # Deterministic fingerprint signature
    signature_payload = f"UA:{ua}|ACC:{accept}|LANG:{accept_lang}|ENC:{accept_enc}|PROTO:{proto}"
    fp_hash = hashlib.sha256(signature_payload.encode("utf-8")).hexdigest()

    return ClientFingerprint(
        fingerprint=fp_hash,
        method="SHA256",
        user_agent=ua if ua else None,
        accept=accept if accept else None,
        accept_language=accept_lang if accept_lang else None,
        accept_encoding=accept_enc if accept_enc else None,
        http_version=proto,
        sanitized=True
    )


def get_tls_fingerprint(request_headers: Optional[Dict[str, Any]] = None) -> TLSFingerprint:
    """
    Check for TLS handshake metadata (e.g. JA3/JA4).
    Since TLS terminates at the reverse proxy (Nginx / Cloudflare) without dedicated JA3 module,
    strictly reports 'NOT AVAILABLE AT CURRENT TERMINATION POINT' without faking hashes.
    """
    raw_headers = request_headers or {}
    # Check if a reverse proxy forwarder passed a legitimate verified header
    ja3 = raw_headers.get("x-ja3-fingerprint") or raw_headers.get("ssl-ja3")
    if ja3 and len(str(ja3)) > 16:
        return TLSFingerprint(
            status="AVAILABLE",
            fingerprint=str(ja3).strip(),
            method="JA3",
            observed_at=None
        )

    return TLSFingerprint(
        status="NOT AVAILABLE AT CURRENT TERMINATION POINT",
        fingerprint=None,
        method=None,
        observed_at=None
    )
