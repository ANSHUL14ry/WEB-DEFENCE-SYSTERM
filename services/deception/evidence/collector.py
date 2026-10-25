"""
AEGIS Ω — Decoy Evidence Collector
Extracts safe observational evidence from interactions within the isolated honeypot.
Strict privacy mandate: raw passwords, cookies, authorization tokens, and real credentials
are NEVER stored, logged, or reflected.
"""

import hashlib
import re
from typing import Dict, Any, Optional

SENSITIVE_KEY_PATTERN = re.compile(r"(?i)(password|pass|secret|token|auth|cookie|key|jwt|bearer)")


def hash_identifier(value: Optional[str]) -> str:
    """Computes a one-way privacy-preserving SHA-256 hash of an identifier."""
    if not value:
        return "anonymous_hash"
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()[:16]


def sanitize_evidence_metadata(raw_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively strips or redacts sensitive keys such as passwords, tokens, and secrets
    from observational evidence metadata dictionaries.
    """
    cleaned: Dict[str, Any] = {}
    for k, v in raw_data.items():
        if SENSITIVE_KEY_PATTERN.search(k):
            cleaned[k] = "[REDACTED_EVIDENCE]"
        elif isinstance(v, dict):
            cleaned[k] = sanitize_evidence_metadata(v)
        elif isinstance(v, list):
            cleaned[k] = [
                sanitize_evidence_metadata(item) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            cleaned[k] = v
    return cleaned


def categorize_endpoint(path: str) -> str:
    """Classifies an HTTP target path into a behavioral interaction category."""
    lower_path = path.lower()
    if "/login" in lower_path or "/auth" in lower_path:
        return "CREDENTIAL_INTERFACE"
    elif "/admin" in lower_path:
        return "ADMINISTRATIVE_SURFACE"
    elif "/api" in lower_path:
        return "API_DATA_SURFACE"
    elif lower_path in ("/", "/robots.txt", "/sitemap.xml", "/index.html"):
        return "RECON_SURFACE"
    return "APPLICATION_ROUTE"
