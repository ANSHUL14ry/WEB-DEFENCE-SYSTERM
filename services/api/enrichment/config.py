"""
Configuration and constants for AEGIS Ω Attacker Intelligence & Threat Context Subsystem.
"""

import os
from typing import Set

class ThreatIntelSettings:
    # Provider configuration via environment variables
    # If not set, status defaults to 'NOT_CONFIGURED' (never fake ratings)
    PROVIDER: str = os.getenv("THREAT_INTEL_PROVIDER", "")
    API_KEY: str = os.getenv("THREAT_INTEL_API_KEY", "")
    
    # Local GeoIP / ASN configuration
    GEOIP_DB_PATH: str = os.getenv("GEOIP_DB_PATH", "")
    
    # In-memory enrichment cache TTL (in seconds)
    CACHE_TTL_SECONDS: int = int(os.getenv("THREAT_INTEL_CACHE_TTL", "3600"))
    
    # Sensitive headers to strip strictly before computing HTTP fingerprint or logging
    SENSITIVE_HEADERS: Set[str] = {
        "authorization", "proxy-authorization", "cookie", "set-cookie",
        "x-api-key", "api-key", "apikey", "x-auth-token", "bearer",
        "secret", "token", "password"
    }

ti_settings = ThreatIntelSettings()
