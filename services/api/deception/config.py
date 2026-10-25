"""
AEGIS Ω — Deception Subsystem Configuration
Centralized settings, timeouts, limits, and decoy endpoints for Phase 8.
"""

import os

class DeceptionSettings:
    VERSION: str = "deception-v1"
    
    # Target decoy container URL on internal Docker network (deception-net)
    DECOY_SERVICE_URL: str = os.getenv("DECOY_SERVICE_URL", "http://decoy:8090")
    
    # Session lifecycle & limits
    DECEPTION_SESSION_TTL_SECONDS: int = int(os.getenv("DECEPTION_SESSION_TTL_SECONDS", "600")) # 10 minutes
    MAX_REQUESTS_PER_SESSION: int = int(os.getenv("MAX_REQUESTS_PER_SESSION", "50"))
    MAX_BODY_SIZE_BYTES: int = int(os.getenv("MAX_BODY_SIZE_BYTES", "1048576")) # 1 MB
    MAX_CONCURRENT_ACTIVE_SESSIONS: int = int(os.getenv("MAX_CONCURRENT_ACTIVE_SESSIONS", "100"))

deception_settings = DeceptionSettings()
