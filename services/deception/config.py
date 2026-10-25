"""
AEGIS Ω — Isolated Decoy Environment Configuration
Synthetic parameters and limits for the isolated honeypot environment.
"""

import os

class DecoySettings:
    SERVICE_NAME: str = "aegis-isolated-decoy"
    PORT: int = int(os.getenv("PORT", "8090"))
    ENVIRONMENT: str = os.getenv("AEGIS_ENV", "isolated-decoy")
    VERSION: str = "0.8.0-decoy"
    
    # Decoy operational limits
    MAX_BODY_SIZE_BYTES: int = 1048576 # 1 MB
    SYNTHETIC_ORG_NAME: str = "Apex Logistics International (Demo)"
    SYNTHETIC_ADMIN_USER: str = "admin_demo"

decoy_settings = DecoySettings()
