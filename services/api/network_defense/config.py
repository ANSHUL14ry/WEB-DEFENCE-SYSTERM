"""
AEGIS Ω — Network Defense Configuration & Constants (Phase 11)
"""

import os
from pydantic_settings import BaseSettings

class NetworkDefenseSettings(BaseSettings):
    SURICATA_ENABLED: bool = os.getenv("SURICATA_ENABLED", "true").lower() in ("true", "1", "yes")
    SURICATA_EVE_LOG_PATH: str = os.getenv("SURICATA_EVE_LOG_PATH", "/var/log/suricata/eve.json")
    SURICATA_SENSOR_NAME: str = "suricata"
    
    # Enforcement mode: "DEV" (in-memory stateful filter with audit log) or "IPTABLES" (Linux netfilter)
    ENFORCEMENT_MODE: str = os.getenv("NETWORK_ENFORCEMENT_MODE", "DEV").upper()
    DEFAULT_TEMP_BLOCK_SECONDS: int = int(os.getenv("DEFAULT_TEMP_BLOCK_SECONDS", "300"))
    DEFAULT_RATE_LIMIT_RPS: int = int(os.getenv("DEFAULT_RATE_LIMIT_RPS", "10"))
    
    # Internal Sensor Ingestion Security Token
    INTERNAL_INGEST_TOKEN: str = os.getenv("NETWORK_SENSOR_SECRET_TOKEN", "aegis_sensor_sec_token_2026")
    
    # DoS / Anomaly Baselines
    BASELINE_SAMPLE_SIZE: int = 50
    BURST_THRESHOLD_MULTIPLIER: float = 3.5
    CRITICAL_BURST_MULTIPLIER: float = 8.0
    
    class Config:
        env_file = ".env"
        extra = "ignore"

netdef_settings = NetworkDefenseSettings()
