"""
AEGIS Ω — Risk Engine Configuration
Centralized thresholds, weights, and sensitivity definitions.
Eliminates magic numbers across the codebase.
"""

from typing import List, Dict

class RiskEngineConfig:
    # Versioning for auditability & traceability
    ENGINE_VERSION: str = "risk-engine-v1"

    # Score Boundaries
    SCORE_MIN: int = 0
    SCORE_MAX: int = 100

    # Severity Thresholds (0-24: LOW, 25-49: MEDIUM, 50-74: HIGH, 75-100: CRITICAL)
    THRESHOLD_LOW_MAX: int = 24
    THRESHOLD_MEDIUM_MAX: int = 49
    THRESHOLD_HIGH_MAX: int = 74
    THRESHOLD_CRITICAL_MIN: int = 75

    # Temporal Correlation Window in seconds
    TEMPORAL_WINDOW_SECONDS: int = 60
    MAX_HISTORICAL_EVENTS_LIMIT: int = 50

    # Signal Weights (Deterministic points contribution)
    WEIGHT_WAF_CRITICAL: int = 30
    WEIGHT_WAF_HIGH: int = 20
    WEIGHT_WAF_MEDIUM: int = 10
    WEIGHT_WAF_LOW: int = 5

    WEIGHT_KNOWN_ATTACK_RULE: int = 20
    WEIGHT_ANOMALY_SCORE_ELEVATED: int = 10

    WEIGHT_ENDPOINT_HIGH_SENSITIVITY: int = 20
    WEIGHT_ENDPOINT_MEDIUM_SENSITIVITY: int = 10
    WEIGHT_ENDPOINT_LOW_SENSITIVITY: int = 0

    WEIGHT_REPEATED_ACTIVITY_MODERATE: int = 10   # 2-3 events in window
    WEIGHT_REPEATED_ACTIVITY_ELEVATED: int = 20   # 4+ events in window

    WEIGHT_HIGH_VELOCITY: int = 15                # >= 5 events in window
    WEIGHT_PROBING_MULTIPLE_ENDPOINTS: int = 10   # >= 3 distinct endpoints visited

    # Endpoint Sensitivity Patterns
    HIGH_SENSITIVITY_PATTERNS: List[str] = [
        "/admin", "/admin/", "/api/users", "/api/auth", "/.env", "/config", "/etc/passwd", "/setup"
    ]
    MEDIUM_SENSITIVITY_PATTERNS: List[str] = [
        "/login", "/search", "/files", "/api/v1/health", "/api/v1/status"
    ]
    LOW_SENSITIVITY_PATTERNS: List[str] = [
        "/", "/products", "/favicon.ico", "/health"
    ]

    # Known High-Risk CRS Rule ID ranges
    ATTACK_RULE_RANGES = [
        (942000, 942999, "SQL Injection Detection"),
        (941000, 941999, "Cross-Site Scripting (XSS) Detection"),
        (930000, 930999, "Local/Remote File Inclusion / Path Traversal"),
        (932000, 932999, "Remote Code Execution (RCE)"),
        (933000, 933999, "PHP Injection"),
        (944000, 944999, "JAVA Injection / Deserialization")
    ]

risk_settings = RiskEngineConfig()
