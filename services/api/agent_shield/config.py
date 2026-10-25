"""
AEGIS Ω — AgentShield Configuration
Centralized behavioral thresholds, signal weights, and progression stage definitions.
Eliminates magic numbers across the behavioral analysis subsystem.
"""

from typing import List, Set, Dict


class AgentShieldConfig:
    # Subsystem version for auditability & traceability
    ENGINE_VERSION: str = "agentshield-v1"

    # Score Boundaries
    SCORE_MIN: int = 0
    SCORE_MAX: int = 100

    # Severity Thresholds (0-24: LOW, 25-49: MEDIUM, 50-74: HIGH, 75-100: CRITICAL)
    THRESHOLD_LOW_MAX: int = 24
    THRESHOLD_MEDIUM_MAX: int = 49
    THRESHOLD_HIGH_MAX: int = 74
    THRESHOLD_CRITICAL_MIN: int = 75

    # Temporal Correlation Window (in seconds)
    TEMPORAL_WINDOW_SECONDS: int = 60
    MAX_HISTORICAL_EVENTS_LIMIT: int = 100

    # Signal Weights (Transparent, configurable points contribution)
    WEIGHT_RAPID_RECON: int = 15
    WEIGHT_ENDPOINT_ENUMERATION: int = 15
    WEIGHT_API_ENUMERATION: int = 15
    WEIGHT_REQUEST_VELOCITY: int = 15
    WEIGHT_AUTHENTICATION_PROBING: int = 10
    WEIGHT_REPEATED_WAF_TRIGGERS: int = 15
    WEIGHT_PARAMETER_MANIPULATION: int = 5
    WEIGHT_ATTACK_SEQUENCE: int = 20

    # Heuristic Thresholds
    RAPID_RECON_MIN_PATHS: int = 3
    ENDPOINT_ENUM_MIN_PATHS: int = 4
    API_ENUM_MIN_PATHS: int = 2
    VELOCITY_THRESHOLD_HIGH: int = 5
    AUTH_PROBING_MIN_REQUESTS: int = 2
    REPEATED_WAF_MIN_COUNT: int = 2
    PARAM_MANIPULATION_MIN_VARIATIONS: int = 2
    ATTACK_SEQUENCE_MIN_STAGES: int = 3

    # Reconnaissance Endpoint Set
    RECON_ENDPOINTS: Set[str] = {
        "/", "/robots.txt", "/sitemap.xml", "/favicon.ico", "/index.html"
    }

    # High-Value Discovery Endpoints
    DISCOVERY_ENDPOINTS: Set[str] = {
        "/admin", "/admin/", "/login", "/register", "/setup", "/config",
        "/.env", "/phpinfo.php", "/console", "/server-status"
    }

    # Authentication Endpoints
    AUTH_ENDPOINTS: Set[str] = {
        "/login", "/auth", "/api/auth", "/api/login", "/api/v1/auth",
        "/signin", "/session", "/oauth/token"
    }

    # Mapping to Risk Engine Contribution
    RISK_CONTRIBUTION_LOW: int = 0
    RISK_CONTRIBUTION_MEDIUM: int = 5
    RISK_CONTRIBUTION_HIGH: int = 10
    RISK_CONTRIBUTION_CRITICAL: int = 20

    # Explicit Technical Disclaimer
    TECHNICAL_DISCLAIMER: str = (
        "AgentShield detects observable behavioral characteristics consistent with automated "
        "or agentic attack workflows. It does NOT identify specific AI models or claim proof of AI identity."
    )


agent_shield_settings = AgentShieldConfig()
