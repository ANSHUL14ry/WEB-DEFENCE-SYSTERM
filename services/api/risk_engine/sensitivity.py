"""
AEGIS Ω — Endpoint Sensitivity Classifier
Maps request targets to explainable risk sensitivity levels.
Keeps endpoint classification distinct from core scoring logic.
"""

from typing import Tuple
from urllib.parse import urlparse
from risk_engine.config import risk_settings


def classify_endpoint_sensitivity(raw_uri: str) -> Tuple[str, int, str]:
    """
    Classify URI into HIGH, MEDIUM, or LOW sensitivity.
    Returns: (level, weight, explanation)
    """
    if not raw_uri:
        return "LOW", risk_settings.WEIGHT_ENDPOINT_LOW_SENSITIVITY, "Default baseline target"

    # Extract path portion ignoring query params
    path = urlparse(raw_uri).path.lower().rstrip("/")
    if not path:
        path = "/"

    # Check High Sensitivity
    for pattern in risk_settings.HIGH_SENSITIVITY_PATTERNS:
        clean_pat = pattern.lower().rstrip("/")
        if path == clean_pat or path.startswith(f"{clean_pat}/") or (clean_pat in path and clean_pat != "/"):
            return (
                "HIGH",
                risk_settings.WEIGHT_ENDPOINT_HIGH_SENSITIVITY,
                f"Target '{path}' classified as High-Sensitivity endpoint ({pattern})"
            )

    # Check Medium Sensitivity
    for pattern in risk_settings.MEDIUM_SENSITIVITY_PATTERNS:
        clean_pat = pattern.lower().rstrip("/")
        if path == clean_pat or path.startswith(f"{clean_pat}/"):
            return (
                "MEDIUM",
                risk_settings.WEIGHT_ENDPOINT_MEDIUM_SENSITIVITY,
                f"Target '{path}' classified as Medium-Sensitivity endpoint ({pattern})"
            )

    # Fallback Low Sensitivity
    return (
        "LOW",
        risk_settings.WEIGHT_ENDPOINT_LOW_SENSITIVITY,
        f"Target '{path}' classified as Low-Sensitivity / Public endpoint"
    )
