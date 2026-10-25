"""
AEGIS Ω — AgentShield Package Entrypoint
Exposes primary behavioral analysis helpers, analyzer functions, and configuration.
"""

from agent_shield.config import agent_shield_settings
from agent_shield.analyzer import analyze_behavior, get_behavior_severity
from agent_shield.service import assess_event_behavior
from agent_shield.models import AgentShieldResult, AgentShieldSignal, AttackStageItem

__all__ = [
    "agent_shield_settings",
    "analyze_behavior",
    "get_behavior_severity",
    "assess_event_behavior",
    "AgentShieldResult",
    "AgentShieldSignal",
    "AttackStageItem"
]
