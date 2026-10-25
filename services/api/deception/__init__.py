"""
AEGIS Ω — Deception Subsystem Package
Exports the deception service, config, models, and repository interfaces.
"""

from deception.config import deception_settings
from deception.models import (
    DeceptionExecutionRequest,
    DeceptionInteractionRequest,
    DeceptionSessionRecord,
    DeceptionEventRecord,
    DeceptionStats
)
from deception.repository import (
    create_session,
    get_session_by_id,
    get_active_session_by_trace,
    update_session_status,
    create_deception_event,
    get_session_events,
    list_deception_sessions,
    list_deception_events,
    get_deception_stats
)
from deception.service import (
    execute_deception_routing,
    interact_with_decoy
)

__all__ = [
    "deception_settings",
    "DeceptionExecutionRequest",
    "DeceptionInteractionRequest",
    "DeceptionSessionRecord",
    "DeceptionEventRecord",
    "DeceptionStats",
    "create_session",
    "get_session_by_id",
    "get_active_session_by_trace",
    "update_session_status",
    "create_deception_event",
    "get_session_events",
    "list_deception_sessions",
    "list_deception_events",
    "get_deception_stats",
    "execute_deception_routing",
    "interact_with_decoy"
]
