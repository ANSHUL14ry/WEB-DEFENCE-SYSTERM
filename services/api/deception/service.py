"""
AEGIS Ω — Deception Subsystem Service Layer
Coordinates trusted policy routing, decoy container proxying, session lifecycle,
and failure-safe evidence recording.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import re
import uuid
from typing import Dict, Any, Optional
import httpx
from sqlalchemy.orm import Session

from deception.config import deception_settings
from deception.models import DeceptionExecutionRequest, DeceptionInteractionRequest
from deception.repository import (
    create_session,
    get_session_by_id,
    get_active_session_by_trace,
    update_session_status,
    increment_session_counts,
    create_deception_event
)

logger = logging.getLogger("aegis.deception_service")
SENSITIVE_KEY_PATTERN = re.compile(r"(?i)(password|pass|secret|token|auth|cookie|key|jwt|bearer)")


def hash_identifier(value: Optional[str]) -> str:
    """Computes a one-way privacy-preserving SHA-256 hash."""
    if not value:
        return "anon_" + uuid.uuid4().hex[:8]
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()[:16]


def sanitize_metadata(raw_data: Any) -> Any:
    """Recursively redacts passwords, tokens, and authorization secrets."""
    if isinstance(raw_data, dict):
        cleaned = {}
        for k, v in raw_data.items():
            if SENSITIVE_KEY_PATTERN.search(str(k)):
                cleaned[k] = "[REDACTED_EVIDENCE]"
            else:
                cleaned[k] = sanitize_metadata(v)
        return cleaned
    elif isinstance(raw_data, list):
        return [sanitize_metadata(item) for item in raw_data]
    return raw_data


def classify_endpoint(route: str) -> str:
    """Categorizes target route for behavioral evidence timeline."""
    lower = route.lower()
    if "/login" in lower or "/auth" in lower:
        return "CREDENTIAL_INTERFACE"
    elif "/admin" in lower:
        return "ADMINISTRATIVE_SURFACE"
    elif "/api" in lower:
        return "API_DATA_SURFACE"
    elif lower in ("/", "/robots.txt", "/sitemap.xml"):
        return "RECON_SURFACE"
    return "APPLICATION_ROUTE"


def execute_deception_routing(
    req: DeceptionExecutionRequest,
    db: Session
) -> Dict[str, Any]:
    """
    Executes controlled deception routing for policy-qualified traffic.
    STRICT SECURITY INVARIANTS:
    1. WAF block is strictly terminal: NO DECEPTION if waf_blocked is True.
    2. Policy decision must be DECEIVE_ELIGIBLE.
    3. Deception failure never falls back to origin.
    """
    now = datetime.now(timezone.utc)
    src_hash = hash_identifier(f"{req.client_ip or 'unknown'}_{req.user_agent or 'unknown'}")

    # =========================================================================
    # INVARIANT 1: WAF Drop Preemption (Zero Deception Bypass)
    # =========================================================================
    if req.waf_blocked or (req.waf_action and req.waf_action.upper() == "BLOCK"):
        logger.warning(
            f"Deception Routing REJECTED for {req.request_id}: "
            f"WAF_BLOCKED == True. Zero deception bypass enforced."
        )
        return {
            "status": "DENIED",
            "decision": "BLOCK",
            "reason": "WAF_BLOCKED_TERMINAL: Zero deception bypass permitted. Request was dropped by ingress WAF.",
            "terminal": True,
            "origin_reached": False
        }

    # =========================================================================
    # INVARIANT 2: Policy Engine Qualification
    # =========================================================================
    if req.policy_decision != "DECEIVE_ELIGIBLE":
        logger.warning(
            f"Deception Routing DENIED for {req.request_id}: "
            f"Policy decision '{req.policy_decision}' does not qualify for deception."
        )
        return {
            "status": "DENIED",
            "reason": f"Policy decision is '{req.policy_decision}'; only DECEIVE_ELIGIBLE requests may enter the isolated decoy.",
            "origin_reached": False
        }

    # Check for existing active session across trace_id
    existing_session = get_active_session_by_trace(db, req.trace_id)
    if existing_session:
        session_id = existing_session["session_id"]
        logger.info(f"Reusing existing active deception session {session_id} for trace {req.trace_id}")
    else:
        # Create new deception session
        session_id = f"ds-{uuid.uuid4().hex[:16]}"
        expires_at = now + timedelta(seconds=deception_settings.DECEPTION_SESSION_TTL_SECONDS)

        session_record = create_session(db, {
            "session_id": session_id,
            "request_id": req.request_id,
            "trace_id": req.trace_id,
            "policy_decision_id": req.policy_decision_id,
            "source_identifier_hash": src_hash,
            "client_ip": req.client_ip,
            "initial_risk_score": req.initial_risk_score or 0,
            "initial_agent_shield_score": req.initial_agent_shield_score or 0,
            "entry_reason": f"High risk ({req.initial_risk_score}) + AgentShield automation ({req.initial_agent_shield_score}) qualified session for isolated deception.",
            "status": "ACTIVE",
            "started_at": now,
            "expires_at": expires_at
        })

        # Record DECEPTION_SESSION_STARTED event
        create_deception_event(db, {
            "event_id": f"de-{uuid.uuid4().hex[:16]}",
            "session_id": session_id,
            "request_id": req.request_id,
            "trace_id": req.trace_id,
            "event_type": "DECEPTION_SESSION_STARTED",
            "route": req.target_route or "/",
            "method": req.method or "GET",
            "source_identifier_hash": src_hash,
            "response_status": 200,
            "endpoint_category": classify_endpoint(req.target_route or "/"),
            "user_agent_classification": "automated_probe" if (req.initial_agent_shield_score or 0) >= 50 else "standard",
            "request_size": len(str(req.body or "")),
            "risk_context": {
                "initial_risk_score": req.initial_risk_score,
                "initial_agent_shield_score": req.initial_agent_shield_score,
                "policy_decision": req.policy_decision
            },
            "metadata": sanitize_metadata({
                "entry_route": req.target_route,
                "headers_present": list((req.headers or {}).keys())
            })
        })

    # =========================================================================
    # Route target request into isolated decoy container
    # =========================================================================
    target_route = req.target_route or "/"
    decoy_url = f"{deception_settings.DECOY_SERVICE_URL}{target_route}"
    decoy_response = None
    status_code = 200

    try:
        sanitized_headers = {
            k: v for k, v in (req.headers or {}).items()
            if not SENSITIVE_KEY_PATTERN.search(k)
        }
        sanitized_headers["X-Deception-Session-ID"] = session_id
        sanitized_headers["X-Trace-ID"] = req.trace_id
        sanitized_headers["X-Request-ID"] = req.request_id

        # Send request to decoy container
        with httpx.Client(timeout=5.0) as client:
            if (req.method or "GET").upper() == "POST":
                res = client.post(
                    decoy_url,
                    json=req.body if isinstance(req.body, dict) else None,
                    content=req.body if isinstance(req.body, (str, bytes)) else None,
                    headers=sanitized_headers
                )
            else:
                res = client.get(decoy_url, headers=sanitized_headers)

        status_code = res.status_code
        try:
            decoy_response = res.json()
        except Exception:
            decoy_response = res.text

    except Exception as e:
        logger.error(f"Isolated decoy execution failure: {e}", exc_info=True)
        # =====================================================================
        # INVARIANT 5: DECEPTION FAILURE != ORIGIN FALLBACK
        # The request must NEVER silently fall back to the real origin.
        # =====================================================================
        update_session_status(db, session_id, "TERMINATED")
        create_deception_event(db, {
            "event_id": f"de-{uuid.uuid4().hex[:16]}",
            "session_id": session_id,
            "request_id": req.request_id,
            "trace_id": req.trace_id,
            "event_type": "DECEPTION_FAILED",
            "route": target_route,
            "method": req.method or "GET",
            "source_identifier_hash": src_hash,
            "response_status": 503,
            "endpoint_category": classify_endpoint(target_route),
            "metadata": {"error": str(e), "origin_protected": True}
        })
        return {
            "session_id": session_id,
            "status": "FAILED",
            "error": "Decoy service unavailable. Suspicious request safely terminated; zero origin fallback.",
            "origin_reached": False
        }

    # Record interaction event and increment counters
    event_type = "DECEPTION_REQUEST"
    if "/login" in target_route:
        event_type = "DECOY_LOGIN_ATTEMPT"
    elif "/admin" in target_route:
        event_type = "DECOY_ADMIN_ACCESS"
    elif "/api" in target_route:
        event_type = "DECOY_API_ACCESS"

    create_deception_event(db, {
        "event_id": f"de-{uuid.uuid4().hex[:16]}",
        "session_id": session_id,
        "request_id": req.request_id,
        "trace_id": req.trace_id,
        "event_type": event_type,
        "route": target_route,
        "method": req.method or "GET",
        "source_identifier_hash": src_hash,
        "response_status": status_code,
        "endpoint_category": classify_endpoint(target_route),
        "request_size": len(str(req.body or "")),
        "metadata": sanitize_metadata({
            "response_code": status_code,
            "route": target_route
        })
    })
    increment_session_counts(db, session_id)

    session_data = get_session_by_id(db, session_id)
    return {
        "session_id": session_id,
        "status": "ACTIVE",
        "origin_reached": False,
        "decoy_response": decoy_response,
        "session": session_data
    }


def interact_with_decoy(
    req: DeceptionInteractionRequest,
    db: Session
) -> Dict[str, Any]:
    """
    Handles subsequent interactive requests within an active deception session.
    """
    session = get_session_by_id(db, req.session_id)
    if not session:
        return {"error": "SESSION_NOT_FOUND", "message": "Deception session does not exist."}

    now = datetime.now(timezone.utc)
    expires_at = datetime.fromisoformat(session["expires_at"].replace("Z", "+00:00")) if session.get("expires_at") else None

    # Check session expiration
    if session["status"] != "ACTIVE" or (expires_at and now > expires_at):
        update_session_status(db, req.session_id, "EXPIRED")
        return {
            "error": "SESSION_EXPIRED",
            "message": "Deception session has expired or been terminated.",
            "status": "EXPIRED"
        }

    # Check maximum requests per session limit
    if session["interaction_count"] >= deception_settings.MAX_REQUESTS_PER_SESSION:
        update_session_status(db, req.session_id, "TERMINATED")
        return {
            "error": "SESSION_LIMIT_EXCEEDED",
            "message": "Maximum allowed interactions exceeded for this deception session.",
            "status": "TERMINATED"
        }

    # Proxy to decoy container
    decoy_url = f"{deception_settings.DECOY_SERVICE_URL}{req.route}"
    status_code = 200
    decoy_response = None

    try:
        sanitized_headers = {
            k: v for k, v in (req.headers or {}).items()
            if not SENSITIVE_KEY_PATTERN.search(k)
        }
        sanitized_headers["X-Deception-Session-ID"] = req.session_id

        with httpx.Client(timeout=5.0) as client:
            if req.method.upper() == "POST":
                res = client.post(
                    decoy_url,
                    json=req.body if isinstance(req.body, dict) else None,
                    content=req.body if isinstance(req.body, (str, bytes)) else None,
                    headers=sanitized_headers
                )
            else:
                res = client.get(decoy_url, headers=sanitized_headers)

        status_code = res.status_code
        try:
            decoy_response = res.json()
        except Exception:
            decoy_response = res.text

    except Exception as e:
        logger.error(f"Decoy interaction failed: {e}")
        return {
            "error": "DECOY_COMMUNICATION_ERROR",
            "message": "Failed to communicate with isolated decoy container.",
            "origin_reached": False
        }

    # Classify event type
    event_type = "DECEPTION_REQUEST"
    if "/login" in req.route:
        event_type = "DECOY_LOGIN_ATTEMPT"
    elif "/admin" in req.route:
        event_type = "DECOY_ADMIN_ACCESS"
    elif "/api" in req.route:
        event_type = "DECOY_API_ACCESS"

    event_id = f"de-{uuid.uuid4().hex[:16]}"
    req_id = req.request_id or f"req-int-{uuid.uuid4().hex[:8]}"
    trace_id = req.trace_id or session["trace_id"]

    ev_record = create_deception_event(db, {
        "event_id": event_id,
        "session_id": req.session_id,
        "request_id": req_id,
        "trace_id": trace_id,
        "event_type": event_type,
        "route": req.route,
        "method": req.method,
        "source_identifier_hash": session["source_identifier_hash"],
        "response_status": status_code,
        "endpoint_category": classify_endpoint(req.route),
        "request_size": len(str(req.body or "")),
        "metadata": sanitize_metadata({
            "response_status": status_code,
            "route": req.route
        })
    })

    increment_session_counts(db, req.session_id)

    return {
        "status": "SUCCESS",
        "session_id": req.session_id,
        "origin_reached": False,
        "response": decoy_response,
        "event": ev_record
    }
