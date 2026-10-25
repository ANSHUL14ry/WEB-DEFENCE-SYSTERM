"""
AEGIS Ω — AgentShield Behavioral Signal Extractors
Pure, deterministic behavioral signal extraction functions.
Analyzes observable event streams without guessing, hallucinating, or calling external AI APIs.
"""

from typing import List, Dict, Any, Tuple, Set, Optional
from urllib.parse import urlparse, parse_qs
from agent_shield.config import agent_shield_settings
from agent_shield.models import AgentShieldSignal, AttackStageItem


def _extract_request_info(event: Dict[str, Any]) -> Tuple[str, str, str, Set[str]]:
    """
    Extracts sanitized method, path, query, and parameter names from a security event.
    NEVER extracts or returns parameter values (passwords, tokens, secrets).
    """
    req = event.get("request", {}) or {}
    uri = req.get("uri") or event.get("uri") or "/"
    method = (req.get("method") or event.get("method") or "GET").upper()

    parsed = urlparse(uri)
    path = parsed.path or "/"
    query = parsed.query or ""
    
    # Extract only parameter names, never values
    param_names = set(parse_qs(query, keep_blank_values=True).keys())
    return method, path, query, param_names


def _is_waf_event(event: Dict[str, Any]) -> bool:
    """Checks if event represents a WAF detection or block."""
    comp = str(event.get("component", "")).lower()
    ev_type = str(event.get("event_type", "")).upper()
    act = str(event.get("action", "")).upper()
    sev = str(event.get("severity", "")).upper()
    return comp == "coraza" or "WAF" in ev_type or act == "BLOCK" or (sev in ("HIGH", "CRITICAL") and "waf" in comp)


def extract_behavioral_signals(
    target_event: Dict[str, Any],
    historical_events: List[Dict[str, Any]]
) -> Tuple[List[AgentShieldSignal], List[str], List[AttackStageItem]]:
    """
    Analyzes the chronological sequence of events for a request/trace and produces
    deterministic behavioral signals, stage classifications, and timeline items.
    """
    # 1. Sort events chronologically (historical + current target)
    all_events = sorted(
        historical_events + [target_event],
        key=lambda e: e.get("timestamp") or ""
    )

    signals: List[AgentShieldSignal] = []
    observed_stages: List[str] = []
    attack_timeline: List[AttackStageItem] = []

    # Aggregation structures
    distinct_paths: Set[str] = set()
    recon_paths: Set[str] = set()
    api_paths: Set[str] = set()
    auth_requests: List[Dict[str, Any]] = []
    waf_triggers: List[Dict[str, Any]] = []
    path_param_map: Dict[str, Set[str]] = {}

    for ev in all_events:
        method, path, query, param_names = _extract_request_info(ev)
        timestamp = ev.get("timestamp") or ""
        distinct_paths.add(path)

        # Track parameter variations per path (structural names only)
        if path not in path_param_map:
            path_param_map[path] = set()
        if query:
            # Store hash/tuple of sorted param names to detect manipulation
            path_param_map[path].add("&".join(sorted(param_names)) or "query_present")

        # Classify stages & collect metrics
        stage_identified: Optional[str] = None
        stage_detail = ""

        # A. Reconnaissance
        if path in agent_shield_settings.RECON_ENDPOINTS:
            recon_paths.add(path)
            stage_identified = "RECON"
            stage_detail = f"Preliminary discovery request to {path}"

        # B. Endpoint Discovery
        elif path in agent_shield_settings.DISCOVERY_ENDPOINTS:
            stage_identified = "ENDPOINT_DISCOVERY"
            stage_detail = f"High-value administrative/configuration endpoint probe: {path}"

        # C. API Enumeration
        if path.startswith("/api/") or path == "/api":
            api_paths.add(path)
            if not stage_identified:
                stage_identified = "API_ENUMERATION"
                stage_detail = f"Application API interface probing: {path}"

        # D. Authentication Probing
        if path in agent_shield_settings.AUTH_ENDPOINTS or path.endswith("/login") or path.endswith("/auth"):
            auth_requests.append(ev)
            if not stage_identified or stage_identified in ("RECON", "ENDPOINT_DISCOVERY"):
                stage_identified = "AUTH_PROBING"
                stage_detail = f"Credential endpoint targeted: {method} {path}"

        # E. WAF Trigger
        if _is_waf_event(ev):
            waf_triggers.append(ev)
            meta = ev.get("metadata", {}) or {}
            rule_id = meta.get("rule_id", "CRS")
            stage_identified = "WAF_TRIGGER"
            stage_detail = f"WAF violation intercepted (Rule: {rule_id})"

        # Add to timeline if stage identified
        if stage_identified:
            attack_timeline.append(AttackStageItem(
                stage=stage_identified,
                timestamp=str(timestamp),
                method=method,
                uri=path,
                detail=stage_detail
            ))
            if not observed_stages or observed_stages[-1] != stage_identified:
                observed_stages.append(stage_identified)

    # -------------------------------------------------------------------------
    # SIGNAL 1: RAPID RECONNAISSANCE (rapid_recon)
    # -------------------------------------------------------------------------
    if len(recon_paths) >= 2 or (len(recon_paths) >= 1 and len(distinct_paths) >= agent_shield_settings.RAPID_RECON_MIN_PATHS):
        signals.append(AgentShieldSignal(
            name="rapid_recon",
            score=agent_shield_settings.WEIGHT_RAPID_RECON,
            evidence={
                "recon_paths_found": sorted(list(recon_paths)),
                "total_paths": len(distinct_paths),
                "window_seconds": agent_shield_settings.TEMPORAL_WINDOW_SECONDS
            },
            reason="Rapid reconnaissance detected: multiple preliminary discovery endpoints probed in short duration."
        ))

    # -------------------------------------------------------------------------
    # SIGNAL 2: ENDPOINT ENUMERATION (endpoint_enumeration)
    # -------------------------------------------------------------------------
    if len(distinct_paths) >= agent_shield_settings.ENDPOINT_ENUM_MIN_PATHS:
        signals.append(AgentShieldSignal(
            name="endpoint_enumeration",
            score=agent_shield_settings.WEIGHT_ENDPOINT_ENUMERATION,
            evidence={
                "distinct_paths_count": len(distinct_paths),
                "paths_sample": sorted(list(distinct_paths))[:6]
            },
            reason=f"Systematic endpoint enumeration observed across {len(distinct_paths)} distinct application paths."
        ))

    # -------------------------------------------------------------------------
    # SIGNAL 3: API ENUMERATION (api_enumeration)
    # -------------------------------------------------------------------------
    if len(api_paths) >= agent_shield_settings.API_ENUM_MIN_PATHS:
        signals.append(AgentShieldSignal(
            name="api_enumeration",
            score=agent_shield_settings.WEIGHT_API_ENUMERATION,
            evidence={
                "api_endpoints_count": len(api_paths),
                "api_paths": sorted(list(api_paths))
            },
            reason=f"Systematic API path enumeration observed ({len(api_paths)} API endpoints probed)."
        ))

    # -------------------------------------------------------------------------
    # SIGNAL 4: REQUEST VELOCITY (request_velocity)
    # -------------------------------------------------------------------------
    if len(all_events) >= agent_shield_settings.VELOCITY_THRESHOLD_HIGH:
        signals.append(AgentShieldSignal(
            name="request_velocity",
            score=agent_shield_settings.WEIGHT_REQUEST_VELOCITY,
            evidence={
                "request_count": len(all_events),
                "window_seconds": agent_shield_settings.TEMPORAL_WINDOW_SECONDS
            },
            reason=f"Elevated request velocity detected: {len(all_events)} requests recorded within {agent_shield_settings.TEMPORAL_WINDOW_SECONDS}s window."
        ))

    # -------------------------------------------------------------------------
    # SIGNAL 5: AUTHENTICATION PROBING (authentication_probing)
    # -------------------------------------------------------------------------
    if len(auth_requests) >= agent_shield_settings.AUTH_PROBING_MIN_REQUESTS:
        signals.append(AgentShieldSignal(
            name="authentication_probing",
            score=agent_shield_settings.WEIGHT_AUTHENTICATION_PROBING,
            evidence={
                "auth_requests_count": len(auth_requests),
                "target_endpoints": sorted(list({_extract_request_info(e)[1] for e in auth_requests}))
            },
            reason=f"Repeated authentication endpoint probing observed ({len(auth_requests)} requests targeted at credential interfaces)."
        ))

    # -------------------------------------------------------------------------
    # SIGNAL 6: REPEATED WAF TRIGGERS (repeated_waf_triggers)
    # -------------------------------------------------------------------------
    if len(waf_triggers) >= agent_shield_settings.REPEATED_WAF_MIN_COUNT:
        waf_rule_ids = set()
        for we in waf_triggers:
            m = we.get("metadata", {}) or {}
            if "rule_id" in m:
                waf_rule_ids.add(str(m["rule_id"]))
        signals.append(AgentShieldSignal(
            name="repeated_waf_triggers",
            score=agent_shield_settings.WEIGHT_REPEATED_WAF_TRIGGERS,
            evidence={
                "waf_trigger_count": len(waf_triggers),
                "rule_ids": sorted(list(waf_rule_ids))
            },
            reason=f"Repeated WAF security violations triggered ({len(waf_triggers)} security rule matches recorded in trace)."
        ))

    # -------------------------------------------------------------------------
    # SIGNAL 7: PARAMETER MANIPULATION (parameter_manipulation)
    # -------------------------------------------------------------------------
    # Check if any path experienced parameter variations
    manipulated_paths = [p for p, queries in path_param_map.items() if len(queries) >= agent_shield_settings.PARAM_MANIPULATION_MIN_VARIATIONS]
    if manipulated_paths:
        signals.append(AgentShieldSignal(
            name="parameter_manipulation",
            score=agent_shield_settings.WEIGHT_PARAMETER_MANIPULATION,
            evidence={
                "manipulated_paths": manipulated_paths,
                "variation_count": sum(len(path_param_map[p]) for p in manipulated_paths)
            },
            reason=f"Parameter fuzzing or manipulation pattern detected across repeated requests to: {', '.join(manipulated_paths)}."
        ))

    # -------------------------------------------------------------------------
    # SIGNAL 8: ATTACK SEQUENCE (attack_sequence)
    # -------------------------------------------------------------------------
    unique_stage_set = set(observed_stages)
    if len(unique_stage_set) >= agent_shield_settings.ATTACK_SEQUENCE_MIN_STAGES:
        signals.append(AgentShieldSignal(
            name="attack_sequence",
            score=agent_shield_settings.WEIGHT_ATTACK_SEQUENCE,
            evidence={
                "progression": observed_stages,
                "stages_count": len(unique_stage_set)
            },
            reason=f"Multi-stage structured attack sequence identified: {' -> '.join(observed_stages)}."
        ))

    return signals, observed_stages, attack_timeline
