import asyncio
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy import text
from database import SessionLocal
from config import settings
from models.events import map_waf_severity, sanitize_value
from broadcaster import broadcaster

logger = logging.getLogger("aegis.waf_watcher")

def parse_coraza_message(msg_str: str) -> Dict[str, Any]:
    """Parse key attributes from a Coraza rule match message string."""
    res = {
        "rule_id": 0,
        "rule_message": "CRS Rule Violation Detected",
        "severity": "CRITICAL",
        "matched_data": "",
        "anomaly_score": 0
    }
    
    id_match = re.search(r'\[id "(\d+)"\]', msg_str)
    if id_match:
        res["rule_id"] = int(id_match.group(1))

    msg_match = re.search(r'\[msg "([^"]+)"\]', msg_str)
    if msg_match:
        res["rule_message"] = msg_match.group(1)

    sev_match = re.search(r'\[severity "([^"]+)"\]', msg_str)
    if sev_match:
        res["severity"] = sev_match.group(1).upper()

    data_match = re.search(r'\[data "([^"]+)"\]', msg_str)
    if data_match:
        res["matched_data"] = data_match.group(1)

    score_match = re.search(r'Total Score:\s*(\d+)', msg_str)
    if score_match:
        res["anomaly_score"] = int(score_match.group(1))

    return res

async def start_waf_log_watcher():
    """Background async worker that tails the Coraza WAF audit log and persists security events."""
    log_path = settings.CORAZA_AUDIT_LOG_PATH
    logger.info(f"Starting Coraza WAF log watcher on path: {log_path}")

    # Wait until log file is created by Coraza
    while not os.path.exists(log_path):
        await asyncio.sleep(2)

    logger.info(f"Coraza WAF audit log detected at {log_path}. Beginning real-time stream ingestion.")

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            # Seek to end of existing file so we don't duplicate on restart
            f.seek(0, os.SEEK_END)

            while True:
                line = f.readline()
                if not line:
                    await asyncio.sleep(0.5)
                    continue

                line = line.strip()
                if not line or not line.startswith("{"):
                    continue

                try:
                    event_data = json.loads(line)
                    tx = event_data.get("transaction", {})
                    req = tx.get("request", {})
                    headers = req.get("headers", {})

                    # Extract propagated request_id and trace_id
                    req_id_header = headers.get("x-request-id")
                    if req_id_header and isinstance(req_id_header, list) and len(req_id_header) > 0:
                        request_id = req_id_header[0]
                    else:
                        request_id = tx.get("id", "unknown-coraza-id")

                    trace_id_header = headers.get("x-trace-id")
                    if trace_id_header and isinstance(trace_id_header, list) and len(trace_id_header) > 0:
                        trace_id = trace_id_header[0]
                    else:
                        trace_id = f"trace-{request_id}"

                    action = "BLOCK" if tx.get("is_interrupted", False) else "DETECT"
                    method = req.get("method", "GET")
                    uri = req.get("uri", "/")
                    client_ip = tx.get("client_ip", "unknown")

                    messages = event_data.get("messages", [])
                    primary_rule_id = 0
                    primary_message = "CRS Rule Matched"
                    primary_severity = "CRITICAL"
                    matched_data = ""
                    anomaly_score = 0

                    for m in messages:
                        err_msg = m.get("error_message", "")
                        parsed = parse_coraza_message(err_msg)
                        # We prioritize attack classification rules (e.g. 942xxx for SQLi, 941xxx for XSS, 930xxx for LFI)
                        if parsed["rule_id"] >= 900000 and parsed["rule_id"] not in [949110, 980170]:
                            primary_rule_id = parsed["rule_id"]
                            primary_message = parsed["rule_message"]
                            primary_severity = parsed["severity"]
                            matched_data = parsed["matched_data"]
                        elif primary_rule_id == 0 and parsed["rule_id"] > 0:
                            primary_rule_id = parsed["rule_id"]
                            primary_message = parsed["rule_message"]
                            primary_severity = parsed["severity"]

                        if parsed["anomaly_score"] > anomaly_score:
                            anomaly_score = parsed["anomaly_score"]

                    # Extract user agent if available
                    user_agent_header = headers.get("user-agent")
                    user_agent = None
                    if user_agent_header:
                        user_agent = user_agent_header[0] if isinstance(user_agent_header, list) else str(user_agent_header)

                    # Compute deterministic event_id for Phase 4 deduplication
                    # Signature: request_id + primary_rule_id
                    raw_sig = f"{request_id}:{primary_rule_id}:{action}"
                    sec_event_id = hashlib.sha256(raw_sig.encode()).hexdigest()[:32]
                    mapped_sev = map_waf_severity(primary_severity)
                    sec_event_type = "WAF_BLOCK" if action == "BLOCK" else "WAF_DETECTION"
                    sec_status = "BLOCKED" if action == "BLOCK" else "DETECTED"
                    sanitized_uri = sanitize_value(uri)

                    sec_metadata = {
                        "rule_id": primary_rule_id,
                        "rule_message": primary_message,
                        "anomaly_score": anomaly_score,
                        "matched_data": sanitize_value(matched_data),
                        "engine": "coraza-v3",
                        "crs_ruleset": "OWASP_CRS_v4.30.0"
                    }

                    # Persist events into PostgreSQL
                    db = SessionLocal()
                    try:
                        # 1. Specialized WAF event store (Phase 3 compatibility)
                        insert_waf_sql = text("""
                            INSERT INTO waf_events (
                                request_id, trace_id, action, severity_label, rule_id,
                                rule_message, engine, http_method, uri, client_ip,
                                anomaly_score, matched_data, raw_details, created_at
                            ) VALUES (
                                :request_id, :trace_id, :action, :severity_label, :rule_id,
                                :rule_message, :engine, :http_method, :uri, :client_ip,
                                :anomaly_score, :matched_data, CAST(:raw_details AS jsonb), CURRENT_TIMESTAMP
                            )
                        """)
                        db.execute(insert_waf_sql, {
                            "request_id": request_id,
                            "trace_id": trace_id,
                            "action": action,
                            "severity_label": primary_severity,
                            "rule_id": primary_rule_id,
                            "rule_message": primary_message,
                            "engine": "coraza-v3",
                            "http_method": method,
                            "uri": uri,
                            "client_ip": client_ip,
                            "anomaly_score": anomaly_score,
                            "matched_data": matched_data,
                            "raw_details": json.dumps(event_data)
                        })

                        # 2. Normalized Security Events Store (Phase 4 Pipeline)
                        # Deduplication via ON CONFLICT (event_id) DO NOTHING
                        insert_sec_sql = text("""
                            INSERT INTO security_events (
                                event_id, event_type, timestamp, request_id, trace_id,
                                session_id, severity, action, component, status,
                                source_ip, user_agent, method, uri, metadata, created_at
                            ) VALUES (
                                :event_id, :event_type, CURRENT_TIMESTAMP, :request_id, :trace_id,
                                NULL, :severity, :action, 'coraza', :status,
                                :source_ip, :user_agent, :method, :uri, CAST(:metadata AS jsonb), CURRENT_TIMESTAMP
                            )
                            ON CONFLICT (event_id) DO NOTHING
                            RETURNING event_id;
                        """)
                        result = db.execute(insert_sec_sql, {
                            "event_id": sec_event_id,
                            "event_type": sec_event_type,
                            "request_id": request_id,
                            "trace_id": trace_id,
                            "severity": mapped_sev,
                            "action": action,
                            "status": sec_status,
                            "source_ip": client_ip,
                            "user_agent": user_agent,
                            "method": method,
                            "uri": sanitized_uri,
                            "metadata": json.dumps(sec_metadata)
                        })
                        db.commit()

                        is_new_sec_event = result.fetchone() is not None
                        logger.info(f"Ingested Coraza WAF event: {request_id} | Rule {primary_rule_id}: {primary_message} | Action: {action}")

                        # Broadcast live via WebSocket if new
                        if is_new_sec_event:
                            normalized_broadcast = {
                                "event_id": sec_event_id,
                                "event_type": sec_event_type,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "request_id": request_id,
                                "trace_id": trace_id,
                                "session_id": None,
                                "source": {"ip": client_ip, "user_agent": user_agent},
                                "request": {"method": method, "uri": sanitized_uri},
                                "severity": mapped_sev,
                                "action": action,
                                "component": "coraza",
                                "status": sec_status,
                                "metadata": sec_metadata,
                                "created_at": datetime.now(timezone.utc).isoformat()
                            }
                            await broadcaster.broadcast(normalized_broadcast)

                    except Exception as db_err:
                        db.rollback()
                        logger.error(f"Failed to persist WAF audit log to DB: {db_err}")
                    finally:
                        db.close()

                except Exception as json_err:
                    logger.warning(f"Error parsing Coraza audit log entry: {json_err}")

    except Exception as e:
        logger.error(f"Fatal error in Coraza WAF log watcher: {e}")
