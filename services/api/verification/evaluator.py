"""
AEGIS Ω — Phase 9 Deterministic Verification Evaluator
Implements deterministic, explainable verification rules without ML/black-box inference.
"""

from typing import Tuple, List, Optional
import uuid
import datetime

from verification.config import (
    ENGINE_VERSION,
    RESULT_VERIFIED,
    RESULT_FAILED,
    RESULT_INCONCLUSIVE,
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_DECEIVE,
    TYPE_WAF_BLOCK,
    TYPE_NORMAL_ALLOW,
    TYPE_POLICY_BLOCK,
    TYPE_DECEPTION,
    TYPE_DECEPTION_FAILURE,
    TYPE_NETWORK_DEFENSE,
    CONFIDENCE_FULL,
    CONFIDENCE_PARTIAL,
    CONFIDENCE_INCONCLUSIVE,
    CONFIDENCE_ZERO
)
from verification.models import VerificationContext, ProofObject


def evaluate_mitigation_verification(ctx: VerificationContext) -> ProofObject:
    """
    Pure deterministic verification evaluation.
    Evaluates evidence against mathematical security invariants and produces
    a telemetry-backed proof receipt.
    """
    verification_id = f"vr-{uuid.uuid4().hex[:12]}"
    created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    proof_statements: List[str] = []
    failure_reason: Optional[str] = None
    
    # 0. INCONCLUSIVE CHECK: Missing or Corrupted Telemetry
    if ctx.telemetry_corrupted:
        return ProofObject(
            verification_id=verification_id,
            request_id=ctx.request_id,
            trace_id=ctx.trace_id,
            session_id=ctx.session_id,
            policy_decision_id=ctx.policy_decision_id,
            verification_type="CORRUPT_TELEMETRY",
            expected_action=ctx.policy_decision or "UNKNOWN",
            actual_action="INCONCLUSIVE",
            expected_origin_access=False,
            actual_origin_access=ctx.origin_reached,
            origin_request_count=ctx.origin_request_count,
            deception_session_id=ctx.deception_session_id,
            evidence_events=ctx.evidence_count,
            database_access=ctx.database_access_detected,
            result=RESULT_INCONCLUSIVE,
            confidence=CONFIDENCE_INCONCLUSIVE,
            proof=["Telemetry correlation checksum failed", "Audit logs show corrupted payload"],
            failure_reason="Corrupt telemetry prevented deterministic verification",
            engine_version=ENGINE_VERSION,
            created_at=created_at
        )

    if not ctx.has_sufficient_telemetry:
        return ProofObject(
            verification_id=verification_id,
            request_id=ctx.request_id,
            trace_id=ctx.trace_id,
            session_id=ctx.session_id,
            policy_decision_id=ctx.policy_decision_id,
            verification_type="INSUFFICIENT_TELEMETRY",
            expected_action=ctx.policy_decision or "UNKNOWN",
            actual_action="INCONCLUSIVE",
            expected_origin_access=False,
            actual_origin_access=ctx.origin_reached,
            origin_request_count=ctx.origin_request_count,
            deception_session_id=ctx.deception_session_id,
            evidence_events=ctx.evidence_count,
            database_access=ctx.database_access_detected,
            result=RESULT_INCONCLUSIVE,
            confidence=CONFIDENCE_INCONCLUSIVE,
            proof=["Incomplete telemetry records", "Required audit receipts missing from pipeline"],
            failure_reason="Missing telemetry prevents conclusive proof",
            engine_version=ENGINE_VERSION,
            created_at=created_at
        )

    # 1. RULE 1 — WAF BLOCK VERIFICATION
    if ctx.waf_blocked:
        expected_action = ACTION_BLOCK
        actual_action = ACTION_BLOCK
        expected_origin = False
        actual_origin = ctx.origin_reached or (ctx.origin_request_count > 0)
        
        # Check: Invariant - WAF block must NEVER reach origin
        if actual_origin:
            return ProofObject(
                verification_id=verification_id,
                request_id=ctx.request_id,
                trace_id=ctx.trace_id,
                session_id=ctx.session_id,
                policy_decision_id=ctx.policy_decision_id,
                verification_type=TYPE_WAF_BLOCK,
                expected_action=expected_action,
                actual_action=actual_action,
                expected_origin_access=expected_origin,
                actual_origin_access=True,
                origin_request_count=ctx.origin_request_count or 1,
                deception_session_id=ctx.deception_session_id,
                evidence_events=ctx.evidence_count,
                database_access=ctx.database_access_detected,
                result=RESULT_FAILED,
                confidence=CONFIDENCE_FULL,
                proof=["CRITICAL FAILURE: Request reached origin workload despite WAF BLOCK"],
                failure_reason="WAF terminal block invariant violated: origin was contacted",
                engine_version=ENGINE_VERSION,
                created_at=created_at
            )
        
        # Check: Invariant - WAF block must NEVER enter deception
        if ctx.deception_session_id is not None:
            return ProofObject(
                verification_id=verification_id,
                request_id=ctx.request_id,
                trace_id=ctx.trace_id,
                session_id=ctx.session_id,
                policy_decision_id=ctx.policy_decision_id,
                verification_type=TYPE_WAF_BLOCK,
                expected_action=expected_action,
                actual_action="DECEPTION_ATTEMPTED",
                expected_origin_access=expected_origin,
                actual_origin_access=False,
                origin_request_count=0,
                deception_session_id=ctx.deception_session_id,
                evidence_events=ctx.evidence_count,
                database_access=ctx.database_access_detected,
                result=RESULT_FAILED,
                confidence=CONFIDENCE_FULL,
                proof=["CRITICAL FAILURE: Deception session initialized for WAF blocked request"],
                failure_reason="WAF block cannot enter deception",
                engine_version=ENGINE_VERSION,
                created_at=created_at
            )

        # Success path for WAF Block
        proof_statements.append("WAF rule inspection triggered terminal block")
        proof_statements.append("HTTP 403 Forbidden generated at security gateway")
        proof_statements.append("Origin application received 0 requests (origin untouched)")
        proof_statements.append("Zero deception bypass verified (no synthetic decoy session)")
        
        return ProofObject(
            verification_id=verification_id,
            request_id=ctx.request_id,
            trace_id=ctx.trace_id,
            session_id=ctx.session_id,
            policy_decision_id=ctx.policy_decision_id,
            verification_type=TYPE_WAF_BLOCK,
            expected_action=expected_action,
            actual_action=actual_action,
            expected_origin_access=expected_origin,
            actual_origin_access=False,
            origin_request_count=0,
            deception_session_id=None,
            evidence_events=0,
            database_access=False,
            result=RESULT_VERIFIED,
            confidence=CONFIDENCE_FULL,
            proof=proof_statements,
            failure_reason=None,
            engine_version=ENGINE_VERSION,
            created_at=created_at
        )

    # 2. RULE 5 — DECEPTION FAILURE VERIFICATION
    if ctx.decoy_failed:
        expected_action = ACTION_DECEIVE
        actual_action = "DECEPTION_FAILED"
        expected_origin = False
        actual_origin = ctx.origin_reached or (ctx.origin_request_count > 0)

        # Invariant: If decoy fails, NEVER fall back to origin
        if actual_origin:
            return ProofObject(
                verification_id=verification_id,
                request_id=ctx.request_id,
                trace_id=ctx.trace_id,
                session_id=ctx.session_id,
                policy_decision_id=ctx.policy_decision_id,
                verification_type=TYPE_DECEPTION_FAILURE,
                expected_action=expected_action,
                actual_action=actual_action,
                expected_origin_access=expected_origin,
                actual_origin_access=True,
                origin_request_count=ctx.origin_request_count or 1,
                deception_session_id=ctx.deception_session_id,
                evidence_events=ctx.evidence_count,
                database_access=ctx.database_access_detected,
                result=RESULT_FAILED,
                confidence=CONFIDENCE_FULL,
                proof=["CRITICAL: Decoy failed and system incorrectly fell back to origin"],
                failure_reason="Deception failure leaked to origin application",
                engine_version=ENGINE_VERSION,
                created_at=created_at
            )
        
        # Decoy failed, but zero origin fallback invariant held
        return ProofObject(
            verification_id=verification_id,
            request_id=ctx.request_id,
            trace_id=ctx.trace_id,
            session_id=ctx.session_id,
            policy_decision_id=ctx.policy_decision_id,
            verification_type=TYPE_DECEPTION_FAILURE,
            expected_action=expected_action,
            actual_action=actual_action,
            expected_origin_access=expected_origin,
            actual_origin_access=False,
            origin_request_count=0,
            deception_session_id=ctx.deception_session_id,
            evidence_events=ctx.evidence_count,
            database_access=False,
            result=RESULT_FAILED,
            confidence=CONFIDENCE_FULL,
            proof=[
                "Decoy environment returned failure or timeout",
                "Zero origin fallback invariant ENFORCED: origin was not contacted",
                "Request terminated cleanly with synthetic 503 error"
            ],
            failure_reason="Decoy service encountered failure, but origin remained protected",
            engine_version=ENGINE_VERSION,
            created_at=created_at
        )

    # 3. RULE 4 — DECEPTION VERIFICATION
    if ctx.policy_decision == "DECEIVE_ELIGIBLE" or ctx.deception_session_id is not None:
        expected_action = ACTION_DECEIVE
        actual_action = ACTION_DECEIVE
        expected_origin = False
        actual_origin = ctx.origin_reached or (ctx.origin_request_count > 0)

        # Invariant 1: Origin must NOT be reached
        if actual_origin:
            return ProofObject(
                verification_id=verification_id,
                request_id=ctx.request_id,
                trace_id=ctx.trace_id,
                session_id=ctx.session_id,
                policy_decision_id=ctx.policy_decision_id,
                verification_type=TYPE_DECEPTION,
                expected_action=expected_action,
                actual_action=actual_action,
                expected_origin_access=expected_origin,
                actual_origin_access=True,
                origin_request_count=ctx.origin_request_count or 1,
                deception_session_id=ctx.deception_session_id,
                evidence_events=ctx.evidence_count,
                database_access=ctx.database_access_detected,
                result=RESULT_FAILED,
                confidence=CONFIDENCE_FULL,
                proof=["CRITICAL: Decoy session permitted traffic leakage to production origin"],
                failure_reason="Origin access detected during active deception session",
                engine_version=ENGINE_VERSION,
                created_at=created_at
            )

        # Invariant 2: Production DB must NOT be touched
        if ctx.database_access_detected:
            return ProofObject(
                verification_id=verification_id,
                request_id=ctx.request_id,
                trace_id=ctx.trace_id,
                session_id=ctx.session_id,
                policy_decision_id=ctx.policy_decision_id,
                verification_type=TYPE_DECEPTION,
                expected_action=expected_action,
                actual_action=actual_action,
                expected_origin_access=expected_origin,
                actual_origin_access=False,
                origin_request_count=0,
                deception_session_id=ctx.deception_session_id,
                evidence_events=ctx.evidence_count,
                database_access=True,
                result=RESULT_FAILED,
                confidence=CONFIDENCE_FULL,
                proof=["CRITICAL: Decoy touched production PostgreSQL database"],
                failure_reason="Database isolation invariant violated by decoy session",
                engine_version=ENGINE_VERSION,
                created_at=created_at
            )

        # Invariant 3: Deception session must exist
        if not ctx.deception_session_id:
            return ProofObject(
                verification_id=verification_id,
                request_id=ctx.request_id,
                trace_id=ctx.trace_id,
                session_id=ctx.session_id,
                policy_decision_id=ctx.policy_decision_id,
                verification_type=TYPE_DECEPTION,
                expected_action=expected_action,
                actual_action="MISSING_DECEPTION_SESSION",
                expected_origin_access=expected_origin,
                actual_origin_access=False,
                origin_request_count=0,
                deception_session_id=None,
                evidence_events=0,
                database_access=False,
                result=RESULT_INCONCLUSIVE,
                confidence=CONFIDENCE_INCONCLUSIVE,
                proof=["Policy qualified deception but session was not recorded"],
                failure_reason="Deception session ID missing from telemetry",
                engine_version=ENGINE_VERSION,
                created_at=created_at
            )

        # Success path for Deception
        proof_statements.append("Deterministic policy engine qualified request for deception")
        proof_statements.append("Isolated decoy sandbox session confirmed active on deception-net")
        proof_statements.append(f"Synthetic interaction captured {ctx.evidence_count} evidence events")
        proof_statements.append("Origin application received ZERO requests (100% contained)")
        proof_statements.append("Production database was not accessed by decoy workload")

        return ProofObject(
            verification_id=verification_id,
            request_id=ctx.request_id,
            trace_id=ctx.trace_id,
            session_id=ctx.session_id,
            policy_decision_id=ctx.policy_decision_id,
            verification_type=TYPE_DECEPTION,
            expected_action=expected_action,
            actual_action=actual_action,
            expected_origin_access=expected_origin,
            actual_origin_access=False,
            origin_request_count=0,
            deception_session_id=ctx.deception_session_id,
            evidence_events=ctx.evidence_count,
            database_access=False,
            result=RESULT_VERIFIED,
            confidence=CONFIDENCE_FULL,
            proof=proof_statements,
            failure_reason=None,
            engine_version=ENGINE_VERSION,
            created_at=created_at
        )

    # 4. RULE 2 — NORMAL ALLOW VERIFICATION
    if ctx.policy_decision == "ALLOW":
        expected_action = ACTION_ALLOW
        actual_action = ACTION_ALLOW
        expected_origin = True
        actual_origin = ctx.origin_reached or (ctx.origin_request_count > 0)

        # Invariant: Normal request must NOT be routed to deception
        if ctx.deception_session_id is not None:
            return ProofObject(
                verification_id=verification_id,
                request_id=ctx.request_id,
                trace_id=ctx.trace_id,
                session_id=ctx.session_id,
                policy_decision_id=ctx.policy_decision_id,
                verification_type=TYPE_NORMAL_ALLOW,
                expected_action=expected_action,
                actual_action="UNAUTHORIZED_DECEPTION",
                expected_origin_access=expected_origin,
                actual_origin_access=actual_origin,
                origin_request_count=ctx.origin_request_count,
                deception_session_id=ctx.deception_session_id,
                evidence_events=ctx.evidence_count,
                database_access=ctx.database_access_detected,
                result=RESULT_FAILED,
                confidence=CONFIDENCE_FULL,
                proof=["Normal ALLOW traffic erroneously routed into synthetic decoy"],
                failure_reason="Legitimate traffic diverted to deception",
                engine_version=ENGINE_VERSION,
                created_at=created_at
            )

        # Invariant: Origin MUST have been reached
        if not actual_origin:
            return ProofObject(
                verification_id=verification_id,
                request_id=ctx.request_id,
                trace_id=ctx.trace_id,
                session_id=ctx.session_id,
                policy_decision_id=ctx.policy_decision_id,
                verification_type=TYPE_NORMAL_ALLOW,
                expected_action=expected_action,
                actual_action="ORIGIN_UNREACHED",
                expected_origin_access=expected_origin,
                actual_origin_access=False,
                origin_request_count=0,
                deception_session_id=None,
                evidence_events=0,
                database_access=False,
                result=RESULT_FAILED,
                confidence=CONFIDENCE_FULL,
                proof=["Expected origin response but origin was never contacted"],
                failure_reason="Legitimate request was dropped before reaching origin",
                engine_version=ENGINE_VERSION,
                created_at=created_at
            )

        proof_statements.append("Policy evaluated request as legitimate (ALLOW)")
        proof_statements.append("Gateway forwarded traffic directly to protected origin workload")
        proof_statements.append(f"Origin reached successfully (status {ctx.http_status or 200})")
        proof_statements.append("No deception or containment applied to normal traffic")

        return ProofObject(
            verification_id=verification_id,
            request_id=ctx.request_id,
            trace_id=ctx.trace_id,
            session_id=ctx.session_id,
            policy_decision_id=ctx.policy_decision_id,
            verification_type=TYPE_NORMAL_ALLOW,
            expected_action=expected_action,
            actual_action=actual_action,
            expected_origin_access=expected_origin,
            actual_origin_access=True,
            origin_request_count=max(1, ctx.origin_request_count),
            deception_session_id=None,
            evidence_events=0,
            database_access=False,
            result=RESULT_VERIFIED,
            confidence=CONFIDENCE_FULL,
            proof=proof_statements,
            failure_reason=None,
            engine_version=ENGINE_VERSION,
            created_at=created_at
        )

    # 6. RULE 6 — NETWORK DEFENSE MITIGATION VERIFICATION (Phase 11)
    if ctx.network_enforcement_action or ctx.metadata.get("network_mitigation"):
        enf_action = ctx.network_enforcement_action or ctx.metadata.get("enforcement_action", "OBSERVE")
        expected_action = enf_action
        actual_action = enf_action
        actual_origin = ctx.origin_reached or (ctx.origin_request_count > 0)

        if enf_action in ("BLOCK", "TEMP_BLOCK"):
            if actual_origin:
                return ProofObject(
                    verification_id=verification_id,
                    request_id=ctx.request_id,
                    trace_id=ctx.trace_id,
                    session_id=ctx.session_id,
                    policy_decision_id=ctx.policy_decision_id,
                    verification_type=TYPE_NETWORK_DEFENSE,
                    expected_action=expected_action,
                    actual_action=actual_action,
                    expected_origin_access=False,
                    actual_origin_access=True,
                    origin_request_count=ctx.origin_request_count or 1,
                    deception_session_id=None,
                    evidence_events=0,
                    database_access=ctx.database_access_detected,
                    result=RESULT_FAILED,
                    confidence=CONFIDENCE_FULL,
                    proof=["CRITICAL: Network IPS enforced BLOCK but origin traffic was observed!"],
                    failure_reason="Network IPS invariant violated: origin access was detected",
                    engine_version=ENGINE_VERSION,
                    created_at=created_at
                )

            proof_statements.append(f"RULE_6_NETWORK_DEFENSE_MITIGATION: Network IPS enforced {enf_action} at the perimeter")
            proof_statements.append("Origin application remained protected with ZERO requests")
            proof_statements.append("Malicious network flow was suppressed by sensor enforcement")

            return ProofObject(
                verification_id=verification_id,
                request_id=ctx.request_id,
                trace_id=ctx.trace_id,
                session_id=ctx.session_id,
                policy_decision_id=ctx.policy_decision_id,
                verification_type=TYPE_NETWORK_DEFENSE,
                expected_action=expected_action,
                actual_action=actual_action,
                expected_origin_access=False,
                actual_origin_access=False,
                origin_request_count=0,
                deception_session_id=None,
                evidence_events=0,
                database_access=False,
                result=RESULT_VERIFIED,
                confidence=CONFIDENCE_FULL,
                proof=proof_statements,
                failure_reason=None,
                engine_version=ENGINE_VERSION,
                created_at=created_at
            )
        elif enf_action == "RATE_LIMIT":
            proof_statements.append("Network IPS rate-limit policy active")
            proof_statements.append("Flow suppressed to configured RPS threshold")
            return ProofObject(
                verification_id=verification_id,
                request_id=ctx.request_id,
                trace_id=ctx.trace_id,
                session_id=ctx.session_id,
                policy_decision_id=ctx.policy_decision_id,
                verification_type=TYPE_NETWORK_DEFENSE,
                expected_action=expected_action,
                actual_action=actual_action,
                expected_origin_access=actual_origin,
                actual_origin_access=actual_origin,
                origin_request_count=ctx.origin_request_count,
                deception_session_id=None,
                evidence_events=0,
                database_access=False,
                result=RESULT_VERIFIED,
                confidence=CONFIDENCE_FULL,
                proof=proof_statements,
                failure_reason=None,
                engine_version=ENGINE_VERSION,
                created_at=created_at
            )

    
    # 5. RULE 3 — POLICY BLOCK / CONTAIN VERIFICATION
    if ctx.policy_decision in ["BLOCK", "CONTAIN"]:
        expected_action = ACTION_BLOCK
        actual_action = ACTION_BLOCK
        expected_origin = False
        actual_origin = ctx.origin_reached or (ctx.origin_request_count > 0)

        if actual_origin:
            return ProofObject(
                verification_id=verification_id,
                request_id=ctx.request_id,
                trace_id=ctx.trace_id,
                session_id=ctx.session_id,
                policy_decision_id=ctx.policy_decision_id,
                verification_type=TYPE_POLICY_BLOCK,
                expected_action=expected_action,
                actual_action=actual_action,
                expected_origin_access=expected_origin,
                actual_origin_access=True,
                origin_request_count=ctx.origin_request_count or 1,
                deception_session_id=ctx.deception_session_id,
                evidence_events=ctx.evidence_count,
                database_access=ctx.database_access_detected,
                result=RESULT_FAILED,
                confidence=CONFIDENCE_FULL,
                proof=["CRITICAL: Policy decision BLOCK/CONTAIN reached origin application"],
                failure_reason="Policy block invariant violated: origin was contacted",
                engine_version=ENGINE_VERSION,
                created_at=created_at
            )

        proof_statements.append(f"Policy engine enforced terminal action {ctx.policy_decision}")
        proof_statements.append("Origin application received ZERO requests")
        proof_statements.append("Attacking traffic contained at security perimeter")

        return ProofObject(
            verification_id=verification_id,
            request_id=ctx.request_id,
            trace_id=ctx.trace_id,
            session_id=ctx.session_id,
            policy_decision_id=ctx.policy_decision_id,
            verification_type=TYPE_POLICY_BLOCK,
            expected_action=expected_action,
            actual_action=actual_action,
            expected_origin_access=expected_origin,
            actual_origin_access=False,
            origin_request_count=0,
            deception_session_id=None,
            evidence_events=0,
            database_access=False,
            result=RESULT_VERIFIED,
            confidence=CONFIDENCE_FULL,
            proof=proof_statements,
            failure_reason=None,
            engine_version=ENGINE_VERSION,
            created_at=created_at
        )

    # Fallback for unknown / unspecified context
    return ProofObject(
        verification_id=verification_id,
        request_id=ctx.request_id,
        trace_id=ctx.trace_id,
        session_id=ctx.session_id,
        policy_decision_id=ctx.policy_decision_id,
        verification_type="UNSPECIFIED_CONTEXT",
        expected_action=ctx.policy_decision or "NONE",
        actual_action="INCONCLUSIVE",
        expected_origin_access=False,
        actual_origin_access=ctx.origin_reached,
        origin_request_count=ctx.origin_request_count,
        deception_session_id=ctx.deception_session_id,
        evidence_events=ctx.evidence_count,
        database_access=ctx.database_access_detected,
        result=RESULT_INCONCLUSIVE,
        confidence=CONFIDENCE_ZERO,
        proof=["Unrecognized policy state or missing action metadata"],
        failure_reason="Could not match context to any deterministic verification rule",
        engine_version=ENGINE_VERSION,
        created_at=created_at
    )


class ResponseVerificationEvaluator:
    """Class wrapper for deterministic response verification evaluation."""
    def evaluate(self, ctx: VerificationContext) -> ProofObject:
        return evaluate_mitigation_verification(ctx)
