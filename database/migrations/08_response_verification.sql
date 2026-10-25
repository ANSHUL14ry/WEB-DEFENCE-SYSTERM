-- AEGIS Ω — Phase 9: Response Verification & Telemetry Proof Schema
-- Stores verification results, origin protection receipts, decoy isolation proofs, and telemetry audits.

CREATE TABLE IF NOT EXISTS verification_results (
    verification_id VARCHAR(64) PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL,
    trace_id VARCHAR(64) NOT NULL,
    session_id VARCHAR(64),
    policy_decision_id VARCHAR(64),
    verification_type VARCHAR(64) NOT NULL,
    expected_action VARCHAR(32) NOT NULL,
    actual_action VARCHAR(32) NOT NULL,
    expected_origin_access BOOLEAN NOT NULL,
    actual_origin_access BOOLEAN NOT NULL,
    origin_request_count INT NOT NULL DEFAULT 0,
    deception_session_id VARCHAR(64),
    evidence_count INT NOT NULL DEFAULT 0,
    database_access_detected BOOLEAN NOT NULL DEFAULT FALSE,
    result VARCHAR(32) NOT NULL,
    confidence NUMERIC(4, 2) DEFAULT 1.00,
    proof JSONB DEFAULT '[]'::jsonb,
    failure_reason TEXT,
    engine_version VARCHAR(32) NOT NULL DEFAULT 'verification-v1',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vr_verification_id ON verification_results(verification_id);
CREATE INDEX IF NOT EXISTS idx_vr_request_id ON verification_results(request_id);
CREATE INDEX IF NOT EXISTS idx_vr_trace_id ON verification_results(trace_id);
CREATE INDEX IF NOT EXISTS idx_vr_session_id ON verification_results(session_id);
CREATE INDEX IF NOT EXISTS idx_vr_policy_id ON verification_results(policy_decision_id);
CREATE INDEX IF NOT EXISTS idx_vr_result ON verification_results(result);
CREATE INDEX IF NOT EXISTS idx_vr_created_at ON verification_results(created_at DESC);

-- Log migration in system_events
INSERT INTO system_events (service_name, event_type, severity, details)
VALUES 
    ('verification_engine', 'VERIFICATION_SUBSYSTEM_INITIALIZED', 'INFO', '{"version": "verification-v1", "phase": 9}');
