-- AEGIS Ω — Phase 7: Deterministic Policy Engine Schema
-- Stores policy decisions, decision reasons, matched rule chains, and terminal status.

DROP TABLE IF EXISTS policy_decisions CASCADE;

CREATE TABLE IF NOT EXISTS policy_decisions (
    decision_id VARCHAR(64) PRIMARY KEY,
    event_id VARCHAR(64),
    request_id VARCHAR(64) NOT NULL,
    trace_id VARCHAR(64) NOT NULL,
    session_id VARCHAR(64),
    risk_assessment_id VARCHAR(64),
    agent_shield_assessment_id VARCHAR(64),
    risk_score INT,
    risk_severity VARCHAR(32),
    risk_confidence NUMERIC(4, 2),
    agent_shield_score INT,
    agent_shield_severity VARCHAR(32),
    agent_shield_confidence NUMERIC(4, 2),
    decision VARCHAR(32) NOT NULL,
    decision_reason TEXT NOT NULL,
    reasons JSONB DEFAULT '[]'::jsonb,
    matched_rules JSONB DEFAULT '[]'::jsonb,
    terminal BOOLEAN NOT NULL DEFAULT FALSE,
    policy_version VARCHAR(32) NOT NULL DEFAULT 'policy-v1',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Targeted indexes for high-speed policy resolution & SOC dashboard lookups
CREATE INDEX IF NOT EXISTS idx_pd_req_id ON policy_decisions(request_id);
CREATE INDEX IF NOT EXISTS idx_pd_trace_id ON policy_decisions(trace_id);
CREATE INDEX IF NOT EXISTS idx_pd_decision ON policy_decisions(decision);
CREATE INDEX IF NOT EXISTS idx_pd_risk_sev ON policy_decisions(risk_severity);
CREATE INDEX IF NOT EXISTS idx_pd_as_sev ON policy_decisions(agent_shield_severity);
CREATE INDEX IF NOT EXISTS idx_pd_created_at ON policy_decisions(created_at DESC);

-- Log migration in system_events
INSERT INTO system_events (service_name, event_type, severity, details)
VALUES 
    ('policy_engine', 'POLICY_ENGINE_INITIALIZED', 'INFO', '{"policy_version": "policy-v1", "phase": 7}');
