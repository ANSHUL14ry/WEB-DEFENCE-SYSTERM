-- AEGIS Ω — Phase 6: AgentShield Behavioral Automation Engine Schema
-- Stores deterministic behavioral analysis assessments, automation indicators, and attack sequence progressions.

CREATE TABLE IF NOT EXISTS agent_shield_assessments (
    assessment_id VARCHAR(64) PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL,
    trace_id VARCHAR(64) NOT NULL,
    session_id VARCHAR(64),
    agent_shield_score INT NOT NULL CHECK (agent_shield_score >= 0 AND agent_shield_score <= 100),
    severity VARCHAR(32) NOT NULL,
    confidence NUMERIC(4, 2) DEFAULT 1.00,
    signals JSONB DEFAULT '[]'::jsonb,
    attack_stages JSONB DEFAULT '[]'::jsonb,
    behavior_summary TEXT NOT NULL,
    engine_version VARCHAR(32) NOT NULL DEFAULT 'agentshield-v1',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Targeted indexes for high-speed correlation, timeline filtering & real-time dashboard lookups
CREATE INDEX IF NOT EXISTS idx_as_req_id ON agent_shield_assessments(request_id);
CREATE INDEX IF NOT EXISTS idx_as_trace_id ON agent_shield_assessments(trace_id);
CREATE INDEX IF NOT EXISTS idx_as_severity ON agent_shield_assessments(severity);
CREATE INDEX IF NOT EXISTS idx_as_score ON agent_shield_assessments(agent_shield_score);
CREATE INDEX IF NOT EXISTS idx_as_created_at ON agent_shield_assessments(created_at DESC);

-- Log migration in system_events
INSERT INTO system_events (service_name, event_type, severity, details)
VALUES 
    ('agent_shield', 'AGENT_SHIELD_INITIALIZED', 'INFO', '{"engine_version": "agentshield-v1", "phase": 6}');
