-- AEGIS Ω — Phase 8: Adaptive Deception & Isolated Honeypot Schema
-- Stores deception sessions, interaction timelines, decoy evidence, and isolation metrics.

CREATE TABLE IF NOT EXISTS deception_sessions (
    session_id VARCHAR(64) PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL,
    trace_id VARCHAR(64) NOT NULL,
    policy_decision_id VARCHAR(64),
    source_identifier_hash VARCHAR(64) NOT NULL,
    client_ip VARCHAR(64),
    initial_risk_score INT,
    initial_agent_shield_score INT,
    entry_reason TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    interaction_count INT DEFAULT 0,
    evidence_count INT DEFAULT 0,
    origin_reached BOOLEAN NOT NULL DEFAULT FALSE,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP WITH TIME ZONE,
    last_interaction_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ds_session_id ON deception_sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_ds_request_id ON deception_sessions(request_id);
CREATE INDEX IF NOT EXISTS idx_ds_trace_id ON deception_sessions(trace_id);
CREATE INDEX IF NOT EXISTS idx_ds_policy_id ON deception_sessions(policy_decision_id);
CREATE INDEX IF NOT EXISTS idx_ds_status ON deception_sessions(status);
CREATE INDEX IF NOT EXISTS idx_ds_created_at ON deception_sessions(created_at DESC);

CREATE TABLE IF NOT EXISTS deception_events (
    event_id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL REFERENCES deception_sessions(session_id) ON DELETE CASCADE,
    request_id VARCHAR(64) NOT NULL,
    trace_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    route VARCHAR(255) NOT NULL,
    method VARCHAR(16) NOT NULL,
    source_identifier_hash VARCHAR(64),
    response_status INT DEFAULT 200,
    endpoint_category VARCHAR(64),
    user_agent_classification VARCHAR(64),
    request_size INT DEFAULT 0,
    risk_context JSONB DEFAULT '{}'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_de_event_id ON deception_events(event_id);
CREATE INDEX IF NOT EXISTS idx_de_session_id ON deception_events(session_id);
CREATE INDEX IF NOT EXISTS idx_de_request_id ON deception_events(request_id);
CREATE INDEX IF NOT EXISTS idx_de_trace_id ON deception_events(trace_id);
CREATE INDEX IF NOT EXISTS idx_de_event_type ON deception_events(event_type);
CREATE INDEX IF NOT EXISTS idx_de_created_at ON deception_events(created_at DESC);

-- Log migration in system_events
INSERT INTO system_events (service_name, event_type, severity, details)
VALUES 
    ('deception_engine', 'DECEPTION_SUBSYSTEM_INITIALIZED', 'INFO', '{"version": "deception-v1", "phase": 8}');
