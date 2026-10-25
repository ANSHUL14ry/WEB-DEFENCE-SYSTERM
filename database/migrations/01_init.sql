-- AEGIS Ω Database Schema Initialization
-- Version: 0.3.0

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. System Events & Health
CREATE TABLE IF NOT EXISTS system_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    service_name VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    severity VARCHAR(32) DEFAULT 'INFO',
    details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Sessions (Tracked by IP / Cookie / Fingerprint)
CREATE TABLE IF NOT EXISTS security_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_token VARCHAR(128) UNIQUE NOT NULL,
    source_ip VARCHAR(64) NOT NULL,
    user_agent TEXT,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    risk_score INT DEFAULT 0,
    classification VARCHAR(64) DEFAULT 'UNKNOWN',
    status VARCHAR(32) DEFAULT 'ACTIVE'
);

-- 3. Traffic Logs (Gateway Ingest)
CREATE TABLE IF NOT EXISTS traffic_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id VARCHAR(64) UNIQUE NOT NULL,
    source_ip VARCHAR(64) NOT NULL,
    http_method VARCHAR(16) NOT NULL,
    endpoint TEXT NOT NULL,
    query_params TEXT,
    headers JSONB DEFAULT '{}'::jsonb,
    status_code INT,
    latency_ms INT,
    session_id UUID REFERENCES security_sessions(id) ON DELETE SET NULL,
    route_target VARCHAR(32) DEFAULT 'ORIGIN', -- ORIGIN, HONEYPOT, BLOCKED
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. WAF Events (Dedicated Security Event Store)
CREATE TABLE IF NOT EXISTS waf_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id VARCHAR(64) NOT NULL,
    trace_id VARCHAR(64),
    action VARCHAR(32) DEFAULT 'BLOCK',
    severity_label VARCHAR(32) DEFAULT 'CRITICAL',
    rule_id INT NOT NULL,
    rule_tag VARCHAR(128),
    rule_message TEXT,
    severity INT DEFAULT 0,
    engine VARCHAR(64) DEFAULT 'coraza-v3',
    http_method VARCHAR(16),
    uri TEXT,
    client_ip VARCHAR(64),
    anomaly_score INT DEFAULT 0,
    matched_data TEXT,
    raw_details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. Policy Decisions (Deterministic Policy Engine Store)
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

-- 6. Mitigation Verifications
CREATE TABLE IF NOT EXISTS mitigation_verifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id VARCHAR(64) NOT NULL,
    verification_status VARCHAR(32) NOT NULL, -- VERIFIED, FAILED, INCONCLUSIVE
    origin_impact_detected BOOLEAN DEFAULT FALSE,
    origin_request_count INT DEFAULT 0,
    evidence_summary JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 7. Decoy Interactions (Honeypot Logs)
CREATE TABLE IF NOT EXISTS decoy_interactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id VARCHAR(64) NOT NULL,
    decoy_endpoint VARCHAR(128) NOT NULL,
    http_method VARCHAR(16) NOT NULL,
    payload TEXT,
    synthetic_response_code INT DEFAULT 200,
    captured_artifacts JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 8. Normalized Security Events (Pipeline & Real-Time Telemetry Store)
CREATE TABLE IF NOT EXISTS security_events (
    event_id VARCHAR(64) PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    request_id VARCHAR(64) NOT NULL,
    trace_id VARCHAR(64) NOT NULL,
    session_id VARCHAR(64),
    severity VARCHAR(32) NOT NULL DEFAULT 'INFO',
    action VARCHAR(32) NOT NULL DEFAULT 'OBSERVED',
    component VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'DETECTED',
    source_ip VARCHAR(64),
    user_agent TEXT,
    method VARCHAR(16),
    uri TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 9. Risk Assessments (Explainable Risk Engine Store)
CREATE TABLE IF NOT EXISTS risk_assessments (
    assessment_id VARCHAR(64) PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL,
    trace_id VARCHAR(64) NOT NULL,
    session_id VARCHAR(64),
    risk_score INT NOT NULL,
    severity VARCHAR(32) NOT NULL,
    confidence NUMERIC(4, 2) DEFAULT 1.00,
    signals JSONB DEFAULT '[]'::jsonb,
    engine_version VARCHAR(32) NOT NULL DEFAULT 'risk-engine-v1',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 10. AgentShield Assessments (Behavioral Automation & Sequence Detection Store)
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



-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_traffic_req_id ON traffic_logs(request_id);
CREATE INDEX IF NOT EXISTS idx_traffic_source_ip ON traffic_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_created_at ON traffic_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_events_request_id ON waf_events(request_id);
CREATE INDEX IF NOT EXISTS idx_waf_events_trace_id ON waf_events(trace_id);
CREATE INDEX IF NOT EXISTS idx_waf_events_created_at ON waf_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_rule_id ON waf_events(rule_id);
CREATE INDEX IF NOT EXISTS idx_waf_severity ON waf_events(severity_label);
CREATE INDEX IF NOT EXISTS idx_waf_action ON waf_events(action);
CREATE INDEX IF NOT EXISTS idx_verif_status ON mitigation_verifications(verification_status);
CREATE INDEX IF NOT EXISTS idx_sec_events_timestamp ON security_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sec_events_request_id ON security_events(request_id);
CREATE INDEX IF NOT EXISTS idx_sec_events_trace_id ON security_events(trace_id);
CREATE INDEX IF NOT EXISTS idx_sec_events_session_id ON security_events(session_id);
CREATE INDEX IF NOT EXISTS idx_sec_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_sec_events_event_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_sec_events_component ON security_events(component);
CREATE INDEX IF NOT EXISTS idx_sec_events_created_at ON security_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_req_id ON risk_assessments(request_id);
CREATE INDEX IF NOT EXISTS idx_risk_trace_id ON risk_assessments(trace_id);
CREATE INDEX IF NOT EXISTS idx_risk_severity ON risk_assessments(severity);
CREATE INDEX IF NOT EXISTS idx_risk_score ON risk_assessments(risk_score);
CREATE INDEX IF NOT EXISTS idx_risk_created_at ON risk_assessments(created_at DESC);

-- Phase 8: Adaptive Deception & Isolated Honeypot Schema
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

-- Phase 9: Response Verification & Telemetry Proof Schema
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
