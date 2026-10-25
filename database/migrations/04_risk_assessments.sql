-- AEGIS Ω — Phase 5: Explainable Risk Engine Schema
-- Stores calculated deterministic risk assessments, severity levels, and explainable signal breakdowns

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

-- Targeted indexes for query performance & timeline drilldowns
CREATE INDEX IF NOT EXISTS idx_risk_req_id ON risk_assessments(request_id);
CREATE INDEX IF NOT EXISTS idx_risk_trace_id ON risk_assessments(trace_id);
CREATE INDEX IF NOT EXISTS idx_risk_severity ON risk_assessments(severity);
CREATE INDEX IF NOT EXISTS idx_risk_score ON risk_assessments(risk_score);
CREATE INDEX IF NOT EXISTS idx_risk_created_at ON risk_assessments(created_at DESC);

-- Log migration in system_events
INSERT INTO system_events (service_name, event_type, severity, details)
VALUES 
    ('risk_engine', 'RISK_ENGINE_INITIALIZED', 'INFO', '{"engine_version": "risk-engine-v1", "phase": 5}');
