-- AEGIS Ω — Phase 4: Normalized Security Events Schema
-- Unified Event Pipeline & Telemetry Store

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

-- Targeted indexes for SOC query performance & correlation
CREATE INDEX IF NOT EXISTS idx_sec_events_timestamp ON security_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sec_events_request_id ON security_events(request_id);
CREATE INDEX IF NOT EXISTS idx_sec_events_trace_id ON security_events(trace_id);
CREATE INDEX IF NOT EXISTS idx_sec_events_session_id ON security_events(session_id);
CREATE INDEX IF NOT EXISTS idx_sec_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_sec_events_event_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_sec_events_component ON security_events(component);
CREATE INDEX IF NOT EXISTS idx_sec_events_created_at ON security_events(created_at DESC);

-- Log migration in system_events
INSERT INTO system_events (service_name, event_type, severity, details)
VALUES 
    ('pipeline', 'SECURITY_EVENT_PIPELINE_INITIALIZED', 'INFO', '{"schema_version": "0.4.0", "phase": 4}');
