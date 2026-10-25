-- AEGIS Ω — Phase 3: Dedicated WAF Events Schema
-- Allows immediate recording of security events independently of access logs

-- Drop old foreign key constraint if present
ALTER TABLE IF EXISTS waf_events DROP CONSTRAINT IF EXISTS waf_events_request_id_fkey;

-- Enhance waf_events table structure
ALTER TABLE IF EXISTS waf_events 
    ADD COLUMN IF NOT EXISTS trace_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS action VARCHAR(32) DEFAULT 'BLOCK',
    ADD COLUMN IF NOT EXISTS severity_label VARCHAR(32) DEFAULT 'CRITICAL',
    ADD COLUMN IF NOT EXISTS engine VARCHAR(64) DEFAULT 'coraza-v3',
    ADD COLUMN IF NOT EXISTS http_method VARCHAR(16),
    ADD COLUMN IF NOT EXISTS uri TEXT,
    ADD COLUMN IF NOT EXISTS client_ip VARCHAR(64),
    ADD COLUMN IF NOT EXISTS anomaly_score INT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS raw_details JSONB DEFAULT '{}'::jsonb;

-- Indexes for SOC query performance
CREATE INDEX IF NOT EXISTS idx_waf_events_request_id ON waf_events(request_id);
CREATE INDEX IF NOT EXISTS idx_waf_events_trace_id ON waf_events(trace_id);
CREATE INDEX IF NOT EXISTS idx_waf_events_created_at ON waf_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_events_severity ON waf_events(severity_label);
CREATE INDEX IF NOT EXISTS idx_waf_events_action ON waf_events(action);

-- Log migration event in system_events
INSERT INTO system_events (service_name, event_type, severity, details)
VALUES 
    ('waf', 'WAF_ENGINE_INITIALIZED', 'INFO', '{"engine": "coraza-v3", "ruleset": "OWASP_CRS_v4.30.0", "phase": 3}');
