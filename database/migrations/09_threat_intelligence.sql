-- AEGIS Ω — Phase 10: Attacker Intelligence & Threat Context Schema
-- Adds source profiling, threat intelligence indicator store, network sensor observations, and deterministic MITRE ATT&CK mappings.

-- 1. Attacker / Source Profiles
CREATE TABLE IF NOT EXISTS source_profiles (
    source_ip VARCHAR(64) PRIMARY KEY,
    client_fingerprint VARCHAR(64),
    user_agent TEXT,
    is_private BOOLEAN DEFAULT FALSE,
    country VARCHAR(64),
    country_code VARCHAR(8),
    region VARCHAR(64),
    city VARCHAR(64),
    latitude NUMERIC(9, 6),
    longitude NUMERIC(9, 6),
    timezone VARCHAR(64),
    asn VARCHAR(32),
    organization TEXT,
    isp TEXT,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    request_count INT DEFAULT 1,
    session_count INT DEFAULT 0,
    reputation_status VARCHAR(32) DEFAULT 'UNKNOWN',
    reputation_provider VARCHAR(64),
    reputation_checked_at TIMESTAMP WITH TIME ZONE,
    raw_metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sp_source_ip ON source_profiles(source_ip);
CREATE INDEX IF NOT EXISTS idx_sp_fingerprint ON source_profiles(client_fingerprint);
CREATE INDEX IF NOT EXISTS idx_sp_last_seen ON source_profiles(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_sp_reputation ON source_profiles(reputation_status);
CREATE INDEX IF NOT EXISTS idx_sp_created_at ON source_profiles(created_at DESC);

-- 2. Provider-Neutral Threat Intelligence Indicators
CREATE TABLE IF NOT EXISTS threat_intelligence (
    indicator_id VARCHAR(64) PRIMARY KEY,
    indicator VARCHAR(255) NOT NULL,
    indicator_type VARCHAR(32) NOT NULL,
    provider VARCHAR(64),
    confidence NUMERIC(4, 2),
    category VARCHAR(64),
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    source_reference TEXT,
    raw_data JSONB DEFAULT '{}'::jsonb,
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ti_indicator ON threat_intelligence(indicator);
CREATE INDEX IF NOT EXISTS idx_ti_type ON threat_intelligence(indicator_type);
CREATE INDEX IF NOT EXISTS idx_ti_provider ON threat_intelligence(provider);
CREATE INDEX IF NOT EXISTS idx_ti_checked_at ON threat_intelligence(checked_at DESC);

-- 3. Network Reconnaissance & Sensor Observations (Zeek / Suricata)
CREATE TABLE IF NOT EXISTS network_observations (
    observation_id VARCHAR(64) PRIMARY KEY,
    sensor VARCHAR(32) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    source_ip VARCHAR(64) NOT NULL,
    destination_ip VARCHAR(64),
    destination_port INT,
    protocol VARCHAR(16),
    ports_observed TEXT,
    connection_count INT DEFAULT 1,
    scan_indicator VARCHAR(64),
    confidence NUMERIC(4, 2),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_no_source_ip ON network_observations(source_ip);
CREATE INDEX IF NOT EXISTS idx_no_sensor ON network_observations(sensor);
CREATE INDEX IF NOT EXISTS idx_no_event_type ON network_observations(event_type);
CREATE INDEX IF NOT EXISTS idx_no_created_at ON network_observations(created_at DESC);

-- 4. Deterministic MITRE ATT&CK Mappings
CREATE TABLE IF NOT EXISTS mitre_mappings (
    mapping_id VARCHAR(64) PRIMARY KEY,
    technique_id VARCHAR(32) NOT NULL,
    technique_name VARCHAR(128) NOT NULL,
    tactic VARCHAR(64) NOT NULL,
    evidence_event_ids JSONB DEFAULT '[]'::jsonb,
    confidence NUMERIC(4, 2) NOT NULL,
    reason TEXT NOT NULL,
    request_id VARCHAR(64),
    trace_id VARCHAR(64),
    source_ip VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mm_technique_id ON mitre_mappings(technique_id);
CREATE INDEX IF NOT EXISTS idx_mm_request_id ON mitre_mappings(request_id);
CREATE INDEX IF NOT EXISTS idx_mm_trace_id ON mitre_mappings(trace_id);
CREATE INDEX IF NOT EXISTS idx_mm_source_ip ON mitre_mappings(source_ip);
CREATE INDEX IF NOT EXISTS idx_mm_created_at ON mitre_mappings(created_at DESC);

-- Log migration in system_events
INSERT INTO system_events (service_name, event_type, severity, details)
VALUES 
    ('threat_intel_engine', 'ATTACKER_INTELLIGENCE_SUBSYSTEM_INITIALIZED', 'INFO', '{"version": "threat-intel-v1", "phase": 10}');
