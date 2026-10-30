-- AEGIS Ω — Phase 11: Real Network Defense — IDS/IPS + Network Behavior Correlation
-- Adds Suricata EVE event store, IPS enforcement state, network anomaly tracking, and unified attack stories.

-- 1. Normalized Network Events (Suricata EVE JSON / Zeek / Sensor Telemetry)
CREATE TABLE IF NOT EXISTS network_events (
    event_id VARCHAR(64) PRIMARY KEY,
    sensor VARCHAR(32) NOT NULL DEFAULT 'suricata',
    sensor_event_id VARCHAR(64),
    event_type VARCHAR(32) NOT NULL, -- alert, flow, http, dns, tls, anomaly
    source_ip VARCHAR(64) NOT NULL,
    destination_ip VARCHAR(64),
    source_port INT,
    destination_port INT,
    protocol VARCHAR(16),
    severity VARCHAR(32) NOT NULL DEFAULT 'INFO', -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    signature VARCHAR(255),
    signature_id INT,
    category VARCHAR(128),
    raw_reference TEXT,
    request_id VARCHAR(64),
    trace_id VARCHAR(64),
    network_risk_score INT DEFAULT 0,
    mitre_technique_id VARCHAR(32),
    enforcement_action VARCHAR(32) DEFAULT 'OBSERVE',
    raw_metadata JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ne_source_ip ON network_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_ne_sensor ON network_events(sensor);
CREATE INDEX IF NOT EXISTS idx_ne_event_type ON network_events(event_type);
CREATE INDEX IF NOT EXISTS idx_ne_severity ON network_events(severity);
CREATE INDEX IF NOT EXISTS idx_ne_timestamp ON network_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ne_request_id ON network_events(request_id);
CREATE INDEX IF NOT EXISTS idx_ne_trace_id ON network_events(trace_id);
CREATE INDEX IF NOT EXISTS idx_ne_created_at ON network_events(created_at DESC);

-- 2. Network IPS Enforcements (OBSERVE, RATE_LIMIT, TEMP_BLOCK, BLOCK)
CREATE TABLE IF NOT EXISTS network_enforcements (
    enforcement_id VARCHAR(64) PRIMARY KEY,
    source_ip VARCHAR(64) NOT NULL,
    action VARCHAR(32) NOT NULL, -- OBSERVE, RATE_LIMIT, TEMP_BLOCK, BLOCK
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, EXPIRED, RELEASED
    rate_limit_rps INT,
    duration_seconds INT,
    reason TEXT NOT NULL,
    trigger_event_id VARCHAR(64),
    network_risk_score INT,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    released_at TIMESTAMP WITH TIME ZONE,
    audit_metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_n_enf_source_ip ON network_enforcements(source_ip);
CREATE INDEX IF NOT EXISTS idx_n_enf_action ON network_enforcements(action);
CREATE INDEX IF NOT EXISTS idx_n_enf_status ON network_enforcements(status);
CREATE INDEX IF NOT EXISTS idx_n_enf_expires_at ON network_enforcements(expires_at);
CREATE INDEX IF NOT EXISTS idx_n_enf_created_at ON network_enforcements(created_at DESC);

-- 3. Network Anomaly & DDoS Baseline Tracking
CREATE TABLE IF NOT EXISTS network_anomalies (
    anomaly_id VARCHAR(64) PRIMARY KEY,
    anomaly_type VARCHAR(64) NOT NULL, -- BURST_RATE, FLOW_SPIKE, DEST_CONCENTRATION, PORT_SCAN, PROTOCOL_ANOMALY
    severity VARCHAR(32) NOT NULL, -- NORMAL, ELEVATED, ANOMALOUS, CRITICAL
    source_ip VARCHAR(64),
    destination_ip VARCHAR(64),
    metric_name VARCHAR(64),
    current_value NUMERIC(10, 2),
    baseline_value NUMERIC(10, 2),
    deviation_factor NUMERIC(6, 2),
    mitigation_recommendation VARCHAR(64), -- LOCAL_MITIGATION_ACTIVE, UPSTREAM_DDOS_RECOMMENDED, NONE
    details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_na_type ON network_anomalies(anomaly_type);
CREATE INDEX IF NOT EXISTS idx_na_severity ON network_anomalies(severity);
CREATE INDEX IF NOT EXISTS idx_na_source_ip ON network_anomalies(source_ip);
CREATE INDEX IF NOT EXISTS idx_na_created_at ON network_anomalies(created_at DESC);

-- 4. Unified Attack Stories (Network -> Web -> Agent -> Policy -> Deception -> Verification)
CREATE TABLE IF NOT EXISTS attack_stories (
    story_id VARCHAR(64) PRIMARY KEY, -- e.g. AEG-1042
    source_ip VARCHAR(64) NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    stages JSONB DEFAULT '[]'::jsonb,
    timeline JSONB DEFAULT '[]'::jsonb,
    highest_risk_score INT DEFAULT 0,
    highest_agentshield_score INT DEFAULT 0,
    highest_network_risk_score INT DEFAULT 0,
    final_policy_decision VARCHAR(32),
    origin_untouched BOOLEAN DEFAULT TRUE,
    mitigation_verified BOOLEAN DEFAULT FALSE,
    status VARCHAR(32) DEFAULT 'ACTIVE',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_as_story_id ON attack_stories(story_id);
CREATE INDEX IF NOT EXISTS idx_as_story_source_ip ON attack_stories(source_ip);
CREATE INDEX IF NOT EXISTS idx_as_story_status ON attack_stories(status);
CREATE INDEX IF NOT EXISTS idx_as_story_created_at ON attack_stories(created_at DESC);

-- System event record
INSERT INTO system_events (service_name, event_type, severity, details)
VALUES 
    ('network_defense', 'NETWORK_DEFENSE_SUBSYSTEM_INITIALIZED', 'INFO', '{"version": "netdef-v1", "phase": 11}');
