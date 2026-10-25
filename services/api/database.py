import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from config import settings

logger = logging.getLogger("aegis.database")

engine = create_engine(
    settings.sqlalchemy_database_url,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def check_db_connection() -> bool:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return False

def init_db():
    """Ensure all required tables and indexes exist on application startup."""
    try:
        with engine.connect() as conn:
            conn.execute(text("""
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

                CREATE INDEX IF NOT EXISTS idx_sec_events_timestamp ON security_events(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_sec_events_request_id ON security_events(request_id);
                CREATE INDEX IF NOT EXISTS idx_sec_events_trace_id ON security_events(trace_id);
                CREATE INDEX IF NOT EXISTS idx_sec_events_session_id ON security_events(session_id);
                CREATE INDEX IF NOT EXISTS idx_sec_events_severity ON security_events(severity);
                CREATE INDEX IF NOT EXISTS idx_sec_events_event_type ON security_events(event_type);
                CREATE INDEX IF NOT EXISTS idx_sec_events_component ON security_events(component);
                CREATE INDEX IF NOT EXISTS idx_sec_events_created_at ON security_events(created_at DESC);

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

                CREATE INDEX IF NOT EXISTS idx_risk_req_id ON risk_assessments(request_id);
                CREATE INDEX IF NOT EXISTS idx_risk_trace_id ON risk_assessments(trace_id);
                CREATE INDEX IF NOT EXISTS idx_risk_severity ON risk_assessments(severity);
                CREATE INDEX IF NOT EXISTS idx_risk_score ON risk_assessments(risk_score);
                CREATE INDEX IF NOT EXISTS idx_risk_created_at ON risk_assessments(created_at DESC);

                -- Phase 6: AgentShield assessments table
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

                CREATE INDEX IF NOT EXISTS idx_as_req_id ON agent_shield_assessments(request_id);
                CREATE INDEX IF NOT EXISTS idx_as_trace_id ON agent_shield_assessments(trace_id);
                CREATE INDEX IF NOT EXISTS idx_as_severity ON agent_shield_assessments(severity);
                CREATE INDEX IF NOT EXISTS idx_as_score ON agent_shield_assessments(agent_shield_score);
                CREATE INDEX IF NOT EXISTS idx_as_created_at ON agent_shield_assessments(created_at DESC);

                -- Phase 7: Policy decisions table
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

                CREATE INDEX IF NOT EXISTS idx_pd_req_id ON policy_decisions(request_id);
                CREATE INDEX IF NOT EXISTS idx_pd_trace_id ON policy_decisions(trace_id);
                CREATE INDEX IF NOT EXISTS idx_pd_decision ON policy_decisions(decision);
                CREATE INDEX IF NOT EXISTS idx_pd_risk_sev ON policy_decisions(risk_severity);
                CREATE INDEX IF NOT EXISTS idx_pd_as_sev ON policy_decisions(agent_shield_severity);
                CREATE INDEX IF NOT EXISTS idx_pd_created_at ON policy_decisions(created_at DESC);

                -- Phase 8: Deception sessions and events tables
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

                -- Phase 9: Verification results table
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

                -- Phase 10: Attacker Intelligence, Source Profiles, Network Recon, & MITRE Tables
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
            """))
            conn.commit()
            logger.info("Security events, risk assessments, AgentShield, Policy Decisions, Deception, Verification, and Attacker Intelligence tables and indexes verified.")
    except Exception as e:
        logger.error(f"Failed to initialize database tables: {e}")

