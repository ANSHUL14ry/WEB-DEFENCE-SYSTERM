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
            """))
            conn.commit()
            logger.info("Security events, risk assessments, AgentShield, Policy Decisions, and Deception tables and indexes verified.")
    except Exception as e:
        logger.error(f"Failed to initialize database tables: {e}")

