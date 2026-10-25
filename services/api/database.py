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
            """))
            conn.commit()
            logger.info("Security events and risk assessments tables and indexes verified.")
    except Exception as e:
        logger.error(f"Failed to initialize database tables: {e}")

