-- Seed initial system state
INSERT INTO system_events (service_name, event_type, severity, details)
VALUES 
    ('system', 'DATABASE_INITIALIZATION', 'INFO', '{"message": "AEGIS Ω database initialized successfully", "version": "0.1.0"}'),
    ('gateway', 'COMPONENT_INITIALIZED', 'INFO', '{"component": "aegis-gateway", "mode": "reverse-proxy"}');
