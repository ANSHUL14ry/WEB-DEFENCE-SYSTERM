export interface ServiceStatus {
  status: 'operational' | 'healthy' | 'connected' | 'reachable' | 'degraded' | 'scheduled' | 'offline';
  type: string;
  role: string;
}

export interface SystemStatusData {
  status: string;
  platform: string;
  tagline: string;
  version: string;
  timestamp: string;
  services: {
    gateway: ServiceStatus;
    database: ServiceStatus;
    api: ServiceStatus;
    origin: ServiceStatus;
    waf: ServiceStatus;
    agent_shield: ServiceStatus;
    risk_engine: ServiceStatus;
    honeypot: ServiceStatus;
  };
  metrics: {
    system_events_count: number;
    recent_events: Array<{
      service_name: string;
      event_type: string;
      severity: string;
      details: any;
      created_at: string;
    }>;
  };
}
