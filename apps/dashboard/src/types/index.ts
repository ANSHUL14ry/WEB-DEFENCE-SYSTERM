export interface ServiceStatus {
  status: 'operational' | 'healthy' | 'connected' | 'reachable' | 'degraded' | 'scheduled' | 'offline';
  type: string;
  role: string;
  mode?: string;
  version?: string;
}

export interface SecurityEvent {
  event_id: string;
  event_type: string;
  timestamp: string;
  request_id: string;
  trace_id: string;
  session_id?: string | null;
  source: {
    ip: string;
    user_agent?: string | null;
  };
  request: {
    method: string;
    uri: string;
  };
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  action: 'ALLOW' | 'BLOCK' | 'OBSERVED' | 'ALERT';
  component: string;
  status: string;
  metadata: Record<string, any>;
  created_at: string;
}

export interface EventStats {
  total_events: number;
  waf_blocks: number;
  high_severity: number;
  critical_severity: number;
  events_24h: number;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
}

export interface SystemStatusData {
  status: string;
  platform: string;
  tagline: string;
  version: string;
  request_id?: string;
  trace_id?: string;
  timestamp: string;
  services: {
    gateway: ServiceStatus;
    database: ServiceStatus;
    api: ServiceStatus;
    origin: ServiceStatus;
    waf: ServiceStatus;
    pipeline?: ServiceStatus;
    agent_shield: ServiceStatus;
    risk_engine: ServiceStatus;
    honeypot: ServiceStatus;
  };
  metrics: {
    system_events_count: number;
    waf_events_count?: number;
    security_events_count?: number;
    recent_events: Array<{
      service_name: string;
      event_type: string;
      severity: string;
      details: any;
      created_at: string;
    }>;
  };
}
