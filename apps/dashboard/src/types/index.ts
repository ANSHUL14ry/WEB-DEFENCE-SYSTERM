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

export interface RiskSignal {
  name: string;
  score: number;
  reason: string;
}

export interface RiskAssessment {
  assessment_id: string;
  request_id: string;
  trace_id: string;
  session_id?: string | null;
  risk_score: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number;
  signals: RiskSignal[];
  engine_version: string;
  created_at: string;
}

export interface RiskStats {
  total_assessments: number;
  average_risk_score: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  latest_assessments: RiskAssessment[];
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
    risk_assessments_count?: number;
    agent_shield_assessments_count?: number;
    recent_events: Array<{
      service_name: string;
      event_type: string;
      severity: string;
      details: any;
      created_at: string;
    }>;
  };
}

export interface AgentShieldSignal {
  name: string;
  score: number;
  evidence: Record<string, any>;
  reason: string;
}

export interface AttackStageItem {
  stage: string;
  timestamp: string;
  method: string;
  uri: string;
  detail: string;
}

export interface AgentShieldAssessment {
  assessment_id: string;
  request_id: string;
  trace_id: string;
  session_id?: string | null;
  agent_shield_score: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number;
  signals: AgentShieldSignal[];
  attack_stages: string[];
  attack_timeline?: AttackStageItem[];
  behavior_summary: string;
  engine_version: string;
  disclaimer: string;
  created_at: string;
  timestamp?: string;
}

export interface AgentShieldStats {
  total_assessments: number;
  average_agent_shield_score: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  recent_assessments: AgentShieldAssessment[];
  disclaimer: string;
}
