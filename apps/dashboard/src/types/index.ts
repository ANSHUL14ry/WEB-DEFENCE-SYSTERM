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
    policy_engine?: ServiceStatus;
    deception_engine?: ServiceStatus;
    verification_engine?: ServiceStatus;
    honeypot: ServiceStatus;
  };
  metrics: {
    system_events_count: number;
    waf_events_count?: number;
    security_events_count?: number;
    risk_assessments_count?: number;
    agent_shield_assessments_count?: number;
    policy_decisions_count?: number;
    deception_sessions_count?: number;
    verifications_count?: number;
    verified_mitigations_count?: number;
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

export interface PolicyDecisionRecord {
  decision_id: string;
  event_id?: string | null;
  request_id: string;
  trace_id: string;
  session_id?: string | null;
  risk_assessment_id?: string | null;
  agent_shield_assessment_id?: string | null;
  risk_score?: number | null;
  risk_severity?: string | null;
  risk_confidence?: number | null;
  agent_shield_score?: number | null;
  agent_shield_severity?: string | null;
  agent_shield_confidence?: number | null;
  decision: 'ALLOW' | 'MONITOR' | 'RATE_LIMIT' | 'BLOCK' | 'CONTAIN' | 'DECEIVE_ELIGIBLE';
  decision_reason: string;
  reasons: string[];
  matched_rules: string[];
  terminal: boolean;
  policy_version: string;
  created_at: string;
  timestamp?: string;
}

export interface PolicyStats {
  total_decisions: number;
  allow_count: number;
  monitor_count: number;
  rate_limit_count: number;
  block_count: number;
  contain_count: number;
  deceive_eligible_count: number;
  recent_decisions: PolicyDecisionRecord[];
  disclaimer: string;
}

export interface DeceptionSession {
  session_id: string;
  request_id: string;
  trace_id: string;
  policy_decision_id?: string | null;
  source_identifier_hash: string;
  client_ip?: string | null;
  initial_risk_score?: number | null;
  initial_agent_shield_score?: number | null;
  entry_reason?: string | null;
  status: 'ACTIVE' | 'TERMINATED' | 'EXPIRED' | 'DENIED';
  interaction_count: number;
  evidence_count: number;
  origin_reached: boolean;
  started_at?: string | null;
  ended_at?: string | null;
  last_interaction_at?: string | null;
  expires_at?: string | null;
  created_at: string;
}

export interface DeceptionEvent {
  event_id: string;
  session_id: string;
  request_id: string;
  trace_id: string;
  event_type: string;
  route: string;
  method: string;
  source_identifier_hash?: string | null;
  response_status: number;
  endpoint_category?: string | null;
  user_agent_classification?: string | null;
  request_size: number;
  risk_context?: Record<string, any>;
  metadata?: Record<string, any>;
  created_at: string;
}

export interface DeceptionStats {
  total_sessions: number;
  active_sessions: number;
  terminated_sessions: number;
  expired_sessions: number;
  denied_sessions: number;
  total_evidence_events: number;
  recent_sessions: DeceptionSession[];
  recent_events: DeceptionEvent[];
  disclaimer: string;
}

export interface VerificationResultRecord {
  verification_id: string;
  request_id: string;
  trace_id: string;
  session_id?: string | null;
  policy_decision_id?: string | null;
  verification_type: string;
  expected_action: string;
  actual_action: string;
  expected_origin_access: boolean;
  actual_origin_access: boolean;
  origin_request_count: number;
  deception_session_id?: string | null;
  evidence_count: number;
  database_access_detected: boolean;
  result: 'VERIFIED' | 'FAILED' | 'INCONCLUSIVE';
  confidence: number;
  proof: string[];
  failure_reason?: string | null;
  engine_version: string;
  created_at: string;
}

export interface VerificationStats {
  total_verifications: number;
  verified_count: number;
  failed_count: number;
  inconclusive_count: number;
  verified_percentage: number;
  recent_verifications: VerificationResultRecord[];
  disclaimer: string;
}
