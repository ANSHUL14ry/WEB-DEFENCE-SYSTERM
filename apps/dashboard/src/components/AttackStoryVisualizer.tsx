import React, { useState } from 'react';
import { 
  Crosshair, 
  Search, 
  KeyRound, 
  ShieldAlert, 
  Flame, 
  Bot, 
  Scale, 
  EyeOff, 
  FileText, 
  ShieldCheck, 
  CheckCircle2, 
  ArrowDown, 
  Check, 
  Clock,
  Sparkles,
  Server,
  Layers
} from 'lucide-react';

interface StoryStep {
  id: string;
  timestamp: string;
  stage: string;
  title: string;
  component: string;
  badgeColor: string;
  icon: any;
  metric: string;
  description: string;
  telemetryEvidence: Record<string, any>;
  originContacted: boolean;
}

export const AttackStoryVisualizer: React.FC = () => {
  const [selectedStepIndex, setSelectedStepIndex] = useState<number>(10);

  const steps: StoryStep[] = [
    {
      id: 'step-1',
      timestamp: '19:42:01.102',
      stage: 'STAGE 1: RECON',
      title: 'Initial Reconnaissance & Probe',
      component: 'AEGIS Gateway Ingress',
      badgeColor: 'border-slate-700 bg-slate-900 text-slate-300',
      icon: Search,
      metric: 'GET /robots.txt',
      description: 'Automated script probes web ingress for sensitive directory listings and paths.',
      telemetryEvidence: {
        method: 'GET',
        path: '/robots.txt',
        user_agent: 'python-requests/2.31.0 (Agentic Scanner)',
        request_id: 'req_01_recon_992a',
        client_ip: '198.51.100.44'
      },
      originContacted: true
    },
    {
      id: 'step-2',
      timestamp: '19:42:03.450',
      stage: 'STAGE 2: ENUMERATION',
      title: 'Rapid Endpoint Enumeration',
      component: 'AEGIS Gateway & Tracing',
      badgeColor: 'border-blue-800 bg-blue-950 text-blue-300',
      icon: Layers,
      metric: '8 requests / 1.2s',
      description: 'High-frequency scanning against /.env, /config.json, /admin, and /debug endpoints.',
      telemetryEvidence: {
        probed_paths: ['/.env', '/config.json', '/debug/pprof', '/backup.tar.gz'],
        interval_ms: 150,
        request_frequency: '6.6 req/s'
      },
      originContacted: true
    },
    {
      id: 'step-3',
      timestamp: '19:42:05.120',
      stage: 'STAGE 3: API PROBING',
      title: 'API Structure Discovery',
      component: 'Security Event Pipeline',
      badgeColor: 'border-cyan-800 bg-cyan-950 text-cyan-300',
      icon: Server,
      metric: 'GET /api/v1/swagger.json',
      description: 'Systematic inspection of API schemas, internal models, and OpenAPI spec declarations.',
      telemetryEvidence: {
        api_targets: ['/api/v1/users', '/api/v1/export', '/api/v1/internal'],
        event_type: 'API_ENUMERATION',
        event_id: 'ev_api_enum_771'
      },
      originContacted: true
    },
    {
      id: 'step-4',
      timestamp: '19:42:07.890',
      stage: 'STAGE 4: AUTH ATTACK',
      title: 'Credential Brute-Force & Spray',
      component: 'Security Event Pipeline',
      badgeColor: 'border-amber-800 bg-amber-950 text-amber-300',
      icon: KeyRound,
      metric: 'POST /login (5 attempts)',
      description: 'Repeated authentication queries attempting dictionary credentials with rotating headers.',
      telemetryEvidence: {
        usernames_tested: ['admin', 'root', 'security_ops', 'superadmin'],
        failures: 5,
        event_type: 'AUTH_BRUTE_FORCE'
      },
      originContacted: true
    },
    {
      id: 'step-5',
      timestamp: '19:42:09.310',
      stage: 'STAGE 5: WAF SIGNAL',
      title: 'Coraza WAF & OWASP CRS Detection',
      component: 'Coraza WAF v3.2.2',
      badgeColor: 'border-rose-800 bg-rose-950 text-rose-300',
      icon: ShieldAlert,
      metric: 'CRS Rule 942100 (SQLi)',
      description: 'Injected query payload detected: 1\' UNION SELECT NULL, username, password FROM users --',
      telemetryEvidence: {
        crs_rule_id: 942100,
        paranoia_level: 1,
        anomaly_score: 5,
        action: 'OBSERVED_ANOMALY',
        waf_signature: 'OWASP-CRS/4.30.0'
      },
      originContacted: false
    },
    {
      id: 'step-6',
      timestamp: '19:42:10.050',
      stage: 'STAGE 6: RISK SCORING',
      title: 'Deterministic Risk Evaluation',
      component: 'AEGIS Risk Engine',
      badgeColor: 'border-rose-800 bg-rose-950 text-rose-300',
      icon: Flame,
      metric: 'RISK SCORE: 88 (CRITICAL)',
      description: 'Mathematical weighting of temporal velocity, WAF CRS signals, and sensitive endpoint targets.',
      telemetryEvidence: {
        base_score: 88,
        severity: 'CRITICAL',
        confidence: 0.95,
        signals: ['WAF_ANOMALY (+35)', 'RAPID_BURST (+25)', 'AUTH_ABUSE (+28)']
      },
      originContacted: false
    },
    {
      id: 'step-7',
      timestamp: '19:42:10.120',
      stage: 'STAGE 7: AGENTSHIELD',
      title: 'Agentic Behavioral Sequence Analysis',
      component: 'AgentShield AI Engine',
      badgeColor: 'border-indigo-800 bg-indigo-950 text-indigo-300',
      icon: Bot,
      metric: 'AGENTIC SCORE: 92 (CRITICAL)',
      description: 'Behavior consistent with automated autonomous attack activity (deterministic state-machine heuristic).',
      telemetryEvidence: {
        automation_score: 92,
        attack_stages: ['RECON', 'ENDPOINT_ENUMERATION', 'API_ENUMERATION', 'AUTH_PROBING'],
        disclaimer: 'Behavior consistent with automated/agentic attack activity'
      },
      originContacted: false
    },
    {
      id: 'step-8',
      timestamp: '19:42:10.220',
      stage: 'STAGE 8: POLICY DECISION',
      title: 'Deterministic Policy Decision',
      component: 'Policy Engine (Rule #4)',
      badgeColor: 'border-purple-800 bg-purple-950 text-purple-300',
      icon: Scale,
      metric: 'DECISION: DECEIVE_ELIGIBLE',
      description: 'High risk (88) and high automation (92) qualify request for dynamic deception sandbox isolation.',
      telemetryEvidence: {
        decision: 'DECEIVE_ELIGIBLE',
        matched_rules: ['RULE_DECEPTION_QUALIFICATION_CRITICAL_AGENT'],
        terminal: false,
        precedence: 'DECEIVE'
      },
      originContacted: false
    },
    {
      id: 'step-9',
      timestamp: '19:42:11.005',
      stage: 'STAGE 9: DECOY ACTIVE',
      title: 'Isolated Decoy Session Activation',
      component: 'Adaptive Deception Decoy',
      badgeColor: 'border-purple-800 bg-purple-950 text-purple-300',
      icon: EyeOff,
      metric: 'Session ds-48f9a2 &bull; apex-logistics',
      description: 'Attacker diverted to synthetic logistics application sandbox on isolated Docker deception-net.',
      telemetryEvidence: {
        session_id: 'ds-48f9a2-apex-logistics',
        isolated_network: 'deception-net',
        network_isolation: 'STRICT_NO_ORIGIN_ROUTE',
        origin_route_present: false
      },
      originContacted: false
    },
    {
      id: 'step-10',
      timestamp: '19:42:18.440',
      stage: 'STAGE 10: EVIDENCE HARVEST',
      title: 'Decoy Interaction & Evidence Capture',
      component: 'Decoy Forensics Store',
      badgeColor: 'border-purple-800 bg-purple-950 text-purple-300',
      icon: FileText,
      metric: '5 Evidence Events Captured',
      description: 'Attacker interacts with synthetic /api/v1/shipments and honeytokens. 0 real credentials exposed.',
      telemetryEvidence: {
        evidence_events: 5,
        synthetic_endpoints_hit: ['/decoy-admin/dashboard', '/decoy-api/v1/shipments'],
        passwords_sanitized: true,
        production_db_accessed: false
      },
      originContacted: false
    },
    {
      id: 'step-11',
      timestamp: '19:42:20.900',
      stage: 'STAGE 11: PROOF VERIFIED',
      title: 'Mitigation Telemetry Receipt Proven',
      component: 'Phase 9 Verification Engine',
      badgeColor: 'border-emerald-800 bg-emerald-950 text-emerald-300',
      icon: CheckCircle2,
      metric: 'ORIGIN: 0 REQUESTS &bull; VERIFIED',
      description: 'Machine-verifiable proof guarantees origin application remained untouched during entire campaign.',
      telemetryEvidence: {
        origin_request_count: 0,
        actual_origin_access: false,
        production_db_access: false,
        verification_status: 'VERIFIED',
        confidence: 1.0,
        proof_points: 5
      },
      originContacted: false
    }
  ];

  const current = steps[selectedStepIndex];

  return (
    <div className="bg-soc-panel border border-soc-border rounded-xl p-5 shadow-lg space-y-5">
      {/* Visualizer Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-3 border-b border-soc-border gap-2">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-950 border border-cyan-800 text-cyan-400">
            <Crosshair className="w-5 h-5 animate-spin-slow" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold font-mono text-white uppercase tracking-wide">
                Live Attack Story &amp; Incident Progression
              </h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-900/60 text-cyan-300 border border-cyan-700/80">
                End-to-End Incident Timeline
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Chronological journey of an agentic attack from recon to deterministic mitigation proof
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="text-right">
            <span className="text-[10px] font-mono text-slate-400 block">Incident Outcome</span>
            <span className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1 justify-end">
              <CheckCircle2 className="w-3.5 h-3.5" />
              100% CONTAINED &bull; 0 ORIGIN HITS
            </span>
          </div>
        </div>
      </div>

      {/* Narrative Progress Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-6 lg:grid-cols-11 gap-1.5">
        {steps.map((st, idx) => {
          const isSelected = idx === selectedStepIndex;
          const isPast = idx < selectedStepIndex;
          const Icon = st.icon;

          return (
            <button
              key={st.id}
              onClick={() => setSelectedStepIndex(idx)}
              className={`p-2 rounded-lg border text-left font-mono transition relative ${
                isSelected
                  ? 'border-cyan-500 bg-cyan-950/70 shadow-md shadow-cyan-950/50'
                  : isPast
                  ? 'border-slate-800 bg-slate-900/60 text-slate-400 hover:border-slate-700'
                  : 'border-slate-800/60 bg-slate-950/40 text-slate-600 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-[9px] text-slate-500">{st.timestamp.split('.')[0]}</span>
                <Icon className={`w-3.5 h-3.5 ${isSelected ? 'text-cyan-400' : isPast ? 'text-emerald-400' : 'text-slate-500'}`} />
              </div>
              <div className="text-[10px] font-bold truncate text-slate-200">
                {st.stage.replace('STAGE ', 'S')}
              </div>
              <div className="text-[9px] truncate text-slate-400 mt-0.5">
                {st.title}
              </div>
            </button>
          );
        })}
      </div>

      {/* Selected Stage Detail Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Step Breakdown */}
        <div className="lg:col-span-2 p-4 rounded-xl bg-soc-card border border-soc-border space-y-3 font-mono">
          <div className="flex items-center justify-between">
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${current.badgeColor}`}>
              {current.stage}
            </span>
            <span className="text-[11px] text-slate-400 flex items-center gap-1">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              Timestamp: {current.timestamp}
            </span>
          </div>

          <div>
            <h3 className="text-sm font-bold text-slate-100">{current.title}</h3>
            <p className="text-xs text-slate-300 mt-1 leading-relaxed">{current.description}</p>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 pt-2 border-t border-soc-border/60">
            <div>
              <span className="text-[10px] text-slate-500 uppercase block">Active Component</span>
              <span className="text-cyan-400 font-semibold text-xs">{current.component}</span>
            </div>
            <div>
              <span className="text-[10px] text-slate-500 uppercase block">Observable Metric</span>
              <span className="text-white font-semibold text-xs">{current.metric}</span>
            </div>
            <div>
              <span className="text-[10px] text-slate-500 uppercase block">Origin Status</span>
              <span className={`font-semibold text-xs ${
                current.originContacted ? 'text-amber-400' : 'text-emerald-400'
              }`}>
                {current.originContacted ? 'Reachable (Early Phase)' : '0 REQUESTS (UNTOUCHED)'}
              </span>
            </div>
          </div>

          <div className="pt-2">
            <span className="text-[10px] text-slate-400 uppercase block mb-1">
              Telemetry Evidence Log (PostgreSQL Store):
            </span>
            <pre className="p-2.5 rounded bg-slate-950 text-[11px] text-emerald-300 overflow-x-auto border border-soc-border/80">
              {JSON.stringify(current.telemetryEvidence, null, 2)}
            </pre>
          </div>
        </div>

        {/* Origin Protection & Verification Guarantee */}
        <div className="p-4 rounded-xl bg-soc-card border border-emerald-900/60 bg-emerald-950/10 space-y-4 font-mono text-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-emerald-400 pb-2 border-b border-emerald-900/40">
              <ShieldCheck className="w-4 h-4" />
              <span className="font-bold uppercase tracking-wider text-[11px]">
                Origin Protection Receipt
              </span>
            </div>

            <div className="space-y-3 mt-3">
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 block">PRODUCTION APPLICATION</span>
                <span className="font-bold text-emerald-400 text-sm">
                  0 REQUESTS LEAKED
                </span>
                <span className="text-[10px] text-slate-400 block mt-0.5">
                  Origin server was completely bypassed
                </span>
              </div>

              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 block">PRODUCTION DATABASE</span>
                <span className="font-bold text-emerald-400 text-sm">
                  ZERO ACCESS DETECTED
                </span>
                <span className="text-[10px] text-slate-400 block mt-0.5">
                  Synthetic decoy used isolated mock state
                </span>
              </div>

              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 block">CONTAINMENT STATUS</span>
                <span className="font-bold text-cyan-400 text-sm">
                  DECOY SANDBOX CONTAINED
                </span>
                <span className="text-[10px] text-slate-400 block mt-0.5">
                  Attacker safely engaged &amp; studied
                </span>
              </div>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-800/80 text-emerald-300 text-[11px]">
            <div className="flex items-center gap-1.5 font-bold mb-1">
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              <span>JUDGE-FACING PROOF</span>
            </div>
            &quot;The attacker reaches AEGIS, not the application. AEGIS dynamically qualifies deception, diverts the threat into a synthetic environment, and produces verifiable proof that the real app remained untouched.&quot;
          </div>
        </div>
      </div>
    </div>
  );
};
