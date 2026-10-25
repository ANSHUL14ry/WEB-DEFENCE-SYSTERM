import React, { useState, useEffect, useRef } from 'react';
import { AgentShieldAssessment, AgentShieldStats, AgentShieldSignal } from '../types';
import { 
  Bot, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Activity, 
  Radio, 
  Layers, 
  Search, 
  Key, 
  Zap, 
  Workflow, 
  Terminal, 
  Info, 
  X, 
  Copy, 
  Check, 
  Clock, 
  ExternalLink 
} from 'lucide-react';

interface AgentShieldPanelProps {
  apiBase: string;
}

export const AgentShieldPanel: React.FC<AgentShieldPanelProps> = ({ apiBase }) => {
  const [stats, setStats] = useState<AgentShieldStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedAssessment, setSelectedAssessment] = useState<AgentShieldAssessment | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [wsConnected, setWsConnected] = useState<boolean>(false);

  const wsRef = useRef<WebSocket | null>(null);

  const fetchAgentShieldStats = async () => {
    try {
      const res = await fetch(`${apiBase}/api/v1/agent-shield/stats`);
      if (res.ok) {
        const data: AgentShieldStats = await res.json();
        setStats(data);
      }
    } catch (err) {
      console.warn('Failed to fetch AgentShield stats:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAgentShieldStats();

    const host = window.location.hostname || 'localhost';
    const wsUrl = `ws://${host}:8001/api/v1/ws/events`;
    let socket: WebSocket;

    try {
      socket = new WebSocket(wsUrl);
      wsRef.current = socket;

      socket.onopen = () => setWsConnected(true);
      socket.onclose = () => setWsConnected(false);
      socket.onerror = () => setWsConnected(false);

      socket.onmessage = (msg) => {
        try {
          const payload = JSON.parse(msg.data);
          if (payload.type === 'AGENTSHIELD_SIGNAL' || payload.event_type === 'AGENTSHIELD_SIGNAL') {
            const raw = payload.data || payload;
            const newAssessment: AgentShieldAssessment = {
              assessment_id: raw.assessment_id,
              request_id: raw.request_id,
              trace_id: raw.trace_id,
              session_id: raw.session_id,
              agent_shield_score: raw.agent_shield_score ?? raw.score ?? 0,
              severity: raw.severity || 'LOW',
              confidence: raw.confidence ?? 1.0,
              signals: raw.signals || [],
              attack_stages: raw.attack_stages || [],
              attack_timeline: raw.attack_timeline || [],
              behavior_summary: raw.behavior_summary || 'Behavior evaluated',
              engine_version: raw.engine_version || 'agentshield-v1',
              disclaimer: raw.disclaimer || '',
              created_at: raw.timestamp || raw.created_at || new Date().toISOString()
            };

            setStats((prev) => {
              const currentTotal = (prev?.total_assessments ?? 0) + 1;
              const recent = [newAssessment, ...(prev?.recent_assessments || [])].slice(0, 10);
              const isCrit = newAssessment.severity === 'CRITICAL';
              const isHigh = newAssessment.severity === 'HIGH';
              const isMed = newAssessment.severity === 'MEDIUM';
              const isLow = newAssessment.severity === 'LOW';

              return {
                total_assessments: currentTotal,
                average_agent_shield_score: newAssessment.agent_shield_score,
                critical_count: (prev?.critical_count ?? 0) + (isCrit ? 1 : 0),
                high_count: (prev?.high_count ?? 0) + (isHigh ? 1 : 0),
                medium_count: (prev?.medium_count ?? 0) + (isMed ? 1 : 0),
                low_count: (prev?.low_count ?? 0) + (isLow ? 1 : 0),
                recent_assessments: recent,
                disclaimer: prev?.disclaimer || ''
              };
            });
          }
        } catch (e) {
          console.error('Error parsing AgentShield WS payload:', e);
        }
      };
    } catch (e) {
      console.warn('AgentShield WS connection failed:', e);
    }

    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, [apiBase]);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const latestAssessment = stats?.recent_assessments?.[0] || null;
  const currentScore = latestAssessment ? latestAssessment.agent_shield_score : 0;
  const currentSeverity = latestAssessment ? latestAssessment.severity : 'LOW';

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-red-950/80 text-red-400 border border-red-700/60 animate-pulse">CRITICAL AUTOMATION</span>;
      case 'HIGH':
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-orange-950/80 text-orange-400 border border-orange-700/60">HIGH AUTOMATION</span>;
      case 'MEDIUM':
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-yellow-950/80 text-yellow-400 border border-yellow-700/60">MODERATE AUTOMATION</span>;
      default:
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-emerald-950/80 text-emerald-400 border border-emerald-700/60">STANDARD INTERACTIVE</span>;
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 75) return 'text-red-400 stroke-red-500';
    if (score >= 50) return 'text-orange-400 stroke-orange-500';
    if (score >= 25) return 'text-yellow-400 stroke-yellow-500';
    return 'text-emerald-400 stroke-emerald-500';
  };

  const activeSignalNames = new Set((latestAssessment?.signals || []).map((s) => s.name));

  const standardIndicators = [
    { id: 'rapid_recon', label: 'Rapid Reconnaissance', icon: Search, desc: 'Multiple endpoints scanned in narrow temporal window' },
    { id: 'endpoint_enumeration', label: 'Endpoint Enumeration', icon: Layers, desc: 'Systematic discovery of multiple paths' },
    { id: 'api_enumeration', label: 'API Enumeration', icon: Terminal, desc: 'Systematic inspection of /api/ endpoints' },
    { id: 'request_velocity', label: 'High Velocity', icon: Zap, desc: 'Burst request rate exceeding normal human pacing' },
    { id: 'authentication_probing', label: 'Auth Probing', icon: Key, desc: 'Repeated requests targeted at credential endpoints' },
    { id: 'repeated_waf_triggers', label: 'Repeated WAF Triggers', icon: ShieldAlert, desc: 'Multiple Coraza CRS rule violations in trace' },
    { id: 'parameter_manipulation', label: 'Param Fuzzing', icon: Activity, desc: 'Systematic parameter mutations on target route' },
    { id: 'attack_sequence', label: 'Attack Sequence', icon: Workflow, desc: 'Multi-stage progression through attack lifecycle' }
  ];

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-2xl backdrop-blur-md">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-indigo-500/10 border border-indigo-500/30 rounded-lg text-indigo-400">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-lg font-bold text-slate-100 tracking-wide">AgentShield Behavioral Engine</h2>
              <span className="px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider rounded bg-indigo-950/60 text-indigo-300 border border-indigo-700/50">
                Phase 6 Active
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Deterministic behavioral analysis of automated &amp; agentic attack workflows
            </p>
          </div>
        </div>

        {/* Live Indicator */}
        <div className="flex items-center space-x-3 self-end sm:self-center">
          <div className="flex items-center space-x-2 text-xs font-mono px-3 py-1 bg-slate-950/70 rounded-full border border-slate-800">
            <Radio className={`w-3 h-3 ${wsConnected ? 'text-indigo-400 animate-pulse' : 'text-slate-500'}`} />
            <span className={wsConnected ? 'text-indigo-300' : 'text-slate-500'}>
              {wsConnected ? 'LIVE FEED' : 'CONNECTING...'}
            </span>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Assessments: <strong className="text-slate-200">{stats?.total_assessments ?? 0}</strong>
          </span>
        </div>
      </div>

      {/* Primary Metrics Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 mt-5">
        {/* Left Column: Normalized Score Gauge (4 Cols) */}
        <div className="lg:col-span-4 bg-slate-950/60 border border-slate-800/80 rounded-xl p-4 flex flex-col items-center justify-center relative overflow-hidden">
          <div className="absolute top-3 left-3 text-[11px] font-mono text-slate-500 uppercase tracking-wider">
            Automation Index
          </div>

          <div className="relative w-36 h-36 flex items-center justify-center my-3">
            {/* SVG Gauge */}
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
              <circle
                cx="50"
                cy="50"
                r="40"
                className="stroke-slate-800"
                strokeWidth="8"
                fill="transparent"
              />
              <circle
                cx="50"
                cy="50"
                r="40"
                className={getScoreColor(currentScore)}
                strokeWidth="8"
                fill="transparent"
                strokeDasharray="251.2"
                strokeDashoffset={251.2 - (251.2 * currentScore) / 100}
                strokeLinecap="round"
                style={{ transition: 'stroke-dashoffset 0.8s ease-in-out' }}
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center">
              <span className={`text-4xl font-extrabold font-mono tracking-tight ${getScoreColor(currentScore).split(' ')[0]}`}>
                {currentScore}
              </span>
              <span className="text-[10px] uppercase font-mono text-slate-400 mt-0.5">/ 100</span>
            </div>
          </div>

          <div className="mt-1 flex flex-col items-center space-y-1">
            {getSeverityBadge(currentSeverity)}
            {latestAssessment && (
              <span className="text-[11px] font-mono text-slate-400 mt-1">
                Confidence: <span className="text-slate-200">{Math.round((latestAssessment.confidence || 1.0) * 100)}%</span>
              </span>
            )}
          </div>
        </div>

        {/* Right Column: Behavior Summary & Stage Progression (8 Cols) */}
        <div className="lg:col-span-8 flex flex-col justify-between space-y-4">
          {/* Behavior Summary Box */}
          <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
                <Info className="w-3.5 h-3.5 text-indigo-400" />
                <span>Behavioral Assessment Summary</span>
              </span>
              {latestAssessment && (
                <span className="text-[11px] font-mono text-slate-500">
                  Trace: {latestAssessment.trace_id.substring(0, 16)}...
                </span>
              )}
            </div>
            <p className="text-sm text-slate-200 font-sans leading-relaxed">
              {latestAssessment?.behavior_summary || 'Awaiting application telemetry to evaluate behavioral automation characteristics.'}
            </p>

            {/* Attack Stage Progression */}
            <div className="mt-4 pt-3 border-t border-slate-800/80">
              <span className="text-[11px] font-mono text-slate-400 block mb-2">Observed Attack Progression:</span>
              <div className="flex flex-wrap items-center gap-2">
                {latestAssessment?.attack_stages && latestAssessment.attack_stages.length > 0 ? (
                  latestAssessment.attack_stages.map((stage, idx) => (
                    <React.Fragment key={idx}>
                      <span className="px-2 py-0.5 text-xs font-mono font-medium rounded bg-indigo-950/80 text-indigo-300 border border-indigo-700/60 flex items-center space-x-1">
                        <span>{stage}</span>
                      </span>
                      {idx < latestAssessment.attack_stages.length - 1 && (
                        <span className="text-slate-600 font-mono text-xs">→</span>
                      )}
                    </React.Fragment>
                  ))
                ) : (
                  <span className="text-xs text-slate-500 font-mono italic">No stage progression triggered</span>
                )}
              </div>
            </div>
          </div>

          {/* Explicit AI Disclaimer Box */}
          <div className="bg-slate-950/40 border border-indigo-900/30 rounded-lg p-3 text-[11px] text-indigo-300/80 flex items-start space-x-2">
            <Info className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
            <p className="leading-snug">
              <strong>Technical Integrity Notice:</strong> AgentShield detects observable behavioral characteristics 
              consistent with automated or agentic attack workflows. It does <em>not</em> claim to identify specific AI models 
              or prove that an attacker is an AI.
            </p>
          </div>
        </div>
      </div>

      {/* Automation Indicators Checklist */}
      <div className="mt-5 pt-4 border-t border-slate-800">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center space-x-2">
            <Activity className="w-3.5 h-3.5 text-indigo-400" />
            <span>Behavioral Automation Indicators</span>
          </h3>
          <span className="text-xs font-mono text-slate-500">
            {latestAssessment?.signals?.length || 0} / 8 Signals Detected
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {standardIndicators.map((ind) => {
            const isActive = activeSignalNames.has(ind.id);
            const Icon = ind.icon;
            return (
              <div
                key={ind.id}
                className={`p-3 rounded-lg border transition-all duration-200 ${
                  isActive
                    ? 'bg-indigo-950/50 border-indigo-700/60 shadow-lg shadow-indigo-950/30'
                    : 'bg-slate-950/40 border-slate-800/60 opacity-60'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-indigo-400' : 'text-slate-500'}`} />
                  {isActive ? (
                    <span className="px-1.5 py-0.2 text-[10px] font-mono font-bold bg-indigo-500/20 text-indigo-300 rounded border border-indigo-500/40">
                      DETECTED
                    </span>
                  ) : (
                    <span className="text-[10px] font-mono text-slate-600">INACTIVE</span>
                  )}
                </div>
                <h4 className={`text-xs font-semibold ${isActive ? 'text-slate-100' : 'text-slate-400'}`}>
                  {ind.label}
                </h4>
                <p className="text-[10px] text-slate-500 mt-1 line-clamp-2">{ind.desc}</p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Correlated Assessment Timeline & Drilldown */}
      <div className="mt-5 pt-4 border-t border-slate-800">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center space-x-2">
            <Clock className="w-3.5 h-3.5 text-indigo-400" />
            <span>Recent AgentShield Assessments</span>
          </h3>
        </div>

        <div className="space-y-2">
          {stats?.recent_assessments && stats.recent_assessments.length > 0 ? (
            stats.recent_assessments.slice(0, 5).map((as) => (
              <div
                key={as.assessment_id}
                onClick={() => setSelectedAssessment(as)}
                className="bg-slate-950/50 hover:bg-slate-800/50 border border-slate-800/80 rounded-lg p-3 flex items-center justify-between cursor-pointer transition-colors duration-150"
              >
                <div className="flex items-center space-x-3">
                  <div className={`w-2.5 h-2.5 rounded-full ${
                    as.severity === 'CRITICAL' ? 'bg-red-500 animate-pulse' :
                    as.severity === 'HIGH' ? 'bg-orange-500' :
                    as.severity === 'MEDIUM' ? 'bg-yellow-500' : 'bg-emerald-500'
                  }`} />
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-mono font-medium text-slate-200">
                        {as.assessment_id}
                      </span>
                      {getSeverityBadge(as.severity)}
                    </div>
                    <p className="text-[11px] text-slate-400 mt-0.5 truncate max-w-md">
                      {as.behavior_summary}
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-4">
                  <div className="text-right">
                    <span className="text-xs font-mono font-bold text-slate-200">
                      Score: {as.agent_shield_score}
                    </span>
                    <span className="block text-[10px] font-mono text-slate-500">
                      {as.created_at ? new Date(as.created_at).toLocaleTimeString() : ''}
                    </span>
                  </div>
                  <ExternalLink className="w-3.5 h-3.5 text-slate-500" />
                </div>
              </div>
            ))
          ) : (
            <div className="p-4 text-center text-xs text-slate-500 font-mono bg-slate-950/30 rounded-lg">
              No recent behavioral assessments recorded. Send requests through gateway to trigger analysis.
            </div>
          )}
        </div>
      </div>

      {/* Assessment Investigation Modal */}
      {selectedAssessment && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-2xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            {/* Modal Header */}
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
              <div className="flex items-center space-x-2">
                <Bot className="w-4 h-4 text-indigo-400" />
                <h3 className="text-sm font-bold text-slate-100">
                  AgentShield Assessment Drilldown
                </h3>
              </div>
              <button
                onClick={() => setSelectedAssessment(null)}
                className="text-slate-400 hover:text-slate-100 p-1 rounded-lg hover:bg-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-5 overflow-y-auto space-y-4 text-xs font-mono">
              <div className="grid grid-cols-2 gap-3 bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div>
                  <span className="text-slate-500 block text-[10px]">ASSESSMENT ID</span>
                  <span className="text-slate-200">{selectedAssessment.assessment_id}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">SEVERITY</span>
                  <div>{getSeverityBadge(selectedAssessment.severity)}</div>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">AUTOMATION SCORE</span>
                  <span className="text-slate-100 font-bold text-sm">{selectedAssessment.agent_shield_score} / 100</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">TRACE ID</span>
                  <span className="text-slate-300 truncate block">{selectedAssessment.trace_id}</span>
                </div>
              </div>

              {/* Signals Breakdown */}
              <div>
                <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                  Triggered Behavioral Signals ({selectedAssessment.signals.length})
                </h4>
                <div className="space-y-2">
                  {selectedAssessment.signals.map((sig, i) => (
                    <div key={i} className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-bold text-indigo-400">{sig.name}</span>
                        <span className="text-slate-300 font-bold">+{sig.score} pts</span>
                      </div>
                      <p className="text-slate-300 text-[11px] mb-2">{sig.reason}</p>
                      {sig.evidence && Object.keys(sig.evidence).length > 0 && (
                        <div className="bg-slate-900/80 p-2 rounded text-[10px] text-slate-400 overflow-x-auto">
                          <pre>{JSON.stringify(sig.evidence, null, 2)}</pre>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Correlated Attack Timeline */}
              {selectedAssessment.attack_timeline && selectedAssessment.attack_timeline.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                    Correlated Attack Timeline ({selectedAssessment.attack_timeline.length} Steps)
                  </h4>
                  <div className="space-y-1.5">
                    {selectedAssessment.attack_timeline.map((step, idx) => (
                      <div key={idx} className="bg-slate-950 p-2 rounded border border-slate-800/80 flex items-center justify-between text-[11px]">
                        <div className="flex items-center space-x-2">
                          <span className="px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-300 font-bold text-[9px] border border-indigo-700/50">
                            {step.stage}
                          </span>
                          <span className="text-slate-200 font-semibold">{step.method}</span>
                          <span className="text-slate-400">{step.uri}</span>
                        </div>
                        <span className="text-slate-500 text-[10px]">{step.detail}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-3 bg-slate-950 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedAssessment(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-sans font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
