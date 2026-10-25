import React, { useState, useEffect, useRef } from 'react';
import { PolicyDecisionRecord, PolicyStats } from '../types';
import { 
  Scale, 
  ShieldAlert, 
  Radio, 
  Info, 
  X, 
  ExternalLink, 
  Clock, 
  Flame, 
  Bot, 
  CheckCircle2, 
  Ban, 
  Eye, 
  SlidersHorizontal 
} from 'lucide-react';

interface PolicyEnginePanelProps {
  apiBase: string;
}

export const PolicyEnginePanel: React.FC<PolicyEnginePanelProps> = ({ apiBase }) => {
  const [stats, setStats] = useState<PolicyStats | null>(null);
  const [selectedDecision, setSelectedDecision] = useState<PolicyDecisionRecord | null>(null);
  const [wsConnected, setWsConnected] = useState<boolean>(false);

  const wsRef = useRef<WebSocket | null>(null);

  const fetchPolicyStats = async () => {
    try {
      const res = await fetch(`${apiBase}/api/v1/policy/stats`);
      if (res.ok) {
        const data: PolicyStats = await res.json();
        setStats(data);
      }
    } catch (err) {
      console.warn('Failed to fetch Policy stats:', err);
    }
  };

  useEffect(() => {
    fetchPolicyStats();

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
          if (payload.type === 'POLICY_DECISION' || payload.event_type === 'POLICY_DECISION') {
            const raw = payload.data || payload;
            const newDecision: PolicyDecisionRecord = {
              decision_id: raw.decision_id,
              event_id: raw.event_id,
              request_id: raw.request_id,
              trace_id: raw.trace_id,
              session_id: raw.session_id,
              risk_assessment_id: raw.risk_assessment_id,
              agent_shield_assessment_id: raw.agent_shield_assessment_id,
              risk_score: raw.risk_score,
              risk_severity: raw.risk_severity,
              risk_confidence: raw.risk_confidence,
              agent_shield_score: raw.agent_shield_score,
              agent_shield_severity: raw.agent_shield_severity,
              agent_shield_confidence: raw.agent_shield_confidence,
              decision: raw.decision,
              decision_reason: raw.decision_reason,
              reasons: raw.reasons || [],
              matched_rules: raw.matched_rules || [],
              terminal: raw.terminal ?? false,
              policy_version: raw.policy_version || 'policy-v1',
              created_at: raw.timestamp || raw.created_at || new Date().toISOString()
            };

            setStats((prev) => {
              const currentTotal = (prev?.total_decisions ?? 0) + 1;
              const recent = [newDecision, ...(prev?.recent_decisions || [])].slice(0, 10);
              const isAllow = newDecision.decision === 'ALLOW';
              const isMonitor = newDecision.decision === 'MONITOR';
              const isRateLimit = newDecision.decision === 'RATE_LIMIT';
              const isBlock = newDecision.decision === 'BLOCK';
              const isContain = newDecision.decision === 'CONTAIN';
              const isDeceive = newDecision.decision === 'DECEIVE_ELIGIBLE';

              return {
                total_decisions: currentTotal,
                allow_count: (prev?.allow_count ?? 0) + (isAllow ? 1 : 0),
                monitor_count: (prev?.monitor_count ?? 0) + (isMonitor ? 1 : 0),
                rate_limit_count: (prev?.rate_limit_count ?? 0) + (isRateLimit ? 1 : 0),
                block_count: (prev?.block_count ?? 0) + (isBlock ? 1 : 0),
                contain_count: (prev?.contain_count ?? 0) + (isContain ? 1 : 0),
                deceive_eligible_count: (prev?.deceive_eligible_count ?? 0) + (isDeceive ? 1 : 0),
                recent_decisions: recent,
                disclaimer: prev?.disclaimer || ''
              };
            });
          }
        } catch (e) {
          console.error('Error parsing Policy WS payload:', e);
        }
      };
    } catch (e) {
      console.warn('Policy WS connection failed:', e);
    }

    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, [apiBase]);

  const latestDecision = stats?.recent_decisions?.[0] || null;

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case 'DECEIVE_ELIGIBLE':
        return (
          <span className="px-3 py-1 text-xs font-bold font-mono rounded-full bg-purple-950/90 text-purple-300 border border-purple-600/70 shadow-lg shadow-purple-950/40 flex items-center space-x-1.5 animate-pulse">
            <Eye className="w-3.5 h-3.5 text-purple-400" />
            <span>DECEIVE ELIGIBLE</span>
          </span>
        );
      case 'BLOCK':
        return (
          <span className="px-3 py-1 text-xs font-bold font-mono rounded-full bg-red-950/90 text-red-400 border border-red-700/70 shadow-lg shadow-red-950/40 flex items-center space-x-1.5">
            <Ban className="w-3.5 h-3.5 text-red-400" />
            <span>BLOCK</span>
          </span>
        );
      case 'RATE_LIMIT':
        return (
          <span className="px-3 py-1 text-xs font-bold font-mono rounded-full bg-orange-950/90 text-orange-400 border border-orange-700/70 flex items-center space-x-1.5">
            <SlidersHorizontal className="w-3.5 h-3.5 text-orange-400" />
            <span>RATE LIMIT</span>
          </span>
        );
      case 'CONTAIN':
        return (
          <span className="px-3 py-1 text-xs font-bold font-mono rounded-full bg-indigo-950/90 text-indigo-300 border border-indigo-700/70 flex items-center space-x-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-indigo-400" />
            <span>CONTAIN</span>
          </span>
        );
      case 'MONITOR':
        return (
          <span className="px-3 py-1 text-xs font-bold font-mono rounded-full bg-yellow-950/90 text-yellow-400 border border-yellow-700/70 flex items-center space-x-1.5">
            <Eye className="w-3.5 h-3.5 text-yellow-400" />
            <span>MONITOR</span>
          </span>
        );
      default:
        return (
          <span className="px-3 py-1 text-xs font-bold font-mono rounded-full bg-emerald-950/90 text-emerald-400 border border-emerald-700/70 flex items-center space-x-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>ALLOW</span>
          </span>
        );
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-2xl backdrop-blur-md">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-purple-500/10 border border-purple-500/30 rounded-lg text-purple-400">
            <Scale className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-lg font-bold text-slate-100 tracking-wide">Deterministic Policy Engine</h2>
              <span className="px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider rounded bg-purple-950/60 text-purple-300 border border-purple-700/50">
                Phase 7 Active
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Rule-based response decision authority: ALLOW, MONITOR, RATE_LIMIT, BLOCK, DECEIVE_ELIGIBLE
            </p>
          </div>
        </div>

        {/* Live Indicator */}
        <div className="flex items-center space-x-3 self-end sm:self-center">
          <div className="flex items-center space-x-2 text-xs font-mono px-3 py-1 bg-slate-950/70 rounded-full border border-slate-800">
            <Radio className={`w-3 h-3 ${wsConnected ? 'text-purple-400 animate-pulse' : 'text-slate-500'}`} />
            <span className={wsConnected ? 'text-purple-300' : 'text-slate-500'}>
              {wsConnected ? 'LIVE FEED' : 'CONNECTING...'}
            </span>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Decisions: <strong className="text-slate-200">{stats?.total_decisions ?? 0}</strong>
          </span>
        </div>
      </div>

      {/* Decision Summary Hero Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 mt-5">
        {/* Left Column: Active Decision Hero (5 Cols) */}
        <div className="lg:col-span-5 bg-slate-950/60 border border-slate-800/80 rounded-xl p-5 flex flex-col justify-between relative overflow-hidden">
          <div className="flex items-center justify-between mb-3">
            <span className="text-[11px] font-mono uppercase text-slate-400">Current Policy Determination</span>
            {latestDecision?.terminal ? (
              <span className="px-2 py-0.5 text-[9px] font-mono font-bold uppercase rounded bg-red-950 text-red-300 border border-red-800">
                TERMINAL DROP
              </span>
            ) : (
              <span className="px-2 py-0.5 text-[9px] font-mono uppercase rounded bg-slate-800 text-slate-300 border border-slate-700">
                NON-TERMINAL
              </span>
            )}
          </div>

          <div className="my-3 flex flex-col items-center sm:items-start space-y-3">
            {getDecisionBadge(latestDecision?.decision || 'ALLOW')}
            
            <p className="text-sm font-sans text-slate-200 leading-snug">
              {latestDecision?.decision_reason || 'Awaiting application telemetry to evaluate policy response.'}
            </p>
          </div>

          {/* Deception Pending Notice */}
          {latestDecision?.decision === 'DECEIVE_ELIGIBLE' && (
            <div className="mt-2 p-2.5 bg-purple-950/40 border border-purple-800/40 rounded-lg text-[11px] text-purple-300 flex items-start space-x-2">
              <Info className="w-3.5 h-3.5 text-purple-400 shrink-0 mt-0.5" />
              <span>
                <strong>Deception Qualified:</strong> Session qualifies for decoy diversion. Active honeypot redirection will execute in Phase 8.
              </span>
            </div>
          )}

          {/* Matched Rules Chain */}
          <div className="mt-4 pt-3 border-t border-slate-800/80">
            <span className="text-[10px] font-mono uppercase text-slate-500 block mb-2">Matched Policy Rules:</span>
            <div className="flex flex-wrap gap-1.5">
              {latestDecision?.matched_rules && latestDecision.matched_rules.length > 0 ? (
                latestDecision.matched_rules.map((rule, idx) => (
                  <span key={idx} className="px-2 py-0.5 text-[10px] font-mono rounded bg-slate-900 text-purple-300 border border-purple-800/50">
                    {rule}
                  </span>
                ))
              ) : (
                <span className="text-[10px] font-mono text-slate-600 italic">No rules matched</span>
              )}
            </div>
          </div>
        </div>

        {/* Right Column: Correlated Telemetry & Decision Metrics (7 Cols) */}
        <div className="lg:col-span-7 flex flex-col justify-between space-y-4">
          {/* Correlated Signals Breakdown */}
          <div className="grid grid-cols-2 gap-3">
            {/* Risk Engine Input */}
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
              <div className="flex items-center space-x-2 mb-2 text-rose-400 text-xs font-mono uppercase">
                <Flame className="w-4 h-4" />
                <span>Risk Intelligence</span>
              </div>
              <div className="flex items-baseline space-x-2">
                <span className="text-2xl font-bold font-mono text-white">
                  {latestDecision?.risk_score ?? '--'}
                </span>
                <span className="text-xs font-mono text-slate-400">/ 100</span>
              </div>
              <div className="mt-1 flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span>Severity: <strong className="text-rose-300">{latestDecision?.risk_severity ?? 'NONE'}</strong></span>
                <span>Conf: {Math.round((latestDecision?.risk_confidence ?? 1.0) * 100)}%</span>
              </div>
            </div>

            {/* AgentShield Input */}
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
              <div className="flex items-center space-x-2 mb-2 text-indigo-400 text-xs font-mono uppercase">
                <Bot className="w-4 h-4" />
                <span>AgentShield Intelligence</span>
              </div>
              <div className="flex items-baseline space-x-2">
                <span className="text-2xl font-bold font-mono text-white">
                  {latestDecision?.agent_shield_score ?? '--'}
                </span>
                <span className="text-xs font-mono text-slate-400">/ 100</span>
              </div>
              <div className="mt-1 flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span>Severity: <strong className="text-indigo-300">{latestDecision?.agent_shield_severity ?? 'NONE'}</strong></span>
                <span>Conf: {Math.round((latestDecision?.agent_shield_confidence ?? 1.0) * 100)}%</span>
              </div>
            </div>
          </div>

          {/* Decision Aggregates Pills */}
          <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
            <span className="text-[10px] font-mono uppercase text-slate-500 block mb-2">Aggregated Decision Distribution:</span>
            <div className="grid grid-cols-3 sm:grid-cols-6 gap-2 text-center text-xs font-mono">
              <div className="p-2 rounded bg-purple-950/40 border border-purple-800/40">
                <div className="text-purple-400 font-bold text-sm">{stats?.deceive_eligible_count ?? 0}</div>
                <div className="text-[9px] text-purple-300/70 mt-0.5">DECEIVE</div>
              </div>
              <div className="p-2 rounded bg-red-950/40 border border-red-800/40">
                <div className="text-red-400 font-bold text-sm">{stats?.block_count ?? 0}</div>
                <div className="text-[9px] text-red-300/70 mt-0.5">BLOCK</div>
              </div>
              <div className="p-2 rounded bg-indigo-950/40 border border-indigo-800/40">
                <div className="text-indigo-400 font-bold text-sm">{stats?.contain_count ?? 0}</div>
                <div className="text-[9px] text-indigo-300/70 mt-0.5">CONTAIN</div>
              </div>
              <div className="p-2 rounded bg-orange-950/40 border border-orange-800/40">
                <div className="text-orange-400 font-bold text-sm">{stats?.rate_limit_count ?? 0}</div>
                <div className="text-[9px] text-orange-300/70 mt-0.5">RATE LIMIT</div>
              </div>
              <div className="p-2 rounded bg-yellow-950/40 border border-yellow-800/40">
                <div className="text-yellow-400 font-bold text-sm">{stats?.monitor_count ?? 0}</div>
                <div className="text-[9px] text-yellow-300/70 mt-0.5">MONITOR</div>
              </div>
              <div className="p-2 rounded bg-emerald-950/40 border border-emerald-800/40">
                <div className="text-emerald-400 font-bold text-sm">{stats?.allow_count ?? 0}</div>
                <div className="text-[9px] text-emerald-300/70 mt-0.5">ALLOW</div>
              </div>
            </div>
          </div>

          {/* Technical Invariant Notice */}
          <div className="bg-slate-950/40 border border-purple-900/30 rounded-lg p-2.5 text-[11px] text-purple-300/80 flex items-start space-x-2">
            <Info className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
            <p className="leading-snug">
              <strong>WAF Safety Invariant:</strong> A request dropped by the WAF is strictly terminal (BLOCK). 
              A WAF-blocked request can <em>never</em> be converted to DECEIVE_ELIGIBLE or ALLOW, guaranteeing zero origin access.
            </p>
          </div>
        </div>
      </div>

      {/* Recent Decisions Timeline */}
      <div className="mt-5 pt-4 border-t border-slate-800">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center space-x-2">
            <Clock className="w-3.5 h-3.5 text-purple-400" />
            <span>Recent Policy Determinations</span>
          </h3>
        </div>

        <div className="space-y-2">
          {stats?.recent_decisions && stats.recent_decisions.length > 0 ? (
            stats.recent_decisions.slice(0, 5).map((dec) => (
              <div
                key={dec.decision_id}
                onClick={() => setSelectedDecision(dec)}
                className="bg-slate-950/50 hover:bg-slate-800/50 border border-slate-800/80 rounded-lg p-3 flex items-center justify-between cursor-pointer transition-colors duration-150"
              >
                <div className="flex items-center space-x-3">
                  <div className={`w-2.5 h-2.5 rounded-full ${
                    dec.decision === 'DECEIVE_ELIGIBLE' ? 'bg-purple-500 animate-pulse' :
                    dec.decision === 'BLOCK' ? 'bg-red-500' :
                    dec.decision === 'RATE_LIMIT' ? 'bg-orange-500' :
                    dec.decision === 'MONITOR' ? 'bg-yellow-500' : 'bg-emerald-500'
                  }`} />
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-mono font-medium text-slate-200">{dec.decision_id}</span>
                      {getDecisionBadge(dec.decision)}
                    </div>
                    <p className="text-[11px] text-slate-400 mt-0.5 truncate max-w-md">
                      {dec.decision_reason}
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-4">
                  <div className="text-right">
                    <span className="text-xs font-mono text-slate-300">
                      Trace: {dec.trace_id.substring(0, 12)}...
                    </span>
                    <span className="block text-[10px] font-mono text-slate-500">
                      {dec.created_at ? new Date(dec.created_at).toLocaleTimeString() : ''}
                    </span>
                  </div>
                  <ExternalLink className="w-3.5 h-3.5 text-slate-500" />
                </div>
              </div>
            ))
          ) : (
            <div className="p-4 text-center text-xs text-slate-500 font-mono bg-slate-950/30 rounded-lg">
              No recent policy decisions recorded. Send requests through the ingress gateway to trigger policy evaluation.
            </div>
          )}
        </div>
      </div>

      {/* Decision Investigation Modal */}
      {selectedDecision && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-2xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            {/* Modal Header */}
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
              <div className="flex items-center space-x-2">
                <Scale className="w-4 h-4 text-purple-400" />
                <h3 className="text-sm font-bold text-slate-100">
                  Policy Decision Audit Record
                </h3>
              </div>
              <button
                onClick={() => setSelectedDecision(null)}
                className="text-slate-400 hover:text-slate-100 p-1 rounded-lg hover:bg-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-5 overflow-y-auto space-y-4 text-xs font-mono">
              <div className="grid grid-cols-2 gap-3 bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div>
                  <span className="text-slate-500 block text-[10px]">DECISION ID</span>
                  <span className="text-slate-200">{selectedDecision.decision_id}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">DETERMINATION</span>
                  <div>{getDecisionBadge(selectedDecision.decision)}</div>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">TERMINAL STATUS</span>
                  <span className={selectedDecision.terminal ? "text-red-400 font-bold" : "text-emerald-400"}>
                    {selectedDecision.terminal ? "TERMINAL (DROPPED)" : "NON-TERMINAL"}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">POLICY VERSION</span>
                  <span className="text-slate-300">{selectedDecision.policy_version}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">REQUEST ID</span>
                  <span className="text-slate-300 truncate block">{selectedDecision.request_id}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">TRACE ID</span>
                  <span className="text-slate-300 truncate block">{selectedDecision.trace_id}</span>
                </div>
              </div>

              {/* Explanatory Reasons */}
              <div>
                <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                  Explanatory Decision Reasons ({selectedDecision.reasons?.length || 0})
                </h4>
                <div className="space-y-1.5 bg-slate-950 p-3 rounded-lg border border-slate-800">
                  {selectedDecision.reasons?.map((reason, i) => (
                    <div key={i} className="text-slate-300 text-[11px] flex items-start space-x-2">
                      <span className="text-purple-400">•</span>
                      <span>{reason}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Matched Rules Chain */}
              <div>
                <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                  Matched Policy Precedence Rules
                </h4>
                <div className="flex flex-wrap gap-2">
                  {selectedDecision.matched_rules?.map((rule, i) => (
                    <span key={i} className="px-2.5 py-1 text-xs font-mono font-medium rounded bg-purple-950/80 text-purple-300 border border-purple-700/60">
                      {rule}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-3 bg-slate-950 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedDecision(null)}
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
