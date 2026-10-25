import React, { useState, useEffect, useRef } from 'react';
import { RiskAssessment, RiskStats } from '../types';
import { 
  Flame, 
  ShieldCheck, 
  Activity, 
  Layers, 
  Radio, 
  ExternalLink, 
  X, 
  Copy, 
  Check 
} from 'lucide-react';

interface RiskEnginePanelProps {
  apiBase: string;
}

export const RiskEnginePanel: React.FC<RiskEnginePanelProps> = ({ apiBase }) => {
  const [stats, setStats] = useState<RiskStats | null>(null);
  const [selectedAssessment, setSelectedAssessment] = useState<RiskAssessment | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [wsConnected, setWsConnected] = useState<boolean>(false);

  const wsRef = useRef<WebSocket | null>(null);

  const fetchRiskStats = async () => {
    try {
      const res = await fetch(`${apiBase}/api/v1/risk/stats`);
      if (res.ok) {
        const data: RiskStats = await res.json();
        setStats(data);
      }
    } catch (err) {
      console.warn('Failed to fetch risk stats:', err);
    }
  };

  useEffect(() => {
    fetchRiskStats();

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
          // If a risk update or security event arrives, refresh risk stats
          if (payload.event_type === 'RISK_SCORE_UPDATE' || payload.event_type === 'WAF_BLOCK' || payload.event_type === 'WAF_DETECTION') {
            fetchRiskStats();
          }
        } catch (e) {
          // ignore non-json
        }
      };
    } catch (e) {
      setWsConnected(false);
    }

    const pollInterval = setInterval(() => {
      fetchRiskStats();
    }, 8000);

    return () => {
      clearInterval(pollInterval);
      if (wsRef.current) wsRef.current.close();
    };
  }, [apiBase]);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const latestAssessment = stats?.latest_assessments?.[0] || null;

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-red-950 text-red-400 border border-red-800">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-amber-950 text-amber-400 border border-amber-800">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-yellow-950 text-yellow-400 border border-yellow-800">MEDIUM</span>;
      default:
        return <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">LOW</span>;
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 75) return 'text-red-400';
    if (score >= 50) return 'text-amber-400';
    if (score >= 25) return 'text-yellow-400';
    return 'text-emerald-400';
  };

  const getScoreBg = (score: number) => {
    if (score >= 75) return 'bg-red-500';
    if (score >= 50) return 'bg-amber-500';
    if (score >= 25) return 'bg-yellow-500';
    return 'bg-emerald-500';
  };

  return (
    <div className="space-y-6">
      {/* Risk Engine Subsystem Header */}
      <div className="bg-soc-panel border border-soc-border rounded-xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-soc-border">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-soc-card rounded-xl border border-rose-900/50 shadow-sm shadow-rose-950">
              <Flame className="w-6 h-6 text-rose-400" />
            </div>
            <div>
              <h2 className="text-sm font-semibold uppercase tracking-wider font-mono text-white flex items-center gap-2">
                AEGIS Ω Explainable Risk Engine
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">
                  risk-engine-v1
                </span>
              </h2>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Deterministic 0–100 threat quantification with explainable signal breakdown
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs font-mono">
            <div className="px-3 py-1.5 rounded-lg bg-soc-card border border-soc-border flex items-center gap-1.5">
              <Radio className={`w-3.5 h-3.5 ${wsConnected ? 'text-emerald-400' : 'text-slate-500'}`} />
              <span className={wsConnected ? 'text-emerald-400' : 'text-slate-400'}>
                {wsConnected ? 'LIVE STREAM' : 'POLLING'}
              </span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-soc-card border border-soc-border flex items-center gap-2">
              <span className="text-slate-400">Total Assessments:</span>
              <span className="font-bold text-white">{stats?.total_assessments ?? 0}</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-soc-card border border-soc-border flex items-center gap-2">
              <span className="text-slate-400">Average Risk:</span>
              <span className={`font-bold ${getScoreColor(stats?.average_risk_score ?? 0)}`}>
                {stats?.average_risk_score ?? 0}/100
              </span>
            </div>
          </div>
        </div>

        {/* Live Active Risk Metric Display */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 pt-6">
          {/* Main Risk Gauge / Score */}
          <div className="bg-soc-card p-5 rounded-xl border border-soc-border flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono uppercase text-slate-400 tracking-wider">
                Current Threat Level
              </span>
              {latestAssessment ? getSeverityBadge(latestAssessment.severity) : (
                <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-slate-900 text-slate-500 border border-slate-800">
                  STANDBY
                </span>
              )}
            </div>

            <div className="py-4 text-center">
              <div className="text-5xl font-black font-mono tracking-tight text-white flex items-baseline justify-center">
                <span className={getScoreColor(latestAssessment?.risk_score ?? 0)}>
                  {latestAssessment ? latestAssessment.risk_score : 0}
                </span>
                <span className="text-slate-600 text-2xl font-normal ml-1">/100</span>
              </div>
              <div className="text-xs font-mono text-slate-400 mt-2">
                {latestAssessment ? (
                  <>Assessment ID: <span className="text-cyan-400">{latestAssessment.assessment_id.slice(0, 16)}</span></>
                ) : (
                  "Awaiting security event evaluation"
                )}
              </div>

              {/* Visual Progress Bar */}
              <div className="w-full bg-slate-800/80 rounded-full h-2.5 mt-4 overflow-hidden">
                <div 
                  className={`h-2.5 rounded-full transition-all duration-500 ${getScoreBg(latestAssessment?.risk_score ?? 0)}`}
                  style={{ width: `${Math.min(100, Math.max(0, latestAssessment?.risk_score ?? 0))}%` }}
                />
              </div>
            </div>

            <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-2 border-t border-soc-border/60">
              <span>Confidence: {latestAssessment ? `${Math.round(latestAssessment.confidence * 100)}%` : 'N/A'}</span>
              <span>Model: Deterministic</span>
            </div>
          </div>

          {/* Top Contributing Risk Signals */}
          <div className="bg-soc-card p-5 rounded-xl border border-soc-border lg:col-span-2 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-mono uppercase text-slate-400 tracking-wider flex items-center gap-2">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  Explainable Signal Decomposition
                </span>
                <span className="text-[10px] font-mono text-slate-500">
                  {latestAssessment?.signals.length ?? 0} Active Signals
                </span>
              </div>

              {latestAssessment && latestAssessment.signals.length > 0 ? (
                <div className="space-y-2 max-h-48 overflow-y-auto font-mono text-xs pr-1">
                  {latestAssessment.signals.map((sig, idx) => (
                    <div 
                      key={idx} 
                      className="p-2.5 rounded-lg bg-soc-panel border border-soc-border/80 flex items-center justify-between"
                    >
                      <div className="flex items-center gap-2.5">
                        <span className="px-2 py-0.5 rounded font-bold text-xs bg-rose-950 text-rose-300 border border-rose-800">
                          +{sig.score}
                        </span>
                        <div>
                          <div className="text-slate-200 font-semibold">{sig.name}</div>
                          <div className="text-[11px] text-slate-400">{sig.reason}</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-10 text-center text-slate-500 font-mono text-xs">
                  <ShieldCheck className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                  No risk assessments available.
                  <div className="text-[11px] text-slate-600 mt-1">
                    When security events trigger, deterministic signals will appear here.
                  </div>
                </div>
              )}
            </div>

            <div className="text-[11px] font-mono text-slate-500 pt-2 border-t border-soc-border/60 mt-3">
              Independent evaluation: CRS rule weights + endpoint sensitivity + 60s temporal velocity
            </div>
          </div>
        </div>

        {/* Recent Risk Assessment Timeline */}
        <div className="mt-6 pt-6 border-t border-soc-border">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-semibold flex items-center gap-2">
              <Layers className="w-4 h-4 text-rose-400" />
              Risk Assessment Timeline & Correlation History
            </h3>
            <span className="text-[11px] font-mono text-slate-500">Latest 5 Evaluations</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-soc-card/70 border-b border-soc-border text-slate-400 uppercase text-[10px]">
                <tr>
                  <th className="py-2 px-3">Time</th>
                  <th className="py-2 px-3">Score</th>
                  <th className="py-2 px-3">Severity</th>
                  <th className="py-2 px-3">Signals</th>
                  <th className="py-2 px-3">Confidence</th>
                  <th className="py-2 px-4">Request ID</th>
                  <th className="py-2 px-4">Trace ID</th>
                  <th className="py-2 px-3 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border/40">
                {!stats || stats.latest_assessments.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-6 text-center text-slate-500 font-mono">
                      No risk assessments recorded yet.
                    </td>
                  </tr>
                ) : (
                  stats.latest_assessments.map((item) => (
                    <tr 
                      key={item.assessment_id}
                      onClick={() => setSelectedAssessment(item)}
                      className="hover:bg-soc-card/80 transition-colors cursor-pointer group"
                    >
                      <td className="py-2.5 px-3 text-slate-400 text-[11px] whitespace-nowrap">
                        {new Date(item.created_at).toLocaleTimeString()}
                      </td>
                      <td className="py-2.5 px-3 font-bold whitespace-nowrap">
                        <span className={getScoreColor(item.risk_score)}>
                          {item.risk_score}/100
                        </span>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        {getSeverityBadge(item.severity)}
                      </td>
                      <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                        <span className="px-1.5 py-0.5 rounded bg-soc-panel border border-soc-border text-[10px]">
                          {item.signals.length} signals
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                        {Math.round(item.confidence * 100)}%
                      </td>
                      <td className="py-2.5 px-4 text-cyan-400 text-[11px] max-w-[120px] truncate">
                        {item.request_id}
                      </td>
                      <td className="py-2.5 px-4 text-purple-400 text-[11px] max-w-[120px] truncate">
                        {item.trace_id}
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button className="text-slate-500 group-hover:text-rose-400 transition-colors p-1">
                          <ExternalLink className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Assessment Investigation Modal */}
      {selectedAssessment && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-soc-panel border border-soc-border rounded-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-soc-border pb-3">
              <div className="flex items-center gap-2">
                <Flame className="w-5 h-5 text-rose-400" />
                <h3 className="text-sm font-bold font-mono text-white">
                  Risk Assessment: {selectedAssessment.assessment_id}
                </h3>
              </div>
              <button 
                onClick={() => setSelectedAssessment(null)}
                className="text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
              <div className="bg-soc-card p-3 rounded-lg border border-soc-border">
                <span className="text-[10px] text-slate-400 uppercase">Calculated Score</span>
                <div className={`mt-1 text-lg font-bold ${getScoreColor(selectedAssessment.risk_score)}`}>
                  {selectedAssessment.risk_score}/100
                </div>
              </div>

              <div className="bg-soc-card p-3 rounded-lg border border-soc-border">
                <span className="text-[10px] text-slate-400 uppercase">Severity</span>
                <div className="mt-1">{getSeverityBadge(selectedAssessment.severity)}</div>
              </div>

              <div className="bg-soc-card p-3 rounded-lg border border-soc-border">
                <span className="text-[10px] text-slate-400 uppercase">Confidence</span>
                <div className="mt-1 font-bold text-slate-200">
                  {Math.round(selectedAssessment.confidence * 100)}%
                </div>
              </div>

              <div className="bg-soc-card p-3 rounded-lg border border-soc-border">
                <span className="text-[10px] text-slate-400 uppercase">Engine Version</span>
                <div className="mt-1 font-mono text-[11px] text-rose-300">
                  {selectedAssessment.engine_version}
                </div>
              </div>
            </div>

            {/* Tracing Identifiers */}
            <div className="bg-soc-card p-4 rounded-lg border border-soc-border space-y-2 text-xs font-mono">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Request ID:</span>
                <div className="flex items-center gap-2 text-slate-200">
                  <span className="text-cyan-400">{selectedAssessment.request_id}</span>
                  <button 
                    onClick={() => copyToClipboard(selectedAssessment.request_id, 'req')}
                    className="text-slate-400 hover:text-white"
                  >
                    {copiedId === 'req' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-slate-400">Trace ID:</span>
                <div className="flex items-center gap-2 text-slate-200">
                  <span className="text-purple-400">{selectedAssessment.trace_id}</span>
                  <button 
                    onClick={() => copyToClipboard(selectedAssessment.trace_id, 'trace')}
                    className="text-slate-400 hover:text-white"
                  >
                    {copiedId === 'trace' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-slate-400">Evaluated Timestamp:</span>
                <span className="text-slate-200">{selectedAssessment.created_at}</span>
              </div>
            </div>

            {/* Explainable Signals Breakdown */}
            <div>
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
                Contributing Signals ({selectedAssessment.signals.length})
              </span>
              <div className="mt-2 space-y-2">
                {selectedAssessment.signals.map((sig, idx) => (
                  <div key={idx} className="p-3 bg-soc-card rounded-lg border border-soc-border text-xs font-mono flex items-center justify-between">
                    <div>
                      <div className="font-semibold text-white">{sig.name}</div>
                      <div className="text-[11px] text-slate-400">{sig.reason}</div>
                    </div>
                    <span className="font-bold text-rose-400 text-sm">+{sig.score}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Raw JSON */}
            <div>
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
                Raw Risk Assessment Payload
              </span>
              <pre className="mt-1 p-3 bg-black/60 rounded-lg border border-soc-border font-mono text-[11px] text-slate-300 overflow-x-auto max-h-40">
                {JSON.stringify(selectedAssessment, null, 2)}
              </pre>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedAssessment(null)}
                className="px-4 py-1.5 bg-soc-card hover:bg-soc-border text-white text-xs font-mono rounded-lg transition-colors border border-soc-border"
              >
                Close Risk Details
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
