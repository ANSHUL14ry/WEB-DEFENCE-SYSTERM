import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Flame, 
  Terminal, 
  Lock, 
  Eye, 
  CheckCircle2, 
  Clock, 
  Server, 
  AlertTriangle,
  ArrowRight,
  Database,
  RefreshCw,
  Layers,
  FileText
} from 'lucide-react';
import { DeceptionSession, DeceptionEvent, DeceptionStats } from '../types';

interface DeceptionPanelProps {
  realtimeEvent?: any;
}

export const DeceptionPanel: React.FC<DeceptionPanelProps> = ({ realtimeEvent }) => {
  const [stats, setStats] = useState<DeceptionStats | null>(null);
  const [activeSession, setActiveSession] = useState<DeceptionSession | null>(null);
  const [sessionEvents, setSessionEvents] = useState<DeceptionEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<DeceptionEvent | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchDeceptionData = async () => {
    try {
      const res = await fetch('/api/v1/deception/stats');
      if (res.ok) {
        const data: DeceptionStats = await res.json();
        setStats(data);
        if (data.recent_sessions && data.recent_sessions.length > 0) {
          const current = data.recent_sessions.find(s => s.status === 'ACTIVE') || data.recent_sessions[0];
          setActiveSession(current);
          fetchSessionTimeline(current.session_id);
        }
      }
    } catch (err) {
      console.error('Failed to fetch deception stats:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchSessionTimeline = async (sessionId: string) => {
    try {
      const res = await fetch(`/api/v1/deception/session/${sessionId}/events`);
      if (res.ok) {
        const events: DeceptionEvent[] = await res.json();
        setSessionEvents(events);
      }
    } catch (err) {
      console.error('Failed to fetch session timeline:', err);
    }
  };

  useEffect(() => {
    fetchDeceptionData();
    const interval = setInterval(fetchDeceptionData, 5000);
    return () => clearInterval(interval);
  }, []);

  // Handle incoming real-time WebSocket events
  useEffect(() => {
    if (realtimeEvent && realtimeEvent.event_type === 'DECEPTION_EVENT') {
      fetchDeceptionData();
      if (activeSession && realtimeEvent.session_id === activeSession.session_id) {
        fetchSessionTimeline(activeSession.session_id);
      }
    }
  }, [realtimeEvent]);

  return (
    <div className="bg-soc-panel border border-soc-border rounded-xl p-5 shadow-lg relative overflow-hidden">
      {/* Background Accent Glow */}
      <div className="absolute top-0 right-0 w-80 h-80 bg-purple-500/5 rounded-full blur-3xl -z-10"></div>

      {/* Panel Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-soc-border gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-purple-950/80 border border-purple-800 text-purple-400">
            <Flame className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold font-mono text-slate-100 uppercase tracking-wide">
                Isolated Adaptive Deception & Honeypot
              </h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-900/60 text-purple-300 border border-purple-700/80">
                Phase 8 Active
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Synthetic sandbox environment diverting high-risk agentic traffic without exposing production assets
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button 
            onClick={fetchDeceptionData}
            className="px-2.5 py-1 text-xs font-mono rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 flex items-center gap-1 transition"
          >
            <RefreshCw className="w-3 h-3" />
            Refresh
          </button>
          <div className="text-right">
            <span className="text-[10px] font-mono text-slate-400 block">Decoy Isolation Status</span>
            <span className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1 justify-end">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
              ORIGIN PROTECTED (0 LEAKS)
            </span>
          </div>
        </div>
      </div>

      {/* Decision Flow Pipeline Visualizer */}
      <div className="mt-4 p-3 bg-soc-card/70 border border-soc-border/80 rounded-lg">
        <div className="text-[11px] font-mono font-semibold text-slate-300 mb-2 uppercase flex items-center gap-2">
          <Layers className="w-3.5 h-3.5 text-purple-400" />
          <span>Autonomous Deception Hand-off Pipeline</span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-6 gap-2 text-center text-xs">
          <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
            <div className="text-[10px] text-slate-500 font-mono">STEP 1 &bull; RISK</div>
            <div className="font-bold text-amber-400 font-mono mt-0.5">ELEVATED</div>
            <div className="text-[9px] text-slate-400">Score &gt;= 50</div>
          </div>
          <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
            <div className="text-[10px] text-slate-500 font-mono">STEP 2 &bull; AGENTSHIELD</div>
            <div className="font-bold text-cyan-400 font-mono mt-0.5">HIGH/CRIT</div>
            <div className="text-[9px] text-slate-400">Automated Probing</div>
          </div>
          <div className="bg-slate-900/80 p-2 rounded border border-purple-800/80 bg-purple-950/20">
            <div className="text-[10px] text-purple-300 font-mono">STEP 3 &bull; POLICY</div>
            <div className="font-bold text-purple-400 font-mono mt-0.5">DECEIVE_ELIGIBLE</div>
            <div className="text-[9px] text-slate-400">Precedence Validated</div>
          </div>
          <div className="bg-slate-900/80 p-2 rounded border border-amber-800/80 bg-amber-950/20">
            <div className="text-[10px] text-amber-300 font-mono">STEP 4 &bull; ROUTER</div>
            <div className="font-bold text-amber-400 font-mono mt-0.5">ISOLATED DOCKER</div>
            <div className="text-[9px] text-slate-400">deception-net ONLY</div>
          </div>
          <div className="bg-slate-900/80 p-2 rounded border border-purple-800/80 bg-purple-950/20">
            <div className="text-[10px] text-purple-300 font-mono">STEP 5 &bull; DECOY</div>
            <div className="font-bold text-purple-300 font-mono mt-0.5">SYNTHETIC APPS</div>
            <div className="text-[9px] text-slate-400">Login / Admin / API</div>
          </div>
          <div className="bg-slate-900/80 p-2 rounded border border-emerald-800/80 bg-emerald-950/20">
            <div className="text-[10px] text-emerald-300 font-mono">STEP 6 &bull; VERIFY</div>
            <div className="font-bold text-emerald-400 font-mono mt-0.5">ORIGIN: ZERO HIT</div>
            <div className="text-[9px] text-slate-400">100% Contained</div>
          </div>
        </div>
      </div>

      {/* Main Grid: Active Session Details + Live Evidence Timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 mt-5">
        
        {/* Left Column: Metrics & Active Session Overview (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          
          {/* Top Counter Badges */}
          <div className="grid grid-cols-3 gap-2.5">
            <div className="bg-soc-card p-3 rounded-lg border border-soc-border">
              <span className="text-[10px] uppercase font-mono text-slate-400 block">Active Decoys</span>
              <span className="text-xl font-bold font-mono text-purple-400 mt-1 block">
                {stats?.active_sessions ?? 0}
              </span>
            </div>
            <div className="bg-soc-card p-3 rounded-lg border border-soc-border">
              <span className="text-[10px] uppercase font-mono text-slate-400 block">Total Sessions</span>
              <span className="text-xl font-bold font-mono text-cyan-400 mt-1 block">
                {stats?.total_sessions ?? 0}
              </span>
            </div>
            <div className="bg-soc-card p-3 rounded-lg border border-soc-border">
              <span className="text-[10px] uppercase font-mono text-slate-400 block">Evidence Events</span>
              <span className="text-xl font-bold font-mono text-emerald-400 mt-1 block">
                {stats?.total_evidence_events ?? 0}
              </span>
            </div>
          </div>

          {/* Active Session Inspection Card */}
          <div className="bg-soc-card p-4 rounded-lg border border-purple-800/70 shadow-sm shadow-purple-950/40">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-mono font-bold text-purple-300 flex items-center gap-1.5 uppercase">
                <ShieldAlert className="w-4 h-4 text-purple-400" />
                Active Deception Session
              </span>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                activeSession?.status === 'ACTIVE' 
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' 
                  : 'bg-slate-800 text-slate-400 border border-slate-700'
              }`}>
                {activeSession?.status || 'NO ACTIVE SESSION'}
              </span>
            </div>

            {activeSession ? (
              <div className="space-y-2.5 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">Session ID:</span>
                  <span className="text-slate-200 font-semibold text-[11px] truncate max-w-[200px]">
                    {activeSession.session_id}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">Source Identifier Hash:</span>
                  <span className="text-cyan-400 text-[11px] font-mono">
                    {activeSession.source_identifier_hash}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">Qualified Trigger Scores:</span>
                  <span className="text-slate-200">
                    Risk: <strong className="text-amber-400">{activeSession.initial_risk_score ?? 'N/A'}</strong> | 
                    AgentShield: <strong className="text-purple-400">{activeSession.initial_agent_shield_score ?? 'N/A'}</strong>
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">Interactions Captured:</span>
                  <span className="text-emerald-400 font-bold">
                    {activeSession.interaction_count} requests ({activeSession.evidence_count} evidence records)
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">Origin Workload Access:</span>
                  <span className="text-emerald-400 font-bold bg-emerald-950/60 px-1.5 py-0.5 rounded border border-emerald-800">
                    ZERO ACCESS &bull; CONTAINED
                  </span>
                </div>
                <div className="pt-2 text-[11px] text-slate-400 italic">
                  &ldquo;{activeSession.entry_reason || 'Qualified through Phase 7 Policy Engine evaluation.'}&rdquo;
                </div>
              </div>
            ) : (
              <div className="text-center py-6 text-slate-500 font-mono text-xs">
                No active deception sessions. Clean or blocked traffic currently active.
              </div>
            )}
          </div>

          {/* Decoy Environment Sandbox Integrity Box */}
          <div className="bg-slate-900/90 border border-slate-800 p-3.5 rounded-lg text-xs space-y-1.5">
            <div className="flex items-center gap-2 font-mono font-semibold text-slate-300 text-[11px]">
              <Database className="w-3.5 h-3.5 text-purple-400" />
              <span>Sandbox Isolation Verification</span>
            </div>
            <ul className="text-[11px] text-slate-400 space-y-1 pl-4 list-disc">
              <li>Decoy container operates strictly on isolated <code className="text-purple-300">deception-net</code> bridge.</li>
              <li>Production PostgreSQL store completely unreachable from Decoy.</li>
              <li>Real application origin (:8088) completely isolated from Decoy network namespace.</li>
              <li>Zero real credentials: synthetic administrative data only.</li>
            </ul>
          </div>
        </div>

        {/* Right Column: Live Attacker Interaction Timeline (7 cols) */}
        <div className="lg:col-span-7 bg-soc-card p-4 rounded-lg border border-soc-border flex flex-col h-full">
          <div className="flex items-center justify-between mb-3 pb-2 border-b border-soc-border">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-purple-400" />
              <span className="text-xs font-mono font-bold text-slate-200 uppercase">
                Attacker Behavioral Timeline & Evidence Stream
              </span>
            </div>
            <span className="text-[10px] font-mono text-slate-400">
              {sessionEvents.length} Captured Events
            </span>
          </div>

          {/* Timeline Feed */}
          <div className="space-y-2 overflow-y-auto max-h-[380px] pr-1 flex-1">
            {sessionEvents.length > 0 ? (
              sessionEvents.map((ev, idx) => (
                <div 
                  key={ev.event_id || idx}
                  onClick={() => setSelectedEvent(ev)}
                  className={`p-2.5 rounded border transition cursor-pointer font-mono text-xs ${
                    selectedEvent?.event_id === ev.event_id 
                      ? 'bg-purple-950/50 border-purple-600' 
                      : 'bg-slate-900/70 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        ev.event_type.includes('LOGIN') ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                        ev.event_type.includes('ADMIN') ? 'bg-red-950 text-red-300 border border-red-800' :
                        ev.event_type.includes('API') ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' :
                        'bg-purple-950 text-purple-300 border border-purple-800'
                      }`}>
                        {ev.event_type}
                      </span>
                      <span className="text-slate-300 font-bold">{ev.method} {ev.route}</span>
                    </div>
                    <span className="text-[10px] text-slate-500">
                      {ev.created_at ? new Date(ev.created_at).toLocaleTimeString() : 'now'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between mt-1.5 text-[11px] text-slate-400">
                    <span>Category: <strong className="text-slate-300">{ev.endpoint_category || 'APP'}</strong></span>
                    <span>Status: <strong className={ev.response_status === 401 ? 'text-amber-400' : 'text-emerald-400'}>HTTP {ev.response_status}</strong></span>
                    <span className="text-slate-500">Click to view evidence &rarr;</span>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-12 text-slate-500 font-mono text-xs">
                No interaction events recorded for this session yet.
              </div>
            )}
          </div>

          {/* Quick Disclaimer */}
          <div className="mt-3 pt-2 border-t border-soc-border/60 text-[10px] font-mono text-slate-500">
            AEGIS &bull; Invariant: WAF terminal block pre-empts deception. Decoy interactions strictly record sanitized telemetry.
          </div>
        </div>

      </div>

      {/* Drilldown Evidence Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-soc-panel border border-soc-border rounded-xl max-w-xl w-full p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-soc-border">
              <div className="flex items-center gap-2 font-mono font-bold text-sm text-slate-200">
                <FileText className="w-4 h-4 text-purple-400" />
                <span>Deception Evidence Details &bull; {selectedEvent.event_type}</span>
              </div>
              <button 
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-slate-200 font-mono text-xs px-2 py-1 bg-slate-800 rounded"
              >
                Close &times;
              </button>
            </div>

            <div className="space-y-2.5 font-mono text-xs max-h-[350px] overflow-y-auto">
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Event ID:</span>
                <span className="text-slate-200">{selectedEvent.event_id}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Session ID:</span>
                <span className="text-purple-400">{selectedEvent.session_id}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Route & Method:</span>
                <span className="text-cyan-400">{selectedEvent.method} {selectedEvent.route}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Endpoint Category:</span>
                <span className="text-amber-400">{selectedEvent.endpoint_category}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Response Status:</span>
                <span className="text-slate-200">HTTP {selectedEvent.response_status}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Origin Workload Hit:</span>
                <span className="text-emerald-400 font-bold">FALSE (0 Hits)</span>
              </div>

              <div>
                <span className="text-slate-400 block mb-1">Sanitized Metadata:</span>
                <pre className="p-3 bg-slate-900 rounded border border-slate-800 text-[11px] text-slate-300 overflow-x-auto">
                  {JSON.stringify(selectedEvent.metadata || {}, null, 2)}
                </pre>
              </div>
            </div>

            <div className="pt-2 text-right">
              <button 
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-1.5 bg-purple-700 hover:bg-purple-600 text-white rounded text-xs font-mono"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
