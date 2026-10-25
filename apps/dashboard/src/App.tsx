import React, { useState, useEffect, useRef } from 'react';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { SystemHealthCard } from './components/SystemHealthCard';
import { TrafficFlowDiagram } from './components/TrafficFlowDiagram';
import { RiskEnginePanel } from './components/RiskEnginePanel';
import { AgentShieldPanel } from './components/AgentShieldPanel';
import { PolicyEnginePanel } from './components/PolicyEnginePanel';
import { DeceptionPanel } from './components/DeceptionPanel';
import { VerificationPanel } from './components/VerificationPanel';
import { AttackerIntelligencePanel } from './components/AttackerIntelligencePanel';
import { AttackStoryVisualizer } from './components/AttackStoryVisualizer';
import { SecurityEventsStream } from './components/SecurityEventsStream';
import { SystemStatusData } from './types';
import { 
  ShieldCheck, 
  Terminal, 
  AlertCircle, 
  ShieldAlert, 
  Radio, 
  Flame, 
  Bot, 
  Scale, 
  EyeOff, 
  CheckCircle2, 
  Crosshair, 
  ArrowRight,
  Compass
} from 'lucide-react';

const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
  ? `http://${window.location.hostname}:8001`
  : '/api';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<string>('overview');
  const [systemData, setSystemData] = useState<SystemStatusData | null>(null);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [lastSynced, setLastSynced] = useState<string>('Never');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [lastWsEvent, setLastWsEvent] = useState<any>(null);

  const wsRef = useRef<WebSocket | null>(null);

  const fetchStatus = async () => {
    setIsRefreshing(true);
    setErrorMsg(null);
    try {
      let res;
      try {
        res = await fetch(`${API_BASE}/api/v1/system/status`);
      } catch (e) {
        res = await fetch(`http://${window.location.hostname}:8080/api/v1/system/status`);
      }
      
      if (!res.ok) {
        throw new Error(`HTTP Error: ${res.status}`);
      }
      const data: SystemStatusData = await res.json();
      setSystemData(data);
      setLastSynced(new Date().toLocaleTimeString());
    } catch (err: any) {
      console.warn('API Fetch error:', err);
      setErrorMsg(`API / Database connection pending. Ensure backend services are running. (${err.message})`);
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 8000);
    return () => clearInterval(interval);
  }, []);

  // Connect global WebSocket to receive live telemetry events
  useEffect(() => {
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
          setLastWsEvent(payload);
          // Auto refresh system status counts on important actions
          if (
            payload.event_type === 'MITIGATION_VERIFIED' ||
            payload.event_type === 'DECEPTION_EVENT' ||
            payload.event_type === 'WAF_BLOCK' ||
            payload.event_type === 'POLICY_DECISION'
          ) {
            fetchStatus();
          }
        } catch (e) {
          // ignore non-json
        }
      };
    } catch (e) {
      console.warn('WebSocket init error:', e);
    }

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  return (
    <div className="min-h-screen bg-soc-bg flex flex-col text-slate-100 font-sans">
      <Header 
        onRefresh={fetchStatus} 
        isRefreshing={isRefreshing} 
        systemStatus={systemData?.status === 'operational' ? 'System Ready' : 'Initializing'} 
      />

      <div className="flex flex-1 overflow-hidden">
        <Sidebar currentTab={currentTab} setCurrentTab={setCurrentTab} />

        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          {errorMsg && (
            <div className="bg-amber-950/50 border border-amber-800/80 rounded-xl p-4 flex items-center justify-between text-amber-300 text-xs font-mono">
              <div className="flex items-center space-x-2">
                <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
                <span>{errorMsg}</span>
              </div>
              <button 
                onClick={fetchStatus} 
                className="underline hover:text-white shrink-0 ml-4"
              >
                Retry
              </button>
            </div>
          )}

          {/* OVERVIEW TAB */}
          {currentTab === 'overview' && (
            <div className="space-y-6">
              {/* Executive Security Header */}
              <div className="bg-soc-panel border border-soc-border rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-cyan-400 font-mono font-bold text-lg">AEGIS Ω</span>
                    <span className="text-slate-500 font-mono text-sm">&bull;</span>
                    <span className="text-slate-300 font-mono text-xs uppercase tracking-wider">
                      Adaptive Security Boundary &amp; Defense Platform
                    </span>
                  </div>
                  <p className="text-slate-400 text-xs mt-1">
                    Detect &rarr; Predict &rarr; Deceive &rarr; Contain &rarr; Verify. Machine-checked origin protection.
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-950/80 border border-emerald-800 text-emerald-400 text-xs font-mono">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                    <span>SYSTEM STATUS: OPERATIONAL</span>
                  </div>
                  <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 text-xs font-mono">
                    WS: {wsConnected ? <span className="text-emerald-400">STREAMING</span> : <span className="text-amber-400">CONNECTING</span>} &bull; Synced: {lastSynced}
                  </div>
                </div>
              </div>

              {/* 9 Real Backend Metrics Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 xl:grid-cols-9 gap-3">
                <div className="bg-soc-panel border border-soc-border rounded-xl p-3 flex flex-col justify-between">
                  <div>
                    <span className="text-slate-400 text-[10px] font-mono uppercase">GATEWAY INGRESS</span>
                    <div className="text-lg font-bold font-mono text-white mt-0.5">PORT 8080</div>
                  </div>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-soc-border/40">
                    <span className="text-[10px] text-cyan-400 font-mono">Nginx Hardened</span>
                    <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  </div>
                </div>

                <div className="bg-soc-panel border border-soc-border rounded-xl p-3 flex flex-col justify-between">
                  <div>
                    <span className="text-slate-400 text-[10px] font-mono uppercase">WAF THREATS</span>
                    <div className="text-lg font-bold font-mono text-amber-400 mt-0.5">
                      {systemData?.metrics.waf_events_count ?? 0}
                    </div>
                  </div>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-soc-border/40">
                    <span className="text-[10px] text-amber-300 font-mono">Coraza + CRS</span>
                    <ShieldAlert className="w-4 h-4 text-amber-400" />
                  </div>
                </div>

                <div className="bg-soc-panel border border-soc-border rounded-xl p-3 flex flex-col justify-between">
                  <div>
                    <span className="text-slate-400 text-[10px] font-mono uppercase">SECURITY EVENTS</span>
                    <div className="text-lg font-bold font-mono text-cyan-400 mt-0.5">
                      {systemData?.metrics.security_events_count ?? 0}
                    </div>
                  </div>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-soc-border/40">
                    <span className="text-[10px] text-cyan-300 font-mono">Correlated</span>
                    <Radio className="w-4 h-4 text-cyan-400" />
                  </div>
                </div>

                <div className="bg-soc-panel border border-soc-border rounded-xl p-3 flex flex-col justify-between">
                  <div>
                    <span className="text-slate-400 text-[10px] font-mono uppercase">RISK SCORES</span>
                    <div className="text-lg font-bold font-mono text-rose-400 mt-0.5">
                      {systemData?.metrics.risk_assessments_count ?? 0}
                    </div>
                  </div>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-soc-border/40">
                    <span className="text-[10px] text-rose-300 font-mono">0-100 Weighted</span>
                    <Flame className="w-4 h-4 text-rose-400" />
                  </div>
                </div>

                <div className="bg-soc-panel border border-soc-border rounded-xl p-3 flex flex-col justify-between">
                  <div>
                    <span className="text-slate-400 text-[10px] font-mono uppercase">AGENTSHIELD</span>
                    <div className="text-lg font-bold font-mono text-indigo-400 mt-0.5">
                      {systemData?.metrics.agent_shield_assessments_count ?? 0}
                    </div>
                  </div>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-soc-border/40">
                    <span className="text-[10px] text-indigo-300 font-mono">Behavioral</span>
                    <Bot className="w-4 h-4 text-indigo-400" />
                  </div>
                </div>

                <div className="bg-soc-panel border border-soc-border rounded-xl p-3 flex flex-col justify-between">
                  <div>
                    <span className="text-slate-400 text-[10px] font-mono uppercase">POLICY DECISIONS</span>
                    <div className="text-lg font-bold font-mono text-purple-400 mt-0.5">
                      {systemData?.metrics.policy_decisions_count ?? 0}
                    </div>
                  </div>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-soc-border/40">
                    <span className="text-[10px] text-purple-300 font-mono">Deterministic</span>
                    <Scale className="w-4 h-4 text-purple-400" />
                  </div>
                </div>

                <div className="bg-soc-panel border border-soc-border rounded-xl p-3 flex flex-col justify-between">
                  <div>
                    <span className="text-slate-400 text-[10px] font-mono uppercase">DECOY SESSIONS</span>
                    <div className="text-lg font-bold font-mono text-purple-400 mt-0.5">
                      {systemData?.metrics.deception_sessions_count ?? 0}
                    </div>
                  </div>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-soc-border/40">
                    <span className="text-[10px] text-purple-300 font-mono">Isolated Decoy</span>
                    <EyeOff className="w-4 h-4 text-purple-400" />
                  </div>
                </div>

                <div className="bg-soc-panel border border-emerald-900/80 bg-emerald-950/20 rounded-xl p-3 flex flex-col justify-between">
                  <div>
                    <span className="text-emerald-400 text-[10px] font-mono uppercase">VERIFIED PROOFS</span>
                    <div className="text-lg font-bold font-mono text-emerald-300 mt-0.5">
                      {systemData?.metrics.verified_mitigations_count ?? 0}
                    </div>
                  </div>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-emerald-900/60">
                    <span className="text-[10px] text-emerald-400 font-mono">Origin Untouched</span>
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  </div>
                </div>

                <div 
                  onClick={() => setCurrentTab('intelligence')}
                  className="bg-soc-panel border border-cyan-900/80 bg-cyan-950/20 rounded-xl p-3 flex flex-col justify-between cursor-pointer hover:border-cyan-500 transition-all"
                >
                  <div>
                    <span className="text-cyan-400 text-[10px] font-mono uppercase">ATTACKER INTEL</span>
                    <div className="text-lg font-bold font-mono text-cyan-300 mt-0.5">
                      {systemData?.metrics.source_profiles_count ?? 0}
                    </div>
                  </div>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-cyan-900/60">
                    <span className="text-[10px] text-cyan-400 font-mono">MITRE &amp; GeoIP</span>
                    <Compass className="w-4 h-4 text-cyan-400" />
                  </div>
                </div>
              </div>

              {/* Traffic Flow Pipeline Component */}
              <TrafficFlowDiagram />

              {/* Attack Story Visualizer Card */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs uppercase font-mono tracking-wider font-semibold text-slate-300 flex items-center gap-2">
                    <Crosshair className="w-4 h-4 text-cyan-400" />
                    Interactive Incident Narrative: Detect &rarr; Analyze &rarr; Decide &rarr; Deceive &rarr; Verify
                  </h3>
                  <button 
                    onClick={() => setCurrentTab('story')}
                    className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                  >
                    Open Story Mode <ArrowRight className="w-3 h-3" />
                  </button>
                </div>
                <AttackStoryVisualizer />
              </div>

              {/* Response Verification Panel */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs uppercase font-mono tracking-wider font-semibold text-slate-300 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    Response Verification &amp; Cryptographic Receipts (Phase 9)
                  </h3>
                  <button 
                    onClick={() => setCurrentTab('verification')}
                    className="text-xs font-mono text-emerald-400 hover:text-emerald-300 flex items-center gap-1"
                  >
                    View All Proofs <ArrowRight className="w-3 h-3" />
                  </button>
                </div>
                <VerificationPanel apiBase={API_BASE} realtimeEvent={lastWsEvent} />
              </div>

              {/* Attacker Intelligence & Threat Context Section */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs uppercase font-mono tracking-wider font-semibold text-slate-300 flex items-center gap-2">
                    <Compass className="w-4 h-4 text-cyan-400" />
                    Attacker Intelligence, Threat Context &amp; MITRE Mapping (Phase 10)
                  </h3>
                  <button 
                    onClick={() => setCurrentTab('intelligence')}
                    className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                  >
                    Open Intelligence Console <ArrowRight className="w-3 h-3" />
                  </button>
                </div>
                <AttackerIntelligencePanel apiBase={API_BASE} realtimeEvent={lastWsEvent} />
              </div>

              {/* Microservices Matrix */}
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-xs uppercase font-mono tracking-wider font-semibold text-slate-300 flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-cyan-400" />
                    AEGIS Ω Microservices Subsystem Status
                  </h3>
                  <span className="text-[11px] font-mono text-slate-500">
                    All Core Modules Active &amp; Isolated
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  {systemData ? (
                    Object.entries(systemData.services).map(([key, service]) => (
                      <SystemHealthCard
                        key={key}
                        serviceKey={key}
                        name={key.replace('_', ' ')}
                        service={service}
                      />
                    ))
                  ) : (
                    <>
                      <SystemHealthCard 
                        serviceKey="gateway" 
                        name="Gateway" 
                        service={{ status: 'operational', type: 'Nginx Ingress Gateway', role: 'Traffic Ingress, Tracing & Headers' }} 
                      />
                      <SystemHealthCard 
                        serviceKey="waf" 
                        name="WAF" 
                        service={{ status: 'operational', type: 'Coraza v3 + OWASP CRS v4.3.0', role: 'Real Application Firewall & Rule Engine' }} 
                      />
                      <SystemHealthCard 
                        serviceKey="database" 
                        name="Database" 
                        service={{ status: 'connected', type: 'PostgreSQL 16', role: 'State & Telemetry Store' }} 
                      />
                      <SystemHealthCard 
                        serviceKey="api" 
                        name="Control Plane" 
                        service={{ status: 'healthy', type: 'FastAPI Core', role: 'Control Plane & REST API' }} 
                      />
                    </>
                  )}
                </div>
              </div>

              {/* System Audit Events */}
              <div className="bg-soc-panel border border-soc-border rounded-xl p-5">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-xs uppercase font-mono tracking-wider font-semibold text-slate-300">
                    System Audit Log &amp; Telemetry Persistence Verification
                  </h3>
                  <span className="text-[11px] font-mono text-cyan-400">PostgreSQL Store</span>
                </div>

                <div className="font-mono text-xs space-y-2 bg-soc-card p-4 rounded-lg border border-soc-border">
                  {systemData?.metrics.recent_events && systemData.metrics.recent_events.length > 0 ? (
                    systemData.metrics.recent_events.map((ev, idx) => (
                      <div key={idx} className="flex items-start justify-between border-b border-soc-border/40 pb-2">
                        <div className="flex items-center gap-2">
                          <span className="text-emerald-400">[{ev.severity}]</span>
                          <span className="text-slate-200">{ev.service_name}:</span>
                          <span className="text-slate-400">{ev.event_type}</span>
                          <span className="text-slate-500 text-[11px]">({JSON.stringify(ev.details)})</span>
                        </div>
                        <span className="text-slate-500 text-[10px]">{ev.created_at}</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-slate-500">
                      Awaiting database connection event logs...
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ATTACK STORY TAB */}
          {currentTab === 'story' && (
            <div className="space-y-4">
              <AttackStoryVisualizer />
            </div>
          )}

          {/* LIVE THREAT FEED TAB */}
          {currentTab === 'feed' && (
            <div className="space-y-4">
              <SecurityEventsStream apiBase={API_BASE} />
            </div>
          )}

          {/* RISK ENGINE TAB */}
          {currentTab === 'risk' && (
            <div className="space-y-4">
              <RiskEnginePanel apiBase={API_BASE} />
            </div>
          )}

          {/* AGENTSHIELD TAB */}
          {currentTab === 'agentshield' && (
            <div className="space-y-4">
              <AgentShieldPanel apiBase={API_BASE} />
            </div>
          )}

          {/* POLICY ENGINE TAB */}
          {currentTab === 'policy' && (
            <div className="space-y-4">
              <PolicyEnginePanel apiBase={API_BASE} />
            </div>
          )}

          {/* DECEPTION TAB */}
          {currentTab === 'deception' && (
            <div className="space-y-4">
              <DeceptionPanel apiBase={API_BASE} realtimeEvent={lastWsEvent} />
            </div>
          )}

          {/* VERIFICATION TAB */}
          {currentTab === 'verification' && (
            <div className="space-y-4">
              <VerificationPanel apiBase={API_BASE} realtimeEvent={lastWsEvent} />
            </div>
          )}

          {/* ATTACKER INTELLIGENCE TAB */}
          {currentTab === 'intelligence' && (
            <div className="space-y-4">
              <AttackerIntelligencePanel apiBase={API_BASE} realtimeEvent={lastWsEvent} />
            </div>
          )}

          {/* ARCHITECTURE / TOPOLOGY TAB */}
          {currentTab === 'architecture' && (
            <div className="space-y-6">
              <TrafficFlowDiagram />
              <div>
                <h3 className="text-xs uppercase font-mono tracking-wider font-semibold text-slate-300 mb-3">
                  Service Topology &amp; Microservice Ingress
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  {systemData && Object.entries(systemData.services).map(([key, service]) => (
                    <SystemHealthCard
                      key={key}
                      serviceKey={key}
                      name={key.replace('_', ' ')}
                      service={service}
                    />
                  ))}
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
};

export default App;
