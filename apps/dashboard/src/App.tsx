import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { SystemHealthCard } from './components/SystemHealthCard';
import { TrafficFlowDiagram } from './components/TrafficFlowDiagram';
import { SystemStatusData } from './types';
import { ShieldCheck, Database, Layers, Terminal, AlertCircle, ShieldAlert } from 'lucide-react';

const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
  ? `http://${window.location.hostname}:8001`
  : '/api';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<string>('overview');
  const [systemData, setSystemData] = useState<SystemStatusData | null>(null);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [lastSynced, setLastSynced] = useState<string>('Never');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

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

  return (
    <div className="min-h-screen bg-soc-bg flex flex-col text-slate-100">
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

          {/* Quick Metrics Banner */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-soc-panel border border-soc-border rounded-xl p-4 flex items-center justify-between">
              <div>
                <span className="text-slate-400 text-xs font-mono">GATEWAY INGRESS</span>
                <div className="text-xl font-bold font-mono text-white mt-1">PORT 8080</div>
                <span className="text-[10px] text-cyan-400 font-mono">Proxy & Tracing Active</span>
              </div>
              <div className="p-3 bg-cyan-950 rounded-lg border border-cyan-800">
                <ShieldCheck className="w-5 h-5 text-cyan-400" />
              </div>
            </div>

            <div className="bg-soc-panel border border-soc-border rounded-xl p-4 flex items-center justify-between">
              <div>
                <span className="text-slate-400 text-xs font-mono">WAF / CRS DEFENSE</span>
                <div className="text-xl font-bold font-mono text-amber-400 mt-1">
                  {systemData?.services.waf.mode ?? 'BLOCK'} MODE
                </div>
                <span className="text-[10px] text-amber-300 font-mono">
                  {systemData?.metrics.waf_events_count ?? 0} Threats Intercepted
                </span>
              </div>
              <div className="p-3 bg-amber-950 rounded-lg border border-amber-800">
                <ShieldAlert className="w-5 h-5 text-amber-400" />
              </div>
            </div>

            <div className="bg-soc-panel border border-soc-border rounded-xl p-4 flex items-center justify-between">
              <div>
                <span className="text-slate-400 text-xs font-mono">DATABASE STATE</span>
                <div className="text-xl font-bold font-mono text-white mt-1">
                  {systemData?.services.database.status === 'connected' ? 'CONNECTED' : 'STANDBY'}
                </div>
                <span className="text-[10px] text-slate-400 font-mono">
                  {systemData?.metrics.system_events_count ?? 0} System Events
                </span>
              </div>
              <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                <Database className="w-5 h-5 text-slate-300" />
              </div>
            </div>

            <div className="bg-soc-panel border border-soc-border rounded-xl p-4 flex items-center justify-between">
              <div>
                <span className="text-slate-400 text-xs font-mono">LAST TELEMETRY SYNC</span>
                <div className="text-xl font-bold font-mono text-cyan-400 mt-1">{lastSynced}</div>
                <span className="text-[10px] text-slate-400 font-mono">Auto-polling: 8s</span>
              </div>
              <div className="p-3 bg-indigo-950 rounded-lg border border-indigo-800">
                <Layers className="w-5 h-5 text-indigo-400" />
              </div>
            </div>
          </div>

          {/* Traffic Flow Pipeline Component */}
          <TrafficFlowDiagram />

          {/* System Services Matrix */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs uppercase font-mono tracking-wider font-semibold text-slate-300 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                AEGIS Ω Microservices Subsystem Status
              </h3>
              <span className="text-[11px] font-mono text-slate-500">
                Phase 3 Prototype Verification
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

          {/* Live Recent System Audit Events */}
          <div className="bg-soc-panel border border-soc-border rounded-xl p-5">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs uppercase font-mono tracking-wider font-semibold text-slate-300">
                System Audit Log & Telemetry Persistence Verification
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
        </main>
      </div>
    </div>
  );
};

export default App;
