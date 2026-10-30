import React, { useState, useEffect } from 'react';
import { 
  Radio, 
  ShieldAlert, 
  Activity, 
  AlertTriangle, 
  Play, 
  RefreshCw, 
  Unlock, 
  Zap, 
  Layers, 
  Search
} from 'lucide-react';
import { 
  NetworkDefenseStatusData, 
  NetworkEventItem, 
  NetworkEnforcementItem 
} from '../types';

interface NetworkDefensePanelProps {
  apiBase: string;
  realtimeEvent?: any;
}

export const NetworkDefensePanel: React.FC<NetworkDefensePanelProps> = ({ 
  apiBase, 
  realtimeEvent 
}) => {
  const [statusData, setStatusData] = useState<NetworkDefenseStatusData | null>(null);
  const [events, setEvents] = useState<NetworkEventItem[]>([]);
  const [enforcements, setEnforcements] = useState<NetworkEnforcementItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [filterText, setFilterText] = useState<string>('');
  const [demoRunning, setDemoRunning] = useState<string | null>(null);
  const [demoMessage, setDemoMessage] = useState<string | null>(null);

  const fetchStatus = async () => {
    try {
      const res = await fetch(`${apiBase}/api/v1/network-defense/status`);
      if (res.ok) {
        const data = await res.json();
        setStatusData(data);
      }
    } catch (e) {
      console.warn("Failed to fetch network defense status:", e);
    }
  };

  const fetchEvents = async () => {
    try {
      const res = await fetch(`${apiBase}/api/v1/network-defense/events?limit=30`);
      if (res.ok) {
        const data = await res.json();
        setEvents(data.events || []);
      }
    } catch (e) {
      console.warn("Failed to fetch network defense events:", e);
    }
  };

  const fetchEnforcements = async () => {
    try {
      const res = await fetch(`${apiBase}/api/v1/network-defense/enforcements`);
      if (res.ok) {
        const data = await res.json();
        setEnforcements(data.enforcements || []);
      }
    } catch (e) {
      console.warn("Failed to fetch enforcements:", e);
    }
  };

  const refreshAll = async () => {
    setIsLoading(true);
    await Promise.all([fetchStatus(), fetchEvents(), fetchEnforcements()]);
    setIsLoading(false);
  };

  useEffect(() => {
    refreshAll();
    const interval = setInterval(refreshAll, 8000);
    return () => clearInterval(interval);
  }, [apiBase]);

  // Handle WebSocket updates
  useEffect(() => {
    if (!realtimeEvent) return;
    if (
      realtimeEvent.event_type === 'NETWORK_EVENT_INGESTED' ||
      realtimeEvent.event_type === 'NETWORK_ENFORCEMENT_ACTION' ||
      realtimeEvent.event_type === 'NETWORK_ANOMALY_DETECTED'
    ) {
      fetchStatus();
      fetchEvents();
      fetchEnforcements();
    }
  }, [realtimeEvent]);

  const handleRelease = async (sourceIp: string) => {
    try {
      const res = await fetch(`${apiBase}/api/v1/network-defense/release/${encodeURIComponent(sourceIp)}`, {
        method: 'POST'
      });
      if (res.ok) {
        fetchEnforcements();
        fetchStatus();
      }
    } catch (e) {
      console.error("Release failed:", e);
    }
  };

  const handleTriggerDemo = async (scenario: string) => {
    setDemoRunning(scenario);
    setDemoMessage(null);
    try {
      const res = await fetch(`${apiBase}/api/v1/network-defense/demo/trigger?scenario=${scenario}`, {
        method: 'POST'
      });
      if (res.ok) {
        const data = await res.json();
        setDemoMessage(`Scenario ${scenario} executed successfully on test IP ${data.demo_ip}. Telemetry streamed to console.`);
        refreshAll();
      } else {
        setDemoMessage(`Failed to execute demo scenario.`);
      }
    } catch (e) {
      setDemoMessage(`Error triggering demo scenario.`);
    } finally {
      setDemoRunning(null);
    }
  };

  const filteredEvents = events.filter(e => 
    e.source_ip.toLowerCase().includes(filterText.toLowerCase()) ||
    (e.signature && e.signature.toLowerCase().includes(filterText.toLowerCase())) ||
    e.event_type.toLowerCase().includes(filterText.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-soc-panel border border-soc-border rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
            <h2 className="text-lg font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2">
              <Radio className="w-5 h-5 text-cyan-400" />
              REAL NETWORK DEFENSE — IDS/IPS &amp; NETWORK CORRELATION
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
              Phase 11 Active
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Suricata EVE JSON IDS/IPS engine, deterministic network risk scoring, adaptive traffic rate-limiting, and DoS anomaly radar.
          </p>
        </div>

        {/* Sensor & Mode Status Badges */}
        <div className="flex items-center gap-3 font-mono text-xs">
          <div className="bg-slate-900 border border-soc-border rounded-lg px-3 py-1.5 flex items-center gap-2">
            <span className="text-slate-400">Sensor:</span>
            <span className="font-bold text-slate-200">Suricata 7</span>
            <span className={`w-2 h-2 rounded-full ${statusData?.sensor?.status === 'LIVE' ? 'bg-emerald-400' : 'bg-amber-400'}`} />
            <span className="text-[10px] text-slate-400 font-semibold">{statusData?.sensor?.status || 'STANDBY'}</span>
          </div>

          <div className="bg-slate-900 border border-soc-border rounded-lg px-3 py-1.5 flex items-center gap-2">
            <span className="text-slate-400">Enforcement:</span>
            <span className="text-emerald-400 font-bold">STATEFUL IPS</span>
          </div>

          <button 
            onClick={refreshAll}
            className="p-2 rounded-lg bg-soc-card border border-soc-border text-slate-400 hover:text-cyan-400 hover:border-cyan-600 transition-all"
            title="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* 4 Real Metric Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-soc-panel border border-soc-border rounded-xl p-4">
          <span className="text-[10px] font-mono uppercase text-slate-400">Total Network Events</span>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">
            {statusData?.stats?.total_network_events ?? events.length}
          </div>
          <div className="text-[11px] font-mono text-cyan-300/80 mt-1 flex items-center gap-1">
            <Activity className="w-3.5 h-3.5" />
            EVE Stream Ingested
          </div>
        </div>

        <div className="bg-soc-panel border border-soc-border rounded-xl p-4">
          <span className="text-[10px] font-mono uppercase text-slate-400">Suricata IDS Alerts</span>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-1">
            {statusData?.stats?.ids_alerts_count ?? events.filter(e => e.event_type === 'ALERT').length}
          </div>
          <div className="text-[11px] font-mono text-amber-300/80 mt-1 flex items-center gap-1">
            <ShieldAlert className="w-3.5 h-3.5" />
            Signature Detections
          </div>
        </div>

        <div className="bg-soc-panel border border-soc-border rounded-xl p-4">
          <span className="text-[10px] font-mono uppercase text-slate-400">Active IPS Enforcements</span>
          <div className="text-2xl font-bold font-mono text-rose-400 mt-1">
            {enforcements.length}
          </div>
          <div className="text-[11px] font-mono text-rose-300/80 mt-1 flex items-center gap-1">
            <Zap className="w-3.5 h-3.5" />
            Blocks &amp; Rate-Limits
          </div>
        </div>

        <div className="bg-soc-panel border border-soc-border rounded-xl p-4">
          <span className="text-[10px] font-mono uppercase text-slate-400">Traffic Rate Baseline</span>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
            {statusData?.traffic_baseline_rps ?? 10.0} <span className="text-xs text-slate-400">req/s</span>
          </div>
          <div className="text-[11px] font-mono text-emerald-300/80 mt-1 flex items-center gap-1">
            <Activity className="w-3.5 h-3.5" />
            Moving Average
          </div>
        </div>
      </div>

      {/* Demo Scenario Controller Bar */}
      <div className="bg-soc-panel border border-soc-border rounded-xl p-4 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Play className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
              Controlled Local Demo Scenarios
            </h3>
            <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
              Container Lab Only
            </span>
          </div>
          <span className="text-[11px] font-mono text-slate-500">
            Simulate realistic multi-stage network attacks without touching external targets
          </span>
        </div>

        <div className="flex flex-wrap gap-2 pt-1">
          <button
            onClick={() => handleTriggerDemo('NORMAL_TRAFFIC')}
            disabled={demoRunning !== null}
            className="px-3 py-1.5 rounded-lg bg-soc-card border border-soc-border hover:border-slate-600 text-slate-300 font-mono text-xs transition-all disabled:opacity-50"
          >
            1. Normal Flow
          </button>
          <button
            onClick={() => handleTriggerDemo('NETWORK_RECON')}
            disabled={demoRunning !== null}
            className="px-3 py-1.5 rounded-lg bg-soc-card border border-amber-900/60 text-amber-300 hover:border-amber-700 font-mono text-xs transition-all disabled:opacity-50"
          >
            2. SYN Port Sweep
          </button>
          <button
            onClick={() => handleTriggerDemo('WEB_ATTACK')}
            disabled={demoRunning !== null}
            className="px-3 py-1.5 rounded-lg bg-soc-card border border-rose-900/60 text-rose-300 hover:border-rose-700 font-mono text-xs transition-all disabled:opacity-50"
          >
            3. Web Exploit Attack
          </button>
          <button
            onClick={() => handleTriggerDemo('TRAFFIC_ANOMALY')}
            disabled={demoRunning !== null}
            className="px-3 py-1.5 rounded-lg bg-soc-card border border-purple-900/60 text-purple-300 hover:border-purple-700 font-mono text-xs transition-all disabled:opacity-50"
          >
            4. Traffic Burst Anomaly
          </button>
          <button
            onClick={() => handleTriggerDemo('FULL_ADAPTIVE_DEFENSE')}
            disabled={demoRunning !== null}
            className="px-3 py-1.5 rounded-lg bg-cyan-950/60 border border-cyan-800 text-cyan-300 hover:border-cyan-600 font-mono text-xs font-bold transition-all disabled:opacity-50"
          >
            5. Complete Attack Chain
          </button>
        </div>

        {demoMessage && (
          <div className="p-2.5 rounded bg-slate-900/80 border border-cyan-800/60 text-xs font-mono text-cyan-300">
            {demoMessage}
          </div>
        )}
      </div>

      {/* Main Grid: Left Threat Feed + Right Active Enforcements & Anomaly Radar */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

        {/* Left Column (7 cols): Real-Time Network Threat Feed */}
        <div className="lg:col-span-7 space-y-4">
          <div className="bg-soc-panel border border-soc-border rounded-xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
                  Real-time Network Threat Feed (Suricata EVE)
                </h3>
              </div>

              {/* Filter */}
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
                <input
                  type="text"
                  placeholder="Filter by IP, Signature..."
                  value={filterText}
                  onChange={(e) => setFilterText(e.target.value)}
                  className="bg-slate-900 border border-soc-border rounded-lg pl-8 pr-3 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-600"
                />
              </div>
            </div>

            {/* Events List */}
            <div className="space-y-2.5 max-h-[580px] overflow-y-auto pr-1">
              {filteredEvents.length === 0 ? (
                <div className="text-center py-10 text-xs font-mono text-slate-500">
                  {isLoading ? "Loading network events..." : "No network events matching filter."}
                </div>
              ) : (
                filteredEvents.map((ev) => (
                  <div
                    key={ev.event_id}
                    className="p-3 rounded-lg bg-soc-card border border-soc-border hover:border-slate-700 transition-all text-xs font-mono space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          ev.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                          ev.severity === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                          ev.severity === 'MEDIUM' ? 'bg-indigo-950 text-indigo-300 border border-indigo-800' :
                          'bg-slate-900 text-slate-400 border border-slate-800'
                        }`}>
                          {ev.severity}
                        </span>
                        <span className="font-bold text-slate-200">
                          {ev.signature || `[${ev.sensor.toUpperCase()}] ${ev.event_type}`}
                        </span>
                      </div>

                      <div className="flex items-center gap-2 text-[10px] text-slate-500">
                        <span>Risk: <strong className="text-rose-400">{ev.network_risk_score ?? 0}/100</strong></span>
                        <span>{new Date(ev.timestamp).toLocaleTimeString()}</span>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center justify-between text-[11px] text-slate-400 gap-2">
                      <div>
                        Source: <span className="text-cyan-400 font-bold">{ev.source_ip}</span>
                        {ev.source_port && `:${ev.source_port}`} &rarr; Target: {ev.destination_ip || 'Internal'}:{ev.destination_port || 'Any'} ({ev.protocol || 'TCP'})
                      </div>

                      <div className="flex items-center gap-2">
                        {ev.mitre_technique_id && (
                          <span className="px-1.5 py-0.5 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-800/80 text-[10px]">
                            {ev.mitre_technique_id}
                          </span>
                        )}
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          ev.enforcement_action === 'BLOCK' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                          ev.enforcement_action === 'TEMP_BLOCK' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                          ev.enforcement_action === 'RATE_LIMIT' ? 'bg-purple-950 text-purple-300 border border-purple-800' :
                          'bg-slate-900 text-slate-400 border border-slate-800'
                        }`}>
                          IPS: {ev.enforcement_action || 'OBSERVE'}
                        </span>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Right Column (5 cols): Active IPS Enforcements & DoS Anomaly Radar */}
        <div className="lg:col-span-5 space-y-5">

          {/* Active IPS Enforcements Card */}
          <div className="bg-soc-panel border border-soc-border rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-rose-400" />
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
                  Active IPS Enforcements ({enforcements.length})
                </h3>
              </div>
              <span className="text-[10px] font-mono text-slate-500">
                Audited Mitigations
              </span>
            </div>

            <div className="space-y-2 max-h-[280px] overflow-y-auto pr-1">
              {enforcements.length === 0 ? (
                <div className="p-4 rounded-lg bg-slate-900/40 border border-soc-border text-center text-xs font-mono text-slate-500">
                  No active blocks or rate limits. All perimeter gates operating normally.
                </div>
              ) : (
                enforcements.map((enf) => (
                  <div
                    key={enf.enforcement_id}
                    className="p-3 rounded-lg bg-soc-card border border-rose-900/60 text-xs font-mono space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-rose-400">{enf.source_ip}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-bold">
                          {enf.action}
                        </span>
                      </div>

                      <button
                        onClick={() => handleRelease(enf.source_ip)}
                        className="px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 text-[10px] flex items-center gap-1 transition-all"
                      >
                        <Unlock className="w-3 h-3" />
                        Release
                      </button>
                    </div>

                    <p className="text-[11px] text-slate-400">
                      {enf.reason}
                    </p>

                    <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1 border-t border-soc-border/40">
                      <span>Applied: {new Date(enf.created_at).toLocaleTimeString()}</span>
                      <span>
                        {enf.expires_at ? `Expires: ${new Date(enf.expires_at).toLocaleTimeString()}` : 'Indefinite'}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* DoS / DDoS Anomaly Radar Card */}
          <div className="bg-soc-panel border border-soc-border rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
                  DoS / Traffic Anomaly Radar
                </h3>
              </div>
              <span className="text-[10px] font-mono text-emerald-400 font-bold">
                NORMAL STATE
              </span>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 rounded-lg bg-soc-card border border-soc-border">
                <span className="text-[10px] text-slate-400 uppercase">Detection Threshold</span>
                <div className="text-sm font-bold text-slate-200 mt-1">3.5x Baseline</div>
                <span className="text-[10px] text-slate-500">Engage Local Rate-Limit</span>
              </div>

              <div className="p-3 rounded-lg bg-soc-card border border-soc-border">
                <span className="text-[10px] text-slate-400 uppercase">Volumetric Scrubber</span>
                <div className="text-sm font-bold text-slate-200 mt-1">&gt; 15x Baseline</div>
                <span className="text-[10px] text-amber-400">Upstream Scrubbing</span>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/60 border border-soc-border text-[11px] font-mono text-slate-400 leading-relaxed">
              <strong className="text-slate-200">Defensive Reality Check:</strong> AEGIS distinguishes local rate-limiting and quarantine from massive ISP-level volumetric floods. If traffic exceeds compute boundary, the system accurately displays <em>UPSTREAM DDoS MITIGATION RECOMMENDED</em> instead of claiming impossible single-node terabit immunity.
            </div>
          </div>

          {/* Top Sources & Protocol Distribution Card */}
          <div className="bg-soc-panel border border-soc-border rounded-xl p-5 space-y-3">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              Observed Top Sources &amp; Protocols
            </h3>

            <div className="space-y-2 text-xs font-mono">
              {statusData?.stats?.top_sources && statusData.stats.top_sources.length > 0 ? (
                statusData.stats.top_sources.map(s => (
                  <div key={s.ip} className="flex justify-between items-center py-1 border-b border-soc-border/40 text-[11px]">
                    <span className="text-cyan-400 font-semibold">{s.ip}</span>
                    <span className="text-slate-400">{s.count} events</span>
                  </div>
                ))
              ) : (
                <div className="text-slate-500 text-xs">No active attack sources observed yet.</div>
              )}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};
