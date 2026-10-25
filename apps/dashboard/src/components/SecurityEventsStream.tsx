import React, { useState, useEffect, useRef } from 'react';
import { SecurityEvent, EventStats } from '../types';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Info, 
  Radio, 
  Filter, 
  Search, 
  ExternalLink, 
  X, 
  Copy, 
  Check, 
  Activity,
  Server,
  Zap
} from 'lucide-react';

interface SecurityEventsStreamProps {
  apiBase: string;
}

export const SecurityEventsStream: React.FC<SecurityEventsStreamProps> = ({ apiBase }) => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [stats, setStats] = useState<EventStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [wsConnected, setWsConnected] = useState<boolean>(false);

  // Filters
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const wsRef = useRef<WebSocket | null>(null);

  // Fetch initial events and stats
  const fetchEventsAndStats = async () => {
    try {
      const [eventsRes, statsRes] = await Promise.all([
        fetch(`${apiBase}/api/v1/events?limit=50`),
        fetch(`${apiBase}/api/v1/events/stats`)
      ]);

      if (eventsRes.ok) {
        const eventsData = await eventsRes.json();
        setEvents(eventsData.events || []);
      }
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }
    } catch (err) {
      console.warn('Failed to fetch events from API:', err);
    } finally {
      setLoading(false);
    }
  };

  // WebSocket live connection
  useEffect(() => {
    fetchEventsAndStats();

    const host = window.location.hostname || 'localhost';
    // Prefer direct port 8001 or fallback through gateway
    const wsUrl = `ws://${host}:8001/api/v1/ws/events`;
    let socket: WebSocket;

    try {
      socket = new WebSocket(wsUrl);
      wsRef.current = socket;

      socket.onopen = () => {
        setWsConnected(true);
      };

      socket.onmessage = (msg) => {
        try {
          const newEvent: SecurityEvent = JSON.parse(msg.data);
          setEvents((prev) => [newEvent, ...prev.filter((e) => e.event_id !== newEvent.event_id)]);
          // Refresh stats dynamically
          fetch(`${apiBase}/api/v1/events/stats`)
            .then((res) => res.json())
            .then((data) => setStats(data))
            .catch(() => {});
        } catch (e) {
          // ignore non-json messages
        }
      };

      socket.onclose = () => {
        setWsConnected(false);
      };

      socket.onerror = () => {
        setWsConnected(false);
      };
    } catch (e) {
      setWsConnected(false);
    }

    // Polling fallback every 6 seconds if WS is disconnected
    const pollInterval = setInterval(() => {
      if (!wsConnected) {
        fetchEventsAndStats();
      }
    }, 6000);

    return () => {
      clearInterval(pollInterval);
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [apiBase]);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Filter events
  const filteredEvents = events.filter((ev) => {
    if (selectedSeverity !== 'ALL' && ev.severity !== selectedSeverity) return false;
    if (selectedType !== 'ALL' && ev.event_type !== selectedType) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchUri = ev.request.uri.toLowerCase().includes(q);
      const matchReqId = ev.request_id.toLowerCase().includes(q);
      const matchTraceId = ev.trace_id.toLowerCase().includes(q);
      const matchRule = String(ev.metadata?.rule_id || '').includes(q);
      if (!matchUri && !matchReqId && !matchTraceId && !matchRule) return false;
    }
    return true;
  });

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-950 text-red-400 border border-red-800">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950 text-amber-400 border border-amber-800">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-yellow-950 text-yellow-400 border border-yellow-800">MEDIUM</span>;
      case 'LOW':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-950 text-blue-400 border border-blue-800">LOW</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-900 text-slate-400 border border-slate-700">INFO</span>;
    }
  };

  const getActionBadge = (action: string) => {
    switch (action) {
      case 'BLOCK':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-red-900/60 text-red-300">BLOCK</span>;
      case 'ALLOW':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-900/60 text-emerald-300">ALLOW</span>;
      case 'ALERT':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-purple-900/60 text-purple-300">ALERT</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-800 text-slate-300">OBSERVE</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Real-time Telemetry Metrics Banner */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="bg-soc-panel border border-soc-border rounded-xl p-3.5 flex items-center justify-between">
          <div>
            <div className="text-[11px] font-mono text-slate-400 uppercase">Total Events</div>
            <div className="text-xl font-bold font-mono text-white mt-0.5">{stats?.total_events ?? 0}</div>
            <div className="text-[10px] font-mono text-slate-500">Recorded In DB</div>
          </div>
          <Activity className="w-5 h-5 text-cyan-400 shrink-0" />
        </div>

        <div className="bg-soc-panel border border-soc-border rounded-xl p-3.5 flex items-center justify-between">
          <div>
            <div className="text-[11px] font-mono text-slate-400 uppercase">WAF Blocks</div>
            <div className="text-xl font-bold font-mono text-red-400 mt-0.5">{stats?.waf_blocks ?? 0}</div>
            <div className="text-[10px] font-mono text-red-500/80">Coraza CRS Blocks</div>
          </div>
          <ShieldAlert className="w-5 h-5 text-red-400 shrink-0" />
        </div>

        <div className="bg-soc-panel border border-soc-border rounded-xl p-3.5 flex items-center justify-between">
          <div>
            <div className="text-[11px] font-mono text-slate-400 uppercase">High Severity</div>
            <div className="text-xl font-bold font-mono text-amber-400 mt-0.5">{stats?.high_severity ?? 0}</div>
            <div className="text-[10px] font-mono text-amber-500/80">Requires SOC Attention</div>
          </div>
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
        </div>

        <div className="bg-soc-panel border border-soc-border rounded-xl p-3.5 flex items-center justify-between">
          <div>
            <div className="text-[11px] font-mono text-slate-400 uppercase">Critical Threats</div>
            <div className="text-xl font-bold font-mono text-purple-400 mt-0.5">{stats?.critical_severity ?? 0}</div>
            <div className="text-[10px] font-mono text-purple-500/80">Active Exploit Canaries</div>
          </div>
          <Zap className="w-5 h-5 text-purple-400 shrink-0" />
        </div>

        <div className="bg-soc-panel border border-soc-border rounded-xl p-3.5 flex items-center justify-between col-span-2 md:col-span-1">
          <div>
            <div className="text-[11px] font-mono text-slate-400 uppercase">Last 24 Hours</div>
            <div className="text-xl font-bold font-mono text-cyan-400 mt-0.5">{stats?.events_24h ?? 0}</div>
            <div className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
              <span className={`w-1.5 h-1.5 rounded-full ${wsConnected ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
              {wsConnected ? 'Live Stream Active' : 'Polling Sync'}
            </div>
          </div>
          <Radio className={`w-5 h-5 ${wsConnected ? 'text-emerald-400' : 'text-slate-500'} shrink-0`} />
        </div>
      </div>

      {/* Main Events Feed Section */}
      <div className="bg-soc-panel border border-soc-border rounded-xl overflow-hidden shadow-2xl">
        {/* Stream Header & Controls */}
        <div className="p-4 border-b border-soc-border flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-soc-card rounded-lg border border-soc-border">
              <Radio className={`w-4 h-4 ${wsConnected ? 'text-emerald-400' : 'text-slate-500'}`} />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white font-mono flex items-center gap-2">
                Live Security Telemetry Feed
                {wsConnected && (
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800">
                    LIVE
                  </span>
                )}
              </h3>
              <p className="text-[11px] text-slate-400 font-mono">
                Normalized events from Gateway, Coraza WAF v3, and Origin
              </p>
            </div>
          </div>

          {/* Filtering Bar */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Search URI, Request ID, Rule..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="bg-soc-card border border-soc-border rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500 w-52"
              />
            </div>

            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="bg-soc-card border border-soc-border rounded-lg px-2.5 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Info</option>
            </select>

            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className="bg-soc-card border border-soc-border rounded-lg px-2.5 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Event Types</option>
              <option value="WAF_BLOCK">WAF_BLOCK</option>
              <option value="WAF_DETECTION">WAF_DETECTION</option>
              <option value="ORIGIN_REQUEST">ORIGIN_REQUEST</option>
              <option value="GATEWAY_REQUEST">GATEWAY_REQUEST</option>
              <option value="SYSTEM_EVENT">SYSTEM_EVENT</option>
            </select>
          </div>
        </div>

        {/* Telemetry Event Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-soc-card/70 border-b border-soc-border text-slate-400 uppercase text-[10px]">
              <tr>
                <th className="py-2.5 px-4">Timestamp</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Event Type</th>
                <th className="py-2.5 px-3">Component</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-4">Method & URI</th>
                <th className="py-2.5 px-3">Rule / Detail</th>
                <th className="py-2.5 px-4">Request ID</th>
                <th className="py-2.5 px-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border/40">
              {loading ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-400 font-mono">
                    Loading security telemetry stream...
                  </td>
                </tr>
              ) : filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-10 text-center text-slate-400 font-mono">
                    <ShieldCheck className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                    <div>No security events detected.</div>
                    <span className="text-[11px] text-slate-500">
                      Controlled attack traffic or normal requests will stream here in real time.
                    </span>
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev) => {
                  const ruleId = ev.metadata?.rule_id;
                  const timeFormatted = new Date(ev.timestamp).toLocaleTimeString();
                  return (
                    <tr 
                      key={ev.event_id} 
                      onClick={() => setSelectedEvent(ev)}
                      className="hover:bg-soc-card/80 transition-colors cursor-pointer group"
                    >
                      <td className="py-2.5 px-4 text-slate-400 text-[11px] whitespace-nowrap">
                        {timeFormatted}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        {getSeverityBadge(ev.severity)}
                      </td>
                      <td className="py-2.5 px-3 font-semibold text-slate-200 whitespace-nowrap">
                        {ev.event_type}
                      </td>
                      <td className="py-2.5 px-3 text-cyan-400/90 whitespace-nowrap">
                        {ev.component}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        {getActionBadge(ev.action)}
                      </td>
                      <td className="py-2.5 px-4 max-w-xs truncate text-slate-300">
                        <span className="text-slate-500 mr-1.5">{ev.request.method}</span>
                        <span className="font-medium text-slate-200">{ev.request.uri}</span>
                      </td>
                      <td className="py-2.5 px-3 text-amber-400 whitespace-nowrap">
                        {ruleId ? (
                          <span className="px-1.5 py-0.5 rounded bg-amber-950/60 border border-amber-800/60 text-[10px]">
                            Rule {ruleId}
                          </span>
                        ) : (
                          <span className="text-slate-500 text-[11px]">-</span>
                        )}
                      </td>
                      <td className="py-2.5 px-4 text-slate-500 text-[11px] max-w-[120px] truncate">
                        {ev.request_id}
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button className="text-slate-500 group-hover:text-cyan-400 transition-colors p-1">
                          <ExternalLink className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Structured Event Detail Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-soc-panel border border-soc-border rounded-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-soc-border pb-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-amber-400" />
                <h3 className="text-sm font-bold font-mono text-white">
                  Event Investigation: {selectedEvent.event_type}
                </h3>
              </div>
              <button 
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Quick Metrics Matrix */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
              <div className="bg-soc-card p-3 rounded-lg border border-soc-border">
                <span className="text-[10px] text-slate-400 uppercase">Severity</span>
                <div className="mt-1">{getSeverityBadge(selectedEvent.severity)}</div>
              </div>

              <div className="bg-soc-card p-3 rounded-lg border border-soc-border">
                <span className="text-[10px] text-slate-400 uppercase">Action Taken</span>
                <div className="mt-1">{getActionBadge(selectedEvent.action)}</div>
              </div>

              <div className="bg-soc-card p-3 rounded-lg border border-soc-border">
                <span className="text-[10px] text-slate-400 uppercase">Origin Reached</span>
                <div className="mt-1">
                  {selectedEvent.action === 'BLOCK' ? (
                    <span className="text-emerald-400 font-bold">NO (Protected)</span>
                  ) : (
                    <span className="text-cyan-400 font-bold">YES (Allowed)</span>
                  )}
                </div>
              </div>

              <div className="bg-soc-card p-3 rounded-lg border border-soc-border">
                <span className="text-[10px] text-slate-400 uppercase">Component</span>
                <div className="mt-1 font-bold text-slate-200">{selectedEvent.component}</div>
              </div>
            </div>

            {/* Request Tracing Identifiers */}
            <div className="bg-soc-card p-4 rounded-lg border border-soc-border space-y-2 text-xs font-mono">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Request ID:</span>
                <div className="flex items-center gap-2 text-slate-200">
                  <span className="text-cyan-400">{selectedEvent.request_id}</span>
                  <button 
                    onClick={() => copyToClipboard(selectedEvent.request_id, 'req')}
                    className="text-slate-400 hover:text-white"
                  >
                    {copiedId === 'req' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-slate-400">Trace ID:</span>
                <div className="flex items-center gap-2 text-slate-200">
                  <span className="text-purple-400">{selectedEvent.trace_id}</span>
                  <button 
                    onClick={() => copyToClipboard(selectedEvent.trace_id, 'trace')}
                    className="text-slate-400 hover:text-white"
                  >
                    {copiedId === 'trace' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-slate-400">Source IP:</span>
                <span className="text-slate-200">{selectedEvent.source.ip}</span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-slate-400">HTTP Target:</span>
                <span className="text-slate-200">{selectedEvent.request.method} {selectedEvent.request.uri}</span>
              </div>

              {selectedEvent.metadata?.rule_id && (
                <>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">OWASP CRS Rule ID:</span>
                    <span className="text-amber-400 font-bold">{selectedEvent.metadata.rule_id}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Rule Message:</span>
                    <span className="text-slate-300 text-right">{selectedEvent.metadata.rule_message}</span>
                  </div>
                  {selectedEvent.metadata?.anomaly_score !== undefined && (
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Anomaly Score:</span>
                      <span className="text-red-400 font-bold">{selectedEvent.metadata.anomaly_score}</span>
                    </div>
                  )}
                </>
              )}
            </div>

            {/* Raw Normalized Payload JSON */}
            <div>
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
                Normalized Telemetry JSON Payload
              </span>
              <pre className="mt-1 p-3 bg-black/60 rounded-lg border border-soc-border font-mono text-[11px] text-slate-300 overflow-x-auto max-h-48">
                {JSON.stringify(selectedEvent, null, 2)}
              </pre>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-1.5 bg-soc-card hover:bg-soc-border text-white text-xs font-mono rounded-lg transition-colors border border-soc-border"
              >
                Close Investigation
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
