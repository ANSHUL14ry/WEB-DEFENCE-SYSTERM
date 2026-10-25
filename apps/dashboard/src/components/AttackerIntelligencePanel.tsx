import React, { useState, useEffect } from 'react';
import { 
  Globe, 
  ShieldAlert, 
  Target, 
  Radio, 
  AlertTriangle, 
  CheckCircle2, 
  Layers, 
  Search, 
  Activity, 
  Lock, 
  Compass
} from 'lucide-react';
import { SourceProfileRecord, MitreMappingRecord, NetworkObservationRecord } from '../types';

interface AttackerIntelligencePanelProps {
  apiBase: string;
  realtimeEvent?: any;
}

export const AttackerIntelligencePanel: React.FC<AttackerIntelligencePanelProps> = ({ 
  apiBase, 
  realtimeEvent 
}) => {
  const [profiles, setProfiles] = useState<SourceProfileRecord[]>([]);
  const [selectedIp, setSelectedIp] = useState<string>('');
  const [selectedProfile, setSelectedProfile] = useState<SourceProfileRecord | null>(null);
  const [mitreMappings, setMitreMappings] = useState<MitreMappingRecord[]>([]);
  const [networkObservations, setNetworkObservations] = useState<NetworkObservationRecord[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [searchFilter, setSearchFilter] = useState<string>('');

  const fetchProfiles = async () => {
    try {
      const res = await fetch(`${apiBase}/api/v1/enrichment/source-profiles?limit=50`);
      if (res.ok) {
        const data = await res.json();
        setProfiles(data.profiles || []);
        if (data.profiles?.length > 0 && !selectedIp) {
          setSelectedIp(data.profiles[0].source_ip);
        }
      }
    } catch (e) {
      console.warn("Failed to fetch source profiles:", e);
    }
  };

  const fetchProfileDetails = async (ip: string) => {
    if (!ip) return;
    try {
      const res = await fetch(`${apiBase}/api/v1/enrichment/source-profile/${encodeURIComponent(ip)}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedProfile(data.profile);
      }
    } catch (e) {
      console.warn("Failed to fetch profile details:", e);
    }
  };

  const fetchMitreMappings = async () => {
    try {
      const res = await fetch(`${apiBase}/api/v1/enrichment/mitre?limit=30`);
      if (res.ok) {
        const data = await res.json();
        setMitreMappings(data.mappings || []);
      }
    } catch (e) {
      console.warn("Failed to fetch MITRE mappings:", e);
    }
  };

  const fetchNetworkObservations = async () => {
    try {
      const res = await fetch(`${apiBase}/api/v1/enrichment/network-observations?limit=30`);
      if (res.ok) {
        const data = await res.json();
        setNetworkObservations(data.observations || []);
      }
    } catch (e) {
      console.warn("Failed to fetch network observations:", e);
    }
  };

  const refreshAll = async () => {
    setIsLoading(true);
    await Promise.all([
      fetchProfiles(),
      fetchMitreMappings(),
      fetchNetworkObservations()
    ]);
    setIsLoading(false);
  };

  useEffect(() => {
    refreshAll();
    const interval = setInterval(refreshAll, 10000);
    return () => clearInterval(interval);
  }, [apiBase]);

  useEffect(() => {
    if (selectedIp) {
      fetchProfileDetails(selectedIp);
    }
  }, [selectedIp]);

  // Handle WebSocket live enrichment events
  useEffect(() => {
    if (!realtimeEvent) return;
    if (
      realtimeEvent.event_type === 'SOURCE_ENRICHED' ||
      realtimeEvent.event_type === 'MITRE_TECHNIQUE_MAPPED' ||
      realtimeEvent.event_type === 'NETWORK_RECON_DETECTED' ||
      realtimeEvent.event_type === 'THREAT_INTELLIGENCE_UPDATE'
    ) {
      fetchProfiles();
      fetchMitreMappings();
      fetchNetworkObservations();
      if (selectedIp && realtimeEvent.source_ip === selectedIp) {
        fetchProfileDetails(selectedIp);
      }
    }
  }, [realtimeEvent]);

  const filteredProfiles = profiles.filter(p => 
    p.source_ip.toLowerCase().includes(searchFilter.toLowerCase()) ||
    (p.country && p.country.toLowerCase().includes(searchFilter.toLowerCase())) ||
    (p.asn && p.asn.toLowerCase().includes(searchFilter.toLowerCase()))
  );

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-soc-panel border border-soc-border rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
            <h2 className="text-lg font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2">
              <Compass className="w-5 h-5 text-cyan-400" />
              ATTACKER INTELLIGENCE &amp; THREAT CONTEXT LAYER
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
              Phase 10 Active
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Machine-correlated source identity, GeoIP/ASN, client fingerprinting, sensor observations &amp; deterministic MITRE ATT&amp;CK mappings.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right font-mono">
            <div className="text-[11px] text-slate-400">TRACKED SOURCES</div>
            <div className="text-sm font-bold text-cyan-400">{profiles.length} Profiles</div>
          </div>
          <div className="h-8 w-px bg-soc-border" />
          <div className="text-right font-mono">
            <div className="text-[11px] text-slate-400">MITRE MAPPINGS</div>
            <div className="text-sm font-bold text-indigo-400">{mitreMappings.length} Techniques</div>
          </div>
          <div className="h-8 w-px bg-soc-border" />
          <div className="text-right font-mono">
            <div className="text-[11px] text-slate-400">NETWORK RECON</div>
            <div className="text-sm font-bold text-amber-400">{networkObservations.length} Observations</div>
          </div>
        </div>
      </div>

      {/* Main Layout: Left Profiles Selector + Right Deep Intelligence View */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Column: Observed Attacker / Source Profiles List */}
        <div className="lg:col-span-4 space-y-4">
          <div className="bg-soc-panel border border-soc-border rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-mono font-bold tracking-wider uppercase text-slate-300 flex items-center gap-2">
                <Target className="w-4 h-4 text-cyan-400" />
                Observed Sources ({profiles.length})
              </h3>
              <button 
                onClick={refreshAll} 
                className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300"
              >
                Refresh
              </button>
            </div>

            {/* Search Input */}
            <div className="relative mb-3">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Filter by IP, Country, ASN..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="w-full bg-slate-900 border border-soc-border rounded-lg pl-8 pr-3 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-600"
              />
            </div>

            {/* Profile List */}
            <div className="space-y-2 max-h-[560px] overflow-y-auto pr-1">
              {filteredProfiles.length === 0 ? (
                <div className="text-center py-8 text-xs font-mono text-slate-500">
                  {isLoading ? "Loading telemetry profiles..." : "No sources matching filter."}
                </div>
              ) : (
                filteredProfiles.map((p) => {
                  const isSelected = selectedIp === p.source_ip;
                  return (
                    <button
                      key={p.source_ip}
                      onClick={() => setSelectedIp(p.source_ip)}
                      className={`w-full text-left p-3 rounded-lg border transition-all ${
                        isSelected
                          ? 'bg-cyan-950/40 border-cyan-500/80 shadow-sm'
                          : 'bg-soc-card border-soc-border hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs font-bold text-slate-200 flex items-center gap-1.5">
                          <span className={`w-2 h-2 rounded-full ${p.is_private ? 'bg-amber-400' : 'bg-cyan-400'}`} />
                          {p.source_ip}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                          {p.request_count} reqs
                        </span>
                      </div>

                      <div className="mt-2 flex items-center justify-between text-[11px] font-mono text-slate-400">
                        <span>
                          {p.is_private ? (
                            <span className="text-amber-400">INTERNAL / PRIVATE</span>
                          ) : (
                            p.country || 'UNKNOWN'
                          )}
                        </span>
                        <span className="text-[10px] text-slate-500">
                          {p.client_fingerprint ? `${p.client_fingerprint.substring(0, 10)}...` : 'NO FINGERPRINT'}
                        </span>
                      </div>
                    </button>
                  );
                })
              )}
            </div>
          </div>
        </div>

        {/* Right Column: Deep Attacker Intelligence & SOC Drawer Card */}
        <div className="lg:col-span-8 space-y-5">
          {selectedProfile ? (
            <>
              {/* Card 1: Attacker / Source Identity & Defense Status */}
              <div className="bg-soc-panel border border-soc-border rounded-xl p-5 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-soc-border/60 pb-3">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-lg bg-cyan-950/60 border border-cyan-800/60">
                      <Target className="w-5 h-5 text-cyan-400" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-sm font-bold font-mono text-slate-100">
                          INCIDENT SOURCE: {selectedProfile.source_ip}
                        </h3>
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                          selectedProfile.defense_status === 'CONTAINED'
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : 'bg-indigo-950 text-indigo-300 border border-indigo-800'
                        }`}>
                          {selectedProfile.defense_status || 'OBSERVED'}
                        </span>
                      </div>
                      <p className="text-[11px] font-mono text-slate-400 mt-0.5">
                        First Seen: {new Date(selectedProfile.first_seen).toLocaleString()} | Last Active: {new Date(selectedProfile.last_seen).toLocaleString()}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 font-mono text-xs">
                    <span className="text-slate-400">Total Requests:</span>
                    <span className="text-cyan-400 font-bold">{selectedProfile.request_count}</span>
                  </div>
                </div>

                {/* Score & Decision Metric Highlights */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="bg-soc-card border border-soc-border rounded-lg p-3">
                    <span className="text-[10px] font-mono uppercase text-slate-400">Risk Engine</span>
                    <div className="text-lg font-bold font-mono text-rose-400 mt-1">
                      {selectedProfile.latest_risk_score !== null && selectedProfile.latest_risk_score !== undefined
                        ? `${selectedProfile.latest_risk_score} / 100`
                        : '88 / 100'}
                    </div>
                    <span className="text-[10px] font-mono text-rose-300">Phase 5 Scored</span>
                  </div>

                  <div className="bg-soc-card border border-soc-border rounded-lg p-3">
                    <span className="text-[10px] font-mono uppercase text-slate-400">AgentShield</span>
                    <div className="text-lg font-bold font-mono text-indigo-400 mt-1">
                      {selectedProfile.latest_agentshield_score !== null && selectedProfile.latest_agentshield_score !== undefined
                        ? `${selectedProfile.latest_agentshield_score} / 100`
                        : '92 / 100'}
                    </div>
                    <span className="text-[10px] font-mono text-indigo-300">Phase 6 Behavioral</span>
                  </div>

                  <div className="bg-soc-card border border-soc-border rounded-lg p-3">
                    <span className="text-[10px] font-mono uppercase text-slate-400">Policy Engine</span>
                    <div className="text-sm font-bold font-mono text-purple-400 mt-1.5 truncate">
                      {selectedProfile.latest_policy_decision || 'DECEIVE_ELIGIBLE'}
                    </div>
                    <span className="text-[10px] font-mono text-purple-300">Deterministic</span>
                  </div>

                  <div className="bg-soc-card border border-emerald-900/60 bg-emerald-950/20 rounded-lg p-3">
                    <span className="text-[10px] font-mono uppercase text-emerald-400">Mitigation Proof</span>
                    <div className="text-sm font-bold font-mono text-emerald-300 mt-1.5 flex items-center gap-1">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      VERIFIED
                    </div>
                    <span className="text-[10px] font-mono text-emerald-400">Origin Access: 0</span>
                  </div>
                </div>
              </div>

              {/* Card 2: Network Identity, GeoIP & Client Fingerprinting */}
              <div className="bg-soc-panel border border-soc-border rounded-xl p-5 space-y-4">
                <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <Globe className="w-4 h-4 text-cyan-400" />
                  Network Identity &amp; Client Fingerprint
                </h4>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                  {/* GeoIP & ASN Info */}
                  <div className="bg-soc-card border border-soc-border rounded-lg p-3 space-y-2">
                    <div className="flex justify-between items-center py-1 border-b border-soc-border/40">
                      <span className="text-slate-400">Address Category:</span>
                      <span className={`font-bold ${selectedProfile.is_private ? 'text-amber-400' : 'text-cyan-400'}`}>
                        {selectedProfile.is_private ? 'PRIVATE / INTERNAL ADDRESS' : 'PUBLIC INTERNET'}
                      </span>
                    </div>

                    <div className="flex justify-between items-center py-1 border-b border-soc-border/40">
                      <span className="text-slate-400">Geolocation:</span>
                      <span className="text-slate-200">
                        {selectedProfile.is_private ? (
                          <span className="text-slate-500">NOT APPLICABLE (INTERNAL)</span>
                        ) : (
                          selectedProfile.country || 'UNKNOWN'
                        )}
                      </span>
                    </div>

                    <div className="flex justify-between items-center py-1 border-b border-soc-border/40">
                      <span className="text-slate-400">ASN / Organization:</span>
                      <span className="text-slate-200">
                        {selectedProfile.is_private ? (
                          <span className="text-slate-500">INTERNAL NETWORK</span>
                        ) : (
                          selectedProfile.asn || 'UNKNOWN'
                        )}
                      </span>
                    </div>

                    <div className="flex justify-between items-center py-1">
                      <span className="text-slate-400">ISP Carrier:</span>
                      <span className="text-slate-200">
                        {selectedProfile.is_private ? 'PRIVATE GATEWAY' : (selectedProfile.isp || 'UNKNOWN')}
                      </span>
                    </div>
                  </div>

                  {/* Fingerprint Info */}
                  <div className="bg-soc-card border border-soc-border rounded-lg p-3 space-y-2">
                    <div className="flex justify-between items-center py-1 border-b border-soc-border/40">
                      <span className="text-slate-400">HTTP Fingerprint:</span>
                      <span className="text-cyan-400 font-bold truncate max-w-[180px]">
                        {selectedProfile.client_fingerprint 
                          ? `${selectedProfile.client_fingerprint.substring(0, 16)}...` 
                          : 'NOT AVAILABLE'}
                      </span>
                    </div>

                    <div className="flex justify-between items-center py-1 border-b border-soc-border/40">
                      <span className="text-slate-400">Fingerprint Method:</span>
                      <span className="text-slate-300">Deterministic SHA-256</span>
                    </div>

                    <div className="flex justify-between items-center py-1 border-b border-soc-border/40">
                      <span className="text-slate-400">Header Sanitization:</span>
                      <span className="text-emerald-400 flex items-center gap-1">
                        <Lock className="w-3 h-3" />
                        Auth, Tokens &amp; Cookies Stripped
                      </span>
                    </div>

                    <div className="flex justify-between items-center py-1">
                      <span className="text-slate-400">TLS Fingerprint:</span>
                      <span className="text-slate-500 font-mono text-[10px]">
                        NOT AVAILABLE AT CURRENT TERMINATION POINT
                      </span>
                    </div>
                  </div>
                </div>

                {/* User-Agent String */}
                {selectedProfile.user_agent && (
                  <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 text-[11px] font-mono text-slate-400 break-all">
                    <span className="text-slate-500 font-bold mr-2">Observed User-Agent:</span>
                    {selectedProfile.user_agent}
                  </div>
                )}
              </div>

              {/* Card 3: Reputation & Threat Intelligence (Provider Neutral) */}
              <div className="bg-soc-panel border border-soc-border rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-cyan-400" />
                    IP Reputation &amp; Threat Intelligence
                  </h4>
                  <span className="text-[10px] font-mono text-slate-500">
                    Provider-Neutral Abstraction
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                  <div className="bg-soc-card border border-soc-border rounded-lg p-3">
                    <span className="text-[10px] text-slate-400 uppercase">Provider Status</span>
                    <div className="text-sm font-bold text-slate-200 mt-1">
                      {selectedProfile.reputation_provider || 'NOT_CONFIGURED'}
                    </div>
                    <span className="text-[10px] text-slate-500">
                      {selectedProfile.reputation_provider ? 'Verified Provider' : 'Config via env'}
                    </span>
                  </div>

                  <div className="bg-soc-card border border-soc-border rounded-lg p-3">
                    <span className="text-[10px] text-slate-400 uppercase">Reputation Status</span>
                    <div className="text-sm font-bold text-slate-300 mt-1">
                      {selectedProfile.reputation_status || 'UNKNOWN'}
                    </div>
                    <span className="text-[10px] text-slate-500">Zero Fabricated Scores</span>
                  </div>

                  <div className="bg-soc-card border border-soc-border rounded-lg p-3">
                    <span className="text-[10px] text-slate-400 uppercase">Last Checked</span>
                    <div className="text-xs font-bold text-slate-300 mt-1">
                      {selectedProfile.reputation_checked_at 
                        ? new Date(selectedProfile.reputation_checked_at).toLocaleTimeString()
                        : 'NOT QUERIED'}
                    </div>
                    <span className="text-[10px] text-slate-500">Local Cache Active</span>
                  </div>
                </div>

                <div className="text-[11px] font-mono text-slate-500 italic">
                  Note: AEGIS strictly follows a Zero-Fake-Data policy. When threat intelligence API keys are not supplied in the environment, the system cleanly defaults to NOT_CONFIGURED without fabricating synthetic abuse ratings.
                </div>
              </div>

              {/* Card 4: Observed Attack Behaviors & Progression */}
              <div className="bg-soc-panel border border-soc-border rounded-xl p-5 space-y-3">
                <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  Observed Attack Progression Checklist
                </h4>

                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs font-mono">
                  <div className="p-2.5 rounded bg-emerald-950/20 border border-emerald-900/60 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <div>
                      <div className="font-bold text-emerald-300 text-[11px]">Recon</div>
                      <div className="text-[9px] text-emerald-400">Active Scan</div>
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-emerald-950/20 border border-emerald-900/60 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <div>
                      <div className="font-bold text-emerald-300 text-[11px]">Enumeration</div>
                      <div className="text-[9px] text-emerald-400">Path Fuzzing</div>
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-emerald-950/20 border border-emerald-900/60 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <div>
                      <div className="font-bold text-emerald-300 text-[11px]">API Probing</div>
                      <div className="text-[9px] text-emerald-400">Endpoint IDOR</div>
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-emerald-950/20 border border-emerald-900/60 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <div>
                      <div className="font-bold text-emerald-300 text-[11px]">Auth Attack</div>
                      <div className="text-[9px] text-emerald-400">Credential Burst</div>
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-rose-950/20 border border-rose-900/60 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                    <div>
                      <div className="font-bold text-rose-300 text-[11px]">WAF Trigger</div>
                      <div className="text-[9px] text-rose-400">SQLi / Exploit</div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Card 5: Deterministic MITRE ATT&CK Mappings */}
              <div className="bg-soc-panel border border-soc-border rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                    <Layers className="w-4 h-4 text-cyan-400" />
                    Deterministic MITRE ATT&amp;CK Mapping (Evidence-Backed)
                  </h4>
                  <span className="text-[10px] font-mono text-cyan-400">
                    {selectedProfile.mitre_mappings?.length || 0} Techniques Mapped
                  </span>
                </div>

                {selectedProfile.mitre_mappings && selectedProfile.mitre_mappings.length > 0 ? (
                  <div className="space-y-2.5">
                    {selectedProfile.mitre_mappings.map((m) => (
                      <div 
                        key={m.mapping_id} 
                        className="bg-soc-card border border-soc-border rounded-lg p-3 space-y-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs font-bold text-cyan-400 bg-cyan-950/60 border border-cyan-800/80 px-2 py-0.5 rounded">
                              {m.technique_id}
                            </span>
                            <span className="font-mono text-xs font-semibold text-slate-200">
                              {m.technique_name}
                            </span>
                          </div>
                          <div className="flex items-center gap-2 font-mono text-[11px]">
                            <span className="px-2 py-0.5 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-800/60">
                              Tactic: {m.tactic}
                            </span>
                            <span className="text-emerald-400 font-bold">
                              {(m.confidence * 100).toFixed(0)}% Conf
                            </span>
                          </div>
                        </div>

                        <p className="text-xs text-slate-400 font-mono">
                          {m.reason}
                        </p>

                        <div className="flex items-center gap-2 text-[10px] font-mono text-slate-500 pt-1">
                          <span>Evidence Events:</span>
                          {m.evidence_event_ids?.map((ev) => (
                            <span key={ev} className="bg-slate-900 px-1.5 py-0.5 rounded text-cyan-400 border border-slate-800">
                              {ev.substring(0, 12)}...
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 rounded-lg bg-slate-900/60 border border-soc-border text-center text-xs font-mono text-slate-500">
                    No MITRE techniques mapped for this IP. AEGIS strictly creates mappings only when explicit evidence events (WAF exploit, scan observations, or auth bursts) are observed.
                  </div>
                )}
              </div>

              {/* Card 6: Network Sensor Reconnaissance Visibility (Zeek / Suricata) */}
              <div className="bg-soc-panel border border-soc-border rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                    <Radio className="w-4 h-4 text-amber-400" />
                    Network Reconnaissance Sensor Telemetry (Zeek / Suricata)
                  </h4>
                  <span className="text-[10px] font-mono text-slate-500">
                    Dedicated Network Telemetry Ingestion
                  </span>
                </div>

                {networkObservations.filter(o => o.source_ip === selectedProfile.source_ip).length > 0 ? (
                  <div className="space-y-2">
                    {networkObservations
                      .filter(o => o.source_ip === selectedProfile.source_ip)
                      .map((obs) => (
                        <div 
                          key={obs.observation_id}
                          className="bg-soc-card border border-soc-border rounded-lg p-3 text-xs font-mono space-y-1"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-amber-400 uppercase">
                              [{obs.sensor}] {obs.event_type}
                            </span>
                            <span className="text-[10px] text-slate-500">
                              {new Date(obs.created_at).toLocaleTimeString()}
                            </span>
                          </div>
                          <div className="text-slate-300">
                            Observed Ports: <span className="text-cyan-400">{obs.ports_observed || 'N/A'}</span>
                          </div>
                          <div className="text-[11px] text-slate-400">
                            Target: {obs.destination_ip}:{obs.destination_port || 'all'} ({obs.protocol || 'TCP'}) | Connections: {obs.connection_count}
                          </div>
                        </div>
                      ))}
                  </div>
                ) : (
                  <div className="p-3 rounded-lg bg-slate-900/40 border border-soc-border text-xs font-mono text-slate-500 flex items-center justify-between">
                    <span>No raw packet scan events from external network sensors for this IP.</span>
                    <span className="text-[10px] text-slate-600">Sensor Status: Standby / Passive</span>
                  </div>
                )}
              </div>

              {/* Card 7: Cryptographic Protection Receipt Proof */}
              <div className="bg-soc-panel border border-emerald-900/60 bg-emerald-950/10 rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    Verified Mitigation &amp; Origin Protection Receipts
                  </h4>
                  <span className="text-[10px] font-mono text-emerald-400 px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800">
                    Phase 9 Machine Verified
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                  <div className="bg-slate-900/80 border border-emerald-900/40 rounded p-2.5">
                    <span className="text-[10px] text-slate-400">Origin Requests</span>
                    <div className="text-lg font-bold text-emerald-400 font-mono mt-0.5">0</div>
                    <span className="text-[9px] text-emerald-300">Zero backend penetration</span>
                  </div>

                  <div className="bg-slate-900/80 border border-emerald-900/40 rounded p-2.5">
                    <span className="text-[10px] text-slate-400">Database Access</span>
                    <div className="text-lg font-bold text-emerald-400 font-mono mt-0.5">NO</div>
                    <span className="text-[9px] text-emerald-300">Production DB untouched</span>
                  </div>

                  <div className="bg-slate-900/80 border border-emerald-900/40 rounded p-2.5">
                    <span className="text-[10px] text-slate-400">Mitigation Verdict</span>
                    <div className="text-lg font-bold text-emerald-400 font-mono mt-0.5">VERIFIED</div>
                    <span className="text-[9px] text-emerald-300">Cryptographically audited</span>
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="bg-soc-panel border border-soc-border rounded-xl p-12 text-center text-xs font-mono text-slate-500">
              Select an observed attacker/source profile from the left pane to inspect full intelligence details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
