import React, { useState, useEffect } from 'react';
import { 
  CheckCircle2, 
  XCircle, 
  AlertCircle, 
  ShieldCheck, 
  Database, 
  Server, 
  Lock, 
  Eye, 
  RefreshCw, 
  FileText, 
  ExternalLink, 
  X, 
  Copy, 
  Check, 
  Layers, 
  ArrowRight
} from 'lucide-react';
import { VerificationStats, VerificationResultRecord } from '../types';

interface VerificationPanelProps {
  apiBase: string;
  realtimeEvent?: any;
}

export const VerificationPanel: React.FC<VerificationPanelProps> = ({ apiBase, realtimeEvent }) => {
  const [stats, setStats] = useState<VerificationStats | null>(null);
  const [selectedVerification, setSelectedVerification] = useState<VerificationResultRecord | null>(null);
  const [filterResult, setFilterResult] = useState<string>('ALL');
  const [loading, setLoading] = useState<boolean>(true);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const fetchVerificationStats = async () => {
    try {
      const res = await fetch(`${apiBase}/api/v1/verification/stats`);
      if (res.ok) {
        const data: VerificationStats = await res.json();
        setStats(data);
      }
    } catch (err) {
      console.warn('Failed to fetch verification stats:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchVerificationStats();
    const interval = setInterval(fetchVerificationStats, 6000);
    return () => clearInterval(interval);
  }, [apiBase]);

  useEffect(() => {
    if (realtimeEvent && (
      realtimeEvent.event_type === 'MITIGATION_VERIFIED' || 
      realtimeEvent.event_type === 'MITIGATION_FAILED' ||
      realtimeEvent.event_type === 'MITIGATION_INCONCLUSIVE'
    )) {
      fetchVerificationStats();
    }
  }, [realtimeEvent]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredVerifications = stats?.recent_verifications?.filter(v => {
    if (filterResult === 'ALL') return true;
    return v.result === filterResult;
  }) || [];

  return (
    <div className="bg-soc-panel border border-soc-border rounded-xl p-5 shadow-lg relative overflow-hidden space-y-5">
      {/* Background Accent Glow */}
      <div className="absolute top-0 right-0 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl -z-10 pointer-events-none"></div>

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-soc-border gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-emerald-950/80 border border-emerald-800 text-emerald-400">
            <CheckCircle2 className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold font-mono text-slate-100 uppercase tracking-wide">
                Response Verification & Telemetry Proof Engine
              </h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-900/60 text-emerald-300 border border-emerald-700/80">
                Phase 9 Active
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Deterministic machine-verifiable proof receipts validating zero origin access and deception isolation
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button 
            onClick={fetchVerificationStats}
            className="px-2.5 py-1 text-xs font-mono rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 flex items-center gap-1 transition"
          >
            <RefreshCw className="w-3 h-3" />
            Refresh
          </button>
          <div className="text-right">
            <span className="text-[10px] font-mono text-slate-400 block">Verification Invariant</span>
            <span className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1 justify-end">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              ORIGIN NEVER TOUCHED
            </span>
          </div>
        </div>
      </div>

      {/* Metrics Banner */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="bg-soc-card p-3 rounded-lg border border-soc-border">
          <div className="text-[11px] font-mono text-slate-400 uppercase">TOTAL VERIFIED ACTIONS</div>
          <div className="text-2xl font-bold font-mono text-white mt-1">
            {stats?.total_verifications ?? 0}
          </div>
          <div className="text-[10px] text-slate-500 font-mono mt-0.5">Evaluated Receipts</div>
        </div>

        <div className="bg-soc-card p-3 rounded-lg border border-emerald-800/60 bg-emerald-950/10">
          <div className="text-[11px] font-mono text-emerald-400 uppercase">VERIFIED MITIGATIONS</div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
            {stats?.verified_count ?? 0}
          </div>
          <div className="text-[10px] text-emerald-500 font-mono mt-0.5">Proof Validated</div>
        </div>

        <div className="bg-soc-card p-3 rounded-lg border border-rose-800/60 bg-rose-950/10">
          <div className="text-[11px] font-mono text-rose-400 uppercase">FAILED MITIGATIONS</div>
          <div className="text-2xl font-bold font-mono text-rose-400 mt-1">
            {stats?.failed_count ?? 0}
          </div>
          <div className="text-[10px] text-rose-500 font-mono mt-0.5">Invariant Breaches</div>
        </div>

        <div className="bg-soc-card p-3 rounded-lg border border-amber-800/60 bg-amber-950/10">
          <div className="text-[11px] font-mono text-amber-400 uppercase">INCONCLUSIVE</div>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-1">
            {stats?.inconclusive_count ?? 0}
          </div>
          <div className="text-[10px] text-amber-500 font-mono mt-0.5">Insufficient Telemetry</div>
        </div>

        <div className="bg-soc-card p-3 rounded-lg border border-soc-border">
          <div className="text-[11px] font-mono text-slate-400 uppercase">PROTECTION SUCCESS</div>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">
            {stats?.verified_percentage ?? 100}%
          </div>
          <div className="text-[10px] text-cyan-500 font-mono mt-0.5">Mathematical Proof</div>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center justify-between border-b border-soc-border pb-2">
        <div className="flex items-center gap-1">
          {['ALL', 'VERIFIED', 'FAILED', 'INCONCLUSIVE'].map((btn) => (
            <button
              key={btn}
              onClick={() => setFilterResult(btn)}
              className={`px-3 py-1 text-xs font-mono rounded-md transition ${
                filterResult === btn
                  ? 'bg-slate-700 text-white font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              {btn}
            </button>
          ))}
        </div>
        <span className="text-[11px] font-mono text-slate-500">
          Showing {filteredVerifications.length} Proof Receipts
        </span>
      </div>

      {/* Verification Receipts Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left font-mono text-xs">
          <thead>
            <tr className="border-b border-soc-border text-slate-400 uppercase text-[10px]">
              <th className="py-2 px-3">Receipt / ID</th>
              <th className="py-2 px-3">Type</th>
              <th className="py-2 px-3">Expected &rarr; Actual</th>
              <th className="py-2 px-3 text-center">Origin Access</th>
              <th className="py-2 px-3 text-center">Decoy Session</th>
              <th className="py-2 px-3 text-center">Database Access</th>
              <th className="py-2 px-3">Status</th>
              <th className="py-2 px-3 text-right">Proof Audit</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-soc-border/40">
            {loading ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-slate-500">
                  Loading verification telemetry receipts...
                </td>
              </tr>
            ) : filteredVerifications.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-slate-500">
                  No verification receipts recorded matching filter.
                </td>
              </tr>
            ) : (
              filteredVerifications.map((v) => {
                const isVerified = v.result === 'VERIFIED';
                const isFailed = v.result === 'FAILED';
                const isInconclusive = v.result === 'INCONCLUSIVE';

                return (
                  <tr key={v.verification_id} className="hover:bg-slate-800/40 transition">
                    <td className="py-2.5 px-3">
                      <div className="font-semibold text-slate-200">{v.verification_id}</div>
                      <div className="text-[10px] text-slate-500">{v.request_id}</div>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                        {v.verification_type}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="text-slate-400">{v.expected_action}</span>
                      <span className="text-slate-600 mx-1">&rarr;</span>
                      <span className="text-slate-200 font-semibold">{v.actual_action}</span>
                    </td>
                    <td className="py-2.5 px-3 text-center">
                      {v.actual_origin_access ? (
                        <span className="px-1.5 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-800 text-[10px]">
                          REACHED ({v.origin_request_count})
                        </span>
                      ) : (
                        <span className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px]">
                          ZERO ACCESS (0)
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-center">
                      {v.deception_session_id ? (
                        <span className="px-1.5 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 text-[10px]">
                          {v.deception_session_id.substring(0, 10)}... ({v.evidence_count} ev)
                        </span>
                      ) : (
                        <span className="text-slate-500 text-[10px]">NONE</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-center">
                      {v.database_access_detected ? (
                        <span className="text-rose-400 font-bold">DETECTED</span>
                      ) : (
                        <span className="text-emerald-400">NO ACCESS</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded font-bold text-[10px] flex items-center gap-1 w-fit ${
                        isVerified
                          ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                          : isFailed
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : 'bg-amber-950 text-amber-300 border border-amber-800'
                      }`}>
                        {isVerified && <CheckCircle2 className="w-3 h-3" />}
                        {isFailed && <XCircle className="w-3 h-3" />}
                        {isInconclusive && <AlertCircle className="w-3 h-3" />}
                        {v.result}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={() => setSelectedVerification(v)}
                        className="px-2 py-1 rounded bg-slate-800 hover:bg-cyan-950 hover:text-cyan-300 text-slate-300 border border-slate-700 text-[11px] transition flex items-center gap-1 ml-auto"
                      >
                        <FileText className="w-3 h-3" />
                        Inspect Proof
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Proof Modal */}
      {selectedVerification && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-soc-panel border border-cyan-800/80 rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-2xl relative font-mono text-xs">
            <div className="flex items-center justify-between pb-3 border-b border-soc-border">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
                  Cryptographic / Telemetry Mitigation Receipt
                </h3>
              </div>
              <button
                onClick={() => setSelectedVerification(null)}
                className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Receipt Summary Card */}
            <div className="p-4 rounded-lg bg-soc-card border border-soc-border space-y-3">
              <div className="grid grid-cols-2 gap-2 text-slate-300">
                <div>
                  <span className="text-slate-500 block text-[10px]">RECEIPT ID</span>
                  <span className="text-cyan-400 font-bold">{selectedVerification.verification_id}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">RESULT STATUS</span>
                  <span className={`font-bold ${
                    selectedVerification.result === 'VERIFIED' ? 'text-emerald-400' : 'text-rose-400'
                  }`}>
                    {selectedVerification.result} ({Math.round(selectedVerification.confidence * 100)}% Confidence)
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">REQUEST ID</span>
                  <span className="text-slate-300">{selectedVerification.request_id}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">TRACE ID</span>
                  <span className="text-slate-300">{selectedVerification.trace_id}</span>
                </div>
              </div>

              <div className="border-t border-soc-border pt-3 grid grid-cols-3 gap-2 text-center">
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">ORIGIN WORKLOAD</span>
                  <span className="font-bold text-emerald-400 text-xs">
                    {selectedVerification.actual_origin_access ? 'ACCESSED' : '0 REQUESTS (UNTOUCHED)'}
                  </span>
                </div>
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">DECOY SESSION</span>
                  <span className="font-bold text-purple-400 text-xs">
                    {selectedVerification.deception_session_id ? 'ISOLATED' : 'NOT INVOLVED'}
                  </span>
                </div>
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">PRODUCTION DB</span>
                  <span className="font-bold text-emerald-400 text-xs">
                    {selectedVerification.database_access_detected ? 'ACCESSED' : 'ZERO ACCESS'}
                  </span>
                </div>
              </div>
            </div>

            {/* Proof Points List */}
            <div>
              <div className="text-[11px] font-semibold text-slate-300 uppercase mb-2">
                Deterministic Telemetry Proof Points:
              </div>
              <div className="space-y-1.5 bg-slate-950 p-3 rounded-lg border border-soc-border">
                {selectedVerification.proof && selectedVerification.proof.length > 0 ? (
                  selectedVerification.proof.map((p, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-emerald-300">
                      <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                      <span>{p}</span>
                    </div>
                  ))
                ) : (
                  <div className="text-slate-500">No proof records provided.</div>
                )}
                {selectedVerification.failure_reason && (
                  <div className="flex items-start gap-2 text-rose-400 pt-2 border-t border-rose-950">
                    <X className="w-3.5 h-3.5 text-rose-500 shrink-0 mt-0.5" />
                    <span>Failure Reason: {selectedVerification.failure_reason}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center justify-between pt-2 border-t border-soc-border">
              <span className="text-[10px] text-slate-500">
                Engine: {selectedVerification.engine_version} &bull; Timestamp: {selectedVerification.created_at}
              </span>
              <button
                onClick={() => handleCopy(JSON.stringify(selectedVerification, null, 2), selectedVerification.verification_id)}
                className="px-3 py-1.5 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-xs flex items-center gap-1.5 transition"
              >
                {copiedId === selectedVerification.verification_id ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Copied JSON</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Copy Proof Receipt</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
