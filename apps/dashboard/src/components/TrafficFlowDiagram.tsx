import React from 'react';
import { Globe, ArrowRight, Shield, Filter, Eye, Server, Lock } from 'lucide-react';

export const TrafficFlowDiagram: React.FC = () => {
  return (
    <div className="bg-soc-panel border border-soc-border rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider font-mono text-slate-200">
            AEGIS Ω Real Architecture & Packet Pipeline
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Phase 1 Active Route: Client &rarr; Ingress Gateway &rarr; Origin (with Request-ID tagging)
          </p>
        </div>
        <span className="text-xs font-mono px-2.5 py-1 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800">
          Reverse Proxy Ingress :8080
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-7 gap-3 items-center py-4 text-center">
        {/* Step 1 */}
        <div className="bg-soc-card p-3 rounded-lg border border-soc-border">
          <Globe className="w-5 h-5 mx-auto text-blue-400 mb-1" />
          <div className="text-xs font-semibold text-slate-200">Client / Browser</div>
          <div className="text-[10px] font-mono text-slate-400 mt-1">:8080 Request</div>
        </div>

        <div className="hidden md:flex justify-center text-slate-600">
          <ArrowRight className="w-4 h-4 text-cyan-500 animate-pulse" />
        </div>

        {/* Step 2 */}
        <div className="bg-soc-card p-3 rounded-lg border border-cyan-800/80 shadow-sm shadow-cyan-950">
          <Shield className="w-5 h-5 mx-auto text-cyan-400 mb-1" />
          <div className="text-xs font-semibold text-slate-200">AEGIS Gateway</div>
          <div className="text-[10px] font-mono text-emerald-400 mt-1">ACTIVE (Nginx)</div>
        </div>

        <div className="hidden md:flex justify-center text-slate-600">
          <ArrowRight className="w-4 h-4 text-slate-600" />
        </div>

        {/* Step 3 */}
        <div className="bg-soc-card p-3 rounded-lg border border-slate-800 opacity-60">
          <Filter className="w-5 h-5 mx-auto text-amber-400 mb-1" />
          <div className="text-xs font-semibold text-slate-300">Coraza WAF</div>
          <div className="text-[10px] font-mono text-slate-500 mt-1">Phase 3</div>
        </div>

        <div className="hidden md:flex justify-center text-slate-600">
          <ArrowRight className="w-4 h-4 text-slate-600" />
        </div>

        {/* Step 4 */}
        <div className="grid grid-cols-2 gap-2">
          <div className="bg-soc-card p-2 rounded-lg border border-emerald-800/60">
            <Server className="w-4 h-4 mx-auto text-emerald-400 mb-1" />
            <div className="text-[11px] font-semibold text-slate-200">Origin</div>
            <div className="text-[9px] font-mono text-emerald-400">ACTIVE</div>
          </div>
          <div className="bg-soc-card p-2 rounded-lg border border-slate-800 opacity-50">
            <Eye className="w-4 h-4 mx-auto text-purple-400 mb-1" />
            <div className="text-[11px] font-semibold text-slate-400">Decoy</div>
            <div className="text-[9px] font-mono text-slate-500">Phase 8</div>
          </div>
        </div>
      </div>

      <div className="mt-4 pt-3 border-t border-soc-border grid grid-cols-1 md:grid-cols-3 gap-3 text-xs text-slate-400">
        <div className="flex items-center gap-2">
          <Lock className="w-3.5 h-3.5 text-cyan-400" />
          <span>Origin Isolation: Backend unreachable except via Gateway</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
          <span>Gateway Health: HTTP 200 on /healthz</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
          <span>Header Propagation: X-Request-ID attached</span>
        </div>
      </div>
    </div>
  );
};
