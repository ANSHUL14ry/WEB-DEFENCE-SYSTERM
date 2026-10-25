import React from 'react';
import { Shield, RefreshCw, Terminal } from 'lucide-react';

interface HeaderProps {
  onRefresh: () => void;
  isRefreshing: boolean;
  systemStatus: string;
}

export const Header: React.FC<HeaderProps> = ({ onRefresh, isRefreshing, systemStatus }) => {
  return (
    <header className="h-16 border-b border-soc-border bg-soc-panel/80 backdrop-blur px-6 flex items-center justify-between sticky top-0 z-50">
      <div className="flex items-center space-x-3">
        <div className="w-10 h-10 rounded-lg bg-gradient-to-tr from-cyan-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-900/30 border border-cyan-400/30">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="font-bold text-lg tracking-wide text-white font-mono">AEGIS Ω</h1>
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
              v0.1.0-alpha
            </span>
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              {systemStatus}
            </span>
          </div>
          <p className="text-xs text-slate-400">Detect. Predict. Deceive. Contain.</p>
        </div>
      </div>

      <div className="flex items-center space-x-4">
        <div className="hidden md:flex items-center text-xs font-mono bg-soc-card px-3 py-1.5 rounded border border-soc-border text-slate-300">
          <Terminal className="w-3.5 h-3.5 mr-2 text-cyan-400" />
          <span>Ingress: :8080 | Dashboard: :3000 | API: :8001</span>
        </div>

        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="flex items-center space-x-1.5 text-xs font-mono px-3 py-1.5 rounded bg-soc-card hover:bg-soc-highlight text-slate-300 border border-soc-border transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Sync</span>
        </button>
      </div>
    </header>
  );
};
