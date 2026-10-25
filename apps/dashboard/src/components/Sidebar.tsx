import React from 'react';
import { 
  Activity, 
  ShieldAlert, 
  Cpu, 
  EyeOff, 
  CheckCircle2, 
  Crosshair, 
  Bot, 
  Server,
  Layers
} from 'lucide-react';

interface SidebarProps {
  currentTab: string;
  setCurrentTab: (tab: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, setCurrentTab }) => {
  const navItems = [
    { id: 'overview', label: 'SOC Overview', icon: Activity, phase: 'Phase 1 Active' },
    { id: 'feed', label: 'Live Threat Feed', icon: ShieldAlert, phase: 'Phase 4' },
    { id: 'agentshield', label: 'AgentShield AI', icon: Cpu, phase: 'Phase 6' },
    { id: 'deception', label: 'Decoy / Honeypot', icon: EyeOff, phase: 'Phase 8' },
    { id: 'verification', label: 'Mitigation Proof', icon: CheckCircle2, phase: 'Phase 9' },
    { id: 'simulator', label: 'Attack Simulator', icon: Crosshair, phase: 'Phase 13' },
    { id: 'copilot', label: 'AI SOC Copilot', icon: Bot, phase: 'Phase 11' },
    { id: 'architecture', label: 'System Topology', icon: Layers, phase: 'Active' },
    { id: 'infrastructure', label: 'Nodes & Services', icon: Server, phase: 'Phase 1 Active' },
  ];

  return (
    <aside className="w-64 border-r border-soc-border bg-soc-panel flex flex-col justify-between p-4">
      <div className="space-y-1">
        <div className="px-3 py-2 text-[11px] font-mono uppercase tracking-wider text-slate-500">
          Defense Console
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setCurrentTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-all text-left ${
                isActive
                  ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-800/60 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-soc-card'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span className="font-medium text-xs tracking-tight">{item.label}</span>
              </div>
              <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded ${
                item.phase.includes('Active')
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-900/60'
                  : 'bg-slate-900 text-slate-500 border border-slate-800'
              }`}>
                {item.phase}
              </span>
            </button>
          );
        })}
      </div>

      <div className="p-3 bg-soc-card rounded-lg border border-soc-border text-xs text-slate-400 space-y-1">
        <div className="flex justify-between items-center text-slate-300 font-mono text-[11px]">
          <span>Hackathon Build</span>
          <span className="text-cyan-400">Phase 1</span>
        </div>
        <p className="text-[11px] text-slate-500 leading-relaxed">
          Zero fake UI. Real reverse proxy gateway, live PostgreSQL state, and verified origin flow.
        </p>
      </div>
    </aside>
  );
};
