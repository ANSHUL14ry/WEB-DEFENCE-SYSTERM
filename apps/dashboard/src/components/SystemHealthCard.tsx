import React from 'react';
import { ServiceStatus } from '../types';
import { CheckCircle2, Clock, AlertTriangle, ShieldCheck } from 'lucide-react';

interface SystemHealthCardProps {
  name: string;
  serviceKey: string;
  service: ServiceStatus;
}

export const SystemHealthCard: React.FC<SystemHealthCardProps> = ({ name, serviceKey, service }) => {
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'operational':
      case 'healthy':
      case 'connected':
      case 'reachable':
        return {
          bg: 'bg-emerald-950/80 text-emerald-400 border-emerald-800',
          dot: 'bg-emerald-400',
          icon: CheckCircle2,
          text: status.toUpperCase()
        };
      case 'degraded':
        return {
          bg: 'bg-amber-950/80 text-amber-400 border-amber-800',
          dot: 'bg-amber-400',
          icon: AlertTriangle,
          text: 'DEGRADED'
        };
      case 'scheduled':
        return {
          bg: 'bg-slate-900 text-slate-400 border-slate-800',
          dot: 'bg-slate-500',
          icon: Clock,
          text: 'PHASE MILESTONE'
        };
      default:
        return {
          bg: 'bg-rose-950/80 text-rose-400 border-rose-800',
          dot: 'bg-rose-400',
          icon: AlertTriangle,
          text: 'OFFLINE'
        };
    }
  };

  const badge = getStatusBadge(service.status);
  const StatusIcon = badge.icon;

  return (
    <div className="bg-soc-panel border border-soc-border hover:border-slate-700 transition-colors rounded-xl p-4 flex flex-col justify-between shadow-sm">
      <div>
        <div className="flex items-center justify-between mb-2">
          <span className="font-mono text-xs uppercase text-slate-400 font-semibold tracking-wider flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
            {name}
          </span>
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border flex items-center gap-1.5 ${badge.bg}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${badge.dot}`}></span>
            {badge.text}
          </span>
        </div>
        <div className="text-sm font-semibold text-slate-200 mt-1">{service.type}</div>
        <p className="text-xs text-slate-400 mt-1 line-clamp-2">{service.role}</p>
      </div>

      <div className="mt-4 pt-3 border-t border-soc-border/60 flex items-center justify-between text-[11px] font-mono text-slate-500">
        <span>Component: {serviceKey}</span>
        <StatusIcon className="w-3.5 h-3.5 text-slate-400" />
      </div>
    </div>
  );
};
