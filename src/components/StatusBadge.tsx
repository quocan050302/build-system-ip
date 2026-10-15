import React from 'react';

interface StatusBadgeProps {
  status: string;
  type?: 'vm' | 'network' | 'channel' | 'generic';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, type: _type = 'generic' }) => {
  let bg = 'bg-slate-800 text-slate-300 border-slate-700';
  let dot = 'bg-slate-400';

  const normalized = status.toUpperCase();

  if (normalized === 'RUNNING' || normalized === 'VERIFIED' || normalized === 'AUTHORIZED' || normalized === 'ACTIVE') {
    bg = 'bg-emerald-950/60 text-emerald-300 border-emerald-800/80';
    dot = 'bg-emerald-400';
  } else if (normalized === 'STARTING' || normalized === 'CHECKING' || normalized === 'DEGRADED') {
    bg = 'bg-amber-950/60 text-amber-300 border-amber-800/80';
    dot = 'bg-amber-400 animate-pulse';
  } else if (normalized === 'STOPPED' || normalized === 'NOT_CHECKED' || normalized === 'INACTIVE') {
    bg = 'bg-slate-800/80 text-slate-400 border-slate-700/80';
    dot = 'bg-slate-500';
  } else if (normalized === 'ERROR' || normalized === 'TERMINATED' || normalized === 'DISCONNECTED') {
    bg = 'bg-rose-950/70 text-rose-300 border-rose-800/80';
    dot = 'bg-rose-500';
  } else if (normalized === 'RESTRICTED' || normalized === 'STOPPING') {
    bg = 'bg-orange-950/60 text-orange-300 border-orange-800/80';
    dot = 'bg-orange-400';
  } else if (normalized === 'UNVERIFIED' || normalized === 'NOT_CONFIGURED') {
    bg = 'bg-slate-800 text-slate-400 border-slate-700';
    dot = 'bg-slate-400';
  }

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${bg}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dot}`}></span>
      {status}
    </span>
  );
};
