import React from 'react';
import { ShieldCheck, HardDrive, RefreshCw } from 'lucide-react';
import { HypervisorInfo } from '../types';

interface HeaderProps {
  title: string;
  subtitle: string;
  hypervisorInfo: HypervisorInfo | null;
  onRefresh: () => void;
  isLoading: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  title,
  subtitle,
  hypervisorInfo,
  onRefresh,
  isLoading,
}) => {
  return (
    <header className="h-16 px-8 border-b border-surface-800 bg-surface-900/60 backdrop-blur-md flex items-center justify-between">
      <div>
        <h2 className="text-lg font-semibold text-slate-100 tracking-tight">{title}</h2>
        <p className="text-xs text-slate-400">{subtitle}</p>
      </div>

      <div className="flex items-center gap-4">
        {/* Hypervisor Status Indicator */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-850 border border-surface-750 text-xs">
          <HardDrive className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-slate-300 font-medium">Hypervisor:</span>
          {hypervisorInfo ? (
            <span className={`font-mono text-[11px] ${hypervisorInfo.available ? 'text-emerald-400' : 'text-amber-400'}`}>
              {hypervisorInfo.name} ({hypervisorInfo.available ? 'Ready' : 'Not Installed'})
            </span>
          ) : (
            <span className="text-slate-500 font-mono text-[11px]">Detecting...</span>
          )}
        </div>

        {/* Security Vault Indicator */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-850 border border-surface-750 text-xs text-slate-300">
          <ShieldCheck className="w-3.5 h-3.5 text-blue-400" />
          <span>Vault:</span>
          <span className="font-mono text-[11px] text-blue-400">Windows DPAPI</span>
        </div>

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isLoading}
          className="p-2 text-slate-400 hover:text-slate-200 hover:bg-surface-800 rounded-lg transition-colors border border-surface-750"
          title="Refresh All Data"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-brand-accent' : ''}`} />
        </button>
      </div>
    </header>
  );
};
