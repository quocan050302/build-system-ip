import React from 'react';
import { ShieldCheck, HardDrive, RefreshCw } from 'lucide-react';
import { HypervisorInfo, PlatformInfo } from '../types';

interface HeaderProps {
  title: string;
  subtitle: string;
  hypervisorInfo: HypervisorInfo | null;
  platformInfo?: PlatformInfo | null;
  onRefresh: () => void;
  isLoading: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  title,
  subtitle,
  hypervisorInfo,
  platformInfo,
  onRefresh,
  isLoading,
}) => {
  const isMac = platformInfo?.os === 'macos' || (typeof navigator !== 'undefined' && navigator.userAgent.toLowerCase().includes('mac'));
  const vaultName = isMac ? 'Apple Keychain' : 'Windows DPAPI';
  const defaultHypervisorName = isMac ? 'UTM' : 'Microsoft Hyper-V';
  const isMock = hypervisorInfo?.name.toLowerCase().includes('mock') ?? false;

  return (
    <header className="h-16 px-8 border-b border-surface-800 bg-surface-900/60 backdrop-blur-md flex items-center justify-between">
      <div>
        <h2 className="text-lg font-semibold text-slate-100 tracking-tight">{title}</h2>
        <p className="text-xs text-slate-400">{subtitle}</p>
      </div>

      <div className="flex items-center gap-3">
        {/* Real vs Demo Mode Badge */}
        <div className="flex items-center">
          {isMock ? (
            <span className="px-2.5 py-1 rounded-md text-[10px] font-mono font-bold bg-amber-950/80 border border-amber-800 text-amber-300 tracking-wider">
              DEMO MODE
            </span>
          ) : (
            <span className="px-2.5 py-1 rounded-md text-[10px] font-mono font-bold bg-emerald-950/80 border border-emerald-800 text-emerald-300 tracking-wider">
              REAL MODE
            </span>
          )}
        </div>

        {/* Hypervisor Status Indicator */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-850 border border-surface-750 text-xs">
          <HardDrive className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-slate-300 font-medium">Hypervisor:</span>
          {hypervisorInfo ? (
            <span className={`font-mono text-[11px] ${hypervisorInfo.available ? 'text-emerald-400' : 'text-amber-400'}`}>
              {hypervisorInfo.name || defaultHypervisorName} ({hypervisorInfo.available ? 'Ready' : 'Unavailable'})
            </span>
          ) : (
            <span className="text-slate-500 font-mono text-[11px]">{defaultHypervisorName} (Detecting...)</span>
          )}
        </div>

        {/* Security Vault Indicator */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-850 border border-surface-750 text-xs text-slate-300">
          <ShieldCheck className="w-3.5 h-3.5 text-blue-400" />
          <span>Vault:</span>
          <span className="font-mono text-[11px] text-blue-400">{vaultName}</span>
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
