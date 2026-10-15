import React from 'react';
import { 
  Layers, 
  Play, 
  Square, 
  ShieldAlert, 
  HardDrive, 
  Cpu, 
  Activity, 
  AlertTriangle,
  ArrowRight
} from 'lucide-react';
import { 
  EnvironmentRecord, 
  HostResources, 
  HypervisorInfo, 
  DuplicateEgressWarning, 
  AuditLogEntry 
} from '../types';
import { NavItem } from '../components/Sidebar';

interface OverviewViewProps {
  environments: EnvironmentRecord[];
  hostResources: HostResources | null;
  hypervisorInfo: HypervisorInfo | null;
  duplicateWarnings: DuplicateEgressWarning[];
  auditLogs: AuditLogEntry[];
  onNavigate: (tab: NavItem) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  environments,
  hostResources,
  hypervisorInfo,
  duplicateWarnings,
  auditLogs,
  onNavigate,
}) => {
  const runningVms = environments.filter((e) => e.status === 'RUNNING').length;
  const stoppedVms = environments.filter((e) => e.status === 'STOPPED').length;
  const verifiedNetworks = environments.filter((e) => Boolean(e.last_observed_ipv4)).length;
  const unverifiedNetworks = environments.length - verifiedNetworks;

  const ramUsedGb = hostResources ? ((hostResources.total_memory_mb - hostResources.available_memory_mb) / 1024).toFixed(1) : '0';
  const ramTotalGb = hostResources ? (hostResources.total_memory_mb / 1024).toFixed(1) : '0';
  const diskAvailGb = hostResources ? (hostResources.available_disk_mb / 1024).toFixed(0) : '0';

  return (
    <div className="space-y-6">
      {/* Operational Warnings / Duplicate IP Banner */}
      {duplicateWarnings.length > 0 && (
        <div className="bg-rose-950/40 border border-rose-800/80 rounded-xl p-4 flex items-start gap-4 shadow-lg shadow-rose-950/20">
          <div className="p-2 bg-rose-900/60 rounded-lg text-rose-300">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div className="flex-1">
            <h4 className="text-sm font-semibold text-rose-200">Critical Network Isolation Alert</h4>
            {duplicateWarnings.map((w, idx) => (
              <p key={idx} className="text-xs text-rose-300/90 mt-1">
                {w.message}
              </p>
            ))}
          </div>
          <button
            onClick={() => onNavigate('network')}
            className="px-3 py-1.5 bg-rose-800/60 hover:bg-rose-700/60 text-rose-100 rounded-lg text-xs font-medium transition-colors border border-rose-700"
          >
            Review Endpoints
          </button>
        </div>
      )}

      {/* Hypervisor Advisory if not detected */}
      {hypervisorInfo && !hypervisorInfo.available && (
        <div className="bg-amber-950/40 border border-amber-800/60 rounded-xl p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
            <div>
              <h4 className="text-sm font-medium text-amber-200">VirtualBox Not Detected On Host</h4>
              <p className="text-xs text-amber-400/80 mt-0.5">
                Install VirtualBox 7.x or configure the custom executable path in Settings. Mock mode is active for UI testing.
              </p>
            </div>
          </div>
          <button
            onClick={() => onNavigate('settings')}
            className="px-3 py-1.5 bg-amber-900/40 hover:bg-amber-800/40 text-amber-200 text-xs rounded-lg border border-amber-700/60"
          >
            Configure Path
          </button>
        </div>
      )}

      {/* Primary KPI Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Managed Environments */}
        <div 
          onClick={() => onNavigate('environments')}
          className="bg-surface-900 border border-surface-800 hover:border-surface-700 p-5 rounded-xl transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Environments</span>
            <div className="p-2 bg-blue-950/50 rounded-lg text-blue-400 group-hover:bg-blue-900/50 transition-colors">
              <Layers className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-100 font-mono">{environments.length}</span>
            <span className="text-xs text-slate-400">total profiles</span>
          </div>
          <div className="mt-3 flex items-center justify-between text-xs text-slate-500 pt-3 border-t border-surface-800/80">
            <span>Manage VMs</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform text-slate-400" />
          </div>
        </div>

        {/* VM State Breakdown */}
        <div className="bg-surface-900 border border-surface-800 p-5 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">VM Lifecycles</span>
            <div className="p-2 bg-emerald-950/50 rounded-lg text-emerald-400">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-center gap-4">
            <div>
              <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-medium">
                <Play className="w-3 h-3 fill-emerald-400" /> Running
              </div>
              <span className="text-xl font-bold text-slate-100 font-mono">{runningVms}</span>
            </div>
            <div className="h-8 w-px bg-surface-800"></div>
            <div>
              <div className="flex items-center gap-1.5 text-xs text-slate-400 font-medium">
                <Square className="w-3 h-3 fill-slate-400" /> Stopped
              </div>
              <span className="text-xl font-bold text-slate-100 font-mono">{stoppedVms}</span>
            </div>
          </div>
          <div className="mt-3 text-xs text-slate-500 pt-3 border-t border-surface-800/80">
            <span>Hypervisor: {hypervisorInfo?.available ? 'Operational' : 'Mock Mode'}</span>
          </div>
        </div>

        {/* Network Diagnostics */}
        <div 
          onClick={() => onNavigate('network')}
          className="bg-surface-900 border border-surface-800 hover:border-surface-700 p-5 rounded-xl transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Egress Checks</span>
            <div className="p-2 bg-indigo-950/50 rounded-lg text-indigo-400 group-hover:bg-indigo-900/50 transition-colors">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-100 font-mono">{verifiedNetworks}</span>
            <span className="text-xs text-emerald-400 font-medium">Verified Egress</span>
          </div>
          <div className="mt-3 flex items-center justify-between text-xs text-slate-500 pt-3 border-t border-surface-800/80">
            <span className={unverifiedNetworks > 0 ? 'text-amber-400/90' : 'text-slate-500'}>
              {unverifiedNetworks} unverified / stopped
            </span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform text-slate-400" />
          </div>
        </div>

        {/* Host Memory & Storage */}
        <div className="bg-surface-900 border border-surface-800 p-5 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Host Capacity</span>
            <div className="p-2 bg-purple-950/50 rounded-lg text-purple-400">
              <Cpu className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between text-xs text-slate-300">
            <span>RAM: <strong className="text-slate-100 font-mono">{ramUsedGb} / {ramTotalGb} GB</strong></span>
            <span>Free Disk: <strong className="text-slate-100 font-mono">{diskAvailGb} GB</strong></span>
          </div>
          <div className="mt-3 w-full bg-surface-800 h-1.5 rounded-full overflow-hidden">
            <div 
              className="bg-purple-500 h-full rounded-full transition-all"
              style={{ width: `${hostResources ? Math.min(100, Math.round(((hostResources.total_memory_mb - hostResources.available_memory_mb) / (hostResources.total_memory_mb || 1)) * 100)) : 25}%` }}
            ></div>
          </div>
          <div className="mt-3 text-xs text-slate-500 pt-3 border-t border-surface-800/80 flex items-center gap-1.5">
            <HardDrive className="w-3 h-3 text-slate-400" />
            <span>Dedicated VDI storage pool</span>
          </div>
        </div>
      </div>

      {/* Bottom Section: Active Environments Summary & Recent Audit Trail */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Environments Quick Status */}
        <div className="lg:col-span-2 bg-surface-900 border border-surface-800 rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-surface-800 flex items-center justify-between bg-surface-850/40">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">Managed Environments</h3>
              <p className="text-xs text-slate-400">Real-time isolation status & hardware allocation</p>
            </div>
            <button
              onClick={() => onNavigate('environments')}
              className="text-xs text-brand-accent hover:text-blue-400 font-medium flex items-center gap-1"
            >
              View all ({environments.length}) <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="divide-y divide-surface-800/80 overflow-x-auto">
            {environments.length === 0 ? (
              <div className="p-8 text-center text-slate-400 text-xs">
                No environments configured yet. Go to Environments to create your first isolated VM profile.
              </div>
            ) : (
              environments.slice(0, 5).map((env) => (
                <div key={env.id} className="px-5 py-3.5 flex items-center justify-between hover:bg-surface-850/30 transition-colors">
                  <div className="flex items-center gap-3">
                    <div className={`w-2.5 h-2.5 rounded-full ${env.status === 'RUNNING' ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600'}`}></div>
                    <div>
                      <h4 className="text-sm font-medium text-slate-200">{env.name}</h4>
                      <p className="text-xs text-slate-400 font-mono">
                        {env.guest_os} • {env.cpu_count} vCPU • {env.memory_mb / 1024} GB RAM
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 text-xs">
                    <div className="text-right">
                      <span className="text-slate-400 block">Observed Egress:</span>
                      <span className="font-mono text-slate-200">
                        {env.last_observed_ipv4 || 'Not Checked'}
                      </span>
                    </div>

                    <span className={`px-2.5 py-1 rounded-full text-[11px] font-medium border ${
                      env.status === 'RUNNING' 
                        ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800/80' 
                        : 'bg-surface-800 text-slate-400 border-surface-700'
                    }`}>
                      {env.status}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Audit Log Feed */}
        <div className="bg-surface-900 border border-surface-800 rounded-xl overflow-hidden flex flex-col">
          <div className="px-5 py-4 border-b border-surface-800 bg-surface-850/40">
            <h3 className="text-sm font-semibold text-slate-100">Audit & Security Log</h3>
            <p className="text-xs text-slate-400">Immutable local event trail</p>
          </div>

          <div className="p-4 space-y-3 flex-1 overflow-y-auto max-h-[360px]">
            {auditLogs.length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-6">No recent events recorded</p>
            ) : (
              auditLogs.slice(0, 7).map((log) => (
                <div key={log.id} className="text-xs space-y-1 pb-2 border-b border-surface-850 last:border-0">
                  <div className="flex items-center justify-between">
                    <span className={`font-mono text-[10px] px-1.5 py-0.5 rounded font-semibold ${
                      log.severity === 'ERROR' || log.severity === 'CRITICAL'
                        ? 'bg-rose-950 text-rose-400 border border-rose-800'
                        : log.severity === 'WARN'
                        ? 'bg-amber-950 text-amber-400 border border-amber-800'
                        : 'bg-surface-800 text-slate-400'
                    }`}>
                      {log.action}
                    </span>
                    <span className="text-[10px] text-slate-500 font-mono">
                      {new Date(log.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </span>
                  </div>
                  <p className="text-slate-300 text-[11px] leading-tight">{log.message}</p>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
