import React, { useState } from 'react';
import { 
  HardDrive, 
  KeyRound, 
  FileText, 
  Check, 
  AlertTriangle,
  RefreshCw,
  Cpu,
  ShieldCheck
} from 'lucide-react';
import { HypervisorInfo, HostResources, AuditLogEntry } from '../types';

interface SettingsViewProps {
  hypervisorInfo: HypervisorInfo | null;
  hostResources: HostResources | null;
  auditLogs: AuditLogEntry[];
  onTestVault: () => Promise<boolean>;
  onRefresh: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  hypervisorInfo,
  hostResources,
  auditLogs,
  onTestVault,
  onRefresh,
}) => {
  const [vaultTestResult, setVaultTestResult] = useState<boolean | null>(null);
  const [isTestingVault, setIsTestingVault] = useState(false);
  const [logFilter, setLogFilter] = useState('ALL');

  const handleTestVault = async () => {
    setIsTestingVault(true);
    try {
      const res = await onTestVault();
      setVaultTestResult(res);
    } catch {
      setVaultTestResult(false);
    } finally {
      setIsTestingVault(false);
    }
  };

  const filteredLogs = auditLogs.filter((log) => {
    if (logFilter === 'ALL') return true;
    return log.severity === logFilter;
  });

  return (
    <div className="space-y-6">
      {/* Hypervisor Settings & Discovery */}
      <div className="bg-surface-900 border border-surface-800 rounded-xl p-5 space-y-4 shadow-sm">
        <div className="flex items-center justify-between border-b border-surface-800 pb-3">
          <div className="flex items-center gap-2.5">
            <HardDrive className="w-5 h-5 text-blue-400" />
            <div>
              <h3 className="text-sm font-semibold text-slate-100">VirtualBox Hypervisor Integration</h3>
              <p className="text-xs text-slate-400">Windows VBoxManage CLI adapter status & path</p>
            </div>
          </div>
          <button
            onClick={onRefresh}
            className="text-xs text-brand-accent hover:text-blue-400 font-medium flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Re-detect
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-3 bg-surface-850 rounded-lg border border-surface-750 space-y-1">
            <span className="text-slate-400">Hypervisor Adapter:</span>
            <div className="font-semibold text-slate-200">
              {hypervisorInfo?.name || 'Detecting...'}
            </div>
            <div className="text-[11px] font-mono text-slate-400">
              Version: {hypervisorInfo?.version || 'N/A'}
            </div>
          </div>

          <div className="p-3 bg-surface-850 rounded-lg border border-surface-750 space-y-1">
            <span className="text-slate-400">Executable Location:</span>
            <div className="font-mono text-slate-200 truncate">
              {hypervisorInfo?.executable_path || 'Not detected on PATH or standard directory'}
            </div>
            <div className="text-[11px] text-emerald-400 font-medium">
              {hypervisorInfo?.available ? '✓ System integration active' : '⚠ Fallback mock adapter active'}
            </div>
          </div>
        </div>

        {/* Host Compute & Memory Allocation Capacity */}
        {hostResources && (
          <div className="p-3 bg-surface-850 rounded-lg border border-surface-750 flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-slate-400" />
              <span className="text-slate-300 font-medium">Host Memory Budget:</span>
              <span className="font-mono text-slate-200">
                {(hostResources.available_memory_mb / 1024).toFixed(1)} GB Available / {(hostResources.total_memory_mb / 1024).toFixed(1)} GB Total
              </span>
            </div>
            <div className="text-slate-400 font-mono">
              Free Disk Space: {(hostResources.available_disk_mb / 1024).toFixed(0)} GB
            </div>
          </div>
        )}
      </div>

      {/* Security & Windows DPAPI Vault */}
      <div className="bg-surface-900 border border-surface-800 rounded-xl p-5 space-y-4 shadow-sm">
        <div className="flex items-center justify-between border-b border-surface-800 pb-3">
          <div className="flex items-center gap-2.5">
            <KeyRound className="w-5 h-5 text-emerald-400" />
            <div>
              <h3 className="text-sm font-semibold text-slate-100">Encrypted Secret Vault (Windows DPAPI)</h3>
              <p className="text-xs text-slate-400">Hardware-bound user master key encryption at rest</p>
            </div>
          </div>
          <button
            onClick={handleTestVault}
            disabled={isTestingVault}
            className="px-3 py-1.5 bg-emerald-950/60 hover:bg-emerald-900/60 text-emerald-300 border border-emerald-800/80 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5"
          >
            {isTestingVault ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
            <span>Run Cryptographic Test</span>
          </button>
        </div>

        <div className="p-4 bg-surface-850 rounded-lg border border-surface-750 space-y-2 text-xs">
          <div className="flex items-center justify-between">
            <span className="text-slate-300 font-medium">Cryptographic Provider:</span>
            <span className="font-mono text-slate-200">Win32 CryptProtectData / CryptUnprotectData</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-300 font-medium">Credential Protection Scope:</span>
            <span className="font-mono text-slate-200">Current Windows User Account (TPM/LSA Sealing)</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-300 font-medium">Vault Integrity Status:</span>
            {vaultTestResult === null ? (
              <span className="text-slate-400 font-mono">Not Tested Yet (Click Run Cryptographic Test)</span>
            ) : vaultTestResult ? (
              <span className="text-emerald-400 font-mono font-semibold flex items-center gap-1">
                <Check className="w-3.5 h-3.5" /> DPAPI Roundtrip Verified
              </span>
            ) : (
              <span className="text-rose-400 font-mono font-semibold flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" /> Verification Failed
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Audit Log Trail Viewer */}
      <div className="bg-surface-900 border border-surface-800 rounded-xl overflow-hidden shadow-sm">
        <div className="px-5 py-4 border-b border-surface-800 bg-surface-850/40 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <FileText className="w-5 h-5 text-purple-400" />
            <div>
              <h3 className="text-sm font-semibold text-slate-100">Audit & Operational Logs</h3>
              <p className="text-xs text-slate-400">Structured system activity trail stored in SQLite</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={logFilter}
              onChange={(e) => setLogFilter(e.target.value)}
              className="bg-surface-850 border border-surface-750 text-slate-300 text-xs rounded-lg px-2.5 py-1 focus:outline-none focus:border-brand-accent"
            >
              <option value="ALL">All Severities</option>
              <option value="INFO">INFO Only</option>
              <option value="WARN">WARN Only</option>
              <option value="ERROR">ERROR Only</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto max-h-80">
          <table className="w-full text-left text-xs">
            <thead className="bg-surface-850/60 border-b border-surface-800 text-slate-400 uppercase font-semibold tracking-wider sticky top-0">
              <tr>
                <th className="py-2.5 px-4">Timestamp</th>
                <th className="py-2.5 px-4">Severity</th>
                <th className="py-2.5 px-4">Action</th>
                <th className="py-2.5 px-4">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-800/80">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-slate-500">
                    No log events recorded matching filter.
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-surface-850/30 transition-colors">
                    <td className="py-2.5 px-4 font-mono text-slate-400 whitespace-nowrap">
                      {new Date(log.created_at).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold ${
                        log.severity === 'ERROR' || log.severity === 'CRITICAL'
                          ? 'bg-rose-950 text-rose-400 border border-rose-800'
                          : log.severity === 'WARN'
                          ? 'bg-amber-950 text-amber-400 border border-amber-800'
                          : 'bg-surface-800 text-slate-400'
                      }`}>
                        {log.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-200 font-medium">
                      {log.action}
                    </td>
                    <td className="py-2.5 px-4 text-slate-300">
                      {log.message}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
