import React, { useState } from 'react';
import { 
  Plus, 
  Search, 
  Play, 
  Square, 
  Trash2, 
  ShieldAlert, 
  Layers, 
  RefreshCw,
  Terminal,
  Compass
} from 'lucide-react';
import { 
  EnvironmentRecord, 
  CreateEnvironmentRequest, 
  NetworkEndpointRecord, 
  ChannelRecord, 
  HypervisorInfo,
  PlatformInfo
} from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { Modal } from '../components/Modal';
import { ConfirmDialog } from '../components/ConfirmDialog';

interface EnvironmentsViewProps {
  environments: EnvironmentRecord[];
  endpoints: NetworkEndpointRecord[];
  channels: ChannelRecord[];
  hypervisorInfo: HypervisorInfo | null;
  platformInfo?: PlatformInfo | null;
  onRefresh: () => void;
  onCreateEnvironment: (req: CreateEnvironmentRequest) => Promise<void>;
  onStartEnvironment: (id: string) => Promise<void>;
  onShutdownEnvironment: (id: string, force: boolean) => Promise<void>;
  onOpenConsole?: (id: string) => Promise<void>;
  onLaunchBrowser?: (id: string) => Promise<void>;
  onDeleteEnvironment: (id: string, deleteDisks: boolean) => Promise<void>;
  onCheckNetwork: (id: string) => Promise<void>;
}

export const EnvironmentsView: React.FC<EnvironmentsViewProps> = ({
  environments,
  endpoints,
  channels,
  hypervisorInfo,
  platformInfo,
  onRefresh,
  onCreateEnvironment,
  onStartEnvironment,
  onShutdownEnvironment,
  onOpenConsole,
  onLaunchBrowser,
  onDeleteEnvironment,
  onCheckNetwork,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [selectedEnvForDelete, setSelectedEnvForDelete] = useState<EnvironmentRecord | null>(null);
  const [isActionLoading, setIsActionLoading] = useState<string | null>(null);

  const isMac = platformInfo?.os === 'macos' || (typeof navigator !== 'undefined' && navigator.userAgent.toLowerCase().includes('mac'));
  const defaultHvType = isMac ? 'UTM' : 'Hyper-V';
  const defaultOsType = isMac ? 'Ubuntu_ARM64' : 'Ubuntu_64';

  // New Environment Form State
  const [newName, setNewName] = useState('');
  const [newHypervisor, setNewHypervisor] = useState(defaultHvType);
  const [newGuestOs, setNewGuestOs] = useState(defaultOsType);
  const [newCpu, setNewCpu] = useState(2);
  const [newRamMb, setNewRamMb] = useState(2048);
  const [newDiskMb, setNewDiskMb] = useState(20480);
  const [newIsoPath, setNewIsoPath] = useState('');
  const [newBrowser, setNewBrowser] = useState('chrome');
  const [newEndpointId, setNewEndpointId] = useState('');
  const [newChannelId, setNewChannelId] = useState('');
  const [formError, setFormError] = useState<string | null>(null);

  const filteredEnvironments = environments.filter((env) => {
    const matchesSearch = 
      env.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (env.channel_name && env.channel_name.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (env.last_observed_ipv4 && env.last_observed_ipv4.includes(searchTerm));
    const matchesStatus = statusFilter === 'ALL' || env.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!newName.trim()) {
      setFormError('Environment name is required');
      return;
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(newName.trim())) {
      setFormError('Name may only contain alphanumeric characters, hyphens, and underscores');
      return;
    }

    try {
      setIsActionLoading('create');
      await onCreateEnvironment({
        name: newName.trim(),
        hypervisor_type: newHypervisor || (hypervisorInfo?.name.includes('UTM') ? 'UTM' : hypervisorInfo?.name.includes('Hyper-V') ? 'Hyper-V' : 'VirtualBox'),
        guest_os: newGuestOs,
        cpu_count: Number(newCpu),
        memory_mb: Number(newRamMb),
        disk_size_mb: Number(newDiskMb),
        iso_path: newIsoPath.trim() ? newIsoPath.trim() : null,
        browser_type: newBrowser,
        network_endpoint_id: newEndpointId || null,
        channel_id: newChannelId || null,
        host_platform: platformInfo?.target_triple || (isMac ? 'macos-aarch64' : 'windows-x86_64'),
        vm_architecture: platformInfo?.arch || (isMac ? 'aarch64' : 'x86_64'),
      });
      setIsCreateOpen(false);
      setNewName('');
      setNewIsoPath('');
    } catch (err: any) {
      setFormError(err?.message || String(err));
    } finally {
      setIsActionLoading(null);
    }
  };

  const handleAction = async (actionFn: () => Promise<void>, loadingKey: string) => {
    try {
      setIsActionLoading(loadingKey);
      await actionFn();
    } catch (err: any) {
      alert(`Action failed: ${err?.message || err}`);
    } finally {
      setIsActionLoading(null);
    }
  };

  return (
    <div className="space-y-5">
      {/* Controls Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 bg-surface-900 border border-surface-800 p-4 rounded-xl">
        <div className="flex items-center gap-3 w-full sm:w-auto">
          {/* Search Box */}
          <div className="relative flex-1 sm:w-72">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search environments, channels, IPs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-surface-850 border border-surface-750 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-brand-accent transition-colors"
            />
          </div>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-surface-850 border border-surface-750 text-slate-300 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-brand-accent"
          >
            <option value="ALL">All Statuses</option>
            <option value="RUNNING">Running</option>
            <option value="STOPPED">Stopped</option>
            <option value="ERROR">Error</option>
          </select>
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto justify-end">
          <button
            onClick={onRefresh}
            className="p-2 text-slate-400 hover:text-slate-200 hover:bg-surface-800 rounded-lg transition-colors border border-surface-750 text-xs flex items-center gap-1.5"
            title="Refresh Environment List"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setIsCreateOpen(true)}
            className="flex items-center gap-2 px-3.5 py-1.5 bg-brand-accent hover:bg-blue-600 text-white rounded-lg text-xs font-semibold shadow-sm transition-colors"
          >
            <Plus className="w-4 h-4" />
            <span>Create Environment</span>
          </button>
        </div>
      </div>

      {/* Environments Table */}
      <div className="bg-surface-900 border border-surface-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-surface-850/60 border-b border-surface-800 text-slate-400 uppercase font-semibold tracking-wider">
              <tr>
                <th className="py-3 px-4">Environment</th>
                <th className="py-3 px-4">Hypervisor & Arch</th>
                <th className="py-3 px-4">Allocated Resources</th>
                <th className="py-3 px-4">Assigned Channel</th>
                <th className="py-3 px-4">Network Egress Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-800/80">
              {filteredEnvironments.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500">
                    <Layers className="w-8 h-8 mx-auto mb-2 opacity-30" />
                    <p className="text-sm font-medium text-slate-400">No environments match your criteria</p>
                    <p className="text-xs mt-1">Create a new isolated guest VM to get started.</p>
                  </td>
                </tr>
              ) : (
                filteredEnvironments.map((env) => {
                  const isRunning = env.status === 'RUNNING';
                  const isLoading = isActionLoading === env.id;

                  return (
                    <tr key={env.id} className="hover:bg-surface-850/40 transition-colors">
                      {/* Name & Status */}
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-2.5">
                          <StatusBadge status={env.status} />
                          <div>
                            <span className="font-semibold text-slate-100 block">{env.name}</span>
                            <span className="text-[11px] text-slate-400 font-mono">{env.vm_identifier}</span>
                          </div>
                        </div>
                      </td>

                      {/* Hypervisor & Architecture */}
                      <td className="py-3.5 px-4">
                        <div className="space-y-0.5">
                          <div className="font-medium text-slate-200">{env.hypervisor_type}</div>
                          <div className="text-[11px] text-slate-400 font-mono">
                            {env.vm_architecture || (isMac ? 'aarch64' : 'x86_64')} • {env.guest_os}
                          </div>
                        </div>
                      </td>

                      {/* Allocations */}
                      <td className="py-3.5 px-4 font-mono text-slate-300">
                        <div className="space-y-0.5">
                          <div>{env.cpu_count} vCPU • {(env.memory_mb / 1024).toFixed(1)} GB RAM</div>
                          <div className="text-[11px] text-slate-400 truncate max-w-xs" title={env.disk_path}>
                            {env.disk_path.split(/[/\\]/).pop()}
                          </div>
                        </div>
                      </td>

                      {/* Channel */}
                      <td className="py-3.5 px-4">
                        {env.channel_name ? (
                          <div className="flex items-center gap-1.5 text-slate-200 font-medium">
                            <span className="w-2 h-2 rounded-full bg-rose-500 inline-block" />
                            <span>{env.channel_name}</span>
                          </div>
                        ) : (
                          <span className="text-slate-500 italic">Unassigned</span>
                        )}
                      </td>

                      {/* Network Status */}
                      <td className="py-3.5 px-4">
                        {env.last_observed_ipv4 ? (
                          <div className="space-y-0.5">
                            <span className="font-mono text-emerald-400 font-medium block">
                              {env.last_observed_ipv4}
                            </span>
                            <span className="text-[10px] text-slate-400">
                              Verified: {new Date(env.last_checked_at || '').toLocaleTimeString()}
                            </span>
                          </div>
                        ) : env.network_endpoint_name ? (
                          <div className="space-y-0.5">
                            <span className="text-slate-300 block">{env.network_endpoint_name}</span>
                            <span className="text-[10px] text-amber-400/90 font-mono">Egress unverified</span>
                          </div>
                        ) : (
                          <span className="text-slate-500 italic">Direct NAT</span>
                        )}
                      </td>

                      {/* Action Controls */}
                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          {/* VM Lifecycle Buttons */}
                          {isRunning ? (
                            <button
                              onClick={() => handleAction(() => onShutdownEnvironment(env.id, false), env.id)}
                              disabled={Boolean(isLoading)}
                              title="Graceful ACPI Shutdown"
                              className="p-1.5 bg-amber-950/40 hover:bg-amber-900/60 text-amber-300 border border-amber-800/60 rounded-md transition-colors"
                            >
                              <Square className="w-3.5 h-3.5" />
                            </button>
                          ) : (
                            <button
                              onClick={() => handleAction(() => onStartEnvironment(env.id), env.id)}
                              disabled={Boolean(isLoading)}
                              title="Start Virtual Machine"
                              className="p-1.5 bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-300 border border-emerald-800/60 rounded-md transition-colors"
                            >
                              <Play className="w-3.5 h-3.5" />
                            </button>
                          )}

                          {/* Open VM Console */}
                          {onOpenConsole && (
                            <button
                              onClick={() => handleAction(() => onOpenConsole(env.id), env.id)}
                              disabled={Boolean(isLoading)}
                              title="Open Hypervisor VM Console"
                              className="p-1.5 bg-surface-800 hover:bg-surface-750 text-blue-300 border border-surface-700 rounded-md transition-colors"
                            >
                              <Terminal className="w-3.5 h-3.5" />
                            </button>
                          )}

                          {/* Launch Guest Browser */}
                          {onLaunchBrowser && (
                            <button
                              onClick={() => handleAction(() => onLaunchBrowser(env.id), env.id)}
                              disabled={Boolean(isLoading)}
                              title="Launch Browser inside Guest VM"
                              className="p-1.5 bg-surface-800 hover:bg-surface-750 text-indigo-300 border border-surface-700 rounded-md transition-colors"
                            >
                              <Compass className="w-3.5 h-3.5" />
                            </button>
                          )}

                          {/* Network Diagnostic Trigger */}
                          <button
                            onClick={() => handleAction(() => onCheckNetwork(env.id), env.id)}
                            disabled={Boolean(isLoading)}
                            title="Verify Guest Network Egress"
                            className="p-1.5 bg-surface-800 hover:bg-surface-750 text-slate-300 border border-surface-700 rounded-md transition-colors"
                          >
                            <ShieldAlert className="w-3.5 h-3.5" />
                          </button>

                          {/* Delete Environment Button */}
                          <button
                            onClick={() => setSelectedEnvForDelete(env)}
                            disabled={Boolean(isLoading) || isRunning}
                            title={isRunning ? 'Stop VM before deleting' : 'Delete Environment'}
                            className={`p-1.5 rounded-md border transition-colors ${
                              isRunning
                                ? 'opacity-40 cursor-not-allowed border-surface-800 text-slate-600'
                                : 'bg-rose-950/40 hover:bg-rose-900/60 text-rose-400 border-rose-800/60'
                            }`}
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create Environment Wizard Modal */}
      <Modal
        isOpen={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
        title="Create Isolated Environment"
        subtitle="Provision dedicated VM storage, isolated guest profile, and network mapping"
        maxWidth="max-w-2xl"
      >
        <form onSubmit={handleCreateSubmit} className="space-y-4 text-xs">
          {formError && (
            <div className="p-3 bg-rose-950/60 border border-rose-800/80 rounded-lg text-rose-300">
              {formError}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-300 font-medium mb-1">Environment Name *</label>
              <input
                type="text"
                required
                placeholder="e.g. ChannelAlpha_Prod"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent font-mono"
              />
              <p className="text-[10px] text-slate-500 mt-1">Alphanumeric, hyphens and underscores only.</p>
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Hypervisor Engine</label>
              <select
                value={newHypervisor}
                onChange={(e) => setNewHypervisor(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent"
              >
                {isMac ? (
                  <>
                    <option value="UTM">UTM (Apple Silicon Native Virtualization)</option>
                    <option value="VirtualBox">VirtualBox (Fallback)</option>
                  </>
                ) : (
                  <>
                    <option value="Hyper-V">Microsoft Hyper-V (Windows 11 Pro)</option>
                    <option value="VirtualBox">Oracle VM VirtualBox</option>
                  </>
                )}
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Guest Operating System</label>
              <select
                value={newGuestOs}
                onChange={(e) => setNewGuestOs(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent"
              >
                {isMac ? (
                  <>
                    <option value="Ubuntu_ARM64">Ubuntu Linux 22.04 ARM64 (Recommended)</option>
                    <option value="Debian_ARM64">Debian 12 ARM64</option>
                    <option value="Fedora_ARM64">Fedora 40 ARM64</option>
                  </>
                ) : (
                  <>
                    <option value="Ubuntu_64">Ubuntu Linux 22.04 x64 (Recommended)</option>
                    <option value="Windows11_64">Windows 11 Guest (x64)</option>
                    <option value="Debian_64">Debian 12 x64</option>
                  </>
                )}
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Guest Browser Type</label>
              <select
                value={newBrowser}
                onChange={(e) => setNewBrowser(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent"
              >
                <option value="chrome">Google Chrome (Isolated Guest Execution)</option>
                <option value="brave">Brave Browser (Privacy Optimized)</option>
                <option value="firefox">Mozilla Firefox</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Allocated vCPU Cores</label>
              <input
                type="number"
                min="1"
                max="16"
                value={newCpu}
                onChange={(e) => setNewCpu(Number(e.target.value))}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Memory Allocation (MB)</label>
              <input
                type="number"
                step="512"
                min="1024"
                max="65536"
                value={newRamMb}
                onChange={(e) => setNewRamMb(Number(e.target.value))}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1 flex items-center justify-between">
                <span>Virtual Disk Size (MB)</span>
                {platformInfo?.available_disk_mb ? (
                  <span className="text-[11px] text-slate-400 font-mono font-normal">
                    (Host Free: {platformInfo.available_disk_mb.toLocaleString()} MB)
                  </span>
                ) : null}
              </label>
              <input
                type="number"
                step="1024"
                min="1024"
                value={newDiskMb}
                onChange={(e) => setNewDiskMb(Number(e.target.value))}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent font-mono"
              />
              <p className="text-[10px] text-slate-500 mt-1">
                Format: {isMac ? '.utm dynamic sparse disk (thin-provisioned)' : '.vhdx dynamic virtual hard disk (thin-provisioned)'}
              </p>
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Installer ISO Image (Optional)</label>
              <input
                type="text"
                placeholder={isMac ? "/Users/.../ubuntu-22.04-arm64.iso" : "C:\\ISO\\ubuntu-22.04-x64.iso"}
                value={newIsoPath}
                onChange={(e) => setNewIsoPath(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Network Proxy Endpoint (Optional)</label>
              <select
                value={newEndpointId}
                onChange={(e) => setNewEndpointId(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent"
              >
                <option value="">Direct / Default NAT (No Proxy)</option>
                {endpoints.map((ep) => (
                  <option key={ep.id} value={ep.id}>
                    {ep.name} ({ep.endpoint_type})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Assign YouTube Channel (Optional)</label>
              <select
                value={newChannelId}
                onChange={(e) => setNewChannelId(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent"
              >
                <option value="">None (Can assign later)</option>
                {channels
                  .filter((c) => !c.environment_id)
                  .map((ch) => (
                    <option key={ch.id} value={ch.id}>
                      {ch.display_name} ({ch.youtube_channel_id})
                    </option>
                  ))}
              </select>
            </div>
          </div>

          <div className="pt-4 border-t border-surface-800 flex items-center justify-end gap-3">
            <button
              type="button"
              onClick={() => setIsCreateOpen(false)}
              className="px-4 py-2 bg-surface-800 hover:bg-surface-750 text-slate-300 rounded-lg font-medium transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isActionLoading === 'create'}
              className="px-4 py-2 bg-brand-accent hover:bg-blue-600 text-white rounded-lg font-medium transition-colors flex items-center gap-2"
            >
              {isActionLoading === 'create' && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
              <span>Provision Isolated VM</span>
            </button>
          </div>
        </form>
      </Modal>

      {/* Delete Confirmation Modal */}
      {selectedEnvForDelete && (
        <ConfirmDialog
          isOpen={true}
          title={`Delete Environment '${selectedEnvForDelete.name}'?`}
          message="This action will unregister the virtual machine, release network bindings, and remove the environment record. Dedicated virtual disk files will also be permanently deleted."
          confirmLabel="Delete Permanently"
          isDestructive={true}
          onConfirm={async () => {
            const envId = selectedEnvForDelete.id;
            setSelectedEnvForDelete(null);
            await handleAction(() => onDeleteEnvironment(envId, true), envId);
          }}
          onClose={() => setSelectedEnvForDelete(null)}
        />
      )}
    </div>
  );
};
