import React, { useState } from 'react';
import { 
  Plus, 
  Search, 
  Play, 
  Square, 
  Trash2, 
  ShieldAlert, 
  Layers, 
  Cpu, 
  HardDrive,
  RefreshCw,
  Activity
} from 'lucide-react';
import { 
  EnvironmentRecord, 
  CreateEnvironmentRequest, 
  NetworkEndpointRecord, 
  ChannelRecord,
  HypervisorInfo 
} from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { Modal } from '../components/Modal';
import { ConfirmDialog } from '../components/ConfirmDialog';

interface EnvironmentsViewProps {
  environments: EnvironmentRecord[];
  endpoints: NetworkEndpointRecord[];
  channels: ChannelRecord[];
  hypervisorInfo: HypervisorInfo | null;
  onRefresh: () => void;
  onCreateEnvironment: (req: CreateEnvironmentRequest) => Promise<void>;
  onStartEnvironment: (id: string) => Promise<void>;
  onShutdownEnvironment: (id: string, force: boolean) => Promise<void>;
  onDeleteEnvironment: (id: string, deleteDisks: boolean) => Promise<void>;
  onCheckNetwork: (id: string) => Promise<void>;
  onLaunchBrowser: (id: string) => Promise<void>;
}

export const EnvironmentsView: React.FC<EnvironmentsViewProps> = ({
  environments,
  endpoints,
  channels,
  hypervisorInfo,
  onRefresh,
  onCreateEnvironment,
  onStartEnvironment,
  onShutdownEnvironment,
  onDeleteEnvironment,
  onCheckNetwork,
  onLaunchBrowser,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [selectedEnvForDelete, setSelectedEnvForDelete] = useState<EnvironmentRecord | null>(null);
  const [isActionLoading, setIsActionLoading] = useState<string | null>(null);

  // New Environment Form State
  const [newName, setNewName] = useState('');
  const [newGuestOs, setNewGuestOs] = useState('Ubuntu_64');
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
        hypervisor_type: hypervisorInfo?.name.includes('VirtualBox') ? 'VirtualBox' : 'Mock',
        guest_os: newGuestOs,
        cpu_count: Number(newCpu),
        memory_mb: Number(newRamMb),
        disk_size_mb: Number(newDiskMb),
        iso_path: newIsoPath.trim() ? newIsoPath.trim() : null,
        browser_type: newBrowser,
        network_endpoint_id: newEndpointId || null,
        channel_id: newChannelId || null,
      });
      setIsCreateOpen(false);
      // Reset form
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
                <th className="py-3.5 px-4">Environment</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4">Guest OS / Specs</th>
                <th className="py-3.5 px-4">Network & Egress</th>
                <th className="py-3.5 px-4">Assigned Channel</th>
                <th className="py-3.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-800/80">
              {filteredEnvironments.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500">
                    <Layers className="w-8 h-8 mx-auto mb-2 text-slate-600" />
                    No virtual environments found. Click "Create Environment" to provision one.
                  </td>
                </tr>
              ) : (
                filteredEnvironments.map((env) => {
                  const isRunning = env.status === 'RUNNING';
                  const isLoading = isActionLoading === env.id;

                  return (
                    <tr key={env.id} className="hover:bg-surface-850/40 transition-colors">
                      {/* Name & ID */}
                      <td className="py-3.5 px-4">
                        <div className="font-semibold text-slate-200">{env.name}</div>
                        <div className="text-[11px] font-mono text-slate-500 truncate max-w-[180px]">
                          {env.vm_identifier}
                        </div>
                      </td>

                      {/* Status */}
                      <td className="py-3.5 px-4">
                        <StatusBadge status={env.status} type="vm" />
                      </td>

                      {/* Specs */}
                      <td className="py-3.5 px-4 text-slate-300">
                        <div className="font-medium text-slate-200">{env.guest_os}</div>
                        <div className="text-[11px] text-slate-500 font-mono">
                          {env.cpu_count} vCPU • {(env.memory_mb / 1024).toFixed(0)} GB RAM
                        </div>
                      </td>

                      {/* Network & Egress */}
                      <td className="py-3.5 px-4">
                        {env.network_endpoint_name ? (
                          <div className="text-slate-200 font-medium truncate max-w-[150px]">
                            {env.network_endpoint_name}
                          </div>
                        ) : (
                          <span className="text-slate-500 italic">Direct / Host NAT</span>
                        )}
                        <div className="text-[11px] font-mono flex items-center gap-1.5 mt-0.5">
                          {env.last_observed_ipv4 ? (
                            <span className="text-emerald-400 font-medium">{env.last_observed_ipv4}</span>
                          ) : (
                            <span className="text-slate-500">Not verified</span>
                          )}
                        </div>
                      </td>

                      {/* Channel */}
                      <td className="py-3.5 px-4">
                        {env.channel_name ? (
                          <span className="text-slate-200 font-medium truncate block max-w-[160px]">
                            {env.channel_name}
                          </span>
                        ) : (
                          <span className="text-slate-500 italic">Unassigned</span>
                        )}
                      </td>

                      {/* Action Controls */}
                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          {/* VM Lifecycle Buttons */}
                          {isRunning ? (
                            <>
                              <button
                                onClick={() => handleAction(() => onShutdownEnvironment(env.id, false), env.id)}
                                disabled={Boolean(isLoading)}
                                title="Graceful ACPI Shutdown"
                                className="p-1.5 bg-amber-950/40 hover:bg-amber-900/60 text-amber-300 border border-amber-800/60 rounded-md transition-colors"
                              >
                                <Square className="w-3.5 h-3.5" />
                              </button>
                            </>
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

                          {/* Launch Isolated Browser */}
                          <button
                            onClick={() => handleAction(() => onLaunchBrowser(env.id), `launch-${env.id}`)}
                            disabled={Boolean(isLoading)}
                            title="🚀 Mở Trình duyệt Kênh (YouTube Studio)"
                            className="px-2 py-1 bg-rose-950/50 hover:bg-rose-900/70 text-rose-300 border border-rose-800/80 rounded-md transition-colors flex items-center gap-1 font-medium text-[11px]"
                          >
                            <span>🚀 Studio</span>
                          </button>

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
        subtitle="Provision dedicated VM storage, isolated browser profile, and network mapping"
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
              <label className="block text-slate-300 font-medium mb-1">Guest Operating System</label>
              <select
                value={newGuestOs}
                onChange={(e) => setNewGuestOs(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent"
              >
                <option value="Ubuntu_64">Ubuntu Linux (64-bit) [Recommended]</option>
                <option value="Debian_64">Debian GNU/Linux (64-bit)</option>
                <option value="Windows11_64">Windows 11 (64-bit, license required)</option>
                <option value="Windows10_64">Windows 10 (64-bit, license required)</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-3 pt-2 border-t border-surface-800">
            <div>
              <label className="block text-slate-300 font-medium mb-1 flex items-center gap-1">
                <Cpu className="w-3 h-3 text-slate-400" /> CPU Allocation
              </label>
              <input
                type="number"
                min={1}
                max={16}
                value={newCpu}
                onChange={(e) => setNewCpu(Number(e.target.value))}
                className="w-full px-3 py-1.5 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 font-mono"
              />
            </div>
            <div>
              <label className="block text-slate-300 font-medium mb-1 flex items-center gap-1">
                <Activity className="w-3 h-3 text-slate-400" /> Memory (MB)
              </label>
              <input
                type="number"
                min={1024}
                step={512}
                value={newRamMb}
                onChange={(e) => setNewRamMb(Number(e.target.value))}
                className="w-full px-3 py-1.5 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 font-mono"
              />
            </div>
            <div>
              <label className="block text-slate-300 font-medium mb-1 flex items-center gap-1">
                <HardDrive className="w-3 h-3 text-slate-400" /> Disk Size (MB)
              </label>
              <input
                type="number"
                min={5120}
                step={1024}
                value={newDiskMb}
                onChange={(e) => setNewDiskMb(Number(e.target.value))}
                className="w-full px-3 py-1.5 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-300 font-medium mb-1">Guest Installer ISO Path (Optional)</label>
            <input
              type="text"
              placeholder="C:\ISOs\ubuntu-24.04-desktop-amd64.iso"
              value={newIsoPath}
              onChange={(e) => setNewIsoPath(e.target.value)}
              className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 font-mono focus:outline-none focus:border-brand-accent"
            />
            <p className="text-[10px] text-slate-500 mt-1">If empty, VM will boot to EFI shell ready for manual image attachment.</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2 border-t border-surface-800">
            <div>
              <label className="block text-slate-300 font-medium mb-1">Browser Engine</label>
              <select
                value={newBrowser}
                onChange={(e) => setNewBrowser(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent"
              >
                <option value="chrome">Google Chrome (Dedicated Profile)</option>
                <option value="brave">Brave Browser (Dedicated Profile)</option>
                <option value="firefox">Mozilla Firefox (Dedicated Profile)</option>
                <option value="edge">Microsoft Edge (Dedicated Profile)</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Assign Network Endpoint</label>
              <select
                value={newEndpointId}
                onChange={(e) => setNewEndpointId(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent"
              >
                <option value="">Direct / None (Host Default)</option>
                {endpoints.map((ep) => (
                  <option key={ep.id} value={ep.id}>
                    {ep.name} ({ep.endpoint_type} - {ep.host || 'Dynamic'})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Assign YouTube Channel</label>
              <select
                value={newChannelId}
                onChange={(e) => setNewChannelId(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent"
              >
                <option value="">Unassigned</option>
                {channels.map((ch) => (
                  <option key={ch.id} value={ch.id}>
                    {ch.display_name} ({ch.authorization_status})
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex items-center justify-end gap-3 pt-4 border-t border-surface-800">
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
              className="px-4 py-2 bg-brand-accent hover:bg-blue-600 text-white rounded-lg font-semibold shadow-sm transition-colors flex items-center gap-1.5"
            >
              {isActionLoading === 'create' && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
              <span>Create Environment</span>
            </button>
          </div>
        </form>
      </Modal>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        isOpen={Boolean(selectedEnvForDelete)}
        onClose={() => setSelectedEnvForDelete(null)}
        onConfirm={async () => {
          if (selectedEnvForDelete) {
            await handleAction(
              () => onDeleteEnvironment(selectedEnvForDelete.id, true),
              selectedEnvForDelete.id
            );
          }
        }}
        title={`Delete Environment '${selectedEnvForDelete?.name}'?`}
        message={`This will permanently remove the virtual machine from the hypervisor and delete its dedicated virtual disk (.vdi) and isolated browser profile. This action cannot be undone.`}
        confirmLabel="Permanently Delete"
        isDestructive={true}
      />
    </div>
  );
};
