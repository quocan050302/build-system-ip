import React, { useState } from 'react';
import { 
  Plus, 
  Globe, 
  AlertTriangle, 
  Trash2, 
  Activity, 
  Lock, 
  RefreshCw,
  Layers
} from 'lucide-react';
import { 
  NetworkEndpointRecord, 
  CreateEndpointRequest, 
  DuplicateEgressWarning, 
  EnvironmentRecord 
} from '../types';
import { Modal } from '../components/Modal';
import { ConfirmDialog } from '../components/ConfirmDialog';

interface NetworkViewProps {
  endpoints: NetworkEndpointRecord[];
  environments: EnvironmentRecord[];
  duplicateWarnings: DuplicateEgressWarning[];
  onRefresh: () => void;
  onCreateEndpoint: (req: CreateEndpointRequest) => Promise<void>;
  onDeleteEndpoint: (id: string) => Promise<void>;
  onAssignEndpoint: (environmentId: string, endpointId?: string | null) => Promise<void>;
  onCheckNetwork: (environmentId: string) => Promise<void>;
}

export const NetworkView: React.FC<NetworkViewProps> = ({
  endpoints,
  environments,
  duplicateWarnings,
  onRefresh,
  onCreateEndpoint,
  onDeleteEndpoint,
  onAssignEndpoint,
  onCheckNetwork,
}) => {
  const [isAddOpen, setIsAddOpen] = useState(false);
  const [selectedEndpointForDelete, setSelectedEndpointForDelete] = useState<NetworkEndpointRecord | null>(null);
  const [loadingKey, setLoadingKey] = useState<string | null>(null);

  // Form State
  const [name, setName] = useState('');
  const [endpointType, setEndpointType] = useState('SOCKS5');
  const [providerLabel, setProviderLabel] = useState('');
  const [host, setHost] = useState('');
  const [port, setPort] = useState(1080);
  const [secret, setSecret] = useState('');
  const [formError, setFormError] = useState<string | null>(null);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!name.trim()) {
      setFormError('Endpoint name is required');
      return;
    }

    try {
      setLoadingKey('create');
      await onCreateEndpoint({
        name: name.trim(),
        endpoint_type: endpointType,
        provider_label: providerLabel.trim() || null,
        host: host.trim() || null,
        port: port ? Number(port) : null,
        credentials_secret: secret.trim() || null,
      });
      setIsAddOpen(false);
      setName('');
      setHost('');
      setSecret('');
      setProviderLabel('');
    } catch (err: any) {
      setFormError(err?.message || String(err));
    } finally {
      setLoadingKey(null);
    }
  };

  const handleDiagnosticTrigger = async (envId: string) => {
    try {
      setLoadingKey(envId);
      await onCheckNetwork(envId);
    } catch (err: any) {
      alert(`Network diagnostic error: ${err?.message || err}`);
    } finally {
      setLoadingKey(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Duplicate Egress Alert Banner */}
      {duplicateWarnings.length > 0 && (
        <div className="bg-rose-950/50 border border-rose-800 rounded-xl p-4 flex items-start gap-4 shadow-lg shadow-rose-950/20">
          <div className="p-2.5 bg-rose-900/60 rounded-lg text-rose-300">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div>
            <h4 className="text-sm font-semibold text-rose-200">Duplicate Public IP Conflict Detected</h4>
            <p className="text-xs text-rose-300/90 mt-1 leading-relaxed">
              Multiple environments have reported the exact same observed public IP address. Separate channel environments must not share network egress identities.
            </p>
            <div className="mt-2 space-y-1">
              {duplicateWarnings.map((w, idx) => (
                <div key={idx} className="text-xs font-mono bg-rose-900/40 px-3 py-1.5 rounded text-rose-200 border border-rose-800/60">
                  IP: <span className="font-bold">{w.ip_address}</span> — Environments: [{w.conflicting_environments.join(', ')}]
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Top Header Controls */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 bg-surface-900 border border-surface-800 p-4 rounded-xl">
        <div>
          <h3 className="text-sm font-semibold text-slate-100">Network Endpoints & Egress Verification</h3>
          <p className="text-xs text-slate-400">
            Configure legitimate residential/dedicated proxies or VPN connections. Verified directly from guest VMs.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onRefresh}
            className="p-2 text-slate-400 hover:text-slate-200 hover:bg-surface-800 rounded-lg transition-colors border border-surface-750 text-xs"
            title="Refresh All Network Checks"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setIsAddOpen(true)}
            className="flex items-center gap-2 px-3.5 py-1.5 bg-brand-accent hover:bg-blue-600 text-white rounded-lg text-xs font-semibold shadow-sm transition-colors"
          >
            <Plus className="w-4 h-4" />
            <span>Add Network Endpoint</span>
          </button>
        </div>
      </div>

      {/* Environment Network Assignment & Live Diagnostics Card Grid */}
      <div className="space-y-3">
        <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider px-1">
          Active Environment Network Egress Status
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {environments.length === 0 ? (
            <div className="col-span-full bg-surface-900 border border-surface-800 rounded-xl p-8 text-center text-slate-500 text-xs">
              No environments available to diagnose. Create an environment first.
            </div>
          ) : (
            environments.map((env) => {
              const isRunning = env.status === 'RUNNING';
              const isChecking = loadingKey === env.id;

              return (
                <div key={env.id} className="bg-surface-900 border border-surface-800 rounded-xl p-4 space-y-3 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Layers className="w-4 h-4 text-blue-400" />
                        <span className="font-semibold text-sm text-slate-100">{env.name}</span>
                      </div>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${
                        isRunning ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/80' : 'bg-surface-800 text-slate-400 border-surface-700'
                      }`}>
                        {env.status}
                      </span>
                    </div>

                    <div className="mt-3 p-3 bg-surface-850 rounded-lg border border-surface-750 space-y-1.5 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Assigned Endpoint:</span>
                        <span className="font-medium text-slate-200">
                          {env.network_endpoint_name || 'Direct / Host NAT'}
                        </span>
                      </div>

                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Observed IPv4:</span>
                        <span className="font-mono text-emerald-400 font-semibold">
                          {env.last_observed_ipv4 || 'Not Checked'}
                        </span>
                      </div>

                      <div className="flex items-center justify-between text-[11px] pt-1 border-t border-surface-750/80 text-slate-500">
                        <span>Last Verified:</span>
                        <span className="font-mono">
                          {env.last_checked_at ? new Date(env.last_checked_at).toLocaleTimeString() : 'Never'}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between gap-2 pt-2 border-t border-surface-800">
                    <select
                      value={env.network_endpoint_id || ''}
                      onChange={(e) => onAssignEndpoint(env.id, e.target.value || null)}
                      className="bg-surface-850 border border-surface-750 text-slate-300 text-xs rounded px-2 py-1 flex-1 focus:outline-none focus:border-brand-accent"
                    >
                      <option value="">Direct / None</option>
                      {endpoints.map((ep) => (
                        <option key={ep.id} value={ep.id}>
                          {ep.name} ({ep.endpoint_type})
                        </option>
                      ))}
                    </select>

                    <button
                      onClick={() => handleDiagnosticTrigger(env.id)}
                      disabled={isChecking}
                      title="Run Guest Diagnostic Egress Check"
                      className="px-2.5 py-1 bg-brand-accent/20 hover:bg-brand-accent/30 text-blue-400 border border-brand-accent/40 rounded text-xs font-medium transition-colors flex items-center gap-1"
                    >
                      <Activity className={`w-3.5 h-3.5 ${isChecking ? 'animate-spin' : ''}`} />
                      <span>{isChecking ? 'Testing...' : 'Verify'}</span>
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Configured Endpoints Inventory Table */}
      <div className="bg-surface-900 border border-surface-800 rounded-xl overflow-hidden shadow-sm">
        <div className="px-5 py-4 border-b border-surface-800 bg-surface-850/40 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">Registered Network Endpoints</h3>
            <p className="text-xs text-slate-400">All credentials securely sealed via Windows DPAPI</p>
          </div>
          <span className="text-xs font-mono text-slate-500">{endpoints.length} configured</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-surface-850/60 border-b border-surface-800 text-slate-400 uppercase font-semibold tracking-wider">
              <tr>
                <th className="py-3 px-4">Endpoint Name</th>
                <th className="py-3 px-4">Protocol</th>
                <th className="py-3 px-4">Host / Port</th>
                <th className="py-3 px-4">Provider / Label</th>
                <th className="py-3 px-4">Security Vault</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-800/80">
              {endpoints.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-slate-500">
                    <Globe className="w-8 h-8 mx-auto mb-2 text-slate-600" />
                    No network endpoints configured. Click "Add Network Endpoint" to add proxies or VPN connections.
                  </td>
                </tr>
              ) : (
                endpoints.map((ep) => (
                  <tr key={ep.id} className="hover:bg-surface-850/40 transition-colors">
                    <td className="py-3.5 px-4 font-semibold text-slate-200">
                      {ep.name}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="font-mono px-2 py-0.5 rounded text-[11px] bg-surface-800 text-blue-400 border border-surface-700">
                        {ep.endpoint_type}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-slate-300">
                      {ep.host ? `${ep.host}:${ep.port || 'default'}` : 'Dynamic Egress'}
                    </td>
                    <td className="py-3.5 px-4 text-slate-400">
                      {ep.provider_label || '—'}
                    </td>
                    <td className="py-3.5 px-4">
                      {ep.has_credentials ? (
                        <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-medium">
                          <Lock className="w-3 h-3" /> Sealed in DPAPI
                        </span>
                      ) : (
                        <span className="text-[11px] text-slate-500">No Credentials</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={() => setSelectedEndpointForDelete(ep)}
                        className="p-1.5 bg-rose-950/40 hover:bg-rose-900/60 text-rose-400 border border-rose-800/60 rounded-md transition-colors"
                        title="Delete Endpoint"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Endpoint Modal */}
      <Modal
        isOpen={isAddOpen}
        onClose={() => setIsAddOpen(false)}
        title="Add Network Endpoint"
        subtitle="Register a legitimate proxy or VPN connection for environment network isolation"
      >
        <form onSubmit={handleCreate} className="space-y-4 text-xs">
          {formError && (
            <div className="p-3 bg-rose-950/60 border border-rose-800/80 rounded-lg text-rose-300">
              {formError}
            </div>
          )}

          <div>
            <label className="block text-slate-300 font-medium mb-1">Endpoint Name *</label>
            <input
              type="text"
              required
              placeholder="e.g. US-Residential-Static-01"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent font-medium"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-300 font-medium mb-1">Protocol Type</label>
              <select
                value={endpointType}
                onChange={(e) => setEndpointType(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent"
              >
                <option value="SOCKS5">SOCKS5 Proxy</option>
                <option value="HTTP">HTTP/HTTPS Proxy</option>
                <option value="WIREGUARD">WireGuard VPN</option>
                <option value="DIRECT">Direct Secondary Adapter</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Provider Label (Optional)</label>
              <input
                type="text"
                placeholder="e.g. BrightData, Mullvad"
                value={providerLabel}
                onChange={(e) => setProviderLabel(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent"
              />
            </div>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2">
              <label className="block text-slate-300 font-medium mb-1">Host / Gateway Address</label>
              <input
                type="text"
                placeholder="198.51.100.25 or proxy.example.com"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 font-mono focus:outline-none focus:border-brand-accent"
              />
            </div>
            <div>
              <label className="block text-slate-300 font-medium mb-1">Port</label>
              <input
                type="number"
                value={port}
                onChange={(e) => setPort(Number(e.target.value))}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-300 font-medium mb-1 flex items-center justify-between">
              <span>Authentication Credentials / Secret (Optional)</span>
              <span className="text-[10px] text-blue-400 font-mono flex items-center gap-1">
                <Lock className="w-3 h-3" /> Sealed with Windows DPAPI
              </span>
            </label>
            <input
              type="password"
              placeholder="user:password or auth token"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 font-mono focus:outline-none focus:border-brand-accent"
            />
            <p className="text-[10px] text-slate-500 mt-1">
              Encrypted locally using your Windows user account master key. Never stored in plaintext.
            </p>
          </div>

          <div className="flex items-center justify-end gap-3 pt-4 border-t border-surface-800">
            <button
              type="button"
              onClick={() => setIsAddOpen(false)}
              className="px-4 py-2 bg-surface-800 hover:bg-surface-750 text-slate-300 rounded-lg font-medium transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loadingKey === 'create'}
              className="px-4 py-2 bg-brand-accent hover:bg-blue-600 text-white rounded-lg font-semibold shadow-sm transition-colors flex items-center gap-1.5"
            >
              {loadingKey === 'create' && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
              <span>Save & Seal Endpoint</span>
            </button>
          </div>
        </form>
      </Modal>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        isOpen={Boolean(selectedEndpointForDelete)}
        onClose={() => setSelectedEndpointForDelete(null)}
        onConfirm={async () => {
          if (selectedEndpointForDelete) {
            await onDeleteEndpoint(selectedEndpointForDelete.id);
          }
        }}
        title={`Delete Endpoint '${selectedEndpointForDelete?.name}'?`}
        message={`This will permanently remove this network configuration and wipe its sealed credentials from the local database.`}
        confirmLabel="Delete Endpoint"
        isDestructive={true}
      />
    </div>
  );
};
