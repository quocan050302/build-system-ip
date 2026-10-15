import React, { useState } from 'react';
import { 
  Plus, 
  Tv2, 
  ShieldCheck, 
  Trash2, 
  CheckCircle2, 
  XCircle, 
  Lock,
  RefreshCw
} from 'lucide-react';
import { 
  ChannelRecord, 
  CreateChannelRequest, 
  EnvironmentRecord 
} from '../types';
import { Modal } from '../components/Modal';
import { ConfirmDialog } from '../components/ConfirmDialog';

interface ChannelsViewProps {
  channels: ChannelRecord[];
  environments: EnvironmentRecord[];
  onRefresh: () => void;
  onCreateChannel: (req: CreateChannelRequest) => Promise<void>;
  onUpdateStatus: (id: string, status: string) => Promise<void>;
  onAssignEnvironment: (channelId: string, environmentId?: string | null) => Promise<void>;
  onDeleteChannel: (id: string) => Promise<void>;
}

export const ChannelsView: React.FC<ChannelsViewProps> = ({
  channels,
  environments,
  onRefresh,
  onCreateChannel,
  onUpdateStatus,
  onAssignEnvironment,
  onDeleteChannel,
}) => {
  const [isAddOpen, setIsAddOpen] = useState(false);
  const [selectedChannelForDelete, setSelectedChannelForDelete] = useState<ChannelRecord | null>(null);

  // Form State
  const [channelId, setChannelId] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [environmentId, setEnvironmentId] = useState('');
  const [authStatus, setAuthStatus] = useState('AUTHORIZED');
  const [formError, setFormError] = useState<string | null>(null);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!channelId.trim()) {
      setFormError('YouTube Channel ID is required (e.g. UC...)');
      return;
    }
    if (!displayName.trim()) {
      setFormError('Channel Display Name is required');
      return;
    }

    try {
      await onCreateChannel({
        youtube_channel_id: channelId.trim(),
        display_name: displayName.trim(),
        environment_id: environmentId || null,
        authorization_status: authStatus,
      });
      setIsAddOpen(false);
      setChannelId('');
      setDisplayName('');
      setEnvironmentId('');
    } catch (err: any) {
      setFormError(err?.message || String(err));
    }
  };

  return (
    <div className="space-y-6">
      {/* Platform Integrity & Compliance Notice */}
      <div className="bg-surface-900 border border-surface-800 rounded-xl p-4 flex items-start gap-4">
        <div className="p-2.5 bg-blue-950/60 rounded-lg text-blue-400 border border-blue-800/40">
          <ShieldCheck className="w-5 h-5" />
        </div>
        <div className="flex-1">
          <h4 className="text-sm font-semibold text-slate-100">Authorized Channels & Platform Compliance</h4>
          <p className="text-xs text-slate-400 mt-1 leading-relaxed">
            YouTube Isolation Manager operates strictly within platform terms of service. Terminated accounts are permanently locked into read-only mode to prevent non-compliant automated publishing actions.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onRefresh}
            className="p-2 text-slate-400 hover:text-slate-200 hover:bg-surface-800 rounded-lg transition-colors border border-surface-750 text-xs"
            title="Refresh Channels"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setIsAddOpen(true)}
            className="flex items-center gap-2 px-3.5 py-1.5 bg-brand-accent hover:bg-blue-600 text-white rounded-lg text-xs font-semibold shadow-sm transition-colors whitespace-nowrap"
          >
            <Plus className="w-4 h-4" />
            <span>Register Channel</span>
          </button>
        </div>
      </div>

      {/* Channels Grid / Table */}
      <div className="bg-surface-900 border border-surface-800 rounded-xl overflow-hidden shadow-sm">
        <div className="px-5 py-4 border-b border-surface-800 bg-surface-850/40 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">Registered YouTube Channels</h3>
            <p className="text-xs text-slate-400">1-to-1 environment mapping and compliance controls</p>
          </div>
          <span className="text-xs font-mono text-slate-500">{channels.length} channels registered</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-surface-850/60 border-b border-surface-800 text-slate-400 uppercase font-semibold tracking-wider">
              <tr>
                <th className="py-3 px-4">Channel Details</th>
                <th className="py-3 px-4">Authorization State</th>
                <th className="py-3 px-4">Publishing Eligibility</th>
                <th className="py-3 px-4">Mapped Environment</th>
                <th className="py-3 px-4">Compliance Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-800/80">
              {channels.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500">
                    <Tv2 className="w-8 h-8 mx-auto mb-2 text-slate-600" />
                    No channels registered. Click "Register Channel" to add an authorized YouTube channel record.
                  </td>
                </tr>
              ) : (
                channels.map((ch) => {
                  const isTerminated = ch.authorization_status === 'TERMINATED';

                  return (
                    <tr key={ch.id} className="hover:bg-surface-850/40 transition-colors">
                      {/* Name & ID */}
                      <td className="py-3.5 px-4">
                        <div className="font-semibold text-slate-200">{ch.display_name}</div>
                        <div className="text-[11px] font-mono text-slate-500 truncate max-w-[200px]">
                          {ch.youtube_channel_id}
                        </div>
                      </td>

                      {/* Status Dropdown */}
                      <td className="py-3.5 px-4">
                        <select
                          value={ch.authorization_status}
                          onChange={(e) => onUpdateStatus(ch.id, e.target.value)}
                          className="bg-surface-850 border border-surface-750 text-slate-200 text-xs rounded-lg px-2.5 py-1 focus:outline-none focus:border-brand-accent font-medium"
                        >
                          <option value="AUTHORIZED">AUTHORIZED</option>
                          <option value="UNVERIFIED">UNVERIFIED</option>
                          <option value="RESTRICTED">RESTRICTED</option>
                          <option value="TERMINATED">TERMINATED (Read-Only)</option>
                          <option value="ARCHIVED">ARCHIVED</option>
                        </select>
                      </td>

                      {/* Publishing Eligibility */}
                      <td className="py-3.5 px-4">
                        {ch.is_eligible_for_publishing ? (
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium bg-emerald-950/60 text-emerald-400 border border-emerald-800/60">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            Eligible for Publishing
                          </span>
                        ) : (
                          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium border ${
                            isTerminated 
                              ? 'bg-rose-950/70 text-rose-300 border-rose-800/80 font-bold' 
                              : 'bg-surface-800 text-slate-400 border-surface-700'
                          }`}>
                            {isTerminated ? <Lock className="w-3 h-3 text-rose-400" /> : <XCircle className="w-3.5 h-3.5" />}
                            {isTerminated ? 'LOCKED / READ-ONLY' : 'Publishing Blocked'}
                          </span>
                        )}
                      </td>

                      {/* Mapped Environment */}
                      <td className="py-3.5 px-4">
                        <select
                          value={ch.environment_id || ''}
                          onChange={(e) => onAssignEnvironment(ch.id, e.target.value || null)}
                          className="bg-surface-850 border border-surface-750 text-slate-300 text-xs rounded px-2.5 py-1 focus:outline-none focus:border-brand-accent max-w-[180px]"
                        >
                          <option value="">Unassigned</option>
                          {environments.map((env) => (
                            <option key={env.id} value={env.id}>
                              {env.name}
                            </option>
                          ))}
                        </select>
                      </td>

                      {/* Content Review Status */}
                      <td className="py-3.5 px-4">
                        <span className="text-[11px] font-mono text-slate-400 bg-surface-850 px-2 py-0.5 rounded border border-surface-750">
                          {ch.content_review_status}
                        </span>
                      </td>

                      {/* Actions */}
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={() => setSelectedChannelForDelete(ch)}
                          className="p-1.5 bg-rose-950/40 hover:bg-rose-900/60 text-rose-400 border border-rose-800/60 rounded-md transition-colors"
                          title="Delete Channel Record"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Register Channel Modal */}
      <Modal
        isOpen={isAddOpen}
        onClose={() => setIsAddOpen(false)}
        title="Register YouTube Channel"
        subtitle="Record an authorized channel record and map to a dedicated environment"
      >
        <form onSubmit={handleCreate} className="space-y-4 text-xs">
          {formError && (
            <div className="p-3 bg-rose-950/60 border border-rose-800/80 rounded-lg text-rose-300">
              {formError}
            </div>
          )}

          <div>
            <label className="block text-slate-300 font-medium mb-1">Channel Display Name *</label>
            <input
              type="text"
              required
              placeholder="e.g. Daily Tech Insights"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 font-medium focus:outline-none focus:border-brand-accent"
            />
          </div>

          <div>
            <label className="block text-slate-300 font-medium mb-1">YouTube Channel ID *</label>
            <input
              type="text"
              required
              placeholder="e.g. UC_x5XG1OV2P6uZZ5FSM9Ttw"
              value={channelId}
              onChange={(e) => setChannelId(e.target.value)}
              className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 font-mono focus:outline-none focus:border-brand-accent"
            />
            <p className="text-[10px] text-slate-500 mt-1">Official unique 24-character YouTube identifier starting with UC.</p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-300 font-medium mb-1">Initial Authorization State</label>
              <select
                value={authStatus}
                onChange={(e) => setAuthStatus(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent"
              >
                <option value="AUTHORIZED">AUTHORIZED (Full Access)</option>
                <option value="UNVERIFIED">UNVERIFIED (Pending Review)</option>
                <option value="RESTRICTED">RESTRICTED</option>
                <option value="TERMINATED">TERMINATED (Read-Only)</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Assign to Dedicated VM</label>
              <select
                value={environmentId}
                onChange={(e) => setEnvironmentId(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent"
              >
                <option value="">None (Assign later)</option>
                {environments.map((env) => (
                  <option key={env.id} value={env.id}>
                    {env.name}
                  </option>
                ))}
              </select>
            </div>
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
              className="px-4 py-2 bg-brand-accent hover:bg-blue-600 text-white rounded-lg font-semibold shadow-sm transition-colors"
            >
              Register Channel
            </button>
          </div>
        </form>
      </Modal>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        isOpen={Boolean(selectedChannelForDelete)}
        onClose={() => setSelectedChannelForDelete(null)}
        onConfirm={async () => {
          if (selectedChannelForDelete) {
            await onDeleteChannel(selectedChannelForDelete.id);
          }
        }}
        title={`Delete Channel Record '${selectedChannelForDelete?.display_name}'?`}
        message={`This will delete the local channel tracking record. The associated VM environment and browser profiles will remain untouched.`}
        confirmLabel="Delete Record"
        isDestructive={true}
      />
    </div>
  );
};
