import React, { useState } from 'react';
import { 
  Plus, 
  Tv2, 
  ShieldCheck, 
  Trash2, 
  CheckCircle2, 
  XCircle, 
  Lock,
  RefreshCw,
  Pencil,
  Check,
  X as XIcon,
  AlertTriangle,
  ExternalLink,
  Link2
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
  onUpdateChannelId?: (channelId: string, youtubeChannelId: string) => Promise<void>;
  onUpdateChannelGumroad?: (id: string, gumroadUrl?: string, utmSource?: string, utmMedium?: string, utmCampaign?: string) => Promise<void>;
  onOpenChannelInBrowser?: (channelId: string, openAnalytics?: boolean) => Promise<void>;
}

const PLATFORM_ICONS: Record<string, string> = {
  youtube: '▶️',
  tiktok: '🎵',
  instagram: '📸',
  facebook: '📘',
  gumroad: '🛒',
};

const PLATFORM_COLORS: Record<string, string> = {
  youtube: 'bg-red-950/60 text-red-300 border-red-800/60',
  tiktok: 'bg-slate-800 text-pink-300 border-pink-800/60',
  instagram: 'bg-purple-950/60 text-purple-300 border-purple-800/60',
  facebook: 'bg-blue-950/60 text-blue-300 border-blue-800/60',
  gumroad: 'bg-pink-950/60 text-pink-300 border-pink-800/60',
};

export const ChannelsView: React.FC<ChannelsViewProps> = ({
  channels,
  environments,
  onRefresh,
  onCreateChannel,
  onUpdateStatus,
  onAssignEnvironment,
  onDeleteChannel,
  onUpdateChannelId,
  onUpdateChannelGumroad: _onUpdateChannelGumroad,
  onOpenChannelInBrowser,
}) => {
  const [isAddOpen, setIsAddOpen] = useState(false);
  const [selectedChannelForDelete, setSelectedChannelForDelete] = useState<ChannelRecord | null>(null);
  const [editingChannelId, setEditingChannelId] = useState<string | null>(null);
  const [editChannelIdValue, setEditChannelIdValue] = useState('');
  const [editChannelIdError, setEditChannelIdError] = useState<string | null>(null);
  const [editChannelIdLoading, setEditChannelIdLoading] = useState(false);
  const [openingChannelId, setOpeningChannelId] = useState<string | null>(null);

  // Form State
  const [channelId, setChannelId] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [platform, setPlatform] = useState('youtube');
  const [workspaceName, setWorkspaceName] = useState('');
  const [accountHandle, setAccountHandle] = useState('');
  const [gumroadUrl, setGumroadUrl] = useState('');
  const [utmSource, setUtmSource] = useState('');
  const [utmMedium, setUtmMedium] = useState('');
  const [utmCampaign, setUtmCampaign] = useState('');
  const [environmentId, setEnvironmentId] = useState('');
  const [authStatus, setAuthStatus] = useState('AUTHORIZED');
  const [formError, setFormError] = useState<string | null>(null);

  const startEditChannelId = (ch: ChannelRecord) => {
    setEditingChannelId(ch.id);
    setEditChannelIdValue(ch.youtube_channel_id.startsWith('UC_') ? '' : ch.youtube_channel_id);
    setEditChannelIdError(null);
  };

  const cancelEditChannelId = () => {
    setEditingChannelId(null);
    setEditChannelIdValue('');
    setEditChannelIdError(null);
  };

  const confirmEditChannelId = async (channelRecordId: string) => {
    const trimmed = editChannelIdValue.trim();
    if (!trimmed) {
      setEditChannelIdError('Channel ID cannot be empty');
      return;
    }
    if (!trimmed.startsWith('UC')) {
      setEditChannelIdError('YouTube Channel ID must start with "UC"');
      return;
    }
    if (trimmed.length < 10) {
      setEditChannelIdError('Channel ID seems too short — check the ID from youtube.com/channel/UC...');
      return;
    }
    if (!onUpdateChannelId) return;
    setEditChannelIdLoading(true);
    try {
      await onUpdateChannelId(channelRecordId, trimmed);
      cancelEditChannelId();
      onRefresh();
    } catch (err: any) {
      setEditChannelIdError(err?.message || String(err));
    } finally {
      setEditChannelIdLoading(false);
    }
  };

  const handleOpenInBrowser = async (ch: ChannelRecord, analytics = false) => {
    if (!onOpenChannelInBrowser) return;
    setOpeningChannelId(ch.id + (analytics ? '-analytics' : ''));
    try {
      await onOpenChannelInBrowser(ch.id, analytics);
    } catch (err: any) {
      alert(`Cannot open in browser: ${err?.message || err}`);
    } finally {
      setOpeningChannelId(null);
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!displayName.trim()) {
      setFormError('Display Name is required');
      return;
    }

    // For YouTube we require a channel ID; other platforms generate a placeholder
    const finalChannelId = platform === 'youtube' && channelId.trim()
      ? channelId.trim()
      : `${platform.toUpperCase()}_${Date.now().toString(36).toUpperCase()}`;

    try {
      await onCreateChannel({
        youtube_channel_id: finalChannelId,
        display_name: displayName.trim(),
        environment_id: environmentId || null,
        authorization_status: authStatus,
        platform: platform || null,
        workspace_name: workspaceName.trim() || null,
        account_handle: accountHandle.trim() || null,
        gumroad_url: gumroadUrl.trim() || null,
        utm_source: utmSource.trim() || null,
        utm_medium: utmMedium.trim() || null,
        utm_campaign: utmCampaign.trim() || null,
      });
      setIsAddOpen(false);
      setChannelId('');
      setDisplayName('');
      setPlatform('youtube');
      setWorkspaceName('');
      setAccountHandle('');
      setGumroadUrl('');
      setUtmSource('');
      setUtmMedium('');
      setUtmCampaign('');
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
          <h4 className="text-sm font-semibold text-slate-100">Social Media Channel Registry — Alexa Creator Studio</h4>
          <p className="text-xs text-slate-400 mt-1 leading-relaxed">
            Manage TikTok, Instagram, Facebook, YouTube, and Gumroad accounts. Terminated accounts are permanently locked into read-only mode. No automated engagement or ban-evasion functionality.
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
            <span>Register Account</span>
          </button>
        </div>
      </div>

      {/* Channels Table */}
      <div className="bg-surface-900 border border-surface-800 rounded-xl overflow-hidden shadow-sm">
        <div className="px-5 py-4 border-b border-surface-800 bg-surface-850/40 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">Registered Social Media Accounts</h3>
            <p className="text-xs text-slate-400">1-to-1 environment mapping, compliance controls, and Gumroad destination tracking</p>
          </div>
          <span className="text-xs font-mono text-slate-500">{channels.length} accounts registered</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-surface-850/60 border-b border-surface-800 text-slate-400 uppercase font-semibold tracking-wider">
              <tr>
                <th className="py-3 px-4">Account Details</th>
                <th className="py-3 px-4">Platform</th>
                <th className="py-3 px-4">Authorization</th>
                <th className="py-3 px-4">Publishing</th>
                <th className="py-3 px-4">Mapped Environment</th>
                <th className="py-3 px-4">Gumroad Destination</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-800/80">
              {channels.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500">
                    <Tv2 className="w-8 h-8 mx-auto mb-2 text-slate-600" />
                    No accounts registered. Click "Register Account" to add TikTok, Instagram, Facebook, or YouTube accounts.
                  </td>
                </tr>
              ) : (
                channels.map((ch) => {
                  const isTerminated = ch.authorization_status === 'TERMINATED';
                  const platformKey = (ch.platform || 'youtube').toLowerCase();
                  const platformIcon = PLATFORM_ICONS[platformKey] || '📺';
                  const platformColor = PLATFORM_COLORS[platformKey] || PLATFORM_COLORS['youtube'];

                  return (
                    <tr key={ch.id} className="hover:bg-surface-850/40 transition-colors">
                      {/* Account Name & ID */}
                      <td className="py-3.5 px-4">
                        <div className="font-semibold text-slate-200">{ch.display_name}</div>
                        {ch.account_handle && (
                          <div className="text-[11px] text-slate-400 mt-0.5">@{ch.account_handle}</div>
                        )}
                        {ch.workspace_name && (
                          <div className="text-[10px] text-slate-500 mt-0.5">📁 {ch.workspace_name}</div>
                        )}
                        {editingChannelId === ch.id ? (
                          <div className="mt-1.5 space-y-1">
                            <div className="flex items-center gap-1">
                              <input
                                autoFocus
                                type="text"
                                value={editChannelIdValue}
                                onChange={e => { setEditChannelIdValue(e.target.value); setEditChannelIdError(null); }}
                                onKeyDown={e => { if (e.key === 'Enter') confirmEditChannelId(ch.id); if (e.key === 'Escape') cancelEditChannelId(); }}
                                placeholder="UCxxxxxxxxxxxxxxxxxx"
                                className="flex-1 w-40 px-2 py-0.5 bg-surface-800 border border-amber-500/60 rounded text-[11px] font-mono text-slate-100 focus:outline-none focus:border-amber-400"
                              />
                              <button
                                onClick={() => confirmEditChannelId(ch.id)}
                                disabled={editChannelIdLoading}
                                title="Save Channel ID"
                                className="p-1 bg-emerald-950/60 hover:bg-emerald-900 border border-emerald-700 rounded text-emerald-400 disabled:opacity-50"
                              >
                                <Check className="w-3 h-3" />
                              </button>
                              <button
                                onClick={cancelEditChannelId}
                                title="Cancel"
                                className="p-1 bg-surface-800 hover:bg-surface-700 border border-surface-700 rounded text-slate-400"
                              >
                                <XIcon className="w-3 h-3" />
                              </button>
                            </div>
                            {editChannelIdError && (
                              <div className="text-[10px] text-rose-400">{editChannelIdError}</div>
                            )}
                          </div>
                        ) : (
                          <div className="flex items-center gap-1 mt-0.5">
                            {ch.youtube_channel_id.startsWith('UC_') || ch.youtube_channel_id.includes('_') ? (
                              <span className="inline-flex items-center gap-1 text-[11px] font-mono text-amber-400 bg-amber-950/50 border border-amber-700/60 px-1.5 py-0.5 rounded">
                                <AlertTriangle className="w-3 h-3 shrink-0" />
                                ID Pending
                              </span>
                            ) : (
                              <span className="text-[11px] font-mono text-slate-500 truncate max-w-[180px]">{ch.youtube_channel_id}</span>
                            )}
                            {onUpdateChannelId && (
                              <button
                                onClick={() => startEditChannelId(ch)}
                                title="Edit Channel ID"
                                className="p-0.5 text-slate-600 hover:text-amber-400 hover:bg-amber-950/30 rounded transition-colors shrink-0"
                              >
                                <Pencil className="w-3 h-3" />
                              </button>
                            )}
                          </div>
                        )}
                      </td>

                      {/* Platform badge */}
                      <td className="py-3.5 px-4">
                        <span className={`inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded border ${platformColor}`}>
                          {platformIcon} {(ch.platform || 'youtube').toUpperCase()}
                        </span>
                      </td>

                      {/* Authorization Dropdown */}
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
                            Eligible
                          </span>
                        ) : (
                          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium border ${
                            isTerminated 
                              ? 'bg-rose-950/70 text-rose-300 border-rose-800/80 font-bold' 
                              : 'bg-surface-800 text-slate-400 border-surface-700'
                          }`}>
                            {isTerminated ? <Lock className="w-3 h-3 text-rose-400" /> : <XCircle className="w-3.5 h-3.5" />}
                            {isTerminated ? 'LOCKED' : 'Blocked'}
                          </span>
                        )}
                      </td>

                      {/* Mapped Environment */}
                      <td className="py-3.5 px-4">
                        <select
                          value={ch.environment_id || ''}
                          onChange={(e) => onAssignEnvironment(ch.id, e.target.value || null)}
                          className="bg-surface-850 border border-surface-750 text-slate-300 text-xs rounded px-2.5 py-1 focus:outline-none focus:border-brand-accent max-w-[160px]"
                        >
                          <option value="">Unassigned</option>
                          {environments.map((env) => (
                            <option key={env.id} value={env.id}>
                              {env.name}
                            </option>
                          ))}
                        </select>
                      </td>

                      {/* Gumroad */}
                      <td className="py-3.5 px-4">
                        {ch.gumroad_url ? (
                          <div className="space-y-0.5">
                            <a
                              href={ch.tracked_destination_url || ch.gumroad_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-1 text-[11px] text-pink-400 hover:text-pink-300 font-mono truncate max-w-[140px]"
                              title={ch.tracked_destination_url || ch.gumroad_url}
                            >
                              <Link2 className="w-3 h-3 shrink-0" />
                              <span className="truncate">Gumroad Link</span>
                            </a>
                            {ch.utm_campaign && (
                              <div className="text-[10px] text-slate-500 font-mono">utm: {ch.utm_campaign}</div>
                            )}
                          </div>
                        ) : (
                          <span className="text-[11px] text-slate-600">—</span>
                        )}
                      </td>

                      {/* Actions */}
                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          {/* Open in Browser */}
                          {onOpenChannelInBrowser && (
                            <button
                              onClick={() => handleOpenInBrowser(ch)}
                              disabled={openingChannelId === ch.id || !ch.environment_id}
                              title={ch.environment_id ? `Open ${ch.display_name} in assigned Edge environment` : 'Assign an environment first'}
                              className={`px-2 py-1 rounded text-[11px] font-semibold flex items-center gap-1 border transition-colors ${
                                ch.environment_id
                                  ? 'bg-purple-950/50 hover:bg-purple-900/70 text-purple-300 border-purple-800/60'
                                  : 'bg-surface-800 text-slate-600 border-surface-700 cursor-not-allowed'
                              }`}
                            >
                              <ExternalLink className="w-3 h-3" />
                              Open
                            </button>
                          )}
                          {/* Delete */}
                          <button
                            onClick={() => setSelectedChannelForDelete(ch)}
                            className="p-1.5 bg-rose-950/40 hover:bg-rose-900/60 text-rose-400 border border-rose-800/60 rounded-md transition-colors"
                            title="Delete Channel Record"
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

      {/* Register Account Modal */}
      <Modal
        isOpen={isAddOpen}
        onClose={() => setIsAddOpen(false)}
        title="Register Social Media Account"
        subtitle="Record an authorized channel and map to a dedicated Edge environment"
      >
        <form onSubmit={handleCreate} className="space-y-4 text-xs">
          {formError && (
            <div className="p-3 bg-rose-950/60 border border-rose-800/80 rounded-lg text-rose-300">
              {formError}
            </div>
          )}

          {/* Platform selector */}
          <div>
            <label className="block text-slate-300 font-medium mb-2">Platform *</label>
            <div className="flex gap-2 flex-wrap">
              {Object.entries(PLATFORM_ICONS).map(([key, icon]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setPlatform(key)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-colors ${
                    platform === key
                      ? 'bg-brand-accent text-white border-brand-accent'
                      : 'bg-surface-850 text-slate-400 border-surface-750 hover:border-slate-500'
                  }`}
                >
                  {icon} {key.charAt(0).toUpperCase() + key.slice(1)}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-300 font-medium mb-1">Display Name *</label>
              <input
                type="text"
                required
                placeholder="e.g. Alexa Creator Studio"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 font-medium focus:outline-none focus:border-brand-accent"
              />
            </div>
            <div>
              <label className="block text-slate-300 font-medium mb-1">Account Handle (Optional)</label>
              <input
                type="text"
                placeholder="@alexacreator"
                value={accountHandle}
                onChange={(e) => setAccountHandle(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 font-mono focus:outline-none focus:border-brand-accent"
              />
            </div>
          </div>

          {platform === 'youtube' && (
            <div>
              <label className="block text-slate-300 font-medium mb-1">YouTube Channel ID</label>
              <input
                type="text"
                placeholder="UC_x5XG1OV2P6uZZ5FSM9Ttw"
                value={channelId}
                onChange={(e) => setChannelId(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 font-mono focus:outline-none focus:border-brand-accent"
              />
              <p className="text-[10px] text-slate-500 mt-1">Official 24-character YouTube identifier starting with UC. Leave blank to set later.</p>
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-300 font-medium mb-1">Workspace Name (Optional)</label>
              <input
                type="text"
                placeholder="Alexa Creator Studio"
                value={workspaceName}
                onChange={(e) => setWorkspaceName(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent"
              />
            </div>
            <div>
              <label className="block text-slate-300 font-medium mb-1">Initial Authorization</label>
              <select
                value={authStatus}
                onChange={(e) => setAuthStatus(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent"
              >
                <option value="AUTHORIZED">AUTHORIZED</option>
                <option value="UNVERIFIED">UNVERIFIED</option>
                <option value="RESTRICTED">RESTRICTED</option>
                <option value="TERMINATED">TERMINATED (Read-Only)</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-slate-300 font-medium mb-1">Assign to Environment</label>
            <select
              value={environmentId}
              onChange={(e) => setEnvironmentId(e.target.value)}
              className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 focus:outline-none focus:border-brand-accent"
            >
              <option value="">None (Assign later)</option>
              {environments.map((env) => (
                <option key={env.id} value={env.id}>
                  {env.name} ({env.execution_mode || 'VM'})
                </option>
              ))}
            </select>
          </div>

          {/* Gumroad Section */}
          <div className="border border-pink-800/40 rounded-lg p-3 bg-pink-950/20 space-y-3">
            <h4 className="text-xs font-semibold text-pink-300">🛒 Gumroad Destination (Optional)</h4>
            <div>
              <label className="block text-slate-300 font-medium mb-1">Gumroad Product URL</label>
              <input
                type="url"
                placeholder="https://alexacreator.gumroad.com/l/product"
                value={gumroadUrl}
                onChange={(e) => setGumroadUrl(e.target.value)}
                className="w-full px-3 py-2 bg-surface-850 border border-surface-750 rounded-lg text-slate-100 font-mono focus:outline-none focus:border-pink-500"
              />
            </div>
            <div className="grid grid-cols-3 gap-2">
              <div>
                <label className="block text-slate-400 mb-1">UTM Source</label>
                <input
                  type="text"
                  placeholder="tiktok"
                  value={utmSource}
                  onChange={(e) => setUtmSource(e.target.value)}
                  className="w-full px-2 py-1.5 bg-surface-850 border border-surface-750 rounded text-slate-100 font-mono focus:outline-none focus:border-pink-500"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">UTM Medium</label>
                <input
                  type="text"
                  placeholder="social"
                  value={utmMedium}
                  onChange={(e) => setUtmMedium(e.target.value)}
                  className="w-full px-2 py-1.5 bg-surface-850 border border-surface-750 rounded text-slate-100 font-mono focus:outline-none focus:border-pink-500"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">UTM Campaign</label>
                <input
                  type="text"
                  placeholder="us-launch-q4"
                  value={utmCampaign}
                  onChange={(e) => setUtmCampaign(e.target.value)}
                  className="w-full px-2 py-1.5 bg-surface-850 border border-surface-750 rounded text-slate-100 font-mono focus:outline-none focus:border-pink-500"
                />
              </div>
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
              Register Account
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
        title={`Delete Account Record '${selectedChannelForDelete?.display_name}'?`}
        message={`This will delete the local channel tracking record. The associated Edge environment and browser profiles will remain untouched.`}
        confirmLabel="Delete Record"
        isDestructive={true}
      />
    </div>
  );
};
