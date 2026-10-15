import React from 'react';
import { 
  LayoutDashboard, 
  Layers, 
  Globe, 
  Tv2, 
  Settings, 
  ShieldCheck,
  Cpu
} from 'lucide-react';

export type NavItem = 'overview' | 'environments' | 'network' | 'channels' | 'settings';

interface SidebarProps {
  currentTab: NavItem;
  onTabChange: (tab: NavItem) => void;
  runningCount: number;
  totalCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onTabChange,
  runningCount,
  totalCount,
}) => {
  const navItems: { id: NavItem; label: string; icon: React.ReactNode; badge?: string }[] = [
    { id: 'overview', label: 'Overview', icon: <LayoutDashboard className="w-4 h-4" /> },
    { 
      id: 'environments', 
      label: 'Environments', 
      icon: <Layers className="w-4 h-4" />,
      badge: totalCount > 0 ? `${runningCount}/${totalCount}` : undefined
    },
    { id: 'network', label: 'Network', icon: <Globe className="w-4 h-4" /> },
    { id: 'channels', label: 'Channels', icon: <Tv2 className="w-4 h-4" /> },
    { id: 'settings', label: 'Settings', icon: <Settings className="w-4 h-4" /> },
  ];

  return (
    <aside className="w-64 bg-surface-900 border-r border-surface-800 flex flex-col justify-between select-none h-screen">
      <div>
        {/* Brand Header */}
        <div className="h-16 flex items-center gap-3 px-5 border-b border-surface-800">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-brand-red to-rose-600 flex items-center justify-center text-white shadow-lg shadow-rose-950/40">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-sm font-semibold tracking-wide text-slate-100">YouTube Isolation</h1>
            <p className="text-[10px] font-mono text-slate-400">Desktop Manager v1.0</p>
          </div>
        </div>

        {/* Primary Navigation (Strict 5 items) */}
        <nav className="p-3 space-y-1">
          {navItems.map((item) => {
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-brand-accent/15 text-blue-400 border border-brand-accent/30 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-surface-850'
                }`}
              >
                <div className="flex items-center gap-3">
                  <span className={isActive ? 'text-brand-accent' : 'text-slate-400'}>
                    {item.icon}
                  </span>
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span className={`text-[11px] font-mono px-2 py-0.5 rounded-full ${
                    runningCount > 0 
                      ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/80' 
                      : 'bg-surface-800 text-slate-400'
                  }`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer System Status */}
      <div className="p-4 border-t border-surface-800 bg-surface-950/40 m-3 rounded-lg text-xs space-y-2">
        <div className="flex items-center justify-between text-slate-400">
          <span className="flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-slate-500" /> Host Guard
          </span>
          <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/50 px-1.5 py-0.5 rounded border border-emerald-800/50">
            DPAPI Active
          </span>
        </div>
        <p className="text-[11px] text-slate-500 leading-tight">
          Isolated guest storage & zero-trust network boundaries.
        </p>
      </div>
    </aside>
  );
};
