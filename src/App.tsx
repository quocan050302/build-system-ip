import React, { useState, useEffect, useCallback } from 'react';
import { Sidebar, NavItem } from './components/Sidebar';
import { Header } from './components/Header';
import { OverviewView } from './views/OverviewView';
import { EnvironmentsView } from './views/EnvironmentsView';
import { NetworkView } from './views/NetworkView';
import { ChannelsView } from './views/ChannelsView';
import { SettingsView } from './views/SettingsView';
import { api } from './api/client';
import { 
  EnvironmentRecord, 
  NetworkEndpointRecord, 
  ChannelRecord, 
  DuplicateEgressWarning, 
  AuditLogEntry, 
  HypervisorInfo, 
  HostResources,
  CreateEnvironmentRequest,
  CreateEndpointRequest,
  CreateChannelRequest
} from './types';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<NavItem>('overview');
  const [isLoading, setIsLoading] = useState(true);

  // Core Data States
  const [environments, setEnvironments] = useState<EnvironmentRecord[]>([]);
  const [endpoints, setEndpoints] = useState<NetworkEndpointRecord[]>([]);
  const [channels, setChannels] = useState<ChannelRecord[]>([]);
  const [duplicateWarnings, setDuplicateWarnings] = useState<DuplicateEgressWarning[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [hypervisorInfo, setHypervisorInfo] = useState<HypervisorInfo | null>(null);
  const [hostResources, setHostResources] = useState<HostResources | null>(null);

  // Load all system data
  const loadData = useCallback(async () => {
    try {
      setIsLoading(true);
      const [envs, eps, chs, warnings, logs, hvInfo, resources] = await Promise.all([
        api.listEnvironments().catch(() => []),
        api.listEndpoints().catch(() => []),
        api.listChannels().catch(() => []),
        api.detectDuplicateEgress().catch(() => []),
        api.listAuditLogs(50).catch(() => []),
        api.getHypervisorInfo().catch(() => null),
        api.getHostResources().catch(() => null),
      ]);

      setEnvironments(envs);
      setEndpoints(eps);
      setChannels(chs);
      setDuplicateWarnings(warnings);
      setAuditLogs(logs);
      setHypervisorInfo(hvInfo);
      setHostResources(resources);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Environments Handlers
  const handleCreateEnvironment = async (req: CreateEnvironmentRequest) => {
    await api.createEnvironment(req);
    await loadData();
  };

  const handleStartEnvironment = async (id: string) => {
    await api.startEnvironment(id);
    await loadData();
  };

  const handleShutdownEnvironment = async (id: string, force: boolean) => {
    await api.shutdownEnvironment(id, force);
    await loadData();
  };

  const handleDeleteEnvironment = async (id: string, deleteDisks: boolean) => {
    await api.deleteEnvironment(id, deleteDisks);
    await loadData();
  };

  // Network Handlers
  const handleCreateEndpoint = async (req: CreateEndpointRequest) => {
    await api.createEndpoint(req);
    await loadData();
  };

  const handleDeleteEndpoint = async (id: string) => {
    await api.deleteEndpoint(id);
    await loadData();
  };

  const handleAssignEndpoint = async (environmentId: string, endpointId?: string | null) => {
    await api.assignEndpoint(environmentId, endpointId);
    await loadData();
  };

  const handleCheckNetwork = async (environmentId: string) => {
    await api.checkNetwork(environmentId);
    await loadData();
  };

  const handleLaunchBrowser = async (environmentId: string) => {
    await api.launchBrowserProfile(environmentId);
  };

  // Channel Handlers
  const handleCreateChannel = async (req: CreateChannelRequest) => {
    await api.createChannel(req);
    await loadData();
  };

  const handleUpdateChannelStatus = async (id: string, status: string) => {
    await api.updateChannelStatus(id, status);
    await loadData();
  };

  const handleAssignChannelEnvironment = async (channelId: string, environmentId?: string | null) => {
    await api.assignChannelEnvironment(channelId, environmentId);
    await loadData();
  };

  const handleDeleteChannel = async (id: string) => {
    await api.deleteChannel(id);
    await loadData();
  };

  // Security Test
  const handleTestVault = async () => {
    return api.testDpapiVault();
  };

  const runningCount = environments.filter((e) => e.status === 'RUNNING').length;

  const getTabTitle = (tab: NavItem) => {
    switch (tab) {
      case 'overview':
        return { title: 'System Overview', subtitle: 'Workstation resource health, active VMs, and operational alerts' };
      case 'environments':
        return { title: 'Virtual Environments', subtitle: 'Isolated guest VMs, dedicated disks, and profile storage' };
      case 'network':
        return { title: 'Network & Egress Diagnostics', subtitle: 'Per-environment proxy endpoints and guest-verified IP checks' };
      case 'channels':
        return { title: 'YouTube Channel Registry', subtitle: 'Authorized channel assignments and platform compliance controls' };
      case 'settings':
        return { title: 'Application Settings', subtitle: 'Hypervisor discovery, DPAPI vault status, and audit logs' };
    }
  };

  const { title, subtitle } = getTabTitle(currentTab);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-surface-950 text-slate-100 font-sans">
      {/* Sidebar Navigation */}
      <Sidebar
        currentTab={currentTab}
        onTabChange={setCurrentTab}
        runningCount={runningCount}
        totalCount={environments.length}
      />

      {/* Main Workspace Layout */}
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        {/* Top Header */}
        <Header
          title={title}
          subtitle={subtitle}
          hypervisorInfo={hypervisorInfo}
          onRefresh={loadData}
          isLoading={isLoading}
        />

        {/* Scrollable View Area */}
        <main className="flex-1 overflow-y-auto p-8 bg-surface-950">
          <div className="max-w-7xl mx-auto">
            {currentTab === 'overview' && (
              <OverviewView
                environments={environments}
                hostResources={hostResources}
                hypervisorInfo={hypervisorInfo}
                duplicateWarnings={duplicateWarnings}
                auditLogs={auditLogs}
                onNavigate={setCurrentTab}
              />
            )}

            {currentTab === 'environments' && (
              <EnvironmentsView
                environments={environments}
                endpoints={endpoints}
                channels={channels}
                hypervisorInfo={hypervisorInfo}
                onRefresh={loadData}
                onCreateEnvironment={handleCreateEnvironment}
                onStartEnvironment={handleStartEnvironment}
                onShutdownEnvironment={handleShutdownEnvironment}
                onDeleteEnvironment={handleDeleteEnvironment}
                onCheckNetwork={handleCheckNetwork}
                onLaunchBrowser={handleLaunchBrowser}
              />
            )}

            {currentTab === 'network' && (
              <NetworkView
                endpoints={endpoints}
                environments={environments}
                duplicateWarnings={duplicateWarnings}
                onRefresh={loadData}
                onCreateEndpoint={handleCreateEndpoint}
                onDeleteEndpoint={handleDeleteEndpoint}
                onAssignEndpoint={handleAssignEndpoint}
                onCheckNetwork={handleCheckNetwork}
                onLaunchBrowser={handleLaunchBrowser}
              />
            )}

            {currentTab === 'channels' && (
              <ChannelsView
                channels={channels}
                environments={environments}
                onRefresh={loadData}
                onCreateChannel={handleCreateChannel}
                onUpdateStatus={handleUpdateChannelStatus}
                onAssignEnvironment={handleAssignChannelEnvironment}
                onDeleteChannel={handleDeleteChannel}
              />
            )}

            {currentTab === 'settings' && (
              <SettingsView
                hypervisorInfo={hypervisorInfo}
                hostResources={hostResources}
                auditLogs={auditLogs}
                onTestVault={handleTestVault}
                onRefresh={loadData}
              />
            )}
          </div>
        </main>
      </div>
    </div>
  );
};
