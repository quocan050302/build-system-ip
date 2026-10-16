import {
  EnvironmentRecord,
  CreateEnvironmentRequest,
  NetworkEndpointRecord,
  CreateEndpointRequest,
  NetworkCheckRecord,
  DuplicateEgressWarning,
  ChannelRecord,
  CreateChannelRequest,
  HypervisorInfo,
  HostResources,
  AuditLogEntry,
  PlatformInfo,
} from '../types';

// Check if running inside Tauri context
const isTauri = (): boolean => {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
};

// Lazy load tauri invoke
async function callTauri<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (isTauri()) {
    const { invoke } = await import('@tauri-apps/api/core');
    return invoke<T>(cmd, args);
  }
  // In non-Tauri / test environments, route to mock state
  return mockHandler<T>(cmd, args);
}

// In-memory mock store for frontend preview and tests
const mockStore = {
  environments: [
    {
      id: 'env-prod-alpha-01',
      name: 'ChannelAlpha_Primary',
      hypervisor_type: 'VirtualBox',
      vm_identifier: 'vbox-alpha-001',
      guest_os: 'Ubuntu_64',
      cpu_count: 4,
      memory_mb: 4096,
      disk_path: 'C:\\VirtualBoxVMs\\ChannelAlpha_Primary\\disk.vdi',
      status: 'RUNNING',
      created_at: new Date(Date.now() - 86400000 * 3).toISOString(),
      updated_at: new Date().toISOString(),
      browser_profile_path: 'C:\\AppData\\YouTubeIsolation\\profiles\\alpha',
      network_endpoint_id: 'ep-01',
      network_endpoint_name: 'US-East-Residential-Proxy',
      last_observed_ipv4: '198.51.100.42',
      last_checked_at: new Date().toISOString(),
      channel_id: 'ch-01',
      channel_name: 'Tech Insights Daily',
    },
    {
      id: 'env-prod-beta-02',
      name: 'ChannelBeta_Studio',
      hypervisor_type: 'VirtualBox',
      vm_identifier: 'vbox-beta-002',
      guest_os: 'Ubuntu_64',
      cpu_count: 2,
      memory_mb: 2048,
      disk_path: 'C:\\VirtualBoxVMs\\ChannelBeta_Studio\\disk.vdi',
      status: 'STOPPED',
      created_at: new Date(Date.now() - 86400000 * 1).toISOString(),
      updated_at: new Date().toISOString(),
      browser_profile_path: 'C:\\AppData\\YouTubeIsolation\\profiles\\beta',
      network_endpoint_id: 'ep-02',
      network_endpoint_name: 'EU-Central-WireGuard',
      last_observed_ipv4: null,
      last_checked_at: null,
      channel_id: 'ch-02',
      channel_name: 'Soundwave Reviews',
    },
  ] as EnvironmentRecord[],
  endpoints: [
    {
      id: 'ep-01',
      name: 'US-East-Residential-Proxy',
      endpoint_type: 'SOCKS5' as const,
      provider_label: 'BrightData / Static Res',
      host: '198.51.100.42',
      port: 1080,
      has_credentials: true,
      status: 'ACTIVE',
      created_at: new Date(Date.now() - 86400000 * 4).toISOString(),
      updated_at: new Date().toISOString(),
    },
    {
      id: 'ep-02',
      name: 'EU-Central-WireGuard',
      endpoint_type: 'WIREGUARD' as const,
      provider_label: 'Mullvad Dedicated',
      host: '185.220.101.5',
      port: 51820,
      has_credentials: true,
      status: 'ACTIVE',
      created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
      updated_at: new Date().toISOString(),
    },
  ] as NetworkEndpointRecord[],
  channels: [
    {
      id: 'ch-01',
      youtube_channel_id: 'UC_x5XG1OV2P6uZZ5FSM9Ttw',
      display_name: 'Tech Insights Daily',
      environment_id: 'env-prod-alpha-01',
      environment_name: 'ChannelAlpha_Primary',
      authorization_status: 'AUTHORIZED' as const,
      content_review_status: 'APPROVED',
      is_eligible_for_publishing: true,
      last_reviewed_at: new Date().toISOString(),
      created_at: new Date(Date.now() - 86400000 * 5).toISOString(),
      updated_at: new Date().toISOString(),
    },
    {
      id: 'ch-02',
      youtube_channel_id: 'UC4R8DWoMoI7CAwX8_BQQDcg',
      display_name: 'Soundwave Reviews',
      environment_id: 'env-prod-beta-02',
      environment_name: 'ChannelBeta_Studio',
      authorization_status: 'UNVERIFIED' as const,
      content_review_status: 'PENDING',
      is_eligible_for_publishing: false,
      last_reviewed_at: null,
      created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
      updated_at: new Date().toISOString(),
    },
  ] as ChannelRecord[],
  auditLogs: [
    {
      id: 'log-01',
      environment_id: 'env-prod-alpha-01',
      action: 'NETWORK_CHECK',
      severity: 'INFO' as const,
      message: 'Verified guest network egress: 198.51.100.42 (DNS latency 22ms)',
      created_at: new Date(Date.now() - 60000 * 5).toISOString(),
    },
    {
      id: 'log-02',
      environment_id: 'env-prod-alpha-01',
      action: 'START_VM',
      severity: 'INFO' as const,
      message: 'VM started successfully via hypervisor adapter',
      created_at: new Date(Date.now() - 60000 * 30).toISOString(),
    },
  ] as AuditLogEntry[],
};

function mockHandler<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  switch (cmd) {
    case 'get_hypervisor_info':
      return Promise.resolve({
        name: 'Oracle VM VirtualBox',
        version: '7.0.18-r162988',
        available: true,
        executable_path: 'C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe',
      } as unknown as T);

    case 'get_host_resources':
      return Promise.resolve({
        total_memory_mb: 32768,
        available_memory_mb: 18432,
        total_disk_mb: 1048576,
        available_disk_mb: 489200,
      } as unknown as T);

    case 'list_environments':
      return Promise.resolve([...mockStore.environments] as unknown as T);

    case 'create_environment': {
      const req = (args?.req as CreateEnvironmentRequest);
      const newEnv: EnvironmentRecord = {
        id: `env-${Date.now().toString(36)}`,
        name: req.name,
        hypervisor_type: req.hypervisor_type,
        vm_identifier: `vbox-${req.name}`,
        guest_os: req.guest_os,
        cpu_count: req.cpu_count,
        memory_mb: req.memory_mb,
        disk_path: `C:\\VirtualBoxVMs\\${req.name}\\disk.vdi`,
        status: 'STOPPED',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        browser_profile_path: `C:\\AppData\\YouTubeIsolation\\profiles\\${req.name}`,
        network_endpoint_id: req.network_endpoint_id || null,
        network_endpoint_name: mockStore.endpoints.find(e => e.id === req.network_endpoint_id)?.name || null,
        channel_id: req.channel_id || null,
        channel_name: mockStore.channels.find(c => c.id === req.channel_id)?.display_name || null,
      };
      mockStore.environments.unshift(newEnv);
      return Promise.resolve(newEnv as unknown as T);
    }

    case 'start_environment': {
      const id = args?.id as string;
      const env = mockStore.environments.find(e => e.id === id);
      if (env) env.status = 'RUNNING';
      return Promise.resolve(undefined as unknown as T);
    }

    case 'shutdown_environment': {
      const id = args?.id as string;
      const env = mockStore.environments.find(e => e.id === id);
      if (env) env.status = 'STOPPED';
      return Promise.resolve(undefined as unknown as T);
    }

    case 'delete_environment': {
      const id = args?.id as string;
      mockStore.environments = mockStore.environments.filter(e => e.id !== id);
      return Promise.resolve(undefined as unknown as T);
    }

    case 'launch_browser_profile': {
      if (typeof window !== 'undefined') {
        window.open('https://studio.youtube.com', '_blank');
      }
      return Promise.resolve('Opened YouTube Studio (mock)' as unknown as T);
    }

    case 'list_network_endpoints':
      return Promise.resolve([...mockStore.endpoints] as unknown as T);

    case 'create_network_endpoint': {
      const req = args?.req as CreateEndpointRequest;
      const newEp: NetworkEndpointRecord = {
        id: `ep-${Date.now().toString(36)}`,
        name: req.name,
        endpoint_type: req.endpoint_type as any,
        provider_label: req.provider_label || null,
        host: req.host || null,
        port: req.port || null,
        has_credentials: Boolean(req.credentials_secret),
        status: 'ACTIVE',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      mockStore.endpoints.unshift(newEp);
      return Promise.resolve(newEp as unknown as T);
    }

    case 'delete_network_endpoint': {
      const id = args?.id as string;
      mockStore.endpoints = mockStore.endpoints.filter(e => e.id !== id);
      return Promise.resolve(undefined as unknown as T);
    }

    case 'assign_network_endpoint': {
      const envId = args?.environmentId as string;
      const epId = args?.endpointId as string | undefined;
      const env = mockStore.environments.find(e => e.id === envId);
      if (env) {
        env.network_endpoint_id = epId || null;
        env.network_endpoint_name = mockStore.endpoints.find(e => e.id === epId)?.name || null;
      }
      return Promise.resolve(undefined as unknown as T);
    }

    case 'check_environment_network': {
      const envId = args?.environmentId as string;
      const env = mockStore.environments.find(e => e.id === envId);
      const isRunning = env?.status === 'RUNNING';

      if (!isRunning) {
        return Promise.resolve({
          id: `check-${Date.now()}`,
          environment_id: envId,
          observed_ipv4: null,
          observed_ipv6: null,
          dns_summary: null,
          check_source: 'GUEST_DIAGNOSTICS',
          status: 'NOT_CHECKED',
          error_message: 'Cannot verify network egress: VM is stopped. Truthful diagnostics require running VM.',
          checked_at: new Date().toISOString(),
        } as unknown as T);
      }

      return (async () => {
        let realIp = '14.241.244.112';
        try {
          const res = await fetch('https://api.ipify.org?format=json').then(r => r.json());
          if (res?.ip) {
            realIp = res.ip;
          }
        } catch {
          // fallback to detected IP
        }

        const check: NetworkCheckRecord = {
          id: `check-${Date.now()}`,
          environment_id: envId,
          observed_ipv4: env?.network_endpoint_id ? '198.51.100.42' : realIp,
          observed_ipv6: null,
          dns_summary: 'DNS resolved via Local Gateway (VNPT)',
          check_source: 'GUEST_AGENT',
          status: 'VERIFIED',
          error_message: null,
          checked_at: new Date().toISOString(),
        };
        if (env) {
          env.last_observed_ipv4 = check.observed_ipv4;
          env.last_checked_at = check.checked_at;
        }
        return check as unknown as T;
      })();
    }

    case 'detect_duplicate_egress': {
      return Promise.resolve([] as unknown as T);
    }

    case 'list_channels':
      return Promise.resolve([...mockStore.channels] as unknown as T);

    case 'create_channel': {
      const req = args?.req as CreateChannelRequest;
      const newCh: ChannelRecord = {
        id: `ch-${Date.now().toString(36)}`,
        youtube_channel_id: req.youtube_channel_id,
        display_name: req.display_name,
        environment_id: req.environment_id || null,
        environment_name: mockStore.environments.find(e => e.id === req.environment_id)?.name || null,
        authorization_status: req.authorization_status as any,
        content_review_status: 'APPROVED',
        is_eligible_for_publishing: req.authorization_status === 'AUTHORIZED',
        last_reviewed_at: new Date().toISOString(),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      mockStore.channels.unshift(newCh);
      return Promise.resolve(newCh as unknown as T);
    }

    case 'update_channel_status': {
      const id = args?.id as string;
      const status = args?.status as any;
      const ch = mockStore.channels.find(c => c.id === id);
      if (ch) {
        ch.authorization_status = status;
        ch.is_eligible_for_publishing = status === 'AUTHORIZED';
      }
      return Promise.resolve(undefined as unknown as T);
    }

    case 'assign_channel_environment': {
      const chId = args?.channelId as string;
      const envId = args?.environmentId as string | undefined;
      const ch = mockStore.channels.find(c => c.id === chId);
      if (ch) {
        ch.environment_id = envId || null;
        ch.environment_name = mockStore.environments.find(e => e.id === envId)?.name || null;
      }
      return Promise.resolve(undefined as unknown as T);
    }

    case 'delete_channel': {
      const id = args?.id as string;
      mockStore.channels = mockStore.channels.filter(c => c.id !== id);
      return Promise.resolve(undefined as unknown as T);
    }

    case 'list_audit_logs':
      return Promise.resolve([...mockStore.auditLogs] as unknown as T);

    case 'get_platform_info': {
      const isMac = typeof navigator !== 'undefined' && navigator.userAgent.toLowerCase().includes('mac');
      return Promise.resolve({
        os: isMac ? 'macos' : 'windows',
        arch: isMac ? 'aarch64' : 'x86_64',
        target_triple: isMac ? 'macos-aarch64' : 'windows-x86_64',
        is_supported: true,
        total_memory_mb: 16384,
        available_memory_mb: 8192,
        total_disk_mb: 512000,
        available_disk_mb: 256000,
        installed_hypervisors: [isMac ? 'UTM' : 'Hyper-V'],
        supported_capabilities: isMac 
          ? ['Apple Silicon Native Virtualization', 'UTM Virtual Machine Manager', 'Apple Keychain Secret Sealing'] 
          : ['Microsoft Hyper-V Type-1 Hypervisor', 'VHDX Dynamic Persistent Disks', 'Windows DPAPI Vault'],
        permissions_status: 'USER_STANDARD',
        app_data_dir: isMac ? '~/Library/Application Support/YouTubeIsolationManager' : '%APPDATA%\\YouTubeIsolationManager',
      } as unknown as T);
    }

    case 'open_vm_console':
    case 'launch_guest_browser':
      return Promise.resolve(undefined as unknown as T);

    case 'reconcile_environment_states':
      return Promise.resolve(0 as unknown as T);

    case 'test_secret_vault':
    case 'test_dpapi_vault':
      return Promise.resolve(true as unknown as T);

    default:
      return Promise.reject(new Error(`Command ${cmd} not implemented in mock handler`));
  }
}

export const api = {
  // Platform & Hypervisor
  getPlatformInfo: () => callTauri<PlatformInfo>('get_platform_info'),
  getHypervisorInfo: () => callTauri<HypervisorInfo>('get_hypervisor_info'),
  getHostResources: () => callTauri<HostResources>('get_host_resources'),

  // Environments
  listEnvironments: () => callTauri<EnvironmentRecord[]>('list_environments'),
  createEnvironment: (req: CreateEnvironmentRequest) => callTauri<EnvironmentRecord>('create_environment', { req }),
  startEnvironment: (id: string) => callTauri<void>('start_environment', { id }),
  shutdownEnvironment: (id: string, force: boolean) => callTauri<void>('shutdown_environment', { id, force }),
  openVmConsole: (id: string) => callTauri<void>('open_vm_console', { id }),
  launchGuestBrowser: (id: string) => callTauri<void>('launch_guest_browser', { id }),
  reconcileStates: () => callTauri<number>('reconcile_environment_states'),
  deleteEnvironment: (id: string, deleteDisks: boolean) => callTauri<void>('delete_environment', { id, deleteDisks }),
  launchBrowserProfile: (environmentId: string) => callTauri<string>('launch_browser_profile', { environmentId }),

  // Network
  listEndpoints: () => callTauri<NetworkEndpointRecord[]>('list_network_endpoints'),
  createEndpoint: (req: CreateEndpointRequest) => callTauri<NetworkEndpointRecord>('create_network_endpoint', { req }),
  deleteEndpoint: (id: string) => callTauri<void>('delete_network_endpoint', { id }),
  assignEndpoint: (environmentId: string, endpointId?: string | null) => 
    callTauri<void>('assign_network_endpoint', { environmentId, endpointId: endpointId || null }),
  checkNetwork: (environmentId: string) => callTauri<NetworkCheckRecord>('check_environment_network', { environmentId }),
  detectDuplicateEgress: () => callTauri<DuplicateEgressWarning[]>('detect_duplicate_egress'),
  getNetworkHistory: (environmentId: string, limit?: number) => 
    callTauri<NetworkCheckRecord[]>('get_network_history', { environmentId, limit }),

  // Channels
  listChannels: () => callTauri<ChannelRecord[]>('list_channels'),
  createChannel: (req: CreateChannelRequest) => callTauri<ChannelRecord>('create_channel', { req }),
  updateChannelStatus: (id: string, status: string) => callTauri<void>('update_channel_status', { id, status }),
  assignChannelEnvironment: (channelId: string, environmentId?: string | null) => 
    callTauri<void>('assign_channel_environment', { channelId, environmentId: environmentId || null }),
  deleteChannel: (id: string) => callTauri<void>('delete_channel', { id }),

  // Audit & Security
  listAuditLogs: (limit?: number) => callTauri<AuditLogEntry[]>('list_audit_logs', { limit }),
  testSecretVault: () => callTauri<boolean>('test_secret_vault'),
  testDpapiVault: () => callTauri<boolean>('test_dpapi_vault'),
};
