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
  BrowserInfo,
  BrowserSession,
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
      name: 'AlexaStudio_Edge_US',
      hypervisor_type: 'NativeBrowser',
      vm_identifier: 'native-edge-alexa-01',
      guest_os: 'macOS_Host',
      cpu_count: 0,
      memory_mb: 0,
      disk_path: '~/Library/Application Support/YouTubeIsolationManager/environments/env-prod-alpha-01',
      status: 'RUNNING',
      created_at: new Date(Date.now() - 86400000 * 3).toISOString(),
      updated_at: new Date().toISOString(),
      browser_profile_path: '~/Library/Application Support/YouTubeIsolationManager/environments/env-prod-alpha-01/browser_profiles/edge/',
      network_endpoint_id: 'ep-01',
      network_endpoint_name: 'J2Proxy-US-HTTP',
      last_observed_ipv4: null,
      last_checked_at: null,
      channel_id: 'ch-01',
      channel_name: 'Alexa Creator Studio',
      // v3 fields
      execution_mode: 'NATIVE_BROWSER',
      startup_url: 'https://www.tiktok.com/tiktokstudio',
      preferred_language: 'en-US',
      browser_session_status: 'RUNNING',
      browser_active_pid: 12345,
      proxy_bridge_port: 54321,
      last_observed_country: 'US',
      last_network_status: 'BROWSER_EGRESS_VERIFIED',
      last_network_error: null,
      vm_architecture: 'aarch64',
      host_platform: 'macos-aarch64',
      provisioning_status: 'COMPLETED',
    },
    {
      id: 'env-prod-beta-02',
      name: 'ChannelBeta_Studio',
      hypervisor_type: 'UTM',
      vm_identifier: 'utm-beta-002',
      guest_os: 'Ubuntu_ARM64',
      cpu_count: 2,
      memory_mb: 2048,
      disk_path: '~/Library/Application Support/YouTubeIsolationManager/environments/env-prod-beta-02/disk.utm',
      status: 'STOPPED',
      created_at: new Date(Date.now() - 86400000 * 1).toISOString(),
      updated_at: new Date().toISOString(),
      browser_profile_path: '~/Library/Application Support/YouTubeIsolationManager/environments/env-prod-beta-02/browser_profiles/',
      network_endpoint_id: 'ep-02',
      network_endpoint_name: 'EU-Central-WireGuard',
      last_observed_ipv4: null,
      last_checked_at: null,
      channel_id: 'ch-02',
      channel_name: 'Soundwave Reviews',
      execution_mode: 'VM',
      startup_url: null,
      preferred_language: null,
      browser_session_status: 'STOPPED',
      browser_active_pid: null,
      proxy_bridge_port: null,
      last_observed_country: null,
      last_network_status: 'NOT_CONFIGURED',
      last_network_error: null,
      vm_architecture: 'aarch64',
      host_platform: 'macos-aarch64',
      provisioning_status: 'COMPLETED',
    },
  ] as EnvironmentRecord[],
  endpoints: [
    {
      id: 'ep-01',
      name: 'J2Proxy-US-HTTP',
      endpoint_type: 'HTTP' as const,
      provider_label: 'J2Proxy / US Static',
      host: 'proxy.j2proxy.com',
      port: 8080,
      has_credentials: true,
      status: 'ACTIVE',
      created_at: new Date(Date.now() - 86400000 * 4).toISOString(),
      updated_at: new Date().toISOString(),
      username: 'alexa_user',
      expected_country: 'US',
      expected_ip: null,
      expires_at: null,
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
      username: null,
      expected_country: 'DE',
      expected_ip: null,
      expires_at: null,
    },
  ] as NetworkEndpointRecord[],
  channels: [
    {
      id: 'ch-01',
      youtube_channel_id: 'UC_x5XG1OV2P6uZZ5FSM9Ttw',
      display_name: 'Alexa Creator Studio',
      environment_id: 'env-prod-alpha-01',
      environment_name: 'AlexaStudio_Edge_US',
      authorization_status: 'AUTHORIZED' as const,
      content_review_status: 'APPROVED',
      is_eligible_for_publishing: true,
      last_reviewed_at: new Date().toISOString(),
      created_at: new Date(Date.now() - 86400000 * 5).toISOString(),
      updated_at: new Date().toISOString(),
      platform: 'tiktok',
      workspace_name: 'Alexa Creator Studio',
      account_handle: '@alexacreator',
      profile_url: 'https://www.tiktok.com/@alexacreator',
      analytics_url: 'https://www.tiktok.com/tiktokstudio',
      gumroad_url: 'https://alexacreator.gumroad.com/l/product',
      utm_source: 'tiktok',
      utm_medium: 'social',
      utm_campaign: 'us-launch-2025',
      tracked_destination_url: 'https://alexacreator.gumroad.com/l/product?utm_source=tiktok&utm_medium=social&utm_campaign=us-launch-2025',
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
      platform: 'youtube',
      workspace_name: null,
      account_handle: null,
      profile_url: null,
      analytics_url: null,
      gumroad_url: null,
      utm_source: null,
      utm_medium: null,
      utm_campaign: null,
      tracked_destination_url: null,
    },
  ] as ChannelRecord[],
  auditLogs: [
    {
      id: 'log-01',
      environment_id: 'env-prod-alpha-01',
      action: 'BROWSER_EGRESS_VERIFIED',
      severity: 'INFO' as const,
      message: 'Browser egress verified via local proxy bridge: US (104.28.x.x) — J2Proxy HTTP',
      created_at: new Date(Date.now() - 60000 * 5).toISOString(),
    },
    {
      id: 'log-02',
      environment_id: 'env-prod-alpha-01',
      action: 'LAUNCH_BROWSER',
      severity: 'INFO' as const,
      message: 'Microsoft Edge launched with proxy bridge on port 54321',
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
      const isNative = req.execution_mode === 'NATIVE_BROWSER' || req.hypervisor_type === 'NativeBrowser';
      const newEnv: EnvironmentRecord = {
        id: `env-${Date.now().toString(36)}`,
        name: req.name,
        hypervisor_type: req.hypervisor_type,
        vm_identifier: isNative ? `native-edge-${req.name.toLowerCase()}` : `vbox-${req.name}`,
        guest_os: isNative ? 'macOS_Host' : req.guest_os,
        cpu_count: isNative ? 0 : req.cpu_count,
        memory_mb: isNative ? 0 : req.memory_mb,
        disk_path: `~/Library/Application Support/YouTubeIsolationManager/environments/${req.name}`,
        status: 'STOPPED',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        browser_profile_path: `~/Library/Application Support/YouTubeIsolationManager/environments/${req.name}/browser_profiles/edge/`,
        network_endpoint_id: req.network_endpoint_id || null,
        network_endpoint_name: mockStore.endpoints.find(e => e.id === req.network_endpoint_id)?.name || null,
        channel_id: req.channel_id || null,
        channel_name: mockStore.channels.find(c => c.id === req.channel_id)?.display_name || null,
        execution_mode: req.execution_mode || (isNative ? 'NATIVE_BROWSER' : 'VM'),
        startup_url: req.startup_url || undefined,
        preferred_language: req.preferred_language || undefined,
        browser_session_status: 'STOPPED',
        browser_active_pid: null,
        proxy_bridge_port: null,
        last_observed_country: null,
        last_network_status: 'NOT_CONFIGURED',
        last_network_error: null,
        vm_architecture: req.vm_architecture || undefined,
        host_platform: req.host_platform || undefined,
        provisioning_status: 'COMPLETED',
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

    case 'detect_browsers': {
      const browsers: BrowserInfo[] = [{
        browser_type: 'Edge',
        display_name: 'Microsoft Edge',
        installed: true,
        executable_path: '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
        version: '157.0.4341.42',
        platform: 'macos',
      }];
      return Promise.resolve(browsers as unknown as T);
    }

    case 'detect_edge_browser': {
      const info: BrowserInfo = {
        browser_type: 'Edge',
        display_name: 'Microsoft Edge',
        installed: true,
        executable_path: '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
        version: '157.0.4341.42',
        platform: 'macos',
      };
      return Promise.resolve(info as unknown as T);
    }

    case 'launch_browser_with_url': {
      const envId = args?.environmentId as string;
      const url = (args?.url as string | undefined) || 'https://www.tiktok.com/';
      const env = mockStore.environments.find(e => e.id === envId);
      if (env) {
        env.browser_session_status = 'RUNNING';
        env.browser_active_pid = Math.floor(Math.random() * 90000) + 10000;
        env.proxy_bridge_port = Math.floor(Math.random() * 10000) + 50000;
        env.status = 'RUNNING';
      }
      const session: BrowserSession = {
        session_id: `sess-${Date.now().toString(36)}`,
        environment_id: envId,
        browser_type: 'Edge',
        executable_path: '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
        profile_path: `~/Library/Application Support/YouTubeIsolationManager/environments/${envId}/browser_profiles/edge/`,
        pid: env?.browser_active_pid ?? 0,
        proxy_bridge_port: env?.proxy_bridge_port ?? null,
        startup_url: url,
        preferred_language: 'en-US',
        started_at: new Date().toISOString(),
        status: 'RUNNING',
      };
      return Promise.resolve(session as unknown as T);
    }

    case 'stop_browser_profile': {
      const envId = args?.environmentId as string;
      const env = mockStore.environments.find(e => e.id === envId);
      if (env) {
        env.browser_session_status = 'STOPPED';
        env.browser_active_pid = null;
        env.proxy_bridge_port = null;
        env.status = 'STOPPED';
      }
      return Promise.resolve(undefined as unknown as T);
    }

    case 'get_browser_status': {
      const envId = args?.environmentId as string;
      const env = mockStore.environments.find(e => e.id === envId);
      return Promise.resolve((env?.browser_session_status || 'STOPPED') as unknown as T);
    }

    case 'open_profile_folder': {
      return Promise.resolve('Profile folder opened (mock)' as unknown as T);
    }

    case 'update_environment_startup_url': {
      const envId = args?.environmentId as string;
      const url = args?.startupUrl as string;
      const env = mockStore.environments.find(e => e.id === envId);
      if (env) env.startup_url = url;
      return Promise.resolve(undefined as unknown as T);
    }

    case 'verify_browser_egress': {
      const envId = args?.environmentId as string;
      const env = mockStore.environments.find(e => e.id === envId);
      if (!env || env.browser_session_status !== 'RUNNING') {
        return Promise.resolve({
          id: `check-${Date.now()}`,
          environment_id: envId,
          observed_ipv4: null,
          observed_ipv6: null,
          observed_country: null,
          dns_summary: null,
          dns_leak_status: 'UNVERIFIED',
          webrtc_status: 'UNVERIFIED',
          check_source: 'BROWSER_SESSION',
          status: 'VERIFICATION_UNAVAILABLE',
          error_message: 'No active browser session found for this environment.',
          checked_at: new Date().toISOString(),
          latency_ms: null,
          session_id: null,
        } as unknown as T);
      }
      env.last_observed_country = 'US';
      env.last_network_status = 'BROWSER_EGRESS_VERIFIED';
      env.last_checked_at = new Date().toISOString();
      return Promise.resolve({
        id: `check-${Date.now()}`,
        environment_id: envId,
        observed_ipv4: '104.28.42.10',
        observed_ipv6: null,
        observed_country: 'US',
        dns_summary: 'DNS resolved via proxy bridge (remote)',
        dns_leak_status: 'REMOTE_PROXY_DNS',
        webrtc_status: 'NON_PROXIED_UDP_DISABLED',
        check_source: 'BROWSER_SESSION',
        status: 'BROWSER_EGRESS_VERIFIED',
        error_message: null,
        checked_at: new Date().toISOString(),
        latency_ms: 85,
        session_id: `sess-${envId}`,
      } as unknown as T);
    }

    case 'update_channel_gumroad': {
      const id = args?.id as string;
      const ch = mockStore.channels.find(c => c.id === id);
      if (ch) {
        if (args?.gumroadUrl !== undefined) ch.gumroad_url = args.gumroadUrl as string | null;
        if (args?.utmSource !== undefined) ch.utm_source = args.utmSource as string | null;
        if (args?.utmMedium !== undefined) ch.utm_medium = args.utmMedium as string | null;
        if (args?.utmCampaign !== undefined) ch.utm_campaign = args.utmCampaign as string | null;
        if (ch.gumroad_url) {
          const params = new URLSearchParams();
          if (ch.utm_source) params.set('utm_source', ch.utm_source);
          if (ch.utm_medium) params.set('utm_medium', ch.utm_medium);
          if (ch.utm_campaign) params.set('utm_campaign', ch.utm_campaign);
          ch.tracked_destination_url = `${ch.gumroad_url}${params.toString() ? '?' + params.toString() : ''}`;
        }
      }
      return Promise.resolve(ch as unknown as T);
    }

    case 'open_channel_in_browser': {
      const channelId = args?.channelId as string;
      const openAnalytics = args?.openAnalytics as boolean | undefined;
      const ch = mockStore.channels.find(c => c.id === channelId);
      const url = openAnalytics ? (ch?.analytics_url || ch?.profile_url) : (ch?.profile_url || null);
      if (url && typeof window !== 'undefined') {
        window.open(url, '_blank');
      }
      return Promise.resolve({ session_id: `sess-${Date.now()}`, status: 'RUNNING' } as unknown as T);
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
        username: req.username || null,
        expected_country: req.expected_country || null,
        expected_ip: req.expected_ip || null,
        expires_at: req.expires_at || null,
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
        platform: req.platform || undefined,
        workspace_name: req.workspace_name || undefined,
        account_handle: req.account_handle || null,
        profile_url: req.profile_url || null,
        analytics_url: req.analytics_url || null,
        gumroad_url: req.gumroad_url || null,
        utm_source: req.utm_source || null,
        utm_medium: req.utm_medium || null,
        utm_campaign: req.utm_campaign || null,
        tracked_destination_url: null,
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

  // Native Browser (macOS Edge) APIs
  detectBrowsers: () => callTauri<BrowserInfo[]>('detect_browsers'),
  detectEdgeBrowser: () => callTauri<BrowserInfo>('detect_edge_browser'),
  launchBrowserWithUrl: (environmentId: string, url?: string) =>
    callTauri<BrowserSession>('launch_browser_with_url', { environmentId, url }),
  stopBrowserProfile: (environmentId: string) => callTauri<void>('stop_browser_profile', { environmentId }),
  getBrowserStatus: (environmentId: string) => callTauri<string>('get_browser_status', { environmentId }),
  openProfileFolder: (environmentId: string) => callTauri<string>('open_profile_folder', { environmentId }),
  updateEnvironmentStartupUrl: (environmentId: string, startupUrl: string) =>
    callTauri<void>('update_environment_startup_url', { environmentId, startupUrl }),
  verifyBrowserEgress: (environmentId: string) =>
    callTauri<NetworkCheckRecord>('verify_browser_egress', { environmentId }),

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

  // Channels & Social Platforms
  listChannels: () => callTauri<ChannelRecord[]>('list_channels'),
  createChannel: (req: CreateChannelRequest) => callTauri<ChannelRecord>('create_channel', { req }),
  updateChannelStatus: (id: string, status: string) => callTauri<void>('update_channel_status', { id, status }),
  assignChannelEnvironment: (channelId: string, environmentId?: string | null) =>
    callTauri<void>('assign_channel_environment', { channelId, environmentId: environmentId || null }),
  deleteChannel: (id: string) => callTauri<void>('delete_channel', { id }),
  updateChannelYoutubeId: (id: string, youtubeChannelId: string) =>
    callTauri<void>('update_channel_youtube_id', { id, youtubeChannelId }),
  updateChannelGumroad: (id: string, gumroadUrl?: string | null, utmSource?: string | null, utmMedium?: string | null, utmCampaign?: string | null) =>
    callTauri<ChannelRecord>('update_channel_gumroad', { id, gumroadUrl, utmSource, utmMedium, utmCampaign }),
  openChannelInBrowser: (channelId: string, openAnalytics?: boolean) =>
    callTauri<BrowserSession>('open_channel_in_browser', { channelId, openAnalytics }),

  // Audit & Security
  listAuditLogs: (limit?: number) => callTauri<AuditLogEntry[]>('list_audit_logs', { limit }),
  testSecretVault: () => callTauri<boolean>('test_secret_vault'),
  testDpapiVault: () => callTauri<boolean>('test_dpapi_vault'),
};
