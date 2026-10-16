export type VmState = 
  | 'NOT_CONFIGURED' 
  | 'STOPPED' 
  | 'STARTING' 
  | 'RUNNING' 
  | 'STOPPING' 
  | 'ERROR' 
  | 'UNKNOWN';

export type ChannelStatus = 
  | 'UNVERIFIED' 
  | 'AUTHORIZED' 
  | 'RESTRICTED' 
  | 'TERMINATED' 
  | 'ARCHIVED';

export type NetworkStatus = 
  | 'NOT_CONFIGURED' 
  | 'NOT_CHECKED' 
  | 'CHECKING' 
  | 'ENDPOINT_CONFIGURED'
  | 'ENDPOINT_REACHABLE'
  | 'GUEST_EGRESS_OBSERVED'
  | 'VERIFIED' 
  | 'DEGRADED' 
  | 'DISCONNECTED' 
  | 'CONNECTION_FAILED'
  | 'ERROR';

export interface PlatformInfo {
  os: string;
  arch: string;
  target_triple: string;
  is_supported: boolean;
  total_memory_mb: number;
  available_memory_mb: number;
  total_disk_mb: number;
  available_disk_mb: number;
  installed_hypervisors: string[];
  supported_capabilities: string[];
  permissions_status: string;
  app_data_dir: string;
}

export interface EnvironmentRecord {
  id: string;
  name: string;
  hypervisor_type: string;
  vm_identifier: string;
  guest_os: string;
  cpu_count: number;
  memory_mb: number;
  disk_path: string;
  status: string;
  created_at: string;
  updated_at: string;
  // Platform & isolation metadata
  host_platform?: string;
  vm_architecture?: string;
  provisioning_status?: string;
  persistent_disk_reference?: string | null;
  network_diagnostics_capability?: string;
  // Relations
  browser_profile_path?: string | null;
  network_endpoint_id?: string | null;
  network_endpoint_name?: string | null;
  last_observed_ipv4?: string | null;
  last_checked_at?: string | null;
  channel_id?: string | null;
  channel_name?: string | null;
}

export interface CreateEnvironmentRequest {
  name: string;
  hypervisor_type: string;
  guest_os: string;
  cpu_count: number;
  memory_mb: number;
  disk_size_mb: number;
  iso_path?: string | null;
  browser_type: string;
  network_endpoint_id?: string | null;
  channel_id?: string | null;
  host_platform?: string | null;
  vm_architecture?: string | null;
}

export interface NetworkEndpointRecord {
  id: string;
  name: string;
  endpoint_type: 'HTTP' | 'SOCKS5' | 'WIREGUARD' | 'DIRECT';
  provider_label?: string | null;
  host?: string | null;
  port?: number | null;
  has_credentials: boolean;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface CreateEndpointRequest {
  name: string;
  endpoint_type: string;
  provider_label?: string | null;
  host?: string | null;
  port?: number | null;
  credentials_secret?: string | null;
}

export interface NetworkCheckRecord {
  id: string;
  environment_id: string;
  observed_ipv4?: string | null;
  observed_ipv6?: string | null;
  dns_summary?: string | null;
  check_source: string;
  status: string;
  error_message?: string | null;
  checked_at: string;
  latency_ms?: number | null;
}

export interface DuplicateEgressWarning {
  ip_address: string;
  conflicting_environments: string[];
  message: string;
}

export interface ChannelRecord {
  id: string;
  youtube_channel_id: string;
  display_name: string;
  environment_id?: string | null;
  environment_name?: string | null;
  authorization_status: ChannelStatus;
  content_review_status: string;
  is_eligible_for_publishing: boolean;
  last_reviewed_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface CreateChannelRequest {
  youtube_channel_id: string;
  display_name: string;
  environment_id?: string | null;
  authorization_status: string;
}

export interface HypervisorInfo {
  name: string;
  version: string;
  available: boolean;
  executable_path?: string | null;
}

export interface HostResources {
  total_memory_mb: number;
  available_memory_mb: number;
  total_disk_mb: number;
  available_disk_mb: number;
}

export interface AuditLogEntry {
  id: string;
  environment_id?: string | null;
  action: string;
  severity: 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL';
  message: string;
  created_at: string;
}
