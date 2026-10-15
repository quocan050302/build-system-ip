use crate::hypervisor::{HostResources, HypervisorInfo};
use crate::security::{get_secret_store, dpapi::DpapiVault};
use crate::services::audit_service::AuditLogEntry;
use crate::services::channel_service::{ChannelRecord, CreateChannelRequest};
use crate::services::network_service::{
    CreateEndpointRequest, DuplicateEgressWarning, NetworkCheckRecord, NetworkEndpointRecord,
};
use crate::services::platform_service::PlatformInfo;
use crate::services::vm_service::{CreateEnvironmentRequest, EnvironmentRecord};
use crate::AppState;
use tauri::State;

// --- Platform & Host Commands ---

#[tauri::command]
pub fn get_platform_info(state: State<AppState>) -> Result<PlatformInfo, String> {
    Ok(state.platform_service.detect())
}

#[tauri::command]
pub fn get_hypervisor_info(state: State<AppState>) -> Result<HypervisorInfo, String> {
    state.vm_service.get_hypervisor_info()
}

#[tauri::command]
pub fn get_host_resources(state: State<AppState>) -> Result<HostResources, String> {
    state.vm_service.get_host_resources()
}

// --- Environment Commands ---

#[tauri::command]
pub fn create_environment(
    req: CreateEnvironmentRequest,
    state: State<AppState>,
) -> Result<EnvironmentRecord, String> {
    state.vm_service.create_environment(req)
}

#[tauri::command]
pub fn list_environments(state: State<AppState>) -> Result<Vec<EnvironmentRecord>, String> {
    state.vm_service.list_environments()
}

#[tauri::command]
pub fn get_environment(id: String, state: State<AppState>) -> Result<Option<EnvironmentRecord>, String> {
    state.vm_service.get_environment(&id)
}

#[tauri::command]
pub fn start_environment(id: String, state: State<AppState>) -> Result<(), String> {
    state.vm_service.start_environment(&id)
}

#[tauri::command]
pub fn shutdown_environment(id: String, force: bool, state: State<AppState>) -> Result<(), String> {
    state.vm_service.shutdown_environment(&id, force)
}

#[tauri::command]
pub fn open_vm_console(id: String, state: State<AppState>) -> Result<(), String> {
    state.vm_service.open_console(&id)
}

#[tauri::command]
pub fn launch_guest_browser(id: String, state: State<AppState>) -> Result<(), String> {
    state.vm_service.launch_guest_browser(&id)
}

#[tauri::command]
pub fn reconcile_environment_states(state: State<AppState>) -> Result<usize, String> {
    state.vm_service.reconcile_states()
}

#[tauri::command]
pub fn delete_environment(id: String, delete_disks: bool, state: State<AppState>) -> Result<(), String> {
    state.vm_service.delete_environment(&id, delete_disks)
}

// --- Network Commands ---

#[tauri::command]
pub fn create_network_endpoint(
    req: CreateEndpointRequest,
    state: State<AppState>,
) -> Result<NetworkEndpointRecord, String> {
    state.network_service.create_endpoint(req)
}

#[tauri::command]
pub fn list_network_endpoints(state: State<AppState>) -> Result<Vec<NetworkEndpointRecord>, String> {
    state.network_service.list_endpoints()
}

#[tauri::command]
pub fn delete_network_endpoint(id: String, state: State<AppState>) -> Result<(), String> {
    state.network_service.delete_endpoint(&id)
}

#[tauri::command]
pub fn assign_network_endpoint(
    environment_id: String,
    endpoint_id: Option<String>,
    state: State<AppState>,
) -> Result<(), String> {
    state.network_service.assign_endpoint_to_environment(&environment_id, endpoint_id.as_deref())
}

#[tauri::command]
pub fn check_environment_network(
    environment_id: String,
    state: State<AppState>,
) -> Result<NetworkCheckRecord, String> {
    state.network_service.check_network(&environment_id)
}

#[tauri::command]
pub fn record_guest_diagnostic_result(
    environment_id: String,
    observed_ipv4: String,
    observed_ipv6: Option<String>,
    dns_summary: String,
    latency_ms: u32,
    state: State<AppState>,
) -> Result<NetworkCheckRecord, String> {
    state.network_service.record_guest_diagnostic_result(
        &environment_id,
        &observed_ipv4,
        observed_ipv6.as_deref(),
        &dns_summary,
        latency_ms,
    )
}

#[tauri::command]
pub fn detect_duplicate_egress(state: State<AppState>) -> Result<Vec<DuplicateEgressWarning>, String> {
    state.network_service.detect_duplicate_egress()
}

#[tauri::command]
pub fn get_network_history(
    environment_id: String,
    limit: Option<usize>,
    state: State<AppState>,
) -> Result<Vec<NetworkCheckRecord>, String> {
    state.network_service.get_network_history(&environment_id, limit.unwrap_or(20))
}

// --- Channel Commands ---

#[tauri::command]
pub fn create_channel(
    req: CreateChannelRequest,
    state: State<AppState>,
) -> Result<ChannelRecord, String> {
    state.channel_service.create_channel(req)
}

#[tauri::command]
pub fn list_channels(state: State<AppState>) -> Result<Vec<ChannelRecord>, String> {
    state.channel_service.list_channels()
}

#[tauri::command]
pub fn update_channel_status(
    id: String,
    status: String,
    state: State<AppState>,
) -> Result<(), String> {
    state.channel_service.update_status(&id, &status)
}

#[tauri::command]
pub fn assign_channel_environment(
    channel_id: String,
    environment_id: Option<String>,
    state: State<AppState>,
) -> Result<(), String> {
    state.channel_service.assign_environment(&channel_id, environment_id.as_deref())
}

#[tauri::command]
pub fn delete_channel(id: String, state: State<AppState>) -> Result<(), String> {
    state.channel_service.delete_channel(&id)
}

// --- Audit & Security Commands ---

#[tauri::command]
pub fn list_audit_logs(
    limit: Option<usize>,
    state: State<AppState>,
) -> Result<Vec<AuditLogEntry>, String> {
    state.audit_service.list_logs(limit.unwrap_or(50))
}

#[tauri::command]
pub fn test_secret_vault() -> Result<bool, String> {
    let store = get_secret_store();
    store.test_vault().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn test_dpapi_vault() -> Result<bool, String> {
    // Backward-compatible command for existing tests and UI
    DpapiVault::test_vault().map_err(|e| e.to_string())
}
