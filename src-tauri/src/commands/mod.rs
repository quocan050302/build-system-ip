use crate::hypervisor::{HostResources, HypervisorInfo};
use crate::security::{dpapi::DpapiVault, get_secret_store};
use crate::services::audit_service::AuditLogEntry;
use crate::services::channel_service::{ChannelRecord, CreateChannelRequest};
use crate::services::network_service::{
    CreateEndpointRequest, DuplicateEgressWarning, NetworkCheckRecord, NetworkEndpointRecord,
};
use crate::services::platform_service::PlatformInfo;
use crate::services::profile_service::{BrowserInfo, BrowserSession};
use crate::services::vm_service::{CreateEnvironmentRequest, EnvironmentRecord};
use crate::AppState;
use tauri::State;

// --- Platform, Browser & Host Commands ---

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

#[tauri::command]
pub fn detect_browsers(state: State<AppState>) -> Result<Vec<BrowserInfo>, String> {
    Ok(state.profile_service.detect_browsers())
}

#[tauri::command]
pub fn detect_edge_browser(state: State<AppState>) -> Result<BrowserInfo, String> {
    state.profile_service.detect_edge()
}

// --- Environment & Browser Profile Commands ---

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
pub fn get_environment(
    id: String,
    state: State<AppState>,
) -> Result<Option<EnvironmentRecord>, String> {
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
pub fn delete_environment(
    id: String,
    delete_disks: bool,
    state: State<AppState>,
) -> Result<(), String> {
    state.vm_service.delete_environment(&id, delete_disks)
}

#[tauri::command]
pub fn launch_browser_profile(
    environment_id: String,
    state: State<AppState>,
) -> Result<String, String> {
    state
        .profile_service
        .launch_isolated_browser(&environment_id)
}

#[tauri::command]
pub fn launch_browser_with_url(
    environment_id: String,
    url: Option<String>,
    state: State<AppState>,
) -> Result<BrowserSession, String> {
    state
        .profile_service
        .launch_browser_session(&environment_id, url.as_deref())
}

#[tauri::command]
pub fn stop_browser_profile(environment_id: String, state: State<AppState>) -> Result<(), String> {
    state.profile_service.stop_browser_session(&environment_id)
}

#[tauri::command]
pub fn get_browser_status(
    environment_id: String,
    state: State<AppState>,
) -> Result<String, String> {
    let status = state
        .profile_service
        .get_browser_session_status(&environment_id)?;
    Ok(status.as_str().to_string())
}

#[tauri::command]
pub fn open_profile_folder(
    environment_id: String,
    state: State<AppState>,
) -> Result<String, String> {
    state.profile_service.open_profile_folder(&environment_id)
}

#[tauri::command]
pub fn update_environment_startup_url(
    environment_id: String,
    startup_url: String,
    state: State<AppState>,
) -> Result<(), String> {
    state
        .profile_service
        .update_startup_url(&environment_id, &startup_url)
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
pub fn list_network_endpoints(
    state: State<AppState>,
) -> Result<Vec<NetworkEndpointRecord>, String> {
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
    state
        .network_service
        .assign_endpoint_to_environment(&environment_id, endpoint_id.as_deref())
}

#[tauri::command]
pub fn check_environment_network(
    environment_id: String,
    state: State<AppState>,
) -> Result<NetworkCheckRecord, String> {
    state.network_service.check_network(&environment_id)
}

#[tauri::command]
pub fn verify_browser_egress(
    environment_id: String,
    state: State<AppState>,
) -> Result<NetworkCheckRecord, String> {
    state
        .network_service
        .verify_browser_egress(&environment_id, &state.profile_service)
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
pub fn detect_duplicate_egress(
    state: State<AppState>,
) -> Result<Vec<DuplicateEgressWarning>, String> {
    state.network_service.detect_duplicate_egress()
}

#[tauri::command]
pub fn get_network_history(
    environment_id: String,
    limit: Option<usize>,
    state: State<AppState>,
) -> Result<Vec<NetworkCheckRecord>, String> {
    state
        .network_service
        .get_network_history(&environment_id, limit.unwrap_or(20))
}

// --- Channel & Workspace Commands ---

#[tauri::command]
pub fn create_channel(
    req: CreateChannelRequest,
    state: State<AppState>,
) -> Result<ChannelRecord, String> {
    state.channel_service.create_channel(req)
}

#[tauri::command]
pub fn update_channel_youtube_id(
    id: String,
    youtube_channel_id: String,
    state: State<AppState>,
) -> Result<(), String> {
    state
        .channel_service
        .update_channel_id(&id, &youtube_channel_id)
}

#[tauri::command]
pub fn update_channel_gumroad(
    id: String,
    gumroad_url: Option<String>,
    utm_source: Option<String>,
    utm_medium: Option<String>,
    utm_campaign: Option<String>,
    state: State<AppState>,
) -> Result<ChannelRecord, String> {
    state.channel_service.update_gumroad_tracking(
        &id,
        gumroad_url.as_deref(),
        utm_source.as_deref(),
        utm_medium.as_deref(),
        utm_campaign.as_deref(),
    )
}

#[tauri::command]
pub fn open_channel_in_browser(
    channel_id: String,
    open_analytics: bool,
    state: State<AppState>,
) -> Result<BrowserSession, String> {
    let ch = state
        .channel_service
        .get_channel(&channel_id)?
        .ok_or_else(|| format!("Channel {} not found", channel_id))?;

    if ch.authorization_status == "TERMINATED" || ch.authorization_status == "RESTRICTED" {
        return Err(format!(
            "Account '{}' is marked as {} and locked against publishing/browser launch.",
            ch.display_name, ch.authorization_status
        ));
    }

    let env_id = ch.environment_id.ok_or_else(|| {
        format!(
            "Account '{}' does not have an assigned browser environment. Assign an environment first.",
            ch.display_name
        )
    })?;

    let (default_profile, default_analytics, _) =
        crate::services::channel_service::ChannelService::default_urls_for_platform(&ch.platform);

    let target_url = if open_analytics {
        ch.analytics_url.unwrap_or(default_analytics)
    } else {
        ch.profile_url.unwrap_or(default_profile)
    };

    state
        .profile_service
        .launch_browser_session(&env_id, Some(&target_url))
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
    state
        .channel_service
        .assign_environment(&channel_id, environment_id.as_deref())
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
    DpapiVault::test_vault().map_err(|e| e.to_string())
}
