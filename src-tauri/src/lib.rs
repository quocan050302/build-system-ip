pub mod commands;
pub mod db;
pub mod hypervisor;
pub mod security;
pub mod services;

use db::Database;
use hypervisor::create_hypervisor_adapter;
use services::audit_service::AuditService;
use services::channel_service::ChannelService;
use services::network_service::NetworkService;
use services::platform_service::PlatformService;
use services::profile_service::ProfileService;
use services::vm_service::VmService;
use std::path::PathBuf;
use std::sync::Arc;

pub struct AppState {
    pub db: Database,
    pub vm_service: Arc<VmService>,
    pub network_service: Arc<NetworkService>,
    pub channel_service: Arc<ChannelService>,
    pub profile_service: Arc<ProfileService>,
    pub audit_service: Arc<AuditService>,
    pub platform_service: Arc<PlatformService>,
    pub is_mock_mode: bool,
}

pub fn init_services(data_dir: PathBuf, force_mock: bool) -> AppState {
    let db_path = data_dir.join("data").join("isolation_manager.db");
    let db = Database::new(&db_path).unwrap_or_else(|_| Database::new_in_memory().unwrap());

    // Never silently fall back to mock mode in production
    let (hypervisor, is_mock_mode) = create_hypervisor_adapter(force_mock, &data_dir);

    let audit_service = Arc::new(AuditService::new(db.clone()));
    let profile_service = Arc::new(ProfileService::new(db.clone(), data_dir.clone()));
    let platform_service = Arc::new(PlatformService::new(data_dir.clone()));
    let vm_service = Arc::new(VmService::new(
        db.clone(),
        hypervisor.clone(),
        profile_service.clone(),
        audit_service.clone(),
        data_dir,
    ));
    let network_service = Arc::new(NetworkService::new(
        db.clone(),
        hypervisor.clone(),
        audit_service.clone(),
    ));
    let channel_service = Arc::new(ChannelService::new(db.clone(), audit_service.clone()));

    // Reconcile VM states on startup
    let _ = vm_service.reconcile_states();

    AppState {
        db,
        vm_service,
        network_service,
        channel_service,
        profile_service,
        audit_service,
        platform_service,
        is_mock_mode,
    }
}

pub fn run() {
    let data_dir = PlatformService::resolve_default_data_dir();
    let force_mock = std::env::var("USE_MOCK_HYPERVISOR").unwrap_or_default() == "1";
    let state = init_services(data_dir, force_mock);

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::get_platform_info,
            commands::get_hypervisor_info,
            commands::get_host_resources,
            commands::create_environment,
            commands::list_environments,
            commands::get_environment,
            commands::start_environment,
            commands::shutdown_environment,
            commands::open_vm_console,
            commands::launch_guest_browser,
            commands::reconcile_environment_states,
            commands::delete_environment,
            commands::launch_browser_profile,
            commands::create_network_endpoint,
            commands::list_network_endpoints,
            commands::delete_network_endpoint,
            commands::assign_network_endpoint,
            commands::check_environment_network,
            commands::record_guest_diagnostic_result,
            commands::detect_duplicate_egress,
            commands::get_network_history,
            commands::create_channel,
            commands::list_channels,
            commands::update_channel_status,
            commands::assign_channel_environment,
            commands::delete_channel,
            commands::list_audit_logs,
            commands::test_secret_vault,
            commands::test_dpapi_vault,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
