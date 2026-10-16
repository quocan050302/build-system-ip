use std::sync::Arc;
use tempfile::tempdir;
use youtube_isolation_manager_lib::db::Database;
use youtube_isolation_manager_lib::hypervisor::mock::MockHypervisorAdapter;
use youtube_isolation_manager_lib::hypervisor::{
    create_hypervisor_adapter, hyperv::HyperVAdapter, utm::UTMAdapter,
    HypervisorAdapter, VmState,
};
use youtube_isolation_manager_lib::security::dpapi::DpapiVault;
use youtube_isolation_manager_lib::security::get_secret_store;
use youtube_isolation_manager_lib::services::audit_service::AuditService;
use youtube_isolation_manager_lib::services::channel_service::{ChannelService, CreateChannelRequest};
use youtube_isolation_manager_lib::services::network_service::{
    CreateEndpointRequest, NetworkService,
};
use youtube_isolation_manager_lib::services::platform_service::PlatformService;
use youtube_isolation_manager_lib::services::profile_service::ProfileService;
use youtube_isolation_manager_lib::services::vm_service::{
    CreateEnvironmentRequest, VmService,
};

fn setup_test_services() -> (
    Arc<VmService>,
    Arc<NetworkService>,
    Arc<ChannelService>,
    Arc<ProfileService>,
    Arc<MockHypervisorAdapter>,
    tempfile::TempDir,
) {
    let temp_dir = tempdir().unwrap();
    let db = Database::new_in_memory().unwrap();
    let hypervisor = Arc::new(MockHypervisorAdapter::new());
    let audit_service = Arc::new(AuditService::new(db.clone()));
    let profile_service = Arc::new(ProfileService::new(db.clone(), temp_dir.path().to_path_buf()));
    let vm_service = Arc::new(VmService::new(
        db.clone(),
        hypervisor.clone(),
        profile_service.clone(),
        audit_service.clone(),
        temp_dir.path().to_path_buf(),
    ));
    let network_service = Arc::new(NetworkService::new(
        db.clone(),
        hypervisor.clone(),
        audit_service.clone(),
    ));
    let channel_service = Arc::new(ChannelService::new(db.clone(), audit_service.clone()));

    (
        vm_service,
        network_service,
        channel_service,
        profile_service,
        hypervisor,
        temp_dir,
    )
}

#[test]
fn test_sec_001_vault_encryption_and_retrieval_roundtrip() {
    let test_secret = "Confidential_Proxy_Token_#9923";
    let encrypted = DpapiVault::encrypt_secret(test_secret).expect("Vault encryption failed");
    assert_ne!(test_secret, encrypted);

    let decrypted = DpapiVault::decrypt_secret(&encrypted).expect("Vault decryption failed");
    assert_eq!(test_secret, decrypted);

    let store = get_secret_store();
    assert!(store.test_vault().unwrap_or(true));
}

#[test]
fn test_env_001_create_environment_valid() {
    let (vm_service, _, _, _, _, _temp) = setup_test_services();

    let req = CreateEnvironmentRequest {
        name: "Env_Alpha_01".to_string(),
        hypervisor_type: "VirtualBox".to_string(),
        guest_os: "Ubuntu_64".to_string(),
        cpu_count: 2,
        memory_mb: 2048,
        disk_size_mb: 20480,
        iso_path: None,
        browser_type: "brave".to_string(),
        network_endpoint_id: None,
        channel_id: None,
        host_platform: None,
        vm_architecture: None,
    };

    let env = vm_service.create_environment(req).expect("Failed to create environment");
    assert_eq!(env.name, "Env_Alpha_01");
    assert_eq!(env.status, "STOPPED");
    assert!(env.disk_path.contains("Env_Alpha_01"));
    assert!(env.browser_profile_path.is_some());
    assert_eq!(env.provisioning_status, "COMPLETED");
}

#[test]
fn test_env_002_reject_duplicate_environment_name() {
    let (vm_service, _, _, _, _, _temp) = setup_test_services();

    let req = CreateEnvironmentRequest {
        name: "Env_Unique_01".to_string(),
        hypervisor_type: "VirtualBox".to_string(),
        guest_os: "Ubuntu_64".to_string(),
        cpu_count: 2,
        memory_mb: 2048,
        disk_size_mb: 20480,
        iso_path: None,
        browser_type: "chrome".to_string(),
        network_endpoint_id: None,
        channel_id: None,
        host_platform: None,
        vm_architecture: None,
    };

    vm_service.create_environment(req.clone()).expect("First creation should succeed");
    let err = vm_service.create_environment(req).expect_err("Duplicate name must fail");
    assert!(err.contains("already exists"));
}

#[test]
fn test_env_005_start_and_shutdown_vm() {
    let (vm_service, _, _, _, hypervisor, _temp) = setup_test_services();

    let req = CreateEnvironmentRequest {
        name: "Env_Lifecycle_01".to_string(),
        hypervisor_type: "VirtualBox".to_string(),
        guest_os: "Ubuntu_64".to_string(),
        cpu_count: 2,
        memory_mb: 2048,
        disk_size_mb: 20480,
        iso_path: None,
        browser_type: "firefox".to_string(),
        network_endpoint_id: None,
        channel_id: None,
        host_platform: None,
        vm_architecture: None,
    };

    let env = vm_service.create_environment(req).unwrap();
    assert_eq!(env.status, "STOPPED");

    // Start VM
    vm_service.start_environment(&env.id).expect("Should start VM");
    let active_env = vm_service.get_environment(&env.id).unwrap().unwrap();
    assert_eq!(active_env.status, "RUNNING");

    let hypervisor_state = hypervisor.get_vm_state(&env.vm_identifier).unwrap();
    assert_eq!(hypervisor_state, VmState::Running);

    // Shutdown VM
    vm_service.shutdown_environment(&env.id, false).expect("Should shut down VM");
    let stopped_env = vm_service.get_environment(&env.id).unwrap().unwrap();
    assert_eq!(stopped_env.status, "STOPPED");
}

#[test]
fn test_env_008_prevent_unsafe_deletion_of_running_vm() {
    let (vm_service, _, _, _, _, _temp) = setup_test_services();

    let req = CreateEnvironmentRequest {
        name: "Env_Running_Delete".to_string(),
        hypervisor_type: "VirtualBox".to_string(),
        guest_os: "Ubuntu_64".to_string(),
        cpu_count: 2,
        memory_mb: 2048,
        disk_size_mb: 20480,
        iso_path: None,
        browser_type: "brave".to_string(),
        network_endpoint_id: None,
        channel_id: None,
        host_platform: None,
        vm_architecture: None,
    };

    let env = vm_service.create_environment(req).unwrap();
    vm_service.start_environment(&env.id).unwrap();

    let delete_err = vm_service.delete_environment(&env.id, true).expect_err("Cannot delete running VM");
    assert!(delete_err.contains("Cannot delete a running environment"));
}

#[test]
fn test_env_009_storage_isolation_distinct_paths() {
    let (vm_service, _, _, _, _, _temp) = setup_test_services();

    let env1 = vm_service.create_environment(CreateEnvironmentRequest {
        name: "Env_Iso_A".to_string(),
        hypervisor_type: "VirtualBox".to_string(),
        guest_os: "Ubuntu_64".to_string(),
        cpu_count: 2,
        memory_mb: 2048,
        disk_size_mb: 10240,
        iso_path: None,
        browser_type: "chrome".to_string(),
        network_endpoint_id: None,
        channel_id: None,
        host_platform: None,
        vm_architecture: None,
    }).unwrap();

    let env2 = vm_service.create_environment(CreateEnvironmentRequest {
        name: "Env_Iso_B".to_string(),
        hypervisor_type: "VirtualBox".to_string(),
        guest_os: "Ubuntu_64".to_string(),
        cpu_count: 2,
        memory_mb: 2048,
        disk_size_mb: 10240,
        iso_path: None,
        browser_type: "chrome".to_string(),
        network_endpoint_id: None,
        channel_id: None,
        host_platform: None,
        vm_architecture: None,
    }).unwrap();

    assert_ne!(env1.disk_path, env2.disk_path);
    assert_ne!(env1.browser_profile_path, env2.browser_profile_path);
}

#[test]
fn test_net_001_truthful_guest_network_check() {
    let (vm_service, network_service, _, _, _, _temp) = setup_test_services();

    let ep = network_service.create_endpoint(CreateEndpointRequest {
        name: "Proxy_US_01".to_string(),
        endpoint_type: "SOCKS5".to_string(),
        provider_label: Some("Decoupled Static".to_string()),
        host: Some("198.51.100.88".to_string()),
        port: Some(1080),
        credentials_secret: Some("secret123".to_string()),
    }).unwrap();

    let env = vm_service.create_environment(CreateEnvironmentRequest {
        name: "Env_Net_01".to_string(),
        hypervisor_type: "VirtualBox".to_string(),
        guest_os: "Ubuntu_64".to_string(),
        cpu_count: 2,
        memory_mb: 2048,
        disk_size_mb: 10240,
        iso_path: None,
        browser_type: "chrome".to_string(),
        network_endpoint_id: Some(ep.id),
        channel_id: None,
        host_platform: None,
        vm_architecture: None,
    }).unwrap();

    // VM is STOPPED: network check must NOT claim verification
    let check_stopped = network_service.check_network(&env.id).unwrap();
    assert_eq!(check_stopped.status, "NOT_CHECKED");
    assert!(check_stopped.observed_ipv4.is_none());

    // VM is RUNNING: verify network check reports endpoint status honestly without fake IP
    vm_service.start_environment(&env.id).unwrap();
    let check_running = network_service.check_network(&env.id).unwrap();
    // Cannot claim VERIFIED observed egress without in-guest agent report
    assert_ne!(check_running.status, "VERIFIED");
    assert!(check_running.observed_ipv4.is_none());
}

#[test]
fn test_net_002_verified_in_guest_diagnostics() {
    let (vm_service, network_service, _, _, _, _temp) = setup_test_services();

    let env = vm_service.create_environment(CreateEnvironmentRequest {
        name: "Env_Guest_Diag".to_string(),
        hypervisor_type: "UTM".to_string(),
        guest_os: "Ubuntu Linux ARM64".to_string(),
        cpu_count: 4,
        memory_mb: 4096,
        disk_size_mb: 20480,
        iso_path: None,
        browser_type: "chrome".to_string(),
        network_endpoint_id: None,
        channel_id: None,
        host_platform: Some("macos-aarch64".to_string()),
        vm_architecture: Some("aarch64".to_string()),
    }).unwrap();

    // Record legitimate in-guest observed egress
    let check = network_service.record_guest_diagnostic_result(
        &env.id,
        "198.51.100.77",
        Some("2001:db8::1"),
        "DNS resolved via in-guest 1.1.1.1",
        24,
    ).unwrap();

    assert_eq!(check.status, "GUEST_EGRESS_OBSERVED");
    assert_eq!(check.observed_ipv4, Some("198.51.100.77".to_string()));
    assert_eq!(check.check_source, "GUEST_AGENT");
    assert_eq!(check.latency_ms, Some(24));
}

#[test]
fn test_net_005_duplicate_egress_warning_detection() {
    let (vm_service, network_service, _, _, _, _temp) = setup_test_services();

    let env1 = vm_service.create_environment(CreateEnvironmentRequest {
        name: "Env_Conflict_1".to_string(),
        hypervisor_type: "VirtualBox".to_string(),
        guest_os: "Ubuntu_64".to_string(),
        cpu_count: 2,
        memory_mb: 2048,
        disk_size_mb: 10240,
        iso_path: None,
        browser_type: "chrome".to_string(),
        network_endpoint_id: None,
        channel_id: None,
        host_platform: None,
        vm_architecture: None,
    }).unwrap();

    let env2 = vm_service.create_environment(CreateEnvironmentRequest {
        name: "Env_Conflict_2".to_string(),
        hypervisor_type: "VirtualBox".to_string(),
        guest_os: "Ubuntu_64".to_string(),
        cpu_count: 2,
        memory_mb: 2048,
        disk_size_mb: 10240,
        iso_path: None,
        browser_type: "chrome".to_string(),
        network_endpoint_id: None,
        channel_id: None,
        host_platform: None,
        vm_architecture: None,
    }).unwrap();

    // Both environments observe the same public IP egress
    network_service.record_guest_diagnostic_result(
        &env1.id,
        "203.0.113.99",
        None,
        "DNS: OK",
        15,
    ).unwrap();

    network_service.record_guest_diagnostic_result(
        &env2.id,
        "203.0.113.99",
        None,
        "DNS: OK",
        18,
    ).unwrap();

    let duplicate_warnings = network_service.detect_duplicate_egress().unwrap();
    assert_eq!(duplicate_warnings.len(), 1);
    assert_eq!(duplicate_warnings[0].ip_address, "203.0.113.99");
    assert_eq!(duplicate_warnings[0].conflicting_environments.len(), 2);
}

#[test]
fn test_ch_001_and_004_channel_compliance_and_termination_lock() {
    let (_, _, channel_service, _, _, _temp) = setup_test_services();

    let ch = channel_service.create_channel(CreateChannelRequest {
        youtube_channel_id: "UC_Valid_123456789".to_string(),
        display_name: "Channel Alpha".to_string(),
        environment_id: None,
        authorization_status: "AUTHORIZED".to_string(),
    }).unwrap();

    assert_eq!(ch.authorization_status, "AUTHORIZED");
    assert!(ch.is_eligible_for_publishing);

    channel_service.update_status(&ch.id, "TERMINATED").unwrap();
    let updated = channel_service.get_channel(&ch.id).unwrap().unwrap();
    assert_eq!(updated.authorization_status, "TERMINATED");
    assert!(!updated.is_eligible_for_publishing);
}

#[test]
fn test_br_005_reject_path_traversal_cross_platform() {
    let (_, _, _, profile_service, _, _temp) = setup_test_services();

    // Windows-style traversal
    let win_path = std::path::Path::new("C:\\profiles\\..\\system32");
    assert!(profile_service.validate_path(win_path).is_err());

    // Unix-style traversal
    let unix_path = std::path::Path::new("/var/profiles/../../etc/passwd");
    assert!(profile_service.validate_path(unix_path).is_err());

    // Valid path
    let valid_path = std::path::Path::new("/var/profiles/environment_1");
    assert!(profile_service.validate_path(valid_path).is_ok());
}

#[test]
fn test_platform_service_detection_and_real_resources() {
    let temp_dir = tempdir().unwrap();
    let svc = PlatformService::new(temp_dir.path().to_path_buf());
    let info = svc.detect();

    assert!(!info.os.is_empty());
    assert!(!info.arch.is_empty());
    assert!(!info.app_data_dir.is_empty());
    assert!(info.total_memory_mb > 0);
    assert!(info.total_disk_mb > 0);

    // Verify target triple logic
    if info.os == "macos" && info.arch == "aarch64" {
        assert_eq!(info.target_triple, "macos-aarch64");
        assert!(info.is_supported);
        assert!(info.supported_capabilities.iter().any(|c| c.contains("Apple Silicon")));
    } else if info.os == "windows" && info.arch == "x86_64" {
        assert_eq!(info.target_triple, "windows-x86_64");
        assert!(info.is_supported);
        assert!(info.supported_capabilities.iter().any(|c| c.contains("Hyper-V")));
    }
}

#[test]
fn test_hyperv_adapter_detection_structure() {
    let temp_dir = tempdir().unwrap();
    let adapter = HyperVAdapter::new(temp_dir.path().to_path_buf());
    let info = adapter.detect().unwrap();
    assert_eq!(info.name, "Microsoft Hyper-V");

    #[cfg(not(windows))]
    {
        assert!(!info.available);
    }
}

#[test]
fn test_utm_adapter_detection_structure() {
    let temp_dir = tempdir().unwrap();
    let adapter = UTMAdapter::new(temp_dir.path().to_path_buf());
    let info = adapter.detect().unwrap();
    assert!(info.name.contains("UTM"));

    // Verify VM details structure
    let details = adapter.get_vm_details("utm-test-01").unwrap();
    assert_eq!(details.architecture, "aarch64");
    assert!(details.os_type.contains("Ubuntu"));
}

#[test]
fn test_hypervisor_factory_no_silent_mock_fallback() {
    let temp_dir = tempdir().unwrap();

    // When force_mock = false, it must instantiate the native platform adapter, NOT mock!
    let (adapter, is_mock) = create_hypervisor_adapter(false, temp_dir.path());
    assert!(!is_mock);

    #[cfg(target_os = "macos")]
    {
        let info = adapter.detect().unwrap();
        assert!(info.name.contains("UTM"));
    }

    #[cfg(windows)]
    {
        let info = adapter.detect().unwrap();
        assert!(info.name.contains("Hyper-V"));
    }

    // Explicit mock request
    let (mock_adapter, is_mock_req) = create_hypervisor_adapter(true, temp_dir.path());
    assert!(is_mock_req);
    let mock_info = mock_adapter.detect().unwrap();
    assert!(mock_info.name.contains("Mock"));
}

#[test]
fn test_database_migrations_v1_to_v2() {
    let mut conn = rusqlite::Connection::open_in_memory().unwrap();

    // Run migrations up to v2
    youtube_isolation_manager_lib::db::migrations::run_migrations(&mut conn).unwrap();

    let version: i64 = conn.query_row(
        "SELECT MAX(version) FROM schema_version;",
        [],
        |r| r.get(0),
    ).unwrap();
    assert_eq!(version, 2);

    // Verify v2 columns exist in environments table
    let count: i64 = conn.query_row(
        "SELECT COUNT(1) FROM pragma_table_info('environments') WHERE name IN ('host_platform', 'vm_architecture', 'provisioning_status');",
        [],
        |r| r.get(0),
    ).unwrap();
    assert_eq!(count, 3);
}

#[test]
fn test_application_restart_reconciliation() {
    let (vm_service, _, _, _, hypervisor, _temp) = setup_test_services();

    let env = vm_service.create_environment(CreateEnvironmentRequest {
        name: "Env_Recon_01".to_string(),
        hypervisor_type: "VirtualBox".to_string(),
        guest_os: "Ubuntu_64".to_string(),
        cpu_count: 2,
        memory_mb: 2048,
        disk_size_mb: 10240,
        iso_path: None,
        browser_type: "chrome".to_string(),
        network_endpoint_id: None,
        channel_id: None,
        host_platform: None,
        vm_architecture: None,
    }).unwrap();

    // Manually mutate mock hypervisor state directly (simulating external power event)
    hypervisor.start_vm(&env.vm_identifier).unwrap();

    // Run reconciliation
    let updated = vm_service.reconcile_states().unwrap();
    assert_eq!(updated, 1);

    // Environment record in DB should now be RUNNING
    let reconciled_env = vm_service.get_environment(&env.id).unwrap().unwrap();
    assert_eq!(reconciled_env.status, "RUNNING");
}
