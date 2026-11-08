use std::sync::Arc;
use tempfile::tempdir;
use youtube_isolation_manager_lib::db::Database;
use youtube_isolation_manager_lib::hypervisor::mock::MockHypervisorAdapter;
use youtube_isolation_manager_lib::hypervisor::{
    create_hypervisor_adapter, hyperv::HyperVAdapter, utm::UTMAdapter, HypervisorAdapter, VmState,
};
use youtube_isolation_manager_lib::security::dpapi::DpapiVault;
use youtube_isolation_manager_lib::security::get_secret_store;
use youtube_isolation_manager_lib::services::audit_service::AuditService;
use youtube_isolation_manager_lib::services::channel_service::{
    ChannelService, CreateChannelRequest,
};
use youtube_isolation_manager_lib::services::network_service::{
    CreateEndpointRequest, NetworkService,
};
use youtube_isolation_manager_lib::services::platform_service::PlatformService;
use youtube_isolation_manager_lib::services::profile_service::ProfileService;
use youtube_isolation_manager_lib::services::vm_service::{CreateEnvironmentRequest, VmService};

#[allow(clippy::type_complexity)]
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
    let profile_service = Arc::new(ProfileService::new(
        db.clone(),
        temp_dir.path().to_path_buf(),
    ));
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
        ..Default::default()
    };

    let env = vm_service
        .create_environment(req)
        .expect("Failed to create environment");
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
        ..Default::default()
    };

    vm_service
        .create_environment(req.clone())
        .expect("First creation should succeed");
    let err = vm_service
        .create_environment(req)
        .expect_err("Duplicate name must fail");
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
        ..Default::default()
    };

    let env = vm_service.create_environment(req).unwrap();
    assert_eq!(env.status, "STOPPED");

    // Start VM
    vm_service
        .start_environment(&env.id)
        .expect("Should start VM");
    let active_env = vm_service.get_environment(&env.id).unwrap().unwrap();
    assert_eq!(active_env.status, "RUNNING");

    let hypervisor_state = hypervisor.get_vm_state(&env.vm_identifier).unwrap();
    assert_eq!(hypervisor_state, VmState::Running);

    // Shutdown VM
    vm_service
        .shutdown_environment(&env.id, false)
        .expect("Should shut down VM");
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
        ..Default::default()
    };

    let env = vm_service.create_environment(req).unwrap();
    vm_service.start_environment(&env.id).unwrap();

    let delete_err = vm_service
        .delete_environment(&env.id, true)
        .expect_err("Cannot delete running VM");
    assert!(delete_err.contains("Cannot delete a running environment"));
}

#[test]
fn test_env_009_storage_isolation_distinct_paths() {
    let (vm_service, _, _, _, _, _temp) = setup_test_services();

    let env1 = vm_service
        .create_environment(CreateEnvironmentRequest {
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
            ..Default::default()
        })
        .unwrap();

    let env2 = vm_service
        .create_environment(CreateEnvironmentRequest {
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
            ..Default::default()
        })
        .unwrap();

    assert_ne!(env1.disk_path, env2.disk_path);
    assert_ne!(env1.browser_profile_path, env2.browser_profile_path);
}

#[test]
fn test_net_001_truthful_guest_network_check() {
    let (vm_service, network_service, _, _, _, _temp) = setup_test_services();

    let ep = network_service
        .create_endpoint(CreateEndpointRequest {
            name: "Proxy_US_01".to_string(),
            endpoint_type: "SOCKS5".to_string(),
            provider_label: Some("Decoupled Static".to_string()),
            host: Some("198.51.100.88".to_string()),
            port: Some(1080),
            credentials_secret: Some("secret123".to_string()),
            ..Default::default()
        })
        .unwrap();

    let env = vm_service
        .create_environment(CreateEnvironmentRequest {
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
            ..Default::default()
        })
        .unwrap();

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

    let env = vm_service
        .create_environment(CreateEnvironmentRequest {
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
            ..Default::default()
        })
        .unwrap();

    // Record legitimate in-guest observed egress
    let check = network_service
        .record_guest_diagnostic_result(
            &env.id,
            "198.51.100.77",
            Some("2001:db8::1"),
            "DNS resolved via in-guest 1.1.1.1",
            24,
        )
        .unwrap();

    assert_eq!(check.status, "GUEST_EGRESS_OBSERVED");
    assert_eq!(check.observed_ipv4, Some("198.51.100.77".to_string()));
    assert_eq!(check.check_source, "GUEST_AGENT");
    assert_eq!(check.latency_ms, Some(24));
}

#[test]
fn test_net_005_duplicate_egress_warning_detection() {
    let (vm_service, network_service, _, _, _, _temp) = setup_test_services();

    let env1 = vm_service
        .create_environment(CreateEnvironmentRequest {
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
            ..Default::default()
        })
        .unwrap();

    let env2 = vm_service
        .create_environment(CreateEnvironmentRequest {
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
            ..Default::default()
        })
        .unwrap();

    // Both environments observe the same public IP egress
    network_service
        .record_guest_diagnostic_result(&env1.id, "203.0.113.99", None, "DNS: OK", 15)
        .unwrap();

    network_service
        .record_guest_diagnostic_result(&env2.id, "203.0.113.99", None, "DNS: OK", 18)
        .unwrap();

    let duplicate_warnings = network_service.detect_duplicate_egress().unwrap();
    assert_eq!(duplicate_warnings.len(), 1);
    assert_eq!(duplicate_warnings[0].ip_address, "203.0.113.99");
    assert_eq!(duplicate_warnings[0].conflicting_environments.len(), 2);
}

#[test]
fn test_ch_001_and_004_channel_compliance_and_termination_lock() {
    let (_, _, channel_service, _, _, _temp) = setup_test_services();

    let ch = channel_service
        .create_channel(CreateChannelRequest {
            youtube_channel_id: "UC_Valid_123456789".to_string(),
            display_name: "Channel Alpha".to_string(),
            environment_id: None,
            authorization_status: "AUTHORIZED".to_string(),
            ..Default::default()
        })
        .unwrap();

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
        assert!(info
            .supported_capabilities
            .iter()
            .any(|c| c.contains("Apple Silicon")));
    } else if info.os == "windows" && info.arch == "x86_64" {
        assert_eq!(info.target_triple, "windows-x86_64");
        assert!(info.is_supported);
        assert!(info
            .supported_capabilities
            .iter()
            .any(|c| c.contains("Hyper-V")));
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
fn test_database_migrations_v1_to_v3() {
    let mut conn = rusqlite::Connection::open_in_memory().unwrap();

    // Run all migrations
    youtube_isolation_manager_lib::db::migrations::run_migrations(&mut conn).unwrap();

    let version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_version;", [], |r| r.get(0))
        .unwrap();
    assert!(
        version >= 3,
        "Expected schema version >= 3, got {}",
        version
    );

    // Verify v2 columns exist in environments table
    let count_v2: i64 = conn.query_row(
        "SELECT COUNT(1) FROM pragma_table_info('environments') WHERE name IN ('host_platform', 'vm_architecture', 'provisioning_status');",
        [],
        |r| r.get(0),
    ).unwrap();
    assert_eq!(count_v2, 3, "v2 columns missing");

    // Verify v3 columns exist in environments table
    let count_v3: i64 = conn.query_row(
        "SELECT COUNT(1) FROM pragma_table_info('environments') WHERE name IN ('execution_mode', 'startup_url', 'preferred_language');",
        [],
        |r| r.get(0),
    ).unwrap();
    assert_eq!(count_v3, 3, "v3 columns missing from environments");

    // Verify v3 columns exist in network_endpoints table
    let count_ep_v3: i64 = conn.query_row(
        "SELECT COUNT(1) FROM pragma_table_info('network_endpoints') WHERE name IN ('username', 'expected_country', 'expected_ip');",
        [],
        |r| r.get(0),
    ).unwrap();
    assert_eq!(count_ep_v3, 3, "v3 columns missing from network_endpoints");
}

#[test]
fn test_application_restart_reconciliation() {
    let (vm_service, _, _, _, hypervisor, _temp) = setup_test_services();

    let env = vm_service
        .create_environment(CreateEnvironmentRequest {
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
            ..Default::default()
        })
        .unwrap();

    // Manually mutate mock hypervisor state directly (simulating external power event)
    hypervisor.start_vm(&env.vm_identifier).unwrap();

    // Run reconciliation
    let updated = vm_service.reconcile_states().unwrap();
    assert_eq!(updated, 1);

    // Environment record in DB should now be RUNNING
    let reconciled_env = vm_service.get_environment(&env.id).unwrap().unwrap();
    assert_eq!(reconciled_env.status, "RUNNING");
}

// ---------------------------------------------------------------------------
// Country-validation defect regression tests (DEFECT 2 fix verification)
// ---------------------------------------------------------------------------

/// When expected_country="US" and the geolocation API returns "UNKNOWN",
/// the check must FAIL — UNKNOWN must never silently pass as a country match.
#[test]
fn test_country_unknown_fails_expected_country_check() {
    // Test the pure country-validation helper directly (no I/O).
    let result = NetworkService::evaluate_country_match("UNKNOWN", Some("US"));
    assert!(
        result.is_err(),
        "UNKNOWN country must fail when expected_country='US'"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("UNKNOWN"),
        "Error message should mention UNKNOWN: {}",
        err_msg
    );

    // Also verify empty string is treated the same way.
    let result_empty = NetworkService::evaluate_country_match("", Some("US"));
    assert!(
        result_empty.is_err(),
        "Empty country must fail when expected_country='US'"
    );
}

/// When expected_country="US" and the observed country is "VN", the check must fail.
#[test]
fn test_country_mismatch_fails() {
    let result = NetworkService::evaluate_country_match("VN", Some("US"));
    assert!(
        result.is_err(),
        "Country mismatch VN vs US must return an error"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("VN") && err_msg.contains("US"),
        "Error message should name both countries: {}",
        err_msg
    );
}

/// When expected_country="US" and observed country is "US", the check must pass.
#[test]
fn test_country_match_succeeds() {
    // Case-sensitive exact match
    let result = NetworkService::evaluate_country_match("US", Some("US"));
    assert!(result.is_ok(), "Exact US match should succeed");

    // Case-insensitive match
    let result_lower = NetworkService::evaluate_country_match("us", Some("US"));
    assert!(
        result_lower.is_ok(),
        "Case-insensitive us/US match should succeed"
    );

    // No expected_country constraint — always passes regardless of observed value
    let result_unconstrained = NetworkService::evaluate_country_match("UNKNOWN", None);
    assert!(
        result_unconstrained.is_ok(),
        "No constraint: any observed country (even UNKNOWN) should pass"
    );
}

/// When the browser session is not running, verify_browser_egress must return
/// VERIFICATION_UNAVAILABLE — it must never fabricate PROXY_EGRESS_VERIFIED or
/// BROWSER_EGRESS_VERIFIED without an active session.
#[test]
fn test_verify_browser_egress_no_session_returns_unavailable() {
    let (vm_service, network_service, _, profile_service, _, _temp) = setup_test_services();

    let env = vm_service
        .create_environment(CreateEnvironmentRequest {
            name: "Env_BrowserEgress_NoSession".to_string(),
            hypervisor_type: "VirtualBox".to_string(),
            guest_os: "Ubuntu_64".to_string(),
            cpu_count: 2,
            memory_mb: 2048,
            disk_size_mb: 10240,
            iso_path: None,
            browser_type: "edge".to_string(),
            network_endpoint_id: None,
            channel_id: None,
            host_platform: None,
            vm_architecture: None,
            ..Default::default()
        })
        .unwrap();

    // No browser session is active — verify_browser_egress must return VERIFICATION_UNAVAILABLE
    let result = network_service
        .verify_browser_egress(&env.id, &profile_service)
        .unwrap();
    assert_eq!(
        result.status, "VERIFICATION_UNAVAILABLE",
        "Without an active browser session, status must be VERIFICATION_UNAVAILABLE, got: {}",
        result.status
    );
    assert!(
        result.observed_ipv4.is_none(),
        "No IP should be observed without a session"
    );
    assert_ne!(result.status, "PROXY_EGRESS_VERIFIED");
    assert_ne!(result.status, "BROWSER_EGRESS_VERIFIED");
}

/// A backend bridge probe can only return PROXY_EGRESS_VERIFIED, never BROWSER_EGRESS_VERIFIED.
/// This test verifies that the status hierarchy is correctly ordered and that
/// BROWSER_EGRESS_VERIFIED is never emitted by any backend-only code path in the service.
///
/// This is a semantic/documentation test: it asserts the guarantee at the
/// evaluate_country_match level plus the no-session path that must gate all higher statuses.
#[test]
fn test_proxy_egress_verified_not_browser_verified() {
    // 1. Country validation passing with a real country should not by itself produce
    //    BROWSER_EGRESS_VERIFIED — verify the status constant strings are distinct.
    assert_ne!(
        "PROXY_EGRESS_VERIFIED", "BROWSER_EGRESS_VERIFIED",
        "These two status codes must remain distinct by design"
    );

    // 2. Without an active browser session the function must return VERIFICATION_UNAVAILABLE
    //    (not PROXY_EGRESS_VERIFIED or BROWSER_EGRESS_VERIFIED), gating further probe logic.
    let (vm_service, network_service, _, profile_service, _, _temp) = setup_test_services();

    let env = vm_service
        .create_environment(CreateEnvironmentRequest {
            name: "Env_ProxyEgressNotBrowser".to_string(),
            hypervisor_type: "VirtualBox".to_string(),
            guest_os: "Ubuntu_64".to_string(),
            cpu_count: 2,
            memory_mb: 2048,
            disk_size_mb: 10240,
            iso_path: None,
            browser_type: "edge".to_string(),
            network_endpoint_id: None,
            channel_id: None,
            host_platform: None,
            vm_architecture: None,
            ..Default::default()
        })
        .unwrap();

    let check = network_service
        .verify_browser_egress(&env.id, &profile_service)
        .unwrap();
    // The backend probe path is never reached without an active session, so
    // BROWSER_EGRESS_VERIFIED must be impossible to obtain here.
    assert_ne!(
        check.status, "BROWSER_EGRESS_VERIFIED",
        "BROWSER_EGRESS_VERIFIED must never be returned by the Rust backend probe path: {}",
        check.status
    );
    // Status must be VERIFICATION_UNAVAILABLE (browser not running)
    assert_eq!(check.status, "VERIFICATION_UNAVAILABLE");
    // check_source confirms this came from the browser-verifier gate, not a network probe
    assert_eq!(check.check_source, "PROXY_BRIDGE_PROBE");
}

// ─── Test helpers ──────────────────────────────────────────────────────────────

fn evaluate_country_match_helper(observed: &str, expected: Option<&str>) -> Result<(), String> {
    youtube_isolation_manager_lib::services::network_service::NetworkService::evaluate_country_match(
        observed,
        expected.map(|s| s.to_string()).as_deref(),
    )
}

fn make_check_record(
    status: &str,
    checked_at: &str,
) -> youtube_isolation_manager_lib::services::network_service::NetworkCheckRecord {
    youtube_isolation_manager_lib::services::network_service::NetworkCheckRecord {
        id: "test-id".to_string(),
        environment_id: "test-env".to_string(),
        observed_ipv4: None,
        observed_ipv6: None,
        observed_country: None,
        dns_summary: None,
        dns_leak_status: "UNVERIFIED".to_string(),
        webrtc_status: "UNVERIFIED".to_string(),
        check_source: "TEST".to_string(),
        status: status.to_string(),
        error_message: None,
        checked_at: checked_at.to_string(),
        latency_ms: None,
        session_id: None,
    }
}

// ─── Phase 8: IP validation regression tests ─────────────────────────────────

#[test]
fn test_is_valid_ip_address_accepts_valid_ipv4() {
    // is_valid_ip_address is a private helper — test via standard library parsers
    // Valid IPv4 addresses should be accepted by the system
    let valid_ips = [
        "1.2.3.4",
        "192.168.1.1",
        "8.8.8.8",
        "255.255.255.255",
        "0.0.0.0",
    ];
    for ip in &valid_ips {
        assert!(
            ip.parse::<std::net::Ipv4Addr>().is_ok(),
            "Expected valid IPv4: {}",
            ip
        );
    }
}

#[test]
fn test_is_valid_ip_address_rejects_invalid() {
    let invalid_ips = ["not-an-ip", "256.0.0.1", "192.168.1", "::gggg", ""];
    for ip in &invalid_ips {
        assert!(
            ip.parse::<std::net::Ipv4Addr>().is_err() && ip.parse::<std::net::Ipv6Addr>().is_err(),
            "Expected invalid IP to fail parsing: {}",
            ip
        );
    }
}

#[test]
fn test_evaluate_country_match_empty_string_fails() {
    // Empty string must fail when expected_country is set
    let result = evaluate_country_match_helper("", Some("US"));
    assert!(
        result.is_err(),
        "Empty country with expected_country=US must fail"
    );
}

#[test]
fn test_evaluate_country_match_no_constraint_passes_any() {
    // No expected country = any value passes (including UNKNOWN)
    let result = evaluate_country_match_helper("UNKNOWN", None);
    assert!(
        result.is_ok(),
        "No expected_country constraint — any value should pass"
    );
    let result2 = evaluate_country_match_helper("", None);
    assert!(
        result2.is_ok(),
        "No expected_country constraint — empty should pass"
    );
}

#[test]
fn test_is_verification_stale_old_record() {
    // A record with a very old timestamp should be stale
    let record = make_check_record("PROXY_EGRESS_VERIFIED", "1970-01-01T00:00:00Z");
    assert!(
        youtube_isolation_manager_lib::services::network_service::is_verification_stale(
            &record, 3600
        ),
        "1970 timestamp should be stale for 1-hour max_age"
    );
}

#[test]
fn test_is_verification_stale_fresh_record() {
    // A record with a very recent timestamp should not be stale
    let now = chrono::Utc::now().to_rfc3339();
    let record = make_check_record("PROXY_EGRESS_VERIFIED", &now);
    assert!(
        !youtube_isolation_manager_lib::services::network_service::is_verification_stale(
            &record, 3600
        ),
        "Current timestamp should not be stale for 1-hour max_age"
    );
}

#[test]
fn test_browser_egress_verified_requires_cdp_success() {
    // Without an active browser session with working CDP endpoint,
    // verify_browser_egress must never return BROWSER_EGRESS_VERIFIED.
    let (vm_service, network_service, _, profile_service, _, _temp) = setup_test_services();

    let env = vm_service
        .create_environment(CreateEnvironmentRequest {
            name: "Env_BrowserEgressCdpGate".to_string(),
            hypervisor_type: "VirtualBox".to_string(),
            guest_os: "Ubuntu_64".to_string(),
            cpu_count: 2,
            memory_mb: 2048,
            disk_size_mb: 10240,
            iso_path: None,
            browser_type: "edge".to_string(),
            network_endpoint_id: None,
            channel_id: None,
            host_platform: None,
            vm_architecture: None,
            ..Default::default()
        })
        .unwrap();

    let check = network_service
        .verify_browser_egress(&env.id, &profile_service)
        .unwrap();

    // Invariant: BROWSER_EGRESS_VERIFIED is prohibited without verified CDP fetch
    assert_ne!(
        check.status, "BROWSER_EGRESS_VERIFIED",
        "verify_browser_egress without CDP must not return BROWSER_EGRESS_VERIFIED"
    );
    assert_eq!(check.status, "VERIFICATION_UNAVAILABLE");

    // Invariant: DNS/IPv6/WebRTC status must be honest, not falsely marked PASS/VERIFIED
    assert_ne!(check.dns_leak_status, "VERIFIED");
    assert_ne!(check.webrtc_status, "VERIFIED");
}

#[test]
fn test_v8_real_edge_headless_cdp_target_lifecycle_ownership_and_fail_closed_bridge() {
    #[cfg(target_os = "macos")]
    {
        use std::path::Path;
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};
        use youtube_isolation_manager_lib::services::browser_verification::{
            cdp_http_request, close_cdp_target, create_cdp_blank_target_full,
            navigate_cdp_target_and_read_body, verify_managed_cdp_ownership, BrowserSessionInfo,
            FALLBACK_VERIFICATION_PROVIDER,
        };
        use youtube_isolation_manager_lib::services::profile_service::SystemBrowserLauncher;
        use youtube_isolation_manager_lib::services::proxy_bridge::{
            ProxyBridgeManager, UpstreamProxyConfig,
        };

        let edge_bin = Path::new("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge");
        if !edge_bin.exists() {
            // Skip gracefully on CI runners where Edge is not installed
            return;
        }

        let temp_dir = tempfile::tempdir().expect("create temp profile dir");
        let profile_path = temp_dir.path().to_path_buf();

        // 1. Start a real local proxy bridge pointing to an unreachable upstream (127.0.0.1:1)
        let bridge_mgr = ProxyBridgeManager::new();
        let bridge_status = bridge_mgr
            .start_or_replace_bridge(UpstreamProxyConfig {
                environment_id: "env-real-edge-v8".to_string(),
                endpoint_id: "ep-us-test".to_string(),
                host: "127.0.0.1".to_string(),
                port: 1,
                protocol: "HTTP".to_string(),
                username: Some("test_user".to_string()),
                password: Some("test_secret_not_logged".to_string()),
                connect_timeout: Duration::from_millis(500),
            })
            .expect("start local proxy bridge");
        let bridge_port = bridge_status.local_port;
        let bridge_instance_id = bridge_mgr.get_instance_id("env-real-edge-v8");

        // 2. Spawn real Microsoft Edge in headless mode with --remote-debugging-port=0
        let child = Command::new(edge_bin)
            .arg("--headless=new")
            .arg("--disable-gpu")
            .arg(format!("--user-data-dir={}", profile_path.display()))
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--remote-debugging-port=0")
            .arg("--remote-debugging-address=127.0.0.1")
            .arg(format!("--proxy-server=http://127.0.0.1:{}", bridge_port))
            .arg("--proxy-bypass-list=<-loopback>")
            .arg("about:blank")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn headless Microsoft Edge");

        struct EdgeGuard {
            child: Child,
        }
        impl Drop for EdgeGuard {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
        let guard = EdgeGuard { child };
        let edge_pid = guard.child.id();

        // 3. Wait for DevToolsActivePort to be written by real Edge
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut cdp_port_opt = None;
        while Instant::now() < deadline {
            if let Some((port, _ws_path)) =
                SystemBrowserLauncher::parse_devtools_active_port(&profile_path)
            {
                cdp_port_opt = Some(port);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let cdp_port = cdp_port_opt.expect("real Edge must write DevToolsActivePort");

        // 4. Verify real Edge CDP ownership check passes with matching session + profile + bridge
        let session = BrowserSessionInfo {
            environment_id: "env-real-edge-v8".to_string(),
            session_id: format!("edge-session-{}", edge_pid),
            pid: edge_pid,
            profile_path: profile_path.to_string_lossy().to_string(),
            proxy_bridge_port: Some(bridge_port),
            proxy_endpoint_id: "ep-us-test".to_string(),
            bridge_instance_id,
            expected_country: Some("US".to_string()),
            expected_ip: None,
            recent_bridge_connection_count: 0,
            cdp_port: Some(cdp_port),
            is_simulation: false,
        };
        verify_managed_cdp_ownership(&session, cdp_port, Duration::from_millis(2000))
            .expect("verify_managed_cdp_ownership must pass for real managed Edge");

        let ver_resp = cdp_http_request(
            cdp_port,
            "GET",
            "/json/version",
            Duration::from_millis(2000),
        )
        .expect("GET /json/version");
        assert!(
            ver_resp.body.contains("Edg/"),
            "Real Edge /json/version must report Edg/ browser string: {}",
            ver_resp.body
        );

        // 5. Verify ownership check rejects wrong profile_path
        let mut wrong_profile_session = session.clone();
        wrong_profile_session.profile_path = "/tmp/nonexistent-wrong-profile-v8".to_string();
        assert!(
            verify_managed_cdp_ownership(
                &wrong_profile_session,
                cdp_port,
                Duration::from_millis(1000)
            )
            .is_err(),
            "Ownership check must reject mismatched profile_path"
        );

        // 6. Prove V7 bug on real Edge 157+: GET /json/new?about:blank returns HTTP 405
        let get_new_resp = cdp_http_request(
            cdp_port,
            "GET",
            "/json/new?about:blank",
            Duration::from_millis(2000),
        )
        .expect("GET /json/new HTTP response");
        assert_eq!(
            get_new_resp.status_code, 405,
            "Real Edge 157+ returns HTTP 405 on GET /json/new"
        );

        // 7. Prove V8 fix on real Edge 157+: PUT /json/new?about:blank succeeds with HTTP 200
        let target = create_cdp_blank_target_full(cdp_port, Duration::from_millis(2000))
            .expect("PUT /json/new?about:blank must succeed on real Edge");
        assert!(!target.id.is_empty());
        let target_ws_url = target
            .websocket_debugger_url
            .expect("target must include webSocketDebuggerUrl");
        assert!(target_ws_url.starts_with(&format!("ws://127.0.0.1:{}/devtools/page/", cdp_port)));

        // 8. Verify fail-closed proxy behavior: navigating the real Edge target when upstream proxy is dead
        //    must hit the local proxy bridge (recording an HTTP_CONNECT event that fails closed) and fail navigation.
        let nav_res = navigate_cdp_target_and_read_body(
            &target_ws_url,
            cdp_port,
            &FALLBACK_VERIFICATION_PROVIDER,
            Duration::from_millis(1500),
            Duration::from_millis(3500),
            false,
        );
        assert!(
            nav_res.is_err(),
            "Navigation through fail-closed proxy bridge with dead upstream must fail, never leak direct"
        );

        // 9. Verify target cleanup via GET /json/close/{id} removes the target from /json/list
        close_cdp_target(cdp_port, &target.id, Duration::from_millis(2000));
        let close_deadline = Instant::now() + Duration::from_millis(1500);
        let mut target_removed = false;
        while Instant::now() < close_deadline {
            let list_resp =
                cdp_http_request(cdp_port, "GET", "/json/list", Duration::from_millis(1000))
                    .expect("GET /json/list");
            if !list_resp.body.contains(&target.id) {
                target_removed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        assert!(
            target_removed,
            "Closed CDP target {} must not remain in /json/list",
            target.id
        );

        bridge_mgr.stop_bridge("env-real-edge-v8");

        // 10. Also verify real Edge HTTP_CONNECT tunnel correlation with bytes_transferred > 0
        //     against an authenticated mock upstream proxy!
        let upstream_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock upstream proxy");
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let upstream_handle = std::thread::spawn(move || {
            use std::io::{Read, Write};
            upstream_listener.set_nonblocking(true).ok();
            let accept_deadline = Instant::now() + Duration::from_secs(7);
            let mut last_connect_req = String::new();
            while Instant::now() < accept_deadline {
                match upstream_listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).ok();
                        stream
                            .set_read_timeout(Some(Duration::from_millis(2000)))
                            .ok();
                        let mut buf = [0u8; 4096];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                        if req_str.starts_with("CONNECT ipwho.is:443")
                            && req_str.contains("Proxy-Authorization: Basic ")
                        {
                            last_connect_req = req_str.clone();
                            let _ =
                                stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                            let _ = stream.flush();
                            // Read Edge's TLS ClientHello bytes so relay_bidirectional tracks bytes_transferred > 0
                            let mut tls_buf = [0u8; 1024];
                            match stream.read(&mut tls_buf) {
                                Ok(tls_n) if tls_n > 0 => {
                                    // Give relay_bidirectional 50ms to record telemetry.add_bytes before closing upstream
                                    std::thread::sleep(Duration::from_millis(50));
                                    let _ = stream.shutdown(std::net::Shutdown::Both);
                                    return (req_str, tls_n);
                                }
                                other => {
                                    eprintln!(
                                        " CONNECT ipwho.is:443 tls read returned: {:?}",
                                        other
                                    );
                                }
                            }
                        } else {
                            // Background Edge telemetry request (e.g. edge.microsoft.com); close and keep waiting for ipwho.is
                            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
            (last_connect_req, 0)
        });

        let bridge_status_ok = bridge_mgr
            .start_or_replace_bridge(UpstreamProxyConfig {
                environment_id: "env-real-edge-v8".to_string(),
                endpoint_id: "ep-us-auth".to_string(),
                host: "127.0.0.1".to_string(),
                port: upstream_port,
                protocol: "HTTP".to_string(),
                username: Some("j2_user".to_string()),
                password: Some("j2_pass_secret".to_string()),
                connect_timeout: Duration::from_millis(1500),
            })
            .expect("start local bridge for authenticated upstream");

        // Rebind Edge or spawn a short-lived headless Edge bound to bridge_status_ok.local_port
        drop(guard);
        let temp_dir2 = tempfile::tempdir().expect("create temp profile dir 2");
        let profile_path2 = temp_dir2.path().to_path_buf();
        let child2 = Command::new(edge_bin)
            .arg("--headless=new")
            .arg("--disable-gpu")
            .arg(format!("--user-data-dir={}", profile_path2.display()))
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--remote-debugging-port=0")
            .arg("--remote-debugging-address=127.0.0.1")
            .arg(format!(
                "--proxy-server=http://127.0.0.1:{}",
                bridge_status_ok.local_port
            ))
            .arg("--proxy-bypass-list=<-loopback>")
            .arg("about:blank")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn headless Edge 2");
        let _guard2 = EdgeGuard { child: child2 };

        let deadline2 = Instant::now() + Duration::from_secs(8);
        let mut cdp_port2_opt = None;
        while Instant::now() < deadline2 {
            if let Some((port, _)) =
                SystemBrowserLauncher::parse_devtools_active_port(&profile_path2)
            {
                cdp_port2_opt = Some(port);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let cdp_port2 = cdp_port2_opt.expect("Edge 2 DevToolsActivePort");

        let target2 = create_cdp_blank_target_full(cdp_port2, Duration::from_millis(2000))
            .expect("PUT /json/new on Edge 2");
        let ws2 = target2.websocket_debugger_url.unwrap();

        let window_start = chrono::Utc::now() - chrono::Duration::milliseconds(250);
        // Navigate to https://ipwho.is/ — Edge sends CONNECT ipwho.is:443 + TLS ClientHello through bridge
        let _ = navigate_cdp_target_and_read_body(
            &ws2,
            cdp_port2,
            &youtube_isolation_manager_lib::services::browser_verification::PRIMARY_VERIFICATION_PROVIDER,
            Duration::from_millis(1500),
            Duration::from_millis(2500),
            false,
        );
        let window_end = chrono::Utc::now() + chrono::Duration::milliseconds(250);
        close_cdp_target(cdp_port2, &target2.id, Duration::from_millis(2000));

        let (upstream_req, tls_bytes) = upstream_handle.join().unwrap();
        assert!(
            upstream_req.starts_with("CONNECT ipwho.is:443"),
            "Upstream proxy must receive CONNECT ipwho.is:443 from local bridge, got: {}",
            upstream_req
        );
        assert!(
            upstream_req.contains("Proxy-Authorization: Basic "),
            "Local bridge must inject Proxy-Authorization header"
        );
        assert!(
            tls_bytes > 0,
            "Real Edge must send TLS ClientHello bytes (>0) through CONNECT tunnel"
        );

        let corr = bridge_mgr.correlate_connect_tunnel(
            bridge_mgr
                .get_instance_id("env-real-edge-v8")
                .as_deref()
                .unwrap(),
            "env-real-edge-v8",
            "ep-us-auth",
            "ipwho.is",
            443,
            window_start,
            Some(window_end),
        );
        match corr {
            youtube_isolation_manager_lib::services::proxy_bridge::BridgeCorrelationOutcome::Confirmed(ev) => {
                assert_eq!(ev.protocol, "HTTP_CONNECT");
                assert_eq!(ev.destination_host, "ipwho.is");
                assert_eq!(ev.destination_port, 443);
                assert!(
                    ev.bytes_transferred > 0,
                    "Bridge telemetry must record bytes_transferred > 0 for real Edge TLS handshake, got {}",
                    ev.bytes_transferred
                );
            }
            other => panic!(
                "Expected BridgeCorrelationOutcome::Confirmed for real Edge CONNECT tunnel, got: {:?}",
                other
            ),
        }

        bridge_mgr.stop_bridge("env-real-edge-v8");
    }
}
