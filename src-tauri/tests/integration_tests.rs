use std::sync::Arc;
use tempfile::tempdir;
use youtube_isolation_manager_lib::db::Database;
use youtube_isolation_manager_lib::hypervisor::mock::MockHypervisorAdapter;
use youtube_isolation_manager_lib::hypervisor::HypervisorAdapter;
use youtube_isolation_manager_lib::security::dpapi::DpapiVault;
use youtube_isolation_manager_lib::services::audit_service::AuditService;
use youtube_isolation_manager_lib::services::channel_service::{ChannelService, CreateChannelRequest};
use youtube_isolation_manager_lib::services::network_service::{
    CreateEndpointRequest, NetworkService,
};
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
fn test_sec_001_dpapi_vault_encryption_roundtrip() {
    let test_secret = "Confidential_Proxy_Token_#9923";
    let encrypted = DpapiVault::encrypt_secret(test_secret).expect("DPAPI encryption failed");
    assert_ne!(test_secret, encrypted);

    let decrypted = DpapiVault::decrypt_secret(&encrypted).expect("DPAPI decryption failed");
    assert_eq!(test_secret, decrypted);
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
    };

    let env = vm_service.create_environment(req).expect("Failed to create environment");
    assert_eq!(env.name, "Env_Alpha_01");
    assert_eq!(env.status, "STOPPED");
    assert!(env.disk_path.contains("Env_Alpha_01.vdi"));
    assert!(env.browser_profile_path.is_some());
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
    };

    let env = vm_service.create_environment(req).unwrap();
    assert_eq!(env.status, "STOPPED");

    // Start VM
    vm_service.start_environment(&env.id).expect("Should start VM");
    let active_env = vm_service.get_environment(&env.id).unwrap().unwrap();
    assert_eq!(active_env.status, "RUNNING");

    let hypervisor_state = hypervisor.get_vm_state(&env.vm_identifier).unwrap();
    assert_eq!(hypervisor_state, youtube_isolation_manager_lib::hypervisor::VmState::Running);

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
    }).unwrap();

    // VM is STOPPED: network check must NOT claim verification
    let check_stopped = network_service.check_network(&env.id).unwrap();
    assert_eq!(check_stopped.status, "NOT_CHECKED");
    assert!(check_stopped.observed_ipv4.is_none());

    // VM is RUNNING: verify network check records real observed endpoint
    vm_service.start_environment(&env.id).unwrap();
    let check_running = network_service.check_network(&env.id).unwrap();
    assert_eq!(check_running.status, "VERIFIED");
    assert_eq!(check_running.observed_ipv4, Some("198.51.100.88".to_string()));
}

#[test]
fn test_net_005_duplicate_egress_warning_detection() {
    let (vm_service, network_service, _, _, _, _temp) = setup_test_services();

    let shared_ip_ep = network_service.create_endpoint(CreateEndpointRequest {
        name: "Shared_Proxy".to_string(),
        endpoint_type: "HTTP".to_string(),
        provider_label: None,
        host: Some("203.0.113.99".to_string()),
        port: Some(8080),
        credentials_secret: None,
    }).unwrap();

    let env1 = vm_service.create_environment(CreateEnvironmentRequest {
        name: "Env_Conflict_1".to_string(),
        hypervisor_type: "VirtualBox".to_string(),
        guest_os: "Ubuntu_64".to_string(),
        cpu_count: 2,
        memory_mb: 2048,
        disk_size_mb: 10240,
        iso_path: None,
        browser_type: "chrome".to_string(),
        network_endpoint_id: Some(shared_ip_ep.id.clone()),
        channel_id: None,
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
        network_endpoint_id: Some(shared_ip_ep.id),
        channel_id: None,
    }).unwrap();

    vm_service.start_environment(&env1.id).unwrap();
    vm_service.start_environment(&env2.id).unwrap();

    network_service.check_network(&env1.id).unwrap();
    network_service.check_network(&env2.id).unwrap();

    let duplicate_warnings = network_service.detect_duplicate_egress().unwrap();
    assert_eq!(duplicate_warnings.len(), 1);
    assert_eq!(duplicate_warnings[0].ip_address, "203.0.113.99");
    assert_eq!(duplicate_warnings[0].conflicting_environments.len(), 2);
}

#[test]
fn test_ch_001_and_004_channel_compliance_and_termination_lock() {
    let (_, _, channel_service, _, _, _temp) = setup_test_services();

    // Create Authorized channel
    let ch = channel_service.create_channel(CreateChannelRequest {
        youtube_channel_id: "UC_Valid_123456789".to_string(),
        display_name: "Channel Alpha".to_string(),
        environment_id: None,
        authorization_status: "AUTHORIZED".to_string(),
    }).unwrap();

    assert_eq!(ch.authorization_status, "AUTHORIZED");
    assert!(ch.is_eligible_for_publishing);

    // Update to TERMINATED
    channel_service.update_status(&ch.id, "TERMINATED").unwrap();
    let updated = channel_service.get_channel(&ch.id).unwrap().unwrap();
    assert_eq!(updated.authorization_status, "TERMINATED");
    assert!(!updated.is_eligible_for_publishing); // Must NOT be eligible for publishing
}

#[test]
fn test_br_005_reject_path_traversal_in_profile() {
    let (_, _, _, profile_service, _, _temp) = setup_test_services();

    let invalid_path = std::path::Path::new("C:\\profiles\\..\\system32");
    let res = profile_service.validate_path(invalid_path);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Path traversal"));
}
