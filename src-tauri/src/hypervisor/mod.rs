pub mod hyperv;
pub mod mock;
pub mod utm;
pub mod vbox;

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HypervisorError {
    #[error("Hypervisor executable not found: {0}")]
    NotFound(String),
    #[error("Command execution failed: {0}")]
    ExecutionFailed(String),
    #[error("VM not found: {0}")]
    VmNotFound(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Operation timeout: {0}")]
    Timeout(String),
    #[error("Resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),
    #[error("Unsupported platform: {0}")]
    UnsupportedPlatform(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmState {
    NotConfigured,
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
    Unknown,
}

impl VmState {
    pub fn as_str(&self) -> &'static str {
        match self {
            VmState::NotConfigured => "NOT_CONFIGURED",
            VmState::Stopped => "STOPPED",
            VmState::Starting => "STARTING",
            VmState::Running => "RUNNING",
            VmState::Stopping => "STOPPING",
            VmState::Error => "ERROR",
            VmState::Unknown => "UNKNOWN",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "NOT_CONFIGURED" => VmState::NotConfigured,
            "STOPPED" => VmState::Stopped,
            "STARTING" => VmState::Starting,
            "RUNNING" => VmState::Running,
            "STOPPING" => VmState::Stopping,
            "ERROR" => VmState::Error,
            _ => VmState::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypervisorInfo {
    pub name: String,
    pub version: String,
    pub available: bool,
    pub executable_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmSummary {
    pub identifier: String,
    pub name: String,
    pub state: VmState,
    pub os_type: String,
    pub cpu_count: u32,
    pub memory_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmDetails {
    pub identifier: String,
    pub name: String,
    pub state: VmState,
    pub os_type: String,
    pub cpu_count: u32,
    pub memory_mb: u64,
    pub disk_path: Option<String>,
    pub console_type: Option<String>,
    pub architecture: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVmSpec {
    pub name: String,
    pub guest_os: String,
    pub cpu_count: u32,
    pub memory_mb: u64,
    pub disk_size_mb: u64,
    pub disk_path: String,
    pub iso_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResources {
    pub total_memory_mb: u64,
    pub available_memory_mb: u64,
    pub total_disk_mb: u64,
    pub available_disk_mb: u64,
}

pub trait HypervisorAdapter: Send + Sync {
    fn detect(&self) -> Result<HypervisorInfo, HypervisorError>;
    fn list_vms(&self) -> Result<Vec<VmSummary>, HypervisorError>;
    fn get_vm_state(&self, vm_identifier: &str) -> Result<VmState, HypervisorError>;
    fn get_vm_details(&self, vm_identifier: &str) -> Result<VmDetails, HypervisorError>;
    fn create_vm(&self, spec: &CreateVmSpec) -> Result<String, HypervisorError>;
    fn start_vm(&self, vm_identifier: &str) -> Result<(), HypervisorError>;
    fn shutdown_vm(&self, vm_identifier: &str, force: bool) -> Result<(), HypervisorError>;
    fn delete_vm(&self, vm_identifier: &str, delete_disks: bool) -> Result<(), HypervisorError>;
    fn open_vm_console(&self, vm_identifier: &str) -> Result<(), HypervisorError>;
    fn get_system_resources(&self) -> Result<HostResources, HypervisorError>;
}

/// Create appropriate hypervisor adapter based on target platform and configuration.
/// In production, never silently fall back to mock mode.
pub fn create_hypervisor_adapter(
    force_mock: bool,
    data_dir: &Path,
) -> (Arc<dyn HypervisorAdapter>, bool) {
    if force_mock {
        return (Arc::new(mock::MockHypervisorAdapter::new()), true);
    }

    #[cfg(target_os = "macos")]
    {
        // On macOS Apple Silicon, use native UTM adapter
        (Arc::new(utm::UTMAdapter::new(data_dir.to_path_buf())), false)
    }

    #[cfg(windows)]
    {
        // On Windows 11 Pro, use Microsoft Hyper-V adapter
        (Arc::new(hyperv::HyperVAdapter::new(data_dir.to_path_buf())), false)
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    {
        // Fallback for other platforms (VirtualBox adapter or Mock if explicitly required)
        (Arc::new(vbox::VirtualBoxAdapter::new(None)), false)
    }
}
