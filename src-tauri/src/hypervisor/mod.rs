pub mod mock;
pub mod vbox;

use serde::{Deserialize, Serialize};
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
    fn create_vm(&self, spec: &CreateVmSpec) -> Result<String, HypervisorError>;
    fn start_vm(&self, vm_identifier: &str) -> Result<(), HypervisorError>;
    fn shutdown_vm(&self, vm_identifier: &str, force: bool) -> Result<(), HypervisorError>;
    fn delete_vm(&self, vm_identifier: &str, delete_disks: bool) -> Result<(), HypervisorError>;
    fn get_system_resources(&self) -> Result<HostResources, HypervisorError>;
}
