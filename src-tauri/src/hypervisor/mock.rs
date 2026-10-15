use super::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
struct MockVm {
    spec: CreateVmSpec,
    state: VmState,
}

#[derive(Clone)]
pub struct MockHypervisorAdapter {
    vms: Arc<Mutex<HashMap<String, MockVm>>>,
    available: bool,
}

impl MockHypervisorAdapter {
    pub fn new() -> Self {
        Self {
            vms: Arc::new(Mutex::new(HashMap::new())),
            available: true,
        }
    }

    pub fn with_availability(available: bool) -> Self {
        Self {
            vms: Arc::new(Mutex::new(HashMap::new())),
            available,
        }
    }

    pub fn insert_vm(&self, id: &str, spec: CreateVmSpec, state: VmState) {
        let mut map = self.vms.lock().unwrap();
        map.insert(id.to_string(), MockVm { spec, state });
    }
}

impl HypervisorAdapter for MockHypervisorAdapter {
    fn detect(&self) -> Result<HypervisorInfo, HypervisorError> {
        Ok(HypervisorInfo {
            name: "Mock VirtualBox Hypervisor".to_string(),
            version: "7.0.18-mock".to_string(),
            available: self.available,
            executable_path: if self.available {
                Some("C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe".to_string())
            } else {
                None
            },
        })
    }

    fn list_vms(&self) -> Result<Vec<VmSummary>, HypervisorError> {
        if !self.available {
            return Err(HypervisorError::NotFound("Mock hypervisor is not available".to_string()));
        }
        let map = self.vms.lock().unwrap();
        let summaries = map.iter().map(|(id, vm)| VmSummary {
            identifier: id.clone(),
            name: vm.spec.name.clone(),
            state: vm.state.clone(),
            os_type: vm.spec.guest_os.clone(),
            cpu_count: vm.spec.cpu_count,
            memory_mb: vm.spec.memory_mb,
        }).collect();
        Ok(summaries)
    }

    fn get_vm_state(&self, vm_identifier: &str) -> Result<VmState, HypervisorError> {
        if !self.available {
            return Err(HypervisorError::NotFound("Mock hypervisor is not available".to_string()));
        }
        let map = self.vms.lock().unwrap();
        match map.get(vm_identifier) {
            Some(vm) => Ok(vm.state.clone()),
            None => Err(HypervisorError::VmNotFound(format!("VM {} not found", vm_identifier))),
        }
    }

    fn create_vm(&self, spec: &CreateVmSpec) -> Result<String, HypervisorError> {
        if !self.available {
            return Err(HypervisorError::NotFound("Mock hypervisor is not available".to_string()));
        }
        let mut map = self.vms.lock().unwrap();
        if map.values().any(|v| v.spec.name == spec.name) {
            return Err(HypervisorError::InvalidConfiguration(format!("VM with name '{}' already exists", spec.name)));
        }
        let vm_id = format!("vbox-mock-{}", uuid::Uuid::new_v4());
        map.insert(vm_id.clone(), MockVm {
            spec: spec.clone(),
            state: VmState::Stopped,
        });
        Ok(vm_id)
    }

    fn start_vm(&self, vm_identifier: &str) -> Result<(), HypervisorError> {
        if !self.available {
            return Err(HypervisorError::NotFound("Mock hypervisor is not available".to_string()));
        }
        let mut map = self.vms.lock().unwrap();
        match map.get_mut(vm_identifier) {
            Some(vm) => {
                if vm.state == VmState::Running {
                    return Ok(());
                }
                vm.state = VmState::Running;
                Ok(())
            }
            None => Err(HypervisorError::VmNotFound(format!("VM {} not found", vm_identifier))),
        }
    }

    fn shutdown_vm(&self, vm_identifier: &str, force: bool) -> Result<(), HypervisorError> {
        if !self.available {
            return Err(HypervisorError::NotFound("Mock hypervisor is not available".to_string()));
        }
        let mut map = self.vms.lock().unwrap();
        match map.get_mut(vm_identifier) {
            Some(vm) => {
                if force {
                    vm.state = VmState::Stopped;
                } else {
                    vm.state = VmState::Stopped;
                }
                Ok(())
            }
            None => Err(HypervisorError::VmNotFound(format!("VM {} not found", vm_identifier))),
        }
    }

    fn delete_vm(&self, vm_identifier: &str, _delete_disks: bool) -> Result<(), HypervisorError> {
        if !self.available {
            return Err(HypervisorError::NotFound("Mock hypervisor is not available".to_string()));
        }
        let mut map = self.vms.lock().unwrap();
        if let Some(vm) = map.get(vm_identifier) {
            if vm.state == VmState::Running || vm.state == VmState::Starting {
                return Err(HypervisorError::ExecutionFailed("Cannot delete a running VM. Stop it first.".to_string()));
            }
        }
        map.remove(vm_identifier);
        Ok(())
    }

    fn get_system_resources(&self) -> Result<HostResources, HypervisorError> {
        Ok(HostResources {
            total_memory_mb: 32768,
            available_memory_mb: 24576,
            total_disk_mb: 1048576,
            available_disk_mb: 614400,
        })
    }
}
