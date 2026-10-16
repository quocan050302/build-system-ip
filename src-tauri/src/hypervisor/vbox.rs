use super::*;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct VirtualBoxAdapter {
    custom_path: Option<PathBuf>,
}

impl VirtualBoxAdapter {
    pub fn new(custom_path: Option<String>) -> Self {
        Self {
            custom_path: custom_path.map(PathBuf::from),
        }
    }

    pub fn find_executable(&self) -> Option<PathBuf> {
        if let Some(ref path) = self.custom_path {
            if path.exists() {
                return Some(path.clone());
            }
        }

        // Check VBOX_MSI_INSTALL_PATH or VBOX_INSTALL_PATH environment variables
        if let Ok(path) = std::env::var("VBOX_MSI_INSTALL_PATH") {
            let p = PathBuf::from(path).join("VBoxManage.exe");
            if p.exists() {
                return Some(p);
            }
        }

        // Standard Windows installation directory
        let default_win_path = PathBuf::from("C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe");
        if default_win_path.exists() {
            return Some(default_win_path);
        }

        // Standard macOS installation directory
        let mac_vbox = PathBuf::from("/Applications/VirtualBox.app/Contents/MacOS/VBoxManage");
        if mac_vbox.exists() {
            return Some(mac_vbox);
        }
        let mac_bin = PathBuf::from("/usr/local/bin/VBoxManage");
        if mac_bin.exists() {
            return Some(mac_bin);
        }

        // Check PATH
        #[cfg(windows)]
        let lookup_cmd = "where.exe";
        #[cfg(not(windows))]
        let lookup_cmd = "which";

        if let Ok(output) = Command::new(lookup_cmd).arg("VBoxManage").output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(first_line) = stdout.lines().next() {
                    let p = PathBuf::from(first_line.trim());
                    if p.exists() {
                        return Some(p);
                    }
                }
            }
        }

        None
    }

    fn run_vbox_cmd(&self, args: &[&str]) -> Result<String, HypervisorError> {
        let exe = self.find_executable().ok_or_else(|| {
            HypervisorError::NotFound("VirtualBox VBoxManage executable not found on system".to_string())
        })?;

        let output = Command::new(exe)
            .args(args)
            .output()
            .map_err(|e| HypervisorError::ExecutionFailed(format!("Failed to spawn VBoxManage: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(HypervisorError::ExecutionFailed(format!(
                "VBoxManage returned error {}: {}",
                output.status,
                stderr.trim()
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

impl HypervisorAdapter for VirtualBoxAdapter {
    fn detect(&self) -> Result<HypervisorInfo, HypervisorError> {
        let exe_path = self.find_executable();
        if let Some(ref exe) = exe_path {
            match self.run_vbox_cmd(&["--version"]) {
                Ok(version_str) => Ok(HypervisorInfo {
                    name: "Oracle VM VirtualBox".to_string(),
                    version: version_str.trim().to_string(),
                    available: true,
                    executable_path: Some(exe.to_string_lossy().to_string()),
                }),
                Err(e) => Ok(HypervisorInfo {
                    name: "Oracle VM VirtualBox".to_string(),
                    version: "Unknown".to_string(),
                    available: false,
                    executable_path: Some(format!("Error: {}", e)),
                }),
            }
        } else {
            Ok(HypervisorInfo {
                name: "Oracle VM VirtualBox".to_string(),
                version: "Not Installed".to_string(),
                available: false,
                executable_path: None,
            })
        }
    }

    fn list_vms(&self) -> Result<Vec<VmSummary>, HypervisorError> {
        let output = self.run_vbox_cmd(&["list", "vms"])?;
        let running_output = self.run_vbox_cmd(&["list", "runningvms"]).unwrap_or_default();

        let mut vms = Vec::new();
        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Format: "Name" {uuid}
            if let Some(first_quote) = line.find('"') {
                if let Some(second_quote) = line[first_quote + 1..].find('"') {
                    let name = &line[first_quote + 1..first_quote + 1 + second_quote];
                    let rest = &line[first_quote + 1 + second_quote + 1..];
                    if let (Some(uuid_start), Some(uuid_end)) = (rest.find('{'), rest.find('}')) {
                        let uuid = &rest[uuid_start + 1..uuid_end];
                        let is_running = running_output.contains(uuid);

                        vms.push(VmSummary {
                            identifier: uuid.to_string(),
                            name: name.to_string(),
                            state: if is_running { VmState::Running } else { VmState::Stopped },
                            os_type: "Unknown".to_string(),
                            cpu_count: 2,
                            memory_mb: 2048,
                        });
                    }
                }
            }
        }

        Ok(vms)
    }

    fn get_vm_state(&self, vm_identifier: &str) -> Result<VmState, HypervisorError> {
        let output = self.run_vbox_cmd(&["showvminfo", vm_identifier, "--machinereadable"])?;
        for line in output.lines() {
            if line.starts_with("VMState=") {
                let state_str = line.trim_start_matches("VMState=").trim_matches('"');
                return Ok(match state_str {
                    "running" => VmState::Running,
                    "paused" => VmState::Running,
                    "poweroff" | "aborted" | "saved" => VmState::Stopped,
                    "starting" => VmState::Starting,
                    "stopping" => VmState::Stopping,
                    _ => VmState::Unknown,
                });
            }
        }
        Ok(VmState::Unknown)
    }

    fn create_vm(&self, spec: &CreateVmSpec) -> Result<String, HypervisorError> {
        // Validate inputs
        if spec.name.is_empty() || !spec.name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(HypervisorError::InvalidConfiguration(
                "Environment VM name must only contain alphanumeric characters, hyphens, or underscores".to_string()
            ));
        }

        if let Some(ref iso) = spec.iso_path {
            if !iso.is_empty() && !Path::new(iso).exists() {
                return Err(HypervisorError::InvalidConfiguration(format!(
                    "Guest OS installer ISO does not exist at path: {}",
                    iso
                )));
            }
        }

        // 1. Create and register VM
        let _ = self.run_vbox_cmd(&[
            "createvm",
            "--name",
            &spec.name,
            "--ostype",
            &spec.guest_os,
            "--register",
        ])?;

        // 2. Modify VM hardware allocations
        let cpus_str = spec.cpu_count.to_string();
        let memory_str = spec.memory_mb.to_string();
        self.run_vbox_cmd(&[
            "modifyvm",
            &spec.name,
            "--cpus",
            &cpus_str,
            "--memory",
            &memory_str,
            "--vram",
            "128",
            "--nic1",
            "nat",
            "--audio",
            "none",
        ])?;

        // 3. Create virtual hard disk
        if let Some(parent) = Path::new(&spec.disk_path).parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let disk_size_str = spec.disk_size_mb.to_string();
        self.run_vbox_cmd(&[
            "createhd",
            "--filename",
            &spec.disk_path,
            "--size",
            &disk_size_str,
            "--format",
            "VDI",
        ])?;

        // 4. Add Storage Controller
        self.run_vbox_cmd(&[
            "storagectl",
            &spec.name,
            "--name",
            "SATA Controller",
            "--add",
            "sata",
            "--controller",
            "IntelAhci",
        ])?;

        // 5. Attach Hard Drive
        self.run_vbox_cmd(&[
            "storageattach",
            &spec.name,
            "--storagectl",
            "SATA Controller",
            "--port",
            "0",
            "--device",
            "0",
            "--type",
            "hdd",
            "--medium",
            &spec.disk_path,
        ])?;

        // 6. Attach ISO if provided
        if let Some(ref iso) = spec.iso_path {
            if !iso.is_empty() {
                self.run_vbox_cmd(&[
                    "storageattach",
                    &spec.name,
                    "--storagectl",
                    "SATA Controller",
                    "--port",
                    "1",
                    "--device",
                    "0",
                    "--type",
                    "dvddrive",
                    "--medium",
                    iso,
                ])?;
            }
        }

        Ok(spec.name.clone())
    }

    fn start_vm(&self, vm_identifier: &str) -> Result<(), HypervisorError> {
        self.run_vbox_cmd(&["startvm", vm_identifier, "--type", "gui"])?;
        Ok(())
    }

    fn shutdown_vm(&self, vm_identifier: &str, force: bool) -> Result<(), HypervisorError> {
        if force {
            self.run_vbox_cmd(&["controlvm", vm_identifier, "poweroff"])?;
        } else {
            self.run_vbox_cmd(&["controlvm", vm_identifier, "acpipowerbutton"])?;
        }
        Ok(())
    }

    fn delete_vm(&self, vm_identifier: &str, delete_disks: bool) -> Result<(), HypervisorError> {
        let state = self.get_vm_state(vm_identifier).unwrap_or(VmState::Unknown);
        if state == VmState::Running || state == VmState::Starting {
            return Err(HypervisorError::ExecutionFailed(
                "Cannot delete a running virtual machine. Please shut down or stop it first.".to_string(),
            ));
        }

        if delete_disks {
            self.run_vbox_cmd(&["unregistervm", vm_identifier, "--delete"])?;
        } else {
            self.run_vbox_cmd(&["unregistervm", vm_identifier])?;
        }
        Ok(())
    }

    fn open_vm_console(&self, vm_identifier: &str) -> Result<(), HypervisorError> {
        let exe = self.find_executable().ok_or_else(|| {
            HypervisorError::NotFound("VirtualBox VBoxManage executable not found".to_string())
        })?;

        // Launch GUI for VM
        Command::new(exe)
            .args(["startvm", vm_identifier, "--type", "gui"])
            .spawn()
            .map_err(|e| HypervisorError::ExecutionFailed(format!("Failed to open VirtualBox console: {}", e)))?;

        Ok(())
    }

    fn get_vm_details(&self, vm_identifier: &str) -> Result<VmDetails, HypervisorError> {
        let state = self.get_vm_state(vm_identifier)?;
        let output = self.run_vbox_cmd(&["showvminfo", vm_identifier, "--machinereadable"])?;

        let mut name = vm_identifier.to_string();
        let mut os_type = "Unknown".to_string();
        let mut cpu_count = 2u32;
        let mut memory_mb = 2048u64;

        for line in output.lines() {
            if line.starts_with("name=") {
                name = line.trim_start_matches("name=").trim_matches('"').to_string();
            } else if line.starts_with("Ostype=") {
                os_type = line.trim_start_matches("Ostype=").trim_matches('"').to_string();
            } else if line.starts_with("cpus=") {
                if let Ok(c) = line.trim_start_matches("cpus=").trim_matches('"').parse::<u32>() {
                    cpu_count = c;
                }
            } else if line.starts_with("memory=") {
                if let Ok(m) = line.trim_start_matches("memory=").trim_matches('"').parse::<u64>() {
                    memory_mb = m;
                }
            }
        }

        Ok(VmDetails {
            identifier: vm_identifier.to_string(),
            name,
            state,
            os_type,
            cpu_count,
            memory_mb,
            disk_path: None,
            console_type: Some("vbox-gui".to_string()),
            architecture: "x86_64".to_string(),
        })
    }

    fn get_system_resources(&self) -> Result<HostResources, HypervisorError> {
        let platform_svc = crate::services::platform_service::PlatformService::new(
            crate::services::platform_service::PlatformService::resolve_default_data_dir()
        );
        let (total_mem, avail_mem, total_disk, avail_disk) = platform_svc.query_system_resources();

        Ok(HostResources {
            total_memory_mb: total_mem,
            available_memory_mb: avail_mem,
            total_disk_mb: total_disk,
            available_disk_mb: avail_disk,
        })
    }
}
