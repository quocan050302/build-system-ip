use super::*;
#[allow(unused_imports)]
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct HyperVAdapter {
    data_dir: PathBuf,
}

#[allow(dead_code)]
impl HyperVAdapter {
    pub fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    fn run_powershell(&self, script: &str) -> Result<String, HypervisorError> {
        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
            .output()
            .map_err(|e| HypervisorError::ExecutionFailed(format!("Failed to execute PowerShell: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let err_msg = if !stderr.trim().is_empty() {
                stderr.trim().to_string()
            } else {
                stdout.trim().to_string()
            };
            return Err(HypervisorError::ExecutionFailed(format!(
                "Hyper-V PowerShell command failed: {}",
                err_msg
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn check_hyperv_feature_enabled(&self) -> bool {
        #[cfg(windows)]
        {
            let script = "if ((Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).HypervisorPresent -or (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization')) { 'Enabled' } else { 'Disabled' }";
            if let Ok(out) = self.run_powershell(script) {
                return out.trim().eq_ignore_ascii_case("Enabled");
            }
        }
        false
    }

    fn check_hyperv_permission(&self) -> bool {
        #[cfg(windows)]
        {
            let script = "try { Get-VM -ErrorAction Stop | Out-Null; 'OK' } catch { if ($_.CategoryInfo.Category -eq 'PermissionDenied' -or $_.Exception.Message -like '*permission*') { 'DENIED' } else { 'OK' } }";
            if let Ok(out) = self.run_powershell(script) {
                return out.trim() == "OK";
            }
        }
        true
    }

    fn check_vmms_service_running(&self) -> bool {
        #[cfg(windows)]
        {
            let script = "Get-Service vmms -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status";
            if let Ok(out) = self.run_powershell(script) {
                return out.trim().eq_ignore_ascii_case("Running");
            }
        }
        false
    }

    fn parse_hyperv_state(state_str: &str) -> VmState {
        match state_str.trim().to_lowercase().as_str() {
            "running" => VmState::Running,
            "off" | "saved" => VmState::Stopped,
            "starting" => VmState::Starting,
            "stopping" => VmState::Stopping,
            "paused" | "suspended" => VmState::Running,
            _ => VmState::Unknown,
        }
    }
}

impl HypervisorAdapter for HyperVAdapter {
    fn detect(&self) -> Result<HypervisorInfo, HypervisorError> {
        #[cfg(windows)]
        {
            let feature_enabled = self.check_hyperv_feature_enabled();
            let service_running = self.check_vmms_service_running();
            let has_permission = self.check_hyperv_permission();

            if feature_enabled && service_running && has_permission {
                // Query version
                let version_script = "[System.Environment]::OSVersion.Version.ToString()";
                let ver = self.run_powershell(version_script).unwrap_or_else(|_| "10.0".to_string()).trim().to_string();

                Ok(HypervisorInfo {
                    name: "Microsoft Hyper-V".to_string(),
                    version: format!("Hyper-V Engine ({})", ver),
                    available: true,
                    executable_path: Some("powershell.exe (Hyper-V Module)".to_string()),
                })
            } else {
                let reason = if !feature_enabled {
                    "Hyper-V optional feature is not enabled on this Windows edition. Enable via 'Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All' in an Administrator PowerShell."
                } else if !service_running {
                    "Hyper-V VM Management Service (vmms) is not running. Start via 'Start-Service vmms'."
                } else {
                    "Hyper-V is running, but requires Administrator rights or session refresh. Please run as Administrator or Sign Out & Sign Back In."
                };

                Ok(HypervisorInfo {
                    name: "Microsoft Hyper-V".to_string(),
                    version: if !has_permission { "Permission Required".to_string() } else { "Unavailable".to_string() },
                    available: false,
                    executable_path: Some(reason.to_string()),
                })
            }
        }

        #[cfg(not(windows))]
        {
            Ok(HypervisorInfo {
                name: "Microsoft Hyper-V".to_string(),
                version: "N/A".to_string(),
                available: false,
                executable_path: Some("Microsoft Hyper-V is only supported on Windows hosts".to_string()),
            })
        }
    }

    fn list_vms(&self) -> Result<Vec<VmSummary>, HypervisorError> {
        #[cfg(windows)]
        {
            let script = "Get-VM -ErrorAction SilentlyContinue | Select-Object Id, Name, State, MemoryAssigned, CPUUsage | ConvertTo-Json -Compress";
            let output = self.run_powershell(script)?;

            if output.trim().is_empty() || output.trim() == "null" {
                return Ok(Vec::new());
            }

            let mut summaries = Vec::new();
            // Could be single JSON object or array
            if let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(&output) {
                for item in items {
                    let id = item["Id"].as_str().unwrap_or("").to_string();
                    let name = item["Name"].as_str().unwrap_or("").to_string();
                    let state_code = item["State"].as_i64().unwrap_or(3); // 2 = Running, 3 = Off
                    let state = match state_code {
                        2 => VmState::Running,
                        3 => VmState::Stopped,
                        _ => VmState::Unknown,
                    };
                    summaries.push(VmSummary {
                        identifier: id,
                        name,
                        state,
                        os_type: "Windows/Linux x64".to_string(),
                        cpu_count: 2,
                        memory_mb: 4096,
                    });
                }
            } else if let Ok(item) = serde_json::from_str::<serde_json::Value>(&output) {
                let id = item["Id"].as_str().unwrap_or("").to_string();
                let name = item["Name"].as_str().unwrap_or("").to_string();
                let state_code = item["State"].as_i64().unwrap_or(3);
                let state = match state_code {
                    2 => VmState::Running,
                    3 => VmState::Stopped,
                    _ => VmState::Unknown,
                };
                summaries.push(VmSummary {
                    identifier: id,
                    name,
                    state,
                    os_type: "Windows/Linux x64".to_string(),
                    cpu_count: 2,
                    memory_mb: 4096,
                });
            }

            Ok(summaries)
        }

        #[cfg(not(windows))]
        {
            Ok(Vec::new())
        }
    }

    fn get_vm_state(&self, vm_identifier: &str) -> Result<VmState, HypervisorError> {
        #[cfg(windows)]
        {
            // Validate UUID or alphanumeric name to prevent injection
            if !vm_identifier.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
                return Err(HypervisorError::InvalidConfiguration("Invalid VM identifier".to_string()));
            }

            let script = format!(
                "(Get-VM -Name '{}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty State).ToString()",
                vm_identifier
            );
            let output = self.run_powershell(&script)?;
            Ok(Self::parse_hyperv_state(&output))
        }

        #[cfg(not(windows))]
        {
            let _ = vm_identifier;
            Ok(VmState::Unknown)
        }
    }

    fn get_vm_details(&self, vm_identifier: &str) -> Result<VmDetails, HypervisorError> {
        let state = self.get_vm_state(vm_identifier).unwrap_or(VmState::Unknown);

        Ok(VmDetails {
            identifier: vm_identifier.to_string(),
            name: vm_identifier.to_string(),
            state,
            os_type: "Hyper-V Guest x64".to_string(),
            cpu_count: 2,
            memory_mb: 4096,
            disk_path: Some(format!("{}\\environments\\{}.vhdx", self.data_dir.to_string_lossy(), vm_identifier)),
            console_type: Some("vmconnect".to_string()),
            architecture: "x86_64".to_string(),
        })
    }

    fn create_vm(&self, spec: &CreateVmSpec) -> Result<String, HypervisorError> {
        #[cfg(windows)]
        {
            if spec.name.is_empty() || !spec.name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
                return Err(HypervisorError::InvalidConfiguration(
                    "Environment VM name must only contain alphanumeric characters, hyphens, or underscores".to_string(),
                ));
            }

            // Ensure parent directory exists
            if let Some(parent) = Path::new(&spec.disk_path).parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    HypervisorError::ExecutionFailed(format!("Failed to create disk directory: {}", e))
                })?;
            }

            // Clean .vhdx path
            let vhdx_path = if spec.disk_path.ends_with(".vhdx") {
                spec.disk_path.clone()
            } else {
                format!("{}.vhdx", spec.disk_path.trim_end_matches(".vdi"))
            };

            let bytes_disk = spec.disk_size_mb * 1024 * 1024;
            let bytes_ram = spec.memory_mb * 1024 * 1024;

            // PowerShell commands to create VHDX and VM
            let mut script = format!(
                "$vhdx = '{}'\n\
                 if (-not (Test-Path $vhdx)) {{ New-VHD -Path $vhdx -SizeBytes {} -Dynamic }}\n\
                 New-VM -Name '{}' -MemoryStartupBytes {} -VHDPath $vhdx -Generation 2\n\
                 Set-VMProcessor -VMName '{}' -Count {}\n",
                vhdx_path, bytes_disk, spec.name, bytes_ram, spec.name, spec.cpu_count
            );

            if let Some(ref iso) = spec.iso_path {
                if !iso.trim().is_empty() {
                    script.push_str(&format!(
                        "Set-VMDvdDrive -VMName '{}' -Path '{}'\n",
                        spec.name, iso
                    ));
                }
            }

            self.run_powershell(&script)?;
            Ok(spec.name.clone())
        }

        #[cfg(not(windows))]
        {
            let _ = spec;
            Err(HypervisorError::ExecutionFailed(
                "Hyper-V is only supported on Windows hosts".to_string(),
            ))
        }
    }

    fn start_vm(&self, vm_identifier: &str) -> Result<(), HypervisorError> {
        #[cfg(windows)]
        {
            let script = format!("Start-VM -Name '{}'", vm_identifier);
            self.run_powershell(&script)?;
            Ok(())
        }

        #[cfg(not(windows))]
        {
            let _ = vm_identifier;
            Err(HypervisorError::ExecutionFailed("Not on Windows".to_string()))
        }
    }

    fn shutdown_vm(&self, vm_identifier: &str, force: bool) -> Result<(), HypervisorError> {
        #[cfg(windows)]
        {
            let script = if force {
                format!("Stop-VM -Name '{}' -TurnOff -Force", vm_identifier)
            } else {
                format!("Stop-VM -Name '{}' -Force", vm_identifier)
            };
            self.run_powershell(&script)?;
            Ok(())
        }

        #[cfg(not(windows))]
        {
            let _ = (vm_identifier, force);
            Err(HypervisorError::ExecutionFailed("Not on Windows".to_string()))
        }
    }

    fn delete_vm(&self, vm_identifier: &str, delete_disks: bool) -> Result<(), HypervisorError> {
        #[cfg(windows)]
        {
            let script = format!("Remove-VM -Name '{}' -Force", vm_identifier);
            self.run_powershell(&script)?;

            if delete_disks {
                let env_dir = self.data_dir.join("environments").join(vm_identifier);
                if env_dir.exists() {
                    std::fs::remove_dir_all(env_dir).ok();
                }
            }
            Ok(())
        }

        #[cfg(not(windows))]
        {
            let _ = (vm_identifier, delete_disks);
            Err(HypervisorError::ExecutionFailed("Not on Windows".to_string()))
        }
    }

    fn open_vm_console(&self, vm_identifier: &str) -> Result<(), HypervisorError> {
        #[cfg(windows)]
        {
            Command::new("vmconnect.exe")
                .args(["localhost", vm_identifier])
                .spawn()
                .map_err(|e| HypervisorError::ExecutionFailed(format!("Failed to spawn vmconnect.exe: {}", e)))?;
            Ok(())
        }

        #[cfg(not(windows))]
        {
            let _ = vm_identifier;
            Err(HypervisorError::NotFound("vmconnect is only available on Windows".to_string()))
        }
    }

    fn get_system_resources(&self) -> Result<HostResources, HypervisorError> {
        let platform_svc = crate::services::platform_service::PlatformService::new(self.data_dir.clone());
        let (total_mem, avail_mem, total_disk, avail_disk) = platform_svc.query_system_resources();

        Ok(HostResources {
            total_memory_mb: total_mem,
            available_memory_mb: avail_mem,
            total_disk_mb: total_disk,
            available_disk_mb: avail_disk,
        })
    }
}
