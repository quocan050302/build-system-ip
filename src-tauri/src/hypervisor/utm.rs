use super::*;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct UTMAdapter {
    data_dir: PathBuf,
}

impl UTMAdapter {
    pub fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    pub fn find_utm_app(&self) -> Option<PathBuf> {
        let app_path = PathBuf::from("/Applications/UTM.app");
        if app_path.exists() {
            return Some(app_path);
        }

        // Check user applications
        if let Ok(home) = std::env::var("HOME") {
            let user_app = PathBuf::from(home).join("Applications").join("UTM.app");
            if user_app.exists() {
                return Some(user_app);
            }
        }

        None
    }

    pub fn find_utmctl(&self) -> Option<PathBuf> {
        // First check inside UTM.app
        if let Some(app) = self.find_utm_app() {
            let utmctl = app.join("Contents").join("MacOS").join("utmctl");
            if utmctl.exists() {
                return Some(utmctl);
            }
        }

        // Check standard path
        if let Ok(output) = Command::new("which").arg("utmctl").output() {
            if output.status.success() {
                let p_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !p_str.is_empty() {
                    let p = PathBuf::from(p_str);
                    if p.exists() {
                        return Some(p);
                    }
                }
            }
        }

        None
    }

    fn run_utmctl(&self, args: &[&str]) -> Result<String, HypervisorError> {
        let utmctl = self.find_utmctl().ok_or_else(|| {
            HypervisorError::NotFound(
                "UTM CLI (utmctl) not found at /Applications/UTM.app/Contents/MacOS/utmctl or on PATH. Please ensure UTM is installed."
                    .to_string(),
            )
        })?;

        let mut child = Command::new(&utmctl)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| HypervisorError::ExecutionFailed(format!("Failed to spawn utmctl: {}", e)))?;

        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(3);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        let _ = child.kill();
                        return Err(HypervisorError::ExecutionFailed(
                            "utmctl command timed out. Ensure UTM.app is open and responding.".to_string(),
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => {
                    return Err(HypervisorError::ExecutionFailed(format!("Error waiting for utmctl: {}", e)));
                }
            }
        };

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        if let Some(mut out) = child.stdout.take() {
            let _ = std::io::Read::read_to_end(&mut out, &mut stdout_buf);
        }
        if let Some(mut err) = child.stderr.take() {
            let _ = std::io::Read::read_to_end(&mut err, &mut stderr_buf);
        }

        if !status.success() {
            let stderr = String::from_utf8_lossy(&stderr_buf);
            let stdout = String::from_utf8_lossy(&stdout_buf);
            let err_msg = if !stderr.trim().is_empty() {
                stderr.trim().to_string()
            } else {
                stdout.trim().to_string()
            };
            return Err(HypervisorError::ExecutionFailed(format!(
                "utmctl error: {}",
                err_msg
            )));
        }

        Ok(String::from_utf8_lossy(&stdout_buf).to_string())
    }

    fn parse_utm_state(status_str: &str) -> VmState {
        let s = status_str.to_lowercase();
        if s.contains("started") || s.contains("running") {
            VmState::Running
        } else if s.contains("stopped") || s.contains("paused") {
            VmState::Stopped
        } else if s.contains("starting") {
            VmState::Starting
        } else if s.contains("stopping") {
            VmState::Stopping
        } else if s.contains("error") {
            VmState::Error
        } else {
            VmState::Unknown
        }
    }
}

impl HypervisorAdapter for UTMAdapter {
    fn detect(&self) -> Result<HypervisorInfo, HypervisorError> {
        let app_path = self.find_utm_app();
        let utmctl_path = self.find_utmctl();

        if let Some(app) = app_path {
            // Attempt to get version from Info.plist
            let info_plist = app.join("Contents").join("Info.plist");
            let mut version = "Unknown".to_string();

            if info_plist.exists() {
                if let Ok(plist_output) = Command::new("defaults")
                    .args(["read", &info_plist.to_string_lossy(), "CFBundleShortVersionString"])
                    .output()
                {
                    if plist_output.status.success() {
                        version = String::from_utf8_lossy(&plist_output.stdout).trim().to_string();
                    }
                }
            }

            Ok(HypervisorInfo {
                name: "UTM (macOS Apple Silicon)".to_string(),
                version,
                available: true,
                executable_path: utmctl_path.map(|p| p.to_string_lossy().to_string()),
            })
        } else {
            Ok(HypervisorInfo {
                name: "UTM (macOS Apple Silicon)".to_string(),
                version: "Not Installed".to_string(),
                available: false,
                executable_path: None,
            })
        }
    }

    fn list_vms(&self) -> Result<Vec<VmSummary>, HypervisorError> {
        let output = match self.run_utmctl(&["list"]) {
            Ok(out) => out,
            Err(_) => return Ok(Vec::new()),
        };

        let mut vms = Vec::new();
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Expected format from utmctl list:
            // UUID Name (status) OR Name (status)
            let mut state = VmState::Unknown;
            let mut name = trimmed.to_string();
            let mut id = trimmed.to_string();

            if let Some(open_paren) = trimmed.rfind('(') {
                if let Some(close_paren) = trimmed.rfind(')') {
                    if open_paren < close_paren {
                        let status_text = &trimmed[open_paren + 1..close_paren];
                        state = Self::parse_utm_state(status_text);
                        let name_part = trimmed[..open_paren].trim();

                        // Check if first token is UUID
                        let parts: Vec<&str> = name_part.splitn(2, ' ').collect();
                        if parts.len() == 2 && parts[0].len() == 36 && parts[0].contains('-') {
                            id = parts[0].to_string();
                            name = parts[1].to_string();
                        } else {
                            id = name_part.to_string();
                            name = name_part.to_string();
                        }
                    }
                }
            }

            vms.push(VmSummary {
                identifier: id,
                name,
                state,
                os_type: "Ubuntu_ARM64".to_string(),
                cpu_count: 4,
                memory_mb: 4096,
            });
        }

        Ok(vms)
    }

    fn get_vm_state(&self, vm_identifier: &str) -> Result<VmState, HypervisorError> {
        let output = self.run_utmctl(&["status", vm_identifier])?;
        Ok(Self::parse_utm_state(&output))
    }

    fn get_vm_details(&self, vm_identifier: &str) -> Result<VmDetails, HypervisorError> {
        let state = self.get_vm_state(vm_identifier).unwrap_or(VmState::Unknown);

        Ok(VmDetails {
            identifier: vm_identifier.to_string(),
            name: vm_identifier.to_string(),
            state,
            os_type: "Ubuntu Linux ARM64".to_string(),
            cpu_count: 4,
            memory_mb: 4096,
            disk_path: Some(format!("{}/environments/{}.utm", self.data_dir.to_string_lossy(), vm_identifier)),
            console_type: Some("utm-gui".to_string()),
            architecture: "aarch64".to_string(),
        })
    }

    fn create_vm(&self, spec: &CreateVmSpec) -> Result<String, HypervisorError> {
        // Validate name
        if spec.name.is_empty() || !spec.name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(HypervisorError::InvalidConfiguration(
                "Environment VM name must only contain alphanumeric characters, hyphens, or underscores".to_string(),
            ));
        }

        // On macOS Apple Silicon UTM, create the environment bundle directory and persistent disk
        let env_dir = Path::new(&spec.disk_path)
            .parent()
            .ok_or_else(|| HypervisorError::InvalidConfiguration("Invalid disk path".to_string()))?;
        std::fs::create_dir_all(env_dir).map_err(|e| {
            HypervisorError::ExecutionFailed(format!("Failed to create environment directory: {}", e))
        })?;

        // Allocate persistent sparse disk image using macOS qemu-img or hdiutil or raw file
        let disk_file = Path::new(&spec.disk_path);
        if !disk_file.exists() {
            // Allocate initial raw disk file placeholder or use qemu-img if available
            let f = std::fs::File::create(disk_file).map_err(|e| {
                HypervisorError::ExecutionFailed(format!("Failed to create persistent disk file: {}", e))
            })?;
            // Set sparse size
            f.set_len(spec.disk_size_mb * 1024 * 1024).map_err(|e| {
                HypervisorError::ExecutionFailed(format!("Failed to allocate disk file length: {}", e))
            })?;
        }

        // Generate guided UTM configuration template / metadata
        let vm_id = format!("utm-{}", spec.name);
        let config_meta_path = env_dir.join("utm_environment_spec.json");
        let meta_content = serde_json::json!({
            "vm_id": vm_id,
            "name": spec.name,
            "architecture": "aarch64",
            "hypervisor": "UTM / Apple Virtualization Framework",
            "guest_os": "Ubuntu Linux ARM64",
            "cpu_cores": spec.cpu_count,
            "memory_mb": spec.memory_mb,
            "disk_path": spec.disk_path,
            "iso_path": spec.iso_path,
            "created_at": chrono::Utc::now().to_rfc3339()
        });
        std::fs::write(&config_meta_path, meta_content.to_string()).ok();

        Ok(vm_id)
    }

    fn start_vm(&self, vm_identifier: &str) -> Result<(), HypervisorError> {
        // If utmctl is available, invoke start
        if self.find_utmctl().is_some() {
            let res = self.run_utmctl(&["start", vm_identifier]);
            if res.is_ok() {
                return Ok(());
            }
        }

        // Also ensure UTM app is running and brought to foreground
        let _ = Command::new("open")
            .args(["-a", "/Applications/UTM.app"])
            .spawn();

        Ok(())
    }

    fn shutdown_vm(&self, vm_identifier: &str, _force: bool) -> Result<(), HypervisorError> {
        if self.find_utmctl().is_some() {
            self.run_utmctl(&["stop", vm_identifier])?;
        }
        Ok(())
    }

    fn delete_vm(&self, vm_identifier: &str, delete_disks: bool) -> Result<(), HypervisorError> {
        let state = self.get_vm_state(vm_identifier).unwrap_or(VmState::Unknown);
        if state == VmState::Running || state == VmState::Starting {
            return Err(HypervisorError::ExecutionFailed(
                "Cannot delete a running UTM environment. Stop the VM first.".to_string(),
            ));
        }

        if delete_disks {
            let env_dir = self.data_dir.join("environments").join(vm_identifier);
            if env_dir.exists() {
                std::fs::remove_dir_all(env_dir).ok();
            }
        }
        Ok(())
    }

    fn open_vm_console(&self, _vm_identifier: &str) -> Result<(), HypervisorError> {
        if let Some(app) = self.find_utm_app() {
            Command::new("open")
                .arg(app)
                .spawn()
                .map_err(|e| HypervisorError::ExecutionFailed(format!("Failed to open UTM console: {}", e)))?;
            Ok(())
        } else {
            Err(HypervisorError::NotFound(
                "UTM application is not installed at /Applications/UTM.app".to_string(),
            ))
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
