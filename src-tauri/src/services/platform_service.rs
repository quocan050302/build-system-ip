use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub os: String,
    pub arch: String,
    pub target_triple: String,
    pub is_supported: bool,
    pub total_memory_mb: u64,
    pub available_memory_mb: u64,
    pub total_disk_mb: u64,
    pub available_disk_mb: u64,
    pub installed_hypervisors: Vec<String>,
    pub supported_capabilities: Vec<String>,
    pub permissions_status: String,
    pub app_data_dir: String,
}

pub struct PlatformService {
    app_data_dir: PathBuf,
}

impl PlatformService {
    pub fn new(app_data_dir: PathBuf) -> Self {
        Self { app_data_dir }
    }

    pub fn get_app_data_dir(&self) -> &Path {
        &self.app_data_dir
    }

    pub fn resolve_default_data_dir() -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            if let Ok(home) = std::env::var("HOME") {
                PathBuf::from(home)
                    .join("Library")
                    .join("Application Support")
                    .join("YouTubeIsolationManager")
            } else {
                PathBuf::from("./app_data")
            }
        }

        #[cfg(windows)]
        {
            if let Ok(appdata) = std::env::var("APPDATA") {
                PathBuf::from(appdata).join("YouTubeIsolationManager")
            } else {
                PathBuf::from("./app_data")
            }
        }

        #[cfg(not(any(target_os = "macos", windows)))]
        {
            if let Ok(home) = std::env::var("HOME") {
                PathBuf::from(home).join(".local").join("share").join("YouTubeIsolationManager")
            } else {
                PathBuf::from("./app_data")
            }
        }
    }

    pub fn detect(&self) -> PlatformInfo {
        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();

        let (target_triple, is_supported) = match (os.as_str(), arch.as_str()) {
            ("windows", "x86_64") => ("windows-x86_64".to_string(), true),
            ("macos", "aarch64") => ("macos-aarch64".to_string(), true),
            _ => (format!("{}-{}", os, arch), false),
        };

        let (total_mem, avail_mem, total_disk, avail_disk) = self.query_system_resources();
        let installed_hypervisors = self.detect_installed_hypervisors();
        let supported_capabilities = self.detect_capabilities(&target_triple);
        let permissions_status = self.check_permissions();

        PlatformInfo {
            os,
            arch,
            target_triple,
            is_supported,
            total_memory_mb: total_mem,
            available_memory_mb: avail_mem,
            total_disk_mb: total_disk,
            available_disk_mb: avail_disk,
            installed_hypervisors,
            supported_capabilities,
            permissions_status,
            app_data_dir: self.app_data_dir.to_string_lossy().to_string(),
        }
    }

    pub fn query_system_resources(&self) -> (u64, u64, u64, u64) {
        #[cfg(windows)]
        {
            use std::mem::zeroed;
            use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
            use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
            use windows::core::HSTRING;

            unsafe {
                let mut mem: MEMORYSTATUSEX = zeroed();
                mem.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
                let _ = GlobalMemoryStatusEx(&mut mem);

                let total_mem = mem.ullTotalPhys / (1024 * 1024);
                let avail_mem = mem.ullAvailPhys / (1024 * 1024);

                let mut free_bytes_avail = 0u64;
                let mut total_bytes = 0u64;
                let mut total_free = 0u64;

                let dir_str = self.app_data_dir.to_string_lossy();
                let drive_prefix = if dir_str.len() >= 3 && &dir_str[1..3] == ":\\" {
                    format!("{}\\", &dir_str[..2])
                } else {
                    "C:\\".to_string()
                };

                let drive_hstring = HSTRING::from(drive_prefix.as_str());
                let _ = GetDiskFreeSpaceExW(
                    &drive_hstring,
                    Some(&mut free_bytes_avail),
                    Some(&mut total_bytes),
                    Some(&mut total_free),
                );

                (
                    total_mem,
                    avail_mem,
                    total_bytes / (1024 * 1024),
                    free_bytes_avail / (1024 * 1024),
                )
            }
        }

        #[cfg(target_os = "macos")]
        {
            let mut total_mem_bytes: u64 = 0;
            let mut size = std::mem::size_of::<u64>();
            unsafe {
                let mut mib = [libc::CTL_HW, libc::HW_MEMSIZE];
                let _ = libc::sysctl(
                    mib.as_mut_ptr(),
                    2,
                    &mut total_mem_bytes as *mut u64 as *mut _,
                    &mut size,
                    std::ptr::null_mut(),
                    0,
                );
            }
            let total_mem_mb = total_mem_bytes / (1024 * 1024);

            let mut available_mem_mb = 0;
            unsafe {
                let mut count = libc::HOST_VM_INFO64_COUNT;
                let mut vm_stat: libc::vm_statistics64 = std::mem::zeroed();
            #[allow(deprecated)]
            let host_port = libc::mach_host_self();
                let ret = libc::host_statistics64(
                    host_port,
                    libc::HOST_VM_INFO64,
                    &mut vm_stat as *mut _ as *mut _,
                    &mut count,
                );
                if ret == libc::KERN_SUCCESS {
                    let page_size = libc::sysconf(libc::_SC_PAGESIZE) as u64;
                    let page_size = if page_size == 0 { 4096 } else { page_size };
                    let avail_bytes = (vm_stat.free_count as u64 + vm_stat.inactive_count as u64) * page_size;
                    available_mem_mb = avail_bytes / (1024 * 1024);
                }
            }

            let mut total_disk_mb = 0;
            let mut available_disk_mb = 0;
            let check_dir = if self.app_data_dir.exists() {
                &self.app_data_dir
            } else {
                Path::new("/")
            };

            let c_path = std::ffi::CString::new(check_dir.to_string_lossy().as_bytes())
                .unwrap_or_else(|_| std::ffi::CString::new("/").unwrap());
            unsafe {
                let mut stat: libc::statvfs = std::mem::zeroed();
                if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
                    let frsize = stat.f_frsize as u64;
                    total_disk_mb = (stat.f_blocks as u64 * frsize) / (1024 * 1024);
                    available_disk_mb = (stat.f_bavail as u64 * frsize) / (1024 * 1024);
                }
            }

            (total_mem_mb, available_mem_mb, total_disk_mb, available_disk_mb)
        }

        #[cfg(not(any(windows, target_os = "macos")))]
        {
            // Fallback for non-target platforms (Linux/BSD) using standard statvfs and /proc/meminfo
            let mut total_mem_mb = 0;
            let mut avail_mem_mb = 0;
            if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
                for line in meminfo.lines() {
                    if line.starts_with("MemTotal:") {
                        if let Some(val) = line.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok()) {
                            total_mem_mb = val / 1024;
                        }
                    } else if line.starts_with("MemAvailable:") {
                        if let Some(val) = line.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok()) {
                            avail_mem_mb = val / 1024;
                        }
                    }
                }
            }

            let mut total_disk_mb = 0;
            let mut available_disk_mb = 0;
            unsafe {
                let mut stat: libc::statvfs = std::mem::zeroed();
                if libc::statvfs(b"/\0".as_ptr() as *const _, &mut stat) == 0 {
                    let frsize = stat.f_frsize as u64;
                    total_disk_mb = (stat.f_blocks as u64 * frsize) / (1024 * 1024);
                    available_disk_mb = (stat.f_bavail as u64 * frsize) / (1024 * 1024);
                }
            }

            (total_mem_mb, avail_mem_mb, total_disk_mb, available_disk_mb)
        }
    }

    fn detect_installed_hypervisors(&self) -> Vec<String> {
        let mut list = Vec::new();

        #[cfg(target_os = "macos")]
        {
            if Path::new("/Applications/UTM.app").exists() || Path::new("/Applications/UTM.app/Contents/MacOS/utmctl").exists() {
                list.push("UTM".to_string());
            }
            if std::process::Command::new("which").arg("utmctl").output().map(|o| o.status.success()).unwrap_or(false) {
                if !list.contains(&"UTM".to_string()) {
                    list.push("UTM".to_string());
                }
            }
            if Path::new("/Applications/VirtualBox.app").exists() || Path::new("/usr/local/bin/VBoxManage").exists() {
                list.push("VirtualBox".to_string());
            }
        }

        #[cfg(windows)]
        {
            // Check Hyper-V via service or PowerShell
            let hyperv_active = std::process::Command::new("powershell")
                .args(["-NoProfile", "-Command", "Get-Service vmms -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("Running"))
                .unwrap_or(false);

            if hyperv_active {
                list.push("Hyper-V".to_string());
            }

            let default_win_path = PathBuf::from("C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe");
            if default_win_path.exists() {
                list.push("VirtualBox".to_string());
            }
        }

        list
    }

    fn detect_capabilities(&self, target_triple: &str) -> Vec<String> {
        let mut caps = Vec::new();

        match target_triple {
            "macos-aarch64" => {
                caps.push("Apple Silicon Native Virtualization".to_string());
                caps.push("UTM Virtual Machine Manager".to_string());
                caps.push("Ubuntu ARM64 Native Guest Virtualization".to_string());
                caps.push("Apple Keychain Secret Sealing".to_string());
            }
            "windows-x86_64" => {
                caps.push("Microsoft Hyper-V Type-1 Hypervisor".to_string());
                caps.push("VHDX Dynamic Persistent Disks".to_string());
                caps.push("Windows DPAPI Hardware-bound Vault".to_string());
                caps.push("VMConnect Virtual Machine Console".to_string());
            }
            _ => {
                caps.push("Generic Unsupported Host".to_string());
            }
        }

        caps
    }

    fn check_permissions(&self) -> String {
        #[cfg(windows)]
        {
            // Check admin token on Windows
            let is_admin = std::process::Command::new("powershell")
                .args(["-NoProfile", "-Command", "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("True"))
                .unwrap_or(false);

            if is_admin {
                "ADMIN_ELEVATED".to_string()
            } else {
                "STANDARD_USER".to_string()
            }
        }

        #[cfg(target_os = "macos")]
        {
            "USER_STANDARD".to_string()
        }

        #[cfg(not(any(windows, target_os = "macos")))]
        {
            "UNRESTRICTED".to_string()
        }
    }
}
