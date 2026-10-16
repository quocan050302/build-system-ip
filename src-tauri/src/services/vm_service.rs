use crate::db::Database;
use crate::hypervisor::{CreateVmSpec, HostResources, HypervisorAdapter, HypervisorInfo};
use crate::services::audit_service::AuditService;
use crate::services::profile_service::ProfileService;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentRecord {
    pub id: String,
    pub name: String,
    pub hypervisor_type: String,
    pub vm_identifier: String,
    pub guest_os: String,
    pub cpu_count: u32,
    pub memory_mb: u64,
    pub disk_path: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    // Cross-platform & isolation fields (Phase 10 migration)
    pub host_platform: String,
    pub vm_architecture: String,
    pub provisioning_status: String,
    pub persistent_disk_reference: Option<String>,
    pub network_diagnostics_capability: String,
    // Joined relations
    pub browser_profile_path: Option<String>,
    pub network_endpoint_id: Option<String>,
    pub network_endpoint_name: Option<String>,
    pub last_observed_ipv4: Option<String>,
    pub last_checked_at: Option<String>,
    pub channel_id: Option<String>,
    pub channel_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEnvironmentRequest {
    pub name: String,
    pub hypervisor_type: String,
    pub guest_os: String,
    pub cpu_count: u32,
    pub memory_mb: u64,
    pub disk_size_mb: u64,
    pub iso_path: Option<String>,
    pub browser_type: String,
    pub network_endpoint_id: Option<String>,
    pub channel_id: Option<String>,
    pub host_platform: Option<String>,
    pub vm_architecture: Option<String>,
}

pub struct VmService {
    db: Database,
    hypervisor: Arc<dyn HypervisorAdapter>,
    profile_service: Arc<ProfileService>,
    audit_service: Arc<AuditService>,
    base_data_dir: PathBuf,
}

impl VmService {
    pub fn new(
        db: Database,
        hypervisor: Arc<dyn HypervisorAdapter>,
        profile_service: Arc<ProfileService>,
        audit_service: Arc<AuditService>,
        base_data_dir: PathBuf,
    ) -> Self {
        Self {
            db,
            hypervisor,
            profile_service,
            audit_service,
            base_data_dir,
        }
    }

    pub fn get_hypervisor_info(&self) -> Result<HypervisorInfo, String> {
        self.hypervisor.detect().map_err(|e| e.to_string())
    }

    pub fn get_host_resources(&self) -> Result<HostResources, String> {
        self.hypervisor.get_system_resources().map_err(|e| e.to_string())
    }

    pub fn reconcile_states(&self) -> Result<usize, String> {
        let envs = self.list_environments()?;
        let mut updated = 0;
        let now = Utc::now().to_rfc3339();

        for env in envs {
            if let Ok(real_state) = self.hypervisor.get_vm_state(&env.vm_identifier) {
                let state_str = real_state.as_str();
                if state_str != "UNKNOWN" && state_str != env.status {
                    let env_id = env.id.clone();
                    self.db.with_conn(|conn| {
                        conn.execute(
                            "UPDATE environments SET status = ?1, updated_at = ?2 WHERE id = ?3",
                            rusqlite::params![state_str, now, env_id],
                        )
                    }).map_err(|e| e.to_string())?;
                    updated += 1;
                }
            }
        }

        Ok(updated)
    }

    pub fn create_environment(&self, req: CreateEnvironmentRequest) -> Result<EnvironmentRecord, String> {
        // Preflight validation: name formatting
        let clean_name = req.name.trim();
        if clean_name.is_empty() {
            return Err("Environment name cannot be empty".to_string());
        }
        if !clean_name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err("Environment name may only contain alphanumeric characters, hyphens, and underscores".to_string());
        }

        // Check for duplicate name in DB
        let name_exists: bool = self.db.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT COUNT(1) FROM environments WHERE name = ?1")?;
            let count: i64 = stmt.query_row(rusqlite::params![clean_name], |r| r.get(0))?;
            Ok(count > 0)
        }).map_err(|e| e.to_string())?;

        if name_exists {
            return Err(format!("An environment named '{}' already exists", clean_name));
        }

        // Check ISO path if provided
        if let Some(ref iso) = req.iso_path {
            if !iso.trim().is_empty() && !Path::new(iso).exists() {
                return Err(format!("Specified ISO image does not exist: {}", iso));
            }
        }

        // Check available host resources
        if let Ok(resources) = self.hypervisor.get_system_resources() {
            if req.memory_mb > resources.available_memory_mb && resources.available_memory_mb > 0 {
                return Err(format!(
                    "Requested RAM ({} MB) exceeds available host RAM ({} MB)",
                    req.memory_mb, resources.available_memory_mb
                ));
            }
            // For thin-provisioned sparse disks (UTM .utm and Hyper-V .vhdx), initial disk usage
            // is minimal (sparse file). Ensure host has at least 512 MB headroom to safely provision.
            let is_sparse = matches!(req.hypervisor_type.to_lowercase().as_str(), "utm" | "hyper-v" | "hyperv");
            if is_sparse {
                if resources.available_disk_mb < 512 && resources.available_disk_mb > 0 {
                    return Err(format!(
                        "Host disk is critically low ({} MB available). At least 512 MB free disk space required.",
                        resources.available_disk_mb
                    ));
                }
            } else if req.disk_size_mb > resources.available_disk_mb && resources.available_disk_mb > 0 {
                return Err(format!(
                    "Requested virtual disk size ({} MB) exceeds available host disk space ({} MB)",
                    req.disk_size_mb, resources.available_disk_mb
                ));
            }
        }

        let env_id = Uuid::new_v4().to_string();
        let env_dir = self.base_data_dir.join("environments").join(&env_id);
        std::fs::create_dir_all(&env_dir).map_err(|e| format!("Failed to create environment directory: {}", e))?;

        // Determine platform-specific persistent virtual disk format
        let disk_ext = match req.hypervisor_type.to_lowercase().as_str() {
            "hyper-v" | "hyperv" => "vhdx",
            "utm" => "utm",
            "virtualbox" => "vdi",
            _ => {
                #[cfg(target_os = "macos")]
                { "utm" }
                #[cfg(windows)]
                { "vhdx" }
                #[cfg(not(any(target_os = "macos", windows)))]
                { "vdi" }
            }
        };

        let host_platform = req.host_platform.unwrap_or_else(|| {
            format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
        });
        let vm_architecture = req.vm_architecture.unwrap_or_else(|| {
            std::env::consts::ARCH.to_string()
        });

        let disk_path = env_dir.join(format!("{}.{}", clean_name, disk_ext));
        let disk_path_str = disk_path.to_string_lossy().to_string();

        let vm_spec = CreateVmSpec {
            name: format!("{}-{}", clean_name, &env_id[..8]),
            guest_os: req.guest_os.clone(),
            cpu_count: req.cpu_count,
            memory_mb: req.memory_mb,
            disk_size_mb: req.disk_size_mb,
            disk_path: disk_path_str.clone(),
            iso_path: req.iso_path.clone(),
        };

        // Invoke hypervisor creation
        let vm_identifier = match self.hypervisor.create_vm(&vm_spec) {
            Ok(id) => id,
            Err(e) => {
                // Rollback directory on failure
                std::fs::remove_dir_all(&env_dir).ok();
                return Err(format!("Hypervisor failed to create VM: {}", e));
            }
        };

        let now = Utc::now().to_rfc3339();

        // Insert into DB with platform-aware fields
        let insert_res = self.db.with_conn_mut(|conn| {
            let tx = conn.transaction()?;

            tx.execute(
                "INSERT INTO environments (
                    id, name, hypervisor_type, vm_identifier, guest_os, cpu_count, memory_mb,
                    disk_path, status, created_at, updated_at,
                    host_platform, vm_architecture, provisioning_status, persistent_disk_reference, network_diagnostics_capability
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                rusqlite::params![
                    env_id,
                    clean_name,
                    req.hypervisor_type,
                    vm_identifier,
                    req.guest_os,
                    req.cpu_count,
                    req.memory_mb,
                    disk_path_str,
                    "STOPPED",
                    now,
                    now,
                    host_platform,
                    vm_architecture,
                    "COMPLETED",
                    disk_path_str,
                    "DIRECT_PROBE"
                ],
            )?;

            // If network endpoint provided, link it
            if let Some(ref ep_id) = req.network_endpoint_id {
                let link_id = Uuid::new_v4().to_string();
                tx.execute(
                    "INSERT INTO environment_networks (id, environment_id, network_endpoint_id, policy_config, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![link_id, env_id, ep_id, "{}", now],
                )?;
            }

            // If channel provided, link it
            if let Some(ref ch_id) = req.channel_id {
                tx.execute(
                    "UPDATE channels SET environment_id = ?1, updated_at = ?2 WHERE id = ?3",
                    rusqlite::params![env_id, now, ch_id],
                )?;
            }

            tx.commit()?;
            Ok(())
        });

        if let Err(e) = insert_res {
            self.hypervisor.delete_vm(&vm_identifier, true).ok();
            std::fs::remove_dir_all(&env_dir).ok();
            return Err(format!("Database error during environment creation: {}", e));
        }

        // Create isolated browser profile reference
        let _profile = self.profile_service.create_profile(&env_id, &req.browser_type)?;

        // Audit log
        self.audit_service.log(
            Some(&env_id),
            "CREATE_ENVIRONMENT",
            "INFO",
            &format!("Created environment '{}' with VM identifier '{}' ({})", clean_name, vm_identifier, req.hypervisor_type),
        ).ok();

        self.get_environment(&env_id)?
            .ok_or_else(|| "Failed to retrieve newly created environment".to_string())
    }

    pub fn list_environments(&self) -> Result<Vec<EnvironmentRecord>, String> {
        self.db.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT e.id, e.name, e.hypervisor_type, e.vm_identifier, e.guest_os, e.cpu_count, e.memory_mb, 
                        e.disk_path, e.status, e.created_at, e.updated_at,
                        COALESCE(e.host_platform, 'unknown'),
                        COALESCE(e.vm_architecture, 'x86_64'),
                        COALESCE(e.provisioning_status, 'COMPLETED'),
                        e.persistent_disk_reference,
                        COALESCE(e.network_diagnostics_capability, 'DIRECT_PROBE'),
                        bp.profile_path,
                        en.network_endpoint_id, ne.name as network_endpoint_name,
                        nc.observed_ipv4, nc.checked_at,
                        c.id as channel_id, c.display_name as channel_name
                 FROM environments e
                 LEFT JOIN browser_profiles bp ON bp.environment_id = e.id
                 LEFT JOIN environment_networks en ON en.environment_id = e.id
                 LEFT JOIN network_endpoints ne ON ne.id = en.network_endpoint_id
                 LEFT JOIN (
                     SELECT environment_id, observed_ipv4, checked_at 
                     FROM network_checks 
                     WHERE id IN (SELECT id FROM network_checks GROUP BY environment_id HAVING MAX(checked_at))
                 ) nc ON nc.environment_id = e.id
                 LEFT JOIN channels c ON c.environment_id = e.id
                 ORDER BY e.created_at DESC"
            )?;

            let rows = stmt.query_map([], |row| {
                Ok(EnvironmentRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    hypervisor_type: row.get(2)?,
                    vm_identifier: row.get(3)?,
                    guest_os: row.get(4)?,
                    cpu_count: row.get(5)?,
                    memory_mb: row.get(6)?,
                    disk_path: row.get(7)?,
                    status: row.get(8)?,
                    created_at: row.get(9)?,
                    updated_at: row.get(10)?,
                    host_platform: row.get(11)?,
                    vm_architecture: row.get(12)?,
                    provisioning_status: row.get(13)?,
                    persistent_disk_reference: row.get(14)?,
                    network_diagnostics_capability: row.get(15)?,
                    browser_profile_path: row.get(16)?,
                    network_endpoint_id: row.get(17)?,
                    network_endpoint_name: row.get(18)?,
                    last_observed_ipv4: row.get(19)?,
                    last_checked_at: row.get(20)?,
                    channel_id: row.get(21)?,
                    channel_name: row.get(22)?,
                })
            })?;

            let mut envs = Vec::new();
            for r in rows {
                envs.push(r?);
            }
            Ok(envs)
        }).map_err(|e| e.to_string())
    }

    pub fn get_environment(&self, id: &str) -> Result<Option<EnvironmentRecord>, String> {
        let envs = self.list_environments()?;
        Ok(envs.into_iter().find(|e| e.id == id))
    }

    pub fn start_environment(&self, id: &str) -> Result<(), String> {
        let env = self.get_environment(id)?
            .ok_or_else(|| format!("Environment {} not found", id))?;

        self.hypervisor.start_vm(&env.vm_identifier)
            .map_err(|e| {
                self.audit_service.log(
                    Some(id),
                    "START_VM_FAILED",
                    "ERROR",
                    &format!("Failed to start VM: {}", e),
                ).ok();
                format!("Failed to start VM in hypervisor: {}", e)
            })?;

        let now = Utc::now().to_rfc3339();
        self.db.with_conn(|conn| {
            conn.execute(
                "UPDATE environments SET status = 'RUNNING', updated_at = ?1 WHERE id = ?2",
                rusqlite::params![now, id],
            )
        }).map_err(|e| e.to_string())?;

        self.audit_service.log(
            Some(id),
            "START_VM",
            "INFO",
            &format!("Started VM '{}' ({})", env.name, env.hypervisor_type),
        ).ok();

        Ok(())
    }

    pub fn shutdown_environment(&self, id: &str, force: bool) -> Result<(), String> {
        let env = self.get_environment(id)?
            .ok_or_else(|| format!("Environment {} not found", id))?;

        self.hypervisor.shutdown_vm(&env.vm_identifier, force)
            .map_err(|e| format!("Hypervisor shutdown failed: {}", e))?;

        let now = Utc::now().to_rfc3339();
        self.db.with_conn(|conn| {
            conn.execute(
                "UPDATE environments SET status = 'STOPPED', updated_at = ?1 WHERE id = ?2",
                rusqlite::params![now, id],
            )
        }).map_err(|e| e.to_string())?;

        self.audit_service.log(
            Some(id),
            if force { "FORCE_STOP_VM" } else { "GRACEFUL_SHUTDOWN_VM" },
            "INFO",
            &format!("Shutdown VM '{}' (force: {})", env.name, force),
        ).ok();

        Ok(())
    }

    pub fn open_console(&self, id: &str) -> Result<(), String> {
        let env = self.get_environment(id)?
            .ok_or_else(|| format!("Environment {} not found", id))?;

        self.hypervisor.open_vm_console(&env.vm_identifier)
            .map_err(|e| format!("Failed to open VM console: {}", e))?;

        self.audit_service.log(
            Some(id),
            "OPEN_CONSOLE",
            "INFO",
            &format!("Opened console for VM '{}'", env.name),
        ).ok();

        Ok(())
    }

    pub fn launch_guest_browser(&self, id: &str) -> Result<(), String> {
        let env = self.get_environment(id)?
            .ok_or_else(|| format!("Environment {} not found", id))?;

        if env.status != "RUNNING" {
            // Auto start if stopped
            self.start_environment(id)?;
        }

        // Open console to guest OS where browser runs
        self.hypervisor.open_vm_console(&env.vm_identifier)
            .map_err(|e| format!("Failed to access guest environment: {}", e))?;

        self.audit_service.log(
            Some(id),
            "LAUNCH_GUEST_BROWSER",
            "INFO",
            &format!("Launched isolated browser session inside guest VM '{}'", env.name),
        ).ok();

        Ok(())
    }

    pub fn delete_environment(&self, id: &str, delete_disks: bool) -> Result<(), String> {
        let env = self.get_environment(id)?
            .ok_or_else(|| format!("Environment {} not found", id))?;

        if env.status == "RUNNING" || env.status == "STARTING" {
            return Err("Cannot delete a running environment. Please stop or shut down the VM first.".to_string());
        }

        self.hypervisor.delete_vm(&env.vm_identifier, delete_disks)
            .map_err(|e| format!("Failed to delete VM from hypervisor: {}", e))?;

        if let Some(ref path) = env.browser_profile_path {
            self.profile_service.delete_profile_files(path).ok();
        }

        if delete_disks {
            let env_dir = self.base_data_dir.join("environments").join(id);
            if env_dir.exists() {
                std::fs::remove_dir_all(&env_dir).ok();
            }
        }

        self.db.with_conn(|conn| {
            conn.execute("DELETE FROM environments WHERE id = ?1", rusqlite::params![id])
        }).map_err(|e| e.to_string())?;

        self.audit_service.log(
            Some(id),
            "DELETE_ENVIRONMENT",
            "WARN",
            &format!("Deleted environment '{}'", env.name),
        ).ok();

        Ok(())
    }
}
