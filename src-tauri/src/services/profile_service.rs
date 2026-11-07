use crate::db::Database;
use crate::security::{get_secret_store, SecretStore};
use crate::services::proxy_bridge::{ProxyBridgeManager, UpstreamProxyConfig};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BrowserError {
    #[error("Browser '{0}' is not installed on this system.Searched paths: {1}")]
    NotInstalled(String, String),
    #[error("Invalid browser executable at '{0}': {1}")]
    InvalidExecutable(String, String),
    #[error("Invalid startup URL '{0}': {1}")]
    InvalidUrl(String, String),
    #[error("Path validation failed: {0}")]
    InvalidPath(String),
    #[error("Browser profile for environment '{0}' is already running (PID {1})")]
    AlreadyRunning(String, u32),
    #[error("Cannot delete profile while browser session is active for environment '{0}'")]
    ProfileActive(String),
    #[error("Proxy configuration error (direct fallback blocked): {0}")]
    ProxyConfigError(String),
    #[error("Failed to launch browser process: {0}")]
    LaunchFailed(String),
    #[error("Browser session '{0}' not found")]
    SessionNotFound(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BrowserInfo {
    pub browser_type: String,
    pub display_name: String,
    pub installed: bool,
    pub executable_path: Option<String>,
    pub version: Option<String>,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserLaunchConfig {
    pub environment_id: String,
    pub browser_type: String,
    pub profile_dir: PathBuf,
    pub startup_url: String,
    pub proxy_server: Option<String>,
    pub proxy_bridge_port: Option<u16>,
    pub preferred_language: String,
    pub us_content_preferences: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrowserStatus {
    Running {
        pid: u32,
        started_at: String,
        proxy_bridge_port: Option<u16>,
        startup_url: String,
    },
    Stopped,
    Error(String),
}

impl BrowserStatus {
    pub fn is_running(&self) -> bool {
        matches!(self, BrowserStatus::Running { .. })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            BrowserStatus::Running { .. } => "RUNNING",
            BrowserStatus::Stopped => "STOPPED",
            BrowserStatus::Error(_) => "ERROR",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSession {
    pub session_id: String,
    pub environment_id: String,
    pub browser_type: String,
    pub executable_path: String,
    pub profile_path: String,
    pub pid: u32,
    pub startup_url: String,
    pub proxy_server: Option<String>,
    pub proxy_bridge_port: Option<u16>,
    pub preferred_language: String,
    pub started_at: String,
    pub status: String,
}

pub trait BrowserLauncher: Send + Sync {
    fn detect(&self) -> Result<BrowserInfo, BrowserError>;
    fn detect_browser(&self, browser_type: &str) -> Result<BrowserInfo, BrowserError>;
    fn list_browsers(&self) -> Vec<BrowserInfo>;
    fn launch(&self, config: BrowserLaunchConfig) -> Result<BrowserSession, BrowserError>;
    fn stop(&self, session_id: &str) -> Result<(), BrowserError>;
    fn status(&self, session_id: &str) -> Result<BrowserStatus, BrowserError>;
}

struct ManagedProcess {
    session: BrowserSession,
    child: Option<Child>,
}

pub struct SystemBrowserLauncher {
    sessions: Mutex<HashMap<String, ManagedProcess>>,
    custom_search_paths: Option<HashMap<String, Vec<PathBuf>>>,
    dry_run_spawn: bool,
}

impl SystemBrowserLauncher {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            custom_search_paths: None,
            dry_run_spawn: false,
        }
    }

    pub fn with_custom_paths(
        custom_paths: HashMap<String, Vec<PathBuf>>,
        dry_run_spawn: bool,
    ) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            custom_search_paths: Some(custom_paths),
            dry_run_spawn,
        }
    }

    pub fn candidate_paths(&self, browser_type: &str) -> Vec<PathBuf> {
        let key = browser_type.trim().to_lowercase();
        if let Some(ref map) = self.custom_search_paths {
            if let Some(paths) = map.get(&key) {
                return paths.clone();
            }
            return Vec::new();
        }

        let mut paths = Vec::new();
        let home_apps = std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join("Applications"));

        #[cfg(target_os = "macos")]
        {
            match key.as_str() {
                "edge" | "msedge" | "microsoft-edge" | "microsoft edge" => {
                    paths.push(PathBuf::from(
                        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                    ));
                    if let Some(ref ha) = home_apps {
                        paths.push(ha.join("Microsoft Edge.app/Contents/MacOS/Microsoft Edge"));
                    }
                }
                "chrome" | "google-chrome" => {
                    paths.push(PathBuf::from(
                        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                    ));
                    if let Some(ref ha) = home_apps {
                        paths.push(ha.join("Google Chrome.app/Contents/MacOS/Google Chrome"));
                    }
                }
                "brave" => {
                    paths.push(PathBuf::from(
                        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
                    ));
                    if let Some(ref ha) = home_apps {
                        paths.push(ha.join("Brave Browser.app/Contents/MacOS/Brave Browser"));
                    }
                }
                "firefox" => {
                    paths.push(PathBuf::from(
                        "/Applications/Firefox.app/Contents/MacOS/firefox",
                    ));
                    if let Some(ref ha) = home_apps {
                        paths.push(ha.join("Firefox.app/Contents/MacOS/firefox"));
                    }
                }
                _ => {
                    paths.push(PathBuf::from(
                        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                    ));
                    if let Some(ref ha) = home_apps {
                        paths.push(ha.join("Microsoft Edge.app/Contents/MacOS/Microsoft Edge"));
                    }
                }
            }
        }

        #[cfg(windows)]
        {
            let local_app_data = std::env::var("LOCALAPPDATA").ok().map(PathBuf::from);
            match key.as_str() {
                "edge" | "msedge" | "microsoft-edge" | "microsoft edge" => {
                    paths.push(PathBuf::from(
                        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                    ));
                    paths.push(PathBuf::from(
                        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                    ));
                    if let Some(ref lad) = local_app_data {
                        paths.push(lad.join(r"Microsoft\Edge\Application\msedge.exe"));
                    }
                }
                "brave" => {
                    paths.push(PathBuf::from(
                        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
                    ));
                    paths.push(PathBuf::from(
                        r"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe",
                    ));
                    if let Some(ref lad) = local_app_data {
                        paths.push(lad.join(r"BraveSoftware\Brave-Browser\Application\brave.exe"));
                    }
                }
                "firefox" => {
                    paths.push(PathBuf::from(
                        r"C:\Program Files\Mozilla Firefox\firefox.exe",
                    ));
                    paths.push(PathBuf::from(
                        r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
                    ));
                }
                _ => {
                    paths.push(PathBuf::from(
                        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                    ));
                    paths.push(PathBuf::from(
                        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                    ));
                    if let Some(ref lad) = local_app_data {
                        paths.push(lad.join(r"Google\Chrome\Application\chrome.exe"));
                    }
                }
            }
        }

        #[cfg(not(any(target_os = "macos", windows)))]
        {
            let _ = home_apps;
            match key.as_str() {
                "edge" | "msedge" => {
                    paths.push(PathBuf::from("/usr/bin/microsoft-edge"));
                    paths.push(PathBuf::from("/usr/bin/microsoft-edge-stable"));
                }
                "brave" => {
                    paths.push(PathBuf::from("/usr/bin/brave-browser"));
                }
                "firefox" => {
                    paths.push(PathBuf::from("/usr/bin/firefox"));
                }
                _ => {
                    paths.push(PathBuf::from("/usr/bin/google-chrome"));
                    paths.push(PathBuf::from("/usr/bin/chromium-browser"));
                }
            }
        }

        paths
    }

    pub fn validate_executable(path: &Path) -> Result<(), BrowserError> {
        if !path.exists() {
            return Err(BrowserError::InvalidExecutable(
                path.to_string_lossy().to_string(),
                "File does not exist".to_string(),
            ));
        }
        let meta = std::fs::metadata(path).map_err(|e| {
            BrowserError::InvalidExecutable(path.to_string_lossy().to_string(), e.to_string())
        })?;
        if !meta.is_file() {
            return Err(BrowserError::InvalidExecutable(
                path.to_string_lossy().to_string(),
                "Path is not a regular file".to_string(),
            ));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o111 == 0 {
                return Err(BrowserError::InvalidExecutable(
                    path.to_string_lossy().to_string(),
                    "File does not have executable permissions".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn detect_version(exe_path: &Path) -> Option<String> {
        // On macOS, check Info.plist inside the .app bundle first (instant and doesn't spawn browser window)
        #[cfg(target_os = "macos")]
        {
            if let Some(macos_dir) = exe_path.parent() {
                if let Some(contents_dir) = macos_dir.parent() {
                    let info_plist = contents_dir.join("Info");
                    if contents_dir.join("Info.plist").exists() {
                        if let Ok(output) = Command::new("defaults")
                            .args([
                                "read",
                                &info_plist.to_string_lossy(),
                                "CFBundleShortVersionString",
                            ])
                            .output()
                        {
                            if output.status.success() {
                                let v = String::from_utf8_lossy(&output.stdout).trim().to_string();
                                if !v.is_empty() {
                                    return Some(v);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Fallback: invoke `--version` on Unix/macOS (avoid on Windows GUI binaries where --version may spawn a window)
        #[cfg(not(windows))]
        {
            if let Ok(output) = Command::new(exe_path).arg("--version").output() {
                if output.status.success() {
                    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !raw.is_empty() {
                        let version_token = raw
                            .split_whitespace()
                            .find(|tok| tok.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false))
                            .unwrap_or(&raw);
                        return Some(version_token.to_string());
                    }
                }
            }
        }

        None
    }

    pub fn display_name_for(browser_type: &str) -> &'static str {
        match browser_type.trim().to_lowercase().as_str() {
            "edge" | "msedge" | "microsoft-edge" | "microsoft edge" => "Microsoft Edge",
            "chrome" | "google-chrome" => "Google Chrome",
            "brave" => "Brave Browser",
            "firefox" => "Mozilla Firefox",
            _ => "Browser",
        }
    }

    pub fn normalize_browser_type(browser_type: &str) -> String {
        match browser_type.trim().to_lowercase().as_str() {
            "edge" | "msedge" | "microsoft-edge" | "microsoft edge" => "edge".to_string(),
            "chrome" | "google-chrome" => "chrome".to_string(),
            "brave" => "brave".to_string(),
            "firefox" => "firefox".to_string(),
            other => other.to_string(),
        }
    }

    pub fn validate_startup_url(url: &str) -> Result<String, BrowserError> {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            return Err(BrowserError::InvalidUrl(
                url.to_string(),
                "Startup URL cannot be empty".to_string(),
            ));
        }
        if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(BrowserError::InvalidUrl(
                url.to_string(),
                "URL must not contain whitespace or control characters".to_string(),
            ));
        }
        if !(trimmed.starts_with("https://") || trimmed.starts_with("http://")) {
            return Err(BrowserError::InvalidUrl(
                url.to_string(),
                "Only http:// and https:// startup URLs are permitted".to_string(),
            ));
        }
        let after_scheme = trimmed
            .strip_prefix("https://")
            .or_else(|| trimmed.strip_prefix("http://"))
            .unwrap_or("");
        let host_part = after_scheme.split('/').next().unwrap_or("");
        if host_part.is_empty() || !host_part.contains('.') && !host_part.starts_with("localhost") && !host_part.starts_with("127.0.0.1") {
            return Err(BrowserError::InvalidUrl(
                url.to_string(),
                "URL must include a valid hostname".to_string(),
            ));
        }
        Ok(trimmed.to_string())
    }

    fn write_us_profile_preferences(
        profile_dir: &Path,
        preferred_language: &str,
        us_content_preferences: bool,
    ) -> Result<(), BrowserError> {
        let default_dir = profile_dir.join("Default");
        std::fs::create_dir_all(&default_dir).map_err(|e| {
            BrowserError::LaunchFailed(format!("Failed creating Default profile directory: {}", e))
        })?;

        let prefs_path = default_dir.join("Preferences");
        let mut prefs_json: serde_json::Value = if prefs_path.exists() {
            std::fs::read_to_string(&prefs_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_else(|| serde_json::json!({}))
        } else {
            serde_json::json!({})
        };

        let lang_list = if us_content_preferences {
            if preferred_language.contains(',') {
                preferred_language.to_string()
            } else {
                format!("{},en", preferred_language)
            }
        } else {
            preferred_language.to_string()
        };

        if let Some(obj) = prefs_json.as_object_mut() {
            obj.insert(
                "intl".to_string(),
                serde_json::json!({
                    "accept_languages": lang_list,
                    "selected_languages": lang_list,
                }),
            );
            // Prevent WebRTC UDP local/public IP leakage when using a proxy
            obj.insert(
                "webrtc".to_string(),
                serde_json::json!({
                    "ip_handling_policy": "disable_non_proxied_udp",
                    "multiple_routes_enabled": false,
                    "nonproxied_udp_enabled": false
                }),
            );
            obj.insert(
                "browser".to_string(),
                serde_json::json!({
                    "has_seen_welcome_page": true,
                    "check_default_browser": false
                }),
            );
        }

        if let Ok(serialized) = serde_json::to_string_pretty(&prefs_json) {
            let _ = std::fs::write(&prefs_path, serialized);
        }
        Ok(())
    }

    fn refresh_process_state(proc_entry: &mut ManagedProcess) -> bool {
        if let Some(ref mut child) = proc_entry.child {
            match child.try_wait() {
                Ok(Some(_exit_status)) => {
                    proc_entry.session.status = "STOPPED".to_string();
                    proc_entry.child = None;
                    return false;
                }
                Ok(None) => return true,
                Err(_) => {
                    proc_entry.session.status = "STOPPED".to_string();
                    proc_entry.child = None;
                    return false;
                }
            }
        }
        // In dry_run mode (unit tests), status string governs running state
        proc_entry.session.status == "RUNNING"
    }
}

impl BrowserLauncher for SystemBrowserLauncher {
    fn detect(&self) -> Result<BrowserInfo, BrowserError> {
        self.detect_browser("edge")
    }

    fn detect_browser(&self, browser_type: &str) -> Result<BrowserInfo, BrowserError> {
        let norm = Self::normalize_browser_type(browser_type);
        let candidates = self.candidate_paths(&norm);
        let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);

        for candidate in &candidates {
            if Self::validate_executable(candidate).is_ok() {
                let version = Self::detect_version(candidate);
                return Ok(BrowserInfo {
                    browser_type: norm.clone(),
                    display_name: Self::display_name_for(&norm).to_string(),
                    installed: true,
                    executable_path: Some(candidate.to_string_lossy().to_string()),
                    version,
                    platform,
                });
            }
        }

        #[cfg(windows)]
        {
            if self.custom_search_paths.is_none() {
                let bin_name = match norm.as_str() {
                    "edge" => "msedge.exe",
                    "brave" => "brave.exe",
                    "firefox" => "firefox.exe",
                    _ => "chrome.exe",
                };
                if let Ok(output) = Command::new("where.exe").arg(bin_name).output() {
                    if output.status.success() {
                        if let Some(line) = String::from_utf8_lossy(&output.stdout).lines().next() {
                            let p = PathBuf::from(line.trim());
                            if Self::validate_executable(&p).is_ok() {
                                return Ok(BrowserInfo {
                                    browser_type: norm.clone(),
                                    display_name: Self::display_name_for(&norm).to_string(),
                                    installed: true,
                                    executable_path: Some(p.to_string_lossy().to_string()),
                                    version: None,
                                    platform,
                                });
                            }
                        }
                    }
                }
            }
        }

        let searched = candidates
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(", ");

        Err(BrowserError::NotInstalled(
            Self::display_name_for(&norm).to_string(),
            searched,
        ))
    }

    fn list_browsers(&self) -> Vec<BrowserInfo> {
        let types = ["edge", "chrome", "brave", "firefox"];
        let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        types
            .iter()
            .map(|t| match self.detect_browser(t) {
                Ok(info) => info,
                Err(_) => BrowserInfo {
                    browser_type: (*t).to_string(),
                    display_name: Self::display_name_for(t).to_string(),
                    installed: false,
                    executable_path: None,
                    version: None,
                    platform: platform.clone(),
                },
            })
            .collect()
    }

    fn launch(&self, config: BrowserLaunchConfig) -> Result<BrowserSession, BrowserError> {
        let valid_url = Self::validate_startup_url(&config.startup_url)?;
        let browser_info = self.detect_browser(&config.browser_type)?;
        let exe_str = browser_info.executable_path.ok_or_else(|| {
            BrowserError::NotInstalled(config.browser_type.clone(), "none".to_string())
        })?;
        let exe_path = PathBuf::from(&exe_str);
        Self::validate_executable(&exe_path)?;

        // Check for duplicate concurrent launch of the same environment or profile path
        {
            let mut map = self
                .sessions
                .lock()
                .map_err(|_| BrowserError::LaunchFailed("Session lock poisoned".to_string()))?;
            if let Some(existing) = map.get_mut(&config.environment_id) {
                if Self::refresh_process_state(existing) {
                    return Err(BrowserError::AlreadyRunning(
                        config.environment_id.clone(),
                        existing.session.pid,
                    ));
                }
            }
            for (_, proc_entry) in map.iter_mut() {
                if Self::refresh_process_state(proc_entry)
                    && proc_entry.session.profile_path == config.profile_dir.to_string_lossy()
                {
                    return Err(BrowserError::AlreadyRunning(
                        proc_entry.session.environment_id.clone(),
                        proc_entry.session.pid,
                    ));
                }
            }
        }

        std::fs::create_dir_all(&config.profile_dir).map_err(|e| {
            BrowserError::LaunchFailed(format!("Failed to create profile directory: {}", e))
        })?;

        let norm_browser = Self::normalize_browser_type(&config.browser_type);
        if norm_browser != "firefox" {
            Self::write_us_profile_preferences(
                &config.profile_dir,
                &config.preferred_language,
                config.us_content_preferences,
            )?;
        }

        let profile_path_str = config.profile_dir.to_string_lossy().to_string();
        let now = Utc::now().to_rfc3339();

        let (child_opt, pid) = if self.dry_run_spawn {
            (None, 42000 + (Uuid::new_v4().as_u128() % 1000) as u32)
        } else {
            let mut cmd = Command::new(&exe_path);
            if norm_browser == "firefox" {
                cmd.arg("-profile").arg(&profile_path_str);
                cmd.arg("-no-remote");
            } else {
                cmd.arg(format!("--user-data-dir={}", profile_path_str));
                cmd.arg("--no-first-run");
                cmd.arg("--no-default-browser-check");
                cmd.arg(format!("--lang={}", config.preferred_language));
                cmd.arg(format!("--accept-lang={},en", config.preferred_language));
                cmd.arg("--force-webrtc-ip-handling-policy=disable_non_proxied_udp");
                cmd.arg("--enforce-webrtc-ip-permission-check");

                if let Some(ref proxy) = config.proxy_server {
                    cmd.arg(format!("--proxy-server={}", proxy));
                    cmd.arg("--proxy-bypass-list=<-loopback>");
                    // Disable DNS prefetching so host never leaks DNS outside the proxy bridge
                    cmd.arg("--dns-prefetch-disable");
                }
            }

            if config.us_content_preferences {
                cmd.env("LANG", "en_US.UTF-8");
                cmd.env("LC_ALL", "en_US.UTF-8");
            }

            cmd.arg(&valid_url);
            cmd.stdin(Stdio::null());
            cmd.stdout(Stdio::null());
            cmd.stderr(Stdio::null());

            let child = cmd.spawn().map_err(|e| {
                BrowserError::LaunchFailed(format!("Failed to spawn '{}': {}", exe_str, e))
            })?;
            let pid = child.id();
            (Some(child), pid)
        };

        let session = BrowserSession {
            session_id: config.environment_id.clone(),
            environment_id: config.environment_id.clone(),
            browser_type: norm_browser,
            executable_path: exe_str,
            profile_path: profile_path_str,
            pid,
            startup_url: valid_url,
            proxy_server: config.proxy_server,
            proxy_bridge_port: config.proxy_bridge_port,
            preferred_language: config.preferred_language,
            started_at: now,
            status: "RUNNING".to_string(),
        };

        {
            let mut map = self
                .sessions
                .lock()
                .map_err(|_| BrowserError::LaunchFailed("Session lock poisoned".to_string()))?;
            map.insert(
                config.environment_id,
                ManagedProcess {
                    session: session.clone(),
                    child: child_opt,
                },
            );
        }

        Ok(session)
    }

    fn stop(&self, session_id: &str) -> Result<(), BrowserError> {
        let mut map = self
            .sessions
            .lock()
            .map_err(|_| BrowserError::LaunchFailed("Session lock poisoned".to_string()))?;

        if let Some(mut proc_entry) = map.remove(session_id) {
            if let Some(ref mut child) = proc_entry.child {
                let _ = child.kill();
                let _ = child.wait();
            }
            proc_entry.session.status = "STOPPED".to_string();
            Ok(())
        } else {
            Ok(())
        }
    }

    fn status(&self, session_id: &str) -> Result<BrowserStatus, BrowserError> {
        let mut map = self
            .sessions
            .lock()
            .map_err(|_| BrowserError::LaunchFailed("Session lock poisoned".to_string()))?;

        if let Some(proc_entry) = map.get_mut(session_id) {
            if Self::refresh_process_state(proc_entry) {
                return Ok(BrowserStatus::Running {
                    pid: proc_entry.session.pid,
                    started_at: proc_entry.session.started_at.clone(),
                    proxy_bridge_port: proc_entry.session.proxy_bridge_port,
                    startup_url: proc_entry.session.startup_url.clone(),
                });
            }
        }
        Ok(BrowserStatus::Stopped)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserProfile {
    pub id: String,
    pub environment_id: String,
    pub browser_type: String,
    pub profile_path: String,
    pub startup_url: String,
    pub preferred_language: String,
    pub executable_path: Option<String>,
    pub active_pid: Option<u32>,
    pub proxy_bridge_port: Option<u16>,
    pub last_launched_at: Option<String>,
    pub session_status: String,
    pub created_at: String,
}

pub struct ProfileService {
    db: Database,
    base_data_dir: PathBuf,
    launcher: Arc<dyn BrowserLauncher>,
    proxy_bridge_manager: Arc<ProxyBridgeManager>,
    secret_store: Arc<dyn SecretStore>,
}

impl ProfileService {
    pub fn new(db: Database, base_data_dir: PathBuf) -> Self {
        Self {
            db,
            base_data_dir,
            launcher: Arc::new(SystemBrowserLauncher::new()),
            proxy_bridge_manager: Arc::new(ProxyBridgeManager::new()),
            secret_store: get_secret_store(),
        }
    }

    pub fn with_components(
        db: Database,
        base_data_dir: PathBuf,
        launcher: Arc<dyn BrowserLauncher>,
        proxy_bridge_manager: Arc<ProxyBridgeManager>,
        secret_store: Arc<dyn SecretStore>,
    ) -> Self {
        Self {
            db,
            base_data_dir,
            launcher,
            proxy_bridge_manager,
            secret_store,
        }
    }

    pub fn launcher(&self) -> &Arc<dyn BrowserLauncher> {
        &self.launcher
    }

    pub fn proxy_bridge_manager(&self) -> &Arc<ProxyBridgeManager> {
        &self.proxy_bridge_manager
    }

    pub fn validate_path(&self, path: &Path) -> Result<(), String> {
        let path_str = path.to_string_lossy();
        if path_str.contains('\0') {
            return Err("Null bytes are not permitted in profile paths".to_string());
        }
        if path_str.split(['/', '\\']).any(|part| part == "..") {
            return Err("Path traversal (..) is not permitted in profile paths".to_string());
        }

        for component in path.components() {
            if let std::path::Component::ParentDir = component {
                return Err("Path traversal (..) is not permitted in profile paths".to_string());
            }
        }
        Ok(())
    }

    pub fn validate_identifier(ident: &str, label: &str) -> Result<(), String> {
        let trimmed = ident.trim();
        if trimmed.is_empty() {
            return Err(format!("{} cannot be empty", label));
        }
        if trimmed.contains("..") || trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains('\0') {
            return Err(format!("Path traversal or directory separators are not permitted in {}", label));
        }
        Ok(())
    }

    pub fn create_profile(
        &self,
        environment_id: &str,
        browser_type: &str,
    ) -> Result<BrowserProfile, String> {
        self.create_profile_with_options(
            environment_id,
            browser_type,
            "https://studio.youtube.com",
            "en-US",
        )
    }

    pub fn create_profile_with_options(
        &self,
        environment_id: &str,
        browser_type: &str,
        startup_url: &str,
        preferred_language: &str,
    ) -> Result<BrowserProfile, String> {
        Self::validate_identifier(environment_id, "Environment ID")?;
        Self::validate_identifier(browser_type, "Browser type")?;

        let norm_browser = SystemBrowserLauncher::normalize_browser_type(browser_type);
        let valid_url = SystemBrowserLauncher::validate_startup_url(startup_url)
            .map_err(|e| e.to_string())?;

        let env_profile_dir = self
            .base_data_dir
            .join("environments")
            .join(environment_id)
            .join("browser_profiles")
            .join(&norm_browser);

        self.validate_path(&env_profile_dir)?;

        std::fs::create_dir_all(&env_profile_dir)
            .map_err(|e| format!("Failed to create browser profile directory: {}", e))?;

        let profile_path_str = env_profile_dir.to_string_lossy().to_string();

        // Check that no other environment shares this profile path
        let path_conflict: bool = self
            .db
            .with_conn(|conn| {
                let count: i64 = conn.query_row(
                    "SELECT COUNT(1) FROM browser_profiles WHERE profile_path = ?1 AND environment_id != ?2",
                    rusqlite::params![profile_path_str, environment_id],
                    |r| r.get(0),
                )?;
                Ok(count > 0)
            })
            .map_err(|e| e.to_string())?;

        if path_conflict {
            return Err("Profile path conflict: another environment is already assigned this profile path".to_string());
        }

        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let detected_exe = self
            .launcher
            .detect_browser(&norm_browser)
            .ok()
            .and_then(|b| b.executable_path);

        self.db
            .with_conn(|conn| {
                conn.execute(
                    "INSERT INTO browser_profiles (
                        id, environment_id, browser_type, profile_path, created_at,
                        startup_url, preferred_language, executable_path, session_status
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'STOPPED')
                    ON CONFLICT(environment_id) DO UPDATE SET
                        browser_type = excluded.browser_type,
                        profile_path = excluded.profile_path,
                        startup_url = excluded.startup_url,
                        preferred_language = excluded.preferred_language,
                        executable_path = excluded.executable_path",
                    rusqlite::params![
                        id,
                        environment_id,
                        norm_browser,
                        profile_path_str,
                        now,
                        valid_url,
                        preferred_language,
                        detected_exe
                    ],
                )
            })
            .map_err(|e| e.to_string())?;

        Ok(BrowserProfile {
            id,
            environment_id: environment_id.to_string(),
            browser_type: norm_browser,
            profile_path: profile_path_str,
            startup_url: valid_url,
            preferred_language: preferred_language.to_string(),
            executable_path: detected_exe,
            active_pid: None,
            proxy_bridge_port: None,
            last_launched_at: None,
            session_status: "STOPPED".to_string(),
            created_at: now,
        })
    }

    pub fn get_profile_by_environment(
        &self,
        environment_id: &str,
    ) -> Result<Option<BrowserProfile>, String> {
        let profile_opt = self
            .db
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, environment_id, browser_type, profile_path, created_at,
                            COALESCE(startup_url, 'https://studio.youtube.com'),
                            COALESCE(preferred_language, 'en-US'),
                            executable_path, active_pid, proxy_bridge_port, last_launched_at,
                            COALESCE(session_status, 'STOPPED')
                     FROM browser_profiles WHERE environment_id = ?1",
                )?;

                let mut rows = stmt.query(rusqlite::params![environment_id])?;
                if let Some(row) = rows.next()? {
                    Ok(Some(BrowserProfile {
                        id: row.get(0)?,
                        environment_id: row.get(1)?,
                        browser_type: row.get(2)?,
                        profile_path: row.get(3)?,
                        created_at: row.get(4)?,
                        startup_url: row.get(5)?,
                        preferred_language: row.get(6)?,
                        executable_path: row.get(7)?,
                        active_pid: row.get(8)?,
                        proxy_bridge_port: row.get(9)?,
                        last_launched_at: row.get(10)?,
                        session_status: row.get(11)?,
                    }))
                } else {
                    Ok(None)
                }
            })
            .map_err(|e| e.to_string())?;

        // Reconcile live process status with launcher
        if let Some(mut profile) = profile_opt {
            if let Ok(live_status) = self.launcher.status(environment_id) {
                match live_status {
                    BrowserStatus::Running {
                        pid,
                        proxy_bridge_port,
                        ..
                    } => {
                        profile.session_status = "RUNNING".to_string();
                        profile.active_pid = Some(pid);
                        profile.proxy_bridge_port = proxy_bridge_port;
                    }
                    BrowserStatus::Stopped => {
                        if profile.session_status == "RUNNING" {
                            profile.session_status = "STOPPED".to_string();
                            profile.active_pid = None;
                            profile.proxy_bridge_port = None;
                            self.proxy_bridge_manager.stop_bridge(environment_id);
                            let _ = self.db.with_conn(|conn| {
                                conn.execute(
                                    "UPDATE browser_profiles SET session_status = 'STOPPED', active_pid = NULL, proxy_bridge_port = NULL WHERE environment_id = ?1",
                                    rusqlite::params![environment_id],
                                )
                            });
                        }
                    }
                    BrowserStatus::Error(_) => {
                        profile.session_status = "ERROR".to_string();
                    }
                }
            }
            return Ok(Some(profile));
        }

        Ok(None)
    }

    pub fn is_browser_running(&self, environment_id: &str) -> bool {
        self.launcher
            .status(environment_id)
            .map(|s| s.is_running())
            .unwrap_or(false)
    }

    pub fn delete_profile_files(&self, profile_path: &str) -> Result<(), String> {
        let path = PathBuf::from(profile_path);
        self.validate_path(&path)?;

        // Check if any environment using this profile path has an active browser session
        let env_id_opt: Option<String> = self
            .db
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT environment_id FROM browser_profiles WHERE profile_path = ?1",
                )?;
                let mut rows = stmt.query(rusqlite::params![profile_path])?;
                if let Some(row) = rows.next()? {
                    Ok(Some(row.get(0)?))
                } else {
                    Ok(None)
                }
            })
            .unwrap_or(None);

        if let Some(ref env_id) = env_id_opt {
            if self.is_browser_running(env_id) {
                return Err(format!(
                    "Cannot delete active browser profile for environment '{}' while the browser is running. Stop the browser first.",
                    env_id
                ));
            }
            self.proxy_bridge_manager.stop_bridge(env_id);
        }

        if path.exists() {
            std::fs::remove_dir_all(&path)
                .map_err(|e| format!("Failed to remove browser profile files: {}", e))?;
        }
        Ok(())
    }

    pub fn detect_browsers(&self) -> Vec<BrowserInfo> {
        self.launcher.list_browsers()
    }

    pub fn detect_edge(&self) -> Result<BrowserInfo, String> {
        self.launcher
            .detect_browser("edge")
            .map_err(|e| e.to_string())
    }

    pub fn find_browser_executable(&self, preferred: &str) -> Option<PathBuf> {
        if let Ok(info) = self.launcher.detect_browser(preferred) {
            if let Some(p) = info.executable_path {
                return Some(PathBuf::from(p));
            }
        }
        if let Ok(edge) = self.launcher.detect_browser("edge") {
            if let Some(p) = edge.executable_path {
                return Some(PathBuf::from(p));
            }
        }
        None
    }

    pub fn update_startup_url(&self, environment_id: &str, startup_url: &str) -> Result<(), String> {
        let valid_url = SystemBrowserLauncher::validate_startup_url(startup_url)
            .map_err(|e| e.to_string())?;
        let now = Utc::now().to_rfc3339();
        self.db
            .with_conn(|conn| {
                conn.execute(
                    "UPDATE environments SET startup_url = ?1, updated_at = ?2 WHERE id = ?3",
                    rusqlite::params![valid_url, now, environment_id],
                )?;
                conn.execute(
                    "UPDATE browser_profiles SET startup_url = ?1 WHERE environment_id = ?2",
                    rusqlite::params![valid_url, environment_id],
                )?;
                Ok(())
            })
            .map_err(|e| e.to_string())
    }

    pub fn launch_isolated_browser(&self, environment_id: &str) -> Result<String, String> {
        let session = self.launch_browser_session(environment_id, None)?;
        Ok(format!(
            "Successfully launched {} (PID {}) at {} with isolated profile",
            SystemBrowserLauncher::display_name_for(&session.browser_type),
            session.pid,
            session.startup_url
        ))
    }

    pub fn launch_browser_session(
        &self,
        environment_id: &str,
        override_url: Option<&str>,
    ) -> Result<BrowserSession, String> {
        let profile = match self.get_profile_by_environment(environment_id)? {
            Some(p) => p,
            None => {
                let default_browser = if cfg!(target_os = "macos") {
                    "edge"
                } else {
                    "chrome"
                };
                self.create_profile(environment_id, default_browser)?
            }
        };

        // Read environment settings and linked proxy endpoint
        let env_net = self
            .db
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT COALESCE(e.startup_url, ?2),
                            COALESCE(e.preferred_language, 'en-US'),
                            COALESCE(e.us_content_preferences, 1),
                            ne.id, ne.type, ne.host, ne.port, ne.username, ne.encrypted_secret_reference
                     FROM environments e
                     LEFT JOIN environment_networks en ON en.environment_id = e.id
                     LEFT JOIN network_endpoints ne ON ne.id = en.network_endpoint_id
                     WHERE e.id = ?1",
                )?;
                let mut rows = stmt.query(rusqlite::params![environment_id, profile.startup_url])?;
                if let Some(row) = rows.next()? {
                    Ok(Some((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)? != 0,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<u16>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, Option<String>>(8)?,
                    )))
                } else {
                    Ok(None)
                }
            })
            .map_err(|e| e.to_string())?;

        let (
            env_startup_url,
            preferred_language,
            us_content_preferences,
            ep_id_opt,
            ep_type_opt,
            ep_host_opt,
            ep_port_opt,
            ep_user_opt,
            ep_secret_ref_opt,
        ) = match env_net {
            Some(v) => v,
            None => (
                profile.startup_url.clone(),
                profile.preferred_language.clone(),
                true,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
        };

        let target_url = override_url.unwrap_or(&env_startup_url);
        let valid_url = SystemBrowserLauncher::validate_startup_url(target_url)
            .map_err(|e| e.to_string())?;

        // If an endpoint is assigned, we MUST route through the supervised localhost proxy bridge
        // and NEVER fall back silently to a direct host connection!
        let (proxy_server_arg, bridge_port_opt) = if let Some(ep_id) = ep_id_opt {
            let proto = ep_type_opt.unwrap_or_else(|| "HTTP".to_string());
            if proto.eq_ignore_ascii_case("DIRECT") {
                (None, None)
            } else {
                let host = ep_host_opt
                    .filter(|h| !h.trim().is_empty())
                    .ok_or_else(|| {
                        "Assigned proxy endpoint has no hostname configured. Refusing to launch with direct connection.".to_string()
                    })?;
                let port = ep_port_opt.filter(|&p| p > 0).ok_or_else(|| {
                    "Assigned proxy endpoint has no valid port configured. Refusing to launch with direct connection.".to_string()
                })?;

                // Retrieve credentials from SecretStore if configured
                let (username, password) = if let Some(ref sref) = ep_secret_ref_opt {
                    let secret_val = self.secret_store.retrieve_secret(sref).map_err(|e| {
                        format!(
                            "Failed to retrieve proxy credentials from secure vault ({}): {}. Refusing direct fallback.",
                            self.secret_store.provider_name(),
                            e
                        )
                    })?;
                    if let Some(u) = ep_user_opt.filter(|u| !u.trim().is_empty()) {
                        if let Some((_u_part, p_part)) = secret_val.split_once(':') {
                            (Some(u), Some(p_part.to_string()))
                        } else {
                            (Some(u), Some(secret_val))
                        }
                    } else if let Some((u_part, p_part)) = secret_val.split_once(':') {
                        (Some(u_part.to_string()), Some(p_part.to_string()))
                    } else {
                        (None, Some(secret_val))
                    }
                } else {
                    (ep_user_opt, None)
                };

                let bridge_cfg = UpstreamProxyConfig {
                    environment_id: environment_id.to_string(),
                    endpoint_id: ep_id,
                    host,
                    port,
                    protocol: proto,
                    username,
                    password,
                    connect_timeout: Duration::from_millis(6000),
                };

                let bridge_status = self
                    .proxy_bridge_manager
                    .start_or_replace_bridge(bridge_cfg)
                    .map_err(|e| format!("Failed to start local proxy bridge: {}", e))?;

                (
                    Some(format!("http://127.0.0.1:{}", bridge_status.local_port)),
                    Some(bridge_status.local_port),
                )
            }
        } else {
            (None, None)
        };

        let profile_dir = PathBuf::from(&profile.profile_path);
        self.validate_path(&profile_dir)?;

        let launch_cfg = BrowserLaunchConfig {
            environment_id: environment_id.to_string(),
            browser_type: profile.browser_type.clone(),
            profile_dir,
            startup_url: valid_url,
            proxy_server: proxy_server_arg,
            proxy_bridge_port: bridge_port_opt,
            preferred_language,
            us_content_preferences,
        };

        let session = match self.launcher.launch(launch_cfg) {
            Ok(s) => s,
            Err(e) => {
                // Clean up bridge if browser launch failed
                if bridge_port_opt.is_some() {
                    self.proxy_bridge_manager.stop_bridge(environment_id);
                }
                return Err(e.to_string());
            }
        };

        let now = Utc::now().to_rfc3339();
        let _ = self.db.with_conn(|conn| {
            conn.execute(
                "UPDATE browser_profiles
                 SET executable_path = ?1, active_pid = ?2, proxy_bridge_port = ?3, last_launched_at = ?4, session_status = 'RUNNING'
                 WHERE environment_id = ?5",
                rusqlite::params![
                    session.executable_path,
                    session.pid,
                    session.proxy_bridge_port,
                    now,
                    environment_id
                ],
            )?;
            // If environment is a native browser environment, mark environment as RUNNING too
            conn.execute(
                "UPDATE environments SET status = 'RUNNING', updated_at = ?1 WHERE id = ?2 AND (execution_mode = 'NATIVE_BROWSER' OR hypervisor_type IN ('NativeBrowser', 'macOS_Native_Edge', 'Native'))",
                rusqlite::params![now, environment_id],
            )?;
            Ok(())
        });

        Ok(session)
    }

    pub fn stop_browser_session(&self, environment_id: &str) -> Result<(), String> {
        self.launcher
            .stop(environment_id)
            .map_err(|e| e.to_string())?;
        self.proxy_bridge_manager.stop_bridge(environment_id);

        let now = Utc::now().to_rfc3339();
        self.db
            .with_conn(|conn| {
                conn.execute(
                    "UPDATE browser_profiles SET session_status = 'STOPPED', active_pid = NULL, proxy_bridge_port = NULL WHERE environment_id = ?1",
                    rusqlite::params![environment_id],
                )?;
                conn.execute(
                    "UPDATE environments SET status = 'STOPPED', updated_at = ?1 WHERE id = ?2 AND (execution_mode = 'NATIVE_BROWSER' OR hypervisor_type IN ('NativeBrowser', 'macOS_Native_Edge', 'Native'))",
                    rusqlite::params![now, environment_id],
                )?;
                Ok(())
            })
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    pub fn get_browser_session_status(&self, environment_id: &str) -> Result<BrowserStatus, String> {
        let status = self
            .launcher
            .status(environment_id)
            .map_err(|e| e.to_string())?;
        if matches!(status, BrowserStatus::Stopped) {
            self.proxy_bridge_manager.stop_bridge(environment_id);
        }
        Ok(status)
    }

    pub fn open_profile_folder(&self, environment_id: &str) -> Result<String, String> {
        let profile = self
            .get_profile_by_environment(environment_id)?
            .ok_or_else(|| format!("No browser profile found for environment {}", environment_id))?;

        let path = PathBuf::from(&profile.profile_path);
        self.validate_path(&path)?;

        if !path.exists() {
            std::fs::create_dir_all(&path)
                .map_err(|e| format!("Failed to create profile directory: {}", e))?;
        }

        #[cfg(target_os = "macos")]
        {
            Command::new("/usr/bin/open")
                .arg(&path)
                .spawn()
                .map_err(|e| format!("Failed to open profile folder in Finder: {}", e))?;
        }

        #[cfg(windows)]
        {
            Command::new("explorer.exe")
                .arg(&path)
                .spawn()
                .map_err(|e| format!("Failed to open profile folder in Explorer: {}", e))?;
        }

        Ok(profile.profile_path)
    }
}
