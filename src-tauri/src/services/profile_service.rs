use crate::db::Database;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserProfile {
    pub id: String,
    pub environment_id: String,
    pub browser_type: String,
    pub profile_path: String,
    pub created_at: String,
}

pub struct ProfileService {
    db: Database,
    base_data_dir: PathBuf,
}

impl ProfileService {
    pub fn new(db: Database, base_data_dir: PathBuf) -> Self {
        Self {
            db,
            base_data_dir,
        }
    }

    pub fn validate_path(&self, path: &Path) -> Result<(), String> {
        // Prevent path traversal across Windows and UNIX path formats
        let path_str = path.to_string_lossy();
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

    pub fn create_profile(
        &self,
        environment_id: &str,
        browser_type: &str,
    ) -> Result<BrowserProfile, String> {
        // Construct dedicated profile directory path
        let env_profile_dir = self
            .base_data_dir
            .join("environments")
            .join(environment_id)
            .join("browser_profiles")
            .join(browser_type.to_lowercase());

        self.validate_path(&env_profile_dir)?;

        // Ensure directory exists
        std::fs::create_dir_all(&env_profile_dir)
            .map_err(|e| format!("Failed to create browser profile directory: {}", e))?;

        let profile_path_str = env_profile_dir.to_string_lossy().to_string();
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        self.db
            .with_conn(|conn| {
                conn.execute(
                    "INSERT INTO browser_profiles (id, environment_id, browser_type, profile_path, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![id, environment_id, browser_type, profile_path_str, now],
                )
            })
            .map_err(|e| e.to_string())?;

        Ok(BrowserProfile {
            id,
            environment_id: environment_id.to_string(),
            browser_type: browser_type.to_string(),
            profile_path: profile_path_str,
            created_at: now,
        })
    }

    pub fn get_profile_by_environment(
        &self,
        environment_id: &str,
    ) -> Result<Option<BrowserProfile>, String> {
        self.db
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, environment_id, browser_type, profile_path, created_at 
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
                    }))
                } else {
                    Ok(None)
                }
            })
            .map_err(|e| e.to_string())
    }

    pub fn delete_profile_files(&self, profile_path: &str) -> Result<(), String> {
        let path = PathBuf::from(profile_path);
        self.validate_path(&path)?;

        if path.exists() {
            std::fs::remove_dir_all(&path)
                .map_err(|e| format!("Failed to remove browser profile files: {}", e))?;
        }
        Ok(())
    }

    pub fn find_browser_executable(&self, preferred: &str) -> Option<PathBuf> {
        let candidates = match preferred.to_lowercase().as_str() {
            "brave" => vec![
                PathBuf::from(r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"),
                PathBuf::from(r"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe"),
            ],
            "firefox" => vec![
                PathBuf::from(r"C:\Program Files\Mozilla Firefox\firefox.exe"),
                PathBuf::from(r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"),
            ],
            _ => vec![
                PathBuf::from(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                PathBuf::from(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
            ],
        };

        for path in candidates {
            if path.exists() {
                return Some(path);
            }
        }

        // Always check Microsoft Edge as universal Windows fallback
        let edge_paths = vec![
            PathBuf::from(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
            PathBuf::from(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
        ];
        for path in edge_paths {
            if path.exists() {
                return Some(path);
            }
        }

        // Try where.exe
        if let Ok(output) = std::process::Command::new("where.exe").arg("chrome").output() {
            if output.status.success() {
                if let Some(line) = String::from_utf8_lossy(&output.stdout).lines().next() {
                    let p = PathBuf::from(line.trim());
                    if p.exists() {
                        return Some(p);
                    }
                }
            }
        }

        None
    }

    pub fn launch_isolated_browser(
        &self,
        environment_id: &str,
    ) -> Result<String, String> {
        let profile = match self.get_profile_by_environment(environment_id)? {
            Some(p) => p,
            None => self.create_profile(environment_id, "chrome")?,
        };

        let exe = self.find_browser_executable(&profile.browser_type)
            .ok_or_else(|| "No supported browser (Chrome, Edge, Brave) found on system".to_string())?;

        // Query proxy if configured
        let proxy_arg: Option<String> = self.db.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT ne.type, ne.host, ne.port
                 FROM environment_networks en
                 JOIN network_endpoints ne ON ne.id = en.network_endpoint_id
                 WHERE en.environment_id = ?1",
            )?;

            let mut rows = stmt.query(rusqlite::params![environment_id])?;
            if let Some(row) = rows.next()? {
                let proto: String = row.get(0)?;
                let host: Option<String> = row.get(1)?;
                let port: Option<u16> = row.get(2)?;
                if let (Some(h), Some(p)) = (host, port) {
                    let proto_str = match proto.to_uppercase().as_str() {
                        "SOCKS5" => "socks5",
                        _ => "http",
                    };
                    Ok(Some(format!("{}://{}:{}", proto_str, h, p)))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        }).unwrap_or(None);

        let mut cmd = std::process::Command::new(&exe);
        cmd.arg(format!("--user-data-dir={}", profile.profile_path));
        cmd.arg("--no-first-run");
        cmd.arg("--no-default-browser-check");

        if let Some(ref proxy) = proxy_arg {
            cmd.arg(format!("--proxy-server={}", proxy));
        }

        cmd.arg("https://studio.youtube.com");

        cmd.spawn()
            .map_err(|e| format!("Failed to spawn browser: {}", e))?;

        Ok(format!(
            "Successfully opened YouTube Studio in isolated profile ({})",
            exe.file_name().unwrap_or_default().to_string_lossy()
        ))
    }
}
