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
}
