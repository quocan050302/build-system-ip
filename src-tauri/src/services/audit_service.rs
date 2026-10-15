use crate::db::Database;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub environment_id: Option<String>,
    pub action: String,
    pub severity: String, // "INFO", "WARN", "ERROR", "CRITICAL"
    pub message: String,
    pub created_at: String,
}

pub struct AuditService {
    db: Database,
}

impl AuditService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub fn log(
        &self,
        environment_id: Option<&str>,
        action: &str,
        severity: &str,
        message: &str,
    ) -> Result<String, String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        self.db
            .with_conn(|conn| {
                conn.execute(
                    "INSERT INTO activity_logs (id, environment_id, action, severity, message, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![id, environment_id, action, severity, message, now],
                )
            })
            .map_err(|e| e.to_string())?;

        Ok(id)
    }

    pub fn list_logs(&self, limit: usize) -> Result<Vec<AuditLogEntry>, String> {
        self.db
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, environment_id, action, severity, message, created_at 
                     FROM activity_logs ORDER BY created_at DESC LIMIT ?1",
                )?;

                let rows = stmt.query_map(rusqlite::params![limit as i64], |row| {
                    Ok(AuditLogEntry {
                        id: row.get(0)?,
                        environment_id: row.get(1)?,
                        action: row.get(2)?,
                        severity: row.get(3)?,
                        message: row.get(4)?,
                        created_at: row.get(5)?,
                    })
                })?;

                let mut logs = Vec::new();
                for row in rows {
                    logs.push(row?);
                }
                Ok(logs)
            })
            .map_err(|e| e.to_string())
    }
}
