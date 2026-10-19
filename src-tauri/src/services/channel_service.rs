use crate::db::Database;
use crate::services::audit_service::AuditService;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelRecord {
    pub id: String,
    pub youtube_channel_id: String,
    pub display_name: String,
    pub environment_id: Option<String>,
    pub environment_name: Option<String>,
    pub authorization_status: String, // "UNVERIFIED", "AUTHORIZED", "RESTRICTED", "TERMINATED", "ARCHIVED"
    pub content_review_status: String, // "PENDING", "APPROVED", "REJECTED"
    pub is_eligible_for_publishing: bool,
    pub last_reviewed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateChannelRequest {
    pub youtube_channel_id: String,
    pub display_name: String,
    pub environment_id: Option<String>,
    pub authorization_status: String,
}

pub struct ChannelService {
    db: Database,
    audit_service: Arc<AuditService>,
}

impl ChannelService {
    pub fn new(db: Database, audit_service: Arc<AuditService>) -> Self {
        Self { db, audit_service }
    }

    pub fn create_channel(&self, req: CreateChannelRequest) -> Result<ChannelRecord, String> {
        let clean_id = req.youtube_channel_id.trim();
        let clean_name = req.display_name.trim();

        if clean_id.is_empty() {
            return Err("YouTube Channel ID cannot be empty".to_string());
        }
        if clean_name.is_empty() {
            return Err("Display name cannot be empty".to_string());
        }

        // Validate unique channel id
        let id_exists: bool = self.db.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT COUNT(1) FROM channels WHERE youtube_channel_id = ?1")?;
            let count: i64 = stmt.query_row(rusqlite::params![clean_id], |r| r.get(0))?;
            Ok(count > 0)
        }).map_err(|e| e.to_string())?;

        if id_exists {
            return Err(format!("A channel with ID '{}' is already registered", clean_id));
        }

        let valid_status = match req.authorization_status.as_str() {
            "AUTHORIZED" | "RESTRICTED" | "TERMINATED" | "ARCHIVED" => req.authorization_status,
            _ => "UNVERIFIED".to_string(),
        };

        let is_eligible = valid_status == "AUTHORIZED";
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        self.db.with_conn(|conn| {
            conn.execute(
                "INSERT INTO channels (id, youtube_channel_id, display_name, environment_id, authorization_status, content_review_status, last_reviewed_at, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    id,
                    clean_id,
                    clean_name,
                    req.environment_id,
                    valid_status,
                    "APPROVED",
                    now,
                    now,
                    now
                ],
            )
        }).map_err(|e| e.to_string())?;

        self.audit_service.log(
            req.environment_id.as_deref(),
            "REGISTER_CHANNEL",
            "INFO",
            &format!("Registered YouTube channel '{}' ({}) status: {}", clean_name, clean_id, valid_status),
        ).ok();

        let mut record = self.get_channel(&id)?.ok_or_else(|| "Failed to retrieve newly created channel".to_string())?;
        record.is_eligible_for_publishing = is_eligible;
        Ok(record)
    }

    pub fn list_channels(&self) -> Result<Vec<ChannelRecord>, String> {
        self.db.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT c.id, c.youtube_channel_id, c.display_name, c.environment_id, e.name as environment_name,
                        c.authorization_status, c.content_review_status, c.last_reviewed_at, c.created_at, c.updated_at
                 FROM channels c
                 LEFT JOIN environments e ON e.id = c.environment_id
                 ORDER BY c.created_at DESC"
            )?;

            let rows = stmt.query_map([], |row| {
                let status: String = row.get(5)?;
                let eligible = status == "AUTHORIZED";

                Ok(ChannelRecord {
                    id: row.get(0)?,
                    youtube_channel_id: row.get(1)?,
                    display_name: row.get(2)?,
                    environment_id: row.get(3)?,
                    environment_name: row.get(4)?,
                    authorization_status: status,
                    content_review_status: row.get(6)?,
                    is_eligible_for_publishing: eligible,
                    last_reviewed_at: row.get(7)?,
                    created_at: row.get(8)?,
                    updated_at: row.get(9)?,
                })
            })?;

            let mut list = Vec::new();
            for r in rows {
                list.push(r?);
            }
            Ok(list)
        }).map_err(|e| e.to_string())
    }

    pub fn get_channel(&self, id: &str) -> Result<Option<ChannelRecord>, String> {
        let channels = self.list_channels()?;
        Ok(channels.into_iter().find(|c| c.id == id))
    }

    pub fn update_status(&self, id: &str, new_status: &str) -> Result<(), String> {
        let valid_status = match new_status {
            "UNVERIFIED" | "AUTHORIZED" | "RESTRICTED" | "TERMINATED" | "ARCHIVED" => new_status,
            _ => return Err(format!("Invalid channel authorization status: {}", new_status)),
        };

        let now = Utc::now().to_rfc3339();
        self.db.with_conn(|conn| {
            conn.execute(
                "UPDATE channels SET authorization_status = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![valid_status, now, id],
            )
        }).map_err(|e| e.to_string())?;

        let severity = if valid_status == "TERMINATED" { "WARN" } else { "INFO" };
        self.audit_service.log(
            None,
            "UPDATE_CHANNEL_STATUS",
            severity,
            &format!("Updated channel {} status to {}", id, valid_status),
        ).ok();

        Ok(())
    }

    pub fn assign_environment(&self, channel_id: &str, environment_id: Option<&str>) -> Result<(), String> {
        let now = Utc::now().to_rfc3339();
        self.db.with_conn(|conn| {
            conn.execute(
                "UPDATE channels SET environment_id = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![environment_id, now, channel_id],
            )
        }).map_err(|e| e.to_string())?;

        self.audit_service.log(
            environment_id,
            "ASSIGN_CHANNEL_ENVIRONMENT",
            "INFO",
            &format!("Assigned channel {} to environment {:?}", channel_id, environment_id),
        ).ok();

        Ok(())
    }

    pub fn update_channel_id(&self, id: &str, new_youtube_channel_id: &str) -> Result<(), String> {
        let clean_id = new_youtube_channel_id.trim();
        if clean_id.is_empty() {
            return Err("YouTube Channel ID cannot be empty".to_string());
        }

        // Check uniqueness (ignore self)
        let already_exists: bool = self.db.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT COUNT(1) FROM channels WHERE youtube_channel_id = ?1 AND id != ?2"
            )?;
            let count: i64 = stmt.query_row(rusqlite::params![clean_id, id], |r| r.get(0))?;
            Ok(count > 0)
        }).map_err(|e| e.to_string())?;

        if already_exists {
            return Err(format!("Channel ID '{}' is already registered to another channel", clean_id));
        }

        let now = Utc::now().to_rfc3339();
        self.db.with_conn(|conn| {
            conn.execute(
                "UPDATE channels SET youtube_channel_id = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![clean_id, now, id],
            )
        }).map_err(|e| e.to_string())?;

        self.audit_service.log(
            None,
            "UPDATE_CHANNEL_ID",
            "INFO",
            &format!("Updated youtube_channel_id for channel {} to '{}'", id, clean_id),
        ).ok();

        Ok(())
    }

    pub fn delete_channel(&self, id: &str) -> Result<(), String> {
        self.db.with_conn(|conn| {
            conn.execute("DELETE FROM channels WHERE id = ?1", rusqlite::params![id])
        }).map_err(|e| e.to_string())?;

        self.audit_service.log(
            None,
            "DELETE_CHANNEL",
            "WARN",
            &format!("Deleted channel record {}", id),
        ).ok();

        Ok(())
    }
}
