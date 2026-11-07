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
    pub platform: String, // "YouTube", "TikTok", "Instagram", "Facebook", "Gumroad"
    pub workspace_name: String, // e.g. "Alexa Creator Studio"
    pub account_handle: Option<String>,
    pub profile_url: Option<String>,
    pub analytics_url: Option<String>,
    pub gumroad_url: Option<String>,
    pub utm_source: Option<String>,
    pub utm_medium: Option<String>,
    pub utm_campaign: Option<String>,
    pub tracked_destination_url: Option<String>,
    pub environment_id: Option<String>,
    pub environment_name: Option<String>,
    pub authorization_status: String, // "UNVERIFIED", "AUTHORIZED", "RESTRICTED", "TERMINATED", "ARCHIVED"
    pub content_review_status: String, // "PENDING", "APPROVED", "REJECTED"
    pub is_eligible_for_publishing: bool,
    pub last_reviewed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CreateChannelRequest {
    pub youtube_channel_id: String,
    pub display_name: String,
    pub environment_id: Option<String>,
    pub authorization_status: String,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub workspace_name: Option<String>,
    #[serde(default)]
    pub account_handle: Option<String>,
    #[serde(default)]
    pub profile_url: Option<String>,
    #[serde(default)]
    pub analytics_url: Option<String>,
    #[serde(default)]
    pub gumroad_url: Option<String>,
    #[serde(default)]
    pub utm_source: Option<String>,
    #[serde(default)]
    pub utm_medium: Option<String>,
    #[serde(default)]
    pub utm_campaign: Option<String>,
}

pub struct ChannelService {
    db: Database,
    audit_service: Arc<AuditService>,
}

impl ChannelService {
    pub fn new(db: Database, audit_service: Arc<AuditService>) -> Self {
        Self { db, audit_service }
    }

    pub fn normalize_platform(platform: Option<&str>) -> String {
        match platform.unwrap_or("YouTube").trim().to_lowercase().as_str() {
            "tiktok" => "TikTok".to_string(),
            "instagram" => "Instagram".to_string(),
            "facebook" | "meta" => "Facebook".to_string(),
            "gumroad" => "Gumroad".to_string(),
            _ => "YouTube".to_string(),
        }
    }

    pub fn default_urls_for_platform(platform: &str) -> (String, String, String) {
        match platform {
            "TikTok" => (
                "https://www.tiktok.com/tiktokstudio".to_string(),
                "https://www.tiktok.com/tiktokstudio".to_string(),
                "tiktok".to_string(),
            ),
            "Instagram" => (
                "https://www.instagram.com/".to_string(),
                "https://business.facebook.com/".to_string(),
                "instagram".to_string(),
            ),
            "Facebook" => (
                "https://www.facebook.com/".to_string(),
                "https://business.facebook.com/".to_string(),
                "facebook".to_string(),
            ),
            "Gumroad" => (
                "https://gumroad.com/".to_string(),
                "https://gumroad.com/".to_string(),
                "gumroad".to_string(),
            ),
            _ => (
                "https://studio.youtube.com".to_string(),
                "https://studio.youtube.com".to_string(),
                "youtube".to_string(),
            ),
        }
    }

    pub fn build_tracked_gumroad_url(
        base_url: Option<&str>,
        utm_source: Option<&str>,
        utm_medium: Option<&str>,
        utm_campaign: Option<&str>,
    ) -> Option<String> {
        let raw = base_url?.trim();
        if raw.is_empty() || !(raw.starts_with("https://") || raw.starts_with("http://")) {
            return None;
        }

        let mut params = Vec::new();
        if let Some(s) = utm_source.map(|v| v.trim()).filter(|v| !v.is_empty()) {
            params.push(format!("utm_source={}", s));
        }
        if let Some(m) = utm_medium.map(|v| v.trim()).filter(|v| !v.is_empty()) {
            params.push(format!("utm_medium={}", m));
        }
        if let Some(c) = utm_campaign.map(|v| v.trim()).filter(|v| !v.is_empty()) {
            params.push(format!("utm_campaign={}", c));
        }

        if params.is_empty() {
            return Some(raw.to_string());
        }

        let sep = if raw.contains('?') { '&' } else { '?' };
        Some(format!("{}{}{}", raw, sep, params.join("&")))
    }

    pub fn create_channel(&self, req: CreateChannelRequest) -> Result<ChannelRecord, String> {
        let clean_id = req.youtube_channel_id.trim();
        let clean_name = req.display_name.trim();

        if clean_id.is_empty() {
            return Err("Account / Channel ID cannot be empty".to_string());
        }
        if clean_name.is_empty() {
            return Err("Display name cannot be empty".to_string());
        }

        let id_exists: bool = self
            .db
            .with_conn(|conn| {
                let mut stmt =
                    conn.prepare("SELECT COUNT(1) FROM channels WHERE youtube_channel_id = ?1")?;
                let count: i64 = stmt.query_row(rusqlite::params![clean_id], |r| r.get(0))?;
                Ok(count > 0)
            })
            .map_err(|e| e.to_string())?;

        if id_exists {
            return Err(format!(
                "A channel with ID '{}' is already registered",
                clean_id
            ));
        }

        let valid_status = match req.authorization_status.as_str() {
            "AUTHORIZED" | "RESTRICTED" | "TERMINATED" | "ARCHIVED" => req.authorization_status,
            _ => "UNVERIFIED".to_string(),
        };

        let platform = Self::normalize_platform(req.platform.as_deref());
        let workspace_name = req
            .workspace_name
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("Alexa Creator Studio")
            .to_string();

        let (default_profile_url, default_analytics_url, default_utm_source) =
            Self::default_urls_for_platform(&platform);

        let profile_url = req
            .profile_url
            .as_deref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or(Some(default_profile_url));

        let analytics_url = req
            .analytics_url
            .as_deref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or(Some(default_analytics_url));

        let gumroad_url = req
            .gumroad_url
            .as_deref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let utm_source = req
            .utm_source
            .as_deref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                if gumroad_url.is_some() {
                    Some(default_utm_source)
                } else {
                    None
                }
            });

        let utm_medium = req
            .utm_medium
            .as_deref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                if gumroad_url.is_some() {
                    Some("organic_social".to_string())
                } else {
                    None
                }
            });

        let utm_campaign = req
            .utm_campaign
            .as_deref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                if gumroad_url.is_some() {
                    Some("alexa_diy".to_string())
                } else {
                    None
                }
            });

        let is_eligible = valid_status == "AUTHORIZED";
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        self.db
            .with_conn(|conn| {
                conn.execute(
                    "INSERT INTO channels (
                        id, youtube_channel_id, display_name, environment_id,
                        authorization_status, content_review_status, last_reviewed_at,
                        created_at, updated_at, platform, workspace_name, account_handle,
                        profile_url, analytics_url, gumroad_url, utm_source, utm_medium, utm_campaign
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
                    rusqlite::params![
                        id,
                        clean_id,
                        clean_name,
                        req.environment_id,
                        valid_status,
                        "APPROVED",
                        now,
                        now,
                        now,
                        platform,
                        workspace_name,
                        req.account_handle,
                        profile_url,
                        analytics_url,
                        gumroad_url,
                        utm_source,
                        utm_medium,
                        utm_campaign
                    ],
                )
            })
            .map_err(|e| e.to_string())?;

        self.audit_service
            .log(
                req.environment_id.as_deref(),
                "REGISTER_CHANNEL",
                "INFO",
                &format!(
                    "Registered {} account '{}' ({}) in workspace '{}' status: {}",
                    platform, clean_name, clean_id, workspace_name, valid_status
                ),
            )
            .ok();

        let mut record = self
            .get_channel(&id)?
            .ok_or_else(|| "Failed to retrieve newly created channel".to_string())?;
        record.is_eligible_for_publishing = is_eligible;
        Ok(record)
    }

    pub fn list_channels(&self) -> Result<Vec<ChannelRecord>, String> {
        self.db
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT c.id, c.youtube_channel_id, c.display_name, c.environment_id, e.name as environment_name,
                            c.authorization_status, c.content_review_status, c.last_reviewed_at, c.created_at, c.updated_at,
                            COALESCE(c.platform, 'YouTube'),
                            COALESCE(c.workspace_name, 'Alexa Creator Studio'),
                            c.account_handle, c.profile_url, c.analytics_url,
                            c.gumroad_url, c.utm_source, c.utm_medium, c.utm_campaign
                     FROM channels c
                     LEFT JOIN environments e ON e.id = c.environment_id
                     ORDER BY c.created_at DESC",
                )?;

                let rows = stmt.query_map([], |row| {
                    let status: String = row.get(5)?;
                    let eligible = status == "AUTHORIZED";
                    let gumroad_url: Option<String> = row.get(15)?;
                    let utm_source: Option<String> = row.get(16)?;
                    let utm_medium: Option<String> = row.get(17)?;
                    let utm_campaign: Option<String> = row.get(18)?;
                    let tracked_destination_url = Self::build_tracked_gumroad_url(
                        gumroad_url.as_deref(),
                        utm_source.as_deref(),
                        utm_medium.as_deref(),
                        utm_campaign.as_deref(),
                    );

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
                        platform: row.get(10)?,
                        workspace_name: row.get(11)?,
                        account_handle: row.get(12)?,
                        profile_url: row.get(13)?,
                        analytics_url: row.get(14)?,
                        gumroad_url,
                        utm_source,
                        utm_medium,
                        utm_campaign,
                        tracked_destination_url,
                    })
                })?;

                let mut list = Vec::new();
                for r in rows {
                    list.push(r?);
                }
                Ok(list)
            })
            .map_err(|e| e.to_string())
    }

    pub fn get_channel(&self, id: &str) -> Result<Option<ChannelRecord>, String> {
        let channels = self.list_channels()?;
        Ok(channels.into_iter().find(|c| c.id == id))
    }

    pub fn update_status(&self, id: &str, new_status: &str) -> Result<(), String> {
        let valid_status = match new_status {
            "UNVERIFIED" | "AUTHORIZED" | "RESTRICTED" | "TERMINATED" | "ARCHIVED" => new_status,
            _ => {
                return Err(format!(
                    "Invalid channel authorization status: {}",
                    new_status
                ))
            }
        };

        let now = Utc::now().to_rfc3339();
        self.db
            .with_conn(|conn| {
                conn.execute(
                    "UPDATE channels SET authorization_status = ?1, updated_at = ?2 WHERE id = ?3",
                    rusqlite::params![valid_status, now, id],
                )
            })
            .map_err(|e| e.to_string())?;

        let severity = if valid_status == "TERMINATED" {
            "WARN"
        } else {
            "INFO"
        };
        self.audit_service
            .log(
                None,
                "UPDATE_CHANNEL_STATUS",
                severity,
                &format!("Updated channel {} status to {}", id, valid_status),
            )
            .ok();

        Ok(())
    }

    pub fn assign_environment(
        &self,
        channel_id: &str,
        environment_id: Option<&str>,
    ) -> Result<(), String> {
        let now = Utc::now().to_rfc3339();
        self.db
            .with_conn(|conn| {
                conn.execute(
                    "UPDATE channels SET environment_id = ?1, updated_at = ?2 WHERE id = ?3",
                    rusqlite::params![environment_id, now, channel_id],
                )
            })
            .map_err(|e| e.to_string())?;

        self.audit_service
            .log(
                environment_id,
                "ASSIGN_CHANNEL_ENVIRONMENT",
                "INFO",
                &format!(
                    "Assigned channel {} to environment {:?}",
                    channel_id, environment_id
                ),
            )
            .ok();

        Ok(())
    }

    pub fn update_channel_id(&self, id: &str, new_youtube_channel_id: &str) -> Result<(), String> {
        let clean_id = new_youtube_channel_id.trim();
        if clean_id.is_empty() {
            return Err("Channel / Account ID cannot be empty".to_string());
        }

        let already_exists: bool = self
            .db
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT COUNT(1) FROM channels WHERE youtube_channel_id = ?1 AND id != ?2",
                )?;
                let count: i64 = stmt.query_row(rusqlite::params![clean_id, id], |r| r.get(0))?;
                Ok(count > 0)
            })
            .map_err(|e| e.to_string())?;

        if already_exists {
            return Err(format!(
                "Channel ID '{}' is already registered to another channel",
                clean_id
            ));
        }

        let now = Utc::now().to_rfc3339();
        self.db
            .with_conn(|conn| {
                conn.execute(
                    "UPDATE channels SET youtube_channel_id = ?1, updated_at = ?2 WHERE id = ?3",
                    rusqlite::params![clean_id, now, id],
                )
            })
            .map_err(|e| e.to_string())?;

        self.audit_service
            .log(
                None,
                "UPDATE_CHANNEL_ID",
                "INFO",
                &format!("Updated identifier for channel {} to '{}'", id, clean_id),
            )
            .ok();

        Ok(())
    }

    pub fn update_gumroad_tracking(
        &self,
        id: &str,
        gumroad_url: Option<&str>,
        utm_source: Option<&str>,
        utm_medium: Option<&str>,
        utm_campaign: Option<&str>,
    ) -> Result<ChannelRecord, String> {
        if let Some(url) = gumroad_url.filter(|s| !s.trim().is_empty()) {
            crate::services::profile_service::SystemBrowserLauncher::validate_startup_url(url)
                .map_err(|e| e.to_string())?;
        }

        let now = Utc::now().to_rfc3339();
        self.db
            .with_conn(|conn| {
                conn.execute(
                    "UPDATE channels
                     SET gumroad_url = ?1, utm_source = ?2, utm_medium = ?3, utm_campaign = ?4, updated_at = ?5
                     WHERE id = ?6",
                    rusqlite::params![
                        gumroad_url.map(|s| s.trim()).filter(|s| !s.is_empty()),
                        utm_source.map(|s| s.trim()).filter(|s| !s.is_empty()),
                        utm_medium.map(|s| s.trim()).filter(|s| !s.is_empty()),
                        utm_campaign.map(|s| s.trim()).filter(|s| !s.is_empty()),
                        now,
                        id
                    ],
                )
            })
            .map_err(|e| e.to_string())?;

        self.get_channel(id)?
            .ok_or_else(|| format!("Channel {} not found", id))
    }

    pub fn delete_channel(&self, id: &str) -> Result<(), String> {
        self.db
            .with_conn(|conn| {
                conn.execute("DELETE FROM channels WHERE id = ?1", rusqlite::params![id])
            })
            .map_err(|e| e.to_string())?;

        self.audit_service
            .log(
                None,
                "DELETE_CHANNEL",
                "WARN",
                &format!("Deleted channel record {}", id),
            )
            .ok();

        Ok(())
    }
}
