use crate::db::Database;
use crate::hypervisor::HypervisorAdapter;
use crate::security::redaction::redact_sensitive_str;
use crate::security::{get_secret_store, SecretStore};
use crate::services::audit_service::AuditService;
use crate::services::browser_verification::{
    attempt_cdp_browser_verification, evaluate_verification_decision, BrowserSessionInfo,
};
use crate::services::profile_service::{BrowserStatus, ProfileService};
use crate::services::proxy_bridge::probe_via_local_bridge;
use crate::services::vm_service::VmService;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEndpointRecord {
    pub id: String,
    pub name: String,
    pub endpoint_type: String, // "HTTP", "HTTPS", "SOCKS5", "WIREGUARD", "DIRECT"
    pub provider_label: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub has_credentials: bool,
    pub expected_country: Option<String>,
    pub expected_ip: Option<String>,
    pub expires_at: Option<String>,
    pub status: String, // "ACTIVE", "INACTIVE", "ERROR"
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CreateEndpointRequest {
    pub name: String,
    pub endpoint_type: String,
    pub provider_label: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    #[serde(default)]
    pub username: Option<String>,
    pub credentials_secret: Option<String>,
    #[serde(default)]
    pub expected_country: Option<String>,
    #[serde(default)]
    pub expected_ip: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCheckRecord {
    pub id: String,
    pub environment_id: String,
    pub observed_ipv4: Option<String>,
    pub observed_ipv6: Option<String>,
    pub observed_country: Option<String>,
    pub dns_summary: Option<String>,
    pub dns_leak_status: String, // "UNVERIFIED", "REMOTE_PROXY_DNS", "HOST_DNS_DETECTED", "VERIFIED", "FAILED", "NOT_APPLICABLE"
    pub webrtc_status: String, // "UNVERIFIED", "NON_PROXIED_UDP_DISABLED", "VERIFIED", "FAILED", "NOT_APPLICABLE", "POLICY_SET_UNVERIFIED"
    pub check_source: String, // "GUEST_AGENT", "PROXY_PROBE", "BROWSER_SESSION", "HOST_PROBE", "DIRECT_PROBE"
    pub status: String, // "NOT_CONFIGURED", "ENDPOINT_CONFIGURED", "ENDPOINT_REACHABLE", "PROXY_EGRESS_VERIFIED", "BROWSER_EGRESS_VERIFIED", "AUTH_FAILED", "CONNECTION_FAILED", "VERIFICATION_UNAVAILABLE", "NOT_CHECKED", "GUEST_EGRESS_OBSERVED", "STALE"
    pub error_message: Option<String>,
    pub checked_at: String,
    pub latency_ms: Option<u32>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateEgressWarning {
    pub ip_address: String,
    pub conflicting_environments: Vec<String>,
    pub message: String,
}

/// Aggregated DNS, IPv6, and WebRTC protection status for display in the UI.
/// Each field uses one of: "VERIFIED", "FAILED", "UNVERIFIED", "NOT_APPLICABLE".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkProtectionStatus {
    pub environment_id: String,
    /// DNS leak status: whether DNS is resolving through the proxy (not host).
    pub dns_status: String,
    /// DNS notes: human-readable explanation of the dns_status.
    pub dns_notes: String,
    /// IPv6 leak status: whether IPv6 traffic could bypass the proxy.
    pub ipv6_status: String,
    /// IPv6 notes.
    pub ipv6_notes: String,
    /// WebRTC status: whether WebRTC is configured to prevent IP leak.
    pub webrtc_status: String,
    /// WebRTC notes.
    pub webrtc_notes: String,
    /// Overall protection rating: "FULLY_PROTECTED", "PARTIALLY_PROTECTED", "UNVERIFIED", "FAILED"
    pub overall_status: String,
    /// Timestamp of the assessment.
    pub assessed_at: String,
}

impl NetworkProtectionStatus {
    /// Build a NetworkProtectionStatus from an existing NetworkCheckRecord.
    /// This translates stored status strings into the structured protection view.
    pub fn from_check_record(record: &NetworkCheckRecord, environment_id: &str) -> Self {
        let dns_status = match record.dns_leak_status.as_str() {
            "REMOTE_PROXY_DNS" => "PROXY_DNS_ASSUMED".to_string(),
            "DNS_VERIFIED" => "VERIFIED".to_string(),
            "HOST_DNS_DETECTED" => "FAILED".to_string(),
            "NOT_APPLICABLE" => "NOT_APPLICABLE".to_string(),
            _ => "UNVERIFIED".to_string(),
        };
        let dns_notes = match record.dns_leak_status.as_str() {
            "REMOTE_PROXY_DNS" => "DNS assumed to be proxied (CONNECT/SOCKS5 semantics). Host-side DNS resolver usage has NOT been independently verified. Packet capture or browser DNS instrumentation required for VERIFIED status.".to_string(),
            "DNS_VERIFIED" => "DNS resolution independently verified to route through proxy.".to_string(),
            "HOST_DNS_DETECTED" => "ALERT: Host-side DNS resolution detected — potential DNS leak.".to_string(),
            "NOT_APPLICABLE" => "DNS verification not applicable for this connection type.".to_string(),
            _ => "DNS routing has not been tested. No network check has been performed, or the check method does not include DNS observation.".to_string(),
        };

        let ipv6_status = "UNVERIFIED".to_string();
        let ipv6_notes = "IPv6 behavior has not been independently tested. The proxy bridge is IPv4-only. Edge may have IPv6 connectivity that bypasses the bridge. Recommended: disable IPv6 at the OS or network level, or verify --disable-ipv6 flag effect in Edge.".to_string();

        let webrtc_status = match record.webrtc_status.as_str() {
            "NON_PROXIED_UDP_DISABLED" => "POLICY_SET_UNVERIFIED".to_string(),
            "VERIFIED" => "VERIFIED".to_string(),
            "FAILED" => "FAILED".to_string(),
            "NOT_APPLICABLE" => "NOT_APPLICABLE".to_string(),
            _ => "UNVERIFIED".to_string(),
        };
        let webrtc_notes = match record.webrtc_status.as_str() {
            "NON_PROXIED_UDP_DISABLED" => "Policy flag --force-webrtc-ip-handling-policy=disable_non_proxied_udp was set at launch. Actual WebRTC behavior has not been verified at runtime — the flag may not be effective in all Edge versions.".to_string(),
            "VERIFIED" => "WebRTC configured and verified to not expose non-proxied IPs.".to_string(),
            "FAILED" => "WebRTC check failed — non-proxied IP may be exposed.".to_string(),
            "NOT_APPLICABLE" => "WebRTC not applicable for this environment.".to_string(),
            _ => "WebRTC protection has not been verified.".to_string(),
        };

        // Overall: only FULLY_PROTECTED if DNS=VERIFIED, IPv6=VERIFIED, WebRTC=VERIFIED
        let overall_status =
            if dns_status == "FAILED" || webrtc_status == "FAILED" || ipv6_status == "FAILED" {
                "FAILED".to_string()
            } else if dns_status == "VERIFIED"
                && ipv6_status == "VERIFIED"
                && webrtc_status == "VERIFIED"
            {
                "FULLY_PROTECTED".to_string()
            } else if dns_status == "PROXY_DNS_ASSUMED"
                || dns_status == "VERIFIED"
                || webrtc_status == "POLICY_SET_UNVERIFIED"
            {
                "PARTIALLY_PROTECTED".to_string()
            } else {
                "UNVERIFIED".to_string()
            };

        Self {
            environment_id: environment_id.to_string(),
            dns_status,
            dns_notes,
            ipv6_status,
            ipv6_notes,
            webrtc_status,
            webrtc_notes,
            overall_status,
            assessed_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

pub struct NetworkService {
    db: Database,
    hypervisor: Arc<dyn HypervisorAdapter>,
    secret_store: Arc<dyn SecretStore>,
    audit_service: Arc<AuditService>,
}

impl NetworkService {
    pub fn new(
        db: Database,
        hypervisor: Arc<dyn HypervisorAdapter>,
        audit_service: Arc<AuditService>,
    ) -> Self {
        Self {
            db,
            hypervisor,
            secret_store: get_secret_store(),
            audit_service,
        }
    }

    pub fn with_secret_store(
        db: Database,
        hypervisor: Arc<dyn HypervisorAdapter>,
        secret_store: Arc<dyn SecretStore>,
        audit_service: Arc<AuditService>,
    ) -> Self {
        Self {
            db,
            hypervisor,
            secret_store,
            audit_service,
        }
    }

    pub fn secret_store(&self) -> &Arc<dyn SecretStore> {
        &self.secret_store
    }

    /// Pure helper: evaluates whether an observed country satisfies an optional expected-country
    /// constraint, following the strict semantics used throughout this service.
    ///
    /// Returns `Ok(())` when no constraint is set, or when the observed country is a
    /// case-insensitive match for the expected one.
    ///
    /// Returns `Err(message)` when:
    /// - `observed` is empty or `"UNKNOWN"` and an expected country is set (cannot confirm).
    /// - `observed` is a non-matching country code (mismatch).
    ///
    /// This function is intentionally `pub` so that integration tests can exercise the country
    /// validation logic without triggering real network I/O.
    pub fn evaluate_country_match(
        observed: &str,
        expected_country: Option<&str>,
    ) -> Result<(), String> {
        if let Some(exp_c) = expected_country {
            let is_match = !observed.is_empty()
                && observed != "UNKNOWN"
                && observed.eq_ignore_ascii_case(exp_c);
            if !is_match {
                let msg = if observed == "UNKNOWN" || observed.is_empty() {
                    format!(
                        "Geolocation returned UNKNOWN country — cannot confirm expected '{}'. Treating as UNVERIFIED.",
                        exp_c
                    )
                } else {
                    format!(
                        "Country mismatch: expected '{}', observed '{}'",
                        exp_c, observed
                    )
                };
                return Err(msg);
            }
        }
        Ok(())
    }

    /// Validates that a string is a syntactically valid IPv4 or IPv6 address.
    /// Uses the standard library's `std::net` parsers — no string heuristics.
    pub fn is_valid_ip_address(addr: &str) -> bool {
        use std::net::{Ipv4Addr, Ipv6Addr};
        addr.parse::<Ipv4Addr>().is_ok() || addr.parse::<Ipv6Addr>().is_ok()
    }

    pub fn create_endpoint(
        &self,
        req: CreateEndpointRequest,
    ) -> Result<NetworkEndpointRecord, String> {
        let clean_name = req.name.trim();
        if clean_name.is_empty() {
            return Err("Endpoint name cannot be empty".to_string());
        }

        let ep_type = req.endpoint_type.trim().to_uppercase();
        if !matches!(
            ep_type.as_str(),
            "HTTP" | "HTTPS" | "SOCKS5" | "WIREGUARD" | "DIRECT"
        ) {
            return Err(format!(
                "Unsupported endpoint protocol '{}'. Supported: HTTP, HTTPS, SOCKS5, WIREGUARD, DIRECT.",
                req.endpoint_type
            ));
        }

        if matches!(ep_type.as_str(), "HTTP" | "HTTPS" | "SOCKS5") {
            if let Some(ref h) = req.host {
                let th = h.trim();
                if th.contains(char::is_whitespace) || th.contains('/') || th.contains('@') {
                    return Err("Invalid proxy hostname: must not contain spaces, slashes, or '@' credentials".to_string());
                }
            }
            if let Some(p) = req.port {
                if p == 0 {
                    return Err("Proxy port must be between 1 and 65535".to_string());
                }
            }
        }

        if matches!(ep_type.as_str(), "WIREGUARD" | "DIRECT")
            && (req
                .username
                .as_ref()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
                || req
                    .credentials_secret
                    .as_ref()
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false))
            && ep_type == "DIRECT"
        {
            return Err(
                "DIRECT network adapter does not support proxy authentication credentials"
                    .to_string(),
            );
        }

        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        let clean_username = req
            .username
            .as_ref()
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty());

        let secret_payload = match (&clean_username, &req.credentials_secret) {
            (Some(u), Some(s)) if !s.is_empty() => {
                if s.contains(':') {
                    Some(s.clone())
                } else {
                    Some(format!("{}:{}", u, s))
                }
            }
            (None, Some(s)) if !s.is_empty() => Some(s.clone()),
            _ => None,
        };

        let encrypted_secret = if let Some(ref creds) = secret_payload {
            Some(
                self.secret_store
                    .store_secret(&id, creds)
                    .map_err(|e| format!("Secret store error: {}", e))?,
            )
        } else {
            None
        };

        let has_credentials = encrypted_secret.is_some();
        let expected_country = req
            .expected_country
            .as_ref()
            .map(|c| c.trim().to_uppercase())
            .filter(|c| !c.is_empty());
        let expected_ip = req
            .expected_ip
            .as_ref()
            .map(|ip| ip.trim().to_string())
            .filter(|ip| !ip.is_empty());
        let expires_at = req
            .expires_at
            .as_ref()
            .map(|ex| ex.trim().to_string())
            .filter(|ex| !ex.is_empty());

        self.db
            .with_conn(|conn| {
                conn.execute(
                    "INSERT INTO network_endpoints (
                        id, name, type, provider_label, host, port, encrypted_secret_reference,
                        status, created_at, updated_at, username, expected_country, expected_ip, expires_at
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    rusqlite::params![
                        id,
                        clean_name,
                        ep_type,
                        req.provider_label,
                        req.host,
                        req.port,
                        encrypted_secret,
                        "ACTIVE",
                        now,
                        now,
                        clean_username,
                        expected_country,
                        expected_ip,
                        expires_at
                    ],
                )
            })
            .map_err(|e| e.to_string())?;

        self.audit_service
            .log(
                None,
                "CREATE_NETWORK_ENDPOINT",
                "INFO",
                &format!(
                    "Created network endpoint '{}' ({}) via {}",
                    clean_name,
                    ep_type,
                    self.secret_store.provider_name()
                ),
            )
            .ok();

        Ok(NetworkEndpointRecord {
            id,
            name: clean_name.to_string(),
            endpoint_type: ep_type,
            provider_label: req.provider_label,
            host: req.host,
            port: req.port,
            username: clean_username,
            has_credentials,
            expected_country,
            expected_ip,
            expires_at,
            status: "ACTIVE".to_string(),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn list_endpoints(&self) -> Result<Vec<NetworkEndpointRecord>, String> {
        self.db
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, name, type, provider_label, host, port, encrypted_secret_reference,
                            status, created_at, updated_at, username, expected_country, expected_ip, expires_at
                     FROM network_endpoints ORDER BY created_at DESC",
                )?;

                let rows = stmt.query_map([], |row| {
                    let secret_ref: Option<String> = row.get(6)?;
                    Ok(NetworkEndpointRecord {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        endpoint_type: row.get(2)?,
                        provider_label: row.get(3)?,
                        host: row.get(4)?,
                        port: row.get(5)?,
                        has_credentials: secret_ref.is_some(),
                        status: row.get(7)?,
                        created_at: row.get(8)?,
                        updated_at: row.get(9)?,
                        username: row.get(10)?,
                        expected_country: row.get(11)?,
                        expected_ip: row.get(12)?,
                        expires_at: row.get(13)?,
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

    pub fn delete_endpoint(&self, id: &str) -> Result<(), String> {
        let secret_ref: Option<String> = self
            .db
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT encrypted_secret_reference FROM network_endpoints WHERE id = ?1",
                )?;
                let mut rows = stmt.query(rusqlite::params![id])?;
                if let Some(r) = rows.next()? {
                    Ok(r.get(0)?)
                } else {
                    Ok(None)
                }
            })
            .unwrap_or(None);

        if let Some(ref sref) = secret_ref {
            self.secret_store.delete_secret(sref).ok();
        }

        self.db
            .with_conn(|conn| {
                conn.execute(
                    "DELETE FROM network_endpoints WHERE id = ?1",
                    rusqlite::params![id],
                )
            })
            .map_err(|e| e.to_string())?;

        self.audit_service
            .log(
                None,
                "DELETE_NETWORK_ENDPOINT",
                "WARN",
                &format!("Deleted network endpoint '{}'", id),
            )
            .ok();

        Ok(())
    }

    pub fn assign_endpoint_to_environment(
        &self,
        environment_id: &str,
        endpoint_id: Option<&str>,
    ) -> Result<(), String> {
        let now = Utc::now().to_rfc3339();

        self.db
            .with_conn_mut(|conn| {
                let tx = conn.transaction()?;
                tx.execute(
                    "DELETE FROM environment_networks WHERE environment_id = ?1",
                    rusqlite::params![environment_id],
                )?;

                if let Some(ep_id) = endpoint_id {
                    if !ep_id.trim().is_empty() {
                        let link_id = Uuid::new_v4().to_string();
                        tx.execute(
                            "INSERT INTO environment_networks (id, environment_id, network_endpoint_id, policy_config, created_at)
                             VALUES (?1, ?2, ?3, ?4, ?5)",
                            rusqlite::params![link_id, environment_id, ep_id, "{}", now],
                        )?;
                    }
                }

                tx.commit()?;
                Ok(())
            })
            .map_err(|e| e.to_string())?;

        self.audit_service
            .log(
                Some(environment_id),
                "ASSIGN_NETWORK_ENDPOINT",
                "INFO",
                &format!(
                    "Assigned endpoint {:?} to environment {}",
                    endpoint_id, environment_id
                ),
            )
            .ok();

        Ok(())
    }

    pub fn probe_http_proxy_egress(
        host: &str,
        port: u16,
        creds: Option<&str>,
        timeout: Duration,
    ) -> Result<(String, Option<String>, u32), String> {
        use base64::Engine;
        use std::io::{Read, Write};
        let start = Instant::now();
        let target_str = format!("{}:{}", host, port);
        let addrs: Vec<_> = target_str
            .to_socket_addrs()
            .map_err(|e| format!("DNS lookup failed for {}:{}: {}", host, port, e))?
            .collect();

        let sock_addr = addrs
            .first()
            .ok_or_else(|| format!("Could not resolve address for {}", host))?;
        let mut stream = TcpStream::connect_timeout(sock_addr, timeout).map_err(|e| {
            format!(
                "Connection to proxy {}:{} timed out / refused: {}",
                host, port, e
            )
        })?;

        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();

        let mut auth_header = String::new();
        if let Some(c) = creds {
            if !c.trim().is_empty() {
                let encoded = base64::engine::general_purpose::STANDARD.encode(c.trim());
                auth_header = format!("Proxy-Authorization: Basic {}\r\n", encoded);
            }
        }

        // Request ipwho.is through proxy for both IP and country verification
        let req = format!(
            "GET http://ipwho.is/ HTTP/1.1\r\nHost: ipwho.is\r\n{}User-Agent: curl/8.4.0\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
            auth_header
        );

        stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("Proxy write failed: {}", e))?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|e| format!("Proxy read failed: {}", e))?;
        let latency = start.elapsed().as_millis() as u32;

        let resp_str = String::from_utf8_lossy(&response);
        let first_line = resp_str.lines().next().unwrap_or("");
        if first_line.contains(" 407 ")
            || first_line.ends_with(" 407")
            || resp_str.contains("407 Proxy Authentication")
        {
            return Err("AUTH_FAILED: Proxy Authentication Failed (HTTP 407)".to_string());
        }

        if let Some(pos) = resp_str.find("\r\n\r\n") {
            let body = resp_str[pos + 4..].trim();
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                if let Some(ip) = json.get("ip").and_then(|v| v.as_str()) {
                    let country = json
                        .get("country_code")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_uppercase());
                    return Ok((ip.to_string(), country, latency));
                }
            }
            if body.split('.').count() == 4
                && body.len() <= 45
                && body.chars().all(|c| c.is_ascii_digit() || c == '.')
            {
                return Ok((body.to_string(), None, latency));
            }
        }

        Err("Proxy returned non-IP response".to_string())
    }

    pub fn probe_direct_egress(timeout: Duration) -> Result<(String, Option<String>, u32), String> {
        use std::io::{Read, Write};
        let start = Instant::now();
        let addrs: Vec<_> = "ipwho.is:80"
            .to_socket_addrs()
            .map_err(|e| format!("DNS lookup failed for ipwho.is: {}", e))?
            .collect();

        let sock_addr = addrs
            .first()
            .ok_or_else(|| "Could not resolve ipwho.is".to_string())?;
        let mut stream = TcpStream::connect_timeout(sock_addr, timeout)
            .map_err(|e| format!("Connection to ipwho.is failed: {}", e))?;

        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();

        let req = "GET / HTTP/1.1\r\nHost: ipwho.is\r\nUser-Agent: curl/8.4.0\r\nAccept: application/json\r\nConnection: close\r\n\r\n";
        stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("Write failed: {}", e))?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|e| format!("Read failed: {}", e))?;
        let latency = start.elapsed().as_millis() as u32;

        let resp_str = String::from_utf8_lossy(&response);
        if let Some(pos) = resp_str.find("\r\n\r\n") {
            let body = resp_str[pos + 4..].trim();
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                if let Some(ip) = json.get("ip").and_then(|v| v.as_str()) {
                    let country = json
                        .get("country_code")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_uppercase());
                    return Ok((ip.to_string(), country, latency));
                }
            }
        }

        Err("Failed to resolve direct egress IP".to_string())
    }

    fn persist_network_check(&self, record: &NetworkCheckRecord) -> Result<(), String> {
        self.db
            .with_conn(|conn| {
                conn.execute(
                    "INSERT INTO network_checks (
                        id, environment_id, observed_ipv4, observed_ipv6, dns_summary,
                        check_source, status, checked_at, latency_ms, egress_stage,
                        observed_country, dns_leak_status, webrtc_status, session_id, error_details
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    rusqlite::params![
                        record.id,
                        record.environment_id,
                        record.observed_ipv4,
                        record.observed_ipv6,
                        record.dns_summary,
                        record.check_source,
                        record.status,
                        record.checked_at,
                        record.latency_ms,
                        record.status,
                        record.observed_country,
                        record.dns_leak_status,
                        record.webrtc_status,
                        record.session_id,
                        record.error_message
                    ],
                )?;

                conn.execute(
                    "UPDATE environments SET updated_at = ?1 WHERE id = ?2",
                    rusqlite::params![record.checked_at, record.environment_id],
                )?;

                Ok(())
            })
            .map_err(|e| e.to_string())
    }

    /// Backend proxy & environment reachability check.
    /// Never claims `BROWSER_EGRESS_VERIFIED` — backend proxy probes at most reach `PROXY_EGRESS_VERIFIED`.
    pub fn check_network(&self, environment_id: &str) -> Result<NetworkCheckRecord, String> {
        let env_info = self
            .db
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT e.name, e.vm_identifier, e.status, e.hypervisor_type, COALESCE(e.execution_mode, 'VM'),
                            en.network_endpoint_id, ne.name, ne.host, ne.port, ne.type,
                            ne.username, ne.encrypted_secret_reference, ne.expected_country, ne.expected_ip
                     FROM environments e
                     LEFT JOIN environment_networks en ON en.environment_id = e.id
                     LEFT JOIN network_endpoints ne ON ne.id = en.network_endpoint_id
                     WHERE e.id = ?1",
                )?;

                let mut rows = stmt.query(rusqlite::params![environment_id])?;
                if let Some(row) = rows.next()? {
                    Ok(Some((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, Option<u16>>(8)?,
                        row.get::<_, Option<String>>(9)?,
                        row.get::<_, Option<String>>(10)?,
                        row.get::<_, Option<String>>(11)?,
                        row.get::<_, Option<String>>(12)?,
                        row.get::<_, Option<String>>(13)?,
                    )))
                } else {
                    Ok(None)
                }
            })
            .map_err(|e| e.to_string())?;

        let (
            env_name,
            vm_id,
            db_status,
            hypervisor_type,
            execution_mode,
            ep_id_opt,
            ep_name,
            ep_host,
            ep_port,
            ep_type,
            ep_username,
            ep_secret_ref,
            expected_country,
            expected_ip,
        ) = match env_info {
            Some(info) => info,
            None => return Err(format!("Environment {} not found", environment_id)),
        };

        let is_native_browser =
            VmService::is_native_browser_mode(&hypervisor_type, Some(&execution_mode));
        let now = Utc::now().to_rfc3339();
        let check_id = Uuid::new_v4().to_string();

        // For VM environments, if the VM is stopped, we cannot verify guest network
        if !is_native_browser {
            let actual_vm_state = self
                .hypervisor
                .get_vm_state(&vm_id)
                .unwrap_or(crate::hypervisor::VmState::Unknown);
            if actual_vm_state != crate::hypervisor::VmState::Running && db_status != "RUNNING" {
                let record = NetworkCheckRecord {
                    id: check_id,
                    environment_id: environment_id.to_string(),
                    observed_ipv4: None,
                    observed_ipv6: None,
                    observed_country: None,
                    dns_summary: Some("DNS: Unreachable (guest VM stopped)".to_string()),
                    dns_leak_status: "UNVERIFIED".to_string(),
                    webrtc_status: "UNVERIFIED".to_string(),
                    check_source: "GUEST_DIAGNOSTICS".to_string(),
                    status: "NOT_CHECKED".to_string(),
                    error_message: Some(format!(
                        "Cannot verify network egress for '{}': VM is stopped. Diagnostics require a running guest OS.",
                        env_name
                    )),
                    checked_at: now,
                    latency_ms: None,
                    session_id: None,
                };
                self.persist_network_check(&record)?;
                return Ok(record);
            }
        }

        // If no network endpoint is configured
        if ep_id_opt.is_none()
            || ep_host
                .as_ref()
                .map(|h| h.trim().is_empty())
                .unwrap_or(true)
        {
            if is_native_browser {
                let record = NetworkCheckRecord {
                    id: check_id,
                    environment_id: environment_id.to_string(),
                    observed_ipv4: None,
                    observed_ipv6: None,
                    observed_country: None,
                    dns_summary: Some(
                        "No proxy endpoint configured for native browser environment".to_string(),
                    ),
                    dns_leak_status: "UNVERIFIED".to_string(),
                    webrtc_status: "UNVERIFIED".to_string(),
                    check_source: "BACKEND_CONFIG_CHECK".to_string(),
                    status: "NOT_CONFIGURED".to_string(),
                    error_message: Some(
                        "No US proxy endpoint is assigned to this environment.".to_string(),
                    ),
                    checked_at: now,
                    latency_ms: None,
                    session_id: None,
                };
                self.persist_network_check(&record)?;
                return Ok(record);
            } else {
                let record = NetworkCheckRecord {
                    id: check_id,
                    environment_id: environment_id.to_string(),
                    observed_ipv4: None,
                    observed_ipv6: None,
                    observed_country: None,
                    dns_summary: Some("Direct host NAT virtual network adapter attached (unverified inside guest)".to_string()),
                    dns_leak_status: "UNVERIFIED".to_string(),
                    webrtc_status: "UNVERIFIED".to_string(),
                    check_source: "DIRECT_PROBE".to_string(),
                    status: "ENDPOINT_CONFIGURED".to_string(),
                    error_message: None,
                    checked_at: now,
                    latency_ms: None,
                    session_id: None,
                };
                self.persist_network_check(&record)?;
                return Ok(record);
            }
        }

        let host = ep_host.unwrap();
        let port = ep_port.unwrap_or(1080);
        let target_addr = format!("{}:{}", host, port);

        let decrypted_secret = if let Some(ref sec_ref) = ep_secret_ref {
            match self.secret_store.retrieve_secret(sec_ref) {
                Ok(val) => {
                    if let Some(ref u) = ep_username {
                        if !u.trim().is_empty() && !val.contains(':') {
                            Some(format!("{}:{}", u.trim(), val))
                        } else {
                            Some(val)
                        }
                    } else {
                        Some(val)
                    }
                }
                Err(e) => {
                    let safe_err = redact_sensitive_str(&e.to_string());
                    let record = NetworkCheckRecord {
                        id: check_id,
                        environment_id: environment_id.to_string(),
                        observed_ipv4: None,
                        observed_ipv6: None,
                        observed_country: None,
                        dns_summary: Some(
                            "Failed to unseal proxy credentials from vault".to_string(),
                        ),
                        dns_leak_status: "UNVERIFIED".to_string(),
                        webrtc_status: "UNVERIFIED".to_string(),
                        check_source: "PROXY_PROBE".to_string(),
                        status: "AUTH_FAILED".to_string(),
                        error_message: Some(format!(
                            "Vault credential retrieval failed: {}",
                            safe_err
                        )),
                        checked_at: now,
                        latency_ms: None,
                        session_id: None,
                    };
                    self.persist_network_check(&record)?;
                    return Ok(record);
                }
            }
        } else {
            None
        };

        let start = Instant::now();
        let reachability_result = target_addr
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .map(|sock_addr| TcpStream::connect_timeout(&sock_addr, Duration::from_millis(2000)));
        let tcp_latency = start.elapsed().as_millis() as u32;

        match reachability_result {
            Some(Ok(_)) => {
                let is_http_proxy = matches!(
                    ep_type.as_deref().unwrap_or("HTTP").to_uppercase().as_str(),
                    "HTTP" | "HTTPS"
                );
                let egress_probe_result = if is_http_proxy {
                    Self::probe_http_proxy_egress(
                        &host,
                        port,
                        decrypted_secret.as_deref(),
                        Duration::from_millis(4000),
                    )
                } else {
                    Err("TCP handshake succeeded; full egress verification requires browser session or HTTP proxy probe".to_string())
                };

                let (
                    observed_ipv4,
                    observed_country,
                    status,
                    dns_info,
                    error_message,
                    final_latency,
                ) = match egress_probe_result {
                    Ok((real_ip, country_opt, real_latency)) => {
                        let country_str =
                            country_opt.clone().unwrap_or_else(|| "UNKNOWN".to_string());
                        let mut err_msg = None;
                        let mut final_status = "PROXY_EGRESS_VERIFIED".to_string();

                        if let Some(ref exp_c) = expected_country {
                            // IMPORTANT: "UNKNOWN" is NOT a valid country match — treat as failure.
                            let is_country_match = !country_str.is_empty()
                                && country_str != "UNKNOWN"
                                && country_str.eq_ignore_ascii_case(exp_c);
                            if !is_country_match {
                                final_status = "CONNECTION_FAILED".to_string();
                                err_msg = Some(
                                    if country_str == "UNKNOWN" || country_str.is_empty() {
                                        format!(
                                            "Geolocation returned UNKNOWN country — cannot confirm expected '{}'. Treating as UNVERIFIED.",
                                            exp_c
                                        )
                                    } else {
                                        format!(
                                            "Proxy country mismatch: expected '{}', but proxy egress resolved to '{}'",
                                            exp_c, country_str
                                        )
                                    },
                                );
                            }
                        }
                        if let Some(ref exp_ip) = expected_ip {
                            if !Self::is_valid_ip_address(exp_ip) {
                                err_msg = Some(format!(
                                    "Configured expected_ip '{}' is not a valid IP address — cannot verify",
                                    exp_ip
                                ));
                                final_status = "CONNECTION_FAILED".to_string();
                            } else if !Self::is_valid_ip_address(&real_ip) {
                                err_msg = Some(format!(
                                    "Observed IP '{}' from geolocation provider is not a valid IP — provider may be unreliable",
                                    real_ip
                                ));
                                final_status = "CONNECTION_FAILED".to_string();
                            } else if &real_ip != exp_ip {
                                err_msg = Some(format!(
                                    "Observed proxy IP ({}) differs from expected IP ({})",
                                    real_ip, exp_ip
                                ));
                            }
                        }

                        let note = format!(
                                "Backend proxy probe via {}:{} -> Observed IP: {} (Country: {}, {}ms). Launch browser to verify in-browser egress.",
                                host, port, real_ip, country_str, real_latency
                            );
                        (
                            Some(real_ip),
                            Some(country_str),
                            final_status,
                            note,
                            err_msg,
                            Some(real_latency),
                        )
                    }
                    Err(ref err) if err.contains("407") || err.contains("AUTH_FAILED") => {
                        let safe_err = redact_sensitive_str(err);
                        (
                            None,
                            None,
                            "AUTH_FAILED".to_string(),
                            "Proxy rejected credentials (HTTP 407)".to_string(),
                            Some(safe_err),
                            Some(tcp_latency),
                        )
                    }
                    Err(ref err) => {
                        let safe_err = redact_sensitive_str(err);
                        let note = format!(
                            "Endpoint {}:{} TCP handshake succeeded ({}ms). Egress probe note: {}",
                            host, port, tcp_latency, safe_err
                        );
                        (
                            None,
                            None,
                            "ENDPOINT_REACHABLE".to_string(),
                            note,
                            None,
                            Some(tcp_latency),
                        )
                    }
                };

                let record = NetworkCheckRecord {
                    id: check_id,
                    environment_id: environment_id.to_string(),
                    observed_ipv4,
                    observed_ipv6: None,
                    observed_country,
                    dns_summary: Some(dns_info),
                    dns_leak_status: "UNVERIFIED".to_string(),
                    webrtc_status: "UNVERIFIED".to_string(),
                    check_source: "PROXY_PROBE".to_string(),
                    status: status.clone(),
                    error_message,
                    checked_at: now,
                    latency_ms: final_latency,
                    session_id: None,
                };

                self.persist_network_check(&record)?;

                self.audit_service
                    .log(
                        Some(environment_id),
                        "NETWORK_REACHABILITY_CHECK",
                        if status == "AUTH_FAILED" {
                            "WARN"
                        } else {
                            "INFO"
                        },
                        &format!(
                            "Endpoint '{:?}' ({}:{}) backend check status: {}",
                            ep_name, host, port, status
                        ),
                    )
                    .ok();

                Ok(record)
            }
            _ => {
                let err_msg = format!(
                    "TCP connection to configured endpoint {}:{} failed (timeout / unreachable)",
                    host, port
                );
                let record = NetworkCheckRecord {
                    id: check_id,
                    environment_id: environment_id.to_string(),
                    observed_ipv4: None,
                    observed_ipv6: None,
                    observed_country: None,
                    dns_summary: Some("Connection to proxy host failed".to_string()),
                    dns_leak_status: "UNVERIFIED".to_string(),
                    webrtc_status: "UNVERIFIED".to_string(),
                    check_source: "HOST_PROBE".to_string(),
                    status: "CONNECTION_FAILED".to_string(),
                    error_message: Some(err_msg),
                    checked_at: now,
                    latency_ms: None,
                    session_id: None,
                };

                self.persist_network_check(&record)?;
                Ok(record)
            }
        }
    }

    /// Proxy-bridge egress verification for a running browser session (Phase 3).
    ///
    /// This function performs a **backend** HTTP probe through the local proxy bridge
    /// (`probe_via_local_bridge`).  Because the probe originates from the Rust process — not from
    /// Microsoft Edge itself — the highest status it can return is `PROXY_EGRESS_VERIFIED`.
    ///
    /// `BROWSER_EGRESS_VERIFIED` requires actual browser-origin verification via the Chrome
    /// DevTools Protocol (CDP) and is **not yet implemented**.  That path currently returns
    /// `VERIFICATION_UNAVAILABLE` as a placeholder until CDP integration is added.
    ///
    /// Status hierarchy:
    /// - Browser not running          → `VERIFICATION_UNAVAILABLE`
    /// - No proxy configured          → `NOT_CONFIGURED`
    /// - No bridge port               → `VERIFICATION_UNAVAILABLE`
    /// - Bridge probe fails           → `CONNECTION_FAILED` or `AUTH_FAILED`
    /// - Bridge probe succeeds + country matches → `PROXY_EGRESS_VERIFIED`
    /// - Direct fallback detected     → `CONNECTION_FAILED`
    /// - Country mismatch / UNKNOWN   → `CONNECTION_FAILED`
    pub fn verify_browser_egress(
        &self,
        environment_id: &str,
        profile_service: &ProfileService,
    ) -> Result<NetworkCheckRecord, String> {
        let now = Utc::now().to_rfc3339();
        let check_id = Uuid::new_v4().to_string();

        // 1. Verify browser session is actively running for this environment
        let browser_status = profile_service.get_browser_session_status(environment_id)?;
        let (pid, bridge_port_opt, cdp_port_opt) = match browser_status {
            BrowserStatus::Running {
                pid,
                proxy_bridge_port,
                cdp_port,
                ..
            } => (pid, proxy_bridge_port, cdp_port),
            _ => {
                let record = NetworkCheckRecord {
                    id: check_id,
                    environment_id: environment_id.to_string(),
                    observed_ipv4: None,
                    observed_ipv6: None,
                    observed_country: None,
                    dns_summary: Some("Browser session is not running".to_string()),
                    dns_leak_status: "UNVERIFIED".to_string(),
                    webrtc_status: "UNVERIFIED".to_string(),
                    check_source: "PROXY_BRIDGE_PROBE".to_string(),
                    status: "VERIFICATION_UNAVAILABLE".to_string(),
                    error_message: Some(
                        "Cannot report BROWSER_EGRESS_VERIFIED: Microsoft Edge session is not running for this environment. Launch the browser first."
                            .to_string(),
                    ),
                    checked_at: now,
                    latency_ms: None,
                    session_id: None,
                };
                self.persist_network_check(&record)?;
                return Ok(record);
            }
        };

        let session_tag = format!("pid:{}", pid);

        // 2. Check configured endpoint metadata for this environment
        let ep_meta = self
            .db
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT ne.id, ne.name, ne.host, ne.port, ne.type, ne.expected_country, ne.expected_ip
                     FROM environment_networks en
                     JOIN network_endpoints ne ON ne.id = en.network_endpoint_id
                     WHERE en.environment_id = ?1",
                )?;
                let mut rows = stmt.query(rusqlite::params![environment_id])?;
                if let Some(row) = rows.next()? {
                    Ok(Some((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<u16>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                    )))
                } else {
                    Ok(None)
                }
            })
            .map_err(|e| e.to_string())?;

        let (_ep_id, ep_name, ep_host_opt, _ep_port_opt, _ep_type, expected_country, expected_ip) =
            match ep_meta {
                Some(m) => m,
                None => {
                    let record = NetworkCheckRecord {
                        id: check_id,
                        environment_id: environment_id.to_string(),
                        observed_ipv4: None,
                        observed_ipv6: None,
                        observed_country: None,
                        dns_summary: Some(
                            "No proxy configured for running browser session".to_string(),
                        ),
                        dns_leak_status: "UNVERIFIED".to_string(),
                        webrtc_status: "NON_PROXIED_UDP_DISABLED".to_string(),
                        check_source: "BROWSER_SESSION".to_string(),
                        status: "NOT_CONFIGURED".to_string(),
                        error_message: Some(
                            "Browser is running without an assigned proxy endpoint.".to_string(),
                        ),
                        checked_at: now,
                        latency_ms: None,
                        session_id: Some(session_tag),
                    };
                    self.persist_network_check(&record)?;
                    return Ok(record);
                }
            };

        let bridge_port = match bridge_port_opt {
            Some(p) => p,
            None => {
                let record = NetworkCheckRecord {
                    id: check_id,
                    environment_id: environment_id.to_string(),
                    observed_ipv4: None,
                    observed_ipv6: None,
                    observed_country: None,
                    dns_summary: Some("No active proxy bridge bound to browser session".to_string()),
                    dns_leak_status: "UNVERIFIED".to_string(),
                    webrtc_status: "UNVERIFIED".to_string(),
                    check_source: "PROXY_BRIDGE_PROBE".to_string(),
                    status: "VERIFICATION_UNAVAILABLE".to_string(),
                    error_message: Some(
                        "Browser session does not have an active local proxy bridge. Restart the browser session to bind the proxy."
                            .to_string(),
                    ),
                    checked_at: now,
                    latency_ms: None,
                    session_id: Some(session_tag),
                };
                self.persist_network_check(&record)?;
                return Ok(record);
            }
        };

        // 3. Verify through the active session's localhost proxy bridge
        match probe_via_local_bridge(bridge_port, Duration::from_millis(6000)) {
            Ok(probe_res) => {
                // Check for unexpected direct network fallback when proxy host is not loopback
                let is_loopback_proxy = ep_host_opt
                    .as_deref()
                    .map(|h| h == "127.0.0.1" || h == "localhost")
                    .unwrap_or(false);

                if !is_loopback_proxy {
                    if let Ok((direct_ip, _, _)) =
                        Self::probe_direct_egress(Duration::from_millis(2000))
                    {
                        if direct_ip == probe_res.observed_ipv4 {
                            let err = format!(
                                "Unexpected direct network fallback detected! Browser egress IP ({}) matches host direct IP.",
                                probe_res.observed_ipv4
                            );
                            let record = NetworkCheckRecord {
                                id: check_id,
                                environment_id: environment_id.to_string(),
                                observed_ipv4: Some(probe_res.observed_ipv4),
                                observed_ipv6: None,
                                observed_country: probe_res.observed_country,
                                dns_summary: Some("Direct fallback leak detected".to_string()),
                                dns_leak_status: "UNVERIFIED".to_string(),
                                webrtc_status: "NON_PROXIED_UDP_DISABLED".to_string(),
                                check_source: "PROXY_BRIDGE_PROBE".to_string(),
                                status: "CONNECTION_FAILED".to_string(),
                                error_message: Some(err),
                                checked_at: now,
                                latency_ms: Some(probe_res.latency_ms),
                                session_id: Some(session_tag),
                            };
                            self.persist_network_check(&record)?;
                            return Ok(record);
                        }
                    }
                }

                let country_code = probe_res
                    .observed_country
                    .clone()
                    .unwrap_or_else(|| "UNKNOWN".to_string());

                // Check expected country match.
                // IMPORTANT: "UNKNOWN" is NOT a valid match — treat as failure when expected_country is set.
                if let Some(ref exp_c) = expected_country {
                    let is_country_match = !country_code.is_empty()
                        && country_code != "UNKNOWN"
                        && country_code.eq_ignore_ascii_case(exp_c);
                    if !is_country_match {
                        let err = if country_code == "UNKNOWN" || country_code.is_empty() {
                            format!(
                                "Geolocation returned UNKNOWN country — cannot confirm expected '{}'. Treating as UNVERIFIED.",
                                exp_c
                            )
                        } else {
                            format!(
                                "Proxy bridge egress country mismatch: expected '{}', observed '{}'",
                                exp_c, country_code
                            )
                        };
                        let record = NetworkCheckRecord {
                            id: check_id,
                            environment_id: environment_id.to_string(),
                            observed_ipv4: Some(probe_res.observed_ipv4),
                            observed_ipv6: probe_res.observed_ipv6,
                            observed_country: Some(country_code),
                            dns_summary: Some(probe_res.dns_summary),
                            dns_leak_status: "REMOTE_PROXY_DNS".to_string(),
                            webrtc_status: "NON_PROXIED_UDP_DISABLED".to_string(),
                            check_source: "PROXY_BRIDGE_PROBE".to_string(),
                            status: "CONNECTION_FAILED".to_string(),
                            error_message: Some(err),
                            checked_at: now,
                            latency_ms: Some(probe_res.latency_ms),
                            session_id: Some(session_tag),
                        };
                        self.persist_network_check(&record)?;
                        return Ok(record);
                    }
                }

                // Check expected IP match if specified
                // Validate expected_ip is a valid IP address before comparing
                if let Some(ref exp_ip) = expected_ip {
                    if !Self::is_valid_ip_address(exp_ip) {
                        let err = format!(
                            "Configured expected_ip '{}' is not a valid IP address — cannot verify",
                            exp_ip
                        );
                        let record = NetworkCheckRecord {
                            id: check_id,
                            environment_id: environment_id.to_string(),
                            observed_ipv4: Some(probe_res.observed_ipv4.clone()),
                            observed_ipv6: probe_res.observed_ipv6.clone(),
                            observed_country: Some(country_code.clone()),
                            dns_summary: Some(probe_res.dns_summary.clone()),
                            dns_leak_status: "UNVERIFIED".to_string(),
                            webrtc_status: "UNVERIFIED".to_string(),
                            check_source: "PROXY_BRIDGE_PROBE".to_string(),
                            status: "CONNECTION_FAILED".to_string(),
                            error_message: Some(err),
                            checked_at: now.clone(),
                            latency_ms: Some(probe_res.latency_ms),
                            session_id: Some(session_tag.clone()),
                        };
                        self.persist_network_check(&record)?;
                        return Ok(record);
                    }
                    if !Self::is_valid_ip_address(&probe_res.observed_ipv4) {
                        let err = format!(
                            "Observed IP '{}' from geolocation provider is not a valid IP — provider may be unreliable",
                            probe_res.observed_ipv4
                        );
                        let record = NetworkCheckRecord {
                            id: check_id,
                            environment_id: environment_id.to_string(),
                            observed_ipv4: None,
                            observed_ipv6: None,
                            observed_country: Some(country_code.clone()),
                            dns_summary: Some(probe_res.dns_summary.clone()),
                            dns_leak_status: "UNVERIFIED".to_string(),
                            webrtc_status: "UNVERIFIED".to_string(),
                            check_source: "PROXY_BRIDGE_PROBE".to_string(),
                            status: "CONNECTION_FAILED".to_string(),
                            error_message: Some(err),
                            checked_at: now.clone(),
                            latency_ms: Some(probe_res.latency_ms),
                            session_id: Some(session_tag.clone()),
                        };
                        self.persist_network_check(&record)?;
                        return Ok(record);
                    }
                    if probe_res.observed_ipv4 != *exp_ip {
                        let err = format!(
                            "Proxy bridge egress IP mismatch: expected '{}', observed '{}'",
                            exp_ip, probe_res.observed_ipv4
                        );
                        let record = NetworkCheckRecord {
                            id: check_id,
                            environment_id: environment_id.to_string(),
                            observed_ipv4: Some(probe_res.observed_ipv4),
                            observed_ipv6: probe_res.observed_ipv6,
                            observed_country: Some(country_code),
                            dns_summary: Some(probe_res.dns_summary),
                            dns_leak_status: "REMOTE_PROXY_DNS".to_string(),
                            webrtc_status: "NON_PROXIED_UDP_DISABLED".to_string(),
                            check_source: "PROXY_BRIDGE_PROBE".to_string(),
                            status: "CONNECTION_FAILED".to_string(),
                            error_message: Some(err),
                            checked_at: now,
                            latency_ms: Some(probe_res.latency_ms),
                            session_id: Some(session_tag),
                        };
                        self.persist_network_check(&record)?;
                        return Ok(record);
                    }
                }

                let bridge_instance_id = profile_service
                    .proxy_bridge_manager()
                    .get_instance_id(environment_id);

                let bridge_session = BrowserSessionInfo {
                    environment_id: environment_id.to_string(),
                    session_id: session_tag.clone(),
                    pid,
                    profile_path: String::new(),
                    proxy_bridge_port: Some(bridge_port),
                    proxy_endpoint_id: _ep_id.clone(),
                    bridge_instance_id,
                    expected_country: expected_country.clone(),
                    expected_ip: expected_ip.clone(),
                    recent_bridge_connection_count: profile_service
                        .proxy_bridge_manager()
                        .recent_tunnel_count(environment_id, 300),
                    cdp_port: cdp_port_opt,
                    is_simulation: false,
                };

                // Attempt real CDP browser-origin verification if Edge has an active loopback debug port
                let cdp_evidence = if let Some(cdp_port) = cdp_port_opt {
                    attempt_cdp_browser_verification(
                        &bridge_session,
                        cdp_port,
                        Some(profile_service.proxy_bridge_manager()),
                    )
                    .ok()
                    .filter(|ev| evaluate_verification_decision(ev).is_ok())
                } else {
                    None
                };

                let (final_status, check_source, audit_msg) = if let Some(ref evidence) =
                    cdp_evidence
                {
                    (
                        "BROWSER_EGRESS_VERIFIED".to_string(),
                        "BROWSER_SESSION".to_string(),
                        format!(
                            "Edge browser-origin egress verified via CDP and correlated with proxy bridge instance ({}) for session ({}): external IP {}, country {}.",
                            evidence.bridge_instance_id.as_deref().unwrap_or("unknown"),
                            session_tag,
                            evidence.observed_public_ip.as_deref().unwrap_or(""),
                            evidence.observed_country.as_deref().unwrap_or("")
                        ),
                    )
                } else {
                    (
                        "PROXY_EGRESS_VERIFIED".to_string(),
                        "PROXY_BRIDGE_PROBE".to_string(),
                        format!(
                            "Proxy bridge probe for session ({}) confirmed egress IP: {} (country: {}, latency: {}ms). Note: browser-origin verification requires active CDP session and correlated proxy tunnel.",
                            session_tag, probe_res.observed_ipv4, country_code, probe_res.latency_ms
                        ),
                    )
                };

                let record = NetworkCheckRecord {
                    id: check_id,
                    environment_id: environment_id.to_string(),
                    observed_ipv4: cdp_evidence
                        .as_ref()
                        .and_then(|e| e.observed_public_ip.clone())
                        .or(Some(probe_res.observed_ipv4.clone())),
                    observed_ipv6: probe_res.observed_ipv6,
                    observed_country: cdp_evidence
                        .as_ref()
                        .and_then(|e| e.observed_country.clone())
                        .or(Some(country_code.clone())),
                    dns_summary: Some(format!(
                        "{} (Bridge 127.0.0.1:{} -> '{}' [{}])",
                        probe_res.dns_summary, bridge_port, ep_name, session_tag
                    )),
                    dns_leak_status: "REMOTE_PROXY_DNS".to_string(),
                    webrtc_status: "NON_PROXIED_UDP_DISABLED".to_string(),
                    check_source,
                    status: final_status.clone(),
                    error_message: None,
                    checked_at: now,
                    latency_ms: cdp_evidence
                        .as_ref()
                        .and_then(|e| e.latency_ms)
                        .or(Some(probe_res.latency_ms)),
                    session_id: Some(session_tag.clone()),
                };

                self.persist_network_check(&record)?;

                self.audit_service
                    .log(Some(environment_id), &final_status, "INFO", &audit_msg)
                    .ok();

                Ok(record)
            }
            Err(err) => {
                let safe_err = redact_sensitive_str(&err);
                let is_auth = safe_err.contains("AUTH_FAILED") || safe_err.contains("407");
                let status = if is_auth {
                    "AUTH_FAILED".to_string()
                } else {
                    "CONNECTION_FAILED".to_string()
                };

                let record = NetworkCheckRecord {
                    id: check_id,
                    environment_id: environment_id.to_string(),
                    observed_ipv4: None,
                    observed_ipv6: None,
                    observed_country: None,
                    dns_summary: Some(
                        "Proxy bridge verification failed (direct fallback blocked)".to_string(),
                    ),
                    dns_leak_status: "UNVERIFIED".to_string(),
                    webrtc_status: "NON_PROXIED_UDP_DISABLED".to_string(),
                    check_source: "PROXY_BRIDGE_PROBE".to_string(),
                    status: status.clone(),
                    error_message: Some(safe_err.clone()),
                    checked_at: now,
                    latency_ms: None,
                    session_id: Some(session_tag),
                };

                self.persist_network_check(&record)?;

                self.audit_service
                    .log(
                        Some(environment_id),
                        "PROXY_BRIDGE_EGRESS_FAILED",
                        "ERROR",
                        &format!(
                            "Proxy bridge egress verification failed ({}): {}",
                            status, safe_err
                        ),
                    )
                    .ok();

                Ok(record)
            }
        }
    }

    /// Record a verified in-guest diagnostic result received from an authorized in-guest probe
    pub fn record_guest_diagnostic_result(
        &self,
        environment_id: &str,
        observed_ipv4: &str,
        observed_ipv6: Option<&str>,
        dns_summary: &str,
        latency_ms: u32,
    ) -> Result<NetworkCheckRecord, String> {
        let check_id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        let record = NetworkCheckRecord {
            id: check_id,
            environment_id: environment_id.to_string(),
            observed_ipv4: Some(observed_ipv4.to_string()),
            observed_ipv6: observed_ipv6.map(|s| s.to_string()),
            observed_country: None,
            dns_summary: Some(dns_summary.to_string()),
            dns_leak_status: "UNVERIFIED".to_string(),
            webrtc_status: "UNVERIFIED".to_string(),
            check_source: "GUEST_AGENT".to_string(),
            status: "GUEST_EGRESS_OBSERVED".to_string(),
            error_message: None,
            checked_at: now,
            latency_ms: Some(latency_ms),
            session_id: None,
        };

        self.persist_network_check(&record)?;

        self.audit_service
            .log(
                Some(environment_id),
                "GUEST_EGRESS_VERIFIED",
                "INFO",
                &format!(
                    "Observed in-guest egress IP: {} (latency: {}ms)",
                    observed_ipv4, latency_ms
                ),
            )
            .ok();

        Ok(record)
    }

    pub fn detect_duplicate_egress(&self) -> Result<Vec<DuplicateEgressWarning>, String> {
        self.db
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT nc.observed_ipv4, GROUP_CONCAT(e.name, ', ') as env_names, COUNT(DISTINCT e.id) as env_count
                     FROM network_checks nc
                     JOIN environments e ON e.id = nc.environment_id
                     WHERE nc.observed_ipv4 IS NOT NULL
                       AND nc.id IN (SELECT id FROM network_checks GROUP BY environment_id HAVING MAX(checked_at))
                     GROUP BY nc.observed_ipv4
                     HAVING env_count > 1",
                )?;

                let rows = stmt.query_map([], |row| {
                    let ip: String = row.get(0)?;
                    let names_str: String = row.get(1)?;
                    let names: Vec<String> = names_str
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect();

                    Ok(DuplicateEgressWarning {
                        ip_address: ip.clone(),
                        conflicting_environments: names,
                        message: format!(
                            "Duplicate Public IP Egress detected! Environments [{}] share the same public IP ({}). This compromises isolation.",
                            names_str, ip
                        ),
                    })
                })?;

                let mut warnings = Vec::new();
                for r in rows {
                    warnings.push(r?);
                }
                Ok(warnings)
            })
            .map_err(|e| e.to_string())
    }

    /// Returns the most recent network check for an environment, or `None` if no checks exist.
    pub fn get_latest_network_check(
        &self,
        environment_id: &str,
    ) -> Result<Option<NetworkCheckRecord>, String> {
        self.db
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, environment_id, observed_ipv4, observed_ipv6, dns_summary, check_source,
                            status, checked_at, latency_ms, observed_country,
                            COALESCE(dns_leak_status, 'UNVERIFIED'),
                            COALESCE(webrtc_status, 'UNVERIFIED'),
                            session_id, error_details
                     FROM network_checks WHERE environment_id = ?1 ORDER BY checked_at DESC LIMIT 1",
                )?;

                let mut rows = stmt.query_map(rusqlite::params![environment_id], |row| {
                    Ok(NetworkCheckRecord {
                        id: row.get(0)?,
                        environment_id: row.get(1)?,
                        observed_ipv4: row.get(2)?,
                        observed_ipv6: row.get(3)?,
                        dns_summary: row.get(4)?,
                        check_source: row.get(5)?,
                        status: row.get(6)?,
                        checked_at: row.get(7)?,
                        latency_ms: row.get(8)?,
                        observed_country: row.get(9)?,
                        dns_leak_status: row.get(10)?,
                        webrtc_status: row.get(11)?,
                        session_id: row.get(12)?,
                        error_message: row.get(13)?,
                    })
                })?;

                if let Some(row) = rows.next() {
                    Ok(Some(row?))
                } else {
                    Ok(None)
                }
            })
            .map_err(|e| e.to_string())
    }

    /// Returns the most recent network check for an environment, tagged as STALE
    /// if it is older than `max_age_secs`. Callers must re-verify before treating
    /// a stale result as evidence of current network state.
    pub fn get_latest_network_check_with_staleness(
        &self,
        environment_id: &str,
        max_age_secs: u64,
    ) -> Result<Option<NetworkCheckRecord>, String> {
        let record = self.get_latest_network_check(environment_id)?;
        if let Some(mut r) = record {
            if crate::services::network_service::is_verification_stale(&r, max_age_secs) {
                r.status = "STALE".to_string();
            }
            Ok(Some(r))
        } else {
            Ok(None)
        }
    }

    pub fn get_network_history(
        &self,
        environment_id: &str,
        limit: usize,
    ) -> Result<Vec<NetworkCheckRecord>, String> {
        self.db
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, environment_id, observed_ipv4, observed_ipv6, dns_summary, check_source,
                            status, checked_at, latency_ms, observed_country,
                            COALESCE(dns_leak_status, 'UNVERIFIED'),
                            COALESCE(webrtc_status, 'UNVERIFIED'),
                            session_id, error_details
                     FROM network_checks WHERE environment_id = ?1 ORDER BY checked_at DESC LIMIT ?2",
                )?;

                let rows = stmt.query_map(rusqlite::params![environment_id, limit as i64], |row| {
                    Ok(NetworkCheckRecord {
                        id: row.get(0)?,
                        environment_id: row.get(1)?,
                        observed_ipv4: row.get(2)?,
                        observed_ipv6: row.get(3)?,
                        dns_summary: row.get(4)?,
                        check_source: row.get(5)?,
                        status: row.get(6)?,
                        checked_at: row.get(7)?,
                        latency_ms: row.get(8)?,
                        observed_country: row.get(9)?,
                        dns_leak_status: row.get(10)?,
                        webrtc_status: row.get(11)?,
                        session_id: row.get(12)?,
                        error_message: row.get(13)?,
                    })
                })?;

                let mut checks = Vec::new();
                for r in rows {
                    checks.push(r?);
                }
                Ok(checks)
            })
            .map_err(|e| e.to_string())
    }

    pub fn get_network_protection_status(
        &self,
        environment_id: &str,
    ) -> Result<NetworkProtectionStatus, String> {
        let latest = self.get_network_history(environment_id, 1)?;
        if let Some(record) = latest.into_iter().next() {
            Ok(NetworkProtectionStatus::from_check_record(
                &record,
                environment_id,
            ))
        } else {
            Ok(NetworkProtectionStatus {
                environment_id: environment_id.to_string(),
                dns_status: "UNVERIFIED".to_string(),
                dns_notes: "No network check has been performed yet.".to_string(),
                ipv6_status: "UNVERIFIED".to_string(),
                ipv6_notes: "No network check has been performed yet.".to_string(),
                webrtc_status: "UNVERIFIED".to_string(),
                webrtc_notes: "No network check has been performed yet.".to_string(),
                overall_status: "UNVERIFIED".to_string(),
                assessed_at: chrono::Utc::now().to_rfc3339(),
            })
        }
    }
}

/// Returns true if a NetworkCheckRecord is stale (older than the given max_age_secs).
/// Any persisted result must be re-verified for a new browser session.
pub fn is_verification_stale(record: &NetworkCheckRecord, max_age_secs: u64) -> bool {
    use chrono::DateTime;
    if let Ok(checked) = record.checked_at.parse::<DateTime<chrono::Utc>>() {
        let age = chrono::Utc::now().signed_duration_since(checked);
        age.num_seconds() > max_age_secs as i64
    } else {
        true // Cannot parse timestamp — treat as stale
    }
}
