use crate::db::Database;
use crate::hypervisor::HypervisorAdapter;
use crate::security::{get_secret_store, SecretStore};
use crate::services::audit_service::AuditService;
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
    pub endpoint_type: String, // "HTTP", "SOCKS5", "WIREGUARD", "DIRECT"
    pub provider_label: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub has_credentials: bool,
    pub status: String, // "ACTIVE", "INACTIVE", "ERROR"
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEndpointRequest {
    pub name: String,
    pub endpoint_type: String,
    pub provider_label: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub credentials_secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCheckRecord {
    pub id: String,
    pub environment_id: String,
    pub observed_ipv4: Option<String>,
    pub observed_ipv6: Option<String>,
    pub dns_summary: Option<String>,
    pub check_source: String, // "GUEST_AGENT", "HOST_PROBE", "DIRECT_PROBE", "TEST_FIXTURE"
    pub status: String,       // "ENDPOINT_CONFIGURED", "ENDPOINT_REACHABLE", "GUEST_EGRESS_OBSERVED", "CONNECTION_FAILED", "VERIFICATION_UNAVAILABLE", "NOT_CHECKED"
    pub error_message: Option<String>,
    pub checked_at: String,
    pub latency_ms: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateEgressWarning {
    pub ip_address: String,
    pub conflicting_environments: Vec<String>,
    pub message: String,
}

fn detect_host_public_ip() -> String {
    if let Ok(output) = std::process::Command::new("curl.exe")
        .args(&["-s", "--max-time", "3", "https://api.ipify.org"])
        .output()
    {
        if output.status.success() {
            let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !ip.is_empty() && ip.chars().all(|c| c.is_ascii_digit() || c == '.') {
                return ip;
            }
        }
    }
    "127.0.0.1".to_string()
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

    pub fn create_endpoint(&self, req: CreateEndpointRequest) -> Result<NetworkEndpointRecord, String> {
        let clean_name = req.name.trim();
        if clean_name.is_empty() {
            return Err("Endpoint name cannot be empty".to_string());
        }

        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        // Encrypt credentials via cross-platform SecretStore
        let encrypted_secret = if let Some(ref creds) = req.credentials_secret {
            if !creds.is_empty() {
                Some(self.secret_store.store_secret(&id, creds).map_err(|e| format!("Secret store error: {}", e))?)
            } else {
                None
            }
        } else {
            None
        };

        let has_credentials = encrypted_secret.is_some();

        self.db.with_conn(|conn| {
            conn.execute(
                "INSERT INTO network_endpoints (id, name, type, provider_label, host, port, encrypted_secret_reference, status, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    id,
                    clean_name,
                    req.endpoint_type,
                    req.provider_label,
                    req.host,
                    req.port,
                    encrypted_secret,
                    "ACTIVE",
                    now,
                    now
                ],
            )
        }).map_err(|e| e.to_string())?;

        self.audit_service.log(
            None,
            "CREATE_NETWORK_ENDPOINT",
            "INFO",
            &format!("Created network endpoint '{}' ({}) via {}", clean_name, req.endpoint_type, self.secret_store.provider_name()),
        ).ok();

        Ok(NetworkEndpointRecord {
            id,
            name: clean_name.to_string(),
            endpoint_type: req.endpoint_type,
            provider_label: req.provider_label,
            host: req.host,
            port: req.port,
            has_credentials,
            status: "ACTIVE".to_string(),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn list_endpoints(&self) -> Result<Vec<NetworkEndpointRecord>, String> {
        self.db.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, name, type, provider_label, host, port, encrypted_secret_reference, status, created_at, updated_at 
                 FROM network_endpoints ORDER BY created_at DESC"
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
                })
            })?;

            let mut list = Vec::new();
            for r in rows {
                list.push(r?);
            }
            Ok(list)
        }).map_err(|e| e.to_string())
    }

    pub fn delete_endpoint(&self, id: &str) -> Result<(), String> {
        // Remove secret from vault if present
        let secret_ref: Option<String> = self.db.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT encrypted_secret_reference FROM network_endpoints WHERE id = ?1")?;
            let mut rows = stmt.query(rusqlite::params![id])?;
            if let Some(r) = rows.next()? {
                Ok(r.get(0)?)
            } else {
                Ok(None)
            }
        }).unwrap_or(None);

        if let Some(ref sref) = secret_ref {
            self.secret_store.delete_secret(sref).ok();
        }

        self.db.with_conn(|conn| {
            conn.execute("DELETE FROM network_endpoints WHERE id = ?1", rusqlite::params![id])
        }).map_err(|e| e.to_string())?;

        self.audit_service.log(
            None,
            "DELETE_NETWORK_ENDPOINT",
            "WARN",
            &format!("Deleted network endpoint '{}'", id),
        ).ok();

        Ok(())
    }

    pub fn assign_endpoint_to_environment(
        &self,
        environment_id: &str,
        endpoint_id: Option<&str>,
    ) -> Result<(), String> {
        let now = Utc::now().to_rfc3339();

        self.db.with_conn_mut(|conn| {
            let tx = conn.transaction()?;
            tx.execute(
                "DELETE FROM environment_networks WHERE environment_id = ?1",
                rusqlite::params![environment_id],
            )?;

            if let Some(ep_id) = endpoint_id {
                let link_id = Uuid::new_v4().to_string();
                tx.execute(
                    "INSERT INTO environment_networks (id, environment_id, network_endpoint_id, policy_config, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![link_id, environment_id, ep_id, "{}", now],
                )?;
            }

            tx.commit()?;
            Ok(())
        }).map_err(|e| e.to_string())?;

        self.audit_service.log(
            Some(environment_id),
            "ASSIGN_NETWORK_ENDPOINT",
            "INFO",
            &format!("Assigned endpoint {:?} to environment {}", endpoint_id, environment_id),
        ).ok();

        Ok(())
    }

    fn probe_http_proxy_egress(host: &str, port: u16, creds: Option<&str>, timeout: Duration) -> Result<(String, u32), String> {
        use std::io::{Read, Write};
        use base64::Engine;
        let start = Instant::now();
        let target_str = format!("{}:{}", host, port);
        let addrs: Vec<_> = target_str
            .to_socket_addrs()
            .map_err(|e| format!("DNS lookup failed for {}:{}: {}", host, port, e))?
            .collect();

        let sock_addr = addrs.first().ok_or_else(|| format!("Could not resolve address for {}", host))?;
        let mut stream = TcpStream::connect_timeout(sock_addr, timeout)
            .map_err(|e| format!("Connection to proxy {}:{} timed out / refused: {}", host, port, e))?;

        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();

        let mut auth_header = String::new();
        if let Some(c) = creds {
            if !c.trim().is_empty() {
                let encoded = base64::engine::general_purpose::STANDARD.encode(c.trim());
                auth_header = format!("Proxy-Authorization: Basic {}\r\n", encoded);
            }
        }

        let req = format!(
            "GET http://api.ipify.org/ HTTP/1.1\r\nHost: api.ipify.org\r\n{}User-Agent: curl/8.4.0\r\nConnection: close\r\n\r\n",
            auth_header
        );

        stream.write_all(req.as_bytes()).map_err(|e| format!("Proxy write failed: {}", e))?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response).map_err(|e| format!("Proxy read failed: {}", e))?;
        let latency = start.elapsed().as_millis() as u32;

        let resp_str = String::from_utf8_lossy(&response);
        if resp_str.contains("407") {
            return Err("Proxy Authentication Failed (HTTP 407): Sai tên đăng nhập hoặc mật khẩu proxy!".to_string());
        }

        if let Some(pos) = resp_str.find("\r\n\r\n") {
            let body = resp_str[pos + 4..].trim().to_string();
            if body.split('.').count() == 4 || body.contains(':') {
                return Ok((body, latency));
            }
        }

        Err("Proxy returned non-IP response".to_string())
    }

    fn probe_direct_egress(timeout: Duration) -> Result<(String, u32), String> {
        use std::io::{Read, Write};
        let start = Instant::now();
        let addrs: Vec<_> = "api.ipify.org:80"
            .to_socket_addrs()
            .map_err(|e| format!("DNS lookup failed for api.ipify.org: {}", e))?
            .collect();

        let sock_addr = addrs.first().ok_or_else(|| "Could not resolve api.ipify.org".to_string())?;
        let mut stream = TcpStream::connect_timeout(sock_addr, timeout)
            .map_err(|e| format!("Connection to api.ipify.org failed: {}", e))?;

        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();

        let req = "GET / HTTP/1.1\r\nHost: api.ipify.org\r\nUser-Agent: curl/8.4.0\r\nConnection: close\r\n\r\n";
        stream.write_all(req.as_bytes()).map_err(|e| format!("Write failed: {}", e))?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response).map_err(|e| format!("Read failed: {}", e))?;
        let latency = start.elapsed().as_millis() as u32;

        let resp_str = String::from_utf8_lossy(&response);
        if let Some(pos) = resp_str.find("\r\n\r\n") {
            let body = resp_str[pos + 4..].trim().to_string();
            if body.split('.').count() == 4 || body.contains(':') {
                return Ok((body, latency));
            }
        }

        Err("Failed to resolve direct egress IP".to_string())
    }

    pub fn check_network(&self, environment_id: &str) -> Result<NetworkCheckRecord, String> {
        // Step 1: Query environment, endpoint, and encrypted secret reference
        let env_info = self.db.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT e.name, e.vm_identifier, e.status, en.network_endpoint_id, ne.name, ne.host, ne.port, ne.type, ne.encrypted_secret_reference
                 FROM environments e
                 LEFT JOIN environment_networks en ON en.environment_id = e.id
                 LEFT JOIN network_endpoints ne ON ne.id = en.network_endpoint_id
                 WHERE e.id = ?1"
            )?;

            let mut rows = stmt.query(rusqlite::params![environment_id])?;
            if let Some(row) = rows.next()? {
                Ok(Some((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
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
        }).map_err(|e| e.to_string())?;

        let (env_name, vm_id, db_status, _ep_id, ep_name, ep_host, ep_port, ep_type, ep_secret_ref) = match env_info {
            Some(info) => info,
            None => return Err(format!("Environment {} not found", environment_id)),
        };

        let decrypted_secret = if let Some(ref sec_ref) = ep_secret_ref {
            self.secret_store.retrieve_secret(sec_ref).ok()
        } else {
            None
        };

        let actual_vm_state = self.hypervisor.get_vm_state(&vm_id).unwrap_or(crate::hypervisor::VmState::Unknown);
        let now = Utc::now().to_rfc3339();
        let check_id = Uuid::new_v4().to_string();

        // Strict truthfulness requirement (Phase 8):
        // If VM is not running, we CANNOT truthfully verify guest egress
        if actual_vm_state != crate::hypervisor::VmState::Running && db_status != "RUNNING" {
            let record = NetworkCheckRecord {
                id: check_id.clone(),
                environment_id: environment_id.to_string(),
                observed_ipv4: None,
                observed_ipv6: None,
                dns_summary: Some("DNS: Unreachable (guest VM stopped)".to_string()),
                check_source: "GUEST_DIAGNOSTICS".to_string(),
                status: "NOT_CHECKED".to_string(),
                error_message: Some(format!(
                    "Cannot verify network egress for '{}': VM is stopped. Diagnostics require a running guest OS.",
                    env_name
                )),
                checked_at: now.clone(),
                latency_ms: None,
            };

            self.db.with_conn(|conn| {
                conn.execute(
                    "INSERT INTO network_checks (id, environment_id, observed_ipv4, observed_ipv6, dns_summary, check_source, status, checked_at, latency_ms, egress_stage)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    rusqlite::params![
                        check_id,
                        environment_id,
                        None::<String>,
                        None::<String>,
                        "DNS: Unreachable (guest VM stopped)",
                        "GUEST_DIAGNOSTICS",
                        "NOT_CHECKED",
                        now,
                        None::<u32>,
                        "VM_STOPPED"
                    ],
                )
            }).map_err(|e| e.to_string())?;

            return Ok(record);
        }
        // If VM is running:
        // Distinguish: ENDPOINT_CONFIGURED, ENDPOINT_REACHABLE, GUEST_EGRESS_OBSERVED, CONNECTION_FAILED, VERIFICATION_UNAVAILABLE
        if let Some(ref host) = ep_host {
            let port = ep_port.unwrap_or(1080);
            let target_addr = format!("{}:{}", host, port);

            let start = Instant::now();
            let reachability_result = target_addr
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .map(|sock_addr| TcpStream::connect_timeout(&sock_addr, Duration::from_millis(2000)));

            let latency = start.elapsed().as_millis() as u32;

            match reachability_result {
                Some(Ok(_)) => {
                    // Try real HTTP proxy egress probe with decrypted credentials from SecretStore
                    let is_http_proxy = ep_type.as_deref().unwrap_or("HTTP").eq_ignore_ascii_case("HTTP");
                    let egress_probe_result = if is_http_proxy {
                        Self::probe_http_proxy_egress(host, port, decrypted_secret.as_deref(), Duration::from_millis(4000))
                    } else {
                        Err("Egress probe currently supported for HTTP endpoints".to_string())
                    };

                    let (observed_ipv4, status, egress_stage, dns_info, error_message) = match egress_probe_result {
                        Ok((real_ip, real_latency)) => {
                            let note = format!("Proxy verified via {}:{} -> Observed Egress IP: {} ({}ms)", host, port, real_ip, real_latency);
                            (Some(real_ip), "VERIFIED".to_string(), "VERIFIED".to_string(), note, None)
                        }
                        Err(ref err) if err.contains("407") => {
                            (None, "CONNECTION_FAILED".to_string(), "AUTH_FAILED".to_string(), err.clone(), Some(err.clone()))
                        }
                        Err(ref err) => {
                            let note = format!("Endpoint {}:{} TCP handshake succeeded ({}ms). Direct probe: {}", host, port, latency, err);
                            (None, "ENDPOINT_REACHABLE".to_string(), "ENDPOINT_REACHABLE".to_string(), note, None)
                        }
                    };

                    let record = NetworkCheckRecord {
                        id: check_id.clone(),
                        environment_id: environment_id.to_string(),
                        observed_ipv4: observed_ipv4.clone(),
                        observed_ipv6: None,
                        dns_summary: Some(dns_info.clone()),
                        check_source: "PROXY_PROBE".to_string(),
                        status: status.clone(),
                        error_message: error_message.clone(),
                        checked_at: now.clone(),
                        latency_ms: Some(latency),
                    };

                    self.db.with_conn(|conn| {
                        conn.execute(
                            "INSERT INTO network_checks (id, environment_id, observed_ipv4, observed_ipv6, dns_summary, check_source, status, checked_at, latency_ms, egress_stage)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                            rusqlite::params![
                                check_id,
                                environment_id,
                                observed_ipv4,
                                None::<String>,
                                dns_info,
                                "PROXY_PROBE",
                                status,
                                now,
                                latency,
                                egress_stage
                            ],
                        )?;

                        conn.execute(
                            "UPDATE environments SET updated_at = ?1 WHERE id = ?2",
                            rusqlite::params![now, environment_id],
                        )?;

                        Ok(())
                    }).map_err(|e| e.to_string())?;

                    self.audit_service.log(
                        Some(environment_id),
                        "NETWORK_REACHABILITY_CHECK",
                        "INFO",
                        &format!("Endpoint '{:?}' ({}:{}) verified status: {}", ep_name, host, port, status),
                    ).ok();

                    Ok(record)
                }
                _ => {
                    let err_msg = format!("TCP connection to configured endpoint {}:{} failed (timeout / unreachable)", host, port);
                    let record = NetworkCheckRecord {
                        id: check_id.clone(),
                        environment_id: environment_id.to_string(),
                        observed_ipv4: None,
                        observed_ipv6: None,
                        dns_summary: Some("Connection to proxy host failed".to_string()),
                        check_source: "HOST_PROBE".to_string(),
                        status: "CONNECTION_FAILED".to_string(),
                        error_message: Some(err_msg.clone()),
                        checked_at: now.clone(),
                        latency_ms: None,
                    };

                    self.db.with_conn(|conn| {
                        conn.execute(
                            "INSERT INTO network_checks (id, environment_id, observed_ipv4, observed_ipv6, dns_summary, check_source, status, checked_at, latency_ms, egress_stage)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                            rusqlite::params![
                                check_id,
                                environment_id,
                                None::<String>,
                                None::<String>,
                                "Connection failed",
                                "HOST_PROBE",
                                "CONNECTION_FAILED",
                                now,
                                None::<u32>,
                                "FAILED"
                            ],
                        )?;

                        conn.execute(
                            "UPDATE environments SET updated_at = ?1 WHERE id = ?2",
                            rusqlite::params![now, environment_id],
                        )?;

                        Ok(())
                    }).map_err(|e| e.to_string())?;

                    Ok(record)
                }
            }
        } else {
            // Direct / NAT network without a configured proxy endpoint
            let direct_probe = Self::probe_direct_egress(Duration::from_millis(3000));
            let (observed_ipv4, status, note, latency) = match direct_probe {
                Ok((ip, lat)) => (Some(ip.clone()), "VERIFIED".to_string(), format!("Direct host NAT egress verified: {} ({}ms)", ip, lat), Some(lat)),
                Err(_) => {
                    let fallback_ip = detect_host_public_ip();
                    if fallback_ip != "127.0.0.1" {
                        (Some(fallback_ip.clone()), "VERIFIED".to_string(), format!("Direct host NAT egress verified: {}", fallback_ip), None)
                    } else {
                        (None, "ENDPOINT_CONFIGURED".to_string(), "Direct host NAT virtual network adapter attached".to_string(), None)
                    }
                }
            };

            let record = NetworkCheckRecord {
                id: check_id.clone(),
                environment_id: environment_id.to_string(),
                observed_ipv4: observed_ipv4.clone(),
                observed_ipv6: None,
                dns_summary: Some(note.clone()),
                check_source: "DIRECT_PROBE".to_string(),
                status: status.clone(),
                error_message: None,
                checked_at: now.clone(),
                latency_ms: latency,
            };

            self.db.with_conn(|conn| {
                conn.execute(
                    "INSERT INTO network_checks (id, environment_id, observed_ipv4, observed_ipv6, dns_summary, check_source, status, checked_at, latency_ms, egress_stage)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    rusqlite::params![
                        check_id,
                        environment_id,
                        observed_ipv4,
                        None::<String>,
                        note,
                        "DIRECT_PROBE",
                        status,
                        now,
                        latency,
                        "DIRECT"
                    ],
                )?;

                conn.execute(
                    "UPDATE environments SET updated_at = ?1 WHERE id = ?2",
                    rusqlite::params![now, environment_id],
                )?;

                Ok(())
            }).map_err(|e| e.to_string())?;

            Ok(record)
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

        self.db.with_conn(|conn| {
            conn.execute(
                "INSERT INTO network_checks (id, environment_id, observed_ipv4, observed_ipv6, dns_summary, check_source, status, checked_at, latency_ms, egress_stage)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    check_id,
                    environment_id,
                    observed_ipv4,
                    observed_ipv6,
                    dns_summary,
                    "GUEST_AGENT",
                    "GUEST_EGRESS_OBSERVED",
                    now,
                    latency_ms,
                    "VERIFIED"
                ],
            )
        }).map_err(|e| e.to_string())?;

        self.audit_service.log(
            Some(environment_id),
            "GUEST_EGRESS_VERIFIED",
            "INFO",
            &format!("Observed in-guest egress IP: {} (latency: {}ms)", observed_ipv4, latency_ms),
        ).ok();

        Ok(NetworkCheckRecord {
            id: check_id,
            environment_id: environment_id.to_string(),
            observed_ipv4: Some(observed_ipv4.to_string()),
            observed_ipv6: observed_ipv6.map(|s| s.to_string()),
            dns_summary: Some(dns_summary.to_string()),
            check_source: "GUEST_AGENT".to_string(),
            status: "GUEST_EGRESS_OBSERVED".to_string(),
            error_message: None,
            checked_at: now,
            latency_ms: Some(latency_ms),
        })
    }

    pub fn detect_duplicate_egress(&self) -> Result<Vec<DuplicateEgressWarning>, String> {
        self.db.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT nc.observed_ipv4, GROUP_CONCAT(e.name, ', ') as env_names, COUNT(DISTINCT e.id) as env_count
                 FROM network_checks nc
                 JOIN environments e ON e.id = nc.environment_id
                 WHERE nc.observed_ipv4 IS NOT NULL
                   AND nc.id IN (SELECT id FROM network_checks GROUP BY environment_id HAVING MAX(checked_at))
                 GROUP BY nc.observed_ipv4
                 HAVING env_count > 1"
            )?;

            let rows = stmt.query_map([], |row| {
                let ip: String = row.get(0)?;
                let names_str: String = row.get(1)?;
                let names: Vec<String> = names_str.split(',').map(|s| s.trim().to_string()).collect();

                Ok(DuplicateEgressWarning {
                    ip_address: ip.clone(),
                    conflicting_environments: names.clone(),
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
        }).map_err(|e| e.to_string())
    }

    pub fn get_network_history(&self, environment_id: &str, limit: usize) -> Result<Vec<NetworkCheckRecord>, String> {
        self.db.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, environment_id, observed_ipv4, observed_ipv6, dns_summary, check_source, status, checked_at, latency_ms
                 FROM network_checks WHERE environment_id = ?1 ORDER BY checked_at DESC LIMIT ?2"
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
                    error_message: None,
                    checked_at: row.get(7)?,
                    latency_ms: row.get(8)?,
                })
            })?;

            let mut checks = Vec::new();
            for r in rows {
                checks.push(r?);
            }
            Ok(checks)
        }).map_err(|e| e.to_string())
    }
}
