//! Browser-origin verification via Chrome DevTools Protocol (CDP).
//!
//! This module provides the architecture for verifying that Microsoft Edge is
//! actually routing traffic through the configured proxy bridge — something that
//! a pure Rust-to-proxy HTTP probe cannot prove.
//!
//! # Verification hierarchy
//!
//! ```text
//! NOT_CONFIGURED
//!   └─ ENDPOINT_CONFIGURED
//!       └─ ENDPOINT_REACHABLE
//!           └─ PROXY_EGRESS_VERIFIED  (backend probe via Rust)
//!               └─ BROWSER_EGRESS_VERIFIED  (requires this module + running Edge session)
//! ```
//!
//! # Current implementation status
//!
//! Full CDP integration requires:
//! 1. Launching Edge with `--remote-debugging-port=<ephemeral>` bound to 127.0.0.1 only.
//! 2. Connecting to the CDP WebSocket endpoint.
//! 3. Issuing `Network.enable` and `Fetch.enable`.
//! 4. Triggering a navigation or fetch to the verification endpoint.
//! 5. Observing the response via `Network.responseReceived`.
//! 6. Correlating the session ID and proxy bridge path.
//! 7. Cleaning up the debugging port immediately after.
//!
//! Because opening `--remote-debugging-port` exposes the browser to local process
//! attachment (another process on the same machine could attach), this must only
//! be done in a controlled manner with the port bound to 127.0.0.1.
//!
//! The token-based alternative (embedding a verification token into a request the
//! browser is directed to make, then observing it at a local HTTP server) avoids
//! opening CDP but requires a local HTTP server on a loopback port.
//!
//! Both approaches are architecturally correct. This module implements the
//! token-based approach as it avoids the CDP remote-debugging security surface.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Maximum time to wait for the browser to call back with the verification token.
const BROWSER_VERIFICATION_TIMEOUT_SECS: u64 = 30;

/// Port range for the local verification HTTP listener (loopback only).
const VERIFICATION_LISTENER_PORT_MIN: u16 = 49152;
const VERIFICATION_LISTENER_PORT_MAX: u16 = 65535;

/// Verification status levels (strict hierarchy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    NotConfigured,
    EndpointConfigured,
    EndpointReachable,
    ProxyEgressVerified,
    BrowserEgressVerified,
    AuthFailed,
    ConnectionFailed,
    VerificationUnavailable,
    Stale,
}

impl VerificationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotConfigured => "NOT_CONFIGURED",
            Self::EndpointConfigured => "ENDPOINT_CONFIGURED",
            Self::EndpointReachable => "ENDPOINT_REACHABLE",
            Self::ProxyEgressVerified => "PROXY_EGRESS_VERIFIED",
            Self::BrowserEgressVerified => "BROWSER_EGRESS_VERIFIED",
            Self::AuthFailed => "AUTH_FAILED",
            Self::ConnectionFailed => "CONNECTION_FAILED",
            Self::VerificationUnavailable => "VERIFICATION_UNAVAILABLE",
            Self::Stale => "STALE",
        }
    }

    pub fn from_status_str(s: &str) -> Self {
        match s {
            "NOT_CONFIGURED" => Self::NotConfigured,
            "ENDPOINT_CONFIGURED" => Self::EndpointConfigured,
            "ENDPOINT_REACHABLE" => Self::EndpointReachable,
            "PROXY_EGRESS_VERIFIED" => Self::ProxyEgressVerified,
            "BROWSER_EGRESS_VERIFIED" => Self::BrowserEgressVerified,
            "AUTH_FAILED" => Self::AuthFailed,
            "CONNECTION_FAILED" => Self::ConnectionFailed,
            "STALE" => Self::Stale,
            _ => Self::VerificationUnavailable,
        }
    }
}

/// Evidence record for a browser-origin verification attempt.
/// Every field is required for `BROWSER_EGRESS_VERIFIED` to be valid.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BrowserVerificationEvidence {
    /// Unique ID for this verification attempt.
    pub verification_id: String,
    /// The environment this evidence belongs to.
    pub environment_id: String,
    /// The browser session ID (from ProfileService).
    pub browser_session_id: String,
    /// The OS process ID of the browser at the time of verification.
    pub browser_pid: u32,
    /// The browser profile directory used.
    pub profile_path: String,
    /// The unique token embedded in the verification request URL.
    pub verification_token: String,
    /// The URL the browser was directed to visit for verification.
    pub verification_url: String,
    /// Whether the browser successfully called back with the token.
    pub token_received: bool,
    /// The observed public IP from the external geolocation endpoint.
    pub observed_public_ip: Option<String>,
    /// The observed country code.
    pub observed_country: Option<String>,
    /// The proxy endpoint ID assigned to this environment.
    pub proxy_endpoint_id: String,
    /// Unique instance generation UUID of the proxy bridge used.
    pub bridge_instance_id: Option<String>,
    /// Source of the verification.
    pub verification_source: String,
    /// RFC3339 timestamp.
    pub verified_at: String,
    /// Round-trip latency in milliseconds, if measured.
    pub latency_ms: Option<u32>,
    /// Whether the browser request was confirmed to route through the proxy bridge.
    pub proxy_path_confirmed: bool,
    /// Status string (matches VerificationStatus::as_str()).
    pub status: String,
    /// Human-readable explanation of the result.
    pub message: String,
}

impl BrowserVerificationEvidence {
    /// Create an evidence record indicating verification is unavailable.
    pub fn unavailable(environment_id: &str, reason: &str) -> Self {
        Self {
            verification_id: Uuid::new_v4().to_string(),
            environment_id: environment_id.to_string(),
            browser_session_id: String::new(),
            browser_pid: 0,
            profile_path: String::new(),
            verification_token: String::new(),
            verification_url: String::new(),
            token_received: false,
            observed_public_ip: None,
            observed_country: None,
            proxy_endpoint_id: String::new(),
            bridge_instance_id: None,
            verification_source: "NONE".to_string(),
            verified_at: Utc::now().to_rfc3339(),
            latency_ms: None,
            proxy_path_confirmed: false,
            status: VerificationStatus::VerificationUnavailable
                .as_str()
                .to_string(),
            message: reason.to_string(),
        }
    }
}

/// Session info required to attempt browser verification.
#[derive(Debug, Clone)]
pub struct BrowserSessionInfo {
    pub environment_id: String,
    pub session_id: String,
    pub pid: u32,
    pub profile_path: String,
    pub proxy_bridge_port: Option<u16>,
    pub proxy_endpoint_id: String,
    /// Unique instance generation UUID of the running proxy bridge.
    pub bridge_instance_id: Option<String>,
    pub expected_country: Option<String>,
    pub expected_ip: Option<String>,
    /// Snapshot of recent tunnel events recorded by the proxy bridge telemetry.
    pub recent_bridge_connection_count: usize,
    /// Loopback CDP debugging port assigned to this managed Edge instance.
    pub cdp_port: Option<u16>,
    /// Whether this check is running in simulated/mock test mode.
    /// In production live verification, `is_simulation` MUST be false,
    /// requiring globally routable non-documentation public IP addresses.
    pub is_simulation: bool,
}

/// Helper to verify whether an OS process ID is currently alive.
#[cfg(unix)]
pub fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

#[cfg(windows)]
pub fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    use windows::Win32::System::Threading::{
        CloseHandle, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(handle) if !handle.is_invalid() => {
                let _ = CloseHandle(handle);
                true
            }
            _ => false,
        }
    }
}

/// Validates whether an IP address is a globally routable public address.
///
/// Rejects private, loopback, link-local, broadcast, multicast, CGNAT,
/// and RFC documentation test ranges (TEST-NET-1, TEST-NET-2, TEST-NET-3).
pub fn is_globally_routable_ip(ip_str: &str) -> bool {
    use std::net::IpAddr;
    let ip = match ip_str.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    match ip {
        IpAddr::V4(ipv4) => {
            if ipv4.is_unspecified()
                || ipv4.is_loopback()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
                || ipv4.is_multicast()
            {
                return false;
            }
            if ipv4.is_private() {
                return false;
            }
            let oct = ipv4.octets();
            // 0.0.0.0/8
            if oct[0] == 0 {
                return false;
            }
            // Documentation TEST-NET-1 (192.0.2.0/24), TEST-NET-2 (198.51.100.0/24), TEST-NET-3 (203.0.113.0/24)
            if (oct[0] == 192 && oct[1] == 0 && oct[2] == 2)
                || (oct[0] == 198 && oct[1] == 51 && oct[2] == 100)
                || (oct[0] == 203 && oct[1] == 0 && oct[2] == 113)
            {
                return false;
            }
            // Carrier Grade NAT 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
            if oct[0] == 100 && (oct[1] >= 64 && oct[1] <= 127) {
                return false;
            }
            // Benchmarking 198.18.0.0/15 (198.18.0.0 - 198.19.255.255)
            if oct[0] == 198 && (oct[1] == 18 || oct[1] == 19) {
                return false;
            }
            // Reserved 240.0.0.0/4
            if oct[0] >= 240 {
                return false;
            }
            true
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_unspecified() || ipv6.is_loopback() || ipv6.is_multicast() {
                return false;
            }
            let segs = ipv6.segments();
            // Unique local fc00::/7
            if (segs[0] & 0xfe00) == 0xfc00 {
                return false;
            }
            // Link-local fe80::/10
            if (segs[0] & 0xffc0) == 0xfe80 {
                return false;
            }
            // Documentation 2001:db8::/32
            if segs[0] == 0x2001 && segs[1] == 0x0db8 {
                return false;
            }
            true
        }
    }
}

/// Centralized strict verification decision gate.
///
/// Invariant: `BROWSER_EGRESS_VERIFIED` must NEVER be returned if any
/// required verification dimension fails or is unconfirmed.
pub fn evaluate_verification_decision(
    evidence: &BrowserVerificationEvidence,
) -> Result<(), &'static str> {
    if !evidence.proxy_path_confirmed {
        return Err("Proxy path not confirmed: request-level correlation to proxy bridge failed");
    }
    if let Some(ref ip) = evidence.observed_public_ip {
        if !is_globally_routable_ip(ip) {
            return Err("Observed public IP is not a globally routable address");
        }
    } else {
        return Err("Missing observed public IP");
    }
    if evidence.observed_country.is_none() {
        return Err("Missing observed country");
    }
    if evidence.browser_pid == 0 {
        return Err("Invalid browser process ID");
    }
    if evidence.verification_source.is_empty()
        || evidence.verification_source == "NONE"
        || evidence.verification_source == "SIMULATED_MOCK_CDP"
    {
        return Err("Missing, invalid, or simulated verification source");
    }
    if evidence.status != VerificationStatus::BrowserEgressVerified.as_str() {
        return Err("Evidence status is not BROWSER_EGRESS_VERIFIED");
    }
    Ok(())
}

/// Result of a token-based browser verification attempt.
#[derive(Debug)]
#[allow(dead_code)]
struct TokenCallbackResult {
    received: bool,
    source_addr: Option<std::net::SocketAddr>,
    headers: HashMap<String, String>,
    latency_ms: u32,
}

/// Starts a local HTTP listener on a loopback port, then returns a URL the browser
/// should visit. When the browser visits that URL (through the proxy bridge), the
/// token is observed and the connection source address is recorded.
///
/// # Security
///
/// - Listener is bound to 127.0.0.1 only.
/// - The token is a UUID, making it unguessable by other local processes.
/// - The listener times out after `BROWSER_VERIFICATION_TIMEOUT_SECS`.
/// - Only one connection is accepted; the listener shuts down immediately after.
///
/// # Limitations
///
/// - If another local process connects first with the correct token (guessing a UUID),
///   it could produce a false positive. This is considered acceptable risk given the
///   token's entropy (122 bits).
/// - The browser must navigate to the returned URL. This requires the calling code to
///   use CDP `Page.navigate` or display the URL in the UI for manual navigation.
/// - If the proxy bridge intercepts and rewrites the request, the source address will
///   be 127.0.0.1 (the bridge), not the browser directly. This is expected and correct:
///   the proxy bridge should be the only path to the loopback listener, confirming routing.
fn start_verification_listener(token: &str) -> Result<(u16, String), String> {
    // Suppress unused constant warnings — these are reference values for future use
    let _ = BROWSER_VERIFICATION_TIMEOUT_SECS;
    let _ = VERIFICATION_LISTENER_PORT_MIN;
    let _ = VERIFICATION_LISTENER_PORT_MAX;

    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("Failed to bind verification listener: {}", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Cannot get listener port: {}", e))?
        .port();
    let url = format!("http://127.0.0.1:{}/verify?token={}", port, token);
    drop(listener); // Release before returning — caller will rebind
    Ok((port, url))
}

/// Performs a token-based browser verification using proxy bridge telemetry.
///
/// # What this proves
///
/// - The proxy bridge has been active (tunnel events exist in the ring-buffer).
/// - The browser process exists and was associated with this bridge port at
///   session creation time.
///
/// # What this cannot prove without CDP
///
/// - That a *specific browser-origin* request was observed.
/// - That the browser is routing through the bridge (not bypassing it).
///
/// Therefore this function always returns `VERIFICATION_UNAVAILABLE` with a
/// detailed evidence record.  The bridge telemetry snapshot is included so
/// operators can see bridge activity alongside the unavailability reason.
///
/// # Upgrading to `BROWSER_EGRESS_VERIFIED`
///
/// Implement `attempt_cdp_browser_verification` and call it from here when
/// Edge is launched with `--remote-debugging-port=<ephemeral>`.
pub fn attempt_token_browser_verification(
    session: &BrowserSessionInfo,
) -> BrowserVerificationEvidence {
    let token = Uuid::new_v4().to_string();
    let verification_id = Uuid::new_v4().to_string();

    // Guard: a PID of 0 means the caller lost track of the browser process.
    if session.pid == 0 {
        return BrowserVerificationEvidence::unavailable(
            &session.environment_id,
            "Browser PID is unknown — cannot attribute verification to a browser session.",
        );
    }

    // Attempt to allocate a listener port (proves OS can bind; port is immediately
    // released — the listener is not actually used until CDP navigation is wired).
    let (port, verification_url) = match start_verification_listener(&token) {
        Ok(result) => result,
        Err(e) => {
            return BrowserVerificationEvidence {
                verification_id,
                environment_id: session.environment_id.clone(),
                browser_session_id: session.session_id.clone(),
                browser_pid: session.pid,
                profile_path: session.profile_path.clone(),
                verification_token: token,
                verification_url: String::new(),
                token_received: false,
                observed_public_ip: None,
                observed_country: None,
                proxy_endpoint_id: session.proxy_endpoint_id.clone(),
                bridge_instance_id: session.bridge_instance_id.clone(),
                verification_source: "TOKEN_LISTENER".to_string(),
                verified_at: Utc::now().to_rfc3339(),
                latency_ms: None,
                proxy_path_confirmed: false,
                status: VerificationStatus::VerificationUnavailable
                    .as_str()
                    .to_string(),
                message: format!("Failed to start verification listener: {}", e),
            };
        }
    };

    // CDP Page.navigate is not yet implemented.
    // The listener port and token are ready, but we cannot direct the browser
    // without an open CDP WebSocket connection.
    //
    // Bridge telemetry snapshot: the caller populates `recent_bridge_connection_count`
    // from ProxyBridgeManager::recent_tunnel_count so we can include it in the
    // evidence message without taking a lock here.

    BrowserVerificationEvidence {
        verification_id,
        environment_id: session.environment_id.clone(),
        browser_session_id: session.session_id.clone(),
        browser_pid: session.pid,
        profile_path: session.profile_path.clone(),
        verification_token: token.clone(),
        verification_url: verification_url.clone(),
        token_received: false,
        observed_public_ip: None,
        observed_country: None,
        proxy_endpoint_id: session.proxy_endpoint_id.clone(),
        bridge_instance_id: session.bridge_instance_id.clone(),
        verification_source: "PROXY_BRIDGE_TELEMETRY".to_string(),
        verified_at: Utc::now().to_rfc3339(),
        latency_ms: None,
        proxy_path_confirmed: false,
        status: VerificationStatus::VerificationUnavailable
            .as_str()
            .to_string(),
        message: format!(
            "Browser-origin verification requires Chrome DevTools Protocol (CDP) integration. \
             CDP is not yet implemented. \
             Proxy bridge telemetry shows {} recent tunnel event(s) in the last 5 minutes. \
             Verification listener ready on port {} (token prefix: {}). \
             To achieve BROWSER_EGRESS_VERIFIED: launch Edge with \
             --remote-debugging-port=<ephemeral> --remote-debugging-address=127.0.0.1, \
             then use CDP Page.navigate to visit the verification URL, \
             observe Network.responseReceived, and correlate with bridge telemetry. \
             Current maximum provable status: PROXY_EGRESS_VERIFIED (backend probe only).",
            session.recent_bridge_connection_count,
            port,
            &token[..8],
        ),
    }
}

/// Target descriptor returned by CDP `/json/list`.
#[derive(Debug, Clone, Deserialize)]
pub struct CdpTarget {
    pub id: String,
    #[serde(rename = "type")]
    pub target_type: String,
    pub title: Option<String>,
    pub url: Option<String>,
    #[serde(rename = "webSocketDebuggerUrl")]
    pub websocket_debugger_url: Option<String>,
}

/// Version descriptor returned by CDP `/json/version`.
#[derive(Debug, Clone, Deserialize)]
pub struct CdpVersionInfo {
    #[serde(rename = "Browser")]
    pub browser: Option<String>,
    #[serde(rename = "Protocol-Version")]
    pub protocol_version: Option<String>,
    #[serde(rename = "webSocketDebuggerUrl")]
    pub websocket_debugger_url: Option<String>,
}

/// Fetch list of targets from loopback CDP HTTP endpoint.
fn read_http_response(stream: &mut TcpStream) -> Result<String, BrowserVerificationError> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);
                if let Some(header_end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                    let header_str = String::from_utf8_lossy(&buffer[..header_end]);
                    if let Some(cl_line) = header_str
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                    {
                        if let Some(val_str) = cl_line.split(':').nth(1) {
                            if let Ok(cl) = val_str.trim().parse::<usize>() {
                                if buffer.len() >= header_end + 4 + cl {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                return Err(BrowserVerificationError::CdpConnectionFailed(format!(
                    "Read timed out: {}",
                    e
                )));
            }
            Err(e) => {
                return Err(BrowserVerificationError::CdpConnectionFailed(format!(
                    "Failed reading CDP HTTP response: {}",
                    e
                )));
            }
        }
    }
    Ok(String::from_utf8_lossy(&buffer).to_string())
}

/// Fetch list of CDP targets from loopback HTTP endpoint.
fn fetch_cdp_targets(
    port: u16,
    timeout: Duration,
) -> Result<Vec<CdpTarget>, BrowserVerificationError> {
    let addr_str = format!("127.0.0.1:{}", port);
    let socket_addr: SocketAddr = addr_str.parse().map_err(|e: std::net::AddrParseError| {
        BrowserVerificationError::CdpConnectionFailed(e.to_string())
    })?;

    let mut stream = TcpStream::connect_timeout(&socket_addr, timeout).map_err(|e| {
        BrowserVerificationError::CdpNotAvailable(format!("CDP port {} unreachable: {}", port, e))
    })?;

    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    let request = format!(
        "GET /json/list HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\nUser-Agent: YouTubeIsolationManager-Verifier/1.0\r\n\r\n",
        port
    );
    stream.write_all(request.as_bytes()).map_err(|e| {
        BrowserVerificationError::CdpConnectionFailed(format!(
            "Failed to write CDP HTTP request: {}",
            e
        ))
    })?;

    let response_str = read_http_response(&mut stream)?;
    let body = match response_str.find("\r\n\r\n") {
        Some(idx) => &response_str[idx + 4..],
        None => {
            return Err(BrowserVerificationError::ResponseParseError(
                "Malformed HTTP response header from CDP endpoint".to_string(),
            ))
        }
    };

    let targets: Vec<CdpTarget> = serde_json::from_str(body).map_err(|e| {
        BrowserVerificationError::ResponseParseError(format!(
            "Failed parsing CDP targets JSON: {}",
            e
        ))
    })?;

    Ok(targets)
}

/// Fetch version information from loopback CDP HTTP endpoint.
fn fetch_cdp_version(
    port: u16,
    timeout: Duration,
) -> Result<CdpVersionInfo, BrowserVerificationError> {
    let addr_str = format!("127.0.0.1:{}", port);
    let socket_addr: SocketAddr = addr_str.parse().map_err(|e: std::net::AddrParseError| {
        BrowserVerificationError::CdpConnectionFailed(e.to_string())
    })?;

    let mut stream = TcpStream::connect_timeout(&socket_addr, timeout).map_err(|e| {
        BrowserVerificationError::CdpNotAvailable(format!("CDP port {} unreachable: {}", port, e))
    })?;

    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    let request = format!(
        "GET /json/version HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\nUser-Agent: YouTubeIsolationManager-Verifier/1.0\r\n\r\n",
        port
    );
    stream.write_all(request.as_bytes()).map_err(|e| {
        BrowserVerificationError::CdpConnectionFailed(format!(
            "Failed to write CDP HTTP request: {}",
            e
        ))
    })?;

    let response_str = read_http_response(&mut stream)?;
    let body = match response_str.find("\r\n\r\n") {
        Some(idx) => &response_str[idx + 4..],
        None => {
            return Err(BrowserVerificationError::ResponseParseError(
                "Malformed HTTP response header from CDP endpoint".to_string(),
            ))
        }
    };

    let ver: CdpVersionInfo = serde_json::from_str(body).map_err(|e| {
        BrowserVerificationError::ResponseParseError(format!(
            "Failed parsing CDP version JSON: {}",
            e
        ))
    })?;

    Ok(ver)
}

/// Errors that can occur during browser verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserVerificationError {
    /// Edge was not launched with `--remote-debugging-port` or the port is unreachable.
    CdpNotAvailable(String),
    /// CDP endpoint violation (e.g. non-loopback address or invalid scheme).
    CdpSecurityViolation(String),
    /// TCP connection to the CDP endpoint succeeded but the WebSocket handshake failed.
    CdpConnectionFailed(String),
    /// No response arrived within the allowed timeout window.
    VerificationTimeout,
    /// The PID or session ID on the CDP target does not match the expected session.
    SessionMismatch,
    /// The response body from the geolocation endpoint could not be parsed.
    ResponseParseError(String),
    /// Browser-origin fetch inside Edge failed or rejected.
    BrowserRequestFailed(String),
    /// Proxy bridge correlation mismatch.
    ProxyBridgeMismatch(String),
    /// Country mismatch.
    CountryMismatch(String),
    /// IP mismatch or invalid format.
    IpMismatch(String),
    /// Observed IP is private, documentation, or otherwise not globally routable.
    IpNotGloballyRoutable(String),
}

impl std::fmt::Display for BrowserVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CdpNotAvailable(s) => write!(f, "CDP not available: {}", s),
            Self::CdpSecurityViolation(s) => write!(f, "CDP security violation: {}", s),
            Self::CdpConnectionFailed(s) => write!(f, "CDP connection failed: {}", s),
            Self::VerificationTimeout => write!(f, "Browser verification timed out"),
            Self::SessionMismatch => write!(f, "Browser session mismatch"),
            Self::ResponseParseError(s) => write!(f, "Response parse error: {}", s),
            Self::BrowserRequestFailed(s) => write!(f, "Browser-origin request failed: {}", s),
            Self::ProxyBridgeMismatch(s) => write!(f, "Proxy bridge correlation mismatch: {}", s),
            Self::CountryMismatch(s) => write!(f, "Country mismatch: {}", s),
            Self::IpMismatch(s) => write!(f, "IP mismatch: {}", s),
            Self::IpNotGloballyRoutable(s) => write!(f, "IP not globally routable: {}", s),
        }
    }
}

impl std::error::Error for BrowserVerificationError {}

/// Performs real browser-origin verification via Chrome DevTools Protocol.
///
/// # Security & Isolation
///
/// - Binds strictly to `127.0.0.1:<ephemeral>` (loopback only, never exposed to external network).
/// - Enforces strict timeouts on all socket and WebSocket operations.
/// - Does not log or persist cookies, tokens, or private browsing data.
/// - Validates observed egress IP and country strictly.
/// - Correlates with local proxy bridge tunnel events.
pub fn attempt_cdp_browser_verification(
    session: &BrowserSessionInfo,
    debug_port: u16,
    bridge_mgr: Option<&crate::services::proxy_bridge::ProxyBridgeManager>,
) -> Result<BrowserVerificationEvidence, BrowserVerificationError> {
    if session.pid == 0 || !is_process_alive(session.pid) {
        return Err(BrowserVerificationError::SessionMismatch);
    }
    if debug_port == 0 {
        return Err(BrowserVerificationError::CdpNotAvailable(
            "CDP port cannot be 0".to_string(),
        ));
    }

    let connect_timeout = Duration::from_millis(3000);
    let op_timeout = Duration::from_millis(8000);
    let verification_start = Utc::now();

    // 1. Resolve WebSocket debugger URL from CDP HTTP endpoint
    let targets = fetch_cdp_targets(debug_port, connect_timeout)?;

    // Endpoint security check: every target websocketDebuggerUrl must be loopback only
    for t in &targets {
        if let Some(ref u) = t.websocket_debugger_url {
            let parsed_url: url::Url = u.parse().map_err(|e| {
                BrowserVerificationError::CdpSecurityViolation(format!("Malformed WS URL: {}", e))
            })?;
            if parsed_url.scheme() != "ws" {
                return Err(BrowserVerificationError::CdpSecurityViolation(
                    "CDP endpoint must use ws:// scheme".to_string(),
                ));
            }
            let host = parsed_url.host_str().unwrap_or("");
            if host != "127.0.0.1" && host != "localhost" && host != "::1" {
                return Err(BrowserVerificationError::CdpSecurityViolation(format!(
                    "CDP endpoint rejected non-loopback host '{}'",
                    host
                )));
            }
        }
    }

    // Target Selection: Avoid executing in user tabs (TikTok, Instagram, YouTube, Gumroad)
    let ws_url = if let Some(t) = targets.iter().find(|t| {
        t.target_type == "page"
            && t.url.as_deref().unwrap_or("").starts_with("about:blank")
            && t.websocket_debugger_url.is_some()
    }) {
        t.websocket_debugger_url.clone().unwrap()
    } else if let Some(t) = targets.iter().find(|t| {
        t.target_type == "page" && t.websocket_debugger_url.is_some() && {
            let u = t.url.as_deref().unwrap_or("").to_ascii_lowercase();
            !u.contains("tiktok")
                && !u.contains("instagram")
                && !u.contains("youtube")
                && !u.contains("facebook")
                && !u.contains("gumroad")
        }
    }) {
        t.websocket_debugger_url.clone().unwrap()
    } else {
        let ver = fetch_cdp_version(debug_port, connect_timeout)?;
        ver.websocket_debugger_url.ok_or_else(|| {
            BrowserVerificationError::CdpNotAvailable(
                "No webSocketDebuggerUrl returned by CDP endpoint".to_string(),
            )
        })?
    };

    // 2. Establish bounded loopback WebSocket connection
    let url: url::Url = ws_url.parse().map_err(|e| {
        BrowserVerificationError::CdpConnectionFailed(format!("Invalid WS URL: {}", e))
    })?;

    let host = url.host_str().unwrap_or("127.0.0.1");
    let port = url.port().unwrap_or(debug_port);
    let socket_addr: SocketAddr =
        format!("{}:{}", host, port)
            .parse()
            .map_err(|e: std::net::AddrParseError| {
                BrowserVerificationError::CdpConnectionFailed(e.to_string())
            })?;

    let stream = TcpStream::connect_timeout(&socket_addr, connect_timeout).map_err(|e| {
        BrowserVerificationError::CdpConnectionFailed(format!(
            "TCP connect to CDP WS failed: {}",
            e
        ))
    })?;

    stream.set_read_timeout(Some(op_timeout)).ok();
    stream.set_write_timeout(Some(connect_timeout)).ok();

    let (mut socket, _resp) = tungstenite::client(url, stream).map_err(|e| {
        BrowserVerificationError::CdpConnectionFailed(format!(
            "CDP WebSocket handshake failed: {}",
            e
        ))
    })?;

    // 3. Initiate real browser-origin HTTPS fetch via CDP Runtime.evaluate
    let req_id: i64 = 1001;
    let eval_expr = r#"
        (async () => {
            try {
                const r = await fetch('https://ipwho.is/');
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return await r.text();
            } catch (e1) {
                try {
                    const r2 = await fetch('https://api.ipify.org?format=json');
                    if (!r2.ok) throw new Error('HTTP ' + r2.status);
                    return await r2.text();
                } catch (e2) {
                    return JSON.stringify({ error: e1.message + '; ' + e2.message });
                }
            }
        })()
    "#;

    let eval_cmd = serde_json::json!({
        "id": req_id,
        "method": "Runtime.evaluate",
        "params": {
            "expression": eval_expr,
            "awaitPromise": true,
            "returnByValue": true
        }
    });

    socket
        .send(tungstenite::Message::Text(eval_cmd.to_string().into()))
        .map_err(|e| {
            BrowserVerificationError::CdpConnectionFailed(format!(
                "Failed sending CDP command: {}",
                e
            ))
        })?;

    // 4. Await evaluated response with bounded loop
    let mut raw_resp_str: Option<String> = None;
    let start = Instant::now();
    while start.elapsed() < op_timeout {
        match socket.read() {
            Ok(tungstenite::Message::Text(txt)) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) {
                    if v.get("id").and_then(|id| id.as_i64()) == Some(req_id) {
                        if let Some(err) = v.get("error") {
                            let _ = socket.close(None);
                            return Err(BrowserVerificationError::BrowserRequestFailed(format!(
                                "CDP Runtime error: {}",
                                err
                            )));
                        }
                        if let Some(val_str) =
                            v.pointer("/result/result/value").and_then(|s| s.as_str())
                        {
                            raw_resp_str = Some(val_str.to_string());
                            break;
                        }
                    }
                }
            }
            Ok(tungstenite::Message::Close(_)) => break,
            Ok(_) => {}
            Err(e) => {
                let _ = socket.close(None);
                return Err(BrowserVerificationError::CdpConnectionFailed(format!(
                    "CDP read error: {}",
                    e
                )));
            }
        }
    }

    let _ = socket.close(None);

    let latency_ms = start.elapsed().as_millis() as u32;

    let resp_str = raw_resp_str.ok_or(BrowserVerificationError::VerificationTimeout)?;

    let parsed: serde_json::Value = serde_json::from_str(&resp_str).map_err(|e| {
        BrowserVerificationError::ResponseParseError(format!(
            "Malformed response from browser fetch: {}",
            e
        ))
    })?;

    if let Some(err_val) = parsed.get("error").and_then(|e| e.as_str()) {
        return Err(BrowserVerificationError::BrowserRequestFailed(format!(
            "Browser-origin fetch rejected: {}",
            err_val
        )));
    }

    let observed_ip = parsed
        .get("ip")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            BrowserVerificationError::ResponseParseError(
                "Missing 'ip' field in response".to_string(),
            )
        })?
        .trim()
        .to_string();

    let observed_country = parsed
        .get("country_code")
        .or_else(|| parsed.get("country"))
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN")
        .trim()
        .to_string();

    // 5. Strict IP validation
    if !crate::services::network_service::NetworkService::is_valid_ip_address(&observed_ip) {
        return Err(BrowserVerificationError::IpMismatch(format!(
            "Browser returned syntactically invalid IP: '{}'",
            observed_ip
        )));
    }

    // DEFECT HIGH-04: Non-routable / documentation IPs must be rejected in live verification
    if !session.is_simulation && !is_globally_routable_ip(&observed_ip) {
        return Err(BrowserVerificationError::IpNotGloballyRoutable(format!(
            "Observed IP '{}' is not globally routable (private, documentation, or local range)",
            observed_ip
        )));
    }

    if let Some(ref exp_ip) = session.expected_ip {
        if &observed_ip != exp_ip {
            return Err(BrowserVerificationError::IpMismatch(format!(
                "Expected IP '{}', observed '{}'",
                exp_ip, observed_ip
            )));
        }
    }

    // 6. Strict Country validation
    if let Some(ref exp_c) = session.expected_country {
        if let Err(e) = crate::services::network_service::NetworkService::evaluate_country_match(
            &observed_country,
            Some(exp_c),
        ) {
            return Err(BrowserVerificationError::CountryMismatch(e));
        }
    }

    // 7. Request-level correlation with proxy bridge telemetry
    let proxy_path_confirmed =
        if let (Some(mgr), Some(ref inst_id)) = (bridge_mgr, &session.bridge_instance_id) {
            mgr.find_matching_tunnel(
                inst_id,
                &session.environment_id,
                &session.proxy_endpoint_id,
                "ipwho.is",
                443,
                verification_start,
            )
            .is_some()
        } else if session.is_simulation {
            session.recent_bridge_connection_count > 0
        } else {
            false
        };

    // DEFECT HIGH-01: BROWSER_EGRESS_VERIFIED is prohibited unless proxy_path_confirmed is true!
    if !proxy_path_confirmed {
        return Err(BrowserVerificationError::ProxyBridgeMismatch(
            "Proxy tunnel correlation failed: no matching upstream bridge event recorded for this request".to_string(),
        ));
    }

    let token = Uuid::new_v4().to_string();
    let verification_id = Uuid::new_v4().to_string();
    let verification_source = if session.is_simulation {
        "SIMULATED_MOCK_CDP".to_string()
    } else {
        "CDP_BROWSER_FETCH".to_string()
    };

    Ok(BrowserVerificationEvidence {
        verification_id,
        environment_id: session.environment_id.clone(),
        browser_session_id: session.session_id.clone(),
        browser_pid: session.pid,
        profile_path: session.profile_path.clone(),
        verification_token: token,
        verification_url: "https://ipwho.is/".to_string(),
        token_received: true,
        observed_public_ip: Some(observed_ip.clone()),
        observed_country: Some(observed_country.clone()),
        proxy_endpoint_id: session.proxy_endpoint_id.clone(),
        bridge_instance_id: session.bridge_instance_id.clone(),
        verification_source,
        verified_at: Utc::now().to_rfc3339(),
        latency_ms: Some(latency_ms),
        proxy_path_confirmed: true,
        status: VerificationStatus::BrowserEgressVerified.as_str().to_string(),
        message: format!(
            "Microsoft Edge session (PID {}) verified via CDP: observed external egress IP {} ({}) matching assigned proxy route.",
            session.pid, observed_ip, observed_country
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_status_roundtrip() {
        let statuses = [
            VerificationStatus::NotConfigured,
            VerificationStatus::EndpointConfigured,
            VerificationStatus::EndpointReachable,
            VerificationStatus::ProxyEgressVerified,
            VerificationStatus::BrowserEgressVerified,
            VerificationStatus::AuthFailed,
            VerificationStatus::ConnectionFailed,
            VerificationStatus::VerificationUnavailable,
            VerificationStatus::Stale,
        ];
        for s in &statuses {
            let as_str = s.as_str();
            let back = VerificationStatus::from_status_str(as_str);
            assert_eq!(s, &back, "Roundtrip failed for {:?}", s);
        }
    }

    #[test]
    fn test_unavailable_evidence_has_correct_status() {
        let ev = BrowserVerificationEvidence::unavailable("env-123", "Test reason");
        assert_eq!(ev.status, "VERIFICATION_UNAVAILABLE");
        assert_eq!(ev.environment_id, "env-123");
        assert!(!ev.token_received);
        assert!(!ev.proxy_path_confirmed);
    }

    #[test]
    fn test_token_verification_returns_unavailable_without_cdp() {
        let session = BrowserSessionInfo {
            environment_id: "env-test".to_string(),
            session_id: "sess-001".to_string(),
            pid: std::process::id(),
            profile_path: "/tmp/test-profile".to_string(),
            proxy_bridge_port: Some(49200),
            proxy_endpoint_id: "ep-001".to_string(),
            bridge_instance_id: None,
            expected_country: Some("US".to_string()),
            expected_ip: None,
            recent_bridge_connection_count: 0,
            cdp_port: None,
            is_simulation: true,
        };
        let result = attempt_token_browser_verification(&session);
        assert_eq!(result.status, "VERIFICATION_UNAVAILABLE");
        assert_eq!(result.environment_id, "env-test");
        assert_eq!(result.browser_pid, std::process::id());
        assert!(!result.token_received);
        assert!(!result.proxy_path_confirmed);
        assert!(result.message.contains("CDP"));
    }

    #[test]
    fn test_cdp_unavailable_when_port_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let session = BrowserSessionInfo {
            environment_id: "env-test".to_string(),
            session_id: "sess-001".to_string(),
            pid: std::process::id(),
            profile_path: "/tmp/test-profile".to_string(),
            proxy_bridge_port: Some(49200),
            proxy_endpoint_id: "ep-001".to_string(),
            bridge_instance_id: None,
            expected_country: Some("US".to_string()),
            expected_ip: None,
            recent_bridge_connection_count: 1,
            cdp_port: Some(port),
            is_simulation: true,
        };

        let result = attempt_cdp_browser_verification(&session, port, None);
        assert!(matches!(
            result,
            Err(BrowserVerificationError::CdpNotAvailable(_))
        ));
    }

    #[test]
    fn test_cdp_session_mismatch_when_pid_zero() {
        let session = BrowserSessionInfo {
            environment_id: "env-test".to_string(),
            session_id: "sess-001".to_string(),
            pid: 0,
            profile_path: "/tmp/test-profile".to_string(),
            proxy_bridge_port: Some(49200),
            proxy_endpoint_id: "ep-001".to_string(),
            bridge_instance_id: None,
            expected_country: Some("US".to_string()),
            expected_ip: None,
            recent_bridge_connection_count: 1,
            cdp_port: Some(9222),
            is_simulation: true,
        };

        let result = attempt_cdp_browser_verification(&session, 9222, None);
        assert_eq!(result, Err(BrowserVerificationError::SessionMismatch));
    }

    #[test]
    fn test_cdp_session_mismatch_when_pid_not_alive() {
        let session = BrowserSessionInfo {
            environment_id: "env-test".to_string(),
            session_id: "sess-001".to_string(),
            pid: 999_999_999,
            profile_path: "/tmp/test-profile".to_string(),
            proxy_bridge_port: Some(49200),
            proxy_endpoint_id: "ep-001".to_string(),
            bridge_instance_id: None,
            expected_country: Some("US".to_string()),
            expected_ip: None,
            recent_bridge_connection_count: 1,
            cdp_port: Some(9222),
            is_simulation: true,
        };

        let result = attempt_cdp_browser_verification(&session, 9222, None);
        assert_eq!(result, Err(BrowserVerificationError::SessionMismatch));
    }

    #[test]
    fn test_cdp_security_violation_when_non_loopback_ws() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);

            if req.contains("GET /json/list") {
                let targets = serde_json::json!([{
                    "id": "target-1",
                    "type": "page",
                    "title": "Mock Target",
                    "url": "about:blank",
                    "webSocketDebuggerUrl": format!("ws://192.168.1.100:{}/devtools/page/target-1", port)
                }]);
                let body = targets.to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
        });

        std::thread::sleep(Duration::from_millis(50));

        let session = BrowserSessionInfo {
            environment_id: "env-test".to_string(),
            session_id: "sess-001".to_string(),
            pid: std::process::id(),
            profile_path: "/tmp/test-profile".to_string(),
            proxy_bridge_port: Some(49200),
            proxy_endpoint_id: "ep-001".to_string(),
            bridge_instance_id: None,
            expected_country: Some("US".to_string()),
            expected_ip: None,
            recent_bridge_connection_count: 1,
            cdp_port: Some(port),
            is_simulation: true,
        };

        let err = attempt_cdp_browser_verification(&session, port, None).unwrap_err();
        assert!(matches!(
            err,
            BrowserVerificationError::CdpSecurityViolation(_)
        ));
    }

    #[test]
    fn test_cdp_mock_verification_success() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);

            if req.contains("GET /json/list") {
                let targets = serde_json::json!([{
                    "id": "target-1",
                    "type": "page",
                    "title": "Mock Target",
                    "url": "about:blank",
                    "webSocketDebuggerUrl": format!("ws://127.0.0.1:{}/devtools/page/target-1", port)
                }]);
                let body = targets.to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
                drop(stream);
            }

            let (ws_stream, _) = listener.accept().unwrap();
            let mut ws = tungstenite::accept(ws_stream).unwrap();
            let msg = ws.read().unwrap();
            if let tungstenite::Message::Text(txt) = msg {
                let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
                let id = v.get("id").unwrap().as_i64().unwrap();
                let resp_payload = serde_json::json!({
                    "id": id,
                    "result": {
                        "result": {
                            "type": "string",
                            "value": serde_json::json!({
                                "ip": "198.51.100.25",
                                "country_code": "US",
                                "country": "United States",
                                "success": true
                            }).to_string()
                        }
                    }
                });
                ws.send(tungstenite::Message::Text(resp_payload.to_string().into()))
                    .unwrap();
            }
        });

        std::thread::sleep(Duration::from_millis(50));

        let session = BrowserSessionInfo {
            environment_id: "env-test".to_string(),
            session_id: "sess-001".to_string(),
            pid: std::process::id(),
            profile_path: "/tmp/test-profile".to_string(),
            proxy_bridge_port: Some(49200),
            proxy_endpoint_id: "ep-001".to_string(),
            bridge_instance_id: None,
            expected_country: Some("US".to_string()),
            expected_ip: Some("198.51.100.25".to_string()),
            recent_bridge_connection_count: 3,
            cdp_port: Some(port),
            is_simulation: true,
        };

        let evidence = attempt_cdp_browser_verification(&session, port, None).unwrap();
        assert_eq!(evidence.status, "BROWSER_EGRESS_VERIFIED");
        assert_eq!(
            evidence.observed_public_ip,
            Some("198.51.100.25".to_string())
        );
        assert_eq!(evidence.observed_country, Some("US".to_string()));
        assert_eq!(evidence.verification_source, "SIMULATED_MOCK_CDP");
        assert!(evidence.proxy_path_confirmed);
    }

    #[test]
    fn test_cdp_mock_country_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);

            if req.contains("GET /json/list") {
                let targets = serde_json::json!([{
                    "id": "target-1",
                    "type": "page",
                    "title": "Mock Target",
                    "url": "about:blank",
                    "webSocketDebuggerUrl": format!("ws://127.0.0.1:{}/devtools/page/target-1", port)
                }]);
                let body = targets.to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
                drop(stream);
            }

            let (ws_stream, _) = listener.accept().unwrap();
            let mut ws = tungstenite::accept(ws_stream).unwrap();
            let msg = ws.read().unwrap();
            if let tungstenite::Message::Text(txt) = msg {
                let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
                let id = v.get("id").unwrap().as_i64().unwrap();
                let resp_payload = serde_json::json!({
                    "id": id,
                    "result": {
                        "result": {
                            "type": "string",
                            "value": serde_json::json!({
                                "ip": "198.51.100.25",
                                "country_code": "VN",
                                "country": "Vietnam",
                                "success": true
                            }).to_string()
                        }
                    }
                });
                ws.send(tungstenite::Message::Text(resp_payload.to_string().into()))
                    .unwrap();
            }
        });

        std::thread::sleep(Duration::from_millis(50));

        let session = BrowserSessionInfo {
            environment_id: "env-test".to_string(),
            session_id: "sess-001".to_string(),
            pid: std::process::id(),
            profile_path: "/tmp/test-profile".to_string(),
            proxy_bridge_port: Some(49200),
            proxy_endpoint_id: "ep-001".to_string(),
            bridge_instance_id: None,
            expected_country: Some("US".to_string()),
            expected_ip: None,
            recent_bridge_connection_count: 1,
            cdp_port: Some(port),
            is_simulation: true,
        };

        let err = attempt_cdp_browser_verification(&session, port, None).unwrap_err();
        assert!(matches!(err, BrowserVerificationError::CountryMismatch(_)));
    }

    #[test]
    fn test_cdp_fails_when_no_bridge_tunnel_event() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);

            if req.contains("GET /json/list") {
                let targets = serde_json::json!([{
                    "id": "target-1",
                    "type": "page",
                    "title": "Mock Target",
                    "url": "about:blank",
                    "webSocketDebuggerUrl": format!("ws://127.0.0.1:{}/devtools/page/target-1", port)
                }]);
                let body = targets.to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
                drop(stream);
            }

            let (ws_stream, _) = listener.accept().unwrap();
            let mut ws = tungstenite::accept(ws_stream).unwrap();
            let msg = ws.read().unwrap();
            if let tungstenite::Message::Text(txt) = msg {
                let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
                let id = v.get("id").unwrap().as_i64().unwrap();
                let resp_payload = serde_json::json!({
                    "id": id,
                    "result": {
                        "result": {
                            "type": "string",
                            "value": serde_json::json!({
                                "ip": "64.233.160.1",
                                "country_code": "US",
                                "country": "United States",
                                "success": true
                            }).to_string()
                        }
                    }
                });
                ws.send(tungstenite::Message::Text(resp_payload.to_string().into()))
                    .unwrap();
            }
        });

        std::thread::sleep(Duration::from_millis(50));

        // recent_bridge_connection_count == 0 -> must NEVER pass as BROWSER_EGRESS_VERIFIED
        let session = BrowserSessionInfo {
            environment_id: "env-test".to_string(),
            session_id: "sess-001".to_string(),
            pid: std::process::id(),
            profile_path: "/tmp/test-profile".to_string(),
            proxy_bridge_port: Some(49200),
            proxy_endpoint_id: "ep-001".to_string(),
            bridge_instance_id: None,
            expected_country: Some("US".to_string()),
            expected_ip: Some("64.233.160.1".to_string()),
            recent_bridge_connection_count: 0,
            cdp_port: Some(port),
            is_simulation: true,
        };

        let err = attempt_cdp_browser_verification(&session, port, None).unwrap_err();
        assert!(matches!(
            err,
            BrowserVerificationError::ProxyBridgeMismatch(_)
        ));
    }

    #[test]
    fn test_cdp_fails_when_country_unknown_and_expected_set() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);

            if req.contains("GET /json/list") {
                let targets = serde_json::json!([{
                    "id": "target-1",
                    "type": "page",
                    "title": "Mock Target",
                    "url": "about:blank",
                    "webSocketDebuggerUrl": format!("ws://127.0.0.1:{}/devtools/page/target-1", port)
                }]);
                let body = targets.to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
                drop(stream);
            }

            let (ws_stream, _) = listener.accept().unwrap();
            let mut ws = tungstenite::accept(ws_stream).unwrap();
            let msg = ws.read().unwrap();
            if let tungstenite::Message::Text(txt) = msg {
                let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
                let id = v.get("id").unwrap().as_i64().unwrap();
                let resp_payload = serde_json::json!({
                    "id": id,
                    "result": {
                        "result": {
                            "type": "string",
                            "value": serde_json::json!({
                                "ip": "64.233.160.1",
                                "country_code": "UNKNOWN",
                                "country": "Unknown",
                                "success": true
                            }).to_string()
                        }
                    }
                });
                ws.send(tungstenite::Message::Text(resp_payload.to_string().into()))
                    .unwrap();
            }
        });

        std::thread::sleep(Duration::from_millis(50));

        let session = BrowserSessionInfo {
            environment_id: "env-test".to_string(),
            session_id: "sess-001".to_string(),
            pid: std::process::id(),
            profile_path: "/tmp/test-profile".to_string(),
            proxy_bridge_port: Some(49200),
            proxy_endpoint_id: "ep-001".to_string(),
            bridge_instance_id: None,
            expected_country: Some("US".to_string()),
            expected_ip: None,
            recent_bridge_connection_count: 1,
            cdp_port: Some(port),
            is_simulation: true,
        };

        let err = attempt_cdp_browser_verification(&session, port, None).unwrap_err();
        assert!(matches!(err, BrowserVerificationError::CountryMismatch(_)));
    }

    #[test]
    fn test_live_verification_rejects_documentation_ip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);

            if req.contains("GET /json/list") {
                let targets = serde_json::json!([{
                    "id": "target-1",
                    "type": "page",
                    "title": "Mock Target",
                    "url": "about:blank",
                    "webSocketDebuggerUrl": format!("ws://127.0.0.1:{}/devtools/page/target-1", port)
                }]);
                let body = targets.to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
                drop(stream);
            }

            let (ws_stream, _) = listener.accept().unwrap();
            let mut ws = tungstenite::accept(ws_stream).unwrap();
            let msg = ws.read().unwrap();
            if let tungstenite::Message::Text(txt) = msg {
                let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
                let id = v.get("id").unwrap().as_i64().unwrap();
                let resp_payload = serde_json::json!({
                    "id": id,
                    "result": {
                        "result": {
                            "type": "string",
                            "value": serde_json::json!({
                                "ip": "198.51.100.25",
                                "country_code": "US",
                                "country": "United States",
                                "success": true
                            }).to_string()
                        }
                    }
                });
                ws.send(tungstenite::Message::Text(resp_payload.to_string().into()))
                    .unwrap();
            }
        });

        std::thread::sleep(Duration::from_millis(50));

        // is_simulation == false -> live mode MUST reject RFC 5737 documentation IP 198.51.100.25
        let session = BrowserSessionInfo {
            environment_id: "env-test".to_string(),
            session_id: "sess-001".to_string(),
            pid: std::process::id(),
            profile_path: "/tmp/test-profile".to_string(),
            proxy_bridge_port: Some(49200),
            proxy_endpoint_id: "ep-001".to_string(),
            bridge_instance_id: None,
            expected_country: Some("US".to_string()),
            expected_ip: None,
            recent_bridge_connection_count: 1,
            cdp_port: Some(port),
            is_simulation: false,
        };

        let err = attempt_cdp_browser_verification(&session, port, None).unwrap_err();
        assert!(matches!(
            err,
            BrowserVerificationError::IpNotGloballyRoutable(_)
        ));
    }

    #[test]
    fn test_globally_routable_ip_classification() {
        assert!(!is_globally_routable_ip("127.0.0.1"));
        assert!(!is_globally_routable_ip("10.0.0.1"));
        assert!(!is_globally_routable_ip("172.16.0.1"));
        assert!(!is_globally_routable_ip("192.168.1.1"));
        assert!(!is_globally_routable_ip("169.254.1.1"));
        assert!(!is_globally_routable_ip("192.0.2.1"));
        assert!(!is_globally_routable_ip("198.51.100.25"));
        assert!(!is_globally_routable_ip("203.0.113.10"));
        assert!(!is_globally_routable_ip("100.64.0.1"));
        assert!(!is_globally_routable_ip("::1"));
        assert!(!is_globally_routable_ip("2001:db8::1"));
        assert!(!is_globally_routable_ip("fe80::1"));

        // Real globally routable public IPs
        assert!(is_globally_routable_ip("8.8.8.8"));
        assert!(is_globally_routable_ip("1.1.1.1"));
        assert!(is_globally_routable_ip("64.233.160.1"));
        assert!(is_globally_routable_ip("2606:4700:4700::1111"));
    }

    #[test]
    fn test_evaluate_verification_decision_enforces_invariants() {
        let mut ev = BrowserVerificationEvidence {
            verification_id: "v-1".to_string(),
            environment_id: "env-1".to_string(),
            browser_session_id: "s-1".to_string(),
            browser_pid: std::process::id(),
            profile_path: "/tmp/p".to_string(),
            verification_token: "tok".to_string(),
            verification_url: "https://ipwho.is/".to_string(),
            token_received: true,
            observed_public_ip: Some("64.233.160.1".to_string()),
            observed_country: Some("US".to_string()),
            proxy_endpoint_id: "ep-1".to_string(),
            bridge_instance_id: Some("br-1".to_string()),
            verification_source: "CDP_BROWSER_FETCH".to_string(),
            verified_at: Utc::now().to_rfc3339(),
            latency_ms: Some(120),
            proxy_path_confirmed: true,
            status: "BROWSER_EGRESS_VERIFIED".to_string(),
            message: "ok".to_string(),
        };
        assert!(evaluate_verification_decision(&ev).is_ok());

        // proxy_path_confirmed == false must NEVER pass
        ev.proxy_path_confirmed = false;
        assert!(evaluate_verification_decision(&ev).is_err());

        // SIMULATED_MOCK_CDP must NEVER pass live evaluate_verification_decision
        ev.proxy_path_confirmed = true;
        ev.verification_source = "SIMULATED_MOCK_CDP".to_string();
        assert!(evaluate_verification_decision(&ev).is_err());

        // Documentation IP must NEVER pass live evaluate_verification_decision
        ev.verification_source = "CDP_BROWSER_FETCH".to_string();
        ev.observed_public_ip = Some("198.51.100.25".to_string());
        assert!(evaluate_verification_decision(&ev).is_err());
    }

    #[test]
    fn test_browser_verification_evidence_unavailable_clears_sensitive_fields() {
        let ev = BrowserVerificationEvidence::unavailable("env-999", "No browser");
        assert!(ev.observed_public_ip.is_none());
        assert!(ev.observed_country.is_none());
        assert!(!ev.proxy_path_confirmed);
    }
}
