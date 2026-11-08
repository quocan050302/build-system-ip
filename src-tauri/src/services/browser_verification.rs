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
///
/// # Safety (Unix)
/// `kill(pid, 0)` is a standard POSIX signal probe — it never delivers a signal,
/// only checks whether the process exists and is reachable by the caller.
#[cfg(unix)]
pub fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: signal 0 is a standard POSIX liveness probe; it does not deliver
    // a signal to the target process. The cast is safe: u32 fits in i32 for any
    // realistic PID value (Linux PIDs are limited to 4_194_304 < i32::MAX).
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Helper to verify whether an OS process ID is currently alive.
///
/// # Safety (Windows)
/// Uses `OpenProcess` with the minimum required access right
/// (`PROCESS_QUERY_LIMITED_INFORMATION`) and immediately closes the handle.
/// The handle is never stored or used for any other purpose.
#[cfg(windows)]
pub fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    // SAFETY: `OpenProcess` returns a handle or error; we immediately close it.
    // `CloseHandle` is safe to call on a valid non-null handle returned by OpenProcess.
    unsafe {
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(handle) if !handle.is_invalid() => {
                // Explicitly ignore the Result<()> returned by CloseHandle —
                // failure to close does not affect the liveness determination.
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
    if evidence.profile_path.trim().is_empty() {
        return Err("Missing browser profile path");
    }
    if evidence.browser_session_id.trim().is_empty() {
        return Err("Missing browser session ID");
    }
    if evidence.proxy_endpoint_id.trim().is_empty() {
        return Err("Missing assigned proxy endpoint ID");
    }
    if evidence
        .bridge_instance_id
        .as_deref()
        .map(|s| s.trim().is_empty())
        .unwrap_or(true)
    {
        return Err("Missing proxy bridge instance ID");
    }
    if let Some(ref ip) = evidence.observed_public_ip {
        if !is_globally_routable_ip(ip) {
            return Err("Observed public IP is not a globally routable address");
        }
    } else {
        return Err("Missing observed public IP");
    }
    if let Some(ref country) = evidence.observed_country {
        let c = country.trim();
        if c.is_empty() || c.eq_ignore_ascii_case("UNKNOWN") || c.eq_ignore_ascii_case("UNVERIFIED")
        {
            return Err("Observed country is missing or UNKNOWN");
        }
    } else {
        return Err("Missing observed country");
    }
    if evidence.browser_pid == 0 || !is_process_alive(evidence.browser_pid) {
        return Err("Invalid or dead browser process ID");
    }
    if !matches!(
        evidence.verification_source.as_str(),
        "CDP_PAGE_NAVIGATE" | "CDP_BROWSER_FETCH"
    ) {
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

/// Target descriptor returned by CDP `/json/list` or `PUT /json/new`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CdpVersionInfo {
    #[serde(rename = "Browser")]
    pub browser: Option<String>,
    #[serde(rename = "Protocol-Version")]
    pub protocol_version: Option<String>,
    #[serde(rename = "webSocketDebuggerUrl")]
    pub websocket_debugger_url: Option<String>,
}

/// Parsed HTTP response from a loopback CDP endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdpHttpResponse {
    pub status_code: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: String,
}

const MAX_CDP_HTTP_HEADER_BYTES: usize = 16 * 1024;
const MAX_CDP_HTTP_BODY_BYTES: usize = 256 * 1024;

/// Validates that a CDP target ID is non-empty and free of path traversal, whitespace, or CRLF characters.
pub fn is_safe_cdp_target_id(target_id: &str) -> bool {
    !target_id.is_empty()
        && target_id.len() <= 128
        && target_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

/// Validates that a CDP WebSocket URL uses `ws://`, a loopback host (`127.0.0.1`, `localhost`, or `[::1]`),
/// and matches `expected_port` when a port is present.
pub fn validate_loopback_ws_url(
    ws_url: &str,
    expected_port: u16,
) -> Result<url::Url, BrowserVerificationError> {
    let parsed_url: url::Url = ws_url.parse().map_err(|e| {
        BrowserVerificationError::CdpSecurityViolation(format!(
            "Malformed WS URL '{}': {}",
            ws_url, e
        ))
    })?;
    if parsed_url.scheme() != "ws" {
        return Err(BrowserVerificationError::CdpSecurityViolation(
            "CDP endpoint must use ws:// scheme".to_string(),
        ));
    }
    let host = parsed_url.host_str().unwrap_or("");
    if host != "127.0.0.1" && host != "localhost" && host != "::1" && host != "[::1]" {
        return Err(BrowserVerificationError::CdpSecurityViolation(format!(
            "CDP endpoint rejected non-loopback host '{}'",
            host
        )));
    }
    if let Some(p) = parsed_url.port() {
        if expected_port != 0 && p != expected_port {
            return Err(BrowserVerificationError::CdpSecurityViolation(format!(
                "CDP WebSocket port {} does not match expected session CDP port {}",
                p, expected_port
            )));
        }
    }
    Ok(parsed_url)
}

/// Execute a bounded HTTP/1.1 request against the loopback CDP endpoint `127.0.0.1:<port>`.
///
/// Enforces:
/// - Loopback-only TCP connection (`127.0.0.1:<port>`)
/// - Strict request method (`GET` or `PUT`) and path validation (no CRLF/header injection)
/// - Bounded header (`16 KiB`) and body (`256 KiB`) sizes
/// - Explicit HTTP status code parsing; never follows `3xx` redirects
pub fn cdp_http_request(
    port: u16,
    method: &str,
    path: &str,
    timeout: Duration,
) -> Result<CdpHttpResponse, BrowserVerificationError> {
    if port == 0 {
        return Err(BrowserVerificationError::CdpNotAvailable(
            "CDP port cannot be 0".to_string(),
        ));
    }
    if !matches!(method, "GET" | "PUT") {
        return Err(BrowserVerificationError::CdpSecurityViolation(format!(
            "Unsupported CDP HTTP method '{}'",
            method
        )));
    }
    if !path.starts_with('/')
        || path
            .chars()
            .any(|c| c == '\r' || c == '\n' || c == '\0' || c.is_whitespace())
    {
        return Err(BrowserVerificationError::CdpSecurityViolation(format!(
            "Invalid or unsafe CDP HTTP path '{}'",
            path
        )));
    }

    let addr_str = format!("127.0.0.1:{}", port);
    let socket_addr: SocketAddr = addr_str.parse().map_err(|e: std::net::AddrParseError| {
        BrowserVerificationError::CdpConnectionFailed(e.to_string())
    })?;

    let mut stream = TcpStream::connect_timeout(&socket_addr, timeout).map_err(|e| {
        BrowserVerificationError::CdpNotAvailable(format!(
            "CDP port {} unreachable for {} {}: {}",
            port, method, path, e
        ))
    })?;

    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    let request = format!(
        "{} {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\nContent-Length: 0\r\nUser-Agent: YouTubeIsolationManager-Verifier/1.0\r\n\r\n",
        method, path, port
    );
    stream.write_all(request.as_bytes()).map_err(|e| {
        BrowserVerificationError::CdpConnectionFailed(format!(
            "Failed to write CDP HTTP request ({} {}): {}",
            method, path, e
        ))
    })?;
    let _ = stream.flush();

    let mut buffer = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    let mut header_end_idx: Option<usize> = None;
    let mut expected_content_len: Option<usize> = None;

    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);
                if header_end_idx.is_none() {
                    if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                        if pos > MAX_CDP_HTTP_HEADER_BYTES {
                            return Err(BrowserVerificationError::ResponseParseError(
                                "CDP HTTP response headers exceeded 16 KiB cap".to_string(),
                            ));
                        }
                        header_end_idx = Some(pos);
                        let header_str = String::from_utf8_lossy(&buffer[..pos]);
                        for line in header_str.lines().skip(1) {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    if let Ok(cl) = v.trim().parse::<usize>() {
                                        if cl > MAX_CDP_HTTP_BODY_BYTES {
                                            return Err(
                                                BrowserVerificationError::ResponseParseError(
                                                    format!(
                                                        "CDP HTTP Content-Length {} exceeds 256 KiB cap",
                                                        cl
                                                    ),
                                                ),
                                            );
                                        }
                                        expected_content_len = Some(cl);
                                    }
                                }
                            }
                        }
                    } else if buffer.len() > MAX_CDP_HTTP_HEADER_BYTES {
                        return Err(BrowserVerificationError::ResponseParseError(
                            "CDP HTTP response headers exceeded 16 KiB cap without terminator"
                                .to_string(),
                        ));
                    }
                }

                if let Some(h_end) = header_end_idx {
                    let body_len = buffer.len().saturating_sub(h_end + 4);
                    if body_len > MAX_CDP_HTTP_BODY_BYTES {
                        return Err(BrowserVerificationError::ResponseParseError(
                            "CDP HTTP response body exceeded 256 KiB cap".to_string(),
                        ));
                    }
                    if let Some(cl) = expected_content_len {
                        if body_len >= cl {
                            break;
                        }
                    }
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if header_end_idx.is_some() {
                    break;
                }
                return Err(BrowserVerificationError::CdpConnectionFailed(format!(
                    "CDP HTTP read timed out on {} {}: {}",
                    method, path, e
                )));
            }
            Err(e) => {
                return Err(BrowserVerificationError::CdpConnectionFailed(format!(
                    "Failed reading CDP HTTP response on {} {}: {}",
                    method, path, e
                )));
            }
        }
    }

    let h_end = header_end_idx.ok_or_else(|| {
        BrowserVerificationError::ResponseParseError(
            "Malformed HTTP response from CDP endpoint (missing header terminator)".to_string(),
        )
    })?;

    let header_str = String::from_utf8_lossy(&buffer[..h_end]);
    let mut lines = header_str.lines();
    let status_line = lines.next().ok_or_else(|| {
        BrowserVerificationError::ResponseParseError("Empty HTTP status line from CDP".to_string())
    })?;

    let mut status_parts = status_line.splitn(3, ' ');
    let http_proto = status_parts.next().unwrap_or("");
    if !http_proto.starts_with("HTTP/1.") {
        return Err(BrowserVerificationError::ResponseParseError(format!(
            "Invalid HTTP protocol in CDP status line: '{}'",
            status_line
        )));
    }
    let status_code = status_parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| {
            BrowserVerificationError::ResponseParseError(format!(
                "Invalid HTTP status code in CDP status line: '{}'",
                status_line
            ))
        })?;
    let status_text = status_parts.next().unwrap_or("").trim().to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    if (300..400).contains(&status_code) {
        return Err(BrowserVerificationError::CdpSecurityViolation(format!(
            "CDP HTTP redirect ({} {}) is prohibited",
            status_code, status_text
        )));
    }

    let raw_body = &buffer[h_end + 4..];
    let slice_len = expected_content_len
        .map(|cl| cl.min(raw_body.len()))
        .unwrap_or(raw_body.len());
    let body = String::from_utf8_lossy(&raw_body[..slice_len]).to_string();

    Ok(CdpHttpResponse {
        status_code,
        status_text,
        headers,
        body,
    })
}

/// Fetch list of CDP targets from loopback HTTP endpoint (`GET /json/list`).
pub fn fetch_cdp_targets(
    port: u16,
    timeout: Duration,
) -> Result<Vec<CdpTarget>, BrowserVerificationError> {
    let resp = cdp_http_request(port, "GET", "/json/list", timeout)?;
    if resp.status_code != 200 {
        return Err(BrowserVerificationError::CdpConnectionFailed(format!(
            "GET /json/list returned HTTP {} {}",
            resp.status_code, resp.status_text
        )));
    }
    let targets: Vec<CdpTarget> = serde_json::from_str(&resp.body).map_err(|e| {
        BrowserVerificationError::ResponseParseError(format!(
            "Failed parsing CDP targets JSON: {}",
            e
        ))
    })?;
    Ok(targets)
}

/// Fetch version information from loopback CDP HTTP endpoint (`GET /json/version`).
pub fn fetch_cdp_version(
    port: u16,
    timeout: Duration,
) -> Result<CdpVersionInfo, BrowserVerificationError> {
    let resp = cdp_http_request(port, "GET", "/json/version", timeout)?;
    if resp.status_code != 200 {
        return Err(BrowserVerificationError::CdpConnectionFailed(format!(
            "GET /json/version returned HTTP {} {}",
            resp.status_code, resp.status_text
        )));
    }
    let ver: CdpVersionInfo = serde_json::from_str(&resp.body).map_err(|e| {
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
    /// Failed to create a dedicated blank CDP target for verification.
    CdpTargetCreationFailed(String),
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
            Self::CdpTargetCreationFailed(s) => {
                write!(f, "CDP target creation failed: {}", s)
            }
        }
    }
}

impl std::error::Error for BrowserVerificationError {}

/// Creates a dedicated blank CDP target via `PUT /json/new?about:blank` and returns the validated `CdpTarget`.
///
/// Modern Chromium / Microsoft Edge rejects `GET /json/new` with HTTP 405 (`Method Not Allowed`)
/// and requires `PUT`. Never retries `405` with `GET`.
pub fn create_cdp_blank_target_full(
    debug_port: u16,
    connect_timeout: Duration,
) -> Result<CdpTarget, BrowserVerificationError> {
    let resp = match cdp_http_request(debug_port, "PUT", "/json/new?about:blank", connect_timeout) {
        Ok(r) => r,
        Err(BrowserVerificationError::CdpNotAvailable(msg)) => {
            return Err(BrowserVerificationError::CdpNotAvailable(msg));
        }
        Err(e) => {
            return Err(BrowserVerificationError::CdpTargetCreationFailed(format!(
                "PUT /json/new?about:blank failed: {}",
                e
            )));
        }
    };

    if resp.status_code != 200 {
        let preview = &resp.body[..resp.body.len().min(200)];
        return Err(BrowserVerificationError::CdpTargetCreationFailed(format!(
            "PUT /json/new?about:blank returned HTTP {} {}: {}",
            resp.status_code,
            resp.status_text,
            preview.trim()
        )));
    }

    let target: CdpTarget = serde_json::from_str(&resp.body).map_err(|e| {
        BrowserVerificationError::CdpTargetCreationFailed(format!(
            "Failed to parse PUT /json/new response: {} — body: {}",
            e,
            &resp.body[..resp.body.len().min(200)]
        ))
    })?;

    if target.target_type != "page" {
        return Err(BrowserVerificationError::CdpTargetCreationFailed(format!(
            "PUT /json/new returned unexpected target type '{}' (expected 'page')",
            target.target_type
        )));
    }

    if !is_safe_cdp_target_id(&target.id) {
        return Err(BrowserVerificationError::CdpTargetCreationFailed(format!(
            "PUT /json/new returned invalid or unsafe target id '{}'",
            target.id
        )));
    }

    if let Some(ref ws_url) = target.websocket_debugger_url {
        validate_loopback_ws_url(ws_url, debug_port)?;
    }

    Ok(target)
}

/// Creates a dedicated blank CDP target via `PUT /json/new?about:blank`.
///
/// Returns the validated target ID string on success.
pub fn create_cdp_blank_target(
    debug_port: u16,
    connect_timeout: Duration,
) -> Result<String, BrowserVerificationError> {
    create_cdp_blank_target_full(debug_port, connect_timeout).map(|t| t.id)
}

/// Closes a CDP target via `GET /json/close/{target_id}` (best-effort cleanup).
/// Only closes validated safe target IDs created by this verifier.
pub fn close_cdp_target(debug_port: u16, target_id: &str, connect_timeout: Duration) {
    if !is_safe_cdp_target_id(target_id) {
        return;
    }
    let path = format!("/json/close/{}", target_id);
    let _ = cdp_http_request(debug_port, "GET", &path, connect_timeout);
}

/// RAII guard that ensures the dedicated verification CDP target is closed on all exit paths.
pub struct CdpTargetGuard {
    debug_port: u16,
    target_id: String,
    timeout: Duration,
    closed: bool,
}

impl CdpTargetGuard {
    pub fn new(debug_port: u16, target_id: String, timeout: Duration) -> Self {
        Self {
            debug_port,
            target_id,
            timeout,
            closed: false,
        }
    }

    pub fn close_now(&mut self) {
        if !self.closed {
            self.closed = true;
            close_cdp_target(self.debug_port, &self.target_id, self.timeout);
        }
    }
}

impl Drop for CdpTargetGuard {
    fn drop(&mut self) {
        self.close_now();
    }
}

/// Specification for an external HTTPS egress verification provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationProviderSpec {
    pub name: &'static str,
    pub url: &'static str,
    pub host: &'static str,
    pub port: u16,
    pub supplies_country: bool,
}

pub const PRIMARY_VERIFICATION_PROVIDER: VerificationProviderSpec = VerificationProviderSpec {
    name: "ipwho.is",
    url: "https://ipwho.is/",
    host: "ipwho.is",
    port: 443,
    supplies_country: true,
};

pub const FALLBACK_VERIFICATION_PROVIDER: VerificationProviderSpec = VerificationProviderSpec {
    name: "api.ipify.org",
    url: "https://api.ipify.org/?format=json",
    host: "api.ipify.org",
    port: 443,
    supplies_country: false,
};

/// Verifies that the loopback CDP endpoint on `debug_port` is genuinely owned by the
/// managed Microsoft Edge process (`session.pid`) and bound to `session.profile_path`.
pub fn verify_managed_cdp_ownership(
    session: &BrowserSessionInfo,
    debug_port: u16,
    timeout: Duration,
) -> Result<(), BrowserVerificationError> {
    if session.pid == 0 || !is_process_alive(session.pid) {
        return Err(BrowserVerificationError::SessionMismatch);
    }
    if debug_port == 0 {
        return Err(BrowserVerificationError::CdpNotAvailable(
            "CDP port cannot be 0".to_string(),
        ));
    }
    if session.profile_path.trim().is_empty() || session.session_id.trim().is_empty() {
        return Err(BrowserVerificationError::SessionMismatch);
    }
    if let Some(expected_port) = session.cdp_port {
        if expected_port != debug_port {
            return Err(BrowserVerificationError::SessionMismatch);
        }
    }

    let profile_dir = std::path::Path::new(&session.profile_path);
    // If DevToolsActivePort exists in the profile dir, its port MUST match debug_port
    if let Some((active_port, _ws_path)) =
        crate::services::profile_service::SystemBrowserLauncher::parse_devtools_active_port(
            profile_dir,
        )
    {
        if active_port != debug_port {
            return Err(BrowserVerificationError::SessionMismatch);
        }
    }

    if session.is_simulation {
        return Ok(());
    }

    if !profile_dir.exists() {
        return Err(BrowserVerificationError::SessionMismatch);
    }

    #[cfg(unix)]
    {
        use std::process::Command;
        let ps_out = Command::new("ps")
            .args(["-p", &session.pid.to_string(), "-o", "command="])
            .output()
            .map_err(|_| BrowserVerificationError::SessionMismatch)?;
        if !ps_out.status.success() {
            return Err(BrowserVerificationError::SessionMismatch);
        }
        let cmd_line = String::from_utf8_lossy(&ps_out.stdout).trim().to_string();
        if cmd_line.is_empty() {
            return Err(BrowserVerificationError::SessionMismatch);
        }
        let cmd_lower = cmd_line.to_ascii_lowercase();
        let is_edge_or_chromium = cmd_lower.contains("microsoft edge")
            || cmd_lower.contains("msedge")
            || cmd_lower.contains("chrome")
            || cmd_lower.contains("brave");
        if !is_edge_or_chromium {
            return Err(BrowserVerificationError::SessionMismatch);
        }

        let canonical_profile = std::fs::canonicalize(profile_dir)
            .ok()
            .map(|p| p.to_string_lossy().to_string());
        let expected_arg_raw = format!("--user-data-dir={}", session.profile_path);
        let matches_profile = cmd_line.contains(&expected_arg_raw)
            || canonical_profile
                .as_ref()
                .map(|cp| cmd_line.contains(&format!("--user-data-dir={}", cp)))
                .unwrap_or(false);
        if !matches_profile {
            return Err(BrowserVerificationError::SessionMismatch);
        }

        if let Some(bridge_port) = session.proxy_bridge_port {
            let expected_proxy_arg = format!("--proxy-server=http://127.0.0.1:{}", bridge_port);
            if !cmd_line.contains(&expected_proxy_arg) {
                return Err(BrowserVerificationError::SessionMismatch);
            }
        }

        // Verify socket ownership via lsof when available on macOS/Unix
        if let Ok(lsof_out) = Command::new("lsof")
            .args([
                "-nP",
                "-a",
                "-p",
                &session.pid.to_string(),
                &format!("-iTCP:{}", debug_port),
                "-sTCP:LISTEN",
            ])
            .output()
        {
            if lsof_out.status.success() {
                let stdout = String::from_utf8_lossy(&lsof_out.stdout);
                if !stdout.contains(&format!(":{}", debug_port)) {
                    return Err(BrowserVerificationError::SessionMismatch);
                }
            } else if crate::services::profile_service::SystemBrowserLauncher::parse_devtools_active_port(profile_dir).is_none() {
                return Err(BrowserVerificationError::SessionMismatch);
            }
        }
    }

    let ver = fetch_cdp_version(debug_port, timeout)?;
    if let Some(ref browser_str) = ver.browser {
        let b_lower = browser_str.to_ascii_lowercase();
        if !b_lower.contains("edg/") && !b_lower.contains("chrome/") {
            return Err(BrowserVerificationError::SessionMismatch);
        }
    } else {
        return Err(BrowserVerificationError::SessionMismatch);
    }
    if let Some(ref ws_url) = ver.websocket_debugger_url {
        validate_loopback_ws_url(ws_url, debug_port)?;
    }

    Ok(())
}

/// Navigate a dedicated CDP target to `provider.url` using `Page.navigate` + `Network` domain
/// and return `(response_body, cdp_request_id, latency_ms)`.
///
/// Does NOT use `Runtime.evaluate(fetch(...))` on `about:blank`, avoiding CORS failures on
/// opaque origins in real Chromium / Microsoft Edge.
pub fn navigate_cdp_target_and_read_body(
    ws_url: &str,
    debug_port: u16,
    provider: &VerificationProviderSpec,
    connect_timeout: Duration,
    op_timeout: Duration,
    allow_simulated_runtime_eval_reply: bool,
) -> Result<(String, String, u32), BrowserVerificationError> {
    let url = validate_loopback_ws_url(ws_url, debug_port)?;
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

    let start = Instant::now();

    let setup_cmds = [
        serde_json::json!({ "id": 1, "method": "Page.enable", "params": {} }),
        serde_json::json!({ "id": 2, "method": "Network.enable", "params": {} }),
        serde_json::json!({
            "id": 3,
            "method": "Network.setCacheDisabled",
            "params": { "cacheDisabled": true }
        }),
        serde_json::json!({
            "id": 4,
            "method": "Page.navigate",
            "params": { "url": provider.url }
        }),
    ];

    for cmd in &setup_cmds {
        if let Err(e) = socket.send(tungstenite::Message::Text(cmd.to_string().into())) {
            let _ = socket.close(None);
            return Err(BrowserVerificationError::CdpConnectionFailed(format!(
                "Failed sending CDP command: {}",
                e
            )));
        }
    }

    let mut tracked_request_id: Option<String> = None;
    let mut tracked_loader_id: Option<String> = None;
    let mut response_status_ok = false;
    let mut sent_get_body = false;
    let mut raw_body: Option<String> = None;

    while start.elapsed() < op_timeout {
        match socket.read() {
            Ok(tungstenite::Message::Text(txt)) => {
                let v: serde_json::Value = match serde_json::from_str(&txt) {
                    Ok(val) => val,
                    Err(_) => continue,
                };

                // Check command responses by id
                if let Some(id) = v.get("id").and_then(|i| i.as_i64()) {
                    if let Some(err) = v.get("error") {
                        let _ = socket.close(None);
                        return Err(BrowserVerificationError::BrowserRequestFailed(format!(
                            "CDP command {} error: {}",
                            id, err
                        )));
                    }

                    // Support legacy single-message simulation mock in unit tests if enabled
                    if allow_simulated_runtime_eval_reply {
                        if let Some(val_str) =
                            v.pointer("/result/result/value").and_then(|s| s.as_str())
                        {
                            raw_body = Some(val_str.to_string());
                            break;
                        }
                    }

                    if id == 4 {
                        if let Some(err_text) =
                            v.pointer("/result/errorText").and_then(|s| s.as_str())
                        {
                            if !err_text.is_empty() {
                                let _ = socket.close(None);
                                return Err(BrowserVerificationError::BrowserRequestFailed(
                                    format!(
                                        "CDP Page.navigate to {} failed: {}",
                                        provider.url, err_text
                                    ),
                                ));
                            }
                        }
                        if let Some(loader_id) =
                            v.pointer("/result/loaderId").and_then(|s| s.as_str())
                        {
                            tracked_loader_id = Some(loader_id.to_string());
                        }
                    } else if id == 5 {
                        let body_str = v
                            .pointer("/result/body")
                            .and_then(|s| s.as_str())
                            .ok_or_else(|| {
                                BrowserVerificationError::ResponseParseError(
                                    "Network.getResponseBody missing 'body' string".to_string(),
                                )
                            })?;
                        let is_b64 = v
                            .pointer("/result/base64Encoded")
                            .and_then(|b| b.as_bool())
                            .unwrap_or(false);
                        let decoded = if is_b64 {
                            use base64::Engine;
                            let bytes = base64::engine::general_purpose::STANDARD
                                .decode(body_str)
                                .map_err(|e| {
                                    BrowserVerificationError::ResponseParseError(format!(
                                        "Failed decoding base64 response body: {}",
                                        e
                                    ))
                                })?;
                            String::from_utf8_lossy(&bytes).to_string()
                        } else {
                            body_str.to_string()
                        };
                        raw_body = Some(decoded);
                        break;
                    }
                    continue;
                }

                // Handle asynchronous CDP Network events
                let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
                match method {
                    "Network.requestWillBeSent" => {
                        let req_id = v
                            .pointer("/params/requestId")
                            .and_then(|s| s.as_str())
                            .unwrap_or("");
                        let req_url = v
                            .pointer("/params/request/url")
                            .and_then(|s| s.as_str())
                            .unwrap_or("");
                        let loader_id = v.pointer("/params/loaderId").and_then(|s| s.as_str());

                        let is_our_request = tracked_request_id.as_deref() == Some(req_id)
                            || (tracked_request_id.is_none()
                                && (req_url.starts_with(provider.url)
                                    || (tracked_loader_id.is_some()
                                        && loader_id == tracked_loader_id.as_deref())));

                        if is_our_request && !req_id.is_empty() {
                            // Check for unexpected cross-origin or non-HTTPS redirects
                            if let Ok(parsed_req_url) = url::Url::parse(req_url) {
                                if parsed_req_url.scheme() != "https"
                                    || !parsed_req_url
                                        .host_str()
                                        .unwrap_or("")
                                        .eq_ignore_ascii_case(provider.host)
                                {
                                    let _ = socket.close(None);
                                    return Err(BrowserVerificationError::CdpSecurityViolation(
                                        format!(
                                            "Verification navigation redirected to unexpected origin '{}'",
                                            req_url
                                        ),
                                    ));
                                }
                            }
                            tracked_request_id = Some(req_id.to_string());
                        }
                    }
                    "Network.responseReceived" => {
                        let req_id = v
                            .pointer("/params/requestId")
                            .and_then(|s| s.as_str())
                            .unwrap_or("");
                        let resp_url = v
                            .pointer("/params/response/url")
                            .and_then(|s| s.as_str())
                            .unwrap_or("");

                        if tracked_request_id.is_none() && resp_url.starts_with(provider.url) {
                            tracked_request_id = Some(req_id.to_string());
                        }

                        if tracked_request_id.as_deref() == Some(req_id) {
                            let from_cache = v
                                .pointer("/params/response/fromDiskCache")
                                .and_then(|b| b.as_bool())
                                .unwrap_or(false)
                                || v.pointer("/params/response/fromServiceWorker")
                                    .and_then(|b| b.as_bool())
                                    .unwrap_or(false);
                            if from_cache {
                                let _ = socket.close(None);
                                return Err(BrowserVerificationError::BrowserRequestFailed(
                                    "Verification response served from cache instead of live network"
                                        .to_string(),
                                ));
                            }

                            if let Ok(parsed_resp_url) = url::Url::parse(resp_url) {
                                if parsed_resp_url.scheme() != "https"
                                    || !parsed_resp_url
                                        .host_str()
                                        .unwrap_or("")
                                        .eq_ignore_ascii_case(provider.host)
                                {
                                    let _ = socket.close(None);
                                    return Err(BrowserVerificationError::CdpSecurityViolation(
                                        format!(
                                            "Verification response URL '{}' does not match expected https://{}",
                                            resp_url, provider.host
                                        ),
                                    ));
                                }
                            }

                            let status = v
                                .pointer("/params/response/status")
                                .and_then(|s| s.as_u64())
                                .unwrap_or(0);
                            if status != 200 {
                                let _ = socket.close(None);
                                return Err(BrowserVerificationError::BrowserRequestFailed(
                                    format!(
                                        "Verification endpoint {} returned HTTP {}",
                                        provider.url, status
                                    ),
                                ));
                            }
                            response_status_ok = true;
                        }
                    }
                    "Network.loadingFailed" => {
                        let req_id = v
                            .pointer("/params/requestId")
                            .and_then(|s| s.as_str())
                            .unwrap_or("");
                        if tracked_request_id.is_none()
                            || tracked_request_id.as_deref() == Some(req_id)
                        {
                            let err_text = v
                                .pointer("/params/errorText")
                                .and_then(|s| s.as_str())
                                .unwrap_or("unknown network error");
                            let _ = socket.close(None);
                            return Err(BrowserVerificationError::BrowserRequestFailed(format!(
                                "Browser navigation to {} failed: {}",
                                provider.url, err_text
                            )));
                        }
                    }
                    "Network.loadingFinished" => {
                        let req_id = v
                            .pointer("/params/requestId")
                            .and_then(|s| s.as_str())
                            .unwrap_or("");
                        if tracked_request_id.as_deref() == Some(req_id) && !sent_get_body {
                            if !response_status_ok {
                                let _ = socket.close(None);
                                return Err(BrowserVerificationError::BrowserRequestFailed(
                                    "Network.loadingFinished received without valid HTTP 200 response"
                                        .to_string(),
                                ));
                            }
                            sent_get_body = true;
                            let get_body_cmd = serde_json::json!({
                                "id": 5,
                                "method": "Network.getResponseBody",
                                "params": { "requestId": req_id }
                            });
                            if let Err(e) = socket
                                .send(tungstenite::Message::Text(get_body_cmd.to_string().into()))
                            {
                                let _ = socket.close(None);
                                return Err(BrowserVerificationError::CdpConnectionFailed(
                                    format!("Failed sending Network.getResponseBody: {}", e),
                                ));
                            }
                        }
                    }
                    _ => {}
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

    let body = raw_body.ok_or(BrowserVerificationError::VerificationTimeout)?;
    let req_id = tracked_request_id.unwrap_or_else(|| "sim-req-1".to_string());
    Ok((body, req_id, latency_ms))
}

/// Performs real browser-origin verification via Chrome DevTools Protocol.
///
/// # Security & Isolation
///
/// - Binds strictly to `127.0.0.1:<ephemeral>` (loopback only, never exposed to external network).
/// - Creates a dedicated blank tab via `PUT /json/new?about:blank` and closes it via RAII `CdpTargetGuard`.
/// - Navigates the dedicated tab via `Page.navigate` + `Network.*` (no CORS-blocked `fetch()` on `about:blank`).
/// - Validates observed egress IP and country strictly.
/// - Correlates with unambiguous fresh local proxy bridge `HTTP_CONNECT`/`SOCKS5_CONNECT` tunnel events.
pub fn attempt_cdp_browser_verification(
    session: &BrowserSessionInfo,
    debug_port: u16,
    bridge_mgr: Option<&crate::services::proxy_bridge::ProxyBridgeManager>,
) -> Result<BrowserVerificationEvidence, BrowserVerificationError> {
    if session.pid == 0 || !is_process_alive(session.pid) {
        return Err(BrowserVerificationError::SessionMismatch);
    }
    if session.profile_path.trim().is_empty() || session.session_id.trim().is_empty() {
        return Err(BrowserVerificationError::SessionMismatch);
    }
    if debug_port == 0 {
        return Err(BrowserVerificationError::CdpNotAvailable(
            "CDP port cannot be 0".to_string(),
        ));
    }
    if let Some(expected_cdp_port) = session.cdp_port {
        if expected_cdp_port != debug_port {
            return Err(BrowserVerificationError::SessionMismatch);
        }
    }
    if let Some((active_port, _)) =
        crate::services::profile_service::SystemBrowserLauncher::parse_devtools_active_port(
            std::path::Path::new(&session.profile_path),
        )
    {
        if active_port != debug_port {
            return Err(BrowserVerificationError::SessionMismatch);
        }
    }

    let connect_timeout = Duration::from_millis(3000);
    let op_timeout = Duration::from_millis(8000);
    let verification_start = Utc::now();

    // 1. Create a dedicated blank target via PUT /json/new?about:blank
    let created_target = create_cdp_blank_target_full(debug_port, connect_timeout)?;
    let new_target_id = created_target.id.clone();
    let mut target_guard = CdpTargetGuard::new(debug_port, new_target_id.clone(), connect_timeout);

    // 2. Fetch target list and verify all targets use loopback ws:// URLs
    let targets = fetch_cdp_targets(debug_port, connect_timeout)?;
    for t in &targets {
        if let Some(ref u) = t.websocket_debugger_url {
            validate_loopback_ws_url(u, debug_port)?;
        }
    }

    // Find our dedicated target by ID — never fall back to user's social media tabs
    let ws_url = targets
        .iter()
        .find(|t| t.id == new_target_id && t.websocket_debugger_url.is_some())
        .and_then(|t| t.websocket_debugger_url.clone())
        .or(created_target.websocket_debugger_url)
        .ok_or_else(|| {
            BrowserVerificationError::CdpNotAvailable(format!(
                "Dedicated blank target '{}' not found in CDP target list after creation",
                new_target_id
            ))
        })?;

    // 3. Navigate dedicated target to primary verification provider (or fallback if primary fails)
    let mut active_provider = &PRIMARY_VERIFICATION_PROVIDER;
    let (resp_str, _cdp_req_id, latency_ms) = match navigate_cdp_target_and_read_body(
        &ws_url,
        debug_port,
        active_provider,
        connect_timeout,
        op_timeout,
        session.is_simulation,
    ) {
        Ok(res) => res,
        Err(primary_err) => {
            if session.is_simulation {
                return Err(primary_err);
            }
            active_provider = &FALLBACK_VERIFICATION_PROVIDER;
            navigate_cdp_target_and_read_body(
                &ws_url,
                debug_port,
                active_provider,
                connect_timeout,
                op_timeout,
                false,
            )
            .map_err(|fallback_err| {
                BrowserVerificationError::BrowserRequestFailed(format!(
                    "Primary provider ({}) failed: {}; Fallback provider ({}) failed: {}",
                    PRIMARY_VERIFICATION_PROVIDER.name,
                    primary_err,
                    FALLBACK_VERIFICATION_PROVIDER.name,
                    fallback_err
                ))
            })?
        }
    };

    // 4. Parse provider JSON body
    let parsed: serde_json::Value = serde_json::from_str(resp_str.trim()).map_err(|e| {
        BrowserVerificationError::ResponseParseError(format!(
            "Malformed JSON response from browser navigation ({}): {}",
            active_provider.name, e
        ))
    })?;

    if let Some(err_val) = parsed.get("error").and_then(|e| e.as_str()) {
        return Err(BrowserVerificationError::BrowserRequestFailed(format!(
            "Browser-origin provider returned error: {}",
            err_val
        )));
    }
    if parsed.get("success").and_then(|b| b.as_bool()) == Some(false) {
        let msg = parsed
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("geolocation lookup failed");
        return Err(BrowserVerificationError::BrowserRequestFailed(format!(
            "Provider {} reported success=false: {}",
            active_provider.name, msg
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

    // Never invent a country if the provider does not supply one
    let observed_country_opt: Option<String> = if active_provider.supplies_country {
        parsed
            .get("country_code")
            .or_else(|| parsed.get("country"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    } else {
        None
    };
    let observed_country_for_eval = observed_country_opt
        .clone()
        .unwrap_or_else(|| "UNKNOWN".to_string());

    // 5 & 6. Strict IP and Country validation via shared pure decision helper
    validate_observed_egress_ip_and_country(
        &observed_ip,
        observed_country_opt.as_deref(),
        &observed_country_for_eval,
        session.expected_ip.as_deref(),
        session.expected_country.as_deref(),
        active_provider.name,
        session.is_simulation,
    )?;

    // 7. In live mode, verify OS process + profile + CDP port ownership
    if !session.is_simulation {
        verify_managed_cdp_ownership(session, debug_port, connect_timeout)?;
    }

    // 8. Unambiguous request-level correlation with proxy bridge CONNECT telemetry
    // Uses the ACTUAL provider host & port (never hardcoded to ipwho.is when fallback is used)
    let proxy_path_confirmed = if let (Some(mgr), Some(ref inst_id)) =
        (bridge_mgr, &session.bridge_instance_id)
    {
        match mgr.correlate_connect_tunnel(
            inst_id,
            &session.environment_id,
            &session.proxy_endpoint_id,
            active_provider.host,
            active_provider.port,
            verification_start,
            Some(Utc::now()),
        ) {
            crate::services::proxy_bridge::BridgeCorrelationOutcome::Confirmed(_) => true,
            crate::services::proxy_bridge::BridgeCorrelationOutcome::NoMatchingTunnel => {
                return Err(BrowserVerificationError::ProxyBridgeMismatch(format!(
                        "Proxy tunnel correlation failed: no fresh HTTP_CONNECT/SOCKS5_CONNECT event to {}:{} on bridge instance {}",
                        active_provider.host, active_provider.port, inst_id
                    )));
            }
            crate::services::proxy_bridge::BridgeCorrelationOutcome::ZeroBytesTransferred(_) => {
                return Err(BrowserVerificationError::ProxyBridgeMismatch(format!(
                    "Proxy tunnel correlation failed: CONNECT tunnel to {}:{} transferred 0 bytes",
                    active_provider.host, active_provider.port
                )));
            }
            crate::services::proxy_bridge::BridgeCorrelationOutcome::AmbiguousConcurrentTunnels(
                count,
            ) => {
                return Err(BrowserVerificationError::ProxyBridgeMismatch(format!(
                        "Proxy tunnel correlation failed: ambiguous {} concurrent CONNECT tunnels to {}:{} during verification window",
                        count, active_provider.host, active_provider.port
                    )));
            }
        }
    } else if session.is_simulation {
        session.recent_bridge_connection_count > 0
    } else {
        false
    };

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
        "CDP_PAGE_NAVIGATE".to_string()
    };

    // Explicitly close the dedicated target before returning
    target_guard.close_now();

    Ok(BrowserVerificationEvidence {
        verification_id,
        environment_id: session.environment_id.clone(),
        browser_session_id: session.session_id.clone(),
        browser_pid: session.pid,
        profile_path: session.profile_path.clone(),
        verification_token: token,
        verification_url: active_provider.url.to_string(),
        token_received: true,
        observed_public_ip: Some(observed_ip.clone()),
        observed_country: Some(observed_country_for_eval.clone()),
        proxy_endpoint_id: session.proxy_endpoint_id.clone(),
        bridge_instance_id: session.bridge_instance_id.clone(),
        verification_source,
        verified_at: Utc::now().to_rfc3339(),
        latency_ms: Some(latency_ms),
        proxy_path_confirmed: true,
        status: VerificationStatus::BrowserEgressVerified.as_str().to_string(),
        message: format!(
            "Microsoft Edge session (PID {}) verified via CDP ({}): observed external egress IP {} ({}) matching assigned proxy route.",
            session.pid, active_provider.name, observed_ip, observed_country_for_eval
        ),
    })
}

/// Shared pure decision function validating observed egress IP and country for both
/// live CDP verification and deterministic replay evaluation.
#[allow(clippy::too_many_arguments)]
pub fn validate_observed_egress_ip_and_country(
    observed_ip: &str,
    observed_country_opt: Option<&str>,
    observed_country_for_eval: &str,
    expected_ip: Option<&str>,
    expected_country: Option<&str>,
    provider_name: &str,
    is_simulation: bool,
) -> Result<(), BrowserVerificationError> {
    if !crate::services::network_service::NetworkService::is_valid_ip_address(observed_ip) {
        return Err(BrowserVerificationError::IpMismatch(format!(
            "Browser returned syntactically invalid IP: '{}'",
            observed_ip
        )));
    }

    if !is_simulation && !is_globally_routable_ip(observed_ip) {
        return Err(BrowserVerificationError::IpNotGloballyRoutable(format!(
            "Observed IP '{}' is not globally routable (private, documentation, or local range)",
            observed_ip
        )));
    }

    if let Some(exp_ip) = expected_ip {
        if observed_ip != exp_ip {
            return Err(BrowserVerificationError::IpMismatch(format!(
                "Expected IP '{}', observed '{}'",
                exp_ip, observed_ip
            )));
        }
    }

    if let Some(exp_c) = expected_country {
        if let Err(e) = crate::services::network_service::NetworkService::evaluate_country_match(
            observed_country_for_eval,
            Some(exp_c),
        ) {
            return Err(BrowserVerificationError::CountryMismatch(e));
        }
    } else if !is_simulation
        && (observed_country_opt.is_none()
            || observed_country_for_eval.eq_ignore_ascii_case("UNKNOWN"))
    {
        return Err(BrowserVerificationError::CountryMismatch(format!(
            "Provider '{}' did not supply a verified country code",
            provider_name
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Synthetic Replay Corpus & Honest Historical Backtest Gate (Phase 4 & 5)
// ---------------------------------------------------------------------------

/// A single frozen verification trace case for deterministic synthetic replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayTraceCase {
    pub case_id: String,
    pub split: String,
    pub category: String,
    pub description: String,
    pub session_pid_alive: bool,
    pub session_ownership_verified: bool,
    pub profile_path: String,
    pub cdp_new_target_method: String,
    pub cdp_new_target_status: u16,
    pub cdp_navigation_succeeded: bool,
    #[serde(default)]
    pub from_cache: bool,
    #[serde(default)]
    pub redirected_to_non_https: bool,
    #[serde(default)]
    pub environment_id: Option<String>,
    pub provider_name: String,
    pub provider_host: String,
    pub provider_port: u16,
    pub observed_ip: Option<String>,
    pub observed_country: Option<String>,
    pub expected_country: Option<String>,
    pub expected_ip: Option<String>,
    pub bridge_instance_id: Option<String>,
    pub proxy_endpoint_id: String,
    pub verification_started_at: String,
    pub verification_ended_at: String,
    pub bridge_events: Vec<crate::services::proxy_bridge::BridgeConnectionEvent>,
    pub expected_status: String,
    pub expected_reason_substring: String,
}

/// Summary metrics and confusion matrix for a replay corpus split (`DEV`, `HOLDOUT`, or `ADVERSARIAL_HOLDOUT`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayCorpusSummary {
    pub split: String,
    pub corpus_classification: String,
    pub total_cases: usize,
    pub exact_status_matches: usize,
    pub reason_matches: usize,
    pub true_positive_browser_verified: usize,
    pub true_negative_rejected: usize,
    pub false_positive_browser_verified: usize,
    pub false_negative_browser_verified: usize,
    pub failures: Vec<String>,
}

/// Honest assessment of genuine historical network backtest evidence vs. synthetic replay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoricalBacktestReport {
    pub classification: String,
    pub status: String,
    pub reason: String,
    pub synthetic_replay_conflated: bool,
}

/// Evaluates whether a genuine pre-recorded historical network capture corpus exists.
/// Never conflates synthetic JSONL decision replay with a real historical network backtest.
pub fn evaluate_historical_backtest_honesty(
    historical_capture_path: Option<&std::path::Path>,
) -> HistoricalBacktestReport {
    match historical_capture_path {
        Some(p) if p.exists() && p.is_file() => HistoricalBacktestReport {
            classification: "HISTORICAL_BACKTEST".to_string(),
            status: "PASS".to_string(),
            reason: format!("Verified historical capture corpus at {}", p.display()),
            synthetic_replay_conflated: false,
        },
        _ => HistoricalBacktestReport {
            classification: "HISTORICAL_BACKTEST".to_string(),
            status: "INSUFFICIENT_HISTORICAL_EVIDENCE".to_string(),
            reason: "No genuine pre-existing historical network packet/session capture archive is present in the repository; synthetic JSONL traces are classified strictly as SYNTHETIC_REPLAY_CORPUS.".to_string(),
            synthetic_replay_conflated: false,
        },
    }
}

/// Deterministically evaluate a single `ReplayTraceCase` through the shared verification decision pipeline.
pub fn evaluate_replay_trace_case(case: &ReplayTraceCase) -> (String, String) {
    if !case.session_pid_alive {
        return (
            "VERIFICATION_UNAVAILABLE".to_string(),
            "SessionMismatch: browser PID is not alive".to_string(),
        );
    }
    if case.profile_path.trim().is_empty() || !case.session_ownership_verified {
        return (
            "VERIFICATION_UNAVAILABLE".to_string(),
            "SessionMismatch: managed Edge profile/CDP ownership unverified".to_string(),
        );
    }
    if case.cdp_new_target_method != "PUT" || case.cdp_new_target_status != 200 {
        return (
            "PROXY_EGRESS_VERIFIED".to_string(),
            format!(
                "CdpTargetCreationFailed: {} /json/new returned HTTP {}",
                case.cdp_new_target_method, case.cdp_new_target_status
            ),
        );
    }
    if case.redirected_to_non_https {
        return (
            "PROXY_EGRESS_VERIFIED".to_string(),
            "CdpSecurityViolation: verification navigation redirected to non-HTTPS or unexpected origin".to_string(),
        );
    }
    if case.from_cache {
        return (
            "PROXY_EGRESS_VERIFIED".to_string(),
            "BrowserRequestFailed: verification response served from cache instead of live network"
                .to_string(),
        );
    }
    if !case.cdp_navigation_succeeded {
        return (
            "PROXY_EGRESS_VERIFIED".to_string(),
            "BrowserRequestFailed: CDP Page.navigate failed".to_string(),
        );
    }

    let ip = match case.observed_ip.as_deref() {
        Some(s) if !s.trim().is_empty() => s.trim(),
        _ => {
            return (
                "CONNECTION_FAILED".to_string(),
                "ResponseParseError: missing observed IP".to_string(),
            );
        }
    };

    let country_opt = if case.provider_name == "api.ipify.org" {
        None
    } else {
        case.observed_country
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
    };
    let country_str = country_opt.unwrap_or("UNKNOWN");

    if let Err(err) = validate_observed_egress_ip_and_country(
        ip,
        country_opt,
        country_str,
        case.expected_ip.as_deref(),
        case.expected_country.as_deref(),
        &case.provider_name,
        false,
    ) {
        let reason = match err {
            BrowserVerificationError::IpMismatch(m) => format!("IpMismatch: {}", m),
            BrowserVerificationError::IpNotGloballyRoutable(m) => {
                format!("IpNotGloballyRoutable: {}", m)
            }
            BrowserVerificationError::CountryMismatch(m) => format!("CountryMismatch: {}", m),
            other => other.to_string(),
        };
        return ("CONNECTION_FAILED".to_string(), reason);
    }

    let inst_id = match case.bridge_instance_id.as_deref() {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            return (
                "PROXY_EGRESS_VERIFIED".to_string(),
                "ProxyBridgeMismatch: missing bridge_instance_id".to_string(),
            );
        }
    };

    let start_ts = match case
        .verification_started_at
        .parse::<chrono::DateTime<Utc>>()
    {
        Ok(t) => t,
        Err(_) => {
            return (
                "PROXY_EGRESS_VERIFIED".to_string(),
                "ProxyBridgeMismatch: invalid verification_started_at".to_string(),
            );
        }
    };
    let end_ts = case
        .verification_ended_at
        .parse::<chrono::DateTime<Utc>>()
        .ok();

    let telemetry = crate::services::proxy_bridge::BridgeTelemetry::new(100);
    for ev in &case.bridge_events {
        telemetry.record_event(ev.clone());
    }

    let expected_env_id = case.environment_id.as_deref().unwrap_or("env-replay");

    match telemetry.correlate_connect_tunnel(
        inst_id,
        expected_env_id,
        &case.proxy_endpoint_id,
        &case.provider_host,
        case.provider_port,
        start_ts,
        end_ts,
    ) {
        crate::services::proxy_bridge::BridgeCorrelationOutcome::Confirmed(ev) => {
            let evidence = BrowserVerificationEvidence {
                verification_id: format!("replay-{}", case.case_id),
                environment_id: expected_env_id.to_string(),
                browser_session_id: "sess-replay".to_string(),
                browser_pid: std::process::id(),
                profile_path: case.profile_path.clone(),
                verification_token: "tok-replay".to_string(),
                verification_url: format!("https://{}/", case.provider_host),
                token_received: true,
                observed_public_ip: Some(ip.to_string()),
                observed_country: Some(country_str.to_string()),
                proxy_endpoint_id: case.proxy_endpoint_id.clone(),
                bridge_instance_id: Some(inst_id.to_string()),
                verification_source: "CDP_PAGE_NAVIGATE".to_string(),
                verified_at: Utc::now().to_rfc3339(),
                latency_ms: ev.latency_ms,
                proxy_path_confirmed: true,
                status: "BROWSER_EGRESS_VERIFIED".to_string(),
                message: format!("Correlated via tunnel event {}", ev.event_id),
            };
            match evaluate_verification_decision(&evidence) {
                Ok(()) => ("BROWSER_EGRESS_VERIFIED".to_string(), evidence.message),
                Err(reason) => (
                    "PROXY_EGRESS_VERIFIED".to_string(),
                    format!("DecisionGateRejected: {}", reason),
                ),
            }
        }
        crate::services::proxy_bridge::BridgeCorrelationOutcome::NoMatchingTunnel => (
            "PROXY_EGRESS_VERIFIED".to_string(),
            "ProxyBridgeMismatch: no matching CONNECT tunnel".to_string(),
        ),
        crate::services::proxy_bridge::BridgeCorrelationOutcome::ZeroBytesTransferred(_) => (
            "PROXY_EGRESS_VERIFIED".to_string(),
            "ProxyBridgeMismatch: zero bytes transferred".to_string(),
        ),
        crate::services::proxy_bridge::BridgeCorrelationOutcome::AmbiguousConcurrentTunnels(n) => (
            "PROXY_EGRESS_VERIFIED".to_string(),
            format!("ProxyBridgeMismatch: ambiguous {} concurrent tunnels", n),
        ),
    }
}

/// Parse and evaluate a JSONL replay corpus, returning a `ReplayCorpusSummary`.
pub fn run_replay_corpus(split_name: &str, jsonl_content: &str) -> ReplayCorpusSummary {
    let mut summary = ReplayCorpusSummary {
        split: split_name.to_string(),
        corpus_classification: "SYNTHETIC_REPLAY_CORPUS".to_string(),
        total_cases: 0,
        exact_status_matches: 0,
        reason_matches: 0,
        true_positive_browser_verified: 0,
        true_negative_rejected: 0,
        false_positive_browser_verified: 0,
        false_negative_browser_verified: 0,
        failures: Vec::new(),
    };

    for (line_idx, raw_line) in jsonl_content.lines().enumerate() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let case: ReplayTraceCase = match serde_json::from_str(trimmed) {
            Ok(c) => c,
            Err(e) => {
                summary
                    .failures
                    .push(format!("Line {}: JSON parse error: {}", line_idx + 1, e));
                continue;
            }
        };
        summary.total_cases += 1;

        let (actual_status, actual_reason) = evaluate_replay_trace_case(&case);
        let expected_is_bv = case.expected_status == "BROWSER_EGRESS_VERIFIED";
        let actual_is_bv = actual_status == "BROWSER_EGRESS_VERIFIED";

        match (expected_is_bv, actual_is_bv) {
            (true, true) => summary.true_positive_browser_verified += 1,
            (false, false) => summary.true_negative_rejected += 1,
            (false, true) => summary.false_positive_browser_verified += 1,
            (true, false) => summary.false_negative_browser_verified += 1,
        }

        let status_ok = actual_status == case.expected_status;
        let reason_ok = actual_reason
            .to_ascii_lowercase()
            .contains(&case.expected_reason_substring.to_ascii_lowercase());

        if status_ok {
            summary.exact_status_matches += 1;
        }
        if reason_ok {
            summary.reason_matches += 1;
        }
        if !status_ok || !reason_ok {
            summary.failures.push(format!(
                "Case {} ({}): expected status='{}' reason~='{}', got status='{}' reason='{}'",
                case.case_id,
                case.description,
                case.expected_status,
                case.expected_reason_substring,
                actual_status,
                actual_reason
            ));
        }
    }

    summary
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

    fn read_http_req_until_end(stream: &mut TcpStream) -> String {
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .ok();
        let mut acc = Vec::with_capacity(512);
        let mut chunk = [0u8; 512];
        while acc.len() < 4096 {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    acc.extend_from_slice(&chunk[..n]);
                    if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&acc).to_string()
    }

    fn finish_http_mock_response(stream: &mut TcpStream, resp: &[u8]) {
        let _ = stream.write_all(resp);
        let _ = stream.flush();
        let _ = stream.shutdown(std::net::Shutdown::Write);
        stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .ok();
        let mut drain = [0u8; 128];
        let _ = stream.read(&mut drain);
    }

    #[test]
    fn test_cdp_security_violation_when_non_loopback_ws() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let target_id = "target-nonloopback";
        let ws_url_bad = format!("ws://192.168.1.100:{}/devtools/page/{}", port, target_id);
        let new_body = format!(
            r#"{{"id":"{}","type":"page","title":"","url":"about:blank","webSocketDebuggerUrl":"{}"}}"#,
            target_id, ws_url_bad
        );
        let list_body = format!(
            r#"[{{"id":"{}","type":"page","title":"","url":"about:blank","webSocketDebuggerUrl":"{}"}}]"#,
            target_id, ws_url_bad
        );

        std::thread::spawn(move || {
            for _ in 0..3 {
                if let Ok((mut stream, _)) = listener.accept() {
                    let req = read_http_req_until_end(&mut stream);
                    if req.starts_with("PUT /json/new") {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            new_body.len(), new_body
                        );
                        finish_http_mock_response(&mut stream, resp.as_bytes());
                    } else if req.starts_with("GET /json/new") {
                        let msg = "Using unsafe HTTP verb GET to invoke /json/new. This action supports only PUT verb.";
                        let resp = format!(
                            "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            msg.len(), msg
                        );
                        finish_http_mock_response(&mut stream, resp.as_bytes());
                    } else if req.starts_with("GET /json/list") {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            list_body.len(), list_body
                        );
                        finish_http_mock_response(&mut stream, resp.as_bytes());
                    } else if req.starts_with("GET /json/close") {
                        finish_http_mock_response(
                            &mut stream,
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                        );
                    }
                }
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

    /// Helper: spawn a realistic mock Chromium/Edge CDP server that:
    /// - Rejects `GET /json/new` with HTTP 405 Method Not Allowed (matching real Edge 157+)
    /// - Accepts `PUT /json/new?about:blank` with HTTP 200 and a `CdpTarget` JSON object
    /// - Serves `GET /json/list` and `GET /json/close/{id}`
    /// - Handles `Page.enable`, `Network.enable`, `Network.setCacheDisabled`, `Page.navigate`,
    ///   emits `Network.requestWillBeSent`, `Network.responseReceived`, `Network.loadingFinished`,
    ///   and responds to `Network.getResponseBody`.
    fn spawn_mock_cdp_server(
        listener: TcpListener,
        target_id: &'static str,
        ws_country_code: &'static str,
        ws_ip: &'static str,
    ) {
        spawn_mock_cdp_server_with_close_tracker(listener, target_id, ws_country_code, ws_ip, None);
    }

    fn spawn_mock_cdp_server_with_close_tracker(
        listener: TcpListener,
        target_id: &'static str,
        ws_country_code: &'static str,
        ws_ip: &'static str,
        close_tracker: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) {
        let port = listener.local_addr().unwrap().port();
        let ws_path = format!("/devtools/page/{}", target_id);
        let ws_url = format!("ws://127.0.0.1:{}{}", port, ws_path);

        std::thread::spawn(move || {
            for _ in 0..8 {
                if let Ok((mut stream, _)) = listener.accept() {
                    stream
                        .set_read_timeout(Some(Duration::from_millis(1000)))
                        .ok();
                    let mut peek_buf = [0u8; 512];
                    let peeked = match stream.peek(&mut peek_buf) {
                        Ok(n) if n > 0 => n,
                        _ => continue,
                    };
                    let peek_str = String::from_utf8_lossy(&peek_buf[..peeked]);

                    if peek_str.starts_with("PUT /json/new") {
                        let _ = read_http_req_until_end(&mut stream);
                        let body = format!(
                            r#"{{"id":"{}","type":"page","title":"","url":"about:blank","webSocketDebuggerUrl":"{}"}}"#,
                            target_id, ws_url
                        );
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        finish_http_mock_response(&mut stream, resp.as_bytes());
                    } else if peek_str.starts_with("GET /json/new") {
                        let _ = read_http_req_until_end(&mut stream);
                        let msg = "Using unsafe HTTP verb GET to invoke /json/new. This action supports only PUT verb.";
                        let resp = format!(
                            "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            msg.len(),
                            msg
                        );
                        finish_http_mock_response(&mut stream, resp.as_bytes());
                    } else if peek_str.starts_with("GET /json/list") {
                        let _ = read_http_req_until_end(&mut stream);
                        let body = format!(
                            r#"[{{"id":"{}","type":"page","title":"","url":"about:blank","webSocketDebuggerUrl":"{}"}}]"#,
                            target_id, ws_url
                        );
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        finish_http_mock_response(&mut stream, resp.as_bytes());
                    } else if peek_str.starts_with("GET /json/close") {
                        let _ = read_http_req_until_end(&mut stream);
                        if let Some(ref tracker) = close_tracker {
                            tracker.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                        finish_http_mock_response(
                            &mut stream,
                            b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\nTarget is closing",
                        );
                    } else if peek_str.contains("Upgrade: websocket")
                        || (peek_str.starts_with("GET") && peek_str.contains(ws_path.as_str()))
                    {
                        let mut ws = match tungstenite::accept(stream) {
                            Ok(ws) => ws,
                            Err(_) => continue,
                        };
                        while let Ok(tungstenite::Message::Text(txt)) = ws.read() {
                            let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) else {
                                continue;
                            };
                            let id = v.get("id").and_then(|i| i.as_i64()).unwrap_or(0);
                            let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
                            match method {
                                "Page.enable" | "Network.enable" | "Network.setCacheDisabled" => {
                                    let ack = serde_json::json!({ "id": id, "result": {} });
                                    let _ =
                                        ws.send(tungstenite::Message::Text(ack.to_string().into()));
                                }
                                "Page.navigate" => {
                                    let nav_url = v
                                        .pointer("/params/url")
                                        .and_then(|u| u.as_str())
                                        .unwrap_or("https://ipwho.is/");
                                    let nav_ack = serde_json::json!({
                                        "id": id,
                                        "result": {
                                            "frameId": target_id,
                                            "loaderId": "loader-1"
                                        }
                                    });
                                    let _ = ws.send(tungstenite::Message::Text(
                                        nav_ack.to_string().into(),
                                    ));

                                    let req_evt = serde_json::json!({
                                        "method": "Network.requestWillBeSent",
                                        "params": {
                                            "requestId": "req-nav-1",
                                            "loaderId": "loader-1",
                                            "type": "Document",
                                            "request": { "url": nav_url, "method": "GET" }
                                        }
                                    });
                                    let _ = ws.send(tungstenite::Message::Text(
                                        req_evt.to_string().into(),
                                    ));

                                    let resp_evt = serde_json::json!({
                                        "method": "Network.responseReceived",
                                        "params": {
                                            "requestId": "req-nav-1",
                                            "loaderId": "loader-1",
                                            "type": "Document",
                                            "response": {
                                                "url": nav_url,
                                                "status": 200,
                                                "fromDiskCache": false,
                                                "fromServiceWorker": false
                                            }
                                        }
                                    });
                                    let _ = ws.send(tungstenite::Message::Text(
                                        resp_evt.to_string().into(),
                                    ));

                                    let fin_evt = serde_json::json!({
                                        "method": "Network.loadingFinished",
                                        "params": {
                                            "requestId": "req-nav-1",
                                            "encodedDataLength": 180
                                        }
                                    });
                                    let _ = ws.send(tungstenite::Message::Text(
                                        fin_evt.to_string().into(),
                                    ));
                                }
                                "Network.getResponseBody" => {
                                    let body_json = serde_json::json!({
                                        "ip": ws_ip,
                                        "country_code": ws_country_code,
                                        "country": "Test Country",
                                        "success": true
                                    })
                                    .to_string();
                                    let body_resp = serde_json::json!({
                                        "id": id,
                                        "result": {
                                            "body": body_json,
                                            "base64Encoded": false
                                        }
                                    });
                                    let _ = ws.send(tungstenite::Message::Text(
                                        body_resp.to_string().into(),
                                    ));
                                    let _ = ws.flush();
                                    ws.get_mut()
                                        .set_read_timeout(Some(Duration::from_millis(100)))
                                        .ok();
                                    let _ = ws.read();
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        });
    }

    #[test]
    fn test_cdp_mock_verification_success() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        spawn_mock_cdp_server(listener, "target-success", "US", "198.51.100.25");
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
        spawn_mock_cdp_server(listener, "target-mismatch", "VN", "198.51.100.25");
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
        spawn_mock_cdp_server(listener, "target-no-bridge", "US", "64.233.160.1");
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
        spawn_mock_cdp_server(
            listener,
            "target-unknown-country",
            "UNKNOWN",
            "64.233.160.1",
        );
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
        spawn_mock_cdp_server(listener, "target-doc-ip", "US", "198.51.100.25");
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

    /// Verifies that `create_cdp_blank_target` sends a `PUT /json/new?about:blank` request
    /// and never uses the unsafe `GET /json/new` verb rejected by modern Chromium/Edge.
    #[test]
    fn test_cdp_target_creation_sends_put_request() {
        use std::sync::{Arc, Mutex};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let received_request: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let received_clone = Arc::clone(&received_request);

        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let req = read_http_req_until_end(&mut stream);
                *received_clone.lock().unwrap() = Some(req.clone());

                if req.starts_with("PUT /json/new?about:blank") {
                    let body = format!(
                        r#"{{"id":"fake-target-id","type":"page","title":"","url":"about:blank","webSocketDebuggerUrl":"ws://127.0.0.1:{}/devtools/page/fake-target-id"}}"#,
                        port
                    );
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    finish_http_mock_response(&mut stream, resp.as_bytes());
                } else {
                    let msg = "Using unsafe HTTP verb GET to invoke /json/new. This action supports only PUT verb.";
                    let resp = format!(
                        "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        msg.len(),
                        msg
                    );
                    finish_http_mock_response(&mut stream, resp.as_bytes());
                }
            }
        });

        std::thread::sleep(Duration::from_millis(50));

        let timeout = Duration::from_millis(500);
        let created_id =
            create_cdp_blank_target(port, timeout).expect("PUT /json/new should succeed");
        assert_eq!(created_id, "fake-target-id");

        let req = received_request.lock().unwrap();
        assert!(
            req.as_deref()
                .unwrap_or("")
                .starts_with("PUT /json/new?about:blank"),
            "Expected PUT /json/new?about:blank in request, got: {:?}",
            req
        );
    }

    /// Verifies that HTTP 405 or non-200 on `/json/new` returns a typed `CdpTargetCreationFailed` error.
    #[test]
    fn test_cdp_target_creation_rejects_405_and_malformed_target() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = read_http_req_until_end(&mut stream);
                let msg = "Method Not Allowed";
                let resp = format!(
                    "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    msg.len(),
                    msg
                );
                finish_http_mock_response(&mut stream, resp.as_bytes());
            }
        });

        std::thread::sleep(Duration::from_millis(30));
        let err = create_cdp_blank_target(port, Duration::from_millis(500)).unwrap_err();
        match err {
            BrowserVerificationError::CdpTargetCreationFailed(msg) => {
                assert!(
                    msg.contains("405"),
                    "Expected 405 in error message: {}",
                    msg
                );
            }
            other => panic!("Expected CdpTargetCreationFailed, got {:?}", other),
        }
    }

    /// Verifies that `close_cdp_target` sends a `GET /json/close/{id}` request and rejects unsafe IDs.
    #[test]
    fn test_cdp_cleanup_sends_close_request() {
        use std::sync::{Arc, Mutex};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let received_request: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let received_clone = Arc::clone(&received_request);

        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let req = read_http_req_until_end(&mut stream);
                *received_clone.lock().unwrap() = Some(req);
                let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
                finish_http_mock_response(&mut stream, resp);
            }
        });

        std::thread::sleep(Duration::from_millis(50));

        let timeout = Duration::from_millis(500);
        // Unsafe target ID with path traversal must be ignored without connecting
        close_cdp_target(port, "../evil\r\nHeader:1", timeout);
        assert!(received_request.lock().unwrap().is_none());

        close_cdp_target(port, "test-target-abc", timeout);

        std::thread::sleep(Duration::from_millis(100));
        let req = received_request.lock().unwrap();
        assert!(
            req.as_deref()
                .unwrap_or("")
                .contains("GET /json/close/test-target-abc"),
            "Expected GET /json/close/test-target-abc in request, got: {:?}",
            req
        );
    }

    /// Verifies that after a CDP session, the target close endpoint is called via RAII guard.
    #[test]
    fn test_cdp_cleanup_closes_target_on_success() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let close_called = Arc::new(AtomicBool::new(false));
        let close_clone = Arc::clone(&close_called);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        spawn_mock_cdp_server_with_close_tracker(
            listener,
            "cleanup-test-target-1",
            "US",
            "198.51.100.25",
            Some(close_clone),
        );

        std::thread::sleep(Duration::from_millis(100));

        let session = BrowserSessionInfo {
            environment_id: "env-cleanup".to_string(),
            session_id: "sess-cleanup".to_string(),
            pid: std::process::id(),
            profile_path: "/tmp/cleanup-profile".to_string(),
            proxy_bridge_port: Some(49200),
            proxy_endpoint_id: "ep-001".to_string(),
            bridge_instance_id: None,
            expected_country: Some("US".to_string()),
            expected_ip: Some("198.51.100.25".to_string()),
            recent_bridge_connection_count: 3,
            cdp_port: Some(port),
            is_simulation: true,
        };

        let result = attempt_cdp_browser_verification(&session, port, None);
        assert!(result.is_ok());

        std::thread::sleep(Duration::from_millis(100));
        assert!(
            close_called.load(Ordering::SeqCst),
            "Expected /json/close to be called after CDP session"
        );
    }

    #[test]
    fn test_session_ownership_rejects_empty_profile_or_port_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let devtools_path = temp.path().join("DevToolsActivePort");
        std::fs::write(&devtools_path, "9222\n/devtools/browser/abc-123\n").unwrap();

        // Empty profile_path must fail with SessionMismatch
        let mut session = BrowserSessionInfo {
            environment_id: "env-own".to_string(),
            session_id: "sess-own".to_string(),
            pid: std::process::id(),
            profile_path: String::new(),
            proxy_bridge_port: Some(49200),
            proxy_endpoint_id: "ep-001".to_string(),
            bridge_instance_id: Some("br-1".to_string()),
            expected_country: Some("US".to_string()),
            expected_ip: None,
            recent_bridge_connection_count: 1,
            cdp_port: Some(9222),
            is_simulation: true,
        };
        assert_eq!(
            verify_managed_cdp_ownership(&session, 9222, Duration::from_millis(500)),
            Err(BrowserVerificationError::SessionMismatch)
        );

        // DevToolsActivePort mismatch (9222 in file vs 9333 requested) must fail
        session.profile_path = temp.path().to_string_lossy().to_string();
        session.cdp_port = Some(9333);
        assert_eq!(
            verify_managed_cdp_ownership(&session, 9333, Duration::from_millis(500)),
            Err(BrowserVerificationError::SessionMismatch)
        );

        // Matching DevToolsActivePort (9222) succeeds in simulation mode
        session.cdp_port = Some(9222);
        assert!(verify_managed_cdp_ownership(&session, 9222, Duration::from_millis(500)).is_ok());
    }

    #[test]
    fn test_v8_replay_corpus_dev_and_holdout() {
        let dev_jsonl = include_str!("../../tests/fixtures/v8_replay_dev.jsonl");
        let holdout_jsonl = include_str!("../../tests/fixtures/v8_replay_holdout.jsonl");

        let dev_summary = run_replay_corpus("DEV", dev_jsonl);
        assert_eq!(dev_summary.corpus_classification, "SYNTHETIC_REPLAY_CORPUS");
        assert_eq!(
            dev_summary.total_cases, 10,
            "DEV corpus must have 10 cases, got {}",
            dev_summary.total_cases
        );
        assert_eq!(
            dev_summary.false_positive_browser_verified, 0,
            "DEV corpus MUST have 0 false-positive BROWSER_EGRESS_VERIFIED: {:?}",
            dev_summary.failures
        );
        assert!(
            dev_summary.failures.is_empty(),
            "DEV corpus failures: {:?}",
            dev_summary.failures
        );

        let holdout_summary = run_replay_corpus("HOLDOUT", holdout_jsonl);
        assert_eq!(
            holdout_summary.corpus_classification,
            "SYNTHETIC_REPLAY_CORPUS"
        );
        assert_eq!(
            holdout_summary.total_cases, 10,
            "HOLDOUT corpus must have 10 cases, got {}",
            holdout_summary.total_cases
        );
        assert_eq!(
            holdout_summary.false_positive_browser_verified, 0,
            "HOLDOUT corpus MUST have 0 false-positive BROWSER_EGRESS_VERIFIED: {:?}",
            holdout_summary.failures
        );
        assert!(
            holdout_summary.failures.is_empty(),
            "HOLDOUT corpus failures: {:?}",
            holdout_summary.failures
        );
    }

    #[test]
    fn test_v9_adversarial_holdout_and_historical_backtest_honesty() {
        let adv_jsonl = include_str!("../../tests/fixtures/v9_adversarial_holdout.jsonl");
        let adv_summary = run_replay_corpus("ADVERSARIAL_HOLDOUT", adv_jsonl);

        assert_eq!(adv_summary.corpus_classification, "SYNTHETIC_REPLAY_CORPUS");
        assert_eq!(
            adv_summary.total_cases, 15,
            "ADVERSARIAL_HOLDOUT corpus must have 15 cases, got {}",
            adv_summary.total_cases
        );
        assert_eq!(
            adv_summary.false_positive_browser_verified, 0,
            "ADVERSARIAL_HOLDOUT corpus MUST have 0 false-positive BROWSER_EGRESS_VERIFIED: {:?}",
            adv_summary.failures
        );
        assert_eq!(
            adv_summary.false_negative_browser_verified, 0,
            "ADVERSARIAL_HOLDOUT corpus MUST have 0 false-negative BROWSER_EGRESS_VERIFIED: {:?}",
            adv_summary.failures
        );
        assert_eq!(adv_summary.exact_status_matches, 15);
        assert_eq!(adv_summary.reason_matches, 15);
        assert!(
            adv_summary.failures.is_empty(),
            "ADVERSARIAL_HOLDOUT failures: {:?}",
            adv_summary.failures
        );

        // Verify honest historical backtest reporting when no real historical packet capture exists
        let hist_report = evaluate_historical_backtest_honesty(None);
        assert_eq!(hist_report.classification, "HISTORICAL_BACKTEST");
        assert_eq!(hist_report.status, "INSUFFICIENT_HISTORICAL_EVIDENCE");
        assert!(!hist_report.synthetic_replay_conflated);
    }
}
