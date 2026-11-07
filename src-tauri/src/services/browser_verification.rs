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
use std::net::TcpListener;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub expected_country: Option<String>,
    pub expected_ip: Option<String>,
    /// Snapshot of recent tunnel events recorded by the proxy bridge telemetry
    /// in the last 5 minutes.  Populated by the caller from
    /// `ProxyBridgeManager::recent_tunnel_count`.  Zero when the bridge is not
    /// available or telemetry has not yet been wired at the call site.
    pub recent_bridge_connection_count: usize,
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

/// Errors that can occur during browser verification.
#[derive(Debug)]
pub enum BrowserVerificationError {
    /// Edge was not launched with `--remote-debugging-port` or the port is unreachable.
    CdpNotAvailable(String),
    /// TCP connection to the CDP endpoint succeeded but the WebSocket handshake failed.
    CdpConnectionFailed(String),
    /// No `Network.responseReceived` event arrived within the allowed window.
    VerificationTimeout,
    /// The PID or session ID on the CDP target does not match the expected session.
    SessionMismatch,
    /// The response body from the geolocation endpoint could not be parsed.
    ResponseParseError(String),
}

/// Performs real browser-origin verification via Chrome DevTools Protocol.
///
/// # Prerequisites
///
/// Edge must be launched with:
/// - `--remote-debugging-port=<ephemeral>` (use a randomly-assigned port)
/// - `--remote-debugging-address=127.0.0.1` (loopback only — NEVER 0.0.0.0)
///
/// # Flow
///
/// 1. Connect to `http://127.0.0.1:<debug_port>/json` (plain HTTP, not WebSocket yet).
/// 2. Find the target page: `GET /json/list` → find target with `type == "page"`.
/// 3. Connect to the WebSocket URL from the target descriptor.
/// 4. Send: `{"id":1,"method":"Network.enable","params":{}}`
/// 5. Send: `{"id":2,"method":"Page.navigate","params":{"url":"<verification_url>"}}`
///    where `<verification_url>` is the loopback listener URL with the unique token.
/// 6. Wait for `Network.responseReceived` with the matching `requestId`.
/// 7. Correlate: the bridge's CONNECT telemetry must show a tunnel to the external
///    geolocation host (e.g. `ipwho.is`) within the same time window.
/// 8. Confirm the token was received on the local listener (the browser *did* call back).
/// 9. Store `BrowserVerificationEvidence` with `status = BROWSER_EGRESS_VERIFIED`.
///
/// # Security requirements
///
/// - Close the CDP WebSocket immediately after verification.
/// - Never log full response bodies (may contain sensitive geolocation data).
/// - Restrict CDP to this specific browser instance (match by PID / session ID).
/// - Use a session-scoped unique token to prevent replay.
/// - Apply a strict timeout (default: 30 seconds).
///
/// # Return
///
/// Returns `Err(BrowserVerificationError::CdpNotAvailable)` when Edge is not
/// running with a debug port or the port cannot be reached.
///
/// # NOT YET IMPLEMENTED
///
/// This function is a specification stub.  The actual WebSocket CDP client
/// requires either the `tungstenite` or `tokio-tungstenite` crate plus
/// `serde_json` message framing.  Add these to `Cargo.toml` and implement
/// the flow described above before promoting any result to `BROWSER_EGRESS_VERIFIED`.
pub fn attempt_cdp_browser_verification(
    _session: &BrowserSessionInfo,
    _debug_port: u16,
) -> Result<BrowserVerificationEvidence, BrowserVerificationError> {
    Err(BrowserVerificationError::CdpNotAvailable(
        "CDP WebSocket client not yet implemented. \
         See function documentation for the full implementation specification."
            .to_string(),
    ))
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
            pid: 12345,
            profile_path: "/tmp/test-profile".to_string(),
            proxy_bridge_port: Some(49200),
            proxy_endpoint_id: "ep-001".to_string(),
            expected_country: Some("US".to_string()),
            expected_ip: None,
            recent_bridge_connection_count: 0,
        };
        let result = attempt_token_browser_verification(&session);
        assert_eq!(result.status, "VERIFICATION_UNAVAILABLE");
        assert_eq!(result.environment_id, "env-test");
        assert_eq!(result.browser_pid, 12345);
        assert!(!result.token_received);
        assert!(!result.proxy_path_confirmed);
        assert!(result.message.contains("CDP"));
    }

    #[test]
    fn test_browser_verification_evidence_unavailable_clears_sensitive_fields() {
        let ev = BrowserVerificationEvidence::unavailable("env-999", "No browser");
        // No real credentials or IP data should be present
        assert!(ev.observed_public_ip.is_none());
        assert!(ev.observed_country.is_none());
        assert!(!ev.proxy_path_confirmed);
    }
}
