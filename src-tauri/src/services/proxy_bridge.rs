use crate::security::redaction::redact_sensitive_str;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const MAX_CONCURRENT_CONNECTIONS: usize = 128;

// ---------------------------------------------------------------------------
// Bridge connection telemetry
// ---------------------------------------------------------------------------

/// A single observed connection event tunnelled through the proxy bridge.
///
/// These records are used by `browser_verification` to build composite
/// evidence showing that the bridge has been active during a session.
/// They do NOT prove browser-origin egress by themselves — that requires CDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeTunnelOutcome {
    Success,
    UpstreamConnectFailed,
    AuthFailed,
    ClientClosed,
    ProtocolError,
}

/// A single observed connection event tunnelled through the proxy bridge.
///
/// Extended in V6 to support exact request-level correlation:
/// - Explicit bridge instance UUID (detects bridge restarts)
/// - Exact destination host & port (no substring matches)
/// - Connection start and finish timestamps
/// - Typed tunnel outcome
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeConnectionEvent {
    pub event_id: String,
    pub bridge_instance_id: String,
    pub environment_id: String,
    pub proxy_endpoint_id: String,
    pub local_bridge_port: u16,
    pub destination_host: String,
    pub destination_port: u16,
    pub protocol: String,
    pub connection_started_at: String,
    pub connection_finished_at: Option<String>,
    pub outcome: BridgeTunnelOutcome,
    pub latency_ms: Option<u32>,
    pub bytes_transferred: u64,
}

/// Result of correlating a browser verification attempt against proxy bridge CONNECT telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeCorrelationOutcome {
    /// Exactly one fresh HTTP_CONNECT or SOCKS5_CONNECT tunnel matched the verification window with >0 bytes transferred.
    Confirmed(BridgeConnectionEvent),
    /// Zero matching CONNECT tunnels in the window (e.g., direct bypass, wrong host/port, stale pre-existing tunnel, or only PLAIN_HTTP backend probe).
    NoMatchingTunnel,
    /// Multiple concurrent CONNECT tunnels to the same destination host:port during the window; cannot attribute unambiguously.
    AmbiguousConcurrentTunnels(usize),
    /// A CONNECT tunnel was opened in the window, but transferred 0 payload bytes.
    ZeroBytesTransferred(BridgeConnectionEvent),
}

/// Thread-safe, bounded ring-buffer of recent bridge connection events.
///
/// Bounded to `max_events` entries so memory usage is O(1) regardless of
/// how long the bridge runs.
pub struct BridgeTelemetry {
    events: Mutex<VecDeque<BridgeConnectionEvent>>,
    max_events: usize,
}

impl BridgeTelemetry {
    pub fn new(max_events: usize) -> Self {
        Self {
            events: Mutex::new(VecDeque::new()),
            max_events,
        }
    }

    /// Push a new event, dropping the oldest if the ring is full.
    pub fn record_event(&self, event: BridgeConnectionEvent) {
        if let Ok(mut events) = self.events.lock() {
            if events.len() >= self.max_events {
                events.pop_front();
            }
            events.push_back(event);
        }
    }

    /// Increment `bytes_transferred` and update `connection_finished_at` for an active tunnel event.
    pub fn add_bytes(&self, event_id: &str, delta_bytes: u64) {
        if delta_bytes == 0 {
            return;
        }
        if let Ok(mut events) = self.events.lock() {
            if let Some(ev) = events.iter_mut().rev().find(|e| e.event_id == event_id) {
                ev.bytes_transferred = ev.bytes_transferred.saturating_add(delta_bytes);
                ev.connection_finished_at = Some(Utc::now().to_rfc3339());
            }
        }
    }

    /// Return all events recorded within the last `since_secs` seconds.
    pub fn recent_events(&self, since_secs: u64) -> Vec<BridgeConnectionEvent> {
        if let Ok(events) = self.events.lock() {
            let cutoff = Utc::now() - chrono::Duration::seconds(since_secs as i64);
            events
                .iter()
                .filter(|e| {
                    e.connection_started_at
                        .parse::<chrono::DateTime<Utc>>()
                        .map(|t| t > cutoff)
                        .unwrap_or(false)
                })
                .cloned()
                .collect()
        } else {
            vec![]
        }
    }

    /// Strictly correlate a browser HTTPS navigation attempt with proxy bridge CONNECT telemetry.
    ///
    /// Enforces:
    /// - Exact `bridge_instance_id`, `environment_id`, `proxy_endpoint_id`
    /// - Exact normalized `destination_host` and `destination_port`
    /// - `outcome == BridgeTunnelOutcome::Success`
    /// - `protocol` is `"HTTP_CONNECT"` or `"SOCKS5_CONNECT"` (rejects `"PLAIN_HTTP"` backend probes)
    /// - `connection_started_at >= started_after` (and `<= ended_before` when provided), rejecting stale/reused tunnels
    /// - Unambiguous cardinality: exactly 1 matching tunnel in the window (`> 1` returns `AmbiguousConcurrentTunnels`)
    /// - Non-zero payload transfer (`bytes_transferred > 0`)
    #[allow(clippy::too_many_arguments)]
    pub fn correlate_connect_tunnel(
        &self,
        bridge_instance_id: &str,
        environment_id: &str,
        proxy_endpoint_id: &str,
        target_host: &str,
        target_port: u16,
        started_after: chrono::DateTime<Utc>,
        ended_before: Option<chrono::DateTime<Utc>>,
    ) -> BridgeCorrelationOutcome {
        let norm_target = target_host.trim_end_matches('.').to_ascii_lowercase();
        let matches: Vec<BridgeConnectionEvent> = if let Ok(events) = self.events.lock() {
            events
                .iter()
                .filter(|e| {
                    if e.bridge_instance_id != bridge_instance_id
                        || e.environment_id != environment_id
                        || e.proxy_endpoint_id != proxy_endpoint_id
                        || e.destination_host != norm_target
                        || (target_port != 0 && e.destination_port != target_port)
                        || e.outcome != BridgeTunnelOutcome::Success
                        || !matches!(e.protocol.as_str(), "HTTP_CONNECT" | "SOCKS5_CONNECT")
                    {
                        return false;
                    }
                    e.connection_started_at
                        .parse::<chrono::DateTime<Utc>>()
                        .map(|t| {
                            t >= started_after
                                && ended_before.map(|end_ts| t <= end_ts).unwrap_or(true)
                        })
                        .unwrap_or(false)
                })
                .cloned()
                .collect()
        } else {
            return BridgeCorrelationOutcome::NoMatchingTunnel;
        };

        if matches.is_empty() {
            return BridgeCorrelationOutcome::NoMatchingTunnel;
        }

        let active_matches: Vec<BridgeConnectionEvent> = matches
            .iter()
            .filter(|e| e.bytes_transferred > 0)
            .cloned()
            .collect();

        match active_matches.len() {
            0 => {
                BridgeCorrelationOutcome::ZeroBytesTransferred(matches.into_iter().next().unwrap())
            }
            1 => BridgeCorrelationOutcome::Confirmed(active_matches.into_iter().next().unwrap()),
            n => BridgeCorrelationOutcome::AmbiguousConcurrentTunnels(n),
        }
    }

    /// Find an exact, unambiguous matching CONNECT tunnel event for browser verification correlation.
    pub fn find_matching_tunnel(
        &self,
        bridge_instance_id: &str,
        environment_id: &str,
        proxy_endpoint_id: &str,
        target_host: &str,
        target_port: u16,
        started_after: chrono::DateTime<Utc>,
    ) -> Option<BridgeConnectionEvent> {
        match self.correlate_connect_tunnel(
            bridge_instance_id,
            environment_id,
            proxy_endpoint_id,
            target_host,
            target_port,
            started_after,
            None,
        ) {
            BridgeCorrelationOutcome::Confirmed(ev) => Some(ev),
            _ => None,
        }
    }

    /// Return `true` when at least one completed tunnel to `target_host` was
    /// recorded within the last `since_secs` seconds with exact host match.
    pub fn has_recent_connection_to(&self, target_host: &str, since_secs: u64) -> bool {
        let norm = target_host.trim_end_matches('.').to_ascii_lowercase();
        self.recent_events(since_secs)
            .iter()
            .any(|e| e.destination_host == norm && e.outcome == BridgeTunnelOutcome::Success)
    }

    /// Total number of events currently held in the ring-buffer.
    pub fn len(&self) -> usize {
        self.events.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
const UPSTREAM_CONNECT_TIMEOUT_MS: u64 = 6000;
const STREAM_IO_TIMEOUT_MS: u64 = 15000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyBridgeStatus {
    pub instance_id: String,
    pub environment_id: String,
    pub endpoint_id: String,
    pub local_port: u16,
    pub listen_addr: String,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub protocol: String,
    pub running: bool,
    pub active_connections: usize,
    pub total_connections: u64,
    pub successful_tunnels: u64,
    pub auth_failures: u64,
    pub connection_failures: u64,
    pub last_error: Option<String>,
    pub last_activity_at: Option<String>,
    pub started_at: String,
}

#[derive(Clone)]
pub struct UpstreamProxyConfig {
    pub environment_id: String,
    pub endpoint_id: String,
    pub host: String,
    pub port: u16,
    pub protocol: String, // "HTTP", "HTTPS", "SOCKS5"
    pub username: Option<String>,
    pub password: Option<String>,
    pub connect_timeout: Duration,
}

impl UpstreamProxyConfig {
    pub fn formatted_credentials(&self) -> Option<String> {
        match (&self.username, &self.password) {
            (Some(u), Some(p)) if !u.is_empty() => Some(format!("{}:{}", u, p)),
            (Some(u), None) if !u.is_empty() => {
                if u.contains(':') {
                    Some(u.clone())
                } else {
                    Some(format!("{}:", u))
                }
            }
            (None, Some(p)) if !p.is_empty() => {
                if p.contains(':') {
                    Some(p.clone())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn basic_auth_header(&self) -> Option<String> {
        self.formatted_credentials().map(|creds| {
            let encoded = base64::engine::general_purpose::STANDARD.encode(creds.as_bytes());
            format!("Proxy-Authorization: Basic {}\r\n", encoded)
        })
    }
}

pub struct ProxyBridgeInstance {
    pub instance_id: String,
    pub config: UpstreamProxyConfig,
    pub local_port: u16,
    pub running: Arc<AtomicBool>,
    pub active_connections: Arc<AtomicUsize>,
    pub total_connections: Arc<AtomicU64>,
    pub successful_tunnels: Arc<AtomicU64>,
    pub auth_failures: Arc<AtomicU64>,
    pub connection_failures: Arc<AtomicU64>,
    pub last_error: Arc<Mutex<Option<String>>>,
    pub last_activity_at: Arc<Mutex<Option<String>>>,
    pub started_at: String,
    /// Ring-buffer of recent tunnel events for browser-verification correlation.
    /// Bounded to 500 entries; each entry is O(100 bytes) ≈ 50 KB worst-case.
    pub telemetry: Arc<BridgeTelemetry>,
}

impl ProxyBridgeInstance {
    pub fn status(&self) -> ProxyBridgeStatus {
        ProxyBridgeStatus {
            instance_id: self.instance_id.clone(),
            environment_id: self.config.environment_id.clone(),
            endpoint_id: self.config.endpoint_id.clone(),
            local_port: self.local_port,
            listen_addr: format!("127.0.0.1:{}", self.local_port),
            upstream_host: self.config.host.clone(),
            upstream_port: self.config.port,
            protocol: self.config.protocol.clone(),
            running: self.running.load(Ordering::SeqCst),
            active_connections: self.active_connections.load(Ordering::SeqCst),
            total_connections: self.total_connections.load(Ordering::SeqCst),
            successful_tunnels: self.successful_tunnels.load(Ordering::SeqCst),
            auth_failures: self.auth_failures.load(Ordering::SeqCst),
            connection_failures: self.connection_failures.load(Ordering::SeqCst),
            last_error: self.last_error.lock().ok().and_then(|g| g.clone()),
            last_activity_at: self.last_activity_at.lock().ok().and_then(|g| g.clone()),
            started_at: self.started_at.clone(),
        }
    }

    pub fn stop(&self) {
        if self.running.swap(false, Ordering::SeqCst) {
            // Wake up accept loop on localhost
            let _ = TcpStream::connect_timeout(
                &SocketAddr::from(([127, 0, 0, 1], self.local_port)),
                Duration::from_millis(100),
            );
        }
    }
}

pub struct ProxyBridgeManager {
    bridges: Mutex<HashMap<String, Arc<ProxyBridgeInstance>>>,
}

impl ProxyBridgeManager {
    pub fn new() -> Self {
        Self {
            bridges: Mutex::new(HashMap::new()),
        }
    }

    pub fn validate_config(config: &UpstreamProxyConfig) -> Result<(), String> {
        let host = config.host.trim();
        if host.is_empty() {
            return Err("Proxy host cannot be empty".to_string());
        }
        if host.contains(char::is_whitespace) || host.contains('/') || host.contains('@') {
            return Err("Invalid proxy hostname format".to_string());
        }
        if config.port == 0 {
            return Err("Proxy port must be between 1 and 65535".to_string());
        }
        let proto = config.protocol.to_uppercase();
        if !matches!(proto.as_str(), "HTTP" | "HTTPS" | "SOCKS5") {
            return Err(format!(
                "Unsupported proxy protocol '{}' for authenticated browser bridge. Supported protocols: HTTP, HTTPS, SOCKS5.",
                config.protocol
            ));
        }
        Ok(())
    }

    pub fn start_or_replace_bridge(
        &self,
        config: UpstreamProxyConfig,
    ) -> Result<ProxyBridgeStatus, String> {
        Self::validate_config(&config)?;

        // Stop existing bridge for this environment if running
        self.stop_bridge(&config.environment_id);

        // Bind strictly to 127.0.0.1:0 (localhost only)
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("Failed to bind localhost proxy bridge: {}", e))?;
        let local_port = listener
            .local_addr()
            .map_err(|e| format!("Failed to read local bridge address: {}", e))?
            .port();

        let instance_id = uuid::Uuid::new_v4().to_string();
        let running = Arc::new(AtomicBool::new(true));
        let active_connections = Arc::new(AtomicUsize::new(0));
        let total_connections = Arc::new(AtomicU64::new(0));
        let successful_tunnels = Arc::new(AtomicU64::new(0));
        let auth_failures = Arc::new(AtomicU64::new(0));
        let connection_failures = Arc::new(AtomicU64::new(0));
        let last_error = Arc::new(Mutex::new(None));
        let last_activity_at = Arc::new(Mutex::new(None));
        let started_at = Utc::now().to_rfc3339();
        let telemetry = Arc::new(BridgeTelemetry::new(500));

        let instance = Arc::new(ProxyBridgeInstance {
            instance_id,
            config: config.clone(),
            local_port,
            running: running.clone(),
            active_connections: active_connections.clone(),
            total_connections: total_connections.clone(),
            successful_tunnels: successful_tunnels.clone(),
            auth_failures: auth_failures.clone(),
            connection_failures: connection_failures.clone(),
            last_error: last_error.clone(),
            last_activity_at: last_activity_at.clone(),
            started_at,
            telemetry,
        });

        {
            let mut map = self
                .bridges
                .lock()
                .map_err(|_| "Bridge lock poisoned".to_string())?;
            map.insert(config.environment_id.clone(), instance.clone());
        }

        let thread_instance = instance.clone();
        thread::spawn(move || {
            run_bridge_accept_loop(listener, thread_instance);
        });

        Ok(instance.status())
    }

    pub fn get_bridge_status(&self, environment_id: &str) -> Option<ProxyBridgeStatus> {
        let map = self.bridges.lock().ok()?;
        map.get(environment_id).map(|b| b.status())
    }

    /// Retrieve the unique instance generation UUID of the currently running bridge.
    pub fn get_instance_id(&self, environment_id: &str) -> Option<String> {
        let map = self.bridges.lock().ok()?;
        map.get(environment_id).map(|b| b.instance_id.clone())
    }

    /// Return the number of recent tunnel events for the given environment.
    /// Used by browser verification to populate `recent_bridge_connection_count`.
    pub fn recent_tunnel_count(&self, environment_id: &str, since_secs: u64) -> usize {
        if let Ok(map) = self.bridges.lock() {
            if let Some(instance) = map.get(environment_id) {
                return instance.telemetry.recent_events(since_secs).len();
            }
        }
        0
    }

    /// Strictly correlate a browser HTTPS navigation attempt with proxy bridge CONNECT telemetry.
    #[allow(clippy::too_many_arguments)]
    pub fn correlate_connect_tunnel(
        &self,
        bridge_instance_id: &str,
        environment_id: &str,
        proxy_endpoint_id: &str,
        target_host: &str,
        target_port: u16,
        started_after: chrono::DateTime<Utc>,
        ended_before: Option<chrono::DateTime<Utc>>,
    ) -> BridgeCorrelationOutcome {
        if let Ok(map) = self.bridges.lock() {
            if let Some(instance) = map.get(environment_id) {
                return instance.telemetry.correlate_connect_tunnel(
                    bridge_instance_id,
                    environment_id,
                    proxy_endpoint_id,
                    target_host,
                    target_port,
                    started_after,
                    ended_before,
                );
            }
        }
        BridgeCorrelationOutcome::NoMatchingTunnel
    }

    /// Inject a telemetry event for deterministic integration/adversarial testing.
    pub fn record_tunnel_event_for_test(&self, environment_id: &str, event: BridgeConnectionEvent) {
        if let Ok(map) = self.bridges.lock() {
            if let Some(instance) = map.get(environment_id) {
                instance.telemetry.record_event(event);
            }
        }
    }

    /// Find an exact matching tunnel event belonging to the current bridge generation,
    /// environment, assigned proxy endpoint, exact host/port, and started after the baseline.
    pub fn find_matching_tunnel(
        &self,
        bridge_instance_id: &str,
        environment_id: &str,
        proxy_endpoint_id: &str,
        target_host: &str,
        target_port: u16,
        started_after: chrono::DateTime<Utc>,
    ) -> Option<BridgeConnectionEvent> {
        if let Ok(map) = self.bridges.lock() {
            if let Some(instance) = map.get(environment_id) {
                return instance.telemetry.find_matching_tunnel(
                    bridge_instance_id,
                    environment_id,
                    proxy_endpoint_id,
                    target_host,
                    target_port,
                    started_after,
                );
            }
        }
        None
    }

    /// Check whether a tunnel to target_host was completed within the last since_secs seconds.
    /// Used by browser verification to correlate browser-origin requests with bridge traffic.
    pub fn has_recent_tunnel_to(
        &self,
        environment_id: &str,
        target_host: &str,
        since_secs: u64,
    ) -> bool {
        if let Ok(map) = self.bridges.lock() {
            if let Some(instance) = map.get(environment_id) {
                return instance
                    .telemetry
                    .has_recent_connection_to(target_host, since_secs);
            }
        }
        false
    }

    pub fn stop_bridge(&self, environment_id: &str) -> bool {
        if let Ok(mut map) = self.bridges.lock() {
            if let Some(instance) = map.remove(environment_id) {
                instance.stop();
                return true;
            }
        }
        false
    }

    pub fn stop_all(&self) {
        if let Ok(mut map) = self.bridges.lock() {
            for (_, instance) in map.drain() {
                instance.stop();
            }
        }
    }
}

impl Drop for ProxyBridgeManager {
    fn drop(&mut self) {
        self.stop_all();
    }
}

impl Default for ProxyBridgeManager {
    fn default() -> Self {
        Self::new()
    }
}

fn run_bridge_accept_loop(listener: TcpListener, instance: Arc<ProxyBridgeInstance>) {
    for stream_res in listener.incoming() {
        if !instance.running.load(Ordering::SeqCst) {
            break;
        }

        let client_stream = match stream_res {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Ensure connection is strictly from localhost
        if let Ok(peer) = client_stream.peer_addr() {
            if !peer.ip().is_loopback() {
                let _ = client_stream.shutdown(Shutdown::Both);
                continue;
            }
        }

        // Enforce bounded concurrency
        let current_active = instance.active_connections.load(Ordering::SeqCst);
        if current_active >= MAX_CONCURRENT_CONNECTIONS {
            let _ = client_stream.shutdown(Shutdown::Both);
            continue;
        }

        instance.active_connections.fetch_add(1, Ordering::SeqCst);
        instance.total_connections.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut ts) = instance.last_activity_at.lock() {
            *ts = Some(Utc::now().to_rfc3339());
        }

        let conn_instance = instance.clone();
        thread::spawn(move || {
            let _ = handle_client_connection(client_stream, &conn_instance);
            conn_instance
                .active_connections
                .fetch_sub(1, Ordering::SeqCst);
        });
    }
}

fn record_bridge_error(instance: &ProxyBridgeInstance, is_auth: bool, msg: String) {
    let redacted = redact_sensitive_str(&msg);
    if is_auth {
        instance.auth_failures.fetch_add(1, Ordering::SeqCst);
    } else {
        instance.connection_failures.fetch_add(1, Ordering::SeqCst);
    }
    if let Ok(mut err) = instance.last_error.lock() {
        *err = Some(redacted);
    }
}

fn send_bad_gateway(client: &mut TcpStream, reason: &str) {
    let safe_reason = redact_sensitive_str(reason);
    let resp = format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
        safe_reason.len(),
        safe_reason
    );
    let _ = client.write_all(resp.as_bytes());
    let _ = client.flush();
    let _ = client.shutdown(Shutdown::Both);
}

fn read_http_request_head(stream: &mut TcpStream) -> Result<(String, Vec<u8>), String> {
    let mut buf = Vec::with_capacity(4096);
    let mut temp = [0u8; 1024];
    loop {
        if buf.len() > 32768 {
            return Err("Request header too large".to_string());
        }
        let n = stream
            .read(&mut temp)
            .map_err(|e| format!("Failed reading client request: {}", e))?;
        if n == 0 {
            return Err("Client closed connection before sending request".to_string());
        }
        buf.extend_from_slice(&temp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            let header_str = String::from_utf8_lossy(&buf[..pos]).to_string();
            let leftover = buf[pos + 4..].to_vec();
            return Ok((header_str, leftover));
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn connect_to_upstream(config: &UpstreamProxyConfig) -> Result<TcpStream, String> {
    let addr_str = format!("{}:{}", config.host, config.port);
    let mut addrs = addr_str
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for proxy {}: {}", addr_str, e))?;
    let sock_addr = addrs
        .next()
        .ok_or_else(|| format!("No socket address resolved for proxy {}", addr_str))?;

    let timeout = if config.connect_timeout.is_zero() {
        Duration::from_millis(UPSTREAM_CONNECT_TIMEOUT_MS)
    } else {
        config.connect_timeout
    };

    let stream = TcpStream::connect_timeout(&sock_addr, timeout)
        .map_err(|e| format!("Failed connecting to upstream proxy {}: {}", addr_str, e))?;

    let io_timeout = Some(Duration::from_millis(STREAM_IO_TIMEOUT_MS));
    stream.set_read_timeout(io_timeout).ok();
    stream.set_write_timeout(io_timeout).ok();
    Ok(stream)
}

#[allow(clippy::too_many_arguments)]
fn record_telemetry_event(
    instance: &ProxyBridgeInstance,
    dest_host: &str,
    dest_port: u16,
    protocol: &str,
    conn_start: chrono::DateTime<Utc>,
    outcome: BridgeTunnelOutcome,
    latency_ms: Option<u32>,
    bytes_transferred: u64,
) -> String {
    let event_id = uuid::Uuid::new_v4().to_string();
    let norm_host = dest_host.trim_end_matches('.').to_ascii_lowercase();
    instance.telemetry.record_event(BridgeConnectionEvent {
        event_id: event_id.clone(),
        bridge_instance_id: instance.instance_id.clone(),
        environment_id: instance.config.environment_id.clone(),
        proxy_endpoint_id: instance.config.endpoint_id.clone(),
        local_bridge_port: instance.local_port,
        destination_host: norm_host,
        destination_port: dest_port,
        protocol: protocol.to_string(),
        connection_started_at: conn_start.to_rfc3339(),
        connection_finished_at: Some(Utc::now().to_rfc3339()),
        outcome,
        latency_ms,
        bytes_transferred,
    });
    event_id
}

fn handle_client_connection(
    mut client: TcpStream,
    instance: &ProxyBridgeInstance,
) -> Result<(), String> {
    let io_timeout = Some(Duration::from_millis(STREAM_IO_TIMEOUT_MS));
    client.set_read_timeout(io_timeout).ok();
    client.set_write_timeout(io_timeout).ok();

    let (header_str, leftover) = read_http_request_head(&mut client)?;

    let first_line = header_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        send_bad_gateway(&mut client, "Malformed HTTP proxy request");
        return Err("Malformed HTTP request line".to_string());
    }

    let method = parts[0].to_uppercase();
    let target = parts[1];
    let (dest_host, dest_port, _rel_path) = match parse_target_host_port(&method, target) {
        Ok(res) => res,
        Err(e) => {
            send_bad_gateway(&mut client, &e);
            return Err(e);
        }
    };

    let conn_start = Utc::now();
    let start_inst = Instant::now();

    if instance.config.protocol.eq_ignore_ascii_case("SOCKS5") {
        return handle_socks5_upstream(
            &mut client,
            instance,
            &method,
            target,
            &dest_host,
            dest_port,
            conn_start,
            start_inst,
            &header_str,
            &leftover,
        );
    }

    // HTTP / HTTPS Upstream Proxy
    let mut upstream = match connect_to_upstream(&instance.config) {
        Ok(s) => s,
        Err(e) => {
            record_bridge_error(instance, false, e.clone());
            record_telemetry_event(
                instance,
                &dest_host,
                dest_port,
                &method,
                conn_start,
                BridgeTunnelOutcome::UpstreamConnectFailed,
                Some(start_inst.elapsed().as_millis() as u32),
                0,
            );
            send_bad_gateway(
                &mut client,
                &format!("Proxy connection failed (direct fallback blocked): {}", e),
            );
            return Err(e);
        }
    };

    if method == "CONNECT" {
        let auth_hdr = instance.config.basic_auth_header().unwrap_or_default();
        let connect_req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n{}Proxy-Connection: keep-alive\r\n\r\n",
            target, target, auth_hdr
        );

        if let Err(e) = upstream.write_all(connect_req.as_bytes()) {
            let msg = format!("Failed writing CONNECT to upstream proxy: {}", e);
            record_bridge_error(instance, false, msg.clone());
            record_telemetry_event(
                instance,
                &dest_host,
                dest_port,
                "HTTP_CONNECT",
                conn_start,
                BridgeTunnelOutcome::UpstreamConnectFailed,
                Some(start_inst.elapsed().as_millis() as u32),
                0,
            );
            send_bad_gateway(&mut client, &msg);
            return Err(msg);
        }

        let (resp_head, upstream_leftover) = match read_http_request_head(&mut upstream) {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("Upstream proxy closed during CONNECT handshake: {}", e);
                record_bridge_error(instance, false, msg.clone());
                record_telemetry_event(
                    instance,
                    &dest_host,
                    dest_port,
                    "HTTP_CONNECT",
                    conn_start,
                    BridgeTunnelOutcome::UpstreamConnectFailed,
                    Some(start_inst.elapsed().as_millis() as u32),
                    0,
                );
                send_bad_gateway(&mut client, &msg);
                return Err(msg);
            }
        };

        let status_line = resp_head.lines().next().unwrap_or("");
        if status_line.contains(" 407 ") || status_line.ends_with(" 407") {
            let msg =
                "Upstream proxy authentication failed (HTTP 407 Proxy Authentication Required)"
                    .to_string();
            record_bridge_error(instance, true, msg.clone());
            record_telemetry_event(
                instance,
                &dest_host,
                dest_port,
                "HTTP_CONNECT",
                conn_start,
                BridgeTunnelOutcome::AuthFailed,
                Some(start_inst.elapsed().as_millis() as u32),
                0,
            );
            send_bad_gateway(&mut client, &msg);
            return Err(msg);
        }

        if !status_line.contains(" 200") {
            let msg = format!("Upstream proxy rejected CONNECT tunnel: {}", status_line);
            record_bridge_error(instance, false, msg.clone());
            record_telemetry_event(
                instance,
                &dest_host,
                dest_port,
                "HTTP_CONNECT",
                conn_start,
                BridgeTunnelOutcome::ProtocolError,
                Some(start_inst.elapsed().as_millis() as u32),
                0,
            );
            send_bad_gateway(&mut client, &msg);
            return Err(msg);
        }

        // Tunnel established!
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .map_err(|e| e.to_string())?;
        if !upstream_leftover.is_empty() {
            client.write_all(&upstream_leftover).ok();
        }
        if !leftover.is_empty() {
            upstream.write_all(&leftover).ok();
        }

        instance.successful_tunnels.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut err) = instance.last_error.lock() {
            *err = None;
        }

        let initial_bytes = (upstream_leftover.len() + leftover.len()) as u64;
        let event_id = record_telemetry_event(
            instance,
            &dest_host,
            dest_port,
            "HTTP_CONNECT",
            conn_start,
            BridgeTunnelOutcome::Success,
            Some(start_inst.elapsed().as_millis() as u32),
            initial_bytes,
        );

        relay_bidirectional(client, upstream, instance.telemetry.clone(), event_id);
        Ok(())
    } else {
        // Plain HTTP request through upstream HTTP proxy
        let auth_hdr = instance.config.basic_auth_header().unwrap_or_default();
        let mut rebuilt = String::new();
        for (idx, line) in header_str.lines().enumerate() {
            if idx == 0 {
                rebuilt.push_str(line);
                rebuilt.push_str("\r\n");
                if !auth_hdr.is_empty() {
                    rebuilt.push_str(&auth_hdr);
                }
            } else if !line
                .to_ascii_lowercase()
                .starts_with("proxy-authorization:")
                && !line.to_ascii_lowercase().starts_with("proxy-connection:")
            {
                rebuilt.push_str(line);
                rebuilt.push_str("\r\n");
            }
        }
        rebuilt.push_str("Connection: close\r\n\r\n");

        if let Err(e) = upstream.write_all(rebuilt.as_bytes()) {
            let msg = format!("Failed sending HTTP request to upstream proxy: {}", e);
            record_bridge_error(instance, false, msg.clone());
            record_telemetry_event(
                instance,
                &dest_host,
                dest_port,
                "PLAIN_HTTP",
                conn_start,
                BridgeTunnelOutcome::UpstreamConnectFailed,
                Some(start_inst.elapsed().as_millis() as u32),
                0,
            );
            send_bad_gateway(&mut client, &msg);
            return Err(msg);
        }
        if !leftover.is_empty() {
            let _ = upstream.write_all(&leftover);
        }

        // Peek first chunk from upstream to detect 407
        let mut first_chunk = [0u8; 2048];
        let n = match upstream.read(&mut first_chunk) {
            Ok(0) => {
                let msg = "Upstream proxy returned empty response".to_string();
                record_bridge_error(instance, false, msg.clone());
                record_telemetry_event(
                    instance,
                    &dest_host,
                    dest_port,
                    "PLAIN_HTTP",
                    conn_start,
                    BridgeTunnelOutcome::UpstreamConnectFailed,
                    Some(start_inst.elapsed().as_millis() as u32),
                    0,
                );
                send_bad_gateway(&mut client, &msg);
                return Err(msg);
            }
            Ok(n) => n,
            Err(e) => {
                let msg = format!("Failed reading upstream proxy response: {}", e);
                record_bridge_error(instance, false, msg.clone());
                record_telemetry_event(
                    instance,
                    &dest_host,
                    dest_port,
                    "PLAIN_HTTP",
                    conn_start,
                    BridgeTunnelOutcome::UpstreamConnectFailed,
                    Some(start_inst.elapsed().as_millis() as u32),
                    0,
                );
                send_bad_gateway(&mut client, &msg);
                return Err(msg);
            }
        };

        let first_str = String::from_utf8_lossy(&first_chunk[..n]);
        let status_line = first_str.lines().next().unwrap_or("");
        if status_line.contains(" 407 ") || status_line.ends_with(" 407") {
            let msg =
                "Upstream proxy authentication failed (HTTP 407 Proxy Authentication Required)"
                    .to_string();
            record_bridge_error(instance, true, msg.clone());
            record_telemetry_event(
                instance,
                &dest_host,
                dest_port,
                "PLAIN_HTTP",
                conn_start,
                BridgeTunnelOutcome::AuthFailed,
                Some(start_inst.elapsed().as_millis() as u32),
                0,
            );
            send_bad_gateway(&mut client, &msg);
            return Err(msg);
        }

        instance.successful_tunnels.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut err) = instance.last_error.lock() {
            *err = None;
        }

        record_telemetry_event(
            instance,
            &dest_host,
            dest_port,
            "PLAIN_HTTP",
            conn_start,
            BridgeTunnelOutcome::Success,
            Some(start_inst.elapsed().as_millis() as u32),
            n as u64,
        );

        let _ = client.write_all(&first_chunk[..n]);
        let _ = std::io::copy(&mut upstream, &mut client);
        let _ = client.shutdown(Shutdown::Both);
        Ok(())
    }
}

fn parse_target_host_port(method: &str, target: &str) -> Result<(String, u16, String), String> {
    if method == "CONNECT" {
        if let Some((h, p_str)) = target.rsplit_once(':') {
            let port = p_str
                .parse::<u16>()
                .map_err(|_| "Invalid CONNECT port".to_string())?;
            return Ok((h.to_string(), port, "/".to_string()));
        }
        return Ok((target.to_string(), 443, "/".to_string()));
    }

    // For GET http://host:port/path
    let without_scheme = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .unwrap_or(target);
    let (host_port, path) = match without_scheme.find('/') {
        Some(idx) => (&without_scheme[..idx], &without_scheme[idx..]),
        None => (without_scheme, "/"),
    };
    if let Some((h, p_str)) = host_port.rsplit_once(':') {
        let port = p_str.parse::<u16>().unwrap_or(80);
        Ok((h.to_string(), port, path.to_string()))
    } else {
        Ok((host_port.to_string(), 80, path.to_string()))
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_socks5_upstream(
    client: &mut TcpStream,
    instance: &ProxyBridgeInstance,
    method: &str,
    target: &str,
    dest_host: &str,
    dest_port: u16,
    conn_start: chrono::DateTime<Utc>,
    start_inst: Instant,
    header_str: &str,
    leftover: &[u8],
) -> Result<(), String> {
    let (_h, _p, rel_path) = parse_target_host_port(method, target)?;
    let mut upstream = match connect_to_upstream(&instance.config) {
        Ok(s) => s,
        Err(e) => {
            record_bridge_error(instance, false, e.clone());
            record_telemetry_event(
                instance,
                dest_host,
                dest_port,
                method,
                conn_start,
                BridgeTunnelOutcome::UpstreamConnectFailed,
                Some(start_inst.elapsed().as_millis() as u32),
                0,
            );
            send_bad_gateway(client, &e);
            return Err(e);
        }
    };

    // SOCKS5 greeting
    let creds = instance.config.formatted_credentials();
    if creds.is_some() {
        upstream
            .write_all(&[0x05, 0x02, 0x00, 0x02])
            .map_err(|e| e.to_string())?;
    } else {
        upstream
            .write_all(&[0x05, 0x01, 0x00])
            .map_err(|e| e.to_string())?;
    }

    let mut method_resp = [0u8; 2];
    if let Err(e) = upstream.read_exact(&mut method_resp) {
        let msg = format!("SOCKS5 greeting failed: {}", e);
        record_bridge_error(instance, false, msg.clone());
        record_telemetry_event(
            instance,
            dest_host,
            dest_port,
            method,
            conn_start,
            BridgeTunnelOutcome::UpstreamConnectFailed,
            Some(start_inst.elapsed().as_millis() as u32),
            0,
        );
        send_bad_gateway(client, &msg);
        return Err(msg);
    }

    if method_resp[0] != 0x05 || method_resp[1] == 0xFF {
        let msg = "SOCKS5 proxy rejected authentication methods".to_string();
        record_bridge_error(instance, true, msg.clone());
        record_telemetry_event(
            instance,
            dest_host,
            dest_port,
            method,
            conn_start,
            BridgeTunnelOutcome::AuthFailed,
            Some(start_inst.elapsed().as_millis() as u32),
            0,
        );
        send_bad_gateway(client, &msg);
        return Err(msg);
    }

    if method_resp[1] == 0x02 {
        let c = creds.ok_or_else(|| {
            let msg = "SOCKS5 proxy requires credentials, but none were provided".to_string();
            record_bridge_error(instance, true, msg.clone());
            record_telemetry_event(
                instance,
                dest_host,
                dest_port,
                method,
                conn_start,
                BridgeTunnelOutcome::AuthFailed,
                Some(start_inst.elapsed().as_millis() as u32),
                0,
            );
            send_bad_gateway(client, &msg);
            msg
        })?;
        let (u, p) = c.split_once(':').unwrap_or((&c, ""));
        let u_bytes = u.as_bytes();
        let p_bytes = p.as_bytes();
        if u_bytes.len() > 255 || p_bytes.len() > 255 {
            return Err("SOCKS5 credentials exceed 255 bytes".to_string());
        }
        let mut auth_pkt = Vec::with_capacity(3 + u_bytes.len() + p_bytes.len());
        auth_pkt.push(0x01);
        auth_pkt.push(u_bytes.len() as u8);
        auth_pkt.extend_from_slice(u_bytes);
        auth_pkt.push(p_bytes.len() as u8);
        auth_pkt.extend_from_slice(p_bytes);
        upstream.write_all(&auth_pkt).map_err(|e| e.to_string())?;

        let mut auth_resp = [0u8; 2];
        upstream
            .read_exact(&mut auth_resp)
            .map_err(|e| e.to_string())?;
        if auth_resp[1] != 0x00 {
            let msg =
                "SOCKS5 proxy authentication failed (invalid username or password)".to_string();
            record_bridge_error(instance, true, msg.clone());
            record_telemetry_event(
                instance,
                dest_host,
                dest_port,
                method,
                conn_start,
                BridgeTunnelOutcome::AuthFailed,
                Some(start_inst.elapsed().as_millis() as u32),
                0,
            );
            send_bad_gateway(client, &msg);
            return Err(msg);
        }
    }

    // SOCKS5 CONNECT command with domain name (0x03) so DNS resolves remotely on proxy
    let host_bytes = dest_host.as_bytes();
    if host_bytes.len() > 255 {
        return Err("Destination hostname too long".to_string());
    }
    let mut req_pkt = Vec::with_capacity(7 + host_bytes.len());
    req_pkt.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
    req_pkt.extend_from_slice(host_bytes);
    req_pkt.extend_from_slice(&dest_port.to_be_bytes());
    upstream.write_all(&req_pkt).map_err(|e| e.to_string())?;

    let mut reply_hdr = [0u8; 4];
    if let Err(e) = upstream.read_exact(&mut reply_hdr) {
        let msg = format!("SOCKS5 connect reply failed: {}", e);
        record_bridge_error(instance, false, msg.clone());
        record_telemetry_event(
            instance,
            dest_host,
            dest_port,
            method,
            conn_start,
            BridgeTunnelOutcome::UpstreamConnectFailed,
            Some(start_inst.elapsed().as_millis() as u32),
            0,
        );
        send_bad_gateway(client, &msg);
        return Err(msg);
    }
    if reply_hdr[1] != 0x00 {
        let msg = format!(
            "SOCKS5 connect to {}:{} failed (code {})",
            dest_host, dest_port, reply_hdr[1]
        );
        record_bridge_error(instance, false, msg.clone());
        record_telemetry_event(
            instance,
            dest_host,
            dest_port,
            method,
            conn_start,
            BridgeTunnelOutcome::ProtocolError,
            Some(start_inst.elapsed().as_millis() as u32),
            0,
        );
        send_bad_gateway(client, &msg);
        return Err(msg);
    }

    // Consume bound address from SOCKS5 reply
    match reply_hdr[3] {
        0x01 => {
            let mut skip = [0u8; 6];
            let _ = upstream.read_exact(&mut skip);
        }
        0x03 => {
            let mut len = [0u8; 1];
            let _ = upstream.read_exact(&mut len);
            let mut skip = vec![0u8; (len[0] as usize) + 2];
            let _ = upstream.read_exact(&mut skip);
        }
        0x04 => {
            let mut skip = [0u8; 18];
            let _ = upstream.read_exact(&mut skip);
        }
        _ => {}
    }

    instance.successful_tunnels.fetch_add(1, Ordering::SeqCst);
    if let Ok(mut err) = instance.last_error.lock() {
        *err = None;
    }

    // Record telemetry for the SOCKS5 tunnel.
    let event_id = record_telemetry_event(
        instance,
        dest_host,
        dest_port,
        if method == "CONNECT" {
            "SOCKS5_CONNECT"
        } else {
            "SOCKS5_HTTP"
        },
        conn_start,
        BridgeTunnelOutcome::Success,
        Some(start_inst.elapsed().as_millis() as u32),
        leftover.len() as u64,
    );

    if method == "CONNECT" {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .map_err(|e| e.to_string())?;
        if !leftover.is_empty() {
            let _ = upstream.write_all(leftover);
        }
        if let Ok(client_clone) = client.try_clone() {
            relay_bidirectional(client_clone, upstream, instance.telemetry.clone(), event_id);
        }
        Ok(())
    } else {
        // Send relative HTTP request through the SOCKS5 tunnel
        let mut rebuilt = format!("{} {} HTTP/1.1\r\n", method, rel_path);
        for (idx, line) in header_str.lines().enumerate() {
            if idx > 0
                && !line.to_ascii_lowercase().starts_with("proxy-")
                && !line.to_ascii_lowercase().starts_with("connection:")
            {
                rebuilt.push_str(line);
                rebuilt.push_str("\r\n");
            }
        }
        rebuilt.push_str("Connection: close\r\n\r\n");
        upstream
            .write_all(rebuilt.as_bytes())
            .map_err(|e| e.to_string())?;
        if !leftover.is_empty() {
            let _ = upstream.write_all(leftover);
        }
        let copied = std::io::copy(&mut upstream, client).unwrap_or(0);
        instance
            .telemetry
            .add_bytes(&event_id, (rebuilt.len() as u64) + copied);
        let _ = client.shutdown(Shutdown::Both);
        Ok(())
    }
}

fn copy_and_track(
    reader: &mut TcpStream,
    writer: &mut TcpStream,
    telemetry: &BridgeTelemetry,
    event_id: &str,
) {
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if writer.write_all(&buf[..n]).is_err() {
                    break;
                }
                let _ = writer.flush();
                telemetry.add_bytes(event_id, n as u64);
            }
            Err(_) => break,
        }
    }
}

fn relay_bidirectional(
    mut client: TcpStream,
    mut upstream: TcpStream,
    telemetry: Arc<BridgeTelemetry>,
    event_id: String,
) {
    let mut client_reader = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut upstream_writer = match upstream.try_clone() {
        Ok(u) => u,
        Err(_) => return,
    };

    let c2u_telemetry = telemetry.clone();
    let c2u_event_id = event_id.clone();
    let c2u = thread::spawn(move || {
        copy_and_track(
            &mut client_reader,
            &mut upstream_writer,
            &c2u_telemetry,
            &c2u_event_id,
        );
        let _ = upstream_writer.shutdown(Shutdown::Write);
    });

    copy_and_track(&mut upstream, &mut client, &telemetry, &event_id);
    let _ = client.shutdown(Shutdown::Both);
    let _ = c2u.join();
}

/// Probe public IP and geolocation through a running localhost proxy bridge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeProbeResult {
    pub observed_ipv4: String,
    pub observed_ipv6: Option<String>,
    pub observed_country: Option<String>,
    pub latency_ms: u32,
    pub dns_summary: String,
}

pub fn probe_via_local_bridge(
    local_port: u16,
    timeout: Duration,
) -> Result<BridgeProbeResult, String> {
    let start = Instant::now();
    let addr = SocketAddr::from(([127, 0, 0, 1], local_port));
    let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(|e| {
        format!(
            "Local proxy bridge (127.0.0.1:{}) unreachable: {}",
            local_port, e
        )
    })?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    // Query ipwho.is over HTTP through the local bridge to obtain both IP and Country code
    let req = "GET http://ipwho.is/ HTTP/1.1\r\nHost: ipwho.is\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/json\r\nConnection: close\r\n\r\n";
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("Failed writing probe request to local bridge: {}", e))?;

    let mut resp = Vec::new();
    stream
        .read_to_end(&mut resp)
        .map_err(|e| format!("Failed reading probe response from local bridge: {}", e))?;
    let latency_ms = start.elapsed().as_millis() as u32;

    let resp_str = String::from_utf8_lossy(&resp);
    let first_line = resp_str.lines().next().unwrap_or("");
    if first_line.contains(" 502 ") || resp_str.contains("Proxy Authentication Failed") {
        let body = resp_str
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.trim())
            .unwrap_or(first_line);
        if body.contains("407") || body.to_lowercase().contains("authentication") {
            return Err(format!("AUTH_FAILED: {}", body));
        }
        return Err(format!("CONNECTION_FAILED: {}", body));
    }

    if let Some((_, body)) = resp_str.split_once("\r\n\r\n") {
        let clean_body = body.trim();
        // Parse JSON if returned from ipwho.is
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(clean_body) {
            if let Some(ip) = json.get("ip").and_then(|v| v.as_str()) {
                let country = json
                    .get("country_code")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_uppercase());
                return Ok(BridgeProbeResult {
                    observed_ipv4: ip.to_string(),
                    observed_ipv6: None,
                    observed_country: country,
                    latency_ms,
                    dns_summary:
                        "Remote DNS resolution via authenticated proxy bridge (no local DNS leak)"
                            .to_string(),
                });
            }
        }
        // If plain IP response
        if clean_body.split('.').count() == 4 && clean_body.len() <= 45 {
            return Ok(BridgeProbeResult {
                observed_ipv4: clean_body.to_string(),
                observed_ipv6: None,
                observed_country: None,
                latency_ms,
                dns_summary: "Remote DNS resolution via authenticated proxy bridge".to_string(),
            });
        }
    }

    // Fallback probe to api.ipify.org through the same bridge
    let mut stream2 = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|e| format!("Local proxy bridge unreachable on fallback: {}", e))?;
    stream2.set_read_timeout(Some(timeout)).ok();
    stream2.set_write_timeout(Some(timeout)).ok();
    let req2 = "GET http://api.ipify.org/ HTTP/1.1\r\nHost: api.ipify.org\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n";
    stream2
        .write_all(req2.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut resp2 = Vec::new();
    stream2.read_to_end(&mut resp2).map_err(|e| e.to_string())?;
    let latency2 = start.elapsed().as_millis() as u32;
    let resp2_str = String::from_utf8_lossy(&resp2);
    if let Some((_, body)) = resp2_str.split_once("\r\n\r\n") {
        let ip = body.trim();
        if ip.split('.').count() == 4 && ip.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return Ok(BridgeProbeResult {
                observed_ipv4: ip.to_string(),
                observed_ipv6: None,
                observed_country: None,
                latency_ms: latency2,
                dns_summary: "Remote DNS resolution via authenticated proxy bridge".to_string(),
            });
        }
    }

    Err("Proxy bridge did not return a valid public IP response".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    #[test]
    fn test_proxy_bridge_config_validation() {
        let valid = UpstreamProxyConfig {
            environment_id: "env-1".to_string(),
            endpoint_id: "ep-1".to_string(),
            protocol: "HTTP".to_string(),
            host: "proxy.us-east.example.com".to_string(),
            port: 8080,
            username: Some("user123".to_string()),
            password: Some("pass123".to_string()),
            connect_timeout: Duration::from_secs(5),
        };
        assert!(ProxyBridgeManager::validate_config(&valid).is_ok());

        let socks = UpstreamProxyConfig {
            protocol: "SOCKS5".to_string(),
            ..valid.clone()
        };
        assert!(ProxyBridgeManager::validate_config(&socks).is_ok());

        let empty_host = UpstreamProxyConfig {
            host: "".to_string(),
            ..valid.clone()
        };
        assert!(ProxyBridgeManager::validate_config(&empty_host).is_err());

        let invalid_port = UpstreamProxyConfig {
            port: 0,
            ..valid.clone()
        };
        assert!(ProxyBridgeManager::validate_config(&invalid_port).is_err());

        let bad_proto = UpstreamProxyConfig {
            protocol: "FTP".to_string(),
            ..valid.clone()
        };
        assert!(ProxyBridgeManager::validate_config(&bad_proto).is_err());
    }

    #[test]
    fn test_proxy_bridge_fail_closed_on_unreachable_upstream() {
        let mgr = ProxyBridgeManager::new();

        // Configure bridge with an unreachable upstream port on localhost
        let config = UpstreamProxyConfig {
            environment_id: "env-fail-closed".to_string(),
            endpoint_id: "ep-fail-closed".to_string(),
            protocol: "HTTP".to_string(),
            host: "127.0.0.1".to_string(),
            port: 1, // Port 1 is reserved/closed
            username: None,
            password: None,
            connect_timeout: Duration::from_millis(500),
        };

        let status = mgr.start_or_replace_bridge(config).unwrap();
        assert!(status.running);
        assert!(status.local_port > 0);

        // Attempt to connect through bridge using CONNECT
        let bridge_addr = format!("127.0.0.1:{}", status.local_port);
        let mut client =
            TcpStream::connect_timeout(&bridge_addr.parse().unwrap(), Duration::from_secs(2))
                .expect("Should connect to local bridge");

        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        client.write_all(req.as_bytes()).unwrap();

        let mut resp = Vec::new();
        client.read_to_end(&mut resp).unwrap();
        let resp_str = String::from_utf8_lossy(&resp);

        // Crucial security invariant: must return 502 Bad Gateway and fail closed.
        // It must NEVER attempt direct connection or allow traffic to escape.
        assert!(
            resp_str.contains("502 Bad Gateway"),
            "Expected 502 Bad Gateway but got: {}",
            resp_str
        );
        assert!(
            resp_str.contains("direct fallback blocked"),
            "Response must explicitly confirm direct fallback blocked: {}",
            resp_str
        );

        // Verify telemetry recorded the connection failure
        let bridge_status = mgr.get_bridge_status("env-fail-closed").unwrap();
        assert!(bridge_status.connection_failures >= 1);

        mgr.stop_bridge("env-fail-closed");
        assert!(mgr.get_bridge_status("env-fail-closed").is_none());
    }

    #[test]
    fn test_proxy_bridge_telemetry_tunnel_tracking() {
        let telemetry = BridgeTelemetry::new(50);
        let baseline = Utc::now() - chrono::Duration::seconds(1);

        telemetry.record_event(BridgeConnectionEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            bridge_instance_id: "inst-1".to_string(),
            environment_id: "env-1".to_string(),
            proxy_endpoint_id: "ep-1".to_string(),
            local_bridge_port: 49200,
            destination_host: "ipwho.is".to_string(),
            destination_port: 443,
            protocol: "HTTP_CONNECT".to_string(),
            connection_started_at: Utc::now().to_rfc3339(),
            connection_finished_at: Some(Utc::now().to_rfc3339()),
            outcome: BridgeTunnelOutcome::Success,
            latency_ms: Some(45),
            bytes_transferred: 1024,
        });

        // Exact match succeeds
        assert!(telemetry
            .find_matching_tunnel("inst-1", "env-1", "ep-1", "ipwho.is", 443, baseline)
            .is_some());
        // Wrong instance ID fails
        assert!(telemetry
            .find_matching_tunnel("inst-2", "env-1", "ep-1", "ipwho.is", 443, baseline)
            .is_none());
        // Wrong environment ID fails
        assert!(telemetry
            .find_matching_tunnel("inst-1", "env-2", "ep-1", "ipwho.is", 443, baseline)
            .is_none());
        // Wrong proxy endpoint ID fails
        assert!(telemetry
            .find_matching_tunnel("inst-1", "env-1", "ep-999", "ipwho.is", 443, baseline)
            .is_none());
        // Wrong destination host fails
        assert!(telemetry
            .find_matching_tunnel("inst-1", "env-1", "ep-1", "example.com", 443, baseline)
            .is_none());
        // Wrong destination port fails
        assert!(telemetry
            .find_matching_tunnel("inst-1", "env-1", "ep-1", "ipwho.is", 80, baseline)
            .is_none());
        // Stale timestamp (baseline after event) fails
        let future = Utc::now() + chrono::Duration::seconds(10);
        assert!(telemetry
            .find_matching_tunnel("inst-1", "env-1", "ep-1", "ipwho.is", 443, future)
            .is_none());

        assert!(telemetry.has_recent_connection_to("ipwho.is", 60));
        assert!(!telemetry.has_recent_connection_to("unknown.domain.org", 60));
        assert_eq!(telemetry.recent_events(60).len(), 1);
    }

    #[test]
    fn test_correlate_connect_tunnel_rejects_plain_http_zero_bytes_and_concurrent_ambiguity() {
        let telemetry = BridgeTelemetry::new(50);
        let baseline = Utc::now() - chrono::Duration::seconds(1);

        // 1. PLAIN_HTTP (from Rust backend probe_via_local_bridge) must NEVER satisfy browser CONNECT correlation
        telemetry.record_event(BridgeConnectionEvent {
            event_id: "ev-plain-http".to_string(),
            bridge_instance_id: "inst-1".to_string(),
            environment_id: "env-1".to_string(),
            proxy_endpoint_id: "ep-1".to_string(),
            local_bridge_port: 49200,
            destination_host: "ipwho.is".to_string(),
            destination_port: 80,
            protocol: "PLAIN_HTTP".to_string(),
            connection_started_at: Utc::now().to_rfc3339(),
            connection_finished_at: Some(Utc::now().to_rfc3339()),
            outcome: BridgeTunnelOutcome::Success,
            latency_ms: Some(25),
            bytes_transferred: 512,
        });
        assert_eq!(
            telemetry.correlate_connect_tunnel(
                "inst-1", "env-1", "ep-1", "ipwho.is", 443, baseline, None
            ),
            BridgeCorrelationOutcome::NoMatchingTunnel
        );
        assert_eq!(
            telemetry.correlate_connect_tunnel(
                "inst-1", "env-1", "ep-1", "ipwho.is", 80, baseline, None
            ),
            BridgeCorrelationOutcome::NoMatchingTunnel
        );

        // 2. Zero-byte HTTP_CONNECT must return ZeroBytesTransferred until bytes flow
        telemetry.record_event(BridgeConnectionEvent {
            event_id: "ev-connect-1".to_string(),
            bridge_instance_id: "inst-1".to_string(),
            environment_id: "env-1".to_string(),
            proxy_endpoint_id: "ep-1".to_string(),
            local_bridge_port: 49200,
            destination_host: "ipwho.is".to_string(),
            destination_port: 443,
            protocol: "HTTP_CONNECT".to_string(),
            connection_started_at: Utc::now().to_rfc3339(),
            connection_finished_at: Some(Utc::now().to_rfc3339()),
            outcome: BridgeTunnelOutcome::Success,
            latency_ms: Some(40),
            bytes_transferred: 0,
        });
        assert!(matches!(
            telemetry.correlate_connect_tunnel(
                "inst-1", "env-1", "ep-1", "ipwho.is", 443, baseline, None
            ),
            BridgeCorrelationOutcome::ZeroBytesTransferred(_)
        ));
        assert!(telemetry
            .find_matching_tunnel("inst-1", "env-1", "ep-1", "ipwho.is", 443, baseline)
            .is_none());

        // 3. Once bytes flow on ev-connect-1, correlation is Confirmed
        telemetry.add_bytes("ev-connect-1", 768);
        assert!(matches!(
            telemetry.correlate_connect_tunnel(
                "inst-1", "env-1", "ep-1", "ipwho.is", 443, baseline, None
            ),
            BridgeCorrelationOutcome::Confirmed(ref ev) if ev.event_id == "ev-connect-1" && ev.bytes_transferred == 768
        ));

        // 4. A second concurrent HTTP_CONNECT to ipwho.is:443 in the same window causes AmbiguousConcurrentTunnels
        telemetry.record_event(BridgeConnectionEvent {
            event_id: "ev-connect-2".to_string(),
            bridge_instance_id: "inst-1".to_string(),
            environment_id: "env-1".to_string(),
            proxy_endpoint_id: "ep-1".to_string(),
            local_bridge_port: 49200,
            destination_host: "ipwho.is".to_string(),
            destination_port: 443,
            protocol: "HTTP_CONNECT".to_string(),
            connection_started_at: Utc::now().to_rfc3339(),
            connection_finished_at: Some(Utc::now().to_rfc3339()),
            outcome: BridgeTunnelOutcome::Success,
            latency_ms: Some(42),
            bytes_transferred: 512,
        });
        assert_eq!(
            telemetry.correlate_connect_tunnel(
                "inst-1", "env-1", "ep-1", "ipwho.is", 443, baseline, None
            ),
            BridgeCorrelationOutcome::AmbiguousConcurrentTunnels(2)
        );
        assert!(telemetry
            .find_matching_tunnel("inst-1", "env-1", "ep-1", "ipwho.is", 443, baseline)
            .is_none());
    }
}
