use crate::security::redaction::redact_sensitive_str;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const MAX_CONCURRENT_CONNECTIONS: usize = 128;
const UPSTREAM_CONNECT_TIMEOUT_MS: u64 = 6000;
const STREAM_IO_TIMEOUT_MS: u64 = 15000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyBridgeStatus {
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
}

impl ProxyBridgeInstance {
    pub fn status(&self) -> ProxyBridgeStatus {
        ProxyBridgeStatus {
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

        let running = Arc::new(AtomicBool::new(true));
        let active_connections = Arc::new(AtomicUsize::new(0));
        let total_connections = Arc::new(AtomicU64::new(0));
        let successful_tunnels = Arc::new(AtomicU64::new(0));
        let auth_failures = Arc::new(AtomicU64::new(0));
        let connection_failures = Arc::new(AtomicU64::new(0));
        let last_error = Arc::new(Mutex::new(None));
        let last_activity_at = Arc::new(Mutex::new(None));
        let started_at = Utc::now().to_rfc3339();

        let instance = Arc::new(ProxyBridgeInstance {
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
        });

        {
            let mut map = self.bridges.lock().map_err(|_| "Bridge lock poisoned".to_string())?;
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
            conn_instance.active_connections.fetch_sub(1, Ordering::SeqCst);
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

fn handle_client_connection(
    mut client: TcpStream,
    instance: &ProxyBridgeInstance,
) -> Result<(), String> {
    let io_timeout = Some(Duration::from_millis(STREAM_IO_TIMEOUT_MS));
    client.set_read_timeout(io_timeout).ok();
    client.set_write_timeout(io_timeout).ok();

    let (header_str, leftover) = match read_http_request_head(&mut client) {
        Ok(res) => res,
        Err(e) => return Err(e),
    };

    let first_line = header_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        send_bad_gateway(&mut client, "Malformed HTTP proxy request");
        return Err("Malformed HTTP request line".to_string());
    }

    let method = parts[0].to_uppercase();
    let target = parts[1];

    if instance.config.protocol.eq_ignore_ascii_case("SOCKS5") {
        return handle_socks5_upstream(&mut client, instance, &method, target, &header_str, &leftover);
    }

    // HTTP / HTTPS Upstream Proxy
    let mut upstream = match connect_to_upstream(&instance.config) {
        Ok(s) => s,
        Err(e) => {
            record_bridge_error(instance, false, e.clone());
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
            send_bad_gateway(&mut client, &msg);
            return Err(msg);
        }

        let (resp_head, upstream_leftover) = match read_http_request_head(&mut upstream) {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("Upstream proxy closed during CONNECT handshake: {}", e);
                record_bridge_error(instance, false, msg.clone());
                send_bad_gateway(&mut client, &msg);
                return Err(msg);
            }
        };

        let status_line = resp_head.lines().next().unwrap_or("");
        if status_line.contains(" 407 ") || status_line.ends_with(" 407") {
            let msg = "Upstream proxy authentication failed (HTTP 407 Proxy Authentication Required)".to_string();
            record_bridge_error(instance, true, msg.clone());
            send_bad_gateway(&mut client, &msg);
            return Err(msg);
        }

        if !status_line.contains(" 200") {
            let msg = format!("Upstream proxy rejected CONNECT tunnel: {}", status_line);
            record_bridge_error(instance, false, msg.clone());
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

        relay_bidirectional(client, upstream);
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
            } else if !line.to_ascii_lowercase().starts_with("proxy-authorization:")
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
                send_bad_gateway(&mut client, &msg);
                return Err(msg);
            }
            Ok(n) => n,
            Err(e) => {
                let msg = format!("Failed reading upstream proxy response: {}", e);
                record_bridge_error(instance, false, msg.clone());
                send_bad_gateway(&mut client, &msg);
                return Err(msg);
            }
        };

        let first_str = String::from_utf8_lossy(&first_chunk[..n]);
        let status_line = first_str.lines().next().unwrap_or("");
        if status_line.contains(" 407 ") || status_line.ends_with(" 407") {
            let msg = "Upstream proxy authentication failed (HTTP 407 Proxy Authentication Required)".to_string();
            record_bridge_error(instance, true, msg.clone());
            send_bad_gateway(&mut client, &msg);
            return Err(msg);
        }

        instance.successful_tunnels.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut err) = instance.last_error.lock() {
            *err = None;
        }

        let _ = client.write_all(&first_chunk[..n]);
        let _ = std::io::copy(&mut upstream, &mut client);
        let _ = client.shutdown(Shutdown::Both);
        Ok(())
    }
}

fn parse_target_host_port(method: &str, target: &str) -> Result<(String, u16, String), String> {
    if method == "CONNECT" {
        if let Some((h, p_str)) = target.rsplit_once(':') {
            let port = p_str.parse::<u16>().map_err(|_| "Invalid CONNECT port".to_string())?;
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

fn handle_socks5_upstream(
    client: &mut TcpStream,
    instance: &ProxyBridgeInstance,
    method: &str,
    target: &str,
    header_str: &str,
    leftover: &[u8],
) -> Result<(), String> {
    let (dest_host, dest_port, rel_path) = parse_target_host_port(method, target)?;
    let mut upstream = match connect_to_upstream(&instance.config) {
        Ok(s) => s,
        Err(e) => {
            record_bridge_error(instance, false, e.clone());
            send_bad_gateway(client, &e);
            return Err(e);
        }
    };

    // SOCKS5 greeting
    let creds = instance.config.formatted_credentials();
    if creds.is_some() {
        upstream.write_all(&[0x05, 0x02, 0x00, 0x02]).map_err(|e| e.to_string())?;
    } else {
        upstream.write_all(&[0x05, 0x01, 0x00]).map_err(|e| e.to_string())?;
    }

    let mut method_resp = [0u8; 2];
    if let Err(e) = upstream.read_exact(&mut method_resp) {
        let msg = format!("SOCKS5 greeting failed: {}", e);
        record_bridge_error(instance, false, msg.clone());
        send_bad_gateway(client, &msg);
        return Err(msg);
    }

    if method_resp[0] != 0x05 || method_resp[1] == 0xFF {
        let msg = "SOCKS5 proxy rejected authentication methods".to_string();
        record_bridge_error(instance, true, msg.clone());
        send_bad_gateway(client, &msg);
        return Err(msg);
    }

    if method_resp[1] == 0x02 {
        let c = creds.ok_or_else(|| {
            let msg = "SOCKS5 proxy requires credentials, but none were provided".to_string();
            record_bridge_error(instance, true, msg.clone());
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
        upstream.read_exact(&mut auth_resp).map_err(|e| e.to_string())?;
        if auth_resp[1] != 0x00 {
            let msg = "SOCKS5 proxy authentication failed (invalid username or password)".to_string();
            record_bridge_error(instance, true, msg.clone());
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
        send_bad_gateway(client, &msg);
        return Err(msg);
    }
    if reply_hdr[1] != 0x00 {
        let msg = format!("SOCKS5 connect to {}:{} failed (code {})", dest_host, dest_port, reply_hdr[1]);
        record_bridge_error(instance, false, msg.clone());
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

    if method == "CONNECT" {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .map_err(|e| e.to_string())?;
        if !leftover.is_empty() {
            let _ = upstream.write_all(leftover);
        }
        if let Ok(client_clone) = client.try_clone() {
            relay_bidirectional(client_clone, upstream);
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
        upstream.write_all(rebuilt.as_bytes()).map_err(|e| e.to_string())?;
        if !leftover.is_empty() {
            let _ = upstream.write_all(leftover);
        }
        let _ = std::io::copy(&mut upstream, client);
        let _ = client.shutdown(Shutdown::Both);
        Ok(())
    }
}

fn relay_bidirectional(mut client: TcpStream, mut upstream: TcpStream) {
    let mut client_reader = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut upstream_writer = match upstream.try_clone() {
        Ok(u) => u,
        Err(_) => return,
    };

    let c2u = thread::spawn(move || {
        let _ = std::io::copy(&mut client_reader, &mut upstream_writer);
        let _ = upstream_writer.shutdown(Shutdown::Write);
    });

    let _ = std::io::copy(&mut upstream, &mut client);
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

pub fn probe_via_local_bridge(local_port: u16, timeout: Duration) -> Result<BridgeProbeResult, String> {
    let start = Instant::now();
    let addr = SocketAddr::from(([127, 0, 0, 1], local_port));
    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|e| format!("Local proxy bridge (127.0.0.1:{}) unreachable: {}", local_port, e))?;
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
                    dns_summary: "Remote DNS resolution via authenticated proxy bridge (no local DNS leak)".to_string(),
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
    stream2.write_all(req2.as_bytes()).map_err(|e| e.to_string())?;
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

