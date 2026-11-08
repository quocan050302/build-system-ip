# Security Model & Threat Assessment

## 1. Core Principles

The **YouTube Isolation Manager** is designed around zero-trust isolation between distinct content environments. The security model adheres strictly to the following principles:

1. **Non-Evasion & Platform Integrity:** The application **does not** provide features designed to bypass YouTube/Google platform integrity systems, such as fingerprint spoofing, CAPTCHA solving, automated identity spinning, or ban circumvention. Terminated accounts are permanently flagged read-only.
2. **Encrypted Storage at Rest:** No plaintext storage of proxy passwords, API tokens, or OAuth credentials. Secrets are sealed using the **Windows Data Protection API (DPAPI)**.
3. **Strict Memory & Log Redaction:** Secret values are zeroized in memory where possible and scrubbed from all application logs, debug outputs, and database crash dumps.
4. **Least-Privilege Process Execution:** The desktop application runs in user space without requiring Administrator privileges during normal operation. System commands (such as `VBoxManage`) are invoked with strict argument arrays without shell interpolation.
5. **No Cross-Contamination:** No shared browser cache, cookies, local storage, writable VM disks, or network sockets between managed environments.

---

## 2. Windows DPAPI Encryption Vault

Sensitive application parameters (e.g., HTTP/SOCKS5 proxy authentication credentials, future Google OAuth refresh tokens) are encrypted on disk using the Windows DPAPI:

- **Windows API:** `CryptProtectData` and `CryptUnprotectData` (via Rust `windows` or `dpapi` crate).
- **Scope:** `CRYPTPROTECT_UI_FORBIDDEN` ensures non-interactive operation; tied to the current logged-in Windows user account.
- **Key Derivation:** Cryptographic keys are managed by Windows Local Security Authority (LSA) and tied to user login credentials and TPM/DPAPI master keys.
- **Export Discipline:** Backups and configuration exports explicitly exclude or redact DPAPI-protected secrets. Unencrypted secrets are never exported into plain JSON configuration files.

---

## 3. Threat Matrix & Mitigations

| Threat | Risk Level | Description | Technical Mitigation |
| :--- | :--- | :--- | :--- |
| **Cross-Profile Cookie Leakage** | High | One channel's session cookies or WebStorage accessed by another channel. | Independent, isolated filesystem directories for each browser profile (`--user-data-dir` / profile folder). Preflight checks verify no two environments reference the same directory path. |
| **Command Injection via VM/Path Name** | High | Malicious characters in VM name or ISO path passed to CLI tools. | Safe process spawning using vector arguments (`std::process::Command` without shell wrapper). Strict regex validation on environment names (`^[a-zA-Z0-9_-]+$`). |
| **Accidental False Clean Egress** | High | User assumes VM has independent proxy, but traffic leaks through host NIC. | Real guest-level diagnostics; no assumed statuses. Host status does not equal guest status. Explicit warning if observed public IP matches any other active environment. |
| **Plaintext Credential Exposure in Logs** | High | Proxy credentials printed during connection error logging. | Structured logging wrapper (`tracing` crate) with custom redaction layers replacing credentials with `[REDACTED]`. |
| **Unsafe VM Deletion** | Medium | User deletes an environment while the VM is executing, causing disk corruption or data loss. | State interlocks: VMs in `RUNNING` or `STARTING` state must be cleanly stopped or confirmed before deletion. Writable disk deletion requires double confirmation. |
| **Privilege Escalation** | Medium | App attempting to modify host routing table or host network adapters. | Hard rule: The app **never** modifies host network configurations or routing tables silently. All proxy configurations are scoped to guest or browser instances. |

---

## 4. Guest Diagnostics Communication Channel

When guest companion diagnostics are enabled:
1. Communication between the host application and the guest VM is strictly local (VirtualBox Guest Control or local host-only loopback port).
2. All messages exchanged carry an ephemeral session token generated at VM launch.
3. The guest companion only exposes diagnostic read queries (public IP query, DNS resolution check, interface list). It **never** exposes an arbitrary code execution interface.

---

## 5. Account Compliance State Machine

To prevent accidental unauthorized actions on restricted or terminated YouTube channels:

```text
[UNVERIFIED] ───(Validate Channel ID)───► [AUTHORIZED]
      │                                       │
      │                                       ├──(Quota / Content Warning)──► [RESTRICTED]
      │                                       │                                   │
      └───────────────────────────────────────┼──(Account Closed / Terminated)────► [TERMINATED]
                                              │                                       │
                                              └──(User Deactivation)──────────────► [ARCHIVED]
```

- **TERMINATED Accounts:** UI publishing controls and automated workflows are permanently disabled and rendered disabled/read-only with an explicit warning badge.

---

## 6. macOS Native Browser Mode — Proxy Bridge Security (Added: v2 Hardening)

When environments use `execution_mode = NATIVE_BROWSER` on macOS Apple Silicon, Microsoft Edge is launched with a supervised localhost proxy bridge instead of direct proxy credentials.

### Architecture

```
Edge Process
    └─ --proxy-server=http://127.0.0.1:<dynamic_port>
           │
           ▼
    Localhost Proxy Bridge (Rust, 127.0.0.1:0)
           │  Credentials: Apple Keychain only
           │  No fallback to direct connection
           ▼
    Upstream HTTP/SOCKS5 Proxy (J2Proxy US)
           │
           ▼
    Target Websites (TikTok, Instagram, Facebook, Gumroad)
```

### Threat Mitigations

| Threat | Mitigation |
|---|---|
| Credential exposure in CLI args | Bridge pattern: Edge receives only `127.0.0.1:<port>`, never `user:pass@host` |
| Local bridge accessible by other processes | Dynamic port (`:0`), not advertised; no authentication required (limitation documented) |
| Direct connection fallback when proxy fails | Bridge returns HTTP 502 Bad Gateway; no silent fallback |
| Non-loopback connections to bridge | Peer address check: non-loopback connections are dropped immediately |
| WebRTC IP leak | `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` applied at Edge launch |
| DNS leak | SOCKS5: domain-mode CONNECT (remote DNS); HTTP: proxy handles DNS |
| IPv6 leak | Bridge is IPv4-only; IPv6 traffic path **unverified** (documented risk) |
| Unbounded resource usage | MAX_CONCURRENT_CONNECTIONS=128; IO timeouts 15s; connect timeout 6s |

### Verification Status Hierarchy

The system uses a strict status hierarchy to avoid false PASS:

| Status | Meaning | Evidence Required |
|---|---|---|
| `NOT_CONFIGURED` | No proxy endpoint assigned | — |
| `ENDPOINT_CONFIGURED` | Proxy config saved to DB | — |
| `ENDPOINT_REACHABLE` | TCP handshake succeeded | TCP connect to proxy host:port |
| `PROXY_EGRESS_VERIFIED` | Backend Rust probe through bridge returned valid US IP | ipwho.is response via 127.0.0.1:bridge_port |
| `BROWSER_EGRESS_VERIFIED` | Real Edge-origin request via CDP confirmed US exit IP, session/profile ownership verified, and proxy CONNECT tunnel correlated | CDP `PUT /json/new?about:blank` + `Page.navigate` (`Network.getResponseBody`) + `verify_managed_cdp_ownership` (`DevToolsActivePort` / `ps` / `lsof`) + `correlate_connect_tunnel` (`HTTP_CONNECT` with `bytes_transferred > 0` and zero concurrent ambiguity) |
| `VERIFICATION_UNAVAILABLE` | Cannot verify (browser not running, no bridge) | — |
| `AUTH_FAILED` | Proxy credentials rejected (HTTP 407) | — |
| `CONNECTION_FAILED` | Network path failed or country mismatch | — |

### Critical Distinctions

**`PROXY_EGRESS_VERIFIED` ≠ `BROWSER_EGRESS_VERIFIED`**

A backend Rust probe through the proxy bridge proves:
- ✅ The bridge is running
- ✅ The upstream proxy accepts connections
- ✅ The upstream proxy reports a US exit IP
- ❌ Does NOT prove Edge browser sent the request
- ❌ Does NOT prove all browser traffic uses the proxy

**`PROXY_EGRESS_VERIFIED` ≠ US Physical Location**
- ✅ The proxy server has a US exit IP
- ❌ Does NOT make the user physically located in the US
- ❌ Does NOT guarantee content is delivered to US audiences
- ❌ Does NOT change account region settings on TikTok/Instagram/Facebook

### Country Validation (Fixed in v2)

If `expected_country` is configured (e.g., "US"):
- `UNKNOWN` geolocation result → `CONNECTION_FAILED` (was: false pass in v1)
- Empty country → `CONNECTION_FAILED`
- Country mismatch (e.g., VN) → `CONNECTION_FAILED`
- Matching country (US) + all other checks pass → `PROXY_EGRESS_VERIFIED`

### Known Gaps (Remaining)

1. **IPv6 bypass risk**: Edge may use IPv6 if the system has it; traffic would bypass the IPv4-only proxy bridge. Recommend disabling IPv6 at UTM VM network level, or adding `--disable-ipv6` to Edge launch args.
2. **WebRTC runtime verification**: `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` is applied at launch but not confirmed effective at runtime. Full verification requires injecting JavaScript via CDP to test `RTCPeerConnection`.
3. **HTTPS CONNECT tunnel opacity & V8 mitigation**: HTTP CONNECT establishes an encrypted TLS tunnel; the local proxy bridge cannot inspect encrypted HTTP payloads inside TLS without MITM interception (which is intentionally avoided to preserve certificate integrity). In V8, `BridgeTelemetry::correlate_connect_tunnel` requires an `HTTP_CONNECT` tunnel (rejecting `PLAIN_HTTP` backend probes), matching `environment_id`, `proxy_endpoint_id`, `bridge_instance_id`, exact provider `host:443`, `bytes_transferred > 0` tracked in real time during bidirectional relay, and **uniqueness** (if >1 concurrent `HTTP_CONNECT` tunnel to the same verification host:port overlaps the window, correlation returns `AmbiguousConcurrentTunnels` and fails closed to `PROXY_EGRESS_VERIFIED`).
4. **CDP session & profile ownership (V8 hardening)**: Edge is launched with `--remote-debugging-port=0 --remote-debugging-address=127.0.0.1` and discovered via `<profile_dir>/DevToolsActivePort` (eliminating pre-bind TOCTOU races). Before any CDP verification runs, `verify_managed_cdp_ownership` verifies PID liveness, non-empty `profile_path`, `DevToolsActivePort` port match, OS process command line (`--user-data-dir`, `--proxy-server=http://127.0.0.1:<bridge_port>`, Edge executable), and TCP LISTEN ownership (`lsof`).
5. **Bridge port visibility**: Any local process can connect to the dynamic port if discovered. Consider token-based access control for the bridge in a future hardening pass.

---

## 7. DNS, IPv6 and WebRTC Protection Status

### 7.1 DNS

| Scenario | Status | Notes |
|---|---|---|
| HTTP proxy (CONNECT) | UNVERIFIED | Proxy handles DNS on remote side; host resolver not used for CONNECT targets |
| SOCKS5 (domain mode) | UNVERIFIED | Domain sent to upstream proxy for resolution; host DNS not invoked |
| Host-side DNS resolver | RISK | If SOCKS5 is used in IP mode or HTTP proxy fails, host DNS may be used |
| Verification method | UNVERIFIED | Runtime DNS verification requires packet capture or browser instrumentation |

**Current limitation:** DNS routing is assumed to be remote (proxy-side) based on CONNECT/SOCKS5 semantics. This has not been independently verified with packet capture or DNS query monitoring.

### 7.2 IPv6

| Property | Status |
|---|---|
| Proxy bridge IPv6 support | NOT APPLICABLE — bridge is IPv4-only (127.0.0.1) |
| Edge IPv6 connectivity | UNVERIFIED |
| IPv6 bypass risk | PRESENT — if system has IPv6 and Edge uses it, traffic may bypass proxy |
| Mitigation applied | NONE — no OS-level IPv6 disable applied |
| Recommended action | Disable IPv6 at UTM VM network level, or add --disable-ipv6 to Edge launch args |

**Current limitation:** The proxy bridge only listens on 127.0.0.1 (IPv4). If Microsoft Edge establishes IPv6 connections to social media endpoints, those connections will NOT route through the proxy bridge. IPv6 bypass is a confirmed risk that has not been mitigated in the current implementation.

### 7.3 WebRTC

| Property | Status |
|---|---|
| Launch flag applied | `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` |
| Flag effectiveness verified | UNVERIFIED — runtime test not performed |
| WebRTC API available | Assumed present in Edge |
| Non-proxied UDP disabled | Assumed via flag; not confirmed |

**Current limitation:** The WebRTC policy flag is supplied at Edge launch. It is not verified at runtime that (a) Edge honored the flag, (b) the flag is effective for the specific Edge version installed, or (c) no WebRTC requests using non-proxied paths were actually made. Full verification requires injecting JavaScript via CDP to test `RTCPeerConnection` behavior.

### 7.4 Protection Summary

| Component | Verified | Evidence |
|---|---|---|
| Proxy bridge loopback binding | ✅ YES | Code: `TcpListener::bind("127.0.0.1:0")` |
| Credential redaction in logs | ✅ YES | `redact_sensitive_str()` applied before all log calls |
| No direct connection fallback | ✅ YES | Bridge returns 502 on upstream failure; no silent fallback |
| DNS routing through proxy | ⚠️ ASSUMED | CONNECT/SOCKS5 semantics; not packet-verified |
| IPv6 bypass prevention | ❌ NOT MITIGATED | No IPv6 disable; bridge is IPv4-only |
| WebRTC non-proxied UDP disable | ⚠️ POLICY SET | Flag applied at launch; runtime not verified |
| Browser-origin verification | ✅ IMPLEMENTED (local controlled proxy proven; live J2Proxy US pending) | CDP `PUT /json/new?about:blank` + `Page.navigate` + `Network.*` → IP/country + `correlate_connect_tunnel` (`bytes_transferred > 0`, unique active tunnel); `ANTI_REQUIRE_REAL_EDGE=1` enforced in `scripts/verify_v9.py` |

## 8. Legitimate Use Boundaries

This system is designed for authorized management of social media accounts for content creators. The following are strictly NOT supported use cases:

- Fabricating US residency or identity
- Circumventing platform account restrictions or bans
- Generating artificial engagement (likes, views, follows, comments)
- Manipulating platform recommendation algorithms
- Operating accounts without platform authorization
- Claiming verified US audience reach based solely on proxy country match

A verified US proxy exit point means:
- Network traffic routes through a US IP address.
- The platform's server observes a US IP for API requests.

It does NOT mean:
- The account holder is a US resident.
- Platform content distribution will target US audiences.
- Audience demographics will be US-based.
- Any platform policy is satisfied or circumvented.

**US PROXY VERIFIED ≠ US ACCOUNT REGION ≠ US AUDIENCE DISTRIBUTION**
