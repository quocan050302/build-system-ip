# Implementation Plan & Cross-Platform Verification Matrix

## 1. Project Upgrade Overview

The YouTube Isolation Manager has been upgraded from a Windows-only prototype to a full production-grade cross-platform desktop application supporting:
- **Windows 11 Pro x64**: Native Type-1 **Microsoft Hyper-V**, Generation 2 VMs, persistent `.vhdx` disks, `vmconnect.exe` console, and Windows DPAPI secret protection.
- **macOS Apple Silicon ARM64**: Native **UTM / Apple Virtualization Framework**, persistent sparse virtual disks, direct console, and Apple Keychain Services secret sealing.

---

## 2. Phase Execution Status

| Phase | Description | Status | Deliverables |
| :--- | :--- | :--- | :--- |
| **Phase 1** | Codebase Audit & Architectural Plan | **COMPLETED** | Complete audit in `audit_and_architecture_plan.md` |
| **Phase 2** | Real Platform & Hardware Detection | **COMPLETED** | `PlatformService` (sysctl/libc + Win32, no fabrication) |
| **Phase 3** | Hypervisor Abstraction Layer | **COMPLETED** | `HypervisorAdapter` trait + factory (no silent mock fallback) |
| **Phase 4** | Windows Hyper-V Implementation | **COMPLETED** | `HyperVAdapter` (PowerShell/WMI, VHDX, vmconnect) |
| **Phase 5** | macOS UTM Implementation | **COMPLETED** | `UTMAdapter` (UTM.app, utmctl, sparse disk, timeouts) |
| **Phase 6** | Cross-Platform Secret Storage | **COMPLETED** | Unified `SecretStore` (Windows DPAPI + macOS Keychain) |
| **Phase 7** | Real Environment & Storage Isolation | **COMPLETED** | Persistent disk formatting, distinct guest paths, browser hook |
| **Phase 8** | Truthful Network Diagnostics | **COMPLETED** | TCP handshake latency, removed fake IPs, duplicate alerts |
| **Phase 9** | Shared Desktop Dashboard | **COMPLETED** | 5-tab UI, dynamic hypervisor badge, Real vs Demo mode |
| **Phase 10** | Database & Versioned Migrations | **COMPLETED** | Migration v2 preserving existing SQLite data intact |
| **Phase 11** | Comprehensive Automated Testing | **COMPLETED** | 17 Rust integration tests + 5 Vitest UI tests (all passed) |
| **Phase 12** | Cross-Platform Build & Packaging | **COMPLETED** | `.app` & `.dmg` (macOS), NSIS/MSI CI workflow (`ci.yml`) |
| **Phase 13** | Verification & Execution Discipline | **COMPLETED** | End-to-end verification and documentation |

---

## 3. Automated Test Traceability Matrix

### Rust Integration Test Suite (`tests/integration_tests.rs`)
| Test ID | Function Name | Scope / Requirement | Result |
| :--- | :--- | :--- | :--- |
| **ENV-001** | `test_env_001_create_environment_valid` | Valid environment creation & DB persistence | **PASSED** |
| **ENV-002** | `test_env_002_reject_duplicate_environment_name` | Unique environment name enforcement | **PASSED** |
| **ENV-005** | `test_env_005_start_and_shutdown_vm` | Hypervisor start & graceful shutdown lifecycle | **PASSED** |
| **ENV-008** | `test_env_008_prevent_unsafe_deletion_of_running_vm` | Prevent destructive deletion of active VMs | **PASSED** |
| **ENV-009** | `test_env_009_storage_isolation_distinct_paths` | Dedicated, disjoint disk & profile paths | **PASSED** |
| **NET-001** | `test_net_001_truthful_guest_network_check` | Stopped VM reports `NOT_CHECKED`, no fake IP | **PASSED** |
| **NET-002** | `test_net_002_verified_in_guest_diagnostics` | Running VM records verified in-guest diagnostics | **PASSED** |
| **NET-005** | `test_net_005_duplicate_egress_warning_detection` | Flags duplicate public IPs across environments | **PASSED** |
| **BR-005** | `test_br_005_reject_path_traversal_cross_platform` | Rejects Windows (`\`) and Unix (`/`) traversal | **PASSED** |
| **CH-001/4**| `test_ch_001_and_004_channel_compliance_and_termination_lock` | Compliance locking on terminated channels | **PASSED** |
| **SEC-001** | `test_sec_001_vault_encryption_and_retrieval_roundtrip` | Native vault (DPAPI / Keychain) roundtrip | **PASSED** |
| **PLAT-001**| `test_platform_service_detection_and_real_resources` | Real OS, RAM, disk, and capabilities detection | **PASSED** |
| **HYPV-001**| `test_hyperv_adapter_detection_structure` | Hyper-V adapter detection structure | **PASSED** |
| **UTM-001** | `test_utm_adapter_detection_structure` | UTM adapter detection structure & VM details | **PASSED** |
| **FACT-001**| `test_hypervisor_factory_no_silent_mock_fallback` | Production factory strictly rejects silent mock | **PASSED** |
| **RECON-001**| `test_application_restart_reconciliation` | Reconciles DB states with native hypervisor | **PASSED** |
| **MIGR-001**| `test_database_migrations_v1_to_v2` | Migration v2 applies without losing v1 data | **PASSED** |

### Frontend UI Test Suite (`src/test/app.test.tsx`)
| Test ID | Test Scenario | Result |
| :--- | :--- | :--- |
| **UI-001** | Brand rendering & 5 primary navigation tabs | **PASSED** |
| **UI-002** | Seamless navigation between all 5 screens (REG-001) | **PASSED** |
| **UI-003** | Semantic status badges rendering | **PASSED** |
| **UI-004** | Create Environment modal workflow and cancellation | **PASSED** |
| **UI-005** | Encrypted secret vault cryptographic test tool in Settings | **PASSED** |

---

## 4. Production Packaging Verification

On macOS Apple Silicon (`aarch64-apple-darwin`):
- **Release Executable**: `src-tauri/target/release/youtube-isolation-manager` (Mach-O 64-bit arm64, 11 MiB) — **VERIFIED**
- **Application Bundle**: `src-tauri/target/release/bundle/macos/YouTube Isolation Manager.app` (11.44 MiB) — **VERIFIED**
- **Disk Image**: `src-tauri/target/release/bundle/dmg/YouTube Isolation Manager_1.0.0_aarch64.dmg` (3.61 MiB) — **VERIFIED**

On Windows x64 (`x86_64-pc-windows-msvc`):
- Configured in `.github/workflows/ci.yml` and `tauri.conf.json` for `.exe` release binary and NSIS/MSI installers.

---

## 5. Known Limitations & Operational Guidance

1. **macOS UTM Daemon Dependency**:
   - `utmctl` communicates with UTM via XPC. If UTM.app is not actively launched, `utmctl` commands require UTM to be launched.
   - Built-in safeguard: `UTMAdapter` incorporates a 3-second non-blocking timeout on all `utmctl` invocations to prevent freezing the application.
2. **Windows Hyper-V Permissions**:
   - Hyper-V PowerShell management requires Administrator privileges or membership in the local `Hyper-V Administrators` group. The `PlatformService` reports permissions status directly to the user in Settings.
3. **Guest Architecture Matching**:
   - On macOS Apple Silicon (ARM64), guest OS images must be ARM64 (e.g., Ubuntu Linux ARM64). Emulating x86_64 images is intentionally not permitted to prioritize virtualization performance over slow CPU emulation.

---

## Phase 6 — Proxy Verification Hardening (fix/macos-edge-us-proxy-verification-v2)

### Status: ENGINEERING_READY_LIVE_VERIFICATION_PENDING (V8)

### Changes delivered (cumulative V1–V8)

#### Defect fixes
1. **FALSE BROWSER_EGRESS_VERIFIED** — `verify_browser_egress()` now returns `PROXY_EGRESS_VERIFIED` for backend bridge probes. `BROWSER_EGRESS_VERIFIED` requires all invariants: managed Edge PID alive, non-empty `profile_path`, verified CDP ownership (`DevToolsActivePort` + `ps` + `lsof`), CDP `PUT /json/new?about:blank` + `Page.navigate` response body parsed, globally-routable public IP observed, non-`UNKNOWN` country match, and unambiguous `HTTP_CONNECT` proxy tunnel with `bytes_transferred > 0`.
2. **UNKNOWN country false pass** — `UNKNOWN` and empty geolocation results now fail when `expected_country` is set.Fallback IP-only providers (`api.ipify.org`) never fabricate a country code.
3. **IP address validation** — `expected_ip` and observed IP validated with `std::net` parsers; RFC5737, private, loopback, link-local, CGNAT ranges all rejected.
4. **Windows E0432** — `Win32_System_Threading` Cargo feature added; `CloseHandle` import corrected to `Win32::Foundation`.
5. **Mock CDP false pass** — `evaluate_verification_decision()` rejects any result with `verification_source == "SIMULATED_MOCK_CDP"`.
6. **V8 Chromium 157+ `/json/new` HTTP 405 fix** — Replaced `GET /json/new?about:blank` with `PUT /json/new?about:blank` in `create_cdp_blank_target_full`, with HTTP status code validation, response size caps, and `CdpTargetGuard` RAII cleanup via `GET /json/close/{id}`.
7. **V8 CORS-free CDP navigation** — Replaced `Runtime.evaluate(fetch(...))` on `about:blank` with `Page.enable`, `Network.enable`, `Network.setCacheDisabled(true)`, `Page.navigate`, `Network.requestWillBeSent`, `Network.responseReceived`, `Network.loadingFinished`, and `Network.getResponseBody`.
8. **V8 `DevToolsActivePort` & CDP session ownership** — Replaced pre-bind/drop port allocation with `--remote-debugging-port=0 --remote-debugging-address=127.0.0.1` and `<profile_dir>/DevToolsActivePort` discovery, plus `verify_managed_cdp_ownership`.
9. **V8 Proxy CONNECT correlation & UI badge truthfulness** — Real-time `bytes_transferred` tracking in `relay_bidirectional`, `correlate_connect_tunnel` rejecting `PLAIN_HTTP` / zero-byte / concurrent ambiguous tunnels, explicit CDP failure surfacing in `verify_browser_egress` (no `.ok()` swallowing), and honest `⚠️ Assumed (Proxy)` (`REMOTE_PROXY_DNS`) badge in `NetworkView.tsx`.

#### CDP browser-origin verification (implemented in V5–V7)
- `attempt_cdp_browser_verification` — connects to Edge's CDP debug port, creates a **dedicated blank target** (`/json/new?about:blank`), injects a `fetch("https://ipwho.is/")` via `Runtime.evaluate`, parses the JSON response for `ip` and `country`, cleans up the target on all exit paths.
- Dedicated blank target prevents CDP commands from contaminating social-media tab state.
- `create_cdp_blank_target` / `close_cdp_target` — explicit lifecycle management with best-effort cleanup.
- `BrowserSessionInfo` carries `bridge_instance_id` and `is_simulation` flags; `is_simulation: true` permanently blocks `BROWSER_EGRESS_VERIFIED`.
- `find_matching_tunnel` — correlates the CDP-observed egress IP against active proxy-bridge tunnel records within a ±60-second time window; confirms the browser request transited the managed proxy.

#### Proxy bridge telemetry (V4–V6)
- `BridgeTunnelOutcome` / `BridgeConnectionEvent` — full telemetry: upstream host, port, timestamp, bytes, latency, outcome.
- `get_instance_id()` — UUID per bridge process lifetime; stale verification invalidated on restart.
- Fail-closed: proxy failure returns error; no silent direct-network fallback.

#### Network protection status
- `NetworkProtectionStatus` — structured DNS/IPv6/WebRTC status reporting to UI.
- `is_verification_stale()` — cached results older than the configured threshold are automatically marked stale.

#### CI & V9 Verification Orchestration
- `macos-14` → `macos-15` for reliable ARM64 runner.
- Feature branch triggers added (`fix/**`, `feature/**`).
- Architecture verification step in macOS jobs.
- Bounded timeouts on all jobs.
- `scripts/verify_v9.py` bounded async/parallel orchestrator:
  - Runs independent DAG branches (`frontend_branch`, `selftest_branch`, `rust_cargo_branch`) concurrently via `asyncio.gather` while strictly serializing Cargo invocations (`Semaphore(1)`).
  - Enforces `ANTI_REQUIRE_REAL_EDGE=1` when Microsoft Edge is installed so absent Edge can never silently pass as green.
  - Evaluates 35 deterministic synthetic replay cases (`10 DEV` + `10 HOLDOUT` + `15 ADVERSARIAL_HOLDOUT`) with `0` false-positive `BROWSER_EGRESS_VERIFIED` outcomes, while classifying `HISTORICAL_BACKTEST_GATE` as `INSUFFICIENT_HISTORICAL_EVIDENCE` and `LIVE_J2PROXY_US_GATE` as `NOT_RUN` when live J2Proxy credentials are not provisioned.
  - Writes durable atomic evidence (`v9_run_manifest.json` + `v9_summary.md` + redacted per-task logs) to `$RUNNER_TEMP/anti-v9` / `/tmp/anti-v9` and uploads CI artifacts with 14-day retention.
- 58 Rust tests (26 unit + 32 integration), 5 npm tests — all pass.

### Known remaining gaps

| Gap | Severity | Recommended action |
|---|---|---|
| HTTPS CONNECT tunnel opacity | MEDIUM | HTTP CONNECT bridge cannot correlate individual encrypted requests inside the tunnel; correlation relies on IP/timestamp heuristics |
| IPv6 bypass possible | HIGH | Add `--disable-ipv6` to Edge launch args or disable at VM network level |
| WebRTC runtime not verified | MEDIUM | Use CDP `Page.addScriptToEvaluateOnNewDocument` to inject WebRTC peer test |
| DNS routing not packet-verified | MEDIUM | Add network packet inspection or DNS query logging at proxy bridge |
| macOS ARM64 live Edge+Proxy test | HIGH | Manual test with real Edge + real J2Proxy credentials required |

### Production readiness
`ENGINEERING_READY_LIVE_VERIFICATION_PENDING`

All CI jobs must be GREEN on the final commit SHA. Real Microsoft Edge + real J2Proxy credentials + macOS ARM64 hardware acceptance test required before `READY_FOR_PRODUCTION`.
