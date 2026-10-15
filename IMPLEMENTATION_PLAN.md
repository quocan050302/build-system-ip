# Implementation Plan & Verification Matrix

## 1. Project Roadmap Overview

This implementation plan follows a strict, incremental phase discipline. Each phase must result in verified, test-passing code before proceeding to the subsequent phase.

```text
Phase 0: Workspace & Architecture Blueprint [COMPLETED]
   │
Phase 1: Desktop Foundation & Persistence (Tauri 2 + React + Rust + SQLite + DPAPI)
   │
Phase 2: Environment Management & Hypervisor Adapter (VirtualBox & Mock Adapter)
   │
Phase 3: Network Diagnostics & Truthful Egress Verification
   │
Phase 4: Browser Profile Isolation & Channel Compliance
   │
Phase 5: Vault Security, Backup & Audit Trail
   │
Phase 6: UI/UX Refinement (Tailwind, Lucide, Modals, Responsive Grids)
   │
Phase 7: Comprehensive Verification & Production Packaging
```

---

## 2. Phase Breakdown & Deliverables

### Phase 0: Workspace & Architecture Blueprint
- [x] Inspect workspace and system environment (Windows 11, Node v22.14.0, pnpm v12.11.2, Rust toolchain setup).
- [x] Author system architecture specification (`ARCHITECTURE.md`).
- [x] Author threat model & security specifications (`SECURITY_MODEL.md`).
- [x] Author implementation roadmap and verification matrix (`IMPLEMENTATION_PLAN.md`).
- [x] Author setup and developer guide (`README.md`).

### Phase 1: Desktop Foundation & Persistence
- Initialize Tauri 2 project with React 18, TypeScript, Tailwind CSS, Vite, and Lucide icons.
- Setup Rust backend with SQLite (using `rusqlite` or `sqlx` with bundled SQLite for zero external dependencies).
- Implement database schema migrations (tables: `environments`, `network_endpoints`, `environment_networks`, `network_checks`, `browser_profiles`, `channels`, `activity_logs`, `application_settings`).
- Implement Windows DPAPI cryptographic service for secure credential storage.
- Implement structured logging with redaction for sensitive values.
- Build desktop shell with 5 primary sidebar views: Overview, Environments, Network, Channels, Settings.
- Establish typed Tauri command invocation layer and error boundaries.

### Phase 2: Environment Management & Hypervisor Abstraction
- Implement `HypervisorAdapter` trait in Rust.
- Implement `VirtualBoxAdapter` parsing `VBoxManage` commands.
- Implement `MockHypervisorAdapter` for deterministic local and CI test execution.
- Implement `VMService` managing transactional VM creation, lifecycle controls (start, graceful ACPI shutdown, forced poweroff), and resource checks.
- Build Environment management UI: creation wizard with preflight checks (disk space, RAM, ISO existence), environment list, resource indicators, status badges, and lifecycle action controls.

### Phase 3: Network Diagnostics & Egress Verification
- Implement `NetworkService` managing endpoint inventories (HTTP, SOCKS5, WireGuard/VPN references).
- Implement guest diagnostic data protocol and network checker.
- Implement truthful egress inspection (IPv4, IPv6, DNS resolution, latency) without fabrication.
- Implement duplicate public IP detection across distinct environments.
- Build Network view: endpoint inventory, assignment map, live egress checks, duplicate warnings, and diagnostic history.

### Phase 4: Browser Profile Isolation & Channel Compliance
- Implement `ProfileService` generating isolated browser profiles (`--user-data-dir`).
- Ensure no shared writable storage, cookies, or cache directories between environments.
- Implement `ChannelService` managing YouTube channels, associations, and compliance states (`UNVERIFIED`, `AUTHORIZED`, `RESTRICTED`, `TERMINATED`, `ARCHIVED`).
- Enforce strict read-only lockouts for terminated channels.
- Build Channels view: channel registry, authorization status, publishing eligibility badges, and association modals.

### Phase 5: Vault Security, Backup & Audit Trail
- Implement `SecurityService` using Windows DPAPI (`CryptProtectData` / `CryptUnprotectData`).
- Implement export and import workflows that exclude or securely protect sensitive secrets.
- Implement `AuditService` logging all operational actions to `activity_logs`.
- Build Settings view: VBoxManage path configuration, default VM allocations, audit log viewer, DPAPI status, and database maintenance.

### Phase 6: UI/UX Refinement
- Implement dark-mode developer-tool aesthetic (dark navy/charcoal background `#0B0F17` / `#131B2E`).
- Add confirmation modals for destructive operations (delete environment, forced VM stop).
- Add actionable toasts, empty states, and loading skeletons.
- Ensure full keyboard accessibility and desktop window resize responsiveness.

### Phase 7: Verification & Packaging
- Run frontend type checking (`tsc --noEmit`) and Vitest test suite.
- Run Rust backend unit and integration tests (`cargo test`).
- Execute end-to-end integration tests validating VM lifecycle, network diagnostics, channel compliance, and secret encryption.
- Build production release bundle (`cargo tauri build`).

---

## 3. Mandatory Test Cases Traceability Matrix

| Test ID | Area | Scenario | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **ENV-001** | Environment | Create environment with valid parameters | Environment persisted in DB, VM registered with adapter, profile created. |
| **ENV-002** | Environment | Create environment with duplicate name | Request rejected with actionable error message; no disk or DB pollution. |
| **ENV-003** | Environment | Create environment with insufficient host disk space | Validation halts creation before invoking hypervisor. |
| **ENV-004** | Environment | Create environment with nonexistent ISO path | Preflight check fails with missing file notification. |
| **ENV-005** | Environment | Start stopped VM | VM transitions through `STARTING` to `RUNNING`; UI updates state. |
| **ENV-006** | Environment | VM startup fails in hypervisor | State transitions to `ERROR`; detailed non-sensitive reason logged. |
| **ENV-007** | Environment | Graceful shutdown of running VM | ACPI power button event dispatched; state transitions to `STOPPING` -> `STOPPED`. |
| **ENV-008** | Environment | Attempt to delete running VM without force | Operation blocked; user prompted to stop VM first. |
| **ENV-009** | Environment | Storage isolation check | Environment A and Environment B have disjoint disk and profile paths. |
| **NET-001** | Network | Guest-observed public IP check | Returns verified public IP observed from the guest egress point. |
| **NET-002** | Network | Guest diagnostics unavailable | Status shows `NOT_CHECKED` or `UNREACHABLE`; never fabricates success. |
| **NET-003** | Network | Connection loss during check | System records degraded/failed check; displays diagnostic warning. |
| **NET-004** | Network | Observed public IP changes unexpectedly | Safety alert generated; audit log records IP transition. |
| **NET-005** | Network | Duplicate public IP detected across two VMs | Alert banner displayed warning of potential egress cross-contamination. |
| **NET-006** | Network | DNS resolution failure | Diagnostics report explicit DNS failure with error details. |
| **NET-007** | Network | Check timeout handling | Non-blocking timeout returned after configured deadline. |
| **NET-008** | Network | Credential log scrubbing | Proxy passwords or auth tokens never appear in application logs. |
| **NET-009** | Network | Safety policy enforcement | App-managed tasks halt when connection policy check fails. |
| **BR-001** | Browser | Independent profile directory creation | Dedicated folder created under environment storage root. |
| **BR-002** | Browser | Verify disjoint profile paths | Distinct environments cannot share writable profile directories. |
| **BR-003** | Browser | Restore profile on restart | Existing profile metadata loaded intact across app restarts. |
| **BR-004** | Browser | Missing browser executable | Clean error message directing user to configure browser path. |
| **BR-005** | Browser | Path traversal protection in profile path | Invalid or relative traversal paths (`..`) are strictly rejected. |
| **CH-001** | Channel | Associate channel with environment | Association persisted in DB with foreign key constraints. |
| **CH-002** | Channel | Duplicate channel ID registration | Unique constraint enforced; duplicate rejected with error. |
| **CH-003** | Channel | Channel state persistence | Channel metadata and authorization state survive app restart. |
| **CH-004** | Channel | Terminated channel enforcement | Automated publishing actions permanently locked; read-only UI. |
| **CH-005** | Channel | No implicit credential sharing | Channel records cannot access credentials of another channel. |
| **REG-001** | Regression | Navigation between all 5 screens | Screen state preserved; no broken views or component crashes. |
| **REG-002** | Regression | Database migration integrity | DB migrations apply cleanly without data loss. |
| **REG-003** | Regression | UI event handler idempotency | Multiple clicks on actions do not trigger duplicate background jobs. |
| **REG-004** | Regression | Type check clean | Frontend TypeScript compiles with 0 errors (`tsc --noEmit`). |
| **REG-005** | Regression | Rust compilation clean | Backend compiles with 0 warnings/errors (`cargo clippy`, `cargo test`). |
