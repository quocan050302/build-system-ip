# YouTube Isolation Manager — System Architecture

## 1. Executive Summary

**YouTube Isolation Manager** is a security-focused Windows desktop application built with **Tauri 2**, **React 18 / TypeScript**, and **Rust**. It provides centralized lifecycle management, truthful network diagnostics, isolated browser storage, and operational guardrails for multiple authorized YouTube channels on a single Windows workstation.

The application strictly enforces isolation:
- Each environment operates in its own dedicated VirtualBox virtual machine (with an extensible hypervisor adapter interface).
- Each environment uses an isolated, non-shared writable browser profile.
- Network endpoints (legitimate proxies/VPNs) are associated per environment and diagnosed from **within the guest** to prevent false assumptions about host egress.
- Platform compliance is paramount: the application **does not** provide account-ban circumvention, stealth fingerprint spoofing, CAPTCHA bypass, or fake account generation. Terminated or restricted channels are strictly enforced as read-only.

---

## 2. High-Level Architecture Diagram

```text
Windows Host (Win 10/11 x64)
│
└── YouTube Isolation Manager (Tauri 2 Desktop App)
    │
    ├── Frontend Presentation Layer (React 18 + TypeScript + Tailwind CSS)
    │   ├── Shell & Navigation (Overview, Environments, Network, Channels, Settings)
    │   ├── Context Providers & State Hooks
    │   ├── Data Grids, Health Badges & Modal Dialogs
    │   └── Tauri IPC Client (Typed Invocation Wrappers)
    │
    ├── Application Core (Rust Backend)
    │   ├── Tauri Command Handlers (Strongly typed, validated input)
    │   ├── Core Service Layer:
    │   │   ├── ProfileService      (Browser profile directories & launch config)
    │   │   ├── VMService           (Virtual machine lifecycle & transaction management)
    │   │   ├── NetworkService      (Endpoint inventory, policy enforcement & checks)
    │   │   ├── ChannelService      (Channel authorization & compliance rules)
    │   │   ├── SecurityService     (Windows DPAPI encryption & secret vault)
    │   │   ├── DiagnosticsService  (Guest telemetry & public egress inspection)
    │   │   └── AuditService        (Structured activity logging & audit trail)
    │   │
    │   ├── Persistence & Storage Layer:
    │   │   ├── SQLite Database (Versioned SQL migrations, WAL mode)
    │   │   └── Encrypted Secret Vault (DPAPI `CryptProtectData` / `CryptUnprotectData`)
    │   │
    │   └── Hypervisor Abstraction Layer:
    │       ├── HypervisorAdapter (Trait)
    │       ├── VirtualBoxAdapter (VBoxManage execution & output parsing)
    │       └── MockHypervisorAdapter (Deterministic test & CI harness)
    │
    └── Managed Environments (Host File System & Hypervisor)
        ├── Environment Alpha
        │   ├── VBox VM Container (vbox / vdi disk)
        │   ├── Dedicated Browser Profile Directory
        │   └── Configured Network Endpoint Reference
        └── Environment Beta ...
```

---

## 3. Core Modules & Responsibilities

### 3.1. Desktop Dashboard (Frontend)
- **Framework:** React 18, TypeScript, Vite, Tailwind CSS, Lucide React icons.
- **Navigation:** Five strict primary tabs:
  1. **Overview:** System status, resource utilization (RAM, Disk), hypervisor readiness, running/stopped counts, recent events.
  2. **Environments:** Table of environments, VM status, hardware allocations, network assignment, quick lifecycle actions (Start, Shutdown, Stop, Diagnostics, Configure, Delete).
  3. **Network:** Inventory of configured proxies/endpoints, assignment mapping, egress verification results, duplicate IP alerts, DNS health.
  4. **Channels:** YouTube channel registry, authorization status (Unverified, Authorized, Restricted, Terminated, Archived), publishing eligibility checks.
  5. **Settings:** Hypervisor paths (VBoxManage), default resource limits, diagnostics intervals, theme, logging verbosity, DPAPI vault status.

### 3.2. Application Core (Rust Services)

| Service | Responsibility |
| :--- | :--- |
| `VMService` | Discovers hypervisor, validates system resources (RAM, disk headroom, ISO existence), coordinates VM creation as a multi-step transaction with rollback, executes start/shutdown/power-off. |
| `NetworkService` | Manages network endpoint records, associates endpoints with environments, compares observed public IPs across all environments, detects duplicate egress, triggers alerts. |
| `DiagnosticsService` | Executes real network probes from the guest or designated network adapters; parses IPv4, IPv6, DNS resolution, and latency. Never fabricates IP addresses. |
| `ProfileService` | Manages independent browser profiles (Chromium/Firefox/Edge data directories) ensuring zero cookie, cache, or session leakage across environments. |
| `ChannelService` | Enforces channel compliance states. Terminated accounts are permanently locked from automated publishing. |
| `SecurityService` | Interacts with Windows Data Protection API (DPAPI) to encrypt/decrypt sensitive credentials (proxy auth, tokens). Redacts secrets from application logs. |
| `AuditService` | Logs all operational activities to SQLite (`activity_logs`) with timestamps, severity levels, and environment IDs. |

---

## 4. Hypervisor Abstraction Layer

To ensure testability and future extensibility (e.g., Hyper-V or WSL2), the hypervisor interface is defined as a Rust `trait`:

```rust
#[async_trait]
pub trait HypervisorAdapter: Send + Sync {
    async fn detect(&self) -> Result<HypervisorInfo, HypervisorError>;
    async fn list_vms(&self) -> Result<Vec<VmSummary>, HypervisorError>;
    async fn get_vm_state(&self, vm_identifier: &str) -> Result<VmState, HypervisorError>;
    async fn create_vm(&self, spec: &CreateVmSpec) -> Result<String, HypervisorError>;
    async fn start_vm(&self, vm_identifier: &str) -> Result<(), HypervisorError>;
    async fn shutdown_vm(&self, vm_identifier: &str, force: bool) -> Result<(), HypervisorError>;
    async fn delete_vm(&self, vm_identifier: &str, delete_disks: bool) -> Result<(), HypervisorError>;
    async fn get_system_resources(&self) -> Result<HostResources, HypervisorError>;
}
```

- **`VirtualBoxAdapter`**: Invokes `VBoxManage.exe` via secure process execution. Parses `vboxmanage list vms`, `vboxmanage showvminfo`, `vboxmanage startvm --type headless/gui`, and `vboxmanage controlvm acpipowerbutton/poweroff`.
- **`MockHypervisorAdapter`**: In-memory deterministic state machine used for automated unit/integration testing without requiring VirtualBox installed on CI agents.

---

## 5. Storage & Database Schema

The application uses an embedded SQLite database configured with:
- `PRAGMA journal_mode = WAL;` (Write-Ahead Logging for high concurrency)
- `PRAGMA foreign_keys = ON;` (Referential integrity enforcement)
- Structured versioned migrations.

### Tables Overview
1. `environments`: Primary record for each isolated workspace.
2. `network_endpoints`: Registered proxy or VPN configurations.
3. `environment_networks`: Link table mapping environment to network endpoint with specific connection safety policies.
4. `network_checks`: Historical log of guest-egress diagnostics (observed IPv4/IPv6, DNS latency, status).
5. `browser_profiles`: Metadata and filesystem paths for dedicated browser profile directories.
6. `channels`: Registered YouTube channels with compliance states (`UNVERIFIED`, `AUTHORIZED`, `RESTRICTED`, `TERMINATED`, `ARCHIVED`).
7. `activity_logs`: Immutable audit trail for user and system actions.
8. `application_settings`: Key-value storage for host preferences and hypervisor paths.

---

## 6. Network Diagnostic Protocol & Integrity Rules

1. **Truthful Reporting:** If a guest VM is stopped or diagnostics are unreachable, the egress status is reported as `NOT_CHECKED` or `UNREACHABLE`. The system will never fabricate an IP or report a cached result as fresh.
2. **Guest-Based Verification:** Host egress does not equal guest egress. Verification queries are routed through the target environment's specific network boundary.
3. **Duplicate Egress Warning:** If Environment A and Environment B report the same observed public IPv4, an immediate operational alert is raised to prevent unintentional cross-contamination.
4. **Safety Interlocks:** Users can configure policies such that workflow actions are halted if network diagnostics detect an unexpected IP change or a connection drop.
