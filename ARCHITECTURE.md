# YouTube Isolation Manager — Cross-Platform System Architecture

## 1. Executive Summary

**YouTube Isolation Manager** is an enterprise-grade cross-platform desktop virtualization manager built with **Tauri 2**, **React 18 / TypeScript**, and **Rust**. It provides centralized environment lifecycle management, hardware-level virtualization, truthful guest network diagnostics, isolated browser storage, and operational guardrails for authorized YouTube channel administration across:
- **Windows 11 Pro x64**: Native Type-1 **Microsoft Hyper-V** hypervisor with PowerShell/WMI management, persistent `.vhdx` virtual disks, `vmconnect.exe` console, and Windows DPAPI secret protection.
- **macOS Apple Silicon ARM64**: Native **UTM / Apple Virtualization Framework** with `utmctl` management, persistent sparse virtual disks, direct console viewing, and Apple Keychain Services secret sealing.

The application strictly enforces isolation and compliance:
- Each environment operates in its own dedicated, persistent virtual machine and virtual disk.
- Platform compliance is paramount: the application **does not** build fingerprint spoofing, account-ban circumvention, CAPTCHA bypass, or stealth mechanisms. Terminated or restricted channels are strictly enforced as read-only.
- **Never fabricates data**: Network diagnostics strictly distinguish between configured endpoints, TCP reachability, and observed in-guest public egress. No synthetic IPs (`198.51.100.42` or host loopbacks) are ever injected.
- **No silent mock fallbacks**: Production builds strictly query real platform hypervisors. Mock hypervisor execution is only permitted when explicitly requested in test suites or developer preview mode.

---

## 2. High-Level Architecture Diagram

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               Shared Desktop UI (React 18)                              │
│       Overview  │  Environments  │  Network  │  Channels  │  Settings                  │
│       - Real Mode vs Demo Mode Indicator      - Dynamic Hypervisor Advisory            │
│       - Live Host RAM & Disk Metrics           - Native Secret Vault Status             │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ Tauri 2 IPC
┌───────────────────────────────────────────▼────────────────────────────────────────────┐
│                                 Rust Application Core                                  │
│                                                                                        │
│   PlatformService               VMService                  NetworkService              │
│   - libc/sysctl RAM/disk (Mac)  - Multi-step provisioning  - Real TCP reachability     │
│   - Win32 memory/disk (Win)     - State reconciliation     - Truthful egress states    │
│   - Target triple detection     - Console & browser hook   - Duplicate egress warning  │
│                                                                                        │
│   ProfileService                ChannelService             AuditService                │
│   - Path traversal guard        - Compliance locking       - SQLite activity log       │
│                                                                                        │
│   SecretStore (Cross-Platform Trait)                                                   │
│   ├── Windows DPAPI: Win32 CryptProtectData / CryptUnprotectData                       │
│   └── macOS Keychain: /usr/bin/security add/find/delete-generic-password               │
└─────────────────────┬───────────────────────────────────────────┬──────────────────────┘
                      │                                           │
         [Windows 11 Pro x64]                       [macOS Apple Silicon ARM64]
                      │                                           │
┌─────────────────────▼───────────────────┐ ┌─────────────────────▼───────────────────┐
│          HyperVAdapter                  │ │            UTMAdapter                   │
│ - WMI / Hyper-V PowerShell module       │ │ - /Applications/UTM.app & utmctl        │
│ - Dynamic VHDX persistent disks         │ │ - Apple Virtualization Framework (ARM64)│
│ - vmconnect.exe native console          │ │ - Native sparse virtual disk bundles    │
│ - Virtual Machine Management Service    │ │ - Child process timeout protection      │
└─────────────────────────────────────────┘ └─────────────────────────────────────────┘
```

---

## 3. Core Modules & Responsibilities

### 3.1. Desktop Dashboard (Frontend)
- **Framework:** React 18, TypeScript, Vite, Tailwind CSS, Lucide React icons.
- **Navigation:** Five strict primary tabs:
  1. **Overview:** System status, live host resource utilization (RAM, Disk), dynamic hypervisor readiness, running/stopped counts, recent events.
  2. **Environments:** Table of environments, VM status, hardware allocations, network assignment, console launcher, in-guest browser launcher, and safe deletion confirmation dialogs.
  3. **Network:** Inventory of configured proxies/endpoints, assignment mapping, truthful egress verification results, duplicate IP alerts, DNS health.
  4. **Channels:** YouTube channel registry, compliance authorization status (`UNVERIFIED`, `AUTHORIZED`, `RESTRICTED`, `TERMINATED`, `ARCHIVED`), publishing eligibility checks.
  5. **Settings:** Platform architecture card, detected hypervisor engine status and discovery, native encrypted secret vault test tool, audit log trail.

### 3.2. Application Core (Rust Services)

| Service | Responsibility |
| :--- | :--- |
| `PlatformService` | Real, non-fabricated detection of OS, CPU architecture, total/available RAM (`sysctl` / Win32), disk capacity (`statvfs` / `GetDiskFreeSpaceExW`), installed hypervisor engines, and app data paths. |
| `VMService` | Discovers native hypervisors, manages multi-step VM provisioning with rollback, reconciles database states with native hypervisor state on startup, launches VM console, and provides guest browser execution hooks. |
| `NetworkService` | Manages network endpoints, tests genuine TCP connection reachability and latency, flags duplicate public egress, and records diagnostic history. |
| `SecretStore` | Hardware/OS-backed credential encryption. Windows uses DPAPI; macOS uses Apple Keychain Services (`/usr/bin/security`). Zero secrets exposed in plaintext logs or frontend state. |
| `ProfileService` | Enforces storage isolation and cross-platform path validation, preventing directory traversal on both Windows (`\`) and Unix (`/`) systems. |
| `ChannelService` | Enforces YouTube compliance rules. Restricts terminated channels from performing publishing actions. |
| `AuditService` | Immutable SQLite operational activity log with severity levels, timestamps, and environment IDs. |

---

## 4. Hypervisor Abstraction Layer

The unified `HypervisorAdapter` trait is implemented by four distinct adapters:

```rust
pub trait HypervisorAdapter: Send + Sync {
    fn detect(&self) -> Result<HypervisorInfo, HypervisorError>;
    fn list_vms(&self) -> Result<Vec<VmSummary>, HypervisorError>;
    fn get_vm_state(&self, vm_identifier: &str) -> Result<VmState, HypervisorError>;
    fn get_vm_details(&self, vm_identifier: &str) -> Result<VmDetails, HypervisorError>;
    fn create_vm(&self, spec: &CreateVmSpec) -> Result<String, HypervisorError>;
    fn start_vm(&self, vm_identifier: &str) -> Result<(), HypervisorError>;
    fn shutdown_vm(&self, vm_identifier: &str, force: bool) -> Result<(), HypervisorError>;
    fn delete_vm(&self, vm_identifier: &str, delete_disks: bool) -> Result<(), HypervisorError>;
    fn open_vm_console(&self, vm_identifier: &str) -> Result<(), HypervisorError>;
    fn get_system_resources(&self) -> Result<HostResources, HypervisorError>;
}
```

- **`HyperVAdapter` (Windows x86_64)**:
  - Validates `vmms` service and `Hyper-V` PowerShell module.
  - Generates parameterized PowerShell commands using `-ExecutionPolicy Bypass` with strict argument sanitization.
  - Provisions Generation 2 VMs with dedicated `.vhdx` disks.
  - Launches `vmconnect.exe localhost <vm_name>`.
- **`UTMAdapter` (macOS aarch64)**:
  - Detects `/Applications/UTM.app` and `/Applications/UTM.app/Contents/MacOS/utmctl`.
  - Reads version directly from `Info.plist` via `defaults read` for instant detection.
  - Protects all `utmctl` invocations with a 3-second non-blocking child process timeout.
  - Provisions dedicated `.utm` sparse bundles and launches the native UTM GUI console.
- **`VirtualBoxAdapter`**:
  - Preserved for backwards compatibility with Oracle VirtualBox.
- **`MockHypervisorAdapter`**:
  - In-memory deterministic state machine for unit tests and frontend demo previews. Never loaded automatically in production builds.

---

## 5. Storage & Database Schema

SQLite with Write-Ahead Logging (`WAL`) and foreign key constraints.

### Migrations
- **Version 1**: Initial schema (`environments`, `network_endpoints`, `channels`, `activity_logs`, etc.).
- **Version 2**: Non-destructive cross-platform migration:
  - Adds `host_platform` (`windows`, `macos`, `linux`)
  - Adds `vm_architecture` (`x86_64`, `aarch64`)
  - Adds `provisioning_status` (`PROVISIONED`, `PENDING_IMPORT`, `FAILED`)
  - Adds `persistent_disk_reference` (Absolute path to `.vhdx` or `.utm`)
  - Adds `network_diagnostics_capability` (`GUEST_AGENT`, `EXTERNAL_PROBE`, `NONE`)
  - Adds `latency_ms` and `egress_stage` to `network_checks`.

Existing records remain completely intact and functional.

---

## 6. Truthful Network Diagnostics & Egress Protocol

1. **Distinct Diagnostic Stages**:
   - `ENDPOINT_CONFIGURED`: Target IP/port registered in database.
   - `ENDPOINT_REACHABLE`: Native TCP handshake completed within timeout with roundtrip latency measured in ms.
   - `GUEST_EGRESS_OBSERVED`: Verified public IP returned directly from inside the running guest OS.
   - `CONNECTION_FAILED`: Network endpoint unreachable or refused connection.
   - `NOT_CHECKED`: VM stopped or diagnostics unperformed.
2. **Strict Removal of Synthetic IP Injections**:
   - Simulated strings such as `198.51.100.42` and host loopback reflections are completely removed from production verification routines.
3. **Duplicate Egress Alerts**:
   - If two distinct environments show the same observed public IP, an alert is surfaced immediately to prevent accidental account linking.
