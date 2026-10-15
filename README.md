# YouTube Isolation Manager

A high-assurance Windows desktop application engineered for secure, isolated management of multiple authorized YouTube channels, virtualized browser environments, independent network egress points, and operational workflows.

---

## Key Features

- **Hypervisor-Level Isolation:** Dedicated VirtualBox virtual machine containers with persistent virtual disks (`.vdi`) per channel environment.
- **Dedicated Browser Profiles:** Independent browser data directories with zero shared cookies, local storage, or session caches.
- **Truthful Network Diagnostics:** Real guest-level public IP observation (IPv4/IPv6), DNS latency checks, and automatic duplicate egress detection across environments.
- **Windows DPAPI Vault:** Hardware/user-bound DPAPI encryption (`CryptProtectData` / `CryptUnprotectData`) for proxy credentials and API secrets. Zero plaintext secrets on disk.
- **Channel Compliance Controls:** Explicit authorization state management (`UNVERIFIED`, `AUTHORIZED`, `RESTRICTED`, `TERMINATED`, `ARCHIVED`). Terminated channels are automatically locked into read-only mode to prevent non-compliant operations.
- **Developer-Grade Dark Interface:** High-contrast, clean 5-view desktop layout (Overview, Environments, Network, Channels, Settings) optimized for clarity and operational safety.

---

## System Requirements

- **Operating System:** Windows 10 / Windows 11 (64-bit)
- **Virtualization:** Oracle VM VirtualBox 7.x (with `VBoxManage.exe` on PATH or configured in Settings)
- **CPU:** Multi-core x86_64 processor with hardware virtualization (VT-x / AMD-V) enabled in BIOS/UEFI
- **RAM:** Minimum 8 GB recommended (16 GB+ for concurrent running VMs)
- **Storage:** Minimum 20 GB free disk space for guest VM virtual disks

---

## Development Prerequisites

- **Node.js:** v18.0.0 or later (v22.x recommended)
- **Package Manager:** `pnpm` (recommended) or `npm`
- **Rust:** 1.75+ (installed via `rustup` with `x86_64-pc-windows-msvc` toolchain)
- **Visual Studio 2022 C++ Build Tools:** C++ core features and Windows 10/11 SDK

---

## Getting Started

### 1. Install Frontend Dependencies
```powershell
pnpm install
```

### 2. Run in Development Mode
```powershell
pnpm tauri dev
```

### 3. Run Automated Tests
```powershell
# Run frontend unit & component tests
pnpm test

# Run Rust backend unit & integration tests
cargo test --manifest-path src-tauri/Cargo.toml
```

### 4. Build Production Bundle
```powershell
pnpm tauri build
```

---

## Documentation

- [System Architecture](ARCHITECTURE.md)
- [Implementation Plan & Test Matrix](IMPLEMENTATION_PLAN.md)
- [Security Model & Threat Assessment](SECURITY_MODEL.md)
