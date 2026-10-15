# YouTube Isolation Manager

A high-assurance, cross-platform desktop application engineered for secure, isolated management of multiple authorized YouTube channels, virtualized environments, independent network egress points, and operational workflows.

Supports:
- **Windows 11 Pro x64**: Native Type-1 **Microsoft Hyper-V**, Generation 2 VMs, persistent `.vhdx` disks, `vmconnect.exe` console, and Windows DPAPI secret protection.
- **macOS Apple Silicon ARM64**: Native **UTM / Apple Virtualization Framework**, persistent sparse virtual disks, direct console, and Apple Keychain Services secret sealing.

---

## Key Features

- **Cross-Platform Native Virtualization:**
  - **Windows**: Microsoft Hyper-V with PowerShell management and `.vhdx` virtual disk creation.
  - **macOS**: UTM with `utmctl` integration, Apple Silicon hardware acceleration, and Ubuntu Linux ARM64 support.
- **Hardware-Isolated Browser Environments:**
  - Independent virtual disk images with browser execution strictly hosted inside the guest OS. Host directories are separated from guest execution.
- **Truthful Network Diagnostics:**
  - Distinguishes between configured endpoints, native TCP handshake reachability (with roundtrip latency in ms), and observed in-guest public egress. Zero fabricated or proxy-host loopback IP addresses.
  - Automatic duplicate public egress detection across environments.
- **Platform-Native Encrypted Secret Storage:**
  - **Windows**: Windows DPAPI (`CryptProtectData` / `CryptUnprotectData`) user-account encryption.
  - **macOS**: Apple Keychain Services (`/usr/bin/security`) hardware/Secure Enclave-backed storage.
  - Zero plaintext secrets in frontend memory, logs, or disk files.
- **Compliance & YouTube Policy Guardrails:**
  - Explicit channel lifecycle tracking (`UNVERIFIED`, `AUTHORIZED`, `RESTRICTED`, `TERMINATED`, `ARCHIVED`).
  - Strict read-only locking on terminated or restricted channels. No account-ban circumvention or stealth fingerprint spoofing.
- **Unified Desktop Dashboard:**
  - High-performance React 18 + Tauri 2 desktop shell featuring 5 primary views: Overview, Environments, Network, Channels, and Settings.
  - Real-time OS and hypervisor detection with dynamic capability indicators and a distinct Real Mode vs Demo Mode badge.

---

## Platform Requirements & Setup

### Windows 11 Pro x64
- **Hypervisor**: Microsoft Hyper-V (Type-1 Hypervisor)
- **Privileges**: Administrator or member of `Hyper-V Administrators` security group.
- **Enabling Hyper-V**:
  ```powershell
  Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
  ```
- **Secret Vault**: Native Windows DPAPI (active out-of-the-box).

### macOS Apple Silicon ARM64
- **Hypervisor**: UTM v4.x installed at `/Applications/UTM.app` (includes `utmctl`).
- **Download UTM**: Available from [mac.getutm.app](https://mac.getutm.app/) or via Homebrew:
  ```bash
  brew install --cask utm
  ```
- **Guest Operating System**: Ubuntu Linux ARM64 (or compatible aarch64 Linux distributions).
- **Secret Vault**: macOS User Keychain (active out-of-the-box).

---

## Development Prerequisites

- **Node.js**: v20+ (v22.x recommended)
- **Rust**: 1.77+ with native target (`aarch64-apple-darwin` on Apple Silicon, `x86_64-pc-windows-msvc` on Windows)
- **Package Manager**: `npm` or `pnpm`

---

## Getting Started

### 1. Install Frontend Dependencies
```bash
npm install
```

### 2. Run in Development Mode
```bash
npm run dev
# Or with Tauri desktop shell
npx @tauri-apps/cli dev
```

### 3. Run Automated Tests
```bash
# Frontend Vitest test suite
npm test

# Rust backend cross-platform integration test suite
cargo test --manifest-path src-tauri/Cargo.toml
```

### 4. Build Production Packages
```bash
# Frontend bundle
npm run build

# Tauri desktop installer (.dmg on macOS, .exe/NSIS on Windows)
npx @tauri-apps/cli build
```

---

## Documentation

- [System Architecture](ARCHITECTURE.md)
- [Implementation Plan & Test Matrix](IMPLEMENTATION_PLAN.md)
- [Security Model & Threat Assessment](SECURITY_MODEL.md)
