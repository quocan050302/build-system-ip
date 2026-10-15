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
