# Axion — NIST 800-53 Rev5 Control Mapping

This document maps Axion's implemented controls to NIST SP 800-53 Rev5 families.
It also notes gaps that require organizational policy, system configuration, or
additional tooling outside of the Axion codebase itself.

**Assessment date:** April 2026  
**Baseline:** NIST SP 800-53 Rev5 Moderate

---

## AC — Access Control

| Control | Title | Axion Implementation | Status |
|---|---|---|---|
| AC-2 | Account Management | User CRUD via `/api/users` (admin only); roles: admin/operator/analyst; accounts logged in audit | ✅ Implemented |
| AC-2(1) | Automated System Account Mgmt | Automated admin account seeding on first run; password updated from env var | ✅ Implemented |
| AC-3 | Access Enforcement | FastAPI `Depends()` on every endpoint enforces role; machine tokens limited to operator scope | ✅ Implemented |
| AC-6 | Least Privilege | Three-tier role hierarchy; analyst read-only; machine tokens cannot manage users | ✅ Implemented |
| AC-7 | Unsuccessful Login Attempts | Login failures logged to audit log with actor + reason | Partial — no account lockout after N failures |
| AC-17 | Remote Access | TLS (HTTPS) required; mTLS supported for agent→server | ✅ Implemented |
| AC-18 | Wireless Access | N/A for server; agent runs on edge network (organizational control) | Organizational |
| AC-19 | Access Control for Mobile | N/A — server does not expose mobile endpoints | N/A |

**Gap (AC-7):** Implement brute-force lockout: track failed login count per username in `users` table; lock account after 5 consecutive failures; unlock after admin reset or 30-minute timeout.

---

## AU — Audit and Accountability

| Control | Title | Axion Implementation | Status |
|---|---|---|---|
| AU-2 | Event Logging | Login success/failure, ack, user CRUD, key rotation, incident correlation logged | ✅ Implemented |
| AU-3 | Content of Audit Records | Each row: ts (epoch), actor, action, target, detail, row_hmac | ✅ Implemented |
| AU-4 | Audit Log Storage Capacity | SQLite on configurable path; `retention.py` prunes; `archive.py` exports to cold storage | ✅ Implemented |
| AU-8 | Time Stamps | All timestamps in UTC epoch float (`time.time()`); monotonic within a process | ✅ Implemented |
| AU-9 | Protection of Audit Information | DB-level triggers prevent DELETE/UPDATE on `audit_log`; HMAC per row via `row_hmac`; verify endpoint `/api/audit/verify` | ✅ Implemented |
| AU-9(3) | Cryptographic Protection | HMAC-SHA256 per row keyed to `AXION_API_KEY` | ✅ Implemented |
| AU-11 | Audit Record Retention | Configurable TTL via `retention.py --days`; default 90 days | ✅ Implemented |
| AU-12 | Audit Record Generation | Every endpoint that modifies state calls `_audit()` | ✅ Implemented |

**Gap (AU-2):** Off-hours access and failed WebSocket token attempts are not audited. Add WebSocket auth failure logging in `ws_endpoint`.

---

## IA — Identification and Authentication

| Control | Title | Axion Implementation | Status |
|---|---|---|---|
| IA-2 | User Identification and Authentication | JWT-based session; PBKDF2-HMAC-SHA256 password hashing (200k iter, 32-byte salt) | ✅ Implemented |
| IA-2(1) | MFA for Privileged Accounts | Not implemented | ❌ Gap |
| IA-3 | Device Identification | Agent identifies via `X-Axion-Key` header; mTLS client cert for device-level identity | ✅ Implemented |
| IA-5 | Authenticator Management | Admin password configurable via `AXION_ADMIN_PASSWORD`; key rotation via `/api/rotate-key` | ✅ Implemented |
| IA-5(1) | Password-Based Authentication | PBKDF2-SHA256, 200k iterations, random 32-byte salt per user | ✅ Implemented |
| IA-8 | Non-Organizational Users | Machine tokens (`X-Axion-Key`) for agent authentication; scoped to operator actions | ✅ Implemented |

**Gap (IA-2(1)):** Add TOTP/HOTP second factor for admin accounts. Recommended library: `pyotp`. Store TOTP secret in `users` table (`totp_secret TEXT`). Require `otp` field in `LoginRequest`.

---

## SC — System and Communications Protection

| Control | Title | Axion Implementation | Status |
|---|---|---|---|
| SC-8 | Transmission Confidentiality | TLS via Uvicorn `ssl_certfile`/`ssl_keyfile`; agent verifies server cert via `ca_cert` | ✅ Implemented |
| SC-8(1) | Cryptographic Protection | TLS 1.2+ (Uvicorn default); mTLS supported for agent→server mutual auth | ✅ Implemented |
| SC-12 | Cryptographic Key Management | API key rotation via `/api/rotate-key`; AXION_API_KEY_FILE for vault agent sidecar | ✅ Implemented |
| SC-13 | Cryptographic Protection | PBKDF2-SHA256 passwords; HMAC-SHA256 audit; JWT HS256 with PBKDF2-derived key | ✅ Implemented |
| SC-28 | Protection of Information at Rest | SQLCipher optional (set AXION_DB_KEY / AXION_AGENT_DB_KEY + install sqlcipher3) | Partial — SQLCipher available, off by default |
| SC-28(1) | Cryptographic Protection | SQLCipher: AES-256-CBC, PBKDF2 64k iter, HMAC-SHA512 page auth | Partial — enabled when AXION_DB_KEY set |

**Gap (SC-28):** SQLCipher is implemented but commented out in `requirements.txt`. For any classified/sensitive deployment, uncomment `sqlcipher3` in requirements, install system package, and set encryption keys. Document key storage in your system security plan.

---

## SI — System and Information Integrity

| Control | Title | Axion Implementation | Status |
|---|---|---|---|
| SI-2 | Flaw Remediation | `pip-audit` in CI on every push; all deps pinned to exact versions | ✅ Implemented |
| SI-3 | Malware Protection | MalwareDetector: hash matching, suspicious process names, DNS tunnel detection | ✅ Implemented |
| SI-4 | System Monitoring | Prometheus metrics (`/metrics`); structured JSON logs; liveness + readiness probes | ✅ Implemented |
| SI-5 | Security Alerts | SIEM output (syslog RFC 5424 / webhook); alert forwarding to central server | ✅ Implemented |

---

## CP — Contingency Planning

| Control | Title | Axion Implementation | Status |
|---|---|---|---|
| CP-9 | System Backup | `scripts/backup.py` — hot SQLite backup (safe while live); `scripts/archive.py` — NDJSON cold export | ✅ Implemented |
| CP-10 | System Recovery | Backup restore: `python scripts/backup.py --db new.sqlite --out restore.sqlite` then swap path | ✅ Implemented |

---

## CM — Configuration Management

| Control | Title | Axion Implementation | Status |
|---|---|---|---|
| CM-6 | Configuration Settings | All config via YAML (agent) and env vars (server); no defaults with elevated privileges | ✅ Implemented |
| CM-7 | Least Functionality | Alpine Docker image; systemd `SystemCallFilter=@system-service`; `PrivateDevices=true` | ✅ Implemented |
| CM-11 | User-Installed Software | Not in scope for the Axion process; organizational control for host | Organizational |

---

## STIG Checklist (Systemd / OS Hardening)

The following systemd hardening directives are applied in `axion-server.service` and `axion-agent.service`:

| Directive | Applied | Notes |
|---|---|---|
| `NoNewPrivileges=true` | ✅ | Prevents privilege escalation |
| `PrivateTmp=true` | ✅ | Isolated /tmp |
| `PrivateDevices=true` | ✅ | No raw device access |
| `ProtectSystem=strict` | ✅ | Read-only system tree |
| `ProtectHome=true` | ✅ | No access to /home |
| `ProtectClock=yes` | ✅ | Cannot change system clock |
| `ProtectHostname=yes` | ✅ | Cannot change hostname |
| `ProtectKernelLogs=yes` | ✅ | No /dev/kmsg access |
| `ProtectKernelModules=yes` | ✅ | Cannot load kernel modules |
| `ProtectKernelTunables=yes` | ✅ | Read-only /proc/sys |
| `ProtectControlGroups=yes` | ✅ | Read-only cgroups |
| `RestrictNamespaces=yes` | ✅ | No namespace creation |
| `RestrictRealtime=yes` | ✅ | No real-time scheduling |
| `RestrictSUIDSGID=yes` | ✅ | Cannot set SUID/SGID bits |
| `LockPersonality=yes` | ✅ | Fixed personality domain |
| `SystemCallFilter=@system-service` | ✅ | Whitelist of safe syscalls |
| `MemoryMax=512M` | ✅ Server / 256M Agent | Resource cap |
| `CPUQuota=80%` | ✅ Server / 50% Agent | CPU cap |
| `WatchdogSec=30s` | ✅ Server | systemd watchdog |

**Not yet applied (optional, may break some Python functionality):**
- `MemoryDenyWriteExecute=yes` — blocks JIT; Python's `ctypes` may fail
- `IPAddressDeny=any` + `IPAddressAllow=` — requires knowing all peer IPs at deploy time

---

## SCAP / OSCAL Notes

A formal XCCDF DataStream or OSCAL System Security Plan (SSP) has not been generated. The
following steps are recommended for any formal ATO or C&A package:

1. Run OpenSCAP against the deployed host using the RHEL8/CentOS8 STIG profile:
   ```bash
   oscap xccdf eval \
     --profile xccdf_org.ssgproject.content_profile_stig \
     --report scap_report.html \
     /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml
   ```

2. For Alpine-based containers, use the CIS Alpine benchmark:
   ```bash
   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
     aquasec/trivy image --compliance docker-cis axion-server:latest
   ```

3. Map remaining findings back to this document and update the gap list.

4. Generate OSCAL SSP using `trestle` CLI:
   ```bash
   pip install compliance-trestle
   trestle init -d axion-ssp
   trestle import -f NIST_SP-800-53_rev5_catalog.json -o nist-800-53-r5
   ```
