# Sentinel Security Model & Threat Assessment (Phase 1)

## Overview
Sentinel is a local-first personal security daemon designed to protect user workstations against unauthorized physical and digital access through continuous tiered authorization, tamper-evident audit logging, robust process supervision, and cryptographic secrets storage.

---

## Authorization Tiers

Every operation within the Sentinel architecture is classified into an immutable authorization tier:

1. **`READ_ONLY` (Level 0)**: Operations with zero state mutation or side effects (e.g. status queries, reading public metrics). Executed without credentials.
2. **`REVERSIBLE` (Level 1)**: Operations with benign or fully reversible state alterations (e.g. toggling verbose logging, adjusting non-security telemetry). Executed without credentials.
3. **`DESTRUCTIVE` (Level 2)**: Operations that modify, overwrite, or delete local data/configurations (e.g. updating credentials, purging cached sessions, altering active protection profiles). Requires valid Primary PIN authorization.
4. **`SYSTEM_LEVEL` (Level 3)**: High-privilege actions altering daemon operations, security policy, master key rotation, or process supervisor settings. Requires valid Primary PIN authorization.
5. **`BLOCKED` (Level 4)**: Catastrophic or universally hazardous actions (e.g. recursive root filesystem deletion, disk formatting, disabling kernel security controls). **Strictly rejected unconditionally**; no PIN or credential can override a `BLOCKED` action.

---

## Security Controls & Invariants

### 1. Fail-Closed Lockout Policy
- Sentinel tracks authentication failures independently for Primary and Recovery PINs.
- **Fail-Closed Guarantee**: If the system is initialized and the lockout state file (`lockout_state.json`) is deleted, corrupted, unreadable, or cannot be locked due to a lock acquisition timeout, Sentinel **strictly fails closed** by denying Primary PIN authentication and requiring Recovery PIN authorization. It never resets failure counts to zero upon failure or state loss.
- Lockout schedule:
  - 1–2 failures: 0s delay
  - 3 failures: 5s delay
  - 4 failures: 30s delay
  - 5–6 failures: 300s (5m) delay
  - 7+ failures: Hard Lockout (Primary PIN disabled until Recovery unlock) / Exponential delay for Recovery PIN.

### 2. PIN Cryptographic Hygiene
- PBKDF2-HMAC-SHA256 with ≥600,000 iterations (exceeding OWASP recommendations).
- Cryptographically isolated 16-byte random salts per credential.
- Constant-time hash verification (`hmac.compare_digest`) to prevent timing side-channel attacks.

### 3. Enrollment Gating & Local-Only Presence Verification
- Initial enrollment on an unconfigured installation requires a high-entropy physical presence token delivered strictly through local channels (interactive local console / restricted local file) — never accessible across network interfaces.
- Any subsequent identity or biometric enrollment strictly requires authenticating with the active Primary PIN.

### 4. Cross-Process Concurrency Safety
- File-level locking (`filelock`) protects all state mutations and verification against race conditions across concurrent processes.
- Any timeout while acquiring state locks immediately fails closed.

---

## Known Limitations

1. **Self-Brick Risk (Fail-Closed State & Vault Corruption)**:
   Because Sentinel strictly fails closed across all subsystems, corrupted or unreadable security metadata files permanently block operations until recovered or reset:
   - If `lockout_state.json` is missing or corrupted on an initialized system, Primary PIN authentication fails closed into Hard Lockout, requiring a valid Recovery PIN to reset.
   - If `rotation_journal.json` is corrupted or unreadable during master key rotation recovery, the Vault raises `RotationRecoveryError` and fails closed, refusing to perform reads, writes, or key generations until the corrupted state is inspected.
   In Phase 1, there is no back-door or bypass mechanism. (A cryptographically signed off-device recovery/remote-unlock mechanism is planned for Phase 4).
2. **PBKDF2 Lock Contention Availability Trade-off**:
   Because the atomic auth flow holds the lockout `FileLock` for the full duration of PBKDF2 derivation (~600,000 iterations), a local attacker flooding `authenticate_primary()` with concurrent burst requests can cause lock contention severe enough that legitimate concurrent attempts hit `lock_timeout` and fail closed with `LockAcquisitionError`. This is an intentional fail-closed security design to prevent parallel brute-force guessing; an upstream rate-limiter is scheduled for Phase 3/4.
3. **Windows ACL / SID Verification Coverage**:
   On Windows, local physical presence token security verifies that the token file's owner SID strictly matches the running process token's `TokenUser` and that the DACL does not grant access to broad groups (`Everyone`, `Authenticated Users`, `BUILTIN\Users`). While unit tests verify this against the live Windows Security API on Windows platforms, cross-platform CI environments (e.g. Linux runners) rely on mocked SID interfaces and cannot validate Windows Kernel Security Reference Monitor behavior natively.
4. **Local Root / OS Administrator Privilege**:
   An adversary with kernel-level or root/SYSTEM administrator privileges can kill processes, modify system memory, or tamper with OS-level secure storage (DPAPI/Keychain). Sentinel mitigates non-root tampering and provides mutual-process supervision and tamper-evident audit logging, but cannot defend against a compromised kernel.
5. **SSD / Flash Wear-Leveling and Residual Plaintext Risk**:
   Multi-pass file shredding (e.g. 3-pass overwrite with random bytes and zeros in `migrate_plaintext_file()`) is best-effort and cannot guarantee physical destruction of data on solid-state drives (SSDs) or flash storage due to Flash Translation Layer (FTL) remapping and wear-leveling algorithms. The physical memory cells originally holding the legacy plaintext file may retain residual data until trimmed or rewritten by the controller. Authoritative security relies on storing credentials exclusively inside the encrypted vault going forward.
6. **Process Memory & Immutable Byte Objects**:
   `wipe_buffer()` zeroes mutable `bytearray` copies of keys and plaintexts in memory, but immutable `bytes` objects (such as those returned by standard file reads or `decrypt_payload()`) cannot be overwritten in-place in Python and remain in the CPython process heap until garbage-collected. CPython does not zero freed heap memory. True guaranteed memory scrubbing requires reading directly into mutable C/Rust buffers from inception (a Phase 3/4 enhancement); memory hygiene in Phase 1 is therefore best-effort.
