# Sentinel & JARVIS Incident Response Runbook (Phase 8)

## 1. Overview & Operational Scope

This document defines the operational procedures for detecting, triaging, containing, and recovering from security incidents on a JARVIS / Sentinel workstation. All procedures, triggers, thresholds, and recovery workflows described herein reflect the actual implemented codebase in `core/`, `sentinel/`, and `jarvis_watchdog.py`.

Sentinel enforces a strict **fail-closed** security architecture: evaluation errors, missing baselines, lock acquisition timeouts, or corrupted security metadata strictly elevate friction or block execution, never defaulting to an open state.

---

## 2. Core Security Subsystems & Trigger Reference

```
 ┌──────────────────────────────────────────────────────────────────────────────────┐
 │                               JARVIS / SENTINEL CORE                             │
 └──────┬─────────────────────┬──────────────────────┬──────────────────────┬───────┘
        │                     │                      │                      │
        ▼                     ▼                      ▼                      ▼
┌──────────────┐      ┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│  Emergency   │      │   Intruder   │       │   Anomaly    │       │    Mutual    │
│  Wipe System │      │ Alert Watcher│       │   Detector   │       │   Watchdog   │
└──────┬───────┘      └──────┬───────┘       └──────┬───────┘       └──────┬───────┘
       │                     │                      │                      │
       └──────────────┬──────┴──────────────────────┴──────────────────────┘
                      ▼
        ┌───────────────────────────┐
        │      ProactiveBridge      │  (Priority: CRITICAL=100)
        └─────────────┬─────────────┘
                      │  [Synchronous Audit-Before-Voice Dispatch]
                      ▼
         ┌─────────────────────────┐
         │ • HMAC-SHA256 Audit Log │
         │ • Voice Audio Queue     │
         │ • Desktop UI HUD Alert  │
         │ • Remote Push (Mobile)  │
         └─────────────────────────┘
```

### 2.1 Emergency Wipe System

The emergency wipe subsystem provides physical and remote destruction of sensitive caches, conversation history, credentials, and configuration files.

#### Triggers & Entry Points
1. **Interactive / CLI / Mobile Wipe** (`core/sentinel_extras.py` -> `EmergencyWipeController`):
   - **Request Phase**: `request_wipe(pin, source, context)`:
     - Authenticates Primary PIN via `authenticate_primary()`.
     - Evaluates environmental anomaly signals via `AnomalyDetector.get_instance().evaluate_friction(context, action="wipe")`.
     - In normal context: Generates a cryptographically random confirmation token (`os.urandom(16).hex()`) valid for a 60-second window.
     - In anomalous context (or upon any evaluation error): Fails closed, marks `requires_step_up = True`, and generates a step-up token requiring Recovery PIN verification.
   - **Confirmation Phase**: `confirm_wipe(token, recovery_pin=None, source="local", context=None)`:
     - Verifies token validity and 60-second expiry window.
     - If `requires_step_up` is `True`, verifies the Recovery PIN via `authenticate_recovery()`. If Recovery PIN is missing or invalid, the wipe is **strictly blocked**, an audit log entry is recorded, and a `CRITICAL` proactive alert is dispatched to `ProactiveBridge`.
     - If verified, executes file shredding and directory removal.

2. **Email / IMAP Remote Wipe** (`core/email_wipe_listener.py` -> `EmailWipeListener`):
   - Polls configured IMAP mailbox over SSL.
   - Requires valid authorization signature/token (`EMAIL_WIPE_SECRET`) and authorized sender address.
   - Evaluates anomaly context (`source="email_remote"`).
   - If anomalous, strictly requires the embedded payload to supply the valid `recovery_pin`.
   - On unauthenticated or blocked attempts: Dispatches `CRITICAL` alert to `ProactiveBridge` and logs to `audit.log`.

---

### 2.2 Intruder Detection & Face Verification Clustering

Monitors physical workstation presence and detects unauthorized access or spoofing attempts.

#### Triggers & Entry Points
- **Subsystems**: `core/face_verify.py` (`FaceVerifier`), `core/sentinel_extras.py` (`IntruderAlertWatcher`).
- **Trigger Condition**:
  - Direct spoof detection or unknown face detection.
  - **Failure Clustering**: Repeated face identification failures (default: >= 3 failures within a 60-second rolling window).
- **Automated Actions**:
  1. Emits `tamper_attempt` or `intruder_detected` event into the HMAC-SHA256 chained audit log.
  2. Captures intruder visual frames / video clip to secure storage.
  3. Dispatches `CRITICAL` alert (`event_type="intruder_alert"`, priority 100) via `ProactiveBridge`.
  4. Triggers immediate screen lockdown or UI intrusion warning.

---

### 2.3 Anomaly Detection & Step-Up Authentication Engine

Evaluates contextual signals across login, credential modification, and wipe operations.

#### Signals Monitored (`sentinel/anomaly/detector.py`)
- **Temporal**: Out-of-profile hour of day, day of week.
- **Network / Environment**: Unknown IP address, subnet shift, unfamiliar device hostname/MAC.
- **Clustering**: Recent burst of authentication or verification failures.
- **Fail-Closed Guarantee**: If `baseline.json` is missing, corrupted, or if `evaluate()` raises any exception, `evaluate_friction()` returns `elevate_friction=True` and `requires_step_up=True`.

---

### 2.4 Mutual Supervisor & Watchdog

Ensures continuous execution and prevents unauthenticated termination of the JARVIS daemon.

#### Mechanics (`jarvis_watchdog.py`)
- **Dual-Process Supervision**: `jarvis_service.py` (main service) and `jarvis_watchdog.py` (companion watchdog) mutually monitor each other's process handles.
- **DACL-Protected Heartbeat**: Process health is asserted every 2 seconds via `heartbeat.dat`. On Windows, the heartbeat file DACL is locked to the specific user SID to prevent unauthorized deletion or tampering.
- **Authenticated Exit Markers**: When JARVIS shuts down intentionally, it writes `exit_marker.dat` containing an HMAC signature derived from DPAPI-protected session keys. If an attacker terminates the service process without the valid authenticated marker, the companion process detects the abnormal termination, immediately relaunches the service, and emits a security alert.
- **Restart Storm Throttling**: Relaunches are rate-limited (max 3 restarts in 60s) to prevent uncontrolled looping.

---

### 2.5 Tamper-Evident Chained Audit Logging

Provides cryptographic proof of log integrity.

#### Mechanics (`core/audit_log.py`)
- Every security event is serialized to JSON and appended to `audit.log`.
- Each record includes `prev_hash`, `timestamp`, `event_type`, `severity`, `actor`, and `details`.
- Cryptographic hash is computed as HMAC-SHA256(K, prev_hash || entry_json).
- Any modification, deletion, or insertion breaks the hash chain and is immediately flagged by `verify_chain()`.

---

## 3. Incident Severity Matrix

| Severity Level | Trigger Conditions | Automated Response | Operator Action Required |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | • Blocked anomalous wipe attempt<br>• Intruder/spoof clustering detected<br>• Audit log hash chain broken<br>• Unauthenticated service termination | `ProactiveBridge` priority 100 dispatch, audio alert, audit logging, screen lock | Immediate manual triage, physical workspace inspection, forensic log review |
| **HIGH** | • Primary PIN Hard Lockout (>= 7 failures)<br>• Master vault key rotation recovery triggered<br>• Anomaly detector elevates friction on destructive action | Elevated friction, Recovery PIN required, audible warning | Verify user presence, check lockout state, execute recovery PIN unlock if legitimate |
| **MEDIUM** | • Soft PIN lockout delay (3-6 failures)<br>• Single face verification failure<br>• Watchdog brief heartbeat lag | Temporary rate-limit backoff (5s-300s), local UI warning | Monitor workstation, verify no unauthorized physical access |
| **LOW** | • Routine token rotation<br>• Minor baseline update<br>• Clean system startup/shutdown | Audit log record appended | No immediate action required |

---

## 4. Standard Incident Response Playbooks

### Playbook A: Anomalous / Unauthorized Wipe Triggered

**Scenario**: A remote or local wipe command was requested under an anomalous context, or failed step-up verification.

1. **Verify Automated Containment**:
   - Confirm that `EmergencyWipeController` blocked the wipe (verify that `requires_step_up` was enforced).
   - Check that `ProactiveBridge` dispatched the critical alert: *"CRITICAL: Anomalous wipe attempt blocked; step-up verification required."*
2. **Examine Audit Log**:
   ```powershell
   python -m core.security_status --audit
   ```
   Inspect the latest `wipe_requested` and `wipe_blocked` entries for source IP, timestamp, and actor details.
3. **If Source was Remote Email**:
   - Check IMAP server logs for unauthorized email origination.
   - Rotate `EMAIL_WIPE_SECRET` stored in the secure vault:
     ```powershell
     python -c "from core.secure_vault import SecureVault; SecureVault().set_secret('EMAIL_WIPE_SECRET', '<NEW_HIGH_ENTROPY_SECRET>')"
     ```
4. **If Source was Local Console**:
   - Inspect workstation physical security; verify whether unauthorized hands-on-keyboard activity occurred.

---

### Playbook B: Intruder Detection / Face Spoof Cluster

**Scenario**: `IntruderAlertWatcher` detected >= 3 face-verify failures in 60 seconds or an active anti-spoofing alert.

1. **Immediate Physical Containment**:
   - Workstation automatically locks screen and pauses active JARVIS command processing.
2. **Review Intruder Evidence**:
   - Check the captured intruder visual artifacts stored under `data/intruder_captures/` or `logs/intruder_log.json`.
3. **Verify Integrity of Biometric Baseline**:
   - Inspect face enrollment templates in `data/face_encodings/`.
   - If tampering is suspected, re-enroll biometric profiles:
     ```powershell
     python -m core.face_verify --enroll
     ```

---

### Playbook C: Watchdog Unauthenticated Termination Alert

**Scenario**: JARVIS service was killed without writing an authenticated `exit_marker.dat`.

1. **Confirm Service Relaunch**:
   - Verify that `jarvis_watchdog.py` successfully re-spawned `jarvis_service.py`.
   - Inspect Task Manager or run:
     ```powershell
     Get-Process -Name python | Select-Object Id, ProcessName, StartTime, CommandLine
     ```
2. **Examine Watchdog Log**:
   - Inspect `logs/watchdog.log` for termination timestamps and parent process IDs (PID).
3. **Check for Malicious Injection / Kill Signals**:
   - Verify if an external task-kill command (`taskkill /F /IM python.exe`) was executed by inspecting Windows Event Logs (`Security` / Event ID 4688 Process Creation).

---

### Playbook D: Audit Chain Integrity Broken / Dashboard Posture CRITICAL

**Scenario**: Security dashboard reports `overall_posture: CRITICAL` with an audit chain validation failure.

1. **Run Full Integrity Audit**:
   ```powershell
   python -m core.security_status
   ```
2. **Locate Point of Chain Breakage**:
   - The diagnostic output will pinpoint the exact sequence number where HMAC(prev_hash) != recorded_hash.
3. **Isolate Corrupted File for Forensics**:
   - Copy `logs/audit.log` to an isolated forensic directory before modifying.
4. **Restore / Rotate Audit Store**:
   - Archive the broken log and initialize a clean cryptographic chain:
     ```powershell
     python -c "from core.audit_log import AuditLogger; AuditLogger.rotate_compromised_log()"
     ```

---

## 5. Post-Incident Recovery & Verification

After any security incident, execute the full automated verification suite to confirm that all gates, hashes, and supervisor channels are fully operational:

```powershell
# 1. Run full unit and security gate test suite
pytest tests/ -v --tb=short

# 2. Run dependency supply-chain security audit
python -m pip_audit -r requirements.txt --desc

# 3. Verify security dashboard posture
python -m core.security_status
```
Ensure all 261+ tests pass, no vulnerabilities exist, and the security posture reports **NORMAL**.
