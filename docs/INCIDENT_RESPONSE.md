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
        │      ProactiveBridge      │  (Priority: CRITICAL=10)
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

The emergency wipe subsystem provides physical and remote destruction of sensitive caches, conversation history, credentials, and configuration files via `send2trash` (Recycle Bin safe execution).

#### Triggers & Entry Points
1. **Interactive / CLI / Mobile Wipe** (`core/sentinel_extras.py:556` -> `EmergencyWipeController`):
   - **Request Phase**: `request_wipe(pin, source, context)`:
     - Authenticates Primary PIN via `authenticate_primary()`.
     - Evaluates environmental anomaly signals via `AnomalyDetector.get_instance().evaluate_friction(context, action="wipe")`.
     - In normal context: Generates a cryptographically random confirmation token (`os.urandom(16).hex()`) valid for a 60.0-second confirmation window (`confirmation_timeout_seconds = 60.0`, `core/sentinel_extras.py:572`).
     - In anomalous context (or upon any evaluation error): Fails closed, marks `requires_step_up = True`, and generates a step-up token requiring Recovery PIN verification.
   - **Confirmation Phase**: `confirm_wipe(token, recovery_pin=None, source="local", context=None)`:
     - Verifies token validity and 60.0-second expiry window.
     - If `requires_step_up` is `True`, verifies the Recovery PIN via `authenticate_recovery()`. If Recovery PIN is missing or invalid, the wipe is **strictly blocked**, an audit log entry (`emergency_wipe_anomaly_step_up_required`) is recorded, and a `CRITICAL` proactive alert is dispatched to `ProactiveBridge` (`ProactivePriority.CRITICAL = 10`, `core/proactive_bridge.py:34`).
     - If verified, executes file shredding and directory removal via `send2trash`.

2. **Email / IMAP Remote Wipe** (`core/email_wipe_listener.py:95` -> `EmailWipeListener`):
   - Polls configured IMAP mailbox over SSL/TLS (default port `993`, `core/email_wipe_listener.py:104`).
   - Requires valid HMAC-SHA256 signature using a 32-byte key stored at rest with Windows DPAPI (`core/email_wipe_listener.py:157`).
   - Validates timestamp freshness against a 300.0-second (5-minute) bounded window (`DEFAULT_FRESHNESS_WINDOW_SECS = 300.0`, `core/email_wipe_listener.py:43`).
   - Evaluates anomaly context (`source="email_remote"`).
   - If anomalous, strictly requires the embedded payload to supply the valid `recovery_pin`.
   - On unauthenticated or blocked attempts: Dispatches `CRITICAL` alert (`ProactivePriority.CRITICAL = 10`) to `ProactiveBridge` and logs to `audit.log`.

---

### 2.2 Intruder Detection & Face Verification Clustering

Monitors physical workstation presence and detects unauthorized access, spoofing attempts, and failed identification clusters.

#### Triggers & Entry Points
- **Subsystems**: `core/face_verify.py` (`FaceVerifier`), `sentinel/anomaly/detector.py` (`AnomalyDetector`), `core/intruder_alert.py` (`IntruderAlertWatcher`).
- **Trigger Conditions**:
  - Direct spoof detection or unknown face detection.
  - **Failure Clustering**: Repeated face identification failures reaching threshold within a rolling window (`FACE_FAILURE_CLUSTER_THRESHOLD = 3` failures within `FACE_FAILURE_CLUSTER_WINDOW_SECS = 180.0` [3 minutes], `sentinel/anomaly/detector.py:27-28`).
- **Automated Actions**:
  1. Emits `tamper_attempt` or `intruder_detected` event into the HMAC-SHA256 chained audit log.
  2. Captures intruder visual frames / video clip to secure storage (`data/intruder_captures/`).
  3. Dispatches `CRITICAL` alert (`event_type="intruder_alert"`, `ProactivePriority.CRITICAL = 10`, `core/proactive_bridge.py:34`) via `ProactiveBridge`.
  4. Triggers immediate screen lockdown or UI intrusion warning.

---

### 2.3 Anomaly Detection & Step-Up Authentication Engine

Evaluates contextual signals across login, credential modification, and wipe operations (`sentinel/anomaly/detector.py`).

#### Signals & Constants
- **Risk Threshold**: `FRICTION_THRESHOLD = 0.5` (`sentinel/anomaly/detector.py:25`).
- **Minimum Calibration**: `MIN_OBSERVATIONS_FOR_CALIBRATION = 3` (`sentinel/anomaly/detector.py:26`).
- **Face Failure Cluster Window**: `FACE_FAILURE_CLUSTER_WINDOW_SECS = 180.0` (3 minutes, threshold: 3, `sentinel/anomaly/detector.py:27-28`).
- **Watchdog Restart Cluster Window**: `WATCHDOG_RESTART_CLUSTER_WINDOW_SECS = 300.0` (5 minutes, threshold: 3, `sentinel/anomaly/detector.py:29-30`).
- **Lock Acquisition Timeout**: `lock_timeout_seconds = 3.0` (`sentinel/anomaly/detector.py:43`).
- **Fail-Closed Guarantee**: If `anomaly_baseline.json` is missing, corrupted, or if `evaluate()` raises any exception, `evaluate_friction()` returns `elevate_friction=True` and `requires_step_up=True`.

---

### 2.4 Mutual Supervisor & Watchdog

Ensures continuous execution and prevents unauthenticated termination of the JARVIS daemon (`jarvis_watchdog.py`).

#### Mechanics & Constants
- **Dual-Process Supervision**: `jarvis_service.py` (main service) and `jarvis_watchdog.py` (companion watchdog) mutually monitor each other's process health.
- **DACL-Protected Heartbeat**: Process health is checked every 15 seconds (`CHECK_INTERVAL_SECS = 15`, `jarvis_watchdog.py:45`) and considered stale after 45 seconds (`HEARTBEAT_STALE_SECS = 45`, `jarvis_watchdog.py:46`). Startup grace period is 60 seconds (`STARTUP_GRACE_SECS = 60`, `jarvis_watchdog.py:47`). On Windows, heartbeat files have owner-only DACLs locked to the user SID.
- **Authenticated Exit Markers**: Clean shutdowns write DPAPI/HMAC-signed `exit_marker.dat` valid for 300.0 seconds (`INTENTIONAL_EXIT_MAX_AGE_SECS = 300.0`, `core/watchdog_auth.py:21`). If an attacker kills the service process without an authenticated marker, the watchdog relaunches JARVIS and logs a security event.
- **Restart Storm Throttling**: 3 restarts within a 300-second (5-minute) rolling window triggers a restart storm alert (`RESTART_STORM_WINDOW_SECS = 300`, `RESTART_STORM_THRESHOLD = 3`, `jarvis_watchdog.py:49-50`).

---

### 2.5 Tamper-Evident Chained Audit Logging

Provides cryptographic proof of log integrity (`core/audit_log.py`, `sentinel/audit/chain.py`).

#### Mechanics
- Every security event is serialized to JSON and appended to `audit.log` / `audit.jsonl`.
- Each record includes `prev_hash`, `timestamp`, `event_type`, `severity`, `actor`, and `details`.
- Cryptographic hash is computed as $\text{HMAC-SHA256}(K, \text{prev\_hash} \parallel \text{entry\_json})$ using 256-bit keys protected by Windows DPAPI.
- Any modification, deletion, or insertion breaks the hash chain and is immediately detected by `verify_chain()`.

---

## 3. Incident Severity Matrix

| Severity Level | Trigger Conditions | Automated Response | Operator Action Required |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | • Blocked anomalous wipe attempt<br>• Face verify cluster ($\ge 3$ failures in 180s)<br>• Audit log hash chain broken<br>• Unauthenticated service termination | `ProactiveBridge` priority 10 (`CRITICAL`) dispatch, voice alert, audit logging, screen lock | Immediate manual triage, physical workspace inspection, forensic log review |
| **HIGH** | • Primary PIN Hard Lockout ($\ge 7$ failures)<br>• Master vault key rotation recovery triggered<br>• Anomaly score $\ge 0.5$ on destructive action | Elevated friction, Recovery PIN required, audible warning | Verify user presence, check lockout state, execute recovery PIN unlock if legitimate |
| **MEDIUM** | • Soft PIN lockout delay (3–6 failures: 5s, 30s, 300s)<br>• Single face verification failure<br>• Watchdog brief heartbeat lag ($> 45\text{s}$) | Temporary rate-limit backoff (5s–300s), local UI warning | Monitor workstation, verify no unauthorized physical access |
| **LOW** | • Routine token rotation<br>• Minor baseline update ($\ge 3$ observations)<br>• Clean system startup/shutdown | Audit log record appended | No immediate action required |

---

## 4. Standard Incident Response Playbooks

### Playbook A: Anomalous / Unauthorized Wipe Triggered

**Scenario**: A remote or local wipe command was requested under an anomalous context, or failed step-up verification.

1. **Verify Automated Containment**:
   - Confirm that `EmergencyWipeController` blocked the wipe (verify that `requires_step_up` was enforced).
   - Check that `ProactiveBridge` dispatched the critical alert (`ProactivePriority.CRITICAL = 10`): *"CRITICAL: Anomalous wipe attempt blocked; step-up verification required."*
2. **Examine Audit Log**:
   ```powershell
   python -m core.security_status --audit
   ```
   Inspect the latest `wipe_requested` and `emergency_wipe_anomaly_step_up_required` entries for source, timestamp, and anomaly scores.
3. **If Source was Remote Email**:
   - Check IMAP server logs for unauthorized email origination.
   - Rotate `EMAIL_WIPE_SECRET` stored in DPAPI-protected storage (`memory/.email_wipe_auth.key`):
     ```powershell
     python -c "from core.email_wipe_listener import EmailWipeListener; EmailWipeListener()._generate_or_load_key()"
     ```
4. **If Source was Local Console / Mobile**:
   - Inspect workstation physical security; verify whether unauthorized hands-on-keyboard or mobile network activity occurred.

---

### Playbook B: Intruder Detection / Face Spoof Cluster

**Scenario**: `IntruderAlertWatcher` detected $\ge 3$ face-verify failures in 180 seconds (`FACE_FAILURE_CLUSTER_WINDOW_SECS = 180.0`) or an active anti-spoofing alert.

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

**Scenario**: JARVIS service was killed without writing an authenticated `exit_marker.dat` (valid for $\le 300\text{s}$).

1. **Confirm Service Relaunch**:
   - Verify that `jarvis_watchdog.py` successfully re-spawned `jarvis_service.py` within `STARTUP_GRACE_SECS = 60`.
   - Inspect Task Manager or run:
     ```powershell
     Get-Process -Name python | Select-Object Id, ProcessName, StartTime, CommandLine
     ```
2. **Examine Watchdog Log**:
   - Inspect `memory/watchdog.log` for termination timestamps and reason strings.
3. **Check for Malicious Injection / Kill Signals**:
   - Verify if an external task-kill command (`taskkill /F /PID ...`) was executed by inspecting Windows Event Logs (`Security` / Event ID 4688 Process Creation).

---

### Playbook D: Audit Chain Integrity Broken / Dashboard Posture CRITICAL

**Scenario**: Security dashboard reports `overall_posture: CRITICAL` with an audit chain validation failure.

1. **Run Full Integrity Audit**:
   ```powershell
   python -m core.security_status
   ```
2. **Locate Point of Chain Breakage**:
   - The diagnostic output will pinpoint the exact sequence number where $\text{HMAC}(\text{prev\_hash}) \ne \text{recorded\_hash}$.
3. **Isolate Corrupted File for Forensics**:
   - Copy `memory/audit.log` or `.sentinel/audit/audit.jsonl` to an isolated forensic directory before modifying.
4. **Restore / Rotate Audit Store**:
   - Archive the broken log and initialize a clean cryptographic chain:
     ```powershell
     python -c "from sentinel.audit.chain import AuditLogger; AuditLogger().rotate()"
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
