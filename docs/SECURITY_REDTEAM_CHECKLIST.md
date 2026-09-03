# Sentinel & JARVIS Security Red-Teaming Checklist (Phase 9)

## 1. Overview & Operational Scope

This document provides an actionable, repeatable red-teaming checklist for challenging every defensive control in JARVIS / Sentinel. For every attack vector, this runbook details:
1. **Target Subsystem & Attack Mechanism**: The concrete vulnerability or bypass attempted.
2. **Automated Test Coverage**: The exact test file, line number, and test function verifying the control.
3. **Fail-Closed Guarantee**: The specific failure mode and security state enforced under attack.
4. **Manual Red-Team Verification**: Hands-on physical/network test procedures extending beyond synthetic unit tests.

---

## 2. Attack Vector 1: State File Deletion & Corruption (Fail-Closed Matrix)

| Target State File | Attack Attempted | Automated Test in Suite | Fail-Closed Mode Enforced | Manual Red-Team Verification Procedure |
| :--- | :--- | :--- | :--- | :--- |
| **Integrity Manifest**<br>`config/manifest.json`<br>`config/manifest.sig` | Delete manifest, delete signature, or corrupt public key | • `test_integrity_manifest.py:260` (`test_integrity_missing_manifest_fails_closed`)<br>• `test_integrity_manifest.py:219` (`test_integrity_missing_public_key_fails_closed`)<br>• `test_integrity_manifest.py:240` (`test_integrity_corrupted_public_key_fails_closed`)<br>• `test_integrity_manifest.py:291` (`test_verify_on_startup_failure_blocks_daemon_startup`) | Returns `(False, reason)` on verify; raises `SystemExit` on startup. Daemon startup strictly blocked. | 1. Rename `config/manifest.json` to `manifest.json.bak`.<br>2. Execute `python jarvis_service.py`.<br>3. Verify daemon exits immediately ($0\text{s}$) with error code $\ne 0$ without opening network ports. |
| **Audit Hash-Chain**<br>`memory/audit.log`<br>`.sentinel/audit/audit.jsonl` | Delete audit log, erase HMAC keys, or delete mid-session mirror state | • `test_audit.py:501` (`test_full_file_deletion_detected_on_startup`)<br>• `test_audit.py:705` (`test_audit_chain_missing_historical_key_fails_verification`)<br>• `test_audit.py:800` (`test_mid_run_mirror_state_deletion_fails_closed_and_logs_audit_tamper`)<br>• `test_audit.py:962` (`test_fail_closed_prevents_further_mirror_writes_after_tamper`) | `verify_chain()` fails, raises `ChainIntegrityError`, logs tamper alarm, and halts mirror writes. | 1. Truncate `audit.jsonl` while daemon is active.<br>2. Run `python -m core.security_status`.<br>3. Confirm posture reports **CRITICAL** (red) and highlights sequence disruption. |
| **Service Heartbeat**<br>`memory/jarvis_heartbeat.json` | Delete or hold exclusive file lock on heartbeat file | • `test_watchdog.py:37` (`test_companion_check_missing_heartbeat_triggers_relaunch`)<br>• `test_watchdog.py:63` (`test_companion_check_stale_heartbeat_triggers_relaunch`)<br>• `test_watchdog.py:403` (`test_fail_closed_heartbeat_deletion_scenario`) | Heartbeat age exceeds `HEARTBEAT_STALE_SECS = 45s`; watchdog cleans ports and triggers fresh restart. | 1. Terminate main process: `taskkill /F /PID <jarvis_pid>`.<br>2. Delete `memory/jarvis_heartbeat.json`.<br>3. Confirm watchdog detects absence within 15-45s and launches replacement process. |
| **Exit Marker**<br>`memory/jarvis_intentional_exit.marker` | Write unauthenticated or forged exit marker to suppress restart | • `test_watchdog.py:296` (`test_attacker_created_unauthenticated_exit_marker_is_rejected`)<br>• `test_watchdog.py:331` (`test_authenticated_exit_marker_bounded_lifetime_and_expiry`)<br>• `test_watchdog.py:359` (`test_attacker_reading_raw_dpapi_ciphertext_key_cannot_forge_marker`) | `verify_authenticated_exit_marker()` rejects non-DPAPI/unauthenticated markers; restarts service. | 1. Write dummy text: `echo "clean_quit" > memory/jarvis_intentional_exit.marker`.<br>2. Kill `jarvis_service.py`.<br>3. Verify watchdog ignores unauthenticated marker and relaunches JARVIS. |
| **Vault Rotation Journal**<br>`vault/rotation_journal.json` | Corrupt or truncate journal during master key rotation crash | • `test_vault.py:522` (`test_vault_store_rotation_crash_recovery`)<br>• `test_vault.py:561` (`test_vault_store_corrupted_journal_fails_closed`)<br>• `test_vault.py:604` (`test_vault_store_rotation_crash_during_staging_recovery`) | Raises `RotationRecoveryError`, halts vault operations, and refuses plaintext leakage. | 1. Inject malformed JSON into `rotation_journal.json`.<br>2. Instantiate `SecureVault()`.<br>3. Confirm vault throws `RotationRecoveryError` and refuses key reads/writes. |
| **Lockout State**<br>`auth/lockout_state.json` | Delete or corrupt lockout state file on initialized system | • `test_auth.py:518` (`test_fail_closed_mid_session_state_deletion`)<br>• `sentinel/auth/lockout.py:89-113` (`_read_state_locked` fail-closed logic) | Assigns `primary_failures=999`, hard-locks Primary PIN, and strictly mandates Recovery PIN. | 1. Delete `auth/lockout_state.json` on a configured system.<br>2. Attempt Primary PIN authentication.<br>3. Confirm Primary PIN is locked out and Recovery PIN prompt is enforced. |
| **Anomaly Baseline**<br>`auth/anomaly_baseline.json` | Delete or corrupt anomaly baseline file | • `test_anomaly_baseline.py:26` (`test_baseline_missing_or_corrupted_fails_toward_more_friction`)<br>• `test_emergency_wipe.py:455` (`test_emergency_wipe_fail_closed_on_anomaly_evaluation_exception`) | `evaluate_friction()` returns `elevate_friction=True` and `requires_step_up=True`. | 1. Write invalid JSON to `auth/anomaly_baseline.json`.<br>2. Trigger `/wipe` request.<br>3. Confirm controller requires Recovery PIN step-up verification. |

---

## 3. Attack Vector 2: Replay of Old Signed Commands

### 2.1 Email Wipe Nonce Reuse Attack
- **Attack Goal**: Re-broadcast a previously intercepted, cryptographically valid signed email wipe payload to trigger an unauthorized wipe.
- **Automated Test Coverage**:
  - `tests/test_email_wipe.py:132` (`test_replayed_valid_command_is_rejected`)
  - `tests/test_email_wipe.py:170` (`test_nonce_file_deletion_replay_prevented_via_audit_anchor`)
  - `tests/test_email_wipe.py:221` (`test_triple_scenario_nonce_deletion_and_audit_line_tamper_detected_via_chain_verification`)
- **Defense Mechanism**:
  1. Primary Check: Validates nonce against local memory store (`.email_wipe_nonces.json`).
  2. Fallback / Anti-Tamper Anchor: Even if an attacker deletes `.email_wipe_nonces.json`, `EmailWipeListener._load_nonces()` reconstructs seen nonces by scanning the verified HMAC-SHA256 audit log (`audit.jsonl`).
  3. Bounded Freshness Window: Rejects any command timestamp older than `DEFAULT_FRESHNESS_WINDOW_SECS = 300.0` (5 minutes).
- **Manual Red-Team Verification**:
  1. Capture a valid signed email body from a previous test run.
  2. Send an email with the identical body to the monitored IMAP inbox 10 minutes later.
  3. Verify `EmailWipeListener` drops the message due to timestamp expiry and logs `email_wipe_rejected_expired`.
  4. Send an email with the same nonce within 5 minutes; confirm rejection due to nonce reuse.

### 2.2 Presence Token Replay & Consumption Attack
- **Attack Goal**: Reuse a physical presence enrollment token or use an expired setup token.
- **Automated Test Coverage**:
  - `tests/test_auth.py:294` (`test_first_run_expired_presence_token`)
  - `tests/test_auth.py:304` (`test_first_run_successful_enrollment_and_token_consumption`)
  - `tests/test_auth.py:326` (`test_generate_presence_token_rejected_when_initialized`)
- **Defense Mechanism**:
  1. Atomic Token Consumption: Presence token is deleted from disk immediately upon first use (`apply_owner_only_dacl`).
  2. Lifetime Expiration: `presence_token_ttl_seconds = 300` (5 minutes).
- **Manual Red-Team Verification**:
  1. Run `python -m sentinel.auth.setup --generate-token`.
  2. Complete initial enrollment using the generated token.
  3. Immediately submit a second enrollment request using the same token.
  4. Confirm the second attempt fails with `InvalidPresenceTokenError`.

---

## 4. Attack Vector 3: Concurrent Access & Race Conditions

### 3.1 DPAPI Key & Vault Store Rotation Race
- **Attack Goal**: Induce race conditions by performing concurrent credential lookups during master key rotation.
- **Automated Test Coverage**:
  - `tests/test_vault.py:451` (`test_vault_store_key_rotation`)
  - `tests/test_vault.py:522` (`test_vault_store_rotation_crash_recovery`)
  - `tests/test_vault.py:604` (`test_vault_store_rotation_crash_during_staging_recovery`)
  - `tests/test_auth.py:653` (`test_concurrent_atomic_authentication_no_lost_updates`)
- **Defense Mechanism**:
  1. Atomic Multi-Stage Journal: `rotation_journal.json` tracks stages: `STARTING` $	o$ `STAGING` $	o$ `COMMITTING` $	o$ `COMPLETED`.
  2. Cross-Process Locking: `FileLock` held across state updates.
- **Manual Red-Team Verification**:
  1. Spawn 10 concurrent threads continuously reading and writing vault secrets.
  2. Trigger `rotate_master_key()` mid-flight.
  3. Verify all concurrent reads either resolve with previous valid keys or new valid keys; verify zero plaintext leakages or corrupted files.

---

## 5. Attack Vector 4: Single-Byte File Tampering

### 4.1 Monitored Source Code & Manifest Tampering
- **Attack Goal**: Modify a single byte in a monitored production script (e.g. `core/access_control.py`) to weaken PIN verification.
- **Automated Test Coverage**:
  - `tests/test_integrity_manifest.py:85` (`test_integrity_tampered_file_fails_verification`)
  - `tests/test_integrity_manifest.py:107` (`test_integrity_missing_file_fails_verification`)
  - `tests/test_integrity_manifest.py:128` (`test_integrity_untracked_injected_file_fails_verification`)
  - `tests/test_integrity_manifest.py:198` (`test_integrity_tampered_manifest_contents_fails_verification`)
- **Defense Mechanism**:
  1. Cryptographic Manifest Verification: SHA-256 hash comparison across all repository files against signed Ed25519 `config/manifest.sig`.
- **Manual Red-Team Verification**:
  1. Edit a single character or add a whitespace byte in `core/sentinel_extras.py`.
  2. Execute `python -m sentinel.integrity.verifier`.
  3. Confirm verification returns `False` and lists `core/sentinel_extras.py` under `tampered_files`.

### 4.2 Audit Log Record Modification
- **Attack Goal**: Alter an audit event payload (e.g. change `wipe_blocked` to `wipe_approved`).
- **Automated Test Coverage**:
  - `tests/test_audit.py:54` (`test_audit_entry_hmac_fails_with_wrong_key_or_modified_payload`)
  - `tests/test_audit.py:264` (`test_verify_chain_detects_payload_modification`)
  - `tests/test_audit.py:289` (`test_verify_chain_detects_deleted_record`)
  - `tests/test_audit.py:312` (`test_verify_chain_detects_inserted_record`)
- **Defense Mechanism**:
  1. Chained HMAC-SHA256: Record $N$ incorporates hash of record $N-1$.
- **Manual Red-Team Verification**:
  1. Open `memory/audit.log` or `.sentinel/audit/audit.jsonl` in a text editor.
  2. Change a single character in a timestamp or event detail.
  3. Execute `python -m core.security_status`.
  4. Confirm that the dashboard flags a broken HMAC chain at that exact sequence number and sets status to **CRITICAL**.

---

## 6. Attack Vector 5: Wipe Anomaly Gating & Step-Up Bypass

### 5.1 Remote Anomalous Wipe Without Recovery PIN
- **Attack Goal**: Send a wipe confirmation using Primary PIN from an untrusted network context without supplying the Recovery PIN.
- **Automated Test Coverage**:
  - `tests/test_emergency_wipe.py:390` (`test_emergency_wipe_anomaly_step_up_refusal_and_proactive_alert`)
  - `tests/test_emergency_wipe.py:426` (`test_emergency_wipe_anomaly_step_up_success_with_recovery_pin`)
  - `tests/test_emergency_wipe.py:455` (`test_emergency_wipe_fail_closed_on_anomaly_evaluation_exception`)
  - `tests/test_email_wipe.py:617` (`test_email_wipe_anomaly_step_up_refusal_and_proactive_alert`)
  - `tests/test_email_wipe.py:661` (`test_email_wipe_anomaly_step_up_success_with_recovery_pin_in_payload`)
- **Defense Mechanism**:
  1. Risk Scoring: If anomaly risk $\ge 	ext{FRICTION\_THRESHOLD} = 0.5$, `requires_step_up` is set to `True`.
  2. Fail-Closed On Evaluation Error: If anomaly evaluation throws any exception, it defaults to `requires_step_up = True`.
  3. Secondary Verification: `EmergencyWipeController.confirm_wipe()` demands `authenticate_recovery()`.
  4. Critical Alert: Dispatches `ProactivePriority.CRITICAL = 10` alert via `ProactiveBridge` synchronously prior to voice dispatch.
- **Manual Red-Team Verification**:
  1. Connect mobile companion / Telegram client from a cellular hotspot (different subnet/SSID).
  2. Request wipe: `/wipe`.
  3. Confirm wipe with Primary PIN only: `/wipe CONFIRM <PRIMARY_PIN>`.
  4. Verify response: *"❌ Wipe refused: Multi-factor step-up verification required due to elevated anomaly risk."*
  5. Verify desktop JARVIS speaks and displays a `CRITICAL` blocked wipe security alarm.
  6. Confirm wipe paths remain untouched in filesystem.

---

## 7. Red-Team Verification Summary Checklist

- [ ] **State Integrity**: Verified fail-closed behavior on missing/corrupted `manifest.json`, `audit.jsonl`, `heartbeat.json`, `exit_marker.marker`, `rotation_journal.json`, and `lockout_state.json`.
- [ ] **Replay Defense**: Verified rejection of replayed email wipe nonces and expired presence tokens.
- [ ] **Concurrency**: Verified zero state corruption under concurrent authentication and master key rotation.
- [ ] **Tamper Detection**: Verified detection of 1-byte edits in codebase manifest and HMAC audit chain.
- [ ] **Anomaly Gating**: Verified refusal of anomalous emergency wipe without Recovery PIN and confirmed `CRITICAL` ProactiveBridge alarm dispatch.
- [ ] **Supervisor Supervision**: Verified unauthenticated task termination triggers watchdog relaunch within 45 seconds.
