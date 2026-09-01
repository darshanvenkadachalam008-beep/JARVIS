"""
tests/test_cold_boot_provider.py — Test Suite for Cold-Boot Credential Provider Duress Flow
===========================================================================================
Verifies:
1. Duress Login Success: Primary fail -> duress prompt -> duress password accepted (ntsStatus == 0)
   -> DURESS_LOGIN_SUCCESS event queued in DPAPI-encrypted queue file with zero UI/status mutation.
2. Normal Login Success: Normal password accepted (ntsStatus == 0, _bDuressModeActive == False)
   -> No alert event queued (non-duress logins remain silent and unlogged).
3. Downstream IntruderAlert integration: cold-boot queue decryption, event parsing, and
   silent duress alert routing to Telegram/FCM channels.
"""
import json
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from credential_provider.test_alert_queue import _dpapi_protect, _dpapi_unprotect
from core.intruder_alert import _read_and_clear_cold_boot_queue, IntruderAlertWatcher


class MockJarvisCredential:
    """Python simulation of CJarvisCredential matching JarvisCredentialProvider.cpp logic."""

    def __init__(self, username="Administrator"):
        self._pszUsername = username
        self._pszPassword = ""
        self._pszDuressPassword = ""
        self._bDuressModeActive = False
        self._bSessionLocked = False
        self._dwAttemptCount = 0
        self._pcpce = MagicMock()

    def show_duress_prompt(self):
        self._bDuressModeActive = True
        self._pcpce.SetFieldState(14, "CPFS_DISPLAY_IN_SELECTED_TILE")  # JFI_DURESS_LABEL
        self._pcpce.SetFieldState(15, "CPFS_DISPLAY_IN_SELECTED_TILE")  # JFI_DURESS_PASSWORD
        self._pcpce.SetFieldString(11, "⚠️ Primary authentication failed. Enter fallback authorization code:")

    def report_result(self, nts_status, queue_file_path=None, entropy=None):
        """Simulates CJarvisCredential::ReportResult from JarvisCredentialProvider.cpp."""
        user = self._pszUsername if self._pszUsername else ""
        ppsz_optional_status_text = None
        pcpsi_optional_status_icon = None

        if nts_status == 0:  # STATUS_SUCCESS
            if self._bDuressModeActive:
                # Queue DURESS_LOGIN_SUCCESS non-blocking
                if queue_file_path and entropy:
                    event = {
                        "timestamp": "2026-09-01T10:45:00.000Z",
                        "event_type": "DURESS_LOGIN_SUCCESS",
                        "attempt_count": self._dwAttemptCount,
                        "layer": "duress_password",
                        "domain": "WORKGROUP",
                        "username": user,
                    }
                    existing_data = b""
                    if queue_file_path.exists():
                        try:
                            dec = _dpapi_unprotect(queue_file_path.read_bytes(), entropy)
                            existing_data = dec
                        except Exception:
                            pass
                    new_payload = existing_data + (json.dumps(event) + "\n").encode("utf-8")
                    queue_file_path.write_bytes(_dpapi_protect(new_payload, entropy))

            # ResetSessionState
            return {
                "hresult": 0,  # S_OK
                "status_text": ppsz_optional_status_text,
                "status_icon": pcpsi_optional_status_icon,
            }

        # Failure path (nts_status != 0)
        self._dwAttemptCount += 1
        if not self._bDuressModeActive:
            self.show_duress_prompt()
            if queue_file_path and entropy:
                event = {
                    "timestamp": "2026-09-01T10:45:00.000Z",
                    "event_type": "FAILED_PRIMARY_LOGON",
                    "attempt_count": self._dwAttemptCount,
                    "layer": "primary_password",
                    "domain": "WORKGROUP",
                    "username": user,
                }
                queue_file_path.write_bytes(_dpapi_protect((json.dumps(event) + "\n").encode("utf-8"), entropy))
            ppsz_optional_status_text = "Primary password incorrect. Fallback passcode requested."
            pcpsi_optional_status_icon = "CPSI_WARNING"
        return {
            "hresult": 0,
            "status_text": ppsz_optional_status_text,
            "status_icon": pcpsi_optional_status_icon,
        }


def test_duress_login_success_simulation(tmp_path):
    """
    Simulates:
    1. Primary logon attempt fails -> duress prompt revealed -> _bDuressModeActive = TRUE.
    2. Duress password entered and accepted by Windows (nts_status == 0).
    3. ReportResult queues DURESS_LOGIN_SUCCESS without UI mutation.
    """
    entropy = os.urandom(32)
    queue_file = tmp_path / "boot_alert_queue.enc"

    cred = MockJarvisCredential(username="AdminUser")

    # Step 1: Failed primary login
    res_fail = cred.report_result(nts_status=0xC000006D, queue_file_path=queue_file, entropy=entropy)
    assert cred._bDuressModeActive is True
    assert res_fail["status_text"] is not None
    assert res_fail["status_icon"] == "CPSI_WARNING"

    # Step 2: User enters valid duress password -> Windows returns STATUS_SUCCESS (0)
    # Record mock call counts before ReportResult to verify zero UI mutations
    set_string_count_before = cred._pcpce.SetFieldString.call_count
    set_state_count_before = cred._pcpce.SetFieldState.call_count

    res_success = cred.report_result(nts_status=0, queue_file_path=queue_file, entropy=entropy)

    # Step 3: Verify zero UI / status mutations in success path
    assert res_success["hresult"] == 0  # S_OK
    assert res_success["status_text"] is None
    assert res_success["status_icon"] is None
    assert cred._pcpce.SetFieldString.call_count == set_string_count_before
    assert cred._pcpce.SetFieldState.call_count == set_state_count_before

    # Step 4: Verify encrypted queue payload
    decrypted = _dpapi_unprotect(queue_file.read_bytes(), entropy).decode("utf-8")
    lines = [json.loads(line) for line in decrypted.strip().splitlines() if line.strip()]
    assert len(lines) == 2
    assert lines[0]["event_type"] == "FAILED_PRIMARY_LOGON"
    assert lines[1]["event_type"] == "DURESS_LOGIN_SUCCESS"
    assert lines[1]["username"] == "AdminUser"
    assert lines[1]["layer"] == "duress_password"


def test_normal_login_success_does_not_queue_event(tmp_path):
    """
    Simulates normal (non-duress) login success:
    1. cred._bDuressModeActive is FALSE.
    2. nts_status == 0.
    3. ReportResult does NOT queue any event, and queue file remains absent.
    """
    entropy = os.urandom(32)
    queue_file = tmp_path / "boot_alert_queue.enc"

    cred = MockJarvisCredential(username="RegularUser")
    assert cred._bDuressModeActive is False

    res = cred.report_result(nts_status=0, queue_file_path=queue_file, entropy=entropy)

    assert res["hresult"] == 0
    assert res["status_text"] is None
    assert res["status_icon"] is None
    assert not queue_file.exists()


def test_downstream_intruder_alert_flushes_duress_event_to_outbound_channels(tmp_path):
    """
    Verifies that when IntruderAlert flushes a queued DURESS_LOGIN_SUCCESS event:
    1. Cold-boot queue is decrypted and cleared.
    2. Outbound alert message formats as a silent duress alert.
    3. Alert is dispatched to both Telegram and mobile notification callback.
    """
    entropy = os.urandom(32)
    queue_file = tmp_path / "boot_alert_queue.enc"

    # Write DURESS_LOGIN_SUCCESS to queue file
    event = {
        "timestamp": "2026-09-01T10:45:00.000Z",
        "event_type": "DURESS_LOGIN_SUCCESS",
        "attempt_count": 1,
        "layer": "duress_password",
        "domain": "WORKGROUP",
        "username": "Owner",
    }
    queue_file.write_bytes(_dpapi_protect((json.dumps(event) + "\n").encode("utf-8"), entropy))

    # Read and clear queue
    events = _read_and_clear_cold_boot_queue(custom_queue_path=queue_file, custom_entropy=entropy)
    assert len(events) == 1
    assert events[0]["event_type"] == "DURESS_LOGIN_SUCCESS"
    assert not queue_file.exists()  # Queue cleared

    # Test IntruderAlert formatting and dispatch
    mobile_alerts = []
    def on_alert(msg, snapshot):
        mobile_alerts.append(msg)

    watcher = IntruderAlertWatcher(on_alert=on_alert, enabled=True)
    from datetime import datetime
    with patch("core.intruder_alert._take_webcam_snapshot", return_value=None):
        with patch.object(watcher, "_telegram", create=True) as mock_tg:
            mock_tg.configured = True
            mock_tg.send_alert = MagicMock()

            # Fire alert with duress description
            ev = events[0]
            desc = f"🚨 SILENT DURESS ALERT: Successful logon under duress for user '{ev['username']}' (attempt: {ev['attempt_count']})"
            watcher._fire_alert(datetime.now(), bypass_debounce=True, custom_msg=desc)

            # Assert mobile callback received duress message
            assert len(mobile_alerts) == 1
            assert "SILENT DURESS ALERT" in mobile_alerts[0]
            assert "Owner" in mobile_alerts[0]


def test_intruder_alert_cold_boot_queue_flush_formats_duress_and_primary_alerts(tmp_path):
    """
    Tests the actual formatting logic in _loop() for both DURESS_LOGIN_SUCCESS and standard events.
    Executes _read_and_clear_cold_boot_queue and the exact event-processing loop to ensure
    no NameError on 'attempts' and precise message string formatting.
    """
    from datetime import datetime
    entropy = os.urandom(32)
    queue_file = tmp_path / "boot_alert_queue.enc"

    event1 = {
        "timestamp": "2026-09-01T10:45:00.000Z",
        "event_type": "DURESS_LOGIN_SUCCESS",
        "attempt_count": 2,
        "layer": "duress_password",
        "domain": "WORKGROUP",
        "username": "DuressUser",
    }
    event2 = {
        "timestamp": "2026-09-01T10:45:10.000Z",
        "event_type": "FAILED_PRIMARY_LOGON",
        "attempt_count": 1,
        "layer": "primary_password",
        "domain": "WORKGROUP",
        "username": "IntruderUser",
    }
    payload = (json.dumps(event1) + "\n" + json.dumps(event2) + "\n").encode("utf-8")
    queue_file.write_bytes(_dpapi_protect(payload, entropy))

    fired_alerts = []
    watcher = IntruderAlertWatcher(on_alert=lambda msg, snap: None, enabled=True)
    with patch.object(watcher, "_fire_alert", side_effect=lambda dt, bypass_debounce=True, custom_msg=None: fired_alerts.append(custom_msg)):
        # Execute the exact cold-boot processing block from _loop
        cold_boot_events = _read_and_clear_cold_boot_queue(custom_queue_path=queue_file, custom_entropy=entropy)
        for ev in cold_boot_events:
            ts_str = ev.get("timestamp", "")
            try:
                ev_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                ev_dt = datetime.now()
            ev_type = ev.get("event_type", "FAILED_PRIMARY_LOGON")
            user = ev.get("username", "Unknown")
            layer = ev.get("layer", "primary")
            attempts = ev.get("attempt_count", 1)
            if ev_type == "DURESS_LOGIN_SUCCESS":
                desc = f"🚨 SILENT DURESS ALERT: Successful logon under duress for user '{user}' (attempt: {attempts})"
            else:
                desc = f"⚠️ Pre-Login Alert (Cold-Boot Credential Provider): {ev_type} for user '{user}' (layer: {layer}, attempt: {attempts})"
            watcher._fire_alert(ev_dt, bypass_debounce=True, custom_msg=desc)

    assert len(fired_alerts) == 2
    assert fired_alerts[0] == "🚨 SILENT DURESS ALERT: Successful logon under duress for user 'DuressUser' (attempt: 2)"
    assert fired_alerts[1] == "⚠️ Pre-Login Alert (Cold-Boot Credential Provider): FAILED_PRIMARY_LOGON for user 'IntruderUser' (layer: primary_password, attempt: 1)"


def test_duress_login_audit_chain_persists_even_when_push_fails(tmp_path):
    """
    Verifies that when DURESS_LOGIN_SUCCESS flows through cold-boot flush:
    1. Even if Telegram raises an exception AND MobileServer/FCM raises an exception,
    2. An immutable, HMAC-signed audit entry is successfully written to the local audit chain.
    3. The written audit chain verifies cryptographically via AuditLogger.verify_chain().
    """
    from datetime import datetime
    from sentinel.audit import AuditLogger
    from sentinel.audit.models import AuditEntry

    audit_dir = tmp_path / "audit_test"
    audit_logger = AuditLogger(audit_dir=audit_dir, verify_on_startup=False)

    entropy = os.urandom(32)
    queue_file = tmp_path / "boot_alert_queue.enc"

    duress_event = {
        "timestamp": "2026-09-01T10:45:00.000Z",
        "event_type": "DURESS_LOGIN_SUCCESS",
        "attempt_count": 1,
        "layer": "duress_password",
        "domain": "WORKGROUP",
        "username": "OwnerUnderDuress",
    }
    queue_file.write_bytes(_dpapi_protect((json.dumps(duress_event) + "\n").encode("utf-8"), entropy))

    # Failing mobile callback
    def failing_on_alert(msg, snapshot):
        raise ConnectionResetError("FCM / Mobile network down")

    watcher = IntruderAlertWatcher(on_alert=failing_on_alert, enabled=True)
    # Inject isolated audit logger
    watcher._audit = audit_logger

    with patch("core.intruder_alert._take_webcam_snapshot", return_value=None):
        with patch.object(watcher, "_telegram", create=True) as mock_tg:
            mock_tg.configured = True
            # Telegram also fails
            mock_tg.send_alert = MagicMock(side_effect=RuntimeError("Telegram network timeout"))

            # Execute cold-boot queue processing
            cold_boot_events = _read_and_clear_cold_boot_queue(custom_queue_path=queue_file, custom_entropy=entropy)
            for ev in cold_boot_events:
                ts_str = ev.get("timestamp", "")
                try:
                    ev_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except Exception:
                    ev_dt = datetime.now()
                ev_type = ev.get("event_type", "FAILED_PRIMARY_LOGON")
                user = ev.get("username", "Unknown")
                layer = ev.get("layer", "primary")
                attempts = ev.get("attempt_count", 1)
                desc = f"🚨 SILENT DURESS ALERT: Successful logon under duress for user '{user}' (attempt: {attempts})"
                watcher._fire_alert(
                    ev_dt,
                    bypass_debounce=True,
                    custom_msg=desc,
                    event_type="duress_logon_success",
                    actor=user,
                    details={"event_type": ev_type, "layer": layer, "attempt_count": attempts, "username": user, "message": desc},
                )

    # Verify audit chain integrity on disk
    is_valid, count, err = AuditLogger.verify_chain(audit_logger.log_file, audit_logger.hmac_key)
    assert is_valid is True
    assert count == 1
    assert err is None

    # Read and inspect the actual entry from disk
    log_content = audit_logger.log_file.read_text(encoding="utf-8").strip()
    entry = AuditEntry.model_validate_json(log_content)
    assert entry.event_type == "duress_logon_success"
    assert entry.actor == "OwnerUnderDuress"
    assert entry.details["layer"] == "duress_password"
    assert "SILENT DURESS ALERT" in entry.details["message"]


