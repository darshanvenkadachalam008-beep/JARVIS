"""
tests/test_email_wipe.py — Tests for Secondary Out-of-Band Remote Wipe via Signed Email
=======================================================================================
Verifies:
1. Validly signed email wipe command triggers EmergencyWipeController.
2. Unsigned, malformed, or forged HMAC signatures are rejected without triggering wipe.
3. Replay attacks with identical nonces are detected and rejected.
4. Nonce-file deletion attack: deleting .email_wipe_nonces.json cannot bypass replay protection
   because nonces are independently reconstructed via cryptographically verified audit chain reads.
5. Triple-scenario: deleting .email_wipe_nonces.json AND tampering with / truncating the audit log
   is caught by verify_chain(), causing the listener to fail closed and refuse execution.
6. Corrupted audit chain fails closed on nonce reconstruction.
7. Real AuditLogger.verify_chain() classmethod invocation succeeds on valid chains.
8. Non-ChainIntegrityError exceptions (e.g., malformed JSON or permissions) are not swallowed
   and fail closed loudly.
9. Missing-keys tamper check fires correctly when audit_dir is resolved via default_settings.audit_dir.
10. Mailbox credentials (imap_user, imap_password) are stored encrypted via Windows DPAPI
    with owner-only DACL and loaded correctly at startup.
11. EmailWipeListener.__init__ precedence rules: explicit args override creds_path, and omitting both
    falls back transparently to WIPE_CREDS_DEFAULT.
12. Timestamp expiry outside the 5-minute freshness window is rejected.
13. IMAP connection/auth failures fail safely to a no-op without false triggers.
"""
import imaplib
import json
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from core.email_wipe_listener import (
    EmailWipeListener,
    save_email_wipe_credentials,
    load_email_wipe_credentials,
    WIPE_CREDS_DEFAULT,
)
from core.sentinel_extras import EmergencyWipeController
from sentinel.audit.chain import AuditLogger, ChainIntegrityError
from sentinel.config.settings import default_settings


@pytest.fixture
def mock_trash():
    """Mocks the send2trash module and function."""
    m_mod = MagicMock()
    m_fn = MagicMock()
    m_mod.send2trash = m_fn
    with patch.dict(sys.modules, {"send2trash": m_mod}):
        yield m_fn


@pytest.fixture
def mock_wipe_controller(tmp_path, mock_trash):
    target_file = tmp_path / "sensitive_data.txt"
    target_file.write_text("classified data", encoding="utf-8")
    auth_dir = tmp_path / "auth"
    from sentinel.anomaly.detector import AnomalyDetector
    AnomalyDetector(auth_dir=auth_dir).seed_initial_enrollment()
    controller = EmergencyWipeController(wipe_paths=[str(target_file)])
    return controller, target_file, mock_trash



def test_valid_signed_email_triggers_shared_wipe_controller(tmp_path, mock_wipe_controller):
    """
    Proves that a validly signed email wipe payload verifies successfully
    and triggers the shared EmergencyWipeController to recycle target paths.
    """
    controller, target_file, mock_trash = mock_wipe_controller
    key = b"A" * 32
    nonce_file = tmp_path / "nonces.json"
    audit_dir = tmp_path / "audit"

    listener = EmailWipeListener(
        hmac_key=key,
        wipe_controller=controller,
        nonce_store_path=nonce_file,
        audit_dir=audit_dir,
    )

    payload = {
        "action": "emergency_wipe",
        "timestamp": time.time(),
        "nonce": "test-nonce-12345",
        "reason": "owner_emergency_signal",
    }
    signature = EmailWipeListener.compute_signature(key, payload)
    command_json = json.dumps({"payload": payload, "signature": signature})

    success, msg = listener.process_email_payload(command_json)

    assert success is True
    assert "Wipe executed successfully" in msg
    mock_trash.assert_called_once_with(str(target_file))


def test_unsigned_or_forged_email_is_rejected_without_triggering_wipe(tmp_path, mock_wipe_controller):
    """
    Proves that unsigned messages or messages signed with an incorrect key
    are rejected as forgeries and do NOT trigger EmergencyWipeController.
    """
    controller, target_file, mock_trash = mock_wipe_controller
    valid_key = b"A" * 32
    attacker_key = b"B" * 32
    nonce_file = tmp_path / "nonces.json"
    audit_dir = tmp_path / "audit"

    listener = EmailWipeListener(
        hmac_key=valid_key,
        wipe_controller=controller,
        nonce_store_path=nonce_file,
        audit_dir=audit_dir,
    )

    payload = {
        "action": "emergency_wipe",
        "timestamp": time.time(),
        "nonce": "fake-nonce-000",
        "reason": "attacker_attempt",
    }
    forged_sig = EmailWipeListener.compute_signature(attacker_key, payload)
    forged_json = json.dumps({"payload": payload, "signature": forged_sig})

    success, msg = listener.process_email_payload(forged_json)

    assert success is False
    assert "Invalid cryptographic signature" in msg
    mock_trash.assert_not_called()


def test_replayed_valid_command_is_rejected(tmp_path, mock_wipe_controller):
    """
    Proves that resending an identical valid command (same nonce)
    is caught by the replay protection store and rejected on subsequent attempts.
    """
    controller, target_file, mock_trash = mock_wipe_controller
    key = b"A" * 32
    nonce_file = tmp_path / "nonces.json"
    audit_dir = tmp_path / "audit"

    listener = EmailWipeListener(
        hmac_key=key,
        wipe_controller=controller,
        nonce_store_path=nonce_file,
        audit_dir=audit_dir,
    )

    payload = {
        "action": "emergency_wipe",
        "timestamp": time.time(),
        "nonce": "unique-replay-nonce-999",
        "reason": "first_run",
    }
    sig = EmailWipeListener.compute_signature(key, payload)
    command_json = json.dumps({"payload": payload, "signature": sig})

    # 1. First execution succeeds
    ok1, msg1 = listener.process_email_payload(command_json)
    assert ok1 is True
    assert mock_trash.call_count == 1

    # 2. Attacker replays exact same message
    ok2, msg2 = listener.process_email_payload(command_json)
    assert ok2 is False
    assert "Replay attack detected" in msg2
    assert mock_trash.call_count == 1  # Not called a second time


def test_nonce_file_deletion_replay_prevented_via_audit_anchor(tmp_path, mock_wipe_controller):
    """
    Proves that an attacker deleting .email_wipe_nonces.json cannot replay a consumed
    command within the freshness window, because nonces are cross-checked against the audit chain.
    """
    controller, target_file, mock_trash = mock_wipe_controller
    key = b"A" * 32
    nonce_file = tmp_path / "nonces.json"
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)

    listener = EmailWipeListener(
        hmac_key=key,
        wipe_controller=controller,
        nonce_store_path=nonce_file,
        audit_dir=audit_dir,
    )

    payload = {
        "action": "emergency_wipe",
        "timestamp": time.time(),
        "nonce": "audit-anchored-nonce-777",
        "reason": "initial_trigger",
    }
    sig = EmailWipeListener.compute_signature(key, payload)
    command_json = json.dumps({"payload": payload, "signature": sig})

    # 1. Execute initial command
    ok1, msg1 = listener.process_email_payload(command_json)
    assert ok1 is True
    assert nonce_file.exists()

    # 2. Attacker deletes the local nonce store file
    nonce_file.unlink()
    assert not nonce_file.exists()

    # 3. Create fresh listener instance representing service restart or re-poll
    fresh_listener = EmailWipeListener(
        hmac_key=key,
        wipe_controller=controller,
        nonce_store_path=nonce_file,
        audit_dir=audit_dir,
    )

    # 4. Attacker attempts to replay the same command
    ok2, msg2 = fresh_listener.process_email_payload(command_json)
    assert ok2 is False
    assert "Replay attack detected" in msg2
    assert mock_trash.call_count == 1  # Wipe was not executed again


def test_triple_scenario_nonce_deletion_and_audit_line_tamper_detected_via_chain_verification(tmp_path, mock_wipe_controller):
    """
    Proves that if an attacker deletes .email_wipe_nonces.json AND truncates / modifies
    the audit log file to erase the execution entry, the cryptographic chain verification
    fails closed and refuses to execute the replayed command.
    """
    controller, target_file, mock_trash = mock_wipe_controller
    key = b"A" * 32
    nonce_file = tmp_path / "nonces.json"
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)

    listener = EmailWipeListener(
        hmac_key=key,
        wipe_controller=controller,
        nonce_store_path=nonce_file,
        audit_dir=audit_dir,
    )

    payload = {
        "action": "emergency_wipe",
        "timestamp": time.time(),
        "nonce": "triple-attack-nonce-888",
        "reason": "initial_trigger",
    }
    sig = EmailWipeListener.compute_signature(key, payload)
    command_json = json.dumps({"payload": payload, "signature": sig})

    # 1. First command execution
    ok1, _ = listener.process_email_payload(command_json)
    assert ok1 is True

    # 2. Attacker deletes nonce file
    nonce_file.unlink()

    # 3. Attacker modifies audit log (corrupts HMAC signature or truncates hash link)
    audit_file = audit_dir / "audit.jsonl"
    assert audit_file.exists()
    content = audit_file.read_text(encoding="utf-8")
    assert "email_listener" in content
    tampered_content = content.replace("email_listener", "intruder")
    audit_file.write_text(tampered_content, encoding="utf-8")

    local_log = audit_dir / "audit_log.jsonl"
    if local_log.exists():
        local_log.unlink()

    # 4. Attacker attempts replay
    fresh_listener = EmailWipeListener(
        hmac_key=key,
        wipe_controller=controller,
        nonce_store_path=nonce_file,
        audit_dir=audit_dir,
    )
    ok2, msg2 = fresh_listener.process_email_payload(command_json)

    assert ok2 is False
    assert "Audit chain integrity failure" in msg2
    assert mock_trash.call_count == 1  # No secondary wipe permitted under tampered state


def test_real_audit_logger_verify_chain_call_signature_succeeds_on_valid_chain(tmp_path):
    """
    Directly verifies that the real AuditLogger.verify_chain() classmethod invocation
    with (audit_file, keys) succeeds without TypeError or missing arguments on a real audit chain,
    and accurately reconstructs nonces into the EmailWipeListener.
    """
    audit_dir = tmp_path / "real_audit"
    prod_logger = AuditLogger(audit_dir=audit_dir)
    prod_logger.log_event("email_wipe_command_executed", actor="email_listener", details={"nonce": "real-verified-nonce-101"})
    prod_logger.log_event("unrelated_security_event", actor="user", details={"data": "test"})

    listener = EmailWipeListener(audit_dir=audit_dir, nonce_store_path=tmp_path / "nonces.json")
    nonces = listener._load_nonces()

    assert "real-verified-nonce-101" in nonces


def test_non_chain_integrity_error_during_nonce_loading_fails_closed(tmp_path):
    """
    Verifies that unexpected errors (e.g. malformed JSON line or unreadable file permissions)
    are not silently swallowed into a no-op, but propagate as a ChainIntegrityError to fail closed.
    """
    audit_dir = tmp_path / "corrupt_audit"
    prod_logger = AuditLogger(audit_dir=audit_dir)
    prod_logger.log_event("email_wipe_command_executed", actor="email_listener", details={"nonce": "nonce-1"})

    audit_file = audit_dir / "audit.jsonl"
    with open(audit_file, "a", encoding="utf-8") as f:
        f.write("{malformed-non-json-line\n")

    listener = EmailWipeListener(audit_dir=audit_dir)

    with pytest.raises(ChainIntegrityError) as exc_info:
        listener._load_nonces()

    assert "Audit log read/decode failure" in str(exc_info.value) or "Audit log chain integrity failure" in str(exc_info.value)


def test_missing_keys_tamper_check_fires_under_default_settings_audit_dir(tmp_path, monkeypatch):
    """
    Verifies that when audit_dir is NOT explicitly passed to EmailWipeListener
    and resolves via default_settings.audit_dir, an existing audit log with missing HMAC keys
    is detected as a tampering condition and raises ChainIntegrityError.
    """
    simulated_base = tmp_path / "simulated_base"
    simulated_base.mkdir(parents=True, exist_ok=True)
    simulated_default_audit = simulated_base / "audit"
    simulated_default_audit.mkdir(parents=True, exist_ok=True)
    audit_file = simulated_default_audit / "audit.jsonl"
    audit_file.write_text('{"index": 0, "event_type": "email_wipe_command_executed", "details": {"nonce": "n1"}}\n', encoding="utf-8")

    # Ensure no key files exist in the directory
    for k in simulated_default_audit.glob("*.key"):
        k.unlink()

    monkeypatch.setattr(default_settings, "base_dir", simulated_base)

    listener = EmailWipeListener()  # audit_dir=None -> resolves via default_settings.audit_dir

    with pytest.raises(ChainIntegrityError) as exc_info:
        listener._load_nonces()

    assert "Missing HMAC keys" in str(exc_info.value) or "Missing audit HMAC keys" in str(exc_info.value)


def test_nonce_reconstruction_fails_closed_on_corrupted_audit_chain(tmp_path, mock_wipe_controller):
    """
    Verifies that _load_nonces() verifies the audit chain cryptographic integrity
    and raises ChainIntegrityError when corrupted records are encountered.
    """
    controller, target_file, mock_trash = mock_wipe_controller
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    audit_file = audit_dir / "audit.jsonl"
    audit_file.write_text('{"index": 0, "hmac": "bad_sig"}\n', encoding="utf-8")

    listener = EmailWipeListener(
        hmac_key=b"A" * 32,
        wipe_controller=controller,
        audit_dir=audit_dir,
    )

    with pytest.raises(ChainIntegrityError):
        listener._load_nonces()


def test_imap_credentials_dpapi_storage_and_loading(tmp_path):
    """
    Verifies that save_email_wipe_credentials stores IMAP credentials encrypted
    at rest via Windows DPAPI and owner-only DACL, and load_email_wipe_credentials
    retrieves them intact.
    """
    creds_file = tmp_path / "test_email_creds.dpapi"
    user = "emergency-inbox@sentinel.org"
    password = "super-secret-app-password-42"

    with patch("core.email_wipe_listener.apply_owner_only_dacl") as mock_dacl:
        saved_path = save_email_wipe_credentials(user, password, creds_path=creds_file)
        assert saved_path == creds_file
        assert creds_file.exists()
        mock_dacl.assert_called_once_with(creds_file)

    # Confirm ciphertext on disk does not contain plaintext password
    raw_disk_bytes = creds_file.read_bytes()
    assert password.encode("utf-8") not in raw_disk_bytes
    assert user.encode("utf-8") not in raw_disk_bytes

    # Confirm loading recovers plaintext
    loaded_user, loaded_pass = load_email_wipe_credentials(creds_path=creds_file)
    assert loaded_user == user
    assert loaded_pass == password

    # Confirm listener initialized with creds_path loads credentials automatically
    listener = EmailWipeListener(creds_path=creds_file, audit_dir=tmp_path / "audit")
    assert listener.imap_user == user
    assert listener.imap_password == password


def test_email_wipe_listener_init_precedence_explicit_overrides_creds_path(tmp_path):
    """
    Verifies that explicitly passed imap_user/imap_password arguments override
    any credentials present in creds_path.
    """
    creds_file = tmp_path / "file_creds.dpapi"
    save_email_wipe_credentials("file_user@test.local", "file_pass", creds_path=creds_file)

    listener = EmailWipeListener(
        imap_user="explicit_user@test.local",
        imap_password="explicit_pass",
        creds_path=creds_file,
        audit_dir=tmp_path / "audit",
    )

    assert listener.imap_user == "explicit_user@test.local"
    assert listener.imap_password == "explicit_pass"


def test_email_wipe_listener_init_precedence_default_fallback(tmp_path, monkeypatch):
    """
    Verifies that when neither explicit args nor creds_path are supplied,
    EmailWipeListener transparently defaults to WIPE_CREDS_DEFAULT and loads credentials.
    """
    dummy_default = tmp_path / "default_creds.dpapi"
    save_email_wipe_credentials("default_user@test.local", "default_pass", creds_path=dummy_default)
    monkeypatch.setattr("core.email_wipe_listener.WIPE_CREDS_DEFAULT", dummy_default)

    listener = EmailWipeListener(audit_dir=tmp_path / "audit")

    assert listener.creds_path == dummy_default
    assert listener.imap_user == "default_user@test.local"
    assert listener.imap_password == "default_pass"


def test_expired_timestamp_outside_freshness_window_is_rejected(tmp_path, mock_wipe_controller):
    """
    Proves that a command timestamp older than the freshness window (300s)
    is rejected even if the signature is mathematically valid.
    """
    controller, target_file, mock_trash = mock_wipe_controller
    key = b"A" * 32
    nonce_file = tmp_path / "nonces.json"
    audit_dir = tmp_path / "audit"

    listener = EmailWipeListener(
        hmac_key=key,
        wipe_controller=controller,
        nonce_store_path=nonce_file,
        audit_dir=audit_dir,
        freshness_window_secs=300.0,
    )

    payload = {
        "action": "emergency_wipe",
        "timestamp": time.time() - 350.0,  # 350s old > 300s limit
        "nonce": "old-expired-nonce",
        "reason": "delayed_signal",
    }
    sig = EmailWipeListener.compute_signature(key, payload)
    command_json = json.dumps({"payload": payload, "signature": sig})

    success, msg = listener.process_email_payload(command_json)

    assert success is False
    assert "expired" in msg.lower()
    mock_trash.assert_not_called()


def test_imap_connectivity_failure_fails_safe_to_noop(tmp_path, mock_wipe_controller):
    """
    Proves that socket errors, authentication errors, or unreachable mailboxes
    fail safely to a no-op without raising unhandled exceptions or triggering false wipes.
    """
    controller, target_file, mock_trash = mock_wipe_controller
    key = b"A" * 32
    nonce_file = tmp_path / "nonces.json"
    audit_dir = tmp_path / "audit"

    listener = EmailWipeListener(
        imap_server="imap.invalid-domain-test.local",
        imap_user="test@example.com",
        imap_password="secretpassword",
        hmac_key=key,
        wipe_controller=controller,
        nonce_store_path=nonce_file,
        audit_dir=audit_dir,
    )

    with patch("imaplib.IMAP4_SSL", side_effect=OSError("Connection refused")):
        results = listener.poll_inbox()

    assert results == []  # Safe empty result
    mock_trash.assert_not_called()
    assert target_file.exists()  # No false wipe


def test_email_wipe_listener_loop_calls_poll_inbox_and_respects_stop_event():
    """
    Proves that _email_wipe_listener_loop in jarvis_service.py repeatedly executes
    listener.poll_inbox() on its polling interval, handles per-cycle exceptions cleanly,
    and terminates cleanly when stop_event is set.
    """
    from jarvis_service import _email_wipe_listener_loop
    import threading

    mock_listener = MagicMock()
    stop_evt = threading.Event()

    def side_effect():
        if mock_listener.poll_inbox.call_count == 1:
            raise RuntimeError("Transient socket glitch")
        if mock_listener.poll_inbox.call_count >= 2:
            stop_evt.set()
        return []

    mock_listener.poll_inbox.side_effect = side_effect

    _email_wipe_listener_loop(listener=mock_listener, poll_interval_secs=0.01, stop_event=stop_evt)

    assert mock_listener.poll_inbox.call_count >= 2
    assert stop_evt.is_set()


def test_send_wipe_command_tooling_generates_valid_signed_payload_and_dispatches(tmp_path, mock_wipe_controller):
    """
    Proves that send_wipe_command.py produces a cryptographically signed payload
    that EmailWipeListener accepts as valid and triggers EmergencyWipeController,
    and send_email_command dispatches via SMTP.
    """
    from send_wipe_command import (
        generate_signed_wipe_payload,
        load_hmac_key,
        send_email_command,
    )

    controller, target_file, mock_trash = mock_wipe_controller
    raw_key = b"K" * 32
    key_hex = raw_key.hex()

    # 1. Test load_hmac_key with key_hex
    loaded_key = load_hmac_key(key_hex=key_hex)
    assert loaded_key == raw_key

    # 2. Test payload generation
    command_dict = generate_signed_wipe_payload(key=loaded_key, reason="operator_drill")
    assert "payload" in command_dict
    assert "signature" in command_dict
    assert command_dict["payload"]["action"] == "emergency_wipe"
    assert command_dict["payload"]["reason"] == "operator_drill"

    # 3. Test verification by EmailWipeListener
    audit_dir = tmp_path / "audit"
    listener = EmailWipeListener(
        hmac_key=raw_key,
        wipe_controller=controller,
        audit_dir=audit_dir,
    )

    success, msg = listener.process_email_payload(command_dict)
    assert success is True
    assert "Wipe executed successfully" in msg
    mock_trash.assert_called_once_with(str(target_file))

    # 4. Test send_email_command dispatching via SMTP mock
    with patch("smtplib.SMTP_SSL") as mock_smtp_cls:
        mock_smtp = MagicMock()
        mock_smtp_cls.return_value.__enter__.return_value = mock_smtp

        ok, status = send_email_command(
            command_dict=command_dict,
            to_addr="emergency-box@sentinel.org",
            smtp_user="operator@sentinel.org",
            smtp_password="app-password-123",
        )

        assert ok is True
        assert "successfully dispatched" in status
        mock_smtp.login.assert_called_once_with("operator@sentinel.org", "app-password-123")
        mock_smtp.send_message.assert_called_once()


def test_export_key_tooling_recovers_identical_verifiable_key_without_leakage(tmp_path, mock_wipe_controller):
    """
    Proves that export_hmac_key extracts the exact DPAPI-protected key that EmailWipeListener
    uses internally, and generates verifiable signed payloads without leaking to temp files or disk.
    """
    from send_wipe_command import export_hmac_key, generate_signed_wipe_payload

    controller, target_file, mock_trash = mock_wipe_controller
    key_file = tmp_path / "auth.key"
    audit_dir = tmp_path / "audit"

    # 1. Export key via tooling
    exported_hex = export_hmac_key(key_path=key_file)
    assert len(exported_hex) == 64
    exported_bytes = bytes.fromhex(exported_hex)

    # 2. Verify listener initialized with same key file verifies command signed with exported key
    listener = EmailWipeListener(
        key_path=key_file,
        wipe_controller=controller,
        audit_dir=audit_dir,
    )

    command_dict = generate_signed_wipe_payload(key=exported_bytes, reason="exported_key_test")
    success, msg = listener.process_email_payload(command_dict)

    assert success is True
    assert "Wipe executed successfully" in msg
    mock_trash.assert_called_once_with(str(target_file))

    # 3. Confirm no extraneous temp files leaked into directory
    remaining_files = list(tmp_path.glob("*.tmp*"))
    assert len(remaining_files) == 0


def test_email_wipe_anomaly_step_up_refusal_and_proactive_alert(tmp_path, mock_wipe_controller):
    """
    Verifies that a validly signed email wipe received under anomalous context
    (unusual hour / unknown network) is refused without step-up/recovery PIN,
    and dispatches a CRITICAL alert through ProactiveBridge.
    """
    controller, target_file, mock_trash = mock_wipe_controller
    bridge_mock = MagicMock()
    controller.set_bridge(bridge_mock)

    key = b"A" * 32
    listener = EmailWipeListener(
        hmac_key=key,
        wipe_controller=controller,
        nonce_store_path=tmp_path / "nonces.json",
        audit_dir=tmp_path / "audit",
    )

    payload = {
        "action": "emergency_wipe",
        "timestamp": time.time(),
        "nonce": "anomaly-nonce-111",
        "reason": "untrusted_network_test",
    }
    signature = EmailWipeListener.compute_signature(key, payload)
    command_dict = {"payload": payload, "signature": signature}

    anomalous_context = {
        "time": "2026-09-01T03:00:00",
        "network_id": "wifi:UntrustedCoffeeShop",
    }

    success, msg = listener.process_email_payload(command_dict, context=anomalous_context)
    assert success is False
    assert "Wipe refused: Multi-factor step-up verification required" in msg
    assert mock_trash.call_count == 0

    # Verify ProactiveBridge CRITICAL dispatch
    assert bridge_mock.dispatch.call_count == 1
    event = bridge_mock.dispatch.call_args[0][0]
    assert event.priority.name == "CRITICAL"
    assert "Blocked Email Wipe Attempt" in event.title


def test_email_wipe_anomaly_step_up_success_with_recovery_pin_in_payload(tmp_path, mock_wipe_controller):
    """
    Verifies that an email wipe under anomalous context succeeds when the
    signed payload includes the valid recovery PIN.
    """
    controller, target_file, mock_trash = mock_wipe_controller
    key = b"A" * 32
    listener = EmailWipeListener(
        hmac_key=key,
        wipe_controller=controller,
        nonce_store_path=tmp_path / "nonces.json",
        audit_dir=tmp_path / "audit",
    )


    # Configure recovery PIN in AccessControl
    from core.access_control import AccessControl
    ac = AccessControl()
    ac.set_pin("1234")
    ac.set_recovery_pin("88888")

    payload = {
        "action": "emergency_wipe",
        "timestamp": time.time(),
        "nonce": "anomaly-recovery-nonce-222",
        "reason": "traveling_disaster_recovery",
        "recovery_pin": "88888",
    }
    signature = EmailWipeListener.compute_signature(key, payload)
    command_dict = {"payload": payload, "signature": signature}

    anomalous_context = {
        "time": "2026-09-01T03:00:00",
        "network_id": "wifi:UntrustedCoffeeShop",
    }

    with patch("core.access_control.AccessControl", return_value=ac):
        success, msg = listener.process_email_payload(command_dict, context=anomalous_context)

    assert success is True
    assert "Wipe executed successfully" in msg
    mock_trash.assert_called_once_with(str(target_file))



