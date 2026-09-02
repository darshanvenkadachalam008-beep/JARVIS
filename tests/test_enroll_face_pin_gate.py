"""Tests for PIN-gated face re-enrollment and reset in enroll_face.py."""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from core.face_verify import FaceVerifier
from core.access_control import AccessControl
import enroll_face


def test_pin_configured_correct_pin_allows_reset_and_enroll(tmp_path):
    """PIN configured, correct PIN entered -> fv.reset() is called and enroll proceeds."""
    # Setup AccessControl with PIN
    ac_path = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_path)
    ac.set_pin("123456")

    # Setup FaceVerifier as already enrolled
    fv = MagicMock(spec=FaceVerifier)
    fv.is_enrolled.return_value = True
    fv.model_path = Path("fake_model.yml")
    fv.threshold = 75.0

    fake_images = [b"img" for _ in range(6)]

    with patch("enroll_face.AccessControl", return_value=ac), \
         patch("enroll_face.FaceVerifier", return_value=fv), \
         patch("builtins.input", side_effect=["y", "", "", "", "", "", ""]), \
         patch("getpass.getpass", return_value="123456") as mock_getpass, \
         patch("enroll_face.capture_photo", side_effect=fake_images), \
         patch("sys.argv", ["enroll_face.py"]):

        enroll_face.main()

    # Confirm getpass was used, reset was called, and enroll was called
    mock_getpass.assert_called_once()
    fv.reset.assert_called_once()
    fv.enroll.assert_called_once()


def test_pin_configured_incorrect_pin_rejects_and_preserves_profile(tmp_path):
    """PIN configured, incorrect PIN entered -> PermissionError caught, exits without modifying profile."""
    ac_path = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_path)
    ac.set_pin("123456")

    mem_dir = tmp_path / "memory"
    fv = FaceVerifier(base_path=mem_dir, access_control=ac)
    fv.model_path.write_text("existing_model", encoding="utf-8")
    fv.meta_path.write_text("existing_meta", encoding="utf-8")

    with patch("enroll_face.AccessControl", return_value=ac), \
         patch("enroll_face.FaceVerifier", return_value=fv), \
         patch("builtins.input", return_value="y"), \
         patch("getpass.getpass", return_value="wrong_pin") as mock_getpass, \
         patch("sys.argv", ["enroll_face.py"]):

        with pytest.raises(SystemExit):
            enroll_face.main()

    mock_getpass.assert_called_once()
    assert fv.model_path.exists()
    assert fv.meta_path.exists()


def test_pin_configured_reset_flag_with_incorrect_pin_rejects(tmp_path):
    """PIN configured, --reset flag used with incorrect PIN -> fv.reset() raises PermissionError, exits immediately."""
    ac_path = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_path)
    ac.set_pin("123456")

    mem_dir = tmp_path / "memory"
    fv = FaceVerifier(base_path=mem_dir, access_control=ac)
    fv.model_path.write_text("existing_model", encoding="utf-8")
    fv.meta_path.write_text("existing_meta", encoding="utf-8")

    with patch("enroll_face.AccessControl", return_value=ac), \
         patch("enroll_face.FaceVerifier", return_value=fv), \
         patch("getpass.getpass", return_value="wrong_pin") as mock_getpass, \
         patch("sys.argv", ["enroll_face.py", "--reset"]):

        with pytest.raises(SystemExit):
            enroll_face.main()

    mock_getpass.assert_called_once()
    assert fv.model_path.exists()
    assert fv.meta_path.exists()


def test_pin_not_configured_allows_ungated_reset_with_warning(tmp_path, capsys):
    """No PIN configured (is_configured() is False) -> reset proceeds without PIN prompt, warning printed."""
    ac_path = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_path)  # No PIN set

    fv = MagicMock(spec=FaceVerifier)
    fv.is_enrolled.return_value = True

    with patch("enroll_face.AccessControl", return_value=ac), \
         patch("enroll_face.FaceVerifier", return_value=fv), \
         patch("getpass.getpass") as mock_getpass, \
         patch("sys.argv", ["enroll_face.py", "--reset"]):

        enroll_face.main()

    # getpass should NOT be called since no PIN is configured
    mock_getpass.assert_not_called()
    fv.reset.assert_called_once()

    captured = capsys.readouterr()
    assert "WARNING: No security PIN is configured" in captured.out


def test_getpass_is_used_not_input_for_pin_prompt():
    """Confirms getpass.getpass is used in verify_identity_for_reset rather than input()."""
    import inspect
    source = inspect.getsource(enroll_face.verify_identity_for_reset)
    assert "getpass.getpass" in source
    assert "input(" not in source


def test_verify_identity_for_reset_contains_only_ascii_strings():
    """Verifies that all string literals and source lines in verify_identity_for_reset are 100% ASCII."""
    import inspect
    source = inspect.getsource(enroll_face.verify_identity_for_reset)
    for line_idx, line in enumerate(source.splitlines(), start=1):
        for char in line:
            assert ord(char) < 128, f"Non-ASCII character {char!r} (ord {ord(char)}) found at line {line_idx}: {line}"


def test_verify_identity_for_reset_handles_strict_ascii_stdout(tmp_path):
    """Verifies that execution succeeds under strict ASCII / CP1252 stdout encoding with no UnicodeEncodeError."""
    import io
    ac_path = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_path)
    ac.set_pin("123456")

    class StrictAsciiStream(io.StringIO):
        def write(self, s):
            s.encode("ascii")  # Raises UnicodeEncodeError if non-ASCII character is passed
            return super().write(s)

    stream = StrictAsciiStream()
    with patch("sys.stdout", stream), patch("getpass.getpass", return_value="123456"):
        res = enroll_face.verify_identity_for_reset(ac)
        assert res is True
        assert "OK: PIN verified" in stream.getvalue()

    stream_fail = StrictAsciiStream()
    with patch("sys.stdout", stream_fail), patch("getpass.getpass", return_value="wrong"):
        res = enroll_face.verify_identity_for_reset(ac)
        assert res is False
        assert "FAILED: Incorrect PIN" in stream_fail.getvalue()


def test_face_verifier_direct_enroll_refused_without_pin_when_configured(tmp_path):
    """
    Directly invokes FaceVerifier.enroll() without going through CLI wrapper.
    Confirms write is refused with PermissionError and no profile files are written when PIN is missing.
    """
    ac_path = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_path)
    ac.set_pin("123456")

    mem_dir = tmp_path / "memory"
    fv = FaceVerifier(base_path=mem_dir, access_control=ac)
    fake_images = [b"img" for _ in range(6)]

    with pytest.raises(PermissionError, match="Face profile face_enroll rejected: Security PIN is required"):
        fv.enroll(fake_images)

    assert not fv.model_path.exists()
    assert not fv.meta_path.exists()

    # Confirm audit trail recorded unauthorized attempt
    events = [entry["event_type"] for entry in fv._audit.read_all()]
    assert "face_enroll_failed_no_pin" in events


def test_face_verifier_direct_enroll_refused_with_wrong_pin(tmp_path):
    """
    Directly invokes FaceVerifier.enroll() with an incorrect PIN.
    Confirms write is refused with PermissionError, profile files are NOT written,
    and failed attempt is audited.
    """
    ac_path = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_path)
    ac.set_pin("123456")

    mem_dir = tmp_path / "memory"
    fv = FaceVerifier(base_path=mem_dir, access_control=ac)
    fake_images = [b"img" for _ in range(6)]

    with pytest.raises(PermissionError, match="Face profile face_enroll rejected: Invalid Security PIN or lockout active"):
        fv.enroll(fake_images, pin="wrong_pin")

    assert not fv.model_path.exists()
    assert not fv.meta_path.exists()

    events = [entry["event_type"] for entry in fv._audit.read_all()]
    assert "face_enroll_failed_invalid_pin" in events


def test_face_verifier_direct_enroll_succeeds_with_correct_pin(tmp_path):
    """
    Directly invokes FaceVerifier.enroll() with the correct PIN.
    Confirms face profile files are written and success is audited.
    """
    ac_path = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_path)
    ac.set_pin("123456")

    mem_dir = tmp_path / "memory"
    fv = FaceVerifier(base_path=mem_dir, access_control=ac)

    import numpy as np
    dummy_patch = np.zeros((200, 200), dtype=np.uint8)
    fake_images = [b"img" for _ in range(6)]

    mock_rec = MagicMock()
    with patch.object(fv, "_detect_and_crop", return_value=dummy_patch), \
         patch.object(fv, "_get_recognizer", return_value=mock_rec):
        ok = fv.enroll(fake_images, pin="123456")

    assert ok is True
    assert fv.meta_path.exists()
    mock_rec.write.assert_called_once_with(str(fv.model_path))

    events = [entry["event_type"] for entry in fv._audit.read_all()]
    assert "face_enroll" in events


def test_face_verifier_direct_reset_refused_without_pin_when_configured(tmp_path):
    """
    Directly invokes FaceVerifier.reset() with existing profile files but without PIN.
    Confirms profile files are NOT deleted and refusal is audited.
    """
    ac_path = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_path)
    ac.set_pin("123456")

    mem_dir = tmp_path / "memory"
    fv = FaceVerifier(base_path=mem_dir, access_control=ac)
    fv.model_path.write_text("model_data", encoding="utf-8")
    fv.meta_path.write_text("meta_data", encoding="utf-8")

    with pytest.raises(PermissionError, match="Face profile face_enroll_reset rejected: Security PIN is required"):
        fv.reset()

    # Existing files must be preserved!
    assert fv.model_path.exists()
    assert fv.meta_path.exists()

    events = [entry["event_type"] for entry in fv._audit.read_all()]
    assert "face_enroll_reset_failed_no_pin" in events


def test_face_verifier_direct_reset_succeeds_with_correct_pin(tmp_path):
    """
    Directly invokes FaceVerifier.reset() with the correct PIN.
    Confirms profile files are deleted and success is audited.
    """
    ac_path = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_path)
    ac.set_pin("123456")

    mem_dir = tmp_path / "memory"
    fv = FaceVerifier(base_path=mem_dir, access_control=ac)
    fv.model_path.write_text("model_data", encoding="utf-8")
    fv.meta_path.write_text("meta_data", encoding="utf-8")

    fv.reset(pin="123456")

    assert not fv.model_path.exists()
    assert not fv.meta_path.exists()

    events = [entry["event_type"] for entry in fv._audit.read_all()]
    assert "face_enroll_reset" in events


def test_face_verifier_ungated_when_access_control_unconfigured(tmp_path):
    """
    When AccessControl has no PIN configured (e.g. fresh install),
    FaceVerifier operations proceed ungated and log an informational warning audit entry.
    """
    ac_path = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_path)  # unconfigured

    mem_dir = tmp_path / "memory"
    fv = FaceVerifier(base_path=mem_dir, access_control=ac)

    import numpy as np
    dummy_patch = np.zeros((200, 200), dtype=np.uint8)
    fake_images = [b"img" for _ in range(6)]

    mock_rec = MagicMock()
    with patch.object(fv, "_detect_and_crop", return_value=dummy_patch), \
         patch.object(fv, "_get_recognizer", return_value=mock_rec):
        ok = fv.enroll(fake_images)

    assert ok is True
    events = [entry["event_type"] for entry in fv._audit.read_all()]
    assert "face_enroll_ungated_unconfigured" in events


def test_deletion_of_credentials_treated_as_tampering_fails_closed(tmp_path):
    """
    Proves that deleting credentials.json after initial configuration is detected as tampering,
    failing closed with PermissionError rather than falling open into fresh-install mode.
    """
    ac_path = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_path)
    ac.set_pin("123456")

    # Confirm marker was created
    marker_file = ac._engine.enrollment_manager.auth_dir / ".auth_initialized"
    assert marker_file.exists()

    # Simulate attacker deleting credentials.json
    creds_file = ac._engine.enrollment_manager.credentials_file
    assert creds_file.exists()
    creds_file.unlink()

    # System is now recognized as tampered
    assert ac.is_tampered() is True
    assert ac.is_configured() is False

    mem_dir = tmp_path / "memory"
    fv = FaceVerifier(base_path=mem_dir, access_control=ac)
    fake_images = [b"img" for _ in range(6)]

    # FaceVerifier.enroll() fails closed with PermissionError
    with pytest.raises(PermissionError, match="Security credentials tampered"):
        fv.enroll(fake_images)

    # FaceVerifier.reset() also fails closed with PermissionError
    with pytest.raises(PermissionError, match="Security credentials tampered"):
        fv.reset()

    # Audit chain records the tamper attempt
    events = [entry["event_type"] for entry in fv._audit.read_all()]
    assert "face_enroll_failed_tampered" in events
    assert "face_enroll_reset_failed_tampered" in events


def test_genuinely_fresh_install_allows_ungated_enrollment_without_tamper_flag(tmp_path):
    """
    Proves that on a genuinely fresh install (PIN never configured, no marker ever written),
    enrollment proceeds ungated without raising a false tamper alarm.
    """
    ac_path = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_path)  # never initialized

    assert ac.is_tampered() is False
    assert ac.is_configured() is False

    mem_dir = tmp_path / "memory"
    fv = FaceVerifier(base_path=mem_dir, access_control=ac)

    import numpy as np
    dummy_patch = np.zeros((200, 200), dtype=np.uint8)
    fake_images = [b"img" for _ in range(6)]

    mock_rec = MagicMock()
    with patch.object(fv, "_detect_and_crop", return_value=dummy_patch), \
         patch.object(fv, "_get_recognizer", return_value=mock_rec):
        ok = fv.enroll(fake_images)

    assert ok is True
    events = [entry["event_type"] for entry in fv._audit.read_all()]
    assert "face_enroll_ungated_unconfigured" in events
    assert "face_enroll_failed_tampered" not in events


def test_unified_lockout_counter_between_cli_and_direct_calls(tmp_path):
    """
    Proves that the lockout counter is strictly unified: wrong PINs entered via CLI
    and wrong PINs passed directly to FaceVerifier increment the exact same global failure counter
    with zero double-counting.
    """
    ac_path = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_path)
    ac.set_pin("123456")

    mem_dir = tmp_path / "memory"
    fv = FaceVerifier(base_path=mem_dir, access_control=ac)

    # Initial state: 0 failures
    state = ac._engine.lockout_manager.get_current_state(True)
    assert state.primary_failures == 0

    fake_images = [b"img" for _ in range(6)]

    # Attempt 1: via CLI path (getpass -> FaceVerifier)
    with patch("enroll_face.AccessControl", return_value=ac), \
         patch("enroll_face.FaceVerifier", return_value=fv), \
         patch("getpass.getpass", return_value="wrong_pin_1"), \
         patch("enroll_face.capture_photo", side_effect=fake_images), \
         patch("builtins.input", side_effect=["", "", "", "", "", ""]), \
         patch("sys.argv", ["enroll_face.py"]):

        with pytest.raises(SystemExit):
            enroll_face.main()

    # Confirms exactly 1 failure recorded (single-pass verification)
    state = ac._engine.lockout_manager.get_current_state(True)
    assert state.primary_failures == 1

    # Attempt 2: directly calling FaceVerifier.enroll()
    with pytest.raises(PermissionError):
        fv.enroll(fake_images, pin="wrong_pin_2")

    # Confirms failure count incremented on the exact same counter to 2
    state = ac._engine.lockout_manager.get_current_state(True)
    assert state.primary_failures == 2


def test_audit_log_content_records_denied_events_and_details(tmp_path):
    """
    Verifies actual audit chain contents: confirms that failed PIN attempts record
    events with result='denied', accurate reason tags, and submitted metadata.
    """
    ac_path = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_path)
    ac.set_pin("123456")

    mem_dir = tmp_path / "memory"
    fv = FaceVerifier(base_path=mem_dir, access_control=ac)
    fake_images = [b"img" for _ in range(6)]

    # Trigger failed enroll due to invalid PIN
    with pytest.raises(PermissionError):
        fv.enroll(fake_images, pin="wrong_pin")

    # Trigger failed reset due to missing PIN
    with pytest.raises(PermissionError):
        fv.reset()

    # Read back all entries from audit log
    records = fv._audit.read_all()
    event_map = {r["event_type"]: r for r in records}

    assert "face_enroll_failed_invalid_pin" in event_map
    enroll_fail = event_map["face_enroll_failed_invalid_pin"]
    assert enroll_fail["details"]["result"] == "denied"
    assert enroll_fail["details"]["reason"] == "invalid_pin_or_locked"

    assert "face_enroll_reset_failed_no_pin" in event_map
    reset_fail = event_map["face_enroll_reset_failed_no_pin"]
    assert reset_fail["details"]["result"] == "denied"
    assert reset_fail["details"]["reason"] == "missing_pin"


def test_combined_deletion_of_credentials_and_marker_fails_closed_via_audit_anchor(tmp_path):
    """
    Simulates the combined-deletion attack: an attacker with local console access
    deletes BOTH credentials.json and the .auth_initialized marker file simultaneously.
    Proves that the cryptographic audit chain serves as an independent anchor:
    is_tampered() detects the historical initialization record, and FaceVerifier
    fails closed with PermissionError rather than allowing ungated enrollment.
    """
    ac_path = tmp_path / "access_control.json"
    audit_path = tmp_path / "audit_log.jsonl"
    ac = AccessControl(path=ac_path, audit_log_path=audit_path)
    ac.set_pin("123456")

    # 1. Confirm both marker and audit anchor exist
    marker_file = ac._engine.enrollment_manager.auth_dir / ".auth_initialized"
    creds_file = ac._engine.enrollment_manager.credentials_file
    assert marker_file.exists()
    assert creds_file.exists()

    events = [entry.get("event_type") for entry in ac._audit.read_all()]
    assert "access_control_initialized" in events or "access_control_pin_set" in events

    # 2. Attack: delete BOTH credentials.json and .auth_initialized in one pass
    creds_file.unlink()
    marker_file.unlink()
    assert not creds_file.exists()
    assert not marker_file.exists()

    # 3. Cryptographic audit chain detects historical initialization -> fails closed
    assert ac.is_configured() is False
    assert ac.is_tampered() is True

    mem_dir = tmp_path / "memory"
    fv = FaceVerifier(base_path=mem_dir, access_control=ac)
    fake_images = [b"img" for _ in range(6)]

    with pytest.raises(PermissionError, match="Security credentials tampered"):
        fv.enroll(fake_images)

    with pytest.raises(PermissionError, match="Security credentials tampered"):
        fv.reset()

    # Audit chain records the tamper attempt
    events = [entry["event_type"] for entry in fv._audit.read_all()]
    assert "face_enroll_failed_tampered" in events


def test_triple_deletion_with_audit_log_line_tampering_detected_via_chain_verification(tmp_path):
    """
    Simulates the full triple-deletion attack:
    1. Attacker deletes credentials.json.
    2. Attacker deletes .auth_initialized marker file.
    3. Attacker attempts to erase history by selectively deleting the access_control_pin_set line from audit_log.jsonl.
    
    Proves that is_tampered() runs cryptographic chain verification before trusting the log:
    the broken hash link is detected, is_tampered() returns True, and FaceVerifier fails closed.
    """
    ac_path = tmp_path / "access_control.json"
    audit_path = tmp_path / "audit_log.jsonl"
    ac = AccessControl(path=ac_path, audit_log_path=audit_path)
    ac.set_pin("123456")

    # Add a subsequent audit entry so removing the init line creates a broken link in the middle
    ac._audit.append("subsequent_security_event", {"action": "test"})

    # 1. Attacker deletes credentials and marker
    creds_file = ac._engine.enrollment_manager.credentials_file
    marker_file = ac._engine.enrollment_manager.auth_dir / ".auth_initialized"
    creds_file.unlink()
    marker_file.unlink()

    # 2. Attacker modifies audit log: removes the initialization event line
    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    filtered_lines = [l for l in lines if "access_control" not in l]
    audit_path.write_text("\n".join(filtered_lines) + "\n", encoding="utf-8")

    # 3. is_tampered() executes chain verification -> detects broken prev_hash link
    ok, reason = ac._audit.verify()
    assert ok is False
    assert "Chain broken" in reason

    assert ac.is_tampered() is True

    # 4. FaceVerifier fails closed with PermissionError
    mem_dir = tmp_path / "memory"
    fv = FaceVerifier(base_path=mem_dir, access_control=ac)
    fake_images = [b"img" for _ in range(6)]

    with pytest.raises(PermissionError, match="Security credentials tampered"):
        fv.enroll(fake_images)

    with pytest.raises(PermissionError, match="Security credentials tampered"):
        fv.reset()


def test_production_sentinel_audit_logger_chain_tamper_detected_by_is_tampered(tmp_path):
    """
    Proves that tampering in the production Sentinel AuditLogger chain (e.g. broken HMAC link)
    is actively detected by AccessControl.is_tampered(), causing FaceVerifier to fail closed.
    """
    import json
    from sentinel.audit.chain import AuditLogger

    base_dir = tmp_path / "sentinel_env"
    ac_path = base_dir / "access_control.json"
    prod_audit_dir = base_dir / "audit"

    # 1. Initialize production AuditLogger and write valid entries
    prod_logger = AuditLogger(audit_dir=prod_audit_dir, verify_on_startup=False)
    prod_logger.log_event("access_control_initialized", actor="system", details={"type": "dual_pin"})
    prod_logger.log_event("subsequent_event", actor="system", details={"action": "check"})

    # 2. Set up AccessControl pointing to this environment
    ac = AccessControl(path=ac_path)
    ac.set_pin("123456")

    # Tamper with production audit log: modify an entry payload on disk to break HMAC
    log_file = prod_audit_dir / "audit.jsonl"
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    entry = json.loads(lines[0])
    entry["details"]["type"] = "tampered_value"
    lines[0] = json.dumps(entry)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # 3. is_tampered() detects production chain tampering
    assert ac.is_tampered() is True

    # 4. FaceVerifier fails closed
    mem_dir = tmp_path / "memory"
    fv = FaceVerifier(base_path=mem_dir, access_control=ac)
    fake_images = [b"img" for _ in range(6)]

    with pytest.raises(PermissionError, match="Security credentials tampered"):
        fv.enroll(fake_images)


def test_production_sentinel_audit_missing_directory_fresh_install_does_not_flag_tampering(tmp_path):
    """
    Proves that a missing production audit directory (fresh install where sentinel audit
    is not yet active) is skipped cleanly and does not cause is_tampered() to falsely flag tampering.
    """
    base_dir = tmp_path / "fresh_env"
    ac_path = base_dir / "access_control.json"
    ac = AccessControl(path=ac_path)  # no PIN, no audit dir

    assert ac.is_configured() is False
    assert ac.is_tampered() is False

    mem_dir = tmp_path / "memory"
    fv = FaceVerifier(base_path=mem_dir, access_control=ac)

    import numpy as np
    dummy_patch = np.zeros((200, 200), dtype=np.uint8)
    fake_images = [b"img" for _ in range(6)]

    mock_rec = MagicMock()
    with patch.object(fv, "_detect_and_crop", return_value=dummy_patch), \
         patch.object(fv, "_get_recognizer", return_value=mock_rec):
        ok = fv.enroll(fake_images)

    assert ok is True
