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
    """PIN configured, incorrect PIN entered -> fv.reset() is NEVER called, exits without modifying profile."""
    ac_path = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_path)
    ac.set_pin("123456")

    fv = MagicMock(spec=FaceVerifier)
    fv.is_enrolled.return_value = True

    with patch("enroll_face.AccessControl", return_value=ac), \
         patch("enroll_face.FaceVerifier", return_value=fv), \
         patch("builtins.input", return_value="y"), \
         patch("getpass.getpass", return_value="wrong_pin") as mock_getpass, \
         patch("sys.argv", ["enroll_face.py"]):

        with pytest.raises(SystemExit):
            enroll_face.main()

    mock_getpass.assert_called_once()
    fv.reset.assert_not_called()
    fv.enroll.assert_not_called()


def test_pin_configured_reset_flag_with_incorrect_pin_rejects(tmp_path):
    """PIN configured, --reset flag used with incorrect PIN -> fv.reset() is NEVER called, exits immediately."""
    ac_path = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_path)
    ac.set_pin("123456")

    fv = MagicMock(spec=FaceVerifier)
    fv.is_enrolled.return_value = True

    with patch("enroll_face.AccessControl", return_value=ac), \
         patch("enroll_face.FaceVerifier", return_value=fv), \
         patch("getpass.getpass", return_value="wrong_pin") as mock_getpass, \
         patch("sys.argv", ["enroll_face.py", "--reset"]):

        with pytest.raises(SystemExit):
            enroll_face.main()

    mock_getpass.assert_called_once()
    fv.reset.assert_not_called()


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
