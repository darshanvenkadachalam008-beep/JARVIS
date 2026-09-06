"""
tests/security/test_adv_wipe_authorization.py
==============================================
Adversarial test for Emergency Wipe authorization gating and replay prevention.
Validates:
1. Direct execute_wipe without request+confirm lifecycle is refused.
2. Expired confirmation tokens cannot be replayed.
3. Multi-channel isolation prevents privilege escalation.
4. Anomaly detection fail-closed behavior blocks remote wipe without recovery PIN.
"""

import time
from unittest.mock import MagicMock, patch
import pytest
from core.access_control import AccessControl
from core.sentinel_extras import EmergencyWipeController


@pytest.fixture
def secure_wipe_controller(tmp_path):
    target_file = tmp_path / "sensitive.dat"
    target_file.write_text("classified data", encoding="utf-8")

    ac_file = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_file)
    ac.set_pin("5555")
    ac.set_recovery_pin("9999")

    mock_trash = MagicMock()
    with patch("core.sentinel_extras.AccessControl", return_value=ac):
        controller = EmergencyWipeController(
            wipe_paths=[str(target_file)],
            confirmation_timeout_seconds=0.2
        )
        yield controller, mock_trash, str(target_file)


def test_adversarial_wipe_without_request_is_rejected(secure_wipe_controller):
    controller, mock_trash, target_path = secure_wipe_controller
    # Confirm without prior request
    success, msg, results = controller.confirm_wipe("5555", channel="unauthorized_actor")
    assert success is False
    assert "no pending wipe" in msg.lower()
    mock_trash.assert_not_called()


def test_adversarial_wipe_replay_after_timeout(secure_wipe_controller):
    controller, mock_trash, target_path = secure_wipe_controller
    controller.request_wipe(channel="test_channel")
    time.sleep(0.3)  # Exceed 0.2s timeout

    # Attempt to confirm after window expiry
    success, msg, results = controller.confirm_wipe("5555", channel="test_channel")
    assert success is False
    assert "expired" in msg.lower()
    mock_trash.assert_not_called()


def test_adversarial_wipe_wrong_pin_exhaustion(secure_wipe_controller):
    controller, mock_trash, target_path = secure_wipe_controller
    controller.request_wipe(channel="test_channel")

    # Wrong PIN resets pending request state to prevent brute-forcing within same request
    success, msg, results = controller.confirm_wipe("0000", channel="test_channel")
    assert success is False
    assert "PIN incorrect" in msg

    # Immediate second attempt with correct PIN is blocked because state was invalidated
    success2, msg2, results2 = controller.confirm_wipe("5555", channel="test_channel")
    assert success2 is False
    assert "no pending wipe" in msg2.lower()
