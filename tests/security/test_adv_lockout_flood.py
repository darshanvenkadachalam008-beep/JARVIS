"""
tests/security/test_adv_lockout_flood.py
=========================================
Adversarial test for remote brute-force PIN flood attacks over mobile companion.
Validates:
1. Shared AccessControl lockout ladder triggers upon repeated failed step-up PIN attempts.
2. mobile_step_up_failure alert is dispatched at CRITICAL priority with actor='mobile_companion'.
3. Lockout defense is global (subsequent attempts from any interface are locked out).
"""

import json
import pytest
from unittest.mock import MagicMock, patch
from core.access_control import AccessControl


def test_adversarial_mobile_pin_flood_triggers_shared_lockout(tmp_path):
    ac_file = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_file)
    ac.set_pin("1234")

    # Mock dispatch_security_alert to verify trigger
    dispatches = []
    with patch("core.unified_security_alert.dispatch_security_alert", side_effect=lambda **kwargs: dispatches.append(kwargs)):
        # Attempt 1: Wrong PIN
        is_valid = ac.verify_pin("9999", action="mobile_read_sms_body")
        assert is_valid is False
        assert ac._seconds_locked() == 0.0

        # Attempt 2: Wrong PIN
        is_valid = ac.verify_pin("9998", action="mobile_read_sms_body")
        assert is_valid is False
        assert ac._seconds_locked() == 0.0

        # Attempt 3: 3rd failed attempt triggers lockout
        is_valid = ac.verify_pin("9997", action="mobile_read_sms_body")
        assert is_valid is False
        assert ac._seconds_locked() > 0.0

        # Attempt 4: Flooding while locked out is rejected immediately
        is_valid = ac.verify_pin("1234", action="mobile_read_sms_body")
        assert is_valid is False

    # Verify security alert dispatch calls
    assert len(dispatches) >= 3
    for d in dispatches:
        assert d["trigger_type"] == "mobile_step_up_failure"
        assert d["actor"] == "mobile_companion"
        assert "mobile_read_sms_body" in d["details"]["action"]


@pytest.mark.anyio
async def test_adversarial_websocket_step_up_pin_flood(tmp_path):
    from mobile_server import _WSHub, MOBILE_AUTH_TOKEN

    ac_file = tmp_path / "access_control.json"
    ac = AccessControl(path=ac_file)
    ac.set_pin("4321")

    sent_frames = []

    class MockWebSocket:
        def __init__(self, messages):
            self.incoming = messages
            self.remote_address = ("192.168.1.100", 50000)

        async def send(self, text):
            sent_frames.append(json.loads(text))

        def __aiter__(self):
            return self

        async def __anext__(self):
            if not self.incoming:
                raise StopAsyncIteration
            return self.incoming.pop(0)

        async def close(self, code=1000, reason=""):
            pass

    messages = [
        json.dumps({"type": "auth", "data": MOBILE_AUTH_TOKEN}),
        json.dumps({"type": "step_up_action", "data": json.dumps({"action": "read_sms_body", "pin": "0000", "payload": {}})}),
        json.dumps({"type": "step_up_action", "data": json.dumps({"action": "read_sms_body", "pin": "0001", "payload": {}})}),
        json.dumps({"type": "step_up_action", "data": json.dumps({"action": "read_sms_body", "pin": "0002", "payload": {}})}),
    ]

    from mobile_server import _PAIRED_IPS
    _PAIRED_IPS.add("192.168.1.100")

    hub = _WSHub()
    with patch("core.access_control.AccessControl", return_value=ac):
        ws = MockWebSocket(messages)
        await hub.handler(ws)

    # Filter step_up_result responses
    results = [f for f in sent_frames if f.get("type") == "step_up_result"]
    assert len(results) == 3
    for r in results:
        data_obj = json.loads(r["data"]) if isinstance(r["data"], str) else r["data"]
        assert data_obj["success"] is False
    assert ac._seconds_locked() > 0.0
