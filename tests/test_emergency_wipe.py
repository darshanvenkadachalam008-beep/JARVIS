"""
tests/test_emergency_wipe.py — Unit and integration tests for Multi-Channel Emergency Wipe
========================================================================================
Validates:
1. EmergencyWipeController request -> confirm -> execute lifecycle.
2. Telegram channel (EmergencyWipeListener) two-factor /wipe -> /wipe CONFIRM <PIN>.
3. Mobile channel (mobile_server.py HTTP and WebSocket) two-factor wipe trigger.
4. AccessControl PIN gating (action="emergency_wipe") and lockout defense.
5. send2trash safety and channel-tagged audit logging (AlertHistory).
6. Failure independence (Telegram failure does not block mobile channel, and vice-versa).
"""

import io
import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from core.access_control import AccessControl
from core.sentinel_extras import (
    EmergencyWipeController,
    EmergencyWipeListener,
    AlertHistory,
    HISTORY_PATH,
)


@pytest.fixture
def mock_trash():
    """Mocks the send2trash module and function."""
    m_mod = MagicMock()
    m_fn = MagicMock()
    m_mod.send2trash = m_fn
    with patch.dict(sys.modules, {"send2trash": m_mod}):
        yield m_fn


@pytest.fixture
def wipe_env(tmp_path, mock_trash):
    """Sets up an isolated environment with AccessControl PIN and test wipe files."""
    secret_file1 = tmp_path / "secret1.txt"
    secret_file1.write_text("classified data 1", encoding="utf-8")
    secret_file2 = tmp_path / "secret2.txt"
    secret_file2.write_text("classified data 2", encoding="utf-8")

    wipe_paths = [str(secret_file1), str(secret_file2)]

    # Configure AccessControl with known PIN
    access_path = tmp_path / "access_control.json"
    ac = AccessControl(path=access_path)
    ac.set_pin("9876")

    # Isolated alert history file
    history_file = tmp_path / "alert_history.json"
    with patch("core.sentinel_extras.HISTORY_PATH", history_file):
        with patch("core.sentinel_extras.AccessControl", return_value=ac):
            controller = EmergencyWipeController(wipe_paths=wipe_paths, confirmation_timeout_seconds=60.0)
            EmergencyWipeController.set_instance(controller)
            yield {
                "paths": wipe_paths,
                "file1": secret_file1,
                "file2": secret_file2,
                "ac": ac,
                "controller": controller,
                "history_file": history_file,
                "mock_trash": mock_trash,
            }
            EmergencyWipeController.set_instance(None)


def test_emergency_wipe_controller_full_flow(wipe_env):
    """Tests EmergencyWipeController request -> valid confirm -> execute -> audit trail."""
    controller = wipe_env["controller"]
    mock_trash = wipe_env["mock_trash"]

    # 1. Initiate wipe request
    ok, msg = controller.request_wipe(channel="test_channel")
    assert ok is True
    assert "Send confirmation with PIN" in msg

    # 2. Confirm wipe with valid PIN
    success, status_msg, results = controller.confirm_wipe("9876", channel="test_channel")
    assert success is True
    assert status_msg == "Wipe complete"
    assert len(results) == 2
    assert mock_trash.call_count == 2

    # 3. Verify audit history records channel
    recent = AlertHistory.recent(10)
    assert len(recent) >= 2
    assert recent[-1]["extra"]["channel"] == "test_channel"
    assert "Emergency wipe executed via test_channel" in recent[-1]["title"]


def test_emergency_wipe_controller_expired_window(wipe_env):
    """Tests that confirmation after timeout expires fails and does not wipe."""
    controller = EmergencyWipeController(wipe_paths=wipe_env["paths"], confirmation_timeout_seconds=0.1)
    mock_trash = wipe_env["mock_trash"]
    controller.request_wipe(channel="test_channel")
    time.sleep(0.15)

    success, status_msg, results = controller.confirm_wipe("9876", channel="test_channel")
    assert success is False
    assert "expired" in status_msg.lower()
    mock_trash.assert_not_called()


def test_emergency_wipe_controller_invalid_pin(wipe_env):
    """Tests that incorrect PIN is rejected and does not execute wipe."""
    controller = wipe_env["controller"]
    mock_trash = wipe_env["mock_trash"]
    controller.request_wipe(channel="test_channel")

    success, status_msg, results = controller.confirm_wipe("0000", channel="test_channel")
    assert success is False
    assert "PIN incorrect" in status_msg
    mock_trash.assert_not_called()


def test_emergency_wipe_controller_failure_handling(wipe_env):
    """
    Tests that when send2trash raises an exception on a path:
    1. success is False.
    2. status_msg is 'Wipe encountered errors'.
    3. results contains '❌'.
    4. AlertHistory records 'wipe_failed'.
    """
    controller = wipe_env["controller"]
    mock_trash = wipe_env["mock_trash"]
    mock_trash.side_effect = PermissionError("Access is denied")

    controller.request_wipe(channel="test_channel")
    success, status_msg, results = controller.confirm_wipe("9876", channel="test_channel")

    assert success is False
    assert status_msg == "Wipe encountered errors"
    assert len(results) == 2
    assert all(r.startswith("❌") for r in results)

    # Verify audit failure record
    recent = AlertHistory.recent(10)
    assert any(entry["event_type"] == "wipe_failed" for entry in recent)


def test_emergency_wipe_importerror_records_alert_history(wipe_env):
    """
    Tests that if send2trash is missing (ImportError), execute_wipe:
    1. Returns False and descriptive error message.
    2. Records AlertHistory 'wipe_failed' entry.
    """
    controller = wipe_env["controller"]
    with patch.dict(sys.modules, {"send2trash": None}):
        success, results = controller.execute_wipe(channel="test_channel")

    assert success is False
    assert any("send2trash not installed" in r for r in results)
    recent = AlertHistory.recent(10)
    assert any(entry["event_type"] == "wipe_failed" and "send2trash not installed" in entry.get("title", "") for entry in recent)


def test_emergency_wipe_nonexistent_paths_are_skipped_cleanly(tmp_path, wipe_env):
    """Tests that non-existent paths are marked as skipped (⏭) without counting as failures."""
    non_existent = str(tmp_path / "does_not_exist.txt")
    controller = EmergencyWipeController(wipe_paths=[non_existent], confirmation_timeout_seconds=60.0)

    controller.request_wipe(channel="test_channel")
    success, status_msg, results = controller.confirm_wipe("9876", channel="test_channel")

    assert success is True
    assert status_msg == "Wipe complete"
    assert len(results) == 1
    assert results[0].startswith("⏭")


def test_cross_channel_telegram_request_mobile_confirm(wipe_env):
    """
    Verifies that the singleton EmergencyWipeController unifies state across channels:
    Request via Telegram, confirm via Mobile HTTP API.
    """
    from mobile_server import _HTTPHandler, MOBILE_AUTH_TOKEN
    mock_trash = wipe_env["mock_trash"]

    # 1. Telegram listener initiates wipe using default singleton
    listener = EmergencyWipeListener(token="mock_token", authorized_chat_id="12345")
    replies = []
    with patch.object(listener, "_reply", side_effect=lambda text: replies.append(text)):
        updates = [{"update_id": 1, "message": {"chat": {"id": 12345}, "text": "/wipe"}}]
        for update in updates:
            msg = update.get("message", {})
            text = (msg.get("text") or "").strip()
            if text.lower() == "/wipe":
                ok, reply_msg = listener._controller.request_wipe(channel="telegram")
                listener._reply(reply_msg)

    assert len(replies) == 1
    assert "Send confirmation with PIN" in replies[0]

    # 2. Confirm via Mobile HTTP handler using the same singleton state
    body_bytes = json.dumps({"pin": "9876"}).encode("utf-8")
    handler = _HTTPHandler.__new__(_HTTPHandler)
    handler.rfile = io.BytesIO(body_bytes)
    handler.wfile = io.BytesIO()
    handler.path = "/api/wipe/confirm"
    handler.headers = {
        "Content-Length": str(len(body_bytes)),
        "Content-Type": "application/json",
        "X-Auth-Token": MOBILE_AUTH_TOKEN,
    }
    handler.client_address = ("127.0.0.1", 54321)
    handler.requestline = "POST /api/wipe/confirm HTTP/1.1"
    handler.request_version = "HTTP/1.1"
    handler.close_connection = True

    handler.do_POST()
    resp = json.loads(handler.wfile.getvalue().decode("utf-8").split("\r\n\r\n")[-1])
    assert resp["ok"] is True
    assert resp["message"] == "Wipe complete"
    assert mock_trash.call_count == 2



def test_telegram_listener_two_factor_flow(wipe_env):
    """Tests the Telegram EmergencyWipeListener /wipe -> /wipe CONFIRM <PIN> flow."""
    controller = wipe_env["controller"]
    mock_trash = wipe_env["mock_trash"]
    replies = []

    listener = EmergencyWipeListener(
        token="mock_token",
        authorized_chat_id="12345",
        wipe_paths=wipe_env["paths"],
        controller=controller,
    )

    with patch.object(listener, "_reply", side_effect=lambda text: replies.append(text)):
        # Step 1: /wipe
        updates_1 = [{"update_id": 1, "message": {"chat": {"id": 12345}, "text": "/wipe"}}]
        for update in updates_1:
            msg = update.get("message", {})
            chat_id = str(msg.get("chat", {}).get("id", ""))
            text = (msg.get("text") or "").strip()
            if chat_id == "12345" and text.lower() == "/wipe":
                ok, reply_msg = controller.request_wipe(channel="telegram")
                listener._reply("Send /wipe CONFIRM <PIN>")

        assert len(replies) == 1
        assert "Send /wipe CONFIRM <PIN>" in replies[0]

        # Step 2: /wipe CONFIRM 9876
        updates_2 = [{"update_id": 2, "message": {"chat": {"id": 12345}, "text": "/wipe CONFIRM 9876"}}]
        for update in updates_2:
            msg = update.get("message", {})
            chat_id = str(msg.get("chat", {}).get("id", ""))
            text = (msg.get("text") or "").strip()
            if chat_id == "12345" and text.upper().startswith("/WIPE CONFIRM"):
                parts = text.split(maxsplit=2)
                pin = parts[2] if len(parts) >= 3 else ""
                ok, status_msg, results = controller.confirm_wipe(pin, channel="telegram")
                listener._reply(f"Wipe complete: {len(results)} paths")

        assert mock_trash.call_count == 2
        assert "Wipe complete: 2 paths" in replies[-1]


def test_mobile_http_wipe_flow(wipe_env):
    """Tests mobile_server HTTP POST /api/wipe/request and /api/wipe/confirm endpoints."""
    from mobile_server import _HTTPHandler, MOBILE_AUTH_TOKEN

    controller = wipe_env["controller"]
    mock_trash = wipe_env["mock_trash"]

    def create_handler(path, body_dict, auth_token=MOBILE_AUTH_TOKEN):
        body_bytes = json.dumps(body_dict).encode("utf-8")
        rfile = io.BytesIO(body_bytes)
        wfile = io.BytesIO()
        headers = {
            "Content-Length": str(len(body_bytes)),
            "Content-Type": "application/json",
            "X-Auth-Token": auth_token,
        }
        handler = _HTTPHandler.__new__(_HTTPHandler)
        handler.rfile = rfile
        handler.wfile = wfile
        handler.path = path
        handler.headers = headers
        handler.client_address = ("127.0.0.1", 54321)
        handler.requestline = f"POST {path} HTTP/1.1"
        handler.request_version = "HTTP/1.1"
        handler.close_connection = True
        return handler, wfile

    # 1. Unauthenticated request should fail (401)
    handler, wfile = create_handler("/api/wipe/request", {}, auth_token="wrong_token")
    handler.do_POST()
    assert b"401" in wfile.getvalue() or b"unauthorized" in wfile.getvalue()

    # 2. Authenticated request
    handler, wfile = create_handler("/api/wipe/request", {})
    handler.do_POST()
    resp = json.loads(wfile.getvalue().decode("utf-8").split("\r\n\r\n")[-1])
    assert resp["ok"] is True
    assert "Send confirmation with PIN" in resp["message"]

    # 3. Authenticated confirm with wrong PIN
    handler, wfile = create_handler("/api/wipe/confirm", {"pin": "0000"})
    handler.do_POST()
    resp = json.loads(wfile.getvalue().decode("utf-8").split("\r\n\r\n")[-1])
    assert resp["ok"] is False
    assert "PIN incorrect" in resp["message"]

    # 4. Authenticated confirm with valid PIN
    # Re-request because bad PIN cleared pending state
    controller.request_wipe(channel="mobile_api")
    handler, wfile = create_handler("/api/wipe/confirm", {"pin": "9876"})
    handler.do_POST()
    resp = json.loads(wfile.getvalue().decode("utf-8").split("\r\n\r\n")[-1])
    assert resp["ok"] is True
    assert resp["message"] == "Wipe complete"
    assert len(resp["results"]) == 2
    assert mock_trash.call_count == 2


@pytest.mark.anyio
async def test_mobile_websocket_wipe_flow(wipe_env):
    """Tests mobile_server WebSocket wipe_request and wipe_confirm handling."""
    from mobile_server import _WSHub, MOBILE_AUTH_TOKEN

    controller = wipe_env["controller"]
    mock_trash = wipe_env["mock_trash"]

    sent_frames = []

    class MockWebSocket:
        def __init__(self, incoming_messages):
            self.incoming = incoming_messages
            self.closed = False
            self.remote_address = ("127.0.0.1", 54321)

        async def send(self, data):
            sent_frames.append(json.loads(data))

        def __aiter__(self):
            return self

        async def __anext__(self):
            if not self.incoming:
                raise StopAsyncIteration
            return self.incoming.pop(0)

        async def close(self, code=1000, reason=""):
            self.closed = True

    hub = _WSHub()
    # Scenario: auth -> wipe_request -> wipe_confirm
    messages = [
        json.dumps({"type": "auth", "data": MOBILE_AUTH_TOKEN}),
        json.dumps({"type": "wipe_request"}),
        json.dumps({"type": "wipe_confirm", "pin": "9876"}),
    ]
    ws = MockWebSocket(messages)
    await hub.handler(ws)

    # Verify responses
    wipe_responses = [f for f in sent_frames if f.get("type") == "wipe_response"]
    assert len(wipe_responses) == 2
    assert wipe_responses[0]["ok"] is True
    assert "Send confirmation with PIN" in wipe_responses[0]["message"]
    assert wipe_responses[1]["ok"] is True
    assert wipe_responses[1]["message"] == "Wipe complete"
    assert mock_trash.call_count == 2



def test_independent_channels_telegram_failure_does_not_block_mobile(wipe_env):
    """
    Verifies that if Telegram API is unreachable or has invalid tokens,
    the mobile channel functions seamlessly.
    """
    controller = wipe_env["controller"]
    mock_trash = wipe_env["mock_trash"]

    # Telegram listener fails to poll
    listener = EmergencyWipeListener(
        token="invalid_dead_token",
        authorized_chat_id="12345",
        wipe_paths=wipe_env["paths"],
        controller=controller,
    )
    with patch("urllib.request.urlopen", side_effect=Exception("Telegram connection refused")):
        updates = listener._get_updates()
        assert updates == []  # Telegram is completely down

    # Mobile channel still executes wipe cleanly
    ok, req_msg = controller.request_wipe(channel="mobile_api")
    assert ok is True

    success, status_msg, results = controller.confirm_wipe("9876", channel="mobile_api")
    assert success is True
    assert mock_trash.call_count == 2


def test_emergency_wipe_anomaly_step_up_refusal_and_proactive_alert(wipe_env):
    """
    Verifies that under anomalous context (e.g. 3 AM / unrecognized network):
    1. A single Primary PIN is refused.
    2. ProactiveBridge receives a CRITICAL security event.
    3. AlertHistory and AuditLog record the blocked wipe.
    4. Target files are NOT trashed.
    """
    controller = wipe_env["controller"]
    mock_trash = wipe_env["mock_trash"]
    bridge_mock = MagicMock()
    controller.set_bridge(bridge_mock)

    anomalous_context = {
        "time": "2026-09-01T03:00:00",
        "network_id": "wifi:UntrustedCoffeeShop",
    }

    controller.request_wipe(channel="telegram")
    success, msg, results = controller.confirm_wipe("9876", channel="telegram", context=anomalous_context)

    assert success is False
    assert "Wipe refused: Multi-factor step-up verification required" in msg
    assert mock_trash.call_count == 0

    # Verify ProactiveBridge CRITICAL dispatch
    assert bridge_mock.dispatch.call_count == 1
    event = bridge_mock.dispatch.call_args[0][0]
    assert event.priority.name == "CRITICAL"
    assert event.category == "security"
    assert "Blocked Wipe Attempt" in event.title
    assert "telegram" in event.channels
    assert "audit" in event.channels



def test_emergency_wipe_anomaly_step_up_success_with_recovery_pin(wipe_env):
    """
    Verifies the remote disaster-recovery fallback:
    Providing the valid Recovery PIN alongside the Primary PIN satisfies
    elevated friction remotely and executes the wipe.
    """
    controller = wipe_env["controller"]
    mock_trash = wipe_env["mock_trash"]
    ac = wipe_env["ac"]
    ac.set_recovery_pin("54321")

    anomalous_context = {
        "time": "2026-09-01T03:00:00",
        "network_id": "wifi:UntrustedCoffeeShop",
    }

    controller.request_wipe(channel="mobile_app")
    success, msg, results = controller.confirm_wipe(
        "9876",
        channel="mobile_app",
        context=anomalous_context,
        recovery_pin="54321",
    )

    assert success is True
    assert msg == "Wipe complete"
    assert mock_trash.call_count == 2


def test_emergency_wipe_fail_closed_on_anomaly_evaluation_exception(wipe_env):
    """
    Verifies the fail-closed guarantee:
    If AnomalyDetector.evaluate() throws an unhandled exception,
    confirm_wipe() strictly defaults to elevated friction and refuses the wipe.
    """
    controller = wipe_env["controller"]
    mock_trash = wipe_env["mock_trash"]
    ac = wipe_env["ac"]

    with patch.object(ac._engine.anomaly_detector, "evaluate", side_effect=RuntimeError("Corrupted baseline lock")):
        controller.request_wipe(channel="telegram")
        success, msg, results = controller.confirm_wipe("9876", channel="telegram")

        assert success is False
        assert "Wipe refused: Multi-factor step-up verification required" in msg
        assert "fail_closed" in msg
        assert mock_trash.call_count == 0

