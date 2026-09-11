"""Unit tests for Sentinel autonomous defense action primitives."""
import os
import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from sentinel.defense.actions import (
    lock_session,
    revoke_active_tokens,
    capture_evidence,
    network_isolate,
    alert_owner,
)
from sentinel.config.settings import default_settings


def test_lock_session_windows_success():
    """Confirms lock_session calls user32.LockWorkStation and returns True on success."""
    mock_user32 = MagicMock()
    mock_user32.LockWorkStation.return_value = 1

    with patch("platform.system", return_value="Windows"), \
         patch("ctypes.windll", create=True) as mock_windll:
        mock_windll.user32 = mock_user32
        result = lock_session()
        assert result is True
        assert mock_user32.LockWorkStation.called


def test_lock_session_windows_failure():
    """Confirms lock_session handles Win32 return 0 properly and returns False."""
    mock_user32 = MagicMock()
    mock_user32.LockWorkStation.return_value = 0

    with patch("platform.system", return_value="Windows"), \
         patch("ctypes.windll", create=True) as mock_windll:
        mock_windll.user32 = mock_user32
        result = lock_session()
        assert result is False


def test_revoke_active_tokens_returns_exact_count(tmp_path):
    """
    Confirms revoke_active_tokens returns the EXACT integer count of revoked tokens,
    asserting on the integer value rather than just truthy check.
    """
    # Create real presence token file
    presence_token_path = tmp_path / "presence_challenge.token"
    presence_token_path.write_text("PRESENCE_CHALLENGE_SECRET_123", encoding="utf-8")
    assert presence_token_path.exists()

    # Mock AuthEngine with enrollment_manager and in-memory session tokens
    mock_auth = MagicMock()
    mock_auth.enrollment_manager = MagicMock()
    mock_auth.enrollment_manager.presence_file = presence_token_path
    mock_auth.active_tokens = {"session_token_1", "session_token_2"}

    # Mock MobileHub with 2 active websocket clients
    mock_hub = MagicMock()
    mock_ws1 = MagicMock()
    mock_ws2 = MagicMock()
    mock_hub._clients = {mock_ws1, mock_ws2}

    # Execute revocation
    revocation_count = revoke_active_tokens(auth_engine=mock_auth, mobile_hub=mock_hub)

    # 1 presence file + 2 auth_engine session tokens + 2 mobile clients = 5 total revoked items
    assert revocation_count == 5
    assert not presence_token_path.exists(), "Presence token file must be deleted"
    assert len(mock_auth.active_tokens) == 0, "Active token set must be cleared"


def test_capture_evidence_writes_local_bundle(tmp_path):
    """
    Confirms capture_evidence operates strictly locally:
    writes context.json, screenshot, applies DACL, and returns evidence path.
    """
    ev_dir = tmp_path / "test_evidence_bundle"
    mock_jpeg = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01test_screenshot_data"

    with patch("actions.screen_processor._capture_screenshot", return_value=mock_jpeg), \
         patch("actions.screen_processor._capture_camera", return_value=mock_jpeg), \
         patch("sentinel.defense.actions.apply_owner_only_dacl") as mock_dacl:

        ret_path = capture_evidence(
            evidence_dir=ev_dir,
            context_summary="Visual artifact test run",
            metadata={"source": "pytest", "threat_score": 0.95},
        )

        assert ret_path == ev_dir
        assert ev_dir.exists()

        # Verify context.json
        ctx_file = ev_dir / "context.json"
        assert ctx_file.exists()
        ctx_data = json.loads(ctx_file.read_text(encoding="utf-8"))
        assert ctx_data["context_summary"] == "Visual artifact test run"
        assert ctx_data["metadata"]["threat_score"] == 0.95
        assert "pid" in ctx_data
        assert "user" in ctx_data

        # Verify screenshot and camera
        assert (ev_dir / "screenshot.jpg").exists()
        assert (ev_dir / "camera.jpg").exists()
        assert mock_dacl.called


def test_network_isolate_respects_config_gate():
    """Confirms network_isolate strictly checks allow_network_isolation config flag."""
    # 1. Disabled by default in settings -> returns False
    with patch.object(default_settings, "allow_network_isolation", False), \
         patch.dict(os.environ, {"SENTINEL_ALLOW_NETWORK_ISOLATION": "0"}):
        res = network_isolate(reason="Test attack")
        assert res is False

    # 2. Enabled + dry_run -> returns True without calling netsh
    with patch.object(default_settings, "allow_network_isolation", True):
        res = network_isolate(reason="Test attack", dry_run=True)
        assert res is True


def test_alert_owner_records_and_dispatches(tmp_path):
    """Confirms alert_owner records to defense_alerts.jsonl and dispatches alert."""
    with patch.object(default_settings, "base_dir", tmp_path), \
         patch("core.telegram_alert.TelegramAlerter.configured", return_value=True), \
         patch("core.telegram_alert.TelegramAlerter.send_message", return_value=True) as mock_tg, \
         patch("sentinel.defense.actions.apply_owner_only_dacl"):

        success = alert_owner(summary="Intrusion simulation alert", evidence_path=tmp_path / "ev1")
        assert success is True
        assert mock_tg.called

        history_file = tmp_path / "defense_alerts.jsonl"
        assert history_file.exists()
        lines = history_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert "Intrusion simulation alert" in record["summary"]
