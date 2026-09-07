"""
tests/test_hud_overlay.py — Test Suite for Red HUD Desktop Overlay
==================================================================
Verifies:
1. JarvisHudOverlay instantiation with required window flags and attributes.
2. Click-through toggle and visibility toggle mechanics.
3. Telemetry gatherer calls AuditLog().verify() and IntegrityMonitor().verify_integrity().
4. Telemetry correctly binds mobile_server, psutil, and agent_manager states.
5. JarvisState transitions correctly update rotation speeds and visual labels.
6. Display geometry change handler runs with complete exception safety.
7. Paint event executes cleanly across mock canvas without rendering errors.
"""

import sys
import os
import pytest
from unittest.mock import patch, MagicMock

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from overlay.hud_overlay import (
    JarvisHudOverlay,
    HudTelemetry,
    RedHudColors,
    Qt,
    QApplication,
    QPainter,
    QPixmap,
    _QT6,
)
from core.states import JarvisState


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_hud_overlay_instantiation_and_flags(qapp):
    """Verifies overlay creates with frameless, translucent, always-on-top, and click-through attributes."""
    overlay = JarvisHudOverlay()
    assert overlay is not None

    # Flags check
    flags = overlay.windowFlags()
    frameless = Qt.WindowType.FramelessWindowHint if _QT6 else Qt.FramelessWindowHint
    stays_top = Qt.WindowType.WindowStaysOnTopHint if _QT6 else Qt.WindowStaysOnTopHint
    assert bool(flags & frameless)
    assert bool(flags & stays_top)

    # Attributes check
    wa_trans = Qt.WidgetAttribute.WA_TranslucentBackground if _QT6 else Qt.WA_TranslucentBackground
    wa_mouse = Qt.WidgetAttribute.WA_TransparentForMouseEvents if _QT6 else Qt.WA_TransparentForMouseEvents
    assert overlay.testAttribute(wa_trans)
    assert overlay.testAttribute(wa_mouse)


def test_hud_overlay_click_through_and_visibility_toggle(qapp):
    """Verifies set_click_through and toggle_hud_visibility behave deterministically."""
    overlay = JarvisHudOverlay()
    wa_mouse = Qt.WidgetAttribute.WA_TransparentForMouseEvents if _QT6 else Qt.WA_TransparentForMouseEvents
    
    # Toggle click-through
    overlay.set_click_through(False)
    assert overlay._click_through is False
    assert not overlay.testAttribute(wa_mouse)

    overlay.set_click_through(True)
    assert overlay._click_through is True
    assert overlay.testAttribute(wa_mouse)

    # Toggle visibility
    init_vis = overlay._hud_visible
    overlay.toggle_hud_visibility()
    assert overlay._hud_visible != init_vis
    overlay.toggle_hud_visibility()
    assert overlay._hud_visible == init_vis


def test_hud_telemetry_wires_real_audit_verify(qapp):
    """Confirms HudTelemetry directly invokes AuditLog().verify()."""
    overlay = JarvisHudOverlay()
    overlay._last_audit_check = 0
    overlay._last_audit_mtime = -1
    
    with patch("core.audit_log.AuditLog.verify", return_value=(True, None)) as mock_verify:
        overlay._refresh_telemetry()
        assert mock_verify.called
        assert overlay.telemetry.audit_chain_valid is True

    overlay._last_audit_check = 0
    overlay._last_audit_mtime = -1
    with patch("core.audit_log.AuditLog.verify", return_value=(False, "Broken link at index 5")) as mock_verify_tamper:
        overlay._refresh_telemetry()
        assert mock_verify_tamper.called
        assert overlay.telemetry.audit_chain_valid is False
        assert "Broken link" in overlay.telemetry.audit_chain_error


def test_hud_telemetry_wires_real_integrity_verify(qapp):
    """Confirms HudTelemetry invokes IntegrityMonitor().verify_integrity() and fails closed."""
    overlay = JarvisHudOverlay()
    overlay._last_integrity_check = 0
    
    mock_report = MagicMock()
    mock_report.is_valid = True
    with patch("core.integrity_monitor.IntegrityMonitor.verify_integrity", return_value=mock_report) as mock_integ:
        overlay._refresh_telemetry()
        assert mock_integ.called
        assert overlay.telemetry.integrity_valid is True

    # Confirm fail-closed on exception
    overlay._last_integrity_check = 0
    with patch("core.integrity_monitor.IntegrityMonitor.verify_integrity", side_effect=RuntimeError("disk read failed")):
        overlay._refresh_telemetry()
        assert overlay.telemetry.integrity_valid is False


def test_hud_telemetry_binds_mobile_server_and_agents(qapp):
    """Verifies pairing window, firewall, and agent states are bound."""
    overlay = JarvisHudOverlay()
    
    with patch("mobile_server.is_pairing_window_open", return_value=True):
        overlay._refresh_telemetry()
        assert overlay.telemetry.pairing_window_open is True

    mock_mgr = MagicMock()
    mock_mgr.get_status.return_value = {
        "Tom": {"status": "running", "progress": 45.0, "current_task": "Building overlay"},
        "Scout": {"status": "idle", "progress": 0.0, "current_task": ""},
        "Ada": {"status": "idle", "progress": 0.0, "current_task": ""},
        "Nova": {"status": "done", "progress": 100.0, "current_task": ""},
    }
    with patch("agents.agent_manager.get_manager", return_value=mock_mgr):
        overlay._refresh_telemetry()
        assert overlay.telemetry.agent_statuses["TOM"] == "RUNNING (45%)"
        assert overlay.telemetry.agent_statuses["SCOUT"] == "IDLE"


def test_hud_jarvis_state_transitions_and_animation(qapp):
    """Verifies set_jarvis_state and _on_anim_frame dynamically update speed and angles."""
    overlay = JarvisHudOverlay()
    
    overlay.set_jarvis_state(JarvisState.LISTENING)
    assert overlay._state_str == "LISTENING"
    a1_before = overlay._rot_angle_1
    overlay._on_anim_frame()
    assert overlay._rot_angle_1 != a1_before

    overlay.set_jarvis_state(JarvisState.ACTIVE_CONVERSATION)
    assert overlay._state_str == "ACTIVE_CONVERSATION"

    overlay.set_jarvis_state(JarvisState.SLEEPING)
    assert overlay._state_str == "SLEEPING"


def test_hud_screen_change_exception_safety(qapp):
    """Confirms _on_screens_changed survives arbitrary exceptions without crashing."""
    overlay = JarvisHudOverlay()
    
    with patch.object(overlay, "_update_screen_geometry", side_effect=RuntimeError("Screen disconnected")):
        # Should not raise exception
        overlay._on_screens_changed()


def test_hud_paint_event_executes_cleanly(qapp):
    """Renders all HUD components onto a mock QPixmap canvas without painter errors."""
    overlay = JarvisHudOverlay()
    overlay.resize(1920, 1080)
    
    pixmap = QPixmap(1920, 1080)
    pixmap.fill(Qt.GlobalColor.transparent if _QT6 else Qt.transparent)
    
    painter = QPainter(pixmap)
    try:
        # Call all component draw routines
        overlay._draw_scanlines(painter, 1920, 1080)
        overlay._draw_clock_module(painter, 40, 40)
        overlay._draw_capacity_gauges(painter, 40, 850)
        overlay._draw_radial_core(painter, 960, 510)
        overlay._draw_telemetry_panel(painter, 1480, 60, 400, 520)
        overlay._draw_bottom_status_strip(painter, 0, 1044, 1920, 36)
        overlay._draw_control_badge(painter, 850, 12, 220, 24)
    finally:
        painter.end()
    
    assert not pixmap.isNull()
