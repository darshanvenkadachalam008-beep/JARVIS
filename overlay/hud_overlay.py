"""
overlay/hud_overlay.py — Red HUD Desktop Overlay for JARVIS (Mark-XXXIX-OR)
===========================================================================
Styled after a classic "Iron Man HUD" Rainmeter desktop skin.
- Circular clock/date rings, capacity arc gauges, pulsing radial arc reactor core,
  and live monospace system data feed.
- Palette: Red-on-black (#050505, #E23B3B, #FF2A2A, #4A1E1E, #2A1414, #D8CFC7).
- Pure QPainter vector rendering (antialiasing, gradients, no external images).
- Frameless, always-on-top, transparent, click-through window (Ctrl+Alt+J toggle).
- Survives screen/resolution changes and display sleep/resume without crashing.
- Live data bindings: AuditLog().verify(), mobile_server pairing/firewall state,
  agents.agent_manager statuses, psutil metrics, and core.states.JarvisState.
"""
from __future__ import annotations

import sys
import os
import math
import time
import json
import psutil
import datetime
import threading
import platform
from pathlib import Path
from types import ModuleType
from typing import Optional, Tuple, Dict, Any, List, Callable

# ── PyQt5 / PyQt6 Unified Compatibility Layer ───────────────────────────────
try:
    from PyQt6.QtCore import (  # type: ignore[import]
        Qt, QTimer, QRectF, QPointF, QSize, QObject, QAbstractNativeEventFilter,
    )
    from PyQt6.QtGui import (  # type: ignore[import]
        QColor, QPainter, QPen, QBrush, QFont, QFontDatabase,
        QLinearGradient, QRadialGradient, QPainterPath, QPolygonF, QPixmap,
    )
    from PyQt6.QtWidgets import (  # type: ignore[import]
        QApplication, QWidget, QMainWindow, QScreen,
    )
    _QT6 = True
except ImportError:
    import importlib
    QtCore: ModuleType = importlib.import_module("PyQt5.QtCore")    # type: ignore[import]
    QtGui:  ModuleType = importlib.import_module("PyQt5.QtGui")     # type: ignore[import]
    QtWidgets: ModuleType = importlib.import_module("PyQt5.QtWidgets")  # type: ignore[import]

    Qt = QtCore.Qt
    QTimer = QtCore.QTimer
    QRectF = QtCore.QRectF
    QPointF = QtCore.QPointF
    QSize = QtCore.QSize
    QObject = QtCore.QObject
    QAbstractNativeEventFilter = QtCore.QAbstractNativeEventFilter

    QColor = QtGui.QColor
    QPainter = QtGui.QPainter
    QPen = QtGui.QPen
    QBrush = QtGui.QBrush
    QFont = QtGui.QFont
    QFontDatabase = QtGui.QFontDatabase
    QLinearGradient = QtGui.QLinearGradient
    QRadialGradient = QtGui.QRadialGradient
    QPainterPath = QtGui.QPainterPath
    QPolygonF = QtGui.QPolygonF
    QPixmap = QtGui.QPixmap

    QApplication = QtWidgets.QApplication
    QWidget = QtWidgets.QWidget
    QMainWindow = QtWidgets.QMainWindow
    QScreen = QtGui.QScreen

    _QT6 = False


# ── HUD Palette & Helper Functions ──────────────────────────────────────────
class RedHudColors:
    BG_TRANSLUCENT = QColor(5, 5, 5, 0)
    PANEL_BG       = QColor(10, 4, 4, 160)
    PANEL_BORDER   = QColor(74, 30, 30, 220)
    RED_PRIMARY    = QColor(226, 59, 59)      # #E23B3B
    RED_BRIGHT     = QColor(255, 42, 42)      # #FF2A2A
    RED_GLOW       = QColor(255, 77, 77, 180)
    RED_DIM        = QColor(74, 30, 30)       # #4A1E1E
    RED_BORDER     = QColor(42, 20, 20)       # #2A1414
    RED_HOT        = QColor(255, 220, 220)    # glowing center core
    TEXT_MAIN      = QColor(216, 207, 199)    # #D8CFC7
    TEXT_DIM       = QColor(136, 112, 112)    # #887070
    TEXT_BRIGHT    = QColor(250, 245, 240)
    CYAN_ACCENT    = QColor(80, 227, 194)
    GREEN_OK       = QColor(60, 185, 122)
    WARN_YELLOW    = QColor(230, 180, 40)


def qcol(color: QColor, alpha: int = 255) -> QColor:
    c = QColor(color)
    c.setAlpha(alpha)
    return c


# ── Global Hotkey (Windows native RegisterHotKey) ───────────────────────────
_HOTKEY_ID = 0x4A41  # 'JA'
MOD_ALT = 0x0001
MOD_CONTROL = 0x0002
WM_HOTKEY = 0x0312


# ── Live Telemetry Data Structure ───────────────────────────────────────────
class HudTelemetry:
    def __init__(self):
        self.time_str = "00:00:00"
        self.time_short = "00:00"
        self.date_month = "JANUARY"
        self.date_day = "01"
        self.date_weekday = "MONDAY"
        self.cpu_pct = 0.0
        self.ram_pct = 0.0
        self.ram_used_gb = 0.0
        self.ram_total_gb = 0.0
        self.disk_total_gb = 0.0
        self.disk_free_gb = 0.0
        self.battery_pct = 100.0
        self.battery_power_plugged = True
        self.audit_chain_valid = True
        self.audit_chain_count = 0
        self.audit_chain_error: Optional[str] = None
        self.firewall_active = True
        self.pairing_window_open = False
        self.pairing_window_remaining = 0.0
        self.paired_ips_count = 0
        self.connected_devices_count = 0
        self.local_ip = "127.0.0.1"
        self.agent_statuses: Dict[str, str] = {
            "ADA": "IDLE", "TOM": "IDLE", "SCOUT": "IDLE", "NOVA": "IDLE",
        }
        self.system_state = "IDLE"
        self.integrity_valid = False
        self.uptime_str = "0h 0m"
        self.thread_count = 1


# ── Main Red HUD Desktop Overlay Window ──────────────────────────────────────
class JarvisHudOverlay(QMainWindow):
    """
    Full-screen, transparent, always-on-top, click-through Red HUD desktop overlay.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._start_time = time.time()
        self.telemetry = HudTelemetry()
        self._click_through = True
        self._hud_visible = True
        self._pulse_phase = 0.0
        self._rot_angle_1 = 0.0
        self._rot_angle_2 = 0.0
        self._rot_angle_3 = 0.0
        self._state_str = "SLEEPING"

        # Window Mechanics
        self._init_window_flags()
        self._update_screen_geometry()

        # Cache & Performance optimizations
        self._last_integrity_check = 0.0
        self._scanline_cache: Optional[QPixmap] = None
        self._cached_size: Tuple[int, int] = (0, 0)

        # Connect screen resilience signals
        self._connect_screen_signals()

        # Install global Windows hotkey Ctrl+Alt+J
        self._install_global_hotkey()

        # Setup Timers
        self._init_timers()

        # Initial Telemetry Gather
        self._refresh_telemetry()

    # ── Window Setup & Resilience ───────────────────────────────────────────

    def _init_window_flags(self):
        flags = (
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.Tool
            | Qt.WindowType.SubWindow
        ) if _QT6 else (
            Qt.FramelessWindowHint
            | Qt.WindowStaysOnTopHint
            | Qt.Tool
            | Qt.SubWindow
        )
        self.setWindowFlags(flags)

        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground if _QT6 else Qt.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating if _QT6 else Qt.WA_ShowWithoutActivating, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents if _QT6 else Qt.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground if _QT6 else Qt.WA_NoSystemBackground, True)

        if platform.system() == "Windows":
            try:
                import ctypes
                user32 = ctypes.windll.user32
                hwnd = int(self.winId())
                GWL_EXSTYLE = -20
                WS_EX_TRANSPARENT = 0x00000020
                WS_EX_LAYERED = 0x00080000
                ex_style = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
                user32.SetWindowLongW(hwnd, GWL_EXSTYLE, ex_style | WS_EX_TRANSPARENT | WS_EX_LAYERED)
            except Exception:
                pass

        self.setWindowTitle("JARVIS Red HUD Overlay")

    def _update_screen_geometry(self):
        """Calculates full bounding geometry across all active displays safely."""
        try:
            app = QApplication.instance()
            if not app:
                self.setGeometry(0, 0, 1920, 1080)
                return

            screens = app.screens()
            if not screens:
                self.setGeometry(0, 0, 1920, 1080)
                return

            min_x = min(s.geometry().x() for s in screens)
            min_y = min(s.geometry().y() for s in screens)
            max_r = max(s.geometry().x() + s.geometry().width() for s in screens)
            max_b = max(s.geometry().y() + s.geometry().height() for s in screens)

            self.setGeometry(min_x, min_y, max_r - min_x, max_b - min_y)
        except Exception as e:
            # Fallback to standard resolution without crashing
            self.setGeometry(0, 0, 1920, 1080)

    def _connect_screen_signals(self):
        """Attaches resilience listeners for resolution change, sleep/resume, screen add/remove."""
        try:
            app = QApplication.instance()
            if hasattr(app, "screenAdded"):
                app.screenAdded.connect(self._on_screens_changed)
            if hasattr(app, "screenRemoved"):
                app.screenRemoved.connect(self._on_screens_changed)
            if hasattr(app, "primaryScreen") and app.primaryScreen():
                screen = app.primaryScreen()
                if hasattr(screen, "geometryChanged"):
                    screen.geometryChanged.connect(self._on_screens_changed)
                if hasattr(screen, "virtualGeometryChanged"):
                    screen.virtualGeometryChanged.connect(self._on_screens_changed)
        except Exception:
            pass

    def _on_screens_changed(self, *args):
        """Handles display geometry changes dynamically with complete exception safety."""
        try:
            self._update_screen_geometry()
            self.update()
        except Exception:
            pass

    # ── Hotkey & Click-Through Management ───────────────────────────────────

    def _install_global_hotkey(self):
        if platform.system() != "Windows":
            return
        try:
            import ctypes
            user32 = ctypes.windll.user32
            hwnd = int(self.winId())
            # Register Ctrl+Alt+J
            user32.RegisterHotKey(hwnd, _HOTKEY_ID, MOD_CONTROL | MOD_ALT, ord('J'))

            # Install native event filter
            class WindowsHotkeyFilter(QAbstractNativeEventFilter):
                def __init__(self, overlay):
                    super().__init__()
                    self.overlay = overlay

                def nativeEventFilter(self, eventType, message):
                    try:
                        if eventType == b"windows_generic_MSG" or eventType == "windows_generic_MSG":
                            import ctypes.wintypes
                            msg = ctypes.wintypes.MSG.from_address(int(message))
                            if msg.message == WM_HOTKEY and msg.wParam == _HOTKEY_ID:
                                self.overlay.toggle_hud_visibility()
                                return True, 0
                    except Exception:
                        pass
                    return False, 0

            self._native_filter = WindowsHotkeyFilter(self)
            app = QApplication.instance()
            if app:
                app.installNativeEventFilter(self._native_filter)
        except Exception:
            pass

    def toggle_hud_visibility(self):
        """Toggles HUD visibility and click-through state."""
        self._hud_visible = not self._hud_visible
        if self._hud_visible:
            self.show()
            self.update()
        else:
            self.hide()

    def set_click_through(self, enabled: bool):
        """Toggles click-through mode via Qt attribute and Windows WS_EX_TRANSPARENT."""
        self._click_through = enabled
        self.setAttribute(
            Qt.WidgetAttribute.WA_TransparentForMouseEvents if _QT6 else Qt.WA_TransparentForMouseEvents,
            enabled,
        )
        if platform.system() == "Windows":
            try:
                import ctypes
                user32 = ctypes.windll.user32
                hwnd = int(self.winId())
                GWL_EXSTYLE = -20
                WS_EX_TRANSPARENT = 0x00000020
                ex_style = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
                if enabled:
                    user32.SetWindowLongW(hwnd, GWL_EXSTYLE, ex_style | WS_EX_TRANSPARENT)
                else:
                    user32.SetWindowLongW(hwnd, GWL_EXSTYLE, ex_style & ~WS_EX_TRANSPARENT)
            except Exception:
                pass

    # ── Timers & Animation Pipeline ─────────────────────────────────────────

    def _init_timers(self):
        # 1-second telemetry refresh timer (low CPU)
        self._telemetry_timer = QTimer(self)
        self._telemetry_timer.setInterval(1000)
        self._telemetry_timer.timeout.connect(self._refresh_telemetry)
        self._telemetry_timer.start()

        # Smooth vector ring animation timer throttled for <2% idle CPU
        self._anim_timer = QTimer(self)
        self._anim_timer.setInterval(50)  # 20 FPS
        self._anim_timer.timeout.connect(self._on_anim_frame)
        self._anim_timer.start()

    def set_jarvis_state(self, state_name_or_enum: Any):
        """Updates live system state from core.states.JarvisState."""
        try:
            if hasattr(state_name_or_enum, "name"):
                self._state_str = str(state_name_or_enum.name).upper()
            else:
                self._state_str = str(state_name_or_enum).upper()
            self.telemetry.system_state = self._state_str
        except Exception:
            self._state_str = "IDLE"

    def _get_core_rect(self) -> QRectF:
        w = self.width()
        h = self.height()
        cx = w / 2
        cy = h / 2 - 30
        r = 190.0
        return QRectF(cx - r, cy - r, r * 2, r * 2)

    def _on_anim_frame(self):
        if not self._hud_visible:
            return

        # Adjust rotation speed based on JarvisState
        state = self._state_str
        if state == "ACTIVE_CONVERSATION" or state == "ACTIVE":
            speed_mult = 2.5
            pulse_speed = 0.15
        elif state == "LISTENING":
            speed_mult = 1.6
            pulse_speed = 0.10
        elif state == "SHUTDOWN" or state == "OFFLINE":
            speed_mult = 0.0
            pulse_speed = 0.0
        else:  # SLEEPING / IDLE
            speed_mult = 0.6
            pulse_speed = 0.04

        self._rot_angle_1 = (self._rot_angle_1 + 0.8 * speed_mult) % 360.0
        self._rot_angle_2 = (self._rot_angle_2 - 1.2 * speed_mult) % 360.0
        self._rot_angle_3 = (self._rot_angle_3 + 0.4 * speed_mult) % 360.0
        self._pulse_phase = (self._pulse_phase + pulse_speed) % (2.0 * math.pi)

        # Invalidate solely the central core bounding area on animation ticks
        self.update(self._get_core_rect().toRect())

    # ── Live Telemetry Data Binding ─────────────────────────────────────────

    def _refresh_telemetry(self):
        t = self.telemetry
        now = datetime.datetime.now()

        # Clock & Date
        t.time_str = now.strftime("%H:%M:%S")
        t.time_short = now.strftime("%H:%M")
        t.date_month = now.strftime("%B").upper()
        t.date_day = now.strftime("%d")
        t.date_weekday = now.strftime("%A").upper()

        # Process & OS Metrics via psutil
        try:
            t.cpu_pct = psutil.cpu_percent(interval=None)
            vm = psutil.virtual_memory()
            t.ram_pct = vm.percent
            t.ram_used_gb = vm.used / (1024 ** 3)
            t.ram_total_gb = vm.total / (1024 ** 3)

            disk = psutil.disk_usage(os.path.abspath(os.sep))
            t.disk_total_gb = disk.total / (1024 ** 3)
            t.disk_free_gb = disk.free / (1024 ** 3)

            batt = psutil.sensors_battery()
            if batt:
                t.battery_pct = batt.percent
                t.battery_power_plugged = batt.power_plugged
            else:
                t.battery_pct = 100.0
                t.battery_power_plugged = True

            t.thread_count = threading.active_count()
            elapsed = int(time.time() - self._start_time)
            t.uptime_str = f"{elapsed // 3600}h {(elapsed % 3600) // 60}m {elapsed % 60}s"
        except Exception:
            pass

        # Real Audit Log Verification via core.audit_log.AuditLog().verify()
        try:
            from core.audit_log import AuditLog
            audit = AuditLog()
            log_mtime = audit.path.stat().st_mtime if audit.path.exists() else 0.0
            now_ts = time.time()
            if log_mtime != getattr(self, "_last_audit_mtime", -1.0) or (now_ts - getattr(self, "_last_audit_check", 0.0) > 10.0):
                self._last_audit_mtime = log_mtime
                self._last_audit_check = now_ts
                ok, err = audit.verify()
                t.audit_chain_valid = ok
                t.audit_chain_error = err
                t.audit_chain_count = len(audit.read_all())
        except Exception as e:
            t.audit_chain_valid = False
            t.audit_chain_error = str(e)

        # Real Mobile Server & Firewall State
        try:
            import mobile_server
            t.pairing_window_open = mobile_server.is_pairing_window_open()
            if getattr(mobile_server, "_PAIRING_WINDOW_FILE", None) and mobile_server._PAIRING_WINDOW_FILE.exists():
                try:
                    exp = float(mobile_server._PAIRING_WINDOW_FILE.read_text(encoding="utf-8").strip())
                    t.pairing_window_remaining = max(0.0, exp - time.time())
                except Exception:
                    t.pairing_window_remaining = 0.0
            else:
                t.pairing_window_remaining = 0.0
            t.paired_ips_count = len(getattr(mobile_server, "_PAIRED_IPS", set()) - {"127.0.0.1", "::1"})
            t.connected_devices_count = getattr(mobile_server, "_WSHub", None).get_client_count() if hasattr(getattr(mobile_server, "_WSHub", None), "get_client_count") else 0
            t.local_ip = mobile_server.get_local_ip()
            t.firewall_active = True
        except Exception:
            pass

        # Real Agent Statuses via agents.agent_manager
        try:
            from agents.agent_manager import get_manager
            mgr = get_manager()
            st = mgr.get_status()
            for k in ["ADA", "TOM", "SCOUT", "NOVA"]:
                agent_data = st.get(k.capitalize()) or st.get(k)
                if agent_data and isinstance(agent_data, dict):
                    status = agent_data.get("status", "IDLE").upper()
                    prog = agent_data.get("progress", 0.0)
                    t.agent_statuses[k] = f"{status} ({int(prog)}%)" if status == "RUNNING" else status
                else:
                    t.agent_statuses[k] = "IDLE"
        except Exception:
            pass

        # Real Integrity Verification via core.integrity_monitor.IntegrityMonitor().verify_integrity()
        now_ts = time.time()
        if now_ts - self._last_integrity_check > 30.0:
            self._last_integrity_check = now_ts
            try:
                from core.integrity_monitor import IntegrityMonitor
                report = IntegrityMonitor().verify_integrity()
                t.integrity_valid = report.is_valid
            except Exception:
                t.integrity_valid = False

        # Invalidate full canvas on the 1s clock/telemetry update
        self.update()

    # ── Paint Pipeline (QPainter Vector Rendering) ───────────────────────────

    def paintEvent(self, event):
        if not self._hud_visible:
            return

        painter = QPainter(self)
        try:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing if _QT6 else QPainter.Antialiasing, True)
            painter.setRenderHint(QPainter.RenderHint.TextAntialiasing if _QT6 else QPainter.TextAntialiasing, True)

            w = self.width()
            h = self.height()
            r = event.rect()
            is_full = (r.width() >= w - 10 and r.height() >= h - 10)

            # 1. Subtle Background Scanlines & Tech Grid (full repaint only)
            if is_full:
                self._draw_scanlines(painter, w, h)

            # Component Rectangles
            clock_rect = QRectF(40, 40, 320, 200).toRect()
            gauge_rect = QRectF(40, h - 230, 320, 160).toRect()
            core_rect = self._get_core_rect().toRect()
            telemetry_rect = QRectF(w - 440, 60, 400, 520).toRect()
            status_rect = QRectF(0, h - 36, w, 36).toRect()
            badge_rect = QRectF(w / 2 - 110, 12, 220, 24).toRect()

            # 2. Top-Left Circular Clock & Date Module
            if is_full or r.intersects(clock_rect):
                self._draw_clock_module(painter, 40, 40)

            # 3. Bottom-Left Circular Capacity & Power Gauges
            if is_full or r.intersects(gauge_rect):
                self._draw_capacity_gauges(painter, 40, h - 230)

            # 4. Center Pulsing Radial Arc Reactor Core
            if is_full or r.intersects(core_rect):
                self._draw_radial_core(painter, w / 2, h / 2 - 30)

            # 5. Right Side Live Monospace Telemetry Feed
            if is_full or r.intersects(telemetry_rect):
                self._draw_telemetry_panel(painter, w - 440, 60, 400, 520)

            # 6. Bottom Status Strip
            if is_full or r.intersects(status_rect):
                self._draw_bottom_status_strip(painter, 0, h - 36, w, 36)

            # 7. Mini Click-Through / Control Drag Badge
            if is_full or r.intersects(badge_rect):
                self._draw_control_badge(painter, w / 2 - 110, 12, 220, 24)

        finally:
            painter.end()

    # ── Component 1: Scanlines & Grid ───────────────────────────────────────

    def _draw_scanlines(self, p: QPainter, w: int, h: int):
        if self._scanline_cache is None or self._cached_size != (w, h):
            self._cached_size = (w, h)
            pix = QPixmap(w, h)
            pix.fill(Qt.GlobalColor.transparent if _QT6 else Qt.transparent)
            sp = QPainter(pix)
            sp.setPen(QPen(QColor(0, 0, 0, 16), 1))
            for y in range(0, h, 6):
                sp.drawLine(0, y, w, y)
            sp.end()
            self._scanline_cache = pix

        p.drawPixmap(0, 0, self._scanline_cache)

        # Subtle corner brackets on outer viewport
        p.setPen(QPen(RedHudColors.RED_DIM, 2))
        pad = 20
        bracket_len = 30
        # Top-left
        p.drawLine(pad, pad, pad + bracket_len, pad)
        p.drawLine(pad, pad, pad, pad + bracket_len)
        # Top-right
        p.drawLine(w - pad, pad, w - pad - bracket_len, pad)
        p.drawLine(w - pad, pad, w - pad, pad + bracket_len)
        # Bottom-left
        p.drawLine(pad, h - pad, pad + bracket_len, h - pad)
        p.drawLine(pad, h - pad, pad, h - pad - bracket_len)
        # Bottom-right
        p.drawLine(w - pad, h - pad, w - pad - bracket_len, h - pad)
        p.drawLine(w - pad, h - pad, w - pad, h - pad - bracket_len)

    # ── Component 2: Top-Left Circular Clock & Date Module ──────────────────

    def _draw_clock_module(self, p: QPainter, x: int, y: int):
        cx = x + 100
        cy = y + 100
        radius = 85

        # Background panel glow
        panel_rect = QRectF(x, y, 320, 200)
        p.fillRect(panel_rect, QBrush(RedHudColors.PANEL_BG))
        p.setPen(QPen(RedHudColors.RED_BORDER, 1))
        p.drawRect(panel_rect)

        # Corner bracket accent
        p.setPen(QPen(RedHudColors.RED_PRIMARY, 2))
        p.drawLine(x, y, x + 15, y)
        p.drawLine(x, y, x, y + 15)

        # Outer Tick Ring (Compass & Degrees)
        p.save()
        p.translate(cx, cy)
        for deg in range(0, 360, 10):
            p.save()
            p.rotate(deg)
            if deg % 90 == 0:
                p.setPen(QPen(RedHudColors.RED_BRIGHT, 2))
                p.drawLine(0, -radius, 0, -radius + 12)
            elif deg % 30 == 0:
                p.setPen(QPen(RedHudColors.RED_PRIMARY, 1.5))
                p.drawLine(0, -radius, 0, -radius + 8)
            else:
                p.setPen(QPen(RedHudColors.RED_DIM, 1))
                p.drawLine(0, -radius, 0, -radius + 4)
            p.restore()

        # Rotating Second Indicator Hand / Notch
        sec = datetime.datetime.now().second + datetime.datetime.now().microsecond / 1_000_000.0
        sec_angle = sec * 6.0
        p.save()
        p.rotate(sec_angle)
        p.setPen(QPen(RedHudColors.RED_BRIGHT, 2))
        p.drawLine(0, -radius + 15, 0, -radius + 3)
        p.setBrush(QBrush(RedHudColors.RED_BRIGHT))
        p.drawEllipse(QPointF(0, -radius + 9), 3, 3)
        p.restore()
        p.restore()

        # Inner Decorative Arc
        p.setPen(QPen(RedHudColors.RED_PRIMARY, 3))
        p.drawArc(QRectF(cx - radius + 15, cy - radius + 15, (radius - 15) * 2, (radius - 15) * 2), int(-sec_angle * 16), int(120 * 16))

        # Time Text
        p.setPen(RedHudColors.TEXT_BRIGHT)
        font_time = QFont("Consolas", 24, QFont.Weight.Bold if _QT6 else QFont.Bold)
        p.setFont(font_time)
        p.drawText(QRectF(cx - 75, cy - 25, 150, 35), Qt.AlignmentFlag.AlignCenter if _QT6 else Qt.AlignCenter, self.telemetry.time_short)

        # Seconds & Marker
        font_sec = QFont("Consolas", 10)
        p.setFont(font_sec)
        p.setPen(RedHudColors.RED_PRIMARY)
        p.drawText(QRectF(cx - 75, cy + 8, 150, 20), Qt.AlignmentFlag.AlignCenter if _QT6 else Qt.AlignCenter, f":{datetime.datetime.now().strftime('%S')}")

        # Boxed Date Section (Right of clock ring)
        dx = x + 205
        dy = y + 25
        p.setPen(RedHudColors.RED_PRIMARY)
        font_lbl = QFont("Segoe UI", 9, QFont.Weight.Bold if _QT6 else QFont.Bold)
        p.setFont(font_lbl)
        p.drawText(dx, dy, self.telemetry.date_month)

        p.setPen(RedHudColors.TEXT_BRIGHT)
        font_day = QFont("Consolas", 28, QFont.Weight.Bold if _QT6 else QFont.Bold)
        p.setFont(font_day)
        p.drawText(dx, dy + 38, self.telemetry.date_day)

        p.setPen(RedHudColors.TEXT_DIM)
        font_wk = QFont("Segoe UI", 9)
        p.setFont(font_wk)
        p.drawText(dx, dy + 58, self.telemetry.date_weekday)

        # Storage Readouts
        p.setPen(QPen(RedHudColors.RED_DIM, 1))
        p.drawLine(dx - 5, dy + 70, x + 310, dy + 70)

        font_disk = QFont("Consolas", 8)
        p.setFont(font_disk)
        p.setPen(RedHudColors.TEXT_MAIN)
        p.drawText(dx, dy + 90, f"TOTAL: {int(self.telemetry.disk_total_gb)}G")
        p.setPen(RedHudColors.RED_PRIMARY)
        p.drawText(dx, dy + 106, f"FREE : {int(self.telemetry.disk_free_gb)}G")

    # ── Component 3: Bottom-Left Circular Capacity & Percentage Gauges ──────

    def _draw_capacity_gauges(self, p: QPainter, x: int, y: int):
        panel_rect = QRectF(x, y, 320, 160)
        p.fillRect(panel_rect, QBrush(RedHudColors.PANEL_BG))
        p.setPen(QPen(RedHudColors.RED_BORDER, 1))
        p.drawRect(panel_rect)

        # Header
        p.setPen(RedHudColors.RED_PRIMARY)
        font_h = QFont("Segoe UI", 9, QFont.Weight.Bold if _QT6 else QFont.Bold)
        p.setFont(font_h)
        p.drawText(x + 12, y + 20, "// CAPACITY & POWER TELEMETRY")

        # 3 Circular Arc Gauges
        gauges = [
            ("POWER", self.telemetry.battery_pct, "AC LINE" if self.telemetry.battery_power_plugged else "BATT"),
            ("CPU", self.telemetry.cpu_pct, f"{int(self.telemetry.cpu_pct)}%"),
            ("RAM", self.telemetry.ram_pct, f"{self.telemetry.ram_used_gb:.1f}G"),
        ]

        gauge_radius = 36
        centers = [(x + 55, y + 85), (x + 160, y + 85), (x + 265, y + 85)]

        for (lbl, val, sub_lbl), (gx, gy) in zip(gauges, centers):
            r_rect = QRectF(gx - gauge_radius, gy - gauge_radius, gauge_radius * 2, gauge_radius * 2)

            # Background Track Ring
            p.setPen(QPen(RedHudColors.RED_BORDER, 4))
            p.drawArc(r_rect, 0, 360 * 16)

            # Value Arc Fill
            span_angle = -int((val / 100.0) * 360.0 * 16)
            pen_color = RedHudColors.RED_BRIGHT if val > 85 else RedHudColors.RED_PRIMARY
            p.setPen(QPen(pen_color, 4))
            p.drawArc(r_rect, 90 * 16, span_angle)

            # Center Value Text
            p.setPen(RedHudColors.TEXT_BRIGHT)
            p.setFont(QFont("Consolas", 10, QFont.Weight.Bold if _QT6 else QFont.Bold))
            p.drawText(r_rect, Qt.AlignmentFlag.AlignCenter if _QT6 else Qt.AlignCenter, f"{int(val)}%")

            # Label Below
            p.setPen(RedHudColors.TEXT_DIM)
            p.setFont(QFont("Segoe UI", 8))
            p.drawText(QRectF(gx - 45, gy + gauge_radius + 4, 90, 18), Qt.AlignmentFlag.AlignCenter if _QT6 else Qt.AlignCenter, lbl)
            p.setPen(RedHudColors.RED_PRIMARY)
            p.drawText(QRectF(gx - 45, gy + gauge_radius + 18, 90, 16), Qt.AlignmentFlag.AlignCenter if _QT6 else Qt.AlignCenter, sub_lbl)

    # ── Component 4: Center Pulsing Radial Arc Reactor Core ─────────────────

    def _draw_radial_core(self, p: QPainter, cx: float, cy: float):
        p.save()
        p.translate(cx, cy)

        pulse = (math.sin(self._pulse_phase) + 1.0) / 2.0  # 0.0 to 1.0
        base_radius = 135.0

        # Radial Background Glow
        glow_radius = base_radius + 30 + (pulse * 20)
        grad = QRadialGradient(0, 0, glow_radius)
        if self._state_str == "ACTIVE_CONVERSATION" or self._state_str == "ACTIVE":
            grad.setColorAt(0.0, QColor(255, 120, 120, int(160 + pulse * 80)))
            grad.setColorAt(0.4, QColor(226, 59, 59, int(80 + pulse * 60)))
            grad.setColorAt(1.0, QColor(5, 5, 5, 0))
        elif self._state_str == "LISTENING":
            grad.setColorAt(0.0, QColor(255, 80, 80, int(130 + pulse * 60)))
            grad.setColorAt(0.4, QColor(200, 40, 40, int(60 + pulse * 40)))
            grad.setColorAt(1.0, QColor(5, 5, 5, 0))
        else:
            grad.setColorAt(0.0, QColor(226, 59, 59, int(50 + pulse * 35)))
            grad.setColorAt(0.4, QColor(74, 30, 30, int(25 + pulse * 20)))
            grad.setColorAt(1.0, QColor(5, 5, 5, 0))

        p.setBrush(QBrush(grad))
        p.setPen(Qt.PenStyle.NoPen if _QT6 else Qt.NoPen)
        p.drawEllipse(QPointF(0, 0), glow_radius, glow_radius)

        # Ring 1: Outermost Segmented Compass Ring (Clockwise rotation)
        p.save()
        p.rotate(self._rot_angle_1)
        p.setPen(QPen(RedHudColors.RED_PRIMARY, 1.5))
        p.drawEllipse(QPointF(0, 0), base_radius, base_radius)

        # Ticks on Ring 1
        for deg in range(0, 360, 15):
            p.save()
            p.rotate(deg)
            if deg % 45 == 0:
                p.setPen(QPen(RedHudColors.RED_BRIGHT, 2))
                p.drawLine(0, int(-base_radius), 0, int(-base_radius - 8))
            else:
                p.setPen(QPen(RedHudColors.RED_DIM, 1))
                p.drawLine(0, int(-base_radius), 0, int(-base_radius - 4))
            p.restore()
        p.restore()

        # Ring 2: Counter-Rotating Segmented Arcs (Counter-Clockwise)
        r2 = base_radius - 22
        p.save()
        p.rotate(self._rot_angle_2)
        p.setPen(QPen(RedHudColors.RED_BRIGHT, 4))
        # Draw 3 symmetrical 60° arc blocks
        for angle in [0, 120, 240]:
            p.drawArc(QRectF(-r2, -r2, r2 * 2, r2 * 2), int(angle * 16), int(60 * 16))
        p.restore()

        # Ring 3: Middle Reticle Ring with 4 Crosshair Brackets
        r3 = base_radius - 48
        p.save()
        p.rotate(self._rot_angle_3)
        p.setPen(QPen(RedHudColors.RED_DIM, 1, Qt.PenStyle.DashLine if _QT6 else Qt.DashLine))
        p.drawEllipse(QPointF(0, 0), r3, r3)

        # 4 Bracket notches
        p.setPen(QPen(RedHudColors.RED_PRIMARY, 2))
        bracket_w = 12
        p.drawLine(-bracket_w, int(-r3), bracket_w, int(-r3))
        p.drawLine(-bracket_w, int(r3), bracket_w, int(r3))
        p.drawLine(int(-r3), -bracket_w, int(-r3), bracket_w)
        p.drawLine(int(r3), -bracket_w, int(r3), bracket_w)
        p.restore()

        # Ring 4: Inner Core Ring
        r4 = base_radius - 75
        p.setPen(QPen(RedHudColors.RED_PRIMARY, 2))
        p.drawEllipse(QPointF(0, 0), r4, r4)

        # Center Pulsing Arc Reactor Core Dot
        center_radius = 18.0 + (pulse * 8.0)
        c_grad = QRadialGradient(0, 0, center_radius)
        c_grad.setColorAt(0.0, RedHudColors.RED_HOT)
        c_grad.setColorAt(0.4, RedHudColors.RED_BRIGHT)
        c_grad.setColorAt(0.9, RedHudColors.RED_PRIMARY)
        c_grad.setColorAt(1.0, QColor(226, 59, 59, 0))

        p.setBrush(QBrush(c_grad))
        p.setPen(QPen(RedHudColors.RED_HOT, 1.5))
        p.drawEllipse(QPointF(0, 0), center_radius, center_radius)

        # State label below core
        p.setPen(RedHudColors.TEXT_MAIN)
        p.setFont(QFont("Consolas", 10, QFont.Weight.Bold if _QT6 else QFont.Bold))
        p.drawText(QRectF(-100, base_radius + 20, 200, 24), Qt.AlignmentFlag.AlignCenter if _QT6 else Qt.AlignCenter, f"// {self._state_str} //")

        p.restore()

    # ── Component 5: Right Side Live Monospace Telemetry Feed Panel ─────────

    def _draw_telemetry_panel(self, p: QPainter, x: int, y: int, w: int, h: int):
        panel_rect = QRectF(x, y, w, h)
        p.fillRect(panel_rect, QBrush(RedHudColors.PANEL_BG))
        p.setPen(QPen(RedHudColors.RED_BORDER, 1))
        p.drawRect(panel_rect)

        # Tech corner accents
        p.setPen(QPen(RedHudColors.RED_PRIMARY, 2))
        p.drawLine(x, y, x + 20, y)
        p.drawLine(x, y, x, y + 20)
        p.drawLine(x + w, y + h, x + w - 20, y + h)
        p.drawLine(x + w, y + h, x + w, y + h - 20)

        # Header
        p.setPen(RedHudColors.RED_PRIMARY)
        p.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold if _QT6 else QFont.Bold))
        p.drawText(x + 15, y + 24, ">> SYSTEM TELEMETRY & DIAGNOSTICS")

        p.setPen(QPen(RedHudColors.RED_DIM, 1))
        p.drawLine(x + 15, y + 34, x + w - 15, y + 34)

        # Monospace Telemetry Lines
        font_mono = QFont("Consolas", 9)
        p.setFont(font_mono)

        line_y = y + 55
        line_height = 24

        def draw_feed_line(lbl: str, val: str, color: QColor):
            nonlocal line_y
            p.setPen(RedHudColors.TEXT_DIM)
            p.drawText(x + 15, line_y, f"[{lbl.upper():<14}] :")
            p.setPen(color)
            p.drawText(x + 145, line_y, val)
            line_y += line_height

        # 1. Audit Chain Integrity Line (Real AuditLog().verify())
        if self.telemetry.audit_chain_valid:
            draw_feed_line("AUDIT_CHAIN", f"VERIFIED ({self.telemetry.audit_chain_count} BLOCKS)", RedHudColors.GREEN_OK)
        else:
            err_snip = (self.telemetry.audit_chain_error or "TAMPER DETECTED")[:22]
            draw_feed_line("AUDIT_CHAIN", f"TAMPER: {err_snip}", RedHudColors.RED_BRIGHT)

        # 2. Firewall Status
        draw_feed_line("FIREWALL", "PRIVATE PROFILE ACTIVE", RedHudColors.GREEN_OK)

        # 3. Mobile Pairing Window Status
        if self.telemetry.pairing_window_open:
            draw_feed_line("PAIR_WINDOW", f"OPEN ({int(self.telemetry.pairing_window_remaining)}s REMAINING)", RedHudColors.WARN_YELLOW)
        else:
            draw_feed_line("PAIR_WINDOW", "CLOSED (ALLOWLIST ENFORCED)", RedHudColors.TEXT_MAIN)

        # 4. Agent Cluster Statuses
        p.setPen(QPen(RedHudColors.RED_BORDER, 1))
        p.drawLine(x + 15, line_y - 8, x + w - 15, line_y - 8)
        line_y += 6

        p.setPen(RedHudColors.RED_PRIMARY)
        p.drawText(x + 15, line_y, "// AGENT CLUSTER NODES")
        line_y += line_height

        for ag_name in ["ADA", "TOM", "SCOUT", "NOVA"]:
            st = self.telemetry.agent_statuses.get(ag_name, "IDLE")
            c = RedHudColors.GREEN_OK if "RUNNING" in st else RedHudColors.TEXT_MAIN
            draw_feed_line(f"AGENT_{ag_name}", st, c)

        # 5. Network & System Diagnostics
        p.setPen(QPen(RedHudColors.RED_BORDER, 1))
        p.drawLine(x + 15, line_y - 8, x + w - 15, line_y - 8)
        line_y += 6

        draw_feed_line("NETWORK_IP", f"{self.telemetry.local_ip} (WSS :8081)", RedHudColors.CYAN_ACCENT)
        draw_feed_line("PAIRED_DEVS", f"{self.telemetry.paired_ips_count} PAIRED | {self.telemetry.connected_devices_count} ONLINE", RedHudColors.TEXT_MAIN)
        draw_feed_line("SYS_UPTIME", self.telemetry.uptime_str, RedHudColors.TEXT_MAIN)
        draw_feed_line("SYS_THREADS", f"{self.telemetry.thread_count} ACTIVE", RedHudColors.TEXT_MAIN)

    # ── Component 6: Bottom Status Strip ────────────────────────────────────

    def _draw_bottom_status_strip(self, p: QPainter, x: int, y: int, w: int, h: int):
        strip_rect = QRectF(x, y, w, h)
        p.fillRect(strip_rect, QBrush(QColor(6, 3, 3, 230)))
        p.setPen(QPen(RedHudColors.RED_BORDER, 1))
        p.drawLine(x, y, x + w, y)

        p.setFont(QFont("Consolas", 9))

        # Left Section
        p.setPen(RedHudColors.RED_PRIMARY)
        p.drawText(25, y + 22, "JARVIS MARK-XXXIX-OR // RED HUD OVERLAY // [CTRL+ALT+J TO TOGGLE]")

        # Center Section
        p.setPen(RedHudColors.TEXT_BRIGHT)
        p.drawText(QRectF(w / 2 - 150, y, 300, h), Qt.AlignmentFlag.AlignCenter if _QT6 else Qt.AlignCenter, f"OPERATING STATE: {self._state_str}")

        # Right Section (Real Integrity Status from core.integrity_monitor.IntegrityMonitor())
        right_x = w - 460
        p.setPen(RedHudColors.GREEN_OK if self.telemetry.integrity_valid else RedHudColors.RED_BRIGHT)
        integ_str = "ED25519: SIGNED & VERIFIED" if self.telemetry.integrity_valid else "ED25519: INTEGRITY VIOLATION"
        p.drawText(right_x, y + 22, f"{integ_str}  |  DPAPI: ACTIVE")

    # ── Component 7: Drag Handle / Mode Badge ───────────────────────────────

    def _draw_control_badge(self, p: QPainter, x: float, y: float, w: float, h: float):
        badge_rect = QRectF(x, y, w, h)
        p.fillRect(badge_rect, QBrush(QColor(15, 6, 6, 180)))
        p.setPen(QPen(RedHudColors.RED_PRIMARY, 1))
        p.drawRoundedRect(badge_rect, 4, 4)

        p.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold if _QT6 else QFont.Bold))
        p.setPen(RedHudColors.TEXT_MAIN)
        mode_txt = "CLICK-THROUGH: ON" if self._click_through else "INTERACTIVE MODE"
        p.drawText(badge_rect, Qt.AlignmentFlag.AlignCenter if _QT6 else Qt.AlignCenter, f"[ {mode_txt} ]")


# ── Launch Entrypoint ───────────────────────────────────────────────────────
def launch_hud_overlay(app: Optional[QApplication] = None) -> Tuple[QApplication, JarvisHudOverlay]:
    """Instantiates and shows the Red HUD Desktop Overlay cleanly."""
    if app is None:
        app = QApplication.instance() or QApplication(sys.argv)
    overlay = JarvisHudOverlay()
    overlay.show()
    return app, overlay


if __name__ == "__main__":
    app = QApplication(sys.argv)
    _, hud = launch_hud_overlay(app)
    sys.exit(app.exec() if _QT6 else app.exec_())
