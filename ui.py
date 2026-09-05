from __future__ import annotations

import json
import math
import os
import platform
import random
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

# ── Suppress CMD windows on Windows ─────────────────────────────────────────
_SUBPROCESS_FLAGS: dict = {}
if sys.platform == "win32":
    _SUBPROCESS_FLAGS["creationflags"] = subprocess.CREATE_NO_WINDOW
from types import ModuleType

import psutil

try:
    from PyQt6.QtCore import (  # type: ignore[import]
        QEasingCurve, QMimeData, QObject, QPointF, QRectF, QSize, Qt,
        QTimer, QUrl, pyqtSignal,
    )
    from PyQt6.QtGui import (  # type: ignore[import]
        QBrush, QColor, QDragEnterEvent, QDropEvent, QFont, QFontDatabase,
        QKeySequence, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap,
        QRadialGradient, QShortcut,
    )
    from PyQt6.QtWidgets import (  # type: ignore[import]
        QApplication, QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit,
        QMainWindow, QPushButton, QScrollArea, QSizePolicy, QSlider, QTextEdit,
        QVBoxLayout, QWidget, QProgressBar, QStackedWidget,
    )
    _QT6 = True
except ImportError:
    import importlib
    QtCore: ModuleType = importlib.import_module("PyQt5.QtCore")    # type: ignore[import]
    QtGui:  ModuleType = importlib.import_module("PyQt5.QtGui")     # type: ignore[import]
    QtWidgets: ModuleType = importlib.import_module("PyQt5.QtWidgets")  # type: ignore[import]

    QEasingCurve = QtCore.QEasingCurve
    QMimeData    = QtCore.QMimeData
    QObject      = QtCore.QObject
    QPointF      = QtCore.QPointF
    QRectF       = QtCore.QRectF
    QSize        = QtCore.QSize
    Qt           = QtCore.Qt
    QTimer       = QtCore.QTimer
    QUrl         = QtCore.QUrl
    pyqtSignal   = QtCore.pyqtSignal

    QBrush          = QtGui.QBrush
    QColor          = QtGui.QColor
    QDragEnterEvent = QtGui.QDragEnterEvent
    QDropEvent      = QtGui.QDropEvent
    QFont           = QtGui.QFont
    QFontDatabase   = QtGui.QFontDatabase
    QKeySequence    = QtGui.QKeySequence
    QLinearGradient = QtGui.QLinearGradient
    QPainter        = QtGui.QPainter
    QPainterPath    = QtGui.QPainterPath
    QPen            = QtGui.QPen
    QPixmap         = QtGui.QPixmap
    QRadialGradient = QtGui.QRadialGradient
    QShortcut       = QtWidgets.QShortcut

    QApplication  = QtWidgets.QApplication
    QFileDialog   = QtWidgets.QFileDialog
    QFrame        = QtWidgets.QFrame
    QHBoxLayout   = QtWidgets.QHBoxLayout
    QLabel        = QtWidgets.QLabel
    QLineEdit     = QtWidgets.QLineEdit
    QMainWindow   = QtWidgets.QMainWindow
    QPushButton   = QtWidgets.QPushButton
    QScrollArea   = QtWidgets.QScrollArea
    QSizePolicy   = QtWidgets.QSizePolicy
    QSlider       = QtWidgets.QSlider
    QTextEdit     = QtWidgets.QTextEdit
    QVBoxLayout   = QtWidgets.QVBoxLayout
    QWidget       = QtWidgets.QWidget
    QProgressBar  = QtWidgets.QProgressBar
    QStackedWidget = QtWidgets.QStackedWidget

    _QT6 = False


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent


BASE_DIR   = _base_dir()
CONFIG_DIR = BASE_DIR / "config"
API_FILE   = CONFIG_DIR / "api_keys.json"

DEFAULT_WAKE_SENSITIVITY = 0.7

_DEFAULT_W, _DEFAULT_H = 980, 700
_MIN_W,     _MIN_H     = 820, 580
_LEFT_W  = 148
_RIGHT_W = 340

_OS = platform.system()

if _OS == "Windows":
    _EMOJI_FONT = "Segoe UI Emoji"
elif _OS == "Darwin":
    _EMOJI_FONT = "Apple Color Emoji"
else:
    _EMOJI_FONT = "Noto Color Emoji"



# ── Stark Industries colour palette ─────────────────────────────────────────
class C:
    BG        = "#0E0F11"         # near-black background
    PANEL     = "#131519"         # panel background
    PANEL2    = "#161A1F"         # secondary panel
    BORDER    = "#2A2D33"         # subtle border
    BORDER_B  = "#3A3D45"         # stronger border
    GOLD      = "#C8922A"         # Stark gold — primary accent
    GOLD_DIM  = "#7A5618"         # dimmed gold
    GOLD_GHO  = "#1A1208"        # ghost gold (very dark)
    STEEL     = "#4A7FA5"         # steel blue — secondary accent
    STEEL_DIM = "#2A4F6A"         # dimmed steel
    GREEN     = "#3CB97A"         # agent TOM
    GREEN_D   = "#1A7A45"
    BLUE      = "#4A7FA5"         # agent SCOUT (same as steel)
    AMBER     = "#C8922A"         # agent ADA (same as gold)
    PINK      = "#C2587A"         # agent NOVA
    RED       = "#C24040"         # errors/alerts
    TEXT      = "#C8C0A8"         # warm off-white text
    TEXT_DIM  = "#6A6055"         # dimmed text
    TEXT_MED  = "#9A9080"         # medium text
    WHITE     = "#E8E0D0"         # bright warm white
    DARK      = "#08090B"         # darkest panels (header/footer)
    BAR_BG    = "#1A1C20"         # metric bar background
    SCANLINE  = "#000000"         # scanline overlay


def qcol(h: str, a: int = 255) -> QColor: # type: ignore
    c = QColor(h); c.setAlpha(a); return c


# ── System metrics (background thread) ──────────────────────────────────────
class _SysMetrics:
    def __init__(self):
        self.cpu  = 0.0
        self.mem  = 0.0
        self.net  = 0.0
        self.gpu  = -1.0
        self.tmp  = -1.0
        self._lock = threading.Lock()
        self._last_net   = psutil.net_io_counters()
        self._last_net_t = time.time()
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            try:
                self._update()
            except Exception:
                pass
            time.sleep(1.5)

    def _update(self):
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent

        nc  = psutil.net_io_counters()
        now = time.time()
        dt  = now - self._last_net_t
        if dt > 0:
            sent = (nc.bytes_sent - self._last_net.bytes_sent) / dt
            recv = (nc.bytes_recv - self._last_net.bytes_recv) / dt
            net  = (sent + recv) / (1024 * 1024)
        else:
            net = 0.0
        self._last_net   = nc
        self._last_net_t = now

        gpu = self._get_gpu()
        tmp = self._get_temp()

        with self._lock:
            self.cpu = cpu
            self.mem = mem
            self.net = net
            self.gpu = gpu
            self.tmp = tmp

    def _get_gpu(self) -> float:
        try:
            r = subprocess.run(
                ["nvidia-smi", "--query-gpu=utilization.gpu",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=2,
                **_SUBPROCESS_FLAGS
            )
            if r.returncode == 0:
                vals = [float(v.strip()) for v in r.stdout.strip().split("\n") if v.strip()]
                if vals:
                    return sum(vals) / len(vals)
        except Exception:
            pass
        if _OS == "Linux":
            try:
                r = subprocess.run(
                    ["rocm-smi", "--showuse", "--csv"],
                    capture_output=True, text=True, timeout=2,
                    **_SUBPROCESS_FLAGS
                )
                if r.returncode == 0:
                    for line in r.stdout.strip().split("\n"):
                        parts = line.split(",")
                        if len(parts) >= 2:
                            try:
                                return float(parts[1].strip().replace("%", ""))
                            except ValueError:
                                pass
            except Exception:
                pass
        return -1.0

    def _get_temp(self) -> float:
        try:
            temps = psutil.sensors_temperatures()
            candidates = ["coretemp", "k10temp", "cpu_thermal", "acpitz",
                          "cpu-thermal", "zenpower", "it8688"]
            for name in candidates:
                if name in temps and temps[name]:
                    return temps[name][0].current
            for entries in temps.values():
                if entries:
                    return entries[0].current
        except Exception:
            pass
        if _OS == "Windows":
            try:
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-CimInstance MSAcpi_ThermalZoneTemperature -Namespace root/wmi"
                     " | Select-Object -First 1 -ExpandProperty CurrentTemperature)"],
                    capture_output=True, text=True, timeout=3,
                    **_SUBPROCESS_FLAGS
                )
                if r.returncode == 0 and r.stdout.strip():
                    raw = float(r.stdout.strip().split("\n")[0])
                    return (raw / 10.0) - 273.15
            except Exception:
                pass
        return -1.0

    def snapshot(self) -> dict:
        with self._lock:
            return {"cpu": self.cpu, "mem": self.mem,
                    "net": self.net, "gpu": self.gpu, "tmp": self.tmp}


_metrics = _SysMetrics()


# ── Hologram wireframe geometry (built once at import time) ─────────────────
def _build_hologram_geometry():
    """
    Low-poly wireframe 'robot bust' in unit model space.
    y is down-positive (matches screen), x/z are the horizontal plane the
    figure rotates around (the Y / vertical axis).
    Returns (vertices, edges) — vertices: list[(x, y, z)], edges: list[(i, j)].
    """
    N = 8
    verts: list[tuple] = []
    edges: list[tuple] = []

    def add_ring(y: float, r: float) -> int:
        start = len(verts)
        for i in range(N):
            a = 2 * math.pi * i / N
            verts.append((r * math.cos(a), y, r * math.sin(a)))
        return start

    apex = len(verts); verts.append((0.0, -1.55, 0.0))      # crown
    up   = add_ring(-1.05, 0.55)                              # brow ring
    lo   = add_ring(-0.55, 0.62)                              # visor ring
    chin = len(verts); verts.append((0.0, -0.15, 0.0))       # chin point
    neck = len(verts); verts.append((0.0,  0.10, 0.0))       # neck point
    sh   = add_ring(0.55, 1.30)                               # shoulder ring
    ch   = add_ring(1.15, 1.05)                               # chest ring
    for i in range(N):
        j = (i + 1) % N
        edges.append((apex, up + i))
        edges.append((up + i, up + j))
        edges.append((up + i, lo + i))
        edges.append((lo + i, lo + j))
        edges.append((lo + i, chin))
        edges.append((neck, sh + i))
        edges.append((sh + i, sh + j))
        edges.append((sh + i, ch + i))
        edges.append((ch + i, ch + j))
    edges.append((chin, neck))
    return verts, edges


_HOLO_VERTS, _HOLO_EDGES = _build_hologram_geometry()

# ── Stark Industries HUD state theming palette ──────────────────────────────
_STATE_THEMES: dict[str, dict[str, Any]] = {
    "LISTENING": {
        "primary":     C.GREEN,       # Emerald / HUD Green
        "secondary":   C.STEEL,       # Steel Blue
        "glow":        C.GREEN_D,
        "speed":       0.018,
        "label":       "LISTENING",
        "symbol_on":   "●",
        "symbol_off":  "○",
    },
    "THINKING": {
        "primary":     C.STEEL,       # Arc Reactor Cyan / Steel Blue
        "secondary":   C.GOLD,        # Stark Gold
        "glow":        C.STEEL_DIM,
        "speed":       0.026,
        "label":       "THINKING",
        "symbol_on":   "◈",
        "symbol_off":  "◇",
    },
    "SPEAKING": {
        "primary":     C.GOLD,        # Stark Gold / Amber
        "secondary":   C.STEEL,       # Steel Blue
        "glow":        C.GOLD_DIM,
        "speed":       0.040,
        "label":       "SPEAKING",
        "symbol_on":   "▲",
        "symbol_off":  "△",
    },
    "ACTIVE_CONVERSATION": {
        "primary":     C.GOLD,        # Stark Gold
        "secondary":   C.GREEN,       # HUD Green
        "glow":        C.GOLD_DIM,
        "speed":       0.032,
        "label":       "ACTIVE CONVERSATION",
        "symbol_on":   "◉",
        "symbol_off":  "◎",
    },
    "ALERT": {
        "primary":     C.RED,         # Security Crimson
        "secondary":   C.PINK,        # Warning Pink
        "glow":        C.RED,
        "speed":       0.045,
        "label":       "SECURITY ALERT",
        "symbol_on":   "⚠",
        "symbol_off":  "!",
    },
    "CRITICAL": {
        "primary":     C.RED,         # Critical Alarm Red
        "secondary":   C.PINK,
        "glow":        C.RED,
        "speed":       0.050,
        "label":       "CRITICAL ALERT",
        "symbol_on":   "✖",
        "symbol_off":  "✕",
    },
    "SLEEPING": {
        "primary":     C.TEXT_DIM,    # Stealth dim amber/grey
        "secondary":   C.GOLD_GHO,
        "glow":        C.GOLD_GHO,
        "speed":       0.005,
        "label":       "SLEEPING",
        "symbol_on":   "☾",
        "symbol_off":  "·",
    },
    "OFFLINE": {
        "primary":     C.BORDER,      # Dark border / standby
        "secondary":   C.DARK,
        "glow":        C.DARK,
        "speed":       0.0,
        "label":       "OFFLINE",
        "symbol_on":   "■",
        "symbol_off":  "□",
    },
}

_HOLO_SPEED = {k: v["speed"] for k, v in _STATE_THEMES.items()}


# ── Rotating hologram (centre panel — replaces video) ────────────────────────
class HologramCanvas(QWidget):
    """
    A self-contained, code-drawn rotating holographic robot bust with
    Stark Industries HUD theming and real audio amplitude reactivity.
    No video files, no QtMultimedia — pure QPainter + trig.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background: #000000;")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._tick       = 0
        self._state      = "LISTENING"
        self._speaking   = False
        self._rings      = [0.0, 120.0, 240.0]
        self._arc_spin   = 0.0
        self._arc_inner  = 0.0
        self._halo       = 60.0
        self._tgt_halo   = 60.0
        self._last_t     = time.time()
        self._blink      = True
        self._blink_tick = 0
        self._rot        = 0.0

        # HUD Reticle, Radar & Chrome state
        self._reticle_rot_outer = 0.0
        self._reticle_rot_inner = 0.0
        self._sweep_angle       = 0.0
        self._frame_tick        = 0

        # Real voice-amplitude reactivity (0.0 - 1.0 RMS from mic / playback PCM stream)
        self._audio_level     = 0.0
        self._audio_level_t   = 0.0
        self._AUDIO_STALE_S   = 0.5

        # Floating holographic data particles
        self._particles = [self._new_particle() for _ in range(36)]

        # Glitch / flicker shader burst on major state transitions
        self._glitch_until = 0.0
        self._glitch_lines: list[tuple[float, float, float]] = []

        self._tmr = QTimer(self)
        self._tmr.timeout.connect(self._step)
        self._tmr.start(16)

    _GLITCH_ENTER_STATES = {"SPEAKING", "ALERT", "CRITICAL"}
    _GLITCH_EXIT_TO_OFFLINE = {"OFFLINE"}

    def get_theme(self) -> dict[str, Any]:
        """Returns the HUD visual theme dictionary for the current state."""
        st = self._state.upper()
        if st in _STATE_THEMES:
            return _STATE_THEMES[st]
        for key, th in _STATE_THEMES.items():
            if key in st:
                return th
        return {
            "primary":     C.GOLD,
            "secondary":   C.STEEL,
            "glow":        C.GOLD_DIM,
            "speed":       0.020,
            "label":       self._state,
            "symbol_on":   "●",
            "symbol_off":  "○",
        }

    def set_state(self, state: str):
        prev = self._state
        if state != prev:
            entering_speaking = state in self._GLITCH_ENTER_STATES
            going_offline = state in self._GLITCH_EXIT_TO_OFFLINE and prev != "OFFLINE"
            if entering_speaking or going_offline:
                self._trigger_glitch()
        self._state    = state
        self._speaking = (state == "SPEAKING")
        self._update_timer_rate()

    def _update_timer_rate(self):
        """Dynamic timer throttling: 16ms (60 FPS) when active, 50ms (20 FPS) when sleeping/offline."""
        target_interval = 50 if self._state in ("SLEEPING", "OFFLINE") else 16
        if self._tmr.interval() != target_interval:
            self._tmr.setInterval(target_interval)

    def _trigger_glitch(self):
        self._glitch_until = time.time() + 0.15
        self._glitch_lines = [
            (random.uniform(0.0, 1.0), random.uniform(0.01, 0.04), random.uniform(4, 18))
            for _ in range(5)
        ]

    def set_audio_level(self, level: float):
        """Called with real 0.0-1.0 RMS amplitude sample from live mic or speaker PCM stream."""
        self._audio_level   = max(0.0, min(1.0, level))
        self._audio_level_t = time.time()

    def _new_particle(self) -> dict:
        return {
            "x":     random.uniform(0.0, 1.0),
            "y":     random.uniform(0.0, 1.0),
            "vx":    random.uniform(-0.0006, 0.0006),
            "vy":    random.uniform(-0.0004, -0.0012),
            "r":     random.uniform(0.8, 2.2),
            "a":     random.uniform(40, 130),
            "drift": random.uniform(0.0, math.tau),
        }

    def _dim_factor(self) -> float:
        if self._state == "OFFLINE":
            return 0.25
        if self._state == "SLEEPING":
            return 0.4
        return 1.0

    def _step(self):
        self._tick += 1
        self._frame_tick = (self._frame_tick + 1) % 0x10000
        now = time.time()
        theme = self.get_theme()

        # Real audio RMS reactivity with gentle idle drift fallback
        audio_fresh = (now - self._audio_level_t) < self._AUDIO_STALE_S
        if audio_fresh and self._state in ("LISTENING", "SPEAKING", "ACTIVE_CONVERSATION", "ALERT", "CRITICAL"):
            lo, hi = (120, 220) if self._speaking else (45, 120)
            self._tgt_halo = lo + (hi - lo) * self._audio_level
            self._last_t = now
        elif now - self._last_t > (0.08 if self._speaking else 0.4):
            self._tgt_halo = random.uniform(120, 180) if self._speaking else random.uniform(45, 70)
            self._last_t = now
        self._halo += (self._tgt_halo - self._halo) * (0.35 if self._speaking else 0.12)

        # Dynamic ring & reticle rotation speeds based on audio level
        audio_boost = 1.0 + (self._audio_level * 1.5 if audio_fresh else 0.0)
        spd = [1.2 * audio_boost, -0.8 * audio_boost, 1.9 * audio_boost] if self._speaking else [0.5, -0.3, 0.8]
        for i, s in enumerate(spd):
            self._rings[i] = (self._rings[i] + s) % 360

        self._arc_spin  = (self._arc_spin  + (2.0 * audio_boost if self._speaking else 0.6)) % 360
        self._arc_inner = (self._arc_inner - (3.5 * audio_boost if self._speaking else 1.2)) % 360

        self._reticle_rot_outer = (self._reticle_rot_outer + (0.8 * audio_boost if self._speaking else 0.3)) % 360.0
        self._reticle_rot_inner = (self._reticle_rot_inner - (1.2 * audio_boost if self._speaking else 0.5)) % 360.0
        self._sweep_angle       = (self._sweep_angle + (3.0 * audio_boost if self._speaking else 1.5)) % 360.0

        rot_spd = theme.get("speed", 0.02)
        self._rot = (self._rot + rot_spd) % (2 * math.pi)

        self._blink_tick += 1
        if self._blink_tick >= 40:
            self._blink = not self._blink
            self._blink_tick = 0

        self._step_particles()
        self.update()

    def _step_particles(self):
        speed_mul = 2.2 if self._speaking else (1.4 if self._state == "THINKING" else 1.0)
        for pt in self._particles:
            pt["x"] += pt["vx"] * speed_mul
            pt["y"] += pt["vy"] * speed_mul
            pt["drift"] += 0.01
            pt["x"] += math.sin(pt["drift"]) * 0.00015
            if pt["y"] < -0.05 or pt["x"] < -0.05 or pt["x"] > 1.05:
                pt.update(self._new_particle())
                pt["y"] = 1.05

    def _draw_radar_sweep(self, p: "QPainter", cx: float, cy: float, fw: float, primary_col: str, dim: float):
        r_sweep = fw * 0.47
        p.setBrush(Qt.BrushStyle.NoBrush)
        for k in range(10):
            a_trail = (self._sweep_angle - k * 3.5) % 360.0
            alpha = int((28 * ((10 - k) / 10.0)) * dim)
            if alpha <= 0:
                continue
            rad = math.radians(a_trail)
            p.setPen(QPen(qcol(primary_col, alpha), 1.2))
            p.drawLine(QPointF(cx, cy), QPointF(cx + r_sweep * math.cos(rad), cy + r_sweep * math.sin(rad)))

        lead_rad = math.radians(self._sweep_angle)
        p.setPen(QPen(qcol(primary_col, int(95 * dim)), 1.4))
        p.drawLine(QPointF(cx, cy), QPointF(cx + r_sweep * math.cos(lead_rad), cy + r_sweep * math.sin(lead_rad)))

    def _draw_audio_spectrum(self, p: "QPainter", cx: float, cy: float, fw: float, primary_col: str, secondary_col: str, dim: float, audio_fresh: bool, audio_boost: float):
        r_base = fw * 0.31
        num_bars = 36
        p.setBrush(Qt.BrushStyle.NoBrush)

        for i in range(num_bars):
            deg = (i * (360.0 / num_bars) + self._arc_spin * 0.15) % 360.0
            rad = math.radians(deg)
            ca, sa = math.cos(rad), math.sin(rad)

            harmonic = 0.5 + 0.5 * math.sin(i * 0.8 + self._tick * 0.12)
            bar_len = (1.5 + 14.0 * audio_boost * harmonic) if audio_fresh else (1.5 + 2.0 * harmonic)

            alpha_bar = int((50 + 180 * (audio_boost if audio_fresh else 0.2)) * dim)
            p.setPen(QPen(qcol(primary_col, alpha_bar), 1.5))
            p.drawLine(QPointF(cx + r_base * ca, cy + r_base * sa),
                       QPointF(cx + (r_base + bar_len) * ca, cy + (r_base + bar_len) * sa))

            if audio_boost > 0.3 and harmonic > 0.7:
                p.setPen(QPen(qcol(secondary_col, int(220 * dim)), 1.8))
                p.drawPoint(QPointF(cx + (r_base + bar_len + 2.0) * ca, cy + (r_base + bar_len + 2.0) * sa))

    def _draw_hud_reticles(self, p: "QPainter", cx: float, cy: float, fw: float, primary_col: str, secondary_col: str, dim: float, audio_boost: float):
        # 1. Outer calibrated degree ring
        r_deg = fw * 0.485
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(qcol(primary_col, int(45 * dim)), 0.8))
        p.drawEllipse(QRectF(cx - r_deg, cy - r_deg, r_deg * 2, r_deg * 2))

        # Degree marks every 10 degrees, with major ticks and cardinal text
        p.setFont(QFont("Consolas", 6))
        for deg in range(0, 360, 10):
            rad = math.radians(deg)
            cos_a = math.cos(rad)
            sin_a = math.sin(rad)
            is_cardinal = (deg % 90 == 0)
            is_major = (deg % 30 == 0)

            tick_len = (10.0 if is_cardinal else (6.0 if is_major else 3.5)) + 2.0 * audio_boost
            r1 = r_deg
            r2 = r_deg - tick_len
            alpha = int((200 if is_cardinal else (120 if is_major else 50)) * dim)
            p.setPen(QPen(qcol(primary_col, alpha), 1.2 if is_cardinal else 0.8))
            p.drawLine(QPointF(cx + r1 * cos_a, cy + r1 * sin_a),
                       QPointF(cx + r2 * cos_a, cy + r2 * sin_a))

            if is_cardinal:
                labels = {0: "090", 90: "180", 180: "270", 270: "000"}
                lbl = labels.get(deg, f"{deg:03d}")
                lr = r_deg - 16.0
                p.setPen(QPen(qcol(secondary_col, int(220 * dim)), 1))
                p.drawText(QRectF(cx + lr * cos_a - 14, cy + lr * sin_a - 6, 28, 12),
                           Qt.AlignmentFlag.AlignCenter, lbl)

        # 2. Counter-rotating segmented orbital arcs
        r_orb1 = fw * (0.435 + 0.015 * audio_boost)
        r_orb2 = fw * (0.395 + 0.010 * audio_boost)

        # Outer orbital arc (4 segments of 45 deg)
        p.setPen(QPen(qcol(primary_col, int(110 * dim)), 1.4 + 0.6 * audio_boost))
        for i in range(4):
            start_a = (self._reticle_rot_outer + i * 90) % 360
            p.drawArc(QRectF(cx - r_orb1, cy - r_orb1, r_orb1 * 2, r_orb1 * 2),
                      int(start_a * 16), int(45 * 16))

        # Inner orbital arc (3 segments of 60 deg)
        p.setPen(QPen(qcol(secondary_col, int(90 * dim)), 1.0))
        for i in range(3):
            start_a = (self._reticle_rot_inner + i * 120) % 360
            p.drawArc(QRectF(cx - r_orb2, cy - r_orb2, r_orb2 * 2, r_orb2 * 2),
                      int(start_a * 16), int(60 * 16))

        # 3. Precision crosshair targeting reticles
        ch_in = fw * 0.16
        ch_out = fw * 0.46
        p.setPen(QPen(qcol(primary_col, int(60 * dim)), 0.8))
        for angle in (0, 90, 180, 270):
            rad = math.radians(angle)
            ca, sa = math.cos(rad), math.sin(rad)
            p.drawLine(QPointF(cx + ch_in * ca, cy + ch_in * sa),
                       QPointF(cx + ch_out * ca, cy + ch_out * sa))
            pip_r = ch_out + 3.0
            p.setPen(QPen(qcol(secondary_col, int(150 * dim)), 1.2))
            p.drawPoint(QPointF(cx + pip_r * ca, cy + pip_r * sa))
            p.setPen(QPen(qcol(primary_col, int(60 * dim)), 0.8))

    def _draw_arc_reactor(self, p: "QPainter", cx: float, cy: float, fw: float, primary_col: str, secondary_col: str, dim: float, audio_boost: float):
        r_core = fw * (0.13 + 0.05 * audio_boost)

        # 1. Outer magnetic confinement coil ring (12 coil segments)
        p.setBrush(Qt.BrushStyle.NoBrush)
        for i in range(12):
            deg = self._arc_spin + i * 30
            rad = math.radians(deg)
            ca, sa = math.cos(rad), math.sin(rad)
            p.setPen(QPen(qcol(primary_col, int(170 * dim)), 1.6 + 0.8 * audio_boost))
            p.drawLine(QPointF(cx + (r_core * 0.88) * ca, cy + (r_core * 0.88) * sa),
                       QPointF(cx + (r_core * 1.12) * ca, cy + (r_core * 1.12) * sa))

        # 2. Segmented concentric confinement rings
        p.setPen(QPen(qcol(primary_col, int(210 * dim)), 2.0 + 1.2 * audio_boost))
        for i in range(6):
            a_start = (self._arc_spin + i * 60) % 360
            p.drawArc(QRectF(cx - r_core, cy - r_core, r_core * 2, r_core * 2),
                      int(a_start * 16), int(36 * 16))

        # 3. Rotating inner geometric containment core (Triangular polygon)
        pts_t = []
        r_tri = r_core * (0.58 + 0.08 * audio_boost)
        for i in range(3):
            a = math.radians(self._arc_inner + i * 120)
            pts_t.append(QPointF(cx + r_tri * math.cos(a),
                                 cy + r_tri * math.sin(a)))
        p.setPen(QPen(qcol(secondary_col, int(220 * dim)), 1.8 + 0.8 * audio_boost))
        for i in range(3):
            p.drawLine(pts_t[i], pts_t[(i+1) % 3])

        # Core vertex nodes
        p.setBrush(QBrush(qcol(secondary_col, int(240 * dim))))
        p.setPen(Qt.PenStyle.NoPen)
        for pt in pts_t:
            p.drawEllipse(pt, 2.2 + 1.0 * audio_boost, 2.2 + 1.0 * audio_boost)

        # 4. Central luminous core emitter gradient
        cg_r = r_core * (0.45 + 0.15 * audio_boost)
        cg = QRadialGradient(cx, cy, cg_r)
        cg.setColorAt(0.0, qcol(primary_col, int(255 * dim)))
        cg.setColorAt(0.45, qcol(primary_col, int(150 * dim)))
        cg.setColorAt(1.0, qcol(primary_col, 0))
        p.setBrush(QBrush(cg))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QRectF(cx - cg_r, cy - cg_r, cg_r * 2, cg_r * 2))

    def _draw_corner_telemetry(self, p: "QPainter", W: float, H: float, fw: float, primary_col: str, secondary_col: str, dim: float, audio_fresh: bool, audio_boost: float, theme: dict):
        # Framing corner brackets
        bl = 24
        margin = max(14.0, fw * 0.035)
        hl = margin
        hr = W - margin
        ht = margin
        hb = H - margin
        bc = qcol(primary_col, int(180 * dim))
        p.setPen(QPen(bc, 1.8))
        p.setBrush(Qt.BrushStyle.NoBrush)
        for bx, by, dx, dy in [(hl, ht, 1, 1), (hr, ht, -1, 1),
                               (hl, hb, 1, -1), (hr, hb, -1, -1)]:
            p.drawLine(QPointF(bx, by), QPointF(bx + dx * bl, by))
            p.drawLine(QPointF(bx, by), QPointF(bx, by + dy * bl))
            p.fillRect(QRectF(bx + dx * 4 - 1, by + dy * 4 - 1, 3, 3), qcol(secondary_col, int(200 * dim)))

        # Monospace HUD telemetry font
        p.setFont(QFont("Consolas", 8))
        alpha_pri = int(200 * dim)
        alpha_sec = int(140 * dim)
        line_h = 13

        # Top-Left Telemetry
        tl_x = hl + 8
        tl_y = ht + 6
        p.setPen(QPen(qcol(primary_col, alpha_pri), 1))
        p.drawText(QPointF(tl_x, tl_y + line_h * 1), "SYS.LOC // MK-XXXIX")
        p.setPen(QPen(qcol(secondary_col, alpha_sec), 1))
        p.drawText(QPointF(tl_x, tl_y + line_h * 2), "CORE: ONLINE [SECURE]")
        p.drawText(QPointF(tl_x, tl_y + line_h * 3), "LINK: GEMINI-LIVE 2.0")

        # Top-Right Telemetry
        tr_w = 150
        tr_x = hr - tr_w - 8
        tr_y = ht + 6
        p.setPen(QPen(qcol(primary_col, alpha_pri), 1))
        p.drawText(QRectF(tr_x, tr_y, tr_w, line_h), Qt.AlignmentFlag.AlignRight, f"TICK: 0x{self._frame_tick:04X}")
        p.setPen(QPen(qcol(secondary_col, alpha_sec), 1))
        p.drawText(QRectF(tr_x, tr_y + line_h, tr_w, line_h), Qt.AlignmentFlag.AlignRight, f"STATUS: {theme['label']}")
        p.drawText(QRectF(tr_x, tr_y + line_h * 2, tr_w, line_h), Qt.AlignmentFlag.AlignRight, "SEC: FAIL-CLOSED")

        # Bottom-Left Telemetry
        bl_x = hl + 8
        bl_y = hb - line_h * 3 - 4
        db_txt = f"{20 * math.log10(max(0.001, self._audio_level)):+.1f} dB" if (audio_fresh and self._audio_level > 0.01) else "-INF dB"
        p.setPen(QPen(qcol(primary_col, alpha_pri), 1))
        p.drawText(QPointF(bl_x, bl_y + line_h * 1), f"AUDIO IN: {int(self._audio_level * 100):02d}%")
        p.setPen(QPen(qcol(secondary_col, alpha_sec), 1))
        p.drawText(QPointF(bl_x, bl_y + line_h * 2), f"RMS: {db_txt}")
        p.drawText(QPointF(bl_x, bl_y + line_h * 3), f"GATE: {'PASS' if audio_boost > 0.05 else 'IDLE'}")

        # Bottom-Right Telemetry
        br_w = 140
        br_x = hr - br_w - 8
        br_y = hb - line_h * 3 - 4
        p.setPen(QPen(qcol(primary_col, alpha_pri), 1))
        p.drawText(QRectF(br_x, br_y, br_w, line_h), Qt.AlignmentFlag.AlignRight, "SENTINEL: ARMED")
        p.setPen(QPen(qcol(secondary_col, alpha_sec), 1))
        p.drawText(QRectF(br_x, br_y + line_h, br_w, line_h), Qt.AlignmentFlag.AlignRight, "INTEGRITY: OK")
        p.drawText(QRectF(br_x, br_y + line_h * 2, br_w, line_h), Qt.AlignmentFlag.AlignRight, "AUDIT: VERIFIED")

    def _draw_wireframe(self, p: "QPainter", cx: float, cy: float, fw: float, primary_col: str, secondary_col: str): # type: ignore
        scale = fw * 0.27
        focal = 4.2
        ct, st = math.cos(self._rot), math.sin(self._rot)
        dim    = self._dim_factor()
        audio_boost = self._audio_level if (time.time() - self._audio_level_t) < self._AUDIO_STALE_S else 0.0

        pts2d, depth = [], []
        for (x, y, z) in _HOLO_VERTS:
            rx = x * ct + z * st
            rz = -x * st + z * ct
            factor = focal / (focal - rz)
            pts2d.append((cx + rx * scale * factor, cy + y * scale * factor))
            depth.append(rz)

        order = sorted(
            range(len(_HOLO_EDGES)),
            key=lambda k: (depth[_HOLO_EDGES[k][0]] + depth[_HOLO_EDGES[k][1]]) * 0.5,
        )
        for k in order:
            i, j = _HOLO_EDGES[k]
            d = (depth[i] + depth[j]) * 0.5
            t = max(0.0, min(1.0, (d + 1.3) / 2.6))
            alpha = int((40 + 180 * t) * dim)
            line_w = (1.4 + 1.2 * audio_boost) if t > 0.5 else (1.0 + 0.6 * audio_boost)
            p.setPen(QPen(qcol(primary_col, alpha), line_w))
            p.drawLine(QPointF(*pts2d[i]), QPointF(*pts2d[j]))

        for idx, (sx, sy) in enumerate(pts2d):
            t = max(0.0, min(1.0, (depth[idx] + 1.3) / 2.6))
            if t > 0.78:
                a = int(220 * dim)
                p.setPen(QPen(qcol(secondary_col, a), 1))
                p.setBrush(QBrush(qcol(secondary_col, a)))
                node_r = 1.6 + 1.0 * audio_boost
                p.drawEllipse(QPointF(sx, sy), node_r, node_r)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H = self.width(), self.height()
        cx, cy = W / 2.0, H / 2.0
        fw = min(W, H)
        theme = self.get_theme()
        primary_col   = theme["primary"]
        secondary_col = theme["secondary"]
        dim = self._dim_factor()
        now = time.time()
        audio_fresh = (now - self._audio_level_t) < self._AUDIO_STALE_S
        audio_boost = self._audio_level if audio_fresh else 0.0

        # Background
        p.fillRect(self.rect(), QColor(C.BG))

        # Faint hex grid background
        size = 28
        dx   = size * math.sqrt(3)
        dy   = size * 1.5
        cols = int(W / dx) + 3
        rows = int(H / dy) + 3
        pen_hex = QPen(qcol(primary_col, int(12 * dim)), 0.6)
        p.setPen(pen_hex); p.setBrush(Qt.BrushStyle.NoBrush)
        for row in range(-1, rows):
            for col in range(-1, cols):
                cx2 = col * dx + (size * math.sqrt(3) / 2 if row % 2 else 0)
                cy2 = row * dy
                path = QPainterPath()
                first = True
                for i in range(6):
                    a = math.radians(60 * i - 30)
                    px2 = cx2 + size * 0.85 * math.cos(a)
                    py2 = cy2 + size * 0.85 * math.sin(a)
                    if first:
                        path.moveTo(px2, py2); first = False
                    else:
                        path.lineTo(px2, py2)
                path.closeSubpath()
                p.drawPath(path)

        # Floating data particles
        p.setPen(Qt.PenStyle.NoPen)
        for pt in self._particles:
            px = pt["x"] * W
            py = pt["y"] * H
            a  = int(pt["a"] * dim)
            p.setBrush(QBrush(qcol(primary_col, a)))
            p.drawEllipse(QPointF(px, py), pt["r"], pt["r"])

        # Outer glow (scaled by real audio amplitude)
        grad_r = fw * (0.55 + 0.12 * audio_boost)
        grad = QRadialGradient(cx, cy, grad_r)
        grad.setColorAt(0.0, qcol(primary_col, int(self._halo * 0.5)))
        grad.setColorAt(0.4, qcol(primary_col, int(self._halo * 0.15)))
        grad.setColorAt(1.0, qcol(primary_col, 0))
        p.setBrush(QBrush(grad)); p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QRectF(cx - grad_r, cy - grad_r, grad_r * 2, grad_r * 2))

        # HUD Targeting Reticles (degree marks, counter-rotating orbital arcs, crosshairs)
        self._draw_hud_reticles(p, cx, cy, fw, primary_col, secondary_col, dim, audio_boost)

        # Radar scanline sweep beam
        self._draw_radar_sweep(p, cx, cy, fw, primary_col, dim)

        # Circular oscilloscope / audio spectrum radiating around orbital perimeter
        self._draw_audio_spectrum(p, cx, cy, fw, primary_col, secondary_col, dim, audio_fresh, audio_boost)

        # Spinning hologram rings (projection halo)
        ring_specs = [(0.44, 3.0, 90, 65), (0.36, 2.0, 65, 48), (0.28, 1.3, 45, 32)]
        for idx, (r_frac, w_r, arc_l, gap) in enumerate(ring_specs):
            ring_r = fw * (r_frac + 0.03 * audio_boost * (idx + 1))
            base   = self._rings[idx]
            a_val  = max(0, min(255, int(self._halo * (1.0 - idx * 0.2))))
            col    = qcol(primary_col, a_val)
            p.setPen(QPen(col, w_r + 0.8 * audio_boost)); p.setBrush(Qt.BrushStyle.NoBrush)
            angle = base
            rect  = QRectF(cx - ring_r, cy - ring_r, ring_r * 2, ring_r * 2)
            while angle < base + 360:
                p.drawArc(rect, int(angle * 16), int(arc_l * 16))
                angle += arc_l + gap

        # Scan arcs
        sr = fw * 0.46
        sa = min(255, int(self._halo * 1.5))
        p.setPen(QPen(qcol(primary_col, sa), 2.2 + 1.0 * audio_boost))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawArc(QRectF(cx-sr, cy-sr, sr*2, sr*2),
                  int(self._arc_spin * 16), int(70 * 16))
        p.setPen(QPen(qcol(secondary_col, sa // 2), 1.4))
        p.drawArc(QRectF(cx-sr, cy-sr, sr*2, sr*2),
                  int(((self._arc_spin + 180) % 360) * 16), int(50 * 16))

        # Arc Reactor Core power source (pulsing with audio amplitude)
        self._draw_arc_reactor(p, cx, cy, fw, primary_col, secondary_col, dim, audio_boost)

        # Rotating wireframe robot bust — the hologram itself
        self._draw_wireframe(p, cx, cy, fw, primary_col, secondary_col)

        # Corner HUD framing & diagnostic telemetry readouts
        self._draw_corner_telemetry(p, W, H, fw, primary_col, secondary_col, dim, audio_fresh, audio_boost, theme)

        # State label & symbol
        sy = cy + fw * 0.40
        sym = theme["symbol_on"] if self._blink else theme["symbol_off"]
        txt = f"{sym}  {theme['label']}"
        if audio_fresh and self._audio_level > 0.05 and self._state in ("LISTENING", "SPEAKING", "ACTIVE_CONVERSATION"):
            db_approx = int(20 * math.log10(max(0.001, self._audio_level)))
            txt += f"  [{db_approx} dB]"

        p.setOpacity(1.0)
        p.setPen(QPen(qcol(primary_col, int(255 * dim)), 1))
        p.setFont(QFont("Courier New", 11, QFont.Weight.Bold))
        p.drawText(QRectF(0, sy, W, 26), Qt.AlignmentFlag.AlignCenter, txt)

        # Glitch / flicker shader burst on major state transitions
        if time.time() < self._glitch_until:
            for (y_frac, h_frac, offset) in self._glitch_lines:
                gy = y_frac * H
                gh = max(1.0, h_frac * H)
                p.setOpacity(0.5)
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(QBrush(qcol(secondary_col, 90)))
                p.drawRect(QRectF(offset, gy, W, gh))
                p.setBrush(QBrush(qcol(primary_col, 70)))
                p.drawRect(QRectF(-offset, gy + gh * 0.4, W, gh * 0.6))
            p.setOpacity(1.0)

        # Scanline overlay
        p.setOpacity(0.04)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(QColor(0, 0, 0)))
        y = 0
        while y < H:
            p.drawRect(0, y, W, 1)
            y += 3
        p.setOpacity(1.0)


# ── Metric bar ────────────────────────────────────────────────────────────────
class MetricBar(QWidget):

    def __init__(self, label: str, color: str = C.GOLD, parent=None):
        super().__init__(parent)
        self._label = label
        self._color = color
        self._value = 0.0
        self._text  = "--"
        self.setFixedHeight(36)
        self.setMinimumWidth(80)

    def set_value(self, pct: float, text: str):
        self._value = max(0.0, min(100.0, pct))
        self._text  = text
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H = self.width(), self.height()

        p.setBrush(QBrush(qcol(C.PANEL2)))
        p.setPen(QPen(qcol(C.BORDER), 1))
        p.drawRoundedRect(QRectF(1, 1, W - 2, H - 2), 3, 3)

        bar_h  = 3
        bar_y  = H - bar_h - 5
        bar_w  = W - 14
        bar_x  = 7
        fill_w = int(bar_w * self._value / 100)

        p.setBrush(QBrush(qcol(C.BAR_BG)))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(QRectF(bar_x, bar_y, bar_w, bar_h), 1, 1)

        if self._value > 85:
            bar_col = qcol(C.RED)
        elif self._value > 65:
            bar_col = qcol(C.AMBER)
        else:
            bar_col = qcol(self._color)

        if fill_w > 0:
            p.setBrush(QBrush(bar_col))
            p.drawRoundedRect(QRectF(bar_x, bar_y, fill_w, bar_h), 1, 1)

        p.setFont(QFont("Arial", 7, QFont.Weight.Bold))
        p.setPen(QPen(qcol(C.TEXT_DIM), 1))
        p.drawText(QRectF(8, 4, 50, 14),
                   Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                   self._label)

        p.setFont(QFont("Arial", 8, QFont.Weight.Bold))
        p.setPen(QPen(bar_col if self._text != "--" else qcol(C.TEXT_DIM), 1))
        p.drawText(QRectF(0, 3, W - 7, 16),
                   Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                   self._text)


# ── Log widget ────────────────────────────────────────────────────────────────
# Colour-coded: SYS=steel blue, YOU=warm white, JARVIS=gold, TOM=green,
# SCOUT=blue, ADA=amber, NOVA=pink, WRN=amber, ERR=red
class LogWidget(QTextEdit):
    _sig = pyqtSignal(str)

    _COLOR_MAP = {
        "you":    "#E8E0D0",   # warm white
        "jarvis": "#C8922A",   # gold
        "sys":    "#4A7FA5",   # steel blue
        "err":    "#C24040",   # red
        "wrn":    "#C8922A",   # amber/gold
        "file":   "#3CB97A",   # green
        "tom":    "#3CB97A",   # green
        "scout":  "#4A7FA5",   # blue
        "ada":    "#C8922A",   # amber
        "nova":   "#C2587A",   # pink
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Courier New", 9))
        self.setStyleSheet(f"""
            QTextEdit {{
                background: {C.PANEL};
                color: {C.TEXT};
                border: 1px solid {C.BORDER};
                border-radius: 3px;
                padding: 6px;
                selection-background-color: {C.GOLD_GHO};
            }}
            QScrollBar:vertical {{
                background: {C.DARK};
                width: 6px;
                border: none;
            }}
            QScrollBar::handle:vertical {{
                background: {C.GOLD_DIM};
                border-radius: 3px;
                min-height: 20px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
        """)
        self._queue: list[str] = []
        self._typing = False
        self._text   = ""
        self._pos    = 0
        self._tag    = "sys"
        self._tmr    = QTimer(self)
        self._tmr.timeout.connect(self._step)
        self._sig.connect(self._enqueue)

    def write_log(self, text: str):
        self._sig.emit(text)

    def append_log(self, text: str):
        self._sig.emit(text)

    def _enqueue(self, text: str):
        self._queue.append(text)
        if not self._typing:
            self._next()

    def _next(self):
        if not self._queue:
            self._typing = False
            return
        self._typing = True
        self._text   = self._queue.pop(0)
        self._pos    = 0
        tl = self._text.lower()
        if   tl.startswith("you:"):    self._tag = "you"
        elif tl.startswith("jarvis:"): self._tag = "jarvis"
        elif tl.startswith("tom:"):    self._tag = "tom"
        elif tl.startswith("scout:"):  self._tag = "scout"
        elif tl.startswith("ada:"):    self._tag = "ada"
        elif tl.startswith("nova:"):   self._tag = "nova"
        elif tl.startswith("wrn:") or "warning" in tl: self._tag = "wrn"
        elif tl.startswith("err:") or "error" in tl:   self._tag = "err"
        elif tl.startswith("file:"):   self._tag = "file"
        else:                          self._tag = "sys"
        self._tmr.start(5)

    def _step(self):
        if self._pos < len(self._text):
            ch  = self._text[self._pos]
            cur = self.textCursor()
            fmt = cur.charFormat()
            hex_col = self._COLOR_MAP.get(self._tag, C.TEXT)
            fmt.setForeground(QBrush(QColor(hex_col)))
            cur.movePosition(cur.MoveOperation.End)
            cur.insertText(ch, fmt)
            self.setTextCursor(cur)
            self.ensureCursorVisible()
            self._pos += 1
        else:
            self._tmr.stop()
            cur = self.textCursor()
            cur.movePosition(cur.MoveOperation.End)
            cur.insertText("\n")
            self.setTextCursor(cur)
            self.ensureCursorVisible()
            QTimer.singleShot(15, self._next)


# ── File drop zone ────────────────────────────────────────────────────────────
_FILE_ICONS = {
    "image":   ("🖼", C.STEEL), "video": ("🎬", C.GOLD),
    "audio":   ("🎵", C.PINK), "pdf":   ("📄", C.RED),
    "word":    ("📝", C.STEEL), "excel": ("📊", C.GREEN),
    "code":    ("💻", C.GOLD), "archive": ("📦", C.AMBER),
    "pptx":   ("📊", C.GOLD), "text":  ("📃", C.TEXT_MED),
    "data":   ("🔧", C.STEEL), "unknown": ("📎", C.TEXT_DIM),
}
_EXT_TO_CAT = {
    **dict.fromkeys(["jpg","jpeg","png","gif","webp","bmp","tiff","svg","ico"], "image"),
    **dict.fromkeys(["mp4","avi","mov","mkv","wmv","flv","webm","m4v"],         "video"),
    **dict.fromkeys(["mp3","wav","ogg","m4a","aac","flac","wma","opus"],        "audio"),
    **dict.fromkeys(["pdf"],                                                     "pdf"),
    **dict.fromkeys(["doc","docx"],                                             "word"),
    **dict.fromkeys(["xls","xlsx","ods"],                                       "excel"),
    **dict.fromkeys(["ppt","pptx"],                                             "pptx"),
    **dict.fromkeys(["py","js","ts","jsx","tsx","html","css","java","c","cpp",
                     "cs","go","rs","rb","php","swift","kt","sh","sql","lua"],   "code"),
    **dict.fromkeys(["zip","rar","tar","gz","7z","bz2","xz"],                   "archive"),
    **dict.fromkeys(["txt","md","rst","log"],                                   "text"),
    **dict.fromkeys(["csv","tsv","json","xml"],                                  "data"),
}


def _file_category(path: Path) -> str:
    return _EXT_TO_CAT.get(path.suffix.lower().lstrip("."), "unknown")


def _fmt_size(size: int) -> str:
    if   size < 1024:    return f"{size} B"
    elif size < 1024**2: return f"{size/1024:.1f} KB"
    elif size < 1024**3: return f"{size/1024**2:.1f} MB"
    else:                return f"{size/1024**3:.1f} GB"


class FileDropZone(QWidget):
    file_selected = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(90)
        self._current_file: str | None = None
        self._hovering   = False
        self._drag_over  = False
        self._dash_off   = 0.0
        self._anim_tmr   = QTimer(self)
        self._anim_tmr.timeout.connect(self._animate)
        self._anim_tmr.start(45)

    def _animate(self):
        self._dash_off = (self._dash_off + 0.7) % 20
        self.update()

    def dragEnterEvent(self, e):
        if e is not None and e.mimeData().hasUrls():
            e.acceptProposedAction()
            self._drag_over = True; self.update()

    def dragLeaveEvent(self, e):
        self._drag_over = False; self.update()

    def dropEvent(self, e):
        self._drag_over = False
        if e is not None:
            urls = e.mimeData().urls()
            if urls:
                path = urls[0].toLocalFile()
                if path and Path(path).is_file():
                    self._set_file(path)
        self.update()

    def mousePressEvent(self, e):
        if e is not None:
            if self._current_file and e.pos().x() > self.width() - 34:
                self.clear_file()
            elif e.button() == Qt.MouseButton.LeftButton:
                self._browse()

    def enterEvent(self, e):
        self._hovering = True; self.update()

    def leaveEvent(self, e):
        self._hovering = False; self.update()

    def current_file(self) -> str | None:
        return self._current_file

    def clear_file(self):
        self._current_file = None; self.update()

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select file for JARVIS", str(Path.home()),
            "All Files (*.*);;"
            "Images (*.jpg *.jpeg *.png *.gif *.webp *.bmp *.svg);;"
            "Documents (*.pdf *.docx *.txt *.md *.pptx);;"
            "Data (*.csv *.xlsx *.json *.xml);;"
            "Code (*.py *.js *.ts *.html *.css *.java *.cpp *.go);;"
            "Audio (*.mp3 *.wav *.ogg *.m4a *.aac *.flac);;"
            "Video (*.mp4 *.avi *.mov *.mkv *.wmv *.webm);;"
            "Archives (*.zip *.rar *.tar *.gz *.7z)",
        )
        if path:
            self._set_file(path)

    def _set_file(self, path: str):
        self._current_file = path
        self.update()
        self.file_selected.emit(path)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H = self.width(), self.height()
        pad  = 5
        rect = QRectF(pad, pad, W - pad * 2, H - pad * 2)

        if self._drag_over:
            bg = qcol("#1A1208")
        elif self._hovering:
            bg = qcol("#131108")
        else:
            bg = qcol(C.PANEL)
        p.setBrush(QBrush(bg)); p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(rect, 4, 4)

        if self._current_file:   bc = qcol(C.GOLD, 200)
        elif self._drag_over:    bc = qcol(C.GOLD, 220)
        elif self._hovering:     bc = qcol(C.GOLD_DIM, 180)
        else:                    bc = qcol(C.BORDER, 160)

        pen = QPen(bc, 1.2, Qt.PenStyle.DashLine)
        pen.setDashOffset(self._dash_off)
        p.setPen(pen); p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawRoundedRect(rect, 4, 4)

        if self._current_file:
            path = Path(self._current_file)
            cat  = _file_category(path)
            icon, icon_col = _FILE_ICONS.get(cat, _FILE_ICONS["unknown"])
            try:
                size_str = _fmt_size(path.stat().st_size)
            except OSError:
                size_str = "?"
            ext_str = path.suffix.upper().lstrip(".") or "FILE"

            p.setFont(QFont(_EMOJI_FONT, 18))
            p.setPen(QPen(qcol(icon_col), 1))
            p.drawText(QRectF(10, 0, 50, H), Qt.AlignmentFlag.AlignCenter, icon)

            tx = 66; tw = W - tx - 36
            p.setFont(QFont("Arial", 8, QFont.Weight.Bold))
            p.setPen(QPen(qcol(C.WHITE), 1))
            name = path.name if len(path.name) <= 30 else path.name[:27] + "..."
            p.drawText(QRectF(tx, H * 0.2, tw, 16),
                       Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, name)

            p.setFont(QFont("Arial", 7))
            p.setPen(QPen(qcol(C.TEXT_DIM), 1))
            p.drawText(QRectF(tx, H * 0.2 + 18, tw, 13),
                       Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                       f"{ext_str}  ·  {size_str}")

            p.setFont(QFont("Arial", 9, QFont.Weight.Bold))
            p.setPen(QPen(qcol(C.RED, 180), 1))
            p.drawText(QRectF(W - 34, 0, 28, H), Qt.AlignmentFlag.AlignCenter, "✕")

        elif self._drag_over:
            p.setFont(QFont("Arial", 16))
            p.setPen(QPen(qcol(C.GOLD), 1))
            p.drawText(QRectF(0, H/2 - 20, W, 28), Qt.AlignmentFlag.AlignCenter, "⬇")
            p.setFont(QFont("Arial", 7, QFont.Weight.Bold))
            p.setPen(QPen(qcol(C.GOLD), 1))
            p.drawText(QRectF(0, H/2 + 10, W, 14), Qt.AlignmentFlag.AlignCenter,
                       "Release to load")
        else:
            cx2, cy2 = W / 2, H / 2 - 6
            col = qcol(C.GOLD_DIM if not self._hovering else C.GOLD)
            p.setPen(QPen(col, 1.6)); p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawLine(QPointF(cx2, cy2 - 10), QPointF(cx2, cy2 + 4))
            p.drawLine(QPointF(cx2 - 7, cy2 - 3), QPointF(cx2, cy2 - 10))
            p.drawLine(QPointF(cx2 + 7, cy2 - 3), QPointF(cx2, cy2 - 10))
            p.drawLine(QPointF(cx2 - 12, cy2 + 4), QPointF(cx2 + 12, cy2 + 4))

            p.setFont(QFont("Arial", 7))
            p.setPen(QPen(qcol(C.TEXT_DIM if not self._hovering else C.TEXT_MED), 1))
            p.drawText(QRectF(0, cy2 + 8, W, 14), Qt.AlignmentFlag.AlignCenter,
                       "Drop file or click to browse")
            p.setFont(QFont("Arial", 6))
            p.setPen(QPen(qcol(C.BORDER_B), 1))
            p.drawText(QRectF(0, cy2 + 22, W, 12), Qt.AlignmentFlag.AlignCenter,
                       "Images · Docs · Audio · Video · Code · Data")


# ── Setup overlay ─────────────────────────────────────────────────────────────
class SetupOverlay(QWidget):
    done = pyqtSignal(str, str, str)

    _KEY_SS = (
        "QLineEdit {{ background: #0A0B0D; color: {text}; "
        "border: 1px solid {border}; border-radius: 2px; padding: 4px 8px; }}"
        "QLineEdit:focus {{ border: 1px solid {focus}; }}"
    )

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(f"""
            SetupOverlay {{
                background: rgba(8, 9, 11, 248);
                border: 1px solid {C.GOLD_DIM};
                border-radius: 4px;
            }}
        """)
        detected = {"darwin": "mac", "windows": "windows"}.get(_OS.lower(), "linux")
        self._sel_os = detected

        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 20, 28, 20)
        lay.setSpacing(7)

        def _lbl(txt, sz=9, bold=False, color=C.GOLD,
                 align=Qt.AlignmentFlag.AlignCenter):
            w = QLabel(txt); w.setAlignment(align)
            w.setFont(QFont("Arial", sz,
                            QFont.Weight.Bold if bold else QFont.Weight.Normal))
            w.setStyleSheet(f"color: {color}; background: transparent;")
            return w

        lay.addWidget(_lbl("INITIALISATION REQUIRED", 12, True))
        lay.addWidget(_lbl("Configure J.A.R.V.I.S. before first boot.", 8,
                           color=C.TEXT_DIM))
        lay.addSpacing(4)
        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color: {C.BORDER};"); lay.addWidget(sep)
        lay.addSpacing(2)

        lay.addWidget(_lbl("GEMINI API KEY", 7, color=C.TEXT_DIM,
                           align=Qt.AlignmentFlag.AlignLeft))
        self._key_input = QLineEdit()
        self._key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._key_input.setPlaceholderText("AIza...")
        self._key_input.setFont(QFont("Courier New", 10))
        self._key_input.setFixedHeight(30)
        self._key_ss = self._KEY_SS.format(
            text=C.TEXT, border=C.BORDER, focus=C.GOLD)
        self._key_input.setStyleSheet(self._key_ss)
        lay.addWidget(self._key_input)
        lay.addSpacing(6)

        lay.addWidget(_lbl("OPENROUTER API KEY", 7, color=C.TEXT_DIM,
                           align=Qt.AlignmentFlag.AlignLeft))
        self._or_input = QLineEdit()
        self._or_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._or_input.setPlaceholderText("sk-or-...")
        self._or_input.setFont(QFont("Courier New", 10))
        self._or_input.setFixedHeight(30)
        self._or_ss = self._KEY_SS.format(
            text=C.TEXT, border=C.BORDER, focus=C.STEEL)
        self._or_input.setStyleSheet(self._or_ss)
        lay.addWidget(self._or_input)
        lay.addSpacing(10)

        sep2 = QFrame(); sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setStyleSheet(f"color: {C.BORDER};"); lay.addWidget(sep2)
        lay.addSpacing(4)

        lay.addWidget(_lbl("OPERATING SYSTEM", 7, color=C.TEXT_DIM,
                           align=Qt.AlignmentFlag.AlignLeft))
        det_name = {"windows": "Windows", "mac": "macOS", "linux": "Linux"}[detected]
        lay.addWidget(_lbl(f"Auto-detected: {det_name}", 7, color=C.STEEL,
                           align=Qt.AlignmentFlag.AlignLeft))

        os_row = QHBoxLayout(); os_row.setSpacing(6)
        self._os_btns: dict[str, QPushButton] = {} # type: ignore
        for key, label in [("windows","Windows"),("mac","macOS"),("linux","Linux")]:
            btn = QPushButton(label)
            btn.setFont(QFont("Arial", 8, QFont.Weight.Bold))
            btn.setFixedHeight(28)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _, k=key: self._sel(k))
            os_row.addWidget(btn)
            self._os_btns[key] = btn
        lay.addLayout(os_row)
        self._sel(detected)
        lay.addSpacing(10)

        init_btn = QPushButton("INITIALISE SYSTEMS")
        init_btn.setFont(QFont("Arial", 9, QFont.Weight.Bold))
        init_btn.setFixedHeight(32)
        init_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        init_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {C.GOLD};
                border: 1px solid {C.GOLD_DIM}; border-radius: 2px;
            }}
            QPushButton:hover {{
                background: {C.GOLD_GHO}; border: 1px solid {C.GOLD};
            }}
        """)
        init_btn.clicked.connect(self._submit)
        lay.addWidget(init_btn)

    def _sel(self, key: str):
        self._sel_os = key
        pal = {"windows": (C.GOLD, C.GOLD_GHO),
               "mac":     (C.STEEL, "#0A1218"),
               "linux":   (C.GREEN, "#081208")}
        for k, btn in self._os_btns.items():
            if k == key:
                fg, bg = pal[k]
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background: {bg}; color: {fg};
                        border: 1px solid {fg}; border-radius: 2px;
                    }}
                """)
            else:
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background: #0A0B0D; color: {C.TEXT_DIM};
                        border: 1px solid {C.BORDER}; border-radius: 2px;
                    }}
                    QPushButton:hover {{ color: {C.TEXT}; border: 1px solid {C.BORDER_B}; }}
                """)

    def _submit(self):
        key    = self._key_input.text().strip()
        or_key = self._or_input.text().strip()
        ok = True
        if not key:
            self._key_input.setStyleSheet(
                self._key_ss + f" QLineEdit {{ border: 1px solid {C.RED}; }}")
            ok = False
        else:
            self._key_input.setStyleSheet(self._key_ss)
        if not or_key:
            self._or_input.setStyleSheet(
                self._or_ss + f" QLineEdit {{ border: 1px solid {C.RED}; }}")
            ok = False
        else:
            self._or_input.setStyleSheet(self._or_ss)
        if not ok:
            return
        self.done.emit(key, or_key, self._sel_os)


# ── Settings overlay ──────────────────────────────────────────────────────────
class SettingsOverlay(QWidget):
    changed = pyqtSignal(float)
    closed  = pyqtSignal()

    def __init__(self, initial_sensitivity: float, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(f"""
            SettingsOverlay {{
                background: rgba(8, 9, 11, 248);
                border: 1px solid {C.GOLD_DIM};
                border-radius: 4px;
            }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 18, 24, 18)
        lay.setSpacing(7)

        def _lbl(txt, sz=9, bold=False, color=C.GOLD,
                 align=Qt.AlignmentFlag.AlignCenter):
            w = QLabel(txt); w.setAlignment(align)
            w.setFont(QFont("Arial", sz,
                            QFont.Weight.Bold if bold else QFont.Weight.Normal))
            w.setStyleSheet(f"color: {color}; background: transparent;")
            return w

        hrow = QHBoxLayout()
        hrow.addWidget(_lbl("SETTINGS", 12, True))
        hrow.addStretch()
        x = QPushButton("✕")
        x.setFixedSize(22, 22)
        x.setCursor(Qt.CursorShape.PointingHandCursor)
        x.setStyleSheet(f"""
            QPushButton {{ background: transparent; color: {C.TEXT_DIM};
                border: 1px solid {C.BORDER}; border-radius: 2px; }}
            QPushButton:hover {{ color: {C.RED}; border: 1px solid {C.RED}; }}
        """)
        x.clicked.connect(self._close)
        hrow.addWidget(x)
        lay.addLayout(hrow)

        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color: {C.BORDER};"); lay.addWidget(sep)
        lay.addSpacing(4)

        lay.addWidget(_lbl("WAKE-WORD SENSITIVITY", 7, color=C.TEXT_DIM,
                           align=Qt.AlignmentFlag.AlignLeft))
        lay.addWidget(_lbl(
            "Lower = more sensitive (may trigger on background audio). "
            "Higher = stricter (may miss soft speech).",
            7, color=C.TEXT_MED, align=Qt.AlignmentFlag.AlignLeft))
        lay.addSpacing(2)
        self._val_lbl = _lbl(f"{initial_sensitivity:.2f}", 11, True, C.GOLD)
        lay.addWidget(self._val_lbl)

        row = QHBoxLayout(); row.setSpacing(8)
        row.addWidget(_lbl("Sensitive", 7, color=C.GREEN))
        self._slider = QSlider(Qt.Orientation.Horizontal)
        self._slider.setRange(5, 95)
        self._slider.setValue(int(round(initial_sensitivity * 100)))
        self._slider.setStyleSheet(f"""
            QSlider::groove:horizontal {{
                height: 3px; background: {C.BORDER}; border-radius: 1px;
            }}
            QSlider::handle:horizontal {{
                background: {C.GOLD}; width: 14px; height: 14px;
                margin: -6px 0; border-radius: 7px;
            }}
            QSlider::sub-page:horizontal {{
                background: {C.GOLD_DIM}; border-radius: 1px;
            }}
        """)
        self._slider.valueChanged.connect(self._on_sens)
        row.addWidget(self._slider, stretch=1)
        row.addWidget(_lbl("Strict", 7, color=C.RED))
        lay.addLayout(row)

        lay.addSpacing(8)
        done = QPushButton("DONE")
        done.setFont(QFont("Arial", 9, QFont.Weight.Bold))
        done.setFixedHeight(30)
        done.setCursor(Qt.CursorShape.PointingHandCursor)
        done.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {C.GOLD};
                border: 1px solid {C.GOLD_DIM}; border-radius: 2px;
            }}
            QPushButton:hover {{
                background: {C.GOLD_GHO}; border: 1px solid {C.GOLD};
            }}
        """)
        done.clicked.connect(self._close)
        lay.addWidget(done)

    def _on_sens(self, v: int):
        val = v / 100.0
        self._val_lbl.setText(f"{val:.2f}")
        self.changed.emit(val)

    def _close(self):
        self.hide()
        self.closed.emit()


# ── Status dot (animated pulsing) ─────────────────────────────────────────────
class StatusDot(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(12, 12)
        self._online = True
        self._phase  = 0.0
        self._tmr = QTimer(self)
        self._tmr.timeout.connect(self._step)
        self._tmr.start(40)

    def set_online(self, online: bool):
        self._online = online

    def _step(self):
        self._phase = (self._phase + 0.12) % (2 * math.pi)
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pulse = 0.5 + 0.5 * math.sin(self._phase)
        if self._online:
            col = qcol(C.GREEN, int(180 + 75 * pulse))
        else:
            col = qcol(C.RED, 220)
        p.setBrush(QBrush(col))
        p.setPen(Qt.PenStyle.NoPen)
        r = 4 + int(1.5 * pulse) if self._online else 4
        cx2, cy2 = 6, 6
        p.drawEllipse(QRectF(cx2 - r, cy2 - r, r * 2, r * 2))


class BootSequenceOverlay(QWidget):
    """
    PHASE 1 GAP FIX: cinematic boot animation, plays once when JARVIS first
    opens, then removes itself. Pure QPainter — no video/audio assets, same
    reasoning as HologramCanvas (nothing that can hang on a codec).

    Sequence (total ~3.2s):
      0.0 - 0.4s  corner brackets snap/animate in from off-screen
      0.2 - 2.6s  boot lines type/reveal one at a time, monospace, gold
      0.0 - 2.6s  a single scanline sweeps top-to-bottom across the panel
      2.6 - 3.2s  whole overlay fades out, then self-deletes
    """

    finished = pyqtSignal()

    _LINES = [
        "INITIALIZING J.A.R.V.I.S CORE...",
        "LOADING NEURAL INTERFACE...",
        "CALIBRATING ARC REACTOR...",
        "ESTABLISHING WAKE-WORD ENGINE... OK",
        "MEMORY BANKS... ONLINE",
        "SYSTEMS ONLINE",
        "CORE STABLE",
        "GOOD EVENING, SIR.",
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(f"background: {C.BG};")
        self._t0          = time.time()
        self._opacity     = 1.0
        self._bracket_t   = 0.0   # 0..1 progress of corner brackets sliding in
        self._lines_shown = 0
        self._scan_y_frac = 0.0
        self._done        = False

        self._tmr = QTimer(self)
        self._tmr.timeout.connect(self._step)
        self._tmr.start(16)

    def _step(self):
        elapsed = time.time() - self._t0

        self._bracket_t = min(1.0, elapsed / 0.4)
        self._scan_y_frac = min(1.0, elapsed / 2.6)

        # Reveal one boot line roughly every 0.3s, starting at 0.2s
        shown = max(0, int((elapsed - 0.2) / 0.3) + 1)
        self._lines_shown = min(len(self._LINES), shown)

        if elapsed >= 2.6:
            fade_t = (elapsed - 2.6) / 0.6
            self._opacity = max(0.0, 1.0 - fade_t)
            if elapsed >= 3.2 and not self._done:
                self._done = True
                self._tmr.stop()
                # hide() immediately so the underlying HUD is guaranteed to
                # be what's drawn on the very next paint, rather than
                # relying solely on deleteLater()'s deferred cleanup timing.
                self.hide()
                self.finished.emit()
                self.deleteLater()
                return

        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setOpacity(self._opacity)
        W, H = self.width(), self.height()

        p.fillRect(self.rect(), QColor(C.BG))

        # Corner brackets sliding in from off-screen toward their resting spot
        margin = 40
        bl = 50
        t  = self._bracket_t
        # ease-out
        t  = 1 - (1 - t) ** 3
        p.setPen(QPen(qcol(C.GOLD, int(220 * min(1.0, t * 1.4))), 2.2))
        corners = [
            (margin, margin, 1, 1),
            (W - margin, margin, -1, 1),
            (margin, H - margin, 1, -1),
            (W - margin, H - margin, -1, -1),
        ]
        slide = (1 - t) * 60
        for cx2, cy2, dx, dy in corners:
            ox = cx2 - dx * slide
            oy = cy2 - dy * slide
            p.drawLine(QPointF(ox, oy), QPointF(ox + dx * bl * t, oy))
            p.drawLine(QPointF(ox, oy), QPointF(ox, oy + dy * bl * t))

        # Center emblem — simple pulsing ring, echoes the hologram without
        # duplicating its full complexity (this overlay is gone in 3s)
        cx2, cy2 = W / 2.0, H / 2.0 - 40
        ring_r = 38 + 4 * math.sin(time.time() * 4)
        p.setPen(QPen(qcol(C.GOLD, 200), 2.0))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(QPointF(cx2, cy2), ring_r, ring_r)
        p.setPen(QPen(qcol(C.STEEL, 140), 1.2))
        p.drawEllipse(QPointF(cx2, cy2), ring_r * 0.6, ring_r * 0.6)

        # Boot text lines
        font = QFont("Courier New", 10, QFont.Weight.Bold)
        p.setFont(font)
        line_h = 22
        start_y = cy2 + 70
        for i in range(self._lines_shown):
            text = self._LINES[i]
            is_last_two = i >= len(self._LINES) - 2
            col = qcol(C.GOLD, 235) if is_last_two else qcol(C.TEXT_MED, 200)
            p.setPen(QPen(col, 1))
            p.drawText(QRectF(0, start_y + i * line_h, W, line_h),
                       Qt.AlignmentFlag.AlignCenter, text)

        # Sweeping scanline across the whole panel while booting
        if self._scan_y_frac < 1.0:
            sy = self._scan_y_frac * H
            grad = QLinearGradient(0, sy - 30, 0, sy + 30)
            grad.setColorAt(0.0, qcol(C.GOLD, 0))
            grad.setColorAt(0.5, qcol(C.GOLD, 60))
            grad.setColorAt(1.0, qcol(C.GOLD, 0))
            p.setBrush(QBrush(grad))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawRect(QRectF(0, sy - 30, W, 60))


# ── Main window ───────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    _log_sig   = pyqtSignal(str)
    _state_sig = pyqtSignal(str)
    _agent_sig = pyqtSignal(str, float)
    _audio_level_sig = pyqtSignal(float)   # PHASE 1 GAP FIX: real voice-reactive pulse
    _game_mode_sig   = pyqtSignal(bool)    # Phase 6: game mode HUD toggle

    def __init__(self, _face_path: str = ""):
        super().__init__()
        self.setWindowTitle("J.A.R.V.I.S — MARK XXXIX")
        self.setMinimumSize(_MIN_W, _MIN_H)
        self.resize(_DEFAULT_W, _DEFAULT_H)

        screen = QApplication.primaryScreen()
        if screen is not None:
            geo = screen.availableGeometry()
            self.move(
                geo.x() + (geo.width()  - _DEFAULT_W) // 2,
                geo.y() + (geo.height() - _DEFAULT_H) // 2,
            )

        # Callbacks
        self.on_text_command             = None
        self.on_mute_toggle              = None
        self.on_gesture_toggle           = None
        self.on_file_selected            = None
        self.on_wake_sensitivity_changed = None
        self.on_open_memory_editor       = None

        self._muted           = False
        self._current_state   = "LISTENING"
        self._current_file: str | None = None
        self._wake_sensitivity = self._load_wake_sensitivity()

        central = QWidget()
        central.setStyleSheet(f"background: {C.BG};")
        self.setCentralWidget(central)

        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_header())

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        body.addWidget(self._build_left_panel(), stretch=0)

        # Centre: video frame
        self._video_frame = HologramCanvas()
        body.addWidget(self._video_frame, stretch=5)

        body.addWidget(self._build_right_panel(), stretch=0)
        root.addLayout(body, stretch=1)
        root.addWidget(self._build_footer())

        # Timers
        self._clock_tmr = QTimer(self)
        self._clock_tmr.timeout.connect(self._tick_clock)
        self._clock_tmr.start(1000)
        self._tick_clock()

        self._metric_tmr = QTimer(self)
        self._metric_tmr.timeout.connect(self._update_metrics)
        self._metric_tmr.start(2000)
        self._update_metrics()

        self._security_tmr = QTimer(self)
        self._security_tmr.timeout.connect(self._refresh_security_status)
        self._security_tmr.start(5000)
        self._refresh_security_status()

        self._log_sig.connect(self._log.append_log)
        self._state_sig.connect(self._apply_state)
        self._agent_sig.connect(self._set_agent_bar)
        self._audio_level_sig.connect(self._video_frame.set_audio_level)
        self._game_mode_sig.connect(self._set_game_mode_hud)  # Phase 6
        self._update_status_panel(self._current_state)

        # Agent manager
        try:
            from agents.agent_manager import get_manager
            self._agent_manager = get_manager()
            self._agent_manager.set_progress_callback(
                lambda name, pct: self._agent_sig.emit(name, pct)
            )
        except Exception:
            self._agent_manager = None

        self._overlay: Optional[SetupOverlay] = None
        self._settings_overlay: Optional[SettingsOverlay] = None
        self._boot_overlay: Optional[BootSequenceOverlay] = None
        self._ready = self._check_config()
        if not self._ready:
            self._show_setup()
        else:
            # Returning user, already configured — play the boot cinematic
            # immediately. (First-time users get it right after they finish
            # setup instead — see _on_setup_done.)
            QTimer.singleShot(0, self._play_boot_sequence)

        self._sc_mute = QShortcut(QKeySequence("F4"), self)
        self._sc_mute.activated.connect(self._toggle_mute)
        self._sc_full = QShortcut(QKeySequence("F11"), self)
        self._sc_full.activated.connect(self._toggle_fullscreen)

    # ── Boot sequence ─────────────────────────────────────────────────────────
    def _play_boot_sequence(self):
        """PHASE 1 GAP FIX: cinematic boot animation on first open."""
        if self._boot_overlay is not None:
            return
        cw = self.centralWidget()
        ov = BootSequenceOverlay(cw)
        ov.setGeometry(0, 0, cw.width(), cw.height())
        ov.finished.connect(self._on_boot_finished)
        ov.show()
        ov.raise_()
        self._boot_overlay = ov

    def _on_boot_finished(self):
        self._boot_overlay = None

    # ── Header ────────────────────────────────────────────────────────────────
    def _build_header(self) -> QWidget: # type: ignore
        w = QWidget()
        w.setFixedHeight(54)
        w.setStyleSheet(f"background: {C.DARK}; border-bottom: 1px solid {C.GOLD_DIM};")
        lay = QHBoxLayout(w)
        lay.setContentsMargins(16, 0, 16, 0)

        # Left: MARK XXXIX + status dot
        left_row = QHBoxLayout(); left_row.setSpacing(8)
        mark_lbl = QLabel("MARK XXXIX")
        mark_lbl.setFont(QFont("Arial", 9, QFont.Weight.Bold))
        mark_lbl.setStyleSheet(f"color: {C.GOLD}; background: transparent; letter-spacing: 2px;")
        self._status_dot = StatusDot()
        left_row.addWidget(mark_lbl)
        left_row.addWidget(self._status_dot)
        left_row.addStretch()
        lay.addLayout(left_row, stretch=1)

        # Centre: title
        mid = QVBoxLayout(); mid.setSpacing(1)
        title = QLabel("J.A.R.V.I.S")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {C.GOLD}; background: transparent; letter-spacing: 3px;")
        mid.addWidget(title)
        sub = QLabel("Just A Rather Very Intelligent System")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setFont(QFont("Arial", 7))
        sub.setStyleSheet(f"color: {C.TEXT_DIM}; background: transparent; letter-spacing: 1px;")
        mid.addWidget(sub)
        lay.addLayout(mid, stretch=2)

        # Right: clock + date
        right_col = QVBoxLayout(); right_col.setSpacing(2); right_col.setAlignment(Qt.AlignmentFlag.AlignRight)
        self._clock_lbl = QLabel("00:00:00")
        self._clock_lbl.setFont(QFont("Courier New", 14, QFont.Weight.Bold))
        self._clock_lbl.setStyleSheet(f"color: {C.GOLD}; background: transparent;")
        self._clock_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
        right_col.addWidget(self._clock_lbl)
        self._date_lbl = QLabel("")
        self._date_lbl.setFont(QFont("Arial", 7))
        self._date_lbl.setStyleSheet(f"color: {C.TEXT_DIM}; background: transparent;")
        self._date_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
        right_col.addWidget(self._date_lbl)
        lay.addLayout(right_col, stretch=1)

        return w

    def _tick_clock(self):
        self._clock_lbl.setText(time.strftime("%H:%M:%S"))
        self._date_lbl.setText(time.strftime("%a %d %b %Y"))

    # ── Left panel ────────────────────────────────────────────────────────────
    def _build_left_panel(self) -> QWidget: # type: ignore
        w = QWidget()
        w.setFixedWidth(_LEFT_W)
        w.setStyleSheet(f"background: {C.DARK}; border-right: 1px solid {C.BORDER};")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(8, 10, 8, 10)
        lay.setSpacing(5)

        def _section_hdr(txt):
            l = QLabel(txt)
            l.setFont(QFont("Arial", 7, QFont.Weight.Bold))
            l.setStyleSheet(
                f"color: {C.GOLD}; background: transparent; "
                f"border-bottom: 1px solid {C.GOLD_DIM}; padding-bottom: 3px; "
                f"letter-spacing: 1px;")
            return l

        lay.addWidget(_section_hdr("STATUS PANEL"))
        lay.addSpacing(2)

        # PHASE 1 GAP FIX: literal HUD status readouts (SYSTEMS ONLINE,
        # CORE STABLE, etc.) reacting to JARVIS's actual state, not just the
        # CPU/MEM/NET system-monitor bars below (which track the host
        # machine, not JARVIS itself).
        status_panel = QWidget()
        status_panel.setStyleSheet(
            f"background: {C.PANEL2}; border: 1px solid {C.BORDER}; border-radius: 3px;")
        sl = QVBoxLayout(status_panel); sl.setContentsMargins(7, 6, 7, 6); sl.setSpacing(4)

        def _status_row(label_text: str) -> QLabel: # type: ignore
            row = QLabel(label_text)
            row.setFont(QFont("Courier New", 7, QFont.Weight.Bold))
            row.setStyleSheet(f"color: {C.GREEN}; background: transparent; border: none;")
            sl.addWidget(row)
            return row

        self._status_systems_lbl   = _status_row("● SYSTEMS ONLINE")
        self._status_core_lbl      = _status_row("● CORE STABLE")
        self._status_link_lbl      = _status_row("● UPLINK ACTIVE")
        self._status_game_mode_lbl = _status_row("● GAME MODE OFF")  # Phase 6

        # Security telemetry — real state from core/secure_vault.py,
        # core/audit_log.py, core/access_control.py, not decorative.
        self._status_security_lbls = [
            _status_row("● VAULT —"),
            _status_row("● AUDIT —"),
            _status_row("● PIN —"),
        ]
        lay.addWidget(status_panel)
        lay.addSpacing(4)

        lay.addWidget(_section_hdr("SYS MONITOR"))
        lay.addSpacing(2)

        self._bar_cpu = MetricBar("CPU", C.STEEL)
        self._bar_mem = MetricBar("MEM", C.GOLD)
        self._bar_net = MetricBar("NET", C.GREEN)
        self._bar_gpu = MetricBar("GPU", C.AMBER)
        self._bar_tmp = MetricBar("TMP", C.PINK)

        for bar in [self._bar_cpu, self._bar_mem, self._bar_net,
                    self._bar_gpu, self._bar_tmp]:
            lay.addWidget(bar)

        # Info sub-panel
        lay.addSpacing(4)
        info = QWidget()
        info.setStyleSheet(
            f"background: {C.PANEL2}; border: 1px solid {C.BORDER}; border-radius: 3px;")
        il = QVBoxLayout(info); il.setContentsMargins(7, 5, 7, 5); il.setSpacing(3)
        self._uptime_lbl = QLabel("UP  --:--")
        self._uptime_lbl.setFont(QFont("Courier New", 7, QFont.Weight.Bold))
        self._uptime_lbl.setStyleSheet(f"color: {C.GREEN}; background: transparent; border: none;")
        il.addWidget(self._uptime_lbl)
        self._proc_lbl = QLabel("PROC  --")
        self._proc_lbl.setFont(QFont("Courier New", 7))
        self._proc_lbl.setStyleSheet(f"color: {C.TEXT_MED}; background: transparent; border: none;")
        il.addWidget(self._proc_lbl)
        os_name = {"Windows": "WIN", "Darwin": "macOS", "Linux": "LINUX"}.get(_OS, _OS.upper())
        os_lbl  = QLabel(f"OS  {os_name}")
        os_lbl.setFont(QFont("Courier New", 7))
        os_lbl.setStyleSheet(f"color: {C.STEEL}; background: transparent; border: none;")
        il.addWidget(os_lbl)
        lay.addWidget(info)

        lay.addSpacing(6)
        lay.addWidget(_section_hdr("AGENTS"))
        lay.addSpacing(2)

        self._bar_tom   = MetricBar("TOM",   C.GREEN)
        self._bar_scout = MetricBar("SCOUT", C.BLUE)
        self._bar_ada   = MetricBar("ADA",   C.AMBER)
        self._bar_nova  = MetricBar("NOVA",  C.PINK)

        for bar in [self._bar_tom, self._bar_scout, self._bar_ada, self._bar_nova]:
            lay.addWidget(bar)

        lay.addStretch()
        return w

    # ── Right panel ───────────────────────────────────────────────────────────
    def _build_right_panel(self) -> QWidget: # type: ignore
        w = QWidget()
        w.setFixedWidth(_RIGHT_W)
        w.setStyleSheet(f"background: {C.DARK}; border-left: 1px solid {C.BORDER};")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(5)

        def _sec(txt):
            l = QLabel(f"▸ {txt}")
            l.setFont(QFont("Arial", 7, QFont.Weight.Bold))
            l.setStyleSheet(f"color: {C.GOLD_DIM}; background: transparent; letter-spacing: 1px;")
            return l

        # Activity log
        lay.addWidget(_sec("ACTIVITY LOG"))
        self._log = LogWidget()
        lay.addWidget(self._log, stretch=1)

        self._add_sep(lay)

        # File drop
        lay.addWidget(_sec("FILE UPLOAD"))
        self._drop_zone = FileDropZone()
        self._drop_zone.file_selected.connect(self._on_file_selected)
        lay.addWidget(self._drop_zone)

        self._file_hint = QLabel("No file loaded")
        self._file_hint.setFont(QFont("Arial", 7))
        self._file_hint.setStyleSheet(f"color: {C.TEXT_DIM}; background: transparent;")
        self._file_hint.setWordWrap(True)
        lay.addWidget(self._file_hint)

        self._add_sep(lay)

        # Command input
        lay.addWidget(_sec("COMMAND INPUT"))
        lay.addLayout(self._build_input_row())

        # Buttons
        self._mute_btn = self._make_btn("MICROPHONE ACTIVE", C.GREEN, height=30)
        self._mute_btn.clicked.connect(self._toggle_mute)
        self._style_mute_btn()
        lay.addWidget(self._mute_btn)

        row2 = QHBoxLayout(); row2.setSpacing(5)
        fs_btn  = self._make_btn("FULLSCREEN [F11]", C.TEXT_DIM, height=26)
        fs_btn.clicked.connect(self._toggle_fullscreen)
        row2.addWidget(fs_btn)
        mem_btn = self._make_btn("MEMORY", C.TEXT_DIM, height=26, hover_color=C.GOLD)
        mem_btn.clicked.connect(self._open_memory_editor)
        row2.addWidget(mem_btn)
        lay.addLayout(row2)

        self._gesture_btn = self._make_btn("GESTURE CONTROL: OFF", C.TEXT_DIM, height=26, hover_color=C.STEEL)
        self._gesture_btn.clicked.connect(self._toggle_gesture)
        lay.addWidget(self._gesture_btn)
        if self._load_gesture_control_enabled():
            self._toggle_gesture()  # sync button visual + self._gesture_enabled to saved config

        cfg_btn = self._make_btn("SETTINGS", C.TEXT_DIM, height=26, hover_color=C.STEEL)
        cfg_btn.clicked.connect(self._show_settings)
        lay.addWidget(cfg_btn)

        return w

    def _add_sep(self, lay):
        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color: {C.BORDER}; margin: 1px 0;")
        lay.addWidget(sep)

    def _make_btn(self, text, color, height=26, hover_color=None) -> QPushButton: # type: ignore
        if hover_color is None:
            hover_color = C.GOLD
        btn = QPushButton(text)
        btn.setFixedHeight(height)
        btn.setFont(QFont("Arial", 7, QFont.Weight.Bold))
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {color};
                border: 1px solid {C.BORDER}; border-radius: 2px;
            }}
            QPushButton:hover {{
                color: {hover_color}; border: 1px solid {hover_color};
                background: {C.PANEL};
            }}
        """)
        return btn

    def _build_input_row(self) -> QHBoxLayout: # type: ignore
        row = QHBoxLayout(); row.setSpacing(5)
        self._input = QLineEdit()
        self._input.setPlaceholderText("Type a command or question...")
        self._input.setFont(QFont("Arial", 9))
        self._input.setFixedHeight(30)
        self._input.setStyleSheet(f"""
            QLineEdit {{
                background: #0A0B0D; color: {C.WHITE};
                border: 1px solid {C.BORDER}; border-radius: 2px; padding: 3px 8px;
            }}
            QLineEdit:focus {{ border: 1px solid {C.GOLD}; }}
        """)
        self._input.returnPressed.connect(self._send)
        row.addWidget(self._input)

        send = QPushButton("▸")
        send.setFixedSize(30, 30)
        send.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        send.setCursor(Qt.CursorShape.PointingHandCursor)
        send.setStyleSheet(f"""
            QPushButton {{
                background: {C.PANEL}; color: {C.GOLD};
                border: 1px solid {C.GOLD_DIM}; border-radius: 2px;
            }}
            QPushButton:hover {{ background: {C.GOLD_GHO}; border: 1px solid {C.GOLD}; }}
        """)
        send.clicked.connect(self._send)
        row.addWidget(send)
        return row

    # ── Footer ────────────────────────────────────────────────────────────────
    def _build_footer(self) -> QWidget: # type: ignore
        w = QWidget()
        w.setFixedHeight(22)
        w.setStyleSheet(f"background: {C.DARK}; border-top: 1px solid {C.GOLD_DIM};")
        lay = QHBoxLayout(w); lay.setContentsMargins(14, 0, 14, 0)

        def _fl(txt, color=C.TEXT_DIM):
            l = QLabel(txt); l.setFont(QFont("Arial", 7))
            l.setStyleSheet(f"color: {color}; background: transparent;")
            return l

        lay.addWidget(_fl("[F4] Mute  [F11] Fullscreen"))
        lay.addStretch()
        lay.addWidget(_fl("STARK INDUSTRIES · CLASSIFIED", C.GOLD_DIM))
        lay.addStretch()
        self._state_lbl = _fl("LISTENING", C.TEXT_DIM)
        lay.addWidget(self._state_lbl)
        return w

    # ── Metrics ───────────────────────────────────────────────────────────────
    def _update_metrics(self):
        snap = _metrics.snapshot()

        cpu = snap["cpu"]
        self._bar_cpu.set_value(cpu, f"{cpu:.0f}%")

        mem = snap["mem"]
        self._bar_mem.set_value(mem, f"{mem:.0f}%")

        net = snap["net"]
        net_str = f"{net*1024:.0f}KB/s" if net < 1.0 else f"{net:.1f}MB/s"
        self._bar_net.set_value(min(100, net * 10), net_str)

        gpu = snap["gpu"]
        self._bar_gpu.set_value(gpu if gpu >= 0 else 0,
                                f"{gpu:.0f}%" if gpu >= 0 else "N/A")

        tmp = snap["tmp"]
        self._bar_tmp.set_value(
            min(100, (tmp / 100) * 100) if tmp >= 0 else 0,
            f"{tmp:.0f}C" if tmp >= 0 else "N/A")

        try:
            elapsed = time.time() - psutil.boot_time()
            h = int(elapsed // 3600); m = int((elapsed % 3600) // 60)
            self._uptime_lbl.setText(f"UP  {h:02d}:{m:02d}")
        except Exception:
            self._uptime_lbl.setText("UP  --:--")
        try:
            self._proc_lbl.setText(f"PROC  {len(psutil.pids())}")
        except Exception:
            self._proc_lbl.setText("PROC  --")

    def _refresh_security_status(self):
        """Pulls real state from the security layer (vault/audit log/PIN)
        into the STATUS PANEL rows added alongside SYSTEMS ONLINE etc."""
        color_map = {"green": C.GREEN, "amber": C.GOLD, "red": C.RED}
        try:
            from core.security_status import get_security_status_lines
            rows = get_security_status_lines()
        except Exception as e:
            rows = [(f"SECURITY MODULE ERROR", "red")] * len(self._status_security_lbls)

        for lbl, (text, color_key) in zip(self._status_security_lbls, rows):
            lbl.setText(f"● {text}")
            lbl.setStyleSheet(
                f"color: {color_map.get(color_key, C.TEXT_DIM)}; "
                f"background: transparent; border: none;"
            )

    def _set_agent_bar(self, name: str, pct: float):
        mapping = {
            "Tom":   getattr(self, "_bar_tom",   None),
            "Scout": getattr(self, "_bar_scout", None),
            "Ada":   getattr(self, "_bar_ada",   None),
            "Nova":  getattr(self, "_bar_nova",  None),
        }
        bar = mapping.get(name)
        if bar is not None:
            bar.set_value(pct, f"{int(pct)}%")

    # ── State ─────────────────────────────────────────────────────────────────
    def _apply_state(self, state: str):
        self._current_state = state
        self._video_frame.set_state(state)
        self._state_lbl.setText(state)
        online = state not in ("OFFLINE", "SLEEPING")
        self._status_dot.set_online(online)
        self._update_status_panel(state)

    def _update_status_panel(self, state: str):
        """PHASE 1 GAP FIX: drive the SYSTEMS ONLINE / CORE STABLE / UPLINK
        readouts to actually reflect what JARVIS is doing, instead of being
        static decoration."""
        sys_lbl  = getattr(self, "_status_systems_lbl", None)
        core_lbl = getattr(self, "_status_core_lbl", None)
        link_lbl = getattr(self, "_status_link_lbl", None)
        if not (sys_lbl and core_lbl and link_lbl):
            return

        if state == "OFFLINE":
            sys_lbl.setText("● SYSTEMS OFFLINE");  sys_lbl.setStyleSheet(self._status_style(C.RED))
            core_lbl.setText("● CORE SHUTDOWN");    core_lbl.setStyleSheet(self._status_style(C.RED))
            link_lbl.setText("● UPLINK SEVERED");   link_lbl.setStyleSheet(self._status_style(C.RED))
        elif state == "SLEEPING":
            sys_lbl.setText("● SYSTEMS ONLINE");    sys_lbl.setStyleSheet(self._status_style(C.GREEN))
            core_lbl.setText("● CORE STABLE");      core_lbl.setStyleSheet(self._status_style(C.GREEN))
            link_lbl.setText("● STANDBY");          link_lbl.setStyleSheet(self._status_style(C.TEXT_DIM))
        elif state == "THINKING":
            sys_lbl.setText("● SYSTEMS ONLINE");    sys_lbl.setStyleSheet(self._status_style(C.GREEN))
            core_lbl.setText("● PROCESSING");       core_lbl.setStyleSheet(self._status_style(C.AMBER))
            link_lbl.setText("● UPLINK ACTIVE");    link_lbl.setStyleSheet(self._status_style(C.STEEL))
        elif state == "SPEAKING":
            sys_lbl.setText("● SYSTEMS ONLINE");    sys_lbl.setStyleSheet(self._status_style(C.GREEN))
            core_lbl.setText("● CORE STABLE");      core_lbl.setStyleSheet(self._status_style(C.GREEN))
            link_lbl.setText("● TRANSMITTING");     link_lbl.setStyleSheet(self._status_style(C.GOLD))
        else:  # LISTENING / ACTIVE_CONVERSATION / anything else
            sys_lbl.setText("● SYSTEMS ONLINE");    sys_lbl.setStyleSheet(self._status_style(C.GREEN))
            core_lbl.setText("● CORE STABLE");      core_lbl.setStyleSheet(self._status_style(C.GREEN))
            link_lbl.setText("● UPLINK ACTIVE");    link_lbl.setStyleSheet(self._status_style(C.GREEN))

    @staticmethod
    def _status_style(color: str) -> str:
        return f"color: {color}; background: transparent; border: none;"

    def _set_game_mode_hud(self, active: bool):
        """Phase 6: Update the GAME MODE status row in the HUD panel."""
        lbl = getattr(self, "_status_game_mode_lbl", None)
        if lbl is None:
            return
        if active:
            lbl.setText("● GAME MODE ON")
            lbl.setStyleSheet(self._status_style("#FF6B35"))  # orange
        else:
            lbl.setText("● GAME MODE OFF")
            lbl.setStyleSheet(self._status_style("#555555"))  # dim grey

    # ── File handler ──────────────────────────────────────────────────────────
    def _on_file_selected(self, path: str):
        self._current_file = path
        p   = Path(path)
        cat = _file_category(p)
        icon, _ = _FILE_ICONS.get(cat, _FILE_ICONS["unknown"])
        try:
            size = _fmt_size(p.stat().st_size)
        except OSError:
            size = "?"
        self._file_hint.setText(f"{icon}  {p.name}  ·  {size}")
        self._log.append_log(f"FILE: {p.name} ({size}) loaded")
        if self.on_file_selected:
            self.on_file_selected(path)
        if self.on_text_command:
            msg = (
                f"[FILE_UPLOADED] path={path} | name={p.name} | "
                f"type={p.suffix.lstrip('.')} | size={size} | "
                f"Briefly tell the user you can see the file '{p.name}' "
                f"({size}) has been uploaded and ask what they'd like to do with it."
            )
            threading.Thread(target=self.on_text_command, args=(msg,), daemon=True).start()

    # ── Mute ──────────────────────────────────────────────────────────────────
    def _toggle_mute(self):
        self._muted = not self._muted
        self._style_mute_btn()
        if self._muted:
            self._apply_state("SLEEPING")
            self._log.append_log("SYS: Microphone muted.")
        else:
            self._apply_state("LISTENING")
            self._log.append_log("SYS: Microphone active.")
        if self.on_mute_toggle:
            self.on_mute_toggle()

    def _toggle_gesture(self):
        self._gesture_enabled = not getattr(self, "_gesture_enabled", False)
        if self._gesture_enabled:
            self._gesture_btn.setText("GESTURE CONTROL: ON")
            self._gesture_btn.setStyleSheet(
                f"QPushButton {{ background: #0A1218; color: {C.STEEL}; "
                f"border: 1px solid {C.STEEL}; border-radius: 2px; }}"
                f"QPushButton:hover {{ background: #0D1A22; }}"
            )
            self._log.append_log("SYS: Gesture control enabled. Open palm = wake, closed fist = sleep.")
        else:
            self._gesture_btn.setText("GESTURE CONTROL: OFF")
            self._gesture_btn.setStyleSheet("")
            self._log.append_log("SYS: Gesture control disabled.")
        if self.on_gesture_toggle:
            self.on_gesture_toggle(self._gesture_enabled)

    def _style_mute_btn(self):
        if self._muted:
            self._mute_btn.setText("MICROPHONE MUTED")
            self._mute_btn.setStyleSheet(f"""
                QPushButton {{
                    background: #180A0A; color: {C.RED};
                    border: 1px solid {C.RED}; border-radius: 2px;
                }}
                QPushButton:hover {{ background: #220D0D; }}
            """)
        else:
            self._mute_btn.setText("MICROPHONE ACTIVE")
            self._mute_btn.setStyleSheet(f"""
                QPushButton {{
                    background: #081210; color: {C.GREEN};
                    border: 1px solid {C.GREEN}; border-radius: 2px;
                }}
                QPushButton:hover {{ background: #0C1A14; }}
            """)

    def _send(self):
        txt = self._input.text().strip()
        if not txt:
            return
        self._input.clear()
        self._log.append_log(f"You: {txt}")
        if self.on_text_command:
            threading.Thread(target=self.on_text_command, args=(txt,), daemon=True).start()

    # ── Fullscreen ────────────────────────────────────────────────────────────
    def _toggle_fullscreen(self):
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    # ── Resize ────────────────────────────────────────────────────────────────
    def resizeEvent(self, event):
        super().resizeEvent(event)
        cw = self.centralWidget()
        if self._overlay and self._overlay.isVisible():
            ow, oh = 460, 430
            self._overlay.setGeometry(
                (cw.width() - ow) // 2, (cw.height() - oh) // 2, ow, oh)
        if self._settings_overlay and self._settings_overlay.isVisible():
            ow, oh = 420, 320
            self._settings_overlay.setGeometry(
                (cw.width() - ow) // 2, (cw.height() - oh) // 2, ow, oh)
        if self._boot_overlay is not None:
            self._boot_overlay.setGeometry(0, 0, cw.width(), cw.height())

    def closeEvent(self, event):
        event.ignore()
        self.hide()

    # ── Config ────────────────────────────────────────────────────────────────
    def _check_config(self) -> bool:
        if not API_FILE.exists():
            return False
        try:
            d = json.loads(API_FILE.read_text(encoding="utf-8"))
            return (bool(d.get("gemini_api_key")) and
                    bool(d.get("openrouter_api_key")) and
                    bool(d.get("os_system")))
        except Exception:
            return False

    def _load_wake_sensitivity(self) -> float:
        if not API_FILE.exists():
            return DEFAULT_WAKE_SENSITIVITY
        try:
            d = json.loads(API_FILE.read_text(encoding="utf-8"))
            return float(d.get("wake_sensitivity", DEFAULT_WAKE_SENSITIVITY))
        except Exception:
            return DEFAULT_WAKE_SENSITIVITY

    def _load_gesture_control_enabled(self) -> bool:
        if not API_FILE.exists():
            return False
        try:
            d = json.loads(API_FILE.read_text(encoding="utf-8"))
            return bool(d.get("gesture_control_enabled", False))
        except Exception:
            return False

    def _save_wake_sensitivity(self, value: float):
        os.makedirs(CONFIG_DIR, exist_ok=True)
        data = {}
        if API_FILE.exists():
            try:
                data = json.loads(API_FILE.read_text(encoding="utf-8"))
            except Exception:
                data = {}
        data["wake_sensitivity"] = value
        API_FILE.write_text(json.dumps(data, indent=4), encoding="utf-8")

    def _on_wake_sensitivity_slider(self, value: float):
        self._wake_sensitivity = value
        if not hasattr(self, "_wake_debounce"):
            self._wake_debounce = QTimer()
            self._wake_debounce.setSingleShot(True)
            self._wake_debounce.timeout.connect(self._commit_wake_sensitivity)
        self._wake_debounce.start(400)

    def _commit_wake_sensitivity(self):
        self._save_wake_sensitivity(self._wake_sensitivity)
        if self.on_wake_sensitivity_changed:
            self.on_wake_sensitivity_changed(self._wake_sensitivity)

    def _show_settings(self):
        ov = SettingsOverlay(self._wake_sensitivity, self.centralWidget())
        cw = self.centralWidget()
        ow, oh = 420, 240
        ov.setGeometry(
            (cw.width() - ow) // 2, (cw.height() - oh) // 2, ow, oh)
        ov.changed.connect(self._on_wake_sensitivity_slider)
        ov.closed.connect(self._on_settings_closed)
        ov.show(); ov.raise_()
        self._settings_overlay = ov

    def _on_settings_closed(self):
        self._settings_overlay = None

    def _open_memory_editor(self):
        if self.on_open_memory_editor:
            self.on_open_memory_editor()

    def _show_setup(self):
        ov = SetupOverlay(self.centralWidget())
        cw = self.centralWidget()
        ow, oh = 460, 430
        ov.setGeometry(
            (cw.width() - ow) // 2, (cw.height() - oh) // 2, ow, oh)
        ov.done.connect(self._on_setup_done)
        ov.show()
        self._overlay = ov

    def _on_setup_done(self, key: str, or_key: str, os_name: str):
        os.makedirs(CONFIG_DIR, exist_ok=True)
        API_FILE.write_text(
            json.dumps({
                "gemini_api_key":     key,
                "openrouter_api_key": or_key,
                "os_system":          os_name,
            }, indent=4),
            encoding="utf-8",
        )
        self._ready = True
        if self._overlay:
            self._overlay.hide()
            self._overlay = None
        self._apply_state("LISTENING")
        self._log.append_log(f"SYS: Initialised. OS={os_name.upper()}. JARVIS online.")
        self._play_boot_sequence()


# ── Shim for root.mainloop() compatibility ────────────────────────────────────
class _RootShim:
    def __init__(self, app: QApplication): # type: ignore
        self._app = app

    def mainloop(self):
        sys.exit(self._app.exec())

    def protocol(self, *_):
        pass


# ── Public API ────────────────────────────────────────────────────────────────
class JarvisUI:
    """
    Drop-in public API consumed by main.py.

    Public methods:
        set_state(state)              — drive video + footer state label
        write_log(text)               — append to activity log
        set_speaking(is_speaking)     — convenience wrapper
        set_muted(is_muted)           — force mute state
        set_metric(name, value)       — update CPU/MEM/NET/GPU/TMP bars
        set_audio_level(level)        — push real mic/playback RMS (0.0-1.0) for voice-reactive pulse
        set_agent_progress(name, val) — update TOM/SCOUT/ADA/NOVA bars
        set_wake_sensitivity(value)   — update slider value
        show_setup_if_needed()        — show setup overlay if no config
        wait_for_api_key()            — block until config present
    """

    def __init__(self, face_path: str = "", size=None):
        self._app = QApplication.instance() or QApplication(sys.argv)
        self._app.setStyle("Fusion")
        self._app.setQuitOnLastWindowClosed(False)
        self._win = MainWindow(face_path)
        self._win.show()
        self.root = _RootShim(self._app)

    # ── Callbacks ─────────────────────────────────────────────────────────────
    @property
    def on_text_command(self):
        return self._win.on_text_command

    @on_text_command.setter
    def on_text_command(self, cb):
        self._win.on_text_command = cb

    @property
    def on_mute_toggle(self):
        return self._win.on_mute_toggle

    @on_mute_toggle.setter
    def on_mute_toggle(self, cb):
        self._win.on_mute_toggle = cb

    @property
    def on_gesture_toggle(self):
        return self._win.on_gesture_toggle

    @on_gesture_toggle.setter
    def on_gesture_toggle(self, cb):
        self._win.on_gesture_toggle = cb

    @property
    def on_file_selected(self):
        return self._win.on_file_selected

    @on_file_selected.setter
    def on_file_selected(self, cb):
        self._win.on_file_selected = cb

    @property
    def on_wake_sensitivity_changed(self):
        return self._win.on_wake_sensitivity_changed

    @on_wake_sensitivity_changed.setter
    def on_wake_sensitivity_changed(self, cb):
        self._win.on_wake_sensitivity_changed = cb

    @property
    def on_open_memory_editor(self):
        return self._win.on_open_memory_editor

    @on_open_memory_editor.setter
    def on_open_memory_editor(self, cb):
        self._win.on_open_memory_editor = cb

    # ── State ─────────────────────────────────────────────────────────────────
    @property
    def muted(self) -> bool:
        return self._win._muted

    @muted.setter
    def muted(self, v: bool):
        if v != self._win._muted:
            self._win._toggle_mute()

    @property
    def current_file(self) -> str | None:
        return self._win._drop_zone.current_file()

    @property
    def wake_sensitivity(self) -> float:
        return self._win._wake_sensitivity

    # ── Public methods ────────────────────────────────────────────────────────
    def set_state(self, state: str):
        """Drive the video panel and footer state label. Thread-safe."""
        self._win._state_sig.emit(state)

    def write_log(self, text: str):
        """Append text to the activity log. Thread-safe."""
        self._win._log_sig.emit(text)

    def set_speaking(self, is_speaking: bool):
        if is_speaking:
            self.set_state("SPEAKING")
        elif not self._win._muted:
            self.set_state("LISTENING")

    def set_muted(self, is_muted: bool):
        self.muted = is_muted

    def set_metric(self, name: str, value: float):
        """Set CPU/MEM/NET/GPU/TMP metric bar value (0-100)."""
        bar_map = {
            "CPU": getattr(self._win, "_bar_cpu", None),
            "MEM": getattr(self._win, "_bar_mem", None),
            "NET": getattr(self._win, "_bar_net", None),
            "GPU": getattr(self._win, "_bar_gpu", None),
            "TMP": getattr(self._win, "_bar_tmp", None),
        }
        bar = bar_map.get(name.upper())
        if bar is not None:
            bar.set_value(value, f"{value:.0f}%")

    def set_agent_progress(self, name: str, value: float):
        """Set TOM/SCOUT/ADA/NOVA agent progress (0-100)."""
        self._win._agent_sig.emit(name, value)

    def set_audio_level(self, level: float):
        """PHASE 1 GAP FIX: push a real 0.0-1.0 RMS amplitude sample from
        main.py's live mic/playback PCM stream — drives the hologram halo's
        voice-reactive pulse with an actual signal instead of randomness.
        Safe to call from any thread (Qt signal handles the hop to the UI
        thread)."""
        self._win._audio_level_sig.emit(level)

    def set_game_mode(self, active: bool):
        """Phase 6: Toggle the GAME MODE HUD indicator. Thread-safe."""
        try:
            self._win._game_mode_sig.emit(active)
        except Exception:
            pass

    def set_wake_sensitivity(self, value: float):
        self._win._wake_sensitivity = value

    def show_setup_if_needed(self):
        if not self._win._ready:
            self._win._show_setup()

    def wait_for_api_key(self):
        """Block the calling thread until config is confirmed."""
        while not self._win._ready:
            time.sleep(0.1)

    def start_speaking(self):
        self.set_state("SPEAKING")

    def stop_speaking(self):
        if not self._win._muted:
            self.set_state("LISTENING")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ui  = JarvisUI("face.png")
    ui.write_log("SYS: JARVIS Mark XXXIX — UI test mode")
    ui.set_state("LISTENING")
    sys.exit(app.exec())