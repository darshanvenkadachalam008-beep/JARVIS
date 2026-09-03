"""
JARVIS Background Service  —  jarvis_service.pyw
=================================================
• .pyw extension = runs with pythonw.exe = NO console window at all
• Starts silently on boot (registered by install_startup.py)
• Sits in the system tray as a small JARVIS icon
• Mic listens 24/7, fully offline, for the wake word "Hey Jarvis"
  (openWakeWord — no cloud calls, no API quota, sub-100ms detection)
• On wake word → JARVIS UI pops up on screen + session activates
• Tray menu: Show JARVIS | Mute | Settings | Quit
• Full JARVIS session runs inside this same process
"""

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Tuple, List

# ── Make sure we can import from the project folder ───────────────────────────
# This file lives in the same folder as main.py
BASE_DIR = Path(__file__).resolve().parent

# ── Watchdog support ─────────────────────────────────────────────────────
# LOCK_PATH: written with our own PID on startup. A second launch checks
# this file, confirms whether that PID is still actually alive (not just
# that the file exists — stale locks from a crash shouldn't block restart),
# and refuses to start if a genuine live instance is already running. This
# is what tonight's port-conflict/zombie-process chaos would have prevented
# entirely.
# HEARTBEAT_PATH: touched every few seconds while running. The separate
# jarvis_watchdog.py script watches this file's timestamp and restarts us
# if it goes stale (meaning we hung or died without cleaning up).
LOCK_PATH      = BASE_DIR / "memory" / "jarvis_service.lock"
HEARTBEAT_PATH = BASE_DIR / "memory" / "jarvis_heartbeat.json"
WATCHDOG_HEARTBEAT_PATH = BASE_DIR / "memory" / "watchdog_heartbeat.json"
WATCHDOG_SCRIPT         = BASE_DIR / "jarvis_watchdog.py"
VENV_PYTHONW            = BASE_DIR / "venv" / "Scripts" / "pythonw.exe"
INTENTIONAL_EXIT_PATH   = BASE_DIR / "memory" / "jarvis_intentional_exit.marker"
HEARTBEAT_INTERVAL_SECS = 10
WATCHDOG_CHECK_INTERVAL_SECS = 60
WATCHDOG_STALE_SECS          = 90
WATCHDOG_STARTUP_GRACE_SECS  = 60


def _write_service_heartbeat(path: Path = HEARTBEAT_PATH) -> None:
    """Writes the main JARVIS service heartbeat atomically with owner-only DACL."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_hb = path.with_suffix(".tmp")
        temp_hb.write_text(json.dumps({
            "pid": os.getpid(), "ts": time.time(),
        }), encoding="utf-8")
        temp_hb.replace(path)
        try:
            from sentinel.security_utils import apply_owner_only_dacl
            apply_owner_only_dacl(path)
        except Exception:
            pass
    except Exception:
        pass


def _read_watchdog_heartbeat(path: Path = WATCHDOG_HEARTBEAT_PATH) -> float | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("ts")
    except Exception:
        return None


def _launch_watchdog(python_exe: Path | None = None, script_path: Path | None = None) -> None:
    exe = python_exe or (VENV_PYTHONW if VENV_PYTHONW.exists() else Path(sys.executable))
    script = script_path or WATCHDOG_SCRIPT
    try:
        subprocess.Popen(
            [str(exe), str(script)],
            cwd=str(BASE_DIR),
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        print(f"[WatchdogMonitor] 🚀 Relaunched jarvis_watchdog.py via {exe.name}")
    except Exception as e:
        print(f"[WatchdogMonitor] ❌ Failed to relaunch jarvis_watchdog.py: {e}")


def _check_and_heal_watchdog(
    last_watchdog_relaunch_time: float,
    startup_deadline: float,
    have_seen_first_hb: bool,
    heartbeat_path: Path = WATCHDOG_HEARTBEAT_PATH,
    intentional_exit_path: Path = INTENTIONAL_EXIT_PATH,
    stale_secs: float = WATCHDOG_STALE_SECS,
    grace_secs: float = WATCHDOG_STARTUP_GRACE_SECS,
    relaunch_fn=None,
    alert_fn=None,
    key_path: Path | None = None,
) -> tuple[float, float, bool]:
    """Checks watchdog health and relaunches if missing or stale.
    Respects cryptographically authenticated INTENTIONAL_EXIT_PATH and cooldown windows.
    Emits high-priority alerts on detection.
    Returns updated (last_watchdog_relaunch_time, startup_deadline, have_seen_first_hb)."""
    from core.watchdog_auth import verify_authenticated_exit_marker

    if verify_authenticated_exit_marker(intentional_exit_path, key_path=key_path):
        return last_watchdog_relaunch_time, startup_deadline, have_seen_first_hb

    relaunch = relaunch_fn or _launch_watchdog
    ts = _read_watchdog_heartbeat(heartbeat_path)
    now = time.time()

    def _trigger_alert(reason: str):
        msg = f"⚠️ [WATCHDOG ALERT] Watchdog process {reason} — auto-relaunch triggered."
        print(f"[WatchdogMonitor] {msg}")
        if alert_fn:
            try:
                alert_fn(msg)
            except Exception as e:
                print(f"[WatchdogMonitor] Failed to send alert via alert_fn: {e}")
        else:
            try:
                from core.telegram_alerter import TelegramAlerter
                TelegramAlerter().send(msg)
            except Exception:
                pass
            try:
                from core.audit_log import AuditLog
                AuditLog().append("watchdog_relaunch_triggered", {"reason": reason, "timestamp": now})
            except Exception:
                pass

    if ts is not None:
        have_seen_first_hb = True
        age = now - ts
        if age > stale_secs:
            if now - last_watchdog_relaunch_time > grace_secs:
                _trigger_alert(f"heartbeat stale ({age:.0f}s old, limit {stale_secs}s)")
                relaunch()
                last_watchdog_relaunch_time = now
                startup_deadline = now + grace_secs
    else:
        # No heartbeat file found
        if not have_seen_first_hb and now < startup_deadline:
            pass  # within initial startup grace period
        elif now - last_watchdog_relaunch_time > grace_secs:
            _trigger_alert("heartbeat file missing (process not running)")
            relaunch()
            last_watchdog_relaunch_time = now
            startup_deadline = now + grace_secs
            have_seen_first_hb = False

    return last_watchdog_relaunch_time, startup_deadline, have_seen_first_hb


def _email_wipe_listener_loop(
    listener: Any = None,
    poll_interval_secs: float = 60.0,
    stop_event: threading.Event | None = None,
) -> None:
    """
    Background polling loop monitoring the dedicated inbox for signed emergency wipe commands.
    Catches per-cycle errors to ensure resilient continuous polling without terminating the loop.
    Interval: 60 seconds (responsive to emergency triggers while preventing IMAP rate limits).
    """
    if listener is None:
        try:
            from core.email_wipe_listener import EmailWipeListener
            listener = EmailWipeListener()
        except Exception as e:
            print(f"[EmailWipeListener] Failed to initialize: {e}")
            return

    while stop_event is None or not stop_event.is_set():
        try:
            listener.poll_inbox()
        except Exception as e:
            print(f"[EmailWipeListener] Error during inbox polling cycle: {e}")

        if stop_event is not None:
            if stop_event.wait(timeout=poll_interval_secs):
                break
        else:
            time.sleep(poll_interval_secs)


# Intercom audio format — must match the phone-side JS exactly (16kHz mono
# 16-bit PCM). This is intentionally a separate, dedicated stream from the
# voice assistant's own SEND_SAMPLE_RATE/RECEIVE_SAMPLE_RATE mic/speaker
# streams, so the two features don't fight over the same audio device
# handles when both happen to be active at once.
INTERCOM_SAMPLE_RATE = 16000
INTERCOM_CHUNK_SIZE  = 1024
sys.path.insert(0, str(BASE_DIR))

# ── Redirect stdout/stderr to a log file (no console available in .pyw) ───────
LOG_PATH = BASE_DIR / "memory" / "jarvis_service.log"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

class _Tee:
    """
    Write to both the log file and the original stream (console), if one
    is attached.

    BUGFIX: the docstring always said "Write to both log file and original
    stream (if any)", but write() only ever wrote to self._f (the log
    file) — the original stream was captured in __init__ and then never
    touched again. Launched via pythonw.exe (the normal way) this made no
    visible difference, since there's no console to write to anyway. But
    it meant that even running this file with `python jarvis_service.pyw`
    (a real console attached, specifically *for* debugging) produced
    total silence on screen — any startup crash went only to the log
    file, and nothing told you the log file was where to look. Genuinely
    writing to both now, so a console, when present, actually shows you
    what's happening in real time instead of only the log file after the
    fact.
    """
    def __init__(self, path: Path, original=None):
        self._f = open(path, "a", encoding="utf-8", buffering=1)
        self._original = original

    def write(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self._f.write(f"[{ts}] {msg}")
        if self._original is not None:
            try:
                self._original.write(msg)
            except Exception:
                pass   # never let a console-write problem break logging

    def flush(self):
        self._f.flush()
        if self._original is not None:
            try:
                self._original.flush()
            except Exception:
                pass

if "pytest" not in sys.modules:
    _orig_stdout, _orig_stderr = sys.stdout, sys.stderr
    sys.stdout = _Tee(LOG_PATH, _orig_stdout)
    sys.stderr = _Tee(LOG_PATH, _orig_stderr)
    print(f"[Startup] Logging to {LOG_PATH}")

# BUGFIX: previously, any exception raised at IMPORT time (before the
# try/except a few lines below even starts) — e.g. a broken dependency,
# a syntax error in an imported module, anything Python itself raises
# during `import X` — would print a traceback to sys.stderr (now correctly
# going to both the log AND a console, per the _Tee fix above) and then
# the interpreter exits with code 1. That part always worked. What did NOT
# work: launched normally via pythonw.exe (no console, the standard way
# this app starts), that traceback had nowhere user-visible to go at all
# except the log file — so a single broken import meant JARVIS would
# never start, with zero indication anything was wrong: no tray icon, no
# balloon, no window, nothing. sys.excepthook below guarantees that even
# a startup-time crash this early gets one more attempt at visibility: a
# native Windows message box, which doesn't depend on a console, a tray
# icon, or any UI JARVIS itself would otherwise need to exist first.
def _crash_messagebox(exc_type, exc_value, exc_tb):
    tb_text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    print(f"[FATAL] Unhandled exception at startup:\n{tb_text}")
    try:
        import ctypes
        short = f"{exc_type.__name__}: {exc_value}"
        ctypes.windll.user32.MessageBoxW(
            0,
            f"JARVIS failed to start:\n\n{short}\n\n"
            f"Full details were written to:\n{LOG_PATH}",
            "JARVIS — Startup Error",
            0x10  # MB_ICONERROR
        )
    except Exception:
        pass   # not on Windows, or ctypes unavailable — log file is still written

sys.excepthook = _crash_messagebox

# ── Now import everything ─────────────────────────────────────────────────────
import importlib
import sounddevice as sd
import numpy as np

try:
    QtCore = importlib.import_module("PyQt6.QtCore")
    QtGui = importlib.import_module("PyQt6.QtGui")
    QtWidgets = importlib.import_module("PyQt6.QtWidgets")
    PYQT = 6
except ImportError:
    QtCore = importlib.import_module("PyQt5.QtCore")
    QtGui = importlib.import_module("PyQt5.QtGui")
    QtWidgets = importlib.import_module("PyQt5.QtWidgets")
    PYQT = 5

Qt = QtCore.Qt
QTimer = QtCore.QTimer
QThread = QtCore.QThread
pyqtSignal = QtCore.pyqtSignal
QObject = QtCore.QObject
QIcon = QtGui.QIcon
QPixmap = QtGui.QPixmap
QColor = QtGui.QColor
QPainter = QtGui.QPainter
QFont = QtGui.QFont
QApplication = QtWidgets.QApplication
QSystemTrayIcon = QtWidgets.QSystemTrayIcon
QMenu = QtWidgets.QMenu
QAction = QtGui.QAction if hasattr(QtGui, "QAction") else QtWidgets.QAction
QMessageBox = QtWidgets.QMessageBox

from google import genai

# ── Project imports ───────────────────────────────────────────────────────────
from ui import JarvisUI
from core.wake_word import WakeWordEngine
from memory.memory_manager import (
    load_memory, update_memory, format_memory_for_prompt,
    should_extract_memory, extract_memory,
    search_memory, format_search_results,
)
from core.proactive_intelligence import ProactiveIntelligence
from core.states import JarvisState
from core.gesture_control import GestureControlEngine
from actions.file_processor    import file_processor
from actions.flight_finder     import flight_finder
from actions.open_app          import open_app
from actions.weather_report    import weather_action
from actions.send_message      import send_message
from actions.reminder          import reminder
from actions.computer_settings import computer_settings
from actions.screen_processor  import screen_process
from mobile_server             import MobileServer   # Phase 7
from core.intruder_alert       import IntruderAlertWatcher   # Phase 7 — security alert
from actions.youtube_video     import youtube_video
from actions.desktop           import desktop_control
from actions.browser_control   import browser_control
from actions.file_controller   import file_controller
from actions.code_helper       import code_helper
from actions.dev_agent         import dev_agent
from actions.web_search        import web_search as web_search_action
from actions.computer_control  import computer_control
from actions.game_updater      import game_updater

# ── Import the new Phase-1 tool declarations + handlers from main.py ──────────
# We reuse everything from main.py so there is zero duplication.
from main import (
    TOOL_DECLARATIONS,
    LIVE_MODEL,
    CHANNELS,
    SEND_SAMPLE_RATE,
    RECEIVE_SAMPLE_RATE,
    CHUNK_SIZE,
    ACTIVE_TIMEOUT_SECS,
    _get_api_key,
    _get_wake_sensitivity,
    _save_wake_sensitivity,
    _get_noise_floor_rms,
    _save_noise_floor_rms,
    _get_gesture_control_enabled,
    _save_gesture_control_enabled,
    _load_system_prompt,
    _load_bi_data,
    _save_bi_data,
    _load_briefing_state,
    _save_briefing_state,
    _update_memory_async,
    _handle_app_stats,
    _handle_content_metrics,
    _handle_ads_performance,
    _handle_email_triage,
    _handle_delegate_task,
    _handle_daily_briefing,
    _handle_set_briefing_schedule,
    _speak_via_edge_tts,
    _clean_report_for_speech,
    BriefingScheduler,
)
from google.genai import types
from core.vad_filter import MicEnergyFilter, DEFAULT_NOISE_FLOOR_RMS


# ═══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

API_CONFIG_PATH = BASE_DIR / "config" / "api_keys.json"
FACE_PATH       = str(BASE_DIR / "face.png")


# ═══════════════════════════════════════════════════════════════════════════════
#  TRAY ICON BUILDER  (draws a simple "J" icon if face.png not found)
# ═══════════════════════════════════════════════════════════════════════════════

def _make_tray_icon() -> QIcon:
    """Return a tray icon: uses face.png if present, else draws a blue J."""
    face = BASE_DIR / "face.png"
    if face.exists():
        px = QPixmap(str(face)).scaled(64, 64)
        return QIcon(px)

    # Draw fallback icon
    px = QPixmap(64, 64)
    px.fill(QColor("#0a0a1a"))
    p = QPainter(px)
    p.setPen(QColor("#00d4ff"))
    f = QFont("Arial", 36, QFont.Weight.Bold)
    p.setFont(f)
    p.drawText(px.rect(), Qt.AlignmentFlag.AlignCenter, "J")
    p.end()
    return QIcon(px)


# ═══════════════════════════════════════════════════════════════════════════════
#  ALWAYS-ON WAKE-WORD LISTENER  (runs before UI is shown)
# ═══════════════════════════════════════════════════════════════════════════════

class AlwaysOnListener(QObject):
    """
    Thin Qt wrapper around core.wake_word.WakeWordEngine — fully offline
    "Hey Jarvis" detection via openWakeWord, no audio ever leaves the
    machine and no Gemini quota is used just to hear the wake word.

    WakeWordEngine runs its own background thread; this class just
    re-emits its callback as a Qt signal so it can be safely connected
    to slots on the Qt main thread (PyQt queues cross-thread emits
    automatically).
    """
    wakeDetected = pyqtSignal()
    loadFailed   = pyqtSignal(str)   # BUGFIX: see __init__ docstring below

    def __init__(self, threshold: float | None = None):
        super().__init__()
        if threshold is None:
            threshold = _get_wake_sensitivity()
        # BUGFIX: previously WakeWordEngine(on_wake=..., threshold=...) was
        # constructed with NO on_error callback. WakeWordEngine.start() never
        # raises on a model-load failure (missing openwakeword/onnxruntime,
        # missing bundled .onnx file, etc.) by design — it calls on_error(msg)
        # instead so the failure is visible somewhere. With on_error left
        # unset, that message went to print(), which is a no-op in a .pyw
        # process (no console attached on Windows) — so a load failure
        # produced total, permanent silence: no wake response, ever, with
        # nothing in any log to explain why. loadFailed re-emits that error
        # as a Qt signal so JarvisTrayApp can surface it via the tray balloon
        # and (once the window exists) the Activity Log — see
        # JarvisTrayApp.__init__ / _on_listener_load_failed.
        self._engine = WakeWordEngine(
            on_wake=self._emit_wake,
            threshold=threshold,
            on_error=self._emit_load_failed,
        )

    def _emit_wake(self):
        self.wakeDetected.emit()

    def _emit_load_failed(self, message: str):
        self.loadFailed.emit(message)

    @property
    def load_error(self) -> str | None:
        """Set after start() if the wake-word model failed to load."""
        return self._engine.load_error

    def start(self):
        self._engine.start()

    def stop(self):
        self._engine.stop()

    def pause(self):
        self._engine.pause()

    def resume(self):
        self._engine.resume()

    def set_threshold(self, value: float):
        self._engine.set_threshold(value)
        _save_wake_sensitivity(value)


class AlwaysOnGestureListener(QObject):
    """
    Thin Qt wrapper around core.gesture_control.GestureControlEngine —
    same pattern as AlwaysOnListener above, but for the webcam gesture
    engine instead of the mic wake-word engine.

    GAP THIS FIXES: main.py's JarvisLive has had full gesture control
    (open palm = wake, closed fist = sleep) wired in for a while. This
    jarvis_service.pyw file — the one that actually runs on cold boot via
    Task Scheduler / startup registry — never imported or instantiated
    GestureControlEngine at all, so gesture control silently did not
    exist in the background service, even when enabled in Settings. This
    class + its wiring in JarvisTrayApp below is what closes that gap,
    the same way ProactiveIntelligence was wired in previously (see the
    BUGFIX comment on that in JarvisSession.__init__).

    Lives at the JarvisTrayApp level (like AlwaysOnListener), not inside
    JarvisSession, because the whole point of gesture wake is to work
    *before* the UI/session exist yet — JarvisTrayApp._ensure_ui() only
    creates them lazily on first wake.

    GestureControlEngine runs its own background camera thread; this
    class re-emits its callbacks as Qt signals so they're safely handled
    on the Qt main thread (PyQt queues cross-thread emits automatically).

    Off by default — camera access is opt-in, same as main.py. Only
    starts if the user previously enabled it via the Settings toggle
    (persisted in config/api_keys.json, shared with main.py via the
    imported _get_gesture_control_enabled/_save_gesture_control_enabled
    helpers above — one source of truth, not a second copy of the flag).
    """
    gestureWake  = pyqtSignal()
    gestureSleep = pyqtSignal()
    gestureError = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self._engine = GestureControlEngine(
            on_gesture={
                "Open_Palm":   self._emit_wake,
                "Closed_Fist": self._emit_sleep,
            },
            on_error=self._emit_error,
        )

    def _emit_wake(self):
        self.gestureWake.emit()

    def _emit_sleep(self):
        self.gestureSleep.emit()

    def _emit_error(self, message: str):
        self.gestureError.emit(message)

    def start(self):
        self._engine.start()

    def stop(self):
        self._engine.stop()


# ═══════════════════════════════════════════════════════════════════════════════
#  JARVIS SESSION RUNNER  (same logic as JarvisLive in main.py)
# ═══════════════════════════════════════════════════════════════════════════════

class JarvisSession:
    """Full JARVIS live session — identical to JarvisLive but without its own
    wake-word detector (the AlwaysOnListener above handles that)."""

    def __init__(self, ui: JarvisUI, wake_listener=None, mobile=None):
        self.ui             = ui
        self.session        = None
        self._loop          = None
        self._is_speaking   = False
        self._speaking_lock = threading.Lock()
        self._tool_in_flight = False
        self._response_in_progress = threading.Event()
        # Parity fixes with main.py's JarvisLive — see _thinking_watchdog
        # and _idle_keepalive below for why these two are tracked.
        self._thinking_since = None
        self._last_activity  = time.time()
        self.audio_in_queue = None
        self.out_queue      = None
        self.ui.on_text_command = self._on_text_cmd
        self._wake_listener = wake_listener
        # Phase 7: direct reference to the MobileServer instance, passed
        # in from JarvisTrayApp. Used below in run_forever() to forward
        # proactive notifications to the phone.
        #
        # BUGFIX: this used to be reached via
        # `self._session._tray_app._mobile` inside run_forever(), but
        # JarvisSession never had a `_tray_app` attribute anywhere — that
        # lookup always raised AttributeError, silently swallowed by a
        # bare `except Exception: pass` around it. So proactive
        # notifications (pattern detection, weather warnings, news
        # digest, reminders) never actually reached the phone, even
        # though MobileServer.notify() worked fine when called directly
        # (e.g. from the intruder alert watcher). Storing the reference
        # directly here removes the broken indirection.
        self._mobile = mobile
        self.ui.on_wake_sensitivity_changed = self._on_wake_sensitivity_changed
        self._mic_filter = MicEnergyFilter(threshold_rms=_get_noise_floor_rms())
        # SAFETY NET: timestamp of the most recent set_speaking(True). Used
        # by _speaking_watchdog() as a second, independent line of defense
        # against the mic getting permanently wedged shut — see the
        # DEADLOCK FIX comment in _play_audio for the actual root cause
        # this is guarding against. Even with that fixed, a stuck flag
        # silently kills ALL voice input for the rest of the session with
        # zero visible symptoms (the UI still shows LISTENING), so this is
        # worth having as a backstop rather than relying on one fix holding
        # forever across every future code change.
        self._speaking_since = None

        # ── Phase 4 FIX: ProactiveIntelligence was fully built and wired
        # into main.py's JarvisLive (morning briefings, pattern detection,
        # weather warnings, news digest) but never imported or instantiated
        # here in JarvisSession — the class that actually runs as the
        # background tray service. That meant the entire feature was dead
        # on arrival for real usage. Wired identically to main.py below.
        #
        # ProactiveIntelligence.get_state() expects a JarvisState enum
        # member (it compares against ACTIVE_CONVERSATION/SHUTDOWN/
        # SLEEPING). JarvisSession has no StateManager — it just sets plain
        # UI label strings ("LISTENING"/"SLEEPING"/"THINKING"/"SPEAKING")
        # directly. _proactive_state_adapter() below maps those strings (and
        # the speaking/tool-in-flight flags) onto the closest JarvisState
        # value so ProactiveIntelligence can reuse the same interruption
        # rules without requiring a full state-machine rewrite here.
        # ── Phase 4: Proactive Bridge (Unified Proactive Push) ────────────────
        from core.proactive_bridge import ProactiveBridge
        self._proactive_bridge = ProactiveBridge(
            get_state=lambda: "SPEAKING" if self._is_speaking else "LISTENING",
            voice_sink=self.speak,
            ui_sink=self.ui.write_log if self.ui else None,
            interrupt_sink=self._interrupt_playback,
        )

        # Wire EmergencyWipeController singleton to ProactiveBridge for CRITICAL blocked wipe alerts
        try:
            from core.sentinel_extras import EmergencyWipeController
            EmergencyWipeController.get_instance().set_bridge(self._proactive_bridge)
        except Exception as _we:
            print(f"[WipeController] Bridge wiring skipped: {_we}")

        self._memory_editor = None

        self.ui.on_open_memory_editor = self._open_memory_editor_ui
        self._proactive = ProactiveIntelligence(
            get_state  = self._proactive_state_adapter,
            speak_fn   = self.speak,
            log_fn     = self.ui.write_log,
            weather_fn = weather_action,
        )

        # ── PARITY FIX: voice emotion detector — main.py's JarvisLive has
        # had this since it was added, but it was never ported here, so
        # the "sir, your voice sounds tense/tired" prompts silently never
        # fired in the background service. Wired identically to main.py:
        # fed raw mic PCM in _listen_audio below, speaks via self.inject()
        # (same path self.speak() uses) rather than self.speak() directly,
        # matching main.py's use of self._inject_text().
        from core.voice_emotion import VoiceEmotionDetector
        def _on_mood(state: str):
            _mood_prompts = {
                "stressed": (
                    "I notice your voice sounds a bit tense, sir. "
                    "Would you like to take a short break, or shall I help lighten the load?"
                ),
                "tired": (
                    "Sir, your voice suggests you may be fatigued. "
                    "Might I suggest wrapping up for now?"
                ),
                "calm": None,   # no interruption for calm — just update state silently
            }
            msg = _mood_prompts.get(state)
            if msg:
                try:
                    self.inject(msg)
                except Exception:
                    pass
        self._emotion = VoiceEmotionDetector(on_state_change=_on_mood)

    def _proactive_state_adapter(self) -> JarvisState:
        """Maps JarvisSession's plain UI-label state onto the JarvisState
        enum that ProactiveIntelligence expects (see __init__ comment)."""
        with self._speaking_lock:
            speaking = self._is_speaking
        if speaking or self._tool_in_flight:
            return JarvisState.ACTIVE_CONVERSATION
        label = self.ui._win._current_state if hasattr(self.ui, '_win') else "LISTENING"
        if label == "SLEEPING":
            return JarvisState.SLEEPING
        if label in ("THINKING", "SPEAKING"):
            return JarvisState.ACTIVE_CONVERSATION
        return JarvisState.LISTENING

    def _open_memory_editor_ui(self):
        """Show the Memory Bank overlay (creates it lazily) — mirrors
        main.py's _open_memory_editor_ui exactly."""
        from memory.memory_editor import MemoryEditorOverlay
        if self._memory_editor is None:
            self._memory_editor = MemoryEditorOverlay()
            self._memory_editor.closed.connect(lambda: None)
        else:
            self._memory_editor.refresh()
        self._memory_editor.show()
        self._memory_editor.raise_()
        self.ui.write_log("SYS: Memory Bank opened")

    async def _speaking_watchdog(self):
        """If set_speaking(True) was called but nothing cleared it within
        a generous window, something is wrong (stray late chunk, an
        exception that skipped the finally block's cleanup before this fix,
        etc.) — force it back to False rather than silently losing the mic
        for the rest of the session. 8s is far longer than any real reply
        chunk gap should ever be."""
        STUCK_AFTER_SECS = 8.0
        while True:
            await asyncio.sleep(2.0)
            with self._speaking_lock:
                stuck = (
                    self._is_speaking
                    and self._speaking_since is not None
                    and (time.time() - self._speaking_since) > STUCK_AFTER_SECS
                )
            if stuck:
                print(f"[DIAG] ⚠️ speaking flag stuck True for >{STUCK_AFTER_SECS}s — "
                      f"forcing it back to False so the mic isn't wedged shut.")
                self.set_speaking(False)

    async def _idle_keepalive(self):
        """PARITY FIX — ported from main.py's JarvisLive, previously
        missing entirely from the background service.

        Persistent, session-wide keepalive. JARVIS spends the majority of
        its life SLEEPING (mic muted, only the wake-word engine listens)
        or idle between turns — _listen_audio's callback intentionally
        sends nothing during that time. That silence is exactly what
        trips the Gemini Live API's ~60s no-audio session timeout, which
        looks like a random "connection dropped" but is really just an
        ordinary idle gap. This pings 100ms of silent PCM every
        PING_INTERVAL seconds whenever nothing else has sent real audio
        recently, and steps aside the instant real audio or a tool-call
        keepalive is already covering it.
        """
        SILENT_CHUNK  = b"\x00\x00" * (SEND_SAMPLE_RATE // 10)  # 100ms @ 16kHz, int16
        PING_INTERVAL = 20  # seconds — comfortably under the ~60s silence timeout
        try:
            while True:
                await asyncio.sleep(PING_INTERVAL)
                if (time.time() - self._last_activity) < PING_INTERVAL:
                    continue
                if self._tool_in_flight:
                    continue  # _keepalive_during_tool() already covers this
                if not self.session:
                    continue
                try:
                    await self.session.send_realtime_input(
                        media={"data": SILENT_CHUNK, "mime_type": "audio/pcm"}
                    )
                except Exception:
                    pass
        except asyncio.CancelledError:
            pass

    async def _thinking_watchdog(self):
        """PARITY FIX — ported from main.py's JarvisLive, previously
        missing entirely from the background service.

        Force-recovers if the THINKING label gets stuck with no
        follow-up (a dropped/empty response, a tool that raises before
        producing speech, a turn Gemini silently swallows) — otherwise
        nothing clears THINKING and the orb sits frozen forever.
        """
        CHECK_INTERVAL = 2
        STUCK_TIMEOUT  = 20
        try:
            while True:
                await asyncio.sleep(CHECK_INTERVAL)
                since = self._thinking_since
                if since is None or (time.time() - since) < STUCK_TIMEOUT:
                    continue
                self._thinking_since = None
                with self._speaking_lock:
                    self._is_speaking = False
                if not self.ui.muted:
                    self.ui.set_state("LISTENING")
                self.ui.write_log(
                    "SYS: No reply came back in time, sir — JARVIS is ready "
                    "again. Please repeat your request."
                )
        except asyncio.CancelledError:
            pass

    def _on_text_cmd(self, text: str):
        if not self._loop or not self.session:
            return
        asyncio.run_coroutine_threadsafe(
            self.session.send_client_content(
                turns={"parts": [{"text": text}]},
                turn_complete=True
            ),
            self._loop
        )

    def inject(self, text: str):
        """Push a message into the live session from outside (wake word / briefing)."""
        if not self._loop or not self.session:
            return
        asyncio.run_coroutine_threadsafe(
            self.session.send_client_content(
                turns={"parts": [{"text": text}]},
                turn_complete=True
            ),
            self._loop
        )

    def set_speaking(self, v: bool):
        with self._speaking_lock:
            self._is_speaking = v
            self._speaking_since = time.time() if v else None
        if self._wake_listener:
            if v:
                self._wake_listener.pause()
            else:
                self._wake_listener.resume()
        if v:
            self.ui.set_state("SPEAKING")
            self._thinking_since = None   # Gemini responded — no longer stuck
        else:
            if not self.ui.muted:
                self.ui.set_state("LISTENING")

        if hasattr(self, "_proactive_bridge") and self._proactive_bridge:
            self._proactive_bridge.on_state_change("SPEAKING" if v else "LISTENING")

    def _interrupt_playback(self):
        """Phase 2: Immediately stops playback, drains incoming audio queue, and opens mic for barge-in."""
        with self._speaking_lock:
            self._is_speaking = False
            self._speaking_since = None
        if self._wake_listener:
            self._wake_listener.resume()
        try:
            import pygame
            if pygame.mixer.get_init():
                pygame.mixer.music.stop()
        except Exception:
            pass
        try:
            import sounddevice as _sd
            _sd.stop()
        except Exception:
            pass
        if self.audio_in_queue:
            while not self.audio_in_queue.empty():
                try:
                    self.audio_in_queue.get_nowait()
                except Exception:
                    break
        if not self.ui.muted:
            self.ui.set_state("LISTENING")
        print("[BARGE-IN] 🛑 Interrupted JARVIS playback; drained audio queue, halted TTS, and returned to LISTENING.")

    def _on_wake_sensitivity_changed(self, value: float):
        if self._wake_listener:
            self._wake_listener.set_threshold(value)
        self.ui.write_log(f"SYS: Wake-word sensitivity set to {value:.2f}")

    def speak(self, text: str):
        self.inject(text)

    def speak_error(self, tool: str, err):
        self.ui.write_log(f"ERR: {tool} — {str(err)[:120]}")
        self.speak(f"Sir, {tool} encountered an error. {str(err)[:120]}")

    def _build_config(self) -> types.LiveConnectConfig:
        memory    = load_memory()
        mem_str   = format_memory_for_prompt(memory)
        sys_prompt = _load_system_prompt()
        bi_data   = _load_bi_data()

        now      = datetime.now()
        time_str = now.strftime("%A, %B %d, %Y — %I:%M %p")

        parts = [
            f"[CURRENT DATE & TIME]\nRight now it is: {time_str}\n",
            "[OPERATIONAL MODE]\nYou are a persistent background service. "
            "You woke up because the user said your wake word. "
            "You behave like Tony Stark's JARVIS — always on, proactive, sharp.\n",
            "[AGENT ROSTER]\n"
            "  • Tom   — developer agent\n"
            "  • Scout — research agent\n"
            "  • Ada   — content agent\n"
            "  • Nova  — analytics agent\n",
        ]
        if bi_data.get("business_context"):
            parts.append(
                "[BUSINESS CONTEXT]\n" +
                json.dumps(bi_data["business_context"], indent=2) + "\n"
            )
        if mem_str:
            parts.append(mem_str)
        parts.append(sys_prompt)
        parts.append(
            "\n[BACKGROUND SERVICE]\n"
            "You started automatically when the user's PC booted. "
            "The user did NOT open VS Code or run any command. "
            "They just said your wake word. Acknowledge naturally and wait.\n"
        )

        return types.LiveConnectConfig(
            response_modalities=["AUDIO"],
            output_audio_transcription={},
            input_audio_transcription={},
            system_instruction="\n".join(parts),
            tools=[{"function_declarations": TOOL_DECLARATIONS}],
            session_resumption=types.SessionResumptionConfig(),
            speech_config=types.SpeechConfig(
                voice_config=types.VoiceConfig(
                    prebuilt_voice_config=types.PrebuiltVoiceConfig(
                        voice_name="Charon"
                    )
                )
            ),
        )

    async def _keepalive_during_tool(self):
        SILENT_CHUNK = b"\x00\x00" * (16000 // 10)
        try:
            while True:
                await asyncio.sleep(5)
                if self.session:
                    try:
                        await self.session.send_realtime_input(
                            media={"data": SILENT_CHUNK, "mime_type": "audio/pcm"}
                        )
                    except Exception:
                        pass
        except asyncio.CancelledError:
            pass

    async def _execute_tool(self, fc) -> types.FunctionResponse:
        name = fc.name
        args = dict(fc.args or {})
        print(f"[JARVIS] 🔧 {name}  {args}")
        with self._speaking_lock:
            _currently_speaking = self._is_speaking
        if not _currently_speaking:
            self.ui.set_state("THINKING")
            self._thinking_since = time.time()

        if name == "save_memory":
            cat, key, val = args.get("category","notes"), args.get("key",""), args.get("value","")
            if key and val:
                update_memory({cat: {key: {"value": val}}})
            if not self.ui.muted: self.ui.set_state("LISTENING")
            return types.FunctionResponse(id=fc.id, name=name, response={"result":"ok","silent":True})

        loop   = asyncio.get_event_loop()
        result = "Done."
        try:
            if   name == "open_app":         r = await loop.run_in_executor(None, lambda: open_app(parameters=args, response=None, player=self.ui));                result = r or f"Opened {args.get('app_name')}."
            elif name == "weather_report":   r = await loop.run_in_executor(None, lambda: weather_action(parameters=args, player=self.ui));                         result = r or "Weather delivered."
            elif name == "browser_control":  r = await loop.run_in_executor(None, lambda: browser_control(parameters=args, player=self.ui));                        result = r or "Done."
            elif name == "file_controller":  r = await loop.run_in_executor(None, lambda: file_controller(parameters=args, player=self.ui));                        result = r or "Done."
            elif name == "send_message":     r = await loop.run_in_executor(None, lambda: send_message(parameters=args, response=None, player=self.ui, session_memory=None)); result = r or "Sent."
            elif name == "reminder":         r = await loop.run_in_executor(None, lambda: reminder(parameters=args, response=None, player=self.ui));                result = r or "Reminder set."
            elif name == "youtube_video":    r = await loop.run_in_executor(None, lambda: youtube_video(parameters=args, response=None, player=self.ui));            result = r or "Done."
            elif name == "computer_settings":r = await loop.run_in_executor(None, lambda: computer_settings(parameters=args, response=None, player=self.ui));       result = r or "Done."
            elif name == "desktop_control":  r = await loop.run_in_executor(None, lambda: desktop_control(parameters=args, player=self.ui));                        result = r or "Done."
            elif name == "code_helper":      r = await loop.run_in_executor(None, lambda: code_helper(parameters=args, player=self.ui, speak=self.speak));          result = r or "Done."
            elif name == "dev_agent":        r = await loop.run_in_executor(None, lambda: dev_agent(parameters=args, player=self.ui, speak=self.speak));             result = r or "Done."
            elif name == "web_search":
                keepalive = asyncio.ensure_future(self._keepalive_during_tool())
                try:
                    r = await loop.run_in_executor(None, lambda: web_search_action(parameters=args, player=self.ui))
                finally:
                    keepalive.cancel()
                search_result = r or "No results found."
                threading.Thread(
                    target=_speak_via_edge_tts,
                    args=(_clean_report_for_speech(search_result), self.ui, self.set_speaking),
                    daemon=True
                ).start()
                result = "[SEARCH_RESULT_DELIVERED_VIA_EDGE_TTS] The search result is already being spoken aloud by the edge-tts engine. Do NOT repeat or summarise it. Stay completely silent."
            elif name == "computer_control": r = await loop.run_in_executor(None, lambda: computer_control(parameters=args, player=self.ui));                       result = r or "Done."
            elif name == "game_updater":     r = await loop.run_in_executor(None, lambda: game_updater(parameters=args, player=self.ui, speak=self.speak));         result = r or "Done."
            elif name == "flight_finder":    r = await loop.run_in_executor(None, lambda: flight_finder(parameters=args, player=self.ui));                          result = r or "Done."
            elif name == "file_processor":
                if not args.get("file_path") and self.ui.current_file:
                    args["file_path"] = self.ui.current_file
                r = await loop.run_in_executor(None, lambda: file_processor(parameters=args, player=self.ui, speak=self.speak))
                result = r or "Done."
            elif name == "screen_process":
                threading.Thread(target=screen_process, kwargs={"parameters":args,"response":None,"player":self.ui,"session_memory":None}, daemon=True).start()
                result = "Vision module activated. Stay completely silent — vision module will speak directly."
            elif name == "agent_task":
                from agent.task_queue import get_queue, TaskPriority
                pm = {"low":TaskPriority.LOW,"normal":TaskPriority.NORMAL,"high":TaskPriority.HIGH}
                tid = get_queue().submit(goal=args.get("goal",""), priority=pm.get(args.get("priority","normal"),TaskPriority.NORMAL), speak=self.speak)
                result = f"Task started (ID: {tid})."
            elif name == "app_stats":        result = await loop.run_in_executor(None, lambda: _handle_app_stats(args))
            elif name == "content_metrics":  result = await loop.run_in_executor(None, lambda: _handle_content_metrics(args))
            elif name == "ads_performance":  result = await loop.run_in_executor(None, lambda: _handle_ads_performance(args))
            elif name == "email_triage":     result = await loop.run_in_executor(None, lambda: _handle_email_triage(args))
            elif name == "delegate_task":    result = await loop.run_in_executor(None, lambda: _handle_delegate_task(args))
            elif name == "daily_briefing":
                keepalive = asyncio.ensure_future(self._keepalive_during_tool())
                try:
                    result = await loop.run_in_executor(None, lambda: _handle_daily_briefing(args, self.speak, ui=self.ui, set_speaking=self.set_speaking))
                finally:
                    keepalive.cancel()
            elif name == "set_briefing_schedule": result = await loop.run_in_executor(None, lambda: _handle_set_briefing_schedule(args))

            # ── Phase 5 FIX: persona_task was declared in TOOL_DECLARATIONS
            # (shared with main.py) and worked correctly in main.py's
            # JarvisLive — but had no matching branch here, so every call to
            # Tom/Scout/Ada/Nova via the actual tray app silently fell
            # through to "Unknown tool: persona_task" below. Ported
            # verbatim from main.py's _execute_tool.
            elif name == "persona_task":
                from agents.agent_manager import get_manager
                task       = args.get("task", "")
                agent_name = args.get("agent_name") or None
                if agent_name and agent_name.capitalize() not in ("Tom", "Scout", "Ada", "Nova"):
                    agent_name = None
                elif agent_name:
                    agent_name = agent_name.capitalize()
                keepalive = asyncio.ensure_future(self._keepalive_during_tool())
                try:
                    r = await loop.run_in_executor(
                        None,
                        lambda: get_manager().route_direct(task, agent_name=agent_name, speak=self.speak)
                    )
                finally:
                    keepalive.cancel()
                report = r or "Agent task completed with no output."
                threading.Thread(
                    target=_speak_via_edge_tts,
                    args=(_clean_report_for_speech(report), self.ui, self.set_speaking),
                    daemon=True
                ).start()
                result = (
                    "[PERSONA_REPORT_DELIVERED_VIA_EDGE_TTS] The full report is already "
                    "in the Activity Log and is being spoken aloud right now by the "
                    "edge-tts engine. Do NOT repeat, summarise, or read it back. Stay "
                    "completely silent."
                )

            elif name == "search_memory":
                query   = args.get("query", "").strip()
                m_results = search_memory(query)
                result  = format_search_results(query, m_results)

            elif name == "open_memory_editor":
                self._open_memory_editor_ui()
                result = "Memory Bank opened, sir."

            # ── Phase 4 FIX: same gap as persona_task — declared, never
            # dispatched here. Ported verbatim from main.py.
            elif name == "get_morning_briefing":
                result = self._proactive.get_morning_briefing()

            elif name == "get_news_digest":
                keepalive = asyncio.ensure_future(self._keepalive_during_tool())
                try:
                    news_prompt = await loop.run_in_executor(None, self._proactive.get_news_digest)
                finally:
                    keepalive.cancel()
                if self.session and self._loop:
                    asyncio.run_coroutine_threadsafe(
                        self.session.send_client_content(
                            turns={"parts": [{"text": news_prompt}]},
                            turn_complete=True
                        ),
                        self._loop
                    )
                result = "News digest in progress, sir."

            elif name == "sleep_jarvis":
                self.ui.set_state("SLEEPING")
                self.ui.write_log("SYS: JARVIS sleeping. Say 'Hey Jarvis' to wake.")
                result = "JARVIS entering sleep mode. Goodnight, sir."

            elif name == "shutdown_jarvis":
                self.ui.write_log("SYS: Going to sleep. Say 'Hey Jarvis' to wake me.")
                try:
                    QTimer.singleShot(2000, self.ui._win.hide)
                except Exception:
                    pass
            else:
                result = f"Unknown tool: {name}"
        except Exception as e:
            result = f"Tool '{name}' failed: {e}"
            traceback.print_exc()
            self.speak_error(name, e)

        print(f"[JARVIS] 📤 {name} → {str(result)[:100]}")
        return types.FunctionResponse(id=fc.id, name=name, response={"result": result})

    async def _send_realtime(self):
        while True:
            msg = await self.out_queue.get()
            await self.session.send_realtime_input(media=msg)

    async def _listen_audio(self):
        loop = asyncio.get_event_loop()
        diag_state = {
            "last_log": 0.0,
            "sent_count": 0,
            "blocked_count": 0,
            "noise_dropped_count": 0,
        }
        last_level_push = [0.0]
        BARGE_IN_DEBOUNCE_SECS = 0.4  # 400ms debounce
        def cb(indata, frames, time_info, status):
            with self._speaking_lock:
                speaking = self._is_speaking
                speaking_since = self._speaking_since
            state_label = self.ui._win._current_state if hasattr(self.ui, '_win') else "LISTENING"
            if_sleeping = (state_label == "SLEEPING")
            muted = self.ui.muted
            now = time.time()

            # ── Phase 2: Barge-in detection during playback ────────────────────────
            # NOTE: Acoustic Echo Cancellation (AEC) limitation:
            # Without hardware or OS-level AEC, acoustic playback from speakers into
            # the microphone can potentially cause false barge-in if speaker volume
            # is very loud. A 400ms debounce ensures initial playback transients do
            # not falsely interrupt, and the calibrated noise floor (280 RMS) requires
            # genuine voice energy to trigger.
            if speaking and not muted and not if_sleeping and not self._tool_in_flight:
                if speaking_since and (now - speaking_since >= BARGE_IN_DEBOUNCE_SECS):
                    pass_filter, rms = self._mic_filter.process_chunk(indata, now=now)
                    if pass_filter and rms >= self._mic_filter.threshold_rms:
                        # Genuine speech onset detected while speaking -> BARGE IN
                        loop.call_soon_threadsafe(self._interrupt_playback)
                        raw = indata.tobytes()
                        self._last_activity = now
                        def _add_barge():
                            try: self.out_queue.put_nowait({"data": raw, "mime_type": "audio/pcm"})
                            except asyncio.QueueFull: pass
                        loop.call_soon_threadsafe(_add_barge)
                        diag_state["sent_count"] += 1
                        return
                diag_state["blocked_count"] += 1
                return

            allowed = not speaking and not muted and not if_sleeping and not self._tool_in_flight

            if not allowed:
                diag_state["blocked_count"] += 1
                self._mic_filter.reset()
            else:
                # Phase 1: Energy-based VAD pre-filter with hangover
                pass_filter, rms = self._mic_filter.process_chunk(indata, now=now)
                if not pass_filter:
                    diag_state["noise_dropped_count"] += 1
                else:
                    diag_state["sent_count"] += 1
                    raw = indata.tobytes()
                    self._last_activity = now
                    def _add():
                        try: self.out_queue.put_nowait({"data": raw, "mime_type": "audio/pcm"})
                        except asyncio.QueueFull: pass
                    loop.call_soon_threadsafe(_add)

                    # Voice-reactive hologram pulse (gated strictly on genuine speech passing filter)
                    if now - last_level_push[0] > 0.08:
                        try:
                            level = min(1.0, rms / 3000.0)
                            self.ui.set_audio_level(level)
                        except Exception:
                            pass
                        last_level_push[0] = now

                    # Voice emotion — feed raw PCM once per VU update (~80ms, speech only)
                    try:
                        self._emotion.feed(raw)
                    except Exception:
                        pass

            if now - diag_state["last_log"] > 2.0:
                print(f"[DIAG] mic gate: speaking={speaking} muted={muted} state={state_label!r} "
                      f"allowed={allowed} sent={diag_state['sent_count']} blocked={diag_state['blocked_count']} "
                      f"noise_dropped={diag_state['noise_dropped_count']}")
                diag_state["last_log"] = now
        with sd.InputStream(samplerate=SEND_SAMPLE_RATE, channels=CHANNELS, dtype="int16", blocksize=CHUNK_SIZE, callback=cb):
            while True:
                await asyncio.sleep(0.1)

    async def _receive_audio(self):
        out_buf, in_buf = [], []
        data_chunk_count = 0
        while True:
            async for response in self.session.receive():
                if response.data:
                    data_chunk_count += 1
                    if data_chunk_count <= 3 or data_chunk_count % 20 == 0:
                        print(f"[DIAG] _receive_audio got response.data #{data_chunk_count}, "
                              f"size={len(response.data)} bytes, queue_size={self.audio_in_queue.qsize() if self.audio_in_queue else 'N/A'}")
                    self._response_in_progress.set()
                    # BUGFIX: put_nowait() on a full queue raised QueueFull
                    # uncaught, which propagated up through run_forever's
                    # asyncio.wait(..., FIRST_EXCEPTION) and killed every
                    # task — forcing a full reconnect (losing the live
                    # session/context) every single time playback fell even
                    # slightly behind Gemini's audio stream. Confirmed in the
                    # field: "asyncio.queues.QueueFull" mid-reply, immediately
                    # followed by a reconnect. A queue overflowing here just
                    # means playback is briefly behind, not a real failure —
                    # drop the single oldest buffered chunk to make room and
                    # keep going, instead of tearing down the whole session.
                    try:
                        self.audio_in_queue.put_nowait(response.data)
                    except asyncio.QueueFull:
                        try:
                            self.audio_in_queue.get_nowait()
                        except asyncio.QueueEmpty:
                            pass
                        try:
                            self.audio_in_queue.put_nowait(response.data)
                        except asyncio.QueueFull:
                            pass
                if response.server_content:
                    sc = response.server_content
                    if sc.output_transcription and sc.output_transcription.text:
                        self.set_speaking(True)
                        self._response_in_progress.set()
                        t = sc.output_transcription.text.strip()
                        if t: out_buf.append(t)
                    if sc.input_transcription and sc.input_transcription.text:
                        t = sc.input_transcription.text.strip()
                        if t: in_buf.append(t)
                    if sc.turn_complete:
                        self._response_in_progress.clear()
                        fi = " ".join(in_buf).strip()
                        if fi: self.ui.write_log(f"You: {fi}")
                        in_buf = []
                        fo = " ".join(out_buf).strip()
                        if fo: self.ui.write_log(f"Jarvis: {fo}")
                        out_buf = []
                        if fi and len(fi) > 5:
                            threading.Thread(target=_update_memory_async, args=(fi, fo), daemon=True).start()
                        if self._tool_in_flight:
                            pass
                        elif fi:
                            self.ui.set_state("SLEEPING")
                            self.ui.write_log("SYS: JARVIS sleeping. Say 'Hey Jarvis' to wake.")
                        else:
                            self.ui.set_state("LISTENING")
                if response.tool_call:
                    self._tool_in_flight = True
                    try:
                        resps = []
                        for fc in response.tool_call.function_calls:
                            resps.append(await self._execute_tool(fc))
                        await self.session.send_tool_response(function_responses=resps)
                    finally:
                        self._tool_in_flight = False

    async def _play_audio(self):
        print("[DIAG] _play_audio task starting...")
        try:
            stream = sd.RawOutputStream(samplerate=RECEIVE_SAMPLE_RATE, channels=CHANNELS, dtype="int16", blocksize=CHUNK_SIZE)
            stream.start()
            print(f"[DIAG] _play_audio stream OPENED OK (device={sd.default.device}, rate={RECEIVE_SAMPLE_RATE})")
        except Exception as e:
            print(f"[DIAG] _play_audio FAILED TO OPEN STREAM: {type(e).__name__}: {e}")
            raise
        chunk_count = 0
        try:
            while True:
                chunk = await self.audio_in_queue.get()
                chunk_count += 1
                if chunk_count <= 3 or chunk_count % 20 == 0:
                    print(f"[DIAG] _play_audio got chunk #{chunk_count}, size={len(chunk)} bytes")
                self.set_speaking(True)
                await asyncio.to_thread(stream.write, chunk)
                # DEADLOCK FIX: this used to also require
                # "not self._response_in_progress.is_set()" before clearing
                # speaking. _response_in_progress is set/cleared by
                # _receive_audio independently (it's meant to gate proactive
                # injections, not to track playback). If even one stray
                # response.data chunk arrived after turn_complete had
                # already cleared it, _response_in_progress.set() fired
                # again, and this condition could never become true again —
                # set_speaking(False) never ran, _is_speaking stayed True
                # forever, and the mic gate in _listen_audio stayed shut for
                # the rest of the session (confirmed via [DIAG] mic gate
                # logs showing speaking=True frozen for minutes straight).
                # Whether JARVIS has finished talking should depend only on
                # whether THIS queue — the one _play_audio itself owns — has
                # actually run dry, not on a different task's bookkeeping
                # flag for an unrelated purpose.
                if self.audio_in_queue.empty():
                    await asyncio.sleep(0.35)
                    if self.audio_in_queue.empty():
                        self.set_speaking(False)
        except Exception as e:
            print(f"[DIAG] _play_audio CRASHED after {chunk_count} chunks: {type(e).__name__}: {e}")
            raise
        finally:
            print(f"[DIAG] _play_audio exiting, total chunks played: {chunk_count}")
            self.set_speaking(False)
            stream.stop(); stream.close()

    async def run_forever(self):
        client = genai.Client(api_key=_get_api_key(), http_options={"api_version": "v1beta"})

        # Phase 4 FIX: start the proactive engine once per process, outside
        # the reconnect loop — it runs its own background thread (see
        # ProactiveIntelligence.start()) and is independent of any single
        # live-session connection, exactly like main.py's JarvisLive.run().
        self._proactive.start()
        # Phase 7: wire proactive notifications to mobile
        try:
            _orig_notify = self._proactive.notify
            def _mobile_notify(msg: str):
                _orig_notify(msg)
                if self._mobile:
                    try:
                        self._mobile.notify(msg)
                    except Exception:
                        pass
            self._proactive.notify = _mobile_notify
        except Exception:
            pass

        # PARITY FIX: ambient vision glances — ported from main.py's
        # run(). Fires a silent screen_process("screen") glance every 15
        # min while JARVIS is idle, so it can offer proactive help
        # unprompted. Previously wired in main.py only.
        def _ambient_glance():
            from actions.screen_processor import screen_process, warmup_session
            warmup_session(player=self.ui)
            screen_process(
                {"angle": "screen",
                 "text": (
                     "You are doing a quiet ambient check on sir's screen. "
                     "If anything looks like it needs attention (an error, a long wait, "
                     "an obvious task you could help with) mention it very briefly — "
                     "one sentence. If the screen looks completely normal and idle, "
                     "stay silent: respond with exactly the word SKIP and nothing else."
                 )},
                player=self.ui,
            )
        self._proactive.set_vision_fn(_ambient_glance, interval_seconds=900)

        # PARITY FIX: calendar meeting reminders (10-min-out alerts) —
        # ported from main.py's run(). Was entirely absent here before,
        # so background-service users never got these at all regardless
        # of the Settings/calendar config being identical to main.py.
        try:
            from core.calendar_intel import CalendarReminder
            self._calendar_reminder = CalendarReminder(
                inject_fn=lambda msg: self.inject(msg),
                bridge=getattr(self, "_proactive_bridge", None),
            )
            self._calendar_reminder.start()
        except Exception as _ce:
            print(f"[Calendar] Reminder skipped: {_ce}")

        reconnect_attempt = 0
        RECONNECT_BASE_DELAY = 3
        RECONNECT_MAX_DELAY  = 30
        was_mid_reply = False

        try:
            while True:
                tasks = []
                try:
                    print("[JARVIS] 🔌 Connecting...")
                    if not was_mid_reply:
                        self.ui.set_state("THINKING")
                    config = self._build_config()
                    async with client.aio.live.connect(model=LIVE_MODEL, config=config) as session:
                        self.session = session
                        self._loop   = asyncio.get_event_loop()
                        self.audio_in_queue = asyncio.Queue(maxsize=300)
                        self.out_queue      = asyncio.Queue(maxsize=100)
                        print("[JARVIS] ✅ Connected.")
                        reconnect_attempt = 0

                        if was_mid_reply:
                            self.ui.set_state("LISTENING")
                            self.ui.write_log(
                                "SYS: Connection dropped mid-reply and was restored. "
                                "Say 'Hey Jarvis' or repeat your request if it cut off."
                            )
                            was_mid_reply = False
                        else:
                            self.ui.set_state("SLEEPING")
                        self.ui.write_log("SYS: JARVIS online  |  background service active")

                        tasks = [
                            asyncio.ensure_future(self._send_realtime()),
                            asyncio.ensure_future(self._listen_audio()),
                            asyncio.ensure_future(self._receive_audio()),
                            asyncio.ensure_future(self._play_audio()),
                            asyncio.ensure_future(self._speaking_watchdog()),
                            asyncio.ensure_future(self._idle_keepalive()),
                            asyncio.ensure_future(self._thinking_watchdog()),
                        ]
                        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
                        for t in pending: t.cancel()
                        for t in done:
                            if not t.cancelled() and t.exception():
                                raise t.exception()

                except Exception as e:
                    print(f"[JARVIS] ⚠️ {e}")
                    traceback.print_exc()
                    was_mid_reply = self._response_in_progress.is_set() or self._is_speaking
                    for t in tasks:
                        if not t.done(): t.cancel()
                else:
                    was_mid_reply = False

                self.session = None
                self.set_speaking(False)
                if not was_mid_reply:
                    self.ui.set_state("THINKING")

                reconnect_attempt += 1
                delay = min(RECONNECT_BASE_DELAY * (2 ** (reconnect_attempt - 1)), RECONNECT_MAX_DELAY)
                print(f"[JARVIS] 🔄 Reconnecting in {delay}s... (attempt {reconnect_attempt})")
                await asyncio.sleep(delay)
        finally:
            # Belt-and-suspenders: if run_forever ever actually exits (it
            # normally only stops via process termination), make sure the
            # proactive background thread is told to stop too. The real,
            # everyday shutdown path is JarvisTrayApp._quit(), which also
            # calls self._proactive.stop() directly.
            self._proactive.stop()


# ═══════════════════════════════════════════════════════════════════════════════
#  SESSION THREAD  (runs asyncio loop in a background thread)
# ═══════════════════════════════════════════════════════════════════════════════

class SessionThread(QThread):
    def __init__(self, session: JarvisSession):
        super().__init__()
        self._session = session

    def run(self):
        asyncio.run(self._session.run_forever())


# ═══════════════════════════════════════════════════════════════════════════════
#  TRAY APPLICATION  (the glue that holds everything together)
# ═══════════════════════════════════════════════════════════════════════════════

class JarvisTrayApp:
    """
    Manages:
      • QApplication + system tray icon
      • AlwaysOnListener (wake word)
      • BriefingScheduler
      • JarvisUI window (hidden until wake word / tray click)
      • JarvisSession + SessionThread
    """

    def __init__(self):
        self._app = QApplication.instance() or QApplication(sys.argv)
        self._app.setQuitOnLastWindowClosed(False)
        self._app.setStyle("Fusion")

        self._tray = QSystemTrayIcon(_make_tray_icon(), self._app)
        self._tray.setToolTip("JARVIS  |  Background Service Active")
        self._tray.activated.connect(self._on_tray_click)
        self._build_tray_menu()
        self._tray.show()

        self._ui_shown    = False
        self._ui          = None
        self._session     = None
        self._sess_thread = None
        self._briefing    = None
        self._intruder_alert = None

        self._listener = AlwaysOnListener()
        self._listener.wakeDetected.connect(self._on_wake)
        self._listener.loadFailed.connect(self._on_listener_load_failed)
        self._listener.start()

        # BUGFIX: this used to fire unconditionally right after .start(),
        # claiming success even when the wake-word model failed to load —
        # the most likely real-world cause being openwakeword/onnxruntime
        # never having been installed (requirements.txt ships empty, so a
        # fresh `pip install` of just the obvious packages skips them
        # silently). Defer this specific message: only show it if nothing
        # has reported a load failure within a couple seconds of startup.
        # _on_listener_load_failed shows its own, more useful balloon if a
        # failure does come in first.
        self._wake_ready_announced = False
        QTimer.singleShot(2000, self._announce_ready_if_ok)

        # ── Gesture control (webcam) — closes the cold-boot feature gap;
        # see AlwaysOnGestureListener docstring above for why this lives
        # here instead of inside JarvisSession. Opt-in: only starts if the
        # user already enabled it via the Settings toggle in a previous
        # session (main.py's _get_gesture_control_enabled reads the same
        # persisted flag).
        self._gesture_listener = AlwaysOnGestureListener()
        self._gesture_listener.gestureWake.connect(self._on_wake)
        self._gesture_listener.gestureSleep.connect(self._on_gesture_sleep)
        self._gesture_listener.gestureError.connect(self._on_gesture_load_failed)
        if _get_gesture_control_enabled():
            self._gesture_listener.start()

        # ── Phase 7: Mobile companion server ──────────────────────────────────
        self._mobile = MobileServer()
        self._intercom_active = False
        self._intercom_mic_stream = None
        self._intercom_speaker_stream = None
        self._mobile.set_callbacks(
            on_command = self._on_mobile_command,
            on_wake    = self._on_wake,
            on_intercom_start = self._on_intercom_start,
            on_intercom_stop  = self._on_intercom_stop,
            on_intercom_audio = self._on_intercom_audio_received,
        )
        # ── Phase 4: Proactive Bridge (Daemon-level unified push) ─────────────
        from core.proactive_bridge import ProactiveBridge
        self._proactive_bridge = ProactiveBridge(
            get_state=lambda: "SPEAKING" if (self._session and getattr(self._session, "_is_speaking", False)) else "LISTENING",
            voice_sink=lambda msg: self._session.speak(msg) if self._session else None,
            ui_sink=lambda msg: self._ui.write_log(msg) if self._ui else None,
            interrupt_sink=lambda: self._session._interrupt_playback() if self._session else None,
        )
        try:
            from sentinel.audit import AuditLogger
            _audit = AuditLogger()
            self._proactive_bridge.set_audit_sink(lambda cat, actor, details: _audit.log_event(cat, actor, details))
        except Exception:
            pass
        try:
            from core.telegram_alert import TelegramAlerter
            _tg = TelegramAlerter()
            if _tg.configured:
                self._proactive_bridge.set_telegram_sink(lambda msg, jpeg: _tg.send_alert(msg, jpeg))
        except Exception:
            pass
        if self._mobile:
            self._proactive_bridge.set_mobile_sink(lambda msg, jpeg: self._on_intruder_alert(msg, jpeg))

        # Wire EmergencyWipeController singleton to ProactiveBridge for CRITICAL blocked wipe alerts
        try:
            from core.sentinel_extras import EmergencyWipeController
            EmergencyWipeController.get_instance().set_bridge(self._proactive_bridge)
        except Exception as _we:
            print(f"[WipeController] Bridge wiring skipped: {_we}")

        # ── Phase 7: Failed-login mobile alert ──────────────────────────────────

        # Watches Windows' own Security Event Log for failed logon attempts
        # (event 4625 — recorded natively by Windows for every wrong password
        # at the lock screen). On a hit: push a notification to the phone and
        # take one webcam snapshot (camera LED is hardware-on, never covert)
        # and send that too. Read-only against the event log; nothing is
        # stored on disk.
        self._intruder_alert = IntruderAlertWatcher(
            on_alert = self._on_intruder_alert,
            log_fn   = lambda msg: self._ui.write_log(msg) if self._ui else print(msg),
            bridge   = self._proactive_bridge,
        )
        self._intruder_alert.start()

        print("[Tray] JARVIS tray service running")

    def _announce_ready_if_ok(self):
        if self._wake_ready_announced:
            return   # a failure (or this) already handled the announcement
        self._wake_ready_announced = True
        self._tray.showMessage(
            "JARVIS",
            "Background service started. Say 'Hey Jarvis' anytime.",
            QSystemTrayIcon.MessageIcon.Information,
            3000
        )

    def _on_listener_load_failed(self, message: str):
        """
        BUGFIX: previously a wake-word model load failure was completely
        silent in this process — print() goes nowhere in a windowless .pyw
        app, and the JarvisUI window (with its Activity Log) doesn't even
        exist yet at this point (it's created lazily on first wake — see
        _ensure_ui — which a load failure means will now never happen via
        voice). This is the fix: surface it loudly via the one UI surface
        that's guaranteed to exist at startup, the tray icon, with a
        WARNING balloon instead of the generic "started fine" message, and
        also write it to the real terminal/log file (see _Tee at the top
        of this file) so `python jarvis_service.pyw` from a console, or the
        log file it writes, shows the actual reason. Typed commands are
        unaffected either way — only voice wake-up needs this listener.
        """
        if self._wake_ready_announced:
            return
        self._wake_ready_announced = True
        print(f"[Tray] ⚠️ WAKE WORD DISABLED: {message}")
        self._tray.showMessage(
            "JARVIS — Wake Word Unavailable",
            "Voice wake-up ('Hey Jarvis') failed to start. Open the window "
            "for details, or check the log. Typed commands still work.",
            QSystemTrayIcon.MessageIcon.Warning,
            8000
        )
        # If/when the UI window does get opened (tray click, etc.), make
        # sure the real reason is visible there too, not just in the
        # balloon that already disappeared.
        self._pending_wake_error = message

    def _build_tray_menu(self):
        menu = QMenu()

        act_show = QAction("🤖  Show JARVIS", self._app)
        act_show.triggered.connect(self._show_ui)
        menu.addAction(act_show)

        act_mute = QAction("🔇  Toggle Mute", self._app)
        act_mute.triggered.connect(self._toggle_mute)
        menu.addAction(act_mute)

        menu.addSeparator()

        act_brief = QAction("📊  Morning Briefing Now", self._app)
        act_brief.triggered.connect(lambda: self._trigger_briefing("morning"))
        menu.addAction(act_brief)

        act_brief2 = QAction("🌙  Evening Briefing Now", self._app)
        act_brief2.triggered.connect(lambda: self._trigger_briefing("evening"))
        menu.addAction(act_brief2)

        menu.addSeparator()

        act_log = QAction("📄  Open Log File", self._app)
        act_log.triggered.connect(self._open_log)
        menu.addAction(act_log)

        act_quit = QAction("✖  Quit JARVIS", self._app)
        act_quit.triggered.connect(self._quit)
        menu.addAction(act_quit)

        self._tray.setContextMenu(menu)

    def _on_tray_click(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self._show_ui()

    def _ensure_ui(self):
        """Create the JarvisUI + session on first call."""
        if self._ui is not None:
            return

        print("[Tray] Creating JARVIS UI...")
        self._ui      = JarvisUI(FACE_PATH)
        self._ui.on_gesture_toggle = self._on_gesture_toggle_ui
        self._session = JarvisSession(self._ui, wake_listener=self._listener, mobile=self._mobile)

        self._briefing = BriefingScheduler(
            on_briefing=self._trigger_briefing,
            bridge=self._proactive_bridge,
        )
        self._briefing.start()

        self._sess_thread = SessionThread(self._session)
        self._sess_thread.start()

        # ── Phase 7: wrap write_log to mirror all log lines to mobile ──────────
        _orig_write_log = self._ui.write_log
        _mobile_ref     = self._mobile
        def _patched_write_log(text: str):
            _orig_write_log(text)
            try:
                _mobile_ref.log(text)
            except Exception:
                pass
        self._ui.write_log = _patched_write_log

        # Also mirror set_state to mobile
        _orig_set_state = self._ui.set_state
        def _patched_set_state(state: str):
            _orig_set_state(state)
            try:
                _mobile_ref.set_state(state)
            except Exception:
                pass
        self._ui.set_state = _patched_set_state

        # BUGFIX: if the wake-word model failed to load before the window
        # existed, _on_listener_load_failed had nowhere to write it except
        # a tray balloon that's likely already gone by the time the user
        # opens the window (e.g. via tray click rather than voice — voice
        # wake won't fire at all in this scenario, which is the bug in the
        # first place). Surface it now that the Activity Log exists.
        pending = getattr(self, "_pending_wake_error", None)
        if pending:
            self._ui.write_log(f"SYS: ⚠️ {pending}")
            self._pending_wake_error = None

        print("[Tray] Session thread started")

    def _show_ui(self):
        """Make JARVIS window visible."""
        self._ensure_ui()
        win = self._ui._win
        win.showNormal()
        win.raise_()
        win.activateWindow()
        self._ui_shown = True
        print("[Tray] UI shown")

    def _hide_ui(self):
        if self._ui:
            self._ui._win.hide()
        self._ui_shown = False

    def _on_intruder_alert(self, text: str, jpeg_bytes):
        """
        Called from IntruderAlertWatcher's background thread.

        Three parallel paths fire simultaneously:

        PATH 1 — FCM data-only (page closed, Chrome closed — still works)
          Service Worker receives silent FCM push → calls
          clients.openWindow(alert_url) → full-screen danger page opens.

        PATH 2 — WebSocket broadcast (page already open on phone)
          Instantly redirects the open JARVIS page to /alert.

        PATH 3 — Telegram (works on any network, even laptop on WiFi only)
          Hacker-themed message + webcam photo sent to @jarvis_shan_bot.
        """
        import socket as _sock
        from datetime import datetime as _dt

        hostname  = _sock.gethostname()
        time_str  = _dt.now().strftime("%H:%M:%S")

        # Build the public alert URL (ngrok or LAN)
        base_url  = self._mobile.url          # e.g. http://10.x.x.x:8080
        # Try to get the ngrok public URL from its local API
        try:
            import urllib.request as _ur, json as _js
            with _ur.urlopen("http://127.0.0.1:4040/api/tunnels", timeout=2) as r:
                tunnels = _js.loads(r.read())
                for t in tunnels.get("tunnels", []):
                    if t.get("proto") == "https":
                        base_url = t["public_url"]
                        break
        except Exception:
            pass   # fall back to LAN IP — still works on same WiFi

        from urllib.parse import urlencode as _ue
        params    = _ue({"machine": hostname, "time": time_str})
        alert_url = f"{base_url}/alert?{params}"
        print(f"[IntruderAlert] 🔗 Alert URL: {alert_url}")

        # PATH 1 — FCM silent data push → Service Worker opens /alert
        try:
            fcm_ok = self._mobile._fcm.send_intruder_alert_fullscreen(
                hostname=hostname,
                time_str=time_str,
                alert_url=alert_url,
            )
            print(f"[IntruderAlert] FCM full-screen push: {'OK' if fcm_ok else 'FAILED (returned False — see [FCM] lines above for the real reason, e.g. stale token)'}")
        except Exception as e:
            print(f"[IntruderAlert] FCM full-screen push raised an exception: {e}")

        # PATH 2 — WebSocket redirect (page open on phone)
        try:
            self._mobile.intruder_alert(
                hostname=hostname,
                time_str=time_str,
                alert_url=alert_url,
            )
        except Exception as e:
            print(f"[IntruderAlert] WS broadcast failed: {e}")

        # PATH 3 — Telegram (always-on backup)
        try:
            self._mobile.notify(text)
            if jpeg_bytes:
                self._mobile.notify_image(text, jpeg_bytes)
        except Exception as e:
            print(f"[IntruderAlert] mobile notify failed: {e}")

        if self._ui:
            try:
                self._ui.write_log(f"NOTIFY: {text}")
            except Exception:
                pass

    def _dispatch_remote_control_direct(self, action: str, value: str = "") -> str:
        """
        Executes a REMOTE-tab button press immediately, on this thread, with
        zero AI involvement — mirrors main.py's `remote_control` tool handler
        exactly, so button taps are instant and don't depend on the model
        choosing to call a tool. Returns a short human-readable result string.
        """
        _t0 = time.monotonic()
        action = (action or "").lower().strip()
        value  = (value or "").strip()
        try:
            from actions.computer_settings import (
                volume_up, volume_down, volume_mute, volume_set,
                brightness_up, brightness_down,
                lock_screen, shutdown_computer, restart_computer,
                minimize_window, close_app, close_window, full_screen,
            )
            from actions.computer_control import computer_control as _cc

            _vol_map    = {"volume_up": volume_up, "volume_down": volume_down, "volume_mute": volume_mute}
            _bright_map = {"brightness_up": brightness_up, "brightness_down": brightness_down}

            if action in _vol_map:
                _vol_map[action](); return f"{action.replace('_', ' ').title()} done, sir."
            if action == "volume_set":
                volume_set(int(value) if value.isdigit() else 50)
                return f"Volume set to {value}%, sir."
            if action in _bright_map:
                _bright_map[action](); return f"{action.replace('_', ' ').title()} done, sir."
            if action in ("lock", "lock_screen"):
                lock_screen(); return "Screen locked, sir."
            if action == "shutdown":
                shutdown_computer(); return "Shutting down, sir."
            if action == "restart":
                restart_computer(); return "Restarting, sir."
            if action == "minimize":
                minimize_window(); return "Window minimised, sir."
            if action in ("close", "close_window"):
                close_window(); return "Window closed, sir."
            if action == "fullscreen":
                full_screen(); return "Toggled fullscreen, sir."
            if action == "screenshot":
                return str(_cc(parameters={"action": "screenshot"}, player=self._ui))
            if action == "hotkey":
                return str(_cc(parameters={"action": "hotkey", "keys": value}, player=self._ui))
            if action in ("scroll_up", "scroll_down"):
                direction = "up" if "up" in action else "down"
                return str(_cc(parameters={"action": "scroll", "direction": direction}, player=self._ui))
            if action in ("play_pause", "media_play", "next_track", "prev_track", "media_stop"):
                _media = {"play_pause": "playpause", "media_play": "playpause",
                          "next_track": "nexttrack", "prev_track": "prevtrack", "media_stop": "stop"}
                return str(_cc(parameters={"action": "press", "key": _media.get(action, "playpause")}, player=self._ui))
            # Generic fallback — pass straight to computer_control, same as main.py
            return str(_cc(parameters={"action": action, "value": value}, player=self._ui))
        except Exception as e:
            return f"Remote control failed ({action}): {e}"

    def _on_mobile_command(self, text: str):
        """Called when a command arrives from the mobile companion app.
        REMOTE-tab button presses (`remote_control ...` / `press hotkey ...`)
        are executed directly on the spot — no AI round-trip, so taps are
        instant and don't depend on the model deciding to call a tool.
        Free-text chat typed into the phone still goes through the AI as
        before, so natural-language commands keep working exactly as they did.
        """
        print(f"[Mobile] Remote command received: {text!r}")

        # --- Fast path: REMOTE-tab button presses -----------------------
        # Checked FIRST, before any UI/Qt calls. _show_ui() below touches
        # Qt objects and MUST run on the Qt main thread; this callback runs
        # on the mobile server's background thread, so calling _show_ui()
        # first (as the old code did) triggers Qt cross-thread errors
        # ("QObject::setParent: Cannot set parent, new parent is in a
        # different thread") which silently aborts the handler before the
        # button ever does anything. Button presses don't need the chat
        # window shown at all, so we dispatch and return immediately,
        # never touching Qt.
        stripped = text.strip()
        result = None
        _dispatch_t0 = time.monotonic()
        if stripped.lower().startswith("remote_control "):
            parts  = stripped.split(maxsplit=2)
            action = parts[1] if len(parts) > 1 else ""
            value  = parts[2] if len(parts) > 2 else ""
            result = self._dispatch_remote_control_direct(action, value)
        elif stripped.lower().startswith("press hotkey "):
            combo  = stripped[len("press hotkey "):].strip()
            result = self._dispatch_remote_control_direct("hotkey", combo)
        elif stripped.lower() in ("lock_screen", "lock", "shutdown", "restart", "screenshot"):
            # The confirm-guarded POWER buttons (LOCK PC / SHUTDOWN) and the
            # SCREENSHOT/SAVE button all send a bare action word with no
            # "remote_control " prefix.
            result = self._dispatch_remote_control_direct(stripped.lower())

        if result is not None:
            _elapsed_ms = (time.monotonic() - _dispatch_t0) * 1000
            print(f"[Mobile] ⚡ Direct dispatch result ({_elapsed_ms:.0f}ms): {result}")
            if _elapsed_ms > 500:
                print(f"[Mobile] ⚠️ Slow dispatch — {_elapsed_ms:.0f}ms for {stripped!r} "
                      f"(anything under ~50ms is normal for these actions)")
            if self._mobile:
                try:
                    self._mobile.notify(result)
                except Exception as e:
                    print(f"[Mobile] notify failed: {e}")
            return
        # ------------------------------------------------------------------

        # Anything else (free-text chat, wake phrases typed in, etc.) — send
        # to the AI as before. This path legitimately needs the chat window,
        # so _show_ui() only runs here, not for button presses.
        self._show_ui()
        if self._ui:
            self._ui.set_state("LISTENING")
            self._ui.write_log(f"You (mobile): {text}")

        if self._session:
            self._session.inject(
                f"[MOBILE COMMAND] The user sent this command from their phone: {text}\n"
                "Treat it exactly as if they said it via voice. Respond naturally."
            )
        else:
            if self._ui:
                self._ui.write_log("SYS: JARVIS session not ready — try again.")

    def _on_wake(self):
        """Called from AlwaysOnListener signal — runs on Qt main thread."""
        print("[Tray] Wake word → showing UI + activating session")
        self._show_ui()
        if self._ui:
            self._ui.set_state("LISTENING")
            self._ui.write_log("SYS: Wake word detected — JARVIS activated")
        self._tray.showMessage(
            "JARVIS Activated",
            "Listening...",
            QSystemTrayIcon.MessageIcon.Information,
            1500
        )
        if self._session:
            # Phase 4 FIX: offer a morning briefing right after wake word,
            # exactly like main.py's _on_wake_word() does via self._proactive.
            try:
                self._session._proactive.on_wake_word()
            except Exception as e:
                print(f"[Proactive] ⚠️ on_wake_word failed: {e}")
            self._session.inject(
                "[WAKE] User said your wake word and is now looking at you. "
                "Give a brief, sharp acknowledgement and wait for their command."
            )

    def _on_gesture_sleep(self):
        """Called from AlwaysOnGestureListener signal (closed fist) — runs
        on the Qt main thread. Mirrors main.py's JarvisLive._on_gesture_sleep:
        only relevant once JARVIS is actually awake, so if the UI/session
        were never created yet (still asleep, nothing to do) or JARVIS is
        mid-response, this is a no-op — same guard shape as voice wake."""
        if self._ui is None or self._session is None:
            return
        label = self._ui._win._current_state if hasattr(self._ui, '_win') else None
        if label in ("THINKING", "SPEAKING"):
            return
        self._ui.set_state("SLEEPING")
        self._ui.write_log("SYS: Gesture detected (closed fist) — JARVIS standing by")

    def _on_gesture_load_failed(self, message: str):
        """Same idea as _on_listener_load_failed, but for the camera/model
        instead of the mic model. Gesture control just won't work this
        session — voice wake and typed commands are unaffected."""
        print(f"[Tray] ⚠️ GESTURE CONTROL DISABLED: {message}")
        if self._ui:
            self._ui.write_log(f"SYS: ⚠️ Gesture control — {message}")

    def _on_gesture_toggle_ui(self, enabled: bool):
        """Called when the user clicks the GESTURE CONTROL toggle in the
        UI (Settings). Starts/stops the real engine and persists the
        choice for next launch — identical behavior to main.py's
        JarvisLive._on_gesture_toggle_ui, sharing the same saved flag."""
        _save_gesture_control_enabled(enabled)
        if enabled:
            self._gesture_listener.start()
        else:
            self._gesture_listener.stop()

    # ── Intercom: live two-way audio with the phone ────────────────────────
    def _on_intercom_start(self, ip: str):
        """Called from the mobile server's background thread when the
        phone taps START INTERCOM. Starts a dedicated mic-capture stream
        (PC mic → phone) and a dedicated playback queue (phone mic → PC
        speakers), independent of the voice-assistant's own mic/speaker
        streams so the two don't interfere with each other."""
        if self._intercom_active:
            return
        print(f"[Intercom] 🎙️ Starting — requested by {ip}")
        self._intercom_active = True
        import queue as _queue
        self._intercom_playback_queue = _queue.Queue()

        def _mic_capture_loop():
            def _cb(indata, frames, time_info, status):
                if not self._intercom_active:
                    raise sd.CallbackStop()
                try:
                    self._mobile.broadcast_intercom_audio(bytes(indata))
                except Exception as e:
                    print(f"[Intercom] ⚠️ mic broadcast error: {e}")
            try:
                with sd.InputStream(samplerate=INTERCOM_SAMPLE_RATE, channels=1,
                                     dtype="int16", blocksize=INTERCOM_CHUNK_SIZE,
                                     callback=_cb) as stream:
                    self._intercom_mic_stream = stream
                    while self._intercom_active:
                        time.sleep(0.1)
            except Exception as e:
                print(f"[Intercom] ❌ mic capture failed: {e}")
            finally:
                self._intercom_mic_stream = None

        def _speaker_playback_loop():
            try:
                with sd.RawOutputStream(samplerate=INTERCOM_SAMPLE_RATE, channels=1,
                                         dtype="int16", blocksize=INTERCOM_CHUNK_SIZE) as stream:
                    self._intercom_speaker_stream = stream
                    while self._intercom_active:
                        try:
                            chunk = self._intercom_playback_queue.get(timeout=0.2)
                        except Exception:
                            continue
                        try:
                            stream.write(chunk)
                        except Exception as e:
                            print(f"[Intercom] ⚠️ playback write error: {e}")
            except Exception as e:
                print(f"[Intercom] ❌ speaker playback failed: {e}")
            finally:
                self._intercom_speaker_stream = None

        threading.Thread(target=_mic_capture_loop, daemon=True, name="IntercomMic").start()
        threading.Thread(target=_speaker_playback_loop, daemon=True, name="IntercomSpeaker").start()
        if self._mobile:
            self._mobile.notify("Intercom link opened, sir.")

    def _on_intercom_stop(self, ip: str):
        if not self._intercom_active:
            return
        print(f"[Intercom] ⏹ Stopping — requested by {ip}")
        self._intercom_active = False
        # The capture/playback threads see the flag flip and exit on their
        # own within ~100-200ms; nothing further to join here since they're
        # daemon threads and won't block process exit either way.
        if self._mobile:
            self._mobile.notify("Intercom link closed, sir.")

    def _on_intercom_audio_received(self, pcm_bytes: bytes):
        """Called from the mobile server's background thread whenever a
        chunk of the phone's mic audio arrives. Queues it for the speaker
        playback thread started in _on_intercom_start."""
        if not self._intercom_active:
            return
        try:
            self._intercom_playback_queue.put_nowait(pcm_bytes)
        except Exception:
            pass

    def _trigger_briefing(self, label: str):
        """PARITY FIX: main.py's JarvisLive (_on_scheduled_briefing) never
        interrupts an active conversation or mid-speech — cutting JARVIS
        off mid-sentence shows up as a garbled command. That guard was
        missing here entirely, so a scheduled auto-briefing could fire
        over a live reply. Ported the same guard.
        """
        if self._session is not None:
            with self._session._speaking_lock:
                currently_speaking = self._session._is_speaking
            response_busy = self._session._response_in_progress.is_set()
            if currently_speaking or response_busy:
                if self._ui:
                    self._ui.write_log(f"SYS: Auto-briefing ({label}) deferred — busy")
                return
        self._show_ui()
        if self._session:
            self._session.inject(
                f"[AUTO BRIEFING] It is {label} briefing time. "
                f"Deliver the {label} briefing now using the daily_briefing tool."
            )

    def _toggle_mute(self):
        if self._ui:
            self._ui.muted = not self._ui.muted

    def _open_log(self):
        os.startfile(str(LOG_PATH))

    def _quit(self):
        print("[Tray] Quit requested — full exit")
        # Tell the watchdog this shutdown was deliberate, not a crash/hang —
        # otherwise it would just relaunch us right after you quit.
        try:
            from core.watchdog_auth import write_authenticated_exit_marker
            write_authenticated_exit_marker(INTENTIONAL_EXIT_PATH, reason="user_quit")
        except Exception:
            pass
        if self._listener:
            self._listener.stop()
        if self._gesture_listener:
            self._gesture_listener.stop()
        if self._briefing:
            self._briefing.stop()
        if self._session:
            try:
                self._session._proactive.stop()
            except Exception:
                pass
        if self._mobile:
            try:
                self._mobile.stop()
            except Exception:
                pass
        if self._intruder_alert:
            try:
                self._intruder_alert.stop()
            except Exception:
                pass
        self._app.quit()

    def run(self):
        sys.exit(self._app.exec() if PYQT == 6 else self._app.exec_())


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import atexit
    import json as _json

    def _pid_is_alive(pid: int) -> bool:
        """Checks whether a PID is a genuinely live process, using the
        Win32 API directly (no extra dependency like psutil needed)."""
        try:
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
                return True
            return False
        except Exception:
            return True  # fail safe: if we can't check, assume it might be alive

    def _acquire_single_instance_lock():
        """Refuses to start a second instance if a genuinely live one is
        already running (checks the PID is actually alive, not just that
        a lock file exists — a stale lock from a crash must not block
        restart). This is exactly the class of problem that caused
        tonight's repeated port-conflict/zombie-process issues."""
        LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        if LOCK_PATH.exists():
            try:
                old_pid = int(LOCK_PATH.read_text().strip())
            except Exception:
                old_pid = None
            if old_pid and old_pid != os.getpid() and _pid_is_alive(old_pid):
                print(f"[Startup] ❌ Another JARVIS instance is already running "
                      f"(PID {old_pid}). Refusing to start a second one.")
                print(f"[Startup]    If you're sure it's actually dead, delete "
                      f"{LOCK_PATH} and try again.")
                sys.exit(1)
            else:
                print(f"[Startup] Stale lock file found (PID {old_pid} not "
                      f"alive) — taking over.")
        LOCK_PATH.write_text(str(os.getpid()))

        def _release():
            try:
                if LOCK_PATH.exists() and LOCK_PATH.read_text().strip() == str(os.getpid()):
                    LOCK_PATH.unlink()
            except Exception:
                pass
        atexit.register(_release)

    def _start_heartbeat_thread():
        """Writes a small heartbeat file periodically. jarvis_watchdog.py
        watches this file's age and restarts us if it goes stale — i.e. if
        this process hangs or dies without a clean shutdown.
        Also runs a companion check monitoring jarvis_watchdog.py's heartbeat,
        relaunching the watchdog if it dies or hangs (mutual self-healing)."""
        def _service_heartbeat_loop():
            while True:
                _write_service_heartbeat(HEARTBEAT_PATH)
                time.sleep(HEARTBEAT_INTERVAL_SECS)

        def _watchdog_monitor_loop():
            last_relaunch = 0.0
            startup_deadline = time.time() + WATCHDOG_STARTUP_GRACE_SECS
            have_seen_first_hb = False
            while True:
                try:
                    last_relaunch, startup_deadline, have_seen_first_hb = _check_and_heal_watchdog(
                        last_relaunch, startup_deadline, have_seen_first_hb
                    )
                except Exception as e:
                    print(f"[WatchdogMonitor] companion check error: {e}")
                time.sleep(WATCHDOG_CHECK_INTERVAL_SECS)

        threading.Thread(target=_service_heartbeat_loop, daemon=True, name="ServiceHeartbeat").start()
        threading.Thread(target=_watchdog_monitor_loop, daemon=True, name="WatchdogMonitor").start()

    def _start_email_wipe_listener_thread():
        """Starts a background daemon thread polling the dedicated email inbox
        for cryptographically signed emergency remote wipe commands."""
        threading.Thread(target=_email_wipe_listener_loop, daemon=True, name="EmailWipeListener").start()

    from core.integrity_monitor import verify_on_startup
    if not verify_on_startup():
        print("[Startup] 🚨 CODEBASE INTEGRITY VERIFICATION FAILED. Refusing to start JARVIS service.")
        sys.exit(1)

    _acquire_single_instance_lock()
    try:
        if INTENTIONAL_EXIT_PATH.exists():
            INTENTIONAL_EXIT_PATH.unlink()
    except Exception:
        pass
    _start_heartbeat_thread()
    _start_email_wipe_listener_thread()

    app = JarvisTrayApp()
    app.run()