"""
debug_jarvis.py — Run this to find exactly why jarvis_service.pyw crashes.
Usage: python debug_jarvis.py
Output goes to console AND memory/debug_jarvis.log
"""
import sys
import traceback
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
LOG = BASE_DIR / "memory" / "debug_jarvis.log"
LOG.parent.mkdir(exist_ok=True)

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")

log("="*60)
log("JARVIS DEBUG START")
log(f"Python: {sys.version}")
log(f"Executable: {sys.executable}")
log(f"BASE_DIR: {BASE_DIR}")
sys.path.insert(0, str(BASE_DIR))

# ── Test 1: PyQt6 ─────────────────────────────────────────────
log("\n[1] Testing PyQt6...")
try:
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtCore import QTimer
    log("    PyQt6 OK")
except Exception as e:
    log(f"    FAIL: {e}")

# ── Test 2: sounddevice / numpy ───────────────────────────────
log("\n[2] Testing sounddevice + numpy...")
try:
    import numpy as np
    import sounddevice as sd
    log(f"    numpy OK ({np.__version__})")
    log(f"    sounddevice OK ({sd.__version__})")
except Exception as e:
    log(f"    FAIL: {e}")
    traceback.print_exc()

# ── Test 3: google.genai ──────────────────────────────────────
log("\n[3] Testing google.genai...")
try:
    from google import genai
    from google.genai import types
    log("    google.genai OK")
except Exception as e:
    log(f"    FAIL: {e}")

# ── Test 4: ui.py ─────────────────────────────────────────────
log("\n[4] Testing ui.py import...")
try:
    import ui
    log("    ui.py OK")
except Exception as e:
    log(f"    FAIL: {e}")
    traceback.print_exc()

# ── Test 5: memory_manager ────────────────────────────────────
log("\n[5] Testing memory.memory_manager...")
try:
    from memory.memory_manager import load_memory
    log("    memory_manager OK")
except Exception as e:
    log(f"    FAIL: {e}")

# ── Test 6: all actions ───────────────────────────────────────
log("\n[6] Testing action modules...")
actions = [
    "actions.file_processor",
    "actions.flight_finder",
    "actions.open_app",
    "actions.weather_report",
    "actions.send_message",
    "actions.reminder",
    "actions.computer_settings",
    "actions.screen_processor",
    "actions.youtube_video",
    "actions.desktop",
    "actions.browser_control",
    "actions.file_controller",
    "actions.code_helper",
    "actions.dev_agent",
    "actions.web_search",
    "actions.computer_control",
    "actions.game_updater",
]
import importlib
for mod in actions:
    try:
        importlib.import_module(mod)
        log(f"    {mod} OK")
    except Exception as e:
        log(f"    {mod} FAIL: {e}")

# ── Test 7: main.py imports ───────────────────────────────────
log("\n[7] Testing main.py imports...")
try:
    from main import (
        TOOL_DECLARATIONS, LIVE_MODEL, CHANNELS,
        SEND_SAMPLE_RATE, RECEIVE_SAMPLE_RATE, CHUNK_SIZE,
        WAKE_WORDS, _get_api_key, BriefingScheduler,
    )
    log("    main.py imports OK")
except Exception as e:
    log(f"    FAIL: {e}")
    traceback.print_exc()

# ── Test 8: API key readable ──────────────────────────────────
log("\n[8] Testing API key...")
try:
    import json
    cfg = BASE_DIR / "config" / "api_keys.json"
    key = json.loads(cfg.read_text())["gemini_api_key"]
    log(f"    API key found (length={len(key)})")
except Exception as e:
    log(f"    FAIL: {e}")

# ── Test 9: QApplication actually starts ──────────────────────
log("\n[9] Testing QApplication + tray icon...")
try:
    import sys as _sys
    from PyQt6.QtWidgets import QApplication, QSystemTrayIcon, QMenu
    from PyQt6.QtGui import QIcon, QPixmap, QColor
    app = QApplication.instance() or QApplication(_sys.argv)
    app.setQuitOnLastWindowClosed(False)

    # Check tray is supported
    if not QSystemTrayIcon.isSystemTrayAvailable():
        log("    FAIL: System tray NOT available on this desktop")
    else:
        log("    System tray available OK")

    # Draw a simple icon
    px = QPixmap(32, 32)
    px.fill(QColor("#00d4ff"))
    tray = QSystemTrayIcon(QIcon(px))
    tray.setToolTip("JARVIS DEBUG")
    tray.show()
    log("    Tray icon shown OK")

    # Run for 3 seconds then quit
    from PyQt6.QtCore import QTimer
    QTimer.singleShot(3000, app.quit)
    log("    Qt event loop starting for 3 seconds...")
    app.exec()
    log("    Qt event loop ended cleanly")
except Exception as e:
    log(f"    FAIL: {e}")
    traceback.print_exc()

log("\n" + "="*60)
log("DEBUG COMPLETE — check output above for any FAIL lines")
log(f"Full log saved to: {LOG}")
input("\nPress Enter to close...")