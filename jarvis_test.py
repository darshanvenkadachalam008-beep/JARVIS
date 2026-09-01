"""
JARVIS Mark XXXIX — Master Test Suite
Run from the project root with your venv active:
    python jarvis_test.py
"""

import subprocess, sys, os, json, time, socket, struct, math
from pathlib import Path
from datetime import datetime

BASE = Path(__file__).parent
PASS = "\033[92m  PASS\033[0m"
FAIL = "\033[91m  FAIL\033[0m"
SKIP = "\033[93m  SKIP\033[0m"
WARN = "\033[93m  WARN\033[0m"
HEAD = "\033[96m"
RST  = "\033[0m"

results = []

def section(title):
    print(f"\n{HEAD}{'─'*55}")
    print(f"  {title}")
    print(f"{'─'*55}{RST}")

def check(name, ok, detail="", warn=False):
    # warn=True → always show WARN (never FAIL), regardless of ok value
    icon = WARN if warn else (PASS if ok else FAIL)
    print(f"{icon}  {name}")
    if detail:
        print(f"        → {detail}")
    results.append((name, ok or warn, warn))  # warn items never count as failures

def run(cmd, **kw):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10, **kw)
    except Exception as e:
        return type("R", (), {"returncode":1,"stdout":"","stderr":str(e)})()

# ══════════════════════════════════════════════════════════
section("1 · PROJECT STRUCTURE")
# ══════════════════════════════════════════════════════════
must_exist = [
    "main.py", "jarvis_service.pyw", "mobile_server.py",
    "ui.py", "or_client.py",
    "actions/screen_processor.py", "actions/computer_control.py",
    "actions/computer_settings.py",
    "core/proactive_intelligence.py", "core/voice_emotion.py",
    "core/calendar_intel.py",
    "memory/memory_manager.py",
    "agents/agent_manager.py",
    "config/api_keys.json",
]
for f in must_exist:
    p = BASE / f
    check(f, p.exists(), "" if p.exists() else "FILE MISSING")

# ══════════════════════════════════════════════════════════
section("2 · SYNTAX CHECK — ALL .PY FILES")
# ══════════════════════════════════════════════════════════
py_files = list(BASE.rglob("*.py"))
errors = []
for pf in py_files:
    if any(x in pf.parts for x in ["venv","__pycache__",".git"]):
        continue
    r = run([sys.executable, "-m", "py_compile", str(pf)])
    if r.returncode != 0:
        errors.append(f"{pf.relative_to(BASE)}: {r.stderr.strip()[:80]}")
check(f"All {len(py_files)} .py files compile cleanly",
      len(errors)==0,
      "; ".join(errors) if errors else "")

# ══════════════════════════════════════════════════════════
section("3 · CONFIG & API KEYS")
# ══════════════════════════════════════════════════════════
cfg_path = BASE / "config" / "api_keys.json"
cfg = {}
if cfg_path.exists():
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception as e:
        check("api_keys.json is valid JSON", False, str(e))

key_checks = [
    ("gemini_api_key",       "Gemini Live API  (voice + vision)"),
    ("telegram_bot_token",   "Telegram alerts"),
    ("telegram_chat_id",     "Telegram chat ID"),
    ("openrouter_api_key",   "OpenRouter  (agents + OR client)"),
]
optional_keys = [
    ("pushbullet_token",     "Pushbullet push"),
    ("twilio_account_sid",   "Twilio SMS/call"),
    ("openweathermap_api_key", "Weather intelligence"),   # optional key name varies by setup
]
for k, label in key_checks:
    val = cfg.get(k,"")
    ok  = bool(val and val not in ("YOUR_KEY_HERE",""))
    check(f"{label}", ok, "KEY MISSING or placeholder" if not ok else "")
for k, label in optional_keys:
    val = cfg.get(k,"")
    ok  = bool(val and val not in ("YOUR_KEY_HERE",""))
    check(f"{label}  [optional]", ok, "not configured" if not ok else "", warn=True)

# Firebase service account
sa_paths = list((BASE/"config").glob("*service*account*.json")) + \
           list((BASE/"config").glob("firebase*.json"))
check("Firebase service account JSON",
      bool(sa_paths), "" if sa_paths else "No firebase/service-account JSON in config/", warn=True)

# Google credentials
check("Google Calendar credentials  [optional]",
      (BASE/"config"/"google_credentials.json").exists(),
      "Add google_credentials.json to enable calendar", warn=True)

# ══════════════════════════════════════════════════════════
section("4 · PYTHON PACKAGES")
# ══════════════════════════════════════════════════════════
required_pkgs = [
    ("google.generativeai",       "google-generativeai",      True),
    ("sounddevice",               "sounddevice",              True),
    ("numpy",                     "numpy",                    True),
    ("win32api",                  "pywin32",                  True),   # pywin32 installs as win32api/win32gui/etc
    ("mss",                       "mss",                      True),
    ("PIL",                       "Pillow",                   True),
    ("pyperclip",                 "pyperclip",                True),
    ("requests",                  "requests",                 True),
    ("firebase_admin",            "firebase-admin",           True),
    ("PyQt6",                     "PyQt6",                    False),
    ("PyQt5",                     "PyQt5",                    False),
    ("sentence_transformers",     "sentence-transformers",    False),
    ("librosa",                   "librosa",                  False),
    ("googleapiclient",           "google-api-python-client", False),
    ("twilio",                    "twilio",                   False),
    ("nssm",                      None,                       False),
]
qt_ok = False
for mod, pip_name, required in required_pkgs:
    if mod == "nssm":
        r = run(["nssm", "version"])
        ok = r.returncode == 0
        check("nssm  [service manager]", ok,
              "Install from https://nssm.cc" if not ok else "", warn=not ok)
        continue
    if mod in ("PyQt6","PyQt5"):
        try:
            __import__(mod)
            qt_ok = True
            check(f"{mod}  [UI framework]", True)
        except ImportError:
            if not qt_ok:
                check(f"{mod}  [UI framework]", False, "", warn=True)
        continue
    try:
        import warnings as _w
        with _w.catch_warnings():
            _w.simplefilter("ignore")
            __import__(mod)
        check(f"{pip_name or mod}", True)
    except ImportError:
        if required:
            check(f"{pip_name}", False, f"pip install {pip_name}")
        else:
            check(f"{pip_name}  [optional]", False,
                  f"pip install {pip_name}  ← enables extra feature", warn=True)

# ══════════════════════════════════════════════════════════
section("5 · TOOL DECLARATION vs DISPATCH PARITY")
# ══════════════════════════════════════════════════════════
main_src = (BASE/"main.py").read_text(encoding="utf-8", errors="replace")
import re
declared = set(re.findall(r'"name":\s*"([a-z_]+)"', main_src))
# Dispatch uses both "if name ==" (chain starters) and "elif name ==" — catch both
dispatched = set(re.findall(r'(?:if|elif) name == "([a-z_]+)"', main_src))
undispatched = declared - dispatched
undeclared   = dispatched - declared - {"sleep_jarvis"}

check(f"{len(declared)} tools declared in TOOL_DECLARATIONS", True)
check("All declared tools have a dispatch branch",
      len(undispatched)==0,
      f"Missing dispatch: {undispatched}" if undispatched else "")
check("No orphaned dispatch branches",
      len(undeclared)==0,
      f"Orphaned: {undeclared}" if undeclared else "")

new_tools = {"read_clipboard","get_active_window","remote_control","get_calendar_events"}
for t in new_tools:
    check(f"New tool '{t}' present", t in declared)

# ══════════════════════════════════════════════════════════
section("6 · DUPLICATE INPUT FIX")
# ══════════════════════════════════════════════════════════
check("_last_typed_text flag in main.py",
      "_last_typed_text" in main_src)
check("DEDUP FIX comment in recv loop",
      "DEDUP FIX" in main_src)

# ══════════════════════════════════════════════════════════
section("7 · SKIP GUARD — AMBIENT GLANCE SILENCE")
# ══════════════════════════════════════════════════════════
sp_src = (BASE/"actions"/"screen_processor.py").read_text(encoding="utf-8", errors="replace")
check("SKIP guard in screen_processor recv loop",
      "SKIP" in sp_src and "staying silent" in sp_src)
check("Ambient glance wired in proactive_intelligence",
      "set_vision_fn" in (BASE/"core"/"proactive_intelligence.py")
      .read_text(encoding="utf-8", errors="replace"))

# ══════════════════════════════════════════════════════════
section("8 · FUSION MODE — NO ERROR 1011")
# ══════════════════════════════════════════════════════════
check("Fusion uses sequential partial turns (turn_complete=False)",
      "turn_complete=False" in sp_src and "sequential partial turns" in sp_src)
check("Old single-parts-list pattern removed",
      'parts = []\n                        if image_a:' not in sp_src)

# ══════════════════════════════════════════════════════════
section("9 · TIMEZONE FIX")
# ══════════════════════════════════════════════════════════
check("tz_label injected into system prompt",
      "tz_label" in main_src)
check("'already IS the user\'s local timezone' instruction present",
      "already IS" in main_src or "already is" in main_src.lower())

# ══════════════════════════════════════════════════════════
section("10 · SEMANTIC MEMORY SEARCH")
# ══════════════════════════════════════════════════════════
mm_src = (BASE/"memory"/"memory_manager.py").read_text(encoding="utf-8", errors="replace")
check("Semantic search code present in memory_manager",
      "_try_load_semantic" in mm_src and "_cosine" in mm_src)
check("Keyword fallback still present",
      "Keyword fallback" in mm_src)
try:
    import numpy as np
    from memory.memory_manager import _try_load_semantic, _embed, _cosine
    if _try_load_semantic():
        v1 = _embed("sister birthday party")
        v2 = _embed("family celebration event")
        v3 = _embed("python programming language")
        sim_related  = _cosine(v1, v2)
        sim_unrelated= _cosine(v1, v3)
        check("Semantic: related phrases score high",
              sim_related > 0.35, f"score={sim_related:.3f}")
        check("Semantic: unrelated phrases score low",
              sim_unrelated < sim_related, f"unrelated={sim_unrelated:.3f}")
    else:
        check("sentence-transformers not installed — keyword fallback active",
              True, "pip install sentence-transformers for semantic search", warn=True)
except Exception as e:
    check("Semantic search self-test", False, str(e))

# ══════════════════════════════════════════════════════════
section("11 · VOICE EMOTION DETECTOR")
# ══════════════════════════════════════════════════════════
ve_src = (BASE/"core"/"voice_emotion.py").read_text(encoding="utf-8", errors="replace")
check("voice_emotion.py exists and has VoiceEmotionDetector", "VoiceEmotionDetector" in ve_src)
check("Emotion detector wired into main.py mic loop",
      "_emotion" in main_src and "voice_emotion" in main_src)

# Functional test — feed synthetic PCM
try:
    sys.path.insert(0, str(BASE))
    from core.voice_emotion import VoiceEmotionDetector, WINDOW_CHUNKS, CHUNK_BYTES
    detected = []
    det = VoiceEmotionDetector(on_state_change=lambda s: detected.append(s))
    det._HOLD_SECONDS    = 0   # bypass hold timer for test
    det._COOLDOWN_SECONDS = 0

    # loud stressed signal: high amplitude + high zero-crossing rate
    n = CHUNK_BYTES // 2
    loud = []
    for i in range(n):
        loud.append(int(2500 * math.sin(2*math.pi*300*i/16000)))  # 300Hz sine, high amp
    pcm_loud = struct.pack(f"<{n}h", *loud)
    for _ in range(WINDOW_CHUNKS + 2):
        det.feed(pcm_loud)

    check("VoiceEmotionDetector feeds without error", True)
except Exception as e:
    check("VoiceEmotionDetector feeds without error", False, str(e))

# ══════════════════════════════════════════════════════════
section("12 · CALENDAR INTEGRATION")
# ══════════════════════════════════════════════════════════
cal_src = (BASE/"core"/"calendar_intel.py").read_text(encoding="utf-8", errors="replace")
check("calendar_intel.py exists with CalendarReminder", "CalendarReminder" in cal_src)
check("get_calendar_events tool declared", "get_calendar_events" in main_src)
check("Calendar wired into main.py startup", "CalendarReminder" in main_src)
creds_ok = (BASE/"config"/"google_credentials.json").exists()
check("Google credentials  [optional]",
      creds_ok, "Add config/google_credentials.json to enable calendar", warn=True)

# ══════════════════════════════════════════════════════════
section("13 · MOBILE SERVER — NEW FEATURES")
# ══════════════════════════════════════════════════════════
ms_src = (BASE/"mobile_server.py").read_text(encoding="utf-8", errors="replace")
mobile_checks = [
    ("Screen stream endpoint /stream/latest.jpg",  "/stream/latest.jpg"),
    ("REMOTE tab in mobile UI",                    "remote-panel"),
    ("SCREEN tab in mobile UI",                    "stream-panel"),
    ("Screen capture background thread",           "_stream_capture_loop"),
    ("HTTP /command endpoint for automation",      "/command"),
    ("Remote control buttons in HTML",             "rc('volume_up')"),
    ("Lock/Shutdown confirm buttons",              "rcConfirm"),
    ("Auto-refresh toggle",                        "toggleAutoRefresh"),
    ("FCM push still present",                     "FCMPusher"),
]
for label, token in mobile_checks:
    check(label, token in ms_src)

# ══════════════════════════════════════════════════════════
section("14 · REMOTE CONTROL DISPATCH")
# ══════════════════════════════════════════════════════════
rc_actions = [
    "volume_up","volume_down","volume_mute",
    "brightness_up","lock","shutdown","screenshot",
    "minimize","close_window","fullscreen",
    "play_pause","next_track","prev_track",
]
for a in rc_actions:
    check(f"remote_control '{a}' handled in dispatch", a in main_src)

# ══════════════════════════════════════════════════════════
section("15 · ACTIVE WINDOW CONTEXT")
# ══════════════════════════════════════════════════════════
check("Active window injected into system prompt", "ACTIVE WINDOW" in main_src)
check("get_active_window tool declared",           "get_active_window" in main_src)
try:
    import win32gui
    hwnd  = win32gui.GetForegroundWindow()
    title = win32gui.GetWindowText(hwnd)
    check("win32gui reads active window live", True, f"Current: '{title}'")
except ImportError:
    check("win32gui available", False, "pip install pywin32", warn=True)

# ══════════════════════════════════════════════════════════
section("16 · CLIPBOARD")
# ══════════════════════════════════════════════════════════
check("read_clipboard tool declared", "read_clipboard" in main_src)
try:
    import pyperclip
    txt = pyperclip.paste()
    check("pyperclip reads clipboard", True,
          f"Current content: '{str(txt)[:40]}'" if txt else "Clipboard is empty")
except Exception as e:
    check("pyperclip reads clipboard", False, str(e))

# ══════════════════════════════════════════════════════════
section("17 · WATCHER SERVICE")
# ══════════════════════════════════════════════════════════
# Check watcher source has native win32evtlog API (not PowerShell-only)
ws_src = (BASE / "jarvis_watcher_service.py").read_text(encoding="utf-8", errors="replace")
check("Native win32evtlog in watcher (no PowerShell timeout risk)",
      "_WIN32EVTLOG_OK" in ws_src,
      "Deploy new jarvis_watcher_service.py" if "_WIN32EVTLOG_OK" not in ws_src else "")

log_path = BASE / "memory" / "watcher_service.log"
if log_path.exists():
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    last20 = "\n".join(lines[-20:])
    has_failed_logon = "FAILED LOGON" in last20
    has_ps_timeout   = "timed out" in last20.lower() and "powershell" in last20.lower()
    has_telegram_ok  = "Telegram: OK" in last20
    has_fcm_ok       = "FCM: OK" in last20
    has_baseline     = "Baseline RecordId" in last20
    import os as _os, time as _t
    log_age_min = (_t.time() - _os.path.getmtime(str(log_path))) / 60
    fresh = log_age_min < 10   # log written in last 10 min = after latest restart
    # Timeout is only a FAIL if the log is fresh (i.e. running the new code)
    check("Watcher baseline established (no crash at start)",
          has_baseline, lines[-1] if lines else "empty log",
          warn=not has_baseline)
    check("No PowerShell timeout in log",
          not has_ps_timeout,
          ("Restart watcher (elevated PS): nssm restart JARVISWatcher" if has_ps_timeout else ""),
          warn=not fresh)    # old log = warn; fresh log with timeout = FAIL
    check("Recent FAILED LOGON detected", has_failed_logon,
          "Win+L → wrong password → wait 5s to trigger", warn=True)
    check("Telegram: OK in recent log", has_telegram_ok,
          "Trigger a failed-login test first", warn=True)
    check("FCM: OK in recent log", has_fcm_ok,
          "Open http://<PC-IP>:8080 on phone once to refresh FCM token", warn=True)
else:
    check("watcher_service.log exists", False,
          "Start JARVISWatcher: nssm start JARVISWatcher", warn=True)

# ══════════════════════════════════════════════════════════
section("18 · NETWORK — MOBILE REACHABILITY")
# ══════════════════════════════════════════════════════════
def get_lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

lan_ip = get_lan_ip()
print(f"        PC LAN IP: {lan_ip}")
print(f"        Mobile URL: http://{lan_ip}:8080")
print(f"        Screen stream: http://{lan_ip}:8080/stream/latest.jpg")
print(f"        WS port: {lan_ip}:8081")

http_open = False
ws_open   = False
for port, label in [(8080,"HTTP/mobile"), (8081,"WebSocket")]:
    s = socket.socket()
    s.settimeout(1.5)
    try:
        s.connect((lan_ip, port))
        ok = True
    except Exception:
        ok = False
    finally:
        s.close()
    if port == 8080: http_open = ok
    if port == 8081: ws_open   = ok
    check(f"Port {port} ({label}) open",
          ok, "Start main.py first" if not ok else "")

# ══════════════════════════════════════════════════════════
section("19 · SCREEN CAPTURE LIVE TEST")
# ══════════════════════════════════════════════════════════
try:
    sys.path.insert(0, str(BASE))
    from actions.screen_processor import _capture_screenshot, _MSS_OK, _PIL_OK
    check("mss installed", _MSS_OK, "pip install mss" if not _MSS_OK else "")
    check("Pillow installed", _PIL_OK, "pip install Pillow" if not _PIL_OK else "")
    if _MSS_OK:
        t0    = time.time()
        frame = _capture_screenshot()
        ms    = (time.time()-t0)*1000
        check("Screenshot captured live",
              len(frame) > 1000, f"{len(frame)//1024}KB in {ms:.0f}ms")
except Exception as e:
    check("Screenshot captured live", False, str(e))

# ══════════════════════════════════════════════════════════
section("20 · MULTI-MONITOR SUPPORT")
# ══════════════════════════════════════════════════════════
try:
    import mss
    with mss.mss() as sct:
        n_monitors = len(sct.monitors) - 1  # index 0 = all combined
    check(f"Monitor count detected: {n_monitors}",
          n_monitors >= 1, f"{n_monitors} monitor(s) found")
    check("_capture_screenshot accepts monitor_index param",
          "monitor_index" in (BASE/"actions"/"screen_processor.py")
          .read_text(encoding="utf-8", errors="replace"))
except Exception as e:
    check("Monitor detection", False, str(e))

# ══════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════
total   = len(results)
passed  = sum(1 for _,ok,w in results if ok and not w)
warned  = sum(1 for _,ok,w in results if w)
failed  = sum(1 for _,ok,w in results if not ok and not w)

print(f"\n{'═'*55}")
print(f"  RESULTS   {passed} passed   {warned} warnings   {failed} failed   ({total} total)")
print(f"{'═'*55}")

if failed == 0:
    print("\033[92m\n  ALL CORE CHECKS PASSED — JARVIS is ready.\033[0m")
else:
    print(f"\033[91m\n  {failed} check(s) failed — see details above.\033[0m")

if warned:
    print(f"\033[93m  {warned} optional feature(s) not configured — see WARN lines above.\033[0m")

print()
