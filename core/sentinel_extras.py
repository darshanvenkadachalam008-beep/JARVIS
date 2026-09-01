"""
core/sentinel_extras.py — JARVIS Sentinel Extensions
======================================================
Shared, dependency-light helpers and background monitors used by the
cold-boot watcher (jarvis_watcher_service.py) to extend the original
"failed login" alert into a broader anti-theft sentinel:

  • AlertHistory          — append-only JSON log of every alert fired,
                             plus an HTML renderer used by mobile_server's
                             /history route.
  • geoip_lookup()         — approximate location via public IP (no GPS
                             hardware needed on a desktop/laptop).
  • gemini_threat_analysis — one-paragraph pattern summary of recent
                             alerts, using the same Gemini key/model the
                             rest of the app already uses.
  • detect_face_present()  — OpenCV Haar-cascade face *detection* (not
                             identity recognition — see note below).
  • take_webcam_burst()    — a few frames in quick succession, sent as a
                             Telegram album. Practical stand-in for true
                             live video (see note below).
  • send_telegram_album()  — sendMediaGroup helper.
  • USBMonitor             — alerts when a removable drive is inserted.
  • BatteryMonitor         — alerts when AC power is unplugged.
  • WifiGeofenceMonitor    — alerts when connected to a WiFi network
                             outside a configured trusted list.
  • EmergencyWipeListener  — long-polls Telegram for an authorized,
                             two-step "wipe" command and moves configured
                             paths to the Recycle Bin (send2trash — never
                             a permanent unrecoverable delete).

NOT implemented here, on purpose:
  • True live video streaming. Real-time video needs a streaming
    transport (your mobile_server already has a WebSocket on :8081 —
    that's the right place for it later). take_webcam_burst() is a
    pragmatic few-stills-in-a-row "flipbook" instead.
  • A "decoy password" that lets a fake login through while secretly
    recording. This watcher only *observes* the Windows Security event
    log after a logon attempt — it has no way to intercept or alter
    Windows' own authentication decision. Doing that for real needs a
    custom Windows Credential Provider, which is a much deeper, fragile
    Windows-internals project and out of scope here.

True face *recognition* (is this actually you vs. a stranger, not just
"a face exists") now lives in core/face_verify.py — see that module's
docstring. It uses OpenCV's built-in LBPH recognizer (opencv-contrib-python)
rather than face_recognition/dlib, specifically to avoid the Windows build
pain noted above. detect_face_present() below is unchanged and still just
answers presence, not identity — face_verify.py is the identity layer.
"""

from __future__ import annotations

import json
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

# Security add-ons: tamper-evident audit trail + PIN-gated destructive actions
from core.audit_log import AuditLog
from core.access_control import AccessControl
from pathlib import Path
from typing import Callable, Optional

BASE_DIR      = Path(__file__).resolve().parent.parent
CONFIG_PATH   = BASE_DIR / "config" / "api_keys.json"
HISTORY_PATH  = BASE_DIR / "memory" / "alert_history.json"
MAX_HISTORY   = 200

NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW — suppresses console flash on Windows


def _log(msg: str, log_fn: Optional[Callable[[str], None]] = None):
    if log_fn:
        try:
            log_fn(msg)
            return
        except Exception:
            pass
    print(f"[Sentinel] {msg}")


def _load_config() -> dict:
    try:
        if CONFIG_PATH.exists():
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


# ═══════════════════════════════════════════════════════════════════════════
# ALERT HISTORY  (used by the /history dashboard in mobile_server.py)
# ═══════════════════════════════════════════════════════════════════════════

_history_lock = threading.Lock()


class AlertHistory:
    """Append-only JSON log of every alert fired, any channel."""

    @staticmethod
    def record(event_type: str, title: str, detail: str = "", extra: Optional[dict] = None):
        entry = {
            "ts":         datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": event_type,
            "title":      title,
            "detail":     detail,
            "extra":      extra or {},
        }
        with _history_lock:
            try:
                items = []
                if HISTORY_PATH.exists():
                    items = json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
                items.append(entry)
                items = items[-MAX_HISTORY:]
                HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
                HISTORY_PATH.write_text(json.dumps(items, indent=2), encoding="utf-8")
            except Exception as e:
                print(f"[Sentinel] AlertHistory write error: {e}")
        try:
            AuditLog().append(f"alert:{event_type}", {"title": title, "detail": detail, "extra": extra or {}})
        except Exception as e:
            print(f"[Sentinel] AuditLog write error: {e}")

    @staticmethod
    def recent(n: int = 10) -> list:
        try:
            if HISTORY_PATH.exists():
                items = json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
                return items[-n:]
        except Exception:
            pass
        return []

    @staticmethod
    def render_html() -> bytes:
        items = list(reversed(AlertHistory.recent(MAX_HISTORY)))
        rows = []
        for it in items:
            rows.append(
                "<tr>"
                f"<td>{it.get('ts','')}</td>"
                f"<td>{it.get('event_type','')}</td>"
                f"<td>{it.get('title','')}</td>"
                f"<td>{it.get('detail','')}</td>"
                "</tr>"
            )
        rows_html = "\n".join(rows) if rows else "<tr><td colspan=4>No alerts yet.</td></tr>"
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JARVIS — Alert History</title>
<style>
body{{background:#0b0b0b;color:#e6e6e6;font-family:Consolas,monospace;margin:0;padding:16px}}
h1{{color:#ff3b3b;font-size:1.3em}}
table{{width:100%;border-collapse:collapse;margin-top:12px}}
th,td{{border-bottom:1px solid #333;padding:8px;text-align:left;font-size:0.85em;word-break:break-word}}
th{{color:#ff8a8a;text-transform:uppercase;font-size:0.75em}}
tr:hover{{background:#1a1a1a}}
.count{{color:#888;font-size:0.85em}}
</style></head><body>
<h1>&#128737; JARVIS Alert History</h1>
<div class="count">{len(items)} alert(s) — most recent first</div>
<table><tr><th>Time</th><th>Type</th><th>Title</th><th>Detail</th></tr>
{rows_html}
</table>
</body></html>"""
        return html.encode("utf-8")


# ═══════════════════════════════════════════════════════════════════════════
# GEOIP (approximate location — no GPS hardware required)
# ═══════════════════════════════════════════════════════════════════════════

def geoip_lookup() -> Optional[dict]:
    """Approximate location from the PC's public IP. City-level accuracy,
    not GPS — most desktops/laptops have no GPS chip at all."""
    try:
        with urllib.request.urlopen("http://ip-api.com/json/?fields=status,city,regionName,country,lat,lon,query", timeout=8) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            return data
    except Exception as e:
        print(f"[Sentinel] GeoIP error: {e}")
    return None


# ═══════════════════════════════════════════════════════════════════════════
# AI THREAT ANALYSIS  (Gemini — same key/model the rest of the app uses)
# ═══════════════════════════════════════════════════════════════════════════

def gemini_threat_analysis(recent_events: list, api_key: str) -> Optional[str]:
    if not api_key or not recent_events:
        return None
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.5-flash")
        lines = "\n".join(
            f"- {e.get('ts')}: {e.get('event_type')} — {e.get('title')}"
            for e in recent_events
        )
        prompt = (
            "You are a terse home-security assistant. Given this recent log "
            "of intrusion-watcher events for one PC, write a single short "
            "paragraph (max 3 sentences) noting any pattern worth flagging "
            "(repeat attempts, odd hours, multiple signal types close "
            "together). If nothing stands out, say so plainly. No preamble.\n\n"
            f"{lines}"
        )
        result = model.generate_content(prompt)
        return (result.text or "").strip()[:500]
    except Exception as e:
        print(f"[Sentinel] Gemini analysis error: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════════
# FACE PRESENCE DETECTION (detection only — not identity recognition)
# ═══════════════════════════════════════════════════════════════════════════

def detect_face_present(jpeg_bytes: bytes) -> Optional[bool]:
    if not jpeg_bytes:
        return None
    try:
        import cv2
        import numpy as np
        arr = np.frombuffer(jpeg_bytes, dtype="uint8")
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            return None
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        cascade = cv2.CascadeClassifier(cascade_path)
        faces = cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(40, 40))
        return len(faces) > 0
    except Exception as e:
        print(f"[Sentinel] Face detection error: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════════
# WEBCAM BURST  (practical stand-in for "live stream")
# ═══════════════════════════════════════════════════════════════════════════

def take_webcam_burst(n: int = 4, interval: float = 0.8) -> list:
    """A few frames in quick succession. Same SYSTEM-session caveat as the
    single-shot capture in jarvis_watcher_service.py applies here too."""
    try:
        import cv2
    except ImportError:
        return []
    frames = []
    cap = cv2.VideoCapture(0)
    try:
        if not cap.isOpened():
            return []
        for _ in range(5):
            cap.read()
        for i in range(max(1, n)):
            ok, frame = cap.read()
            if ok and frame is not None:
                ok2, buf = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 85])
                if ok2:
                    frames.append(bytes(buf))
            if i < n - 1:
                time.sleep(interval)
    except Exception as e:
        print(f"[Sentinel] Webcam burst error: {e}")
    finally:
        cap.release()
    return frames


# ═══════════════════════════════════════════════════════════════════════════
# TELEGRAM HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def send_telegram_text(token: str, chat_id: str, text: str) -> bool:
    if not token or not chat_id:
        return False
    try:
        payload = json.dumps({"chat_id": chat_id, "text": text, "parse_mode": "HTML"}).encode("utf-8")
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=payload, headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"[Sentinel] Telegram text error: {e}")
        return False


def send_telegram_album(token: str, chat_id: str, jpeg_list: list, caption: str = "") -> bool:
    if not token or not chat_id or not jpeg_list:
        return False
    try:
        boundary = "----JARVISAlbumBoundary7MA4YWxkTrZu0gW"
        media = []
        body = []

        body.append(f"--{boundary}".encode())
        body.append(b'Content-Disposition: form-data; name="chat_id"')
        body.append(b"")
        body.append(str(chat_id).encode())

        for i, jpeg in enumerate(jpeg_list[:10]):  # Telegram album max 10
            field = f"photo{i}"
            entry = {"type": "photo", "media": f"attach://{field}"}
            if i == 0 and caption:
                entry["caption"] = caption
            media.append(entry)

            body.append(f"--{boundary}".encode())
            body.append(f'Content-Disposition: form-data; name="{field}"; filename="{field}.jpg"'.encode())
            body.append(b"Content-Type: image/jpeg")
            body.append(b"")
            body.append(jpeg)

        body.append(f"--{boundary}".encode())
        body.append(b'Content-Disposition: form-data; name="media"')
        body.append(b"")
        body.append(json.dumps(media).encode("utf-8"))

        body.append(f"--{boundary}--".encode())
        payload = b"\r\n".join(body)

        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMediaGroup",
            data=payload,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=40) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"[Sentinel] Telegram album error: {e}")
        return False


def send_pushbullet_text(token: str, title: str, body: str) -> bool:
    if not token:
        return False
    try:
        payload = json.dumps({"type": "note", "title": title, "body": body}).encode("utf-8")
        req = urllib.request.Request(
            "https://api.pushbullet.com/v2/pushes",
            data=payload,
            headers={"Access-Token": token, "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"[Sentinel] Pushbullet text error: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════
# RUN-PS HELPER (invisible PowerShell, same pattern as the watcher)
# ═══════════════════════════════════════════════════════════════════════════

def _run_ps(cmd: str, timeout: int = 8) -> str:
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout, creationflags=NO_WINDOW,
        )
        return result.stdout.strip()
    except Exception:
        return ""


# ═══════════════════════════════════════════════════════════════════════════
# USB MONITOR
# ═══════════════════════════════════════════════════════════════════════════

DRIVE_REMOVABLE = 2


class USBMonitor:
    """Polls logical drives every few seconds; fires on_insert when a new
    removable drive letter appears that wasn't there before."""

    def __init__(self, on_insert: Callable[[str], None], poll_interval: float = 3.0):
        self._on_insert = on_insert
        self._poll = poll_interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._known: set = set()

    def _scan(self) -> set:
        try:
            import win32api
            import win32file
            drives = win32api.GetLogicalDriveStrings().split("\x00")
            removable = set()
            for d in drives:
                if not d:
                    continue
                try:
                    if win32file.GetDriveType(d) == DRIVE_REMOVABLE:
                        removable.add(d)
                except Exception:
                    continue
            return removable
        except Exception as e:
            print(f"[Sentinel] USBMonitor scan error: {e}")
            return set()

    def start(self):
        self._known = self._scan()  # baseline — don't alert on drives already present
        self._thread = threading.Thread(target=self._loop, daemon=True, name="USBMonitor")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            current = self._scan()
            new_drives = current - self._known
            for d in new_drives:
                try:
                    self._on_insert(d)
                except Exception as e:
                    print(f"[Sentinel] USBMonitor callback error: {e}")
            self._known = current
            self._stop.wait(self._poll)


# ═══════════════════════════════════════════════════════════════════════════
# BATTERY / POWER MONITOR
# ═══════════════════════════════════════════════════════════════════════════

class BatteryMonitor:
    """Polls psutil.sensors_battery(); fires on_unplugged the moment AC
    power is removed (e.g. someone unplugging the laptop to walk off with
    it). Silently does nothing on desktops with no battery."""

    def __init__(self, on_unplugged: Callable[[], None], poll_interval: float = 5.0):
        self._on_unplugged = on_unplugged
        self._poll = poll_interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_plugged: Optional[bool] = None

    def start(self):
        try:
            import psutil
            batt = psutil.sensors_battery()
            if batt is None:
                print("[Sentinel] BatteryMonitor: no battery detected — monitor not started")
                return
        except Exception as e:
            print(f"[Sentinel] BatteryMonitor unavailable: {e}")
            return
        self._thread = threading.Thread(target=self._loop, daemon=True, name="BatteryMonitor")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        import psutil
        while not self._stop.is_set():
            try:
                batt = psutil.sensors_battery()
                if batt is not None:
                    plugged = bool(batt.power_plugged)
                    if self._last_plugged is True and plugged is False:
                        self._on_unplugged()
                    self._last_plugged = plugged
            except Exception as e:
                print(f"[Sentinel] BatteryMonitor poll error: {e}")
            self._stop.wait(self._poll)


# ═══════════════════════════════════════════════════════════════════════════
# WIFI GEOFENCE MONITOR
# ═══════════════════════════════════════════════════════════════════════════

class WifiGeofenceMonitor:
    """Polls the currently connected WiFi SSID; fires on_untrusted(ssid)
    whenever the PC joins a network NOT in trusted_ssids. Configure the
    allow-list via "trusted_wifi_ssids": ["Home-WiFi", ...] in
    config/api_keys.json. If that key is absent, the monitor logs once
    and does nothing (fail-safe — no false alarms with no config)."""

    def __init__(self, on_untrusted: Callable[[str], None], trusted_ssids: list, poll_interval: float = 15.0):
        self._on_untrusted = on_untrusted
        self._trusted = set(trusted_ssids or [])
        self._poll = poll_interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_alerted_ssid: Optional[str] = None

    def _current_ssid(self) -> Optional[str]:
        out = _run_ps(
            "(netsh wlan show interfaces) | Select-String '^\\s*SSID\\s*:' "
            "| Select-Object -First 1 | ForEach-Object { ($_ -split ':',2)[1].Trim() }"
        )
        return out or None

    def start(self):
        if not self._trusted:
            print("[Sentinel] WifiGeofenceMonitor: no trusted_wifi_ssids configured — monitor not started")
            return
        self._thread = threading.Thread(target=self._loop, daemon=True, name="WifiGeofenceMonitor")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            try:
                ssid = self._current_ssid()
                if ssid and ssid not in self._trusted and ssid != self._last_alerted_ssid:
                    self._last_alerted_ssid = ssid
                    self._on_untrusted(ssid)
                elif ssid in self._trusted:
                    self._last_alerted_ssid = None
            except Exception as e:
                print(f"[Sentinel] WifiGeofenceMonitor poll error: {e}")
            self._stop.wait(self._poll)


# ═══════════════════════════════════════════════════════════════════════════
# EMERGENCY WIPE CONTROLLER & LISTENERS  (Multi-channel remote kill switch)
# ═══════════════════════════════════════════════════════════════════════════
#
# Multi-channel, two-factor, Recycle-Bin-only (send2trash — never a
# permanent unrecoverable delete). Configure the paths you'd actually want
# wiped via "wipe_paths": ["D:\\Secrets", ...] in config/api_keys.json.
# With no wipe_paths configured, every wipe request is rejected — safe by default.
#
# Channels:
#   1. Telegram Bot (EmergencyWipeListener)
#   2. Mobile Hub WebSocket / HTTP REST API (mobile_server.py)
#
# Protocol (Both Channels):
#   Step 1: Send wipe request (/wipe or wipe_request) -> 60s confirmation countdown starts.
#   Step 2: Send confirmation (/wipe CONFIRM <PIN> or wipe_confirm with PIN) within 60s.
#   Step 3: AccessControl validates PIN (action="emergency_wipe") with brute-force lockout.
#   Step 4: Configured wipe_paths moved to Recycle Bin via send2trash.
#   Step 5: AlertHistory and Sentinel AuditLog record the wipe tagged with trigger channel.
# ═══════════════════════════════════════════════════════════════════════════

class EmergencyWipeController:
    """
    Centralized controller for two-factor emergency remote wipe requests.
    Supports multi-channel trigger sources (Telegram, Mobile WebSocket/API, etc.)
    with:
    1. Independent 60s confirmation countdown window.
    2. AccessControl PBKDF2 PIN verification (action="emergency_wipe") with lockout defense.
    3. Safe execution using send2trash (Recycle Bin, not permanent raw unrecoverable delete).
    4. Comprehensive, channel-tagged audit logging via AlertHistory.record() and Sentinel AuditLog.
    """
    _instance: Optional["EmergencyWipeController"] = None
    _lock = threading.Lock()

    def __init__(self, wipe_paths: Optional[list] = None, confirmation_timeout_seconds: float = 60.0):
        self._paths = wipe_paths if wipe_paths is not None else (_load_config().get("wipe_paths") or [])
        self._timeout = confirmation_timeout_seconds
        self._pending_lock = threading.Lock()
        self._pending_channel: Optional[str] = None
        self._pending_since: Optional[float] = None

    @classmethod
    def get_instance(cls) -> "EmergencyWipeController":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def set_instance(cls, instance: Optional["EmergencyWipeController"]):
        with cls._lock:
            cls._instance = instance

    def request_wipe(self, channel: str = "telegram") -> tuple[bool, str]:
        """Initiates a pending wipe request with a 60-second confirmation window."""
        if not self._paths:
            return False, "⚠️ No wipe_paths configured in config/api_keys.json — nothing to wipe."

        with self._pending_lock:
            self._pending_since = time.monotonic()
            self._pending_channel = channel

        msg = (
            f"⚠️ Emergency wipe requested via {channel}. Send confirmation with PIN within {int(self._timeout)}s "
            f"to move {len(self._paths)} configured path(s) to the Recycle Bin."
        )
        return True, msg

    def confirm_wipe(self, pin: str, channel: str = "telegram") -> tuple[bool, str, list[str]]:
        """
        Validates confirmation timing and security PIN, then executes wipe.
        Returns: (success: bool, status_message: str, results: list[str])
        """
        with self._pending_lock:
            pending_since = self._pending_since
            if not pending_since or (time.monotonic() - pending_since) > self._timeout:
                self._pending_since = None
                self._pending_channel = None
                return False, "⏱ No pending wipe request (or request expired). Initiate wipe request first.", []

        ac = AccessControl()
        if not ac.is_configured():
            return False, "❌ No security PIN configured yet (core/access_control.py) — wipe refused for safety. Run setup_security.py first.", []

        if not ac.verify_pin(pin, action="emergency_wipe"):
            return False, "❌ PIN incorrect or lockout active — wipe refused. This attempt was logged.", []

        with self._pending_lock:
            self._pending_since = None
            self._pending_channel = None

        success, results = self.execute_wipe(channel=channel)
        status_msg = "Wipe complete" if success else "Wipe encountered errors"
        return success, status_msg, results

    def execute_wipe(self, channel: str = "unknown") -> tuple[bool, list[str]]:
        """Executes moving configured wipe_paths to Recycle Bin via send2trash."""
        try:
            from send2trash import send2trash
        except ImportError:
            return False, ["❌ send2trash not installed — cannot wipe safely. Aborted."]

        results = []
        any_failed = False
        for p in self._paths:
            path = Path(p)
            try:
                if path.exists():
                    send2trash(str(path))
                    results.append(f"✅ {p}")
                    AlertHistory.record("wipe", f"Emergency wipe executed via {channel}", p, extra={"channel": channel})
                else:
                    results.append(f"⏭ {p} (not found)")
            except Exception as e:
                any_failed = True
                results.append(f"❌ {p} ({e})")
                AlertHistory.record("wipe_failed", f"Emergency wipe error on {p} via {channel}", str(e), extra={"channel": channel})

        overall_success = not any_failed and len(results) > 0
        return overall_success, results


class EmergencyWipeListener:

    def __init__(self, token: str, authorized_chat_id: str, wipe_paths: Optional[list] = None, poll_interval: float = 4.0, controller: Optional[EmergencyWipeController] = None):
        self._token   = token
        self._chat_id = str(authorized_chat_id)
        self._poll    = poll_interval
        self._stop    = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._offset  = 0
        self._controller = controller or EmergencyWipeController.get_instance()
        if wipe_paths is not None:
            self._controller._paths = wipe_paths

    def start(self):
        if not self._token or not self._chat_id:
            print("[Sentinel] EmergencyWipeListener: Telegram not configured — not started")
            return
        self._thread = threading.Thread(target=self._loop, daemon=True, name="EmergencyWipeListener")
        self._thread.start()
        print(f"[Sentinel] EmergencyWipeListener active — {len(self._controller._paths)} path(s) configured")

    def stop(self):
        self._stop.set()

    def _get_updates(self) -> list:
        try:
            url = (f"https://api.telegram.org/bot{self._token}/getUpdates"
                   f"?offset={self._offset + 1}&timeout=3")
            with urllib.request.urlopen(url, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            return data.get("result", [])
        except Exception:
            return []

    def _reply(self, text: str):
        send_telegram_text(self._token, self._chat_id, text)

    def _loop(self):
        while not self._stop.is_set():
            for update in self._get_updates():
                self._offset = max(self._offset, update.get("update_id", 0))
                msg = update.get("message", {})
                chat_id = str(msg.get("chat", {}).get("id", ""))
                text = (msg.get("text") or "").strip()

                if chat_id != self._chat_id:
                    continue  # ignore anyone not the configured owner chat

                if text.lower() == "/wipe":
                    ok, reply_msg = self._controller.request_wipe(channel="telegram")
                    self._reply(reply_msg)
                elif text.upper().startswith("/WIPE CONFIRM"):
                    parts = text.split(maxsplit=2)
                    pin = parts[2] if len(parts) >= 3 else ""
                    ok, status_msg, results = self._controller.confirm_wipe(pin, channel="telegram")
                    if results:
                        self._reply(f"🗑 <b>{status_msg}</b>\n\n" + "\n".join(results))
                    else:
                        self._reply(status_msg)
            self._stop.wait(self._poll)