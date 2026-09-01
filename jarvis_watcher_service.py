"""
jarvis_watcher_service.py — JARVIS Cold-Boot Intruder Detection Service
=========================================================================
A true Windows Service (runs as SYSTEM from cold boot, before any user
logs in). Watches for failed login attempts (Event ID 4625) from the
very first second Windows starts.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
COMMANDS (all require Administrator except status/test):

  python jarvis_watcher_service.py install   ← register + auto-start on boot
  python jarvis_watcher_service.py start     ← start right now
  python jarvis_watcher_service.py stop      ← stop
  python jarvis_watcher_service.py remove    ← uninstall
  python jarvis_watcher_service.py status    ← check if running
  python jarvis_watcher_service.py test      ← run inline for 60s (no install needed)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import base64
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import win32event
    import win32service
    import win32serviceutil
    import servicemanager
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

# fcm_push.py lives alongside this file in the project root — it's the
# free (no Twilio account needed) loud-alert channel: a high-priority
# Android push that opens the full-screen /alert siren page on your phone.
try:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from fcm_push import FCMPusher
    HAS_FCM = True
except ImportError:
    HAS_FCM = False


# ═══════════════════════════════════════════════════════════════════════════════
# PATHS
# ═══════════════════════════════════════════════════════════════════════════════

BASE_DIR    = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config" / "api_keys.json"
STATE_PATH  = BASE_DIR / "memory" / "watcher_service_state.json"
LOG_PATH    = BASE_DIR / "memory" / "watcher_service.log"


# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

def _log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}\n"
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# STATE
# ═══════════════════════════════════════════════════════════════════════════════

def _load_state() -> int:
    try:
        if STATE_PATH.exists():
            data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            return int(data.get("last_alerted_record_id", 0))
    except Exception:
        pass
    return 0


def _save_state(record_id: int):
    try:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        STATE_PATH.write_text(
            json.dumps({"last_alerted_record_id": record_id}),
            encoding="utf-8"
        )
    except Exception as e:
        _log(f"State save error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

def _load_config() -> dict:
    try:
        if CONFIG_PATH.exists():
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        _log(f"Config load error: {e}")
    return {}


# ═══════════════════════════════════════════════════════════════════════════════
# TELEGRAM
# ═══════════════════════════════════════════════════════════════════════════════

def _owner_display_name(hostname: str) -> str:
    """Human greeting name for the alert. Reads 'owner_name' from config if
    set, otherwise falls back to the machine hostname, title-cased."""
    try:
        cfg = _load_config()
        name = cfg.get("owner_name")
        if name:
            return str(name)
    except Exception:
        pass
    return hostname.capitalize()


def _alert_caption(hostname: str, time_str: str) -> str:
    """Telegram version — HTML bold tags render fine here."""
    name = _owner_display_name(hostname)
    return (
        "🔴🔴🔴 <b>DANGER  DANGER  DANGER</b> 🔴🔴🔴\n"
        "☠️ <b>SECURITY BREACH DETECTED</b> ☠️\n\n"
        f"⚠️ Hey {name},\n"
        "Someone is trying to unlock your system RIGHT NOW!\n\n"
        f"🖥 <b>MACHINE</b>  →  {hostname}\n"
        f"⏱ <b>TIME</b>     →  {time_str}\n"
        "🔒 <b>STATUS</b>   →  INTRUSION DETECTED\n"
        "📸 <b>SNAPSHOT</b> →  CAPTURED\n"
        "🚨 <b>THREAT</b>   →  HIGH\n\n"
        "🔴 INITIATING SECURITY PROTOCOL...\n"
        "🔴🔴🔴 DANGER  DANGER  DANGER 🔴🔴🔴\n\n"
        "— J.A.R.V.I.S | Stark Industries\n"
        "Mark-XXXIX-OR Security System"
    )


def _alert_text_plain(hostname: str, time_str: str, snapshot_captured: bool = True) -> str:
    """SMS version — same content, no HTML tags (SMS can't render them)."""
    name = _owner_display_name(hostname)
    snapshot_line = "CAPTURED" if snapshot_captured else "UNAVAILABLE"
    return (
        "🔴🔴🔴 DANGER  DANGER  DANGER 🔴🔴🔴\n"
        "☠️ SECURITY BREACH DETECTED ☠️\n\n"
        f"⚠️ Hey {name},\n"
        "Someone is trying to unlock your system RIGHT NOW!\n\n"
        f"🖥 MACHINE  →  {hostname}\n"
        f"⏱ TIME     →  {time_str}\n"
        "🔒 STATUS   →  INTRUSION DETECTED\n"
        f"📸 SNAPSHOT →  {snapshot_line}\n"
        "🚨 THREAT   →  HIGH\n\n"
        "🔴 INITIATING SECURITY PROTOCOL...\n"
        "🔴🔴🔴 DANGER  DANGER  DANGER 🔴🔴🔴\n\n"
        "— J.A.R.V.I.S | Stark Industries\n"
        "Mark-XXXIX-OR Security System"
    )


def _send_telegram(token: str, chat_id: str, hostname: str, time_str: str) -> bool:
    """Plain text alert — no screenshot. Used directly, and also as the
    guaranteed fallback if the screenshot-attached send fails for any reason."""
    text = _alert_caption(hostname, time_str)

    payload = json.dumps({
        "chat_id":    chat_id,
        "text":       text,
        "parse_mode": "HTML",
    }).encode("utf-8")

    url = f"https://api.telegram.org/bot{token}/sendMessage"

    # A screen-lock event can suspend network/DNS for well over a minute on
    # some machines (confirmed by testing: an outage lasting ~47s was seen
    # affecting both Telegram and FCM simultaneously). Retry across a long
    # enough window that a real outage still has a chance to clear before
    # we give up on this alert. Runs in its own thread (see _fire_alert),
    # so this does not block detection of further events.
    delays = [3, 5, 8, 13, 20]  # ~49s of total backoff across 6 attempts
    last_err: Optional[Exception] = None
    for attempt in range(1, len(delays) + 2):
        try:
            req = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception as e:
            last_err = e
            if attempt <= len(delays):
                _log(f"Telegram attempt {attempt} failed: {e} — retrying in {delays[attempt-1]}s")
                time.sleep(delays[attempt - 1])
    _log(f"Telegram error: {last_err}")
    return False


def _capture_alert_camera() -> Optional[bytes]:
    """Best-effort webcam capture for the alert — this is the useful shot,
    since it can catch whoever is actually at the keyboard. Unlike a
    screenshot, it isn't blocked by the lock screen's secure desktop or by
    Session-0 isolation (the watcher runs as a service), because it talks
    to the camera driver directly rather than reading a desktop surface.
    Any failure (no camera, driver busy, missing opencv-python, etc.)
    returns None rather than raising, so it can never block the alert."""
    try:
        from actions.screen_processor import _capture_camera
        return _capture_camera()
    except Exception as e:
        _log(f"Camera capture for alert failed: {e}")
        return None


ALERT_PHOTO_PATH = BASE_DIR / "memory" / "latest_intruder_photo.jpg"


def _capture_and_save_alert_photo() -> Optional[bytes]:
    """Captures once (webcam first, screenshot fallback) and saves to
    shared disk at ALERT_PHOTO_PATH, so jarvis_service.pyw's mobile HTTP
    server (a separate process) can serve it to the phone at
    /alert/latest.jpg — both for the full-screen alert page and as the
    image attached directly to the push notification itself. Returns the
    same bytes so the caller (Telegram sender) doesn't have to capture
    twice."""
    photo = _capture_alert_camera() or _capture_alert_screenshot()
    if photo:
        try:
            ALERT_PHOTO_PATH.parent.mkdir(parents=True, exist_ok=True)
            ALERT_PHOTO_PATH.write_bytes(photo)
        except Exception as e:
            _log(f"Could not save alert photo to disk: {e}")
    return photo


def _capture_alert_screenshot() -> Optional[bytes]:
    """Best-effort screen capture for the alert. Kept as a secondary
    fallback behind the camera: while the workstation is locked this will
    reliably fail (BitBlt can't read the secure desktop, and the service's
    Session-0 context blocks it independently of that), but it's cheap to
    try and harmless if it fails, so it stays as a fallback in case the
    alert ever fires in a context where the screen IS capturable (e.g. an
    unlocked-session event added later) and the camera is unavailable.
    Any failure here returns None rather than raising, so a screenshot
    problem can never block the guaranteed text alert."""
    try:
        from actions.screen_processor import _capture_screenshot
        return _capture_screenshot()
    except Exception as e:
        _log(f"Screenshot capture for alert failed: {e}")
        return None


def _send_telegram_photo(token: str, chat_id: str, caption: str, photo_bytes: bytes) -> bool:
    """Send the alert as a Telegram photo message (sendPhoto) with the
    snapshot attached. Built with plain urllib (no extra dependency) using
    a manual multipart/form-data body."""
    boundary = f"----JarvisBoundary{int(time.time() * 1000)}"
    body = bytearray()

    def _field(name: str, value: str):
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        body.extend(f"{value}\r\n".encode())

    _field("chat_id", chat_id)
    _field("caption", caption)
    _field("parse_mode", "HTML")
    body.extend(f"--{boundary}\r\n".encode())
    body.extend(b'Content-Disposition: form-data; name="photo"; filename="snapshot.jpg"\r\n')
    body.extend(b"Content-Type: image/jpeg\r\n\r\n")
    body.extend(photo_bytes)
    body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode())

    url = f"https://api.telegram.org/bot{token}/sendPhoto"
    delays = [3, 5, 8, 13, 20]
    last_err: Optional[Exception] = None
    for attempt in range(1, len(delays) + 2):
        try:
            req = urllib.request.Request(
                url, data=bytes(body), method="POST",
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status == 200
        except Exception as e:
            last_err = e
            if attempt <= len(delays):
                _log(f"Telegram photo attempt {attempt} failed: {e} — retrying in {delays[attempt-1]}s")
                time.sleep(delays[attempt - 1])
    _log(f"Telegram photo error: {last_err}")
    return False


def _send_telegram_alert(token: str, chat_id: str, hostname: str, time_str: str,
                          photo: Optional[bytes] = None) -> bool:
    """What _fire_alert actually calls: uses the alert photo captured once
    up front by _fire_alert (webcam first, screenshot fallback — see
    _capture_and_save_alert_photo), and guarantees the plain text alert
    still goes out if no image was captured or the photo send ultimately
    fails."""
    if photo:
        caption = _alert_caption(hostname, time_str)
        if _send_telegram_photo(token, chat_id, caption, photo):
            return True
        _log("Telegram photo send failed after retries — falling back to text-only alert")
    return _send_telegram(token, chat_id, hostname, time_str)


# ═══════════════════════════════════════════════════════════════════════════════
# TWILIO SMS  (fires alongside Telegram on every alert)
# ═══════════════════════════════════════════════════════════════════════════════

def _send_twilio_sms(sid: str, token: str, from_num: str, to_num: str,
                      hostname: str, time_str: str) -> bool:
    """Send SMS alert via Twilio. Plain text only — see note in _fire_alert
    about why a snapshot can't be attached without extra infrastructure.
    Note: since this fires in parallel with Telegram and doesn't wait to
    find out whether the snapshot capture succeeded, the SNAPSHOT line
    always says CAPTURED here — Telegram is the source of truth for
    whether an image actually made it through."""
    msg = _alert_text_plain(hostname, time_str, snapshot_captured=True)
    payload = urllib.parse.urlencode({
        "To":   to_num,
        "From": from_num,
        "Body": msg,
    }).encode("utf-8")
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    credentials = base64.b64encode(f"{sid}:{token}".encode()).decode()

    # Same retry rationale as Telegram — a screen-lock network blip
    # shouldn't drop the one alert channel meant to work when Telegram can't.
    delays = [3, 5, 8, 13, 20]
    last_err: Optional[Exception] = None
    message_sid: Optional[str] = None
    for attempt in range(1, len(delays) + 2):
        try:
            req = urllib.request.Request(
                url, data=payload,
                headers={
                    "Authorization": f"Basic {credentials}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read().decode())
                if result.get("status") in ("failed", "undelivered"):
                    return False
                message_sid = result.get("sid")
                break
        except Exception as e:
            last_err = e
            if attempt <= len(delays):
                _log(f"Twilio SMS attempt {attempt} failed: {e} — retrying in {delays[attempt-1]}s")
                time.sleep(delays[attempt - 1])
    else:
        _log(f"Twilio SMS error: {last_err}")
        return False

    # The create-message response above only ever reports "queued"/"sent" —
    # Twilio hasn't heard back from the carrier yet at that point, so it is
    # NOT proof the text actually reached the phone. Wait briefly, then
    # fetch the message resource by SID to see the real carrier-reported
    # status. This matters especially for SMS to Indian numbers, where
    # international-route messages can be silently filtered by the carrier
    # after Twilio has already accepted and queued them.
    if message_sid:
        time.sleep(8)
        try:
            status_url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages/{message_sid}.json"
            req = urllib.request.Request(
                status_url,
                headers={"Authorization": f"Basic {credentials}"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                final = json.loads(resp.read().decode())
                final_status = final.get("status")
                error_code = final.get("error_code")
                _log(f"Twilio SMS final status: {final_status}"
                     + (f" (error {error_code}: {final.get('error_message')})" if error_code else ""))
                if final_status in ("failed", "undelivered"):
                    return False
        except Exception as e:
            # Couldn't confirm final status — don't fail the alert over a
            # status-check hiccup; the message may well have gone through.
            _log(f"Twilio SMS status check failed: {e}")

    return True


# ═══════════════════════════════════════════════════════════════════════════════
# TWILIO VOICE CALL  (the loud, hands-off channel — the phone rings on its
# own ringtone, no notification or link to tap, and answering — a single
# button — auto-plays the alarm. This is the only channel that reaches a
# plain cellular phone with actual audio.)
# ═══════════════════════════════════════════════════════════════════════════════

def _build_alert_twiml(hostname: str, time_str: str, owner_name: str,
                        siren_url: str = "") -> str:
    """TwiML played the instant the call is answered. Optional siren_url
    (any public mp3/wav, e.g. a Twilio Asset you upload) plays first and
    loops, followed by a spoken alert repeated a few times so it's audible
    even if the phone is answered mid-ring or held away from the ear."""
    parts = ['<?xml version="1.0" encoding="UTF-8"?>', "<Response>"]
    if siren_url:
        parts.append(f'<Play loop="4">{siren_url}</Play>')
    msg = (
        f"Security alert. Security alert. {owner_name}, someone is trying "
        f"to unlock your system, {hostname}, right now, at {time_str}. "
        f"This is not a drill. Check your device immediately."
    )
    parts.append(f'<Say voice="Polly.Aditi" language="en-IN" loop="3">{msg}</Say>')
    parts.append("</Response>")
    return "".join(parts)


def _send_twilio_call(sid: str, token: str, from_num: str, to_num: str,
                       hostname: str, time_str: str, owner_name: str,
                       siren_url: str = "", max_attempts: int = 3) -> bool:
    """Place the alert as an outbound voice call, redialing (not just
    retrying the HTTP request) up to max_attempts times if it isn't
    answered — busy / no-answer / failed — since a missed first ring
    shouldn't mean a missed alert."""
    twiml = _build_alert_twiml(hostname, time_str, owner_name, siren_url)
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Calls.json"
    credentials = base64.b64encode(f"{sid}:{token}".encode()).decode()

    for attempt in range(1, max_attempts + 1):
        call_sid: Optional[str] = None
        try:
            payload = urllib.parse.urlencode({
                "To": to_num,
                "From": from_num,
                "Twiml": twiml,
            }).encode("utf-8")
            req = urllib.request.Request(
                url, data=payload,
                headers={
                    "Authorization": f"Basic {credentials}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read().decode())
                call_sid = result.get("sid")
        except Exception as e:
            _log(f"Twilio call attempt {attempt} request failed: {e}")

        if not call_sid:
            time.sleep(5)
            continue

        # Let the call ring, get answered, and play through before checking
        # its final status — Twilio needs the carrier's callback for this.
        time.sleep(25)
        try:
            status_url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Calls/{call_sid}.json"
            req = urllib.request.Request(
                status_url,
                headers={"Authorization": f"Basic {credentials}"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                final = json.loads(resp.read().decode())
                status = final.get("status")
                _log(f"Twilio call attempt {attempt} status: {status}")
                if status == "completed":
                    return True
                if status in ("no-answer", "busy", "failed", "canceled"):
                    if attempt < max_attempts:
                        _log(f"Call not answered ({status}) — redialing "
                             f"(attempt {attempt + 1}/{max_attempts})")
                        time.sleep(3)
                        continue
                    return False
        except Exception as e:
            _log(f"Twilio call status check failed: {e}")
            # Ambiguous status check — don't burn a redial on a status-check
            # hiccup when the call itself likely went through fine.
            return True

    return False


# ═══════════════════════════════════════════════════════════════════════════════
# FCM FULL-SCREEN ALARM  (free — replaces the paid Twilio Voice call as the
# loud, hands-off channel; see fcm_push.py / core/alert.html)
# ═══════════════════════════════════════════════════════════════════════════════

MOBILE_HTTP_PORT = 8080  # must match HTTP_PORT in mobile_server.py

def _get_local_ip() -> str:
    """Best-effort LAN IP — same approach as mobile_server.get_local_ip()."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return "127.0.0.1"


def _build_alert_url(hostname: str, time_str: str) -> str:
    """Public/LAN URL for the full-screen /alert siren page. Tries a
    running ngrok tunnel first (works off-network), falls back to the
    LAN IP (works if the phone shares WiFi with the PC)."""
    base_url = f"http://{_get_local_ip()}:{MOBILE_HTTP_PORT}"
    try:
        req = urllib.request.Request("http://127.0.0.1:4040/api/tunnels")
        with urllib.request.urlopen(req, timeout=2) as r:
            for t in json.loads(r.read().decode()).get("tunnels", []):
                if t.get("proto") == "https":
                    base_url = t["public_url"]
                    break
    except Exception:
        pass
    query = urllib.parse.urlencode({"machine": hostname, "time": time_str})
    return f"{base_url}/alert?{query}"


# ═══════════════════════════════════════════════════════════════════════════════
# EVENT LOG POLLING
# ═══════════════════════════════════════════════════════════════════════════════

NO_WINDOW = 0x08000000   # CREATE_NO_WINDOW — suppresses console flash

def _run_ps(cmd: str, timeout: int = 10) -> str:
    """Run a PowerShell command invisibly and return stdout."""
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout,
            creationflags=NO_WINDOW,
        )
        return result.stdout.strip()
    except Exception as e:
        _log(f"PowerShell error: {e}")
        return ""


def _run_wevtutil(args: list[str], timeout: int = 8) -> tuple[bool, str]:
    """Run wevtutil.exe invisibly. Returns (succeeded, stdout).

    succeeded=True + stdout=="" is a completely normal, common result: it
    means the query ran fine and simply found zero matching events. Only
    a nonzero return code / timeout / missing binary counts as failure.
    Native, in-process-fast (<100ms), works under SYSTEM with no special
    permissions — unlike PowerShell, which spins up a full runtime and
    reliably times out on this machine.
    """
    try:
        result = subprocess.run(
            ["wevtutil"] + args,
            capture_output=True, text=True, timeout=timeout,
            creationflags=NO_WINDOW,
        )
        if result.returncode != 0:
            _log(f"wevtutil returned code {result.returncode}: {result.stderr.strip()}")
            return False, ""
        return True, result.stdout
    except Exception as e:
        _log(f"wevtutil error: {e}")
        return False, ""


def _local_tag(tag: str) -> str:
    """Strip an XML namespace prefix like '{...}EventRecordID' down to 'EventRecordID'."""
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _parse_wevtutil_xml(out: str) -> list[tuple[int, datetime]]:
    """Parse wevtutil /f:xml output into (record_id, timestamp) tuples.

    /f:text output was found (via direct on-machine testing) to NOT include
    any 'Record Number' field at all on this Windows build — the previous
    text-based parser was silently matching zero events, every single time,
    with no error, which is exactly why alerts never fired despite correct
    detection of new Security-log events. XML output always contains a
    guaranteed <EventRecordID> field in the standard Windows Event schema,
    so this is parsed instead of guessing at human-readable text labels.
    """
    events: list[tuple[int, datetime]] = []
    if not out.strip():
        return events
    # wevtutil emits one or more sibling <Event>...</Event> XML docs with no
    # common root — wrap them so ElementTree can parse the whole batch.
    wrapped = f"<Events>{out}</Events>"
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError as e:
        _log(f"wevtutil XML parse error: {e}")
        return events

    for ev in root:
        if _local_tag(ev.tag) != "Event":
            continue
        record_id: Optional[int] = None
        time_created = datetime.now()
        for elem in ev.iter():
            tag = _local_tag(elem.tag)
            if tag == "EventRecordID" and elem.text:
                try:
                    record_id = int(elem.text.strip())
                except ValueError:
                    pass
            elif tag == "TimeCreated":
                sys_time = elem.get("SystemTime")
                if sys_time:
                    try:
                        # Windows Event Log SystemTime is ALWAYS UTC (the
                        # trailing 'Z' says so). Previously the 'Z' was
                        # stripped and the value parsed as a naive datetime,
                        # which silently treated UTC as if it were local
                        # time — off by exactly the local UTC offset (e.g.
                        # ~5.5h fast for IST). Parse it as UTC-aware, then
                        # convert to the machine's local timezone so the
                        # alert shows the time the person would actually
                        # read on their clock.
                        cleaned = sys_time.rstrip("Z")
                        if "." in cleaned:
                            head, frac = cleaned.split(".", 1)
                            cleaned = f"{head}.{frac[:6]}"  # datetime needs <=6 fractional digits
                        utc_dt = datetime.fromisoformat(cleaned).replace(tzinfo=timezone.utc)
                        time_created = utc_dt.astimezone()  # local tz, tz-aware
                    except Exception:
                        pass
        if record_id is not None:
            events.append((record_id, time_created))
    return events


def _get_latest_record_id() -> Optional[int]:
    # Native path: wevtutil, fast and reliable under SYSTEM.
    ok, out = _run_wevtutil(
        ["qe", "Security", "/q:*[System[EventID=4625]]", "/rd:true", "/c:1", "/f:xml"]
    )
    if ok:
        events = _parse_wevtutil_xml(out)
        if events:
            return events[0][0]
        # Query genuinely succeeded and found zero 4625 events ever logged.
        # That's a legitimate state (fresh install) — start baseline at 0.
        return 0

    # Fallback path: PowerShell (only reached if wevtutil itself failed).
    ps_out = _run_ps(
        "Get-WinEvent -LogName Security -MaxEvents 1 "
        "-FilterXPath '*[System[EventID=4625]]' "
        "-ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty RecordId",
        timeout=8,
    )
    return int(ps_out) if ps_out.isdigit() else None


def _query_events_after(baseline_id: int) -> list[tuple[int, datetime]]:
    query = f"*[System[EventID=4625 and EventRecordID>{baseline_id}]]"
    ok, out = _run_wevtutil(["qe", "Security", f"/q:{query}", "/rd:false", "/c:20", "/f:xml"])
    if ok:
        # Empty output here just means "no new failed logons since baseline"
        # — the normal case on every poll. Do NOT fall back to PowerShell.
        return sorted(_parse_wevtutil_xml(out), key=lambda e: e[0])

    # Fallback path: PowerShell (only reached if wevtutil itself failed to run).
    ps_out = _run_ps(
        f"Get-WinEvent -LogName Security -MaxEvents 20 "
        f"-FilterXPath '*[System[EventID=4625]]' "
        f"-ErrorAction SilentlyContinue "
        f"| Where-Object {{ $_.RecordId -gt {baseline_id} }} "
        f"| Select-Object RecordId, TimeCreated "
        f"| Sort-Object RecordId "
        f"| ForEach-Object {{ \"$($_.RecordId)|$($_.TimeCreated)\" }}"
    )
    ps_events = []
    for line in ps_out.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        parts = line.split("|", 1)
        if len(parts) != 2:
            continue
        try:
            record_id    = int(parts[0].strip())
            time_created = datetime.strptime(parts[1].strip(), "%m/%d/%Y %I:%M:%S %p")
        except ValueError:
            try:
                record_id    = int(parts[0].strip())
                time_created = datetime.now()
            except Exception:
                continue
        ps_events.append((record_id, time_created))
    return sorted(ps_events, key=lambda e: e[0])


# ═══════════════════════════════════════════════════════════════════════════════
# WATCHER CORE
# ═══════════════════════════════════════════════════════════════════════════════

POLL_INTERVAL  = 1.0
DEBOUNCE_SECS  = 15

# ── Auto-lockdown on repeated failed logons ─────────────────────────────
# Fires once N failed attempts land inside a rolling time window. Sends an
# escalated (louder, distinctly-tagged) alert on every configured channel,
# plays a local audible siren on the PC itself, then shuts the machine down
# after a short grace period (long enough for the alerts to actually reach
# the phone before power cuts, and to give a legitimate owner who mistyped
# their own password a last chance to notice and cancel it).
#
# All of this is configurable via config/api_keys.json:
#   "lockdown_enabled":            true
#   "lockdown_threshold":          3      (failed attempts to trigger)
#   "lockdown_window_secs":        600    (10 min rolling window)
#   "lockdown_shutdown_delay_secs":15     (grace period before power-off)
LOCKDOWN_THRESHOLD_DEFAULT        = 3
LOCKDOWN_WINDOW_SECS_DEFAULT      = 600
LOCKDOWN_SHUTDOWN_DELAY_DEFAULT   = 15


class IntruderWatcher:

    def __init__(self, stop_event: threading.Event):
        self._stop     = stop_event
        self._config   = _load_config()
        self._hostname = socket.gethostname()
        self._last_ts  = 0.0

        self._tg_token   = (self._config.get("telegram_bot_token")
                            or self._config.get("TELEGRAM_BOT_TOKEN"))
        self._tg_chat_id = str(self._config.get("telegram_chat_id")
                               or self._config.get("TELEGRAM_CHAT_ID") or "")
        self._tg_ok      = bool(self._tg_token and self._tg_chat_id)

        self._tw_sid   = self._config.get("twilio_account_sid") or ""
        self._tw_token = self._config.get("twilio_auth_token") or ""
        self._tw_from  = self._config.get("twilio_from_number") or ""
        self._tw_to    = self._config.get("twilio_to_number") or ""
        self._tw_ok    = all([self._tw_sid, self._tw_token, self._tw_from, self._tw_to])

        # SMS is OFF by default — Telegram + the FCM full-screen alarm cover
        # it. Set "twilio_sms_enabled": true in config to bring it back.
        self._sms_ok = self._tw_ok and bool(self._config.get("twilio_sms_enabled"))

        # Voice call reuses the same Twilio account/number — it's a third
        # channel, not a separate integration. Gated behind a config flag:
        # OFF by default since it requires a paid Twilio account (trial
        # accounts inject a mandatory "press any key" disclaimer that
        # defeats the whole point of a hands-off alert). Set
        # "twilio_voice_enabled": true in config once you've upgraded
        # Twilio if you want the call back as a belt-and-braces channel.
        self._tw_call_ok  = self._tw_ok and bool(self._config.get("twilio_voice_enabled"))
        self._siren_url   = self._config.get("twilio_siren_url") or ""
        self._owner_name  = _owner_display_name(self._hostname)

        # FCM full-screen alarm — the free, hands-off channel. Safe to
        # construct even if Firebase isn't set up yet; .configured just
        # comes back False and this channel is silently skipped.
        self._fcm = FCMPusher(log_fn=_log) if HAS_FCM else None
        self._fcm_ok = bool(self._fcm and self._fcm.configured)

        # Auto-lockdown (escalated alert + auto-shutdown) settings.
        self._lockdown_enabled = bool(self._config.get("lockdown_enabled", True))
        self._lockdown_threshold = int(
            self._config.get("lockdown_threshold", LOCKDOWN_THRESHOLD_DEFAULT))
        self._lockdown_window_secs = float(
            self._config.get("lockdown_window_secs", LOCKDOWN_WINDOW_SECS_DEFAULT))
        self._lockdown_shutdown_delay = int(
            self._config.get("lockdown_shutdown_delay_secs", LOCKDOWN_SHUTDOWN_DELAY_DEFAULT))
        self._fail_times: list = []   # rolling list of monotonic() timestamps

        _log(f"Telegram configured: {self._tg_ok}")
        _log(f"Twilio SMS enabled: {self._sms_ok}")
        _log(f"Twilio Voice call configured: {self._tw_call_ok}")
        _log(f"FCM full-screen alarm configured: {self._fcm_ok}")
        _log(f"Auto-lockdown: enabled={self._lockdown_enabled} "
             f"threshold={self._lockdown_threshold} "
             f"window={self._lockdown_window_secs:.0f}s "
             f"shutdown_delay={self._lockdown_shutdown_delay}s")

    def run(self):
        _log("Watcher thread starting...")
        last_alerted  = _load_state()
        latest        = _get_latest_record_id()
        state_existed = STATE_PATH.exists()

        if latest is None:
            _log("WARNING: Could not read Security log — check permissions")
            baseline = last_alerted
        elif not state_existed:
            # Fresh install, no prior state on disk — don't replay the
            # entire historical Security log (could be years of old
            # failed-logon events). Start counting from whatever's
            # already in the log right now.
            baseline = latest
            _log(f"First run — baseline RecordId={baseline} (not replaying full history)")
        elif last_alerted <= 0:
            # State file exists but came back empty/unreadable — same
            # safety net as a fresh install, don't replay full history.
            baseline = latest
            _log(f"State unreadable — baseline RecordId={baseline} (not replaying full history)")
        else:
            # Trust the persisted state. This is what makes cold-boot /
            # service-restart catch-up actually work: if a failed logon
            # happens in the gap between the machine booting and this
            # service finishing startup (or while the service was briefly
            # stopped for any reason), that event's RecordId is already
            # <= 'latest' by the time we get here — but it's still >
            # last_alerted, since we never fired an alert for it. Using
            # last_alerted directly (instead of max(latest, last_alerted),
            # which used to silently swallow exactly this case) is what
            # lets that event still be detected and alerted on the very
            # first poll below, instead of being treated as already-seen.
            baseline = last_alerted
            _log(f"Baseline RecordId={baseline} — resuming from last known alert (boot-gap catch-up enabled)")

        highest_seen = baseline

        while not self._stop.is_set():
            try:
                events = _query_events_after(highest_seen)
                if events:
                    for record_id, time_created in events:
                        if record_id > highest_seen:
                            highest_seen = record_id
                        _log(f"FAILED LOGON! RecordId={record_id} at {time_created}")
                        self._fire_alert(time_created)
                        self._track_and_check_lockdown(time_created)
                    _save_state(highest_seen)
            except Exception as e:
                _log(f"Poll error: {e}")
            self._stop.wait(POLL_INTERVAL)

        _log("Watcher thread stopped.")

    def _fire_alert(self, when: datetime):
        now = time.monotonic()
        if now - self._last_ts < DEBOUNCE_SECS:
            _log("Debounced")
            return
        self._last_ts = now

        time_str = when.strftime("%H:%M:%S")
        _log(f"Firing alert — host={self._hostname} time={time_str}")

        threads = []

        # Capture the photo exactly once, in its own thread, shared by both
        # Telegram and FCM below (each waits for it via photo_ready — SMS
        # and voice call don't need it and start immediately, unaffected).
        photo_result = {}
        photo_ready = threading.Event()

        def _capture_photo_once():
            photo_result["bytes"] = _capture_and_save_alert_photo()
            photo_ready.set()
        threading.Thread(target=_capture_photo_once, daemon=True).start()

        if self._tg_ok:
            def _fire_telegram():
                photo_ready.wait(timeout=8)
                photo = photo_result.get("bytes")
                ok = _send_telegram_alert(self._tg_token, self._tg_chat_id,
                                           self._hostname, time_str, photo=photo)
                _log(f"Telegram: {'OK' if ok else 'FAILED'}")
            t = threading.Thread(target=_fire_telegram, daemon=True)
            t.start(); threads.append(t)

        if self._sms_ok:
            t = threading.Thread(
                target=lambda: _log(
                    f"Twilio SMS: {'OK' if _send_twilio_sms(self._tw_sid, self._tw_token, self._tw_from, self._tw_to, self._hostname, time_str) else 'FAILED'}"
                ),
                daemon=True,
            )
            t.start(); threads.append(t)

        if self._tw_call_ok:
            t = threading.Thread(
                target=lambda: _log(
                    f"Twilio Voice call: {'OK' if _send_twilio_call(self._tw_sid, self._tw_token, self._tw_from, self._tw_to, self._hostname, time_str, self._owner_name, self._siren_url) else 'FAILED'}"
                ),
                daemon=True,
            )
            t.start(); threads.append(t)

        if self._fcm_ok:
            def _fire_fcm():
                alert_url = _build_alert_url(self._hostname, time_str)
                photo_ready.wait(timeout=8)
                photo_url = None
                if photo_result.get("bytes"):
                    # Same base URL/host resolution as the alert page itself
                    # (ngrok if available, else LAN IP) — the phone's
                    # notification tray fetches this directly to show the
                    # photo inline in the push notification, before you
                    # even tap it.
                    base = alert_url.split("/alert?")[0]
                    photo_url = f"{base}/alert/latest.jpg?t={int(time.time())}"
                ok = self._fcm.send_intruder_alert_fullscreen(
                    hostname=self._hostname, time_str=time_str, alert_url=alert_url,
                    photo_url=photo_url,
                )
                _log(f"FCM full-screen alarm: {'OK' if ok else 'FAILED'} -> {alert_url}"
                     + (f" (photo: {photo_url})" if photo_url else " (no photo)"))
            t = threading.Thread(target=_fire_fcm, daemon=True)
            t.start(); threads.append(t)

        if not threads:
            _log("No alert channels configured — alert not delivered")

    def _track_and_check_lockdown(self, when: datetime):
        """Counts failed attempts independently of the alert debounce above
        (a debounced/suppressed alert still counts as a real attempt for
        lockdown purposes). Once `self._lockdown_threshold` attempts land
        inside the rolling `self._lockdown_window_secs` window, triggers
        the escalated response."""
        if not self._lockdown_enabled:
            return
        now = time.monotonic()
        self._fail_times.append(now)
        # prune anything outside the rolling window
        cutoff = now - self._lockdown_window_secs
        self._fail_times = [t for t in self._fail_times if t >= cutoff]

        if len(self._fail_times) >= self._lockdown_threshold:
            count = len(self._fail_times)
            self._fail_times = []  # reset so this doesn't refire every subsequent attempt
            self._trigger_lockdown(when, count)

    def _trigger_lockdown(self, when: datetime, count: int):
        time_str = when.strftime("%H:%M:%S")
        delay = self._lockdown_shutdown_delay
        note = (f"{count} failed attempts within "
                f"{int(self._lockdown_window_secs)}s — AUTO-SHUTDOWN in {delay}s")
        _log(f"🚨 LOCKDOWN TRIGGERED — {note}")

        # 1) Escalated push notification — distinct tag/title so it shows
        #    as a separate, more urgent alert even if the per-attempt one
        #    is still on screen.
        if self._fcm_ok:
            def _fire_escalated_fcm():
                alert_url = _build_alert_url(self._hostname, time_str)
                photo_url = None
                if ALERT_PHOTO_PATH.exists():
                    base = alert_url.split("/alert?")[0]
                    photo_url = f"{base}/alert/latest.jpg?t={int(time.time())}"
                ok = self._fcm.send_intruder_alert_fullscreen(
                    hostname=self._hostname, time_str=time_str, alert_url=alert_url,
                    escalated=True, extra_note=note, photo_url=photo_url,
                )
                _log(f"FCM escalated alarm: {'OK' if ok else 'FAILED'}")
            threading.Thread(target=_fire_escalated_fcm, daemon=True).start()

        # 2) Escalated Telegram message, separate from the normal per-attempt one.
        if self._tg_ok:
            def _fire_escalated_telegram():
                ok = _send_telegram_lockdown_notice(
                    self._tg_token, self._tg_chat_id, self._hostname, time_str, note)
                _log(f"Telegram escalated notice: {'OK' if ok else 'FAILED'}")
            threading.Thread(target=_fire_escalated_telegram, daemon=True).start()

        # 3) Local audible siren — draws attention from anyone physically
        #    nearby, independent of whether the phone alerts are seen in time.
        threading.Thread(target=_play_local_siren, daemon=True).start()

        # 4) Delayed shutdown. Uses the built-in `shutdown` command (works
        #    regardless of which session/account this service runs under,
        #    unlike calling a GUI action directly). The delay gives the
        #    alerts above a real chance to land before power actually cuts,
        #    and gives a legitimate owner who mistyped their own password a
        #    last window to notice the warning message and cancel it with:
        #        shutdown /a
        try:
            subprocess.Popen([
                "shutdown", "/s", "/t", str(delay),
                "/c", f"JARVIS SECURITY: {note}. Run 'shutdown /a' to cancel.",
            ], creationflags=subprocess.CREATE_NO_WINDOW)
            _log(f"Shutdown scheduled in {delay}s (run 'shutdown /a' on this "
                 f"machine to cancel).")
        except Exception as e:
            _log(f"Failed to schedule shutdown: {e}")


def _send_telegram_lockdown_notice(token: str, chat_id: str, hostname: str,
                                    time_str: str, note: str) -> bool:
    """Separate, distinctly-worded Telegram message for the escalated
    lockdown event — sent in addition to (not instead of) the normal
    per-attempt alert."""
    text = (
        f"\U0001F6A8 <b>JARVIS LOCKDOWN TRIGGERED</b> \U0001F6A8\n"
        f"MACHINE: {hostname}\n"
        f"TIME: {time_str}\n"
        f"{note}"
    )
    payload = json.dumps({
        "chat_id": chat_id, "text": text, "parse_mode": "HTML",
    }).encode("utf-8")
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        req = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception as e:
        _log(f"Telegram lockdown notice error: {e}")
        return False


def _play_local_siren(duration_secs: float = 12.0):
    """Plays an audible alternating-tone siren through the PC's own
    speakers — useful independent of the phone (e.g. to startle/deter
    someone physically at the keyboard). Uses stdlib `winsound`, so no
    extra dependency. Silently no-ops on non-Windows or if audio is
    unavailable for any reason."""
    try:
        import winsound
    except Exception:
        _log("Local siren skipped — winsound unavailable")
        return
    try:
        end = time.monotonic() + duration_secs
        while time.monotonic() < end:
            winsound.Beep(1200, 250)
            winsound.Beep(800, 250)
    except Exception as e:
        _log(f"Local siren error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# WINDOWS SERVICE  (pywin32 — correct pattern using HandleCommandLine)
# ═══════════════════════════════════════════════════════════════════════════════

if HAS_WIN32:

    class JARVISWatcherService(win32serviceutil.ServiceFramework):
        _svc_name_         = "JARVISWatcherService"
        _svc_display_name_ = "JARVIS Intruder Watcher"
        _svc_description_  = (
            "Monitors Windows Security Event Log for failed logins and "
            "alerts your phone via Telegram, with SMS fallback. Part of JARVIS."
        )

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._h_stop      = win32event.CreateEvent(None, 0, 0, None)
            self._thread_stop = threading.Event()

        def SvcStop(self):
            _log("Service stop requested")
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._thread_stop.set()
            win32event.SetEvent(self._h_stop)

        def SvcDoRun(self):
            _log("=== Service SvcDoRun started ===")
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            watcher = IntruderWatcher(self._thread_stop)
            t = threading.Thread(target=watcher.run, daemon=True)
            t.start()
            win32event.WaitForSingleObject(self._h_stop, win32event.INFINITE)
            self._thread_stop.set()
            t.join(timeout=10)
            _log("=== Service stopped ===")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _require_admin():
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("\n❌  Must be run as Administrator.")
        print("   Right-click PowerShell → 'Run as Administrator'")
        sys.exit(1)


def cmd_install():
    _require_admin()
    print("\n🤖  Installing JARVIS Watcher Service...")
    print("=" * 50)

    # Use HandleCommandLine internally — this is the correct pywin32 pattern.
    # It registers PythonService.exe as the host (not python.exe directly),
    # which is what Windows Services using pywin32 require.
    sys.argv = [sys.argv[0], "--startup", "auto", "install"]
    win32serviceutil.HandleCommandLine(JARVISWatcherService)

    print()
    print("  ✅  Service registered — starts automatically on every boot")
    print()
    print("  Start it now (no reboot needed):")
    print("    python jarvis_watcher_service.py start")
    print(f"\n  Log file: {LOG_PATH}")


def cmd_start():
    _require_admin()
    print("\n🚀  Starting JARVIS Watcher Service...")
    sys.argv = [sys.argv[0], "start"]
    win32serviceutil.HandleCommandLine(JARVISWatcherService)
    print(f"  📋  Log: {LOG_PATH}")


def cmd_stop():
    _require_admin()
    print("\n⏹  Stopping JARVIS Watcher Service...")
    sys.argv = [sys.argv[0], "stop"]
    win32serviceutil.HandleCommandLine(JARVISWatcherService)


def cmd_remove():
    _require_admin()
    print("\n🗑️  Removing JARVIS Watcher Service...")
    sys.argv = [sys.argv[0], "remove"]
    win32serviceutil.HandleCommandLine(JARVISWatcherService)
    print("  ✅  Removed — will no longer start on boot")


def cmd_status():
    try:
        status    = win32serviceutil.QueryServiceStatus("JARVISWatcherService")
        state_map = {
            win32service.SERVICE_RUNNING:       "✅  RUNNING",
            win32service.SERVICE_STOPPED:       "⛔  STOPPED",
            win32service.SERVICE_START_PENDING: "⏳  STARTING",
            win32service.SERVICE_STOP_PENDING:  "⏳  STOPPING",
        }
        print(f"\n  Status: {state_map.get(status[1], f'Unknown ({status[1]})')}")
    except Exception as e:
        print(f"\n  ❌  Not installed or not found: {e}")

    print(f"  Log:    {LOG_PATH}")
    if LOG_PATH.exists():
        lines = LOG_PATH.read_text(encoding="utf-8").strip().splitlines()
        print("\n  Last 10 log lines:")
        for line in lines[-10:]:
            print(f"    {line}")
    else:
        print("  (no log file yet)")


def cmd_test():
    """Run the watcher inline for 60s — no install needed, for quick testing."""
    print("\n🧪  TEST MODE — running watcher inline for 60 seconds")
    print(f"  Log: {LOG_PATH}")
    print("  Trigger: Win+L → wrong password\n")
    stop = threading.Event()
    watcher = IntruderWatcher(stop)
    t = threading.Thread(target=watcher.run)
    t.start()
    try:
        time.sleep(60)
    except KeyboardInterrupt:
        print("\n  Stopped by Ctrl+C")
    finally:
        stop.set()
        t.join(timeout=5)
    print("  Test complete. Check log above.")


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

COMMANDS = {
    "install": cmd_install,
    "start":   cmd_start,
    "stop":    cmd_stop,
    "remove":  cmd_remove,
    "status":  cmd_status,
    "test":    cmd_test,
}

if __name__ == "__main__":
    if sys.platform != "win32":
        print("❌  Windows only.")
        sys.exit(1)

    if not HAS_WIN32:
        print("❌  pywin32 not installed. Run: pip install pywin32")
        sys.exit(1)

    if len(sys.argv) < 2:
        print(__doc__)
        print("Commands: install | start | stop | remove | status | test")
        sys.exit(0)

    cmd = sys.argv[1].lower()
    if cmd in COMMANDS:
        COMMANDS[cmd]()
    else:
        # Fall through to pywin32 framework for any other args
        win32serviceutil.HandleCommandLine(JARVISWatcherService)