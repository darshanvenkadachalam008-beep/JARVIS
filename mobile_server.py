"""
Phase 7 — JARVIS Mobile Companion Server
=========================================
Runs as a background thread inside jarvis_service.pyw.
Provides:
  • HTTP  on port 8080 — serves the mobile web app (index.html)
  • WS    on port 8081 — real-time log streaming + command relay to JARVIS

The mobile web app (served at http://<PC-IP>:8080) lets your phone:
  • See the JARVIS activity log live
  • Wake JARVIS remotely (tap button)
  • Send text commands to JARVIS
  • Receive push notifications from JARVIS

No external dependencies beyond what the project already has (websockets).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Callable, Optional, Set

# ── Logging ───────────────────────────────────────────────────────────────────
log = logging.getLogger("JARVISMobile")

# ── Ports ─────────────────────────────────────────────────────────────────────
HTTP_PORT = 8080
WS_PORT   = 8081

BASE_DIR = Path(__file__).resolve().parent
FIREBASE_WEB_CONFIG_PATH = BASE_DIR / "config" / "firebase_web_config.json"
API_KEYS_PATH            = BASE_DIR / "config" / "api_keys.json"


# ═══════════════════════════════════════════════════════════════════════════════
#  Auth token — required on every WS/HTTP command from now on
# ═══════════════════════════════════════════════════════════════════════════════

def _load_or_create_mobile_token() -> str:
    """
    Reads mobile_auth_token from config/api_keys.json, generating and
    persisting a new random one the first time this runs. Anyone who wants
    to control this JARVIS instance (WS commands, /command, /register-token)
    must now present this exact token.
    """
    cfg = {}
    try:
        if API_KEYS_PATH.exists():
            cfg = json.loads(API_KEYS_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning(f"Could not read api_keys.json: {e}")

    token = cfg.get("mobile_auth_token", "").strip() if isinstance(cfg, dict) else ""
    if token:
        return token

    token = secrets.token_urlsafe(24)
    cfg["mobile_auth_token"] = token
    try:
        API_KEYS_PATH.parent.mkdir(parents=True, exist_ok=True)
        API_KEYS_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        print(f"[Mobile] 🔐 Generated new mobile_auth_token and saved to {API_KEYS_PATH.name}")
        print(f"[Mobile] 🔐 Token: {token}")
        print(f"[Mobile] 🔐 Enter this once in the mobile app / your Shortcuts automation.")
    except Exception as e:
        log.warning(f"Could not persist mobile_auth_token: {e}")
    return token


MOBILE_AUTH_TOKEN = _load_or_create_mobile_token()


# ═══════════════════════════════════════════════════════════════════════════════
#  Sentinel Bridge — inbound webhook from FusionShield AI (fraud alerts)
# ═══════════════════════════════════════════════════════════════════════════════

def _load_sentinel_secret() -> str:
    """
    Reads sentinel_shared_secret from config/api_keys.json. This is a
    *different* secret from MOBILE_AUTH_TOKEN on purpose: MOBILE_AUTH_TOKEN
    authenticates the phone/you controlling JARVIS; sentinel_shared_secret
    authenticates a completely different caller (the FusionShield backend)
    hitting a completely different, narrower endpoint (/fraud-alert only).
    Returns "" if unset — in that case the /fraud-alert route stays
    permanently disabled rather than silently accepting unsigned webhooks.
    """
    try:
        if API_KEYS_PATH.exists():
            cfg = json.loads(API_KEYS_PATH.read_text(encoding="utf-8"))
            secret = cfg.get("sentinel_shared_secret", "").strip() if isinstance(cfg, dict) else ""
            if secret:
                return secret
    except Exception as e:
        log.warning(f"Could not read sentinel_shared_secret: {e}")
    print("[Sentinel] [!] sentinel_shared_secret not set in api_keys.json — "
          "/fraud-alert webhook is disabled until it's configured.")
    return ""


SENTINEL_SHARED_SECRET = _load_sentinel_secret()

# Keeps the most recent fraud alert so GET /fraud-alert (the page a push
# notification opens) can render it even after the triggering POST request
# has finished.
_LATEST_FRAUD_ALERT: dict = {}
_fraud_alert_lock = threading.Lock()


def _load_fusionshield_api_url() -> str:
    """Reads fusionshield_api_url from config/api_keys.json — the base URL
    JARVIS calls BACK into FusionShield on when a supervisor confirms an
    action (e.g. 'freeze this account'). Defaults to localhost:8000, which
    is right if both run on the same machine (the common hackathon setup)."""
    try:
        if API_KEYS_PATH.exists():
            cfg = json.loads(API_KEYS_PATH.read_text(encoding="utf-8"))
            url = (cfg.get("fusionshield_api_url", "") or "").strip() if isinstance(cfg, dict) else ""
            if url:
                return url.rstrip("/")
    except Exception as e:
        log.warning(f"Could not read fusionshield_api_url: {e}")
    return "http://127.0.0.1:8000/api/v1"


FUSIONSHIELD_API_URL = _load_fusionshield_api_url()

# ── Pending "should I freeze this account?" confirmations ───────────────────
# token -> {"case_id":..., "user_id":..., "expires": unix_ts}
_PENDING_ACTIONS: dict = {}
_pending_lock = threading.Lock()

_TG_POLL_STARTED = False
_TG_POLL_LOCK = threading.Lock()
_TG_UPDATE_OFFSET = 0

# Set by MobileServer.__init__ so the background dispatch thread below can
# reuse the SAME FCMPusher instance (already-loaded device token, already
# -initialised Firebase app) instead of constructing a new one per alert.
_SENTINEL_FCM_REF = None
_SENTINEL_TELEGRAM = None  # lazy singleton, created on first fraud alert


def _get_sentinel_telegram():
    global _SENTINEL_TELEGRAM
    if _SENTINEL_TELEGRAM is None:
        from core.telegram_alert import TelegramAlerter
        _SENTINEL_TELEGRAM = TelegramAlerter()
    return _SENTINEL_TELEGRAM


def _format_fraud_alert_message(alert: dict) -> str:
    reasons = alert.get("reasons") or []
    reason_str = "; ".join(reasons[:3]) if reasons else "elevated risk signals detected"
    score = alert.get("risk_score")
    score_str = f"{score:.1f}" if isinstance(score, (int, float)) else "unknown"
    return (
        f"🚨 <b>{alert.get('severity', 'UNKNOWN')} FRAUD ALERT</b>\n"
        f"Case: {alert.get('case_id')}\n"
        f"Transaction: {alert.get('transaction_id')} (account {alert.get('user_id')})\n"
        f"Risk score: {score_str}/100\n"
        f"Assigned to: {alert.get('assigned_to')}\n"
        f"Reasons: {reason_str}"
    )


def _format_fraud_alert_voice_line(alert: dict) -> str:
    """Short spoken line — deliberately shorter than the Telegram message
    and free of HTML markup, since this goes straight to edge-tts."""
    severity = alert.get("severity", "UNKNOWN")
    score = alert.get("risk_score")
    score_str = f"{score:.0f} percent" if isinstance(score, (int, float)) else "an elevated"
    case_id = alert.get("case_id", "unknown case")
    assigned = alert.get("assigned_to")
    tail = f" Assigned to {assigned}." if assigned and assigned != "unassigned" else " Currently unassigned."
    line = (
        f"Sir, {severity.lower()} fraud alert. Case {case_id}, risk score {score_str}."
        f"{tail}"
    )
    if severity == "CRITICAL":
        line += " Should I freeze this account? Reply on Telegram to confirm."
    return line


def _speak_fraud_alert(alert: dict):
    """Speaks the alert immediately using JARVIS's own edge-tts pipeline
    (main._speak_via_edge_tts) — imported lazily here since main.py does
    NOT import mobile_server (no circular import risk) but mobile_server
    importing main at module load time would still be fragile if load
    order ever changes, so the import stays inside this function."""
    try:
        from main import _speak_via_edge_tts
        line = _format_fraud_alert_voice_line(alert)
        _speak_via_edge_tts(line)  # already synchronous+self-contained; we're
                                    # already off the request thread here
    except Exception as e:
        log.warning(f"[Sentinel] Voice announcement failed: {e}")


def _load_telegram_creds():
    """Raw bot token + chat id, read directly (TelegramAlerter keeps these
    private) — needed here for getUpdates/answerCallbackQuery/inline
    keyboards, which TelegramAlerter doesn't expose."""
    try:
        if API_KEYS_PATH.exists():
            cfg = json.loads(API_KEYS_PATH.read_text(encoding="utf-8"))
            token = cfg.get("telegram_bot_token") or cfg.get("TELEGRAM_BOT_TOKEN")
            chat_id = cfg.get("telegram_chat_id") or cfg.get("TELEGRAM_CHAT_ID")
            return token, (str(chat_id) if chat_id else None)
    except Exception as e:
        log.warning(f"Could not read telegram creds: {e}")
    return None, None


_TG_TOKEN, _TG_CHAT_ID = _load_telegram_creds()
_TG_API = "https://api.telegram.org/bot{token}/{method}"

FREEZE_CONFIRM_WINDOW_SECONDS = 90


def _load_twilio_creds():
    """Reads the twilio_* keys from config/api_keys.json — same four keys
    jarvis_watcher_service.py already uses for the intruder-call/SMS
    alert. Reused here for the account-holder freeze notice so this
    doesn't need its own separate Twilio setup."""
    try:
        if API_KEYS_PATH.exists():
            cfg = json.loads(API_KEYS_PATH.read_text(encoding="utf-8"))
            if isinstance(cfg, dict):
                return (
                    cfg.get("twilio_account_sid") or "",
                    cfg.get("twilio_auth_token") or "",
                    cfg.get("twilio_from_number") or "",
                    cfg.get("twilio_to_number") or "",
                )
    except Exception as e:
        log.warning(f"Could not read twilio creds: {e}")
    return "", "", "", ""


_TW_SID, _TW_TOKEN, _TW_FROM, _TW_TO = _load_twilio_creds()


def _notify_account_holder(case_id: str, user_id: str):
    """Fires the moment a freeze is confirmed successful — the account
    holder facing message, distinct from every other alert in this file
    (those all go to Shan/the supervisor). In production this would be
    routed to whatever contact number is on file for `user_id`; for this
    prototype/demo build there's no real customer directory, so it's
    sent to the single number configured as twilio_to_number in
    config/api_keys.json (defaults to the hackathon demo phone). Never
    raises - a failed customer SMS must not affect the freeze itself,
    which has already succeeded by the time this is called."""
    body = (
        "FusionShield AI Security Notice: Your account has been "
        f"temporarily blocked due to suspicious activity (case {case_id}). "
        "If this wasn't you, no action is needed - it's already secured. "
        "If you believe this is a mistake, contact support to restore access."
    )
    try:
        from core.sentinel_extras import send_twilio_sms
        ok = send_twilio_sms(_TW_SID, _TW_TOKEN, _TW_FROM, _TW_TO, body)
        if ok:
            log.info(f"[Sentinel] Account-holder SMS sent to {_TW_TO} for case {case_id}")
        else:
            log.warning(f"[Sentinel] Account-holder SMS not sent (Twilio not configured or failed) for case {case_id}")
        try:
            from core.sentinel_extras import AlertHistory
            AlertHistory.record(
                "account_holder_notice",
                f"Freeze notice sent for case {case_id}",
                f"user={user_id} to={_TW_TO} sms_ok={ok}",
            )
        except Exception:
            pass
    except Exception as e:
        log.warning(f"[Sentinel] Account-holder notification error: {e}")


def _send_freeze_confirmation_request(alert: dict):
    """Sends a Telegram message with 'Freeze Account' / 'Ignore' buttons
    for a CRITICAL alert, and makes sure the polling loop that watches for
    the tap is running."""
    if not (_TG_TOKEN and _TG_CHAT_ID):
        log.info("[Sentinel] Telegram not configured — skipping freeze-confirmation buttons")
        return

    token = secrets.token_urlsafe(8)
    with _pending_lock:
        _PENDING_ACTIONS[token] = {
            "case_id": alert.get("case_id"),
            "user_id": alert.get("user_id"),
            "expires": time.time() + FREEZE_CONFIRM_WINDOW_SECONDS,
        }

    text = (
        f"⚠️ Freeze account {alert.get('user_id')} for case {alert.get('case_id')}? "
        f"This request expires in {FREEZE_CONFIRM_WINDOW_SECONDS}s."
    )
    keyboard = {
        "inline_keyboard": [[
            {"text": "🔒 Freeze Account", "callback_data": f"freeze:{token}"},
            {"text": "Ignore", "callback_data": f"ignore:{token}"},
        ]]
    }
    body = json.dumps({"chat_id": _TG_CHAT_ID, "text": text, "reply_markup": keyboard}).encode("utf-8")
    req = urllib.request.Request(
        _TG_API.format(token=_TG_TOKEN, method="sendMessage"),
        data=body, headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        log.warning(f"[Sentinel] Failed to send freeze-confirmation buttons: {e}")
        return

    _ensure_telegram_poll_thread()


def _ensure_telegram_poll_thread():
    global _TG_POLL_STARTED
    with _TG_POLL_LOCK:
        if _TG_POLL_STARTED:
            return
        _TG_POLL_STARTED = True
    threading.Thread(target=_telegram_poll_loop, name="SentinelTelegramPoll", daemon=True).start()


def _answer_callback(callback_query_id: str, text: str):
    if not (_TG_TOKEN and callback_query_id):
        return
    body = json.dumps({"callback_query_id": callback_query_id, "text": text}).encode("utf-8")
    req = urllib.request.Request(
        _TG_API.format(token=_TG_TOKEN, method="answerCallbackQuery"),
        data=body, headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        log.warning(f"[Sentinel] answerCallbackQuery failed: {e}")


def _execute_freeze(pending: dict):
    """The actual callback into FusionShield once a human has confirmed.
    Signed the same way as the outbound FusionShield->JARVIS webhook, just
    reversed — same shared secret, same HMAC-SHA256-over-raw-body scheme."""
    case_id = pending.get("case_id")
    user_id = pending.get("user_id")
    payload = {"case_id": case_id, "user_id": user_id, "action": "freeze", "actor": "jarvis-sentinel"}
    body = json.dumps(payload).encode("utf-8")

    ok = False
    if SENTINEL_SHARED_SECRET:
        sig = hmac.new(SENTINEL_SHARED_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()
        req = urllib.request.Request(
            f"{FUSIONSHIELD_API_URL}/sentinel/action",
            data=body, method="POST",
            headers={"Content-Type": "application/json", "X-Sentinel-Signature": sig},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                ok = bool(result.get("ok"))
        except Exception as e:
            log.warning(f"[Sentinel] Freeze callback to FusionShield failed: {e}")
    else:
        log.warning("[Sentinel] Cannot execute freeze — sentinel_shared_secret not configured")

    if ok:
        # Customer-facing notice, separate from every other alert in this
        # file (those all go to Shan/the supervisor). Fire-and-forget on
        # its own thread so a slow/failed SMS never delays the voice
        # confirmation below.
        threading.Thread(
            target=_notify_account_holder,
            args=(case_id, user_id),
            name="AccountHolderNotify",
            daemon=True,
        ).start()

    try:
        from main import _speak_via_edge_tts
        if ok:
            _speak_via_edge_tts(
                f"Account frozen for case {case_id}. The account holder has been notified by SMS."
            )
        else:
            _speak_via_edge_tts("Freeze request failed. Please check the case manually.")
    except Exception as e:
        log.warning(f"[Sentinel] Freeze-result voice line failed: {e}")

    print(f"[Sentinel] 🔒 Freeze action for case {case_id}: {'success' if ok else 'FAILED'}")


def _telegram_poll_loop():
    """Long-polls Telegram getUpdates, watching for a tap on one of the
    freeze-confirmation buttons. Idles (cheap 2s sleep, no network call)
    whenever nothing is pending, so this costs nothing between alerts."""
    global _TG_UPDATE_OFFSET
    while True:
        with _pending_lock:
            now = time.time()
            for t in [t for t, v in _PENDING_ACTIONS.items() if v["expires"] < now]:
                _PENDING_ACTIONS.pop(t, None)
            has_pending = bool(_PENDING_ACTIONS)

        if not has_pending:
            time.sleep(2)
            continue

        try:
            params = urllib.parse.urlencode({
                "timeout": 5,
                "offset": _TG_UPDATE_OFFSET + 1,
                "allowed_updates": json.dumps(["callback_query"]),
            })
            url = _TG_API.format(token=_TG_TOKEN, method="getUpdates") + "?" + params
            with urllib.request.urlopen(url, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            log.warning(f"[Sentinel] Telegram poll error: {e}")
            time.sleep(2)
            continue

        for update in data.get("result", []):
            _TG_UPDATE_OFFSET = max(_TG_UPDATE_OFFSET, update.get("update_id", _TG_UPDATE_OFFSET))
            cq = update.get("callback_query")
            if not cq:
                continue
            cq_id = cq.get("id")
            action, _, token = (cq.get("data") or "").partition(":")
            with _pending_lock:
                pending = _PENDING_ACTIONS.pop(token, None)
            if pending is None:
                _answer_callback(cq_id, "Expired or unknown request.")
                continue
            if action == "freeze":
                _answer_callback(cq_id, "Freezing account…")
                _execute_freeze(pending)
            else:
                _answer_callback(cq_id, "No action taken.")
                try:
                    from main import _speak_via_edge_tts
                    _speak_via_edge_tts("Understood. No action taken.")
                except Exception:
                    pass


def _dispatch_fraud_alert_async(alert: dict):
    """
    Runs on its own daemon thread — see _HTTPHandler._handle_fraud_alert
    for why. Telegram and FCM are each wrapped separately so one being
    slow/broken never blocks or cancels the other.
    """
    message = _format_fraud_alert_message(alert)

    # Voice goes first — it's the "JARVIS interrupts you" moment, and it
    # should start before the (usually slower) Telegram/FCM network calls.
    _speak_fraud_alert(alert)

    try:
        telegram = _get_sentinel_telegram()
        if telegram.configured:
            telegram.send_message(message)
        else:
            log.info("[Sentinel] Telegram not configured — skipping Telegram leg of fraud alert")
    except Exception as e:
        log.warning(f"[Sentinel] Telegram dispatch failed: {e}")

    try:
        if _SENTINEL_FCM_REF is not None:
            plain = message.replace("<b>", "").replace("</b>", "")
            _SENTINEL_FCM_REF.send(
                f"{alert.get('severity', 'UNKNOWN')} Fraud Alert — {alert.get('case_id')}",
                plain,
            )
    except Exception as e:
        log.warning(f"[Sentinel] FCM dispatch failed: {e}")

    if alert.get("severity") == "CRITICAL":
        try:
            _send_freeze_confirmation_request(alert)
        except Exception as e:
            log.warning(f"[Sentinel] Freeze-confirmation request failed: {e}")

    print(f"[Sentinel] 🚨 Fraud alert dispatched (Telegram + FCM) for case {alert.get('case_id')}")

# ── Simple per-IP throttle for bad auth attempts ─────────────────────────────
_FAILED_AUTH: dict = {}       # ip -> [timestamps of failed attempts]
_BLOCK_UNTIL: dict = {}       # ip -> unix time until which ip is blocked
_FAIL_WINDOW_SEC   = 60
_FAIL_LIMIT        = 5
_BLOCK_SEC         = 300


def _ip_is_blocked(ip: str) -> bool:
    until = _BLOCK_UNTIL.get(ip)
    return bool(until and time.time() < until)


# Set once the real _WSHub is constructed (MobileServer creates exactly one).
# Lets module-level auth helpers push live security events to connected phones.
_ACTIVE_HUB = None


def _broadcast_conn_event(kind: str, ip: str, detail: str = ""):
    """kind: 'auth_ok' | 'auth_fail' | 'blocked' | 'unauthed'"""
    if _ACTIVE_HUB is None:
        return
    payload = json.dumps({
        "kind": kind, "ip": ip, "detail": detail, "ts": time.strftime("%H:%M:%S"),
    })
    try:
        _ACTIVE_HUB.broadcast("conn_log", payload)
    except Exception:
        pass


def _record_failed_auth(ip: str, detail: str = "bad token"):
    now = time.time()
    attempts = [t for t in _FAILED_AUTH.get(ip, []) if now - t < _FAIL_WINDOW_SEC]
    attempts.append(now)
    _FAILED_AUTH[ip] = attempts
    _broadcast_conn_event("auth_fail", ip, detail)
    if len(attempts) >= _FAIL_LIMIT:
        _BLOCK_UNTIL[ip] = now + _BLOCK_SEC
        print(f"[Mobile] 🚫 Blocking {ip} for {_BLOCK_SEC}s after {len(attempts)} failed auth attempts")
        _broadcast_conn_event("blocked", ip, f"{_BLOCK_SEC}s block")


def _load_firebase_web_config() -> Optional[dict]:
    """
    Loads the Firebase *web app* config (different from the service
    account JSON used server-side in fcm_push.py — this one is public-safe,
    it's the same config object Firebase has you paste into any web page).
    Returns None if not configured yet; the mobile page then simply skips
    FCM registration and falls back to local-WiFi-only WebSocket alerts.
    """
    try:
        if FIREBASE_WEB_CONFIG_PATH.exists():
            return json.loads(FIREBASE_WEB_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning(f"Could not read firebase_web_config.json: {e}")
    return None


# ── Get local IP so we can print the QR-friendly URL ─────────────────────────
def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


# ═══════════════════════════════════════════════════════════════════════════════
#  WebSocket hub — broadcasts log lines, receives commands
# ═══════════════════════════════════════════════════════════════════════════════

class _WSHub:
    """Manages all connected mobile clients."""

    def __init__(self):
        self._clients:  Set  = set()
        self._loop:     Optional[asyncio.AbstractEventLoop] = None
        self._on_cmd:   Optional[Callable[[str], None]]     = None  # callback → JARVIS
        self._on_wake:  Optional[Callable[[], None]]        = None  # callback → wake JARVIS
        self._on_token: Optional[Callable[[str], None]]     = None  # callback → save FCM token
        self._on_intercom_start: Optional[Callable[[str], None]] = None  # callback(ip) → start mic/speaker
        self._on_intercom_stop:  Optional[Callable[[str], None]] = None  # callback(ip) → stop mic/speaker
        self._on_intercom_audio: Optional[Callable[[bytes], None]] = None  # callback(pcm_bytes) → play on PC
        self._on_incoming_call:  Optional[Callable[[dict], None]]  = None  # callback(call_info) → speak / announce
        self._on_incoming_sms:   Optional[Callable[[dict], None]]  = None  # callback(sms_info) → speak / announce
        self._intercom_clients: Set = set()  # subset of self._clients currently in an intercom session
        global _ACTIVE_HUB
        _ACTIVE_HUB = self

    def set_callbacks(self, on_command: Callable, on_wake: Callable, on_token_register: Optional[Callable] = None,
                       on_intercom_start: Optional[Callable] = None, on_intercom_stop: Optional[Callable] = None,
                       on_intercom_audio: Optional[Callable] = None, on_incoming_call: Optional[Callable] = None,
                       on_incoming_sms: Optional[Callable] = None):
        self._on_cmd   = on_command
        self._on_wake  = on_wake
        self._on_token = on_token_register
        self._on_intercom_start = on_intercom_start
        self._on_intercom_stop  = on_intercom_stop
        self._on_intercom_audio = on_intercom_audio
        self._on_incoming_call  = on_incoming_call
        self._on_incoming_sms   = on_incoming_sms

    def send_sms(self, recipient: str, body: str):
        """Dispatches a send_sms command to connected mobile companion client."""
        payload = json.dumps({"recipient": recipient, "body": body})
        self.broadcast("send_sms", payload)

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    # ── called from any thread (UI, JARVIS session) ───────────────────────────
    def broadcast(self, msg_type: str, payload: str):
        """Thread-safe broadcast to all connected mobile clients."""
        if not self._clients or not self._loop:
            return
        data = json.dumps({"type": msg_type, "data": payload})
        asyncio.run_coroutine_threadsafe(self._async_broadcast(data), self._loop)

    async def _async_broadcast(self, data: str):
        dead = set()
        for ws in list(self._clients):
            try:
                await ws.send(data)
            except Exception:
                dead.add(ws)
        self._clients -= dead

    # ── Intercom audio (binary frames) ─────────────────────────────────────
    def broadcast_audio(self, pcm_bytes: bytes):
        """Thread-safe: pushes a raw PCM chunk (PC mic) to every client
        currently in an active intercom session. Called from the audio
        capture thread, which is NOT the asyncio event loop thread."""
        if not self._intercom_clients or not self._loop:
            return
        asyncio.run_coroutine_threadsafe(
            self._async_broadcast_audio(pcm_bytes), self._loop)

    async def _async_broadcast_audio(self, pcm_bytes: bytes):
        dead = set()
        for ws in list(self._intercom_clients):
            try:
                await ws.send(pcm_bytes)
            except Exception:
                dead.add(ws)
        self._intercom_clients -= dead

    # ── WebSocket handler ─────────────────────────────────────────────────────
    async def handler(self, websocket):
        ip = websocket.remote_address[0] if websocket.remote_address else "?"

        if _ip_is_blocked(ip):
            print(f"[Mobile] 🚫 Rejected connection from blocked IP: {ip}")
            await websocket.close(code=4403, reason="blocked")
            return

        self._clients.add(websocket)
        print(f"[Mobile] 📱 Client connected: {ip}  (total: {len(self._clients)})")
        _broadcast_conn_event("connected", ip, f"{len(self._clients)} online")
        # Send welcome — but do NOT allow any privileged action until auth'd
        await websocket.send(json.dumps({
            "type": "sys",
            "data": "JARVIS Mobile connected. Send auth token to continue."
        }))
        authed = False
        try:
            async for raw in websocket:
                # Binary frames are raw PCM audio chunks from the phone's
                # mic during an active intercom session — never JSON, so
                # check this before attempting json.loads.
                if isinstance(raw, (bytes, bytearray)):
                    if authed and websocket in self._intercom_clients and self._on_intercom_audio:
                        try:
                            self._on_intercom_audio(bytes(raw))
                        except Exception as e:
                            print(f"[Mobile] ⚠️ intercom audio handler error: {e}")
                    continue

                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                kind = msg.get("type", "")

                if kind == "auth":
                    token = str(msg.get("data", "")).strip()
                    if token and secrets.compare_digest(token, MOBILE_AUTH_TOKEN):
                        authed = True
                        await websocket.send(json.dumps({
                            "type": "sys", "data": "JARVIS Mobile connected. Ready, sir."
                        }))
                        print(f"[Mobile] 🔓 {ip} authenticated")
                        _broadcast_conn_event("auth_ok", ip)
                    else:
                        _record_failed_auth(ip)
                        print(f"[Mobile] ⛔ Bad auth token from {ip}")
                        await websocket.send(json.dumps({
                            "type": "sys", "data": "Auth failed."
                        }))
                        if _ip_is_blocked(ip):
                            await websocket.close(code=4403, reason="blocked")
                            break
                    continue

                if kind == "ping":
                    await websocket.send(json.dumps({"type": "pong", "data": ""}))
                    continue

                if not authed:
                    # Refuse every privileged action until the client authenticates.
                    _record_failed_auth(ip)
                    print(f"[Mobile] ⛔ Unauthenticated {kind!r} attempt from {ip}")
                    await websocket.send(json.dumps({
                        "type": "sys", "data": "Not authenticated."
                    }))
                    if _ip_is_blocked(ip):
                        await websocket.close(code=4403, reason="blocked")
                        break
                    continue

                if kind == "wake":
                    print(f"[Mobile] 📱 Remote wake triggered (from {ip})")
                    if self._on_wake:
                        self._on_wake()
                elif kind == "command":
                    text = msg.get("data", "").strip()
                    if text and self._on_cmd:
                        print(f"[Mobile] 📱 Remote command from {ip}: {text!r}")
                        self._on_cmd(text)
                elif kind == "register_token":
                    token = msg.get("data", "").strip()
                    if token and self._on_token:
                        print(f"[Mobile] 📱 FCM token registered ({token[:12]}...)")
                        self._on_token(token)
                        await websocket.send(json.dumps({
                            "type": "sys",
                            "data": "Registered for push notifications. Alerts will now reach you on any network."
                        }))
                elif kind == "intercom_start":
                    print(f"[Mobile] 🎙️ Intercom started by {ip}")
                    self._intercom_clients.add(websocket)
                    if self._on_intercom_start:
                        try:
                            self._on_intercom_start(ip)
                        except Exception as e:
                            print(f"[Mobile] ⚠️ intercom start handler error: {e}")
                    await websocket.send(json.dumps({
                        "type": "intercom_status", "data": "started"
                    }))
                elif kind == "intercom_stop":
                    print(f"[Mobile] 🎙️ Intercom stopped by {ip}")
                    self._intercom_clients.discard(websocket)
                    if self._on_intercom_stop:
                        try:
                            self._on_intercom_stop(ip)
                        except Exception as e:
                            print(f"[Mobile] ⚠️ intercom stop handler error: {e}")
                    await websocket.send(json.dumps({
                        "type": "intercom_status", "data": "stopped"
                    }))
                elif kind == "incoming_call":
                    raw_data = msg.get("data", "")
                    call_info = {}
                    if isinstance(raw_data, str) and raw_data.strip():
                        try:
                            call_info = json.loads(raw_data)
                        except Exception:
                            call_info = {"number": raw_data, "name": ""}
                    elif isinstance(raw_data, dict):
                        call_info = raw_data
                    
                    number = call_info.get("number", "Unknown")
                    name = call_info.get("name", "")
                    caller_str = f"{name} ({number})" if name else number
                    print(f"[Mobile] 📞 Incoming call: {caller_str} (from {ip})")
                    if self._on_incoming_call:
                        try:
                            self._on_incoming_call(call_info)
                        except Exception as e:
                            print(f"[Mobile] ⚠️ incoming call handler error: {e}")
                elif kind == "incoming_sms":
                    raw_data = msg.get("data", "")
                    sms_info = {}
                    if isinstance(raw_data, str) and raw_data.strip():
                        try:
                            sms_info = json.loads(raw_data)
                        except Exception:
                            sms_info = {"sender": "Unknown", "body": raw_data}
                    elif isinstance(raw_data, dict):
                        sms_info = raw_data

                    sender = sms_info.get("sender", "Unknown")
                    body = sms_info.get("body", "")
                    # Privacy: redact SMS body in console logs — log sender and length only
                    print(f"[Mobile] 💬 Incoming SMS from {sender} ({len(body)} chars, from {ip})")
                    if self._on_incoming_sms:
                        try:
                            self._on_incoming_sms(sms_info)
                        except Exception as e:
                            print(f"[Mobile] ⚠️ incoming SMS handler error: {e}")
                elif kind == "wipe_request":
                    try:
                        from core.sentinel_extras import EmergencyWipeController
                        controller = EmergencyWipeController.get_instance()
                        ok, reply_msg = controller.request_wipe(channel="mobile_ws")
                        await websocket.send(json.dumps({
                            "type": "wipe_response", "ok": ok, "message": reply_msg, "expires_in": 60
                        }))
                    except Exception as e:
                        await websocket.send(json.dumps({
                            "type": "wipe_response", "ok": False, "message": str(e)
                        }))
                elif kind == "wipe_confirm":
                    try:
                        pin = str(msg.get("pin") or msg.get("data") or "").strip()
                        from core.sentinel_extras import EmergencyWipeController
                        controller = EmergencyWipeController.get_instance()
                        ok, reply_msg, results = controller.confirm_wipe(pin, channel="mobile_ws")
                        await websocket.send(json.dumps({
                            "type": "wipe_response", "ok": ok, "message": reply_msg, "results": results
                        }))
                    except Exception as e:
                        await websocket.send(json.dumps({
                            "type": "wipe_response", "ok": False, "message": str(e)
                        }))
        except Exception:
            pass
        finally:
            self._clients.discard(websocket)
            was_in_intercom = websocket in self._intercom_clients
            self._intercom_clients.discard(websocket)
            if was_in_intercom and self._on_intercom_stop:
                # Client vanished (closed tab, lost signal, etc.) mid-session
                # — make sure the PC's mic/speaker actually get released
                # rather than left running with nobody listening.
                try:
                    self._on_intercom_stop(ip)
                except Exception:
                    pass
            print(f"[Mobile] 📱 Client disconnected (remaining: {len(self._clients)})")

    async def serve(self):
        try:
            import websockets as _ws
            self._loop = asyncio.get_running_loop()
            print(f"[Mobile] 🔌 WebSocket server on ws://0.0.0.0:{WS_PORT}")
            async with _ws.serve(self.handler, "0.0.0.0", WS_PORT):
                await asyncio.Future()   # run forever
        except Exception as e:
            print(f"[Mobile] ❌ WebSocket server error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
#  HTTP server — serves the mobile web app HTML
# ═══════════════════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════════════════
#  MJPEG Screen Streaming
# ═══════════════════════════════════════════════════════════════════════════════

import threading as _threading
import time as _time
import base64 as _base64

_stream_frame: bytes = b""
_stream_clients: list = []
_stream_lock = _threading.Lock()

def _stream_capture_loop():
    """Background thread: captures screen every 150ms for live stream."""
    global _stream_frame
    while True:
        try:
            from actions.screen_processor import _capture_screenshot, _PIL_OK
            frame = _capture_screenshot()
            with _stream_lock:
                _stream_frame = frame
        except Exception:
            pass
        _time.sleep(0.15)

_stream_thread_started = False
def _ensure_stream_thread():
    global _stream_thread_started
    if not _stream_thread_started:
        t = _threading.Thread(target=_stream_capture_loop, daemon=True, name="ScreenStreamCapture")
        t.start()
        _stream_thread_started = True


# ═══════════════════════════════════════════════════════════════════════════════
#  HTML served to mobile
# ═══════════════════════════════════════════════════════════════════════════════

def _get_html(pc_ip: str, firebase_config=None) -> bytes:
    fcm_config_json = json.dumps(firebase_config) if firebase_config else "null"
    firebase_sdk_tags = (
        '<script src="https://www.gstatic.com/firebasejs/10.13.0/firebase-app-compat.js"></script>\n'
        '<script src="https://www.gstatic.com/firebasejs/10.13.0/firebase-messaging-compat.js"></script>'
        if firebase_config else
        '<!-- FCM not configured -->'
    )
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<title>J.A.R.V.I.S — Mark XXXIX</title>
<style>
:root{{
  --gold:#C9A84C;--cyan:#00D4FF;--bg:#050A0F;--panel:#0A1520;
  --border:#1A3040;--text:#B0C8D8;--dim:#4A6070;
  --red:#FF4444;--green:#44FF88;--blue:#4499FF;--orange:#FF8844;
}}
*{{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}}
body{{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;
  height:100dvh;display:flex;flex-direction:column;overflow:hidden}}

/* ── header ── */
header{{background:var(--panel);border-bottom:1px solid var(--gold);
  padding:10px 14px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0}}
.logo{{font-size:17px;font-weight:700;letter-spacing:4px;color:var(--gold)}}
.status-dot{{width:9px;height:9px;border-radius:50%;background:var(--red);
  box-shadow:0 0 7px var(--red);transition:all .3s}}
.status-dot.on{{background:var(--green);box-shadow:0 0 7px var(--green)}}

/* ── tabs ── */
.tabs{{display:flex;background:var(--panel);border-bottom:1px solid var(--border);flex-shrink:0}}
.tab{{flex:1;padding:9px 4px;text-align:center;font-size:10px;letter-spacing:2px;
  color:var(--dim);cursor:pointer;border-bottom:2px solid transparent;transition:all .2s}}
.tab.active{{color:var(--cyan);border-bottom-color:var(--cyan)}}

/* ── panels ── */
.panel{{display:none;flex:1;flex-direction:column;overflow:hidden}}
.panel.active{{display:flex}}

/* ── log ── */
#log{{flex:1;overflow-y:auto;padding:10px 12px;display:flex;flex-direction:column;
  gap:3px;-webkit-overflow-scrolling:touch}}
.ln{{font-size:12px;line-height:1.5;padding:4px 8px;border-radius:4px;
  border-left:2px solid var(--border);word-break:break-word}}
.ln.j{{color:var(--cyan);border-color:var(--cyan);background:rgba(0,212,255,.04)}}
.ln.y{{color:var(--gold);border-color:var(--gold);background:rgba(201,168,76,.04)}}
.ln.s{{color:var(--dim);border-color:var(--border)}}
.ln.n{{color:var(--green);border-color:var(--green)}}
.ln.a{{color:var(--red);border-color:var(--red);background:rgba(255,68,68,.07)}}
.alert-img{{display:block;width:100%;max-width:260px;margin-top:6px;
  border-radius:6px;border:1px solid var(--red)}}

/* ── cmd bar ── */
.cmd-bar{{display:flex;gap:6px;padding:8px 12px 12px;flex-shrink:0}}
#cmd{{flex:1;background:var(--panel);border:1px solid var(--border);border-radius:8px;
  color:var(--text);font-family:'Courier New',monospace;font-size:13px;
  padding:9px 11px;outline:none;transition:border-color .2s}}
#cmd:focus{{border-color:var(--cyan)}}
#cmd::placeholder{{color:var(--dim)}}
.send-btn{{background:var(--panel);border:1px solid var(--cyan);border-radius:8px;
  color:var(--cyan);font-family:'Courier New',monospace;font-size:12px;font-weight:700;
  padding:9px 13px;cursor:pointer;white-space:nowrap;transition:all .15s}}
.send-btn:active{{background:rgba(0,212,255,.12);transform:scale(.96)}}

/* ── wake btn ── */
#wake-btn{{margin:8px 12px 4px;padding:14px;background:linear-gradient(135deg,#0A2030,#0D2840);
  border:1px solid var(--gold);border-radius:10px;color:var(--gold);
  font-family:'Courier New',monospace;font-size:14px;font-weight:700;letter-spacing:3px;
  text-align:center;cursor:pointer;transition:all .15s;flex-shrink:0;
  box-shadow:0 0 18px rgba(201,168,76,.1)}}
#wake-btn:active{{background:linear-gradient(135deg,#1A3040,#1D3A50);
  box-shadow:0 0 30px rgba(201,168,76,.3);transform:scale(.98)}}
@keyframes wake-pulse{{0%,100%{{box-shadow:0 0 18px rgba(201,168,76,.1)}}
  50%{{box-shadow:0 0 40px rgba(201,168,76,.5)}}}}
#wake-btn.pulsing{{animation:wake-pulse 1s ease-in-out}}

/* ── state badge ── */
#state-badge{{text-align:center;font-size:9px;letter-spacing:3px;
  color:var(--dim);padding:2px 0 4px;flex-shrink:0}}

/* ── screen stream ── */
#stream-wrap{{flex:1;display:flex;flex-direction:column;align-items:center;
  justify-content:flex-start;overflow:hidden;padding:8px}}
#stream-img{{width:100%;max-height:55vw;object-fit:contain;border-radius:8px;
  border:1px solid var(--border);background:#000}}
#stream-status{{font-size:10px;color:var(--dim);margin-top:6px;letter-spacing:2px}}
.stream-controls{{display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;justify-content:center}}
.ctrl-btn{{background:var(--panel);border:1px solid var(--border);border-radius:8px;
  color:var(--text);font-family:'Courier New',monospace;font-size:10px;
  padding:8px 12px;cursor:pointer;transition:all .15s;letter-spacing:1px}}
.ctrl-btn:active{{border-color:var(--cyan);color:var(--cyan)}}
.ctrl-btn.danger{{border-color:var(--red);color:var(--red)}}
.ctrl-btn.danger:active{{background:rgba(255,68,68,.12)}}

/* ── remote control grid ── */
#remote-wrap{{flex:1;overflow-y:auto;padding:10px 12px}}
.rc-section{{margin-bottom:14px}}
.rc-title{{font-size:9px;letter-spacing:3px;color:var(--dim);margin-bottom:8px;
  text-transform:uppercase}}
.rc-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:6px}}
.rc-grid.cols2{{grid-template-columns:repeat(2,1fr)}}
.rc-grid.cols4{{grid-template-columns:repeat(4,1fr)}}
.rc-grid.cols5{{grid-template-columns:repeat(5,1fr)}}

#intercom-wrap{{display:flex;flex-direction:column;align-items:center;justify-content:center;
  height:100%;padding:24px;gap:20px;text-align:center}}
#intercom-status-badge{{font-size:13px;letter-spacing:2px;color:var(--dim);
  border:1px solid var(--border);border-radius:20px;padding:6px 18px}}
#intercom-status-badge.live{{color:var(--red);border-color:var(--red);
  animation:pulseBadge 1.4s infinite}}
@keyframes pulseBadge{{0%,100%{{opacity:1}}50%{{opacity:.45}}}}
#intercom-hint{{font-size:12px;color:var(--dim);max-width:280px;line-height:1.6}}
#intercom-btn{{background:var(--panel);border:2px solid var(--gold);color:var(--gold);
  font-family:inherit;font-size:15px;letter-spacing:2px;padding:22px 36px;border-radius:50%;
  width:160px;height:160px;cursor:pointer;transition:all .2s}}
#intercom-btn.live{{border-color:var(--red);color:var(--red);
  box-shadow:0 0 24px rgba(255,68,68,.35)}}
#intercom-viz{{display:grid;grid-template-columns:1fr 1fr;gap:8px 16px;align-items:center;
  width:100%;max-width:280px}}
.viz-bar{{height:8px;border-radius:4px;background:var(--border);overflow:hidden;position:relative}}
.viz-fill{{height:100%;width:0%;transition:width .08s linear;background:var(--cyan)}}
.viz-bar.out .viz-fill{{background:var(--green)}}
.viz-label{{font-size:10px;color:var(--dim);letter-spacing:1px}}
.rc-btn{{background:var(--panel);border:1px solid var(--border);border-radius:10px;
  color:var(--text);font-family:'Courier New',monospace;font-size:10px;
  padding:12px 6px;text-align:center;cursor:pointer;transition:all .15s;
  display:flex;flex-direction:column;align-items:center;gap:4px}}
.rc-btn .icon{{font-size:18px;line-height:1}}
.rc-btn:active{{border-color:var(--cyan);color:var(--cyan);transform:scale(.95)}}
.rc-btn.red:active{{border-color:var(--red);color:var(--red)}}
.rc-btn.gold{{border-color:var(--gold);color:var(--gold)}}
.rc-btn.gold:active{{background:rgba(201,168,76,.12)}}

/* ── connection / security log ── */
#conn-log{{display:flex;flex-direction:column;gap:3px;max-height:220px;overflow-y:auto}}
.cl{{font-size:10px;line-height:1.5;padding:5px 8px;border-radius:4px;
  border-left:2px solid var(--border);display:flex;justify-content:space-between;gap:8px}}
.cl .ip{{opacity:.75}}
.cl.ok{{color:var(--green);border-color:var(--green);background:rgba(68,255,136,.05)}}
.cl.fail{{color:var(--orange);border-color:var(--orange);background:rgba(255,136,68,.06)}}
.cl.block{{color:var(--red);border-color:var(--red);background:rgba(255,68,68,.08)}}
.cl.info{{color:var(--dim);border-color:var(--border)}}
</style>
</head>
<body>
<script>window.__FIREBASE_CONFIG__ = {fcm_config_json};</script>
{firebase_sdk_tags}

<header>
  <div class="logo">J.A.R.V.I.S</div>
  <div style="display:flex;align-items:center;gap:8px">
    <span id="conn-lbl" style="font-size:10px;letter-spacing:2px;color:var(--dim)">OFFLINE</span>
    <div class="status-dot" id="dot"></div>
  </div>
</header>

<div class="tabs">
  <div class="tab active" onclick="tab(this,'chat-panel')">CHAT</div>
  <div class="tab" onclick="tab(this,'stream-panel')">SCREEN</div>
  <div class="tab" onclick="tab(this,'remote-panel')">REMOTE</div>
  <div class="tab" onclick="tab(this,'intercom-panel')">TALK</div>
</div>

<!-- ── CHAT PANEL ── -->
<div class="panel active" id="chat-panel">
  <div id="log"></div>
  <div id="state-badge">MARK XXXIX · MOBILE</div>
  <button id="wake-btn" onclick="wake()">⬡ HEY JARVIS</button>
  <div class="cmd-bar">
    <input id="cmd" type="text" placeholder="Type a command..." autocomplete="off"
           autocorrect="off" autocapitalize="off" spellcheck="false"
           onkeydown="if(event.key==='Enter')send()">
    <button class="send-btn" onclick="send()">SEND ▶</button>
  </div>
</div>

<!-- ── SCREEN PANEL ── -->
<div class="panel" id="stream-panel">
  <div id="stream-wrap">
    <img id="stream-img" src="/stream/latest.jpg" alt="Screen stream">
    <div id="stream-status">TAP REFRESH TO UPDATE</div>
    <div class="stream-controls">
      <button class="ctrl-btn" onclick="refreshStream()">⟳ REFRESH</button>
      <button class="ctrl-btn" onclick="toggleAutoRefresh(this)">▶ AUTO (2s)</button>
      <button class="ctrl-btn" onclick="cmd2('screenshot')">📸 SAVE</button>
      <button class="ctrl-btn" onclick="cmd2('screen analyze')">👁 ANALYZE</button>
    </div>
  </div>
</div>

<!-- ── REMOTE PANEL ── -->
<div class="panel" id="remote-panel">
  <div id="remote-wrap">
    <div class="rc-section">
      <div class="rc-title">Volume &amp; Media</div>
      <div class="rc-grid cols5">
        <div class="rc-btn" onclick="rc('volume_up')"><span class="icon">🔊</span>VOL+</div>
        <div class="rc-btn" onclick="rc('volume_down')"><span class="icon">🔉</span>VOL−</div>
        <div class="rc-btn" onclick="rc('volume_mute')"><span class="icon">🔇</span>MUTE</div>
        <div class="rc-btn" onclick="rc('play_pause')"><span class="icon">⏯</span>PLAY</div>
        <div class="rc-btn" onclick="rc('prev_track')"><span class="icon">⏮</span>PREV</div>
        <div class="rc-btn" onclick="rc('next_track')"><span class="icon">⏭</span>NEXT</div>
        <div class="rc-btn" onclick="rc('media_stop')"><span class="icon">⏹</span>STOP</div>
        <div class="rc-btn" onclick="rc('brightness_up')"><span class="icon">☀️</span>BRGT+</div>
        <div class="rc-btn" onclick="rc('brightness_down')"><span class="icon">🔅</span>BRGT−</div>
      </div>
    </div>
    <div class="rc-section">
      <div class="rc-title">Windows</div>
      <div class="rc-grid cols4">
        <div class="rc-btn" onclick="rc('minimize')"><span class="icon">⬇</span>MIN</div>
        <div class="rc-btn" onclick="rc('fullscreen')"><span class="icon">⬜</span>FULL</div>
        <div class="rc-btn" onclick="rc('close_window')"><span class="icon">✕</span>CLOSE</div>
        <div class="rc-btn" onclick="rcKey('alt+tab')"><span class="icon">⇄</span>ALT+TAB</div>
        <div class="rc-btn" onclick="rcKey('win+d')"><span class="icon">🖥</span>DESKTOP</div>
        <div class="rc-btn" onclick="rcKey('win+l')"><span class="icon">🔒</span>LOCK</div>
        <div class="rc-btn" onclick="rcKey('ctrl+c')"><span class="icon">📋</span>COPY</div>
        <div class="rc-btn" onclick="rcKey('ctrl+v')"><span class="icon">📌</span>PASTE</div>
      </div>
    </div>
    <div class="rc-section">
      <div class="rc-title">Scroll &amp; Navigation</div>
      <div class="rc-grid cols4">
        <div class="rc-btn" onclick="rc('scroll_up')"><span class="icon">↑</span>UP</div>
        <div class="rc-btn" onclick="rc('scroll_down')"><span class="icon">↓</span>DOWN</div>
        <div class="rc-btn" onclick="rcKey('ctrl+home')"><span class="icon">⤒</span>TOP</div>
        <div class="rc-btn" onclick="rcKey('ctrl+end')"><span class="icon">⤓</span>BOTTOM</div>
      </div>
    </div>
    <div class="rc-section">
      <div class="rc-title">Power</div>
      <div class="rc-grid cols2">
        <div class="rc-btn red" onclick="rcConfirm('lock_screen','Lock screen?')"><span class="icon">🔒</span>LOCK PC</div>
        <div class="rc-btn red" onclick="rcConfirm('shutdown','Shutdown?')"><span class="icon">⏻</span>SHUTDOWN</div>
      </div>
    </div>
    <div class="rc-section">
      <div class="rc-title">Voice Command</div>
      <div class="cmd-bar" style="padding:0">
        <input id="rc-cmd" class="rc-btn gold" style="text-align:left;font-size:12px;padding:10px;flex:1;cursor:text"
               placeholder="Type any JARVIS command..." type="text"
               onkeydown="if(event.key==='Enter')sendRcCmd()">
        <button class="ctrl-btn" onclick="sendRcCmd()">▶ GO</button>
      </div>
    </div>
    <div class="rc-section">
      <div class="rc-title">Security &amp; Connections</div>
      <div id="conn-log"></div>
    </div>
  </div>
</div>

<!-- ── INTERCOM PANEL ── -->
<div class="panel" id="intercom-panel">
  <div id="intercom-wrap">
    <div id="intercom-status-badge">🎙️ INTERCOM OFFLINE</div>
    <div id="intercom-hint">
      Opens a live two-way audio link with the PC — you'll hear whatever
      the PC's mic picks up, and anything you say plays through the PC's
      speakers in real time.
    </div>
    <button id="intercom-btn" onclick="toggleIntercom()">🎙️ START INTERCOM</button>
    <div id="intercom-viz">
      <div class="viz-bar" id="viz-in"><div class="viz-fill"></div></div>
      <div class="viz-label">PC → YOU</div>
      <div class="viz-bar out" id="viz-out"><div class="viz-fill"></div></div>
      <div class="viz-label">YOU → PC</div>
    </div>
  </div>
</div>

<script>
const WS_URL = 'ws://{pc_ip}:{WS_PORT}';
const STREAM_URL = '/stream/latest.jpg';
const MAX_LINES = 120;
let ws = null, reconnect = null, autoRefreshTimer = null, autoRefreshOn = false;

// ── auth token: a URL like http://<ip>:8080/?token=XXXX saves it once ──────
(function() {{
  const urlToken = new URLSearchParams(location.search).get('token');
  if (urlToken) {{
    localStorage.setItem('jarvis_auth_token', urlToken);
    history.replaceState({{}}, '', location.pathname);
  }}
}})();
function getAuthToken() {{
  let t = localStorage.getItem('jarvis_auth_token');
  if (!t) {{
    t = prompt('Enter JARVIS device token (shown once on the PC console):') || '';
    if (t) localStorage.setItem('jarvis_auth_token', t);
  }}
  return t;
}}

const logEl = document.getElementById('log');
const dot   = document.getElementById('dot');
const cLbl  = document.getElementById('conn-lbl');
const badge = document.getElementById('state-badge');

function tab(el, pid) {{
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  el.classList.add('active');
  document.getElementById(pid).classList.add('active');
  if (pid==='stream-panel') refreshStream();
}}

function addLine(text, cls) {{
  const d = document.createElement('div');
  d.className = 'ln ' + cls;
  d.textContent = text;
  logEl.appendChild(d);
  while (logEl.children.length > MAX_LINES) logEl.removeChild(logEl.firstChild);
  logEl.scrollTop = logEl.scrollHeight;
}}

function addImgAlert(caption, b64) {{
  const d = document.createElement('div');
  d.className = 'ln a';
  d.innerHTML = '🚨 ' + caption;
  if (b64) {{
    const img = document.createElement('img');
    img.className = 'alert-img';
    img.src = 'data:image/jpeg;base64,' + b64;
    d.appendChild(img);
  }}
  logEl.appendChild(d);
  logEl.scrollTop = logEl.scrollHeight;
}}

function addConnLog(ev) {{
  const box = document.getElementById('conn-log');
  if (!box) return;
  const kindMap = {{
    connected: ['ok','📱 connected'],
    auth_ok:   ['ok','🔓 authenticated'],
    auth_fail: ['fail','⛔ auth failed'],
    blocked:   ['block','🚫 blocked'],
    unauthed:  ['fail','⛔ unauthenticated attempt'],
  }};
  const [cls,label] = kindMap[ev.kind] || ['info', ev.kind];
  const d = document.createElement('div');
  d.className = 'cl ' + cls;
  d.innerHTML = '<span>'+ev.ts+' '+label+(ev.detail? ' — '+ev.detail : '')+'</span><span class="ip">'+ev.ip+'</span>';
  box.appendChild(d);
  while (box.children.length > 40) box.removeChild(box.firstChild);
  box.scrollTop = box.scrollHeight;
}}

function setConn(ok) {{
  dot.className = 'status-dot' + (ok ? ' on' : '');
  cLbl.textContent = ok ? 'ONLINE' : 'OFFLINE';
  cLbl.style.color = ok ? 'var(--green)' : 'var(--dim)';
}}

function connect() {{
  if (ws) {{ try{{ ws.close(); }}catch(e){{}} }}
  ws = new WebSocket(WS_URL);
  ws.binaryType = 'arraybuffer';
  ws.onopen = () => {{
    setConn(true);
    clearInterval(reconnect); reconnect = null;
    addLine('SYS: Mobile connected.', 's');
    const authTok = getAuthToken();
    if (authTok) ws.send(JSON.stringify({{type:'auth', data: authTok}}));
    if (window.__PENDING_FCM_TOKEN__) {{
      ws.send(JSON.stringify({{type:'register_token',data:window.__PENDING_FCM_TOKEN__}}));
      window.__PENDING_FCM_TOKEN__ = null;
    }}
  }};
  ws.onmessage = (e) => {{
    if (e.data instanceof ArrayBuffer) {{
      playIncomingAudio(e.data);
      return;
    }}
    try {{
      const msg = JSON.parse(e.data);
      const t=msg.type||'', d=msg.data||'';
      if (t==='pong') return;
      if (t==='intercom_status') {{
        setIntercomUI(d==='started');
        return;
      }}
      if (t==='log') {{
        const cls = d.startsWith('Jarvis:')? 'j': d.startsWith('You:')? 'y':
                    d.startsWith('NOTIFY:')? 'n': 's';
        addLine(d, cls);
      }} else if (t==='state') {{
        badge.textContent = 'JARVIS · '+d.toUpperCase();
      }} else if (t==='sys') {{
        addLine(d, 's');
      }} else if (t==='notify') {{
        addLine('🔔 '+d, 'n');
        if (Notification.permission==='granted') new Notification('J.A.R.V.I.S', {{body:d}});
      }} else if (t==='notify_image') {{
        try {{
          const inner = JSON.parse(d);
          addImgAlert(inner.caption||'Security alert', inner.image_b64||'');
          if (Notification.permission==='granted')
            new Notification('J.A.R.V.I.S — Security Alert', {{body:inner.caption||''}});
        }} catch(err) {{ addLine('🚨 '+d, 'a'); }}
      }} else if (t==='intruder_alert') {{
        try {{
          const inner = JSON.parse(d);
          addLine('🚨 INTRUDER: '+inner.machine+' @ '+inner.time, 'a');
        }} catch(err) {{ addLine('🚨 '+d, 'a'); }}
      }} else if (t==='conn_log') {{
        try {{ addConnLog(JSON.parse(d)); }} catch(err) {{}}
      }}
    }} catch(err) {{}}
  }};
  ws.onclose = () => {{
    setConn(false);
    addLine('SYS: Reconnecting...', 's');
    if (!reconnect) reconnect = setInterval(connect, 4000);
  }};
  ws.onerror = () => ws.close();
}}

function sendWs(obj) {{
  if (!ws || ws.readyState!==1) {{ addLine('SYS: Not connected.','s'); return false; }}
  ws.send(JSON.stringify(obj)); return true;
}}

function wake() {{
  sendWs({{type:'wake'}});
  const btn = document.getElementById('wake-btn');
  btn.classList.add('pulsing');
  setTimeout(()=>btn.classList.remove('pulsing'), 1000);
  addLine('You: [Wake command sent]', 'y');
}}

function send() {{
  const inp = document.getElementById('cmd');
  const txt = inp.value.trim(); if (!txt) return;
  if (!sendWs({{type:'command',data:txt}})) return;
  addLine('You: '+txt, 'y'); inp.value='';
}}

function cmd2(text) {{ sendWs({{type:'command',data:text}}); }}

function rc(action, value='') {{
  sendWs({{type:'command', data:'remote_control '+action+(value?' '+value:'')}});
  addLine('SYS: Remote → '+action+(value?' ('+value+')':''), 's');
}}

function rcKey(combo) {{
  sendWs({{type:'command', data:'press hotkey '+combo}});
  addLine('SYS: Hotkey → '+combo, 's');
}}

function rcConfirm(action, msg) {{
  if (!confirm(msg)) return;
  sendWs({{type:'command', data:action}});
}}

function sendRcCmd() {{
  const inp = document.getElementById('rc-cmd');
  const txt = inp.value.trim(); if (!txt) return;
  sendWs({{type:'command', data:txt}});
  addLine('You: '+txt, 'y'); inp.value='';
}}

/* ── Intercom: live two-way audio with the PC ──────────────────────────────
   Mic capture uses a ScriptProcessorNode (works everywhere, no separate
   AudioWorklet file needed) to grab Float32 samples at the device's native
   rate, resample down to 16kHz mono to match the PC side, convert to
   Int16 PCM, and send each chunk as a raw binary WebSocket frame.
   Incoming binary frames (PC mic audio, also 16kHz mono Int16 PCM) are
   converted back to Float32 and scheduled for gapless playback. */
const INTERCOM_RATE = 16000;
let intercomActive = false;
let micStream = null, micCtx = null, micSource = null, micProcessor = null;
let playCtx = null, playTime = 0;

function setIntercomUI(live) {{
  intercomActive = live;
  const btn = document.getElementById('intercom-btn');
  const badge = document.getElementById('intercom-status-badge');
  if (live) {{
    btn.textContent = '⏹ STOP INTERCOM';
    btn.classList.add('live');
    badge.textContent = '🔴 INTERCOM LIVE';
    badge.classList.add('live');
  }} else {{
    btn.textContent = '🎙️ START INTERCOM';
    btn.classList.remove('live');
    badge.textContent = '🎙️ INTERCOM OFFLINE';
    badge.classList.remove('live');
  }}
}}

function toggleIntercom() {{
  if (intercomActive) stopIntercom(); else startIntercom();
}}

async function startIntercom() {{
  if (!ws || ws.readyState !== 1) {{ addLine('SYS: Not connected.', 's'); return; }}
  try {{
    micStream = await navigator.mediaDevices.getUserMedia({{ audio: {{
      channelCount: 1, echoCancellation: true, noiseSuppression: true, autoGainControl: true
    }} }});
  }} catch (err) {{
    addLine('SYS: Microphone permission denied — ' + err.message, 's');
    return;
  }}
  micCtx = new (window.AudioContext || window.webkitAudioContext)();
  micSource = micCtx.createMediaStreamSource(micStream);
  micProcessor = micCtx.createScriptProcessor(2048, 1, 1);
  const nativeRate = micCtx.sampleRate;
  const ratio = nativeRate / INTERCOM_RATE;

  micProcessor.onaudioprocess = (ev) => {{
    if (!intercomActive) return;
    const input = ev.inputBuffer.getChannelData(0);
    const outLen = Math.floor(input.length / ratio);
    const pcm16 = new Int16Array(outLen);
    let level = 0;
    for (let i = 0; i < outLen; i++) {{
      const srcIdx = Math.floor(i * ratio);
      let s = input[srcIdx];
      level = Math.max(level, Math.abs(s));
      s = Math.max(-1, Math.min(1, s));
      pcm16[i] = s < 0 ? s * 0x8000 : s * 0x7FFF;
    }}
    setViz('viz-out', level);
    if (ws && ws.readyState === 1) ws.send(pcm16.buffer);
  }};
  micSource.connect(micProcessor);
  const silentGain = micCtx.createGain();
  silentGain.gain.value = 0;  // keeps the audio graph active in browsers that
                              // require a path to destination, without any
                              // audible feedback of your own mic into your speakers
  micProcessor.connect(silentGain);
  silentGain.connect(micCtx.destination);

  playCtx = new (window.AudioContext || window.webkitAudioContext)();
  playTime = playCtx.currentTime;

  sendWs({{type: 'intercom_start'}});
  setIntercomUI(true);
  addLine('SYS: Intercom started — live audio link open.', 's');
}}

function stopIntercom() {{
  sendWs({{type: 'intercom_stop'}});
  if (micProcessor) {{ try {{ micProcessor.disconnect(); }} catch(e){{}} }}
  if (micSource)    {{ try {{ micSource.disconnect(); }} catch(e){{}} }}
  if (micStream)    {{ micStream.getTracks().forEach(t => t.stop()); }}
  if (micCtx)       {{ try {{ micCtx.close(); }} catch(e){{}} }}
  micProcessor = micSource = micStream = micCtx = null;
  setIntercomUI(false);
  setViz('viz-out', 0); setViz('viz-in', 0);
  addLine('SYS: Intercom stopped.', 's');
}}

function playIncomingAudio(arrayBuffer) {{
  if (!playCtx) return;
  const pcm16 = new Int16Array(arrayBuffer);
  const frameCount = pcm16.length;
  if (frameCount === 0) return;
  const buf = playCtx.createBuffer(1, frameCount, INTERCOM_RATE);
  const chan = buf.getChannelData(0);
  let level = 0;
  for (let i = 0; i < frameCount; i++) {{
    chan[i] = pcm16[i] / 0x8000;
    level = Math.max(level, Math.abs(chan[i]));
  }}
  setViz('viz-in', level);
  const src = playCtx.createBufferSource();
  src.buffer = buf;
  src.connect(playCtx.destination);
  const now = playCtx.currentTime;
  if (playTime < now) playTime = now;
  src.start(playTime);
  playTime += buf.duration;
}}

function setViz(id, level) {{
  const bar = document.getElementById(id);
  if (!bar) return;
  const fill = bar.querySelector('.viz-fill');
  if (!fill) return;
  const pct = Math.min(100, Math.round(level * 220));
  fill.style.width = pct + '%';
}}

/* ── Screen streaming ── */
function refreshStream() {{
  const img = document.getElementById('stream-img');
  const st  = document.getElementById('stream-status');
  img.src = STREAM_URL + '?t=' + Date.now();
  img.onload = () => {{ st.textContent = 'UPDATED ' + new Date().toLocaleTimeString(); }};
  img.onerror = () => {{ st.textContent = 'STREAM UNAVAILABLE — START JARVIS FIRST'; }};
}}

function toggleAutoRefresh(btn) {{
  autoRefreshOn = !autoRefreshOn;
  if (autoRefreshOn) {{
    autoRefreshTimer = setInterval(refreshStream, 2000);
    btn.textContent = '⏸ AUTO (2s)';
    btn.style.borderColor = 'var(--cyan)';
    btn.style.color = 'var(--cyan)';
  }} else {{
    clearInterval(autoRefreshTimer);
    btn.textContent = '▶ AUTO (2s)';
    btn.style.borderColor = '';
    btn.style.color = '';
  }}
}}

/* ── FCM ── */
async function registerFCM() {{
  if (!window.__FIREBASE_CONFIG__) return;
  if (!('serviceWorker' in navigator) || !('Notification' in window)) return;
  try {{
    const perm = await Notification.requestPermission();
    if (perm !== 'granted') return;
    const swReg = await navigator.serviceWorker.register('/firebase-messaging-sw.js');
    firebase.initializeApp(window.__FIREBASE_CONFIG__);
    const messaging = firebase.messaging();
    const token = await messaging.getToken({{ serviceWorkerRegistration: swReg }});
    if (token) {{
      if (ws && ws.readyState===1) {{
        ws.send(JSON.stringify({{type:'register_token', data:token}}));
        fetch('/register-token', {{method:'POST',headers:{{'Content-Type':'application/json','X-Auth-Token':getAuthToken()}},
          body:JSON.stringify({{token:token}})}}).catch(()=>{{}});
        addLine('SYS: Registered for push notifications.', 's');
      }} else {{
        window.__PENDING_FCM_TOKEN__ = token;
      }}
    }}
  }} catch(err) {{ addLine('SYS: Push registration failed: '+err.message, 's'); }}
}}

document.getElementById('wake-btn').addEventListener('touchstart', ()=>{{
  if (Notification.permission==='default') Notification.requestPermission();
}}, {{once:true}});

setInterval(()=>{{ if(ws && ws.readyState===1) ws.send(JSON.stringify({{type:'ping'}})); }}, 30000);

connect();
if (window.__FIREBASE_CONFIG__) setTimeout(registerFCM, 1500);
</script>
</body>
</html>"""
    return html.encode("utf-8")


def _get_service_worker_js(firebase_config) -> bytes:
    import json as _json
    config_json = _json.dumps(firebase_config) if firebase_config else "{}"
    js = f"""importScripts('https://www.gstatic.com/firebasejs/10.13.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.13.0/firebase-messaging-compat.js');
firebase.initializeApp({config_json});
const messaging = firebase.messaging();
self.addEventListener('notificationclick', function(event) {{
  event.notification.close();
  var url = (event.notification.data && event.notification.data.alert_url)
            ? event.notification.data.alert_url : self.registration.scope;
  event.waitUntil(clients.matchAll({{type:'window',includeUncontrolled:true}}).then(function(cs) {{
    for (var i=0;i<cs.length;i++) {{
      if (cs[i].url.indexOf('/alert')!==-1 && 'focus' in cs[i]) return cs[i].focus();
    }}
    if (clients.openWindow) return clients.openWindow(url);
  }}));
}});
messaging.onBackgroundMessage(function(payload) {{
  var data = payload.data || {{}};
  var ntype = data.type || '';
  var alertUrl = data.alert_url || (self.registration.scope + 'alert');
  if (ntype === 'intruder_alert') {{
    return self.registration.showNotification('INTRUSION DETECTED', {{
      body: 'MACHINE: '+(data.machine||'UNKNOWN')+'\\nTIME: '+(data.time||''),
      tag:'jarvis-intruder', renotify:true, requireInteraction:true,
      vibrate:[300,120,300,120,600], data:{{alert_url:alertUrl}},
    }});
  }}
  var title = (payload.notification && payload.notification.title) || 'J.A.R.V.I.S';
  var body  = (payload.notification && payload.notification.body) || '';
  return self.registration.showNotification(title, {{body:body, tag:'jarvis-alert', data:{{alert_url:alertUrl}}}});
}});
"""
    return js.encode("utf-8")


def _get_alert_html() -> bytes:
    p = BASE_DIR / "core" / "alert.html"
    if p.exists():
        return p.read_bytes()
    return (
        b"<!DOCTYPE html><html><head><meta charset=UTF-8>"
        b"<meta name=viewport content='width=device-width,initial-scale=1'>"
        b"<title>JARVIS ALERT</title>"
        b"<style>body{background:#000;color:#f00;font-family:monospace;"
        b"display:flex;align-items:center;justify-content:center;"
        b"min-height:100vh;text-align:center;margin:0}"
        b"h1{font-size:2em;animation:f 0.8s infinite}"
        b"@keyframes f{50%{opacity:0}}</style></head>"
        b"<body><div><h1>&#9888; INTRUSION DETECTED &#9888;</h1>"
        b"<p>Someone tried to unlock your system!</p></div></body></html>"
    )


def _get_fraud_alert_html() -> bytes:
    """Page opened when tapping the FCM fraud-alert push notification.
    Shows whatever fraud alert is currently cached in _LATEST_FRAUD_ALERT."""
    with _fraud_alert_lock:
        alert = dict(_LATEST_FRAUD_ALERT) if _LATEST_FRAUD_ALERT else {}

    if not alert:
        body = "<p>No active fraud alert.</p>"
    else:
        reasons = alert.get("reasons") or []
        reasons_html = "".join(f"<li>{r}</li>" for r in reasons) or "<li>elevated risk signals</li>"
        score = alert.get("risk_score")
        score_str = f"{score:.1f}" if isinstance(score, (int, float)) else "unknown"
        body = f"""
        <div class="card">
          <h1>&#9888; {alert.get('severity', 'UNKNOWN')} FRAUD ALERT</h1>
          <table>
            <tr><td>Case</td><td>{alert.get('case_id')}</td></tr>
            <tr><td>Transaction</td><td>{alert.get('transaction_id')}</td></tr>
            <tr><td>Account</td><td>{alert.get('user_id')}</td></tr>
            <tr><td>Risk score</td><td>{score_str}/100</td></tr>
            <tr><td>Assigned to</td><td>{alert.get('assigned_to')}</td></tr>
            <tr><td>Detected</td><td>{alert.get('time', '')}</td></tr>
          </table>
          <p>Reasons:</p>
          <ul>{reasons_html}</ul>
        </div>
        """

    html = f"""<!DOCTYPE html><html><head><meta charset=UTF-8>
<meta name=viewport content='width=device-width,initial-scale=1'>
<title>SENTINEL — FRAUD ALERT</title>
<style>
body{{background:#0a0e14;color:#e6edf3;font-family:'JetBrains Mono',monospace;
margin:0;padding:24px;min-height:100vh;box-sizing:border-box}}
h1{{color:#ff4d4d;font-size:1.4em;margin-top:0}}
.card{{max-width:480px;margin:0 auto;background:#111826;border:1px solid #2a3550;
border-radius:10px;padding:20px}}
table{{width:100%;border-collapse:collapse;margin:12px 0}}
td{{padding:6px 4px;border-bottom:1px solid #1e2635;font-size:0.9em}}
td:first-child{{color:#7d8ba1;width:40%}}
ul{{margin:8px 0;padding-left:20px;font-size:0.9em;color:#f2c94c}}
</style></head><body>{body}</body></html>"""
    return html.encode("utf-8")


class _HTTPHandler(BaseHTTPRequestHandler):
    pc_ip: str = "127.0.0.1"
    firebase_config = None
    _command_cb = None   # set by MobileServer so HTTP routes can dispatch commands

    def do_GET(self):
        p = self.path.split("?")[0]
        if p in ("/", "/index.html"):
            body = _get_html(self.pc_ip, self.firebase_config)
            self._respond(200, "text/html; charset=utf-8", body)
        elif p == "/firebase-messaging-sw.js":
            self._respond(200, "application/javascript; charset=utf-8",
                          _get_service_worker_js(self.firebase_config))
        elif p == "/stream/latest.jpg":
            # Serve the latest captured screen frame
            _ensure_stream_thread()
            with _stream_lock:
                frame = _stream_frame
            if frame:
                self._respond(200, "image/jpeg", frame,
                              extra=[("Cache-Control", "no-store"),
                                     ("Access-Control-Allow-Origin", "*")])
            else:
                self._respond(204, "image/jpeg", b"")
        elif p.startswith("/sounds/"):
            fname = p.lstrip("/sounds/")
            sp = BASE_DIR / "core" / "sounds" / fname
            ct = "audio/mpeg" if fname.endswith(".mp3") else "audio/ogg"
            body = sp.read_bytes() if sp.exists() else b""
            self._respond(200, ct, body, extra=[("Cache-Control", "public, max-age=86400")])
        elif p == "/alert/latest.jpg":
            # Serves the webcam (or screenshot-fallback) photo captured by
            # jarvis_watcher_service.py on the most recent failed-logon
            # alert. Written to shared disk since the watcher runs as a
            # separate SYSTEM-context process and can't call back into this
            # one directly.
            photo_path = BASE_DIR / "memory" / "latest_intruder_photo.jpg"
            if photo_path.exists():
                try:
                    body = photo_path.read_bytes()
                    self._respond(200, "image/jpeg", body,
                                  extra=[("Cache-Control", "no-store"),
                                         ("Access-Control-Allow-Origin", "*")])
                except Exception:
                    self._respond(204, "image/jpeg", b"")
            else:
                self._respond(204, "image/jpeg", b"")
        elif p.startswith("/fraud-alert"):
            self._respond(200, "text/html; charset=utf-8", _get_fraud_alert_html())
        elif p.startswith("/alert"):
            self._respond(200, "text/html; charset=utf-8", _get_alert_html())
        elif p.startswith("/history"):
            try:
                from core.sentinel_extras import AlertHistory
                body = AlertHistory.render_html()
            except Exception as e:
                body = f"<html><body>History unavailable: {e}</body></html>".encode("utf-8")
            self._respond(200, "text/html; charset=utf-8", body)
        else:
            self.send_response(404); self.end_headers()

    def _client_ip(self) -> str:
        return self.client_address[0] if self.client_address else "?"

    def _check_auth(self, data: dict) -> bool:
        ip = self._client_ip()
        if _ip_is_blocked(ip):
            return False
        supplied = (self.headers.get("X-Auth-Token") or data.get("auth_token") or "").strip()
        ok = bool(supplied) and secrets.compare_digest(supplied, MOBILE_AUTH_TOKEN)
        if not ok:
            _record_failed_auth(ip)
            print(f"[Mobile] ⛔ Rejected unauthenticated HTTP {self.path} from {ip}")
        else:
            _broadcast_conn_event("auth_ok", ip, self.path)
        return ok

    def _verify_sentinel_signature(self, raw_body: bytes) -> bool:
        if not SENTINEL_SHARED_SECRET:
            return False
        supplied = (self.headers.get("X-Sentinel-Signature") or "").strip()
        if not supplied:
            return False
        expected = hmac.new(SENTINEL_SHARED_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(supplied, expected)

    def _handle_fraud_alert(self, raw_body: bytes, data: dict):
        ip = self._client_ip()
        if not self._verify_sentinel_signature(raw_body):
            _record_failed_auth(ip, "bad sentinel signature")
            resp = json.dumps({"ok": False, "error": "invalid signature"}).encode()
            self._respond(401, "application/json", resp,
                          extra=[("Access-Control-Allow-Origin", "*")])
            return

        case_id        = data.get("case_id", "UNKNOWN")
        severity       = (data.get("severity") or "UNKNOWN").upper()
        transaction_id = data.get("transaction_id") or "unknown"
        user_id        = data.get("user_id") or "unknown"
        risk_score     = data.get("risk_score")
        assigned_to    = data.get("assigned_to") or "unassigned"
        reasons        = data.get("reasons") or []

        alert = {
            "case_id": case_id, "severity": severity,
            "transaction_id": transaction_id, "user_id": user_id,
            "risk_score": risk_score, "assigned_to": assigned_to,
            "reasons": reasons, "time": time.strftime("%H:%M:%S"),
        }
        with _fraud_alert_lock:
            _LATEST_FRAUD_ALERT.clear()
            _LATEST_FRAUD_ALERT.update(alert)

        # ── Respond to FusionShield NOW ──────────────────────────────────
        # Everything below this point is fast and local: signature already
        # verified, alert already cached, websocket broadcast is just an
        # in-memory queue push. None of it waits on a network round trip,
        # so the response goes back well inside FusionShield's timeout.
        resp = json.dumps({"ok": True}).encode()
        self._respond(200, "application/json", resp,
                      extra=[("Access-Control-Allow-Origin", "*")])

        # Instant update to any phone/desktop HUD already connected over
        # the local WebSocket — this is in-memory, not a network call, so
        # it stays before the response is sent... actually it's fine after
        # too, but keeping it here means the HUD updates before Telegram/
        # FCM even start, which is the more useful ordering for a demo.
        try:
            if _ACTIVE_HUB is not None:
                _ACTIVE_HUB.broadcast("fraud_alert", json.dumps(alert))
        except Exception as e:
            log.warning(f"fraud_alert websocket broadcast failed: {e}")

        # ── Telegram + FCM happen HERE, on a background thread ───────────
        # BUG THIS FIXES: this handler runs inside HTTPServer's single
        # request-handling thread (JARVIS uses plain HTTPServer, not
        # ThreadingHTTPServer — see MobileServer.start()). Doing the
        # Telegram/FCM network calls synchronously, before send_response,
        # meant a slow Telegram/Firebase endpoint could delay the HTTP
        # response past FusionShield's own request timeout, even though
        # JARVIS was still working and would have finished a few seconds
        # later. The response above is now already sent; this thread can
        # take as long as it needs without anyone waiting on it.
        threading.Thread(
            target=_dispatch_fraud_alert_async,
            args=(alert,),
            name="FraudAlertDispatch",
            daemon=True,
        ).start()

    def do_POST(self):
        p = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            data = {}

        if p == "/fraud-alert":
            # Separate auth path: FusionShield authenticates with an
            # HMAC-SHA256 signature over the raw body, not the mobile
            # auth token (that token is for you/your phone, not a server).
            self._handle_fraud_alert(body, data)
            return

        if not self._check_auth(data):
            resp = json.dumps({"ok": False, "error": "unauthorized"}).encode()
            self._respond(401, "application/json", resp,
                          extra=[("Access-Control-Allow-Origin", "*")])
            return

        if p == "/register-token":
            token = data.get("token", "").strip()
            if token:
                TOKEN_STORE = BASE_DIR / "memory" / "fcm_token.json"
                TOKEN_STORE.parent.mkdir(parents=True, exist_ok=True)
                TOKEN_STORE.write_text(json.dumps({"token": token}), encoding="utf-8")
                print(f"[Mobile] 📱 FCM token refreshed via HTTP ({token[:12]}...)")
                resp = json.dumps({"ok": True}).encode()
            else:
                resp = json.dumps({"ok": False, "error": "empty token"}).encode()
            self._respond(200, "application/json", resp,
                          extra=[("Access-Control-Allow-Origin", "*")])

        elif p == "/command":
            # HTTP remote control endpoint for automation/shortcuts
            cmd = data.get("command", "").strip()
            if cmd and self._command_cb:
                try:
                    self._command_cb(cmd)
                    resp = json.dumps({"ok": True}).encode()
                except Exception as e:
                    resp = json.dumps({"ok": False, "error": str(e)}).encode()
            else:
                resp = json.dumps({"ok": False, "error": "no command or not ready"}).encode()
            self._respond(200, "application/json", resp,
                          extra=[("Access-Control-Allow-Origin", "*")])

        elif p in ("/api/wipe/request", "/wipe/request"):
            try:
                from core.sentinel_extras import EmergencyWipeController
                controller = EmergencyWipeController.get_instance()
                ok, msg = controller.request_wipe(channel="mobile_api")
                resp = json.dumps({"ok": ok, "message": msg, "expires_in": 60}).encode("utf-8")
            except Exception as e:
                resp = json.dumps({"ok": False, "error": str(e)}).encode("utf-8")
            self._respond(200, "application/json", resp,
                          extra=[("Access-Control-Allow-Origin", "*")])

        elif p in ("/api/wipe/confirm", "/wipe/confirm"):
            try:
                pin = str(data.get("pin", "")).strip()
                from core.sentinel_extras import EmergencyWipeController
                controller = EmergencyWipeController.get_instance()
                ok, status_msg, results = controller.confirm_wipe(pin, channel="mobile_api")
                resp = json.dumps({"ok": ok, "message": status_msg, "results": results}).encode("utf-8")
            except Exception as e:
                resp = json.dumps({"ok": False, "error": str(e)}).encode("utf-8")
            self._respond(200, "application/json", resp,
                          extra=[("Access-Control-Allow-Origin", "*")])
        else:
            self.send_response(404); self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _respond(self, code: int, ct: str, body: bytes, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if extra:
            for k, v in extra:
                self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # suppress access log spam


# ═══════════════════════════════════════════════════════════════════════════════
#  Public API — MobileServer
# ═══════════════════════════════════════════════════════════════════════════════

class MobileServer:
    """
    Start with:
        server = MobileServer()
        server.set_callbacks(on_command=..., on_wake=...)
        server.start()

    Then call from JARVIS:
        server.log("Jarvis: Hello sir.")
        server.notify("Rain expected at 3pm")
        server.set_state("LISTENING")
    """

    def __init__(self):
        self._hub       = _WSHub()
        self._http      = None
        self._pc_ip     = get_local_ip()
        from fcm_push import FCMPusher
        self._fcm = FCMPusher(log_fn=self.log)
        global _SENTINEL_FCM_REF
        _SENTINEL_FCM_REF = self._fcm

    def set_callbacks(self, on_command, on_wake, on_token_register=None,
                       on_intercom_start=None, on_intercom_stop=None, on_intercom_audio=None,
                       on_incoming_call=None, on_incoming_sms=None):
        def _save_and_forward(token: str):
            self._fcm.save_token(token)
            if on_token_register:
                try: on_token_register(token)
                except Exception: pass
        self._hub.set_callbacks(on_command, on_wake, _save_and_forward,
                                 on_intercom_start, on_intercom_stop, on_intercom_audio,
                                 on_incoming_call, on_incoming_sms)
        _HTTPHandler._command_cb = on_command

    def send_sms(self, recipient: str, body: str):
        """Sends a canned SMS reply through the connected mobile companion app.
        Privacy: logs recipient and length only; message text is redacted from logs."""
        print(f"[Mobile] 📤 Dispatched canned SMS to {recipient} ({len(body)} chars)")
        self._hub.send_sms(recipient, body)

    def broadcast_intercom_audio(self, pcm_bytes: bytes):
        """Streams a chunk of PC mic audio to the phone during an active
        intercom session. Call this repeatedly from the mic capture
        thread with small chunks (e.g. ~20-50ms of audio at a time)."""
        self._hub.broadcast_audio(pcm_bytes)

    def start(self):
        _HTTPHandler.pc_ip = self._pc_ip
        _HTTPHandler.firebase_config = _load_firebase_web_config()
        self._http = HTTPServer(("0.0.0.0", HTTP_PORT), _HTTPHandler)
        threading.Thread(target=self._http.serve_forever, daemon=True,
                         name="JARVISMobileHTTP").start()
        threading.Thread(target=self._run_ws, daemon=True,
                         name="JARVISMobileWS").start()
        # Start screen capture thread for streaming
        _ensure_stream_thread()
        url = f"http://{self._pc_ip}:{HTTP_PORT}"
        print(f"[Mobile] 🌐 Companion app → {url}")
        print(f"[Mobile] 📱 Open on phone (same WiFi): {url}")
        print(f"[Mobile] 📡 Screen stream: {url}/stream/latest.jpg")
        if _HTTPHandler.firebase_config:
            print("[Mobile] 📤 FCM push configured")
        else:
            print("[Mobile] ⚠️ FCM not configured — local WiFi only")

    def stop(self):
        if self._http: self._http.shutdown()

    def _run_ws(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._hub.serve())

    def log(self, text: str):
        # Previously this ONLY broadcast over WebSocket to whatever phone
        # happened to be connected at that exact moment — meaning any log
        # generated while no phone was connected (e.g. FCM's own internal
        # success/failure messages during a real intrusion, when nobody's
        # sitting on the CHAT tab) vanished completely: no console line, no
        # file, nothing. Printing here too means it's always at least
        # visible in the running console / jarvis_service.log.
        print(f"[MobileLog] {text}")
        self._hub.broadcast("log", text)

    def notify(self, text: str):
        self._hub.broadcast("notify", text)
        print(f"[Mobile] 🔔 Notification: {text}")
        self._fcm.send("JARVIS", text)

    def notify_image(self, caption: str, jpeg_bytes: bytes):
        import base64
        try:
            b64 = base64.b64encode(jpeg_bytes).decode("ascii")
        except Exception as e:
            print(f"[Mobile] ❌ notify_image encode failed: {e}")
            return
        payload = json.dumps({"caption": caption, "image_b64": b64})
        self._hub.broadcast("notify_image", payload)
        print(f"[Mobile] 🔔📷 Photo alert: {caption}")

    def notify_video(self, caption: str, video_bytes: bytes, filename: str = "intruder.mp4"):
        import base64
        try:
            b64 = base64.b64encode(video_bytes).decode("ascii")
        except Exception as e:
            print(f"[Mobile] ❌ notify_video encode failed: {e}")
            return
        payload = json.dumps({"caption": caption, "video_b64": b64, "filename": filename})
        self._hub.broadcast("notify_video", payload)
        print(f"[Mobile] 🔔🎥 Video alert: {caption} ({len(video_bytes)} bytes)")

    def intruder_alert(self, hostname: str, time_str: str, alert_url: str = ""):
        payload = json.dumps({"machine": hostname, "time": time_str, "alert_url": alert_url})
        self._hub.broadcast("intruder_alert", payload)
        print(f"[Mobile] 🚨 Intruder alert → {hostname} at {time_str}")

    def set_state(self, state: str):
        self._hub.broadcast("state", state)

    @property
    def url(self) -> str:
        return f"http://{self._pc_ip}:{HTTP_PORT}"