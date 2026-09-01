"""
fcm_push.py — Firebase Cloud Messaging push notifications (Phase 7 add-on)
============================================================================
Sends real Android push notifications to your phone over Firebase Cloud
Messaging (FCM) — Google's free push notification service. Unlike the
local WebSocket companion server (mobile_server.py), this works on ANY
network: your phone doesn't need to be on the same WiFi/hotspot as your
laptop, doesn't need the mobile web page open, and the notification
lands in the real Android notification tray even if the JARVIS page
was closed.

Why this exists
----------------
mobile_server.py's WebSocket push only reaches your phone while both
devices share a local network (it broadcasts to ws://<laptop-LAN-IP>),
because that's literally what a local WebSocket server is. FCM solves
that by routing through Google's always-on infrastructure instead:

    Laptop --(HTTPS, your service account)--> FCM servers --(push)--> Phone

Cost: completely free. FCM has no paid tier for sending notifications —
Google does not charge for messages sent through it, regardless of
volume, for this kind of usage.

One-time setup you need to do (see SETUP.md / the README section in
this file's docstring for the long version):
  1. Create a free Firebase project at https://console.firebase.google.com
  2. In Project Settings -> Service Accounts -> "Generate new private key"
     -> download the JSON file -> save it as config/firebase-service-account.json
  3. Add a Web App to the same Firebase project, copy its config object
     into the mobile web app (mobile_server.py does this for you once you
     fill in config/firebase_web_config.json — see that file's template).
  4. Open the mobile web app on your phone once, accept the notification
     permission prompt -> it registers an FCM token with Firebase and
     sends that token to the laptop over the (local-network) WebSocket
     -> the laptop stores it in memory/fcm_token.json for all future use.
     This one-time registration step does need the same network; every
     push AFTER that works from anywhere.

This module only handles step 5 onward: storing the token and sending
pushes. It does not touch your existing local WebSocket alerts — both
fire side by side, so on the same network you still get the instant
local alert AND the FCM push; off-network you still get the FCM push.

Usage
-----
    from fcm_push import FCMPusher

    pusher = FCMPusher()              # loads service account + saved token
    pusher.save_token("dEvIcE-tOkEn-from-phone")   # called once on registration
    pusher.send("JARVIS Alert", "Failed login attempt on JARVIS-PC at 14:32")
    pusher.send("JARVIS Alert", "...", image_b64=jpeg_base64_string)  # optional photo
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent
SERVICE_ACCOUNT_PATH = BASE_DIR / "config" / "firebase-service-account.json"
TOKEN_STORE_PATH      = BASE_DIR / "memory" / "fcm_token.json"

# FCM data-message payloads have a 4KB total limit, which an inline JPEG
# blows past immediately — so unlike the local WebSocket path, photos are
# NOT embedded directly in the FCM push. Instead we send a small data
# message that tells the phone "a photo is waiting"; the actual photo
# bytes still travel over the local WebSocket the next time the phone is
# on the same network (mobile_server.py already queues these — see
# MobileServer.notify_image queuing in jarvis_service.pyw wiring).
MAX_INLINE_IMAGE_BYTES = 0  # intentionally disabled for FCM; see note above


class FCMPusher:
    """
    Thin wrapper around firebase_admin.messaging for sending alerts to a
    single registered phone. Safe to construct even if Firebase isn't
    configured yet — methods become no-ops (with a clear log) until
    both the service account file and a saved device token exist.
    """

    def __init__(self, log_fn=None):
        def safe_log(msg: str):
            try:
                (log_fn or print)(msg)
            except UnicodeEncodeError:
                try:
                    (log_fn or print)(msg.encode("ascii", errors="backslashreplace").decode("ascii"))
                except Exception:
                    pass
            except Exception:
                pass

        self._log = safe_log
        self._app = None
        self._token: Optional[str] = None
        self._lock = threading.Lock()
        self._ready = False

        self._load_token()
        self._init_firebase()

    # ── setup ────────────────────────────────────────────────────────────

    def _init_firebase(self):
        sa_cred = None
        try:
            from core.secure_vault import get_secret
            vault_sa = get_secret("firebase_service_account")
            if vault_sa and isinstance(vault_sa, dict):
                sa_cred = vault_sa
        except Exception:
            pass

        if not sa_cred and not SERVICE_ACCOUNT_PATH.exists():
            self._log(
                "SYS: ⚠️ FCM not configured — "
                "missing Firebase Service Account in vault or config/. "
                "Phone alerts will only work over local WiFi until this is added."
            )
            return

        try:
            import firebase_admin
            from firebase_admin import credentials

            if sa_cred:
                cred = credentials.Certificate(sa_cred)
            else:
                cred = credentials.Certificate(str(SERVICE_ACCOUNT_PATH))

            try:
                self._app = firebase_admin.get_app()
            except ValueError:
                self._app = firebase_admin.initialize_app(cred)
            self._ready = True
            self._log("SYS: ✅ FCM push notifications ready (works on any network)")
        except ImportError:
            self._log(
                "SYS: ⚠️ 'firebase-admin' not installed — run: pip install firebase-admin"
            )
        except Exception as e:
            self._log(f"SYS: ⚠️ FCM init failed: {e}")

    def _load_token(self):
        try:
            if TOKEN_STORE_PATH.exists():
                data = json.loads(TOKEN_STORE_PATH.read_text(encoding="utf-8"))
                self._token = data.get("token")
                if self._token:
                    self._log("SYS: 📱 Loaded saved FCM device token")
        except Exception as e:
            self._log(f"SYS: ⚠️ Could not read saved FCM token: {e}")

    def save_token(self, token: str):
        """
        Called when the phone registers (or re-registers — tokens can
        rotate, e.g. after the app is reinstalled or Android refreshes
        it). Overwrites any previously saved token for this phone.
        """
        if not token or not isinstance(token, str):
            return
        with self._lock:
            self._token = token
            try:
                TOKEN_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
                # Atomic-ish write: write to a temp file then replace, so a
                # crash mid-write can't corrupt the token file.
                fd, tmp_path = tempfile.mkstemp(dir=str(TOKEN_STORE_PATH.parent))
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump({"token": token}, f)
                os.replace(tmp_path, TOKEN_STORE_PATH)
                self._log("SYS: 📱 FCM device token registered — phone alerts now work on any network")
            except Exception as e:
                self._log(f"SYS: ⚠️ Could not save FCM token: {e}")

    @property
    def configured(self) -> bool:
        return self._ready and bool(self._token)

    # ── sending ──────────────────────────────────────────────────────────

    def send(self, title: str, body: str, data: Optional[dict] = None) -> bool:
        """
        Send a push notification. Returns True if FCM accepted the
        message, False otherwise (including "not configured yet" — this
        never raises, so a missing Firebase setup never crashes a caller
        like the intruder alert watcher).
        """
        if not self._ready:
            self._log("SYS: ⚠️ FCM push skipped — Firebase service account is not initialized/ready")
            return False
        if not self._token:
            self._log("SYS: ⚠️ No phone registered for FCM yet — open the mobile app once on the same WiFi")
            return False

        try:
            from firebase_admin import messaging

            message = messaging.Message(
                notification=messaging.Notification(title=title, body=body),
                data={k: str(v) for k, v in (data or {}).items()},
                token=self._token,
                android=messaging.AndroidConfig(
                    priority="high",
                    notification=messaging.AndroidNotification(
                        channel_id="jarvis_alerts",
                        sound="default",
                    ),
                ),
            )
            response = messaging.send(message)
            self._log(f"SYS: 📤 FCM push sent ({response})")
            return True
        except Exception as e:
            err = str(e)
            # The most common real-world failure: the saved token is stale
            # (app reinstalled, data cleared, token rotated). Surface that
            # plainly instead of a raw stack trace.
            if "registration-token-not-registered" in err.lower() or "not found" in err.lower() or "not-found" in err.lower():
                self._log(
                    "SYS: ⚠️ Phone's FCM token is no longer valid — "
                    "open the mobile app once on the same WiFi to re-register."
                )
            else:
                self._log(f"SYS: ⚠️ FCM push failed: {e}")
            return False

    def send_intruder_alert(self, text: str) -> bool:
        """Convenience wrapper with the right title for security alerts."""
        return self.send("JARVIS — Security Alert", text, data={"type": "intruder_alert"})

    def send_intruder_alert_fullscreen(
        self,
        hostname: str,
        time_str: str,
        alert_url: str,
        escalated: bool = False,
        extra_note: str = "",
        photo_url: Optional[str] = None,
    ) -> bool:
        """
        Sends a REAL high-priority Android notification (not a silent
        data-only message) on a dedicated "jarvis_intrusion" channel,
        with the hacker-alarm sound, a strong vibration pattern, a red
        accent color, and the threat details visible directly in the
        notification body (BigTextStyle) -- no tap required to see them.

        Data-only messages are unreliable once the browser/PWA is fully
        backgrounded or closed: Android can delay or coalesce them, and
        the Service Worker's onBackgroundMessage may simply never fire
        in time. A real AndroidNotification on a high-importance channel
        is what Android actually guarantees gets shown and makes sound
        for -- that reliability is the whole point of this change.

        Tapping the notification still opens the full-screen /alert page
        (handled by the Service Worker's notificationclick listener).
        """
        if not self._ready:
            self._log("[FCM] ⚠️ Full-screen alert skipped — Firebase service account is not initialized/ready")
            return False
        if not self._token:
            self._log("[FCM] ⚠️ Full-screen alert skipped — No phone registered for FCM yet (memory/fcm_token.json is missing or empty)")
            return False
        try:
            from firebase_admin import messaging

            if escalated:
                title = "\U0001F6A8\U0001F6A8 REPEATED LOGIN FAILURES \U0001F6A8\U0001F6A8"
                body_lines = (
                    f"MACHINE: {hostname}\n"
                    f"TIME: {time_str}\n"
                    f"STATUS: BRUTE-FORCE PATTERN DETECTED\n"
                    f"THREAT: CRITICAL\n"
                    f"{extra_note}\n"
                    f"Tap to view full alert."
                )
                notif_tag = "jarvis-intruder-critical"
            else:
                title = "\U0001F480 INTRUSION DETECTED \U0001F480"
                body_lines = (
                    f"MACHINE: {hostname}\n"
                    f"TIME: {time_str}\n"
                    f"STATUS: INTRUSION\n"
                    f"THREAT: HIGH\n"
                    f"Tap to view full alert."
                )
                notif_tag = "jarvis-intruder"

            # Same HTTPS requirement/failure mode as alert_url above: FCM's
            # notification.image fields are validated client-side too and
            # will kill the whole send() if given a bare http:// URL (which
            # is exactly what photo_url is on a plain LAN setup with no
            # ngrok tunnel). Only attach it when it's actually https.
            safe_photo_url = photo_url if (photo_url and photo_url.startswith("https://")) else None

            message = messaging.Message(
                notification=messaging.Notification(
                    title=title,
                    body=f"Someone tried to unlock {hostname} at {time_str}!",
                    image=safe_photo_url,
                ),
                data={
                    "type":      "intruder_alert",
                    "machine":   hostname,
                    "time":      time_str,
                    "alert_url": alert_url,
                    "photo_url": photo_url or "",
                },
                token=self._token,
                android=messaging.AndroidConfig(
                    priority="high",
                    notification=messaging.AndroidNotification(
                        title=title,
                        body=body_lines,
                        channel_id="jarvis_intrusion",
                        sound="jarvis_alert",
                        color="#FF1D1D",
                        priority="max",
                        visibility="public",
                        vibrate_timings_millis=[0, 300, 120, 300, 120, 300, 120, 600],
                        notification_count=1,
                        click_action="FLUTTER_NOTIFICATION_CLICK",
                        tag=notif_tag,
                        image=safe_photo_url,
                    ),
                ),
                # FCM's webpush.fcm_options.link is validated client-side and
                # MUST be https — it silently kills the entire send() call if
                # it isn't (this is what was failing: "link must be a HTTPS
                # URL" whenever no ngrok tunnel is running, i.e. almost
                # always on a plain LAN setup). The link field only controls
                # what the *browser's own default* notification-click does;
                # our service worker already has a custom notificationclick
                # handler that reads data.alert_url instead (works with any
                # scheme, including a bare LAN http:// URL). So: only attach
                # fcm_options when we actually have an https URL to give it,
                # and never let a missing tunnel take down the whole alert.
                webpush=messaging.WebpushConfig(
                    fcm_options=(messaging.WebpushFCMOptions(link=alert_url)
                                 if alert_url.startswith("https://") else None),
                    notification=messaging.WebpushNotification(
                        title=title,
                        body=body_lines,
                        icon="/static/icon.png",
                        image=safe_photo_url,
                        require_interaction=True,
                        tag=notif_tag,
                        vibrate=[300, 120, 300, 120, 300, 120, 600],
                    ),
                ),
            )

            # A screen-lock event can suspend network/DNS for well over a
            # minute on some machines (same outage that Telegram's sender
            # already retries through — see jarvis_watcher_service.py).
            # FCM previously had zero retries here, so it silently died on
            # exactly the DNS blip Telegram survived. Mirror the same
            # backoff schedule so both channels have equal odds of landing.
            delays = [3, 5, 8, 13, 20]  # ~49s of total backoff across 6 attempts
            last_err: Optional[Exception] = None
            for attempt in range(1, len(delays) + 2):
                try:
                    response = messaging.send(message)
                    self._log(f"[FCM] Full-screen alert dispatched -> {alert_url} ({response})")
                    return True
                except Exception as e:
                    last_err = e
                    err = str(e)
                    if "registration-token-not-registered" in err.lower() or "not found" in err.lower() or "not-found" in err.lower():
                        # Permanent failure — the token itself is stale, retrying won't help.
                        self._log(
                            "[FCM] Phone's FCM token is no longer valid — "
                            "open the mobile app once on the same WiFi to re-register."
                        )
                        return False
                    if attempt <= len(delays):
                        self._log(f"[FCM] Full-screen alert attempt {attempt} failed: {e} — retrying in {delays[attempt-1]}s")
                        time.sleep(delays[attempt - 1])
            self._log(f"[FCM] FAILED send_intruder_alert_fullscreen after retries: {last_err}")
            return False
        except Exception as e:
            self._log(f"[FCM] FAILED send_intruder_alert_fullscreen: {e}")
            return False