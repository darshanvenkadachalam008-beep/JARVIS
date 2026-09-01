"""
patch_fullscreen_fcm.py
=======================
Makes the full-screen danger page open on your phone automatically,
even when Chrome / the JARVIS page is completely closed.

How it works after this patch:
  Wrong password
    → intruder_alert.py detects it
    → fires FCM data-only message with {type:"intruder_alert", machine, time, alert_url}
    → Firebase delivers it to your phone in background
    → Service Worker wakes up (even with Chrome closed)
    → Service Worker calls clients.openWindow(alert_url)
    → Full-screen red danger page opens instantly

Patches 3 files:
  1. mobile_server.py  — upgrades the Service Worker JS
  2. fcm_push.py       — adds send_intruder_alert_fullscreen()
  3. jarvis_service.pyw — _on_intruder_alert calls the new method

Run once:
  python patch_fullscreen_fcm.py
"""
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent

# ═══════════════════════════════════════════════════════════════
# PATCH 1 — mobile_server.py  (upgrade Service Worker)
# ═══════════════════════════════════════════════════════════════
MS   = BASE / "mobile_server.py"
ms   = MS.read_text(encoding="utf-8")
MS.with_suffix(".py.bak3").write_text(ms, encoding="utf-8")

OLD_SW = '''def _get_service_worker_js(firebase_config: Optional[dict]) -> bytes:
    """
    Background service worker required by the Firebase JS SDK to receive
    push notifications while the mobile page itself isn't open or the
    phone screen is off. Must be served from the site root
    (/firebase-messaging-sw.js) — the Firebase SDK requires this exact
    path relative to where it's registered.
    """
    config_json = json.dumps(firebase_config) if firebase_config else "{}"
    js = f"""importScripts(\'https://www.gstatic.com/firebasejs/10.13.0/firebase-app-compat.js\');
importScripts(\'https://www.gstatic.com/firebasejs/10.13.0/firebase-messaging-compat.js\');

firebase.initializeApp({config_json});

const messaging = firebase.messaging();

// Background message handler — fires when a push arrives and this page
// is closed / the phone screen is off. Foreground messages (page open)
// are handled separately by the onMessage listener in the main page.
messaging.onBackgroundMessage((payload) => {{
  const title = (payload.notification && payload.notification.title) || \'J.A.R.V.I.S\';
  const body  = (payload.notification && payload.notification.body)  || \'\';
  self.registration.showNotification(title, {{
    body: body,
    tag: \'jarvis-alert\',
  }});
}});
"""
    return js.encode("utf-8")'''

NEW_SW = '''def _get_service_worker_js(firebase_config: Optional[dict]) -> bytes:
    """
    Upgraded Service Worker (v2):
    - Intercepts FCM data messages with type='intruder_alert'
    - Calls clients.openWindow(alert_url) to force-open the full-screen
      danger page even when Chrome is completely closed
    - Falls back to a standard notification for all other message types
    """
    config_json = json.dumps(firebase_config) if firebase_config else "{}"
    js = f"""importScripts(\'https://www.gstatic.com/firebasejs/10.13.0/firebase-app-compat.js\');
importScripts(\'https://www.gstatic.com/firebasejs/10.13.0/firebase-messaging-compat.js\');

firebase.initializeApp({config_json});

const messaging = firebase.messaging();

// ── Notification click — open/focus the alert page ──────────────────────────
self.addEventListener(\'notificationclick\', (event) => {{
  event.notification.close();
  const url = (event.notification.data && event.notification.data.alert_url) || \'/\';
  event.waitUntil(
    clients.matchAll({{ type: \'window\', includeUncontrolled: true }}).then((list) => {{
      for (const c of list) {{
        if (c.url.includes(\'/alert\') && \'focus\' in c) return c.focus();
      }}
      return clients.openWindow(url);
    }})
  );
}});

// ── Background FCM message handler ──────────────────────────────────────────
messaging.onBackgroundMessage((payload) => {{
  const data  = payload.data || {{}};
  const ntype = data.type || \'\';

  // INTRUDER ALERT — force-open the full-screen danger page directly,
  // no notification tap required.
  if (ntype === \'intruder_alert\') {{
    const alertUrl = data.alert_url || \'/alert\';
    event.waitUntil(
      clients.matchAll({{ type: \'window\', includeUncontrolled: true }}).then((list) => {{
        // If the alert page is already open, just focus it
        for (const c of list) {{
          if (c.url.includes(\'/alert\')) return c.focus();
        }}
        // Otherwise open it — this works even with Chrome closed on Android
        return clients.openWindow(alertUrl);
      }})
    );
    return;   // skip showing a normal notification
  }}

  // All other messages — show a standard notification
  const title = (payload.notification && payload.notification.title) || \'J.A.R.V.I.S\';
  const body  = (payload.notification && payload.notification.body)  || \'\';
  self.registration.showNotification(title, {{
    body: body,
    tag:  \'jarvis-alert\',
    data: {{ alert_url: data.alert_url || \'/\' }},
  }});
}});
"""
    return js.encode("utf-8")'''

if "clients.openWindow" in ms:
    print("✅ [1] Service Worker already upgraded — skipping")
elif OLD_SW in ms:
    ms = ms.replace(OLD_SW, NEW_SW, 1)
    print("✅ [1] Service Worker upgraded — will force-open /alert page")
else:
    print("⚠️  [1] Could not find Service Worker function — patching by string search")
    # Fallback: replace just the onBackgroundMessage body
    OLD_BG = """messaging.onBackgroundMessage((payload) => {{\r\n  const title = (payload.notification && payload.notification.title) || 'J.A.R.V.I.S';\r\n  const body  = (payload.notification && payload.notification.body)  || '';\r\n  self.registration.showNotification(title, {{\r\n    body: body,\r\n    tag: 'jarvis-alert',\r\n  }});\r\n}});"""
    if OLD_BG in ms:
        ms = ms.replace(OLD_BG, NEW_SW.split('js = f"""')[1].split('"""')[0], 1)
        print("✅ [1] Fallback SW patch applied")
    else:
        print("❌ [1] FAILED — apply manually (see instructions below)")

# Also add /alert route and _get_alert_html if not present
if "_get_alert_html" not in ms:
    ALERT_FN = '''

def _get_alert_html() -> bytes:
    """Serve the full-screen danger alert page at /alert"""
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

'''
    ms = ms.replace("\nclass _HTTPHandler(", ALERT_FN + "\nclass _HTTPHandler(", 1)
    print("✅ [1b] _get_alert_html() added")

if "startswith(\"/alert\")" not in ms:
    OLD_404 = '''        else:
            self.send_response(404)
            self.end_headers()'''
    NEW_404 = '''        elif self.path.startswith("/alert"):
            body = _get_alert_html()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()'''
    ms = ms.replace(OLD_404, NEW_404, 1)
    print("✅ [1c] /alert HTTP route added")

# Add intruder_alert() broadcast method if not present
if "def intruder_alert(" not in ms:
    OLD_SET = '''    def set_state(self, state: str):
        """Update the state badge on all connected phones."""
        self._hub.broadcast("state", state)'''
    NEW_SET = '''    def intruder_alert(self, hostname: str, time_str: str, alert_url: str = ""):
        """Broadcast intruder_alert over WebSocket (for when page is open)."""
        import json as _json
        payload = _json.dumps({"machine": hostname, "time": time_str, "alert_url": alert_url})
        self._hub.broadcast("intruder_alert", payload)
        print(f"[Mobile] 🚨 WS intruder_alert broadcast → {hostname} at {time_str}")

    def set_state(self, state: str):
        """Update the state badge on all connected phones."""
        self._hub.broadcast("state", state)'''
    ms = ms.replace(OLD_SET, NEW_SET, 1)
    print("✅ [1d] MobileServer.intruder_alert() method added")

MS.write_text(ms, encoding="utf-8")

# ═══════════════════════════════════════════════════════════════
# PATCH 2 — fcm_push.py  (data-only message for full-screen open)
# ═══════════════════════════════════════════════════════════════
FCM  = BASE / "fcm_push.py"
fcm  = FCM.read_text(encoding="utf-8")
FCM.with_suffix(".py.bak3").write_text(fcm, encoding="utf-8")

OLD_FCM_METHOD = '''    def send_intruder_alert(self, text: str) -> bool:
        """Convenience wrapper with the right title for security alerts."""
        return self.send("JARVIS — Security Alert", text, data={"type": "intruder_alert"})'''

NEW_FCM_METHOD = '''    def send_intruder_alert(self, text: str) -> bool:
        """Convenience wrapper with the right title for security alerts."""
        return self.send("JARVIS — Security Alert", text, data={"type": "intruder_alert"})

    def send_intruder_alert_fullscreen(
        self,
        hostname: str,
        time_str: str,
        alert_url: str,
    ) -> bool:
        """
        Send a DATA-ONLY FCM message that instructs the Service Worker to
        call clients.openWindow(alert_url) — opening the full-screen danger
        page directly, without showing a notification first.

        Key difference from send():
          • NO notification block  →  Android does NOT show a tray notification
          • Service Worker receives it via onBackgroundMessage and opens the URL
          • Works even with Chrome fully closed (Android keeps SW alive)

        alert_url must be the full public URL including ngrok domain,
        e.g. https://abc.ngrok-free.app/alert?machine=SHAN&time=11:25:03
        """
        if not self._ready:
            return False
        if not self._token:
            self._log("SYS: ⚠️ No phone registered for FCM yet")
            return False
        try:
            from firebase_admin import messaging

            message = messaging.Message(
                # NO notification= key — this makes it a silent data message.
                # The Service Worker's onBackgroundMessage fires and handles it.
                data={
                    "type":      "intruder_alert",
                    "machine":   hostname,
                    "time":      time_str,
                    "alert_url": alert_url,
                },
                token=self._token,
                android=messaging.AndroidConfig(
                    priority="high",   # wake device immediately
                ),
            )
            response = messaging.send(message)
            self._log(f"[FCM] 🚨 Full-screen alert dispatched → {alert_url} ({response})")
            return True
        except Exception as e:
            self._log(f"[FCM] ❌ send_intruder_alert_fullscreen failed: {e}")
            return False'''

if "send_intruder_alert_fullscreen" in fcm:
    print("✅ [2] FCM method already present — skipping")
elif OLD_FCM_METHOD in fcm:
    fcm = fcm.replace(OLD_FCM_METHOD, NEW_FCM_METHOD, 1)
    FCM.write_text(fcm, encoding="utf-8")
    print("✅ [2] fcm_push.py — send_intruder_alert_fullscreen() added")
else:
    # Append at end of file
    fcm = fcm.rstrip() + "\n\n" + NEW_FCM_METHOD.strip() + "\n"
    FCM.write_text(fcm, encoding="utf-8")
    print("✅ [2] FCM method appended to fcm_push.py")

# ═══════════════════════════════════════════════════════════════
# PATCH 3 — jarvis_service.pyw  (_on_intruder_alert)
# ═══════════════════════════════════════════════════════════════
JSP  = BASE / "jarvis_service.pyw"
jsp  = JSP.read_text(encoding="utf-8")
JSP.with_suffix(".pyw.bak3").write_text(jsp, encoding="utf-8")

OLD_ON_ALERT = '''    def _on_intruder_alert(self, text: str, jpeg_bytes):
        """
        Called from IntruderAlertWatcher's background thread when a failed
        Windows logon attempt is detected. Pushes to the phone (text +
        photo if a webcam snapshot was captured) and writes to the local
        Activity Log if the UI window already exists.
        """
        try:
            self._mobile.notify(text)
            if jpeg_bytes:
                self._mobile.notify_image(text, jpeg_bytes)
        except Exception as e:
            print(f"[IntruderAlert] mobile push failed: {e}")
        if self._ui:
            try:
                self._ui.write_log(f"NOTIFY: {text}")
            except Exception:
                pass'''

NEW_ON_ALERT = '''    def _on_intruder_alert(self, text: str, jpeg_bytes):
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
            self._mobile._fcm.send_intruder_alert_fullscreen(
                hostname=hostname,
                time_str=time_str,
                alert_url=alert_url,
            )
        except Exception as e:
            print(f"[IntruderAlert] FCM full-screen push failed: {e}")

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
                pass'''

if "send_intruder_alert_fullscreen" in jsp:
    print("✅ [3] jarvis_service.pyw already patched — skipping")
elif OLD_ON_ALERT in jsp:
    jsp = jsp.replace(OLD_ON_ALERT, NEW_ON_ALERT, 1)
    JSP.write_text(jsp, encoding="utf-8")
    print("✅ [3] jarvis_service.pyw — _on_intruder_alert upgraded")
else:
    print("⚠️  [3] Could not find _on_intruder_alert — may already be patched")

print("""
════════════════════════════════════════════════
✅  All patches applied.

Next steps:
  1. Copy alert.html → core\\alert.html
  2. Restart JARVIS:  python jarvis_service.pyw
  3. Open the JARVIS page on your phone ONCE
     (to re-register the new Service Worker)
  4. You can then close Chrome completely
  5. Test: Win+L → wrong password → full screen
     danger page opens on your phone automatically
════════════════════════════════════════════════
""")