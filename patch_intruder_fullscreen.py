"""
patch_intruder_fullscreen.py
============================
Patches mobile_server.py to:
  1. Add a new 'intruder_alert' WebSocket message type that the phone
     handles by immediately redirecting to /alert (full-screen danger page)
  2. Add /alert HTTP route that serves alert.html from core/
  3. Add MobileServer.intruder_alert() method

Then patches jarvis_service.pyw _on_intruder_alert to call
  self._mobile.intruder_alert() instead of just self._mobile.notify()

Run once:  python patch_intruder_fullscreen.py
"""
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent

# ─────────────────────────────────────────────────────────────
# PATCH 1: mobile_server.py
# ─────────────────────────────────────────────────────────────
MS = BASE / "mobile_server.py"
ms = MS.read_text(encoding="utf-8")
(BASE / "mobile_server.py.bak2").write_text(ms, encoding="utf-8")

CHANGES = 0

# 1a — Add intruder_alert handler in JS onmessage block
OLD_JS = """        }} else if (t === 'notify_image') {{
          try {{
            const inner = JSON.parse(d);
            addImageAlert(inner.caption || 'Security alert', inner.image_b64 || '');
            if (Notification.permission === 'granted') {{
              new Notification('J.A.R.V.I.S — Security Alert', {{ body: inner.caption || '' }});
            }}
          }} catch(err) {{
            addLine('🚨 ' + d, 'alert');
          }}
        }}"""

NEW_JS = """        }} else if (t === 'notify_image') {{
          try {{
            const inner = JSON.parse(d);
            addImageAlert(inner.caption || 'Security alert', inner.image_b64 || '');
            if (Notification.permission === 'granted') {{
              new Notification('J.A.R.V.I.S — Security Alert', {{ body: inner.caption || '' }});
            }}
          }} catch(err) {{
            addLine('🚨 ' + d, 'alert');
          }}
        }} else if (t === 'intruder_alert') {{
          // Full-screen danger takeover — redirect immediately
          addLine('🚨 INTRUSION DETECTED — opening security alert...', 'notify');
          try {{
            const info = JSON.parse(d);
            const params = new URLSearchParams({{
              machine: info.machine || 'UNKNOWN',
              time:    info.time    || new Date().toTimeString().slice(0,8),
            }});
            window.location.href = '/alert?' + params.toString();
          }} catch(_) {{
            window.location.href = '/alert';
          }}
        }}"""

if OLD_JS in ms:
    ms = ms.replace(OLD_JS, NEW_JS, 1)
    CHANGES += 1
    print("✅ [1a] JS onmessage intruder_alert handler added")
else:
    print("⚠️  [1a] JS handler not found — already patched or file changed")

# 1b — Add /alert HTTP route in do_GET
OLD_GET = """        elif self.path == "/firebase-messaging-sw.js":
            body = _get_service_worker_js(self.firebase_config)
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()"""

NEW_GET = """        elif self.path == "/firebase-messaging-sw.js":
            body = _get_service_worker_js(self.firebase_config)
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/alert"):
            body = _get_alert_html()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()"""

if OLD_GET in ms:
    ms = ms.replace(OLD_GET, NEW_GET, 1)
    CHANGES += 1
    print("✅ [1b] /alert HTTP route added")
else:
    print("⚠️  [1b] /alert route not found — already patched or file changed")

# 1c — Add _get_alert_html() function before class _HTTPHandler
ALERT_FN = '''

def _get_alert_html() -> bytes:
    """Serve the full-screen danger alert page at /alert?machine=X&time=HH:MM:SS"""
    alert_html_path = BASE_DIR / "core" / "alert.html"
    if alert_html_path.exists():
        return alert_html_path.read_bytes()
    # Minimal fallback if alert.html missing
    return (
        b"<!DOCTYPE html><html><head><meta charset=UTF-8>"
        b"<meta name=viewport content='width=device-width,initial-scale=1'>"
        b"<title>JARVIS ALERT</title>"
        b"<style>body{background:#000;color:#f00;font-family:monospace;"
        b"display:flex;align-items:center;justify-content:center;"
        b"min-height:100vh;text-align:center;}"
        b"h1{font-size:2em;animation:f 0.8s infinite}"
        b"@keyframes f{50%{opacity:0}}</style></head>"
        b"<body><div><h1>&#9888; SECURITY ALERT &#9888;</h1>"
        b"<p>Someone is trying to unlock your system!</p></div></body></html>"
    )

'''

INSERT_BEFORE = "\nclass _HTTPHandler("
if ALERT_FN.strip() not in ms:
    ms = ms.replace(INSERT_BEFORE, ALERT_FN + INSERT_BEFORE, 1)
    CHANGES += 1
    print("✅ [1c] _get_alert_html() function inserted")
else:
    print("⚠️  [1c] _get_alert_html already present")

# 1d — Add intruder_alert() method to MobileServer after notify_image
OLD_METHOD = """    def set_state(self, state: str):
        \"\"\"Update the state badge on all connected phones.\"\"\"
        self._hub.broadcast(\"state\", state)"""

NEW_METHOD = """    def intruder_alert(self, hostname: str, time_str: str):
        \"\"\"
        Send a WebSocket 'intruder_alert' message that causes the phone's
        browser to immediately redirect to /alert (the full-screen danger page).
        Works only while the JARVIS mobile page is open on the phone.
        \"\"\"
        payload = json.dumps({"machine": hostname, "time": time_str})
        self._hub.broadcast("intruder_alert", payload)
        print(f"[Mobile] 🚨 Full-screen alert triggered → /alert")

    def set_state(self, state: str):
        \"\"\"Update the state badge on all connected phones.\"\"\"
        self._hub.broadcast(\"state\", state)"""

if OLD_METHOD in ms:
    ms = ms.replace(OLD_METHOD, NEW_METHOD, 1)
    CHANGES += 1
    print("✅ [1d] MobileServer.intruder_alert() method added")
else:
    print("⚠️  [1d] set_state not found — already patched or file changed")

MS.write_text(ms, encoding="utf-8")
print(f"\n  mobile_server.py: {CHANGES} change(s) applied")

# ─────────────────────────────────────────────────────────────
# PATCH 2: jarvis_service.pyw — _on_intruder_alert
# ─────────────────────────────────────────────────────────────
JS_PYW = BASE / "jarvis_service.pyw"
js = JS_PYW.read_text(encoding="utf-8")
(BASE / "jarvis_service.pyw.bak2").write_text(js, encoding="utf-8")

OLD_ALERT = """    def _on_intruder_alert(self, text: str, jpeg_bytes):
        \"\"\"
        Called from IntruderAlertWatcher's background thread when a failed
        Windows logon attempt is detected. Pushes to the phone (text +
        photo if a webcam snapshot was captured) and writes to the local
        Activity Log if the UI window already exists.
        \"\"\"
        try:
            self._mobile.notify(text)
            if jpeg_bytes:
                self._mobile.notify_image(text, jpeg_bytes)
        except Exception as e:
            print(f\"[IntruderAlert] mobile push failed: {e}\")
        if self._ui:
            try:
                self._ui.write_log(f\"NOTIFY: {text}\")
            except Exception:
                pass"""

NEW_ALERT = """    def _on_intruder_alert(self, text: str, jpeg_bytes):
        \"\"\"
        Called from IntruderAlertWatcher's background thread when a failed
        Windows logon attempt is detected.

        Two parallel paths:
          1. intruder_alert() — WebSocket push that immediately redirects
             the phone's browser to /alert (full-screen danger page).
             Works while the JARVIS mobile page is open on the phone.
          2. notify() + notify_image() — FCM push notification (any network)
             + webcam photo over WebSocket. Works even with the page closed.
        \"\"\"
        import socket as _sock
        hostname = _sock.gethostname()
        from datetime import datetime as _dt
        time_str = _dt.now().strftime(\"%H:%M:%S\")

        try:
            # Path 1: full-screen takeover (page must be open)
            self._mobile.intruder_alert(hostname=hostname, time_str=time_str)
        except Exception as e:
            print(f\"[IntruderAlert] full-screen alert failed: {e}\")

        try:
            # Path 2: FCM push + photo (works with page closed / off-network)
            self._mobile.notify(text)
            if jpeg_bytes:
                self._mobile.notify_image(text, jpeg_bytes)
        except Exception as e:
            print(f\"[IntruderAlert] mobile push failed: {e}\")

        if self._ui:
            try:
                self._ui.write_log(f\"NOTIFY: {text}\")
            except Exception:
                pass"""

if OLD_ALERT in js:
    js = js.replace(OLD_ALERT, NEW_ALERT, 1)
    JS_PYW.write_text(js, encoding="utf-8")
    print("✅ [2]  jarvis_service.pyw _on_intruder_alert patched")
else:
    print("⚠️  [2]  _on_intruder_alert not found — may already be patched")

print("\n✅ All done. Copy alert.html to core/, then restart JARVIS.")