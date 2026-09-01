"""
fix_sw_and_fcm.py
=================
Fixes two bugs introduced by the previous patch:

BUG 1 — Service Worker: used `event.waitUntil(...)` inside
  onBackgroundMessage but the Firebase compat SDK does NOT pass an
  `event` object to that callback — it crashes silently and the
  openWindow call never fires.
  FIX: use `self.clients.openWindow(url)` directly (returns a Promise,
  no event needed).

BUG 2 — jarvis_service.pyw: send_intruder_alert_fullscreen() exists
  in fcm_push.py but _on_intruder_alert was already patched to call it
  via self._mobile._fcm — however if the patched version didn't write
  correctly to disk the old version still runs.
  FIX: rewrite _on_intruder_alert completely and verify.

Run: python fix_sw_and_fcm.py
"""
from pathlib import Path
import re

BASE = Path(__file__).resolve().parent

# ══════════════════════════════════════════════════════════════
# FIX 1 — Rewrite Service Worker in mobile_server.py
# ══════════════════════════════════════════════════════════════
MS = BASE / "mobile_server.py"
ms = MS.read_text(encoding="utf-8")
MS.with_suffix(".py.bak_fix").write_text(ms, encoding="utf-8")

# Replace everything inside _get_service_worker_js with fixed version
OLD_SW_MARKER = "def _get_service_worker_js("
if OLD_SW_MARKER not in ms:
    print("❌ Could not find _get_service_worker_js in mobile_server.py")
else:
    # Find start and end of the function
    start = ms.index(OLD_SW_MARKER)
    # Find the next top-level def or class after this function
    rest = ms[start:]
    # Find end by looking for next def/class at column 0
    match = re.search(r'\ndef _get_alert_html|\nclass _HTTPHandler', rest)
    if match:
        func_end = start + match.start()
    else:
        print("❌ Could not find end of _get_service_worker_js")
        func_end = None

    if func_end:
        NEW_SW_FUNC = '''def _get_service_worker_js(firebase_config) -> bytes:
    """
    Service Worker v3 — fixed openWindow call.
    Uses self.clients.openWindow() directly (no event.waitUntil needed).
    onBackgroundMessage in Firebase compat SDK does NOT provide an event
    object — calling event.waitUntil() crashes silently.
    """
    import json as _json
    config_json = _json.dumps(firebase_config) if firebase_config else "{}"
    js = f"""importScripts(\'https://www.gstatic.com/firebasejs/10.13.0/firebase-app-compat.js\');
importScripts(\'https://www.gstatic.com/firebasejs/10.13.0/firebase-messaging-compat.js\');

firebase.initializeApp({config_json});
const messaging = firebase.messaging();

// ── Notification click — tap notification → open alert page ─────────────────
self.addEventListener(\'notificationclick\', function(event) {{
  event.notification.close();
  var url = (event.notification.data && event.notification.data.alert_url)
            ? event.notification.data.alert_url
            : self.registration.scope;
  event.waitUntil(
    clients.matchAll({{type: \'window\', includeUncontrolled: true}}).then(function(cs) {{
      for (var i = 0; i < cs.length; i++) {{
        if (cs[i].url.indexOf(\'/alert\') !== -1 && \'focus\' in cs[i]) {{
          return cs[i].focus();
        }}
      }}
      if (clients.openWindow) return clients.openWindow(url);
    }})
  );
}});

// ── Background FCM message ───────────────────────────────────────────────────
messaging.onBackgroundMessage(function(payload) {{
  var data  = payload.data  || {{}};
  var ntype = data.type     || \'\';
  var alertUrl = data.alert_url || (self.registration.scope + \'alert\');

  if (ntype === \'intruder_alert\') {{
    // DATA-ONLY message — open the full-screen danger page directly.
    // self.clients is always available in Service Worker scope.
    // We do NOT call event.waitUntil because there is no event here.
    self.clients.matchAll({{type: \'window\', includeUncontrolled: true}})
      .then(function(cs) {{
        for (var i = 0; i < cs.length; i++) {{
          if (cs[i].url.indexOf(\'/alert\') !== -1) {{
            cs[i].focus();
            return;
          }}
        }}
        self.clients.openWindow(alertUrl);
      }});
    // Also show a notification as fallback (in case openWindow is blocked)
    return self.registration.showNotification(\'\\u26a0 SECURITY ALERT\', {{
      body:    \'Someone tried to unlock \' + (data.machine || \'your system\') + \'!\',
      tag:     \'jarvis-intruder\',
      renotify: true,
      requireInteraction: true,
      data:    {{ alert_url: alertUrl }},
    }});
  }}

  // All other messages — standard notification
  var title = (payload.notification && payload.notification.title) || \'J.A.R.V.I.S\';
  var body  = (payload.notification && payload.notification.body)  || \'\';
  return self.registration.showNotification(title, {{
    body: body,
    tag:  \'jarvis-alert\',
    data: {{ alert_url: alertUrl }},
  }});
}});
"""
    return js.encode("utf-8")

'''
        ms = ms[:start] + NEW_SW_FUNC + ms[func_end:]
        print("✅ [1] Service Worker rewritten — fixed openWindow, no event.waitUntil")

MS.write_text(ms, encoding="utf-8")

# ══════════════════════════════════════════════════════════════
# FIX 2 — Rewrite _on_intruder_alert in jarvis_service.pyw
# ══════════════════════════════════════════════════════════════
JSP = BASE / "jarvis_service.pyw"
jsp = JSP.read_text(encoding="utf-8")
JSP.with_suffix(".pyw.bak_fix").write_text(jsp, encoding="utf-8")

# Find and replace _on_intruder_alert — match any version
START_MARKER = "    def _on_intruder_alert(self, text: str, jpeg_bytes):"
END_MARKER   = "    def _on_mobile_command("

if START_MARKER not in jsp:
    print("❌ Could not find _on_intruder_alert in jarvis_service.pyw")
else:
    start = jsp.index(START_MARKER)
    end   = jsp.index(END_MARKER, start)

    NEW_METHOD = '''    def _on_intruder_alert(self, text: str, jpeg_bytes):
        """
        Intruder alert handler — three parallel paths:

        PATH 1 (FCM silent data push):
          Sends data-only FCM to phone → Service Worker wakes →
          self.clients.openWindow(alert_url) → full-screen danger page opens.
          Works even with Chrome fully closed.

        PATH 2 (WebSocket broadcast):
          If JARVIS page is open on phone, redirects it to /alert instantly.

        PATH 3 (Telegram):
          Hacker-themed message always arrives regardless of network.
        """
        import socket as _sock
        from datetime import datetime as _dt
        from urllib.parse import urlencode as _ue

        hostname = _sock.gethostname()
        time_str = _dt.now().strftime("%H:%M:%S")

        # Build public alert URL — try ngrok first, fall back to LAN
        base_url = self._mobile.url   # http://LAN-IP:8080
        try:
            import urllib.request as _ur, json as _js
            with _ur.urlopen("http://127.0.0.1:4040/api/tunnels", timeout=2) as r:
                for t in _js.loads(r.read()).get("tunnels", []):
                    if t.get("proto") == "https":
                        base_url = t["public_url"]
                        break
        except Exception:
            pass

        alert_url = f"{base_url}/alert?{_ue({'machine': hostname, 'time': time_str})}"
        print(f"[IntruderAlert] 🔗 Alert URL: {alert_url}")

        # PATH 1 — FCM silent data push → Service Worker opens /alert
        try:
            ok = self._mobile._fcm.send_intruder_alert_fullscreen(
                hostname=hostname,
                time_str=time_str,
                alert_url=alert_url,
            )
            print(f"[IntruderAlert] FCM fullscreen dispatch: {'✅ sent' if ok else '❌ failed'}")
        except Exception as e:
            print(f"[IntruderAlert] FCM fullscreen error: {e}")

        # PATH 2 — WebSocket redirect (page open)
        try:
            self._mobile.intruder_alert(
                hostname=hostname,
                time_str=time_str,
                alert_url=alert_url,
            )
        except Exception as e:
            print(f"[IntruderAlert] WS broadcast error: {e}")

        # PATH 3 — Telegram + FCM notification (always-on backup)
        try:
            self._mobile.notify(text)
            if jpeg_bytes:
                self._mobile.notify_image(text, jpeg_bytes)
        except Exception as e:
            print(f"[IntruderAlert] notify error: {e}")

        if self._ui:
            try:
                self._ui.write_log(f"NOTIFY: {text}")
            except Exception:
                pass

    def _on_mobile_command('''

    jsp = jsp[:start] + NEW_METHOD + jsp[end + len("    def _on_mobile_command("):]
    JSP.write_text(jsp, encoding="utf-8")
    print("✅ [2] _on_intruder_alert rewritten with explicit debug prints")

print("""
════════════════════════════════════════════════
✅  Fixes applied.

Steps:
  1. Restart JARVIS: python jarvis_service.pyw
  2. Open ngrok URL on phone, wait 5s, close Chrome
  3. Win+L → wrong password → check console for:
       [IntruderAlert] FCM fullscreen dispatch: ✅ sent
  4. Danger page should open on phone automatically
════════════════════════════════════════════════
""")