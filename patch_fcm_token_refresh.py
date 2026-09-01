"""
patch_fcm_token_refresh.py
==========================
Adds POST /register-token endpoint to mobile_server.py so the phone
can push a fresh FCM token to the PC automatically every time the
JARVIS mobile app is opened — no ngrok, no WebSocket needed.

Run once:
    python patch_fcm_token_refresh.py

Then restart JARVIS:
    python jarvis_service.pyw
"""

from pathlib import Path
import re, sys, shutil

BASE_DIR   = Path(__file__).resolve().parent
TARGET     = BASE_DIR / "mobile_server.py"
BACKUP     = BASE_DIR / "mobile_server.py.bak"

if not TARGET.exists():
    print(f"❌  Not found: {TARGET}")
    sys.exit(1)

# ── backup ────────────────────────────────────────────────────────────────────
shutil.copy2(TARGET, BACKUP)
print(f"✅  Backup saved → {BACKUP.name}")

src = TARGET.read_text(encoding="utf-8")

# ── check not already patched ─────────────────────────────────────────────────
if "/register-token" in src:
    print("ℹ️   Patch already applied — nothing to do.")
    sys.exit(0)

# ── PATCH 1: add do_POST to _HTTPHandler ──────────────────────────────────────
# Insert before the log_message method which is right after do_GET
OLD_LOG = "    def log_message(self, fmt, *args):\n        pass   # suppress default access log spam"

NEW_POST = '''\
    def do_POST(self):
        """
        POST /register-token
        Body: {"token": "<fcm-device-token>"}
        Called by the mobile app on every launch to refresh the saved
        FCM token so the watcher service always has a valid one.
        """
        if self.path == "/register-token":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body   = self.rfile.read(length)
                import json as _json
                data   = _json.loads(body.decode("utf-8"))
                token  = data.get("token", "").strip()
                if token:
                    TOKEN_STORE = BASE_DIR / "memory" / "fcm_token.json"
                    TOKEN_STORE.parent.mkdir(parents=True, exist_ok=True)
                    TOKEN_STORE.write_text(
                        _json.dumps({"token": token}), encoding="utf-8"
                    )
                    print(f"[Mobile] 📱 FCM token refreshed via HTTP ({token[:12]}...)")
                    resp = _json.dumps({"ok": True}).encode()
                else:
                    resp = _json.dumps({"ok": False, "error": "empty token"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(resp)
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                print(f"[Mobile] ⚠️  /register-token error: {e}")
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        # CORS preflight for the mobile web app
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

'''

NEW_LOG = NEW_POST + OLD_LOG

if OLD_LOG not in src:
    print("❌  Could not find insertion point in mobile_server.py")
    print("    Expected to find: def log_message(self, fmt, *args):")
    sys.exit(1)

src = src.replace(OLD_LOG, NEW_LOG, 1)

# ── PATCH 2: inject JS into the mobile web app to POST token on every open ───
# Find the section where the FCM token is sent via WebSocket and ALSO post it via HTTP

OLD_WS_SEND = "ws.send(JSON.stringify({type: 'register_token', data: token}}));"

# This exact string may have double braces due to f-string escaping - find it flexibly
ws_send_pattern = r"(ws\.send\(JSON\.stringify\(\{+type: 'register_token', data: token\}+\)\);)"

match = re.search(ws_send_pattern, src)
if match:
    old_ws = match.group(0)
    new_ws = old_ws + """
          // Also POST token via HTTP so the watcher service always has it fresh
          fetch('/register-token', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({token: token})
          }).then(r => r.json()).then(d => {
            if (d.ok) addLine('SYS: 📱 FCM token refreshed on PC (alerts work after cold boot)', 'sys');
          }).catch(() => {});"""
    src = src.replace(old_ws, new_ws, 1)
    print("✅  Patch 2 applied — JS will POST token on every app open")
else:
    print("⚠️   Could not find WebSocket token send in JS — Patch 2 skipped")
    print("    FCM token refresh via HTTP POST still works when called manually")

# ── write ─────────────────────────────────────────────────────────────────────
TARGET.write_text(src, encoding="utf-8")
print("✅  Patch 1 applied — POST /register-token endpoint added")
print()
print("=" * 55)
print("  Restart JARVIS now:")
print("    python jarvis_service.pyw")
print()
print("  How it works after this patch:")
print("  • Every time you open the JARVIS mobile app,")
print("    it POSTs the fresh FCM token to the PC via")
print("    local WiFi (port 8080) — no ngrok needed.")
print("  • The watcher service reads the token from disk")
print("    on every alert, so it always uses the latest.")
print("  • FCM alerts will work after every cold boot as")
print("    long as you open the app once after logging in.")
print("=" * 55)
