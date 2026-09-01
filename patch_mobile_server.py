"""
patch_mobile_server.py — adds /alert route to mobile_server.py
Run once: python patch_mobile_server.py
"""
import sys
from pathlib import Path

BASE    = Path(__file__).resolve().parent
TARGET  = BASE / "mobile_server.py"
BACKUP  = BASE / "mobile_server.py.bak"

OLD = '''        elif self.path == "/firebase-messaging-sw.js":
            body = _get_service_worker_js(self.firebase_config)
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()'''

NEW = '''        elif self.path == "/firebase-messaging-sw.js":
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
            self.end_headers()'''

ALERT_FN = '''

def _get_alert_html() -> bytes:
    """Serve the full-screen danger alert page at /alert?machine=X&time=HH:MM:SS"""
    alert_html_path = BASE_DIR / "core" / "alert.html"
    if alert_html_path.exists():
        return alert_html_path.read_bytes()
    # Fallback minimal page if alert.html not found
    return b"""<!DOCTYPE html><html><head><meta charset=UTF-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>JARVIS ALERT</title>
<style>body{background:#000;color:#f00;font-family:monospace;display:flex;
align-items:center;justify-content:center;min-height:100vh;text-align:center;}
h1{font-size:2em;animation:f 0.8s infinite}@keyframes f{50%{opacity:0}}</style>
</head><body><div><h1>&#9888; SECURITY ALERT &#9888;</h1>
<p>Someone is trying to unlock your system!</p></div></body></html>"""

'''

src = TARGET.read_text(encoding="utf-8")

if "/alert" in src:
    print("✅ /alert route already present — nothing to do.")
    sys.exit(0)

if OLD not in src:
    print("❌ Could not find the patch target in mobile_server.py.")
    print("   The file may have changed. Apply the change manually.")
    sys.exit(1)

# Make backup
BACKUP.write_text(src, encoding="utf-8")
print(f"  Backup saved → {BACKUP.name}")

# Inject _get_alert_html() before class _HTTPHandler
insert_before = "\nclass _HTTPHandler("
src = src.replace(insert_before, ALERT_FN + insert_before, 1)

# Patch do_GET
src = src.replace(OLD, NEW, 1)

TARGET.write_text(src, encoding="utf-8")
print("✅ mobile_server.py patched — /alert route added.")
print("   Restart JARVIS for the change to take effect.")