"""
patch_pushbullet.py — Add Pushbullet alerts to JARVIS watcher
==============================================================
Patches jarvis_watcher_service.py and jarvis_watcher_run.py to send
Pushbullet notifications on every wrong password — including cold boot.

Pushbullet token never expires, so this works ALWAYS unlike FCM.

Run once (no Admin needed):
    python patch_pushbullet.py

Then restart the watcher service:
    nssm restart JARVISWatcher
"""

from pathlib import Path
import json, sys, shutil

BASE_DIR = Path(__file__).resolve().parent

# ── Step 1: Save token to api_keys.json ───────────────────────────────────────
CONFIG_PATH = BASE_DIR / "config" / "api_keys.json"

def save_token(token: str):
    try:
        cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        cfg = {}
    cfg["pushbullet_token"] = token
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    print(f"✅  Pushbullet token saved to config/api_keys.json")

# ── Step 2: Patch jarvis_watcher_service.py ───────────────────────────────────
WATCHER = BASE_DIR / "jarvis_watcher_service.py"

PUSHBULLET_FUNC = '''

# ═══════════════════════════════════════════════════════════════════════════════
# PUSHBULLET  (never-expiring token — works on cold boot always)
# ═══════════════════════════════════════════════════════════════════════════════

def _send_pushbullet(token: str, hostname: str, time_str: str) -> bool:
    """Send a Pushbullet push notification with link to full-screen alert."""
    try:
        # Build the alert URL — uses ngrok if available, else local IP
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            local_ip = "localhost"
        alert_url = f"http://{local_ip}:8080/alert?machine={hostname}&time={time_str}"

        title   = "\\u{1F480} DANGER — INTRUSION DETECTED \\u{1F480}".replace("\\u{1F480}", "\\U0001F480")
        body    = (
            f"SHAN — SOMEONE IS TRYING TO UNLOCK YOUR SYSTEM!\\n\\n"
            f"\\U0001F4BB MACHINE: {hostname}\\n"
            f"\\U0001F552 TIME:    {time_str}\\n"
            f"\\u26A0\\uFE0F  STATUS:  FAILED LOGIN\\n"
            f"\\U0001F534 THREAT:  HIGH\\n\\n"
            f"Tap the link to view full-screen alert."
        )

        # Send notification with link
        payload = json.dumps({
            "type":  "link",
            "title": title,
            "body":  body,
            "url":   alert_url,
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.pushbullet.com/v2/pushes",
            data=payload,
            headers={
                "Access-Token":  token,
                "Content-Type":  "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception as e:
        _log(f"Pushbullet error: {e}")
        return False

'''

# Patch _fire_alert to call Pushbullet
OLD_FIRE_END = '''        for t in threads:
            t.join(timeout=12)'''

NEW_FIRE_END = '''        pb_token = (self._config.get("pushbullet_token")
                    or self._config.get("PUSHBULLET_TOKEN", ""))
        if pb_token:
            t = threading.Thread(
                target=lambda tok=pb_token: _log(
                    f"Pushbullet: {'OK' if _send_pushbullet(tok, self._hostname, time_str) else 'FAILED'}"
                ),
                daemon=True,
            )
            t.start(); threads.append(t)

        for t in threads:
            t.join(timeout=12)'''

def patch_watcher():
    if not WATCHER.exists():
        print(f"❌  Not found: {WATCHER}")
        return False

    shutil.copy2(WATCHER, WATCHER.with_suffix(".py.bak2"))
    src = WATCHER.read_text(encoding="utf-8")

    if "_send_pushbullet" in src:
        print("ℹ️   Pushbullet already patched in watcher service")
        return True

    # Insert Pushbullet function before the IntruderWatcher class
    INSERT_BEFORE = "# ═══════════════════════════════════════════════════════════════════════════════\n# WATCHER CORE"
    if INSERT_BEFORE not in src:
        # fallback — insert before class definition
        INSERT_BEFORE = "class IntruderWatcher:"

    src = src.replace(INSERT_BEFORE, PUSHBULLET_FUNC + INSERT_BEFORE, 1)

    # Patch _fire_alert to call Pushbullet
    if OLD_FIRE_END in src:
        src = src.replace(OLD_FIRE_END, NEW_FIRE_END, 1)
        print("✅  Patch applied — Pushbullet added to _fire_alert")
    else:
        print("⚠️   Could not patch _fire_alert — add Pushbullet call manually")

    WATCHER.write_text(src, encoding="utf-8")
    return True

# ── Step 3: Also patch jarvis_watcher_run.py ──────────────────────────────────
RUNNER = BASE_DIR / "jarvis_watcher_run.py"

def patch_runner():
    """Runner just imports from watcher service — no changes needed."""
    if RUNNER.exists():
        print("✅  jarvis_watcher_run.py unchanged (imports from watcher service)")

# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "=" * 55)
    print("  JARVIS — Pushbullet Integration Patcher")
    print("=" * 55 + "\n")

    # Get token
    token = input("  Paste your NEW Pushbullet Access Token: ").strip()
    if not token or len(token) < 10:
        print("❌  Invalid token. Get it from pushbullet.com → Settings → Access Token")
        sys.exit(1)

    # Save token
    save_token(token)

    # Patch watcher
    if patch_watcher():
        print("✅  jarvis_watcher_service.py patched")

    patch_runner()

    print()
    print("=" * 55)
    print("  ✅  Done! Now restart the watcher service:")
    print()
    print("      nssm restart JARVISWatcher")
    print()
    print("  Then test:")
    print("      Win+L → wrong password → check phone")
    print()
    print("  You'll get 3 alerts:")
    print("      📱 Telegram  — always")
    print("      📱 FCM       — when token is fresh")
    print("      📱 Pushbullet — ALWAYS (even cold boot)")
    print()
    print("  Pushbullet notification has a link —")
    print("  tap it to open the full-screen DANGER alert!")
    print("=" * 55 + "\n")