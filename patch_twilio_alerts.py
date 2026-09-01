"""
patch_twilio_alerts.py — Add Twilio SMS + Voice Call to JARVIS watcher
=======================================================================
Adds both SMS and Voice Call alerts to jarvis_watcher_service.py.
When wrong password detected:
  1. Voice call fires first — rings your phone loudly
  2. SMS sent as backup — arrives even if call missed

Run once:
    python patch_twilio_alerts.py

Then restart watcher:
    nssm restart JARVISWatcher
"""

from pathlib import Path
import sys, shutil, json

BASE_DIR = Path(__file__).resolve().parent
WATCHER  = BASE_DIR / "jarvis_watcher_service.py"
CONFIG   = BASE_DIR / "config" / "api_keys.json"

# ── Check watcher exists ───────────────────────────────────────────────────────
if not WATCHER.exists():
    print(f"ERROR: {WATCHER} not found")
    sys.exit(1)

# ── Backup ────────────────────────────────────────────────────────────────────
shutil.copy2(WATCHER, WATCHER.with_suffix(".py.bak_twilio"))
print("Backup saved")

src = WATCHER.read_text(encoding="utf-8")

# ── Check already patched ─────────────────────────────────────────────────────
if "_send_twilio_sms" in src:
    print("Twilio already patched")
else:
    # ── Twilio functions to inject ─────────────────────────────────────────────
    TWILIO_CODE = '''

# ═══════════════════════════════════════════════════════════════════════════════
# TWILIO SMS + VOICE CALL
# Works with just mobile signal — no internet needed on phone
# ═══════════════════════════════════════════════════════════════════════════════

def _send_twilio_sms(sid: str, token: str, from_num: str, to_num: str,
                     hostname: str, time_str: str) -> bool:
    """Send SMS alert via Twilio."""
    try:
        msg = (
            f"JARVIS SECURITY ALERT\\n\\n"
            f"MACHINE: {hostname}\\n"
            f"TIME: {time_str}\\n"
            f"STATUS: FAILED LOGIN\\n"
            f"THREAT: HIGH\\n\\n"
            f"Someone is trying to unlock your system RIGHT NOW!\\n\\n"
            f"- J.A.R.V.I.S MARK-XXXIX"
        )
        import base64
        payload = urllib.parse.urlencode({
            "To":   to_num,
            "From": from_num,
            "Body": msg,
        }).encode("utf-8")
        url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
        credentials = base64.b64encode(f"{sid}:{token}".encode()).decode()
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
            return result.get("status") not in ("failed", "undelivered")
    except Exception as e:
        _log(f"Twilio SMS error: {e}")
        return False


def _send_twilio_call(sid: str, token: str, from_num: str, to_num: str,
                      hostname: str, time_str: str) -> bool:
    """Make a voice call alert via Twilio with spoken message."""
    try:
        import base64
        # TwiML — spoken message during the call
        twiml = (
            f"<Response>"
            f"<Say voice=\\"alice\\" loop=\\"3\\">"
            f"Alert! Alert! This is J.A.R.V.I.S Security System. "
            f"Danger! Someone is attempting to unlock {hostname} computer right now! "
            f"Time of intrusion: {time_str}. "
            f"This is a high priority security alert. "
            f"Please check your system immediately. "
            f"Alert! Alert!"
            f"</Say>"
            f"</Response>"
        )
        payload = urllib.parse.urlencode({
            "To":    to_num,
            "From":  from_num,
            "Twiml": twiml,
        }).encode("utf-8")
        url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Calls.json"
        credentials = base64.b64encode(f"{sid}:{token}".encode()).decode()
        req = urllib.request.Request(
            url, data=payload,
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type":  "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())
            return result.get("status") not in ("failed",)
    except Exception as e:
        _log(f"Twilio Call error: {e}")
        return False

'''

    # Insert before WATCHER CORE section
    INSERT_BEFORE = "# ═══════════════════════════════════════════════════════════════════════════════\n# WATCHER CORE"
    if INSERT_BEFORE not in src:
        INSERT_BEFORE = "class IntruderWatcher:"

    src = src.replace(INSERT_BEFORE, TWILIO_CODE + INSERT_BEFORE, 1)

    # Add urllib.parse import if not present
    if "import urllib.parse" not in src:
        src = src.replace(
            "import urllib.error",
            "import urllib.error\nimport urllib.parse"
        )

    print("Twilio functions added")

# ── Patch _fire_alert to call Twilio ──────────────────────────────────────────
if "_send_twilio_sms" in src and "twilio_account_sid" not in src:
    OLD = '''        for t in threads:
            t.join(timeout=12)'''

    NEW = '''        # Twilio SMS + Voice Call
        tw_sid    = (self._config.get("twilio_account_sid") or "")
        tw_token  = (self._config.get("twilio_auth_token") or "")
        tw_from   = (self._config.get("twilio_from_number") or "")
        tw_to     = (self._config.get("twilio_to_number") or "")
        tw_ok     = all([tw_sid, tw_token, tw_from, tw_to])

        if tw_ok:
            # Voice call first — rings loudly even on silent
            t = threading.Thread(
                target=lambda: _log(
                    f"Twilio Call: {'OK' if _send_twilio_call(tw_sid, tw_token, tw_from, tw_to, self._hostname, time_str) else 'FAILED'}"
                ),
                daemon=True,
            )
            t.start(); threads.append(t)

            # SMS backup
            t = threading.Thread(
                target=lambda: _log(
                    f"Twilio SMS: {'OK' if _send_twilio_sms(tw_sid, tw_token, tw_from, tw_to, self._hostname, time_str) else 'FAILED'}"
                ),
                daemon=True,
            )
            t.start(); threads.append(t)

        for t in threads:
            t.join(timeout=12)'''

    if OLD in src:
        src = src.replace(OLD, NEW, 1)
        print("_fire_alert patched with Twilio")
    else:
        print("WARNING: Could not patch _fire_alert — already patched or structure changed")

WATCHER.write_text(src, encoding="utf-8")

# ── Print setup instructions ───────────────────────────────────────────────────
print()
print("=" * 60)
print("  TWILIO SETUP — Add your credentials")
print("=" * 60)
print()
print("  Run this in PowerShell with YOUR actual values:")
print()
print("""  $c = Get-Content "D:\\Mark-XXXIX-OR-main\\Mark-XXXIX-OR-main\\config\\api_keys.json" | ConvertFrom-Json
  $c | Add-Member -NotePropertyName "twilio_account_sid"  -NotePropertyValue "ACxxxxxxxx" -Force
  $c | Add-Member -NotePropertyName "twilio_auth_token"   -NotePropertyValue "your_token" -Force
  $c | Add-Member -NotePropertyName "twilio_from_number"  -NotePropertyValue "+1xxxxxxxxxx" -Force
  $c | Add-Member -NotePropertyName "twilio_to_number"    -NotePropertyValue "+91xxxxxxxxxx" -Force
  $c | ConvertTo-Json | Set-Content "D:\\Mark-XXXIX-OR-main\\Mark-XXXIX-OR-main\\config\\api_keys.json"
  Write-Host "Saved!" """)
print()
print("  Then restart watcher:")
print("    nssm stop JARVISWatcher")
print("    nssm start JARVISWatcher")
print()
print("  On wrong password you will get:")
print("    📞 Voice call — rings loudly even on silent")
print("    💬 SMS — arrives even with no data, just signal")
print("=" * 60)
