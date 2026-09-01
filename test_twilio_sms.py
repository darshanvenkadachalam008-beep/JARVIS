"""
test_twilio_sms.py — standalone Twilio SMS isolation test.

Run this directly from the Mark-XXXIX-OR-main folder:

    python test_twilio_sms.py

It reads the same config/api_keys.json your app uses, makes the exact
same Twilio API call _notify_account_holder() makes, and prints the
FULL raw Twilio response (including error codes/messages) instead of
swallowing it — so you can see exactly why the SMS isn't arriving.
"""

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parent / "config" / "api_keys.json"


def main():
    if not CONFIG_PATH.exists():
        print(f"❌ Config not found at {CONFIG_PATH}")
        return

    cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    sid = cfg.get("twilio_account_sid") or ""
    token = cfg.get("twilio_auth_token") or ""
    from_num = cfg.get("twilio_from_number") or ""
    to_num = cfg.get("twilio_to_number") or ""

    print("── Config loaded ──")
    print(f"  Account SID : {sid[:6]}...{sid[-4:] if len(sid) > 10 else ''}")
    print(f"  From number : {from_num}")
    print(f"  To number   : {to_num}")
    print()

    if not (sid and token and from_num and to_num):
        print("❌ One or more twilio_* fields are missing/empty in config/api_keys.json.")
        return

    body = (
        "FusionShield AI Security Notice: TEST MESSAGE - this is a direct "
        "Twilio isolation test, not routed through the app."
    )
    payload = urllib.parse.urlencode({"To": to_num, "From": from_num, "Body": body}).encode("utf-8")
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

    print("── Sending request to Twilio ──")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())
            print(f"✅ HTTP {resp.status}")
            print(json.dumps(result, indent=2))
            print()
            print(f"Twilio-reported status: {result.get('status')}")
            print(f"Message SID: {result.get('sid')}")
            if result.get("status") in ("failed", "undelivered"):
                print("⚠️  Twilio accepted the request but flagged it failed/undelivered "
                      "immediately — check error_code/error_message above.")
    except urllib.error.HTTPError as e:
        # This is the important branch — Twilio's real error body, which
        # the app's try/except was silently discarding.
        err_body = e.read().decode(errors="replace")
        print(f"❌ HTTP {e.code} {e.reason}")
        try:
            print(json.dumps(json.loads(err_body), indent=2))
        except Exception:
            print(err_body)
    except urllib.error.URLError as e:
        print(f"❌ Network error reaching Twilio: {e.reason}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


if __name__ == "__main__":
    main()