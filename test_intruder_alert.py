"""
test_intruder_alert.py — Manual End-to-End Test for Intruder Alert Pipeline
===========================================================================
Allows on-demand verification of the intruder alert pipeline without
requiring a real failed Windows login attempt.

Usage:
  python test_intruder_alert.py
  python test_intruder_alert.py --fcm-only
  python test_intruder_alert.py --telegram-only
"""

import sys
import time
import argparse
from datetime import datetime
from pathlib import Path

# Ensure UTF-8 console output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


def check_fcm_token() -> tuple[bool, str]:
    token_file = BASE_DIR / "memory" / "fcm_token.json"
    if not token_file.exists():
        return False, "memory/fcm_token.json does not exist."
    try:
        import json
        data = json.loads(token_file.read_text(encoding="utf-8"))
        token = data.get("token")
        if not token:
            return False, "memory/fcm_token.json contains no token."
        return True, token
    except Exception as e:
        return False, f"Failed to read fcm_token.json: {e}"


def test_fcm_push():
    print("\n" + "=" * 60)
    print("1. TESTING FCM PUSH NOTIFICATION CHANNEL")
    print("=" * 60)

    has_token, token_info = check_fcm_token()
    if not has_token:
        print(f"❌ FCM Token Check Failed: {token_info}")
        print("   To fix: Open the mobile web companion on your phone while on WiFi.")
        return False

    print(f"✅ FCM Token found in memory/fcm_token.json: {token_info[:25]}... (len={len(token_info)})")

    try:
        from fcm_push import FCMPusher
        pusher = FCMPusher(log_fn=print)
        if not pusher.configured:
            print("❌ FCMPusher is not fully configured (check Firebase service account / token).")
            return False

        print("📡 Sending test notification via FCM...")
        ok = pusher.send(
            title="🚨 JARVIS Test Alert",
            body=f"Manual intruder alert test at {datetime.now().strftime('%H:%M:%S')}",
            data={"type": "test_alert"}
        )
        if ok:
            print("✅ FCM test push dispatched successfully to your phone!")
        else:
            print("❌ FCM test push failed. Check the error log above.")
        return ok
    except Exception as e:
        print(f"❌ Error testing FCM: {e}")
        return False


def test_telegram_alert():
    print("\n" + "=" * 60)
    print("2. TESTING TELEGRAM ALERT CHANNEL")
    print("=" * 60)
    try:
        from core.telegram_alert import TelegramAlerter
        alerter = TelegramAlerter()
        if not alerter.configured:
            print("⚠️ Telegram is NOT configured in config/api_keys.json.")
            print("   Required keys in config/api_keys.json:")
            print("     - telegram_bot_token : Your Telegram Bot token from @BotFather")
            print("     - telegram_chat_id   : Your Telegram Chat ID from @userinfobot")
            return False

        print("📡 Sending test alert message via Telegram...")
        ok = alerter.send_alert(
            text="🧪 Manual test alert from JARVIS test_intruder_alert.py",
            hostname="JARVIS-TEST-PC",
            time_str=datetime.now().strftime("%H:%M:%S")
        )
        if ok:
            print("✅ Telegram alert sent successfully!")
        else:
            print("❌ Telegram alert failed to send.")
        return ok
    except Exception as e:
        print(f"❌ Error testing Telegram: {e}")
        return False


def test_intruder_watcher_pipeline():
    print("\n" + "=" * 60)
    print("3. TESTING FULL INTRUDER ALERT PIPELINE (SYNTHETIC ALERT)")
    print("=" * 60)

    from core.intruder_alert import IntruderAlertWatcher

    alert_received = []

    def mock_on_alert(text: str, jpeg_bytes):
        print(f"\n[Mock on_alert Callback] Received alert:")
        print(f"  - Message: {text}")
        if jpeg_bytes:
            print(f"  - Snapshot: {len(jpeg_bytes)} bytes JPEG captured")
        else:
            print("  - Snapshot: None")
        alert_received.append((text, bool(jpeg_bytes)))

    watcher = IntruderAlertWatcher(on_alert=mock_on_alert, log_fn=print)
    print("Firing synthetic alert...")
    watcher.fire_synthetic_alert(
        custom_msg="🚨 SYNTHETIC TEST: Intruder alert pipeline verification"
    )

    # Wait briefly for background threads (Telegram send, etc.)
    time.sleep(2.5)

    if alert_received:
        print("\n✅ Full intruder alert pipeline test completed successfully!")
    else:
        print("\n❌ Pipeline test did not complete as expected.")


def main():
    parser = argparse.ArgumentParser(description="Test JARVIS Intruder Alert Pipeline")
    parser.add_argument("--fcm-only", action="store_true", help="Test FCM push only")
    parser.add_argument("--telegram-only", action="store_true", help="Test Telegram alert only")
    args = parser.parse_args()

    print("═══════════════════════════════════════════════════════════════")
    print("        JARVIS INTRUDER ALERT PIPELINE DIAGNOSTIC & TEST       ")
    print("═══════════════════════════════════════════════════════════════")

    if args.fcm_only:
        test_fcm_push()
    elif args.telegram_only:
        test_telegram_alert()
    else:
        test_fcm_push()
        test_telegram_alert()
        test_intruder_watcher_pipeline()

    print("\n═══════════════════════════════════════════════════════════════")
    print("Diagnostic complete.")


if __name__ == "__main__":
    main()
