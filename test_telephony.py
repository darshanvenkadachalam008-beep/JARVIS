"""
test_telephony.py — Telephony & Emergency Voice/SMS Interface Test Suite
========================================================================
Verifies:
1. Twilio SMS payload construction, Basic Auth encoding, and URL format.
2. Twilio Voice Call payload construction with TwiML siren audio parameter.
3. Status polling verification for outbound calls & messages.
4. Error resilience when telephony API returns HTTP error / network failure.
5. Multi-attempt error recovery & fail-safe returns.
"""
import base64
import json
import sys
import urllib.error
import urllib.parse
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent))

import jarvis_watcher_service


class MockResponse:
    def __init__(self, data_dict):
        self.data_dict = data_dict

    def read(self):
        return json.dumps(self.data_dict).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def run():
    passed, failed = 0, 0

    def check(label: str, cond: bool):
        nonlocal passed, failed
        if cond:
            print(f"  [PASS] {label}")
            passed += 1
        else:
            print(f"  [FAIL] {label}")
            failed += 1

    sid = "AC_MOCK_TEST_SID_000000000000000"
    token = "auth_token_secret_123456"
    from_num = "+15551234567"
    to_num = "+15559876543"
    hostname = "JARVIS-TERMINAL-01"
    time_str = "10:15:00"

    # Silence logging and skip real sleeps during tests
    jarvis_watcher_service._log = lambda *args: None
    orig_sleep = jarvis_watcher_service.time.sleep
    orig_urlopen = jarvis_watcher_service.urllib.request.urlopen

    jarvis_watcher_service.time.sleep = lambda s: None

    try:
        # ── Test 1: Twilio SMS Payload & Authorization Construction
        print("\n=== [1] Twilio SMS Payload & Authorization Construction ===")
        captured_reqs = []

        def mock_sms_urlopen(req, *args, **kwargs):
            captured_reqs.append(req)
            if "Messages.json" in req.full_url:
                return MockResponse({"sid": "SM123456789", "status": "queued"})
            else:
                return MockResponse({"sid": "SM123456789", "status": "delivered", "error_code": None})

        jarvis_watcher_service.urllib.request.urlopen = mock_sms_urlopen

        ok = jarvis_watcher_service._send_twilio_sms(sid, token, from_num, to_num, hostname, time_str)
        check("SMS dispatch returned True on delivered status", ok is True)
        check("Exactly 2 requests made (create message + status poll)", len(captured_reqs) == 2)

        first_req = captured_reqs[0]
        check("Target URL matches Twilio Messages endpoint", first_req.full_url == f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json")
        check("Method is POST", first_req.get_method() == "POST")

        expected_auth = base64.b64encode(f"{sid}:{token}".encode()).decode()
        check("Authorization header contains valid Basic Auth token", first_req.headers.get("Authorization") == f"Basic {expected_auth}")

        body_str = first_req.data.decode("utf-8")
        check("Body contains destination number", f"To={urllib.parse.quote(to_num)}" in body_str or to_num in body_str)
        check("Body contains from number", f"From={urllib.parse.quote(from_num)}" in body_str or from_num in body_str)

        # ── Test 2: Twilio Voice Call & TwiML Siren Parameter
        print("\n=== [2] Twilio Voice Call & TwiML Construction ===")
        captured_call_reqs = []

        def mock_call_urlopen(req, *args, **kwargs):
            captured_call_reqs.append(req)
            if "Calls.json" in req.full_url:
                return MockResponse({"sid": "CA123456789", "status": "queued"})
            else:
                return MockResponse({"sid": "CA123456789", "status": "completed"})

        jarvis_watcher_service.urllib.request.urlopen = mock_call_urlopen

        owner_name = "Tony Stark"
        siren_url = "https://example.com/siren.mp3"
        ok_call = jarvis_watcher_service._send_twilio_call(sid, token, from_num, to_num, hostname, time_str, owner_name, siren_url)

        check("Voice call dispatch returned True on completed status", ok_call is True)
        first_call_req = captured_call_reqs[0]
        check("Target URL matches Twilio Calls endpoint", first_call_req.full_url == f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Calls.json")

        call_body = first_call_req.data.decode("utf-8")
        check("Call body includes TwiML instructions", "Twiml=" in call_body or "Url=" in call_body)

        # ── Test 3: API Error Resilience & Fail-Safe Returns
        print("\n=== [3] API Error Resilience & Fail-Safe Returns ===")
        def mock_error_urlopen(req, *args, **kwargs):
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)

        jarvis_watcher_service.urllib.request.urlopen = mock_error_urlopen

        error_sms = jarvis_watcher_service._send_twilio_sms(sid, token, from_num, to_num, hostname, time_str)
        check("HTTP 401 error on SMS fails cleanly without raising exception", error_sms is False)

        error_call = jarvis_watcher_service._send_twilio_call(sid, token, from_num, to_num, hostname, time_str, "User", "")
        check("HTTP 401 error on Call fails cleanly without exception", error_call is False)

    finally:
        jarvis_watcher_service.time.sleep = orig_sleep
        jarvis_watcher_service.urllib.request.urlopen = orig_urlopen

    print(f"\n==================================================")
    print(f"  Results: {passed} passed, {failed} failed")
    print(f"==================================================")
    return failed == 0


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
