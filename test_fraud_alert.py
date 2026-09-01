import json, hmac, hashlib, urllib.request, time

with open("config/api_keys.json") as f:
    secret = json.load(f)["sentinel_shared_secret"].encode("utf-8")

payload = {
    "event": "fraud_alert",
    "case_id": "CASE-TEST-001",
    "severity": "CRITICAL",
    "transaction_id": "TXN-999",
    "user_id": "ACC-123",
    "risk_score": 94.2,
    "assigned_to": "analyst1",
    "reasons": ["velocity spike", "new device"],
    "sent_at": time.time(),
}

body = json.dumps(payload).encode()
sig = hmac.new(secret, body, hashlib.sha256).hexdigest()

req = urllib.request.Request(
    "http://127.0.0.1:8080/fraud-alert",
    data=body,
    headers={
        "Content-Type": "application/json",
        "X-Sentinel-Signature": sig,
    },
)

t0 = time.time()
with urllib.request.urlopen(req, timeout=10) as r:
    elapsed = round(time.time() - t0, 2)
    print("status:", r.status)
    print("took:", elapsed, "seconds")
    print("response:", r.read())