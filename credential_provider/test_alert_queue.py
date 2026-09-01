"""
credential_provider/test_alert_queue.py — Unit Tests for Cold-Boot Alert Queue
================================================================================
Verifies:
1. DPAPI machine-scope encryption with entropy secret.
2. JSON event serialization and queue persistence.
3. Multiple event accumulation.
4. Tamper and corruption resilience (malformed ciphertext / missing entropy).
5. Queue flush and truncation lifecycle.
"""
import ctypes
from ctypes import wintypes
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

# ── Windows DPAPI Cryptography Helper ───────────────────────────────────────
class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

CRYPTPROTECT_LOCAL_MACHINE = 0x4


def _dpapi_protect(plain_bytes: bytes, entropy_bytes: bytes = b"") -> bytes:
    blob_in = DATA_BLOB(len(plain_bytes), ctypes.cast(ctypes.create_string_buffer(plain_bytes), ctypes.POINTER(ctypes.c_byte)))
    blob_entropy = None
    p_entropy = None
    if entropy_bytes:
        blob_entropy = DATA_BLOB(len(entropy_bytes), ctypes.cast(ctypes.create_string_buffer(entropy_bytes), ctypes.POINTER(ctypes.c_byte)))
        p_entropy = ctypes.byref(blob_entropy)

    blob_out = DATA_BLOB()
    if ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(blob_in),
        "JarvisColdBootAlertQueue",
        p_entropy,
        None,
        None,
        CRYPTPROTECT_LOCAL_MACHINE,
        ctypes.byref(blob_out)
    ):
        cipher = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return cipher
    raise RuntimeError("CryptProtectData failed")


def _dpapi_unprotect(cipher_bytes: bytes, entropy_bytes: bytes = b"") -> bytes:
    blob_in = DATA_BLOB(len(cipher_bytes), ctypes.cast(ctypes.create_string_buffer(cipher_bytes), ctypes.POINTER(ctypes.c_byte)))
    blob_entropy = None
    p_entropy = None
    if entropy_bytes:
        blob_entropy = DATA_BLOB(len(entropy_bytes), ctypes.cast(ctypes.create_string_buffer(entropy_bytes), ctypes.POINTER(ctypes.c_byte)))
        p_entropy = ctypes.byref(blob_entropy)

    blob_out = DATA_BLOB()
    if ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in),
        None,
        p_entropy,
        None,
        None,
        CRYPTPROTECT_LOCAL_MACHINE,
        ctypes.byref(blob_out)
    ):
        plain = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return plain
    raise RuntimeError("CryptUnprotectData failed")


def run():
    tmpdir = tempfile.mkdtemp()
    base = Path(tmpdir)
    passed, failed = 0, 0

    def check(label: str, cond: bool):
        nonlocal passed, failed
        if cond:
            print(f"  [PASS] {label}")
            passed += 1
        else:
            print(f"  [FAIL] {label}")
            failed += 1

    try:
        entropy = os.urandom(32)
        queue_file = base / "boot_alert_queue.enc"

        # ── Test 1: Single Event Queue Write & DPAPI Encryption
        print("\n=== [1] Single Event Queue Write & Encryption ===")
        event1 = {
            "timestamp": "2026-08-28T09:15:00.123Z",
            "event_type": "FAILED_PRIMARY_LOGON",
            "attempt_count": 1,
            "layer": "primary_password",
            "domain": "WORKGROUP",
            "username": "Administrator"
        }

        payload1 = (json.dumps(event1) + "\n").encode("utf-8")
        encrypted1 = _dpapi_protect(payload1, entropy)
        queue_file.write_bytes(encrypted1)

        check("Queue file created on disk", queue_file.exists())
        check("Ciphertext is not plaintext", queue_file.read_bytes() != payload1)

        decrypted1 = _dpapi_unprotect(queue_file.read_bytes(), entropy)
        recovered1 = json.loads(decrypted1.decode("utf-8").strip())
        check("Decrypted payload matches original event", recovered1["event_type"] == "FAILED_PRIMARY_LOGON")
        check("Event metadata intact", recovered1["attempt_count"] == 1 and recovered1["username"] == "Administrator")

        # ── Test 2: Accumulating Multiple Duress Events
        print("\n=== [2] Accumulating Multiple Duress Events ===")
        event2 = {
            "timestamp": "2026-08-28T09:15:10.456Z",
            "event_type": "FAILED_DURESS_PASSWORD",
            "attempt_count": 2,
            "layer": "duress_password",
            "domain": "WORKGROUP",
            "username": "Administrator"
        }
        event3 = {
            "timestamp": "2026-08-28T09:15:20.789Z",
            "event_type": "FAILED_DURESS_EXCEEDED",
            "attempt_count": 3,
            "layer": "duress_password",
            "domain": "WORKGROUP",
            "username": "Administrator"
        }
        event4 = {
            "timestamp": "2026-08-28T09:15:30.000Z",
            "event_type": "DURESS_LOGIN_SUCCESS",
            "attempt_count": 1,
            "layer": "duress_password",
            "domain": "WORKGROUP",
            "username": "Administrator"
        }

        current_plain = _dpapi_unprotect(queue_file.read_bytes(), entropy).decode("utf-8")
        accumulated = current_plain + json.dumps(event2) + "\n" + json.dumps(event3) + "\n" + json.dumps(event4) + "\n"
        queue_file.write_bytes(_dpapi_protect(accumulated.encode("utf-8"), entropy))

        decrypted_all = _dpapi_unprotect(queue_file.read_bytes(), entropy).decode("utf-8")
        lines = [json.loads(l) for l in decrypted_all.strip().splitlines() if l.strip()]
        check("Accumulated 4 distinct logon events", len(lines) == 4)
        check("Duress escalation captured", lines[2]["event_type"] == "FAILED_DURESS_EXCEEDED" and lines[2]["attempt_count"] == 3)
        check("Duress login success event captured", lines[3]["event_type"] == "DURESS_LOGIN_SUCCESS" and lines[3]["layer"] == "duress_password")

        # ── Test 3: Corruption & Wrong Entropy Resilience (Fail-Closed)
        print("\n=== [3] Corruption & Wrong Entropy Resilience ===")
        wrong_entropy = os.urandom(32)
        corrupted_rejected = False
        try:
            _dpapi_unprotect(queue_file.read_bytes(), wrong_entropy)
        except Exception:
            corrupted_rejected = True
        check("Wrong entropy fails closed without exposing data", corrupted_rejected is True)

        truncated_file = base / "corrupted_queue.enc"
        truncated_file.write_bytes(b"BAD_HEADER_TRUNCATED_CIPHERTEXT")
        trunc_rejected = False
        try:
            _dpapi_unprotect(truncated_file.read_bytes(), entropy)
        except Exception:
            trunc_rejected = True
        check("Truncated ciphertext fails closed safely", trunc_rejected is True)

        # ── Test 4: Queue Flush & Post-Boot Rotation
        print("\n=== [4] Queue Flush & Post-Boot Rotation ===")
        flushed_events = []
        if queue_file.exists():
            data = _dpapi_unprotect(queue_file.read_bytes(), entropy).decode("utf-8")
            for line in data.strip().splitlines():
                if line.strip():
                    flushed_events.append(json.loads(line.strip()))
            queue_file.unlink(missing_ok=True)

        check("Successfully read all pending entries for flush", len(flushed_events) == 4)
        check("Queue file atomically removed/cleared after flush", not queue_file.exists())

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print(f"\n==================================================")
    print(f"  Results: {passed} passed, {failed} failed")
    print(f"==================================================")
    return failed == 0


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
