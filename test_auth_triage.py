"""
test_auth_triage.py — Test Suite for Failed-Authentication Triage Flow
======================================================================
Verifies:
1. Owner mistype with verified face -> OWNER_MISTYPE, permits fallback recovery PIN.
2. Wrong password with NO face detected -> INTRUDER_SUSPECTED (fails closed, suppresses PIN, fires alert).
3. Wrong password with IMPOSTOR face -> INTRUDER_SUSPECTED (fails closed, suppresses PIN, fires alert).
4. Repeated failures -> Escalating lockout ladder (session locks regardless of face).
5. Tamper-evident audit chain captures all triage events.
"""
import shutil
import sys
import tempfile
import time
from pathlib import Path
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).parent))

from core.access_control import AccessControl, TriageStatus
from core.audit_log import AuditLog
from core.face_verify import IdentifyResult


class MockFaceVerifier:
    def __init__(self, mode="owner"):
        self.mode = mode  # "owner" | "impostor" | "no_face" | "error"

    def identify(self, jpeg_bytes: bytes, action: str = "") -> IdentifyResult:
        if self.mode == "owner":
            return IdentifyResult(enrolled=True, face_found=True, accepted=True, confidence=32.0)
        elif self.mode == "impostor":
            return IdentifyResult(enrolled=True, face_found=True, accepted=False, confidence=95.0, reason="below_match_quality")
        elif self.mode == "no_face":
            return IdentifyResult(enrolled=True, face_found=False, accepted=False, reason="no_face_found")
        else:
            raise RuntimeError("Webcam stream read error")


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
        ac_path = base / "access_control.json"
        audit_path = base / "audit_log.jsonl"
        ac = AccessControl(path=ac_path)
        ac._audit = AuditLog(path=audit_path)

        ac.set_pin("MasterPassword123")
        ac.set_recovery_pin("FallbackPin9999")

        # ── Test 1: Owner Mistype Branch
        print("\n=== [1] Owner Mistype Branch (Face matches owner) ===")
        alert_fired = []
        mock_fv_owner = MockFaceVerifier(mode="owner")

        res1 = ac.triage_authentication(
            candidate_pin="WrongPass1",
            action="unlock_vault",
            snapshot_bytes=b"fake_jpeg_owner",
            face_verifier=mock_fv_owner,
            alert_callback=lambda msg, shot: alert_fired.append(msg),
        )

        check("Status is OWNER_MISTYPE", res1.status == TriageStatus.OWNER_MISTYPE)
        check("Can prompt for fallback recovery PIN", res1.can_prompt_pin is True)
        check("No intruder alert dispatched for owner mistype", len(alert_fired) == 0)
        check("Fail count incremented to 1", res1.fail_count == 1)

        # Verify fallback recovery PIN works
        rec_ok = ac.verify_recovery_pin("FallbackPin9999", action="recovery_unlock")
        check("Fallback recovery PIN accepted", rec_ok is True)

        # ── Test 2: No-Face Detected Branch (Fail Closed)
        print("\n=== [2] No-Face Detected Branch (Fail Closed) ===")
        ac._state["fail_count"] = 0
        ac._state["locked_until"] = 0
        ac._save()

        alert_fired_noface = []
        mock_fv_noface = MockFaceVerifier(mode="no_face")

        res2 = ac.triage_authentication(
            candidate_pin="AttackerGuess1",
            action="permanent_delete",
            snapshot_bytes=b"fake_jpeg_empty",
            face_verifier=mock_fv_noface,
            alert_callback=lambda msg, shot: alert_fired_noface.append(msg),
        )

        check("Status is INTRUDER_SUSPECTED", res2.status == TriageStatus.INTRUDER_SUSPECTED)
        check("Cannot prompt PIN (prompt suppressed)", res2.can_prompt_pin is False)
        check("Intruder alert triggered immediately", len(alert_fired_noface) == 1)
        check("Alert message contains failure reason", "no_face_in_frame" in alert_fired_noface[0])

        # ── Test 3: Impostor Face Branch (Fail Closed)
        print("\n=== [3] Impostor Face Branch (Fail Closed) ===")
        ac._state["fail_count"] = 0
        ac._state["locked_until"] = 0
        ac._save()

        alert_fired_impostor = []
        mock_fv_impostor = MockFaceVerifier(mode="impostor")

        res3 = ac.triage_authentication(
            candidate_pin="AttackerGuess2",
            action="restart_system",
            snapshot_bytes=b"fake_jpeg_stranger",
            face_verifier=mock_fv_impostor,
            alert_callback=lambda msg, shot: alert_fired_impostor.append(msg),
        )

        check("Status is INTRUDER_SUSPECTED", res3.status == TriageStatus.INTRUDER_SUSPECTED)
        check("Cannot prompt PIN (prompt suppressed)", res3.can_prompt_pin is False)
        check("Intruder alert triggered immediately", len(alert_fired_impostor) == 1)
        check("Alert message flags face mismatch", "face_mismatch_impostor" in alert_fired_impostor[0])

        # ── Test 4: Camera Error / Unavailable (Fail Closed)
        print("\n=== [4] Camera Error / Unavailable Branch (Fail Closed) ===")
        ac._state["fail_count"] = 0
        ac._state["locked_until"] = 0
        ac._save()

        alert_fired_err = []
        mock_fv_err = MockFaceVerifier(mode="error")

        res4 = ac.triage_authentication(
            candidate_pin="BadPass",
            action="sensitive_action",
            snapshot_bytes=b"fake_jpeg",
            face_verifier=mock_fv_err,
            alert_callback=lambda msg, shot: alert_fired_err.append(msg),
        )

        check("Status is INTRUDER_SUSPECTED on camera error", res4.status == TriageStatus.INTRUDER_SUSPECTED)
        check("Prompt suppressed on camera failure", res4.can_prompt_pin is False)
        check("Intruder alert dispatched", len(alert_fired_err) == 1)

        # ── Test 5: Escalating Rate-Limiting Lockout
        print("\n=== [5] Escalating Rate-Limiting Lockout ===")
        ac_esc = AccessControl(path=base / "ac_esc.json")
        ac_esc._audit = AuditLog(path=base / "audit_esc.jsonl")
        ac_esc.set_pin("ValidPin123")

        # Attempt 1: 0s backoff
        r_1 = ac_esc.triage_authentication("wrong", action="test", snapshot_bytes=b"frame", face_verifier=mock_fv_owner)
        check("Attempt 1: fail_count=1, backoff=0s", r_1.fail_count == 1 and r_1.backoff_s == 0.0)

        # Attempt 2: 0s backoff
        r_2 = ac_esc.triage_authentication("wrong", action="test", snapshot_bytes=b"frame", face_verifier=mock_fv_owner)
        check("Attempt 2: fail_count=2, backoff=0s", r_2.fail_count == 2 and r_2.backoff_s == 0.0)

        # Attempt 3: 5s backoff
        r_3 = ac_esc.triage_authentication("wrong", action="test", snapshot_bytes=b"frame", face_verifier=mock_fv_owner)
        check("Attempt 3: fail_count=3, backoff ~5s", r_3.fail_count == 3 and 4.0 <= r_3.backoff_s <= 5.0)

        ac_esc._state["locked_until"] = 0
        lockout_alerts = []
        r_4 = ac_esc.triage_authentication(
            "wrong",
            action="test",
            snapshot_bytes=b"frame",
            face_verifier=mock_fv_owner,
            alert_callback=lambda msg, shot: lockout_alerts.append(msg),
        )
        check("Attempt 4: Hard escalated lockout (LOCKED_OUT)", r_4.status == TriageStatus.LOCKED_OUT)
        check("Prompt suppressed on hard lockout", r_4.can_prompt_pin is False)
        check("Lockout alert fired", len(lockout_alerts) == 1)

        # ── Test 6: Audit Log Integrity
        print("\n=== [6] Audit Log Integrity ===")
        ok1, _ = ac._audit.verify()
        ok2, _ = ac_esc._audit.verify()
        check("Main triage audit log is intact", ok1 is True)
        check("Escalation audit log is intact", ok2 is True)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print(f"\n==================================================")
    print(f"  Results: {passed} passed, {failed} failed")
    print(f"==================================================")
    return failed == 0


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
