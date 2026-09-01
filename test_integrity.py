"""
test_integrity.py — Test Suite for Codebase & Startup Integrity Monitoring
==========================================================================
Verifies:
1. Baseline manifest generation & Ed25519 asymmetric signing.
2. Clean verification on untouched code.
3. Detection of unauthorized file modification (tampering).
4. Detection of missing files or manifest signature corruption.
5. Re-baselining flow with PIN authorization.
"""
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.integrity_monitor import IntegrityMonitor
from core.access_control import AccessControl
from core.audit_log import AuditLog


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
        # Create a mock codebase hierarchy inside temp directory
        (base / "core").mkdir()
        (base / "agent").mkdir()
        (base / "actions").mkdir()
        (base / "memory").mkdir()

        f1 = base / "core" / "test_module.py"
        f2 = base / "agent" / "executor.py"
        f3 = base / "actions" / "desktop.py"

        f1.write_text("print('core')", encoding="utf-8")
        f2.write_text("print('executor')", encoding="utf-8")
        f3.write_text("print('desktop')", encoding="utf-8")

        manifest_file = base / "memory" / "integrity_manifest.json"
        ac = AccessControl(path=base / "memory" / "access_control.json")
        ac._audit = AuditLog(path=base / "memory" / "audit_log.jsonl")
        ac.set_pin("AdminPin1234")

        monitor = IntegrityMonitor(manifest_path=manifest_file, base_dir=base)
        monitor._audit = ac._audit

        from core.integrity_monitor import generate_keypair
        priv, pub = generate_keypair()

        # ── Test 1: Baseline Generation
        print("\n=== [1] Baseline Manifest Generation ===")
        # Unauthenticated baseline update should fail
        unauth_failed = False
        try:
            monitor.generate_baseline(private_key=priv, pin="wrong", access_control=ac)
        except PermissionError:
            unauth_failed = True
        check("Re-baselining rejects invalid PIN", unauth_failed)

        # Reset lockout state after intentional negative test
        ac._state["fail_count"] = 0
        ac._state["locked_until"] = 0
        ac._save()

        # Valid baseline generation
        payload = monitor.generate_baseline(private_key=priv, pin="AdminPin1234", access_control=ac)
        check("Manifest file created on disk", manifest_file.exists())
        check("Manifest contains Ed25519 signature", bool(payload.get("signature")))
        check("Manifest tracked all 3 test files", payload["manifest"]["file_count"] == 3)

        # ── Test 2: Clean Integrity Verification
        print("\n=== [2] Clean Integrity Verification ===")
        alerts = []
        rep1 = monitor.verify_integrity(alert_callback=lambda msg: alerts.append(msg))
        check("Clean codebase verifies as valid", rep1.is_valid is True)
        check("No tampered files detected", len(rep1.tampered_files) == 0)
        check("No alert triggered for clean state", len(alerts) == 0)

        # ── Test 3: Post-Baseline Code Tampering Detection
        print("\n=== [3] Post-Baseline Code Tampering Detection ===")
        # Inject malicious payload / modification into core/test_module.py
        f1.write_text("print('core')\n# TAMPERED: malicious backdoor injected", encoding="utf-8")

        tamper_alerts = []
        rep2 = monitor.verify_integrity(alert_callback=lambda msg: tamper_alerts.append(msg))

        check("Tampered codebase fails verification (is_valid == False)", rep2.is_valid is False)
        check("Tampered file identified in report", "core/test_module.py" in rep2.tampered_files)
        check("Intrusion alert dispatched", len(tamper_alerts) == 1)
        check("Alert message names the tampered file", "core/test_module.py" in tamper_alerts[0])

        # ── Test 4: Manifest Signature Tampering Detection
        print("\n=== [4] Manifest Signature Tampering Detection ===")
        raw_manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        raw_manifest["signature"] = "0000000000000000000000000000000000000000000000000000000000000000"
        manifest_file.write_text(json.dumps(raw_manifest), encoding="utf-8")

        sig_alerts = []
        rep3 = monitor.verify_integrity(alert_callback=lambda msg: sig_alerts.append(msg))
        check("Forged manifest signature fails verification", rep3.is_valid is False)
        check("Signature tampering alert dispatched", len(sig_alerts) == 1)

        # ── Test 5: Re-baseline with PIN
        print("\n=== [5] Legitimate Re-baseline with PIN ===")
        # Legitimate edit: update baseline
        monitor.generate_baseline(private_key=priv, pin="AdminPin1234", access_control=ac)
        rep4 = monitor.verify_integrity()
        check("Integrity restored after authorized re-baseline", rep4.is_valid is True)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print(f"\n==================================================")
    print(f"  Results: {passed} passed, {failed} failed")
    print(f"==================================================")
    return failed == 0


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
