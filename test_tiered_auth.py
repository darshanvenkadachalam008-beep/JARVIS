"""
test_tiered_auth.py — Test Suite for Tiered Command Guard & Access Control
==========================================================================
Verifies:
1. READ_ONLY tier auto-permits without confirmation or PIN.
2. REVERSIBLE_WRITE tier logs and permits.
3. DESTRUCTIVE tier requires explicit confirmation AND security PIN.
4. SYSTEM_LEVEL tier requires explicit named confirmation AND security PIN (rejects generic approval).
5. BLOCKED Invariant Deny-List ALWAYS blocks, regardless of flags/PIN.
6. Audit log chain verification after all evaluations.
"""
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.command_guard import AuthTier, check_command, classify_action, guard
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
        # Set up isolated access control and audit log
        ac_path = base / "access_control.json"
        audit_path = base / "audit_log.jsonl"
        ac = AccessControl(path=ac_path)
        ac._audit = AuditLog(path=audit_path)

        # ── Test 1: Classification Tiers
        print("\n=== [1] Action & Command Classification ===")
        v_read = check_command(["ls", "-la"])
        check("ls -la is READ_ONLY", v_read.tier == AuthTier.READ_ONLY)

        v_rev = classify_action("create_file", target="test.txt")
        check("create_file is REVERSIBLE_WRITE", v_rev.tier == AuthTier.REVERSIBLE_WRITE)

        v_dest = check_command(["del", "/f", "/s", "C:\\temp\\file.txt"])
        check("del /f is DESTRUCTIVE", v_dest.tier == AuthTier.DESTRUCTIVE)

        v_sys = check_command(["reg", "add", "HKCU\\Software\\Test"])
        check("reg add is SYSTEM_LEVEL", v_sys.tier == AuthTier.SYSTEM_LEVEL)

        v_block = check_command(["format", "C:"])
        check("format C: is BLOCKED", v_block.tier == AuthTier.BLOCKED)

        # ── Test 2: Invariant Deny-List (Must ALWAYS block)
        print("\n=== [2] Invariant Deny-List Enforcement ===")
        ac.set_pin("9876")

        blocked_cases = [
            ("format D:", "", {}),
            ("rm -rf /", "", {}),
            ("powershell Set-MpPreference -DisableRealtimeMonitoring $true", "", {}),
            ("cat memory/audit_log.jsonl", "delete_audit_log", {}),
            ("python core/intruder_alert.py", "disable_intruder_alert", {}),
            ("python core/secure_vault.py", "dump_vault", {}),
            ("python core/access_control.py", "modify_access_control", {}),
            ("cat memory/integrity_manifest.json", "tamper_integrity_manifest", {}),
            ("del memory/integrity_manifest.json", "delete_integrity_manifest", {}),
            ("python core/integrity_monitor.py", "disable_integrity_monitor", {}),
            ("type config/vault_key.dpapi", "dump_integrity_key", {}),
        ]

        for cmd, act, kw in blocked_cases:
            blocked = False
            try:
                guard(
                    command=cmd,
                    confirmed=True,
                    pin="9876",
                    action_name=act,
                    confirmed_action_name=act,
                    access_control=ac,
                )
            except PermissionError as e:
                blocked = True
                check(f"Blocked invariant: {cmd[:35]} (Reason: {str(e)[:40]})", True)
            if not blocked:
                check(f"FAILED TO BLOCK INVARIANT: {cmd}", False)

        # ── Test 2b: Sensitivity Check Independent of Tier (READ_ONLY Sensitive Target Blocking)
        print("\n=== [2b] Sensitivity Check Independent of Tier (READ_ONLY Blocked) ===")
        read_sensitive_cases = [
            ("file_controller:read config/vault.enc", "read", "config/vault.enc"),
            ("file_controller:read memory/integrity_manifest.json", "read", "memory/integrity_manifest.json"),
            ("file_controller:read config/vault_key.dpapi", "read", "config/vault_key.dpapi"),
            ("file_processor:auto config/vault.enc", "read", "config/vault.enc"),
            ("code_helper:read core/integrity_monitor.py", "read", "core/integrity_monitor.py"),
        ]

        for cmd, act, tgt in read_sensitive_cases:
            read_blocked = False
            try:
                guard(
                    command=cmd,
                    confirmed=True,
                    pin="9876",
                    action_name=act,
                    target=tgt,
                    access_control=ac,
                )
            except PermissionError as e:
                read_blocked = True
                check(f"Blocked READ_ONLY on sensitive target: {tgt} (Reason: {str(e)[:40]})", True)
            if not read_blocked:
                check(f"FAILED TO BLOCK READ_ONLY SENSITIVE TARGET: {tgt}", False)

        # ── Test 3: READ_ONLY & REVERSIBLE_WRITE Execution
        print("\n=== [3] READ_ONLY & REVERSIBLE_WRITE Authorization ===")
        try:
            guard("ls -la", confirmed=False, pin="", action_name="list_files", access_control=ac)
            check("READ_ONLY proceeds without confirmation/PIN", True)
        except Exception as e:
            check(f"READ_ONLY failed unexpectedly: {e}", False)

        try:
            guard("echo hello > test.txt", confirmed=False, pin="", action_name="create_file", access_control=ac)
            check("REVERSIBLE_WRITE proceeds and is logged", True)
        except Exception as e:
            check(f"REVERSIBLE_WRITE failed unexpectedly: {e}", False)

        # ── Test 4: DESTRUCTIVE Tier Gating
        print("\n=== [4] DESTRUCTIVE Tier Gating ===")
        # Unconfirmed should fail
        unconfirmed_failed = False
        try:
            guard("del /f /s C:\\dummy", confirmed=False, pin="9876", action_name="permanent_delete", access_control=ac)
        except PermissionError:
            unconfirmed_failed = True
        check("DESTRUCTIVE fails when unconfirmed", unconfirmed_failed)

        # Wrong PIN should fail and cause backoff
        wrong_pin_failed = False
        try:
            guard("del /f /s C:\\dummy", confirmed=True, pin="0000", action_name="permanent_delete", access_control=ac)
        except PermissionError:
            wrong_pin_failed = True
        check("DESTRUCTIVE fails with wrong PIN", wrong_pin_failed)

        # Reset fail state for testing subsequent success
        ac._state["fail_count"] = 0
        ac._state["locked_until"] = 0
        ac._save()

        # Correct confirmation + PIN should succeed
        dest_success = False
        try:
            guard("del /f /s C:\\dummy", confirmed=True, pin="9876", action_name="permanent_delete", access_control=ac)
            dest_success = True
        except Exception as e:
            print(f"    Unexpected failure: {e}")
        check("DESTRUCTIVE succeeds with confirmed=True + valid PIN", dest_success)

        # ── Test 5: SYSTEM_LEVEL Tier Gating (Named Confirmation) ==
        print("\n=== [5] SYSTEM_LEVEL Tier Gating (Named Confirmation) ===")
        # Generic confirmation without matching action name should fail
        mismatch_failed = False
        try:
            guard(
                "shutdown /s /t 10",
                confirmed=True,
                pin="9876",
                action_name="shutdown",
                confirmed_action_name="yes",  # Generic 'yes' instead of named 'shutdown'
                access_control=ac,
            )
        except PermissionError as e:
            mismatch_failed = True
            check(f"SYSTEM_LEVEL rejects generic approval (Reason: {str(e)[:45]})", True)
        if not mismatch_failed:
            check("SYSTEM_LEVEL incorrectly allowed generic 'yes'", False)

        # Reset fail state before testing valid named confirmation
        ac._state["fail_count"] = 0
        ac._state["locked_until"] = 0
        ac._save()

        # Named confirmation + correct PIN should succeed
        sys_success = False
        try:
            guard(
                "shutdown /s /t 10",
                confirmed=True,
                pin="9876",
                action_name="shutdown",
                confirmed_action_name="shutdown",  # Exact action name confirmed
                access_control=ac,
            )
            sys_success = True
        except Exception as e:
            print(f"    Unexpected failure: {e}")
        check("SYSTEM_LEVEL succeeds with named confirmation ('shutdown') + valid PIN", sys_success)

        # ── Test 6: Audit Log Integrity
        print("\n=== [6] Audit Log Integrity ===")
        ok, reason = ac._audit.verify()
        entries = ac._audit.read_all()
        check(f"Audit log verify: intact={ok} ({len(entries)} entries)", ok is True)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print(f"\n==================================================")
    print(f"  Results: {passed} passed, {failed} failed")
    print(f"==================================================")
    return failed == 0


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
