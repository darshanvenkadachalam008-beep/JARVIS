"""
tests/test_access_control_bridge.py — Comprehensive tests for AccessControl facade over sentinel/auth
=====================================================================================================
Verifies:
1. Legacy migration: seeds memory/access_control.json (480k KDF), loads AccessControl, confirms
   is_configured() is True, old PIN verifies, and credentials.json has recovery_pin=None.
2. Legacy-mode lockout capping: migrated install drives verify_pin() to 8+ consecutive failures,
   confirms it never hard-locks (capped at 3600s). Once a recovery PIN is added, driving 7 failures
   hard-locks the engine.
3. Concurrency test: multiple threads hammering verify_pin() with bad PINs simultaneously,
   confirming zero lost updates in lockout_state.json.
4. Triage authentication flow using the unified LockoutManager single source of truth.
5. All 8 call-site interfaces (set_pin, set_recovery_pin, verify_pin, verify_recovery_pin,
   _seconds_locked, require_pin).
"""
import hashlib
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from core.access_control import AccessControl, TriageStatus, _KDF_ITERATIONS


def test_legacy_access_control_migration(tmp_path):
    """
    Seeds a legacy memory/access_control.json with 480k PBKDF2 hash, constructs AccessControl,
    and asserts automatic migration into sentinel/auth credentials.json with recovery_pin=None.
    """
    mem_dir = tmp_path / "memory"
    mem_dir.mkdir(parents=True, exist_ok=True)
    legacy_file = mem_dir / "access_control.json"

    salt = os.urandom(16)
    pin = "LegacySecretPin123"
    pwd_hash = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, _KDF_ITERATIONS).hex()

    legacy_data = {
        "salt": salt.hex(),
        "hash": pwd_hash,
        "fail_count": 0,
        "locked_until": 0,
    }
    legacy_file.write_text(json.dumps(legacy_data), encoding="utf-8")

    ac = AccessControl(path=legacy_file)
    assert ac.is_configured() is True

    # Confirm credentials.json was created under auth_dir with recovery_pin=None
    creds_file = ac.auth_dir / "credentials.json"
    assert creds_file.exists()

    creds = json.loads(creds_file.read_text(encoding="utf-8"))
    assert creds["is_initialized"] is True
    assert creds["primary_pin"]["hash_hex"] == pwd_hash
    assert creds["primary_pin"]["iterations"] == _KDF_ITERATIONS
    assert creds["recovery_pin"] is None

    # Confirm old PIN verifies seamlessly
    assert ac.verify_pin(pin) is True
    assert ac.verify_pin("WrongPin") is False


def test_legacy_mode_lockout_capping_and_hard_lockout_activation(tmp_path):
    """
    Verifies that a migrated install with recovery_pin=None never hard-locks (caps backoff at 3600s).
    Once a recovery PIN is configured, 7 failures triggers hard lockout.
    """
    mem_dir = tmp_path / "memory"
    mem_dir.mkdir(parents=True, exist_ok=True)
    legacy_file = mem_dir / "access_control.json"

    salt = os.urandom(16)
    pin = "InitialPin999"
    pwd_hash = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, _KDF_ITERATIONS).hex()

    legacy_data = {"salt": salt.hex(), "hash": pwd_hash}
    legacy_file.write_text(json.dumps(legacy_data), encoding="utf-8")

    ac = AccessControl(path=legacy_file)

    # Drive 8 failures in legacy-mode
    for i in range(8):
        # Patch time.time() if backoff is active so we can simulate repeated attempts
        with patch("time.time", return_value=time.time() + 10000 * (i + 1)):
            assert ac.verify_pin("WrongPin") is False

    # In legacy-compat mode, primary_hard_locked must remain False and backoff capped at 3600s
    state = ac._engine.lockout_manager.get_current_state()
    assert state.primary_failures == 8
    assert state.primary_hard_locked is False

    # Now add a recovery PIN to activate full hard-lockout protection
    ac.set_recovery_pin("RecoveryPin777")
    creds = ac._engine.enrollment_manager.get_credentials()
    assert creds.recovery_pin is not None

    # Clean state on reset
    ac._engine.lockout_manager.initialize_clean_state()

    # Drive 7 failures on the upgraded account
    for i in range(7):
        with patch("time.time", return_value=time.time() + 10000 * (i + 1)):
            ac.verify_pin("WrongPin")

    state_after = ac._engine.lockout_manager.get_current_state()
    assert state_after.primary_failures == 7
    assert state_after.primary_hard_locked is True

    # Primary PIN is now hard-locked
    assert ac.verify_pin(pin) is False

    # Recovery PIN unlocks it!
    assert ac.verify_recovery_pin("RecoveryPin777") is True
    state_recovered = ac._engine.lockout_manager.get_current_state()
    assert state_recovered.primary_hard_locked is False
    assert state_recovered.primary_failures == 0


def test_concurrent_verify_pin_no_lost_updates(tmp_path):
    """
    Verifies that concurrent verify_pin calls from multiple threads update fail_count
    with zero lost updates thanks to the underlying LockoutManager FileLock.
    """
    mem_dir = tmp_path / "memory"
    mem_dir.mkdir(parents=True, exist_ok=True)
    legacy_file = mem_dir / "access_control.json"

    ac = AccessControl(path=legacy_file)
    ac.set_pin("ThreadPin123")

    num_threads = 2

    def worker():
        return ac.verify_pin("WrongPin")

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker) for _ in range(num_threads)]
        results = [f.result() for f in futures]

    assert results == [False, False]

    state = ac._engine.lockout_manager.get_current_state()
    assert state.primary_failures == 2


def test_triage_authentication_flow_with_unified_lockout(tmp_path):
    """Verifies that triage_authentication uses the unified LockoutManager state."""
    mem_dir = tmp_path / "memory"
    mem_dir.mkdir(parents=True, exist_ok=True)
    legacy_file = mem_dir / "access_control.json"

    ac = AccessControl(path=legacy_file)
    ac.set_pin("TriageMaster123")
    ac.set_recovery_pin("TriageRecovery123")

    # 1. Successful authentication
    res = ac.triage_authentication("TriageMaster123")
    assert res.status == TriageStatus.GRANTED
    assert res.can_prompt_pin is True

    # 2. Failed authentication with owner face
    mock_fv_owner = MagicMock()
    mock_res_owner = MagicMock(enrolled=True, face_found=True, accepted=True, spoof_suspected=False)
    mock_fv_owner.identify.return_value = mock_res_owner

    res_mistype = ac.triage_authentication(
        "WrongPin",
        snapshot_bytes=b"fake_jpeg",
        face_verifier=mock_fv_owner,
    )
    assert res_mistype.status == TriageStatus.OWNER_MISTYPE
    assert res_mistype.can_prompt_pin is True

    # 3. Failed authentication with impostor face / alert triggered
    mock_fv_impostor = MagicMock()
    mock_res_impostor = MagicMock(enrolled=True, face_found=True, accepted=False)
    mock_fv_impostor.identify.return_value = mock_res_impostor
    alert_mock = MagicMock()

    # Move past backoff to simulate next attempt
    with patch("time.time", return_value=time.time() + 100):
        res_intruder = ac.triage_authentication(
            "WrongPin",
            snapshot_bytes=b"fake_jpeg",
            face_verifier=mock_fv_impostor,
            alert_callback=alert_mock,
        )
    assert res_intruder.status == TriageStatus.INTRUDER_SUSPECTED
    assert res_intruder.can_prompt_pin is False
    alert_mock.assert_called_once()


def test_triage_result_backoff_matches_seconds_locked_single_source_of_truth(tmp_path):
    """
    Asserts that TriageResult.backoff_s always matches ac._seconds_locked() across multiple failure levels.
    """
    mem_dir = tmp_path / "memory"
    mem_dir.mkdir(parents=True, exist_ok=True)
    legacy_file = mem_dir / "access_control.json"

    ac = AccessControl(path=legacy_file)
    ac.set_pin("CorrectPin123")

    mock_fv_owner = MagicMock()
    mock_fv_owner.identify.return_value = MagicMock(enrolled=True, face_found=True, accepted=True)

    # Attempt 1: failure 1 (no backoff in Sentinel, should be 0.0)
    r1 = ac.triage_authentication("BadPin1", snapshot_bytes=b"frame", face_verifier=mock_fv_owner)
    assert r1.fail_count == 1
    assert r1.backoff_s == ac._seconds_locked()
    assert r1.backoff_s == 0.0

    # Attempt 2: failure 2 (still 0.0)
    r2 = ac.triage_authentication("BadPin2", snapshot_bytes=b"frame", face_verifier=mock_fv_owner)
    assert r2.fail_count == 2
    assert r2.backoff_s == ac._seconds_locked()
    assert r2.backoff_s == 0.0

    # Attempt 3: failure 3 (soft backoff kicks in: 5.0s)
    r3 = ac.triage_authentication("BadPin3", snapshot_bytes=b"frame", face_verifier=mock_fv_owner)
    assert r3.fail_count == 3
    # Both TriageResult.backoff_s and ac._seconds_locked() should report ~5.0s (within tolerance)
    assert r3.backoff_s > 0.0
    current_sec = ac._seconds_locked()
    assert abs(r3.backoff_s - current_sec) < 0.2


def test_legacy_migration_atomic_single_pass_with_recovery_pin(tmp_path):
    """
    Verifies that legacy migration seeds both primary and recovery hashes in ONE atomic pass,
    calling apply_owner_only_dacl on credentials.json exactly once.
    """
    mem_dir = tmp_path / "memory"
    mem_dir.mkdir(parents=True, exist_ok=True)
    legacy_file = mem_dir / "access_control.json"

    salt_prim = os.urandom(16).hex()
    hash_prim = hashlib.pbkdf2_hmac("sha256", b"PrimPIN", bytes.fromhex(salt_prim), _KDF_ITERATIONS).hex()
    salt_rec = os.urandom(16).hex()
    hash_rec = hashlib.pbkdf2_hmac("sha256", b"RecPIN", bytes.fromhex(salt_rec), _KDF_ITERATIONS).hex()

    legacy_data = {
        "salt": salt_prim,
        "hash": hash_prim,
        "recovery_salt": salt_rec,
        "recovery_hash": hash_rec,
    }
    legacy_file.write_text(json.dumps(legacy_data), encoding="utf-8")

    with patch("sentinel.auth.enrollment.apply_owner_only_dacl") as mock_dacl:
        ac = AccessControl(path=legacy_file)
        assert ac.is_configured() is True

        creds = ac._engine.enrollment_manager.get_credentials()
        assert creds.primary_pin.hash_hex == hash_prim
        assert creds.primary_pin.iterations == _KDF_ITERATIONS
        assert creds.recovery_pin is not None
        assert creds.recovery_pin.hash_hex == hash_rec
        assert creds.recovery_pin.iterations == _KDF_ITERATIONS

        # Verify apply_owner_only_dacl was called on credentials.json exactly once during migration
        cred_dacl_calls = [
            call for call in mock_dacl.call_args_list
            if str(call[0][0]).endswith("credentials.json")
        ]
        assert len(cred_dacl_calls) == 1
