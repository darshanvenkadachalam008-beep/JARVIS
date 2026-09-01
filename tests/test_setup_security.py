"""
tests/test_setup_security.py — Tests for setup_security.py dual-PIN UX and replacement gating
=============================================================================================
Verifies:
1. Case (a): Fresh install enrolls dual PINs with presence token, creating credentials.json with
   both primary and recovery PINs, and is armed with hard lockout (7 failures hard-locks).
2. Case (b): Configured install with recovery PIN gates replacement on current primary PIN verification.
   Invalid current PIN fails closed, records failure against LockoutManager, and prevents new PIN prompt.
   Valid current PIN replaces credentials via EnrollmentManager.enroll(current_primary_pin=...).
3. Case (c): Migrated legacy install (recovery_pin=None) offers add-recovery-PIN path, keeping
   the primary PIN untouched and verifying with its original value.
"""
import hashlib
import json
import os
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from core.access_control import AccessControl, _KDF_ITERATIONS
from setup_security import _setup_access_control


def test_setup_security_case_a_fresh_install_dual_pin(tmp_path):
    """
    Case (a): Fresh install prompts for primary + recovery PINs, generates and consumes
    presence token, and enrolls dual credentials with full hard-lockout capability.
    """
    mem_dir = tmp_path / "memory"
    mem_dir.mkdir(parents=True, exist_ok=True)
    legacy_file = mem_dir / "access_control.json"

    ac = AccessControl(path=legacy_file)
    assert not ac.is_configured()

    # Mock interactive PIN prompts: primary="MySecretPrimary", recovery="MySecretRecovery"
    with patch("setup_security._prompt_pin", side_effect=["MySecretPrimary", "MySecretRecovery"]):
        _setup_access_control(ac)

    assert ac.is_configured() is True
    assert ac.has_recovery_pin() is True

    creds = ac._engine.enrollment_manager.get_credentials()
    assert creds.primary_pin is not None
    assert creds.recovery_pin is not None

    # Verify both PINs verify
    assert ac.verify_pin("MySecretPrimary") is True
    assert ac.verify_recovery_pin("MySecretRecovery") is True

    # Confirm it is NOT in legacy-compat mode: driving 7 failures triggers hard lockout
    for i in range(7):
        with patch("time.time", return_value=time.time() + 10000 * (i + 1)):
            ac.verify_pin("WrongGuess")

    state = ac._engine.lockout_manager.get_current_state()
    assert state.primary_failures == 7
    assert state.primary_hard_locked is True


def test_setup_security_case_b_replace_gated_on_current_pin(tmp_path):
    """
    Case (b): Configured install with recovery PIN prompts for replace.
    - Incorrect current PIN fails closed, aborts, and records failure in LockoutManager.
    - Correct current PIN successfully updates credentials.
    """
    mem_dir = tmp_path / "memory"
    mem_dir.mkdir(parents=True, exist_ok=True)
    legacy_file = mem_dir / "access_control.json"

    ac = AccessControl(path=legacy_file)
    # Enroll initial credentials
    tok = ac.generate_presence_challenge()
    ac.enroll_dual_pin("InitialPrim123", "InitialRec123", presence_token=tok)
    assert ac.has_recovery_pin() is True

    # 1. Attempt replace with WRONG current PIN
    prompt_pin_mock = MagicMock()
    with patch("builtins.input", return_value="y"), \
         patch("getpass.getpass", return_value="WrongCurrentPin"), \
         patch("setup_security._prompt_pin", prompt_pin_mock):
        _setup_access_control(ac)

    # Prompt for new PINs must NEVER have been called
    prompt_pin_mock.assert_not_called()

    # Failure must be recorded in LockoutManager
    state = ac._engine.lockout_manager.get_current_state()
    assert state.primary_failures == 1

    # Old PIN is still active
    # Advance time beyond 0s backoff to verify old PIN
    assert ac.verify_pin("InitialPrim123") is True

    # 2. Attempt replace with CORRECT current PIN
    with patch("builtins.input", return_value="y"), \
         patch("getpass.getpass", return_value="InitialPrim123"), \
         patch("setup_security._prompt_pin", side_effect=["BrandNewPrim456", "BrandNewRec456"]):
        _setup_access_control(ac)

    assert ac.verify_pin("BrandNewPrim456") is True
    assert ac.verify_recovery_pin("BrandNewRec456") is True
    assert ac.verify_pin("InitialPrim123") is False


def test_setup_security_case_c_legacy_mode_add_recovery_pin(tmp_path):
    """
    Case (c): Migrated legacy install (recovery_pin=None) offers to add recovery PIN.
    Primary PIN remains unchanged and valid.
    """
    mem_dir = tmp_path / "memory"
    mem_dir.mkdir(parents=True, exist_ok=True)
    legacy_file = mem_dir / "access_control.json"

    salt = os.urandom(16).hex()
    prim_pin = "ExistingLegacyPrim999"
    pwd_hash = hashlib.pbkdf2_hmac("sha256", prim_pin.encode("utf-8"), bytes.fromhex(salt), _KDF_ITERATIONS).hex()

    legacy_data = {"salt": salt, "hash": pwd_hash}
    legacy_file.write_text(json.dumps(legacy_data), encoding="utf-8")

    ac = AccessControl(path=legacy_file)
    assert ac.is_configured() is True
    assert ac.has_recovery_pin() is False

    # Run setup_security answering 'y' to add recovery PIN
    with patch("builtins.input", return_value="y"), \
         patch("setup_security._prompt_pin", return_value="NewlyAddedRecoveryPin777"):
        _setup_access_control(ac)

    assert ac.has_recovery_pin() is True
    assert ac.verify_recovery_pin("NewlyAddedRecoveryPin777") is True

    # Primary PIN was never changed and still verifies
    assert ac.verify_pin(prim_pin) is True
