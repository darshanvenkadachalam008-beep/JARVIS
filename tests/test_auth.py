"""Comprehensive test suite for sentinel.auth module."""

import os
import time
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch, MagicMock
import pytest
from filelock import FileLock

from sentinel.auth.models import AuthTier, PinHashRecord, IdentityCredentials, LockoutState
from sentinel.auth.hasher import PinHasher
from sentinel.auth.lockout import (
    LockoutManager,
    HardLockoutError,
    TemporaryLockoutError,
    LockAcquisitionError,
)
from sentinel.auth.enrollment import (
    EnrollmentManager,
    EnrollmentError,
    PresenceTokenError,
    UnauthorizedEnrollmentError,
)
from sentinel.auth.engine import (
    AuthEngine,
    require_auth,
    AuthorizationError,
    UnauthorizedError,
    AuthorizationBlockedError,
)


# ============================================================================
# 1. Hasher Tests
# ============================================================================

def test_hasher_minimum_iterations_enforced():
    with pytest.raises(ValueError, match="at least 480,000"):
        PinHasher(iterations=100_000)


def test_hasher_pin_length_validation():
    hasher = PinHasher(iterations=480_000)
    with pytest.raises(ValueError, match="at least 4 characters"):
        hasher.hash_pin("123")
    with pytest.raises(ValueError, match="at least 4 characters"):
        hasher.hash_pin("")


def test_hasher_generates_independent_salts():
    hasher = PinHasher(iterations=480_000)
    rec1 = hasher.hash_pin("1234")
    rec2 = hasher.hash_pin("1234")

    assert rec1.salt_hex != rec2.salt_hex
    assert rec1.hash_hex != rec2.hash_hex
    assert len(bytes.fromhex(rec1.salt_hex)) == 16
    assert len(bytes.fromhex(rec1.hash_hex)) == 32


def test_hasher_verify_valid_and_invalid_pins():
    hasher = PinHasher(iterations=480_000)
    rec = hasher.hash_pin("SecurePin99!")

    assert hasher.verify_pin("SecurePin99!", rec) is True
    assert hasher.verify_pin("WrongPin00!", rec) is False
    assert hasher.verify_pin("", rec) is False
    assert hasher.verify_pin("securepin99!", rec) is False


def test_hasher_verify_corrupted_record():
    hasher = PinHasher(iterations=480_000)
    rec = hasher.hash_pin("123456")

    corrupt_rec = PinHashRecord(salt_hex="not_a_hex", hash_hex=rec.hash_hex, iterations=rec.iterations)
    assert hasher.verify_pin("123456", corrupt_rec) is False


def test_hasher_custom_salt_validation():
    hasher = PinHasher(iterations=480_000)
    with pytest.raises(ValueError, match="at least 16 bytes"):
        hasher.hash_pin("123456", salt=b"short_salt")

    custom_salt = os.urandom(16)
    rec = hasher.hash_pin("123456", salt=custom_salt)
    assert rec.salt_hex == custom_salt.hex()
    assert hasher.verify_pin("123456", rec) is True
    assert hasher.verify_pin("", rec) is False
    assert hasher.verify_pin("123456", None) is False


# ============================================================================
# 2. Lockout Tests
# ============================================================================

def test_lockout_primary_escalation(tmp_path):
    d = tmp_path / "lockout_prim"
    mgr = LockoutManager(d)
    mgr.initialize_clean_state()

    # Failures 1 and 2: 0s
    assert mgr.execute_atomic_primary_auth(is_system_initialized=True, verify_callback=lambda: False) is False
    assert mgr.execute_atomic_primary_auth(is_system_initialized=True, verify_callback=lambda: False) is False

    # Failure 3: 5s backoff
    assert mgr.execute_atomic_primary_auth(is_system_initialized=True, verify_callback=lambda: False) is False
    with pytest.raises(TemporaryLockoutError) as exc_info:
        mgr.execute_atomic_primary_auth(is_system_initialized=True, verify_callback=lambda: True)
    assert exc_info.value.remaining_seconds > 0

    # Manually test failure 4 (30s) and 5, 6 (300s) and 7 (Hard lockout) calculations
    assert mgr._get_primary_backoff(4) == 30.0
    assert mgr._get_primary_backoff(5) == 300.0
    assert mgr._get_primary_backoff(6) == 300.0
    assert mgr._get_primary_backoff(7) == float("inf")

    # Set 7 failures and assert HardLockoutError
    state_file = d / "lockout_state.json"
    with open(state_file, "r") as f:
        st = json.load(f)
    st["primary_failures"] = 7
    st["primary_hard_locked"] = True
    st["primary_locked_until"] = None
    with open(state_file, "w") as f:
        json.dump(st, f)

    with pytest.raises(HardLockoutError):
        mgr.execute_atomic_primary_auth(is_system_initialized=True, verify_callback=lambda: True)


def test_lockout_primary_soft_cap_when_no_recovery_pin(tmp_path):
    """
    Verifies that when has_recovery_pin=False (e.g. legacy migrated install without recovery PIN),
    primary PIN failures >= 7 do NOT trigger a permanent hard lockout. Instead, backoff soft-caps
    at 3600s, raising TemporaryLockoutError rather than HardLockoutError.
    """
    d = tmp_path / "lockout_no_rec"
    mgr = LockoutManager(d)
    mgr.initialize_clean_state()

    # Drive 8 consecutive failures with has_recovery_pin=False
    for i in range(8):
        with patch("time.time", return_value=100_000.0 + (i * 10_000.0)):
            res = mgr.execute_atomic_primary_auth(
                is_system_initialized=True,
                verify_callback=lambda: False,
                has_recovery_pin=False,
            )
            assert res is False

    # Check state file directly: 8 failures, NOT hard locked, locked_until is set
    st = mgr.get_current_state()
    assert st.primary_failures == 8
    assert st.primary_hard_locked is False
    assert st.primary_locked_until is not None

    # Verify backoff calculation caps at 3600.0s
    assert mgr._get_primary_backoff(7, cap_at_max_soft=True) == 3600.0
    assert mgr._get_primary_backoff(8, cap_at_max_soft=True) == 3600.0
    assert mgr._get_primary_backoff(99, cap_at_max_soft=True) == 3600.0

    # Next attempt during lock window raises TemporaryLockoutError (NOT HardLockoutError)
    with patch("time.time", return_value=100_000.0 + 70_000.0 + 100.0):
        with pytest.raises(TemporaryLockoutError) as exc_info:
            mgr.execute_atomic_primary_auth(
                is_system_initialized=True,
                verify_callback=lambda: True,
                has_recovery_pin=False,
            )
        assert exc_info.value.target == "primary"
        assert exc_info.value.remaining_seconds > 0


def test_lockout_recovery_escalation(tmp_path):
    d = tmp_path / "lockout_rec"
    mgr = LockoutManager(d)
    mgr.initialize_clean_state()

    # Failures 1, 2: 0s
    assert mgr.execute_atomic_recovery_auth(is_system_initialized=True, verify_callback=lambda: False) is False
    assert mgr.execute_atomic_recovery_auth(is_system_initialized=True, verify_callback=lambda: False) is False

    # Failure 3: 5s
    assert mgr.execute_atomic_recovery_auth(is_system_initialized=True, verify_callback=lambda: False) is False
    with pytest.raises(TemporaryLockoutError):
        mgr.execute_atomic_recovery_auth(is_system_initialized=True, verify_callback=lambda: True)

    # Test calculation curves for 4 (30s), 5-6 (300s), 7 (1800s), 8 (3600s)
    assert mgr._get_recovery_backoff(4) == 30.0
    assert mgr._get_recovery_backoff(5) == 300.0
    assert mgr._get_recovery_backoff(6) == 300.0
    assert mgr._get_recovery_backoff(7) == 1800.0
    assert mgr._get_recovery_backoff(8) == 3600.0


def test_fail_closed_on_deleted_state_file(tmp_path):
    d = tmp_path / "lockout_del"
    mgr = LockoutManager(d)
    mgr.initialize_clean_state()

    state_file = d / "lockout_state.json"
    assert state_file.exists()
    state_file.unlink()

    with pytest.raises(HardLockoutError):
        mgr.execute_atomic_primary_auth(is_system_initialized=True, verify_callback=lambda: True)


def test_fail_closed_on_corrupted_state_file(tmp_path):
    d = tmp_path / "lockout_corr"
    mgr = LockoutManager(d)
    mgr.initialize_clean_state()

    state_file = d / "lockout_state.json"
    with open(state_file, "w", encoding="utf-8") as f:
        f.write("{invalid_json: true, broken...")

    with pytest.raises(HardLockoutError):
        mgr.execute_atomic_primary_auth(is_system_initialized=True, verify_callback=lambda: True)


def test_lock_acquisition_timeout_fails_closed(tmp_path):
    d = tmp_path / "lockout_timeout"
    mgr = LockoutManager(d, lock_timeout_seconds=0.2)
    mgr.initialize_clean_state()

    lock_file = d / ".lockout.lock"
    external_lock = FileLock(str(lock_file))

    locked_event = threading.Event()
    release_event = threading.Event()

    def lock_holder():
        with external_lock:
            locked_event.set()
            release_event.wait(timeout=3.0)

    t = threading.Thread(target=lock_holder, daemon=True)
    t.start()
    locked_event.wait(timeout=1.0)

    try:
        with pytest.raises(LockAcquisitionError):
            mgr.execute_atomic_primary_auth(is_system_initialized=True, verify_callback=lambda: True)
        with pytest.raises(LockAcquisitionError):
            mgr.execute_atomic_recovery_auth(is_system_initialized=True, verify_callback=lambda: True)
    finally:
        release_event.set()
        t.join()


def test_recovery_success_clears_hard_lockout(tmp_path):
    d = tmp_path / "lockout_rec_success"
    mgr = LockoutManager(d)
    mgr.initialize_clean_state()

    # Set hard lockout
    state_file = d / "lockout_state.json"
    with open(state_file, "r") as f:
        st = json.load(f)
    st["primary_failures"] = 7
    st["primary_hard_locked"] = True
    with open(state_file, "w") as f:
        json.dump(st, f)

    with pytest.raises(HardLockoutError):
        mgr.execute_atomic_primary_auth(is_system_initialized=True, verify_callback=lambda: True)

    # Recovery success clears it
    assert mgr.execute_atomic_recovery_auth(is_system_initialized=True, verify_callback=lambda: True) is True

    # Primary auth should succeed now
    assert mgr.execute_atomic_primary_auth(is_system_initialized=True, verify_callback=lambda: True) is True


# ============================================================================
# 3. Enrollment Tests
# ============================================================================

def test_first_run_requires_presence_token(tmp_path):
    auth_dir = tmp_path / "enroll_req"
    mgr = EnrollmentManager(auth_dir=auth_dir, hasher=PinHasher(480_000))
    assert not mgr.is_initialized()

    with pytest.raises(PresenceTokenError, match="requires physical presence token"):
        mgr.enroll(primary_pin="123456", recovery_pin="654321")

    with pytest.raises(PresenceTokenError, match="Invalid or expired"):
        mgr.enroll(primary_pin="123456", recovery_pin="654321", presence_token="invalid_token_123")


def test_first_run_expired_presence_token(tmp_path):
    auth_dir = tmp_path / "enroll_exp"
    mgr = EnrollmentManager(auth_dir=auth_dir, hasher=PinHasher(480_000), presence_token_ttl=1)
    token = mgr.generate_presence_challenge(print_to_console=False)
    time.sleep(1.1)

    with pytest.raises(PresenceTokenError, match="Invalid or expired"):
        mgr.enroll(primary_pin="123456", recovery_pin="654321", presence_token=token)


def test_first_run_successful_enrollment_and_token_consumption(tmp_path):
    auth_dir = tmp_path / "enroll_success"
    mgr = EnrollmentManager(auth_dir=auth_dir, hasher=PinHasher(480_000))
    token = mgr.generate_presence_challenge(print_to_console=False)

    success = mgr.enroll(primary_pin="123456", recovery_pin="987654", presence_token=token)
    assert success is True
    assert mgr.is_initialized()

    with pytest.raises(UnauthorizedEnrollmentError):
        mgr.enroll(primary_pin="newpin1", recovery_pin="newpin2", presence_token=token)


def test_identical_primary_and_recovery_pins_rejected(tmp_path):
    auth_dir = tmp_path / "enroll_ident"
    mgr = EnrollmentManager(auth_dir=auth_dir, hasher=PinHasher(480_000))
    token = mgr.generate_presence_challenge(print_to_console=False)

    with pytest.raises(ValueError, match="must not be identical"):
        mgr.enroll(primary_pin="123456", recovery_pin="123456", presence_token=token)


def test_generate_presence_token_rejected_when_initialized(tmp_path):
    auth_dir = tmp_path / "enroll_reinit"
    mgr = EnrollmentManager(auth_dir=auth_dir, hasher=PinHasher(480_000))
    token = mgr.generate_presence_challenge(print_to_console=False)
    mgr.enroll(primary_pin="123456", recovery_pin="987654", presence_token=token)

    with pytest.raises(EnrollmentError, match="already initialized"):
        mgr.generate_presence_challenge(print_to_console=False)


def test_re_enrollment_requires_valid_current_pin(tmp_path):
    auth_dir = tmp_path / "enroll_re"
    hasher = PinHasher(480_000)
    mgr = EnrollmentManager(auth_dir=auth_dir, hasher=hasher)
    token = mgr.generate_presence_challenge(print_to_console=False)
    mgr.enroll(primary_pin="PrimaryPass1", recovery_pin="RecoveryPass1", presence_token=token)

    with pytest.raises(UnauthorizedEnrollmentError, match="requires current Primary PIN"):
        mgr.enroll(primary_pin="NewPrimaryPass2", recovery_pin="NewRecoveryPass2")

    with pytest.raises(UnauthorizedEnrollmentError, match="Invalid current Primary PIN"):
        mgr.enroll(
            primary_pin="NewPrimaryPass2",
            recovery_pin="NewRecoveryPass2",
            current_primary_pin="WrongOldPIN",
        )

    success = mgr.enroll(
        primary_pin="NewPrimaryPass2",
        recovery_pin="NewRecoveryPass2",
        current_primary_pin="PrimaryPass1",
    )
    assert success is True
    creds = mgr.get_credentials()
    assert hasher.verify_pin("NewPrimaryPass2", creds.primary_pin) is True
    assert hasher.verify_pin("NewRecoveryPass2", creds.recovery_pin) is True


def test_enrollment_lock_timeout_fails_closed(tmp_path):
    auth_dir = tmp_path / "enroll_lock_test"
    enroll_mgr = EnrollmentManager(auth_dir=auth_dir, lock_timeout_seconds=0.2)
    token = enroll_mgr.generate_presence_challenge(print_to_console=False)

    lock_file = auth_dir / ".enrollment.lock"
    ext_lock = FileLock(str(lock_file))

    locked_event = threading.Event()
    release_event = threading.Event()

    def lock_holder():
        with ext_lock:
            locked_event.set()
            release_event.wait(timeout=3.0)

    t = threading.Thread(target=lock_holder, daemon=True)
    t.start()
    locked_event.wait(timeout=1.0)

    try:
        with pytest.raises(LockAcquisitionError):
            enroll_mgr.enroll("Primary123", "Recovery123", presence_token=token)
    finally:
        release_event.set()
        t.join()


def test_windows_presence_security_mismatched_sid_rejected(tmp_path):
    auth_dir = tmp_path / "enroll_win_sid"
    mgr = EnrollmentManager(auth_dir=auth_dir, hasher=PinHasher(480_000))
    token = mgr.generate_presence_challenge(print_to_console=True)

    with patch.object(mgr, "_check_security_descriptor_allowlist", return_value=False):
        with patch("os.name", "nt"):
            assert mgr._verify_and_consume_presence_token(token) is False


def test_windows_presence_security_foreign_owner_sid_rejected(tmp_path):
    """Verifies that a file owned by a foreign user SID is rejected on Windows."""
    if os.name == "nt":
        import win32security

        auth_dir = tmp_path / "enroll_win_foreign_owner"
        mgr = EnrollmentManager(auth_dir=auth_dir, hasher=PinHasher(480_000))
        token = mgr.generate_presence_challenge(print_to_console=False)

        # Mock owner SID returning a non-user, non-admin SID (e.g. World SID)
        foreign_sid = win32security.CreateWellKnownSid(win32security.WinWorldSid, None)

        mock_sd = MagicMock()
        mock_sd.GetSecurityDescriptorOwner.return_value = foreign_sid
        mock_sd.GetSecurityDescriptorDacl.return_value = None

        with patch("win32security.GetFileSecurity", return_value=mock_sd):
            assert mgr._verify_windows_file_security(mgr.presence_file) is False


def test_windows_presence_security_broad_group_dacl_rejected(tmp_path):
    """Verifies that a file granting Allow ACE to Authenticated Users or BUILTIN\\Users is rejected."""
    if os.name == "nt":
        import win32security
        import ntsecuritycon
        import win32api

        auth_dir = tmp_path / "enroll_win_dacl"
        mgr = EnrollmentManager(auth_dir=auth_dir, hasher=PinHasher(480_000))
        token = mgr.generate_presence_challenge(print_to_console=False)

        # Build a DACL with Authenticated Users (broad group)
        user_sid = win32security.GetTokenInformation(
            win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY),
            win32security.TokenUser,
        )[0]
        auth_users_sid = win32security.CreateWellKnownSid(win32security.WinAuthenticatedUserSid, None)

        dacl = win32security.ACL()
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, user_sid)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_GENERIC_READ, auth_users_sid)

        sd = win32security.SECURITY_DESCRIPTOR()
        sd.SetSecurityDescriptorOwner(user_sid, False)
        sd.SetSecurityDescriptorDacl(1, dacl, False)
        win32security.SetFileSecurity(str(mgr.presence_file), win32security.DACL_SECURITY_INFORMATION, sd)

        # Must reject due to broad group in DACL
        assert mgr._verify_windows_file_security(mgr.presence_file) is False


def test_real_windows_presence_security_local_user(tmp_path):
    """Executes live Windows security verification with real pywin32 API calls if on Windows."""
    if os.name == "nt":
        auth_dir = tmp_path / "enroll_real_win"
        mgr = EnrollmentManager(auth_dir=auth_dir, hasher=PinHasher(480_000))
        token = mgr.generate_presence_challenge(print_to_console=False)
        assert mgr.presence_file.exists()
        assert mgr._verify_windows_file_security(mgr.presence_file) is True


# ============================================================================
# 4. Engine & E2E Security Tests
# ============================================================================

def test_uninitialized_engine_rejects_auth(tmp_path):
    auth_dir = tmp_path / "engine_uninit"
    engine = AuthEngine(auth_dir=auth_dir, iterations=480_000)
    assert not engine.is_initialized()
    with pytest.raises(UnauthorizedError, match="not initialized"):
        engine.authenticate_primary("123456")
    with pytest.raises(UnauthorizedError, match="not initialized"):
        engine.authenticate_recovery("654321")


def test_full_enrollment_and_authentication_flow(tmp_path):
    auth_dir = tmp_path / "engine_flow"
    engine = AuthEngine(auth_dir=auth_dir, iterations=480_000)
    token = engine.generate_presence_challenge(print_to_console=False)
    assert len(token) == 32

    assert engine.enroll(
        primary_pin="MasterPIN2026!",
        recovery_pin="EmergencyRecoveryKey2026!",
        presence_token=token,
    )
    assert engine.is_initialized()
    assert engine.authenticate_primary("MasterPIN2026!") is True
    assert engine.authenticate_primary("WrongPIN") is False


def test_hard_lockout_and_recovery_flow(tmp_path):
    auth_dir = tmp_path / "engine_lock_rec"
    engine = AuthEngine(auth_dir=auth_dir, iterations=480_000)
    token = engine.generate_presence_challenge(print_to_console=False)
    engine.enroll(
        primary_pin="MasterPIN2026!",
        recovery_pin="EmergencyRecoveryKey2026!",
        presence_token=token,
    )

    state_file = engine.auth_dir / "lockout_state.json"
    with open(state_file, "r") as f:
        st = json.load(f)
    st["primary_failures"] = 7
    st["primary_hard_locked"] = True
    with open(state_file, "w") as f:
        json.dump(st, f)

    with pytest.raises(HardLockoutError):
        engine.authenticate_primary("MasterPIN2026!")

    assert engine.authenticate_recovery("EmergencyRecoveryKey2026!") is True
    assert engine.authenticate_primary("MasterPIN2026!") is True


def test_fail_closed_mid_session_state_deletion(tmp_path):
    auth_dir = tmp_path / "engine_del_state"
    engine = AuthEngine(auth_dir=auth_dir, iterations=480_000)
    token = engine.generate_presence_challenge(print_to_console=False)
    engine.enroll(
        primary_pin="MasterPIN2026!",
        recovery_pin="EmergencyRecoveryKey2026!",
        presence_token=token,
    )
    assert engine.authenticate_primary("MasterPIN2026!") is True

    state_file = engine.auth_dir / "lockout_state.json"
    assert state_file.exists()
    state_file.unlink()

    with pytest.raises(HardLockoutError):
        engine.authenticate_primary("MasterPIN2026!")

    assert engine.authenticate_recovery("EmergencyRecoveryKey2026!") is True
    assert engine.authenticate_primary("MasterPIN2026!") is True


def test_lock_acquisition_timeout_fails_closed_in_engine(tmp_path):
    auth_dir = tmp_path / "engine_timeout"
    engine = AuthEngine(auth_dir=auth_dir, iterations=480_000, lock_timeout_seconds=0.2)
    token = engine.generate_presence_challenge(print_to_console=False)
    engine.enroll(
        primary_pin="MasterPIN2026!",
        recovery_pin="EmergencyRecoveryKey2026!",
        presence_token=token,
    )

    lock_file = engine.auth_dir / ".lockout.lock"
    external_lock = FileLock(str(lock_file))

    locked_event = threading.Event()
    release_event = threading.Event()

    def lock_holder():
        with external_lock:
            locked_event.set()
            release_event.wait(timeout=3.0)

    t = threading.Thread(target=lock_holder, daemon=True)
    t.start()
    locked_event.wait(timeout=1.0)

    try:
        with pytest.raises(LockAcquisitionError):
            engine.authenticate_primary("MasterPIN2026!")
        with pytest.raises(LockAcquisitionError):
            engine.authenticate_recovery("EmergencyRecoveryKey2026!")
    finally:
        release_event.set()
        t.join()


def test_tier_authorization_and_require_auth_decorator(tmp_path):
    auth_dir = tmp_path / "engine_tiers"
    engine = AuthEngine(auth_dir=auth_dir, iterations=480_000)
    token = engine.generate_presence_challenge(print_to_console=False)
    engine.enroll(
        primary_pin="MasterPIN2026!",
        recovery_pin="EmergencyRecoveryKey2026!",
        presence_token=token,
    )

    class SecuredService:
        def __init__(self, auth_engine: AuthEngine):
            self.auth_engine = auth_engine

        @require_auth(AuthTier.READ_ONLY)
        def get_status(self):
            return "status_ok"

        @require_auth(AuthTier.REVERSIBLE)
        def toggle_debug(self):
            return "debug_toggled"

        @require_auth(AuthTier.DESTRUCTIVE)
        def delete_cache(self, pin=None):
            return "cache_deleted"

        @require_auth(AuthTier.SYSTEM_LEVEL)
        def rotate_keys(self, pin=None):
            return "keys_rotated"

        @require_auth(AuthTier.BLOCKED)
        def catastrophic_action(self, pin=None):
            return "never_executes"

    svc = SecuredService(engine)

    assert svc.get_status() == "status_ok"
    assert svc.toggle_debug() == "debug_toggled"

    with pytest.raises(UnauthorizedError, match="No PIN provided"):
        svc.delete_cache()

    with pytest.raises(UnauthorizedError, match="Invalid Primary PIN"):
        svc.delete_cache(pin="WrongPin")

    assert svc.delete_cache(pin="MasterPIN2026!") == "cache_deleted"
    assert svc.rotate_keys(pin="MasterPIN2026!") == "keys_rotated"

    with pytest.raises(AuthorizationBlockedError, match="BLOCKED"):
        svc.catastrophic_action(pin="MasterPIN2026!")


def test_require_auth_missing_engine_decorator():
    @require_auth(AuthTier.DESTRUCTIVE)
    def orphan_function(pin=None):
        return "ok"

    with pytest.raises(AuthorizationError, match="No AuthEngine instance provided"):
        orphan_function(pin="1234")


def test_auth_engine_event_sink_forwarding(tmp_path):
    events = []

    def sink(event_type, details):
        events.append((event_type, details))

    auth_dir = tmp_path / "engine_sink_test"
    engine = AuthEngine(auth_dir=auth_dir, iterations=480_000, event_sink=sink)

    token = engine.generate_presence_challenge(print_to_console=False)
    engine.enroll("Primary123", "Recovery123", presence_token=token)

    assert engine.authenticate_primary("Primary123") is True
    assert engine.authenticate_primary("WrongPrimary") is False
    assert any(e[0] == "primary_auth_success" for e in events)


def test_concurrent_atomic_authentication_no_lost_updates(tmp_path):
    """
    Spawns concurrent worker threads submitting invalid PINs simultaneously.
    Asserts that atomic check-verify-record transactions prevent lost updates,
    and the failure count strictly increments without race conditions.
    """
    auth_dir = tmp_path / "concurrent_auth_test"
    engine = AuthEngine(auth_dir=auth_dir, iterations=480_000, lock_timeout_seconds=5.0)

    token = engine.generate_presence_challenge(print_to_console=False)
    engine.enroll("MasterPIN2026!", "RecoveryKey2026!", presence_token=token)

    # Run 2 concurrent attempts (which fall within the 0s backoff tier for failures 1 & 2)
    num_threads = 2
    results = []

    def worker_attempt():
        return engine.authenticate_primary("WrongGuessPIN")

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker_attempt) for _ in range(num_threads)]
        for f in futures:
            results.append(f.result())

    # Both must return False (failed authentication)
    assert results == [False, False]

    # Read the final state file and assert exact equality
    with open(engine.auth_dir / "lockout_state.json", "r") as f:
        state_data = json.load(f)

    # Exactly 2 failures recorded with zero lost updates
    assert state_data["primary_failures"] == 2
    assert state_data["primary_hard_locked"] is False


def test_enrollment_symlink_rejection_and_corrupt_files(tmp_path):
    auth_dir = tmp_path / "enroll_symlink_test"
    mgr = EnrollmentManager(auth_dir=auth_dir, hasher=PinHasher(480_000))
    token = mgr.generate_presence_challenge(print_to_console=False)

    real_file = mgr.presence_file
    if hasattr(os, "symlink"):
        try:
            symlink_file = auth_dir / "symlink.token"
            os.symlink(real_file, symlink_file)
            mgr.presence_file = symlink_file
            assert mgr._verify_and_consume_presence_token(token) is False
        except (OSError, NotImplementedError):
            pass
        finally:
            mgr.presence_file = real_file

    with open(mgr.credentials_file, "w") as f:
        f.write("invalid json")
    assert mgr.is_initialized() is False
    assert mgr.get_credentials() is None


def test_windows_presence_security_live_gate_uses_fd_method(tmp_path):
    """Verifies that _verify_and_consume_presence_token delegates to _verify_windows_file_security_on_fd and NOT path-based."""
    auth_dir = tmp_path / "enroll_win_fd_gate"
    mgr = EnrollmentManager(auth_dir=auth_dir, hasher=PinHasher(480_000))
    token = mgr.generate_presence_challenge(print_to_console=False)

    with patch.object(mgr, "_verify_windows_file_security_on_fd", return_value=False) as mock_fd_check, \
         patch.object(mgr, "_verify_windows_file_security") as mock_path_check, \
         patch("os.name", "nt"):
        assert mgr._verify_and_consume_presence_token(token) is False
        mock_fd_check.assert_called_once()
        # Ensure the argument passed is an int file descriptor
        assert isinstance(mock_fd_check.call_args[0][0], int)
        mock_path_check.assert_not_called()


def test_real_windows_presence_security_fd_handle_race_resilience(tmp_path):
    """
    Real Windows verification test for presence token handle security:
    Note on Windows sharing semantics:
      In production, Python's os.open() routes through the CRT (_wsopen_s) with _SH_DENYNO,
      which maps to CreateFile(dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE). This default
      sharing mode already blocks uncoordinated file replacement/deletion (ERROR_SHARING_VIOLATION)
      while the legitimate descriptor is open.

      This test deliberately opens the test descriptor with FILE_SHARE_DELETE to model and verify
      _verify_windows_file_security_on_fd's correctness as defense-in-depth under a widened sharing
      mode:
      1. Generates presence challenge token with valid owner-only DACL.
      2. Opens descriptor with FILE_SHARE_DELETE.
      3. Swaps/replaces the file at the path on disk with a file having an insecure broad DACL.
      4. Asserts _verify_windows_file_security_on_fd(fd) returns True (validates original handle).
      5. Control assertion: asserts _verify_windows_file_security(path) returns False on the swapped path.
    """
    if os.name == "nt":
        import msvcrt
        import win32api
        import win32file
        import win32security
        import ntsecuritycon

        auth_dir = tmp_path / "enroll_win_fd_real"
        mgr = EnrollmentManager(auth_dir=auth_dir, hasher=PinHasher(480_000))
        token = mgr.generate_presence_challenge(print_to_console=False)

        # 1. Open original token file with FILE_SHARE_DELETE to permit on-disk replacement
        h = win32file.CreateFile(
            str(mgr.presence_file),
            win32file.GENERIC_READ | ntsecuritycon.DELETE,
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE | win32file.FILE_SHARE_DELETE,
            None,
            win32file.OPEN_EXISTING,
            0,
            None,
        )
        fd = msvcrt.open_osfhandle(int(h), os.O_RDONLY)

        try:
            # 2. Swap out file at path: move original, create replacement with broad DACL
            moved_file = mgr.presence_file.with_suffix(".moved")
            mgr.presence_file.rename(moved_file)

            # Create replacement file at mgr.presence_file with broad DACL (Authenticated Users)
            mgr.presence_file.write_text("swapped_insecure_payload")

            proc = win32api.GetCurrentProcess()
            token_handle = win32security.OpenProcessToken(proc, win32security.TOKEN_QUERY)
            user_sid, _ = win32security.GetTokenInformation(token_handle, win32security.TokenUser)
            auth_users_sid = win32security.CreateWellKnownSid(win32security.WinAuthenticatedUserSid, None)

            dacl = win32security.ACL()
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, user_sid)
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_GENERIC_READ, auth_users_sid)

            sd = win32security.SECURITY_DESCRIPTOR()
            sd.SetSecurityDescriptorOwner(user_sid, False)
            sd.SetSecurityDescriptorDacl(1, dacl, False)
            win32security.SetFileSecurity(str(mgr.presence_file), win32security.DACL_SECURITY_INFORMATION, sd)

            # 3. Handle-based check on open fd: MUST return True (validates original handle)
            assert mgr._verify_windows_file_security_on_fd(fd) is True

            # 4. Control check on swapped path: MUST return False (catches insecure file at path)
            assert mgr._verify_windows_file_security(mgr.presence_file) is False
        finally:
            os.close(fd)


def test_dacl_protection_applied_on_all_writes(tmp_path):
    """Verifies that apply_owner_only_dacl is called on every write to credentials.json and lockout_state.json."""
    auth_dir = tmp_path / "dacl_all_writes"
    with patch("sentinel.auth.enrollment.apply_owner_only_dacl") as mock_enroll_dacl, \
         patch("sentinel.auth.lockout.apply_owner_only_dacl") as mock_lockout_dacl:

        engine = AuthEngine(auth_dir=auth_dir, iterations=480_000)
        token = engine.generate_presence_challenge(print_to_console=False)

        # 1. Presence challenge generation applies DACL
        mock_enroll_dacl.assert_called_with(engine.enrollment_manager.presence_file)

        # 2. First-run enrollment applies DACL to credentials.json and lockout_state.json
        engine.enroll("Primary123", "Recovery123", presence_token=token)
        mock_enroll_dacl.assert_called_with(engine.enrollment_manager.credentials_file)
        mock_lockout_dacl.assert_called_with(engine.lockout_manager.state_file)

        mock_enroll_dacl.reset_mock()
        mock_lockout_dacl.reset_mock()

        # 3. Failed authentication applies DACL to lockout_state.json
        engine.authenticate_primary("WrongPin")
        mock_lockout_dacl.assert_called_with(engine.lockout_manager.state_file)
        mock_lockout_dacl.reset_mock()

        # 4. Successful authentication applies DACL to lockout_state.json
        engine.authenticate_primary("Primary123")
        mock_lockout_dacl.assert_called_with(engine.lockout_manager.state_file)
        mock_lockout_dacl.reset_mock()

        # 5. Re-enrollment / credential update applies DACL to credentials.json and lockout_state.json
        engine.enroll("NewPrimary456", "NewRecovery456", current_primary_pin="Primary123")
        mock_enroll_dacl.assert_called_with(engine.enrollment_manager.credentials_file)
        mock_lockout_dacl.assert_called_with(engine.lockout_manager.state_file)

