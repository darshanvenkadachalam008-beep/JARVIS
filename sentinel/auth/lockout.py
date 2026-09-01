"""Fail-closed escalating lockout manager with dual counters and atomic file locking."""

import json
import time
from pathlib import Path
from typing import Callable, Optional, Dict, Any
from filelock import FileLock, Timeout
from datetime import datetime, timezone

from sentinel.auth.models import LockoutState
from sentinel.audit.security_utils import apply_owner_only_dacl


class LockoutException(Exception):
    """Base exception for lockout violations."""
    pass


class LockAcquisitionError(LockoutException):
    """Raised when filelock cannot be acquired within the timeout (fails closed)."""
    pass


class HardLockoutError(LockoutException):
    """Raised when primary authentication is in hard-lockout state."""
    pass


class TemporaryLockoutError(LockoutException):
    """Raised when an attempt is made during an active temporary backoff window."""
    def __init__(self, remaining_seconds: float, target: str = "primary"):
        super().__init__(f"{target.capitalize()} PIN is locked out. Try again in {remaining_seconds:.1f}s.")
        self.remaining_seconds = remaining_seconds
        self.target = target


class LockoutManager:
    """Manages independent primary and recovery lockout state with strict fail-closed invariants."""

    def __init__(
        self,
        state_dir: Path,
        lock_timeout_seconds: float = 2.0,
        event_sink: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.state_dir / "lockout_state.json"
        self.lock_file = self.state_dir / ".lockout.lock"
        self.lock_timeout = lock_timeout_seconds
        self.event_sink = event_sink

    def _emit_event(self, event_type: str, details: Dict[str, Any]) -> None:
        if self.event_sink:
            try:
                self.event_sink(event_type, details)
            except Exception:
                pass

    def _get_primary_backoff(self, failures: int, cap_at_max_soft: bool = False) -> float:
        """Calculates backoff duration in seconds for primary PIN failures."""
        if failures < 3:
            return 0.0
        elif failures == 3:
            return 5.0
        elif failures == 4:
            return 30.0
        elif failures in (5, 6):
            return 300.0
        else:
            if cap_at_max_soft:
                return 3600.0  # Legacy compatibility cap
            return float("inf")  # 7+ is hard lockout

    def _get_recovery_backoff(self, failures: int) -> float:
        """Calculates backoff duration in seconds for recovery PIN failures."""
        if failures < 3:
            return 0.0
        elif failures == 3:
            return 5.0
        elif failures == 4:
            return 30.0
        elif failures in (5, 6):
            return 300.0
        else:
            exponent = min(failures - 7, 6)
            return 1800.0 * (2 ** exponent)

    def _read_state_locked(self, is_system_initialized: bool) -> LockoutState:
        """Reads lockout state under file lock. Strictly fails closed if corrupted/missing on initialized systems."""
        if not self.state_file.exists():
            if is_system_initialized:
                self._emit_event("lockout_state_missing_fail_closed", {"state_file": str(self.state_file)})
                return LockoutState(
                    primary_failures=999,
                    primary_hard_locked=True,
                    recovery_failures=0,
                )
            else:
                return LockoutState()

        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return LockoutState.model_validate(data)
        except Exception as e:
            self._emit_event("lockout_state_corrupted_fail_closed", {"error": str(e)})
            return LockoutState(
                primary_failures=999,
                primary_hard_locked=True,
                recovery_failures=0,
            )

    def _write_state_locked(self, state: LockoutState) -> None:
        """Persists lockout state atomically under file lock."""
        temp_file = self.state_dir / f"lockout_state.tmp.{time.time_ns()}"
        data = state.model_dump()
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        temp_file.replace(self.state_file)
        apply_owner_only_dacl(self.state_file)

    def get_current_state(self, is_system_initialized: bool = True) -> LockoutState:
        """
        Advisory read of current lockout state under lock (for UI status / triage early returns).
        WARNING: This method must NEVER be used to make actual grant/deny authentication decisions.
        All enforcement decisions must occur exclusively within execute_atomic_primary_auth.
        """
        try:
            with FileLock(str(self.lock_file), timeout=self.lock_timeout):
                return self._read_state_locked(is_system_initialized)
        except Timeout:
            return LockoutState(primary_failures=999, primary_hard_locked=True)

    def execute_atomic_primary_auth(
        self,
        is_system_initialized: bool,
        verify_callback: Callable[[], bool],
        has_recovery_pin: bool = True,
    ) -> bool:
        """
        Executes check -> verify -> record as ONE atomic transaction under a single held FileLock.
        Prevents concurrent burst-guessing races and lost failure count updates.
        """
        try:
            with FileLock(str(self.lock_file), timeout=self.lock_timeout):
                state = self._read_state_locked(is_system_initialized)
                now = time.time()

                if state.primary_hard_locked:
                    raise HardLockoutError(
                        "Primary PIN is hard-locked due to excessive failures or state file corruption. Recovery PIN required."
                    )

                if state.primary_locked_until and now < state.primary_locked_until:
                    remaining = state.primary_locked_until - now
                    raise TemporaryLockoutError(remaining, target="primary")

                # Perform constant-time verification while holding the lock
                is_valid = verify_callback()
                state.last_attempt_at = datetime.now(timezone.utc).isoformat()

                if is_valid:
                    state.primary_failures = 0
                    state.primary_locked_until = None
                    state.primary_hard_locked = False
                    self._write_state_locked(state)
                    self._emit_event("primary_auth_success", {})
                    return True
                else:
                    state.primary_failures += 1
                    if has_recovery_pin and state.primary_failures >= 7:
                        state.primary_hard_locked = True
                        state.primary_locked_until = None
                        self._write_state_locked(state)
                        self._emit_event("primary_hard_lockout_triggered", {"failures": state.primary_failures})
                    else:
                        backoff = self._get_primary_backoff(state.primary_failures, cap_at_max_soft=(not has_recovery_pin))
                        state.primary_locked_until = (now + backoff) if backoff > 0 else None
                        self._write_state_locked(state)
                        if backoff > 0:
                            self._emit_event("primary_lockout_triggered", {"failures": state.primary_failures, "duration": backoff})
                    return False
        except Timeout as e:
            self._emit_event("lock_timeout_fail_closed", {"target": "primary_auth_atomic"})
            raise LockAcquisitionError("Failed to acquire state lock within timeout. Failing closed.") from e

    def execute_atomic_recovery_auth(
        self,
        is_system_initialized: bool,
        verify_callback: Callable[[], bool],
    ) -> bool:
        """
        Executes check -> verify -> record for Recovery PIN as ONE atomic transaction under a single held FileLock.
        """
        try:
            with FileLock(str(self.lock_file), timeout=self.lock_timeout):
                state = self._read_state_locked(is_system_initialized)
                now = time.time()

                if state.recovery_locked_until and now < state.recovery_locked_until:
                    remaining = state.recovery_locked_until - now
                    raise TemporaryLockoutError(remaining, target="recovery")

                is_valid = verify_callback()
                state.last_attempt_at = datetime.now(timezone.utc).isoformat()

                if is_valid:
                    new_state = LockoutState(
                        primary_failures=0,
                        primary_locked_until=None,
                        primary_hard_locked=False,
                        recovery_failures=0,
                        recovery_locked_until=None,
                        last_attempt_at=datetime.now(timezone.utc).isoformat(),
                    )
                    self._write_state_locked(new_state)
                    self._emit_event("recovery_auth_success_lockout_cleared", {})
                    return True
                else:
                    state.recovery_failures += 1
                    backoff = self._get_recovery_backoff(state.recovery_failures)
                    state.recovery_locked_until = now + backoff
                    self._write_state_locked(state)
                    self._emit_event("recovery_lockout_triggered", {"failures": state.recovery_failures, "duration": backoff})
                    return False
        except Timeout as e:
            self._emit_event("lock_timeout_fail_closed", {"target": "recovery_auth_atomic"})
            raise LockAcquisitionError("Failed to acquire state lock within timeout. Failing closed.") from e

    def initialize_clean_state(self) -> None:
        """Initializes a pristine lockout state file during fresh enrollment."""
        try:
            with FileLock(str(self.lock_file), timeout=self.lock_timeout):
                clean_state = LockoutState()
                self._write_state_locked(clean_state)
        except Timeout as e:
            raise LockAcquisitionError("Failed to acquire state lock within timeout.") from e

    def record_primary_failure_for_test(self, is_system_initialized: bool = True) -> float:
        """Helper to increment failure count directly in test fixtures."""
        return self.execute_atomic_primary_auth(is_system_initialized, lambda: False)

    def record_recovery_failure_for_test(self, is_system_initialized: bool = True) -> float:
        """Helper to increment recovery failure count directly in test fixtures."""
        return self.execute_atomic_recovery_auth(is_system_initialized, lambda: False)
