"""Primary Authorization Engine and decorator guards for Sentinel."""

import functools
from pathlib import Path
from typing import Optional, Callable, Dict, Any

from sentinel.auth.models import AuthTier, AuthResult
from sentinel.auth.hasher import PinHasher
from sentinel.auth.lockout import (
    LockoutManager,
    LockoutException,
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
from sentinel.anomaly.detector import AnomalyDetector
from sentinel.anomaly.models import AnomalyVerdict
from sentinel.config.settings import default_settings


class AuthorizationError(Exception):
    """Base exception for authorization failures."""
    pass


class UnauthorizedError(AuthorizationError):
    """Raised when authentication fails or valid PIN is missing for gated tiers."""
    pass


class AuthorizationBlockedError(AuthorizationError):
    """Raised when an operation is classified as BLOCKED (unconditionally denied)."""
    pass


class AuthEngine:
    """Central engine providing tiered authorization and authentication services."""

    def __init__(
        self,
        auth_dir: Optional[Path] = None,
        iterations: Optional[int] = None,
        lock_timeout_seconds: Optional[float] = None,
        event_sink: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ):
        self.auth_dir = Path(auth_dir or default_settings.auth_dir)
        self.auth_dir.mkdir(parents=True, exist_ok=True)
        self.event_sink = event_sink

        self.hasher = PinHasher(iterations=iterations or default_settings.pbkdf2_iterations)
        self.lockout_manager = LockoutManager(
            state_dir=self.auth_dir,
            lock_timeout_seconds=lock_timeout_seconds if lock_timeout_seconds is not None else default_settings.lock_timeout_seconds,
            event_sink=self.event_sink,
        )
        self.enrollment_manager = EnrollmentManager(
            auth_dir=self.auth_dir,
            hasher=self.hasher,
            lockout_manager=self.lockout_manager,
            presence_token_ttl=default_settings.presence_token_ttl_seconds,
            event_sink=self.event_sink,
        )
        self.anomaly_detector = AnomalyDetector(
            auth_dir=self.auth_dir,
            lock_timeout_seconds=lock_timeout_seconds if lock_timeout_seconds is not None else default_settings.lock_timeout_seconds,
            event_sink=self.event_sink,
        )

    def _emit_event(self, event_type: str, details: Dict[str, Any]) -> None:
        if self.event_sink:
            try:
                self.event_sink(event_type, details)
            except Exception:
                pass

    def is_initialized(self) -> bool:
        """Returns True if the daemon has enrolled credentials."""
        return self.enrollment_manager.is_initialized()

    def generate_presence_challenge(self, print_to_console: bool = True) -> str:
        """Generates a first-run local-only presence token."""
        return self.enrollment_manager.generate_presence_challenge(for_step_up=False, print_to_console=print_to_console)

    def generate_step_up_challenge(self, print_to_console: bool = True) -> str:
        """Generates a real time-bound single-use physical presence challenge token for step-up auth."""
        return self.enrollment_manager.generate_presence_challenge(for_step_up=True, print_to_console=print_to_console)

    def verify_and_consume_presence_token(self, token: str) -> bool:
        """Verifies and immediately consumes a single-use physical presence challenge token."""
        return self.enrollment_manager.verify_and_consume_presence_token(token)

    def enroll(
        self,
        primary_pin: str,
        recovery_pin: str,
        current_primary_pin: Optional[str] = None,
        presence_token: Optional[str] = None,
    ) -> bool:
        """Enrolls or modifies identity credentials."""
        initialized_before = self.is_initialized()
        success = self.enrollment_manager.enroll(
            primary_pin=primary_pin,
            recovery_pin=recovery_pin,
            current_primary_pin=current_primary_pin,
            presence_token=presence_token,
        )
        if success and not initialized_before:
            try:
                self.anomaly_detector.seed_initial_enrollment()
            except Exception as e:
                self._emit_event("anomaly_baseline_seed_failed_during_enrollment", {"error": str(e)})
        return success

    def authenticate_primary(self, pin: str) -> bool:
        """
        Authenticates a user with their Primary PIN atomically.
        Fails closed on lockout, corruption, or missing credentials.
        Entire check -> verify -> record sequence happens under a single held lock.
        """
        initialized = self.is_initialized()
        if not initialized:
            raise UnauthorizedError("Sentinel is not initialized. Complete first-run enrollment first.")

        creds = self.enrollment_manager.get_credentials()
        if not creds:
            raise UnauthorizedError("Failed to retrieve credentials. Failing closed.")

        def verify_fn() -> bool:
            return self.hasher.verify_pin(pin, creds.primary_pin)

        has_recovery = creds.recovery_pin is not None
        return self.lockout_manager.execute_atomic_primary_auth(
            is_system_initialized=True,
            verify_callback=verify_fn,
            has_recovery_pin=has_recovery,
        )

    def authenticate_recovery(self, recovery_pin: str) -> bool:
        """
        Authenticates a user with their Recovery PIN atomically.
        Clears hard lockout upon success. Fails closed on lock timeout or missing recovery PIN.
        Entire check -> verify -> record sequence happens under a single held lock.
        """
        initialized = self.is_initialized()
        if not initialized:
            raise UnauthorizedError("Sentinel is not initialized.")

        creds = self.enrollment_manager.get_credentials()
        if not creds:
            raise UnauthorizedError("Failed to retrieve credentials. Failing closed.")

        if creds.recovery_pin is None:
            self._emit_event("recovery_auth_no_recovery_pin_configured", {})
            raise UnauthorizedError("No Recovery PIN is configured for this installation.")

        def verify_fn() -> bool:
            return self.hasher.verify_pin(recovery_pin, creds.recovery_pin)

        return self.lockout_manager.execute_atomic_recovery_auth(
            is_system_initialized=True,
            verify_callback=verify_fn,
        )

    def check_authorization(
        self,
        tier: AuthTier,
        pin: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        presence_token: Optional[str] = None,
        step_up_token: Optional[str] = None,
    ) -> AnomalyVerdict:
        """
        Validates authorization for a requested tier with anomaly-based friction elevation.
        - BLOCKED: strictly and unconditionally rejected.
        - Anomaly baseline evaluation:
          * Normal context:
            - READ_ONLY / REVERSIBLE: permitted without credentials.
            - DESTRUCTIVE / SYSTEM_LEVEL: requires valid Primary PIN.
          * Anomalous context (score >= threshold):
            - READ_ONLY: permitted.
            - REVERSIBLE: elevated to require valid Primary PIN.
            - DESTRUCTIVE / SYSTEM_LEVEL: elevated to require Multi-Factor Verification
              (Primary PIN + real validated Presence/Step-up Challenge Token).
        """
        if tier == AuthTier.BLOCKED:
            raise AuthorizationBlockedError(
                "Execution BLOCKED: This operation is classified as universally hazardous "
                "and cannot be executed regardless of authorization tier or credentials."
            )

        # Evaluate contextual anomaly score
        ctx = context or {}
        verdict = self.anomaly_detector.evaluate(
            current_time=ctx.get("time"),
            network_id=ctx.get("network_id"),
            command_tier=tier.name,
        )

        if verdict.elevate_friction:
            # 1. READ_ONLY remains permitted
            if tier == AuthTier.READ_ONLY:
                return verdict

            # 2. REVERSIBLE under elevated friction requires Primary PIN
            if tier == AuthTier.REVERSIBLE:
                if not pin:
                    raise UnauthorizedError(
                        f"Tier {tier.name} requires Primary PIN due to elevated anomaly risk (score {verdict.score})."
                    )
                if not self.authenticate_primary(pin):
                    raise UnauthorizedError(
                        f"Tier {tier.name} authentication failed: Invalid Primary PIN under elevated friction."
                    )
                # Success under anomaly intentionally DOES NOT call record_success()
                # to prevent poisoning the baseline with anomalous contexts.
                return verdict

            # 3. DESTRUCTIVE and SYSTEM_LEVEL under elevated friction require PIN + real verified step_up presence token
            if tier in (AuthTier.DESTRUCTIVE, AuthTier.SYSTEM_LEVEL):
                if not pin:
                    raise UnauthorizedError(
                        f"Tier {tier.name} requires Primary PIN authentication. No PIN provided."
                    )
                if not self.authenticate_primary(pin):
                    raise UnauthorizedError(
                        f"Tier {tier.name} authentication failed: Invalid Primary PIN."
                    )
                # Elevated friction step-up factor check
                token = presence_token or step_up_token or ctx.get("presence_token") or ctx.get("step_up_token")
                if not token:
                    raise UnauthorizedError(
                        f"Tier {tier.name} requires multi-factor step-up verification due to elevated anomaly risk (score {verdict.score}). "
                        "Missing physical presence challenge token."
                    )
                if not self.verify_and_consume_presence_token(token):
                    raise UnauthorizedError(
                        f"Tier {tier.name} multi-factor step-up verification failed: "
                        "Invalid, expired, or reused physical presence challenge token."
                    )
                # Success under anomaly step-up intentionally DOES NOT call record_success()
                # to prevent poisoning the baseline with anomalous contexts.
                return verdict

        # Normal trust path
        if tier in (AuthTier.READ_ONLY, AuthTier.REVERSIBLE):
            return verdict

        if tier in (AuthTier.DESTRUCTIVE, AuthTier.SYSTEM_LEVEL):
            if not pin:
                raise UnauthorizedError(
                    f"Tier {tier.name} requires Primary PIN authentication. No PIN provided."
                )
            if not self.authenticate_primary(pin):
                raise UnauthorizedError(
                    f"Tier {tier.name} authentication failed: Invalid Primary PIN."
                )
            self.anomaly_detector.record_success(
                current_time=ctx.get("time"),
                network_id=ctx.get("network_id"),
                command_tier=tier.name,
            )
            return verdict

        return verdict


def require_auth(tier: AuthTier, engine: Optional[AuthEngine] = None):
    """
    Decorator for gating functions by AuthTier.
    Passes 'pin' from keyword arguments or kwargs['auth_pin'] to verify authorization.
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if tier == AuthTier.BLOCKED:
                raise AuthorizationBlockedError(
                    f"Action '{func.__name__}' is classified as BLOCKED and cannot be executed."
                )

            # For AuthEngine resolution
            pin = kwargs.get("pin") or kwargs.get("auth_pin")
            context = kwargs.get("context") or kwargs.get("auth_context")
            presence_token = kwargs.get("presence_token") or kwargs.get("step_up_token")

            auth_eng = engine
            if auth_eng is None and len(args) > 0 and hasattr(args[0], "auth_engine"):
                auth_eng = getattr(args[0], "auth_engine")

            if auth_eng is None:
                if tier in (AuthTier.READ_ONLY, AuthTier.REVERSIBLE):
                    return func(*args, **kwargs)
                raise AuthorizationError(
                    f"Cannot enforce @require_auth on '{func.__name__}': No AuthEngine instance provided."
                )

            auth_eng.check_authorization(
                tier,
                pin=pin,
                context=context,
                presence_token=presence_token,
            )
            return func(*args, **kwargs)

        return wrapper
    return decorator
