"""Sentinel Authentication and Tiered Authorization Module."""

from sentinel.auth.models import (
    AuthTier,
    PinHashRecord,
    IdentityCredentials,
    LockoutState,
    AuthResult,
)
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
from sentinel.auth.engine import (
    AuthEngine,
    AuthorizationError,
    UnauthorizedError,
    AuthorizationBlockedError,
    require_auth,
)

__all__ = [
    "AuthTier",
    "PinHashRecord",
    "IdentityCredentials",
    "LockoutState",
    "AuthResult",
    "PinHasher",
    "LockoutManager",
    "LockoutException",
    "HardLockoutError",
    "TemporaryLockoutError",
    "LockAcquisitionError",
    "EnrollmentManager",
    "EnrollmentError",
    "PresenceTokenError",
    "UnauthorizedEnrollmentError",
    "AuthEngine",
    "AuthorizationError",
    "UnauthorizedError",
    "AuthorizationBlockedError",
    "require_auth",
]
