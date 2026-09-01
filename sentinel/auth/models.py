"""Data models and enums for the Sentinel Authorization Engine."""
from enum import IntEnum
from typing import Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class AuthTier(IntEnum):
    """Authorization tiers for operations."""
    READ_ONLY = 0      # No side effects; no credentials required
    REVERSIBLE = 1     # Benign or reversible side effects; no credentials required
    DESTRUCTIVE = 2    # Modifies or deletes data; requires Primary PIN
    SYSTEM_LEVEL = 3   # System/daemon config, policy changes; requires Primary PIN
    BLOCKED = 4        # Catastrophic operations; unconditionally denied


class PinHashRecord(BaseModel):
    """Cryptographic hash record for a stored PIN."""
    salt_hex: str
    hash_hex: str
    iterations: int = 600_000
    algorithm: str = "pbkdf2_sha256"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class IdentityCredentials(BaseModel):
    """Persisted credential bundle containing primary and recovery hashes."""
    is_initialized: bool = True
    primary_pin: PinHashRecord
    recovery_pin: Optional[PinHashRecord] = None  # None on migrated legacy installs
    enrolled_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    version: int = 1


class LockoutState(BaseModel):
    """Persisted fail-closed lockout tracking state."""
    primary_failures: int = 0
    primary_locked_until: Optional[float] = None  # Unix timestamp
    primary_hard_locked: bool = False

    recovery_failures: int = 0
    recovery_locked_until: Optional[float] = None  # Unix timestamp

    last_attempt_at: Optional[str] = None
    state_version: int = 1


class AuthResult(BaseModel):
    """Result of an authentication attempt."""
    success: bool
    tier: Optional[AuthTier] = None
    error_message: Optional[str] = None
    lockout_remaining_seconds: float = 0.0
    is_hard_locked: bool = False
