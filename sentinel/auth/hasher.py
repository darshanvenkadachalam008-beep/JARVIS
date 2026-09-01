"""Cryptographic PIN hashing and constant-time verification for Sentinel.

Algorithm Choice:
PBKDF2-HMAC-SHA256 (with 600,000 iterations and 16-byte cryptographically secure salts)
is selected over Argon2id for Phase 1 because it is natively supported by the standard
`cryptography` and `hashlib` libraries without requiring external compiled C/Rust
extensions on diverse operating systems (Windows, macOS, Linux). 600,000 iterations
provides strong computational resistance against parallel offline dictionary attacks
while maintaining responsive local evaluation (<150ms).
"""

import os
import hmac
from typing import Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from sentinel.auth.models import PinHashRecord


DEFAULT_ITERATIONS = 600_000
SALT_BYTES = 16
KEY_LENGTH_BYTES = 32


class PinHasher:
    """Handles secure hashing and constant-time verification of PINs."""

    def __init__(self, iterations: int = DEFAULT_ITERATIONS):
        if iterations < 480_000:
            raise ValueError("PBKDF2 iterations must be at least 480,000 as per security requirements.")
        self.iterations = iterations

    def hash_pin(self, pin: str, salt: bytes | None = None) -> PinHashRecord:
        """Hashes a plaintext PIN using PBKDF2-HMAC-SHA256 with a unique random salt."""
        if not pin or len(pin.strip()) < 4:
            raise ValueError("PIN must be at least 4 characters long.")

        if salt is None:
            salt = os.urandom(SALT_BYTES)
        elif len(salt) < 16:
            raise ValueError("Salt must be at least 16 bytes.")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH_BYTES,
            salt=salt,
            iterations=self.iterations,
        )
        derived_key = kdf.derive(pin.encode("utf-8"))

        return PinHashRecord(
            salt_hex=salt.hex(),
            hash_hex=derived_key.hex(),
            iterations=self.iterations,
            algorithm="pbkdf2_sha256",
        )

    def verify_pin(self, pin: str, record: PinHashRecord) -> bool:
        """Verifies a plaintext PIN against a stored record in constant time."""
        if not pin or not record or not record.salt_hex or not record.hash_hex:
            return False

        try:
            salt = bytes.fromhex(record.salt_hex)
            expected_key = bytes.fromhex(record.hash_hex)
        except ValueError:
            return False

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH_BYTES,
            salt=salt,
            iterations=record.iterations,
        )
        try:
            derived_key = kdf.derive(pin.encode("utf-8"))
            # Constant-time comparison to prevent timing attacks
            return hmac.compare_digest(derived_key, expected_key)
        except Exception:
            return False
