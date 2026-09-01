"""Authenticated symmetric envelope encryption using AES-256-GCM and zero-memory handling."""

import os
import ctypes
from typing import Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


VAULT_PAYLOAD_VERSION = 0x01
NONCE_LENGTH_BYTES = 12
KEY_LENGTH_BYTES = 32


class CryptoError(Exception):
    """Base exception for crypto operations."""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption or tag verification fails."""
    pass


def wipe_buffer(buf: Union[bytearray, memoryview]) -> None:
    """
    Overwrites mutable memory buffers with zeros in-place to prevent secret leakage in process memory.
    """
    if isinstance(buf, (bytearray, memoryview)):
        for i in range(len(buf)):
            buf[i] = 0


def encrypt_payload(plaintext: bytes, key: bytes, associated_data: bytes | None = None) -> bytes:
    """
    Encrypts plaintext bytes using AES-256-GCM with a random 12-byte nonce.
    Format: [VERSION (1B)] [NONCE (12B)] [CIPHERTEXT + TAG (var)]
    """
    if len(key) != KEY_LENGTH_BYTES:
        raise ValueError(f"AES-256 key must be exactly {KEY_LENGTH_BYTES} bytes.")

    nonce = os.urandom(NONCE_LENGTH_BYTES)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

    version_byte = bytes([VAULT_PAYLOAD_VERSION])
    return version_byte + nonce + ciphertext


def decrypt_payload(payload: bytes, key: bytes, associated_data: bytes | None = None) -> bytes:
    """
    Decrypts an AES-256-GCM payload with authenticated tag verification.
    """
    if len(key) != KEY_LENGTH_BYTES:
        raise ValueError(f"AES-256 key must be exactly {KEY_LENGTH_BYTES} bytes.")

    if len(payload) < (1 + NONCE_LENGTH_BYTES + 16):  # 1B version + 12B nonce + min 16B tag
        raise DecryptionError("Payload is too short to be a valid encrypted vault record.")

    version = payload[0]
    if version != VAULT_PAYLOAD_VERSION:
        raise DecryptionError(f"Unsupported payload version: {version}")

    nonce = payload[1 : 1 + NONCE_LENGTH_BYTES]
    ciphertext = payload[1 + NONCE_LENGTH_BYTES :]

    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext
    except Exception as e:
        raise DecryptionError("Decryption failed: corrupted data or incorrect master key.") from e
