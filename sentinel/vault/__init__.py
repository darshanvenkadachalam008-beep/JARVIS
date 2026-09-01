"""Sentinel Vault package: OS-native encrypted secrets store."""

from sentinel.vault.storage import (
    MasterKeyStorage,
    WindowsDPAPIStorage,
    KeyringMasterKeyStorage,
    FileFallbackStorage,
    get_platform_key_storage,
)
from sentinel.vault.crypto import (
    encrypt_payload,
    decrypt_payload,
    wipe_buffer,
    CryptoError,
    DecryptionError,
)
from sentinel.vault.models import SecretMetadata
from sentinel.vault.store import (
    VaultStore,
    VaultError,
    SecretNotFoundError,
    RotationRecoveryError,
)

__all__ = [
    "MasterKeyStorage",
    "WindowsDPAPIStorage",
    "KeyringMasterKeyStorage",
    "FileFallbackStorage",
    "get_platform_key_storage",
    "encrypt_payload",
    "decrypt_payload",
    "wipe_buffer",
    "CryptoError",
    "DecryptionError",
    "SecretMetadata",
    "VaultStore",
    "VaultError",
    "SecretNotFoundError",
    "RotationRecoveryError",
]
