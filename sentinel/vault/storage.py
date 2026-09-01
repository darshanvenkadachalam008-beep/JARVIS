"""OS-native secure master key storage for Sentinel Vault.

Supports:
- Windows: DPAPI (Data Protection API) via win32crypt / ctypes crypt32
- macOS: Keychain via keyring
- Linux: Secret Service / libsecret via keyring
- Fallback: Local master envelope for headless/testing environments
"""

import os
import sys
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional
import secrets
from filelock import FileLock

from sentinel.config.settings import default_settings

logger = logging.getLogger(__name__)


class StorageError(Exception):
    """Base exception for master key storage failures."""
    pass


class MasterKeyStorage(ABC):
    """Abstract interface for OS-native master key storage with pending-key rotation support."""

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Returns the identifier name of this storage backend."""
        pass

    @abstractmethod
    def get_or_create_master_key(self) -> bytes:
        """Retrieves existing 256-bit master key or generates and stores a new one."""
        pass

    @abstractmethod
    def store_master_key(self, new_key: bytes) -> None:
        """Saves a new primary master key to secure storage."""
        pass

    @abstractmethod
    def delete_master_key(self) -> None:
        """Deletes the primary master key."""
        pass

    @abstractmethod
    def store_pending_master_key(self, pending_key: bytes) -> str:
        """
        Saves a pending rotated master key in OS-native secure storage during rotation.
        Returns the exact backend name used to store the pending key.
        """
        pass

    @abstractmethod
    def get_pending_master_key(self, target_backend: Optional[str] = None) -> Optional[bytes]:
        """
        Retrieves the pending master key from OS-native secure storage.
        If target_backend is specified, targets that specific backend.
        """
        pass

    @abstractmethod
    def clear_pending_master_key(self, target_backend: Optional[str] = None) -> None:
        """Deletes any pending master key from OS-native secure storage."""
        pass

    def promote_pending_master_key(self, target_backend: Optional[str] = None) -> bytes:
        """Promotes the pending master key to primary and clears the pending slot."""
        pending = self.get_pending_master_key(target_backend=target_backend)
        if not pending:
            raise StorageError("No pending master key found to promote.")
        self.store_master_key(pending)
        self.clear_pending_master_key(target_backend=target_backend)
        return pending


class WindowsDPAPIStorage(MasterKeyStorage):
    """
    Windows DPAPI (Data Protection API) backend.
    Encrypts primary and pending master keys via CryptProtectData.
    """

    def __init__(self, vault_dir: Path):
        self.vault_dir = Path(vault_dir)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.key_file = self.vault_dir / "master_key.dpapi"
        self.pending_key_file = self.vault_dir / "master_key_pending.dpapi"
        self.lock_file = self.vault_dir / ".master_key.lock"

    @property
    def backend_name(self) -> str:
        return "windows_dpapi"

    def _protect(self, data: bytes) -> bytes:
        try:
            import win32crypt
            return win32crypt.CryptProtectData(data, "Sentinel Master Key", None, None, None, 0)
        except (ImportError, AttributeError):
            import ctypes
            from ctypes import wintypes

            class DATA_BLOB(ctypes.Structure):
                _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

            crypt32 = ctypes.windll.crypt32
            kernel32 = ctypes.windll.kernel32

            in_blob = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
            out_blob = DATA_BLOB()

            if not crypt32.CryptProtectData(ctypes.byref(in_blob), "Sentinel Master Key", None, None, None, 0, ctypes.byref(out_blob)):
                raise StorageError("CryptProtectData failed to encrypt master key.")

            try:
                protected = ctypes.string_at(out_blob.pbData, out_blob.cbData)
                return protected
            finally:
                kernel32.LocalFree(out_blob.pbData)

    def _unprotect(self, protected_data: bytes) -> bytes:
        try:
            import win32crypt
            _, data = win32crypt.CryptUnprotectData(protected_data, None, None, None, 0)
            return data
        except (ImportError, AttributeError):
            import ctypes
            from ctypes import wintypes

            class DATA_BLOB(ctypes.Structure):
                _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

            crypt32 = ctypes.windll.crypt32
            kernel32 = ctypes.windll.kernel32

            in_blob = DATA_BLOB(len(protected_data), ctypes.cast(ctypes.create_string_buffer(protected_data), ctypes.POINTER(ctypes.c_byte)))
            out_blob = DATA_BLOB()

            if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
                raise StorageError("CryptUnprotectData failed to decrypt master key.")

            try:
                decrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
                return decrypted
            finally:
                kernel32.LocalFree(out_blob.pbData)

    def get_or_create_master_key(self) -> bytes:
        with FileLock(str(self.lock_file), timeout=5.0):
            if self.key_file.exists():
                with open(self.key_file, "rb") as f:
                    protected = f.read()
                return self._unprotect(protected)

            new_key = secrets.token_bytes(32)
            self._store_master_key_unlocked(new_key)
            return new_key

    def _store_master_key_unlocked(self, new_key: bytes) -> None:
        if len(new_key) != 32:
            raise ValueError("Master key must be exactly 32 bytes.")
        protected = self._protect(new_key)
        temp_file = self.vault_dir / f"master.tmp.{secrets.token_hex(8)}"
        with open(temp_file, "wb") as f:
            f.write(protected)
        temp_file.replace(self.key_file)

    def store_master_key(self, new_key: bytes) -> None:
        with FileLock(str(self.lock_file), timeout=5.0):
            self._store_master_key_unlocked(new_key)

    def delete_master_key(self) -> None:
        with FileLock(str(self.lock_file), timeout=5.0):
            if self.key_file.exists():
                self.key_file.unlink()

    def store_pending_master_key(self, pending_key: bytes) -> str:
        if len(pending_key) != 32:
            raise ValueError("Master key must be exactly 32 bytes.")
        with FileLock(str(self.lock_file), timeout=5.0):
            protected = self._protect(pending_key)
            temp_file = self.vault_dir / f"pending.tmp.{secrets.token_hex(8)}"
            with open(temp_file, "wb") as f:
                f.write(protected)
            temp_file.replace(self.pending_key_file)
            return self.backend_name

    def get_pending_master_key(self, target_backend: Optional[str] = None) -> Optional[bytes]:
        with FileLock(str(self.lock_file), timeout=5.0):
            if not self.pending_key_file.exists():
                return None
            try:
                with open(self.pending_key_file, "rb") as f:
                    protected = f.read()
                return self._unprotect(protected)
            except Exception:
                return None

    def clear_pending_master_key(self, target_backend: Optional[str] = None) -> None:
        with FileLock(str(self.lock_file), timeout=5.0):
            if self.pending_key_file.exists():
                self.pending_key_file.unlink()


class FileFallbackStorage(MasterKeyStorage):
    """
    File-based master key storage (used exclusively for testing and headless/container environments).
    WARNING: Stores the master key in raw file on disk (.raw file).
    """

    def __init__(self, vault_dir: Path):
        self.vault_dir = Path(vault_dir)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.key_file = self.vault_dir / "master_key.raw"
        self.pending_key_file = self.vault_dir / "master_key_pending.raw"
        self.lock_file = self.vault_dir / ".fallback_master.lock"
        logger.warning(
            "INSECURE MASTER KEY STORAGE ACTIVE: FileFallbackStorage is storing master key in plaintext file %s",
            self.key_file,
        )

    @property
    def backend_name(self) -> str:
        return "file_fallback"

    def get_or_create_master_key(self) -> bytes:
        with FileLock(str(self.lock_file), timeout=5.0):
            if self.key_file.exists():
                with open(self.key_file, "rb") as f:
                    key = f.read()
                if len(key) == 32:
                    return key

            new_key = secrets.token_bytes(32)
            self._store_master_key_unlocked(new_key)
            return new_key

    def _store_master_key_unlocked(self, new_key: bytes) -> None:
        if len(new_key) != 32:
            raise ValueError("Master key must be exactly 32 bytes.")
        temp_file = self.vault_dir / f"master.tmp.{secrets.token_hex(8)}"
        with open(temp_file, "wb") as f:
            f.write(new_key)
        temp_file.replace(self.key_file)

    def store_master_key(self, new_key: bytes) -> None:
        with FileLock(str(self.lock_file), timeout=5.0):
            self._store_master_key_unlocked(new_key)

    def delete_master_key(self) -> None:
        with FileLock(str(self.lock_file), timeout=5.0):
            if self.key_file.exists():
                self.key_file.unlink()

    def store_pending_master_key(self, pending_key: bytes) -> str:
        if len(pending_key) != 32:
            raise ValueError("Master key must be exactly 32 bytes.")
        with FileLock(str(self.lock_file), timeout=5.0):
            temp_file = self.vault_dir / f"pending.tmp.{secrets.token_hex(8)}"
            with open(temp_file, "wb") as f:
                f.write(pending_key)
            temp_file.replace(self.pending_key_file)
            return self.backend_name

    def get_pending_master_key(self, target_backend: Optional[str] = None) -> Optional[bytes]:
        with FileLock(str(self.lock_file), timeout=5.0):
            if not self.pending_key_file.exists():
                return None
            with open(self.pending_key_file, "rb") as f:
                data = f.read()
            return data if len(data) == 32 else None

    def clear_pending_master_key(self, target_backend: Optional[str] = None) -> None:
        with FileLock(str(self.lock_file), timeout=5.0):
            if self.pending_key_file.exists():
                self.pending_key_file.unlink()


class KeyringMasterKeyStorage(MasterKeyStorage):
    """
    macOS Keychain and Linux Secret Service backend using the `keyring` library.
    Supports primary and pending master key slots with failover to FileFallbackStorage.
    """

    def __init__(
        self,
        service_name: str = "sentinel_vault",
        username: str = "master_key",
        vault_dir: Path | None = None,
    ):
        self.service_name = service_name
        self.username = username
        self.pending_username = f"{username}_pending"
        self.vault_dir = Path(vault_dir or default_settings.vault_dir)
        self._fallback_storage: Optional[FileFallbackStorage] = None

    @property
    def backend_name(self) -> str:
        return "keyring"

    def _get_fallback(self) -> FileFallbackStorage:
        if self._fallback_storage is None:
            logger.warning(
                "KEYRING RUNTIME DEGRADATION: Keyring unavailable or raised an error; falling back to FileFallbackStorage."
            )
            self._fallback_storage = FileFallbackStorage(self.vault_dir)
        return self._fallback_storage

    def get_or_create_master_key(self) -> bytes:
        try:
            import keyring
            stored_hex = keyring.get_password(self.service_name, self.username)
            if stored_hex:
                try:
                    key = bytes.fromhex(stored_hex)
                    if len(key) == 32:
                        return key
                except ValueError:
                    pass

            new_key = secrets.token_bytes(32)
            keyring.set_password(self.service_name, self.username, new_key.hex())
            return new_key
        except Exception as e:
            logger.warning(
                "Keyring backend error during get_or_create_master_key (%s); failing over to FileFallbackStorage.", e
            )
            return self._get_fallback().get_or_create_master_key()

    def store_master_key(self, new_key: bytes) -> None:
        if len(new_key) != 32:
            raise ValueError("Master key must be exactly 32 bytes.")
        try:
            import keyring
            keyring.set_password(self.service_name, self.username, new_key.hex())
        except Exception as e:
            logger.warning("Keyring backend error during store_master_key (%s); failing over to FileFallbackStorage.", e)
            self._get_fallback().store_master_key(new_key)

    def delete_master_key(self) -> None:
        try:
            import keyring
            keyring.delete_password(self.service_name, self.username)
        except Exception:
            if self._fallback_storage:
                self._fallback_storage.delete_master_key()

    def store_pending_master_key(self, pending_key: bytes) -> str:
        if len(pending_key) != 32:
            raise ValueError("Master key must be exactly 32 bytes.")
        try:
            import keyring
            keyring.set_password(self.service_name, self.pending_username, pending_key.hex())
            return "keyring"
        except Exception as e:
            logger.warning("Keyring backend error during store_pending_master_key (%s); failing over to FileFallbackStorage.", e)
            return self._get_fallback().store_pending_master_key(pending_key)

    def get_pending_master_key(self, target_backend: Optional[str] = None) -> Optional[bytes]:
        # If journal explicitly states fallback was used, fetch directly from fallback
        if target_backend == "file_fallback":
            return self._get_fallback().get_pending_master_key()

        try:
            import keyring
            stored_hex = keyring.get_password(self.service_name, self.pending_username)
            if stored_hex:
                key = bytes.fromhex(stored_hex)
                if len(key) == 32:
                    return key
            # Genuinely absent from the targeted backend — not an error, just missing.
            return None
        except Exception as e:
            if target_backend == "keyring":
                # The journal says this key lives in keyring specifically.
                # A transient keyring error here is NOT the same as "key is
                # missing" — don't silently reroute to a backend that never
                # held this key, or a real key looks permanently lost and
                # triggers a false RotationRecoveryError lockout.
                logger.error(
                    "Keyring backend error retrieving pending key explicitly targeted at "
                    "'keyring' (%s); NOT falling back, to avoid a false missing-key lockout. "
                    "Caller should retry.", e
                )
                raise StorageError(
                    f"Keyring backend transiently unavailable while retrieving pending master "
                    f"key (target_backend='keyring'): {e}"
                ) from e

            # No specific backend was targeted (legacy/undetermined caller) —
            # best-effort fallback retrieval is reasonable here since we don't
            # know for certain the key was ever in keyring to begin with.
            logger.warning(
                "Keyring backend error during get_pending_master_key (%s); "
                "no target_backend specified, attempting fallback retrieval.", e
            )
            return self._get_fallback().get_pending_master_key()

    def clear_pending_master_key(self, target_backend: Optional[str] = None) -> None:
        if target_backend == "file_fallback":
            if self._fallback_storage:
                self._fallback_storage.clear_pending_master_key()
            return

        try:
            import keyring
            keyring.delete_password(self.service_name, self.pending_username)
        except Exception:
            if self._fallback_storage:
                self._fallback_storage.clear_pending_master_key()


def get_platform_key_storage(vault_dir: Path | None = None, force_backend: str | None = None) -> MasterKeyStorage:
    """
    Factory creating appropriate OS-native master key storage.
    """
    v_dir = Path(vault_dir or default_settings.vault_dir)

    if force_backend == "fallback":
        logger.warning("Explicit fallback master key storage selected.")
        return FileFallbackStorage(v_dir)
    elif force_backend == "windows":
        return WindowsDPAPIStorage(v_dir)
    elif force_backend == "keyring":
        return KeyringMasterKeyStorage(vault_dir=v_dir)

    if sys.platform == "win32":
        return WindowsDPAPIStorage(v_dir)
    elif sys.platform in ("darwin", "linux"):
        try:
            import keyring
            return KeyringMasterKeyStorage(vault_dir=v_dir)
        except ImportError:
            logger.warning("Keyring package missing on %s; falling back to FileFallbackStorage.", sys.platform)
            return FileFallbackStorage(v_dir)
    else:
        logger.warning("Unsupported platform %s; falling back to FileFallbackStorage.", sys.platform)
        return FileFallbackStorage(v_dir)
