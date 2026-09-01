"""
core/secure_vault.py — Encrypted Secrets Vault (DPAPI & OS Keyring Backed)
=============================================================================
Replaces plaintext config/api_keys.json and config/firebase-service-account.json
with an authenticated AES-encrypted file (config/vault.enc), with master keys
protected directly in the OS secure storage (Windows Credential Manager / DPAPI,
macOS Keychain, Linux Secret Service).

Zero-Plaintext Invariant
------------------------
- Secrets (Gemini, OpenRouter, GitHub, Firebase Service Account, Twilio, etc.)
  are decrypted only in-process memory.
- Plaintext secret files (config/api_keys.json and config/firebase-service-account.json)
  are securely overwritten and removed once migrated.
- Key derivation uses PBKDF2-HMAC-SHA256 with 480,000 iterations and a per-vault random salt.
- On Windows, DPAPI (CryptProtectData / CryptUnprotectData) secures the vault key without
  exposing credentials in plaintext files or unprotected environment variables.
"""
from __future__ import annotations

import base64
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    import keyring
    _KEYRING_OK = True
except ImportError:
    _KEYRING_OK = False

_KEYRING_SERVICE = "mark-xxxix-or-vault"
_KEYRING_USER = "vault-key"
_KDF_ITERATIONS = 480_000


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


# ── Windows DPAPI Support ───────────────────────────────────────────────────

def _is_windows() -> bool:
    return sys.platform.startswith("win")


def _dpapi_protect(data: bytes) -> bytes:
    """Encrypts bytes using Windows DPAPI (CryptProtectData)."""
    if not _is_windows():
        raise NotImplementedError("DPAPI is only supported on Windows.")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    blob_in = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
    blob_out = DATA_BLOB()
    if ctypes.windll.crypt32.CryptProtectData(ctypes.byref(blob_in), "jarvis-vault-key", None, None, None, 0, ctypes.byref(blob_out)):
        ciphertext = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return ciphertext
    raise RuntimeError("CryptProtectData failed")


def _dpapi_unprotect(data: bytes) -> bytes:
    """Decrypts bytes using Windows DPAPI (CryptUnprotectData)."""
    if not _is_windows():
        raise NotImplementedError("DPAPI is only supported on Windows.")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    blob_in = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
    blob_out = DATA_BLOB()
    if ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
        plaintext = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return plaintext
    raise RuntimeError("CryptUnprotectData failed")


# ── Secure Vault Engine ─────────────────────────────────────────────────────

class SecureVault:
    def __init__(self, path: Optional[Path] = None):
        self._base = _base_dir()
        self.path = path or (self._base / "config" / "vault.enc")
        self._dpapi_key_path = self.path.parent / "vault_key.dpapi"
        self._fernet: Optional[Fernet] = None
        self._data: dict[str, Any] = {}

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=_KDF_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

    def exists(self) -> bool:
        return self.path.exists()

    def set_master_password(self, password: str) -> None:
        """Creates a brand-new empty vault protected by `password`."""
        salt = os.urandom(16)
        key = self._derive_key(password, salt)
        self._fernet = Fernet(key)
        self._data = {}
        self._write(salt)

        # Store in OS keyring
        if _KEYRING_OK:
            try:
                keyring.set_password(_KEYRING_SERVICE, _KEYRING_USER, password)
            except Exception:
                pass

        # Windows DPAPI fallback backup
        if _is_windows():
            try:
                dpapi_blob = _dpapi_protect(password.encode("utf-8"))
                self._dpapi_key_path.write_bytes(dpapi_blob)
            except Exception:
                pass

    def unlock(self, password: Optional[str] = None) -> bool:
        """Unlocks an existing vault. Tries provided password, or automated OS Keyring/DPAPI."""
        if not self.exists():
            raise FileNotFoundError(
                f"No vault at {self.path}. Call set_master_password() first."
            )
        raw = self.path.read_bytes()
        salt, ciphertext = raw[:16], raw[16:]

        candidates = []
        if password is not None:
            # Explicit password supplied: test ONLY this password
            candidates.append(password)
        else:
            # 1. OS Keyring
            if _KEYRING_OK:
                try:
                    cached = keyring.get_password(_KEYRING_SERVICE, _KEYRING_USER)
                    if cached:
                        candidates.append(cached)
                except Exception:
                    pass

            # 2. Windows DPAPI Key File
            if _is_windows() and self._dpapi_key_path.exists():
                try:
                    dpapi_data = self._dpapi_key_path.read_bytes()
                    recovered = _dpapi_unprotect(dpapi_data).decode("utf-8")
                    if recovered:
                        candidates.append(recovered)
                except Exception:
                    pass

            # 3. Interactive prompt if no automatic key found
            if not candidates and sys.stdin.isatty():
                candidates.append(getpass.getpass("Vault master password: "))

        for pw in candidates:
            key = self._derive_key(pw, salt)
            try:
                f = Fernet(key)
                self._data = json.loads(f.decrypt(ciphertext).decode("utf-8"))
                self._fernet = f
                return True
            except (InvalidToken, Exception):
                continue
        return False

    def _write(self, salt: bytes) -> None:
        assert self._fernet is not None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self._data).encode("utf-8")
        ciphertext = self._fernet.encrypt(payload)
        self.path.write_bytes(salt + ciphertext)
        try:
            os.chmod(self.path, 0o600)
        except Exception:
            pass

    def _save(self) -> None:
        salt = self.path.read_bytes()[:16] if self.exists() else os.urandom(16)
        self._write(salt)

    def get(self, name: str, default: Any = None) -> Any:
        if self._fernet is None:
            raise RuntimeError("Vault is locked. Call unlock() first.")
        return self._data.get(name, default)

    def set(self, name: str, value: Any) -> None:
        if self._fernet is None:
            raise RuntimeError("Vault is locked. Call unlock() first.")
        self._data[name] = value
        self._save()

    def all_keys(self) -> list[str]:
        if self._fernet is None:
            return []
        return list(self._data.keys())

    def migrate_legacy_secrets(self, delete_originals: bool = True) -> list[str]:
        """
        Pulls every key from config/api_keys.json and firebase-service-account.json into the vault,
        and securely deletes the plaintext original files.
        """
        migrated = []
        legacy_keys_path = self._base / "config" / "api_keys.json"
        legacy_fb_path = self._base / "config" / "firebase-service-account.json"

        if legacy_keys_path.exists():
            try:
                data = json.loads(legacy_keys_path.read_text(encoding="utf-8"))
                for k, v in data.items():
                    self.set(k, v)
                    migrated.append(k)
            except Exception as e:
                print(f"[SecureVault] Could not migrate api_keys.json: {e}")

        if legacy_fb_path.exists():
            try:
                fb_data = json.loads(legacy_fb_path.read_text(encoding="utf-8"))
                self.set("firebase_service_account", fb_data)
                migrated.append("firebase_service_account")
            except Exception as e:
                print(f"[SecureVault] Could not migrate firebase-service-account.json: {e}")

        if delete_originals and migrated:
            for p in (legacy_keys_path, legacy_fb_path):
                if p.exists():
                    _secure_delete(p)

        return migrated


def _secure_delete(path: Path) -> None:
    """Overwrites file contents with random bytes before deleting from filesystem."""
    try:
        if path.is_file():
            length = path.stat().st_size
            with open(path, "r+b") as f:
                f.write(os.urandom(length))
                f.flush()
                os.fsync(f.fileno())
    except Exception:
        pass
    finally:
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass


# ── Global Convenience Accessors ────────────────────────────────────────────

_vault_singleton: Optional[SecureVault] = None


def unlock_global_vault(password: Optional[str] = None) -> bool:
    """Call once at startup to unlock the process-wide vault singleton."""
    global _vault_singleton
    vault = SecureVault()
    if not vault.exists():
        return False
    ok = vault.unlock(password)
    if ok:
        _vault_singleton = vault
    return ok


def get_secret(name: str, default: Any = None) -> Any:
    """
    Retrieves a secret from the unlocked vault.
    If vault is not initialized yet and legacy plaintext exists, falls back only during setup.
    """
    global _vault_singleton
    if _vault_singleton is not None:
        try:
            return _vault_singleton.get(name, default)
        except RuntimeError:
            pass

    # Try automatic unlock if vault exists
    vault = SecureVault()
    if vault.exists():
        try:
            if vault.unlock():
                _vault_singleton = vault
                return vault.get(name, default)
        except Exception:
            pass
        return default

    # Fallback to legacy file only if vault has never been created
    legacy_path = _base_dir() / "config" / "api_keys.json"
    if legacy_path.exists():
        try:
            data = json.loads(legacy_path.read_text(encoding="utf-8"))
            return data.get(name, default)
        except Exception:
            return default

    return default