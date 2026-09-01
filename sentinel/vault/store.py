"""Zero-plaintext secure secrets store with crash-resilient key rotation and secure file shredding."""

import os
import json
import secrets
import hashlib
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List, Union, Callable
from filelock import FileLock, Timeout
from datetime import datetime, timezone

from sentinel.vault.storage import MasterKeyStorage, get_platform_key_storage, StorageError
from sentinel.vault.crypto import encrypt_payload, decrypt_payload, wipe_buffer, DecryptionError
from sentinel.vault.models import SecretMetadata
from sentinel.config.settings import default_settings

logger = logging.getLogger(__name__)


class VaultError(Exception):
    """Base exception for vault store operations."""
    pass


class SecretNotFoundError(VaultError):
    """Raised when a requested secret key does not exist."""
    pass


class RotationRecoveryError(VaultError):
    """Raised when an unreadable or corrupted rotation journal prevents safe vault operations (fails closed)."""
    pass


class VaultStore:
    """
    Encrypted secrets store maintaining the zero-plaintext-on-disk invariant
    and crash-resilient two-phase key rotation with OS-protected pending keys.
    """

    def __init__(
        self,
        vault_dir: Path | None = None,
        key_storage: Optional[MasterKeyStorage] = None,
        lock_timeout_seconds: float = 5.0,
        event_sink: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ):
        self.vault_dir = Path(vault_dir or default_settings.vault_dir)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.entries_dir = self.vault_dir / "entries"
        self.entries_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.vault_dir / "vault_index.json"
        self.rotation_journal_file = self.vault_dir / "rotation_journal.json"
        self.lock_file = self.vault_dir / ".vault.lock"
        self.lock_timeout = lock_timeout_seconds
        self.event_sink = event_sink
        self.key_storage = key_storage or get_platform_key_storage(self.vault_dir)

        # Reconcile any leftover rotation journal on startup under lock
        with FileLock(str(self.lock_file), timeout=self.lock_timeout):
            self._recover_pending_rotation_locked()

    def _emit_event(self, event_type: str, details: Dict[str, Any]) -> None:
        if self.event_sink:
            try:
                self.event_sink(event_type, details)
            except Exception:
                pass

    def _key_to_filename(self, key: str) -> str:
        """Derives a deterministic, filesystem-safe filename hash for an arbitrary secret key."""
        hashed = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return f"{hashed}.enc"

    def _read_index_unlocked(self) -> Dict[str, Dict[str, Any]]:
        if not self.index_file.exists():
            return {}
        try:
            with open(self.index_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _write_index_unlocked(self, index: Dict[str, Dict[str, Any]]) -> None:
        temp_file = self.vault_dir / f"index.tmp.{secrets.token_hex(8)}"
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(index, f, indent=2)
        temp_file.replace(self.index_file)

    def _write_journal_atomic_locked(self, journal_data: Dict[str, Any]) -> None:
        """
        Atomically writes rotation journal to disk with restrictive 0o600 permissions
        and protected Windows DACL.
        """
        temp_file = self.vault_dir / f"journal.tmp.{secrets.token_hex(8)}"
        flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY

        fd = os.open(temp_file, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(journal_data, f, indent=2)

        # On Windows, set explicit protected DACL allowing only current user, SYSTEM, and Administrators
        if os.name == "nt":
            try:
                import win32api
                import win32security
                import ntsecuritycon

                proc = win32api.GetCurrentProcess()
                token_handle = win32security.OpenProcessToken(proc, win32security.TOKEN_QUERY)
                user_sid, _ = win32security.GetTokenInformation(token_handle, win32security.TokenUser)
                sys_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
                admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)

                dacl = win32security.ACL()
                dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, user_sid)
                dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, sys_sid)
                dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, admin_sid)

                sd = win32security.SECURITY_DESCRIPTOR()
                sd.SetSecurityDescriptorDacl(1, dacl, False)
                win32security.SetFileSecurity(
                    str(temp_file),
                    win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                    sd,
                )
            except Exception as e:
                logger.warning("Failed to apply restrictive Windows DACL to rotation journal (%s); default permissions apply.", e)

        temp_file.replace(self.rotation_journal_file)

    def _recover_pending_rotation_locked(self) -> None:
        """
        Recovers from an incomplete master key rotation.
        Strictly fails closed by raising RotationRecoveryError if the journal is corrupted or unreadable.
        """
        if not self.rotation_journal_file.exists():
            return

        try:
            with open(self.rotation_journal_file, "r", encoding="utf-8") as f:
                journal = json.load(f)
        except Exception as e:
            self._emit_event("vault_rotation_recovery_corrupted_fail_closed", {"error": str(e)})
            raise RotationRecoveryError(
                f"Rotation journal '{self.rotation_journal_file}' is corrupted or unreadable. "
                "Failing closed to prevent data loss."
            ) from e

        stage = journal.get("stage")
        staged_files = journal.get("staged_files", [])
        target_backend = journal.get("pending_key_backend")

        if not stage:
            raise RotationRecoveryError("Rotation journal is missing stage information.")

        pending_key = None
        max_attempts = 3
        last_storage_err = None
        for attempt in range(1, max_attempts + 1):
            try:
                pending_key = self.key_storage.get_pending_master_key(target_backend=target_backend)
                last_storage_err = None
                break
            except StorageError as e:
                last_storage_err = e
                logger.warning(
                    "Attempt %d/%d to retrieve pending master key failed: %s",
                    attempt, max_attempts, e,
                )
                if attempt < max_attempts:
                    import time
                    time.sleep(0.05 * attempt)

        if last_storage_err is not None:
            self._emit_event("vault_rotation_recovery_storage_error", {"error": str(last_storage_err)})
            raise RotationRecoveryError(
                f"Storage backend unavailable during rotation recovery: {last_storage_err}. "
                "Retry operation after backend is restored."
            ) from last_storage_err

        if stage in ("staged", "files_replacing"):
            if not pending_key:
                raise RotationRecoveryError("Rotation journal indicates staged files but no pending key exists in secure storage.")

            # Complete staged file replacement
            for temp_path_str, dest_path_str in staged_files:
                temp_p = Path(temp_path_str)
                dest_p = Path(dest_path_str)
                if temp_p.exists():
                    temp_p.replace(dest_p)

            # Promote pending key to primary in OS storage
            self.key_storage.promote_pending_master_key(target_backend=target_backend)

        elif stage == "files_committed":
            if pending_key:
                self.key_storage.promote_pending_master_key(target_backend=target_backend)

        # Remove journal file upon successful recovery
        if self.rotation_journal_file.exists():
            self.rotation_journal_file.unlink()

        logger.warning("Vault successfully recovered from interrupted master key rotation.")
        self._emit_event("vault_rotation_recovered_after_crash", {})

    def set_secret(
        self,
        key: str,
        value: Union[str, bytes],
        content_type: str = "text/plain",
        custom_metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Encrypts and stores a secret payload under the master key.
        """
        if not key or not isinstance(key, str):
            raise ValueError("Secret key must be a non-empty string.")

        raw_bytes = value.encode("utf-8") if isinstance(value, str) else bytes(value)

        with FileLock(str(self.lock_file), timeout=self.lock_timeout):
            self._recover_pending_rotation_locked()
            master_key = self.key_storage.get_or_create_master_key()
            encrypted_data = encrypt_payload(
                plaintext=raw_bytes,
                key=master_key,
                associated_data=key.encode("utf-8"),
            )

            # Store encrypted blob
            entry_filename = self._key_to_filename(key)
            entry_path = self.entries_dir / entry_filename
            temp_file = self.entries_dir / f"{entry_filename}.tmp.{secrets.token_hex(8)}"

            with open(temp_file, "wb") as f:
                f.write(encrypted_data)
            temp_file.replace(entry_path)

            # Update index
            index = self._read_index_unlocked()
            meta = SecretMetadata(
                key=key,
                created_at=index.get(key, {}).get("created_at", datetime.now(timezone.utc).isoformat()),
                updated_at=datetime.now(timezone.utc).isoformat(),
                content_type=content_type,
                custom_metadata=custom_metadata or {},
            )
            index[key] = meta.model_dump()
            self._write_index_unlocked(index)

            self._emit_event("vault_secret_set", {"key": key, "content_type": content_type})

    def get_secret(self, key: str) -> bytes:
        """
        Decrypts and returns the raw secret bytes in memory.
        Raises SecretNotFoundError if the key does not exist.
        """
        with FileLock(str(self.lock_file), timeout=self.lock_timeout):
            self._recover_pending_rotation_locked()
            index = self._read_index_unlocked()
            if key not in index:
                raise SecretNotFoundError(f"Secret '{key}' not found in vault.")

            entry_filename = self._key_to_filename(key)
            entry_path = self.entries_dir / entry_filename
            if not entry_path.exists():
                raise SecretNotFoundError(f"Secret data file for '{key}' is missing from disk.")

            with open(entry_path, "rb") as f:
                encrypted_data = f.read()

            master_key = self.key_storage.get_or_create_master_key()
            plaintext = decrypt_payload(
                payload=encrypted_data,
                key=master_key,
                associated_data=key.encode("utf-8"),
            )

            self._emit_event("vault_secret_accessed", {"key": key})
            return plaintext

    def get_secret_string(self, key: str, encoding: str = "utf-8") -> str:
        """Helper to return decrypted secret directly as a string."""
        return self.get_secret(key).decode(encoding)

    def has_secret(self, key: str) -> bool:
        """Returns True if the secret exists in the vault."""
        with FileLock(str(self.lock_file), timeout=self.lock_timeout):
            self._recover_pending_rotation_locked()
            index = self._read_index_unlocked()
            return key in index

    def list_secrets(self) -> List[str]:
        """Returns a list of all secret keys currently stored in the vault."""
        with FileLock(str(self.lock_file), timeout=self.lock_timeout):
            self._recover_pending_rotation_locked()
            index = self._read_index_unlocked()
            return sorted(list(index.keys()))

    def get_metadata(self, key: str) -> Optional[SecretMetadata]:
        """Returns metadata for a secret without decrypting the secret content."""
        with FileLock(str(self.lock_file), timeout=self.lock_timeout):
            self._recover_pending_rotation_locked()
            index = self._read_index_unlocked()
            if key not in index:
                return None
            return SecretMetadata.model_validate(index[key])

    def delete_secret(self, key: str) -> bool:
        """
        Deletes a secret entry and wipes its encrypted blob file.
        """
        with FileLock(str(self.lock_file), timeout=self.lock_timeout):
            self._recover_pending_rotation_locked()
            index = self._read_index_unlocked()
            if key not in index:
                return False

            entry_filename = self._key_to_filename(key)
            entry_path = self.entries_dir / entry_filename
            if entry_path.exists():
                # Securely overwrite before unlinking
                self._secure_wipe_file(entry_path)

            del index[key]
            self._write_index_unlocked(index)
            self._emit_event("vault_secret_deleted", {"key": key})
            return True

    def _secure_wipe_file(self, file_path: Path, passes: int = 3) -> None:
        """Overwrites file contents with random and zero bytes before unlinking."""
        if not file_path.exists():
            return
        size = file_path.stat().st_size
        try:
            with open(file_path, "ba+", buffering=0) as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(size))
                    f.flush()
                f.seek(0)
                f.write(b"\x00" * size)
                f.flush()
            file_path.unlink()
        except Exception:
            if file_path.exists():
                file_path.unlink()

    def migrate_plaintext_file(
        self,
        plaintext_path: Path,
        secret_key: str,
        content_type: str = "text/plain",
    ) -> None:
        """
        Migrates a legacy plaintext secret file into the encrypted vault,
        then performs a multi-pass secure wipe of the plaintext source file on disk.
        """
        p_path = Path(plaintext_path)
        if not p_path.exists():
            raise FileNotFoundError(f"Plaintext source file not found: {plaintext_path}")

        # Read into memory
        with open(p_path, "rb") as f:
            plaintext_data = f.read()

        # Store in vault
        self.set_secret(secret_key, plaintext_data, content_type=content_type)

        # Wipe memory copy of plaintext bytes
        b_array = bytearray(plaintext_data)
        wipe_buffer(b_array)

        # Multi-pass secure wipe and unlink plaintext file from disk
        self._secure_wipe_file(p_path)
        self._emit_event("vault_file_migrated", {"source_path": str(plaintext_path), "secret_key": secret_key})

    def rotate_master_key(self) -> None:
        """
        Re-encrypts all vault entries under a newly generated master key using a crash-safe
        two-phase commit protocol.
        Commit Ordering:
        1. Decrypt all entries in memory under old key.
        2. Generate new master key and store in OS-native secure storage under pending slot.
        3. Re-encrypt all entries to staged temporary files with new key.
        4. Atomically write on-disk rotation journal recording stage and backend used (NO raw keys on disk).
        5. Replace all entry files on disk with new ciphertexts.
        6. Update journal stage to files_committed.
        7. Promote pending master key to primary in OS-native storage.
        8. Delete rotation journal and wipe transient key buffers.
        """
        with FileLock(str(self.lock_file), timeout=self.lock_timeout):
            self._recover_pending_rotation_locked()

            old_master_key = self.key_storage.get_or_create_master_key()
            index = self._read_index_unlocked()

            # 1. Decrypt all entries in memory
            decrypted_entries: Dict[str, bytes] = {}
            for key in index.keys():
                entry_filename = self._key_to_filename(key)
                entry_path = self.entries_dir / entry_filename
                if entry_path.exists():
                    with open(entry_path, "rb") as f:
                        enc_data = f.read()
                    decrypted_entries[key] = decrypt_payload(
                        payload=enc_data,
                        key=old_master_key,
                        associated_data=key.encode("utf-8"),
                    )

            # 2. Generate new 32-byte master key and store in OS-native pending slot
            new_master_key = secrets.token_bytes(32)
            backend_used = self.key_storage.store_pending_master_key(new_master_key)

            # 3. Re-encrypt all entries to temporary staged files
            staged_files: List[tuple[str, str]] = []
            for key, plaintext in decrypted_entries.items():
                new_encrypted = encrypt_payload(
                    plaintext=plaintext,
                    key=new_master_key,
                    associated_data=key.encode("utf-8"),
                )
                entry_filename = self._key_to_filename(key)
                dest_path = self.entries_dir / entry_filename
                temp_path = self.entries_dir / f"rotate.tmp.{entry_filename}.{secrets.token_hex(6)}"

                with open(temp_path, "wb") as f:
                    f.write(new_encrypted)
                staged_files.append((str(temp_path), str(dest_path)))

            # 4. Write atomic rotation journal with NO raw keys
            journal_data = {
                "stage": "staged",
                "has_pending_key": True,
                "pending_key_backend": backend_used,
                "staged_files": staged_files,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            self._write_journal_atomic_locked(journal_data)

            # 5. Replace all entry files on disk (files now contain new ciphertext)
            for temp_path_str, dest_path_str in staged_files:
                temp_p = Path(temp_path_str)
                dest_p = Path(dest_path_str)
                temp_p.replace(dest_p)

            # 6. Update journal stage atomically
            journal_data["stage"] = "files_committed"
            self._write_journal_atomic_locked(journal_data)

            # 7. Promote pending master key to primary in OS-native secure storage
            self.key_storage.promote_pending_master_key(target_backend=backend_used)

            # 8. Remove journal file upon successful completion
            if self.rotation_journal_file.exists():
                self.rotation_journal_file.unlink()

            # In-memory buffer hygiene: wipe decrypted entries and old key
            for key in list(decrypted_entries.keys()):
                b_val = bytearray(decrypted_entries[key])
                wipe_buffer(b_val)
                del decrypted_entries[key]

            old_key_buf = bytearray(old_master_key)
            wipe_buffer(old_key_buf)

            self._emit_event("vault_master_key_rotated", {"reencrypted_count": len(staged_files)})
