"""Enrollment gating and local-only physical presence challenge verification."""

import os
import json
import secrets
import time
from pathlib import Path
from typing import Optional, Callable, Dict, Any
from filelock import FileLock, Timeout

from sentinel.auth.models import IdentityCredentials, PinHashRecord
from sentinel.auth.hasher import PinHasher
from sentinel.auth.lockout import LockoutManager, LockAcquisitionError
from sentinel.audit.security_utils import apply_owner_only_dacl


class EnrollmentError(Exception):
    """Base exception for enrollment errors."""
    pass


class PresenceTokenError(EnrollmentError):
    """Raised when physical presence token is missing, invalid, or expired."""
    pass


class UnauthorizedEnrollmentError(EnrollmentError):
    """Raised when re-enrollment/change is attempted without valid active credentials."""
    pass


class EnrollmentManager:
    """Manages identity credential enrollment with strict physical presence and auth gating."""

    def __init__(
        self,
        auth_dir: Path,
        hasher: Optional[PinHasher] = None,
        lockout_manager: Optional[LockoutManager] = None,
        presence_token_ttl: int = 300,
        lock_timeout_seconds: float = 3.0,
        event_sink: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ):
        self.auth_dir = Path(auth_dir)
        self.auth_dir.mkdir(parents=True, exist_ok=True)
        self.credentials_file = self.auth_dir / "credentials.json"
        self.presence_file = self.auth_dir / "presence_challenge.token"
        self.lock_file = self.auth_dir / ".enrollment.lock"
        self.hasher = hasher or PinHasher()
        self.lockout_manager = lockout_manager or LockoutManager(self.auth_dir)
        self.presence_ttl = presence_token_ttl
        self.lock_timeout = lock_timeout_seconds
        self.event_sink = event_sink

    def _emit_event(self, event_type: str, details: Dict[str, Any]) -> None:
        if self.event_sink:
            try:
                self.event_sink(event_type, details)
            except Exception:
                pass

    def is_initialized(self) -> bool:
        """Returns True if valid identity credentials exist on disk."""
        if not self.credentials_file.exists():
            return False
        try:
            with open(self.credentials_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            creds = IdentityCredentials.model_validate(data)
            return creds.is_initialized
        except Exception:
            return False

    def is_tampered(self) -> bool:
        """
        Returns True if the system was previously initialized but credentials.json
        was deleted or corrupted (tamper detected).
        """
        marker_file = self.auth_dir / ".auth_initialized"
        if marker_file.exists():
            if not self.credentials_file.exists():
                return True
            try:
                with open(self.credentials_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                creds = IdentityCredentials.model_validate(data)
                return not creds.is_initialized
            except Exception:
                return True
        return False

    def _save_credentials_file_unlocked(self, new_creds: IdentityCredentials) -> None:
        """Persists credentials atomically and sets DACL-protected initialization marker."""
        marker_file = self.auth_dir / ".auth_initialized"
        if not marker_file.exists():
            marker_file.write_text("INITIALIZED", encoding="utf-8")
        apply_owner_only_dacl(marker_file)

        temp_cred = self.auth_dir / f"creds.tmp.{time.time_ns()}"
        flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        fd = os.open(temp_cred, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(new_creds.model_dump(), f, indent=2)
        temp_cred.replace(self.credentials_file)
        apply_owner_only_dacl(self.credentials_file)

    def _get_credentials_unlocked(self) -> Optional[IdentityCredentials]:
        """Loads credentials from disk without acquiring lock (caller must hold lock)."""
        if not self.credentials_file.exists():
            return None
        try:
            with open(self.credentials_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return IdentityCredentials.model_validate(data)
        except Exception:
            return None

    def get_credentials(self) -> Optional[IdentityCredentials]:
        """Loads credentials from disk under lock."""
        if not self.is_initialized():
            return None
        try:
            with FileLock(str(self.lock_file), timeout=2.0):
                return self._get_credentials_unlocked()
        except Exception:
            return None

    def generate_presence_challenge(self, for_step_up: bool = False, print_to_console: bool = True) -> str:
        """
        Generates a high-entropy physical presence token.
        Design constraint: Token is strictly delivered via local channels (stdout / restricted local file)
        and never exposed over network APIs.
        Atomic creation with 0o600 permissions eliminates file creation race windows.
        """
        if not for_step_up and self.is_initialized():
            raise EnrollmentError("System is already initialized. Physical presence token generation is restricted to first-run setup.")

        token = secrets.token_hex(16)  # 32 characters hex
        payload = {
            "token": token,
            "created_at": time.time(),
            "expires_at": time.time() + self.presence_ttl,
        }

        # Atomically open temp file with strict mode (0o600 on POSIX) at creation time
        temp_file = self.auth_dir / f"presence.tmp.{time.time_ns()}"
        flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY

        fd = os.open(temp_file, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f)

        temp_file.replace(self.presence_file)
        apply_owner_only_dacl(self.presence_file)

        if print_to_console:
            tag = "STEP-UP MFA" if for_step_up else "SENTINEL ENROLLMENT"
            print(f"\n[{tag}] Physical Presence Verification Token: {token}\n(Valid for {self.presence_ttl} seconds on local session only)\n")

        self._emit_event("presence_challenge_generated", {"ttl": self.presence_ttl, "step_up": for_step_up})
        return token

    def _check_security_descriptor_allowlist(self, sd) -> bool:
        """
        Validates a Windows security descriptor against the allowed trustee allowlist:
        Owner must be current user or Administrators.
        Allow ACEs must only grant access to Current User, Local SYSTEM, or Administrators.
        """
        try:
            import win32api
            import win32security

            # Get current process token user SID
            proc = win32api.GetCurrentProcess()
            token_handle = win32security.OpenProcessToken(proc, win32security.TOKEN_QUERY)
            user_sid, _ = win32security.GetTokenInformation(token_handle, win32security.TokenUser)

            file_owner_sid = sd.GetSecurityDescriptorOwner()
            if file_owner_sid is None:
                self._emit_event("presence_token_security_check_error", {"error": "Missing Security Descriptor Owner"})
                return False

            # Convert SIDs to string representations for hashable set lookups
            user_sid_str = win32security.ConvertSidToStringSid(user_sid)
            sys_sid_str = win32security.ConvertSidToStringSid(win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None))
            admin_sid_str = win32security.ConvertSidToStringSid(win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None))

            allowed_sid_strs = {user_sid_str, sys_sid_str, admin_sid_str}
            allowed_owner_strs = {user_sid_str, admin_sid_str}

            # Verify Owner SID
            file_owner_sid_str = win32security.ConvertSidToStringSid(file_owner_sid)
            if file_owner_sid_str not in allowed_owner_strs:
                self._emit_event("presence_token_foreign_owner_rejected", {"error": f"Owner SID {file_owner_sid_str} not in allowed owners"})
                return False

            # Allowlist model for DACL Allow ACEs:
            # We strictly permit only: Current User, Local SYSTEM (for service management),
            # and BUILTIN\\Administrators. Any other trustee with an Allow ACE is rejected.
            dacl = sd.GetSecurityDescriptorDacl()
            if dacl is not None:
                for i in range(dacl.GetAceCount()):
                    ace = dacl.GetAce(i)
                    ace_header, mask, sid = ace
                    ace_type = ace_header[0]

                    # Only check ACCESS_ALLOWED_ACE_TYPE (0); skip Deny ACEs (which restrict permissions)
                    if ace_type == win32security.ACCESS_ALLOWED_ACE_TYPE:
                        sid_str = win32security.ConvertSidToStringSid(sid)
                        if sid_str not in allowed_sid_strs:
                            self._emit_event(
                                "presence_token_insecure_dacl_rejected",
                                {"error": f"Disallowed trustee SID in DACL: {sid_str}"},
                            )
                            return False
            return True
        except ImportError:
            # Fallback if pywin32 is absent on non-Windows test runners
            return True
        except Exception as e:
            self._emit_event("presence_token_security_check_error", {"error": str(e)})
            return False

    def _verify_windows_file_security(self, path: Path) -> bool:
        """
        Verifies that the token file on Windows is owned by the current process user
        and that its DACL uses an explicit allowlist (only current user, SYSTEM, and Administrators).
        Path-based validation helper.
        """
        try:
            import win32security
            sd = win32security.GetFileSecurity(
                str(path),
                win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
            )
            return self._check_security_descriptor_allowlist(sd)
        except ImportError:
            return True
        except Exception as e:
            self._emit_event("presence_token_security_check_error", {"error": str(e)})
            return False

    def _verify_windows_file_security_on_fd(self, fd: int) -> bool:
        """
        Verifies that the open file descriptor on Windows is owned by the current process user
        and that its DACL uses an explicit allowlist, operating on the open handle to eliminate TOCTOU races.
        """
        try:
            import msvcrt
            import win32security

            handle = msvcrt.get_osfhandle(fd)
            sd = win32security.GetSecurityInfo(
                handle,
                win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
            )
            return self._check_security_descriptor_allowlist(sd)
        except ImportError:
            return True
        except Exception as e:
            self._emit_event("presence_token_security_check_error", {"error": str(e)})
            return False

    def _verify_and_consume_presence_token(self, provided_token: str) -> bool:
        """
        Verifies and immediately invalidates the presence token.
        Fixes TOCTOU race: opens descriptor first (with O_NOFOLLOW on POSIX),
        verifies fstat() / Windows SID on the open descriptor/handle, and reads payload.
        """
        if not provided_token or not self.presence_file.exists():
            return False

        if os.path.islink(self.presence_file):
            self._emit_event("presence_token_symlink_rejected", {"path": str(self.presence_file)})
            return False

        # Open file descriptor first to prevent TOCTOU swapping
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY

        try:
            fd = os.open(self.presence_file, flags)
        except Exception:
            return False

        try:
            # POSIX ownership and permissions check on the open file descriptor
            if os.name != "nt":
                st = os.fstat(fd)
                if st.st_uid != os.getuid():
                    os.close(fd)
                    self._emit_event("presence_token_foreign_owner_rejected", {"owner_uid": st.st_uid})
                    return False
                if (st.st_mode & 0o077) != 0:  # Must be 0600 or stricter
                    os.close(fd)
                    self._emit_event("presence_token_insecure_permissions_rejected", {"mode": oct(st.st_mode)})
                    return False

            # Windows SID and DACL security verification on the open handle
            if os.name == "nt":
                if not self._verify_windows_file_security_on_fd(fd):
                    os.close(fd)
                    return False

            # Read payload through the open descriptor
            with os.fdopen(fd, "r", encoding="utf-8") as f:
                payload = json.load(f)

            expected_token = payload.get("token")
            expires_at = payload.get("expires_at", 0)

            if time.time() > expires_at:
                if self.presence_file.exists():
                    self.presence_file.unlink()
                self._emit_event("presence_token_expired", {})
                return False

            if secrets.compare_digest(provided_token.strip(), expected_token):
                # Valid token: consume immediately
                if self.presence_file.exists():
                    self.presence_file.unlink()
                return True
            return False
        except Exception:
            return False

    def verify_and_consume_presence_token(self, provided_token: str) -> bool:
        """Public interface for validating and consuming a single-use physical presence challenge token."""
        return self._verify_and_consume_presence_token(provided_token)

    def enroll(
        self,
        primary_pin: str,
        recovery_pin: str,
        current_primary_pin: Optional[str] = None,
        presence_token: Optional[str] = None,
    ) -> bool:
        """
        Enrolls or updates PIN credentials.
        - First-run: requires presence_token.
        - Re-enrollment / Update: requires current_primary_pin.
        """
        if primary_pin == recovery_pin:
            raise ValueError("Primary PIN and Recovery PIN must not be identical.")

        try:
            with FileLock(str(self.lock_file), timeout=self.lock_timeout):
                initialized = self.is_initialized()

                if not initialized:
                    # First run: verify physical presence token
                    if not presence_token:
                        self._emit_event("enrollment_failed_missing_presence_token", {})
                        raise PresenceTokenError("First-run enrollment requires physical presence token.")

                    if not self._verify_and_consume_presence_token(presence_token):
                        self._emit_event("enrollment_failed_invalid_presence_token", {})
                        raise PresenceTokenError("Invalid or expired physical presence token.")
                else:
                    # System already initialized: must authenticate with current primary PIN
                    if not current_primary_pin:
                        self._emit_event("enrollment_failed_missing_current_pin", {})
                        raise UnauthorizedEnrollmentError("Changing credentials requires current Primary PIN.")

                    creds = self._get_credentials_unlocked()
                    if not creds or not self.hasher.verify_pin(current_primary_pin, creds.primary_pin):
                        # Record failure in lockout manager atomically
                        has_rec = (creds.recovery_pin is not None) if creds else True
                        self.lockout_manager.execute_atomic_primary_auth(
                            is_system_initialized=True,
                            verify_callback=lambda: False,
                            has_recovery_pin=has_rec,
                        )
                        self._emit_event("enrollment_failed_invalid_current_pin", {})
                        raise UnauthorizedEnrollmentError("Invalid current Primary PIN.")

                # Hash credentials independently
                primary_record = self.hasher.hash_pin(primary_pin)
                recovery_record = self.hasher.hash_pin(recovery_pin)

                new_creds = IdentityCredentials(
                    is_initialized=True,
                    primary_pin=primary_record,
                    recovery_pin=recovery_record,
                )

                # Persist credentials atomically
                self._save_credentials_file_unlocked(new_creds)

                # Initialize / reset lockout state cleanly
                self.lockout_manager.initialize_clean_state()

                # When updating existing credentials, rotate vault master key
                if initialized:
                    try:
                        from sentinel.vault.store import VaultStore
                        vault = VaultStore()
                        if vault.list_secrets() or vault.index_file.exists():
                            vault.rotate_master_key()
                    except Exception as e:
                        self._emit_event("vault_rotation_failed_during_enrollment", {"error": str(e)})

                event_name = "enrollment_first_run_success" if not initialized else "credentials_updated_success"
                self._emit_event(event_name, {})
                return True
        except Timeout as e:
            self._emit_event("enrollment_lock_timeout_fail_closed", {})
            raise LockAcquisitionError("Failed to acquire enrollment lock.") from e

    def migrate_legacy_credentials(
        self,
        salt_hex: str,
        hash_hex: str,
        recovery_salt_hex: Optional[str] = None,
        recovery_hash_hex: Optional[str] = None,
        iterations: int = 480_000,
        recovery_iterations: Optional[int] = None,
    ) -> bool:
        """
        Migrates a legacy AccessControl record into IdentityCredentials under atomic file lock.
        Builds primary_pin (and recovery_pin if provided) in ONE atomic temp-file-write + rename + DACL pass.
        Restricted to initial uninitialized state.
        """
        try:
            with FileLock(str(self.lock_file), timeout=self.lock_timeout):
                if self.is_initialized():
                    return False  # Already initialized; migration skipped

                primary_record = PinHashRecord(
                    salt_hex=salt_hex,
                    hash_hex=hash_hex,
                    iterations=iterations,
                )
                recovery_record = None
                if recovery_salt_hex and recovery_hash_hex:
                    recovery_record = PinHashRecord(
                        salt_hex=recovery_salt_hex,
                        hash_hex=recovery_hash_hex,
                        iterations=recovery_iterations or iterations,
                    )

                new_creds = IdentityCredentials(
                    is_initialized=True,
                    primary_pin=primary_record,
                    recovery_pin=recovery_record,
                )

                self._save_credentials_file_unlocked(new_creds)

                self.lockout_manager.initialize_clean_state()
                self._emit_event(
                    "legacy_access_control_migrated_success",
                    {"iterations": iterations, "has_recovery_pin": recovery_record is not None},
                )
                return True
        except Timeout as e:
            self._emit_event("enrollment_lock_timeout_fail_closed", {})
            raise LockAcquisitionError("Failed to acquire enrollment lock.") from e

    def set_primary_pin_direct(self, primary_pin: str) -> None:
        """
        Sets or updates the primary PIN directly under lock (used by legacy AccessControl facade).
        """
        try:
            with FileLock(str(self.lock_file), timeout=self.lock_timeout):
                primary_record = self.hasher.hash_pin(primary_pin)
                existing = self._get_credentials_unlocked()
                recovery_rec = existing.recovery_pin if existing else None

                new_creds = IdentityCredentials(
                    is_initialized=True,
                    primary_pin=primary_record,
                    recovery_pin=recovery_rec,
                )

                self._save_credentials_file_unlocked(new_creds)

                self.lockout_manager.initialize_clean_state()
                self._emit_event("primary_pin_set_direct_success", {})
        except Timeout as e:
            self._emit_event("enrollment_lock_timeout_fail_closed", {})
            raise LockAcquisitionError("Failed to acquire enrollment lock.") from e

    def set_recovery_pin_direct(self, recovery_pin: str) -> None:
        """
        Sets or updates the recovery PIN directly under lock (used by legacy AccessControl facade).
        """
        try:
            with FileLock(str(self.lock_file), timeout=self.lock_timeout):
                existing = self._get_credentials_unlocked()
                if not existing or not existing.is_initialized:
                    raise EnrollmentError("Cannot set recovery PIN: primary PIN must be set first.")

                recovery_record = self.hasher.hash_pin(recovery_pin)
                new_creds = IdentityCredentials(
                    is_initialized=True,
                    primary_pin=existing.primary_pin,
                    recovery_pin=recovery_record,
                )

                self._save_credentials_file_unlocked(new_creds)

                self.lockout_manager.initialize_clean_state()
                self._emit_event("recovery_pin_set_direct_success", {})
        except Timeout as e:
            self._emit_event("enrollment_lock_timeout_fail_closed", {})
            raise LockAcquisitionError("Failed to acquire enrollment lock.") from e
