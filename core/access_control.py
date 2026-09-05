"""
core/access_control.py — PIN-Gated Authorization & Failed-Auth Triage Engine
=============================================================================
Provides cryptographic identity gating and intelligent failed-authentication triage.
Refactored as a facade over sentinel/auth (AuthEngine, LockoutManager, PinHasher, EnrollmentManager)
with FileLock concurrency safety, PBKDF2-HMAC-SHA256 hashing, Windows owner-only DACLs,
and tamper-evident hash-chained audit logging.
"""
from __future__ import annotations

import enum
import functools
import json
import logging
import os
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional
from filelock import FileLock

from core.audit_log import AuditLog
from sentinel.auth.engine import AuthEngine, UnauthorizedError
from sentinel.auth.lockout import (
    LockoutException,
    HardLockoutError,
    TemporaryLockoutError,
    LockAcquisitionError,
)
from sentinel.config.settings import default_settings

logger = logging.getLogger(__name__)

_KDF_ITERATIONS = 480_000


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


class TriageStatus(enum.Enum):
    GRANTED = "GRANTED"
    OWNER_MISTYPE = "OWNER_MISTYPE"
    INTRUDER_SUSPECTED = "INTRUDER_SUSPECTED"
    LOCKED_OUT = "LOCKED_OUT"
    DENIED = "DENIED"


@dataclass
class TriageResult:
    status: TriageStatus
    decision: str  # "granted" | "owner_mistype" | "intruder_suspected" | "locked_out" | "denied"
    can_prompt_pin: bool
    fail_count: int
    backoff_s: float = 0.0
    reason: str = ""


class _StateDict(dict):
    """Compatibility dictionary proxy allowing legacy test fixtures to mutate failure counters."""
    def __init__(self, owner, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._owner = owner

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if key == "fail_count" and value == 0:
            self._owner._engine.lockout_manager.initialize_clean_state()
        elif key == "locked_until" and value == 0:
            try:
                with FileLock(str(self._owner._engine.lockout_manager.lock_file), timeout=2.0):
                    st = self._owner._engine.lockout_manager._read_state_locked(True)
                    st.primary_locked_until = None
                    self._owner._engine.lockout_manager._write_state_locked(st)
            except Exception:
                pass
        else:
            logger.warning("Ignored legacy _state write to key %r; credentials are now managed by sentinel/auth.", key)


class AccessControl:
    """
    Facade maintaining full backward compatibility with core access control call sites
    while delegating all identity persistence, locking, and hashing to sentinel/auth.
    """
    _default_bridge: Optional[Any] = None
    _default_bridge_lock = threading.Lock()

    @classmethod
    def set_default_bridge(cls, bridge: Optional[Any]) -> None:
        """Sets the process-wide default ProactiveBridge for AccessControl instances."""
        with cls._default_bridge_lock:
            cls._default_bridge = bridge

    @classmethod
    def get_default_bridge(cls) -> Optional[Any]:
        """Gets the process-wide default ProactiveBridge for AccessControl instances."""
        with cls._default_bridge_lock:
            return cls._default_bridge

    def __init__(self, path: Optional[Path] = None, audit_log_path: Optional[Path] = None, bridge: Optional[Any] = None):
        if path is not None:
            self.legacy_path = Path(path)
            self.auth_dir = self.legacy_path.parent / "auth"
            default_audit = self.legacy_path.parent / "audit_log.jsonl"
        else:
            self.legacy_path = _base_dir() / "memory" / "access_control.json"
            self.auth_dir = default_settings.auth_dir
            default_audit = None

        self.auth_dir.mkdir(parents=True, exist_ok=True)
        self.legacy_path.parent.mkdir(parents=True, exist_ok=True)

        self._audit = AuditLog(path=audit_log_path or default_audit)
        self._engine = AuthEngine(auth_dir=self.auth_dir)
        self._bridge = bridge if bridge is not None else self.get_default_bridge()

        # One-time lazy migration of legacy memory/access_control.json if uninitialized
        if not self._engine.is_initialized() and self.legacy_path.exists():
            self._try_migrate_legacy()

    def set_bridge(self, bridge: Optional[Any]) -> None:
        self._bridge = bridge

    @property
    def path(self) -> Path:
        return self.legacy_path

    @property
    def _state(self) -> _StateDict:
        state = self._engine.lockout_manager.get_current_state(self.is_configured())
        creds = self._engine.enrollment_manager.get_credentials()
        d = {
            "salt": creds.primary_pin.salt_hex if creds else None,
            "hash": creds.primary_pin.hash_hex if creds else None,
            "recovery_salt": creds.recovery_pin.salt_hex if (creds and creds.recovery_pin) else None,
            "recovery_hash": creds.recovery_pin.hash_hex if (creds and creds.recovery_pin) else None,
            "fail_count": state.primary_failures,
            "locked_until": state.primary_locked_until or 0,
        }
        return _StateDict(self, d)

    def _save(self) -> None:
        """No-op for backward compatibility with legacy tests calling ac._save()."""
        pass

    def _try_migrate_legacy(self) -> None:
        """
        Migrates legacy access_control.json salt/hash to credentials.json in ONE atomic pass if uninitialized.
        Logs an audit event if the legacy file is corrupted.
        """
        try:
            with open(self.legacy_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            salt = data.get("salt")
            pwd_hash = data.get("hash")
            rec_salt = data.get("recovery_salt")
            rec_hash = data.get("recovery_hash")
            if salt and pwd_hash:
                self._engine.enrollment_manager.migrate_legacy_credentials(
                    salt_hex=salt,
                    hash_hex=pwd_hash,
                    recovery_salt_hex=rec_salt,
                    recovery_hash_hex=rec_hash,
                    iterations=_KDF_ITERATIONS,
                )
        except json.JSONDecodeError as e:
            logger.warning("Legacy access_control.json is corrupted: %s", e)
            self._audit.append("access_control_legacy_migration_corrupted", {"error": str(e), "file": str(self.legacy_path)})
        except Exception as e:
            logger.warning("Could not migrate legacy access_control.json: %s", e)
            self._audit.append("access_control_legacy_migration_error", {"error": str(e), "file": str(self.legacy_path)})

    def is_configured(self) -> bool:
        """Returns True if identity credentials exist in the backing engine."""
        return self._engine.is_initialized()

    def is_tampered(self) -> bool:
        """
        Returns True if credentials were previously configured but credentials.json
        was deleted or corrupted (tampering detected).
        Checks:
        1. Local marker file (.auth_initialized).
        2. Cryptographic audit chain integrity verification (detects modified/deleted records).
        3. Production AuditLogger mirror-backed chain integrity (if present).
        4. Cryptographic audit chain history (presence of initialization events on unconfigured system).
        """
        if self._engine.enrollment_manager.is_tampered():
            return True

        # 1. Verify integrity of the audit log chain (detects targeted line deletions/modifications)
        if self._audit.path.exists():
            ok, reason = self._audit.verify()
            if not ok:
                logger.critical("Audit chain verification failed in is_tampered(): %s", reason)
                return True

        # 2. Check production Sentinel AuditLogger if present
        try:
            from sentinel.audit.chain import AuditLogger, ChainIntegrityError
            prod_audit_dir = (self.auth_dir.parent / "audit") if self.auth_dir else default_settings.audit_dir
            if prod_audit_dir.exists():
                audit_log_file = prod_audit_dir / "audit.jsonl"
                mirror_state_file = prod_audit_dir / ".audit_mirror_state.json"

                if mirror_state_file.exists() and not audit_log_file.exists():
                    logger.critical("Production audit.jsonl deleted while mirror state exists — tampering detected.")
                    return True

                if audit_log_file.exists() and audit_log_file.stat().st_size > 0:
                    try:
                        AuditLogger(audit_dir=prod_audit_dir, verify_on_startup=True)
                    except ChainIntegrityError as cie:
                        logger.critical("Production AuditLogger chain integrity broken: %s", cie)
                        return True
                    except (OSError, IOError, json.JSONDecodeError, ValueError) as io_err:
                        logger.critical("Production AuditLogger failed with I/O or corruption error: %s", io_err)
                        return True
        except ImportError:
            pass

        # 3. Check for historical initialization events on unconfigured system
        if not self.is_configured():
            events = [entry.get("event_type") for entry in self._audit.read_all()]
            init_events = {
                "access_control_initialized",
                "access_control_pin_set",
                "access_control_dual_pin_enrolled",
                "legacy_access_control_migrated_success",
            }
            if any(ev in init_events for ev in events):
                return True

        return False

    def has_recovery_pin(self) -> bool:
        """Returns True if a recovery PIN is configured in credentials."""
        creds = self._engine.enrollment_manager.get_credentials()
        return bool(creds and creds.recovery_pin is not None)

    def generate_presence_challenge(self, print_to_console: bool = True) -> str:
        """Generates a physical presence challenge token."""
        return self._engine.enrollment_manager.generate_presence_challenge(print_to_console=print_to_console)

    def enroll_dual_pin(
        self,
        primary_pin: str,
        recovery_pin: str,
        current_primary_pin: Optional[str] = None,
        presence_token: Optional[str] = None,
    ) -> bool:
        """
        Enrolls or re-enrolls dual PIN credentials through EnrollmentManager.
        - First run: requires presence_token.
        - Re-enrollment: requires current_primary_pin.
        """
        success = self._engine.enrollment_manager.enroll(
            primary_pin=primary_pin,
            recovery_pin=recovery_pin,
            current_primary_pin=current_primary_pin,
            presence_token=presence_token,
        )
        if success:
            event = "access_control_dual_pin_enrolled" if not current_primary_pin else "access_control_dual_pin_updated"
            self._audit.append(event, {"result": "success"})
            if not current_primary_pin:
                self._audit.append("access_control_initialized", {"type": "dual_pin"})
        return success

    def set_pin(self, pin: str) -> None:
        """Sets or updates the primary PIN."""
        if len(pin) < 4:
            raise ValueError("PIN must be at least 4 characters — a longer passphrase is stronger.")
        was_configured = self.is_configured()
        self._engine.enrollment_manager.set_primary_pin_direct(pin)
        self._audit.append("access_control_pin_set", {"result": "success", "type": "primary"})
        if not was_configured:
            self._audit.append("access_control_initialized", {"type": "primary"})
            try:
                self._engine.anomaly_detector.seed_initial_enrollment()
            except Exception:
                pass


    def set_recovery_pin(self, pin: str) -> None:
        """Sets or updates the recovery PIN."""
        if len(pin) < 4:
            raise ValueError("Recovery PIN must be at least 4 characters.")
        self._engine.enrollment_manager.set_recovery_pin_direct(pin)
        self._audit.append("access_control_pin_set", {"result": "success", "type": "recovery"})

    def _seconds_locked(self) -> float:
        """
        Advisory check for remaining lock duration.
        Returns 0.0 when not locked, active backoff seconds, or 3600.0 on hard-lockout.
        """
        state = self._engine.lockout_manager.get_current_state(self.is_configured())
        if state.primary_hard_locked:
            return 3600.0
        now = time.time()
        if state.primary_locked_until and state.primary_locked_until > now:
            return max(0.0, state.primary_locked_until - now)
        return 0.0

    def _dispatch_pin_failure_alert(self, action: str, result: str, details: Optional[dict] = None) -> None:
        """Dispatches a unified security alert for PIN authentication failures or lockouts."""
        try:
            from core.unified_security_alert import dispatch_security_alert
            alert_details = {"action": action, "result": result}
            if details:
                alert_details.update(details)
            dispatch_security_alert(
                trigger_type="jarvis_pin_failure",
                actor="user",
                details=alert_details,
                bridge=getattr(self, "_bridge", None),
            )
        except Exception as _e:
            logger.debug("Failed to dispatch pin failure alert: %s", _e)

    def verify_pin(self, pin: str, action: str = "unspecified") -> bool:
        """Standard PIN check with audit trail and atomic lockout ladder."""
        if not self.is_configured():
            self._audit.append("access_control_check", {"action": action, "result": "denied_not_configured"})
            return False

        locked_for = self._seconds_locked()
        if locked_for > 0:
            self._audit.append(
                "access_control_check",
                {"action": action, "result": "denied_locked_out", "retry_in_s": round(locked_for, 1)},
            )
            self._dispatch_pin_failure_alert(action, "denied_locked_out", {"retry_in_s": round(locked_for, 1)})
            return False

        try:
            success = self._engine.authenticate_primary(pin)
            if success:
                self._audit.append("access_control_check", {"action": action, "result": "granted"})
                return True
            else:
                state = self._engine.lockout_manager.get_current_state(self.is_configured())
                backoff = self._seconds_locked()
                self._audit.append(
                    "access_control_check",
                    {"action": action, "result": "denied_wrong_pin", "fail_count": state.primary_failures, "backoff_s": backoff},
                )
                self._dispatch_pin_failure_alert(action, "denied_wrong_pin", {"fail_count": state.primary_failures, "backoff_s": backoff})
                return False
        except HardLockoutError:
            self._audit.append("access_control_check", {"action": action, "result": "denied_hard_lockout"})
            self._dispatch_pin_failure_alert(action, "denied_hard_lockout")
            return False
        except TemporaryLockoutError as e:
            self._audit.append(
                "access_control_check",
                {"action": action, "result": "denied_locked_out", "retry_in_s": round(e.remaining_seconds, 1)},
            )
            self._dispatch_pin_failure_alert(action, "denied_locked_out", {"retry_in_s": round(e.remaining_seconds, 1)})
            return False
        except LockAcquisitionError:
            self._audit.append("access_control_check", {"action": action, "result": "denied_lock_timeout"})
            return False
        except (UnauthorizedError, LockoutException):
            self._audit.append("access_control_check", {"action": action, "result": "denied_unauthorized"})
            self._dispatch_pin_failure_alert(action, "denied_unauthorized")
            return False

    def verify_recovery_pin(self, pin: str, action: str = "unspecified", allow_during_backoff: bool = True) -> bool:
        """Verifies the fallback recovery PIN."""
        if not self.is_configured():
            self._audit.append("access_control_recovery_check", {"action": action, "result": "denied_not_configured"})
            return False

        try:
            success = self._engine.authenticate_recovery(pin)
            if success:
                self._audit.append("access_control_recovery_check", {"action": action, "result": "granted_recovery"})
                return True
            else:
                state = self._engine.lockout_manager.get_current_state(self.is_configured())
                backoff = max(0.0, (state.recovery_locked_until or 0) - time.time())
                self._audit.append(
                    "access_control_recovery_check",
                    {"action": action, "result": "denied_wrong_recovery_pin", "fail_count": state.recovery_failures, "backoff_s": backoff},
                )
                self._dispatch_pin_failure_alert(action, "denied_wrong_recovery_pin", {"fail_count": state.recovery_failures, "backoff_s": backoff})
                return False
        except TemporaryLockoutError as e:
            self._audit.append(
                "access_control_recovery_check",
                {"action": action, "result": "denied_locked_out", "retry_in_s": round(e.remaining_seconds, 1)},
            )
            self._dispatch_pin_failure_alert(action, "denied_locked_out", {"retry_in_s": round(e.remaining_seconds, 1)})
            return False
        except LockAcquisitionError:
            self._audit.append("access_control_recovery_check", {"action": action, "result": "denied_lock_timeout"})
            return False
        except (UnauthorizedError, LockoutException):
            self._audit.append("access_control_recovery_check", {"action": action, "result": "denied_unauthorized"})
            self._dispatch_pin_failure_alert(action, "denied_unauthorized")
            return False

    def triage_authentication(
        self,
        candidate_pin: str,
        action: str = "unspecified",
        snapshot_bytes: Optional[bytes] = None,
        face_verifier=None,
        alert_callback: Optional[Callable[[str, Optional[bytes]], None]] = None,
    ) -> TriageResult:
        """
        Failed-Authentication Triage:
        - Correct PIN -> GRANTED
        - Wrong PIN -> triggers silent secondary webcam check:
            * Matches owner face -> OWNER_MISTYPE: allows fallback PIN recovery prompt.
            * No face, wrong face, or camera down -> INTRUDER_SUSPECTED: fails closed, suppresses PIN prompt,
              captures webcam snapshot, and triggers intruder alert immediately.
        - Repeated failures escalate lockout regardless of face match.
        """
        if not self.is_configured():
            self._audit.append("auth_triage", {"action": action, "result": "denied_not_configured"})
            return TriageResult(
                status=TriageStatus.DENIED,
                decision="denied_not_configured",
                can_prompt_pin=False,
                fail_count=0,
                reason="Access control not configured",
            )

        locked_for = self._seconds_locked()
        if locked_for > 0:
            state = self._engine.lockout_manager.get_current_state(self.is_configured())
            self._audit.append(
                "auth_triage",
                {"action": action, "result": "locked_out", "retry_in_s": round(locked_for, 1)},
            )
            return TriageResult(
                status=TriageStatus.LOCKED_OUT,
                decision="locked_out",
                can_prompt_pin=False,
                fail_count=state.primary_failures,
                backoff_s=locked_for,
                reason=f"Account locked. Try again in {int(locked_for)} seconds.",
            )

        # Atomic execution of check
        auth_success = self.verify_pin(candidate_pin, action=action)
        if auth_success:
            self._audit.append("auth_triage", {"action": action, "result": "granted"})
            return TriageResult(
                status=TriageStatus.GRANTED,
                decision="granted",
                can_prompt_pin=True,
                fail_count=0,
                reason="Authentication successful",
            )

        # On failure, read updated authoritative lockout state
        state = self._engine.lockout_manager.get_current_state(self.is_configured())
        fail_count = state.primary_failures
        backoff = self._seconds_locked()

        # Hard lockout escalation on excessive repeated attempts (>= 4 attempts)
        if fail_count >= 4 or state.primary_hard_locked:
            self._audit.append(
                "auth_triage",
                {"action": action, "result": "escalated_lockout", "fail_count": fail_count, "backoff_s": backoff},
            )
            try:
                from core.unified_security_alert import dispatch_security_alert
                dispatch_security_alert(
                    trigger_type="jarvis_pin_failure",
                    actor="user",
                    details={"action": action, "fail_count": fail_count, "backoff_s": backoff, "result": "escalated_lockout"},
                    snapshot_bytes=snapshot_bytes,
                    bridge=getattr(self, "_bridge", None),
                    on_alert_cb=alert_callback,
                )
            except Exception:
                if alert_callback:
                    try:
                        alert_callback(f"🚨 Repeated authentication failures ({fail_count} attempts) — session locked.", snapshot_bytes)
                    except Exception:
                        pass
            return TriageResult(
                status=TriageStatus.LOCKED_OUT,
                decision="escalated_lockout",
                can_prompt_pin=False,
                fail_count=fail_count,
                backoff_s=backoff,
                reason=f"Maximum attempts exceeded. Session locked for {int(backoff)}s.",
            )

        # Silent Secondary Check (Face Recognition Verification)
        face_match = False
        face_reason = "no_frame_or_check_failed"

        try:
            if face_verifier is None:
                from core.face_verify import FaceVerifier
                face_verifier = FaceVerifier()

            if snapshot_bytes and face_verifier:
                face_res = face_verifier.identify(snapshot_bytes, action=f"triage:{action}")
                if face_res.enrolled and face_res.face_found and face_res.accepted:
                    if getattr(face_res, "spoof_suspected", False) is True:
                        face_match = False
                        face_reason = "face_spoof_suspected"
                    else:
                        face_match = True
                        face_reason = "face_matched_owner"
                elif not face_res.face_found:
                    face_reason = "no_face_in_frame"
                else:
                    face_reason = "face_mismatch_impostor"
            else:
                face_reason = "no_snapshot_available"
        except Exception as e:
            face_reason = f"face_verifier_error_{type(e).__name__}"

        # Branch 1: Owner Mistype
        if face_match:
            self._audit.append(
                "auth_triage_mistype",
                {
                    "action": action,
                    "result": "owner_mistype_detected",
                    "fail_count": fail_count,
                    "backoff_s": backoff,
                    "face_reason": face_reason,
                },
            )
            return TriageResult(
                status=TriageStatus.OWNER_MISTYPE,
                decision="owner_mistype",
                can_prompt_pin=True,
                fail_count=fail_count,
                backoff_s=backoff,
                reason="Owner face confirmed. Please use your fallback recovery PIN.",
            )

        # Branch 2: Potential Intruder (FAIL CLOSED)
        self._audit.append(
            "auth_triage_intruder",
            {
                "action": action,
                "result": "intruder_suspected",
                "fail_count": fail_count,
                "face_reason": face_reason,
                "backoff_s": backoff,
            },
        )

        try:
            from core.unified_security_alert import dispatch_security_alert
            dispatch_security_alert(
                trigger_type="jarvis_pin_failure",
                actor="user",
                details={
                    "action": action,
                    "fail_count": fail_count,
                    "face_reason": face_reason,
                    "backoff_s": backoff,
                    "result": "intruder_suspected",
                },
                snapshot_bytes=snapshot_bytes,
                bridge=getattr(self, "_bridge", None),
                custom_msg=f"⚠️ Intruder Alert: Failed authentication on action '{action}' ({face_reason})",
                on_alert_cb=alert_callback,
            )
        except Exception:
            if alert_callback:
                try:
                    alert_text = f"⚠️ Intruder Alert: Failed authentication on action '{action}' ({face_reason})"
                    alert_callback(alert_text, snapshot_bytes)
                except Exception:
                    pass

        return TriageResult(
            status=TriageStatus.INTRUDER_SUSPECTED,
            decision="intruder_suspected",
            can_prompt_pin=False,
            fail_count=fail_count,
            backoff_s=backoff,
            reason="Authentication failed. Security alert triggered.",
        )

    def require_pin(self, func: Callable) -> Callable:
        """Decorator gating execution on valid PIN verification."""
        @functools.wraps(func)
        def wrapper(*args, pin: str = "", **kwargs):
            if not self.verify_pin(pin, action=func.__name__):
                raise PermissionError(
                    f"Action '{func.__name__}' refused — PIN verification failed or account is locked."
                )
            return func(*args, **kwargs)
        return wrapper