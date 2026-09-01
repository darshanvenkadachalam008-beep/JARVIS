"""HMAC hash-chained audit logger with chain-walking integrity verification."""

import os
import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple, Union
from filelock import FileLock

from sentinel.audit.models import AuditEntry, GENESIS_HASH
from sentinel.audit.sinks import AuditSink, LocalFileSink, WebhookMirrorSink, MultiSink
from sentinel.audit.security_utils import apply_owner_only_dacl
from sentinel.config.settings import default_settings

logger = logging.getLogger(__name__)


class AuditError(Exception):
    """Base exception for audit logging errors."""
    pass


class ChainIntegrityError(AuditError):
    """Raised when the hash chain verification detects tampering, omission, or corruption."""
    pass


class AuditLogger:
    """
    Append-only, HMAC-signed, hash-chained security event logger.
    Guarantees tamper-evidence: any modification, insertion, deletion, or reordering
    of log entries breaks cryptographic verification.
    """

    def __init__(
        self,
        audit_dir: Path | None = None,
        hmac_key: Optional[bytes] = None,
        sinks: Optional[List[AuditSink]] = None,
        lock_timeout_seconds: float = 5.0,
        verify_on_startup: bool = True,
    ):
        self.audit_dir = Path(audit_dir or default_settings.audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.audit_dir / "audit.jsonl"
        self.lock_file = self.audit_dir / ".audit.lock"
        self.key_state_file = self.audit_dir / ".audit_key_state.json"
        self.lock_timeout = lock_timeout_seconds
        self._mirror_tampered = False

        self.hmac_keys: Dict[int, bytes] = {}
        if hmac_key is not None:
            self.current_key_version = 1
            self.hmac_key = hmac_key
            self.hmac_keys = {1: hmac_key}
        else:
            self._load_or_create_hmac_keys()

        # Build sink chain
        local_sink = LocalFileSink(self.log_file)
        if sinks:
            self.sink = MultiSink([local_sink] + sinks)
        else:
            self.sink = local_sink

        # WebhookMirrorSink's worker thread starts inside its own __init__,
        # before AuditLogger wraps callbacks; safe since no entries exist yet.
        for s in (sinks or []):
            if isinstance(s, WebhookMirrorSink):
                orig_on_success = s.on_success
                orig_on_failure = s.on_failure

                def make_on_success(orig):
                    def _on_success(entry: AuditEntry) -> None:
                        if orig:
                            orig(entry)
                        if self._mirror_tampered:
                            logger.critical(
                                "MID-RUN AUDIT MIRRORING HALTED: Mirror state previously tampered; refusing to advance state file"
                            )
                            return

                        try:
                            current = self._read_mirror_state()
                        except ChainIntegrityError as cie:
                            self._mirror_tampered = True
                            logger.critical("MID-RUN AUDIT MIRROR STATE TAMPERING DETECTED: %s", cie)
                            if entry.event_type != "audit_mirror_state_tampered":
                                self.log_event(
                                    "audit_mirror_state_tampered",
                                    actor="system",
                                    details={"entry_index": entry.index, "error": str(cie)},
                                )
                            return
                        except (OSError, IOError) as ioe:
                            logger.warning("Transient I/O error reading mirror state: %s", ioe)
                            return

                        if entry.index > current:
                            self._write_mirror_state(entry.index)
                    return _on_success

                def make_on_failure(orig):
                    def _on_failure(entry: AuditEntry, exc: Exception) -> None:
                        if orig:
                            orig(entry, exc)
                        if entry.event_type != "audit_mirror_failed":
                            self.log_event(
                                "audit_mirror_failed",
                                actor="system",
                                details={"entry_index": entry.index, "error": str(exc)},
                            )
                    return _on_failure

                s.on_success = make_on_success(orig_on_success)
                s.on_failure = make_on_failure(orig_on_failure)

        # Verify existing log integrity on startup
        if verify_on_startup:
            with FileLock(str(self.lock_file), timeout=self.lock_timeout):
                is_valid, count, err = self.verify_chain(self.log_file, self.hmac_keys or self.hmac_key)
                if not is_valid:
                    logger.critical("STARTUP AUDIT LOG TAMPERING DETECTED: %s", err)
                    raise ChainIntegrityError(f"Startup audit verification failed: {err}")

                local_tail_index = count - 1
                last_confirmed = self._read_mirror_state()
                if last_confirmed > local_tail_index:
                    logger.critical(
                        "STARTUP AUDIT TRUNCATION DETECTED: mirror confirms index %d but local tail is %d",
                        last_confirmed, local_tail_index,
                    )
                    raise ChainIntegrityError(
                        f"Local audit log truncated: mirror confirmed index {last_confirmed}, "
                        f"local tail is {local_tail_index}"
                    )

    def _read_mirror_state(self) -> int:
        """
        Returns last_confirmed_mirrored_index, or -1 if never initialized.
        Raises ChainIntegrityError if state file is corrupt or missing after initialization.
        Propagates raw OSError/IOError for transient OS-level I/O failures.
        """
        state_file = self.audit_dir / ".audit_mirror_state.json"
        marker_file = self.audit_dir / ".audit_mirror_initialized"

        if not state_file.exists():
            if marker_file.exists():
                logger.critical(
                    "STARTUP AUDIT TAMPERING DETECTED: mirror marker exists but %s was deleted",
                    state_file,
                )
                raise ChainIntegrityError(
                    f"Mirror state file {state_file.name} missing after mirror initialization (tampering detected)"
                )
            return -1

        # 1. OS-level file access: transient errors propagate directly as OSError/IOError
        with open(state_file, "r", encoding="utf-8") as f:
            raw_content = f.read()

        # 2. Content deserialization & schema validation: corruption indicates tampering
        try:
            data = json.loads(raw_content)
            if not isinstance(data, dict) or "last_confirmed_mirrored_index" not in data:
                raise ValueError("Missing 'last_confirmed_mirrored_index' in state file")
            val = int(data["last_confirmed_mirrored_index"])
            return val
        except (json.JSONDecodeError, ValueError, TypeError, KeyError) as e:
            logger.critical("STARTUP AUDIT TAMPERING DETECTED: mirror state file %s corrupted: %s", state_file, e)
            raise ChainIntegrityError(f"Audit mirror state file corrupted: {e}")

    def _write_mirror_state(self, index: int) -> None:
        """Atomically persists last_confirmed_mirrored_index and sets initialization marker."""
        state_file = self.audit_dir / ".audit_mirror_state.json"
        marker_file = self.audit_dir / ".audit_mirror_initialized"
        tmp_file = state_file.with_suffix(f".tmp.{os.getpid()}")
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump({"last_confirmed_mirrored_index": index}, f)
            os.replace(tmp_file, state_file)
            apply_owner_only_dacl(state_file)

            if not marker_file.exists():
                marker_file.write_text("INITIALIZED", encoding="utf-8")
            apply_owner_only_dacl(marker_file)
        except Exception as e:
            logger.error("Could not write mirror state file %s: %s", state_file, e)
            if tmp_file.exists():
                try:
                    tmp_file.unlink(missing_ok=True)
                except Exception:
                    pass

    def _load_or_create_hmac_keys(self) -> None:
        """
        Loads all available versioned HMAC keys and current key state,
        or creates version 1 if none exists.
        """
        current_version = 1
        if self.key_state_file.exists():
            try:
                with open(self.key_state_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                current_version = int(data.get("current_key_version", 1))
            except Exception as e:
                logger.warning("Could not read audit key state file: %s", e)

        # Scan and load all versioned key files
        keys = self.load_hmac_keys_from_dir(self.audit_dir)

        legacy_key_file = self.audit_dir / ".audit_hmac.key"
        if not keys:
            if legacy_key_file.exists():
                with open(legacy_key_file, "rb") as f:
                    k = f.read()
                if len(k) == 32:
                    keys[1] = k
                    self._save_versioned_key(1, k)
            else:
                new_key = os.urandom(32)
                keys[1] = new_key
                self._save_versioned_key(1, new_key)
                self._save_legacy_key(new_key)

        self.hmac_keys = keys
        if current_version not in self.hmac_keys:
            current_version = max(self.hmac_keys.keys()) if self.hmac_keys else 1

        self.current_key_version = current_version
        self.hmac_key = self.hmac_keys.get(current_version) or list(self.hmac_keys.values())[0]
        self._write_key_state(current_version)

    def _save_versioned_key(self, version: int, key: bytes) -> Path:
        key_file = self.audit_dir / f".audit_hmac_v{version}.key"
        flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        try:
            fd = os.open(key_file, flags, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key)
        except FileExistsError:
            pass
        apply_owner_only_dacl(key_file)
        return key_file

    def _save_legacy_key(self, key: bytes) -> Path:
        key_file = self.audit_dir / ".audit_hmac.key"
        temp_file = self.audit_dir / f".audit_hmac.key.tmp.{os.getpid()}"
        flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        try:
            fd = os.open(temp_file, flags, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key)
            os.replace(temp_file, key_file)
        except Exception:
            if temp_file.exists():
                try:
                    temp_file.unlink(missing_ok=True)
                except Exception:
                    pass
        apply_owner_only_dacl(key_file)
        return key_file

    def _write_key_state(self, version: int) -> None:
        temp_file = self.key_state_file.with_suffix(f".tmp.{os.getpid()}")
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump({"current_key_version": version}, f, indent=2)
            os.replace(temp_file, self.key_state_file)
            apply_owner_only_dacl(self.key_state_file)
        except Exception as e:
            logger.error("Could not write audit key state: %s", e)
            if temp_file.exists():
                try:
                    temp_file.unlink(missing_ok=True)
                except Exception:
                    pass

    @classmethod
    def load_hmac_keys_from_dir(cls, audit_dir: Path) -> Dict[int, bytes]:
        """Loads all versioned and legacy HMAC keys present in an audit directory."""
        keys: Dict[int, bytes] = {}
        p = Path(audit_dir)
        if not p.exists():
            return keys

        for f in p.glob(".audit_hmac_v*.key"):
            try:
                name = f.stem  # .audit_hmac_v1
                ver_str = name.split("_v")[-1]
                ver = int(ver_str)
                with open(f, "rb") as kf:
                    data = kf.read()
                if len(data) == 32:
                    keys[ver] = data
                    apply_owner_only_dacl(f)
            except Exception:
                pass

        legacy = p / ".audit_hmac.key"
        if legacy.exists() and 1 not in keys:
            try:
                with open(legacy, "rb") as kf:
                    data = kf.read()
                if len(data) == 32:
                    keys[1] = data
                    apply_owner_only_dacl(legacy)
            except Exception:
                pass

        return keys

    def rotate_hmac_key(self, actor: str = "system") -> int:
        """
        Rotates the audit HMAC signing key:
        1. Increments key_version.
        2. Generates new 32-byte key material.
        3. Persists new versioned key file with 0o600 permissions and owner-only DACL.
        4. Updates key state file atomically.
        5. Logs an audit entry signed with the *new* key recording the rotation event.
        Returns the new key_version.
        """
        with FileLock(str(self.lock_file), timeout=self.lock_timeout):
            old_version = self.current_key_version
            new_version = old_version + 1
            new_key = os.urandom(32)

            self._save_versioned_key(new_version, new_key)
            self._save_legacy_key(new_key)
            self._write_key_state(new_version)

            self.hmac_keys[new_version] = new_key
            self.current_key_version = new_version
            self.hmac_key = new_key

            # Record rotation in the tamper-evident chain signed with the NEW key
            next_index, prev_hash = self._get_tail_state_unlocked()
            timestamp = datetime.now(timezone.utc).isoformat()

            entry = AuditEntry.create(
                index=next_index,
                timestamp=timestamp,
                event_type="audit_hmac_key_rotated",
                actor=actor,
                tier="admin",
                details={
                    "previous_key_version": old_version,
                    "new_key_version": new_version,
                },
                prev_hash=prev_hash,
                hmac_key=new_key,
                key_version=new_version,
            )
            self.sink.emit(entry)
            logger.info("Audit HMAC key rotated from version %d to %d by actor '%s'", old_version, new_version, actor)
            return new_version

    def _get_tail_state_unlocked(self) -> Tuple[int, str]:
        """
        Reads the last valid entry in the log file to determine the next index and prev_hash.
        Returns (next_index, prev_hash).
        """
        if not self.log_file.exists() or self.log_file.stat().st_size == 0:
            return 0, GENESIS_HASH

        last_line = None
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    last_line = stripped

        if not last_line:
            return 0, GENESIS_HASH

        try:
            data = json.loads(last_line)
            last_entry = AuditEntry.model_validate(data)
            return last_entry.index + 1, last_entry.compute_sha256()
        except Exception as e:
            logger.error("Failed to read tail audit entry: %s", e)
            raise AuditError(f"Audit log file is corrupted at tail: {e}") from e

    def log_event(
        self,
        event_type: str,
        actor: str = "system",
        tier: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEntry:
        """
        Constructs, signs, and logs a new tamper-evident audit event.
        Guarantees atomicity and chain continuity under FileLock.
        """
        with FileLock(str(self.lock_file), timeout=self.lock_timeout):
            next_index, prev_hash = self._get_tail_state_unlocked()
            timestamp = datetime.now(timezone.utc).isoformat()

            entry = AuditEntry.create(
                index=next_index,
                timestamp=timestamp,
                event_type=event_type,
                actor=actor,
                tier=tier,
                details=details or {},
                prev_hash=prev_hash,
                hmac_key=self.hmac_key,
                key_version=self.current_key_version,
            )

            self.sink.emit(entry)
            return entry

    @classmethod
    def verify_chain(
        cls,
        log_path: Path,
        hmac_key: Union[bytes, Dict[int, bytes], Path],
    ) -> Tuple[bool, int, Optional[str]]:
        """
        Performs a full cryptographic chain-walk verification of an audit log.
        Validates:
        1. JSON syntax and schema of every record.
        2. Strict index monotonicity (0, 1, 2...).
        3. Prev-hash integrity linking to preceding entry's SHA-256 (genesis hash at index 0).
        4. HMAC signature verification on every record against the appropriate versioned HMAC key.

        Returns:
            (is_valid, verified_record_count, failure_reason)
        """
        p = Path(log_path)
        if not p.exists() or p.stat().st_size == 0:
            return True, 0, None

        if isinstance(hmac_key, dict):
            keys = dict(hmac_key)
        elif isinstance(hmac_key, Path):
            keys = cls.load_hmac_keys_from_dir(hmac_key)
        elif isinstance(hmac_key, bytes):
            keys = cls.load_hmac_keys_from_dir(p.parent)
            if not keys:
                keys = {1: hmac_key}
            else:
                keys[1] = keys.get(1, hmac_key)
        else:
            keys = {}

        expected_index = 0
        expected_prev_hash = GENESIS_HASH

        with open(p, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                stripped = line.strip()
                if not stripped:
                    continue

                try:
                    data = json.loads(stripped)
                    entry = AuditEntry.model_validate(data)
                except Exception as e:
                    return False, expected_index, f"Line {line_num}: JSON decode or schema error: {e}"

                # 1. Verify index sequence
                if entry.index != expected_index:
                    return (
                        False,
                        expected_index,
                        f"Line {line_num}: Sequence gap/tamper. Expected index {expected_index}, found {entry.index}",
                    )

                # 2. Verify previous entry hash link
                if entry.prev_hash != expected_prev_hash:
                    return (
                        False,
                        expected_index,
                        f"Line {line_num}: Broken hash chain. Expected prev_hash {expected_prev_hash}, found {entry.prev_hash}",
                    )

                # 3. Verify HMAC signature under appropriate key version
                k_ver = getattr(entry, "key_version", 1) or 1
                key_for_record = keys.get(k_ver)
                if not key_for_record:
                    if len(keys) == 1 and 1 in keys and k_ver == 1:
                        key_for_record = keys[1]
                    elif isinstance(hmac_key, bytes) and len(keys) <= 1:
                        key_for_record = hmac_key
                    else:
                        return (
                            False,
                            expected_index,
                            f"Line {line_num}: Missing HMAC key for key_version {k_ver}",
                        )

                if not entry.verify_hmac(key_for_record):
                    return (
                        False,
                        expected_index,
                        f"Line {line_num}: Invalid HMAC signature on record index {entry.index} (key_version {k_ver})",
                    )

                # Advance chain state
                expected_prev_hash = entry.compute_sha256()
                expected_index += 1

        return True, expected_index, None
