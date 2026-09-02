"""
core/watchdog_auth.py — Cryptographic HMAC signature and bounded lifetime verification
for Watchdog Intentional-Exit Marker and Service Heartbeats.
Uses Windows DPAPI (CryptProtectData / CryptUnprotectData) to protect secret keys at rest.
"""
from __future__ import annotations

import hmac
import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional, Dict, Any

from sentinel.security_utils import apply_owner_only_dacl

logger = logging.getLogger(__name__)

INTENTIONAL_EXIT_MAX_AGE_SECS = 300.0  # 5 minutes bounded lifetime


def _protect_key_bytes(data: bytes) -> bytes:
    """Encrypts raw key bytes using Windows DPAPI (CryptProtectData)."""
    try:
        import win32crypt
        return win32crypt.CryptProtectData(data, "Sentinel Watchdog Auth Key", None, None, None, 0)
    except (ImportError, AttributeError):
        try:
            import ctypes
            from ctypes import wintypes

            class DATA_BLOB(ctypes.Structure):
                _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

            crypt32 = ctypes.windll.crypt32
            kernel32 = ctypes.windll.kernel32

            in_blob = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
            out_blob = DATA_BLOB()

            if not crypt32.CryptProtectData(ctypes.byref(in_blob), "Sentinel Watchdog Auth Key", None, None, None, 0, ctypes.byref(out_blob)):
                return data

            try:
                return ctypes.string_at(out_blob.pbData, out_blob.cbData)
            finally:
                kernel32.LocalFree(out_blob.pbData)
        except Exception:
            return data


def _unprotect_key_bytes(protected_data: bytes) -> bytes:
    """Decrypts protected key bytes using Windows DPAPI (CryptUnprotectData)."""
    try:
        import win32crypt
        _, data = win32crypt.CryptUnprotectData(protected_data, None, None, None, 0)
        return data
    except (ImportError, AttributeError):
        try:
            import ctypes
            from ctypes import wintypes

            class DATA_BLOB(ctypes.Structure):
                _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

            crypt32 = ctypes.windll.crypt32
            kernel32 = ctypes.windll.kernel32

            in_blob = DATA_BLOB(len(protected_data), ctypes.cast(ctypes.create_string_buffer(protected_data), ctypes.POINTER(ctypes.c_byte)))
            out_blob = DATA_BLOB()

            if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
                return protected_data

            try:
                return ctypes.string_at(out_blob.pbData, out_blob.cbData)
            finally:
                kernel32.LocalFree(out_blob.pbData)
        except Exception:
            return protected_data


def _get_or_create_watchdog_key(key_path: Optional[Path] = None, use_dpapi: bool = True) -> bytes:
    """
    Retrieves or atomically creates a 32-byte HMAC secret key.
    The key file is encrypted via Windows DPAPI and protected with owner-only DACL.
    """
    if key_path is None:
        key_path = Path(__file__).resolve().parent.parent / "memory" / ".watchdog_auth.key"

    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        try:
            with open(key_path, "rb") as f:
                data = f.read()
            if data:
                unprotected = _unprotect_key_bytes(data) if use_dpapi else data
                if len(unprotected) == 32:
                    return unprotected
        except Exception as e:
            logger.warning("Could not read watchdog key (%s); generating new key.", e)

    new_key = os.urandom(32)
    payload_to_write = _protect_key_bytes(new_key) if use_dpapi else new_key
    temp_key = key_path.with_suffix(f".tmp.{os.getpid()}")
    flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(temp_key, flags, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(payload_to_write)
        temp_key.replace(key_path)
    except Exception:
        if temp_key.exists():
            try:
                temp_key.unlink(missing_ok=True)
            except Exception:
                pass
        try:
            key_path.write_bytes(payload_to_write)
        except Exception:
            pass

    apply_owner_only_dacl(key_path)
    return new_key


def _compute_hmac(key: bytes, payload_dict: Dict[str, Any]) -> str:
    """Computes deterministic HMAC-SHA256 over canonical JSON string of payload."""
    canonical_data = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
    return hmac.new(key, canonical_data, hashlib.sha256).hexdigest()


def write_authenticated_exit_marker(
    marker_path: Path,
    reason: str = "user_quit",
    key_path: Optional[Path] = None,
    use_dpapi: bool = True,
) -> Path:
    """
    Writes a cryptographically signed intentional-exit marker with timestamp and PID.
    Applies DACL protection atomically.
    """
    key = _get_or_create_watchdog_key(key_path, use_dpapi=use_dpapi)
    payload = {
        "pid": os.getpid(),
        "ts": time.time(),
        "reason": reason,
    }
    sig = _compute_hmac(key, payload)
    marker_data = {
        "payload": payload,
        "hmac": sig,
    }

    marker_path.parent.mkdir(parents=True, exist_ok=True)
    temp_file = marker_path.with_suffix(f".tmp.{os.getpid()}")
    temp_file.write_text(json.dumps(marker_data, indent=2), encoding="utf-8")
    temp_file.replace(marker_path)
    apply_owner_only_dacl(marker_path)
    return marker_path


def verify_authenticated_exit_marker(
    marker_path: Path,
    max_age_secs: float = INTENTIONAL_EXIT_MAX_AGE_SECS,
    key_path: Optional[Path] = None,
    use_dpapi: bool = True,
) -> bool:
    """
    Verifies that the intentional-exit marker exists, has a valid HMAC signature
    from a legitimate running process, and is within its bounded TTL window.
    If the file is forged, corrupted, or expired, returns False and removes it.
    """
    if not marker_path.exists():
        return False

    try:
        raw_text = marker_path.read_text(encoding="utf-8").strip()
        data = json.loads(raw_text)
        if not isinstance(data, dict) or "payload" not in data or "hmac" not in data:
            logger.critical("FORGERY ATTEMPT: Intentional-exit marker has invalid schema. Rejecting.")
            try:
                marker_path.unlink(missing_ok=True)
            except Exception:
                pass
            return False

        payload = data["payload"]
        sig = data["hmac"]
        key = _get_or_create_watchdog_key(key_path, use_dpapi=use_dpapi)
        expected_sig = _compute_hmac(key, payload)

        if not hmac.compare_digest(sig, expected_sig):
            logger.critical("FORGERY ATTEMPT: Intentional-exit marker HMAC signature mismatch. Rejecting.")
            try:
                marker_path.unlink(missing_ok=True)
            except Exception:
                pass
            return False

        ts = payload.get("ts", 0)
        age = time.time() - ts
        if age > max_age_secs:
            logger.info("Intentional-exit marker expired (%.1fs old > %.1fs limit). Resuming monitoring.", age, max_age_secs)
            try:
                marker_path.unlink(missing_ok=True)
            except Exception:
                pass
            return False

        return True
    except Exception as e:
        logger.critical("Error verifying intentional-exit marker (%s). Rejecting as tampered.", e)
        try:
            marker_path.unlink(missing_ok=True)
        except Exception:
            pass
        return False
