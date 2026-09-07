import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

_DIR = Path(__file__).parent
_CONFIG_PATH = _DIR / "api_keys.json"
_DPAPI_CONFIG_PATH = _DIR / "api_keys.json.dpapi"

_CACHED_CONFIG: Optional[Dict[str, Any]] = None


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
    if ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(blob_in), "jarvis-api-keys", None, None, None, 0, ctypes.byref(blob_out)
    ):
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
    if ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    ):
        plaintext = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return plaintext
    raise RuntimeError("CryptUnprotectData failed")


def _shred_file(path: Path) -> None:
    """Overwrites file with random bytes and zero bytes before unlinking."""
    try:
        if path.exists():
            size = path.stat().st_size
            with open(path, "wb") as f:
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
            with open(path, "wb") as f:
                f.write(b"\x00" * size)
                f.flush()
                os.fsync(f.fileno())
            path.unlink(missing_ok=True)
    except Exception:
        path.unlink(missing_ok=True)


def get_config(force_reload: bool = False) -> Dict[str, Any]:
    """
    Returns the application configuration dictionary.
    Decrypts config/api_keys.json.dpapi in-memory via Windows DPAPI.
    If only plaintext config/api_keys.json exists on Windows, it is automatically
    migrated to api_keys.json.dpapi and the plaintext file is shredded.
    """
    global _CACHED_CONFIG
    if _CACHED_CONFIG is not None and not force_reload:
        return _CACHED_CONFIG

    # 1. Check for DPAPI encrypted file
    if _DPAPI_CONFIG_PATH.exists():
        try:
            if _is_windows():
                with open(_DPAPI_CONFIG_PATH, "rb") as f:
                    raw_cipher = f.read()
                plaintext = _dpapi_unprotect(raw_cipher)
                _CACHED_CONFIG = json.loads(plaintext.decode("utf-8"))
            else:
                # Fallback for testing / non-Windows if plain exists
                if _CONFIG_PATH.exists():
                    with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
                        _CACHED_CONFIG = json.load(f)
                else:
                    _CACHED_CONFIG = {}
        except Exception as e:
            if _CONFIG_PATH.exists():
                with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
                    _CACHED_CONFIG = json.load(f)
            else:
                raise RuntimeError(f"Failed to decrypt {_DPAPI_CONFIG_PATH.name}: {e}")

        # If legacy plaintext still lingers alongside dpapi, shred it
        if _is_windows() and _CONFIG_PATH.exists():
            _shred_file(_CONFIG_PATH)

        return _CACHED_CONFIG

    # 2. Check for legacy plaintext config
    if _CONFIG_PATH.exists():
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        _CACHED_CONFIG = data

        # Auto-migrate to DPAPI on Windows
        if _is_windows():
            try:
                raw_bytes = json.dumps(data, indent=2).encode("utf-8")
                cipher = _dpapi_protect(raw_bytes)
                with open(_DPAPI_CONFIG_PATH, "wb") as f:
                    f.write(cipher)
                    f.flush()
                    os.fsync(f.fileno())
                _shred_file(_CONFIG_PATH)
            except Exception:
                pass  # Fallback to in-memory config if DPAPI migration fails

        return _CACHED_CONFIG

    return {}


def save_config(config_data: Dict[str, Any]) -> None:
    """Saves config data encrypted via DPAPI on Windows, or JSON on other OS."""
    global _CACHED_CONFIG
    _CACHED_CONFIG = dict(config_data)

    if _is_windows():
        raw_bytes = json.dumps(config_data, indent=2).encode("utf-8")
        cipher = _dpapi_protect(raw_bytes)
        with open(_DPAPI_CONFIG_PATH, "wb") as f:
            f.write(cipher)
            f.flush()
            os.fsync(f.fileno())
        if _CONFIG_PATH.exists():
            _shred_file(_CONFIG_PATH)
    else:
        with open(_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)


def get_os() -> str:
    """Returns: 'windows' | 'mac' | 'linux'"""
    return get_config().get("os_system", "windows").lower()


def is_windows() -> bool: return get_os() == "windows"
def is_mac()     -> bool: return get_os() == "mac"
def is_linux()   -> bool: return get_os() == "linux"