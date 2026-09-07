"""
tests/security/test_adv_secrets_dpapi.py
==========================================
Verifies Windows DPAPI secrets-at-rest protection, transparent in-memory
decryption, and automatic migration shredding of plaintext config.
"""
import os
import sys
import json
import pytest
from pathlib import Path
from config import get_config, save_config, _dpapi_protect, _dpapi_unprotect, _is_windows


def test_dpapi_protect_and_unprotect_roundtrip():
    """Tests low-level DPAPI encryption and decryption on Windows."""
    if not _is_windows():
        pytest.skip("DPAPI is Windows-only")

    secret_payload = b'{"test_secret": "super_confidential_key_12345"}'
    ciphertext = _dpapi_protect(secret_payload)
    assert ciphertext != secret_payload
    assert len(ciphertext) > len(secret_payload)

    decrypted = _dpapi_unprotect(ciphertext)
    assert decrypted == secret_payload


def test_get_config_in_memory_decryption():
    """Verifies get_config returns valid dict with expected secret keys."""
    cfg = get_config(force_reload=True)
    assert isinstance(cfg, dict)
    assert "mobile_auth_token" in cfg
    assert "os_system" in cfg


def test_auto_migration_and_shredding(tmp_path, monkeypatch):
    """Verifies that plaintext api_keys.json is auto-migrated to .dpapi and securely shredded."""
    if not _is_windows():
        pytest.skip("DPAPI is Windows-only")

    import config
    fake_dir = tmp_path / "config"
    fake_dir.mkdir(parents=True, exist_ok=True)

    plain_file = fake_dir / "api_keys.json"
    dpapi_file = fake_dir / "api_keys.json.dpapi"

    test_data = {"test_key": "secret_value_xyz", "os_system": "windows"}
    plain_file.write_text(json.dumps(test_data), encoding="utf-8")

    monkeypatch.setattr(config, "_CONFIG_PATH", plain_file)
    monkeypatch.setattr(config, "_DPAPI_CONFIG_PATH", dpapi_file)
    monkeypatch.setattr(config, "_CACHED_CONFIG", None)

    loaded = config.get_config(force_reload=True)
    assert loaded.get("test_key") == "secret_value_xyz"

    # DPAPI file must exist now, and plaintext must be shredded and unlinked
    assert dpapi_file.exists()
    assert not plain_file.exists()

    # Reading again without plain_file should work from .dpapi
    monkeypatch.setattr(config, "_CACHED_CONFIG", None)
    loaded_from_dpapi = config.get_config(force_reload=True)
    assert loaded_from_dpapi.get("test_key") == "secret_value_xyz"
