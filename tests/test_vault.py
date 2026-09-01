"""Comprehensive test suite for sentinel.vault module."""

import os
import json
import secrets
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock

from sentinel.vault.storage import (
    WindowsDPAPIStorage,
    KeyringMasterKeyStorage,
    FileFallbackStorage,
    get_platform_key_storage,
    StorageError,
)
from sentinel.vault.crypto import (
    encrypt_payload,
    decrypt_payload,
    wipe_buffer,
    DecryptionError,
    VAULT_PAYLOAD_VERSION,
    NONCE_LENGTH_BYTES,
)
from sentinel.vault.models import SecretMetadata
from sentinel.vault.store import (
    VaultStore,
    VaultError,
    SecretNotFoundError,
    RotationRecoveryError,
)


# ============================================================================
# 1. Crypto & Memory Hygiene Tests
# ============================================================================

def test_crypto_encrypt_and_decrypt_success():
    key = secrets.token_bytes(32)
    plaintext = b"super_secret_api_key_12345!@#$%"
    aad = b"associated_context_data"

    encrypted = encrypt_payload(plaintext, key, associated_data=aad)
    assert len(encrypted) > len(plaintext)
    assert encrypted[0] == VAULT_PAYLOAD_VERSION

    decrypted = decrypt_payload(encrypted, key, associated_data=aad)
    assert decrypted == plaintext


def test_crypto_invalid_key_length_rejected():
    with pytest.raises(ValueError, match="must be exactly 32 bytes"):
        encrypt_payload(b"test", key=b"too_short")

    with pytest.raises(ValueError, match="must be exactly 32 bytes"):
        decrypt_payload(b"dummy_payload", key=b"too_short")


def test_crypto_tampered_ciphertext_fails_decryption():
    key = secrets.token_bytes(32)
    plaintext = b"critical_credentials"
    encrypted = bytearray(encrypt_payload(plaintext, key))

    # Tamper with the last byte (auth tag)
    encrypted[-1] ^= 0xFF

    with pytest.raises(DecryptionError, match="Decryption failed"):
        decrypt_payload(bytes(encrypted), key)


def test_crypto_wrong_key_fails_decryption():
    key1 = secrets.token_bytes(32)
    key2 = secrets.token_bytes(32)
    encrypted = encrypt_payload(b"secret_data", key1)

    with pytest.raises(DecryptionError, match="Decryption failed"):
        decrypt_payload(encrypted, key2)


def test_crypto_aad_mismatch_fails_decryption():
    key = secrets.token_bytes(32)
    encrypted = encrypt_payload(b"secret_data", key, associated_data=b"original_aad")

    with pytest.raises(DecryptionError, match="Decryption failed"):
        decrypt_payload(encrypted, key, associated_data=b"wrong_aad")


def test_crypto_truncated_payload_fails():
    key = secrets.token_bytes(32)
    with pytest.raises(DecryptionError, match="Payload is too short"):
        decrypt_payload(b"short", key)


def test_crypto_unsupported_version_fails():
    key = secrets.token_bytes(32)
    payload = bytes([0x99]) + os.urandom(NONCE_LENGTH_BYTES + 32)
    with pytest.raises(DecryptionError, match="Unsupported payload version"):
        decrypt_payload(payload, key)


def test_crypto_nonce_uniqueness():
    key = secrets.token_bytes(32)
    enc1 = encrypt_payload(b"same_plaintext", key)
    enc2 = encrypt_payload(b"same_plaintext", key)

    nonce1 = enc1[1 : 1 + NONCE_LENGTH_BYTES]
    nonce2 = enc2[1 : 1 + NONCE_LENGTH_BYTES]
    assert nonce1 != nonce2
    assert enc1 != enc2


def test_wipe_buffer_zeros_memory():
    data = bytearray(b"highly_sensitive_master_key_material")
    assert any(b != 0 for b in data)

    wipe_buffer(data)
    assert all(b == 0 for b in data)


# ============================================================================
# 2. Master Key Storage Tests
# ============================================================================

def test_file_fallback_storage(tmp_path):
    storage = FileFallbackStorage(tmp_path)
    key1 = storage.get_or_create_master_key()
    assert len(key1) == 32

    # Subsequent retrieval returns same key
    key2 = storage.get_or_create_master_key()
    assert key1 == key2

    # Store and retrieve pending key
    pending_key = secrets.token_bytes(32)
    storage.store_pending_master_key(pending_key)
    assert storage.get_pending_master_key() == pending_key

    # Promote pending key
    promoted = storage.promote_pending_master_key()
    assert promoted == pending_key
    assert storage.get_or_create_master_key() == pending_key
    assert storage.get_pending_master_key() is None

    # Invalid key length rejected
    with pytest.raises(ValueError, match="must be exactly 32 bytes"):
        storage.store_master_key(b"short")

    # Delete master key
    storage.delete_master_key()
    assert not storage.key_file.exists()


def test_windows_dpapi_ctypes_fallback(tmp_path):
    """Tests that WindowsDPAPIStorage falls back to direct ctypes CryptProtectData if win32crypt is missing."""
    if os.name == "nt":
        with patch.dict("sys.modules", {"win32crypt": None}):
            storage = WindowsDPAPIStorage(tmp_path)
            key = secrets.token_bytes(32)
            protected = storage._protect(key)
            assert protected != key
            unprotected = storage._unprotect(protected)
            assert unprotected == key


def test_windows_dpapi_storage(tmp_path):
    if os.name == "nt":
        storage = WindowsDPAPIStorage(tmp_path)
        key1 = storage.get_or_create_master_key()
        assert len(key1) == 32

        # Stored file on disk is encrypted, not raw plaintext key
        with open(storage.key_file, "rb") as f:
            disk_bytes = f.read()
        assert disk_bytes != key1

        # Re-reading decrypts via DPAPI
        key2 = storage.get_or_create_master_key()
        assert key1 == key2

        # Pending key operations
        new_key = secrets.token_bytes(32)
        storage.store_pending_master_key(new_key)
        assert storage.get_pending_master_key() == new_key
        storage.promote_pending_master_key()
        assert storage.get_or_create_master_key() == new_key
        assert storage.get_pending_master_key() is None

        # Delete
        storage.delete_master_key()
        assert not storage.key_file.exists()


def test_keyring_storage_mock(tmp_path):
    fake_vault = {}

    def mock_get(service, username):
        return fake_vault.get((service, username))

    def mock_set(service, username, password):
        fake_vault[(service, username)] = password

    def mock_del(service, username):
        fake_vault.pop((service, username), None)

    with patch("keyring.get_password", side_effect=mock_get), \
         patch("keyring.set_password", side_effect=mock_set), \
         patch("keyring.delete_password", side_effect=mock_del):

        storage = KeyringMasterKeyStorage(service_name="test_sentinel", username="test_user", vault_dir=tmp_path)
        key1 = storage.get_or_create_master_key()
        assert len(key1) == 32

        key2 = storage.get_or_create_master_key()
        assert key1 == key2

        new_key = secrets.token_bytes(32)
        storage.store_pending_master_key(new_key)
        assert storage.get_pending_master_key() == new_key
        storage.promote_pending_master_key()
        assert storage.get_or_create_master_key() == new_key
        assert storage.get_pending_master_key() is None

        storage.delete_master_key()
        assert (("test_sentinel", "test_user")) not in fake_vault


def test_keyring_storage_runtime_failure_falls_back_with_warning(tmp_path, caplog):
    """Verifies that runtime exceptions from keyring trigger FileFallbackStorage with warning logging."""
    import logging
    with patch("keyring.get_password", side_effect=RuntimeError("Keyring locked by daemon")):
        with caplog.at_level(logging.WARNING):
            storage = KeyringMasterKeyStorage(service_name="test_err", username="test_user", vault_dir=tmp_path)
            key = storage.get_or_create_master_key()
            assert len(key) == 32
            assert "Keyring backend error" in caplog.text or "KEYRING RUNTIME DEGRADATION" in caplog.text


def test_keyring_pending_key_targeted_backend(tmp_path):
    """
    Verifies that when pending key was stored in keyring, get_pending_master_key with target_backend
    targets keyring directly, and if stored in fallback, targets fallback directly.
    """
    storage = KeyringMasterKeyStorage(service_name="test_target", username="user1", vault_dir=tmp_path)
    new_k = secrets.token_bytes(32)

    # Force fallback store
    with patch("keyring.set_password", side_effect=RuntimeError("keyring unavailable")):
        backend_used = storage.store_pending_master_key(new_k)
        assert backend_used == "file_fallback"

    # Confirm targeted retrieval targets fallback
    assert storage.get_pending_master_key(target_backend="file_fallback") == new_k


def test_keyring_pending_key_targeted_keyring_raises_storage_error_on_failure(tmp_path):
    """Verifies that when target_backend='keyring' and keyring raises, StorageError is raised without querying fallback."""
    storage = KeyringMasterKeyStorage(service_name="test_service", username="test_user", vault_dir=tmp_path)
    
    mock_fallback = MagicMock(spec=FileFallbackStorage)
    storage._fallback_storage = mock_fallback

    with patch("keyring.get_password", side_effect=RuntimeError("D-Bus connection dropped")):
        with pytest.raises(StorageError, match="Keyring backend transiently unavailable"):
            storage.get_pending_master_key(target_backend="keyring")

    mock_fallback.get_pending_master_key.assert_not_called()


def test_keyring_pending_key_untargeted_backend_falls_back_on_error(tmp_path):
    """Verifies that when target_backend=None and keyring raises, fallback retrieval is attempted."""
    storage = KeyringMasterKeyStorage(service_name="test_service", username="test_user", vault_dir=tmp_path)
    mock_fallback = MagicMock(spec=FileFallbackStorage)
    fallback_key = secrets.token_bytes(32)
    mock_fallback.get_pending_master_key.return_value = fallback_key
    storage._fallback_storage = mock_fallback

    with patch("keyring.get_password", side_effect=RuntimeError("Keyring locked")):
        res = storage.get_pending_master_key(target_backend=None)
        assert res == fallback_key

    mock_fallback.get_pending_master_key.assert_called_once()


def test_keyring_pending_key_targeted_keyring_returns_none_when_absent(tmp_path):
    """Verifies that when target_backend='keyring' and key is absent (no error), returns None without querying fallback."""
    storage = KeyringMasterKeyStorage(service_name="test_service", username="test_user", vault_dir=tmp_path)
    mock_fallback = MagicMock(spec=FileFallbackStorage)
    storage._fallback_storage = mock_fallback

    with patch("keyring.get_password", return_value=None):
        res = storage.get_pending_master_key(target_backend="keyring")
        assert res is None

    mock_fallback.get_pending_master_key.assert_not_called()


def test_vault_store_rotation_recovery_storage_error_handling(tmp_path):
    """Verifies that transient StorageError during rotation recovery raises RotationRecoveryError with retry message."""
    mock_storage = MagicMock(spec=KeyringMasterKeyStorage)
    mock_storage.get_pending_master_key.side_effect = StorageError("Keyring transiently unavailable")

    journal_data = {
        "stage": "staged",
        "has_pending_key": True,
        "pending_key_backend": "keyring",
        "staged_files": [],
        "created_at": "2026-08-31T12:00:00Z",
    }
    journal_file = tmp_path / "rotation_journal.json"
    with open(journal_file, "w", encoding="utf-8") as f:
        json.dump(journal_data, f)

    with pytest.raises(RotationRecoveryError, match="Storage backend unavailable during rotation recovery"):
        VaultStore(vault_dir=tmp_path, key_storage=mock_storage)

    assert mock_storage.get_pending_master_key.call_count == 3


def test_vault_store_rotation_recovery_succeeds_on_retry_attempt_3(tmp_path):
    """Verifies that if storage errors on attempts 1 and 2 but succeeds on attempt 3, recovery succeeds."""
    mock_storage = MagicMock(spec=KeyringMasterKeyStorage)
    real_key = secrets.token_bytes(32)
    mock_storage.get_pending_master_key.side_effect = [
        StorageError("fail 1"),
        StorageError("fail 2"),
        real_key,
    ]

    journal_data = {
        "stage": "files_committed",
        "has_pending_key": True,
        "pending_key_backend": "keyring",
        "staged_files": [],
        "created_at": "2026-08-31T12:00:00Z",
    }
    journal_file = tmp_path / "rotation_journal.json"
    with open(journal_file, "w", encoding="utf-8") as f:
        json.dump(journal_data, f)

    store = VaultStore(vault_dir=tmp_path, key_storage=mock_storage)
    assert mock_storage.get_pending_master_key.call_count == 3
    mock_storage.promote_pending_master_key.assert_called_once_with(target_backend="keyring")
    assert not journal_file.exists()


def test_vault_store_journal_dacl_warning_logged(tmp_path, caplog):
    """Verifies that failures applying Windows DACL to rotation journal log a warning."""
    import logging
    storage = FileFallbackStorage(tmp_path)
    store = VaultStore(vault_dir=tmp_path, key_storage=storage)

    if os.name == "nt":
        with patch("win32security.SetFileSecurity", side_effect=RuntimeError("Simulated DACL error")):
            with caplog.at_level(logging.WARNING):
                store._write_journal_atomic_locked({"test": "data"})
                assert "Failed to apply restrictive Windows DACL" in caplog.text


def test_get_platform_key_storage_factory(tmp_path):
    storage_fallback = get_platform_key_storage(tmp_path, force_backend="fallback")
    assert isinstance(storage_fallback, FileFallbackStorage)

    if os.name == "nt":
        storage_win = get_platform_key_storage(tmp_path, force_backend="windows")
        assert isinstance(storage_win, WindowsDPAPIStorage)


# ============================================================================
# 3. VaultStore CRUD & Migration Tests
# ============================================================================

def test_vault_store_set_and_get(tmp_path):
    storage = FileFallbackStorage(tmp_path)
    store = VaultStore(vault_dir=tmp_path, key_storage=storage)

    store.set_secret("OPENAI_API_KEY", "sk-proj-1234567890abcdef", content_type="text/plain")
    assert store.has_secret("OPENAI_API_KEY") is True
    assert store.get_secret_string("OPENAI_API_KEY") == "sk-proj-1234567890abcdef"
    assert store.get_secret("OPENAI_API_KEY") == b"sk-proj-1234567890abcdef"

    # Inspect metadata
    meta = store.get_metadata("OPENAI_API_KEY")
    assert meta is not None
    assert meta.key == "OPENAI_API_KEY"
    assert meta.content_type == "text/plain"


def test_vault_store_zero_plaintext_on_disk(tmp_path):
    storage = FileFallbackStorage(tmp_path)
    store = VaultStore(vault_dir=tmp_path, key_storage=storage)
    secret_value = "VERY_CONFIDENTIAL_PLAINTEXT_SECRET_123"

    store.set_secret("DATABASE_PASSWORD", secret_value)

    # Grep across all files in vault directory to confirm plaintext never appears on disk
    for root, _, files in os.walk(tmp_path):
        for f in files:
            file_p = Path(root) / f
            with open(file_p, "rb") as fh:
                content = fh.read()
                assert secret_value.encode("utf-8") not in content


def test_vault_store_get_nonexistent_key_raises(tmp_path):
    storage = FileFallbackStorage(tmp_path)
    store = VaultStore(vault_dir=tmp_path, key_storage=storage)

    with pytest.raises(SecretNotFoundError, match="not found in vault"):
        store.get_secret("NON_EXISTENT_KEY")

    assert store.has_secret("NON_EXISTENT_KEY") is False
    assert store.get_metadata("NON_EXISTENT_KEY") is None


def test_vault_store_list_and_delete(tmp_path):
    storage = FileFallbackStorage(tmp_path)
    store = VaultStore(vault_dir=tmp_path, key_storage=storage)

    store.set_secret("KEY_A", "val_a")
    store.set_secret("KEY_B", "val_b")
    store.set_secret("KEY_C", "val_c")

    assert store.list_secrets() == ["KEY_A", "KEY_B", "KEY_C"]

    assert store.delete_secret("KEY_B") is True
    assert store.list_secrets() == ["KEY_A", "KEY_C"]
    assert store.has_secret("KEY_B") is False

    assert store.delete_secret("KEY_B") is False


def test_vault_store_migrate_plaintext_file(tmp_path):
    storage = FileFallbackStorage(tmp_path)
    store = VaultStore(vault_dir=tmp_path, key_storage=storage)

    plaintext_file = tmp_path / ".env.legacy"
    legacy_content = b"STRIPE_KEY=sk_live_998877665544\nAWS_SECRET=supersecret123\n"
    with open(plaintext_file, "wb") as f:
        f.write(legacy_content)

    assert plaintext_file.exists()

    store.migrate_plaintext_file(plaintext_file, secret_key="ENV_CONFIG", content_type="text/env")

    # Verify migration: secret is in vault and original file is shredded and removed from disk
    assert not plaintext_file.exists()
    assert store.has_secret("ENV_CONFIG") is True
    assert store.get_secret("ENV_CONFIG") == legacy_content


def test_vault_store_key_rotation(tmp_path):
    storage = FileFallbackStorage(tmp_path)
    store = VaultStore(vault_dir=tmp_path, key_storage=storage)

    # Store multiple secrets under original master key
    store.set_secret("SECRET_1", "value_one")
    store.set_secret("SECRET_2", "value_two")
    store.set_secret("SECRET_3", "value_three")

    old_master_key = storage.get_or_create_master_key()

    # Capture raw encrypted files on disk before rotation
    encrypted_blobs_before = {}
    for key in store.list_secrets():
        fname = store._key_to_filename(key)
        with open(store.entries_dir / fname, "rb") as f:
            encrypted_blobs_before[key] = f.read()

    # Perform atomic key rotation
    store.rotate_master_key()

    new_master_key = storage.get_or_create_master_key()
    assert old_master_key != new_master_key

    # Confirm all secrets are still decryptable with new key
    assert store.get_secret_string("SECRET_1") == "value_one"
    assert store.get_secret_string("SECRET_2") == "value_two"
    assert store.get_secret_string("SECRET_3") == "value_three"

    # Confirm ciphertext on disk has changed and cannot be decrypted with old key
    for key in store.list_secrets():
        fname = store._key_to_filename(key)
        with open(store.entries_dir / fname, "rb") as f:
            new_blob = f.read()
        assert new_blob != encrypted_blobs_before[key]
        with pytest.raises(DecryptionError):
            decrypt_payload(new_blob, old_master_key, associated_data=key.encode("utf-8"))


def test_vault_store_rotation_journal_contains_no_raw_keys(tmp_path):
    """
    Test (a): Confirms that during/after rotation, the journal file contains NO substring
    matching either the old key hex or the new key hex.
    """
    storage = FileFallbackStorage(tmp_path)
    store = VaultStore(vault_dir=tmp_path, key_storage=storage)
    store.set_secret("CONFIDENTIAL", "secret_content_val")

    old_key = storage.get_or_create_master_key()
    journal_content_captured = []

    orig_promote = storage.promote_pending_master_key

    def inspect_journal_before_commit(*args, **kwargs):
        assert store.rotation_journal_file.exists()
        with open(store.rotation_journal_file, "r", encoding="utf-8") as f:
            raw_text = f.read()
            journal_content_captured.append(raw_text)
            pending_k = storage.get_pending_master_key()
            # Assert NO raw hex key material in the journal
            assert old_key.hex() not in raw_text
            assert pending_k.hex() not in raw_text
        return orig_promote(*args, **kwargs)

    storage.promote_pending_master_key = inspect_journal_before_commit
    store.rotate_master_key()

    assert len(journal_content_captured) == 1
    assert not store.rotation_journal_file.exists()


def test_vault_store_rotation_crash_recovery(tmp_path):
    """
    Simulates a mid-rotation process crash right after files are replaced on disk
    but before pending key promotion. Asserts that the vault automatically
    detects the rotation journal on startup, promotes the pending key, and decrypts all data.
    """
    storage = FileFallbackStorage(tmp_path)
    store = VaultStore(vault_dir=tmp_path, key_storage=storage)

    store.set_secret("DB_PASS", "super_secret_db_password")
    store.set_secret("AUTH_TOKEN", "jwt_auth_token_xyz")

    orig_promote = storage.promote_pending_master_key

    def crashing_promote(*args, **kwargs):
        raise RuntimeError("Simulated crash right after files replaced and before promotion!")

    storage.promote_pending_master_key = crashing_promote

    with pytest.raises(RuntimeError, match="Simulated crash"):
        store.rotate_master_key()

    # Confirm rotation journal was written and exists on disk
    assert store.rotation_journal_file.exists()

    # Restore real storage function to simulate process reboot
    storage.promote_pending_master_key = orig_promote

    # Spin up new VaultStore instance (simulating application restart)
    recovered_store = VaultStore(vault_dir=tmp_path, key_storage=storage)

    # Automatic recovery must reconcile the state and delete the journal
    assert not recovered_store.rotation_journal_file.exists()

    # All secrets must remain 100% accessible and decryptable
    assert recovered_store.get_secret_string("DB_PASS") == "super_secret_db_password"
    assert recovered_store.get_secret_string("AUTH_TOKEN") == "jwt_auth_token_xyz"


def test_vault_store_corrupted_journal_fails_closed(tmp_path):
    """
    Test (c): Confirms that an unreadable/corrupted rotation journal on startup raises
    RotationRecoveryError and fails closed across all vault operations.
    """
    storage = FileFallbackStorage(tmp_path)
    store = VaultStore(vault_dir=tmp_path, key_storage=storage)
    store.set_secret("API_KEY", "value_123")

    # Attacker / corruption writes invalid JSON to rotation journal
    with open(store.rotation_journal_file, "w", encoding="utf-8") as f:
        f.write("{invalid_corrupted_json_content...")

    # Instantiating store or performing operations must fail closed
    with pytest.raises(RotationRecoveryError, match="corrupted or unreadable"):
        VaultStore(vault_dir=tmp_path, key_storage=storage)

    with pytest.raises(RotationRecoveryError, match="corrupted or unreadable"):
        store.get_secret("API_KEY")

    with pytest.raises(RotationRecoveryError, match="corrupted or unreadable"):
        store.set_secret("NEW_KEY", "new_val")


def test_vault_event_sink(tmp_path):
    events = []

    def sink(event_type, details):
        events.append((event_type, details))

    storage = FileFallbackStorage(tmp_path)
    store = VaultStore(vault_dir=tmp_path, key_storage=storage, event_sink=sink)

    store.set_secret("TEST_KEY", "test_val")
    store.get_secret("TEST_KEY")
    store.delete_secret("TEST_KEY")

    event_names = [e[0] for e in events]
    assert "vault_secret_set" in event_names
    assert "vault_secret_accessed" in event_names
    assert "vault_secret_deleted" in event_names


def test_vault_store_rotation_crash_during_staging_recovery(tmp_path):
    """
    Simulates a mid-rotation crash when journal is at 'staged' stage (after temp files are written
    and journal written, but before all files are replaced).
    Asserts that next startup successfully completes replacement and promotes pending key.
    """
    storage = FileFallbackStorage(tmp_path)
    store = VaultStore(vault_dir=tmp_path, key_storage=storage)
    store.set_secret("KEY1", "val1")
    store.set_secret("KEY2", "val2")

    orig_write_journal = store._write_journal_atomic_locked

    def crashing_journal(journal_data):
        orig_write_journal(journal_data)
        if journal_data.get("stage") == "staged":
            raise RuntimeError("Simulated crash right after writing staged journal!")

    store._write_journal_atomic_locked = crashing_journal

    with pytest.raises(RuntimeError, match="Simulated crash"):
        store.rotate_master_key()

    assert store.rotation_journal_file.exists()

    # Reopen store: startup recovery handles 'staged' journal, completes file move and promotes key
    store_recovered = VaultStore(vault_dir=tmp_path, key_storage=storage)
    assert not store_recovered.rotation_journal_file.exists()
    assert store_recovered.get_secret_string("KEY1") == "val1"
    assert store_recovered.get_secret_string("KEY2") == "val2"


def test_enrollment_vault_rotation_failure_emits_audit_and_completes_pin_change(tmp_path):
    """
    Forces VaultStore.rotate_master_key() to raise an exception during re-enrollment and confirms:
    (a) The PIN change still successfully completes.
    (b) The vault_rotation_failed_during_enrollment event is emitted to the audit event sink with error details.
    """
    from sentinel.auth.enrollment import EnrollmentManager
    from sentinel.auth.hasher import PinHasher

    emitted_events = []

    def sink(event_type, details):
        emitted_events.append((event_type, details))

    auth_dir = tmp_path / "auth"
    vault_dir = tmp_path / "vault"
    hasher = PinHasher()

    mgr = EnrollmentManager(auth_dir=auth_dir, hasher=hasher, event_sink=sink)

    # 1. First run enrollment
    token = mgr.generate_presence_challenge()
    mgr.enroll(primary_pin="111111", recovery_pin="222222", presence_token=token)

    # 2. Re-enroll with new PIN while vault rotation raises an exception
    with patch("sentinel.vault.store.VaultStore.rotate_master_key", side_effect=RuntimeError("Simulated DPAPI failure")):
        with patch("sentinel.vault.store.VaultStore.list_secrets", return_value=["SECRET1"]):
            success = mgr.enroll(
                primary_pin="333333",
                recovery_pin="444444",
                current_primary_pin="111111",
            )
            # (a) PIN change must succeed
            assert success is True

    # (b) Failure event must be recorded in the audit event sink
    event_names = [e[0] for e in emitted_events]
    assert "vault_rotation_failed_during_enrollment" in event_names
    failed_event = next(e for e in emitted_events if e[0] == "vault_rotation_failed_during_enrollment")
    assert "Simulated DPAPI failure" in failed_event[1]["error"]

    # Verify new PIN is active
    creds = mgr.get_credentials()
    assert hasher.verify_pin("333333", creds.primary_pin)


