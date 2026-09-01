"""Comprehensive test suite for the sentinel.audit module."""

import os
import json
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from sentinel.audit.models import AuditEntry, GENESIS_HASH
from sentinel.audit.sinks import (
    LocalFileSink,
    WebhookMirrorSink,
    MultiSink,
    LocalSinkError,
)
from sentinel.audit.security_utils import apply_owner_only_dacl
from sentinel.audit.chain import AuditLogger, AuditError, ChainIntegrityError


# ============================================================================
# 1. Models & Hashing Tests
# ============================================================================

def test_audit_entry_canonical_bytes_deterministic():
    hmac_key = secrets.token_bytes(32)
    entry1 = AuditEntry.create(
        index=0,
        timestamp="2026-08-31T12:00:00Z",
        event_type="auth_success",
        actor="user1",
        tier="admin",
        details={"ip": "127.0.0.1", "method": "pin"},
        prev_hash=GENESIS_HASH,
        hmac_key=hmac_key,
    )
    entry2 = AuditEntry.create(
        index=0,
        timestamp="2026-08-31T12:00:00Z",
        event_type="auth_success",
        actor="user1",
        tier="admin",
        details={"method": "pin", "ip": "127.0.0.1"},  # different key order
        prev_hash=GENESIS_HASH,
        hmac_key=hmac_key,
    )
    assert entry1.canonical_bytes() == entry2.canonical_bytes()
    assert entry1.entry_hmac == entry2.entry_hmac
    assert entry1.verify_hmac(hmac_key) is True


def test_audit_entry_hmac_fails_with_wrong_key_or_modified_payload():
    key1 = secrets.token_bytes(32)
    key2 = secrets.token_bytes(32)

    entry = AuditEntry.create(
        index=0,
        timestamp="2026-08-31T12:00:00Z",
        event_type="secret_accessed",
        actor="daemon",
        tier=None,
        details={"key": "API_TOKEN"},
        prev_hash=GENESIS_HASH,
        hmac_key=key1,
    )

    # Wrong key fails
    assert entry.verify_hmac(key2) is False

    # Tampered payload fails
    tampered_dict = entry.model_dump()
    tampered_dict["details"]["key"] = "ATTACKER_OVERWRITE"
    tampered_entry = AuditEntry.model_validate(tampered_dict)
    assert tampered_entry.verify_hmac(key1) is False


# ============================================================================
# 2. Sinks Tests
# ============================================================================

def test_local_file_sink_appends(tmp_path):
    log_file = tmp_path / "audit_test.jsonl"
    sink = LocalFileSink(log_file)
    hmac_key = secrets.token_bytes(32)

    entry = AuditEntry.create(
        index=0,
        timestamp="2026-08-31T12:00:00Z",
        event_type="test_event",
        actor="tester",
        tier=None,
        details={},
        prev_hash=GENESIS_HASH,
        hmac_key=hmac_key,
    )
    sink.emit(entry)

    assert log_file.exists()
    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event_type"] == "test_event"


def test_webhook_mirror_sink_worker_success(tmp_path):
    hmac_key = secrets.token_bytes(32)
    entry = AuditEntry.create(
        index=0,
        timestamp="2026-08-31T12:00:00Z",
        event_type="remote_event",
        actor="system",
        tier=None,
        details={"host": "node1"},
        prev_hash=GENESIS_HASH,
        hmac_key=hmac_key,
    )

    posted_requests = []

    def mock_urlopen(req, timeout=None):
        posted_requests.append((req.full_url, req.data, req.headers))
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        sink = WebhookMirrorSink("https://audit-mirror.internal/events", auth_header="Bearer secret_token")
        sink.emit(entry)
        sink.flush()
        sink.close()

    assert len(posted_requests) == 1
    assert posted_requests[0][0] == "https://audit-mirror.internal/events"
    assert b"remote_event" in posted_requests[0][1]


def test_webhook_mirror_sink_retry_and_failure_alert(tmp_path):
    hmac_key = secrets.token_bytes(32)
    entry = AuditEntry.create(
        index=42,
        timestamp="2026-08-31T12:00:00Z",
        event_type="failed_mirror_event",
        actor="system",
        tier=None,
        details={},
        prev_hash=GENESIS_HASH,
        hmac_key=hmac_key,
    )

    failed_notifications = []

    def on_fail(ent, exc):
        failed_notifications.append((ent.index, str(exc)))

    with patch("urllib.request.urlopen", side_effect=RuntimeError("Endpoint unreachable 503")):
        sink = WebhookMirrorSink(
            "https://unreachable.mirror/events",
            max_retries=2,
            on_failure=on_fail,
        )
        sink.emit(entry)
        sink.flush()
        sink.close()

    assert len(failed_notifications) == 1
    assert failed_notifications[0][0] == 42
    assert "Endpoint unreachable" in failed_notifications[0][1]


def test_multi_sink_fanout_and_local_fail_closed():
    local_sink = MagicMock(spec=LocalFileSink)
    local_sink.emit.side_effect = LocalSinkError("Disk I/O error on local audit file")
    mirror_sink = MagicMock(spec=WebhookMirrorSink)

    multi = MultiSink([local_sink, mirror_sink])
    hmac_key = secrets.token_bytes(32)
    entry = AuditEntry.create(
        index=0,
        timestamp="2026-08-31T12:00:00Z",
        event_type="test",
        actor="system",
        tier=None,
        details={},
        prev_hash=GENESIS_HASH,
        hmac_key=hmac_key,
    )

    # Local sink failure must raise LocalSinkError and not be silently ignored
    with pytest.raises(LocalSinkError, match="Disk I/O error"):
        multi.emit(entry)


# ============================================================================
# 3. AuditLogger & Chain Integrity Verification Tests
# ============================================================================

def test_audit_logger_auto_key_generation(tmp_path):
    """Verifies that AuditLogger automatically generates and persists a 32-byte HMAC key."""
    logger1 = AuditLogger(audit_dir=tmp_path)
    assert len(logger1.hmac_key) == 32
    assert (tmp_path / ".audit_hmac.key").exists()

    logger2 = AuditLogger(audit_dir=tmp_path)
    assert logger2.hmac_key == logger1.hmac_key


def test_audit_logger_event_creation_and_chaining(tmp_path):
    hmac_key = secrets.token_bytes(32)
    logger = AuditLogger(audit_dir=tmp_path, hmac_key=hmac_key)

    e0 = logger.log_event("vault_initialized", actor="admin", details={"version": "1.0"})
    assert e0.index == 0
    assert e0.prev_hash == GENESIS_HASH

    e1 = logger.log_event("secret_set", actor="service_a", details={"key": "DATABASE_URL"})
    assert e1.index == 1
    assert e1.prev_hash == e0.compute_sha256()

    e2 = logger.log_event("auth_login", actor="user2", tier="operator")
    assert e2.index == 2
    assert e2.prev_hash == e1.compute_sha256()

    # Verify unbroken chain
    valid, count, error = AuditLogger.verify_chain(logger.log_file, hmac_key)
    assert valid is True
    assert count == 3
    assert error is None


def test_audit_logger_startup_verification_detects_tampering(tmp_path):
    hmac_key = secrets.token_bytes(32)
    logger1 = AuditLogger(audit_dir=tmp_path, hmac_key=hmac_key)
    logger1.log_event("evt_1")
    logger1.log_event("evt_2")

    # Tamper with file
    with open(logger1.log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
    data = json.loads(lines[0])
    data["event_type"] = "tampered_type"
    lines[0] = json.dumps(data) + "\n"
    with open(logger1.log_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    # Next startup must fail closed with ChainIntegrityError
    with pytest.raises(ChainIntegrityError, match="Startup audit verification failed"):
        AuditLogger(audit_dir=tmp_path, hmac_key=hmac_key, verify_on_startup=True)


def test_verify_chain_empty_log(tmp_path):
    empty_file = tmp_path / "empty.jsonl"
    empty_file.touch()
    hmac_key = secrets.token_bytes(32)

    valid, count, error = AuditLogger.verify_chain(empty_file, hmac_key)
    assert valid is True
    assert count == 0
    assert error is None


def test_verify_chain_detects_payload_modification(tmp_path):
    hmac_key = secrets.token_bytes(32)
    logger = AuditLogger(audit_dir=tmp_path, hmac_key=hmac_key)

    logger.log_event("login", actor="alice")
    logger.log_event("delete_db", actor="alice")
    logger.log_event("logout", actor="alice")

    # Attacker modifies the second record in the file
    with open(logger.log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    record1 = json.loads(lines[1])
    record1["actor"] = "bob"  # Tamper actor
    lines[1] = json.dumps(record1) + "\n"

    with open(logger.log_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    valid, failed_index, error = AuditLogger.verify_chain(logger.log_file, hmac_key)
    assert valid is False
    assert failed_index == 1
    assert "Invalid HMAC signature" in error


def test_verify_chain_detects_deleted_record(tmp_path):
    hmac_key = secrets.token_bytes(32)
    logger = AuditLogger(audit_dir=tmp_path, hmac_key=hmac_key)

    logger.log_event("event_0")
    logger.log_event("event_1_sensitive_action")
    logger.log_event("event_2")

    # Attacker deletes the second line
    with open(logger.log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    del lines[1]

    with open(logger.log_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    valid, failed_index, error = AuditLogger.verify_chain(logger.log_file, hmac_key)
    assert valid is False
    assert failed_index == 1
    assert "Sequence gap" in error or "Broken hash chain" in error


def test_verify_chain_detects_inserted_record(tmp_path):
    hmac_key = secrets.token_bytes(32)
    logger = AuditLogger(audit_dir=tmp_path, hmac_key=hmac_key)

    logger.log_event("event_0")
    logger.log_event("event_1")

    # Attacker duplicates / inserts a line
    with open(logger.log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    lines.insert(1, lines[0])

    with open(logger.log_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    valid, failed_index, error = AuditLogger.verify_chain(logger.log_file, hmac_key)
    assert valid is False
    assert failed_index == 1
    assert "Sequence gap" in error or "Broken hash chain" in error


def test_verify_chain_detects_reordered_records(tmp_path):
    hmac_key = secrets.token_bytes(32)
    logger = AuditLogger(audit_dir=tmp_path, hmac_key=hmac_key)

    logger.log_event("event_0")
    logger.log_event("event_1")
    logger.log_event("event_2")

    # Attacker swaps lines 1 and 2
    with open(logger.log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    lines[1], lines[2] = lines[2], lines[1]

    with open(logger.log_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    valid, failed_index, error = AuditLogger.verify_chain(logger.log_file, hmac_key)
    assert valid is False
    assert failed_index == 1


def test_verify_chain_fails_with_wrong_hmac_key(tmp_path):
    key1 = secrets.token_bytes(32)
    key2 = secrets.token_bytes(32)

    logger = AuditLogger(audit_dir=tmp_path, hmac_key=key1)
    logger.log_event("action_a")
    logger.log_event("action_b")

    valid, failed_index, error = AuditLogger.verify_chain(logger.log_file, key2)
    assert valid is False
    assert failed_index == 0
    assert "Invalid HMAC signature" in error


def test_audit_logger_concurrent_writes(tmp_path):
    hmac_key = secrets.token_bytes(32)
    logger = AuditLogger(audit_dir=tmp_path, hmac_key=hmac_key)

    total_events = 40

    def write_event(i):
        logger.log_event(f"event_{i}", actor=f"worker_{i % 4}", details={"num": i})

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(write_event, range(total_events)))

    valid, count, error = AuditLogger.verify_chain(logger.log_file, hmac_key)
    assert valid is True
    assert count == total_events
    assert error is None


# ============================================================================
# 4. Security Gap Fixes Tests (DACL, Truncation Detection, Failure Logging)
# ============================================================================

def test_hmac_key_dacl_protection(tmp_path):
    """Asserts .audit_hmac.key exists and has appropriate protection applied."""
    logger = AuditLogger(audit_dir=tmp_path)
    key_file = tmp_path / ".audit_hmac.key"
    assert key_file.exists()
    assert len(logger.hmac_key) == 32

    if os.name == "nt":
        import win32security
        sd = win32security.GetFileSecurity(
            str(key_file),
            win32security.DACL_SECURITY_INFORMATION,
        )
        dacl = sd.GetSecurityDescriptorDacl()
        assert dacl is not None
        assert dacl.GetAceCount() >= 1
    else:
        mode = key_file.stat().st_mode & 0o777
        assert mode == 0o600


def test_apply_owner_only_dacl_mocked(tmp_path):
    """Asserts apply_owner_only_dacl calls win32security on Windows or handles errors gracefully."""
    test_file = tmp_path / "test_sec.txt"
    test_file.touch()

    # Calling apply_owner_only_dacl should never raise even if mocked or real
    apply_owner_only_dacl(test_file)

    with patch("os.name", "nt"), patch.dict("sys.modules", {"win32api": MagicMock(), "win32security": MagicMock(), "ntsecuritycon": MagicMock()}):
        apply_owner_only_dacl(test_file)


def test_webhook_mirror_sink_on_success_callback(tmp_path):
    """Asserts on_success callback fires upon successful HTTP 2xx delivery."""
    hmac_key = secrets.token_bytes(32)
    entry = AuditEntry.create(
        index=10,
        timestamp="2026-08-31T12:00:00Z",
        event_type="success_event",
        actor="system",
        tier=None,
        details={"status": "ok"},
        prev_hash=GENESIS_HASH,
        hmac_key=hmac_key,
    )

    success_entries = []

    def on_succ(ent):
        success_entries.append(ent.index)

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        sink = WebhookMirrorSink(
            "https://mirror.internal/events",
            on_success=on_succ,
        )
        sink.emit(entry)
        sink.flush()
        sink.close()

    assert len(success_entries) == 1
    assert success_entries[0] == 10


def test_tail_truncation_detected_on_startup(tmp_path):
    """Asserts that removing the last line from audit.jsonl triggers ChainIntegrityError on startup."""
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        mirror_sink = WebhookMirrorSink("https://mirror.internal/events")
        logger = AuditLogger(audit_dir=tmp_path, sinks=[mirror_sink], verify_on_startup=False)

        for i in range(5):
            logger.log_event(f"event_{i}")

        mirror_sink.flush()
        mirror_sink.close()

    # Verify mirror state file has last_confirmed_mirrored_index == 4
    state_file = tmp_path / ".audit_mirror_state.json"
    assert state_file.exists()
    with open(state_file, "r", encoding="utf-8") as f:
        state_data = json.load(f)
    assert state_data.get("last_confirmed_mirrored_index") == 4

    # Remove the last line from audit.jsonl (truncation)
    with open(logger.log_file, "r", encoding="utf-8") as f:
        lines = [line for line in f if line.strip()]
    assert len(lines) == 5

    with open(logger.log_file, "w", encoding="utf-8") as f:
        f.writelines(lines[:-1])

    # Restart AuditLogger with verify_on_startup=True
    mirror_sink2 = WebhookMirrorSink("https://mirror.internal/events")
    try:
        with pytest.raises(ChainIntegrityError, match="Local audit log truncated|mirror confirmed index 4"):
            AuditLogger(audit_dir=tmp_path, sinks=[mirror_sink2], verify_on_startup=True)
    finally:
        mirror_sink2.close()


def test_full_file_deletion_detected_on_startup(tmp_path):
    """Asserts that deleting audit.jsonl entirely triggers ChainIntegrityError on startup if mirror state exists."""
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        mirror_sink = WebhookMirrorSink("https://mirror.internal/events")
        logger = AuditLogger(audit_dir=tmp_path, sinks=[mirror_sink], verify_on_startup=False)

        for i in range(3):
            logger.log_event(f"event_{i}")

        mirror_sink.flush()
        mirror_sink.close()

    # Delete audit.jsonl entirely
    logger.log_file.unlink()

    # Restart AuditLogger with verify_on_startup=True
    mirror_sink2 = WebhookMirrorSink("https://mirror.internal/events")
    try:
        with pytest.raises(ChainIntegrityError, match="Local audit log truncated|mirror confirmed index 2"):
            AuditLogger(audit_dir=tmp_path, sinks=[mirror_sink2], verify_on_startup=True)
    finally:
        mirror_sink2.close()


def test_mirror_failure_self_logs_and_preserves_callbacks(tmp_path):
    """Asserts mirror failure appends audit_mirror_failed to chain and invokes user on_failure callback."""
    user_failures = []
    user_successes = []

    def on_fail(ent, exc):
        user_failures.append((ent.index, str(exc)))

    def on_succ(ent):
        user_successes.append(ent.index)

    mirror_sink = WebhookMirrorSink(
        "https://failing.mirror/events",
        max_retries=1,
        on_failure=on_fail,
        on_success=on_succ,
    )

    with patch("urllib.request.urlopen", side_effect=RuntimeError("Connection refused")):
        logger = AuditLogger(audit_dir=tmp_path, sinks=[mirror_sink], verify_on_startup=False)
        logger.log_event("action_that_fails_mirror", actor="alice", details={"foo": "bar"})

        mirror_sink.flush()
        mirror_sink.close()

    # 1. User on_failure callback was preserved and called
    assert len(user_failures) >= 1
    assert user_failures[0][0] == 0
    assert "Connection refused" in user_failures[0][1]
    assert len(user_successes) == 0

    # 2. Local audit chain contains the original event AND the audit_mirror_failed event
    with open(logger.log_file, "r", encoding="utf-8") as f:
        lines = [json.loads(line) for line in f if line.strip()]

    assert len(lines) >= 2
    assert lines[0]["event_type"] == "action_that_fails_mirror"
    assert lines[1]["event_type"] == "audit_mirror_failed"
    assert lines[1]["actor"] == "system"
    assert lines[1]["details"]["entry_index"] == 0
    assert "Connection refused" in lines[1]["details"]["error"]

    # 3. Local chain is cryptographically valid
    valid, count, err = AuditLogger.verify_chain(logger.log_file, logger.hmac_key)
    assert valid is True
    assert count == len(lines)
    assert err is None


def test_mirror_success_preserves_user_callback(tmp_path):
    """Asserts mirror success invokes user on_success callback while also updating mirror state."""
    user_successes = []

    def on_succ(ent):
        user_successes.append(ent.index)

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    mirror_sink = WebhookMirrorSink(
        "https://success.mirror/events",
        on_success=on_succ,
    )

    with patch("urllib.request.urlopen", return_value=mock_resp):
        logger = AuditLogger(audit_dir=tmp_path, sinks=[mirror_sink], verify_on_startup=False)
        logger.log_event("evt_succ")

        mirror_sink.flush()
        mirror_sink.close()

    assert len(user_successes) == 1
    assert user_successes[0] == 0
    assert logger._read_mirror_state() == 0


# ============================================================================
# 8. Key Rotation Tests
# ============================================================================

def test_audit_hmac_key_rotation_end_to_end(tmp_path):
    """
    Validates that:
    1. Entries signed under key v1 and key v2 coexist in a single hash chain.
    2. verify_chain() validates all records correctly using historical key lookup.
    3. Tampering with a v1-signed entry is still cryptographically detected.
    4. The rotation event itself is logged and signed under key v2.
    """
    logger = AuditLogger(audit_dir=tmp_path, verify_on_startup=False)

    # 1. Log entries under initial key (v1)
    e0 = logger.log_event("login_attempt", actor="alice", details={"ip": "10.0.0.1"})
    e1 = logger.log_event("access_granted", actor="alice", details={"resource": "vault"})
    assert e0.key_version == 1
    assert e1.key_version == 1

    v1_key = logger.hmac_key
    assert logger.current_key_version == 1

    # 2. Rotate HMAC key
    new_version = logger.rotate_hmac_key(actor="secops_admin")
    assert new_version == 2
    assert logger.current_key_version == 2
    assert logger.hmac_key != v1_key

    # 3. Log entries under new key (v2)
    e3 = logger.log_event("secret_read", actor="alice", details={"secret": "API_KEY"})
    assert e3.key_version == 2

    # Verify key files on disk
    v1_key_file = tmp_path / ".audit_hmac_v1.key"
    v2_key_file = tmp_path / ".audit_hmac_v2.key"
    assert v1_key_file.exists()
    assert v2_key_file.exists()
    assert v1_key_file.read_bytes() == v1_key
    assert v2_key_file.read_bytes() == logger.hmac_key

    # 4. verify_chain end-to-end with loaded keys
    is_valid, count, err = AuditLogger.verify_chain(logger.log_file, logger.hmac_keys)
    assert is_valid is True
    assert count == 4  # e0, e1, rotation event (e2), e3
    assert err is None

    # 5. verify_chain by passing directory path
    is_valid, count, err = AuditLogger.verify_chain(logger.log_file, tmp_path)
    assert is_valid is True
    assert count == 4
    assert err is None

    # 6. Tampering with v1-signed entry breaks verification
    with open(logger.log_file, "r", encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]

    tampered_lines = list(lines)
    tampered_lines[1]["details"]["resource"] = "tampered_resource"
    tampered_file = tmp_path / "tampered_audit.jsonl"
    with open(tampered_file, "w", encoding="utf-8") as f:
        for entry_dict in tampered_lines:
            f.write(json.dumps(entry_dict) + "\n")

    is_valid, count, err = AuditLogger.verify_chain(tampered_file, logger.hmac_keys)
    assert is_valid is False
    assert "Invalid HMAC signature" in err or "Broken hash chain" in err


def test_audit_key_rotation_preserves_old_key_files(tmp_path):
    """
    Confirms multiple rotations retain all historical key files without overwriting or deletion.
    """
    logger = AuditLogger(audit_dir=tmp_path, verify_on_startup=False)
    assert logger.current_key_version == 1

    v1_key = (tmp_path / ".audit_hmac_v1.key").read_bytes()

    # Rotate to v2
    logger.rotate_hmac_key(actor="admin1")
    assert logger.current_key_version == 2
    v2_key = (tmp_path / ".audit_hmac_v2.key").read_bytes()

    # Rotate to v3
    logger.rotate_hmac_key(actor="admin2")
    assert logger.current_key_version == 3
    v3_key = (tmp_path / ".audit_hmac_v3.key").read_bytes()

    assert v1_key != v2_key != v3_key
    assert len(v1_key) == 32 and len(v2_key) == 32 and len(v3_key) == 32

    # Check that reload loads all 3 versions
    loaded_keys = AuditLogger.load_hmac_keys_from_dir(tmp_path)
    assert len(loaded_keys) == 3
    assert loaded_keys[1] == v1_key
    assert loaded_keys[2] == v2_key
    assert loaded_keys[3] == v3_key


def test_audit_chain_missing_historical_key_fails_verification(tmp_path):
    """
    Confirms verify_chain reports missing key error when an entry requires an unknown key_version.
    """
    logger = AuditLogger(audit_dir=tmp_path, verify_on_startup=False)
    logger.log_event("event_v1", actor="user")
    logger.rotate_hmac_key(actor="admin")
    logger.log_event("event_v2", actor="user")

    # Pass only key version 2 (missing version 1)
    only_v2_keys = {2: logger.hmac_keys[2]}
    is_valid, count, err = AuditLogger.verify_chain(logger.log_file, only_v2_keys)
    assert is_valid is False
    assert "Missing HMAC key for key_version 1" in err


# ============================================================================
# 9. Mirror State Protection & Fresh vs. Tampered Distinction Tests
# ============================================================================

def test_mirror_state_dacl_protection(tmp_path):
    """Proves apply_owner_only_dacl is applied to both .audit_mirror_state.json and .audit_mirror_initialized."""
    dacl_calls = []

    def mock_dacl(p):
        dacl_calls.append(Path(p).name)
        return True

    with patch("sentinel.audit.chain.apply_owner_only_dacl", side_effect=mock_dacl):
        logger = AuditLogger(audit_dir=tmp_path, verify_on_startup=False)
        logger._write_mirror_state(5)

    assert ".audit_mirror_state.json" in dacl_calls
    assert ".audit_mirror_initialized" in dacl_calls


def test_mirror_state_file_deletion_detected_as_tampering(tmp_path):
    """
    Asserts that if .audit_mirror_state.json is deleted after mirroring was active
    (while .audit_mirror_initialized remains), startup verification flags tampering.
    """
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        mirror_sink = WebhookMirrorSink("https://mirror.internal/events")
        logger = AuditLogger(audit_dir=tmp_path, sinks=[mirror_sink], verify_on_startup=False)

        for i in range(3):
            logger.log_event(f"event_{i}")

        mirror_sink.flush()
        mirror_sink.close()

    # Mirror state should exist and be index 2
    state_file = tmp_path / ".audit_mirror_state.json"
    marker_file = tmp_path / ".audit_mirror_initialized"
    assert state_file.exists()
    assert marker_file.exists()

    # Simulate attacker deleting .audit_mirror_state.json to hide previous sync index
    state_file.unlink()

    # Restart AuditLogger with verify_on_startup=True
    mirror_sink2 = WebhookMirrorSink("https://mirror.internal/events")
    try:
        with pytest.raises(ChainIntegrityError, match="Mirror state file .* missing after mirror initialization"):
            AuditLogger(audit_dir=tmp_path, sinks=[mirror_sink2], verify_on_startup=True)
    finally:
        mirror_sink2.close()


def test_fresh_install_no_mirror_no_tamper_alarm(tmp_path):
    """
    Confirms a fresh install where mirroring was never active does NOT trigger
    any tamper detection at startup.
    """
    logger = AuditLogger(audit_dir=tmp_path, verify_on_startup=True)
    assert logger.log_file.exists()
    assert logger._read_mirror_state() == -1


def test_corrupted_mirror_state_fails_loud(tmp_path):
    """
    Confirms that a malformed/corrupted .audit_mirror_state.json raises ChainIntegrityError
    rather than silently defaulting to a permissive index.
    """
    state_file = tmp_path / ".audit_mirror_state.json"
    state_file.write_text("CORRUPTED_NOT_JSON!#$%", encoding="utf-8")

    with pytest.raises(ChainIntegrityError, match="Audit mirror state file corrupted"):
        AuditLogger(audit_dir=tmp_path, verify_on_startup=True)


def test_mid_run_mirror_state_deletion_fails_closed_and_logs_audit_tamper(tmp_path):
    """
    Simulates mid-run tampering: service is actively running, state file previously confirmed,
    attacker deletes .audit_mirror_state.json while service runs.
    Confirms:
    1. on_success catches ChainIntegrityError without swallowing/auto-healing.
    2. .audit_mirror_state.json is NOT recreated/healed.
    3. audit_mirror_state_tampered is logged into the audit chain.
    4. AuditLogger._mirror_tampered flag is set to True.
    """
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        sink = WebhookMirrorSink("https://mirror.internal/events")
        logger = AuditLogger(audit_dir=tmp_path, sinks=[sink], verify_on_startup=False)

        # 1. Normal sync
        logger.log_event("event_0")
        sink.flush()

        state_file = tmp_path / ".audit_mirror_state.json"
        assert state_file.exists()
        assert logger._read_mirror_state() == 0

        # 2. Mid-run attack: delete .audit_mirror_state.json
        state_file.unlink()
        assert not state_file.exists()

        # 3. Next mirror delivery fires on_success
        logger.log_event("event_1")
        sink.flush()
        sink.close()

    # 4. Assert fail-closed: state file was NOT recreated/healed
    assert not state_file.exists()
    assert logger._mirror_tampered is True

    # 5. Assert audit_mirror_state_tampered event was recorded
    with open(logger.log_file, "r", encoding="utf-8") as f:
        events = [json.loads(line)["event_type"] for line in f if line.strip()]

    assert "audit_mirror_state_tampered" in events


def test_transient_io_error_during_read_mirror_state_does_not_flag_tampering(tmp_path):
    """
    Confirms that transient OS I/O errors during _read_mirror_state (e.g. PermissionError/sharing violation)
    propagate directly as OSError (not wrapped as ChainIntegrityError), do not set _mirror_tampered,
    and do not log an audit_mirror_state_tampered event.
    Exercises the real _read_mirror_state() function.
    """
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        sink = WebhookMirrorSink("https://mirror.internal/events")
        logger = AuditLogger(audit_dir=tmp_path, sinks=[sink], verify_on_startup=False)

        # 1. Normal first event writes valid mirror state
        logger.log_event("event_0")
        sink.flush()

        state_file = tmp_path / ".audit_mirror_state.json"
        assert state_file.exists()

        # 2. Confirm real _read_mirror_state() directly raises PermissionError (raw OSError) when open() fails
        orig_open = open
        def faulty_open(file, *args, **kwargs):
            if Path(file).name == ".audit_mirror_state.json" and "r" in args:
                raise PermissionError("WinError 32: The process cannot access the file because it is being used by another process")
            return orig_open(file, *args, **kwargs)

        with patch("builtins.open", side_effect=faulty_open):
            with pytest.raises(PermissionError):
                logger._read_mirror_state()

            # 3. Trigger mirror delivery with the transient open error active
            logger.log_event("event_1")
            sink.flush()

        sink.close()

    # 4. Confirm transient failure did not trigger tamper alarm or tamper flag
    assert logger._mirror_tampered is False
    with open(logger.log_file, "r", encoding="utf-8") as f:
        events = [json.loads(line)["event_type"] for line in f if line.strip()]
    assert "audit_mirror_state_tampered" not in events


def test_content_corruption_in_read_mirror_state_raises_chain_integrity_error(tmp_path):
    """
    Confirms that real _read_mirror_state() raises ChainIntegrityError across various
    content-corruption schemas: malformed JSON, missing key, non-int value, and non-dict root.
    """
    logger = AuditLogger(audit_dir=tmp_path, verify_on_startup=False)
    state_file = tmp_path / ".audit_mirror_state.json"

    # Case 1: Malformed JSON syntax
    state_file.write_text('{"last_confirmed_mirrored_index": ', encoding="utf-8")
    with pytest.raises(ChainIntegrityError, match="Audit mirror state file corrupted"):
        logger._read_mirror_state()

    # Case 2: Missing required key
    state_file.write_text('{"wrong_key": 42}', encoding="utf-8")
    with pytest.raises(ChainIntegrityError, match="Audit mirror state file corrupted"):
        logger._read_mirror_state()

    # Case 3: Non-integer value
    state_file.write_text('{"last_confirmed_mirrored_index": "invalid_not_number"}', encoding="utf-8")
    with pytest.raises(ChainIntegrityError, match="Audit mirror state file corrupted"):
        logger._read_mirror_state()

    # Case 4: Non-dict payload
    state_file.write_text('[1, 2, 3]', encoding="utf-8")
    with pytest.raises(ChainIntegrityError, match="Audit mirror state file corrupted"):
        logger._read_mirror_state()


def test_transient_io_recovery_advances_mirror_state_on_subsequent_success(tmp_path):
    """
    Confirms that when a transient I/O error occurs during one delivery,
    the system does not get stuck: the next successful mirror delivery advances state normally.
    """
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        sink = WebhookMirrorSink("https://mirror.internal/events")
        logger = AuditLogger(audit_dir=tmp_path, sinks=[sink], verify_on_startup=False)

        # 1. First event succeeds -> index 0
        logger.log_event("event_0")
        sink.flush()
        assert logger._read_mirror_state() == 0

        # 2. Second event encounters transient I/O error during on_success
        orig_open = open
        def faulty_open(file, *args, **kwargs):
            if Path(file).name == ".audit_mirror_state.json" and "r" in args:
                raise OSError("Sharing violation")
            return orig_open(file, *args, **kwargs)

        with patch("builtins.open", side_effect=faulty_open):
            logger.log_event("event_1")
            sink.flush()

        # State remains at 0, not tampered
        assert logger._mirror_tampered is False
        assert logger._read_mirror_state() == 0

        # 3. Third event arrives with no I/O error -> advances state to index 2
        logger.log_event("event_2")
        sink.flush()
        assert logger._read_mirror_state() == 2

        sink.close()


def test_fail_closed_prevents_further_mirror_writes_after_tamper(tmp_path):
    """
    Confirms that once _mirror_tampered is True, subsequent mirror successes do not
    attempt to write or heal .audit_mirror_state.json.
    """
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        sink = WebhookMirrorSink("https://mirror.internal/events")
        logger = AuditLogger(audit_dir=tmp_path, sinks=[sink], verify_on_startup=False)
        logger._mirror_tampered = True

        state_file = tmp_path / ".audit_mirror_state.json"
        if state_file.exists():
            state_file.unlink()

        logger.log_event("event_after_tamper")
        sink.flush()
        sink.close()

    assert not state_file.exists()




