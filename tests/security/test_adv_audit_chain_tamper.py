"""
tests/security/test_adv_audit_chain_tamper.py
==============================================
Verifies periodic and mid-run audit log tampering detection and security alert dispatch.
"""
import time
import pytest
from pathlib import Path
from sentinel.audit.chain import AuditLogger, ChainIntegrityError
from sentinel.audit.sinks import WebhookMirrorSink
from core.unified_security_alert import TRIGGER_TITLES


def test_audit_chain_tampered_trigger_registered():
    """Asserts audit_chain_tampered is properly registered in TRIGGER_TITLES."""
    assert "audit_chain_tampered" in TRIGGER_TITLES
    assert "Tampering" in TRIGGER_TITLES["audit_chain_tampered"]


def test_periodic_verifier_detects_log_corruption(tmp_path, monkeypatch):
    """Verifies periodic verifier thread detects tampered log file and dispatches alert."""
    dispatched = []

    def mock_dispatch(trigger_type, actor="system", details=None, **kwargs):
        dispatched.append((trigger_type, actor, details))
        return {"trigger_type": trigger_type, "actor": actor, "details": details}

    import core.unified_security_alert
    monkeypatch.setattr(core.unified_security_alert, "dispatch_security_alert", mock_dispatch)

    audit_dir = tmp_path / "audit"
    logger = AuditLogger(audit_dir=audit_dir, hmac_key=b"test_hmac_secret_32_bytes_long_1", verify_on_startup=False)

    # Log 3 events
    logger.log_event("action1", actor="alice", details={"x": 1})
    logger.log_event("action2", actor="bob", details={"x": 2})
    logger.log_event("action3", actor="carol", details={"x": 3})

    # Tamper with the middle entry in the log file
    log_file = audit_dir / "audit.jsonl"
    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    # Corrupt event payload of line 1 (LocalFileSink uses compact separators)
    lines[1] = lines[1].replace('"x":2', '"x":9999')
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Start periodic verifier with rapid 0.05s interval
    t = logger.start_periodic_verifier(interval_seconds=0.05)
    try:
        time.sleep(0.3)
        assert len(dispatched) > 0
        trigger, actor, details = dispatched[0]
        assert trigger == "audit_chain_tampered"
        assert actor == "audit_sentinel"
        assert details["source"] == "periodic_verifier"
    finally:
        logger.stop_periodic_verifier()


def test_mid_run_sink_tamper_alert_dispatch(tmp_path, monkeypatch):
    """Verifies that mid-run mirror tampering dispatches audit_chain_tampered alert."""
    dispatched = []

    def mock_dispatch(trigger_type, actor="system", details=None, **kwargs):
        dispatched.append((trigger_type, actor, details))
        return {"trigger_type": trigger_type, "actor": actor, "details": details}

    import core.unified_security_alert
    monkeypatch.setattr(core.unified_security_alert, "dispatch_security_alert", mock_dispatch)

    audit_dir = tmp_path / "audit_sink"
    sink = WebhookMirrorSink(endpoint_url="http://127.0.0.1:9999/mirror", timeout_seconds=0.5)

    logger = AuditLogger(
        audit_dir=audit_dir,
        hmac_key=b"test_hmac_secret_32_bytes_long_1",
        sinks=[sink],
        verify_on_startup=False,
    )

    # Simulate tampered mirror state file
    state_file = audit_dir / ".audit_mirror_state.json"
    marker_file = audit_dir / ".audit_mirror_initialized"
    marker_file.write_text("initialized", encoding="utf-8")
    state_file.write_text("CORRUPTED_JSON_CONTENT", encoding="utf-8")

    # Create dummy entry to trigger sink on_success
    from sentinel.audit.models import AuditEntry
    dummy_entry = AuditEntry(
        index=0,
        timestamp="2026-09-07T00:00:00Z",
        event_type="test_event",
        actor="test",
        details={},
        prev_hash="0000000000000000000000000000000000000000000000000000000000000000",
        entry_hmac="dummy_hmac",
        key_version=1,
    )

    # When sink on_success runs, it should catch ChainIntegrityError and dispatch alert
    sink.on_success(dummy_entry)

    assert len(dispatched) > 0
    trigger, actor, details = dispatched[0]
    assert trigger == "audit_chain_tampered"
    assert actor == "audit_sentinel"
    assert details["source"] == "mid_run_mirror"
