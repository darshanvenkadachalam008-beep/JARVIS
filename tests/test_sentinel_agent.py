"""Unit tests for SentinelAgent state machine, ordering invariants, and de-escalation."""
import pytest
from unittest.mock import patch, MagicMock, call
from pathlib import Path

from agents.sentinel_agent import SentinelAgent, SentinelState
from sentinel.audit.chain import AuditLogger


@pytest.fixture
def mock_auth_engine():
    auth = MagicMock()
    # Mock primary PIN verification: only "correct_1234" succeeds
    def mock_auth_primary(pin: str) -> bool:
        return pin == "correct_1234"

    # Mock recovery PIN verification: only "recovery_5678" succeeds
    def mock_auth_recovery(pin: str) -> bool:
        return pin == "recovery_5678"

    auth.authenticate_primary.side_effect = mock_auth_primary
    auth.authenticate_recovery.side_effect = mock_auth_recovery
    auth.is_initialized.return_value = True
    return auth


@pytest.fixture
def real_audit_logger(tmp_path):
    # Use real AuditLogger on tmp_path to verify cryptographic hash chain integrity
    logger = AuditLogger(audit_dir=tmp_path / "audit", hmac_key=b"pytest_sentinel_secret_key_32b!!")
    return logger


def test_initial_state_normal(mock_auth_engine, real_audit_logger):
    """Confirms SentinelAgent initializes in NORMAL state."""
    agent = SentinelAgent(auth_engine=mock_auth_engine, audit_logger=real_audit_logger)
    assert agent.defense_state == SentinelState.NORMAL
    assert agent.agent_name == "Sentinel"


def test_normal_to_elevated_on_friction_event(mock_auth_engine, real_audit_logger):
    """Confirms auth friction elevation moves state from NORMAL to ELEVATED."""
    agent = SentinelAgent(auth_engine=mock_auth_engine, audit_logger=real_audit_logger)

    agent.on_event("auth_anomaly_friction_elevated", {"score": 0.85, "reasons": ["Unrecognized subnet"]})
    assert agent.defense_state == SentinelState.ELEVATED


def test_transition_to_defense_on_face_failure_cluster(mock_auth_engine, real_audit_logger):
    """Confirms face failure clustering elevates state directly to DEFENSE."""
    agent = SentinelAgent(auth_engine=mock_auth_engine, audit_logger=real_audit_logger)

    with patch("agents.sentinel_agent.capture_evidence", return_value=Path("/tmp/ev")), \
         patch("agents.sentinel_agent.alert_owner"), \
         patch("agents.sentinel_agent.lock_session"):

        agent.on_event("face_failure_cluster_detected", {"cluster_count": 3, "window_secs": 180.0})
        assert agent.defense_state == SentinelState.DEFENSE


def test_defense_execution_ordering_invariant(mock_auth_engine, real_audit_logger):
    """
    CRITICAL INVARIANT TEST:
    Asserts evidence capture runs and completes BEFORE alert dispatch,
    and alert dispatch runs BEFORE OS lock.
    """
    call_order = []

    def mock_capture(**kwargs):
        call_order.append("capture_evidence")
        return Path("/tmp/ev_test")

    def mock_alert(*args, **kwargs):
        call_order.append("alert_owner")
        return True

    def mock_lock():
        call_order.append("lock_session")
        return True

    agent = SentinelAgent(auth_engine=mock_auth_engine, audit_logger=real_audit_logger)

    with patch("agents.sentinel_agent.capture_evidence", side_effect=mock_capture), \
         patch("agents.sentinel_agent.alert_owner", side_effect=mock_alert), \
         patch("agents.sentinel_agent.lock_session", side_effect=mock_lock):

        agent.transition_to(SentinelState.DEFENSE, reason="Ordering verification test")

    assert call_order == ["capture_evidence", "alert_owner", "lock_session"], (
        f"Incorrect execution order: {call_order}"
    )


def test_lockdown_execution_ordering_invariant(mock_auth_engine, real_audit_logger):
    """
    CRITICAL INVARIANT TEST:
    In LOCKDOWN, evidence must be captured FIRST, alerts dispatched SECOND,
    tokens revoked THIRD, session locked FOURTH, and network isolated LAST.
    """
    call_order = []

    def mock_capture(**kwargs):
        call_order.append("capture_evidence")
        return Path("/tmp/ev_test")

    def mock_alert(*args, **kwargs):
        call_order.append("alert_owner")
        return True

    def mock_revoke(*args, **kwargs):
        call_order.append("revoke_active_tokens")
        return 2

    def mock_lock():
        call_order.append("lock_session")
        return True

    def mock_isolate(*args, **kwargs):
        call_order.append("network_isolate")
        return True

    agent = SentinelAgent(auth_engine=mock_auth_engine, audit_logger=real_audit_logger)

    with patch("agents.sentinel_agent.capture_evidence", side_effect=mock_capture), \
         patch("agents.sentinel_agent.alert_owner", side_effect=mock_alert), \
         patch("agents.sentinel_agent.revoke_active_tokens", side_effect=mock_revoke), \
         patch("agents.sentinel_agent.lock_session", side_effect=mock_lock), \
         patch("agents.sentinel_agent.network_isolate", side_effect=mock_isolate):

        agent.transition_to(SentinelState.LOCKDOWN, reason="Lockdown ordering test")

    expected_order = [
        "capture_evidence",
        "alert_owner",
        "revoke_active_tokens",
        "lock_session",
        "network_isolate",
    ]
    assert call_order == expected_order, f"Incorrect lockdown order: {call_order}"


def test_deescalate_strictly_requires_authenticated_primary_pin(mock_auth_engine, real_audit_logger):
    """
    Confirms de-escalation cannot be automatic:
    Wrong PIN leaves state unchanged; correct PIN steps down exactly one level per call.
    """
    agent = SentinelAgent(auth_engine=mock_auth_engine, audit_logger=real_audit_logger)

    with patch("agents.sentinel_agent.capture_evidence", return_value=Path("/tmp/ev")), \
         patch("agents.sentinel_agent.alert_owner"), \
         patch("agents.sentinel_agent.lock_session"):

        # Escalate directly to DEFENSE
        agent.transition_to(SentinelState.DEFENSE, reason="Tamper simulation")
        assert agent.defense_state == SentinelState.DEFENSE

        # 1. Incorrect PIN: de-escalation must FAIL and state must remain DEFENSE
        success_bad = agent.deescalate("wrong_pin")
        assert success_bad is False
        assert agent.defense_state == SentinelState.DEFENSE

        # 2. Correct Primary PIN: steps down DEFENSE -> ELEVATED
        success_good_1 = agent.deescalate("correct_1234")
        assert success_good_1 is True
        assert agent.defense_state == SentinelState.ELEVATED

        # 3. Correct Primary PIN: steps down ELEVATED -> NORMAL
        success_good_2 = agent.deescalate("correct_1234")
        assert success_good_2 is True
        assert agent.defense_state == SentinelState.NORMAL


def test_deescalate_via_recovery_pin(mock_auth_engine, real_audit_logger):
    """Confirms de-escalation using recovery PIN when recovery=True."""
    agent = SentinelAgent(auth_engine=mock_auth_engine, audit_logger=real_audit_logger)

    with patch("agents.sentinel_agent.capture_evidence", return_value=Path("/tmp/ev")), \
         patch("agents.sentinel_agent.alert_owner"), \
         patch("agents.sentinel_agent.lock_session"):

        agent.transition_to(SentinelState.DEFENSE, reason="Lockout test")
        assert agent.defense_state == SentinelState.DEFENSE

        # Bad recovery PIN fails
        assert agent.deescalate("bad_rec", recovery=True) is False
        assert agent.defense_state == SentinelState.DEFENSE

        # Valid recovery PIN succeeds
        assert agent.deescalate("recovery_5678", recovery=True) is True
        assert agent.defense_state == SentinelState.ELEVATED


def test_audit_chain_integrity_preserved_after_defense_lifecycle(mock_auth_engine, real_audit_logger):
    """
    Cryptographic verification:
    Ensures that state escalations and de-escalations create valid, unbroken HMAC hash chain entries.
    """
    agent = SentinelAgent(auth_engine=mock_auth_engine, audit_logger=real_audit_logger)

    with patch("agents.sentinel_agent.capture_evidence", return_value=Path("/tmp/ev")), \
         patch("agents.sentinel_agent.alert_owner"), \
         patch("agents.sentinel_agent.lock_session"):

        agent.transition_to(SentinelState.ELEVATED, reason="Friction rising")
        agent.transition_to(SentinelState.DEFENSE, reason="Face cluster detected")
        agent.deescalate("correct_1234")
        agent.deescalate("correct_1234")

    # Verify cryptographic audit chain integrity
    is_valid, count, err = real_audit_logger.verify()
    assert is_valid is True
    assert count >= 4


def test_tamper_event_triggers_immediate_defense(mock_auth_engine, real_audit_logger):
    """Confirms audit tampering callback triggers immediate defense state."""
    agent = SentinelAgent(auth_engine=mock_auth_engine, audit_logger=real_audit_logger)

    with patch("agents.sentinel_agent.capture_evidence", return_value=Path("/tmp/ev")), \
         patch("agents.sentinel_agent.alert_owner"), \
         patch("agents.sentinel_agent.lock_session"):

        agent.on_event("audit_chain_tamper_detected", {"error": "HMAC mismatch at index 4"})
        assert agent.defense_state == SentinelState.DEFENSE


def test_action_failure_does_not_abort_state_transition(mock_auth_engine, real_audit_logger):
    """
    REGRESSION TEST:
    Forces capture_evidence() to raise an exception.
    Asserts that:
    1. The defense state still transitions to DEFENSE (never fail open).
    2. An audit event 'sentinel_action_failed' is logged recording the failure.
    3. The top-level 'sentinel_defense_mode_entered' audit event is logged.
    4. Cryptographic audit chain remains valid.
    """
    agent = SentinelAgent(auth_engine=mock_auth_engine, audit_logger=real_audit_logger)

    with patch("agents.sentinel_agent.capture_evidence", side_effect=RuntimeError("Disk full during evidence capture")), \
         patch("agents.sentinel_agent.alert_owner") as mock_alert, \
         patch("agents.sentinel_agent.lock_session") as mock_lock:

        success = agent.transition_to(SentinelState.DEFENSE, reason="Intruder activity detected")

    assert success is True
    assert agent.defense_state == SentinelState.DEFENSE
    mock_alert.assert_called_once_with("Sentinel DEFENSE engaged: Intruder activity detected", evidence_path=None)
    mock_lock.assert_called_once()

    # Verify audit entries
    entries = real_audit_logger.read_all()
    event_types = [e.event_type for e in entries]

    assert "sentinel_action_failed" in event_types
    assert "sentinel_defense_mode_entered" in event_types

    failure_entry = next(e for e in entries if e.event_type == "sentinel_action_failed")
    assert failure_entry.details["action"] == "capture_evidence"
    assert "Disk full" in failure_entry.details["error"]
    assert failure_entry.details["target_state"] == "DEFENSE"

    entered_entry = next(e for e in entries if e.event_type == "sentinel_defense_mode_entered")
    assert entered_entry.details["evidence_path"] is None
    assert "capture_evidence" in entered_entry.details["action_failures"]

    # Verify cryptographic integrity
    is_valid, count, _ = real_audit_logger.verify()
    assert is_valid is True
    assert count >= 2


def test_lockdown_multiple_action_failures_fail_secure(mock_auth_engine, real_audit_logger):
    """
    REGRESSION TEST:
    Forces multiple actions in LOCKDOWN (e.g. alert_owner and network_isolate) to fail.
    Asserts state is still LOCKDOWN and all failures are audited without crashing.
    """
    agent = SentinelAgent(auth_engine=mock_auth_engine, audit_logger=real_audit_logger)

    with patch("agents.sentinel_agent.capture_evidence", return_value=Path("/tmp/ev_lockdown")), \
         patch("agents.sentinel_agent.alert_owner", side_effect=ConnectionError("Network unavailable")), \
         patch("agents.sentinel_agent.revoke_active_tokens", return_value=3), \
         patch("agents.sentinel_agent.lock_session"), \
         patch("agents.sentinel_agent.network_isolate", side_effect=PermissionError("UAC required")):

        success = agent.transition_to(SentinelState.LOCKDOWN, reason="Cluster attack detected")

    assert success is True
    assert agent.defense_state == SentinelState.LOCKDOWN

    entries = real_audit_logger.read_all()
    failure_entries = [e for e in entries if e.event_type == "sentinel_action_failed"]
    failed_actions = [e.details["action"] for e in failure_entries]

    assert "alert_owner" in failed_actions
    assert "network_isolate" in failed_actions

    lockdown_entry = next(e for e in entries if e.event_type == "sentinel_lockdown_entered")
    assert lockdown_entry.details["revoked_tokens"] == 3
    assert lockdown_entry.details["network_isolated"] is False
    assert "alert_owner" in lockdown_entry.details["action_failures"]
    assert "network_isolate" in lockdown_entry.details["action_failures"]

    is_valid, _, _ = real_audit_logger.verify()
    assert is_valid is True


def test_sentinel_agent_shares_singleton_instances(tmp_path):
    """
    REGRESSION TEST:
    Asserts SentinelAgent's audit_logger and auth_engine are object-identical (is)
    to the app's shared singletons, preventing duplicate file writers.
    """
    from sentinel.auth.engine import AuthEngine
    from sentinel.audit.chain import AuditLogger
    from agents.agent_manager import AgentManager

    # Reset singletons for clean test isolation
    AuthEngine.reset_instance()
    AuditLogger.reset_instance()

    try:
        # Pre-initialize singletons with custom tmp directory
        shared_audit = AuditLogger.get_instance(
            audit_dir=tmp_path / "shared_audit",
            hmac_key=b"shared_key_32_bytes_test_12345678",
            verify_on_startup=False,
        )
        shared_auth = AuthEngine.get_instance(auth_dir=tmp_path / "shared_auth")

        # 1. Direct instantiation without parameters uses singletons
        agent = SentinelAgent()
        assert agent.audit_logger is shared_audit, "SentinelAgent audit_logger must be object-identical to shared singleton"
        assert agent.auth_engine is shared_auth, "SentinelAgent auth_engine must be object-identical to shared singleton"

        # 2. AgentManager registers SentinelAgent with identical singletons
        manager = AgentManager()
        sentinel_in_mgr = manager.get_agent("Sentinel")
        assert sentinel_in_mgr is not None
        assert sentinel_in_mgr.audit_logger is shared_audit, "AgentManager Sentinel must share singleton audit_logger"
        assert sentinel_in_mgr.auth_engine is shared_auth, "AgentManager Sentinel must share singleton auth_engine"

    finally:
        AuthEngine.reset_instance()
        AuditLogger.reset_instance()

