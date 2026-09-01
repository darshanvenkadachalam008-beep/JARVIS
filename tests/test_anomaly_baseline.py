"""
tests/test_anomaly_baseline.py — Comprehensive Test Suite for Geofencing & Anomaly Baseline (C9)
================================================================================================
Validates:
1. Baseline calibration and normal-friction authorization for established patterns.
2. Anomaly detection for unusual hour + unrecognized network identity triggering elevated friction.
3. Concrete auth flow change: REVERSIBLE requires PIN; DESTRUCTIVE requires multi-factor step-up.
4. Fail-secure guarantee: Missing or corrupted baseline file fails toward MORE friction (score=1.0).
5. Audit trail: Every anomaly-triggered elevation emits a verifiable event with context.
6. Baseline rolling window updates and reset capabilities.
"""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from sentinel.anomaly.models import BaselineModel, AnomalyVerdict, NetworkProfile
from sentinel.anomaly.detector import AnomalyDetector, FRICTION_THRESHOLD
from sentinel.auth.engine import AuthEngine, UnauthorizedError, AuthorizationBlockedError
from sentinel.auth.models import AuthTier
from sentinel.auth.hasher import PinHasher


def test_baseline_missing_or_corrupted_fails_toward_more_friction(tmp_path):
    """
    Confirms that if the baseline file is missing, empty, or corrupted,
    the detector strictly fails closed with score=1.0 and elevated friction.
    """
    events = []
    detector = AnomalyDetector(auth_dir=tmp_path, event_sink=lambda k, d: events.append((k, d)))

    # Case 1: Missing baseline
    verdict = detector.evaluate(current_time=datetime(2026, 9, 1, 14, 0), network_id="wifi:Office")
    assert verdict.score == 1.0
    assert verdict.is_anomalous is True
    assert verdict.elevate_friction is True
    assert "baseline_missing" in verdict.reasons or "baseline_uncalibrated" in verdict.reasons
    assert len(events) == 1
    assert events[0][0] == "auth_anomaly_friction_elevated"

    # Case 2: Corrupted baseline
    corrupted_file = tmp_path / "anomaly_baseline.json"
    corrupted_file.write_text("{corrupted_json_content...", encoding="utf-8")

    verdict_corrupt = detector.evaluate(current_time=datetime(2026, 9, 1, 14, 0), network_id="wifi:Office")
    assert verdict_corrupt.score == 1.0
    assert verdict_corrupt.is_anomalous is True
    assert verdict_corrupt.elevate_friction is True


def test_normal_baseline_pattern_proceeds_at_normal_friction(tmp_path):
    """
    Establishes a baseline of 10 AM - 6 PM on 'wifi:HomeOffice' and verifies that
    a subsequent 2 PM access on 'wifi:HomeOffice' proceeds with low risk score and no friction elevation.
    """
    events = []
    detector = AnomalyDetector(auth_dir=tmp_path, event_sink=lambda k, d: events.append((k, d)))

    # Seed baseline with normal working hours (e.g. 10 AM, 12 PM, 2 PM, 4 PM)
    for hour in (10, 12, 14, 16):
        for day in range(5):
            detector.record_success(
                current_time=datetime(2026, 9, 1, hour, 0),
                network_id="wifi:HomeOffice",
                command_tier="READ_ONLY",
            )

    # Evaluate at 2 PM on HomeOffice
    verdict = detector.evaluate(
        current_time=datetime(2026, 9, 1, 14, 0),
        network_id="wifi:HomeOffice",
        command_tier="READ_ONLY",
    )

    assert verdict.score < FRICTION_THRESHOLD
    assert verdict.is_anomalous is False
    assert verdict.elevate_friction is False
    assert len(events) == 0  # No friction elevation events emitted


def test_anomalous_login_triggers_elevated_friction_and_concrete_auth_changes(tmp_path):
    """
    Tests that a 3 AM login on an unrecognized public Wi-Fi:
    1. Generates anomaly score >= threshold.
    2. Elevates REVERSIBLE tier to require PIN (which normally doesn't need PIN).
    3. Elevates DESTRUCTIVE tier to require both PIN and real validated physical presence challenge token.
    4. Strictly rejects invalid/garbage tokens.
    5. Succeeds when real generated token is provided.
    6. Confirms token is consumed on single-use (rejects reuse).
    7. Confirms anomalous success does NOT poison/normalize into baseline.
    8. Emits auth_anomaly_friction_elevated audit event.
    """
    audit_events = []
    auth_dir = tmp_path / "auth"

    engine = AuthEngine(
        auth_dir=auth_dir,
        event_sink=lambda k, d: audit_events.append((k, d)),
    )

    # Enroll user
    token = engine.generate_presence_challenge(print_to_console=False)
    engine.enroll(primary_pin="123456", recovery_pin="654321", presence_token=token)

    # Build established baseline (daytime office hours)
    for hour in (9, 11, 13, 15, 17):
        for _ in range(3):
            engine.anomaly_detector.record_success(
                current_time=datetime(2026, 9, 1, hour, 0),
                network_id="wifi:CorporateNet",
                command_tier="READ_ONLY",
            )

    anomalous_context = {
        "time": datetime(2026, 9, 1, 3, 0),  # 3 AM
        "network_id": "wifi:UnknownCoffeeShop",
    }

    # 1. READ_ONLY still passes (monitoring not broken)
    v_read = engine.check_authorization(AuthTier.READ_ONLY, context=anomalous_context)
    assert v_read.elevate_friction is True

    # 2. REVERSIBLE normally succeeds with no PIN; under anomaly it MUST fail without PIN
    with pytest.raises(UnauthorizedError, match="requires Primary PIN due to elevated anomaly risk"):
        engine.check_authorization(AuthTier.REVERSIBLE, pin=None, context=anomalous_context)

    # Providing correct PIN allows REVERSIBLE to succeed
    v_rev = engine.check_authorization(AuthTier.REVERSIBLE, pin="123456", context=anomalous_context)
    assert v_rev.is_anomalous is True

    # 3. DESTRUCTIVE with PIN only fails under anomaly (requires presence step-up)
    with pytest.raises(UnauthorizedError, match="requires multi-factor step-up verification"):
        engine.check_authorization(
            AuthTier.DESTRUCTIVE,
            pin="123456",
            context=anomalous_context,
            presence_token=None,
        )

    # 4. Providing invalid/garbage token fails verification
    with pytest.raises(UnauthorizedError, match="multi-factor step-up verification failed"):
        engine.check_authorization(
            AuthTier.DESTRUCTIVE,
            pin="123456",
            context=anomalous_context,
            presence_token="invalid_garbage_token_12345",
        )

    # 5. Generate a real physical presence step-up challenge token
    real_step_up_token = engine.generate_step_up_challenge(print_to_console=False)
    assert isinstance(real_step_up_token, str) and len(real_step_up_token) == 32

    # Providing valid PIN + real step-up token succeeds
    v_dest = engine.check_authorization(
        AuthTier.DESTRUCTIVE,
        pin="123456",
        context=anomalous_context,
        presence_token=real_step_up_token,
    )
    assert v_dest.is_anomalous is True

    # 6. Single-use enforcement: Attempting to reuse the same consumed step-up token must fail
    with pytest.raises(UnauthorizedError, match="multi-factor step-up verification failed"):
        engine.check_authorization(
            AuthTier.DESTRUCTIVE,
            pin="123456",
            context=anomalous_context,
            presence_token=real_step_up_token,
        )

    # 7. Baseline non-poisoning: Verify anomalous 3 AM / UnknownCoffeeShop was NOT recorded into baseline
    baseline, _ = engine.anomaly_detector._load_baseline_locked()
    assert "wifi:UnknownCoffeeShop" not in baseline.known_networks
    assert baseline.hourly_distribution.get("3", 0) == 0

    # 8. Verify audit event emission
    event_names = [e[0] for e in audit_events]
    assert "auth_anomaly_friction_elevated" in event_names
    elev_event = next(e for e in audit_events if e[0] == "auth_anomaly_friction_elevated")
    assert elev_event[1]["network_id"] == "wifi:UnknownCoffeeShop"
    assert elev_event[1]["hour"] == 3


def test_step_up_token_expired_is_rejected(tmp_path):
    """
    Confirms that an expired physical presence challenge token is rejected for DESTRUCTIVE step-up.
    """
    auth_dir = tmp_path / "auth"
    engine = AuthEngine(auth_dir=auth_dir)
    init_token = engine.generate_presence_challenge(print_to_console=False)
    engine.enroll(primary_pin="123456", recovery_pin="654321", presence_token=init_token)

    for h in (9, 12, 15):
        engine.anomaly_detector.record_success(datetime(2026, 9, 1, h, 0), "wifi:KnownNet")

    anomalous_context = {"time": datetime(2026, 9, 1, 2, 0), "network_id": "wifi:Unknown"}

    # Generate step-up challenge with mocked expired time
    real_token = engine.generate_step_up_challenge(print_to_console=False)

    # Mock time forward beyond TTL (300 seconds)
    with patch("time.time", return_value=datetime.now().timestamp() + 1000):
        with pytest.raises(UnauthorizedError, match="multi-factor step-up verification failed"):
            engine.check_authorization(
                AuthTier.DESTRUCTIVE,
                pin="123456",
                context=anomalous_context,
                presence_token=real_token,
            )


def test_network_identity_discovery():
    """Verifies that get_current_network_identity returns a non-empty formatted string without crashing."""
    net_id = AnomalyDetector.get_current_network_identity()
    assert isinstance(net_id, str)
    assert len(net_id) > 0
    assert any(net_id.startswith(p) for p in ("wifi:", "subnet:", "network:"))


def test_baseline_reset(tmp_path):
    """Verifies baseline reset removes old patterns and initializes fresh baseline."""
    detector = AnomalyDetector(auth_dir=tmp_path)
    for _ in range(5):
        detector.record_success(datetime(2026, 9, 1, 12, 0), "wifi:OldNet")

    baseline, _ = detector._load_baseline_locked()
    assert baseline.total_observations == 5

    detector.reset_baseline()
    baseline_fresh, _ = detector._load_baseline_locked()
    assert baseline_fresh.total_observations == 0


def test_unmigrated_check_authorization_without_context_succeeds_at_normal_friction(tmp_path):
    """
    Proves that calling check_authorization() without passing explicit context (e.g. legacy call sites)
    auto-resolves local network identity and time, executing at normal friction on a calibrated machine
    without erroneously forcing step-up MFA.
    """
    auth_dir = tmp_path / "auth"
    engine = AuthEngine(auth_dir=auth_dir)
    token = engine.generate_presence_challenge()
    engine.enroll(primary_pin="999888", recovery_pin="111222", presence_token=token)

    # Legacy/unmigrated call with no context kwarg:
    # 1. READ_ONLY succeeds
    v_read = engine.check_authorization(AuthTier.READ_ONLY)
    assert v_read.elevate_friction is False

    # 2. REVERSIBLE succeeds with no PIN
    v_rev = engine.check_authorization(AuthTier.REVERSIBLE)
    assert v_rev.elevate_friction is False

    # 3. DESTRUCTIVE succeeds with Primary PIN only (no step_up needed)
    v_dest = engine.check_authorization(AuthTier.DESTRUCTIVE, pin="999888")
    assert v_dest.elevate_friction is False


def test_enrollment_anomaly_seed_failure_emits_audit_and_completes_enrollment(tmp_path):
    """
    Confirms that if seed_initial_enrollment() raises an exception during enrollment:
    (a) First-run enrollment still completes successfully.
    (b) The anomaly_baseline_seed_failed_during_enrollment event is recorded in the event sink.
    """
    events = []
    auth_dir = tmp_path / "auth"
    engine = AuthEngine(auth_dir=auth_dir, event_sink=lambda k, d: events.append((k, d)))

    token = engine.generate_presence_challenge()

    with patch.object(engine.anomaly_detector, "seed_initial_enrollment", side_effect=RuntimeError("Disk write failed")):
        success = engine.enroll(primary_pin="123123", recovery_pin="321321", presence_token=token)
        assert success is True

    # Check that identity is enrolled
    assert engine.is_initialized() is True

    # Check audit event emission
    event_names = [e[0] for e in events]
    assert "anomaly_baseline_seed_failed_during_enrollment" in event_names
    err_event = next(e for e in events if e[0] == "anomaly_baseline_seed_failed_during_enrollment")
    assert "Disk write failed" in err_event[1]["error"]


def test_anomaly_verdict_truthiness_semantics():
    """
    Explicitly validates that AnomalyVerdict evaluates to truthy regardless of elevate_friction,
    preventing any caller from misinterpreting a successful check_authorization return as a falsy None.
    """
    normal_verdict = AnomalyVerdict(score=0.0, is_anomalous=False, elevate_friction=False)
    elevated_verdict = AnomalyVerdict(score=1.0, is_anomalous=True, elevate_friction=True)

    assert bool(normal_verdict) is True
    assert bool(elevated_verdict) is True


def test_step_up_invalid_garbage_token_is_rejected(tmp_path):
    """
    Confirms that providing a garbage or invalid token string against an active,
    unconsumed step-up challenge is strictly rejected with UnauthorizedError.
    """
    auth_dir = tmp_path / "auth"
    engine = AuthEngine(auth_dir=auth_dir)
    init_token = engine.generate_presence_challenge(print_to_console=False)
    engine.enroll(primary_pin="123456", recovery_pin="654321", presence_token=init_token)

    for h in (9, 12, 15):
        engine.anomaly_detector.record_success(datetime(2026, 9, 1, h, 0), "wifi:KnownNet")

    anomalous_context = {"time": datetime(2026, 9, 1, 2, 0), "network_id": "wifi:Unknown"}

    # Issue real step-up challenge
    engine.generate_step_up_challenge(print_to_console=False)

    # Submit garbage/invalid token string
    with pytest.raises(UnauthorizedError, match="multi-factor step-up verification failed"):
        engine.check_authorization(
            AuthTier.DESTRUCTIVE,
            pin="123456",
            context=anomalous_context,
            presence_token="invalid_garbage_token_abc_123",
        )


def test_step_up_token_reuse_is_rejected(tmp_path):
    """
    Confirms single-use enforcement: a valid step-up token can only be consumed once.
    Attempting to reuse the exact same token for a second DESTRUCTIVE operation is rejected.
    """
    auth_dir = tmp_path / "auth"
    engine = AuthEngine(auth_dir=auth_dir)
    init_token = engine.generate_presence_challenge(print_to_console=False)
    engine.enroll(primary_pin="123456", recovery_pin="654321", presence_token=init_token)

    for h in (9, 12, 15):
        engine.anomaly_detector.record_success(datetime(2026, 9, 1, h, 0), "wifi:KnownNet")

    anomalous_context = {"time": datetime(2026, 9, 1, 2, 0), "network_id": "wifi:Unknown"}

    # 1. Issue real step-up challenge
    real_token = engine.generate_step_up_challenge(print_to_console=False)

    # 2. First authorization succeeds and consumes token
    v1 = engine.check_authorization(
        AuthTier.DESTRUCTIVE,
        pin="123456",
        context=anomalous_context,
        presence_token=real_token,
    )
    assert v1.is_anomalous is True

    # 3. Second authorization with the same consumed token MUST fail
    with pytest.raises(UnauthorizedError, match="multi-factor step-up verification failed"):
        engine.check_authorization(
            AuthTier.DESTRUCTIVE,
            pin="123456",
            context=anomalous_context,
            presence_token=real_token,
        )


