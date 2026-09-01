"""
tests/test_face_verify.py — Tests for face liveness/anti-spoofing and auth triage integration
=============================================================================================
Verifies:
1. High-variance textured face crop -> spoof_suspected=False.
2. Low-variance / flat / heavily blurred face crop -> spoof_suspected=True.
3. triage_authentication(): face matches owner AND spoof_suspected=True -> INTRUDER_SUSPECTED.
4. triage_authentication(): face matches owner AND spoof_suspected=False -> OWNER_MISTYPE.
5. IdentifyResult reports distinct accepted vs spoof_suspected signals.
"""
import numpy as np
import pytest
from pathlib import Path
from unittest.mock import MagicMock

from core.face_verify import FaceVerifier, IdentifyResult, DEFAULT_SPOOF_LAPLACIAN_THRESHOLD
from core.access_control import AccessControl, TriageStatus


def _create_textured_face(size: int = 200) -> np.ndarray:
    """Generates a high-frequency textured synthetic face patch (high Laplacian variance)."""
    yy, xx = np.mgrid[0:size, 0:size]
    stripes = np.sin(0.4 * xx) * np.cos(0.4 * yy)
    noise = np.random.RandomState(42).normal(0, 0.2, size=(size, size))
    patch = np.clip((stripes + noise) * 127 + 128, 0, 255).astype(np.uint8)
    return patch


def _create_flat_blurred_face(size: int = 200) -> np.ndarray:
    """Generates a flat, blurred synthetic image (low Laplacian variance, simulating photo-of-a-photo / screen)."""
    yy, xx = np.mgrid[0:size, 0:size]
    # Very gentle, smooth gradient with near zero high-frequency edges
    gradient = (xx / size) * 20.0 + 100.0
    return np.clip(gradient, 0, 255).astype(np.uint8)


def test_face_liveness_heuristic_textured_vs_flat(tmp_path):
    """Verifies that high-variance patch yields spoof_suspected=False and flat patch yields spoof_suspected=True."""
    fv = FaceVerifier(base_path=tmp_path / "memory")

    textured = _create_textured_face()
    flat = _create_flat_blurred_face()

    spoof_textured, score_textured = fv._compute_spoof_metrics(textured)
    spoof_flat, score_flat = fv._compute_spoof_metrics(flat)

    assert score_textured > DEFAULT_SPOOF_LAPLACIAN_THRESHOLD
    assert spoof_textured is False

    assert score_flat < DEFAULT_SPOOF_LAPLACIAN_THRESHOLD
    assert spoof_flat is True


def test_face_identify_reports_independent_spoof_and_accepted_signals(tmp_path):
    """
    Verifies that identify() evaluates anti-spoofing independently from recognition match:
    IdentifyResult.accepted is True (identity match) while spoof_suspected is reported accurately.
    """
    fv = FaceVerifier(base_path=tmp_path / "memory")

    # Mock crop to return flat blurred image
    flat_patch = _create_flat_blurred_face()
    fv._detect_and_crop = MagicMock(return_value=flat_patch)

    # When not enrolled
    res_not_enrolled = fv.identify(b"fake_jpeg")
    assert res_not_enrolled.enrolled is False
    assert res_not_enrolled.face_found is True
    assert res_not_enrolled.accepted is False
    assert res_not_enrolled.spoof_suspected is True
    assert res_not_enrolled.spoof_score is not None

    # When enrolled with trained recognizer predicting owner match
    mock_rec = MagicMock()
    mock_rec.predict.return_value = (0, 30.0)  # Owner label (0), low distance (30.0 <= 75.0)
    fv._get_recognizer = MagicMock(return_value=mock_rec)
    fv.model_path.touch()
    fv.meta_path.write_text('{"threshold": 75.0, "spoof_threshold": 50.0}', encoding="utf-8")

    res_enrolled = fv.identify(b"fake_jpeg")
    assert res_enrolled.enrolled is True
    assert res_enrolled.face_found is True
    assert res_enrolled.accepted is True  # Identity matched owner
    assert res_enrolled.spoof_suspected is True  # But flagged by anti-spoofing heuristic


def test_triage_authentication_spoofed_owner_face_triggers_intruder_suspected(tmp_path):
    """
    Verifies that when wrong PIN is entered and the owner face matches BUT spoof_suspected=True,
    triage_authentication fails closed to INTRUDER_SUSPECTED and triggers an alert.
    """
    ac = AccessControl(path=tmp_path / "memory" / "access_control.json")
    ac.set_pin("CorrectMasterPin123")
    ac.set_recovery_pin("RecoveryPin456")

    # Mock FaceVerifier returning accepted=True (owner match) BUT spoof_suspected=True
    mock_fv = MagicMock()
    mock_fv.identify.return_value = IdentifyResult(
        enrolled=True,
        face_found=True,
        accepted=True,
        confidence=25.0,
        spoof_suspected=True,
        spoof_score=12.5,
    )

    alerts = []
    res = ac.triage_authentication(
        candidate_pin="WrongPinGuess",
        action="unlock_vault",
        snapshot_bytes=b"fake_jpeg_photo_of_owner",
        face_verifier=mock_fv,
        alert_callback=lambda msg, snap: alerts.append(msg),
    )

    assert res.status == TriageStatus.INTRUDER_SUSPECTED
    assert res.can_prompt_pin is False
    assert len(alerts) == 1
    assert "face_spoof_suspected" in alerts[0]


def test_triage_authentication_live_owner_face_grants_owner_mistype(tmp_path):
    """
    Verifies that when wrong PIN is entered and the owner face matches AND spoof_suspected=False,
    triage_authentication classifies the event as OWNER_MISTYPE, permitting recovery PIN fallback.
    """
    ac = AccessControl(path=tmp_path / "memory" / "access_control.json")
    ac.set_pin("CorrectMasterPin123")
    ac.set_recovery_pin("RecoveryPin456")

    # Mock FaceVerifier returning accepted=True AND spoof_suspected=False
    mock_fv = MagicMock()
    mock_fv.identify.return_value = IdentifyResult(
        enrolled=True,
        face_found=True,
        accepted=True,
        confidence=25.0,
        spoof_suspected=False,
        spoof_score=150.0,
    )

    alerts = []
    res = ac.triage_authentication(
        candidate_pin="WrongPinGuess",
        action="unlock_vault",
        snapshot_bytes=b"fake_jpeg_live_owner",
        face_verifier=mock_fv,
        alert_callback=lambda msg, snap: alerts.append(msg),
    )

    assert res.status == TriageStatus.OWNER_MISTYPE
    assert res.can_prompt_pin is True
    assert len(alerts) == 0  # No alert dispatched for genuine owner mistype
