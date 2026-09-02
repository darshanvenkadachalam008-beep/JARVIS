"""
tests/test_vad_filter.py — Test Suite for Energy-based Mic Pre-filter & Noise Gate (Phase 1)
============================================================================================
Verifies:
1. Low-energy synthetic noise (RMS < threshold) is dropped.
2. Speech-level synthetic audio (RMS >= threshold) passes.
3. Hangover/hysteresis preserves trailing frames within the hangover window.
4. Silence beyond hangover window is properly closed/dropped.
5. Gate reset clears hysteresis state.
6. Config persistence via _get_noise_floor_rms / _save_noise_floor_rms.
"""

import json
import numpy as np
import pytest
from pathlib import Path

from core.vad_filter import (
    MicEnergyFilter,
    compute_chunk_rms,
    DEFAULT_NOISE_FLOOR_RMS,
    DEFAULT_HANGOVER_SECS,
)
from main import _get_noise_floor_rms, _save_noise_floor_rms


def generate_pcm_chunk(rms_target: float, num_samples: int = 1024) -> np.ndarray:
    """Generates a synthetic sine wave PCM chunk with a specified target RMS."""
    if rms_target <= 0:
        return np.zeros(num_samples, dtype=np.int16)
    t = np.linspace(0, 2 * np.pi, num_samples, endpoint=False)
    amplitude = rms_target * np.sqrt(2.0)
    samples = amplitude * np.sin(t)
    return np.clip(samples, -32768, 32767).astype(np.int16)


def test_compute_chunk_rms():
    # Zero audio
    zeros = np.zeros(1024, dtype=np.int16)
    assert compute_chunk_rms(zeros) == 0.0
    assert compute_chunk_rms(zeros.tobytes()) == 0.0

    # Sine wave with known RMS
    target_rms = 500.0
    chunk = generate_pcm_chunk(target_rms, 1024)
    computed_rms = compute_chunk_rms(chunk)
    assert pytest.approx(computed_rms, rel=0.05) == target_rms

    # Bytes input
    assert pytest.approx(compute_chunk_rms(chunk.tobytes()), rel=0.05) == target_rms


def test_low_energy_noise_is_dropped():
    gate = MicEnergyFilter(threshold_rms=250.0, hangover_secs=0.5)
    noise_chunk = generate_pcm_chunk(rms_target=50.0)  # well below 250

    should_send, rms = gate.process_chunk(noise_chunk, now=100.0)
    assert should_send is False
    assert rms < 250.0
    assert gate.dropped_noise_count == 1
    assert gate.passed_speech_count == 0


def test_speech_energy_passes():
    gate = MicEnergyFilter(threshold_rms=250.0, hangover_secs=0.5)
    speech_chunk = generate_pcm_chunk(rms_target=800.0)  # speech level

    should_send, rms = gate.process_chunk(speech_chunk, now=100.0)
    assert should_send is True
    assert rms >= 250.0
    assert gate.passed_speech_count == 1
    assert gate.dropped_noise_count == 0


def test_hangover_window_preserves_inter_word_pauses():
    gate = MicEnergyFilter(threshold_rms=250.0, hangover_secs=0.5)
    speech_chunk = generate_pcm_chunk(rms_target=800.0)
    silence_chunk = generate_pcm_chunk(rms_target=30.0)

    # 1. Speech frame at t=1.0 -> passes
    pass1, _ = gate.process_chunk(speech_chunk, now=1.0)
    assert pass1 is True

    # 2. Silence frame at t=1.2 (within 0.5s hangover) -> passes
    pass2, _ = gate.process_chunk(silence_chunk, now=1.2)
    assert pass2 is True

    # 3. Silence frame at t=1.4 (within 0.5s hangover) -> passes
    pass3, _ = gate.process_chunk(silence_chunk, now=1.4)
    assert pass3 is True

    # 4. Silence frame at t=1.6 (0.6s after last speech at t=1.0, past hangover) -> dropped
    pass4, _ = gate.process_chunk(silence_chunk, now=1.6)
    assert pass4 is False


def test_gate_reset_immediately_closes_hangover():
    gate = MicEnergyFilter(threshold_rms=250.0, hangover_secs=0.8)
    speech_chunk = generate_pcm_chunk(rms_target=800.0)
    silence_chunk = generate_pcm_chunk(rms_target=30.0)

    # Speech frame
    gate.process_chunk(speech_chunk, now=1.0)

    # Reset gate (e.g. state changed to SLEEPING or JARVIS started speaking)
    gate.reset()

    # Silence frame at t=1.1 should now be dropped immediately
    pass_silence, _ = gate.process_chunk(silence_chunk, now=1.1)
    assert pass_silence is False


def test_noise_floor_config_persistence(tmp_path, monkeypatch):
    import main
    fake_config = tmp_path / "api_keys.json"
    fake_config.write_text(json.dumps({"gemini_api_key": "test"}), encoding="utf-8")
    monkeypatch.setattr(main, "API_CONFIG_PATH", fake_config)

    # Default fallback
    assert main._get_noise_floor_rms() == DEFAULT_NOISE_FLOOR_RMS

    # Save custom value
    main._save_noise_floor_rms(350.0)
    assert main._get_noise_floor_rms() == 350.0

    # Bounds clamping
    main._save_noise_floor_rms(5.0)
    assert main._get_noise_floor_rms() == 10.0  # min bound
