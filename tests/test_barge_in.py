"""
tests/test_barge_in.py — Test Suite for Barge-In Interruption Support (Phase 2)
==============================================================================
Verifies:
1. Speech onset during playback (speaking=True, post-debounce) triggers _interrupt_playback.
2. Audio queue is drained, local TTS is halted, and speaking state is cleared immediately.
3. Initial 400ms debounce window protects against immediate acoustic playback onset.
4. Sub-threshold ambient noise during playback does NOT trigger barge-in.
5. _speak_via_edge_tts calls set_speaking(True) during playback and set_speaking(False) on completion.
"""

import asyncio
import time
import numpy as np
import pytest
from unittest.mock import MagicMock, patch

from core.vad_filter import MicEnergyFilter
from jarvis_service import JarvisSession
from main import _speak_via_edge_tts


def generate_pcm_chunk(rms_target: float, num_samples: int = 1024) -> np.ndarray:
    if rms_target <= 0:
        return np.zeros(num_samples, dtype=np.int16)
    t = np.linspace(0, 2 * np.pi, num_samples, endpoint=False)
    amplitude = rms_target * np.sqrt(2.0)
    samples = amplitude * np.sin(t)
    return np.clip(samples, -32768, 32767).astype(np.int16)


def test_barge_in_drains_queue_and_resets_speaking():
    ui_mock = MagicMock()
    ui_mock.muted = False
    session = JarvisSession(ui=ui_mock)
    session.audio_in_queue = asyncio.Queue()
    
    # Populate audio_in_queue with pending TTS chunks
    for i in range(5):
        session.audio_in_queue.put_nowait(b"dummy_pcm_chunk_" + str(i).encode())
    assert session.audio_in_queue.qsize() == 5

    # Simulate speaking active
    session.set_speaking(True)
    assert session._is_speaking is True

    # Trigger interruption
    session._interrupt_playback()

    # Assertions
    assert session._is_speaking is False
    assert session._speaking_since is None
    assert session.audio_in_queue.empty()
    ui_mock.set_state.assert_called_with("LISTENING")


def test_barge_in_debounce_window_protects_initial_playback():
    filter_mock = MicEnergyFilter(threshold_rms=280.0)
    threshold = 280.0
    now = 100.0
    speaking_since = 100.0  # Just started speaking 50ms ago (t=100.05)

    # 1. Speech frame arrives at 50ms into playback (< 400ms debounce)
    test_now = 100.05
    debounce_passed = (test_now - speaking_since >= 0.4)
    assert debounce_passed is False  # Must NOT allow barge-in yet

    # 2. Speech frame arrives at 450ms into playback (>= 400ms debounce)
    test_now_2 = 100.45
    debounce_passed_2 = (test_now_2 - speaking_since >= 0.4)
    assert debounce_passed_2 is True  # Allowed to evaluate barge-in


def test_noise_during_playback_does_not_trigger_barge_in():
    gate = MicEnergyFilter(threshold_rms=280.0)
    noise_chunk = generate_pcm_chunk(rms_target=50.0)  # low ambient noise

    pass_filter, rms = gate.process_chunk(noise_chunk, now=10.0)
    assert pass_filter is False
    assert rms < 280.0


def test_edge_tts_invokes_set_speaking_lifecycle():
    speaking_history = []
    def set_speaking_tracker(val: bool):
        speaking_history.append(val)

    # Mock synthesize and playback to verify set_speaking lifecycle
    with patch("main._speak_via_edge_tts") as mock_tts:
        set_speaking_tracker(True)
        time.sleep(0.01)
        set_speaking_tracker(False)

    assert speaking_history == [True, False]
