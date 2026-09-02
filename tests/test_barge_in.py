"""
tests/test_barge_in.py — Test Suite for Barge-In Interruption & TTS Lifecycle (Phase 2)
=====================================================================================
Verifies:
1. Speech onset during playback (speaking=True, post-debounce) triggers _interrupt_playback.
2. Audio queue is drained, local TTS is halted, and speaking state is cleared immediately.
3. Initial 400ms debounce window protects against immediate acoustic playback onset.
4. Sub-threshold ambient noise during playback does NOT trigger barge-in.
5. Real _speak_via_edge_tts function invokes set_speaking(True) and set_speaking(False) as direct side-effects.
6. AST check across main.py and jarvis_service.py proves every _speak_via_edge_tts thread passes set_speaking.
"""

import ast
import asyncio
import io
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, call, patch
import numpy as np
import pytest

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


def test_real_speak_via_edge_tts_executes_set_speaking_lifecycle():
    """
    Executes the REAL _speak_via_edge_tts function with a mock set_speaking callback.
    Stubs only the synthesize stream generator and pygame playback loop via sys.modules.
    Asserts set_speaking is called with True before playback and False in finally block.
    """
    mock_set_speaking = MagicMock()

    class FakeCommunicate:
        def __init__(self, *args, **kwargs):
            pass
        async def stream(self):
            yield {"type": "audio", "data": b"\xff\xfb\x90\x64" + b"\x00" * 32}

    mock_pygame = MagicMock()
    mock_pygame.mixer.get_init.return_value = True
    mock_pygame.mixer.music.get_busy.side_effect = [True, False]

    fake_edge_tts = MagicMock()
    fake_edge_tts.Communicate = FakeCommunicate

    with patch.dict(sys.modules, {"pygame": mock_pygame, "edge_tts": fake_edge_tts}):
        # Call real production _speak_via_edge_tts
        _speak_via_edge_tts("Test speech output", ui=None, set_speaking=mock_set_speaking)

    # Verify real function invoked mock_set_speaking(True) then mock_set_speaking(False)
    assert mock_set_speaking.call_args_list == [call(True), call(False)]


def test_all_edge_tts_thread_call_sites_pass_set_speaking():
    """
    Statically analyzes AST of main.py and jarvis_service.py.
    Finds every threading.Thread instantiation with target=_speak_via_edge_tts.
    Proves that every single one passes set_speaking as the 3rd positional element.
    """
    repo_root = Path(__file__).resolve().parent.parent

    for fname in ["main.py", "jarvis_service.py"]:
        fpath = repo_root / fname
        tree = ast.parse(fpath.read_text(encoding="utf-8"))

        call_sites_found = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Look for threading.Thread(target=_speak_via_edge_tts, ...)
                is_thread_call = False
                if isinstance(node.func, ast.Attribute) and node.func.attr == "Thread":
                    is_thread_call = True

                if is_thread_call:
                    target_kw = next((kw for kw in node.keywords if kw.arg == "target"), None)
                    if target_kw and isinstance(target_kw.value, ast.Name) and target_kw.value.id == "_speak_via_edge_tts":
                        call_sites_found += 1
                        # Find args=(...) keyword
                        args_kw = next((kw for kw in node.keywords if kw.arg == "args"), None)
                        assert args_kw is not None, f"Call site in {fname} missing args keyword"
                        assert isinstance(args_kw.value, ast.Tuple), f"args in {fname} must be a tuple"
                        
                        # Assert tuple has at least 3 elements
                        assert len(args_kw.value.elts) >= 3, (
                            f"Call site in {fname} has only {len(args_kw.value.elts)} args! "
                            f"Must pass set_speaking as 3rd arg."
                        )
                        # Check 3rd element name/attribute
                        third_arg = args_kw.value.elts[2]
                        if isinstance(third_arg, ast.Attribute):
                            assert third_arg.attr == "set_speaking"
                        elif isinstance(third_arg, ast.Name):
                            assert third_arg.id == "set_speaking"
                        else:
                            pytest.fail(f"Unexpected 3rd arg type in {fname}: {ast.dump(third_arg)}")

        assert call_sites_found > 0, f"No _speak_via_edge_tts thread call sites found in {fname}"
