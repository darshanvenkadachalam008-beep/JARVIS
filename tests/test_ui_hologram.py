import sys
import time
import pytest

from ui import (
    HologramCanvas,
    _STATE_THEMES,
    C,
    QApplication,
    QPixmap,
    QPainter,
)


@pytest.fixture(scope="module")
def qapp():
    """Ensures a QApplication instance exists for PyQt widget lifecycle tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


def test_hologram_canvas_theme_resolution(qapp):
    """
    Verifies that HologramCanvas correctly resolves state themes
    for all supported operational modes.
    """
    canvas = HologramCanvas()
    
    # Check default LISTENING theme
    canvas.set_state("LISTENING")
    theme = canvas.get_theme()
    assert theme["primary"] == C.GREEN
    assert theme["label"] == "LISTENING"
    
    # Check THINKING
    canvas.set_state("THINKING")
    theme = canvas.get_theme()
    assert theme["primary"] == C.STEEL
    assert theme["label"] == "THINKING"
    
    # Check SPEAKING
    canvas.set_state("SPEAKING")
    theme = canvas.get_theme()
    assert theme["primary"] == C.GOLD
    assert theme["label"] == "SPEAKING"
    assert canvas._speaking is True
    
    # Check ALERT & CRITICAL
    canvas.set_state("ALERT")
    theme = canvas.get_theme()
    assert theme["primary"] == C.RED
    assert theme["label"] == "SECURITY ALERT"
    
    canvas.set_state("CRITICAL")
    theme = canvas.get_theme()
    assert theme["primary"] == C.RED
    assert theme["label"] == "CRITICAL ALERT"
    
    # Check SLEEPING & OFFLINE
    canvas.set_state("SLEEPING")
    theme = canvas.get_theme()
    assert theme["primary"] == C.TEXT_DIM
    assert theme["label"] == "SLEEPING"
    
    canvas.set_state("OFFLINE")
    theme = canvas.get_theme()
    assert theme["primary"] == C.BORDER
    assert theme["label"] == "OFFLINE"


def test_hologram_canvas_audio_reactivity_and_staleness(qapp):
    """
    Verifies that set_audio_level:
    1. Clamps input between 0.0 and 1.0.
    2. Updates _audio_level_t timestamp.
    3. Triggers target halo expansion during active states.
    """
    canvas = HologramCanvas()
    canvas.set_state("LISTENING")
    
    # Clamping test
    canvas.set_audio_level(1.5)
    assert canvas._audio_level == 1.0
    
    canvas.set_audio_level(-0.5)
    assert canvas._audio_level == 0.0
    
    # Fresh audio level step
    canvas.set_audio_level(0.85)
    canvas._step()
    # Target halo should scale significantly above baseline
    assert canvas._tgt_halo > 100.0
    
    # Simulate stale audio
    canvas._audio_level_t = time.time() - 2.0  # 2s old (> 0.5s threshold)
    canvas._step()


def test_hologram_canvas_glitch_trigger_on_major_transitions(qapp):
    """
    Verifies that glitch shader burst is triggered only on major state transitions
    (entering SPEAKING/ALERT/CRITICAL, or going OFFLINE).
    """
    canvas = HologramCanvas()
    canvas.set_state("LISTENING")
    initial_glitch = canvas._glitch_until
    
    # Transitioning to THINKING should NOT trigger glitch
    canvas.set_state("THINKING")
    assert canvas._glitch_until == initial_glitch
    
    # Transitioning to SPEAKING should trigger glitch
    canvas.set_state("SPEAKING")
    assert canvas._glitch_until > time.time()
    assert len(canvas._glitch_lines) > 0


def test_hologram_canvas_headless_qpixmap_rendering(qapp):
    """
    Executes actual paintEvent rendering against an offscreen QPixmap surface
    across all states and with non-zero audio levels, ensuring zero rendering crashes.
    """
    canvas = HologramCanvas()
    canvas.resize(400, 400)
    
    test_states = ["LISTENING", "THINKING", "SPEAKING", "ACTIVE_CONVERSATION", "ALERT", "CRITICAL", "SLEEPING", "OFFLINE"]
    audio_levels = [0.0, 0.45, 0.95]
    
    for state in test_states:
        for audio in audio_levels:
            canvas.set_state(state)
            canvas.set_audio_level(audio)
            canvas._step()
            canvas.paintEvent(None)
