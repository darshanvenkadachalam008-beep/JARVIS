"""
core/voice_emotion.py — Voice Emotion Detection
================================================
Analyses the raw PCM microphone stream that JARVIS already captures and
infers the user's emotional state from acoustic features: energy (RMS),
speech rate (zero-crossing rate as a pitch proxy), and dynamic range.

No cloud API, no model download needed for the basic version.
Optional: install librosa for richer pitch + tempo analysis.

Usage (called from the existing mic capture loop in main.py):
    from core.voice_emotion import VoiceEmotionDetector
    _emotion = VoiceEmotionDetector(on_state_change=_inject_mood_fn)
    _emotion.feed(pcm_bytes)   # call every time a mic chunk arrives
"""

from __future__ import annotations

import math
import struct
import time
import threading
from collections import deque
from typing import Callable, Optional

# Optional librosa for richer features
_LIBROSA_OK = False
try:
    import librosa as _librosa
    import numpy as _np
    _LIBROSA_OK = True
except ImportError:
    pass

SAMPLE_RATE    = 16000   # Hz — must match JARVIS mic config
CHUNK_BYTES    = 512     # 16-bit PCM samples per feed() call
WINDOW_SECONDS = 4       # rolling analysis window
WINDOW_CHUNKS  = (SAMPLE_RATE * WINDOW_SECONDS) // (CHUNK_BYTES // 2)

# Thresholds (tunable)
STRESS_RMS_HIGH     = 1800   # above this = loud / intense speech
STRESS_ZCR_HIGH     = 0.20   # above this = high pitch / tense
CALM_RMS_LOW        = 600    # below this = quiet / relaxed
TIRED_ZCR_LOW       = 0.05   # below this = slow / monotone
HOLD_SECONDS        = 45     # seconds a mood must persist before we announce it
COOLDOWN_SECONDS    = 300    # minimum gap between mood announcements


class VoiceEmotionDetector:
    """
    Feed raw 16-bit little-endian PCM bytes.  When the user's emotional
    state changes and holds for HOLD_SECONDS, calls on_state_change(state)
    where state is one of: "stressed", "calm", "tired", "neutral".
    """

    STATES = ("neutral", "stressed", "calm", "tired")

    def __init__(self, on_state_change: Optional[Callable[[str], None]] = None):
        self._on_change   = on_state_change
        self._buf: deque  = deque(maxlen=WINDOW_CHUNKS)
        self._lock        = threading.Lock()
        self._last_state  = "neutral"
        self._candidate   = "neutral"
        self._candidate_since = 0.0
        self._last_announce   = 0.0
        self._enabled     = True
        print("[Emotion] 🎤 Voice emotion detector started"
              + (" (librosa active)" if _LIBROSA_OK else " (basic mode)"))

    # ── public ────────────────────────────────────────────────────────────────

    def feed(self, pcm_bytes: bytes):
        """Call with every raw PCM chunk from the microphone."""
        if not self._enabled or not pcm_bytes:
            return
        with self._lock:
            n = len(pcm_bytes) // 2
            samples = struct.unpack(f"<{n}h", pcm_bytes[:n * 2])
            self._buf.append(samples)
            if len(self._buf) == WINDOW_CHUNKS:
                self._analyse()

    def set_enabled(self, enabled: bool):
        self._enabled = enabled

    def current_state(self) -> str:
        return self._last_state

    # ── internal ──────────────────────────────────────────────────────────────

    def _analyse(self):
        flat = []
        for chunk in self._buf:
            flat.extend(chunk)
        if not flat:
            return

        if _LIBROSA_OK:
            state = self._analyse_librosa(flat)
        else:
            state = self._analyse_basic(flat)

        now = time.time()
        if state == self._candidate:
            if (now - self._candidate_since >= HOLD_SECONDS
                    and state != self._last_state
                    and now - self._last_announce >= COOLDOWN_SECONDS):
                self._last_state   = state
                self._last_announce = now
                print(f"[Emotion] 🎭 Mood detected: {state.upper()}")
                if self._on_change:
                    try:
                        self._on_change(state)
                    except Exception as e:
                        print(f"[Emotion] ⚠️ on_state_change error: {e}")
        else:
            self._candidate       = state
            self._candidate_since = now

    def _analyse_basic(self, samples: list) -> str:
        """RMS energy + zero-crossing rate only."""
        n   = len(samples)
        rms = math.sqrt(sum(s * s for s in samples) / n)
        zc  = sum(1 for i in range(1, n) if (samples[i] >= 0) != (samples[i-1] >= 0)) / n

        if rms > STRESS_RMS_HIGH and zc > STRESS_ZCR_HIGH:
            return "stressed"
        if rms < CALM_RMS_LOW and 0.06 < zc < 0.18:
            return "calm"
        if rms < CALM_RMS_LOW and zc < TIRED_ZCR_LOW:
            return "tired"
        return "neutral"

    def _analyse_librosa(self, samples: list) -> str:
        """Richer analysis using librosa: spectral centroid + RMS energy."""
        import numpy as np
        arr = np.array(samples, dtype=np.float32) / 32768.0  # normalise to [-1, 1]

        rms      = float(np.sqrt(np.mean(arr ** 2)))
        centroid = float(np.mean(_librosa.feature.spectral_centroid(y=arr, sr=SAMPLE_RATE)))
        # centroid < 800 Hz → low/flat voice;  > 2000 Hz → bright/tense
        zc       = float(np.mean(_librosa.feature.zero_crossing_rate(arr)))

        # Richer rules using centroid + energy
        if rms > 0.055 and centroid > 1800:
            return "stressed"
        if rms < 0.018 and 800 < centroid < 2000:
            return "calm"
        if rms < 0.018 and centroid < 800:
            return "tired"
        return "neutral"