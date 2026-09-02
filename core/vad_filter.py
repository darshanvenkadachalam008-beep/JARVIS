"""
core/vad_filter.py — Energy-based Mic Pre-filter & Hangover Gate
================================================================
Filters low-energy background noise, breathing, ambient room sounds, and hum
BEFORE mic frames are queued and transmitted to Gemini Live.

Key properties:
- Short-term RMS computation on PCM int16 audio frames.
- Configurable noise floor threshold (loaded from config/api_keys.json or default).
- Hangover / hysteresis window to preserve natural inter-word speech pauses without clipping.
- Periodic metric tracking for diagnostic observability (sent vs noise-dropped).
"""
from __future__ import annotations

import logging
import time
from typing import Optional, Union, Tuple
import numpy as np

logger = logging.getLogger(__name__)

DEFAULT_NOISE_FLOOR_RMS: float = 250.0  # RMS in int16 scale [0..32767]
DEFAULT_HANGOVER_SECS: float = 0.8      # Keep gate open for 800ms after speech energy


def compute_chunk_rms(chunk: Union[np.ndarray, bytes]) -> float:
    """Computes root-mean-square (RMS) amplitude of 16-bit PCM audio samples."""
    if isinstance(chunk, bytes):
        samples = np.frombuffer(chunk, dtype=np.int16).astype(np.float32)
    elif isinstance(chunk, np.ndarray):
        samples = chunk.astype(np.float32)
    else:
        return 0.0

    if len(samples) == 0:
        return 0.0

    return float(np.sqrt(np.mean(samples * samples)))


class MicEnergyFilter:
    """
    Stateful energy gate with hangover for real-time PCM audio streaming.
    """
    def __init__(
        self,
        threshold_rms: float = DEFAULT_NOISE_FLOOR_RMS,
        hangover_secs: float = DEFAULT_HANGOVER_SECS,
    ):
        self.threshold_rms = max(1.0, float(threshold_rms))
        self.hangover_secs = max(0.0, float(hangover_secs))
        self._last_speech_time: float = 0.0
        self._in_speech: bool = False
        self.dropped_noise_count: int = 0
        self.passed_speech_count: int = 0

    def set_threshold(self, threshold_rms: float) -> None:
        self.threshold_rms = max(1.0, float(threshold_rms))

    def reset(self) -> None:
        """Reset internal hysteresis/hangover state."""
        self._last_speech_time = 0.0
        self._in_speech = False

    def process_chunk(
        self,
        chunk: Union[np.ndarray, bytes],
        now: Optional[float] = None
    ) -> Tuple[bool, float]:
        """
        Evaluate an audio chunk against energy threshold and hangover window.

        Parameters
        ----------
        chunk : np.ndarray | bytes
            Audio samples (int16 mono).
        now : float | None
            Current timestamp in seconds. Uses time.time() if None.

        Returns
        -------
        (should_send: bool, rms: float)
        """
        if now is None:
            now = time.time()

        rms = compute_chunk_rms(chunk)
        if rms >= self.threshold_rms:
            self._last_speech_time = now
            self._in_speech = True
            self.passed_speech_count += 1
            return True, rms

        # Below threshold: check if within hangover/hysteresis window
        if self._in_speech and (now - self._last_speech_time <= self.hangover_secs):
            self.passed_speech_count += 1
            return True, rms

        # Beyond hangover window: gate closed, drop chunk
        self._in_speech = False
        self.dropped_noise_count += 1
        return False, rms
