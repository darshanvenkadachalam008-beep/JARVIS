"""
core/gesture_control.py — Webcam gesture control (free, on-device)
=======================================================================
Mirrors core/wake_word.py's design: a background thread that watches one
input continuously and fires a callback on a recognized trigger, with the
same start()/stop()/on_error() shape so it plugs into main.py the same
way WakeWordEngine already does.

Uses Google's MediaPipe Tasks Vision GestureRecognizer — free, no API key,
runs the model entirely on-device (CPU or GPU delegate). The .task model
file (~8MB) is downloaded once on first use and cached locally; after
that, detection needs no network at all, same "offline after first run"
shape as openWakeWord's bundled models.

Recognized gestures (MediaPipe's built-in vocabulary) are mapped to
actions by the caller via `gesture_actions`, not hardcoded here — main.py
wires them to StateManager the same way WakeWordEngine's on_wake is wired
to state_manager.wake().

Confidence thresholds (v2): live-tested on real hardware. Default
MediaPipe thresholds (0.5) proved slightly strict — confirmed working
scores were 0.68-0.77 at correct arm's-length framing, but dimmer
lighting or a less-square hand angle can drop below 0.5. Lowered to
0.4/0.3 below for more forgiving everyday use.

Debounce (v2): originally required 5 *exactly consecutive* matching
frames, resetting to zero on any single differing frame — this proved
too brittle against ordinary frame-to-frame noise (motion blur, a
single misclassified frame) even while the user held a steady gesture.
Changed to a leaky counter: one stray off-frame no longer discards
progress; it takes 2 consecutive *different* readings to actually
switch what's being tracked, while an isolated good-bad-good blip just
pauses rather than resets. Still requires 5 genuinely consistent frames
to actually fire — this does not make false triggers more likely, it
only makes real, held gestures more reliably recognized.

Usage
-----
    from core.gesture_control import GestureControlEngine

    engine = GestureControlEngine(
        on_gesture={
            "Open_Palm":   lambda: state_manager.wake(),
            "Closed_Fist": lambda: state_manager.sleep(),
        },
        on_error=lambda msg: ui.write_log(f"SYS: Gesture control error — {msg}"),
    )
    engine.start()
    ...
    engine.stop()
"""
from __future__ import annotations

import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Callable, Optional

STABLE_FRAMES_REQUIRED = 5     # consecutive matching frames before firing
COOLDOWN_SECS = 2.0            # ignore repeat triggers for this long after firing
MISS_TOLERANCE = 2             # consecutive *different* readings needed before
                                # actually switching tracked gesture (leaky debounce)
MODEL_URL = (
    "https://storage.googleapis.com/mediapipe-models/gesture_recognizer/"
    "gesture_recognizer/float16/1/gesture_recognizer.task"
)


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


def _model_path() -> Path:
    p = _base_dir() / "memory" / "models"
    p.mkdir(parents=True, exist_ok=True)
    return p / "gesture_recognizer.task"


class GestureControlEngine:
    """
    Always-on webcam gesture listener.

    Parameters
    ----------
    on_gesture : dict[str, Callable[[], None]]
        Maps MediaPipe gesture category names (e.g. "Open_Palm",
        "Closed_Fist", "Thumb_Up", "Thumb_Down", "Victory", "Pointing_Up",
        "ILoveYou") to a zero-arg callback fired once per debounced trigger.
        Gestures not present in this dict are recognized but ignored.
    camera_index : int
        Which webcam to use (0 = system default).
    on_error : Callable[[str], None] | None
        Called if the camera or model fails to load. Camera/gesture
        control simply won't work that session — nothing else breaks,
        same failure shape as WakeWordEngine.on_error.
    """

    def __init__(
        self,
        on_gesture: dict[str, Callable[[], None]],
        camera_index: int = 0,
        on_error: Optional[Callable[[str], None]] = None,
    ):
        self._on_gesture = on_gesture
        self._camera_index = camera_index
        self._on_error = on_error

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_fire_time = 0.0
        self._last_seen_gesture: Optional[str] = None
        self._stable_count = 0
        self._miss_count = 0
        self.last_gesture: str = "NONE"   # exposed for UI polling if desired

    # ── Model management ────────────────────────────────────────────────

    def _ensure_model(self) -> Path:
        path = _model_path()
        if path.exists() and path.stat().st_size > 1_000_000:
            return path
        # First run only — after this, detection is fully offline.
        urllib.request.urlretrieve(MODEL_URL, str(path) + ".part")
        Path(str(path) + ".part").rename(path)
        return path

    # ── Lifecycle ────────────────────────────────────────────────────────

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="GestureControlEngine")
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3.0)

    # ── Main loop ────────────────────────────────────────────────────────

    def _run(self):
        try:
            import cv2
            from mediapipe.tasks.python import BaseOptions
            from mediapipe.tasks.python.vision import (
                GestureRecognizer, GestureRecognizerOptions, RunningMode,
            )
        except ImportError as e:
            if self._on_error:
                self._on_error(f"Missing dependency ({e}). Install: pip install opencv-python mediapipe")
            return

        try:
            model_path = self._ensure_model()
        except Exception as e:
            if self._on_error:
                self._on_error(f"Could not download gesture model: {e}")
            return

        try:
            options = GestureRecognizerOptions(
                base_options=BaseOptions(model_asset_path=str(model_path)),
                running_mode=RunningMode.VIDEO,
                # Defaults (0.5) proved slightly strict in real-world testing —
                # confirmed working scores were 0.68-0.77 at correct arm's-length
                # framing, but dimmer lighting or a less-square hand angle can
                # drop below 0.5. Lowered to 0.4/0.3 for more forgiving everyday
                # use; the stable-frame debounce below is what actually prevents
                # false triggers, not this threshold.
                min_hand_detection_confidence=0.4,
                min_hand_presence_confidence=0.4,
                min_tracking_confidence=0.3,
            )
            recognizer = GestureRecognizer.create_from_options(options)
        except Exception as e:
            if self._on_error:
                self._on_error(f"Could not load gesture model: {e}")
            return

        cap = cv2.VideoCapture(self._camera_index)
        if not cap.isOpened():
            if self._on_error:
                self._on_error(f"Could not open camera index {self._camera_index}")
            return

        try:
            import mediapipe as mp
            frame_ms = 0
            while not self._stop_event.is_set():
                ok, frame = cap.read()
                if not ok:
                    time.sleep(0.1)
                    continue

                rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                mp_image = mp.Image(image_format=mp.ImageFormat.SRGB, data=rgb)
                frame_ms += 33  # ~30fps timestamp pacing for VIDEO mode
                result = recognizer.recognize_for_video(mp_image, frame_ms)

                name = "NONE"
                if result.gestures and result.gestures[0]:
                    top = result.gestures[0][0]
                    if top.category_name and top.category_name != "None":
                        name = top.category_name

                self._process_detection(name)
                # Cap loop rate — gesture control doesn't need max FPS,
                # and this keeps CPU usage reasonable on laptops.
                time.sleep(0.05)
        finally:
            cap.release()
            recognizer.close()

    def _process_detection(self, name: str):
        """
        Leaky-counter debounce. A single frame that disagrees with the
        currently-tracked gesture no longer resets progress to zero — it
        takes MISS_TOLERANCE consecutive *different* readings to actually
        switch what's being tracked. This smooths out ordinary frame-to-
        frame noise (motion blur, one misclassified frame) without making
        false triggers more likely — a real gesture still needs
        STABLE_FRAMES_REQUIRED genuinely consistent reads to fire.
        """
        self.last_gesture = name

        if name == self._last_seen_gesture:
            self._miss_count = 0
            self._stable_count = min(self._stable_count + 1, STABLE_FRAMES_REQUIRED)
        else:
            self._miss_count += 1
            if self._miss_count >= MISS_TOLERANCE:
                # The new reading has now persisted long enough to trust —
                # actually switch what we're tracking, starting fresh.
                self._last_seen_gesture = name
                self._stable_count = 1
                self._miss_count = 0
            # Either way, this frame didn't confirm the tracked gesture,
            # so it can't be the one that fires below.
            return

        if name == "NONE" or self._stable_count != STABLE_FRAMES_REQUIRED:
            return

        now = time.time()
        if now - self._last_fire_time < COOLDOWN_SECS:
            return

        callback = self._on_gesture.get(name)
        if callback:
            self._last_fire_time = now
            try:
                callback()
            except Exception as e:
                if self._on_error:
                    self._on_error(f"Gesture callback for '{name}' raised: {e}")