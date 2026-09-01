"""
core/wake_word.py — Offline, always-on wake-word detection.
=============================================================
Replaces the old "record 2.5s -> upload to Gemini -> ask it to transcribe"
approach. That design sent raw microphone audio to the cloud every few
seconds, all day, just to check whether you said "Jarvis" — slow,
expensive on API quota, and not great for privacy.

This module uses openWakeWord (https://github.com/dscripka/openWakeWord),
a free, MIT-licensed, fully offline wake-word engine. It ships a
pre-trained "hey_jarvis" model out of the box. Detection happens
entirely on your CPU, in tens of milliseconds, with nothing leaving
your machine — there is no API call involved in wake detection at all.

Usage:
    from core.wake_word import WakeWordEngine

    engine = WakeWordEngine(on_wake=lambda: print("woke up!"))
    engine.start()
    ...
    engine.stop()

Pretrained models ship bundled inside the installed openwakeword package
(resources/models/*.onnx) — no download step or internet connection is
needed, on first run or ever. (An older openwakeword release used a
separate download_models() helper and a different Model() constructor
signature; that API no longer exists in current releases — see
_resolve_model_paths()/_load_model() below for the current one.)
"""

from __future__ import annotations

import collections
import threading
import time
from typing import Callable, Optional

import numpy as np
import sounddevice as sd

SAMPLE_RATE = 16000          # openWakeWord expects 16kHz mono int16 audio
FRAME_SIZE  = 1280           # 80ms frames; openWakeWord's recommended chunk size
COOLDOWN_SECS = 2.0          # ignore repeat triggers for this many seconds after a wake

# How much trailing audio to keep around so that, the instant a wake word
# fires, there's already a usable clip of the utterance to hand to speaker
# verification (core/speaker_verify.py) — without this buffer we'd only have
# the detection *event*, not any audio to check WHO said it.
UTTERANCE_BUFFER_SECONDS = 2.5
_BUFFER_MAXLEN = int(UTTERANCE_BUFFER_SECONDS * SAMPLE_RATE / FRAME_SIZE)


class WakeWordEngine:
    """
    Always-on, fully local wake-word listener.

    Parameters
    ----------
    on_wake : Callable[[], None]
        Called (from a background thread) the moment the wake word is detected.
    wakeword_models : list[str] | None
        Which bundled openWakeWord models to load. Defaults to ["hey_jarvis"].
        Other bundled options: "alexa", "hey_mycroft", "hey_rhasspy".
    threshold : float
        Detection confidence threshold (0-1). Lower = more sensitive / more
        false triggers. Higher = stricter / may miss soft speech. 0.5 is a
        good starting point; raise to ~0.6-0.7 if it triggers on TV/music.
    input_device : int | None
        Specific microphone device index. None = system default mic.
    """

    def __init__(
        self,
        on_wake: Callable[[], None],
        wakeword_models: Optional[list] = None,
        threshold: float = 0.5,
        input_device: Optional[int] = None,
        on_error: Optional[Callable[[str], None]] = None,
    ):
        self._on_wake      = on_wake
        self._models       = wakeword_models or ["hey_jarvis"]
        self._threshold    = threshold
        self._input_device = input_device
        # BUGFIX: start() previously raised straight out of __init__'s caller
        # (run()) on any load failure — and since run() executes on a daemon
        # thread with only `except KeyboardInterrupt` around it, that
        # exception silently killed the entire JARVIS backend the moment
        # the app launched. The PyQt window stayed open and showed SLEEPING
        # forever, with no error anywhere the user could see, because the
        # crash happened before the very first log line was ever written.
        # on_error lets the caller surface this in the Activity Log instead.
        self._on_error     = on_error

        self._running   = False
        self._thread    = None
        self._oww_model = None
        self._last_wake_time = 0.0
        self._paused     = False
        self.load_error  = None   # set if start() failed to load the model

        # Rolling buffer of recent raw PCM frames + a snapshot of it taken at
        # the moment of the most recent wake-word detection. Read via
        # get_last_utterance_audio() by speaker verification. Guarded by a
        # lock since _run() writes to it from the listener thread while the
        # caller reads it from the on_wake callback (same thread, but the
        # method is safe to call from anywhere).
        self._audio_buffer = collections.deque(maxlen=_BUFFER_MAXLEN)
        self._last_utterance: Optional[np.ndarray] = None
        self._utterance_lock = threading.Lock()

    # ── lifecycle ──────────────────────────────────────────────────────────

    def start(self):
        """Loads the model and starts listening. Never raises — on failure
        it records the error in self.load_error / calls on_error(msg) and
        simply doesn't start the listener thread, so a model-loading problem
        degrades to "wake word doesn't work" with a visible explanation,
        not a silent crash of the whole app."""
        try:
            self._load_model()
        except Exception as e:
            msg = (
                f"Wake-word model failed to load ({type(e).__name__}: {e}). "
                f"Voice wake word ('Hey Jarvis') will not work this session — "
                f"typed commands still work. Try: pip install --upgrade "
                f"openwakeword onnxruntime"
            )
            print(f"[WakeWord] ❌ {msg}")
            self.load_error = msg
            if self._on_error:
                try:
                    self._on_error(msg)
                except Exception:
                    pass
            return

        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        print(f"[WakeWord] Listening offline for: {self._models} (threshold={self._threshold})")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def pause(self):
        """Temporarily ignore detections (e.g. while JARVIS itself is talking,
        so it doesn't hear its own TTS output and re-trigger)."""
        self._paused = True

    def resume(self):
        self._paused = False

    def set_threshold(self, threshold: float):
        """Update detection sensitivity at runtime (e.g. from a settings
        slider), without needing to restart the listener or reload the
        model. Lower = more sensitive / more false triggers. Higher =
        stricter / may miss soft speech."""
        self._threshold = max(0.05, min(0.95, float(threshold)))

    @property
    def threshold(self) -> float:
        return self._threshold

    def get_last_utterance_audio(self) -> Optional[np.ndarray]:
        """Returns a copy of the raw int16 mono PCM audio (at SAMPLE_RATE)
        captured in the trailing UTTERANCE_BUFFER_SECONDS window ending at
        the most recent wake-word detection. Intended to be called from
        inside (or immediately after) the on_wake callback, since that's
        the only point where "most recent detection" is unambiguous.
        Returns None if no detection has happened yet this session."""
        with self._utterance_lock:
            return None if self._last_utterance is None else self._last_utterance.copy()

    # ── setup ──────────────────────────────────────────────────────────────

    # Bundled pretrained wake-word models. As of openwakeword 0.6.0 these are
    # NO LONGER shipped inside the installed package itself — a packaging
    # change ("Remove model files", openWakeWord release v0.6.0) means
    # resources/models/ is empty on a fresh install, and the .onnx files
    # must be fetched once via openwakeword.utils.download_models(). Older
    # installs (<=0.5.x) still ship them bundled. _resolve_model_paths()
    # below handles both cases: use the file if it's already there (bundled
    # OR previously downloaded), otherwise download it once automatically.
    #
    # BUGFIX: previously _resolve_model_paths() raised FileNotFoundError the
    # instant a bundled file was missing, with a misleading suggested fix
    # ("try pip install --upgrade openwakeword" — which is actually what
    # CAUSES this on 0.6.0+, not what fixes it). Combined with start() only
    # ever logging failures via print() (see WakeWordEngine.start() and, in
    # jarvis_service.pyw, AlwaysOnListener not wiring on_error at all until
    # this fix), this produced a completely silent, permanent "Hey Jarvis
    # does nothing" with no visible cause anywhere — even after manually
    # confirming openwakeword/onnxruntime were both installed correctly.
    _BUNDLED_MODEL_FILES = {
        "hey_jarvis":  "hey_jarvis_v0.1.onnx",
        "alexa":       "alexa_v0.1.onnx",
        "hey_mycroft": "hey_mycroft_v0.1.onnx",
        "hey_marvin":  "hey_marvin_v0.1.onnx",
        "timer":       "timer_v0.1.onnx",
        "weather":     "weather_v0.1.onnx",
    }

    def _resolve_model_paths(self) -> list[str]:
        """Map friendly model names (e.g. "hey_jarvis") to actual .onnx file
        paths, downloading them once via openwakeword's own downloader if
        they aren't already present (covers openwakeword>=0.6.0, where
        models ship empty and must be fetched on first use)."""
        import os
        import openwakeword

        pkg_dir   = os.path.dirname(openwakeword.__file__)
        model_dir = os.path.join(pkg_dir, "resources", "models")

        for name in self._models:
            if name not in self._BUNDLED_MODEL_FILES:
                raise ValueError(
                    f"Unknown wake-word model '{name}'. Available bundled "
                    f"models: {list(self._BUNDLED_MODEL_FILES)}"
                )

        missing = [
            name for name in self._models
            if not os.path.exists(
                os.path.join(model_dir, self._BUNDLED_MODEL_FILES[name])
            )
        ]
        if missing:
            print(
                f"[WakeWord] Model file(s) for {missing} not found locally "
                f"(openwakeword>=0.6.0 no longer bundles them) — downloading "
                f"once now via openwakeword.utils.download_models(). This "
                f"needs internet THIS ONE TIME; detection itself stays fully "
                f"offline afterward."
            )
            try:
                import openwakeword.utils as oww_utils
                oww_utils.download_models(model_names=missing)
            except Exception as e:
                raise RuntimeError(
                    f"Auto-download of wake-word model(s) {missing} failed "
                    f"({type(e).__name__}: {e}). Check your internet "
                    f"connection, or manually run: python -c "
                    f"\"import openwakeword.utils; "
                    f"openwakeword.utils.download_models()\""
                ) from e
            print("[WakeWord] Model download complete.")

        paths = []
        for name in self._models:
            path = os.path.join(model_dir, self._BUNDLED_MODEL_FILES[name])
            if not os.path.exists(path):
                # Downloaded but still missing — something is genuinely wrong
                # (disk write failure, antivirus quarantine, etc.), not just
                # "needs a download". Fail with the real path for debugging.
                raise FileNotFoundError(
                    f"Model file still not found after download attempt: "
                    f"{path}. Check antivirus/permissions on that folder."
                )
            paths.append(path)
        return paths

    def _load_model(self):
        # BUGFIX: the correct keyword argument for "list of .onnx file paths
        # to load" has changed across openwakeword versions:
        #   - 0.4.0 and earlier: wakeword_model_paths (only option, no
        #     wakeword_models keyword exists at all — TypeError if used)
        #   - 0.6.0+: wakeword_models is the current name; the old
        #     wakeword_model_paths still works via a deprecation shim but
        #     logs a "no longer valid" warning on every call
        # Rather than hardcode one and break on whichever version isn't
        # installed, try the modern name first and fall back to the legacy
        # one if the installed version doesn't recognize it. This was
        # caught by testing this exact fix against both openwakeword 0.4.0
        # and 0.6.0 side by side — don't reduce this back to a single
        # hardcoded keyword without re-testing against both.
        from openwakeword.model import Model

        model_paths = self._resolve_model_paths()
        try:
            self._oww_model = Model(wakeword_models=model_paths)
        except TypeError:
            self._oww_model = Model(wakeword_model_paths=model_paths)

    # ── main loop ──────────────────────────────────────────────────────────

    def _run(self):
        # BUGFIX (sensitivity decay after every reply): this loop used to
        # check `if self._paused: continue` BEFORE calling predict(), which
        # meant predict() was never called at all for the entire duration of
        # every JARVIS reply (pause() is called the instant JARVIS starts
        # speaking, resume() only once it finishes). openWakeWord is not a
        # stateless per-frame classifier — it keeps a rolling buffer of
        # recent audio embeddings across consecutive predict() calls to do
        # its streaming classification. Starving it of calls for the length
        # of every reply (which can be several seconds) left that buffer
        # cold, so detection accuracy quietly degraded turn after turn:
        # reliable right after boot (warmed up for a while before first
        # use), then progressively worse after each reply, until "Hey
        # Jarvis" stopped registering at all. Fix: ALWAYS call predict() so
        # the model's internal state stays warm and continuous — only skip
        # ACTING on a high score while paused (which is pause()'s actual
        # job: don't let JARVIS hear its own voice and re-trigger itself).
        #
        # Also: a single bad frame/predict() call used to take the entire
        # background thread down silently (caught only by the outer
        # try/except, which then just exits — "Hey Jarvis" stops working
        # forever with nothing visible anywhere). The inner try/except below
        # logs and keeps the loop alive instead of dying on a transient
        # error; the outer one now also tries one automatic stream restart
        # rather than going permanently silent.
        restart_attempts = 0
        while self._running and restart_attempts <= 1:
            try:
                with sd.InputStream(
                    samplerate=SAMPLE_RATE,
                    channels=1,
                    dtype="int16",
                    blocksize=FRAME_SIZE,
                    device=self._input_device,
                ) as stream:
                    while self._running:
                        try:
                            frame, _overflowed = stream.read(FRAME_SIZE)

                            pcm = frame.flatten().astype(np.int16)
                            self._audio_buffer.append(pcm)
                            predictions = self._oww_model.predict(pcm)

                            if self._paused:
                                continue

                            for model_name, score in predictions.items():
                                if score >= self._threshold:
                                    now = time.time()
                                    if now - self._last_wake_time < COOLDOWN_SECS:
                                        continue
                                    self._last_wake_time = now
                                    print(f"[WakeWord] 🔔 Detected '{model_name}' (score={score:.2f})")
                                    # Snapshot the trailing audio buffer BEFORE
                                    # calling on_wake(), so speaker_verify has
                                    # a clip covering the utterance that
                                    # triggered this detection, not whatever
                                    # accumulates while on_wake() is running.
                                    with self._utterance_lock:
                                        self._last_utterance = (
                                            np.concatenate(list(self._audio_buffer))
                                            if self._audio_buffer else None
                                        )
                                    try:
                                        self._on_wake()
                                    except Exception as cb_err:
                                        print(f"[WakeWord] on_wake callback error: {cb_err}")
                                    # Reset internal model state so the same
                                    # utterance doesn't immediately re-trigger
                                    # across frames.
                                    self._oww_model.reset()
                        except Exception as frame_err:
                            # One bad frame/predict() call should never kill
                            # the whole listener for the rest of the app's
                            # life. Log it, keep listening.
                            print(f"[WakeWord] ⚠️ Frame error (continuing): "
                                  f"{type(frame_err).__name__}: {frame_err}")
                # _running was set False (normal stop()) — exit cleanly.
                return
            except Exception as e:
                restart_attempts += 1
                print(f"[WakeWord] Fatal listener error: {e}")
                print("[WakeWord] Check that a microphone is connected and not in use "
                      "exclusively by another application.")
                if self._running and restart_attempts <= 1:
                    print("[WakeWord] Attempting one automatic restart of the listener stream...")
                    time.sleep(1.0)
                else:
                    if self._on_error and self._running:
                        try:
                            self._on_error(
                                f"Wake-word listener stopped unexpectedly ({type(e).__name__}: {e}). "
                                f"Restart JARVIS to re-enable voice wake-up; typed commands still work."
                            )
                        except Exception:
                            pass