import asyncio
import base64
import io
import json
import re
import os
import sys
import time
import threading
import sounddevice as sd
import numpy as np
from pathlib import Path

# CRASH FIX: cv2 (webcam capture) and mss (screenshot capture) were hard,
# unguarded top-level imports — if either package wasn't installed, the
# ENTIRE app (jarvis_service.pyw) crashed at startup before anything else
# could run, with no graceful fallback (unlike PIL.Image just below, which
# already uses the correct try/except pattern). Most users never touch the
# screenshot/webcam tools in a typical session, so a missing optional
# dependency shouldn't be able to take down the whole assistant. Now this
# follows the exact same soft-fail pattern as PIL: import what's available,
# set an _OK flag, and only raise a clear, actionable error if a caller
# actually tries to use the specific feature that needs the missing package.
try:
    import cv2
    _CV2_OK = True
except ImportError:
    _CV2_OK = False

try:
    import mss
    import mss.tools
    _MSS_OK = True
except ImportError:
    _MSS_OK = False

try:
    import PIL.Image
    _PIL_OK = True
except ImportError:
    _PIL_OK = False

from google import genai
from google.genai import types

# ── Phase 6 improvements ──────────────────────────────────────────────────────
try:
    import numpy as _np
    _NP_OK = True
except ImportError:
    _NP_OK = False

def get_base_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent

BASE_DIR        = get_base_dir()
API_CONFIG_PATH = BASE_DIR / "config" / "api_keys.json"

LIVE_MODEL          = "models/gemini-2.5-flash-native-audio-preview-12-2025"
CHANNELS            = 1
RECEIVE_SAMPLE_RATE = 24000
CHUNK_SIZE          = 1024

IMG_MAX_W = 640
IMG_MAX_H = 360
JPEG_Q    = 55

try:
    from core.taint_tracker import SYSTEM_PROMPT_GUARDRAIL
except ImportError:
    SYSTEM_PROMPT_GUARDRAIL = ""

SYSTEM_PROMPT = (
    "You are JARVIS from Iron Man movies. "
    "Analyze images with technical precision and intelligence. "
    "Help the user in a way they can understand — don't be overly complex. "
    "Be direct and brief. Respond naturally.\n\n"
    + SYSTEM_PROMPT_GUARDRAIL
)

# ── Phase 6: mode-specific system prompts ─────────────────────────────────────
SYSTEM_PROMPT_GAME = (
    "You are JARVIS, Iron Man's combat AI — real-time tactical screen analyst. "
    "You are in GAME MODE. Analyse each frame and give sharp, actionable intel: "
    "enemy positions, health levels, objectives, threats, recommended moves. "
    "Be extremely terse — max 1 sentence per frame. Never repeat yourself. "
    "Address the user as 'sir'. Prioritise speed over completeness."
)

SYSTEM_PROMPT_DOCUMENT = (
    "You are JARVIS from Iron Man. You are reading a document on screen. "
    "Extract the key information: title, main points, important numbers/dates, "
    "action items, and any errors or anomalies. "
    "Be thorough but concise. Structure your response clearly. "
    "Address the user as 'sir'."
)

SYSTEM_PROMPT_AUTOFILL = (
    "You are JARVIS from Iron Man. You see a form on screen. "
    "Identify every visible field label and its current value (or 'empty'). "
    "List them as JSON: [{\"field\": \"...\", \"value\": \"...\", \"needs_fill\": true/false}]. "
    "Output ONLY the JSON array — no preamble, no markdown fences."
)

# ── Phase 6.5: Fusion mode — screen + camera together ──────────────────────
SYSTEM_PROMPT_FUSION = (
    "You are JARVIS from Iron Man. You are shown TWO images in this turn: "
    "the FIRST is the user's screen, the SECOND is their webcam. "
    "Correlate them — read the user's expression, posture, or reaction in the "
    "webcam image, and connect it to what's actually happening on screen "
    "(an error, a long document, a game, a video call, etc). "
    "If something on screen looks like a problem (error, crash, confusing UI) "
    "and the user looks stuck or frustrated, proactively offer to help. "
    "Be concise — max 2 short sentences. Address the user as 'sir'."
)

# Game-mode polling interval (seconds between automatic screen captures)
GAME_MODE_INTERVAL = 4.0

# Frame-diff threshold for smart game mode (0-100; higher = less sensitive)
# Frames with a mean pixel change below this are skipped silently.
# 3.5 = sensitive enough to catch video motion (talking heads, live streams)
GAME_MODE_DIFF_THRESHOLD = 3.5

# Speed presets (seconds) — set via voice "set game mode speed to fast/normal/slow"
GAME_MODE_SPEEDS = {"fast": 2.0, "normal": 4.0, "slow": 8.0}


def _get_api_key() -> str:
    try:
        with open(API_CONFIG_PATH, "r", encoding="utf-8") as f:
            keys = json.load(f)
        key = keys.get("gemini_api_key", "")
        if not key:
            raise ValueError("gemini_api_key not found")
        return key
    except Exception as e:
        raise RuntimeError(f"Could not load API key: {e}")


def _get_camera_index() -> int:
    try:
        with open(API_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if "camera_index" in cfg:
            return int(cfg["camera_index"])
    except Exception:
        pass

    print("[Camera] 🔍 No camera index in config. Auto-detecting...")
    best_index = 0

    for idx in range(6):
        cap = cv2.VideoCapture(idx, cv2.CAP_DSHOW)
        if not cap.isOpened():
            cap.release()
            continue
        for _ in range(5):
            cap.read()
        ret, frame = cap.read()
        cap.release()
        if ret and frame is not None and frame.mean() > 5:
            best_index = idx
            print(f"[Camera] ✅ Camera found at index {idx} — saving to config.")
            break
        else:
            print(f"[Camera] ⚠️  Index {idx}: no valid frame.")

    try:
        cfg = {}
        if API_CONFIG_PATH.exists():
            with open(API_CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        cfg["camera_index"] = best_index
        with open(API_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=4)
        print(f"[Camera] 💾 Camera index {best_index} saved to config.")
    except Exception as e:
        print(f"[Camera] ⚠️  Could not save camera index: {e}")

    return best_index


def _to_jpeg(img_bytes: bytes) -> bytes:
    if not _PIL_OK:
        return img_bytes
    img = PIL.Image.open(io.BytesIO(img_bytes)).convert("RGB")
    img.thumbnail([IMG_MAX_W, IMG_MAX_H], PIL.Image.BILINEAR)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=JPEG_Q, optimize=False)
    return buf.getvalue()


def _capture_screenshot(monitor_index: int | None = None) -> bytes:
    """Capture a screenshot.

    monitor_index: 1-based index of a specific monitor, or None to auto-select.
    None uses the value from config ("monitor_index" key, default 1).
    Pass 0 to capture ALL monitors merged into one wide image.
    """
    if not _MSS_OK:
        raise RuntimeError(
            "Screenshot capture needs the 'mss' package, which isn't "
            "installed. Run: pip install mss"
        )
    if monitor_index is None:
        try:
            with open(API_CONFIG_PATH, "r", encoding="utf-8") as _f:
                monitor_index = int(json.load(_f).get("monitor_index", 1))
        except Exception:
            monitor_index = 1
    with mss.mss() as sct:
        # monitor 0 = all monitors combined; 1..N = individual monitors
        idx = max(0, min(monitor_index, len(sct.monitors) - 1))
        shot      = sct.grab(sct.monitors[idx])
        png_bytes = mss.tools.to_png(shot.rgb, shot.size)
    return _to_jpeg(png_bytes)


def _capture_tab_bar(monitor_index: int | None = None) -> bytes:
    """Capture and upscale only the top 90px of the screen (browser tab bar).
    Returned as JPEG at 2x resolution so Gemini Vision can read small tab text.
    Falls back to full screenshot if PIL is not available.
    """
    if not _MSS_OK or not _PIL_OK:
        return _capture_screenshot(monitor_index=monitor_index)
    with mss.mss() as sct:
        _mon_idx = monitor_index if monitor_index is not None else 1
        _mon_idx = max(1, min(_mon_idx, len(sct.monitors) - 1))
        mon   = sct.monitors[_mon_idx]
        # Crop: full width, top 90 pixels only
        region = {
            "left":   mon["left"],
            "top":    mon["top"],
            "width":  mon["width"],
            "height": min(90, mon["height"]),
            "mon":    1,
        }
        shot      = sct.grab(region)
        png_bytes = mss.tools.to_png(shot.rgb, shot.size)
    # Upscale 2x so tiny tab text is readable
    img = PIL.Image.open(io.BytesIO(png_bytes)).convert("RGB")
    w, h = img.size
    img = img.resize((w * 2, h * 2), PIL.Image.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85, optimize=False)
    return buf.getvalue()


def _screenshot_to_numpy(img_bytes: bytes):
    """Convert screenshot bytes to a grayscale numpy array for frame diffing.
    Returns None if numpy or PIL is unavailable."""
    if not _NP_OK or not _PIL_OK:
        return None
    try:
        img = PIL.Image.open(io.BytesIO(img_bytes)).convert("L")  # greyscale
        img = img.resize((160, 90))  # tiny for fast comparison
        return _np.array(img, dtype=_np.float32)
    except Exception:
        return None


def _capture_camera() -> bytes:
    if not _CV2_OK:
        raise RuntimeError(
            "Camera capture needs the 'opencv-python' package, which isn't "
            "installed. Run: pip install opencv-python"
        )
    camera_index = _get_camera_index()
    cap = cv2.VideoCapture(camera_index, cv2.CAP_DSHOW)
    if not cap.isOpened():
        raise RuntimeError(f"Camera could not be opened: index {camera_index}")
    for _ in range(10):
        cap.read()
    ret, frame = cap.read()
    cap.release()
    if not ret or frame is None:
        raise RuntimeError("Could not capture camera frame.")
    if _PIL_OK:
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        img = PIL.Image.fromarray(rgb)
        img.thumbnail([IMG_MAX_W, IMG_MAX_H], PIL.Image.BILINEAR)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=JPEG_Q, optimize=False)
        return buf.getvalue()
    _, buf = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, JPEG_Q])
    return buf.tobytes()


class _LiveSession:

    def __init__(self):
        self._loop:            asyncio.AbstractEventLoop | None = None
        self._thread:          threading.Thread | None          = None
        self._session                                           = None
        self._out_queue:       asyncio.Queue | None             = None
        self._audio_in:        asyncio.Queue | None             = None
        self._ready:           threading.Event                  = threading.Event()
        self._player                                            = None
        self._send_lock:       asyncio.Lock | None              = None
        # Phase 6: runtime system-prompt swap + text-only callback
        self._system_prompt:   str                              = SYSTEM_PROMPT
        self._text_callback                                     = None

    def start(self, player=None):
        if self._thread and self._thread.is_alive():
            return
        self._player = player
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="VisionSessionThread"
        )
        self._thread.start()
        ok = self._ready.wait(timeout=20)
        if not ok:
            raise RuntimeError("Vision session did not start within 20s.")
        print("[ScreenProcess] ✅ Vision session ready (no mic)")

    def _run_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._main())

    async def _main(self):
        self._out_queue = asyncio.Queue(maxsize=30)
        self._audio_in  = asyncio.Queue()
        self._send_lock = asyncio.Lock()

        client = genai.Client(
            api_key=_get_api_key(),
            http_options={"api_version": "v1beta"}
        )

        config = types.LiveConnectConfig(
            response_modalities=["AUDIO"],
            output_audio_transcription={},
            system_instruction=self._system_prompt,
            speech_config=types.SpeechConfig(
                voice_config=types.VoiceConfig(
                    prebuilt_voice_config=types.PrebuiltVoiceConfig(
                        voice_name="Charon"
                    )
                )
            ),
        )

        while True:
            try:
                print("[ScreenProcess] 🔌 Vision session connecting...")
                async with client.aio.live.connect(model=LIVE_MODEL, config=config) as session:
                    self._session = session
                    self._ready.set()
                    print("[ScreenProcess] ✅ Vision session connected")
                    # Python 3.10 compatible replacement for asyncio.TaskGroup
                    # (TaskGroup requires Python 3.11+)
                    tasks = [
                        asyncio.ensure_future(self._send_loop()),
                        asyncio.ensure_future(self._recv_loop()),
                        asyncio.ensure_future(self._play_loop()),
                    ]
                    try:
                        done, pending = await asyncio.wait(
                            tasks, return_when=asyncio.FIRST_EXCEPTION
                        )
                        # Cancel remaining tasks cleanly
                        for t in pending:
                            t.cancel()
                            try:
                                await t
                            except (asyncio.CancelledError, Exception):
                                pass
                        # Re-raise the exception from the failed task
                        for t in done:
                            if t.exception():
                                raise t.exception()
                    except Exception:
                        for t in tasks:
                            t.cancel()
                        raise
            except Exception as e:
                print(f"[ScreenProcess] ⚠️ Disconnected: {e} — reconnecting...")
                self._session = None
                self._ready.clear()
                await asyncio.sleep(2)
                self._ready.set()

    async def _send_loop(self):
        while True:
            item = await self._out_queue.get()
            if self._session:
                # Dual-image fusion turn (screen + camera together)
                # FIX: Gemini Live API crashes (error 1011) if two inline_data
                # images are packed into one turn's parts list.  Send them as
                # three sequential partial turns instead: screen → camera → text.
                if len(item) == 5:
                    image_a, mime_a, image_b, mime_b, user_text = item
                    if not image_a and not image_b:
                        continue
                    try:
                        async with self._send_lock:
                            # Part 1: screen image (turn still open)
                            if image_a:
                                await self._session.send_client_content(
                                    turns={"parts": [{"inline_data": {
                                        "mime_type": mime_a,
                                        "data": base64.b64encode(image_a).decode("utf-8"),
                                    }}]},
                                    turn_complete=False,
                                )
                                await asyncio.sleep(0.05)
                            # Part 2: camera image (turn still open)
                            if image_b:
                                await self._session.send_client_content(
                                    turns={"parts": [{"inline_data": {
                                        "mime_type": mime_b,
                                        "data": base64.b64encode(image_b).decode("utf-8"),
                                    }}]},
                                    turn_complete=False,
                                )
                                await asyncio.sleep(0.05)
                            # Part 3: text prompt — closes the turn
                            await self._session.send_client_content(
                                turns={"parts": [{"text": user_text}]},
                                turn_complete=True,
                            )
                        print("[ScreenProcess] ✅ Fusion images sent (sequential partial turns)")
                    except Exception as e:
                        print(f"[ScreenProcess] ⚠️ Fusion send error: {e}")
                        raise
                    continue

                image_bytes, mime_type, user_text = item
                # Skip empty-image items (e.g. from set_system_prompt calls)
                # — sending b"" causes WebSocket 1007 and kills the session.
                if not image_bytes:
                    continue
                try:
                    b64 = base64.b64encode(image_bytes).decode("utf-8")
                    await self._session.send_client_content(
                        turns={
                            "parts": [
                                {"inline_data": {"mime_type": mime_type, "data": b64}},
                                {"text": user_text}
                            ]
                        },
                        turn_complete=True
                    )
                    print("[ScreenProcess] ✅ Image sent")
                except Exception as e:
                    print(f"[ScreenProcess] ⚠️ Send error: {e}")
                    # Re-raise so asyncio.wait() sees FIRST_EXCEPTION and
                    # the outer while-loop reconnects the session cleanly.
                    raise

    async def _recv_loop(self):
        transcript_buf: list[str] = []
        try:
            async for response in self._session.receive():
                if response.data:
                    await self._audio_in.put(response.data)
                sc = response.server_content
                if not sc:
                    continue
                if sc.output_transcription and sc.output_transcription.text:
                    chunk = sc.output_transcription.text.strip()
                    if chunk:
                        transcript_buf.append(chunk)
                if sc.turn_complete:
                    full = re.sub(r'\s+', ' ', " ".join(transcript_buf)).strip()
                    # SKIP guard: ambient glance prompt tells JARVIS to respond
                    # with exactly "SKIP" when the screen looks normal and there
                    # is nothing to mention.  Drop that response entirely so the
                    # user never hears a random word every 15 minutes.
                    if full and full.strip().upper() == "SKIP":
                        print("[ScreenProcess] 🔇 Ambient glance: nothing notable — staying silent")
                        transcript_buf = []
                        continue
                    if full:
                        if self._player:
                            self._player.write_log(f"Jarvis: {full}")
                            print(f"[ScreenProcess] 💬 {full}")
                        if self._text_callback:
                            try:
                                self._text_callback(full)
                            except Exception as _cb_e:
                                print(f"[ScreenProcess] ⚠️ text_callback error: {_cb_e}")
                            self._text_callback = None
                    transcript_buf = []
        except Exception as e:
            print(f"[ScreenProcess] ⚠️ Recv error: {e}")
            transcript_buf = []
            # Re-raise so asyncio.wait() sees FIRST_EXCEPTION and the outer
            # while-loop triggers a clean reconnect.
            raise

    async def _play_loop(self):
        stream = sd.RawOutputStream(
            samplerate=RECEIVE_SAMPLE_RATE,
            channels=CHANNELS,
            dtype="int16",
            blocksize=CHUNK_SIZE,
        )
        stream.start()
        try:
            while True:
                chunk = await self._audio_in.get()
                await asyncio.to_thread(stream.write, chunk)
        except Exception as e:
            print(f"[ScreenProcess] ❌ Play error: {e}")
            raise
        finally:
            stream.stop()
            stream.close()

    def analyze(self, image_bytes: bytes, mime_type: str, user_text: str):
        if not self._loop:
            return
        asyncio.run_coroutine_threadsafe(
            self._out_queue.put((image_bytes, mime_type, user_text)),
            self._loop
        )

    def analyze_dual(self, image_a: bytes, mime_a: str,
                      image_b: bytes, mime_b: str, user_text: str):
        """Fusion mode — send TWO images (typically screen + camera) in the
        SAME turn so the model can correlate them (e.g. user's expression
        against what's on screen), instead of two separate disconnected
        turns. Falls back silently if the session isn't ready."""
        if not self._loop:
            return
        asyncio.run_coroutine_threadsafe(
            self._out_queue.put((image_a, mime_a, image_b, mime_b, user_text)),
            self._loop
        )

    def analyze_text_only(self, image_bytes: bytes, mime_type: str,
                          user_text: str, callback=None):
        """Like analyze() but registers a one-shot callback for the transcript
        (used by auto-fill to capture the JSON response as text, not audio)."""
        self._text_callback = callback
        self.analyze(image_bytes, mime_type, user_text)

    def set_system_prompt(self, prompt: str):
        """Swap the system prompt. Takes effect on the next session reconnect.
        We deliberately do NOT inject an empty-image turn here — sending b""
        to the Gemini Live API causes WebSocket error 1007 (invalid payload)
        which kills the session. The new prompt is picked up automatically
        after the next natural disconnect/reconnect cycle.
        """
        self._system_prompt = prompt

    def is_ready(self) -> bool:
        return self._session is not None


_live       = _LiveSession()
_started    = False
_start_lock = threading.Lock()

# ── Phase 6: Game Mode state ──────────────────────────────────────────────────
_game_mode_active   = False
_game_mode_thread:  threading.Thread | None = None
_game_mode_stop     = threading.Event()
_game_mode_player   = None
_game_mode_interval = GAME_MODE_INTERVAL  # mutable at runtime via set_game_mode_speed()


def set_game_mode_speed(speed_name: str) -> str:
    """Change game mode polling interval at runtime.
    speed_name: 'fast' (2s), 'normal' (4s), 'slow' (8s)
    """
    global _game_mode_interval
    key = speed_name.lower().strip()
    if key not in GAME_MODE_SPEEDS:
        return f"Unknown speed '{speed_name}', sir. Use fast, normal, or slow."
    _game_mode_interval = GAME_MODE_SPEEDS[key]
    print(f"[ScreenProcess] 🎮 Speed set to {key} ({_game_mode_interval}s)")
    return f"[GAME_MODE_SPEED] Game mode speed set to {key} — {_game_mode_interval:.0f} second intervals."


def _ensure_started(player=None):
    global _started
    with _start_lock:
        if not _started:
            _live.start(player=player)
            _started = True
        elif player is not None:
            _live._player = player


# ── Phase 6: Game Mode ────────────────────────────────────────────────────────

# Max seconds of silence before game mode speaks regardless of frame diff
GAME_MODE_MAX_SILENCE = 20.0

def _game_mode_loop():
    """Background thread: smart frame-diff game mode.

    Captures the screen every GAME_MODE_INTERVAL seconds. Compares each frame
    to the previous using mean absolute pixel difference (greyscale 160x90).
    Skips silent frames below GAME_MODE_DIFF_THRESHOLD BUT guarantees at least
    one update every GAME_MODE_MAX_SILENCE seconds so you always know it's alive.
    """
    print("[ScreenProcess] 🎮 Game mode loop started (smart frame-diff active)")
    prev_frame      = None
    skipped         = 0
    last_spoke_time = 0.0   # timestamp of last analysis sent

    while not _game_mode_stop.is_set():
        try:
            import time as _time
            now  = _time.monotonic()
            img  = _capture_screenshot()
            mime = "image/jpeg" if _PIL_OK else "image/png"

            # ── Frame diff check ──────────────────────────────────────────
            curr_frame   = _screenshot_to_numpy(img)
            force_update = (now - last_spoke_time) >= GAME_MODE_MAX_SILENCE

            if curr_frame is not None and prev_frame is not None and not force_update:
                diff = float(_np.mean(_np.abs(curr_frame - prev_frame)))
                if diff < GAME_MODE_DIFF_THRESHOLD:
                    skipped += 1
                    if skipped % 5 == 0:
                        print(f"[ScreenProcess] 🎮 Skipped {skipped} unchanged frames "
                              f"(diff={diff:.1f}, silent for {now - last_spoke_time:.0f}s)")
                    _game_mode_stop.wait(timeout=_game_mode_interval)
                    continue
                skipped = 0
                print(f"[ScreenProcess] 🎮 Frame changed (diff={diff:.1f}) — analysing")
            elif force_update:
                print(f"[ScreenProcess] 🎮 Max silence reached ({GAME_MODE_MAX_SILENCE}s) — forcing update")

            prev_frame      = curr_frame
            last_spoke_time = now
            _live.analyze(img, mime,
                "Tactical update — what do you see happening on screen right now? One concise sentence.")

        except Exception as e:
            print(f"[ScreenProcess] ⚠️ Game mode capture: {e}")

        _game_mode_stop.wait(timeout=_game_mode_interval)

    print("[ScreenProcess] 🎮 Game mode loop stopped")


def start_game_mode(player=None) -> str:
    """Activate continuous real-time screen analysis for gaming.
    If already active, restarts cleanly instead of layering a second instance.
    """
    global _game_mode_active, _game_mode_thread, _game_mode_player
    if _game_mode_active:
        # Stop the existing instance cleanly before restarting
        print("[ScreenProcess] 🎮 Game mode already active — restarting cleanly")
        _game_mode_stop.set()
        if _game_mode_thread and _game_mode_thread.is_alive():
            _game_mode_thread.join(timeout=3)
        _game_mode_active = False
    _game_mode_player = player
    _ensure_started(player=player)
    # Swap to game-mode system prompt
    _live.set_system_prompt(SYSTEM_PROMPT_GAME)
    _game_mode_stop.clear()
    _game_mode_active = True
    _game_mode_thread = threading.Thread(target=_game_mode_loop, daemon=True, name="GameModeThread")
    _game_mode_thread.start()
    if player:
        try:
            player.set_game_mode(True)
        except Exception:
            pass
    print("[ScreenProcess] 🎮 Game mode ACTIVE")
    return "[GAME_MODE_STARTED] Continuous tactical screen analysis active."


def stop_game_mode(player=None) -> str:
    """Deactivate game mode and return to normal vision."""
    global _game_mode_active
    if not _game_mode_active:
        return "Game mode is not currently active, sir."
    _game_mode_stop.set()
    _game_mode_active = False
    _live.set_system_prompt(SYSTEM_PROMPT)
    if player or _game_mode_player:
        try:
            (player or _game_mode_player).set_game_mode(False)
        except Exception:
            pass
    print("[ScreenProcess] 🎮 Game mode DEACTIVATED")
    return "[GAME_MODE_STOPPED] Returning to standard vision mode."


def is_game_mode_active() -> bool:
    return _game_mode_active


# ── Phase 6: Read / Summarise Document ───────────────────────────────────────

def read_document_on_screen(player=None) -> bool:
    """Capture the screen and ask JARVIS to read and summarise the document."""
    _ensure_started(player=player)
    try:
        img = _capture_screenshot()
        mime = "image/jpeg" if _PIL_OK else "image/png"
    except Exception as e:
        print(f"[ScreenProcess] ❌ Document capture failed: {e}")
        return False
    # Temporarily switch system prompt for a thorough document read
    _live.set_system_prompt(SYSTEM_PROMPT_DOCUMENT)
    _live.analyze(img, mime,
        "Please read and summarise this document for me. "
        "Extract all key information, headings, action items, and important values.")
    # Restore standard prompt after a brief delay
    def _restore():
        import time as _t; _t.sleep(6)
        _live.set_system_prompt(SYSTEM_PROMPT)
    threading.Thread(target=_restore, daemon=True).start()
    return True


# ── Phase 6: Auto-Fill Forms ─────────────────────────────────────────────────

def analyze_form_on_screen(player=None) -> list[dict]:
    """Capture the screen, detect form fields, and return structured data.

    Returns a list of dicts: [{"field": "...", "value": "...", "needs_fill": bool}]
    Caller (tool dispatch) uses browser_control to fill the fields.
    """
    _ensure_started(player=player)
    result_holder: list[list[dict]] = [[]]
    done = threading.Event()

    def _on_json(text: str):
        import re, json as _json
        try:
            clean = re.sub(r'```json|```', '', text).strip()
            data  = _json.loads(clean)
            result_holder[0] = data if isinstance(data, list) else []
        except Exception as e:
            print(f"[ScreenProcess] ⚠️ Form JSON parse error: {e}")
        done.set()

    try:
        img  = _capture_screenshot()
        mime = "image/jpeg" if _PIL_OK else "image/png"
    except Exception as e:
        print(f"[ScreenProcess] ❌ Form capture failed: {e}")
        return []

    _live.set_system_prompt(SYSTEM_PROMPT_AUTOFILL)
    _live.analyze_text_only(img, mime,
        "List every form field visible. Return JSON only.", callback=_on_json)
    done.wait(timeout=15)
    _live.set_system_prompt(SYSTEM_PROMPT)
    return result_holder[0]




def _speak_error(player, message: str):
    """Speak an error message via edge-tts so silence is never ambiguous."""
    try:
        import asyncio as _asyncio, edge_tts as _etts
        async def _say():
            comm = _etts.Communicate(message, voice="en-GB-RyanNeural")
            async for chunk in comm.stream():
                if chunk["type"] == "audio" and player:
                    try:
                        player._audio_queue.put_nowait(chunk["data"])
                    except Exception:
                        pass
        _asyncio.run(_say())
    except Exception as e:
        print(f"[ScreenProcess] ⚠️ speak_error fallback: {e}")
        if player:
            player.write_log(f"Jarvis: {message}")


def _save_screenshot_to_disk() -> str:
    """Save a timestamped screenshot to <project>/screenshots/ and return the path."""
    import datetime
    base  = get_base_dir()
    folder = base / "screenshots"
    folder.mkdir(exist_ok=True)
    ts    = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path  = folder / f"JARVIS_{ts}.jpg"
    img_bytes = _capture_screenshot()
    path.write_bytes(img_bytes)
    return str(path)


def screen_process(
    parameters:     dict,
    response:       str | None = None,
    player=None,
    session_memory=None,
) -> bool:
    """Phase 6 — Vision & Screen Awareness entry point.

    Supported modes (via parameters["mode"]):
      "analyze"        — (default) one-shot screenshot/camera question
      "analyze_tabs"   — zoomed tab-bar capture for reading browser tabs
      "game_start"     — start continuous real-time game analysis
      "game_stop"      — stop game mode
      "game_speed"     — change game mode speed (fast/normal/slow via parameters["speed"])
      "read_document"  — read & summarise document on screen
      "auto_fill"      — detect form fields (result spoken + logged)
      "save_screen"    — save a screenshot to disk and confirm verbally

    The "angle" key selects source: "screen" (default), "camera", or
    "both" (fusion — sends screen + camera together in one correlated turn).
    """
    params    = parameters or {}
    mode      = params.get("mode", "analyze").lower().strip()
    user_text = (params.get("text") or params.get("user_text", "")).strip()
    angle     = params.get("angle", "screen").lower().strip()

    print(f"[ScreenProcess] mode={mode!r}  angle={angle!r}  text={user_text!r}")

    # ── game mode control ────────────────────────────────────────────────────
    if mode == "game_start":
        msg = start_game_mode(player=player)
        if player:
            player.write_log(f"Jarvis: {msg}")
        return True

    if mode == "game_stop":
        msg = stop_game_mode(player=player)
        if player:
            player.write_log(f"Jarvis: {msg}")
        return True

    if mode == "game_speed":
        speed = params.get("speed", "normal")
        msg   = set_game_mode_speed(speed)
        if player:
            player.write_log(f"Jarvis: {msg}")
        return True

    # ── save screenshot ──────────────────────────────────────────────────────
    if mode == "save_screen":
        try:
            path = _save_screenshot_to_disk()
            msg  = f"Screenshot saved, sir. File: {Path(path).name}"
            print(f"[ScreenProcess] 📸 {path}")
        except Exception as e:
            msg = f"Screenshot failed, sir. Error: {e}"
            print(f"[ScreenProcess] ⚠️ save_screen: {e}")
        if player:
            player.write_log(f"Jarvis: {msg}")
        return True

    # ── document read ────────────────────────────────────────────────────────
    if mode == "read_document":
        _ensure_started(player=player)
        return read_document_on_screen(player=player)

    # ── auto-fill ────────────────────────────────────────────────────────────
    if mode == "auto_fill":
        _ensure_started(player=player)
        fields = analyze_form_on_screen(player=player)
        if not fields:
            err = "I could not detect any form fields on screen, sir."
            _speak_error(player, err)
            return False
        needs_fill = [f for f in fields if f.get("needs_fill")]
        summary = (
            f"I found {len(fields)} field(s) on the form. "
            f"{len(needs_fill)} need filling. "
            + (", ".join(f["field"] for f in needs_fill[:5]) if needs_fill else "All fields appear filled.")
        )
        print(f"[ScreenProcess] Form fields: {fields}")
        if player:
            player.write_log(f"Jarvis: {summary}")
        return True

    # ── analyze_tabs: zoomed tab bar for reading browser tabs ────────────────
    if mode == "analyze_tabs":
        _ensure_started(player=player)
        try:
            tab_img   = _capture_tab_bar()
            full_img  = _capture_screenshot()
            mime_type = "image/jpeg"
            # Send both: zoomed tab bar first, then full screen for context
            if not user_text:
                user_text = ("List every browser tab title you can read in the top strip. "
                             "Then briefly describe the main content visible on screen.")
            print(f"[ScreenProcess] 🔍 Tab bar captured ({len(tab_img)} bytes) + full screen ({len(full_img)} bytes)")
            # Queue tab bar image with the question, then full screen as context
            _live.analyze(tab_img,  mime_type, user_text)
            _live.analyze(full_img, mime_type, "And here is the full screen for context.")
        except Exception as e:
            err = f"Tab analysis failed, sir. {e}"
            print(f"[ScreenProcess] ⚠️ analyze_tabs: {e}")
            _speak_error(player, err)
            return False
        return True

    # ── default: one-shot analyze ────────────────────────────────────────────
    if not user_text:
        user_text = "What do you see on screen? Describe it briefly."

    _ensure_started(player=player)

    # ── fusion: screen + camera together, correlated in one turn ────────────
    if angle == "both":
        try:
            screen_bytes = _capture_screenshot()
            screen_mime  = "image/jpeg" if _PIL_OK else "image/png"
        except Exception as e:
            print(f"[ScreenProcess] ⚠️ Fusion screen capture failed: {e}")
            screen_bytes, screen_mime = b"", "image/jpeg"
        try:
            camera_bytes = _capture_camera()
            camera_mime  = "image/jpeg"
        except Exception as e:
            print(f"[ScreenProcess] ⚠️ Fusion camera capture failed: {e}")
            camera_bytes, camera_mime = b"", "image/jpeg"

        if not screen_bytes and not camera_bytes:
            _speak_error(player, "Vision capture failed on both screen and camera, sir.")
            return False

        fusion_text = user_text if params.get("text") else (
            "Look at my screen and my webcam together. What's going on, "
            "and do I look like I need help with anything?"
        )
        _live.set_system_prompt(SYSTEM_PROMPT_FUSION)
        print(f"[ScreenProcess] 🔗 Fusion: screen={len(screen_bytes)}B camera={len(camera_bytes)}B")
        _live.analyze_dual(screen_bytes, screen_mime, camera_bytes, camera_mime, fusion_text)

        def _restore():
            import time as _t; _t.sleep(6)
            _live.set_system_prompt(SYSTEM_PROMPT)
        threading.Thread(target=_restore, daemon=True).start()
        return True

    try:
        if angle == "camera":
            image_bytes = _capture_camera()
            mime_type   = "image/jpeg"
            print("[ScreenProcess] Camera captured")
        else:
            image_bytes = _capture_screenshot()
            mime_type   = "image/jpeg" if _PIL_OK else "image/png"
            print("[ScreenProcess] Screen captured")
    except Exception as e:
        import traceback; traceback.print_exc()
        err = f"Vision capture failed, sir. {e}"
        print(f"[ScreenProcess] Capture error: {e}")
        _speak_error(player, "Vision capture failed, sir. Please try again.")
        return False

    print(f"[ScreenProcess] {len(image_bytes)} bytes -> sending")
    _live.analyze(image_bytes, mime_type, user_text)
    return True


def warmup_session(player=None):
    try:
        _ensure_started(player=player)
    except Exception as e:
        print(f"[ScreenProcess] ⚠️ Warmup error: {e}")


if __name__ == "__main__":
    print("[TEST] screen_processor.py v8 — image-only session")
    print("=" * 50)
    mode    = input("screen / camera (default: screen): ").strip().lower() or "screen"
    request = input("Question (Enter for default): ").strip() or "What do you see? Be brief."

    t0 = time.perf_counter()
    warmup_session()
    print(f"Session ready — {time.perf_counter()-t0:.2f}s\n")

    t1     = time.perf_counter()
    result = screen_process({"angle": mode, "text": request}, player=None)
    print(f"Sent — {time.perf_counter()-t1:.3f}s | audio incoming...")
    time.sleep(8)
    print(f"\n{'✅' if result else '❌'}")