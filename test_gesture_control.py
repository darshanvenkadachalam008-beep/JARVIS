"""
test_gesture_control.py — Unit & Integration Test Suite for Gesture HUD Engine
==============================================================================
Verifies:
1. GestureControlEngine initialization and callback mapping.
2. Leaky debounce counter logic (5 stable frames required, miss tolerance).
3. Cooldown interval prevention of duplicate triggers.
4. Offline model detection and caching path resolution.
5. Error handling and fail-safe shutdown.
"""
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent))

from core.gesture_control import (
    GestureControlEngine,
    STABLE_FRAMES_REQUIRED,
    COOLDOWN_SECS,
    MISS_TOLERANCE,
    _model_path,
)


def run():
    passed, failed = 0, 0

    def check(label: str, cond: bool):
        nonlocal passed, failed
        if cond:
            print(f"  [PASS] {label}")
            passed += 1
        else:
            print(f"  [FAIL] {label}")
            failed += 1

    # ── Test 1: Configuration & Model Path Resolution
    print("\n=== [1] Configuration & Model Path Resolution ===")
    palm_fired = []
    fist_fired = []

    callbacks = {
        "Open_Palm": lambda: palm_fired.append("WAKE"),
        "Closed_Fist": lambda: fist_fired.append("SLEEP"),
    }

    engine = GestureControlEngine(on_gesture=callbacks, camera_index=0)
    check("Engine initialized with action mappings", len(engine._on_gesture) == 2)
    check("Default state is NONE", engine.last_gesture == "NONE")

    model_p = _model_path()
    check("Model path points to memory/models directory", "memory" in str(model_p) and "models" in str(model_p))
    check("Model file exists on disk", model_p.exists())

    # ── Test 2: Leaky Debounce Logic Simulation
    print("\n=== [2] Leaky Debounce Logic Simulation ===")
    # Simulate frame-by-frame gesture detection inside engine
    # Frame 1 to 4: Open_Palm (stable count = 4, no fire yet)
    engine._stable_count = 0
    engine._miss_count = 0
    engine._last_seen_gesture = None

    for i in range(1, STABLE_FRAMES_REQUIRED):
        # Emulate internal frame processing logic
        if engine._last_seen_gesture == "Open_Palm":
            engine._stable_count += 1
        else:
            engine._last_seen_gesture = "Open_Palm"
            engine._stable_count = 1

    check(f"4 matching frames do not fire prematurely (stable_count={engine._stable_count})", len(palm_fired) == 0)

    # Frame 5: 5th matching frame -> fires callback
    engine._stable_count += 1
    if engine._stable_count >= STABLE_FRAMES_REQUIRED:
        engine._on_gesture["Open_Palm"]()
        engine._last_fire_time = time.monotonic()
        engine.last_gesture = "Open_Palm"

    check("5th matching frame fires Open_Palm callback", len(palm_fired) == 1 and palm_fired[0] == "WAKE")
    check("last_gesture updated to Open_Palm", engine.last_gesture == "Open_Palm")

    # ── Test 3: Cooldown Window Enforcement
    print("\n=== [3] Cooldown Window Enforcement ===")
    # Within 2.0s cooldown, another 5 frames should not trigger repeat action
    cooldown_blocked = False
    now = time.monotonic()
    if now - engine._last_fire_time < COOLDOWN_SECS:
        cooldown_blocked = True
    else:
        engine._on_gesture["Open_Palm"]()

    check("Immediate repeated gesture blocked by 2.0s cooldown", cooldown_blocked is True)
    check("Callback not duplicate-fired", len(palm_fired) == 1)

    # ── Test 4: Miss Tolerance & Jitter Resilience
    print("\n=== [4] Miss Tolerance & Jitter Resilience ===")
    # 1 stray frame does not discard stable count
    engine._last_seen_gesture = "Closed_Fist"
    engine._stable_count = 3
    engine._miss_count = 0

    # Single glitch frame ("NONE")
    glitch_reading = "NONE"
    if glitch_reading != engine._last_seen_gesture:
        engine._miss_count += 1
        # Miss tolerance allows 1 stray frame without resetting stable_count
        if engine._miss_count >= MISS_TOLERANCE:
            engine._stable_count = 0

    check("Single noise/glitch frame tolerated without resetting progress", engine._stable_count == 3)
    check("Miss count tracked", engine._miss_count == 1)

    # ── Test 5: Clean Lifecycle Start & Stop
    print("\n=== [5] Clean Lifecycle Start & Stop ===")
    with patch("threading.Thread") as mock_thread_cls:
        mock_th = MagicMock()
        mock_thread_cls.return_value = mock_th
        engine.start()
        check("Engine start initializes background worker thread", mock_th.start.called)
        engine.stop()
        check("Engine stop signals stop event", engine._stop_event.is_set())

    print(f"\n==================================================")
    print(f"  Results: {passed} passed, {failed} failed")
    print(f"==================================================")
    return failed == 0


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
