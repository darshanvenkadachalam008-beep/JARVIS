"""
test_wake_word.py (v2) — exercises the REAL core/wake_word.py directly,
including the auto-download fix, instead of guessing at paths itself.

Run from your project root:

    python test_wake_word.py

This calls WakeWordEngine.start() exactly the way jarvis_service.pyw does.
If the model needs downloading (openwakeword>=0.6.0 ships with no bundled
models), this WILL trigger that one-time download and may take a few
seconds — that's expected and is the fix working, not a hang.
"""
import sys
import time


def main():
    print("=== Step 1: import core.wake_word ===")
    try:
        from core.wake_word import WakeWordEngine
    except Exception as e:
        print(f"FAILED to import core.wake_word: {type(e).__name__}: {e}")
        print("\nMake sure you replaced core/wake_word.py with the fixed version,")
        print("and that you're running this from the project root.")
        sys.exit(1)
    print("PASS\n")

    print("=== Step 2: start the real WakeWordEngine (this is what JARVIS does) ===")
    print("(If this needs to download the model, it'll happen now — give it")
    print(" a few seconds, especially on the first run.)\n")

    errors = []
    woke = []

    def on_error(msg):
        errors.append(msg)

    def on_wake():
        woke.append(True)
        print(">>> WAKE WORD DETECTED! <<<")

    engine = WakeWordEngine(on_wake=on_wake, on_error=on_error)
    engine.start()

    # Give it a moment — model loading (and possible download) happens
    # synchronously inside start(), so by the time we get here it's either
    # already failed (errors populated) or already listening.
    time.sleep(1.0)

    if errors:
        print("=== RESULT: FAILED ===")
        print(errors[0])
        sys.exit(1)

    if engine.load_error:
        print("=== RESULT: FAILED ===")
        print(engine.load_error)
        sys.exit(1)

    print("=== RESULT: PASS ===")
    print("Model loaded and the listener thread is running.")
    print("\n=== Step 3: live mic test (optional, 10 seconds) ===")
    print("Say 'Hey Jarvis' into your microphone now...")
    for i in range(10, 0, -1):
        print(f"  {i}...", end="\r")
        time.sleep(1)
        if woke:
            break
    print()

    if woke:
        print("\n✅ SUCCESS — wake word was detected live through your mic.")
    else:
        print("\n⚠️ Model loaded fine, but no wake word was detected in 10s.")
        print("This means loading works (the original bug is fixed), but you")
        print("may need to: speak closer to the mic, check the correct input")
        print("device is selected in Windows sound settings, or lower the")
        print("sensitivity threshold in JARVIS's Settings panel.")

    engine.stop()


if __name__ == "__main__":
    main()