"""
Concurrent-stream diagnostic for JARVIS.

The standalone test_audio_output.py proved your speakers/headphones work
fine with a single, isolated RawOutputStream. But the real app has THREE
sounddevice streams open at once:
  1. The wake-word listener's InputStream (always-on mic)
  2. Gemini's own InputStream (mic -> Gemini, only while LISTENING)
  3. Gemini's own RawOutputStream (Gemini's voice -> your speakers)

This script reproduces #1 + #3 running AT THE SAME TIME (the exact
combination active right when JARVIS replies after a wake word), using
the same parameters as the real code, to see if a second concurrently
open InputStream silently breaks audio OUTPUT on your machine.

Run from the project root:
    python test_concurrent_audio.py
"""
import sys
import time
import threading

try:
    import sounddevice as sd
    import numpy as np
except ImportError as e:
    print(f"FAILED to import sounddevice/numpy: {e}")
    sys.exit(1)

SEND_SAMPLE_RATE    = 16000   # mic rate, same as main.py
RECEIVE_SAMPLE_RATE = 24000   # playback rate, same as main.py
CHANNELS            = 1
CHUNK_SIZE          = 1024

mic_frames_seen = [0]


def mic_callback(indata, frames, time_info, status):
    if status:
        print(f"[MIC] status flag: {status}")
    mic_frames_seen[0] += frames


def main():
    print("=== Step 1: open a background InputStream (simulating the ===")
    print("===         always-on wake-word listener mic)              ===")
    try:
        mic_stream = sd.InputStream(
            samplerate=SEND_SAMPLE_RATE,
            channels=CHANNELS,
            dtype="int16",
            blocksize=CHUNK_SIZE,
            callback=mic_callback,
        )
        mic_stream.start()
        print("PASS — background mic InputStream opened and started.")
    except Exception as e:
        print(f"FAILED to open background InputStream: {type(e).__name__}: {e}")
        sys.exit(1)

    time.sleep(0.5)
    print(f"Mic frames captured so far: {mic_frames_seen[0]} (should be > 0)")

    print()
    print("=== Step 2: WHILE that mic stream is still running, open an ===")
    print("===         output stream and play a tone (simulating      ===")
    print("===         Gemini's voice reply happening right after a   ===")
    print("===         wake word, while the wake-word mic is open)    ===")
    print("    Listen carefully — turn your volume up.")

    duration_s = 1.5
    t = np.linspace(0, duration_s, int(RECEIVE_SAMPLE_RATE * duration_s), endpoint=False)
    tone = (np.sin(2 * np.pi * 440 * t) * 12000).astype(np.int16)
    tone_bytes = tone.tobytes()

    try:
        out_stream = sd.RawOutputStream(
            samplerate=RECEIVE_SAMPLE_RATE,
            channels=CHANNELS,
            dtype="int16",
            blocksize=CHUNK_SIZE,
        )
        out_stream.start()
        bytes_per_chunk = CHUNK_SIZE * 2
        for i in range(0, len(tone_bytes), bytes_per_chunk):
            out_stream.write(tone_bytes[i:i + bytes_per_chunk])
        out_stream.stop()
        out_stream.close()
        print()
        print("=== RESULT: output stream wrote successfully, no exception ===")
    except Exception as e:
        print()
        print(f"=== RESULT: FAILED while mic was open — {type(e).__name__}: {e} ===")
        print("THIS IS THE BUG: a concurrently-open InputStream is breaking")
        print("output on your machine. Paste this whole output back.")
        mic_stream.stop()
        mic_stream.close()
        sys.exit(1)

    mic_frames_after = mic_frames_seen[0]
    mic_stream.stop()
    mic_stream.close()

    print()
    print(f"Mic frames captured by the end: {mic_frames_after}")
    print()
    print("Did you hear the beep just now, WHILE the background mic")
    print("stream was also open?")
    print("  - If YES: concurrent streams are NOT the bug. The silence in")
    print("    the real app is happening somewhere else in the code logic")
    print("    (e.g. the queue/task never actually receiving chunks).")
    print("  - If NO:  confirmed — having a second InputStream open at the")
    print("    same time silently kills output on your machine. This is a")
    print("    real, fixable PortAudio/host-API conflict, and the fix is")
    print("    to force a specific host API or explicit device= for the")
    print("    output stream so it can't collide with the wake-word mic.")


if __name__ == "__main__":
    main()