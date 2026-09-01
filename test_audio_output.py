"""
Standalone audio output diagnostic for JARVIS.

This does NOT touch any JARVIS code. It just:
 1. Lists every audio device PortAudio sees, and which one is the
    current DEFAULT OUTPUT device (the one JARVIS's _play_audio()
    silently relies on, since no device= is ever specified).
 2. Plays a 1-second 440Hz test tone through that exact same device,
    using the exact same samplerate/channels/dtype/blocksize that
    main.py's _play_audio() uses (24000Hz, mono, int16, 1024 blocksize).

Run from the project root:
    python test_audio_output.py

If you DON'T hear a beep, the bug is 100% your Windows default output
device (wrong device selected, disconnected, or muted at the OS level)
-- not a JARVIS code bug. If you DO hear it, the bug is somewhere else
and we keep digging into main.py.
"""
import sys

try:
    import sounddevice as sd
    import numpy as np
except ImportError as e:
    print(f"FAILED to import sounddevice/numpy: {e}")
    print("Run: pip install sounddevice numpy")
    sys.exit(1)

RECEIVE_SAMPLE_RATE = 24000   # same as main.py
CHANNELS = 1                  # same as main.py
CHUNK_SIZE = 1024             # same as main.py

print("=== All audio devices PortAudio can see ===")
devices = sd.query_devices()
for i, d in enumerate(devices):
    marker = ""
    print(f"[{i}] {d['name']!r}  "
          f"in={d['max_input_channels']} out={d['max_output_channels']} "
          f"default_samplerate={d['default_samplerate']}")

try:
    default_in, default_out = sd.default.device
except Exception as e:
    print(f"Could not read sd.default.device: {e}")
    default_in, default_out = (None, None)

print()
print(f"Default INPUT device index:  {default_in}")
print(f"Default OUTPUT device index: {default_out}")

if default_out is None or default_out < 0:
    print()
    print("!!! NO DEFAULT OUTPUT DEVICE IS SET. This alone would explain")
    print("    silent playback with zero exceptions raised.")
    sys.exit(1)

out_info = devices[default_out]
print(f"Default OUTPUT device name: {out_info['name']!r}")
print(f"Max output channels on it:  {out_info['max_output_channels']}")

if out_info['max_output_channels'] < CHANNELS:
    print()
    print(f"!!! Default output device only supports "
          f"{out_info['max_output_channels']} channels, but JARVIS "
          f"requests {CHANNELS}. This would cause a silent failure "
          f"or an exception depending on the backend.")

print()
print("=== Playing a 1-second 440Hz test tone now ===")
print("    (using the SAME params _play_audio() uses: "
      f"{RECEIVE_SAMPLE_RATE}Hz, {CHANNELS}ch, int16, blocksize={CHUNK_SIZE})")
print("    Listen carefully — turn your volume up.")

duration_s = 1.0
t = np.linspace(0, duration_s, int(RECEIVE_SAMPLE_RATE * duration_s), endpoint=False)
tone = (np.sin(2 * np.pi * 440 * t) * 12000).astype(np.int16)  # not too loud
tone_bytes = tone.tobytes()

try:
    stream = sd.RawOutputStream(
        samplerate=RECEIVE_SAMPLE_RATE,
        channels=CHANNELS,
        dtype="int16",
        blocksize=CHUNK_SIZE,
    )
    stream.start()
    # write in CHUNK_SIZE*2-byte pieces, just like _play_audio does per response.data chunk
    bytes_per_chunk = CHUNK_SIZE * 2  # int16 = 2 bytes/sample, mono
    for i in range(0, len(tone_bytes), bytes_per_chunk):
        stream.write(tone_bytes[i:i + bytes_per_chunk])
    stream.stop()
    stream.close()
    print()
    print("=== RESULT: stream wrote successfully with no exception ===")
    print("Did you actually HEAR a beep just now?")
    print("  - If YES: the audio hardware path is fine. The bug is")
    print("    somewhere in JARVIS's own code/state logic, not the device.")
    print("  - If NO:  this confirms it's your Windows default OUTPUT")
    print("    device (see the device list above) — wrong device, muted,")
    print("    or disconnected. Fix it in Windows Sound Settings, or we")
    print("    can hardcode device= in main.py to force the right one.")
except Exception as e:
    print()
    print(f"=== RESULT: FAILED — {type(e).__name__}: {e} ===")
    print("This is a real, visible exception — very useful. Paste this")
    print("whole output back.")