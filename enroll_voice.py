"""
enroll_voice.py — One-time voice enrollment for speaker verification
========================================================================
Records a few short clips of your voice through the mic and builds the
profile that core/speaker_verify.py compares future wake-word utterances
against. Run this once (re-run any time with --reset to replace it).

Usage
-----
    python enroll_voice.py                 # interactive, records via mic
    python enroll_voice.py --reset         # deletes the existing profile
    python enroll_voice.py --list-devices  # show mic device indices
    python enroll_voice.py --device 3      # use a specific mic

Notes
-----
- Say a MIX of phrases across the clips: some should be "Hey Jarvis" itself,
  some should just be normal sentences. This makes the profile robust to
  more than one exact phrasing.
- Each clip is ~2.5s, which is intentionally the same length as
  UTTERANCE_BUFFER_SECONDS in core/wake_word.py, so enrollment conditions
  match verification conditions.
- This only builds the voice profile. It does NOT touch your PIN
  (core/access_control.py) or your vault (core/secure_vault.py) — those
  stay exactly as configured.
"""
from __future__ import annotations

import argparse
import sys
import time

import numpy as np
import sounddevice as sd

from core.speaker_verify import SpeakerVerifier, MIN_ENROLL_CLIPS

SAMPLE_RATE = 16000
CLIP_SECONDS = 2.5

PROMPTS = [
    "Say: \"Hey Jarvis\" (normal voice, normal distance from the mic)",
    "Say: \"Hey Jarvis, what's the weather today\"",
    "Say a normal sentence, e.g. \"Open my email and check for new messages\"",
    "Say: \"Hey Jarvis\" again, a little further from the mic this time",
    "Say any sentence you like, at your normal speaking volume",
]


def record_clip(seconds: float, device: int | None) -> np.ndarray:
    frames = sd.rec(
        int(seconds * SAMPLE_RATE), samplerate=SAMPLE_RATE, channels=1,
        dtype="int16", device=device,
    )
    sd.wait()
    return frames.flatten()


def list_devices():
    print(sd.query_devices())


def main():
    parser = argparse.ArgumentParser(description="Enroll your voice for JARVIS speaker verification.")
    parser.add_argument("--reset", action="store_true", help="Delete the existing voice profile and exit.")
    parser.add_argument("--list-devices", action="store_true", help="List audio input devices and exit.")
    parser.add_argument("--device", type=int, default=None, help="Input device index (see --list-devices).")
    parser.add_argument("--clips", type=int, default=max(MIN_ENROLL_CLIPS, 4),
                         help=f"How many clips to record (min {MIN_ENROLL_CLIPS}).")
    args = parser.parse_args()

    if args.list_devices:
        list_devices()
        return

    sv = SpeakerVerifier()

    if args.reset:
        sv.reset()
        print("Voice profile deleted. Run without --reset to enroll again.")
        return

    if sv.is_enrolled():
        answer = input("A voice profile already exists. Replace it? [y/N]: ").strip().lower()
        if answer != "y":
            print("Cancelled — existing profile kept.")
            return
        sv.reset()

    n_clips = max(args.clips, MIN_ENROLL_CLIPS)
    print(f"\nRecording {n_clips} clips of ~{CLIP_SECONDS}s each. Speak clearly, wait for 'Recording...'.\n")

    clips = []
    for i in range(n_clips):
        prompt = PROMPTS[i % len(PROMPTS)]
        input(f"[{i + 1}/{n_clips}] {prompt}\n    Press Enter, then speak immediately...")
        print("    Recording...", end="", flush=True)
        clip = record_clip(CLIP_SECONDS, args.device)
        print(" done.")
        clips.append(clip)
        time.sleep(0.3)

    print("\nBuilding voice profile...")
    try:
        sv.enroll(clips, sample_rate=SAMPLE_RATE)
    except ValueError as e:
        print(f"\nEnrollment failed: {e}")
        sys.exit(1)

    print(
        f"\nDone. Voice profile saved to {sv.path}\n"
        f"Default match threshold: {sv.threshold:.2f} — this is a starting point,\n"
        f"not calibrated to your specific mic/room. If JARVIS repeatedly logs\n"
        f"'voice did NOT match' for you, or accepts an obviously different\n"
        f"voice, run core/speaker_verify.py's calibrate() with a few clips of\n"
        f"your own voice and a few of someone else's to find a better threshold\n"
        f"for your setup, then pass it via SpeakerVerifier(threshold=...).\n"
    )


if __name__ == "__main__":
    main()