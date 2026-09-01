"""
start_mobile_server.py — Standalone Mobile Companion Server Launcher
=====================================================================
Starts MobileServer independently for testing phone access, FCM,
and two-way intercom without running main.py.

Usage:
  python start_mobile_server.py
"""

import queue
import sys
import threading
import time
from pathlib import Path

# Set UTF-8 encoding on Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import sounddevice as sd
from mobile_server import MobileServer

intercom_active = False
intercom_playback_queue = None
server = None


def on_cmd(text: str):
    print(f"[Standalone MobileServer] 📥 Received command from phone: {text!r}")


def on_wake():
    print("[Standalone MobileServer] ⚡ Wake button tapped on phone!")


def on_intercom_start(ip: str):
    global intercom_active, intercom_playback_queue
    if intercom_active:
        return
    print(f"[Intercom] 🎙️ Starting — requested by {ip}")
    intercom_active = True
    intercom_playback_queue = queue.Queue()

    def _mic_capture_loop():
        def _cb(indata, frames, time_info, status):
            if not intercom_active:
                raise sd.CallbackStop()
            try:
                if server:
                    server.broadcast_intercom_audio(bytes(indata))
            except Exception as e:
                print(f"[Intercom] ⚠️ mic broadcast error: {e}")
        try:
            with sd.InputStream(samplerate=16000, channels=1,
                                 dtype="int16", blocksize=1024,
                                 callback=_cb):
                while intercom_active:
                    time.sleep(0.1)
        except Exception as e:
            print(f"[Intercom] ❌ mic capture failed: {e}")

    def _speaker_playback_loop():
        try:
            with sd.RawOutputStream(samplerate=16000, channels=1,
                                     dtype="int16", blocksize=1024) as stream:
                while intercom_active:
                    try:
                        chunk = intercom_playback_queue.get(timeout=0.2)
                    except Exception:
                        continue
                    try:
                        stream.write(chunk)
                    except Exception as e:
                        print(f"[Intercom] ⚠️ playback write error: {e}")
        except Exception as e:
            print(f"[Intercom] ❌ speaker playback failed: {e}")

    threading.Thread(target=_mic_capture_loop, daemon=True, name="IntercomMic").start()
    threading.Thread(target=_speaker_playback_loop, daemon=True, name="IntercomSpeaker").start()
    if server:
        server.notify("Intercom link opened, sir.")


def on_intercom_stop(ip: str):
    global intercom_active
    if not intercom_active:
        return
    print(f"[Intercom] ⏹ Stopping — requested by {ip}")
    intercom_active = False
    if server:
        server.notify("Intercom link closed, sir.")


def on_intercom_audio(pcm_bytes: bytes):
    if not intercom_active or intercom_playback_queue is None:
        return
    try:
        intercom_playback_queue.put_nowait(pcm_bytes)
    except Exception:
        pass


if __name__ == "__main__":
    print("=" * 60)
    print("       JARVIS STANDALONE MOBILE COMPANION SERVER       ")
    print("=" * 60)

    server = MobileServer()
    server.set_callbacks(
        on_command=on_cmd,
        on_wake=on_wake,
        on_intercom_start=on_intercom_start,
        on_intercom_stop=on_intercom_stop,
        on_intercom_audio=on_intercom_audio,
    )
    server.start()

    print("\n✅ Server is live. Intercom is wired.")
    print("Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping MobileServer...")
        server.stop()
