"""
tests/test_intruder_video_clip.py — Tests for Video Clip Capture on Intrusion
=============================================================================
Validates:
1. _capture_webcam_clip() success path (produces bytes, cleans temp files).
2. _capture_webcam_clip() camera-unavailable and read failure path (returns None, clean temp file handling).
3. Hard wall-clock cutoff preventing hung camera drivers from blocking execution.
4. _fire_alert fast path (still + face verify + push) is not delayed by video capture.
5. send_video() and on_video_alert() dispatch when video clip is available.
"""

import json
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

import numpy as np
import pytest

from core.intruder_alert import (
    _capture_webcam_clip,
    _take_webcam_snapshot,
    IntruderAlertWatcher,
)
from core.telegram_alert import TelegramAlerter
from mobile_server import MobileServer


class MockVideoCapture:
    def __init__(self, is_opened=True, frame_count=30, read_delay=0.0):
        self._is_opened = is_opened
        self._frame_count = frame_count
        self._read_count = 0
        self._read_delay = read_delay

    def isOpened(self):
        return self._is_opened

    def set(self, prop, val):
        pass

    def read(self):
        if self._read_delay > 0:
            time.sleep(self._read_delay)
        if self._read_count >= self._frame_count:
            return False, None
        self._read_count += 1
        dummy_frame = np.zeros((480, 640, 3), dtype=np.uint8)
        return True, dummy_frame

    def release(self):
        self._is_opened = False


class MockVideoWriter:
    created_files = []

    def __init__(self, filename, fourcc, fps, frame_size):
        self.filename = filename
        self.fourcc = fourcc
        self.fps = fps
        self.frame_size = frame_size
        self._is_opened = True
        self.written_frames = 0
        MockVideoWriter.created_files.append(filename)
        # Write dummy content so file exists
        Path(filename).write_bytes(b"MOCK_VIDEO_BINARY_DATA_STREAM")

    def isOpened(self):
        return self._is_opened

    def write(self, frame):
        self.written_frames += 1

    def release(self):
        self._is_opened = False


def test_capture_webcam_clip_success(tmp_path):
    """Verifies that _capture_webcam_clip produces bytes and unlinks its temp file."""
    mock_cv2 = MagicMock()
    mock_cv2.VideoCapture = MagicMock(return_value=MockVideoCapture(is_opened=True, frame_count=30))
    mock_cv2.VideoWriter = MagicMock(side_effect=MockVideoWriter)
    mock_cv2.VideoWriter_fourcc = MagicMock(return_value=1234)

    MockVideoWriter.created_files.clear()

    with patch.dict(sys.modules, {"cv2": mock_cv2}):
        clip_bytes = _capture_webcam_clip(duration_seconds=0.5, fps=10, resolution=(640, 480))
        assert clip_bytes == b"MOCK_VIDEO_BINARY_DATA_STREAM"

        # Verify all created temp files were cleaned up
        for f in MockVideoWriter.created_files:
            assert not Path(f).exists()


def test_capture_webcam_clip_camera_unavailable():
    """Verifies that _capture_webcam_clip returns None when webcam is unavailable."""
    mock_cv2 = MagicMock()
    mock_cv2.VideoCapture = MagicMock(return_value=MockVideoCapture(is_opened=False))

    with patch.dict(sys.modules, {"cv2": mock_cv2}):
        clip_bytes = _capture_webcam_clip(duration_seconds=1.0)
        assert clip_bytes is None


def test_capture_webcam_clip_wall_clock_cutoff():
    """
    Verifies that a stalled webcam driver triggers the hard wall-clock cutoff
    and does not hang the caller.
    """
    mock_cv2 = MagicMock()
    # Mock camera with 0.1s delay per frame to trigger timeout
    mock_cv2.VideoCapture = MagicMock(return_value=MockVideoCapture(is_opened=True, frame_count=100, read_delay=0.1))
    mock_cv2.VideoWriter = MagicMock(side_effect=MockVideoWriter)
    mock_cv2.VideoWriter_fourcc = MagicMock(return_value=1234)

    with patch.dict(sys.modules, {"cv2": mock_cv2}):
        start = time.monotonic()
        clip_bytes = _capture_webcam_clip(duration_seconds=0.2, fps=10)
        elapsed = time.monotonic() - start

        # Must finish within duration + 2.0s cutoff
        assert elapsed < 2.5
        assert clip_bytes == b"MOCK_VIDEO_BINARY_DATA_STREAM"


def test_fire_alert_fast_path_not_blocked_by_slow_clip():
    """
    Verifies that _fire_alert sends the still image alert immediately
    while clip capture runs in the background.
    """
    received_alerts = []
    received_videos = []

    def on_alert(msg, snap):
        received_alerts.append((msg, snap))

    def on_video_alert(caption, clip):
        received_videos.append((caption, clip))

    watcher = IntruderAlertWatcher(on_alert=on_alert, on_video_alert=on_video_alert, enabled=True)

    dummy_still = b"JPEG_STILL_FRAME"
    dummy_clip = b"MP4_VIDEO_CLIP"

    def slow_clip_capture(duration_seconds=5.0):
        time.sleep(0.6)
        return dummy_clip

    with patch("core.intruder_alert._take_webcam_snapshot", return_value=dummy_still):
        with patch("core.intruder_alert._capture_webcam_clip", side_effect=slow_clip_capture):
            with patch("core.face_verify.FaceVerifier.identify", return_value=None):
                with patch.object(watcher._telegram, "send_alert", return_value=True):
                    with patch.object(watcher._telegram, "send_video", return_value=True):
                        start = time.monotonic()
                        watcher._fire_alert(datetime.now(), bypass_debounce=True, custom_msg="🚨 Intruder Alert Test")
                        fast_path_elapsed = time.monotonic() - start

                        # Fast path must return immediately (< 0.35s, while clip capture takes 0.60s)
                        assert fast_path_elapsed < 0.35
                        assert len(received_alerts) == 1
                        assert "Intruder Alert Test" in received_alerts[0][0]
                        assert received_alerts[0][1] == dummy_still

                        # Wait for background clip capture thread to finish
                        time.sleep(0.7)
                        assert len(received_videos) == 1
                        assert received_videos[0][1] == dummy_clip


def test_telegram_send_video_success():
    """Tests that TelegramAlerter.send_video builds and posts multipart video payload."""
    alerter = TelegramAlerter(token="test_token", chat_id="99999")
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({"ok": True}).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        ok = alerter.send_video(b"DUMMY_MP4_BYTES", caption="Video Test", filename="test.mp4")
        assert ok is True
        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert "multipart/form-data" in req.headers["Content-type"]
        assert b"DUMMY_MP4_BYTES" in req.data


def test_mobile_server_notify_video():
    """Tests MobileServer.notify_video base64 encoding and hub broadcasting."""
    server = MobileServer()
    broadcast_messages = []

    with patch.object(server._hub, "broadcast", side_effect=lambda kind, data: broadcast_messages.append((kind, data))):
        server.notify_video("Intrusion Clip", b"VIDEO_BYTES", filename="intruder.mp4")
        assert len(broadcast_messages) == 1
        kind, payload_str = broadcast_messages[0]
        assert kind == "notify_video"
        payload = json.loads(payload_str)
        assert payload["caption"] == "Intrusion Clip"
        assert payload["filename"] == "intruder.mp4"
        import base64
        assert base64.b64decode(payload["video_b64"]) == b"VIDEO_BYTES"


def test_webcam_concurrency_cold_boot_flush_burst():
    """
    Simulates a rapid burst of cold-boot logon failure alerts and verifies:
    1. No two threads open cv2.VideoCapture simultaneously (active_caps <= 1).
    2. All fast-path snapshots succeed.
    3. The shared mutex and preemptive event prevent driver collisions.
    """
    active_caps = 0
    max_concurrent_caps = 0
    cap_lock = threading.Lock()

    class ConcurrencyTrackingVideoCapture:
        def __init__(self, is_opened=True, frame_count=15):
            nonlocal active_caps, max_concurrent_caps
            with cap_lock:
                active_caps += 1
                if active_caps > max_concurrent_caps:
                    max_concurrent_caps = active_caps
            self._is_opened = is_opened
            self._frame_count = frame_count
            self._read_count = 0

        def isOpened(self):
            return self._is_opened

        def set(self, prop, val):
            pass

        def read(self):
            time.sleep(0.01)
            if self._read_count >= self._frame_count:
                return False, None
            self._read_count += 1
            return True, np.zeros((480, 640, 3), dtype=np.uint8)

        def release(self):
            nonlocal active_caps
            with cap_lock:
                if self._is_opened:
                    active_caps -= 1
                    self._is_opened = False

    mock_cv2 = MagicMock()
    mock_cv2.VideoCapture = MagicMock(side_effect=lambda idx: ConcurrencyTrackingVideoCapture(is_opened=True))
    mock_cv2.VideoWriter = MagicMock(side_effect=MockVideoWriter)
    mock_cv2.VideoWriter_fourcc = MagicMock(return_value=1234)
    mock_cv2.imencode.return_value = (True, b"DUMMY_JPEG_BYTES")

    received_alerts = []
    received_videos = []

    watcher = IntruderAlertWatcher(
        on_alert=lambda msg, snap: received_alerts.append((msg, snap)),
        on_video_alert=lambda cap, clip: received_videos.append((cap, clip)),
        enabled=True,
    )

    with patch.dict(sys.modules, {"cv2": mock_cv2}):
        with patch.object(watcher._telegram, "send_alert", return_value=True):
            with patch.object(watcher._telegram, "send_video", return_value=True):
                # Simulate 3 rapid alerts in cold-boot flush loop
                for i in range(3):
                    watcher._fire_alert(
                        datetime.now(),
                        bypass_debounce=True,
                        custom_msg=f"Cold-Boot Event {i}",
                        record_id=1000 + i,
                    )
                    time.sleep(0.02)

                time.sleep(0.5)

                # Strict concurrency assertion: at NO point was active_caps > 1
                assert max_concurrent_caps == 1
                # All 3 fast-path alerts fired
                assert len(received_alerts) == 3


def test_fast_path_snapshot_preempts_clip_recording():
    """
    Tests that when a background clip is currently recording,
    a subsequent fast-path _take_webcam_snapshot() sets the abort event,
    causing the clip to yield the device promptly so the snapshot succeeds.
    """
    mock_cv2 = MagicMock()
    mock_cv2.VideoCapture = MagicMock(side_effect=lambda idx: MockVideoCapture(is_opened=True, frame_count=100, read_delay=0.02))
    mock_cv2.VideoWriter = MagicMock(side_effect=MockVideoWriter)
    mock_cv2.VideoWriter_fourcc = MagicMock(return_value=1234)
    mock_cv2.imencode.return_value = (True, b"PREEMPTED_SNAPSHOT_BYTES")

    with patch.dict(sys.modules, {"cv2": mock_cv2}):
        # Start clip capture on background thread
        clip_thread = threading.Thread(
            target=_capture_webcam_clip,
            kwargs={"duration_seconds": 2.0, "fps": 10},
        )
        clip_thread.start()
        time.sleep(0.05)  # Let clip capture acquire lock and start

        # Now execute fast-path snapshot
        start = time.monotonic()
        snap_bytes = _take_webcam_snapshot(timeout=0.5)
        elapsed = time.monotonic() - start

        clip_thread.join(timeout=1.0)

        assert snap_bytes == b"PREEMPTED_SNAPSHOT_BYTES"
        assert elapsed < 0.5


def test_webcam_lock_released_on_clip_exception():
    """
    Tests that when an unhandled exception occurs in _capture_webcam_clip,
    the mutex is guaranteed to be released in the finally block.
    """
    from core.intruder_alert import _WEBCAM_LOCK

    mock_cv2 = MagicMock()
    mock_cap = MockVideoCapture(is_opened=True)
    mock_cv2.VideoCapture = MagicMock(return_value=mock_cap)
    # Inject error on VideoWriter
    mock_cv2.VideoWriter = MagicMock(side_effect=RuntimeError("Simulated video writer crash"))
    mock_cv2.VideoWriter_fourcc = MagicMock(return_value=1234)

    with patch.dict(sys.modules, {"cv2": mock_cv2}):
        clip_bytes = _capture_webcam_clip(duration_seconds=1.0)
        assert clip_bytes is None
        # Mutex must not remain locked
        assert not _WEBCAM_LOCK.locked()

