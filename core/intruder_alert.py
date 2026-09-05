"""
core/intruder_alert.py — Failed-Login Mobile Alert (Phase 7 add-on)
=====================================================================
v5: Passes hostname + time_str to TelegramAlerter.send_alert()
    for the hacker-themed message format.
"""

from __future__ import annotations

import json
import platform
import socket
import subprocess
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

FAILED_LOGON_EVENT_ID = 4625
DEBOUNCE_SECONDS = 15
POLL_INTERVAL_SECONDS = 3.0

# CREATE_NO_WINDOW — suppresses the console flash. This module polls every
# 3 seconds via PowerShell; without this flag Windows briefly opens a console
# window for every single poll. jarvis_watcher_service.py and sentinel_extras.py
# already had this; this file was the one patch_no_flash.py was written for
# but it was never actually run against this file.
NO_WINDOW = 0x08000000

# How far back (in minutes) to look on startup for failed logons that
# happened BEFORE JARVIS finished booting — e.g. a wrong password typed
# at the Windows lock screen during the ~15-20s gap between login and
# JARVIS actually starting its watcher. Windows logs these the instant
# they happen regardless of whether JARVIS is running yet; this just
# catches up on anything logged in the recent past on startup, once.
BOOT_CATCHUP_WINDOW_MINUTES = 10

STATE_PATH = Path(__file__).resolve().parent.parent / "memory" / "intruder_alert_state.json"


def _load_last_alerted_record_id() -> int:
    try:
        if STATE_PATH.exists():
            data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            return int(data.get("last_alerted_record_id", 0))
    except Exception:
        pass
    return 0


def _save_last_alerted_record_id(record_id: int):
    try:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        STATE_PATH.write_text(
            json.dumps({"last_alerted_record_id": record_id}), encoding="utf-8"
        )
    except Exception as e:
        print(f"[IntruderAlert] Could not save state: {e}")


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


_WEBCAM_LOCK = threading.Lock()
_CLIP_ABORT_EVENT = threading.Event()


def _take_webcam_snapshot(timeout: float = 0.5) -> Optional[bytes]:
    try:
        import cv2
    except ImportError:
        print("[IntruderAlert] opencv-python not installed — skipping snapshot")
        return None

    # Preempt any active background video clip so snapshot gets device promptly
    _CLIP_ABORT_EVENT.set()

    acquired = _WEBCAM_LOCK.acquire(timeout=timeout)
    if not acquired:
        print(f"[IntruderAlert] ⚠️ Webcam device busy (timed out after {timeout}s) — skipping snapshot")
        return None

    cap = None
    try:
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            print("[IntruderAlert] No webcam available")
            return None
        for _ in range(5):
            cap.read()
        ok, frame = cap.read()
        if not ok or frame is None:
            print("[IntruderAlert] Webcam read failed")
            return None
        ok, buf = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 85])
        if not ok:
            return None
        return bytes(buf)
    except Exception as e:
        print(f"[IntruderAlert] Snapshot error: {e}")
        return None
    finally:
        if cap is not None:
            try:
                cap.release()
            except Exception:
                pass
        _CLIP_ABORT_EVENT.clear()
        _WEBCAM_LOCK.release()


def _capture_webcam_clip(
    duration_seconds: float = 5.0,
    fps: int = 15,
    resolution: tuple[int, int] = (640, 480),
) -> Optional[bytes]:
    """
    Captures a compact forensic video clip from the webcam.
    Features:
    - Shared mutex with non-blocking try-acquire: skips redundant clips during alert bursts.
    - Preemptive abort support: yields device immediately if a fast-path snapshot arrives.
    - Multi-codec fallback (MP4V, AVC1, MJPG).
    - Strict wall-clock cutoff preventing hung camera drivers from blocking the system.
    - Guaranteed cleanup of device handles, writers, temp files, and mutex locks under all outcomes.
    """
    try:
        import cv2
    except ImportError:
        print("[IntruderAlert] opencv-python not installed — skipping video clip")
        return None

    # Non-blocking acquire: if device is busy (recording another clip or taking snapshot), skip
    acquired = _WEBCAM_LOCK.acquire(blocking=False)
    if not acquired:
        print("[IntruderAlert] ⏭ Webcam device busy — skipping video clip capture")
        return None

    cap = None
    writer = None
    temp_path = None
    try:
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            print("[IntruderAlert] No webcam available for video clip")
            return None

        cap.set(cv2.CAP_PROP_FRAME_WIDTH, resolution[0])
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, resolution[1])
        cap.set(cv2.CAP_PROP_FPS, fps)

        for _ in range(3):
            if _CLIP_ABORT_EVENT.is_set():
                return None
            cap.read()

        ok, first_frame = cap.read()
        if not ok or first_frame is None:
            print("[IntruderAlert] Webcam read failed for video clip")
            return None

        h, w = first_frame.shape[:2]

        codecs_to_try = [
            ("mp4v", ".mp4"),
            ("avc1", ".mp4"),
            ("MJPG", ".avi"),
        ]

        for fourcc_str, ext in codecs_to_try:
            try:
                fourcc = cv2.VideoWriter_fourcc(*fourcc_str)
                with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tf:
                    t_path = Path(tf.name)
                twriter = cv2.VideoWriter(str(t_path), fourcc, fps, (w, h))
                if twriter.isOpened():
                    writer = twriter
                    temp_path = t_path
                    break
                else:
                    if t_path.exists():
                        t_path.unlink(missing_ok=True)
            except Exception:
                pass

        if not writer or not temp_path:
            print("[IntruderAlert] No suitable video writer codec found")
            return None

        writer.write(first_frame)
        frames_target = int(duration_seconds * fps)
        frames_recorded = 1
        start_time = time.monotonic()
        max_wall_clock = duration_seconds + 1.5
        frame_interval = 1.0 / fps

        while frames_recorded < frames_target:
            if _CLIP_ABORT_EVENT.is_set():
                print(f"[IntruderAlert] ⚠️ Video clip aborted early for fast-path snapshot ({frames_recorded} frames)")
                break

            now = time.monotonic()
            if (now - start_time) > max_wall_clock:
                print(f"[IntruderAlert] ⏱ Video clip capture hit wall-clock cutoff ({frames_recorded} frames recorded)")
                break

            ok, frame = cap.read()
            if not ok or frame is None:
                break

            writer.write(frame)
            frames_recorded += 1
            time.sleep(min(0.01, frame_interval / 2))

        writer.release()
        writer = None

        if temp_path.exists() and temp_path.stat().st_size > 0:
            return temp_path.read_bytes()
        return None

    except Exception as e:
        print(f"[IntruderAlert] Video clip capture error: {e}")
        return None
    finally:
        if writer is not None:
            try:
                writer.release()
            except Exception:
                pass
        if cap is not None:
            try:
                cap.release()
            except Exception:
                pass
        if temp_path and temp_path.exists():
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass
        _WEBCAM_LOCK.release()


def _get_latest_failed_logon_record_id() -> Optional[int]:
    cmd = (
        "Get-WinEvent -LogName Security -MaxEvents 1 "
        "-FilterXPath '*[System[EventID=4625]]' "
        "| Select-Object -ExpandProperty RecordId"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=8,
            creationflags=NO_WINDOW,
        )
        output = result.stdout.strip()
        if output and output.isdigit():
            return int(output)
        return None
    except Exception as e:
        print(f"[IntruderAlert] PowerShell query error: {e}")
        return None


def _get_failed_logon_events_since_minutes_ago(minutes: int) -> list[tuple[int, datetime]]:
    """
    Used once on startup to catch failed logons that happened BEFORE
    JARVIS's watcher thread started (e.g. at the Windows lock screen,
    during the boot-to-running gap). Uses an explicit time filter rather
    than RecordId so it's correct across reboots regardless of how the
    log's RecordId counter behaves.
    """
    cmd = (
        f"$cutoff = (Get-Date).AddMinutes(-{minutes}); "
        f"Get-WinEvent -LogName Security -MaxEvents 50 "
        f"-FilterXPath '*[System[EventID=4625]]' "
        f"| Where-Object {{ $_.TimeCreated -ge $cutoff }} "
        f"| Select-Object RecordId, TimeCreated "
        f"| Sort-Object RecordId "
        f"| ForEach-Object {{ \"$($_.RecordId)|$($_.TimeCreated)\" }}"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=10,
            creationflags=NO_WINDOW,
        )
        events = []
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if not line or "|" not in line:
                continue
            parts = line.split("|", 1)
            if len(parts) != 2:
                continue
            try:
                record_id = int(parts[0].strip())
                time_created = datetime.strptime(
                    parts[1].strip(), "%m/%d/%Y %I:%M:%S %p"
                )
            except (ValueError, TypeError):
                continue
            events.append((record_id, time_created))
        return events
    except Exception as e:
        print(f"[IntruderAlert] Boot catch-up query error: {e}")
        return []


def _get_failed_logon_events_after(baseline_id: int) -> list[tuple[int, datetime]]:
    cmd = (
        f"Get-WinEvent -LogName Security -MaxEvents 20 "
        f"-FilterXPath '*[System[EventID=4625]]' "
        f"| Where-Object {{ $_.RecordId -gt {baseline_id} }} "
        f"| Select-Object RecordId, TimeCreated "
        f"| Sort-Object RecordId "
        f"| ForEach-Object {{ \"$($_.RecordId)|$($_.TimeCreated)\" }}"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=10,
            creationflags=NO_WINDOW,
        )
        events = []
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if not line or "|" not in line:
                continue
            parts = line.split("|", 1)
            if len(parts) != 2:
                continue
            try:
                record_id = int(parts[0].strip())
                time_created = datetime.strptime(
                    parts[1].strip(), "%m/%d/%Y %I:%M:%S %p"
                )
            except (ValueError, TypeError):
                try:
                    time_created = datetime.now()
                    record_id = int(parts[0].strip())
                except Exception:
                    continue
            events.append((record_id, time_created))
        return events
    except Exception as e:
        print(f"[IntruderAlert] PowerShell event query error: {e}")
        return []


COLD_BOOT_QUEUE_PATH = Path(r"C:\ProgramData\JarvisSecurity\boot_alert_queue.enc")
COLD_BOOT_REGISTRY_KEY = r"SOFTWARE\JarvisSecurity"
COLD_BOOT_ENTROPY_VAL = "ColdBootEntropy"


def _get_cold_boot_entropy() -> Optional[bytes]:
    """Reads and unprotects the machine-scope entropy from registry."""
    if not _is_windows():
        return None
    try:
        import winreg
        from credential_provider.test_alert_queue import _dpapi_unprotect
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, COLD_BOOT_REGISTRY_KEY, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            val, typ = winreg.QueryValueEx(key, COLD_BOOT_ENTROPY_VAL)
            if typ == winreg.REG_BINARY and val:
                return _dpapi_unprotect(val, b"")
    except Exception as e:
        print(f"[IntruderAlert] Could not read cold-boot entropy: {e}")
    return None


def _read_and_clear_cold_boot_queue(custom_queue_path: Optional[Path] = None, custom_entropy: Optional[bytes] = None) -> list[dict]:
    """Decrypts and flushes pending cold-boot duress / failed logon events."""
    q_path = custom_queue_path or COLD_BOOT_QUEUE_PATH
    if not q_path.exists():
        return []

    events = []
    try:
        entropy = custom_entropy if custom_entropy is not None else _get_cold_boot_entropy()
        if not entropy:
            return []
        cipher_bytes = q_path.read_bytes()
        if not cipher_bytes:
            return []
        from credential_provider.test_alert_queue import _dpapi_unprotect
        plain_text = _dpapi_unprotect(cipher_bytes, entropy).decode("utf-8")
        for line in plain_text.strip().splitlines():
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except Exception:
                    pass
    except Exception as e:
        print(f"[IntruderAlert] Error reading cold-boot alert queue: {e}")
    finally:
        try:
            q_path.unlink(missing_ok=True)
        except Exception:
            pass
    return events


class IntruderAlertWatcher:

    def __init__(
        self,
        on_alert: Callable[[str, Optional[bytes]], None],
        log_fn: Optional[Callable[[str], None]] = None,
        enabled: bool = True,
        on_video_alert: Optional[Callable[[str, bytes], None]] = None,
        bridge: Optional[Any] = None,
    ):
        self._on_alert = on_alert
        self._on_video_alert = on_video_alert
        self._log = log_fn or (lambda _msg: None)
        self._enabled = enabled
        self._bridge = bridge
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._last_alert_ts = 0.0
        self._hostname = socket.gethostname()

        try:
            try:
                from core.telegram_alert import TelegramAlerter
            except ImportError:
                from telegram_alert import TelegramAlerter
            self._telegram = TelegramAlerter()
        except Exception as e:
            print(f"[IntruderAlert] Telegram not available: {e}")
            self._telegram = None

        try:
            from sentinel.audit import AuditLogger
            self._audit = AuditLogger()
        except Exception as e:
            print(f"[IntruderAlert] AuditLogger not available: {e}")
            self._audit = None

    def set_enabled(self, value: bool):
        self._enabled = value
        self._log(f"SYS: Intruder alert watcher {'enabled' if value else 'disabled'}")

    def start(self):
        if not _is_windows():
            print("[IntruderAlert] Not on Windows — watcher disabled")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="IntruderAlertWatcher"
        )
        self._thread.start()
        print("[IntruderAlert] [Security] Watcher started — monitoring failed logon attempts")
        self._log("SYS: Intruder alert watcher active — failed logins will alert your phone")

    def stop(self):
        self._running = False
        print("[IntruderAlert] Watcher stopped")

    def _loop(self):
        # ── 1. Flush Cold-Boot Credential Provider Offline Queue ───
        try:
            cold_boot_events = _read_and_clear_cold_boot_queue()
            if cold_boot_events:
                print(f"[IntruderAlert] [Security] Cold-Boot Queue: Flushing {len(cold_boot_events)} pending pre-network event(s)")
                for ev in cold_boot_events:
                    ts_str = ev.get("timestamp", "")
                    try:
                        ev_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    except Exception:
                        ev_dt = datetime.now()
                    ev_type = ev.get("event_type", "FAILED_PRIMARY_LOGON")
                    user = ev.get("username", "Unknown")
                    layer = ev.get("layer", "primary")
                    attempts = ev.get("attempt_count", 1)
                    if ev_type == "DURESS_LOGIN_SUCCESS":
                        desc = f"[!] SILENT DURESS ALERT: Successful logon under duress for user '{user}' (attempt: {attempts})"
                    else:
                        desc = f"[!] Pre-Login Alert (Cold-Boot Credential Provider): {ev_type} for user '{user}' (layer: {layer}, attempt: {attempts})"
                    self._fire_alert(
                        ev_dt,
                        bypass_debounce=True,
                        custom_msg=desc,
                        event_type="duress_logon_success" if ev_type == "DURESS_LOGIN_SUCCESS" else "failed_logon",
                        actor=user,
                        details={"event_type": ev_type, "layer": layer, "attempt_count": attempts, "message": desc},
                    )
        except Exception as e:
            print(f"[IntruderAlert] Cold-boot queue flush error: {e}")

        # ── 2. Windows Event Log Boot Catch-up ───────────────────
        last_alerted = _load_last_alerted_record_id()
        try:
            catchup_events = _get_failed_logon_events_since_minutes_ago(
                BOOT_CATCHUP_WINDOW_MINUTES
            )
        except Exception as e:
            print(f"[IntruderAlert] Boot catch-up failed: {e}")
            catchup_events = []

        new_events = [e for e in catchup_events if e[0] > last_alerted]
        if new_events:
            print(
                f"[IntruderAlert] [Boot Catch-up] found {len(new_events)} "
                f"failed logon(s) from before JARVIS started — alerting now"
            )
            for record_id, time_created in new_events:
                print(f"[IntruderAlert] [!] Missed failed logon! RecordId={record_id} at {time_created}")
                self._fire_alert(time_created, bypass_debounce=True, record_id=record_id)
                last_alerted = max(last_alerted, record_id)
            _save_last_alerted_record_id(last_alerted)
        else:
            print("[IntruderAlert] [Boot Catch-up] no missed failed logons found")

        baseline_id = _get_latest_failed_logon_record_id()
        if baseline_id is None:
            baseline_id = max(last_alerted, 0)
            print("[IntruderAlert] [!] Could not read baseline")
        else:
            print(f"[IntruderAlert] [OK] Baseline RecordId={baseline_id} — watching for newer events")

        highest_seen = max(baseline_id, last_alerted)
        while self._running:
            try:
                if self._enabled:
                    highest_seen = self._scan_once(highest_seen)
            except Exception as e:
                print(f"[IntruderAlert] poll error: {e}")
            time.sleep(POLL_INTERVAL_SECONDS)

    def _scan_once(self, highest_seen: int) -> int:
        events = _get_failed_logon_events_after(highest_seen)
        if not events:
            return highest_seen

        new_highest = highest_seen
        for record_id, time_created in events:
            if record_id > new_highest:
                new_highest = record_id
            print(f"[IntruderAlert] [!] New failed logon! RecordId={record_id} at {time_created}")
            self._fire_alert(time_created, record_id=record_id)

        _save_last_alerted_record_id(new_highest)
        return new_highest

    def fire_synthetic_alert(self, custom_msg: Optional[str] = None, record_id: Optional[int] = None):
        """Fires a synthetic intruder alert immediately, bypassing debounce."""
        print("[IntruderAlert] [Test] Triggering synthetic test alert...")
        self._fire_alert(
            when=datetime.now(),
            bypass_debounce=True,
            custom_msg=custom_msg or f"[Test] SYNTHETIC TEST ALERT — Intruder Alert Pipeline Test on {self._hostname}",
            record_id=record_id or 9999999,
        )

    def _fire_alert(
        self,
        when: datetime,
        bypass_debounce: bool = False,
        custom_msg: Optional[str] = None,
        record_id: Optional[int] = None,
        event_type: Optional[str] = None,
        actor: Optional[str] = None,
        details: Optional[dict] = None,
    ):
        now = time.monotonic()
        if not bypass_debounce and now - self._last_alert_ts < DEBOUNCE_SECONDS:
            print("[IntruderAlert] [Debounce] Debounced")
            return
        self._last_alert_ts = now

        time_str = when.strftime("%H:%M:%S")
        jpeg_bytes = _take_webcam_snapshot()

        # Face IDENTITY check (core/face_verify.py)
        face_note = ""
        try:
            from core.face_verify import FaceVerifier
            face_result = FaceVerifier().identify(jpeg_bytes, action="intruder_alert") if jpeg_bytes else None
            if face_result is not None:
                if not face_result.enrolled:
                    face_note = ""
                elif not face_result.face_found:
                    face_note = " (no face visible in webcam frame)"
                elif face_result.accepted:
                    face_note = " — webcam face matches the enrolled owner"
                else:
                    face_note = " — [!] webcam face does NOT match the enrolled owner"
        except Exception as e:
            print(f"[IntruderAlert] Face identity check error (non-fatal): {e}")

        if custom_msg:
            text = f"{custom_msg}{face_note}"
        else:
            text = f"[!] Failed login attempt on {self._hostname} at {time_str}{face_note}"
        print(f"[IntruderAlert] [Alert] Firing alert: {text}")

        # ── Route through Unified Security Alert Pipeline ───────────────────
        try:
            from core.unified_security_alert import dispatch_security_alert
            ev_name = event_type or ("duress_logon_success" if (custom_msg and "DURESS" in custom_msg) else "windows_lockscreen_failure")
            alert_details = details or {"message": text, "record_id": record_id, "time": time_str}
            if record_id is not None:
                alert_details["record_id"] = record_id

            dispatch_security_alert(
                trigger_type=ev_name,
                actor=actor or "system",
                details=alert_details,
                snapshot_bytes=jpeg_bytes,
                bridge=self._bridge,
                custom_msg=text,
                face_note=face_note,
                on_alert_cb=self._on_alert,
                log_fn=self._log,
            )
        except Exception as e:
            print(f"[IntruderAlert] Unified alert dispatch error: {e}")
            self._log(f"SYS: ⚠️ Unified alert dispatch error: {e}")

        # 4. Asynchronous Video Clip Capture (follows up fast still alert without delaying it)
        def _clip_worker():
            try:
                clip_bytes = _capture_webcam_clip(duration_seconds=5.0)
                if clip_bytes:
                    if self._telegram and self._telegram.configured:
                        self._telegram.send_video(
                            clip_bytes,
                            caption=f"🎥 Intruder Video Clip ({self._hostname} @ {time_str})",
                        )
                    if hasattr(self, "_on_video_alert") and self._on_video_alert:
                        try:
                            self._on_video_alert(f"Intruder Video: {self._hostname}", clip_bytes)
                        except Exception as e:
                            print(f"[IntruderAlert] on_video_alert callback error: {e}")
            except Exception as e:
                print(f"[IntruderAlert] Async video clip error: {e}")

        threading.Thread(target=_clip_worker, name="IntruderVideoClipCapture", daemon=True).start()


if __name__ == "__main__":
    import sys
    import argparse

    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
            sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
        except Exception:
            pass

    _proj_root = Path(__file__).resolve().parent.parent
    if str(_proj_root) not in sys.path:
        sys.path.insert(0, str(_proj_root))

    parser = argparse.ArgumentParser(description="JARVIS Intruder Alert Watcher & Synthetic Test")
    parser.add_argument("--test", action="store_true", help="Fire a synthetic intruder alert immediately")
    parser.add_argument("--msg", type=str, default="", help="Custom message for the synthetic alert")
    args = parser.parse_args()

    def _cli_alert_cb(text: str, jpeg: Optional[bytes]):
        print(f"[Callback] on_alert received text: {text}")
        if jpeg:
            print(f"[Callback] on_alert received webcam snapshot: {len(jpeg)} bytes")
        else:
            print("[Callback] on_alert: No webcam snapshot")

    watcher = IntruderAlertWatcher(on_alert=_cli_alert_cb, log_fn=print)

    if args.test or len(sys.argv) == 1:
        print("[IntruderAlert] CLI: Running synthetic test...")
        watcher.fire_synthetic_alert(custom_msg=args.msg or None)
        time.sleep(2)
    else:
        watcher.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            watcher.stop()